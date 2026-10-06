#!/usr/bin/env python3
"""Host harness for the N22 live claim trace.

The failure this exists to catch is a class, not an instance: a decode that
claims a protocol the timing does not support, with nothing recording the timing
that produced the claim. 's loose KeeLoq gate was the latest member of
that class. The trace keeps one record per decode — claimed or not — so the
claim and the numbers behind it sit side by side.

The assertions below run against the SHIPPED code, extracting the ring, the
emitter and the fields from the firmware source and linking them with the real
ArduinoJson library the sketch builds against:

  1. The record lands at the one exit every decode reaches, and no early return
     can skip it (the old silent path is the whole point of the trace).
  2. The ring reads oldest-first from the helpers and the emitter renders
     newest-first, so a terminal and a dashboard agree on "what just happened".
  3. A claim carries its protocol label and its gate; a silence carries neither
     a protocol key nor a gate other than "none".
  4. The spread field is the shipped ks_teStddev over the pulse train as a
     percentage, so a jittered capture reads higher than a clean one.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
AJ = Path.home() / "Documents/Arduino/libraries/ArduinoJson/src"
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def extract_fn(src, signature):
    # Return type may contain const/&/<>, so match "static" then anything up to
    # the function name, then the parameter list up to the opening brace.
    pat = re.compile(r"^static\s+[^\n(]*?\b" + re.escape(signature) +
                     r"\s*\([^{;]*?\)\s*\{", re.M | re.S)
    m = pat.search(src)
    if not m:
        return None
    i = src.index("{", m.start())
    depth = 0
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    return None


def slice_region(src, start_marker, end_marker):
    a = src.index(start_marker)
    b = src.index(end_marker, a)
    return src[a:b]


def compile_run(prologue, body, tag, check):
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "t.cpp"
        tp.write_text(prologue + body)
        exe = str(Path(tmp) / "t")
        r = subprocess.run(["clang++", "-O1", "-std=c++17",
                            "-I", str(AJ), "-o", exe, str(tp)],
                           capture_output=True, text=True)
        check(r.returncode == 0, f"{tag} compiles {r.stderr[:300]}")
        if r.returncode != 0:
            return ""
        run = subprocess.run([exe], capture_output=True, text=True)
        return run.stdout


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the pieces exist in the shipping source ===")
    for fn in ("ks_ctPush", "ks_ctStart", "ks_ctAt", "ks_ctClear",
               "ks_ctEmit", "ks_ctGateName", "ks_ctProtoName", "ks_teStddev"):
        check(extract_fn(src, fn) is not None, f"{fn} extracted")
    check("#define CT_RING_MAX 8" in src, "ring depth is 8")
    check("struct ClaimRec {" in src, "ClaimRec record declared")
    check('op=="claim_trace"' in src, "serial claim_trace command wired")
    check('protectedRoute("/api/claim_trace"' in src, "HTTP /api/claim_trace route wired")
    check('{"cmd":"claim_trace"}' in src, "command documented in the serial header")

    print("\n=== the record lands at the one exit every decode reaches ===")
    # ClaimRec has to be visible to the preprocessor prototype block, so it is
    # hoisted above the sketch body; the ring helpers live near the other
    # telemetry helpers. Both placements are load-bearing, so pin them.
    i_struct = src.index("struct ClaimRec {")
    i_push = src.index("static void ks_ctPush")
    check(i_struct < i_push, "ClaimRec is hoisted above the ring helpers")
    di = src.index("decodeSignal(")
    i_trace = src.index("// \u2500\u2500 Live claim trace (N22)", di)
    i_push_call = src.index("ks_ctPush(_r);", i_trace)
    # Everything from the trace block to the closing brace of decodeSignal must
    # be free of early returns, or a decode could exit without being recorded.
    # The only return left is the function's own, which is the point.
    tail = src[i_push_call:src.index("\n}\n", i_push_call)]
    check(tail.count("return ") == 1 and "return lastDecode;" in tail,
          "the trace record is followed only by decodeSignal's own exit")
    check(src.index('serializeJson(doc,lastDecode);', di) < i_trace,
          "the trace reads back the JSON the decoder already built")
    check('_r.claimed = (_cp[0] != \'\\0\');' in src,
          "claimed is keyed off the decoded proto label, not a second guess")

    print("\n=== ring helpers and emitter against the shipped code ===")
    decl = re.search(r"struct ClaimRec \{.*?\};", src, re.S)
    check(decl is not None, "ClaimRec body sliced from source")
    region = slice_region(src, "#define CT_RING_MAX 8", "// KeeLoq encrypt")
    check("ks_ctEmit" in region and "CT_GATE_NONE" in region,
          "ring region sliced with the gate/proto tables")
    # The region uses ArduinoJson and String, so link the real library with a
    # minimal std::string shim — the same header the sketch builds against.
    prologue = ("#include <ArduinoJson.h>\n#include <string>\n#include <cstdio>\n"
                "#include <cstdint>\n#include <cstring>\n"
                "using String = std::string;\n"
                + (decl.group(0) if decl else "") + "\n" + region + "\n")

    body = r"""
static void dump(const char* tag, JsonDocument& d){
  String s; serializeJson(d,s);
  printf("%s %s\n", tag, s.c_str());
}
int main(void){
  ks_ctClear();
  // Oldest -> newest: a real KeeLoq press (loose gate), an unclaimed silence,
  // then a confirmed Kia frame. Pushing in this order exercises the wrap.
  ClaimRec a; a.te=380; a.edges=104; a.hash=0x11223344; a.gate=CT_GATE_LOOSE;
              a.ratio=4;  a.proto=CT_PROTO_KEELOQ;  a.claimed=true;
  ClaimRec b; b.te=900; b.edges=22;  b.hash=0xAABBCCDD; b.gate=CT_GATE_NONE;
              b.ratio=41; b.proto=CT_PROTO_NONE;    b.claimed=false;
  ClaimRec c; c.te=396; c.edges=112; c.hash=0xDEADBEEF; c.gate=CT_GATE_KNOWN;
              c.ratio=3;  c.proto=CT_PROTO_KIA;     c.claimed=true;
  ks_ctPush(a); ks_ctPush(b); ks_ctPush(c);

  JsonDocument d;
  ks_ctEmit(d);
  dump("EMIT", d);
  printf("COUNT %u\n", (unsigned)CT_CNT);
  printf("START %u\n", (unsigned)ks_ctStart());
  printf("AT0_TE %u\n", (unsigned)ks_ctAt(0).te);
  printf("AT2_TE %u\n", (unsigned)ks_ctAt(2).te);

  // Overflow: push until the ring wraps, then the oldest must be evicted.
  for(int i=0;i<8;i++){
    ClaimRec r; r.te=(uint16_t)(1000+i); r.edges=8; r.hash=(uint32_t)i;
    r.gate=CT_GATE_NONE; r.ratio=0; r.proto=CT_PROTO_NONE; r.claimed=false;
    ks_ctPush(r);
  }
  printf("WRAP_CNT %u\n", (unsigned)CT_CNT);
  printf("WRAP_OLDEST %u\n", (unsigned)ks_ctAt(0).te);
  printf("WRAP_NEWEST %u\n", (unsigned)ks_ctAt(CT_CNT-1).te);
  JsonDocument d2; ks_ctEmit(d2); dump("WRAP", d2);

  ks_ctClear();
  printf("CLEAR_CNT %u\n", (unsigned)CT_CNT);
  JsonDocument d3; ks_ctEmit(d3); dump("CLEAR", d3);
  return 0;
}
"""
    out = compile_run(prologue, body, "claim-trace harness", check)
    if out:
        print("\n".join("    " + ln for ln in out.strip().splitlines()))
        m = re.search(r"^EMIT (\{.*\})$", out, re.M)
        check(m is not None, "emitter produced JSON")
        if m:
            d = json.loads(m.group(1))
            check(d.get("count") == 3 and d.get("max") == 8,
                  "count and max report the ring depth")
            t = d.get("trace", [])
            check(len(t) == 3, "three records rendered")
            check(t[0].get("proto") == "Kia" and t[0].get("gate") == "known",
                  "newest record is first and carries proto+gate")
            check(t[1].get("claimed") is False and "proto" not in t[1],
                  "an unclaimed decode carries no proto key")
            check(t[1].get("gate") == "none", "an unclaimed decode gates as none")
            check(t[2].get("proto") == "KeeLoq" and t[2].get("gate") == "loose",
                  "oldest record is last (newest-first render)")
            check(t[0].get("te_us") == 396 and t[1].get("edges") == 22 and
                  t[2].get("std_pct") == 4,
                  "te/edges/spread fields survive the render")
            check(t[0].get("hash") == "0xDEADBEEF",
                  "hash renders as a fixed-width hex string")
        check("AT0_TE 380" in out, "ks_ctAt(0) is the oldest record")
        check("WRAP_CNT 8" in out, "ring saturates at CT_RING_MAX")
        check("WRAP_OLDEST 1000" in out and "WRAP_NEWEST 1007" in out,
              "wrap evicts the oldest and keeps order")
        mw = re.search(r"^WRAP (\{.*\})$", out, re.M)
        if mw:
            dw = json.loads(mw.group(1))
            check(len(dw.get("trace", [])) == 8, "wrapped ring still renders 8")
            check(dw["trace"][0].get("te_us") == 1007,
                  "wrapped render is still newest-first")
        check("CLEAR_CNT 0" in out, "clear zeroes the ring")
        mc = re.search(r"^CLEAR (\{.*\})$", out, re.M)
        if mc:
            dc = json.loads(mc.group(1))
            check(dc.get("count") == 0 and dc.get("trace") == [],
                  "cleared ring renders an empty trace")

    print("\n=== spread field is the shipped ks_teStddev as a percentage ===")
    std_fn = extract_fn(src, "ks_teStddev")
    spread = ("#include <cstdio>\n#include <cstdint>\n#include <cmath>\n" + std_fn + "\n" + r"""
int main(void){
  // A clean 32-pulse train at te=380, then the same train jittered by +-15%.
  uint32_t clean[32], rough[32];
  for(int i=0;i<32;i++){ clean[i]=380; rough[i]=(i&1)?380:440; }
  uint32_t sc = ks_teStddev(clean,32,380);
  uint32_t sr = ks_teStddev(rough,32,380);
  printf("CLEAN_STD %u\n", (unsigned)sc);
  printf("ROUGH_STD %u\n", (unsigned)sr);
  printf("CLEAN_PCT %u\n", (unsigned)((sc*100u)/380));
  printf("ROUGH_PCT %u\n", (unsigned)((sr*100u)/380));
  return 0;
}
""")
    out2 = compile_run(spread, "", "spread harness", check)
    if out2:
        print("\n".join("    " + ln for ln in out2.strip().splitlines()))
        check("CLEAN_STD 0" in out2, "a uniform pulse train has zero spread")
        mcp = re.search(r"CLEAN_PCT (\d+)", out2)
        mrp = re.search(r"ROUGH_PCT (\d+)", out2)
        # +-15% jitter sits inside the ks_teStddev acceptance band, so it counts
        # toward the spread rather than being discarded as an outlier.
        check(mcp and mrp and int(mrp.group(1)) > int(mcp.group(1)),
              "a jittered pulse train reads a higher spread percentage")

    print()
    if FAILS:
        print(f"FAILED ({len(FAILS)}):")
        for f in FAILS:
            print("  -", f)
        return 1
    print("all live claim-trace checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
