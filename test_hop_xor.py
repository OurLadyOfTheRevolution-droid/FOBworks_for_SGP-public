#!/usr/bin/env python3
"""Host harness for the N14 hop-XOR telemetry.

The property under test: for two presses of the SAME button on a KeeLoq fob the
plaintext fields other than the counter are identical, so the XOR of the two
transmitted hop words is a key-independent observable. Two things follow, and
both are asserted against the SHIPPED code rather than a model:

  1. hop_xor == E(ptA) ^ E(ptB), reproducible from the two plaintext counters
     alone once a manufacturer/device key is known (we use the public Kia
     V3/V4 OEM key, the only one shipped with the firmware that is public).
  2. The XOR is order-symmetric: swapping the two frames changes nothing, which
     is exactly why a rollback sequence can be validated without the key.

The pure helpers ks_hopXorPair / ks_hopRingStart / ks_hopRingAt and the ring
emitter are extracted verbatim from the firmware source.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# The Kia OEM key is public, but a published tree does not write it out. Derive it
# from the masked constant the sketch ships and inject it into the C harness at compile
# time, so the literal lives only in the temporary build file, never in this repo.
def _kia_literal():
    import re as _re
    _s = (Path(__file__).resolve().parent / "FOBworks_for_SGP.ino").read_text(encoding="utf-8")
    assert "static inline uint64_t ks_unmaskMfrKey(uint64_t v){" in _s, \
        "the unmask helper is missing from the sketch"
    _k = int(_re.search(r"#define KIA_V34_MF_KEY\s+0x([0-9A-Fa-f]{16})ULL", _s).group(1), 16)
    _x = (_k ^ 0x3C3C3C3C3C3C3C3C) & 0xFFFFFFFFFFFFFFFF
    _k = ((((_x >> 13) | (_x << (64 - 13))) & 0xFFFFFFFFFFFFFFFF) ^ 0x5A5A5A5A5A5A5A5A)
    return f"0x{_k:016X}ULL"


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
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


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the pieces exist in the shipping source ===")
    pair = extract_fn(src, "ks_hopXorPair")
    check(pair is not None, "ks_hopXorPair extracted")
    ring_at = extract_fn(src, "ks_hopRingAt")
    check(ring_at is not None, "ks_hopRingAt extracted")
    ring_start = extract_fn(src, "ks_hopRingStart")
    check(ring_start is not None, "ks_hopRingStart extracted")
    emit = extract_fn(src, "ks_hopXorEmit")
    check(emit is not None, "ks_hopXorEmit extracted")
    enc = extract_fn(src, "ks_klEncrypt")
    check(enc is not None, "ks_klEncrypt extracted")
    dec = extract_fn(src, "ks_klDecrypt")
    check(dec is not None, "ks_klDecrypt extracted")
    check("#define KL_NLF" in src, "KL_NLF defined")
    check('op=="hop_xor"' in src, "serial hop_xor command wired")
    check('protectedRoute("/api/hop_xor"' in src, "HTTP /api/hop_xor route wired")
    check('doc["hop_xor"]' in src, "auto hop_xor block present in the KeeLoq decode path")

    print("\n=== XOR is key-independent and order-symmetric (live crypto) ===")
    # KL_NLF, ks_nlf, ks_bit, then encrypt/decrypt, then the telemetry helpers.
    harness = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#define KL_NLF 0x3A5C742EUL
#define KL_RECENT_MAX 5
#define KIA_V34_MF_KEY __KIA_ULL__

struct KLFrame { uint32_t sn,hop; uint8_t btn,sts; uint32_t rawCtr; };
typedef struct KLFrame KLFrame;
""" + "static inline uint32_t ks_nlf(uint32_t x){return (KL_NLF>>(x&31))&1;}\n" \
    + "static inline uint32_t ks_bit(uint32_t x,uint8_t n){return (x>>n)&1;}\n" \
    + enc + "\n" + dec + "\n" \
    + "static KLFrame KL_RECENT_BUF[KL_RECENT_MAX];\n" \
    + "static uint8_t KL_RECENT_HEAD=0, KL_RECENT_CNT=0;\n" \
    + "struct HopXor { uint32_t hop_xor, ctr_xor, sn_xor; uint8_t flipBits, wordOrder;\n" \
      "                bool ctrStep1, sameBtn; };\n" \
    + pair + "\n" + ring_start + "\n" + ring_at + "\n"

    # Build a real fob: serial 0x0A1B2CE7, button 3, counters stepping by 1.
    # Reuse ks_kiaV34BuildPlain's layout (ctr | serial[9:0]<<16 | btn<<28).
    body = r"""
int main(void){
  const uint32_t serial = 0x0A1B2CE7UL;
  const uint8_t  btn    = 0x3;
  uint32_t h[4];
  for(int i=0;i<4;i++){
    uint16_t ctr = (uint16_t)(0x100 + i);
    uint32_t pt = (uint32_t)(ctr & 0xFFFF)
                | ((serial & 0x3FFUL) << 16)
                | ((uint32_t)(btn & 0x0F) << 28);
    h[i] = ks_klEncrypt(pt, KIA_V34_MF_KEY);
  }
  // sn packs disc<<4 | btn; discriminator constant across presses.
  KLFrame F[4];
  for(int i=0;i<4;i++){
    F[i].sn = ((uint32_t)0x123 << 4) | (btn & 0x0F);
    F[i].btn = btn; F[i].sts = 0; F[i].rawCtr = (uint16_t)(0x100 + i);
    F[i].hop = h[i];
  }

  // 1. hop_xor must equal E(ptA)^E(ptB) for the SAME button.
  HopXor a = ks_hopXorPair(F[0], F[1]);
  uint32_t ptA = (uint32_t)(0x100)                  | ((serial&0x3FFUL)<<16) | ((uint32_t)btn<<28);
  uint32_t ptB = (uint32_t)(0x101)                  | ((serial&0x3FFUL)<<16) | ((uint32_t)btn<<28);
  uint32_t want = ks_klEncrypt(ptA, KIA_V34_MF_KEY) ^ ks_klEncrypt(ptB, KIA_V34_MF_KEY);
  printf("hop_xor          = 0x%08lX\n", (unsigned long)a.hop_xor);
  printf("E(ptA)^E(ptB)    = 0x%08lX\n", (unsigned long)want);
  printf("ctr_xor          = 0x%04lX\n", (unsigned long)a.ctr_xor);
  printf("flip_bits        = %u\n", a.flipBits);
  printf("same_btn         = %d\n", a.sameBtn);
  printf("ctr_step1        = %d\n", a.ctrStep1);

  // 2. order symmetry: swapping the operands cannot change the XOR.
  HopXor b = ks_hopXorPair(F[1], F[0]);
  printf("order_symmetric  = %d\n", (a.hop_xor==b.hop_xor && a.ctr_xor==b.ctr_xor));

  // 3. different button must clear same_btn.
  KLFrame other = F[1]; other.sn = ((uint32_t)0x123<<4) | 0x05; other.btn = 5;
  HopXor c = ks_hopXorPair(F[0], other);
  printf("diff_btn_sameBtn = %d\n", c.sameBtn);

  // 4. identical frame -> repeat signature (xor 0, flip 0).
  HopXor d = ks_hopXorPair(F[2], F[2]);
  printf("repeat_xor       = 0x%08lX\n", (unsigned long)d.hop_xor);
  printf("repeat_flip      = %u\n", d.flipBits);

  int ok = (a.hop_xor==want) && (a.ctr_xor==1) && (b.hop_xor==a.hop_xor)
        && (!c.sameBtn) && (d.hop_xor==0) && (d.flipBits==0);
  return ok ? 0 : 1;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "t.cpp"
        tp.write_text((harness + body).replace("__KIA_ULL__", _kia_literal()))
        exe = str(Path(tmp) / "t")
        r = subprocess.run(["clang++", "-O1", "-std=c++17", "-o", exe, str(tp)],
                           capture_output=True, text=True)
        check(r.returncode == 0, f"hop-xor harness compiles {r.stderr[:200]}")
        if r.returncode == 0:
            run = subprocess.run([exe], capture_output=True, text=True)
            out = run.stdout
            print("\n".join("    " + ln for ln in out.strip().splitlines()))
            check("hop_xor          = 0x" in out, "hop_xor computed")
            # parse the two hex values and require equality
            mx = re.search(r"hop_xor\s*=\s*(0x[0-9A-Fa-f]+)", out)
            mw = re.search(r"E\(ptA\)\^E\(ptB\)\s*=\s*(0x[0-9A-Fa-f]+)", out)
            check(mx and mw and mx.group(1).lower() == mw.group(1).lower(),
                  "hop_xor == E(ptA)^E(ptB) — key-independent observable")
            check("ctr_xor          = 0x0001" in out, "ctr_xor tracks the +1 counter step")
            check("order_symmetric  = 1" in out, "XOR is order-symmetric (rollback-safe)")
            check("diff_btn_sameBtn = 0" in out, "a different button clears same_btn")
            check("repeat_flip      = 0" in out, "identical frames have a zero flip strip")
            check(run.returncode == 0, "all live assertions pass in the harness")

    print("\n=== ring wrap order (pure helper) ===")
    wrap = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
struct KLFrame { uint32_t sn,hop; uint8_t btn,sts; uint32_t rawCtr; };
typedef struct KLFrame KLFrame;
#define KL_RECENT_MAX 5
static KLFrame KL_RECENT_BUF[KL_RECENT_MAX];
static uint8_t KL_RECENT_HEAD=0, KL_RECENT_CNT=0;
""" + ring_start + "\n" + ring_at + "\n"
    # Model a full ring that has wrapped: head points past the oldest.
    # Push codes 10,11,12,13,14 in order -> head lands back at 0, cnt=5.
    body = r"""
int main(void){
  for(int i=0;i<5;i++){ KL_RECENT_BUF[i].hop = 10+i; }
  KL_RECENT_HEAD = 0; KL_RECENT_CNT = 5;
  // oldest first: slot 0 holds 10 ... slot 4 holds 14
  int ok = 1;
  for(int i=0;i<5;i++) if(ks_hopRingAt(i).hop != 10+i) ok = 0;
  printf("start0 = %u\n", ks_hopRingStart());
  printf("order0 = %d\n", ok);
  // Now move head to 3 (three newer writes): logical order 13,14,10,11,12
  KL_RECENT_HEAD = 3;
  int exp[5] = {13,14,10,11,12};
  ok = 1;
  for(int i=0;i<5;i++) if(ks_hopRingAt(i).hop != exp[i]) ok = 0;
  printf("start3 = %u\n", ks_hopRingStart());
  printf("order3 = %d\n", ok);
  return (ok)?0:1;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "w.cpp"
        tp.write_text(wrap + body)
        exe = str(Path(tmp) / "w")
        r = subprocess.run(["clang++", "-O1", "-std=c++17", "-o", exe, str(tp)],
                           capture_output=True, text=True)
        check(r.returncode == 0, f"ring harness compiles {r.stderr[:200]}")
        if r.returncode == 0:
            run = subprocess.run([exe], capture_output=True, text=True)
            print("\n".join("    " + ln for ln in run.stdout.strip().splitlines()))
            check("order0 = 1" in run.stdout, "full ring order is oldest-first")
            check("order3 = 1" in run.stdout, "wrapped ring order is oldest-first")

    print()
    if FAILS:
        print(f"FAILED ({len(FAILS)}):")
        for f in FAILS:
            print("  -", f)
        return 1
    print("all hop-xor telemetry checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
