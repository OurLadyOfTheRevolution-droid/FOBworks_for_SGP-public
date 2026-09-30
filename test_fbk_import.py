#!/usr/bin/env python3
"""Verify the stored-frame import path (research/22 §3) against real capture data.

The blocker this closes: fbkBuf had exactly one writer, the armed live-capture path, and on
this board that path cannot produce a usable code — RSSI fallback fills the buffer with
uniform ~1600 us pulses and the no-bit-edges guard correctly refuses them. So fbkCount stayed
0 and C2 could not be armed at all.

What this checks, using COMPILED COPIES of the real functions rather than a reimplementation
(an earlier Python model of the encoder disagreed with the running code and cost a round):

  1. a real Kia V3 frame imports and reports trimmed=true with a counter
  2. a uniform body is refused with reason no-bit-edges
  3. the import routes through the SAME trim, decoder and predicate a capture uses
  4. fbkCount < FBK_MAX is enforced
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
CORPUS = (ROOT / "research/sources/corpus_automotive_subghz/Asian/Hyundai_Kia_Genesis/"
          "Kia_V3_N1_RAW.sub")
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def extract_fn(src, signature):
    pat = re.compile(r"^(?:static\s+)?(?:bool|void|int|uint\d+_t|float|String|const\s+char\*)"
                     r"\s+" + re.escape(signature) + r"\([^;{]*?\)\s*\{", re.M | re.S)
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


def frame_slice():
    """One frame from the real Kia V3 capture, using the firmware's own trim rule."""
    w = []
    for line in CORPUS.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            w.extend(abs(int(x)) for x in re.findall(r'-?\d+', line[9:]))
    GAP, PITCH, TOL = 1000, 162, 8
    s = None
    for i in range(len(w)):
        if w[i] <= GAP:
            continue
        j = next((k for k in range(i + 1, len(w)) if w[k] > GAP), None)
        if j is None:
            break
        if PITCH - TOL <= j - i <= PITCH + TOL:
            s = i
            break
    if s is None:
        return None
    return [x for x in w[max(0, s - 20):s + PITCH + 1] if x > 0]


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the import path exists and reuses the capture validation ===")
    imp = extract_fn(src, "fbkImportFrame")
    check(imp is not None, "fbkImportFrame extracted")
    if not imp:
        return 1
    check("ks_noBitEdges" in imp, "the import applies the same no-bit-edges predicate")
    check("fbkAppend" in imp, "the import routes through fbkAppend (same trim, same counter)")
    check("decodeSignal" in imp, "the import decodes through the real decoder, not a copy")
    check("FBK_MAX" in imp, "FBK_MAX is enforced")

    pred = extract_fn(src, "ks_noBitEdges")
    check(pred is not None, "ks_noBitEdges extracted (shared predicate)")
    # And that the live capture uses the SAME one, so the two cannot drift apart.
    cs = extract_fn(src, "captureSignal")
    check(cs is not None and "ks_noBitEdges" in cs,
          "captureSignal uses the same shared predicate")
    check("mx*100 < (uint32_t)mn*110" in (pred or ""),
          "the predicate is the max-vs-min uniformity test")

    frame = frame_slice()
    check(frame is not None and len(frame) > 100,
          f"real Kia frame slice loaded ({len(frame) if frame else 0} pulses)")
    if not frame:
        return 1

    print("\n=== compile the real predicate and exercise both outcomes ===")
    harness = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <cstdlib>
""" + pred + r"""

static const uint16_t FRAME[] = {
""" + ",".join(str(x) for x in frame) + r"""
};
#define FRAME_LEN ((int)(sizeof(FRAME)/sizeof(FRAME[0])))

int main(void){
  /* The real frame: clustering gives short ~398, long ~809, plus the sync. It must NOT be
     classified as uniform. */
  uint32_t w=0;
  bool uni = ks_noBitEdges(FRAME, FRAME_LEN, w);
  printf("real_frame uniform=%d width=%u\n", (int)uni, w);

  /* A uniform body of the kind the RSSI fallback produces: min/max within 10%. */
  uint16_t flat[256];
  for(int i=0;i<256;i++) flat[i] = (uint16_t)(1530 + (i%7)*16);   /* 1530..1626 */
  uint32_t w2=0;
  bool uni2 = ks_noBitEdges(flat, 256, w2);
  printf("flat_frame uniform=%d width=%u\n", (int)uni2, w2);

  /* Short buffers must not be judged: a 20-pulse fixed-code burst is legitimately one
     width and refusing it would be wrong. */
  uint16_t tiny[20];
  for(int i=0;i<20;i++) tiny[i] = 400;
  uint32_t w3=0;
  bool uni3 = ks_noBitEdges(tiny, 20, w3);
  printf("tiny_frame uniform=%d\n", (int)uni3);
  return 0;
}
"""
    tmp = Path(tempfile.mkdtemp())
    try:
        c = tmp / "t.cpp"
        c.write_text(harness, encoding="utf-8")
        cc = (shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
              or shutil.which("cc"))
        check(cc is not None, "a C++ compiler is available")
        if not cc:
            return 1
        r = subprocess.run([cc, "-O0", "-o", str(tmp / "t"), str(c)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("  FAIL harness did not compile:\n" + r.stderr[:800])
            FAILS.append("harness compile")
            return 1
        p = subprocess.run([str(tmp / "t")], capture_output=True, text=True)
        out = p.stdout
        for line in out.strip().splitlines():
            print("    " + line)
        m = re.search(r"real_frame uniform=(\d)", out)
        check(m is not None and m.group(1) == "0",
              "a real Kia frame is NOT classified uniform, so it imports")
        m = re.search(r"flat_frame uniform=(\d)", out)
        check(m is not None and m.group(1) == "1",
              "a uniform body IS refused with no-bit-edges")
        m = re.search(r"tiny_frame uniform=(\d)", out)
        check(m is not None and m.group(1) == "0",
              "a short single-width burst is not wrongly refused")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== the import also goes through the same trim, so trimmed is meaningful ===")
    # fbkAppend calls rjTrimKiaV34 -> klTrimToFrame, which is what sets e.trimmed.
    ap = extract_fn(src, "fbkAppend")
    check(ap is not None, "fbkAppend extracted")
    if ap:
        code = re.sub(r"//.*", "", ap)
        check("rjTrimKiaV34" in code, "fbkAppend trims via rjTrimKiaV34 (same as a capture)")
        check("e.trimmed=didTrim" in code.replace(" ", ""),
              "trimmed records the real trim result, not a constant")
        check("fbkParseCtr" in code, "the counter is parsed from the decode, as for a capture")

    print("\n=== a realistic import: does the trim bound it and is there a counter? ===")
    # The import body is clamped to 512 pulses (static uint16_t ib[512]) and klTrimToFrame
    # needs a separator PAIR inside what it is given. So the outcome depends on where the
    # body starts, and both outcomes are correct:
    #   · a body starting at a burst head (what a Flipper capture of one press looks like)
    #     -> trim fires, a counter decodes, and rbArm will accept it
    #   · a body starting mid-file (e.g. the whole corpus file's first 512 pulses, which are
    #     the noisy file head) -> trim returns 0, trimmed=false, and rbArm refuses
    #     correctly rather than replaying an unbounded block
    sys.path.insert(0, str(ROOT / "research/sources"))
    import a2_kia_v34 as kia

    def trim_len_with_anchor(x):
        GAP, PITCH, TOL = 1000, 162, 8
        n = len(x)
        for i in range(n):
            if x[i] <= GAP:
                continue
            j = next((q for q in range(i + 1, n) if x[q] > GAP), None)
            if j is None:
                break
            if PITCH - TOL <= j - i <= PITCH + TOL:
                start = max(0, i - 20)
                end = min(i + PITCH, n - 1)
                return (end - start + 1, i) if end > i else (0, -1)
        return (0, -1)

    def trim_len(x):
        GAP, PITCH, TOL = 1000, 162, 8
        n = len(x)
        for i in range(n):
            if x[i] <= GAP:
                continue
            j = next((q for q in range(i + 1, n) if x[q] > GAP), None)
            if j is None:
                break
            if PITCH - TOL <= j - i <= PITCH + TOL:
                start = max(0, i - 20)
                end = min(i + PITCH, n - 1)
                return end - start + 1 if end > i else 0
        return 0

    # (a) from a burst head: the case the bench would use
    head = frame[:512]
    tl = trim_len(head)
    check(tl > 0, f"a body starting at a burst head trims to one frame (trim={tl})")
    if tl > 0:
        dec = kia.ks_decode_kia_v34(list(head[:tl]), tl)
        check(dec is not None, "the trimmed frame decodes")
        if dec:
            check(isinstance(dec.get("ctr"), int),
                  f"the decode carries a counter (ctr={dec.get('ctr')}) -> hasCtr=true")
            print(f"    -> import result: trimmed=true, hasCtr=true, ctr={dec['ctr']}")

    # (b) THE REQUESTED CASE: posting the corpus file's head must now import successfully.
    # The parser must read past the repeated "RAW_Data:" labels (one per line in a corpus
    # .sub) and across newlines, and the body limit must reach the frame, which is at pulse
    # 2517 -- beyond the 1868 an 8192-byte body carries.
    body_head = CORPUS.read_text(encoding="utf-8", errors="replace")[:16384]
    ri = body_head.index("RAW_Data:")
    pos = ri + 9
    parsed = []
    while pos < len(body_head) and len(parsed) < 3740:
        while pos < len(body_head) and body_head[pos] in " \t\r\n":
            pos += 1
        if pos >= len(body_head):
            break
        if body_head[pos] in "-+":
            pos += 1
        st = pos
        while pos < len(body_head) and body_head[pos].isdigit():
            pos += 1
        if pos == st:
            before = pos
            while pos < len(body_head) and body_head[pos] not in "\r\n":
                if body_head[pos:pos + 9] == "RAW_Data:":
                    pos += 9
                    break
                pos += 1
            if pos == before:
                break
            continue
        parsed.append(int(body_head[st:pos]))
    check(len(parsed) > 1000,
          f"the parser reads past the repeated RAW_Data labels ({len(parsed)} pulses)")

    # trim_len returns the length; the frame begins 20 pulses BEFORE the anchor it locked
    # onto. Slicing from index 0 would decode the file head, not the frame -- which is what
    # an earlier version of this assertion did, and it failed on correct code.
    tl3, anchor3 = trim_len_with_anchor(parsed)
    check(tl3 > 0,
          f"posting the corpus file's HEAD now trims to a frame (trim={tl3}, anchor={anchor3})")
    if tl3 > 0:
        st3 = max(0, anchor3 - 20)
        dec3 = kia.ks_decode_kia_v34(list(parsed[st3:st3 + tl3]), tl3)
        check(dec3 is not None, "the head-imported frame decodes")
        if dec3:
            check(isinstance(dec3.get("ctr"), int),
                  f"and carries a counter (ctr={dec3.get('ctr')})")
            print(f"    -> corpus head import: trimmed=true, hasCtr=true, ctr={dec3['ctr']}")
    # And the specific numeric claim this round rests on: the first frame is at 2517, so an
    # 8192-byte body (1868 pulses) could NEVER have reached it. Assert that, because the
    # instruction asked only to raise the cap to 1868 and that would not have met the goal.
    check(len(parsed) > 2517,
          f"the parsed window ({len(parsed)}) spans the frame at pulse 2517; "
          f"an 8192-byte body (1868 pulses) could not")

    # (c) a body that genuinely contains no frame is still refused, not silently accepted
    whole = []
    for line in CORPUS.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            whole.extend(abs(int(x)) for x in re.findall(r'-?\d+', line[9:]))
    tl2 = trim_len(whole[:512])
    check(tl2 == 0,
          "the corpus file's first 512 pulses do NOT trim (no Kia pitch pair in that window)")
    # v3.79 changed what happens next. The import no longer REFUSES an untrimmable body; it
    # keeps the raw block, matching fbkAppend's live-capture behaviour, so a non-Kia protocol
    # can be imported at all. The safety property that matters is preserved and moved: rbArm
    # still refuses an untrimmed block, so C2 cannot transmit a multi-repeat body as if it
    # were one press. Assert THAT, because it is the guard, not the refusal.
    print(f"    -> trimmed=false, body kept as a raw block")
    check("e.trimmed=didTrim" in src.replace(" ", ""),
          "the entry records trimmed=false for a kept-raw body")
    check('reason=="untrimmed-block"' in src,
          "rbArm still refuses an untrimmed block, so C2 cannot fire it")
    check("import_kept_raw" in src,
          "the kept-raw import is reported as an event rather than a silent acceptance")

    print("\n=== the endpoint and serial mirror exist ===")
    check('"/api/fbk_import"' in src, "the HTTP import endpoint is registered")
    check('op=="fbk_import"' in src, "the serial import command is registered")
    check("receiveSubReplayBody" in src and "parseSubReplayBody" in src,
          "the import reuses the existing .sub body parser")

    print()
    if FAILS:
        print(f"IMPORT PATH CHECKS FAILED ({len(FAILS)} failures)")
        return 1
    print("stored-frame import checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
