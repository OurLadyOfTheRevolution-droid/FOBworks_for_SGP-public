#!/usr/bin/env python3
"""F5 — validate frame trimming against a real capture.

A capture is not one code. `captureSignal` fills CAP_SZ=512 pulses, and a fob press
emits its frame repeatedly, so one stored block holds several repeats of the SAME
code. C1 (RollJam) and C2 (RollBack) both assume "one block = one code", so the block
must be trimmed to a single frame before storing.

This runs the SHIPPED `klTrimToFrame()` / `rjTrimKiaV34()` over a real RF capture
(KIA V3 N1 RAW.sub, 67,977 pulses), and decodes the trimmed output with the SHIPPED
Kia decoder, both extracted verbatim. That matters: the previous version of this test
printed only a trim length and then decoded a raw slice in Python, which is not what
the helper produced — an offset mismatch that made the result meaningless.

Asserts the property both features need:
  · trimming yields ONE frame, not CAP_SZ and not several repeats
  · the trimmed frame DECODES (a trim that cuts mid-frame would not)
  · the trim is stable in length
  · counters advance across the file, so the frames are successive presses

Run: python3 test_frame_trim.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKETCH = HERE / "FOBworks_for_SGP.ino"
CAPTURE = HERE / "research" / "sources" / "captures" / "kia" / "KIA V3 N1 RAW.sub"

src = SKETCH.read_text(encoding="utf-8")


def block(marker: str) -> str:
    """Definition starting at `marker`, brace-matched, keeping a trailing ';'.

    Skips forward declarations (marker lines ending in ';' before the '{'),
    which sit above the definitions since the N10 consensus work.
    """
    pos = 0
    while True:
        i = src.index(marker, pos)
        i = src.rindex("\n", 0, i) + 1
        j = src.index("{", i)
        semi = src.find(";", i, j)
        if semi < 0:
            break
        pos = semi + 1
    depth, k = 0, j
    while k < len(src):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    end = k + 1
    if end < len(src) and src[end] == ";":
        end += 1
    return src[i:end] + "\n"


def line(marker: str) -> str:
    i = src.index(marker)
    return src[i : src.index("\n", i) + 1]


# ── Static assertions ───────────────────────────────────────────────────────
for sym, why in [
    ("static int klTrimToFrame(", "trim helper missing"),
    ("static int rjTrimKiaV34(", "Kia trim wrapper missing"),
    ("#define KIA_V34_FRAME_GAP_US", "frame separator constant missing"),
    ("#define KIA_V34_FRAME_PITCH_PULS", "frame pitch constant missing"),
]:
    assert sym in src, why

# ── Harness: trim helper + the Kia decoder it feeds, both shipped ───────────
PARTS = [
    "// Extracted by test_frame_trim.py - functions extracted verbatim from\n"
    "// FOBworks_for_SGP.ino. Trim and decode both run the shipped code so the test\n"
    "// measures the same path the firmware uses.\n"
    "#include <stdio.h>\n"
    "#include <stdint.h>\n"
    "#include <stdbool.h>\n"
    "#include <string.h>\n"
    "#include <stdlib.h>\n"
    "#define CAP_SZ 512\n"
    "#define KL_NLF 0x3A5C742EUL\n",
    block("struct KiaV34Frame {"),
    # constants
]
for c in ("KIA_V34_MF_KEY", "KIA_V34_TE_SHORT", "KIA_V34_TE_LONG", "KIA_V34_TE_DELTA",
          "KIA_V34_MIN_BITS", "KIA_V34_FRAME_GAP_US", "KIA_V34_FRAME_PITCH_PULS",
          "KIA_V34_FRAME_PITCH_TOL"):
    PARTS.append(line(f"#define {c}"))
# The published branch stores KIA_V34_MF_KEY masked and unwraps it at each use, so its cipher
# calls read ks_unmaskMfrKey(KIA_V34_MF_KEY). Include the helper when the sketch defines it,
# so this harness compiles against both branches without a per-branch copy. The mask constants
# it references are emitted with it.
if "static inline uint64_t ks_unmaskMfrKey(" in src:
    for c in ("MFR_KEY_A", "MFR_KEY_B", "MFR_KEY_N"):
        PARTS.append(line(f"#define {c}"))
    PARTS.append(block("static inline uint64_t ks_unmaskMfrKey("))
# cipher, then decoder, then trim
for fn in ("static inline uint32_t ks_nlf(", "static inline uint32_t ks_bit(",
           "static uint32_t ks_klEncrypt(", "static uint32_t ks_klDecrypt(",
           "static inline uint8_t ks_kiaV34Rev8(", "static inline bool ks_kiaV34Match(",
           "static void ks_kiaV34Extract(", "static bool ks_kiaV34Validate(",
           "static inline bool ks_kiaV34IsPulse(", "static bool ks_kiaV34IsSync(",
           "static uint16_t ks_kiaV34PwmAt(", "static uint16_t ks_kiaV34Pwm(",
           "static void ks_kiaV34BitsToBytes(", "static bool ks_decodeKiaV34(",
           "static int klTrimToFrame(", "static int rjTrimKiaV34("):
    PARTS.append(block(fn))

PARTS.append(r'''
// Decode a trimmed frame with the shipped decoder. Returns the counter, or -1.
static long decodeCtr(const uint16_t* w,int len){
  // ks_decodeKiaV34 takes uint32_t* (the sketch's capture buffer is uint32_t).
  static uint32_t tmp[512];
  if(len>512) len=512;
  for(int i=0;i<len;i++) tmp[i]=w[i];
  KiaV34Frame o;
  if(!ks_decodeKiaV34(tmp,len,o)) return -1;
  return (long)o.ctr;
}

static int loadRaw(const char* path,uint16_t* out,int cap){
  FILE* f=fopen(path,"r"); if(!f) return -1;
  static char line[1<<20]; int n=0;
  while(fgets(line,sizeof line,f)){
    if(strncmp(line,"RAW_Data:",9)) continue;
    char* p=line+9;
    while(*p && n<cap){
      while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
      if(!*p) break;
      char* e; long v=strtol(p,&e,10); if(e==p) break; p=e;
      out[n++]=(uint16_t)(v<0?-v:v);
    }
  }
  fclose(f); return n;
}

int main(int argc,char** argv){
  if(argc<2){ printf("usage: %s capture.sub\n",argv[0]); return 2; }
  static uint16_t cap[200000];
  int n=loadRaw(argv[1],cap,200000);
  if(n<200){ printf("FAIL: load returned %d\n",n); return 1; }
  printf("loaded %d pulses\n",n);

  // Decode the untrimmed head as a baseline: it works today, because the decoder
  // scans inside the block. The problem is not that decoding fails, it is that the
  // block is several codes and a replay sends all of them.
  static uint16_t frame[512];
  int headLen=(n>512)?512:n;
  long headCtr=decodeCtr(cap,headLen);
  printf("untrimmed head (%d pulses) decodes ctr=%ld\n",headLen,headCtr);

  // Walk the file, trimming at each step and decoding the TRIMMED output.
  int emitted=0, decoded=0, off=0, firstTrim=0;
  while(off < n-200 && emitted<=400){
    int avail=(n-off>512)?512:(n-off);
    static uint16_t blk[512];
    for(int i=0;i<avail;i++) blk[i]=cap[off+i];
    int tl=rjTrimKiaV34(blk,avail,frame,512,nullptr);   // 5th arg: anchor out (unused here)
    if(tl<=0){ off+=64; continue; }
    long ctr=decodeCtr(frame,tl);
    if(ctr>=0) decoded++;
    if(!firstTrim) firstTrim=tl;
    printf("FRAME off=%d trimlen=%d ctr=%ld\n",off,tl,ctr);
    emitted++;
    // Advance to just past the trimmed frame. Stepping a fixed 162 drifts out of
    // phase with the real train and then re-anchors mid-frame, which is a harness
    // artefact rather than a trim failure. Re-anchoring from the end of the slice
    // keeps the walk aligned.
    off += (tl>20)?(tl-20):64;
  }
  printf("EMITTED %d %d\n",emitted,decoded);
  return 0;
}
''')

HARNESS = "".join(PARTS)


def main() -> int:
    if not CAPTURE.is_file():
        print(f"note: {CAPTURE} not present; cannot run F5", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        cpp = wd / "trim.cpp"
        cpp.write_text(HARNESS, encoding="utf-8")
        exe = wd / "trim"
        cc = shutil.which("c++") or shutil.which("clang++") or "c++"
        r = subprocess.run([cc, "-O1", "-std=c++17", "-w", str(cpp), "-o", str(exe)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("harness compile failed:\n" + r.stderr[:3000], file=sys.stderr)
            return 2
        out = subprocess.run([str(exe), str(CAPTURE)], capture_output=True, text=True)
        if out.returncode != 0:
            print(out.stdout)
            print(out.stderr, file=sys.stderr)
            return 1

    frames = re.findall(r"^FRAME off=(\d+) trimlen=(\d+) ctr=(-?\d+)$", out.stdout, re.M)
    emitted = decoded = 0
    m = re.search(r"^EMITTED (\d+) (\d+)$", out.stdout, re.M)
    if m:
        emitted, decoded = int(m.group(1)), int(m.group(2))

    lens = Counter(int(t) for _, t, _ in frames)
    ctrs = [int(c) for _, _, c in frames if int(c) >= 0]

    print(out.stdout.strip().splitlines()[0])
    print(f"trimmed frames emitted : {emitted}")
    print(f"trimmed frames decoding: {decoded}")
    print(f"trim length distribution: {lens.most_common(6)}")
    print(f"counters seen: {sorted(set(ctrs))[:12]}")

    fails = 0

    # The trim must be meaningfully shorter than the capture window, or it has not
    # isolated anything.
    if not lens:
        print("FAIL: no frames emitted")
        return 1
    dom = lens.most_common(1)[0][0]
    if dom >= 512:
        print(f"FAIL: dominant trim length {dom} is the whole block, not one frame")
        fails += 1
    if not (60 <= dom <= 260):
        print(f"FAIL: dominant trim length {dom} is not one frame")
        fails += 1

    # The great majority of trimmed frames must decode. Not all: this walk re-anchors
    # blindly every slice, so it drifts out of phase at burst boundaries and at a few
    # noise-contaminated separators, where it locks 27 pulses late and the slice starts
    # mid-frame. Those are properties of blind re-anchoring, not of the trim — the
    # firmware trims ONCE per capture, from a known-good burst head.
    #
    # A threshold is used rather than "all", and the observed rate is recorded, so the
    # test states what was measured instead of implying perfection.
    if emitted == 0:
        print("FAIL: no frames emitted")
        fails += 1
    else:
        rate = decoded / emitted
        print(f"decode rate: {decoded}/{emitted} = {rate:.1%}")
        if rate < 0.85:
            print(f"FAIL: decode rate {rate:.1%} below 85%")
            fails += 1

    # Stability, measured as the size of the dominant cluster rather than the count of
    # distinct lengths. The phase drift above produces a handful of singletons, but a
    # correct boundary puts the vast majority on one or two values; a wrong boundary
    # spreads them evenly. Observed: 111 at 183 and 45 at 182.
    top2 = sum(c for _, c in lens.most_common(2))
    if emitted and top2 / emitted < 0.9:
        print(f"FAIL: trim length not stable — top 2 values cover only "
              f"{top2}/{emitted}")
        fails += 1
    else:
        print(f"dominant lengths: {lens.most_common(2)} = "
              f"{top2}/{emitted} of frames")

    # The property C1/C2 rely on: successive frames carry successive counters.
    if len(set(ctrs)) < 2:
        print(f"FAIL: counters do not advance (saw {sorted(set(ctrs))})")
        fails += 1

    print()
    if fails:
        print(f"FAIL ({fails} failures)")
        return 1
    print("F5: frame trimming validated against a real capture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
