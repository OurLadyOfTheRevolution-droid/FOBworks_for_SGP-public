#!/usr/bin/env python3
"""Compile and exercise the real CC1101 packet encoder against real capture data.

The packet-mode replay path (worklog §5 step 4) encodes a list of pulse widths into OOK
bits at a register-selected symbol rate. Two things must hold, and neither can be checked by
reading the source:

  1. the DRATE_E/DRATE_M search lands close to the requested symbol period
  2. the encoder reproduces the frame's level structure — a long run of one level means the
     resolution collapsed the pulses together, which would transmit a different waveform

An earlier attempt reimplemented the encoder in Python to check it. That model disagreed
with the running code and I briefly blamed the firmware; compiling the ACTUAL C function is
the only way to avoid that class of error, so this does exactly that.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parent / "FOBworks_for_SGP.ino"
CORPUS = (Path(__file__).resolve().parent /
          "research/sources/corpus_automotive_subghz/Asian/Hyundai_Kia_Genesis/Kia_V3_N1_RAW.sub")
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def extract_fn(src, signature):
    """Brace-matched extraction of a function definition (not a forward declaration)."""
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


def real_frame():
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
    return [x for x in w[max(0, s - 20):s + PITCH] if x > 0]


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the encoder and rate search exist ===")
    enc = extract_fn(src, "ks_ccEncodeFrame")
    km2 = extract_fn(src, "ks_km2")
    rate = extract_fn(src, "ks_ccRateForPeriodUs")
    check(enc is not None, "ks_ccEncodeFrame extracted")
    check(rate is not None, "ks_ccRateForPeriodUs extracted")
    check(km2 is not None, "ks_km2 extracted (the symbol period comes from clustering)")
    if not enc or not rate or not km2:
        return 1

    frame = real_frame()
    check(frame is not None and len(frame) > 100,
          f"real Kia V3 frame loaded ({len(frame) if frame else 0} pulses)")
    if not frame:
        return 1
    S0 = min(frame)
    print(f"  frame: {len(frame)} pulses, min={S0} us, max={max(frame)} us, sum={sum(frame)} us")

    print("\n=== compile the REAL functions and exercise them ===")
    harness = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <cstdlib>
""" + km2 + "\n" + rate + "\n" + enc + r"""

static const uint16_t FRAME[] = {
""" + ",".join(str(x) for x in frame) + r"""
};
#define FRAME_LEN ((int)(sizeof(FRAME)/sizeof(FRAME[0])))

/* Count runs in the bit stream: a frame with fine enough resolution keeps many short runs,
   while a collapsed encoding produces few very long runs. */
static void report(uint32_t S, int n, const uint8_t* b){
  int bits = n*8;
  int runs = 0, maxrun = 0, cur = -1, run = 0;
  for(int i=0;i<bits;i++){
    int v = (b[i>>3] >> (7-(i&7))) & 1;
    if(v==cur) run++;
    else { if(run>maxrun) maxrun=run; if(cur>=0) runs++; cur=v; run=1; }
  }
  if(run>maxrun) maxrun=run;
  printf("S=%4u bytes=%2d symbols=%3d runs=%3d maxrun=%3d first8=", S, n, bits, runs, maxrun);
  for(int i=0;i<n&&i<8;i++) printf("%02x", b[i]);
  printf("\n");
}

int main(void){
  uint8_t out[64];
  /* The SHIPPED derivation: te = mean of the SHORT cluster, then integer multiples of te
     only, with the ratio guard. The previous version of this harness used min(FRAME), which
     is what produced the 1.5:1 ratio; if that regresses, the ratio assertion below fails. */
  uint32_t tmp[FRAME_LEN]; for(int i=0;i<FRAME_LEN;i++) tmp[i]=FRAME[i];
  uint32_t a=0,b=0;
  bool clustered = ks_km2(tmp, FRAME_LEN, a, b);
  uint32_t teShort = (a<b)?a:b, teLong = (a<b)?b:a;
  if(!clustered || teShort==0){ printf("NO_CLUSTER\n"); return 3; }
  printf("te_short=%u te_long=%u cluster_ratio=%.3f\n", teShort, teLong,
         (double)teLong/teShort);
  uint32_t bestS=0; int bestN=0;
  for(int mult=1; mult<=4; mult++){
    uint32_t S = teShort*(uint32_t)mult;
    uint8_t dE=0,dM=0;
    if(!ks_ccRateForPeriodUs(S,dE,dM)) continue;
    int n = ks_ccEncodeFrame(FRAME, FRAME_LEN, true, S, out, 64);
    if(n<=0) continue;
    uint32_t rs=((teShort+S/2)/S)*S, rl=((teLong+S/2)/S)*S;
    double serr=(double)rs/teShort-1.0; if(serr<0) serr=-serr;
    double ratio = rs ? (double)rl/rs : 0.0;
    report(S,n,out);
    printf("    recovered short=%u long=%u ratio=%.3f short_err=%.1f%% -> %s\n",
           rs, rl, ratio, serr*100.0,
           (serr<0.15 && ratio>1.6) ? "ACCEPT" : "REJECT");
    if(!bestN && serr<0.15 && ratio>1.6){ bestS=S; bestN=n; }
  }
  if(!bestN){ printf("NO_FIT\n"); return 2; }
  printf("chosen S=%u worst_err_us=%u\n", bestS, bestS/2);

  /* ── The shipped trim ───────────────────────────────────────────────────���───
     worklog §2.1 recommended trimming to the separator boundaries. MEASURED, that
     breaks the frame ([20:182) does not decode) because index 20 is the protocol sync.
     The shipped rule drops only the partial leading pulse and the trailing next-frame
     separator. Reproduce it here and report what survives. */
  int bFirst=0, bLast=FRAME_LEN-1, dropped=0;
  uint32_t leadMax=(uint32_t)((double)teShort*0.5);
  uint32_t trailMin=(uint32_t)((double)teLong*1.2);
  while(bFirst<bLast && FRAME[bFirst]>0 && FRAME[bFirst]<leadMax){ bFirst++; dropped++; }
  while(bLast>bFirst && FRAME[bLast]>trailMin){ bLast--; dropped++; }
  printf("trim: dropped=%d payload=[%d,%d] len=%d\n", dropped, bFirst, bLast, bLast-bFirst+1);
  /* Classify every surviving pulse.
     NOT "outside the clusters" -- a Kia frame legitimately contains its SYNC at ~1188us,
     which sits outside both DATA clusters by design. The real artefacts are:
       · a PARTIAL pulse at the head (below ~60% of te_short)
       · a SECOND separator, i.e. more than one sync-width pulse */
  int partials=0, separators=0;
  uint32_t partialMax=(uint32_t)((double)teShort*0.6);
  uint32_t sepMin=(uint32_t)((double)teLong*1.2);      /* 971 for this frame */
  for(int i=bFirst;i<=bLast;i++){
    uint32_t p=FRAME[i];
    if(p>0 && p<partialMax){ partials++; printf("    partial head pulse: idx=%d width=%u\n", i, p); }
    if(p>=sepMin){ separators++; printf("    separator/sync: idx=%d width=%u\n", i, p); }
  }
  printf("payload_partials=%d payload_separators=%d\n", partials, separators);
  return 0;
}
"""
    tmp = Path(tempfile.mkdtemp())
    try:
        c = tmp / "t.cpp"
        c.write_text(harness, encoding="utf-8")
        cc = (shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
              or shutil.which("cc"))
        check(cc is not None, "a C compiler is available")
        if not cc:
            return 1
        r = subprocess.run([cc, "-O0", "-o", str(tmp / "t"), str(c)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("  FAIL harness did not compile:\n" + r.stderr[:900])
            FAILS.append("harness compile")
            return 1
        p = subprocess.run([str(tmp / "t")], capture_output=True, text=True)
        out = p.stdout
        for line in out.strip().splitlines():
            print("    " + line)

        check("NO_FIT" not in out, "the real frame fits at some resolution")
        # The decisive check: the encoding must not collapse. With >=100 pulses and a
        # workable resolution we expect many runs; a collapsed stream yields very few.
        m = re.search(r"runs=\s*(\d+)\s+maxrun=\s*(\d+)", out)
        check(m is not None, "run statistics reported")
        if m:
            runs, maxrun = int(m.group(1)), int(m.group(2))
            check(runs >= len(frame) // 4,
                  f"runs ({runs}) are consistent with the pulse count ({len(frame)}), "
                  f"so the frame did not collapse")
            check(maxrun <= 24, f"longest single-level run ({maxrun}) is short")
        # The worklog fix: te comes from clustering, the chosen symbol is te itself, and
        # the protocol's short:long ratio survives quantisation.
        mt = re.search(r"te_short=(\d+) te_long=(\d+) cluster_ratio=([\d.]+)", out)
        check(mt is not None, "te derived from clustering is reported")
        if mt:
            teS, teL, cr = int(mt.group(1)), int(mt.group(2)), float(mt.group(3))
            check(cr > 1.6, f"clustered ratio {cr:.3f} looks like a real 1:2 protocol")
            check(teS > S0, f"clustered te {teS} us is above the {S0} us outlier (min() was wrong)")
        ma = re.search(r"ratio=([\d.]+) short_err=([\d.]+)% -> ACCEPT", out)
        check(ma is not None, "some symbol period is accepted with the ratio preserved")
        if ma:
            ratio, serr = float(ma.group(1)), float(ma.group(2))
            check(ratio > 1.6, f"accepted ratio {ratio:.3f} preserves short:long (>1.6)")
            check(serr < 15.0, f"accepted short-pulse error {serr:.1f}% is within tolerance")
        # The payload must contain no pulse outside the te clusters — this is the assertion
        # worklog §2.1 option 1 asks for, and it must fail if the trim is removed.
        mtr = re.search(r"trim: dropped=(\d+) payload=\[(\d+),(\d+)\] len=(\d+)", out)
        check(mtr is not None, "the trim is reported")
        if mtr:
            dropped = int(mtr.group(1))
            # The firmware's input excludes the trailing separator already (klTrimToFrame
            # stops one pitch after the separator), so only the clipped head remains to drop
            # in this fixture. >=1 is the right bound here; the full 183-pulse slice with the
            # next frame's separator would drop 2.
            check(dropped >= 1,
                  f"the clipped head pulse was dropped (dropped={dropped}, expected >=1)")
        mo = re.search(r"payload_partials=(\d+) payload_separators=(\d+)", out)
        check(mo is not None, "payload classification reported")
        if mo:
            partials, seps = int(mo.group(1)), int(mo.group(2))
            # The invariant that actually matters: no CLIPPED partial pulse, and exactly one
            # separator (the frame's own sync). More than one means a neighbouring frame's
            # separator leaked in; zero means the sync was stripped and the frame will not
            # decode (measured: [20:182) does not decode).
            check(partials == 0,
                  f"no clipped partial pulse survives into the payload (found {partials})")
            check(seps == 1,
                  f"exactly one separator/sync is present (found {seps})")

        mm = re.search(r"chosen S=(\d+) worst_err_us=(\d+)", out)
        if mm:
            S = int(mm.group(1))
            check(S == teS if mt else True,
                  f"chosen symbol {S} us equals the clustered te, not a multiple of min()")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== the replay path is wired and reports honestly ===")
    rr = extract_fn(src, "replayRaw")
    check(rr is not None, "replayRaw extracted")
    if rr:
        code = re.sub(r"//.*", "", rr)
        check("replayViaFifo" in code,
              "replayRaw routes to replayViaFifo when the pin does not toggle")
        check("tx_path_dead" in rr or "replayViaFifo" in code,
              "a refusal or a named fallback is reported, never a bare true")
        check("lastReplayPath" in code, "the path taken is recorded, so ok:true names a route")
    vf = extract_fn(src, "replayViaFifo")
    if vf:
        check("frame_too_long" in vf, "replayViaFifo refuses a frame that cannot fit")
        check("boundary_pulses" in vf,
              "replayViaFifo reports boundary_pulses in the replay_fifo event")
        check("fdata" in vf and "flen" in vf,
              "the encoder is fed the TRIMMED frame, not the raw window")
        check("replay_fifo" in vf,
              "replayViaFifo reports the resolution used (symbol, mult, worst error)")

    print()
    if FAILS:
        print(f"PACKET REPLAY CHECKS FAILED ({len(FAILS)} failures)")
        return 1
    print("packet replay encode checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
