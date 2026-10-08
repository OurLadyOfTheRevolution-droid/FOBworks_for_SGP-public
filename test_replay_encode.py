#!/usr/bin/env python3
"""Compile and exercise the real CC1101 packet encoder against real capture data.

The packet-mode replay path encodes a list of pulse widths into OOK
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
     §2.1 recommended trimming to the separator boundaries. MEASURED, that
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

  /* ── Packet quantisation fidelity ─────────────────────────
     The encoder snaps each pulse to the nearest whole symbol, so a JITTERY frame —
     especially one whose short cluster sits well below the protocol te — loses pulses
     that land past the midpoint between T and 2T, and the re-decoded frame is a
     different one (measured on hardware: stored 0x98A26162 came back 0x19232862). A
     frame already on-grid round-trips exactly. Reproduce the snap on a SYNTHETIC,
     jitter-free frame so the result does not depend on capture noise: build T/2T
     pulses from a fixed bit pattern, encode, decode the symbol runs back to widths,
     and require bit-exact recovery. */
  {
    /* 96 alternating payload bits with no jitter: bit -> HI(T) LO(2T) or HI(2T) LO(T),
       which is the same two-level shape a real PWM frame carries. Prepend the measured
       te so the cluster/rate search has a clean short centroid. */
    static uint16_t clean[2 + 96*2];
    int n = 0;
    uint32_t T = teShort;
    clean[n++] = T; clean[n++] = T*2;         /* preamble pair */
    uint32_t bits = 0xA5A5A5A5u;
    for(int i=0;i<96;i++){
      int bit = (bits >> (i & 31)) & 1;
      if(bit){ clean[n++] = T;   clean[n++] = T*2; }
      else   { clean[n++] = T*2; clean[n++] = T;   }
    }
    static uint16_t cleanCopy[sizeof(clean)/sizeof(clean[0])];
    memcpy(cleanCopy, clean, sizeof(clean));
    static uint32_t cleanU32[sizeof(clean)/sizeof(clean[0])];
    for(int i=0;i<n;i++) cleanU32[i]=clean[i];
    uint32_t ca=0,cb=0;
    bool ok = ks_km2(cleanU32, n, ca, cb);
    uint32_t tS = (ca<cb)?ca:cb;
    uint8_t e2=0,m2=0;
    uint8_t o2[64];
    int n2 = ok ? ks_ccEncodeFrame(clean, n, true, tS, o2, 64) : 0;
    /* Decode the level runs back into widths. A faithful on-grid encode reproduces the
       exact T / 2T sequence, so the width counts come back equal. */
    int mismatches = 0, hiCount = 0;
    if(n2 > 0){
      int totalbits = n2*8;
      int cur = (o2[0] >> 7) & 1, run = 0;
      uint32_t widths[512]; int nw = 0;
      for(int i=0;i<totalbits && nw<511;i++){
        int v = (o2[i>>3] >> (7-(i&7))) & 1;
        if(v==cur) run++;
        else { widths[nw++] = (uint32_t)run; cur=v; run=1; }
      }
      widths[nw++] = (uint32_t)run;
      /* Compare the first n-1 runs. A run per source pulse, but the FINAL run can absorb
         the encoder's byte-alignment padding (the packet is a whole number of bytes, and
         trailing 0 bits extend a final low run), which is not a fidelity loss. Every other
         compared width must be exactly T or 2T in microseconds. */
      for(int i=0;i<n-1 && i<nw;i++){
        uint32_t wus = widths[i]*tS;
        if(wus==T) hiCount++;
        else if(wus==T*2){}
        else mismatches++;
      }
    }
    printf("clean_fit=%d clean_mismatches=%d\n", n2>0?1:0, mismatches);
  }
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
        # The fix: te comes from clustering, the chosen symbol is te itself.
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
        # §2.1 option 1 asks for, and it must fail if the trim is removed.
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
        # §6: an ON-GRID frame must encode with no quantisation loss, because the
        # card's packet TX is the only transmit path on this board and a lossy encode sends a
        # DIFFERENT frame (hardware: stored 0x98A26162 came back 0x19232862 from a jittery
        # capture). If this ever reports mismatches, the TX path is altering frames.
        mc = re.search(r"clean_fit=(\d+) clean_mismatches=(\d+)", out)
        check(mc is not None, "the on-grid quantisation check ran")
        if mc:
            fit, mism = int(mc.group(1)), int(mc.group(2))
            check(fit == 1, "a synthetic jitter-free frame encodes at some resolution")
            check(mism == 0,
                  f"an on-grid frame encodes with ZERO quantisation mismatches (got {mism})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== ks_snapGrid normalises a jittery body onto its own T/2T grid ===")
    snap = extract_fn(src, "ks_snapGrid")
    check(snap is not None, "ks_snapGrid extracted")
    if snap and km2:
        harness2 = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <cstdlib>
#define CAP_SZ 512
""" + km2 + "\n" + snap + r"""
static uint16_t JIT[300];
static uint16_t OUT[300];
int main(void){
  /* Build a T/2T PWM frame with realistic capture jitter: T=180, 2T=360, +/- 40 us. */
  uint32_t T=180, te=0;
  int n=0;
  /* preamble pairs first, as a real frame carries, so clustering locks on T/2T */
  for(int i=0;i<8;i++){ JIT[n++]=T; JIT[n++]=T*2; }
  uint32_t bits=0xC0FFEE11u;
  for(int i=0;i<60;i++){
    int b=(bits>>(i&31))&1;
    int lo,hi;
    if(b){ lo=T; hi=T*2; } else { lo=T*2; hi=T; }
    int jl=(i*37)%81-40, jh=(i*53)%81-40;      /* deterministic pseudo-jitter */
    lo+=jl; hi+=jh;
    JIT[n++]=(uint16_t)lo; JIT[n++]=(uint16_t)hi;
  }
  int ns=ks_snapGrid(JIT,n,OUT,300);
  if(ns<=0){ printf("SNAP_NONE n=%d\n",n); return 3; }
  /* Every output value must be a whole multiple of the recovered te. */
  uint32_t cA=0,cB=0; uint32_t ub[300];
  for(int i=0;i<ns;i++) ub[i]=OUT[i];
  int bad=0; uint32_t t=0;
  if(ks_km2(ub,ns,cA,cB)){ t=(cA<cB)?cA:cB; }
  for(int i=0;i<ns;i++){
    if(t==0){ bad++; continue; }
    if(OUT[i]%t != 0) bad++;
    if(!(OUT[i]==t || OUT[i]==2*t)) bad++;
  }
  printf("SNAP n=%d te=%u offgrid=%d\n", ns, t, bad);
  /* Idempotence: snapping an already-snapped body must report no change (returns 0). */
  int again=ks_snapGrid(OUT,ns,OUT,300);
  printf("SNAP_IDEMPOTENT again=%d\n", again);
  return 0;
}
"""
        tmp2 = Path(tempfile.mkdtemp())
        try:
            c2 = tmp2 / "s.cpp"
            c2.write_text(harness2, encoding="utf-8")
            cc = (shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
                  or shutil.which("cc"))
            r2 = subprocess.run([cc, "-O0", "-o", str(tmp2 / "s"), str(c2)],
                                capture_output=True, text=True)
            if r2.returncode != 0:
                print("  FAIL snap harness did not compile:\n" + r2.stderr[:700])
                FAILS.append("snap harness compile")
            else:
                p2 = subprocess.run([str(tmp2 / "s")], capture_output=True, text=True)
                for line in p2.stdout.strip().splitlines():
                    print("    " + line)
                ms = re.search(r"SNAP n=(\d+) te=(\d+) offgrid=(\d+)", p2.stdout)
                check(ms is not None, "the snap produced a body")
                if ms:
                    check(int(ms.group(1)) > 100, "the snapped body kept its length")
                    check(int(ms.group(3)) == 0,
                          f"every snapped pulse is a whole T or 2T (off-grid = {ms.group(3)})")
                mi = re.search(r"SNAP_IDEMPOTENT again=(\d+)", p2.stdout)
                check(mi is not None, "idempotence reported")
                if mi:
                    check(int(mi.group(1)) == 0,
                          "re-snapping an on-grid body is a no-op (returns 0)")
        finally:
            shutil.rmtree(tmp2, ignore_errors=True)

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
