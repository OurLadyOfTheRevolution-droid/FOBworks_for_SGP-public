#!/usr/bin/env python3
"""Diagnose one .sub capture: gate values, pulse resolution, and Toyota candidates.

Written because the corpus is the only input this project has had, and its scaling is
unreliable. A capture taken on real hardware -- the Flipper's CC1101, whose
GDO0 is actually routed, unlike the SGP board's -- is the first input with trustworthy
pulse resolution, so having the diagnostic ready matters more than the analysis script
being pretty.

Reports, in order:
  1. header          -- frequency, preset, pulse count
  2. pulse widths    -- the most common values, which expose the capture's quantisation
  3. k-means         -- cA / cB / ratio / km, exactly as decodeSignal computes them
  4. gates           -- which te_* gate would pass at this frequency
  5. Toyota          -- preamble candidates and every frame ks_decodeToyota would accept

Usage:
    python3 tools/sub_probe.py capture.sub [more.sub ...]
    python3 tools/sub_probe.py --json out.json capture.sub
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKETCH = ROOT / "FOBworks_for_SGP.ino"


def extract_fn(src: str, name: str):
    """Brace-matched function extraction, same approach as corpus_regression."""
    pat = re.compile(
        r"^(?:static\s+)?(?:inline\s+)?[\w\s\*]*\b" + re.escape(name) +
        r"\s*\([^;{]*?\)\s*\{", re.M | re.S)
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


def parse_sub(path: Path):
    """Pulse widths (unsigned) and the frequency in MHz."""
    widths, mhz = [], 433.92
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Frequency:"):
            try:
                hz = int(line.split(":", 1)[1].strip())
                if hz > 100_000_000:
                    mhz = hz / 1e6
            except ValueError:
                pass
        if line.startswith("RAW_Data:"):
            widths.extend(abs(int(x)) for x in re.findall(r"-?\d+", line[9:]))
    return widths, mhz


def header_of(path: Path):
    """The .sub header fields, so the preset the capture used is visible."""
    out = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:12]:
        if ":" in line and not line.startswith("RAW_Data"):
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
        if line.startswith("RAW_Data"):
            break
    return out


PROBE = r'''
/* Mirrors decodeSignal's preprocessing, then the Toyota candidate scan verbatim. */
static uint16_t RAWIN[1<<20];
static uint16_t TRIMMED[CAP_SZ];

static void report(int argc,char** argv){
  /* single capture mode: argv[1] = pulse file */
  FILE* f=fopen(argv[1],"r"); if(!f){ printf("LOADFAIL\n"); return; }
  double mhz=0; if(fscanf(f,"%lf",&mhz)!=1){ fclose(f); printf("LOADFAIL\n"); return; }
  int rn=0; while(rn<(int)(sizeof(RAWIN)/sizeof(RAWIN[0]))){
    unsigned long v; if(fscanf(f,"%lu",&v)!=1) break; RAWIN[rn++]=(uint16_t)v;
  }
  fclose(f);
  if(rn<32){ printf("LOADFAIL\n"); return; }
  if(rn<(int)sizeof(RAWIN)/2){ RAWIN[rn]=0; }

  /* Trim to one frame first, exactly as captureSignal and fbkImportFrame do. A .sub from
     a multi-press recording holds several repeats, and the gates (computed from the
     cluster spread) describe the wrong data without this. If the trim finds nothing, keep
     the raw block, which is the firmware's own bias: a wrong trim is worse than a long one. */
  int tn = doTrim(RAWIN, rn, TRIMMED, CAP_SZ);
  const uint16_t* SRC = (tn>0) ? TRIMMED : RAWIN;
  int sn_ = (tn>0) ? tn : rn;
  printf("T trim=%d n=%d of raw=%d\n", tn, sn_, rn);

  /* histogram of pulse widths, to expose the capture's quantisation */
  printf("H");
  { static uint32_t seen[4096]; int ns=0;
    for(int i=0;i<sn_ && ns<4096;i++){
      int dup=0; for(int j=0;j<ns;j++) if(seen[j]==SRC[i]){dup=1;break;}
      if(!dup) seen[ns++]=SRC[i];
    }
    for(int i=0;i<ns;i++) for(int j=i+1;j<ns;j++) if(seen[j]<seen[i]){uint32_t t=seen[i];seen[i]=seen[j];seen[j]=t;}
    int printed=0;
    for(int i=0;i<ns && printed<14;i++){
      int c=0; for(int k=0;k<sn_;k++) if(SRC[k]==seen[i]) c++;
      if(c>=2){ printf(" %u:%d",seen[i],c); printed++; }
    }
  }
  printf("\n");

  /* k-means on the clipped copy, as decodeSignal does */
  static uint32_t B[CAP_SZ], K[CAP_SZ];
  int n=(sn_>CAP_SZ)?CAP_SZ:sn_;
  for(int i=0;i<n;i++) B[i]=SRC[i];
  int kn=0; for(int i=0;i<n;i++) if(B[i]<=5000) K[kn++]=B[i];
  uint32_t cA=0,cB=0;
  bool km=ks_km2(kn>=6?K:B, kn>=6?kn:n, cA, cB);
  uint32_t thr=(cA+cB)/2;
  static char bits[CAP_SZ*4+16], mb[CAP_SZ/2+1];
  int bLen=ks_mkBits(B,n,bits,thr);
  int ml=ks_manchester(bits,bLen,mb);
  float ratio=(cA>0)?(float)cB/(float)cA:0.f;
  printf("K cA=%u cB=%u ratio=%.3f km=%d bLen=%d ml=%d thr=%u\n",cA,cB,ratio,(int)km,bLen,ml,thr);

  /* gates, evaluated at this frequency */
  int tA=(mhz>=311.5&&mhz<=313.5), tB=(mhz>=313.8&&mhz<=315.5);
  printf("G mhz=%.3f band=%s te_toy=%d te_kl=%d te_frdv0=%d eu433=%d\n",
         mhz, tA?"A":(tB?"B":"-"),
         (int)((tA||tB)&&cA>=150&&cA<=700),
         (int)(cA>=100&&cA<=750&&ratio>=1.6f&&ratio<=2.4f),
         (int)(cA>=150&&cA<=380&&ratio>=1.4f&&ratio<=2.6f&&bLen>=76),
         (int)(mhz>=433.f&&mhz<=434.6f));
  printf("P toyota_pathA=%d toyota_pathB=%d\n",
         (int)(!km && mhz>=311.5f && mhz<=315.5f),
         (int)(((tA||tB)&&cA>=150&&cA<=700) && ratio>=3.5f));

  /* Toyota candidate scan, verbatim from ks_decodeToyota with prints inserted */
  static uint32_t cbuf[CAP_SZ];
  int ccnt=(n<=CAP_SZ)?n:CAP_SZ;
  cbuf[0]=B[0];
  for(int i=1;i<ccnt;i++) cbuf[i]=(B[i]<=5000)?B[i]:cbuf[i-1];
  int cand=0, accepted=0, bestpc=0;
  for(int pi=0;pi+79<ccnt;pi++){
    uint32_t te0=cbuf[pi];
    if(te0<150||te0>700) continue;
    int pc=0,j=pi; uint64_t a=0;
    while(j+1<ccnt&&ks_inR(cbuf[j],te0,35)&&ks_inR(cbuf[j+1],te0,50)){ a+=cbuf[j]; pc++; j+=2; }
    if(pc<8) continue;
    if(pc>bestpc) bestpc=pc;
    uint32_t te=(uint32_t)(a/(uint64_t)pc);
    int ds=j;
    if(j+1<ccnt&&ks_inR(cbuf[j],te,35)&&cbuf[j+1]>=te*3&&cbuf[j+1]<=28000UL) ds=j+2;
    if(ds+79>ccnt) continue;
    uint64_t w=0; bool ok=false; int used=0;
    for(int t=ds;t<=ds+1&&!ok;t++){
      if(t+79>ccnt) break;
      w=0; bool o2=true;
      for(int b=0;b<40;b++){
        uint32_t hi=cbuf[t+b*2];
        bool is1=ks_inR(hi,2*te,35), is0=(!is1)&&ks_inR(hi,te,35);
        if(is1) w=(w<<1)|1ULL; else if(is0) w<<=1;
        else { o2=(b>=38); w<<=1; break; }
      }
      if(o2){ ok=true; used=t; }
    }
    if(!ok) continue;
    long sn=(long)((w>>16)&0xFFFFFFUL);
    long ct=(long)(w&0xFFFUL);
    long bt=(long)((w>>12)&0xFUL);
    if(sn==0||sn==0xFFFFFFL) continue;
    int tr=0;for(int i=0;i<39;i++) if(((w>>i)&1)!=((w>>(i+1))&1)) tr++;
    cand++;
    if(tr<8||tr>32) continue;
    accepted++;
    if(accepted<=20)
      printf("C pi=%d te=%u pc=%d ds=%d used=%d sn=0x%06lX ctr=%ld btn=%lX tr=%d\n",
             pi,te,pc,ds,used,sn,ct,bt,tr);
  }
  printf("S candidates=%d accepted=%d maxpc=%d\n",cand,accepted,bestpc);
}
'''

HARNESS = """
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#define CAP_SZ 512
"""


def build_exe(src: str, tmp: Path, trim: bool):
    parts = [HARNESS]
    if trim:
        # klTrimToFrame plus the Kia V3/V4 pitch constants rjTrimKiaV34 passes. Self-contained:
        # the gap and pitch are parameters, so no cipher code comes along with it.
        for macro in ("KIA_V34_FRAME_GAP_US", "KIA_V34_FRAME_PITCH_PULS",
                      "KIA_V34_FRAME_PITCH_TOL"):
            m = re.search(r"^#define\s+" + macro + r"\s+[^\n]+", src, re.M)
            if not m:
                raise SystemExit(f"could not find #define {macro}")
            parts.append(m.group(0) + "\n")
        parts.append(extract_fn(src, "klTrimToFrame") + "\n")
        parts.append("""
static int doTrim(const uint16_t* in,int n,uint16_t* out,int cap){
  return klTrimToFrame(in,n,out,cap,KIA_V34_FRAME_GAP_US,
                       KIA_V34_FRAME_PITCH_PULS,KIA_V34_FRAME_PITCH_TOL,nullptr);
}
""")
    for fn in ("ks_km2", "ks_mkBits", "ks_manchester", "ks_inR"):
        b = extract_fn(src, fn)
        if not b:
            raise SystemExit(f"could not extract {fn} from the sketch")
        parts.append(b + "\n")
    parts.append(PROBE)
    parts.append("\nint main(int c,char**v){ if(c<2) return 2; report(c,v); return 0; }\n")
    cpp = tmp / "probe.cpp"
    cpp.write_text("".join(parts), encoding="utf-8")
    exe = tmp / "probe"
    cc = shutil.which("c++") or shutil.which("clang++") or "c++"
    r = subprocess.run([cc, "-O1", "-w", "-o", str(exe), str(cpp)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("harness compile failed:\n" + r.stderr[:3000])
    return exe


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    src = SKETCH.read_text(encoding="utf-8")
    results = []
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        exe = build_exe(src, tmp, trim=True)
        for fp in args.files:
            p = Path(fp)
            if not p.is_file():
                print(f"missing: {p}", file=sys.stderr)
                continue
            widths, mhz = parse_sub(p)
            hdr = header_of(p)
            pf = tmp / "in.txt"
            pf.write_text(f"{mhz}\n" + "\n".join(str(w) for w in widths), encoding="utf-8")
            out = subprocess.run([str(exe), str(pf)], capture_output=True, text=True).stdout

            hist = ""
            lines = {}
            cands = []
            summary = {}
            for ln in out.splitlines():
                if ln.startswith("T "):
                    lines["T"] = ln[2:].strip()
                elif ln.startswith("H "):
                    hist = ln[2:].strip()
                elif ln.startswith(("K ", "G ", "P ")):
                    lines[ln[0]] = ln[2:].strip()
                elif ln.startswith("C "):
                    cands.append(ln[2:].strip())
                elif ln.startswith("S "):
                    for kv in ln[2:].split():
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            summary[k] = int(v)

            # width histogram with counts, most common first
            pairs = []
            for tok in hist.split():
                if ":" in tok:
                    w, c = tok.split(":")
                    pairs.append((int(w), int(c)))
            pairs.sort(key=lambda t: -t[1])

            print("=" * 78)
            print(f"{p.name}")
            print(f"  header   : {hdr.get('Frequency','?')} Hz  preset={hdr.get('Preset','?')}  "
                  f"protocol={hdr.get('Protocol','?')}")
            print(f"  pulses   : {len(widths)}")
            if "T" in lines:
                print(f"  trim     : {lines['T']}")
            print(f"  widths   : " + ", ".join(f"{w}us x{c}" for w, c in pairs[:10]))
            for k in ("K", "G", "P"):
                if k in lines:
                    print(f"  {k}        : {lines[k]}")
            if summary:
                print(f"  toyota   : candidates={summary.get('candidates',0)} "
                      f"accepted={summary.get('accepted',0)} "
                      f"max_preamble_pairs={summary.get('maxpc',0)}")
            for c in cands:
                print(f"      {c}")
            if not cands and summary.get("maxpc", 0) < 8:
                print(f"      (no candidate reached the 8-pair preamble minimum; "
                      f"best was {summary.get('maxpc',0)})")

            results.append({"file": str(p), "header": hdr, "pulses": len(widths),
                            "trim": lines.get("T", ""), "widths": pairs[:14],
                            "kmeans": lines.get("K", ""),
                            "gates": lines.get("G", ""), "paths": lines.get("P", ""),
                            "candidates": cands, "summary": summary})

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
