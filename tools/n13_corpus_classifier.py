#!/usr/bin/env python3
"""N13 corpus classifier: measure whether the timing fingerprint separates brands.

§N13 §N13 describe the fingerprint as lead generation:
an unmatched capture should report "no decoder, but timing-matches the PSA/Kia
families" instead of bare OOK-raw. The firmware accumulates those histograms
live, but nobody had asked whether the quantization actually separates brands.
This script answers that against the 301 labeled corpus captures.

It extracts the SHIPPED quantization (freq 0.2 MHz, TE log2 from 64 us, ratio
0.25, bits log2 from 32) and the SHIPPED preprocessing (trim to one frame,
k-means, ratio) from the sketch, compiles them, and runs over every .sub file:

  1. Bucket every capture; report bucket occupancy.
  2. Leave-one-out brand prediction. For each capture, look at the OTHER
     captures sharing its (freq, TE, bits) fingerprint — deliberately dropping
     the ratio axis, which is the noisiest — and predict the most common brand
     among those neighbours.
  3. Coverage: how many captures have >=1 neighbour at all, and how often the
     brand they land nearest is unique across the corpus.

Honest scope: this measures the fingerprint's brand SEPARATION, not whether it
beats a decoder. A capture that a decoder already names needs no fingerprint.

Needs only a C++ compiler. No hardware.

Run:
    python3 tools/n13_corpus_classifier.py
    python3 tools/n13_corpus_classifier.py --dump-neighbours
"""

from __future__ import annotations

import argparse
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKETCH = ROOT / "FOBworks_for_SGP.ino"
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

sys.path.insert(0, str(ROOT / "tools"))
from corpus_regression import parse_sub, brand_of  # reuse the exact .sub reader


def extract_fn(src: str, name: str):
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


def quant_axes(mhz: float, cA: int, ratio: float, bLen: int) -> tuple[int, int, int, int]:
    """The sketch's quantization, mirrored in Python for the report tables."""
    fb = int(mhz / 0.2) if mhz >= 400.0 else int(mhz * 5000.0)
    tb = int(math.log2(cA / 64.0) * 4.0) if cA > 0 else 0
    rb = int(ratio / 0.25) if ratio > 0 else 0
    bb = int(math.log2(bLen / 32.0) * 4.0) if bLen > 0 else 0
    return fb, tb, rb, bb


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-neighbours", action="store_true",
                    help="print every capture's neighbours when it is mispredicted")
    ap.add_argument("--regression-json", default=None,
                    help="corpus_regression.py --json output; adds the lead-gen table "
                         "for captures no decoder matched")
    ap.add_argument("--corpus", default=None)
    args = ap.parse_args()

    corpus = Path(args.corpus) if args.corpus else CORPUS
    src = SKETCH.read_text(encoding="utf-8")

    print("=== extract the shipped preprocessing and quantizer ===")
    funcs = {}
    for n in ("ks_km2", "ks_mkBits", "rjTrimKiaV34", "klTrimToFrame"):
        b = extract_fn(src, n)
        funcs[n] = b
        print(f"  {'ok  ' if b else 'MISS'} {n}")
    if any(v is None for v in funcs.values()):
        print("  cannot proceed: a preprocessing helper did not extract")
        return 1

    # Constants the extracted functions reference.
    consts = "\n".join(
        f"#define {n} {v}" for n, v in re.findall(
            r"^#define\s+(KIA_V34_FRAME_[A-Z0-9_]+)\s+([0-9]+)", src, re.M))

    harness = f"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#define CAP_SZ 512
{consts}
static uint16_t rfBuf[CAP_SZ];
static int rfLen=0;
static bool rfStartHigh=true;
{funcs['klTrimToFrame']}
{funcs['rjTrimKiaV34']}
{funcs['ks_km2']}
{funcs['ks_mkBits']}

int main(int argc,char**argv){{
  FILE* f=fopen(argv[1],"r");
  if(!f) return 2;
  double mhz=0;
  if(fscanf(f,"%lf",&mhz)!=1){{ fclose(f); return 2; }}
  int rn=0; unsigned long v;
  while(rn<4096 && fscanf(f,"%lu",&v)==1) rfBuf[rn++]=(uint16_t)v;
  fclose(f);
  if(rn<18){{ printf("NONE\\n"); return 0; }}
  static uint16_t trimmed[CAP_SZ];
  int tl = rjTrimKiaV34(rfBuf, rn, trimmed, CAP_SZ, nullptr);
  uint32_t B[CAP_SZ]; int n=0;
  if(tl>0){{ for(int i=0;i<tl&&i<CAP_SZ;i++) B[n++]=(uint32_t)trimmed[i]; }}
  else    {{ for(int i=0;i<rn&&i<CAP_SZ;i++) B[n++]=(uint32_t)rfBuf[i]; }}
  static uint32_t kbuf[CAP_SZ]; int kn=0;
  for(int i=0;i<n;i++) if(B[i]<=5000) kbuf[kn++]=B[i];
  uint32_t cA=0,cB=0;
  ks_km2(kn>=6?kbuf:B, kn>=6?kn:n, cA, cB);
  uint32_t thr=(cA+cB)/2;
  static char bits[CAP_SZ+1];
  uint16_t bLen=ks_mkBits(B, n, bits, thr);
  float ratio=(cA>0)?(float)cB/(float)cA:0.f;
  printf("%.3f %u %u %.4f %u\\n", mhz, (unsigned)cA, (unsigned)cB, ratio, (unsigned)bLen);
  return 0;
}}
"""
    tmp = Path(tempfile.mkdtemp())
    try:
        cpp = tmp / "h.cpp"
        cpp.write_text(harness, encoding="utf-8")
        exe = tmp / "h"
        cc = shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
        r = subprocess.run([cc, "-O1", "-w", "-o", str(exe), str(cpp)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("harness did not compile:\n" + r.stderr[:2000])
            return 1
        print("  measurement harness compiled\n")

        rows = []
        for sub in sorted(corpus.rglob("*.sub")):
            w, mhz = parse_sub(sub)
            if len(w) < 18:
                continue
            inp = tmp / "c.txt"
            inp.write_text(f"{mhz}\n" + "\n".join(map(str, w)), encoding="utf-8")
            cr = subprocess.run([str(exe), str(inp)], capture_output=True, text=True)
            toks = cr.stdout.split()
            if len(toks) < 5 or toks[0] == "NONE":
                continue
            f_mhz = float(toks[0]); cA = int(toks[1]); cB = int(toks[2])
            ratio = float(toks[3]); bLen = int(toks[4])
            fb, tb, rb, bb = quant_axes(f_mhz, cA, ratio, bLen)
            rows.append({
                "path": str(sub.relative_to(corpus)),
                "brand": brand_of(sub),
                "freq": f_mhz, "cA": cA, "cB": cB, "ratio": ratio, "bLen": bLen,
                "fb": fb, "tb": tb, "rb": rb, "bb": bb,
            })

        print(f"=== {len(rows)} corpus captures measured ===\n")

        # 1. Bucket occupancy — the full 4-axis key the firmware uses.
        buckets = defaultdict(list)
        for r in rows:
            buckets[(r["fb"], r["tb"], r["rb"], r["bb"])].append(r)
        brand_counts = Counter(r["brand"] for r in rows)
        print("=== brand histogram of the corpus ===")
        for b, c in brand_counts.most_common():
            print(f"  {b:<12} {c}")
        print(f"\n  distinct full 4-axis buckets: {len(buckets)}")
        pure = sum(1 for k, v in buckets.items() if len({x['brand'] for x in v}) == 1)
        print(f"  buckets containing exactly one brand: {pure}/{len(buckets)} "
              f"({100*pure/max(1,len(buckets)):.0f}%)")

        # 2. Leave-one-out prediction on (freq, TE, bits) — ratio dropped as the
        # noisiest axis.
        print("\n=== leave-one-out brand prediction on (freq, TE, bits) ===")
        index = defaultdict(list)
        for i, r in enumerate(rows):
            index[(r["fb"], r["tb"], r["bb"])].append(i)

        hit = 0
        no_neighbour = 0
        mispredict = []
        for i, r in enumerate(rows):
            key = (r["fb"], r["tb"], r["bb"])
            neighbours = [rows[j] for j in index[key] if j != i]
            if not neighbours:
                no_neighbour += 1
                continue
            neighbour_brands = Counter(x["brand"] for x in neighbours)
            pred, npop = neighbour_brands.most_common(1)[0]
            if pred == r["brand"]:
                hit += 1
            else:
                mispredict.append((r, pred, npop, len(neighbours), neighbour_brands))

        covered = len(rows) - no_neighbour
        print(f"  captures with >=1 neighbour:   {covered}/{len(rows)}")
        print(f"  capture had NO neighbour:      {no_neighbour}")
        print(f"  brand predicted correctly:     {hit}/{covered} "
              f"({100*hit/max(1,covered):.0f}% of covered, "
              f"{100*hit/max(1,len(rows)):.0f}% of all)")
        # Baseline: always predicting the majority brand.
        maj_brand, maj_n = brand_counts.most_common(1)[0]
        print(f"  majority-brand baseline:       {maj_n}/{len(rows)} "
              f"({100*maj_n/len(rows):.0f}%) always predicting '{maj_brand}'")

        if args.dump_neighbours and mispredict:
            print("\n=== mispredictions ===")
            for r, pred, npop, nn, nb in sorted(mispredict, key=lambda x: x[0]["brand"]):
                print(f"  {r['brand']:<10} -> {pred:<10} "
                      f"(f={r['freq']:.2f} te={r['cA']} bits={r['bLen']} "
                      f"neigh={nn} {dict(nb.most_common(3))})  {r['path']}")

        # 3. Lead generation — for each brand, is its own fingerprint distinctive?
        print("\n=== per-brand: does the fingerprint point home? ===")
        print(f"  {'brand':<12} {'n':>3} {'buckets':>7} {'hits':>4} {'miss':>4} {'noNbr':>5}")
        by_brand = defaultdict(lambda: {"n": 0, "buckets": set(), "hit": 0, "miss": 0, "non": 0})
        for i, r in enumerate(rows):
            s = by_brand[r["brand"]]
            s["n"] += 1
            s["buckets"].add((r["fb"], r["tb"], r["bb"]))
            neighbours = [rows[j] for j in index[(r["fb"], r["tb"], r["bb"])] if j != i]
            if not neighbours:
                s["non"] += 1
            elif Counter(x["brand"] for x in neighbours).most_common(1)[0][0] == r["brand"]:
                s["hit"] += 1
            else:
                s["miss"] += 1
        for b, s in sorted(by_brand.items(), key=lambda kv: -kv[1]["n"]):
            print(f"  {b:<12} {s['n']:>3} {len(s['buckets']):>7} "
                  f"{s['hit']:>4} {s['miss']:>4} {s['non']:>5}")

        print("\nNote: a capture the decoders already name needs no fingerprint. The")
        print("value here is the captures matching nothing, where the fingerprint's")
        print("nearest neighbours are a lead for the next decoder effort.")

        # 4. Lead-gen table: for the captures no decoder matched, group by
        #    fingerprint bucket and name the brand their neighbours suggest.
        if args.regression_json:
            import json as _json
            reg = _json.loads(Path(args.regression_json).read_text())
            none_set = {p for p in reg.get("matched_none", [])}
            print(f"\n=== lead-gen for the {len(none_set)} captures no decoder matched ===")
            # bucket -> brand counts across the WHOLE corpus (a bucket's identity).
            bucket_brands = {k: Counter(rows[j]["brand"] for j in v)
                             for k, v in index.items()}
            leads = defaultdict(lambda: {"n": 0, "brands": Counter(), "paths": []})
            for r in rows:
                if r["path"] not in none_set:
                    continue
                key = (r["fb"], r["tb"], r["bb"])
                bb_ = bucket_brands.get(key, Counter())
                leads[key]["n"] += 1
                leads[key]["brands"].update(bb_)
                leads[key]["paths"].append((r["brand"], r["path"]))
            # Rank buckets by how many unmatched captures they hold.
            print(f"  {'freq-bin':>9} {'te-bin':>6} {'bits-bin':>8} {'n':>3}  leads (brand:count)")
            for key, s in sorted(leads.items(), key=lambda kv: -kv[1]["n"])[:25]:
                fb, tb, bb = key
                hint = ", ".join(f"{b}:{c}" for b, c in s["brands"].most_common(4))
                print(f"  {fb:>9} {tb:>6} {bb:>8} {s['n']:>3}  {hint}")
            # Roll up: what fraction of the unmatched set has a brand-carrying neighbour?
            with_lead = sum(1 for key, s in leads.items() if s["brands"])
            unmatched_rows = sum(s["n"] for s in leads.values())
            print(f"\n  unmatched captures: {unmatched_rows}")
            print(f"  buckets with a labelled neighbour: {with_lead}/{len(leads)}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
