#!/usr/bin/env python3
"""Classify corpus captures by repeated-frame structure.

needed a way to tell a genuine repeated-frame OOK capture from a dense
recording that has no frame in it. The metric that settled the Renault question was:
quantise each capture to its own base unit, then find the longest run of symbols that
appears more than once. A repeated-frame fob shows a long run (the FIAT Grande Punto and
Bravo captures give 200-600); a frame-less recording shows almost nothing (the Renault
Megane/Captur/`Ren2` captures give 0-13).

This tool applies that metric across the corpus so the next decoder target can be picked
from evidence instead of from a dominant-width guess.

CAVEAT — read this before using the numbers as a verdict. A high score proves the file
contains repeated frames and is therefore worth decoder work. A LOW score does NOT prove
the file is unusable: a protocol whose fob transmits once per press (Kia V3/V4 is one)
decodes fine from a single frame and will still score low here. Treat STRONG as a
reliable positive and everything below it as "needs a look", not as "junk".

  python3 tools/frame_structure_scan.py [--strong] [--path SUBSTR] [dir]
"""
import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

STRONG, WEAK = 64, 16


def parse(path):
    widths = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            widths.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
    return widths


def best_unit(widths):
    c = Counter(abs(w) for w in widths if 0 < abs(w) < 2000)
    best = (0, 33)
    for cand in range(20, 221):
        fit = sum(n for w, n in c.items() if abs(w / cand - round(w / cand)) < 0.10)
        if fit > best[0]:
            best = (fit, cand)
    return best[1]


def longest_repeat(widths, te, k=12, cap=8000, budget=4000):
    seq = [round(abs(w) / te) if 0 < abs(w) <= 3000 else 0 for w in widths][:cap]
    n = len(seq)
    if n < k:
        return 0
    idx = defaultdict(list)
    for i in range(n - k):
        idx[tuple(seq[i:i + k])].append(i)
    best = 0
    for starts in idx.values():
        if len(starts) < 2:
            continue
        for a in range(len(starts)):
            for b in range(a + 1, len(starts)):
                budget -= 1
                if budget <= 0:
                    return best
                i, j = starts[a], starts[b]
                m = 0
                while i + m < n and j + m < n and seq[i + m] == seq[j + m] and m < 800:
                    m += 1
                if m > best:
                    best = m
    return best


def band(rep):
    return "STRONG" if rep >= STRONG else ("WEAK" if rep >= WEAK else "NONE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", nargs="?", default=str(CORPUS))
    ap.add_argument("--path", help="only files whose relative path contains this substring")
    ap.add_argument("--strong", action="store_true", help="print only STRONG captures")
    ap.add_argument("--summary", action="store_true", help="print only the tallies")
    args = ap.parse_args()

    base = Path(args.dir)
    files = sorted(base.rglob("*.sub"))
    rows = []
    for p in files:
        rel = str(p.relative_to(base))
        if args.path and args.path.lower() not in rel.lower():
            continue
        w = parse(p)
        if len(w) < 40:
            rows.append((rel, 0, len(w)))
            continue
        te = best_unit(w)
        rows.append((rel, longest_repeat(w, te), len(w)))

    strong = [r for r in rows if r[1] >= STRONG]
    weak = [r for r in rows if WEAK <= r[1] < STRONG]
    none = [r for r in rows if r[1] < WEAK]

    if not args.summary:
        for rel, rep, n in sorted(rows, key=lambda x: -x[1]):
            if args.strong and rep < STRONG:
                continue
            print(f"{band(rep):6s} rep={rep:4d} n={n:6d}  {rel}")
        print()

    print(f"scanned {len(rows)} captures")
    print(f"  STRONG (>= {STRONG} repeated symbols): {len(strong)}")
    print(f"  WEAK   ({WEAK}-{STRONG - 1}): {len(weak)}")
    print(f"  NONE   (< {WEAK}): {len(none)}")
    print("  reminder: STRONG is a reliable positive; NONE is not a verdict "
          "(single-shot protocols score low but still decode).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
