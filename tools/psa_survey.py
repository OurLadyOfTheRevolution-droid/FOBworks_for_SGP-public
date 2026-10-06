#!/usr/bin/env python3
"""PSA/Renault corpus survey — data-first, before writing any decoder.

The corpus has ~34 RAW captures across Renault, Peugeot, Groupe_PSA and Citroen
folders. This measures what is actually there: pulse-width histograms (PWM
shape), bit lengths after 2-level slicing, header preambles, and inter-frame
repeat structure — the numbers a te_ gate and a decoder need.

Triage stage 1 for the PSA/Renault decoder work. Run it against the raw
files; it prints one summary line per file plus a per-family histogram so
gate windows can be picked from data, not folklore.
"""

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"
FAMILIES = ["Renault", "Peugeot", "Groupe_PSA", "Citroen"]


def parse_sub(path, cap=4096):
    w, mhz = [], 433.92
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Frequency:"):
            try:
                hz = int(line.split(":", 1)[1].strip())
                if hz > 100000000:
                    mhz = hz / 1e6
            except ValueError:
                pass
        if line.startswith("RAW_Data:"):
            w.extend(abs(int(x)) for x in re.findall(r"-?\d+", line[9:]))
        if len(w) >= cap:
            break
    return w[:cap], mhz


def two_level(w):
    """2-level PWM slice like ks_mkBits: short/long via the bimodal split."""
    hi = [x for x in w if x < 10000]
    if len(hi) < 8:
        return None
    hi.sort()
    # Bimodal split at the biggest relative gap in the middle 10-90% range
    lo = hi[int(len(hi) * 0.1):int(len(hi) * 0.9) + 1]
    best, cut = 0.0, None
    for i in range(1, len(lo)):
        gap = (lo[i] - lo[i - 1]) / max(1, (lo[i] + lo[i - 1]) / 2)
        if gap > best:
            best, cut = gap, (lo[i] + lo[i - 1]) / 2
    if cut is None or best < 0.2:
        return None
    short = [x for x in hi if x < cut]
    long = [x for x in hi if x >= cut]
    if not short or not long:
        return None
    cA = sum(short) / len(short)
    cB = sum(long) / len(long)
    bits = "".join("0" if x < cut else "1" for x in hi)
    return cut, cA, cB, bits


def main():
    per_family = {}
    for fam in FAMILIES:
        fam_dir = CORPUS / "European" / fam
        if not fam_dir.is_dir():
            continue
        for f in sorted(fam_dir.rglob("*.sub")):
            w, mhz = parse_sub(f)
            if len(w) < 40:
                continue
            r = two_level(w)
            rel = f.relative_to(CORPUS / "European")
            if r is None:
                print(f"{fam:10s} {str(rel):55s} mhz={mhz:7.3f} pulses={len(w):5d}  "
                      f"(no clean 2-level split — Manchester or multi-level?)")
                continue
            cut, cA, cB, bits = r
            ratio = cB / cA if cA else 0
            # Frame repeat structure: pulses >1 ms (PSA separator scale)
            seps = [i for i, x in enumerate(w) if x > 1000]
            # Modal pitch between separators
            pitch = None
            if len(seps) >= 3:
                d = Counter()
                for a, b in zip(seps, seps[1:]):
                    dd = b - a
                    if 24 <= dd <= 400:
                        d[dd] += 1
                if d:
                    pitch, pc = d.most_common(1)[0]
            # Skip the file head noise: first real pulse > 5 ms or leading quiet
            # Corpus PSA files start with e.g. 8905 or 11801 µs idle leading.
            first_real = 0
            for i, x in enumerate(w):
                if x < 5000:
                    first_real = i
                    break
            body = w[first_real:]
            br = two_level(body) if len(body) >= 40 else None
            bbits = br[3] if br else ""
            print(f"{fam:10s} {str(rel):55s} mhz={mhz:7.3f} pulses={len(w):5d} "
                  f"cA={cA:6.1f} cB={cB:6.1f} r={ratio:4.2f} bits={len(bits):4d} "
                  f"sepN={len(seps):3d} pitch={str(pitch) if pitch else '-':>4s} "
                  f"bodyBits={len(bbits):4d}")
            key = fam
            per_family.setdefault(key, []).append((cA, cB, ratio, len(bits)))
    # Family summary: the gate windows
    print("\n=== family summaries (cA/cB = 2-level short/long means, µs) ===")
    for fam, rows in per_family.items():
        cAs = sorted(r[0] for r in rows)
        cBs = sorted(r[1] for r in rows)
        rs = sorted(r[2] for r in rows)
        bl = sorted(r[3] for r in rows)
        print(f"{fam:10s} n={len(rows):2d}  cA {cAs[0]:6.1f}-{cAs[-1]:6.1f}  "
              f"cB {cBs[0]:6.1f}-{cBs[-1]:6.1f}  ratio {rs[0]:.2f}-{rs[-1]:.2f}  "
              f"bits {bl[0]}-{bl[-1]}")


if __name__ == "__main__":
    sys.exit(main())
