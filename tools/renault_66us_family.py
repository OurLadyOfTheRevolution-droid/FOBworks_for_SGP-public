#!/usr/bin/env python3
"""Characterise the non-Hitag2 Renault families (the "~66 us" captures).

separated the Renault corpus into one genuine Hitag2 recording
(Trafic 2011) and everything else. then closed Hitag2 Layer 2. That
leaves the bulk of the corpus — Captur 2017, Kadjar 2023 ("Ren"), and the Megane/
Scenic 2005 set — which share a base pulse near 66 us but are a different physical
layer. This tool is the reconnaissance step for those: it reports, per file, the
pulse quantisation, the candidate base unit, the sync/prelude, and whether any of
the frames decode as a plausible Manchester or PWM bitstream.

It does NOT ship a decoder. It exists so the family can be told apart on evidence
(base unit, modulation, frame length, repetition) before anything is ported, the
same way the Hitag2 work started.

  python3 tools/renault_66us_family.py [file.sub ...]
"""
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research/sources/corpus_automotive_subghz/European/Renault"

DEFAULT = [
    "Captur 2017/Renault_Captur_2017_Lock_x5.sub.sub",
    "Captur 2017/Renault_Captur_2017_Unlock_x5.sub",
    "Kadjar 2023/Renault1.sub",
    "Kadjar 2023/Ren2.sub",
    "Kadjar 2023/Ren3.sub",
    "Renault_Megane_Scenic_2005_lock.sub",
    "Renault_Megane_Scenic_2005_unlock.sub",
    "Renault_Megane_Scenic_2005_trunk.sub",
]


def parse(path):
    widths, hdr = [], {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            widths.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
        elif ":" in line and not hdr.get("_done"):
            k, _, v = line.partition(":")
            if k == "RAW_Data":
                hdr["_done"] = True
            else:
                hdr[k.strip()] = v.strip()
    return [abs(w) for w in widths], hdr


def quantise(widths):
    """Most common widths, and the best base unit in the ~33/66 us region."""
    c = Counter(w for w in widths if w > 0)
    top = c.most_common(16)
    # base unit: the largest d such that many widths are near-integer multiples of d.
    best = (0, 0, 0)
    for cand in range(20, 140):
        fit = sum(n for w, n in c.items() if w >= cand and abs(w / cand - round(w / cand)) < 0.12)
        if fit > best[0]:
            best = (fit, cand, sum(n for w, n in c.items()))
    return top, best


def sync_prelude(widths, base):
    """The first long pulse (>= 4x base) and the run of short pulses before it."""
    idx = next((i for i, w in enumerate(widths) if w >= 4 * base and i >= 2), None)
    if idx is None:
        return None
    head = widths[max(0, idx - 8):idx + 6]
    return idx, head


def manchester_attempt(widths, base):
    """Greedy Manchester decode from the first long gap; report bits and parity of
    the short/short pairing. Diagnostic only — no protocol claim."""
    lo, hi = 0.45 * base, 1.75 * base
    bits, i, n = [], 0, len(widths)
    started = False
    while i + 1 < n and len(bits) < 256:
        a, b = widths[i], widths[i + 1]
        short_a, short_b = lo <= a <= hi, lo <= b <= hi
        if not short_a or not short_b:
            if started:
                break
            i += 1
            continue
        started = True
        # Manchester: (short,long)=1, (long,short)=0 approximated by ratio
        bits.append(1 if a <= b else 0)
        i += 2
    return bits


def run_metrics(widths, base):
    gaps = [i for i, w in enumerate(widths) if w >= 10 * base]
    return gaps[:12], len(gaps)


def main():
    files = sys.argv[1:] or [str(CORPUS / f) for f in DEFAULT]
    for f in files:
        p = Path(f)
        if not p.is_file():
            print(f"missing: {p}")
            continue
        widths, hdr = parse(p)
        top, (fit, unit, tot) = quantise(widths)
        print("=" * 78)
        print(f"{p.name}")
        print(f"  freq {hdr.get('Frequency','?')}  preset {hdr.get('Preset','?')}"
              + (f"  module {hdr.get('Custom_preset_module','')}" if hdr.get('Custom_preset_module') else ""))
        print(f"  pulses {len(widths)}")
        print(f"  top widths: " + ", ".join(f"{w}x{n}" for w, n in top[:10]))
        print(f"  candidate base unit: {unit} us  ({fit}/{tot} pulses are near-integer multiples)")
        sp = sync_prelude(widths, unit)
        if sp:
            idx, head = sp
            print(f"  first >=4x pulse at index {idx}; around it: {head}")
        gaps, ngap = run_metrics(widths, unit)
        print(f"  long gaps (>=10x base): {ngap}  first at: {gaps}")
        bits = manchester_attempt(widths, unit)
        if bits:
            hx = "".join(str(b) for b in bits[:64])
            print(f"  manchester-ish bits ({len(bits)}): {hx}{'...' if len(bits)>64 else ''}")
        print()


if __name__ == "__main__":
    sys.exit(main())
