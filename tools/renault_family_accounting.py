#!/usr/bin/env python3
"""Renault corpus accounting and family separation.

called the non-Hitag2 Renault captures "the ~66 us family" and counted
22 files. Both of those framings turn out to be wrong, and this tool is the evidence
for the correction:

  * the corpus is far smaller than the file count suggests, because most of the files
    are byte-identical duplicates parked in more than one folder;
  * the Kadjar "Ren" set is not one group — Ren2 is a clean ~105 us PWM remote, Ren3 is
    an FSK capture that carries no PWM width meaning at all, and Renault1 is a poor
    capture that fits no lattice well;
  * the genuine grouping is by base-unit fit, not by dominant pulse width, which is
    what lumped everything together and produced the misleading "66 us" label.

Reports, per unique capture: content hash, copy count, preset, pulse count, base-unit
fit at 33/66/105 us, and the parity-split symbol clusters.

  python3 tools/renault_family_accounting.py
"""
import hashlib
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

NAME_HINTS = ("renault", "ren2", "ren3", "renault1",
              "captur", "kadjar", "megane", "trafic", "scenic")
FAMILY_TES = (33, 66, 105)


def parse(path):
    widths = []
    hdr = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            widths.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
        elif ":" in line and "RAW_Data" not in line and "Preset" not in hdr:
            k, _, v = line.partition(":")
            hdr.setdefault(k.strip(), v.strip())
        elif line.startswith("Preset:"):
            hdr["Preset"] = line[7:].strip()
    return widths, hdr


def candidates():
    """Files whose *path tokens* name a Renault fob.

    Tokenised rather than substring-matched on purpose: a substring test on "captur"
    also matches "Captured", which pulled three Tesla files into the first run of this
    tool. Split on non-alphanumerics and compare whole tokens.
    """
    hints = set(NAME_HINTS)
    out = []
    for p in CORPUS.rglob("*.sub"):
        toks = {t for t in re.split(r"[^a-z0-9]+", p.name.lower()) if t}
        parent = " ".join(re.split(r"[^a-z0-9]+", str(p.parent).lower()))
        if (toks & hints) or "renault" in parent.split():
            out.append(p)
    return out


def base_fit(widths, te):
    if not widths:
        return 0.0
    ok = sum(1 for w in widths
             if abs(abs(w) - round(abs(w) / te) * te) < te * 0.25)
    return ok / len(widths)


def symbols(widths, te):
    hi = Counter()
    lo = Counter()
    for i, w in enumerate(widths):
        (hi if w > 0 else lo)[round(abs(w) / te)] += 1
    return hi, lo


def main():
    groups = defaultdict(list)
    for p in candidates():
        groups[hashlib.md5(p.read_bytes()).hexdigest()[:10]].append(p)

    total = sum(len(v) for v in groups.values())
    print(f"Renault-named files: {total}   unique by content: {len(groups)}"
          f"   duplicates: {total - len(groups)}\n")

    for h, paths in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        widths, hdr = parse(paths[0])
        preset = hdr.get("Preset", "?")
        freq = hdr.get("Frequency", "?")
        fsk = "FSK" in preset.upper()
        print("=" * 78)
        print(f"{paths[0].name}   x{len(paths)} copies   {freq}   {preset}")
        print(f"  pulses: {len(widths)}")
        if not widths:
            print("  empty")
            continue
        fits = {te: base_fit(widths, te) for te in FAMILY_TES}
        best = max(fits, key=fits.get)
        print("  base-unit fit: "
              + "  ".join(f"{te}us={fits[te]:.2f}" for te in FAMILY_TES)
              + f"   -> best {best}us")
        if fsk:
            print("  FSK preset: pulse widths carry no PWM meaning; out of scope "
                  "for OOK symbol work")
            continue
        hi, lo = symbols(widths, best)
        print(f"  symbol clusters (units of {best}us, low-half of each pulse):")
        print("    HIGH-side:", sorted(hi.items())[:10])
        print("    LOW-side :", sorted(lo.items())[:10])
        if fits[best] < 0.7:
            print("  NOTE: fit below 0.70 — degraded or mis-triggered capture, "
                  "re-capture before classifying")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
