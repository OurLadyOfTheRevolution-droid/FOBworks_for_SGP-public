#!/usr/bin/env python3
"""Honda corpus survey: pulse structure + the honda_static alignment test.

records why a Honda decoder is blocked. This tool makes that
measurement reproducible: it reports, per Honda-family capture, the band, the
pulse quantum, the k-means clusters, and whether the ProtoPirate `honda_static`
geometry (short 28-98, long 61-191, sync 700 us, Manchester, 64-bit packed
XOR-checksummed frame) validates on the capture.

A capture that validates is a decoder target; every one that does not is why the
port was held. Needs only Python. No hardware.

    python3 tools/honda_survey.py
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

# ProtoPirate honda_static geometry.
SHORT_BASE, SHORT_SPAN = 28, 70
LONG_BASE, LONG_SPAN = 61, 130
PREAMBLE_MAX_TRANSITIONS = 19
BIT_COUNT = 64


def parse(path: Path, cap: int = 65536):
    w, mhz = [], 433.92
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("Frequency:"):
            try:
                hz = int(line.split(":", 1)[1].strip())
                if hz > 1e8:
                    mhz = hz / 1e6
            except ValueError:
                pass
        if line.startswith("RAW_Data:"):
            w.extend(abs(int(x)) for x in re.findall(r"-?\d+", line[9:]))
        if len(w) >= cap:
            break
    return w[:cap], mhz


def kmeans2(w):
    xs = sorted(x for x in w if 0 < x < 3000)
    if not xs:
        return 0, 0
    cA, cB = xs[0], xs[-1]
    for _ in range(30):
        ga = [x for x in xs if abs(x - cA) < abs(x - cB)]
        gb = [x for x in xs if abs(x - cA) >= abs(x - cB)]
        if ga:
            cA = sum(ga) / len(ga)
        if gb:
            cB = sum(gb) / len(gb)
    return round(cA), round(cB)


def to_symbols(w):
    sym, lv = [], 1
    for a in w:
        if SHORT_BASE <= a <= SHORT_BASE + SHORT_SPAN:
            sym.append(lv)
        elif LONG_BASE <= a <= LONG_BASE + LONG_SPAN:
            sym.append(lv); sym.append(lv)
        else:
            lv = 1 - lv
            continue
        lv = 1 - lv
    return sym


def manchester64(sym, start, inv):
    pkt, bc, pos = [0] * 9, 0, start
    while pos + 1 < len(sym) and bc < BIT_COUNT:
        a, b = sym[pos], sym[pos + 1]
        if a == b:
            pos += 1
            continue
        bit = (a == 0 and b == 1) if inv else (a == 1 and b == 0)
        if bit:
            pkt[bc >> 3] |= 1 << ((~bc) & 7)
        bc += 1
        pos += 2
    return pkt, bc


def get_bits(pkt, start, count):
    v = 0
    for i in range(count):
        v = (v << 1) | ((pkt[(start + i) >> 3] >> ((~(start + i)) & 7)) & 1)
    return v


def static_validate(sym):
    """Run the honda_static parse; return (btn,ser,cnt) on a valid frame or None."""
    count = len(sym)
    idx, tr = 1, 0
    while idx < count:
        if sym[idx] != sym[idx - 1]:
            tr += 1
        else:
            if tr > PREAMBLE_MAX_TRANSITIONS:
                break
            tr = 0
        idx += 1
    if idx >= count:
        return None
    while idx + 1 < count and sym[idx] == sym[idx + 1]:
        idx += 1
    for inv in (True, False):
        pkt, bc = manchester64(sym, idx, inv)
        if bc < BIT_COUNT:
            continue
        calc = 0
        for i in range(7):
            calc ^= pkt[i]
        if get_bits(pkt, 56, 8) != calc:
            continue
        btn = get_bits(pkt, 0, 4)
        ser = get_bits(pkt, 4, 28)
        if btn <= 9 and ((0x336 >> btn) & 1) and ser not in (0, 0x0FFFFFFF):
            return btn, ser, get_bits(pkt, 32, 24)
    return None


def main() -> int:
    files = set()
    for pat in ("*onda*", "*cura*"):
        files |= set(CORPUS.rglob(pat + ".sub"))
    if not files:
        print("no Honda captures found")
        return 1
    print(f"{'capture':<48} {'MHz':>7} {'n':>6} {'cA':>4} {'cB':>5} "
          f"{'quant':>5}  static")
    for f in sorted(files):
        w, mhz = parse(f)
        if len(w) < 40:
            print(f"{f.name:<48} {mhz:7.3f} {len(w):>6}   (short)")
            continue
        cA, cB = kmeans2(w)
        # smallest common width = the pulse quantum
        common = Counter(x for x in w if 20 <= x <= 300).most_common(1)
        quantum = common[0][0] if common else 0
        sym = to_symbols(w)
        hit = static_validate(sym)
        tag = (f"btn={hit[0]} ser={hit[1]:07X} cnt={hit[2]:06X}" if hit else "-")
        print(f"{f.name:<48} {mhz:7.3f} {len(w):>6} {cA:>4} {cB:>5} "
              f"{quantum:>5}  {tag}")
    print("\nA '-' in the static column is a capture honda_static does not validate.")
    print("explains why the captures fit no single documented variant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
