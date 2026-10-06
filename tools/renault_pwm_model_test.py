#!/usr/bin/env python3
"""Test the fixed-slot PWM model proposed for the Renault "33 us" OOK captures.

looked at the symbol histogram of the Megane/Scenic 2005 and Captur 2017
captures, saw widths clustered at roughly 66 / 99 / 133 / 166 us (2T/3T/4T/5T on a
33.3 us unit), and proposed that the family is a pulse-width code in which each bit
occupies a fixed 5T slot carrying a 2T pulse (one) or a 4T pulse (zero). That model
makes two claims which are directly testable against the files, and this tool tests
both:

  1. FIXED SLOT. If each bit is a 5T slot, then a mark together with the space that
     follows it must sum to ~5T for essentially every pair. A code without fixed slots
     leaves pair sums spread over a wide range.

  2. FRAME REPETITION. An automotive fob repeats one frame several times per press
     (the Captur filename itself says x5). If the family were such a frame code, the
     same long run of pulses would appear repeatedly inside a capture, and the unit
     autocorrelation would show a strong peak at the frame period. A capture with
     neither is not a repeated-frame transmission.

Both are reported next to controls (Fiat captures) that a shipped decoder already
reads, so "no repetition" can be told apart from "the metric is just weak".

This tool ships no decoder. It exists to falsify or confirm the model before anything
is ported.

  python3 tools/renault_pwm_model_test.py [file.sub ...]
"""
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

DEFAULT = [
    ("European/Renault/Renault_Megane_Scenic_2005_lock.sub", 33.3),
    ("European/Renault/Renault_Megane_Scenic_2005_unlock.sub", 33.3),
    ("European/Renault/Renault_Megane_Scenic_2005_trunk.sub", 33.3),
    ("European/Renault/Captur 2017/Renault_Captur_2017_Lock_x5.sub.sub", 33.3),
    ("European/Renault/Captur 2017/Renault_Captur_2017_Unlock_x5.sub", 33.3),
    ("European/Renault/Kadjar 2023/Ren2.sub", 104.7),
    ("European/FIAT/Grande Punto/open.sub", 107.0),
    ("European/FIAT/Fiat Bravo 2010 S.Croce 433.88 am650.sub", 201.0),
]


def parse(path):
    widths = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            widths.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
    return widths


def best_unit(widths):
    """Largest unit in 20..220 us that most positive widths sit near a multiple of."""
    pos = [abs(w) for w in widths if 0 < abs(w) < 2000]
    if not pos:
        return 33.0
    c = Counter(pos)
    total = sum(c.values())
    best = (0.0, 33.0)
    for cand in range(20, 221):
        fit = sum(n for w, n in c.items() if abs(w / cand - round(w / cand)) < 0.10)
        if fit > best[0]:
            best = (fit / total, float(cand))
    return best[1]


def slot_test(widths, te, slot_units=5):
    """Fraction of mark+space pairs whose sum is within +/-15% of slot_units*te."""
    target = slot_units * te
    sums = []
    i = 0
    while i + 1 < len(widths):
        a, b = abs(widths[i]), abs(widths[i + 1])
        if a >= 3000 or b >= 3000:
            i += 1
            continue
        sums.append(a + b)
        i += 2
    if not sums:
        return 0.0, [], 0
    near = sum(1 for s in sums if abs(s - target) <= 0.15 * target)
    # also report the spread: how many distinct 20 us buckets the sums occupy
    buckets = Counter(round(s / 20) * 20 for s in sums)
    occupied = len(buckets)
    return near / len(sums), sorted(buckets.items()), occupied


def unit_seq(widths, te, cap=12000):
    return [round(abs(w) / te) if 0 < abs(w) <= 3000 else 0 for w in widths][:cap]


def longest_repeat(seq, k=16):
    """Longest run of symbols (>= k) that appears at least twice."""
    n = len(seq)
    best = 0
    idx = defaultdict(list)
    for i in range(n - k):
        idx[tuple(seq[i:i + k])].append(i)
    for starts in idx.values():
        if len(starts) < 2:
            continue
        for a in range(len(starts)):
            for b in range(a + 1, len(starts)):
                i, j = starts[a], starts[b]
                m = 0
                while i + m < n and j + m < n and seq[i + m] == seq[j + m] and m < 600:
                    m += 1
                if m > best:
                    best = m
    return best


def acf_peak(seq, minlag=8):
    """Normalised autocorrelation peak (no numpy dependency), lag >= minlag."""
    x = [float(v) for v in seq]
    n = len(x)
    if n < 256:
        return 0.0, 0
    mean = sum(x) / n
    xm = [v - mean for v in x]
    d = sum(v * v for v in xm)
    if d == 0:
        return 0.0, 0
    maxlag = min(3000, n // 2)
    best, bl = 0.0, 0
    for L in range(minlag, maxlag):
        s = 0.0
        for i in range(n - L):
            s += xm[i] * xm[i + L]
        r = s / d
        if r > best:
            best, bl = r, L
    return best, bl


def burst_lengths(widths, gap_us=4000):
    out, cur = [], []
    for w in widths:
        if abs(w) > gap_us:
            if cur:
                out.append(cur)
                cur = []
        else:
            cur.append(w)
    if cur:
        out.append(cur)
    return [len(b) for b in out]


def main():
    args = sys.argv[1:]
    if args:
        cases = [(a, None) for a in args]
    else:
        cases = [(str(CORPUS / f), te) for f, te in DEFAULT]

    print("Renault 33 us fixed-slot PWM model test")
    print("A fixed-5T-slot code needs: pair sums clustered at 5T, and frame repetition.")
    print()

    for f, te_hint in cases:
        p = Path(f)
        if not p.is_file():
            print(f"missing: {p}")
            continue
        widths = parse(p)
        te = te_hint or best_unit(widths)
        near, buckets, occupied = slot_test(widths, te)
        seq = unit_seq(widths, te)
        rep = longest_repeat(seq)
        acf, lag = acf_peak(seq)
        bursts = burst_lengths(widths)

        print("=" * 78)
        print(f"{p.name}")
        print(f"  pulses {len(widths)}  base unit {te:.1f} us")
        print(f"  FIXED SLOT: pair sums within +/-15% of 5T = {near*100:5.1f}%  "
              f"(occupied 20us buckets: {occupied})")
        print(f"              most common pair sums: "
              + ", ".join(f"{s}us x{n}" for s, n in sorted(buckets, key=lambda kv: -kv[1])[:6]))
        print(f"  REPETITION: longest repeated >={16}-symbol run = {rep}   "
              f"ACF peak {acf:.3f} at lag {lag}")
        if bursts:
            top = Counter(bursts).most_common(4)
            print(f"  bursts (>{4000}us gap): {len(bursts)}  "
                  f"modal lengths {[f'{n}x{c}' for n, c in top]}")

        fixed_slot = near > 0.60
        repeats = rep >= 32 and acf > 0.30
        if fixed_slot and repeats:
            verdict = "consistent with the fixed-slot model"
        elif not fixed_slot and not repeats:
            verdict = "NOT the fixed-slot model (no slot, no repeats)"
        elif not fixed_slot:
            verdict = "no fixed slot — PWM model does not hold"
        else:
            verdict = "slots present but no frame repetition"
        print(f"  VERDICT: {verdict}")
        print()


if __name__ == "__main__":
    sys.exit(main())
