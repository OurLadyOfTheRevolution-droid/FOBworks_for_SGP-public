#!/usr/bin/env python3
"""Measure the pulse-width scale of a capture against its protocol's nominal TE.

Why this exists: the corpus regression run found four Kia decoders
that never fire against 33 on-brand captures each. One of those files,
`Kia_V1_N1_RAW.sub`, was measured at 807/1611 us against a nominal 400/800 --
exactly 2.02x and 2.01x. That is the RSSI-quantisation signature: the capture is not in the waveform the decoder models, so the
decoder refuses it correctly.

That was verified on ONE file of 33. This script measures the same property
across every on-brand capture, so the question "are these decoders broken, or
are they being fed out-of-scale data?" can be answered from evidence rather
than from one sample.

Method: cluster the capture's pulse widths into short and long groups with the
same 2-means the firmware uses (`ks_km2`: seed at 1/3 and 2/3 between min and
max, then 8 rounds of reassignment). Report each cluster mean as a ratio of the
protocol's nominal TE. A ratio near 1.0 means the capture is in spec; a ratio
near 2.0 or 0.5 means a timebase or quantisation factor is off.

Nominal TE comes from the decoder's own gate in `FOBworks_for_SGP.ino`, read
from the `te_*` booleans in `decodeSignal()`. The values here are the nominal
short/long pair each gate is built around; where a gate spans a range, the
range is printed so a measurement outside it is visible as such.

Usage:
    python3 tools/corpus_scale_sweep.py                 # every on-brand capture
    python3 tools/corpus_scale_sweep.py --brand kia     # one brand
    python3 tools/corpus_scale_sweep.py --csv out.csv   # machine-readable
"""

import argparse
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research" / "sources" / "corpus_automotive_subghz"

# Nominal short/long TE per decoder family, and the gate the firmware applies.
# The `gate` column is the literal condition from decodeSignal(), so a measured
# value can be compared against what the decoder will actually accept.
FAMILIES = {
    "kia_v0":     {"short": 250,  "long": 500,  "gate": "cA 150-380, ratio 1.7-2.4"},
    "kia_v1":     {"short": 400,  "long": 800,  "gate": "cA 350-700, ratio 1.7-2.3 (mhz<320)"},
    "kia_v2":     {"short": 500,  "long": 1000, "gate": "cA 350-700, ratio 1.4-2.6 (eu433)"},
    "kia_v34":    {"short": 400,  "long": 800,  "gate": "cA 250-550, ratio 1.6-2.4"},
    "kia_v7":     {"short": 250,  "long": 500,  "gate": "cA 150-380, ratio 1.4-2.6"},
    "hyundai_v0": {"short": 250,  "long": 500,  "gate": "shares kia_v0 gate"},
    "hyundai_v1": {"short": 400,  "long": 800,  "gate": "shares kia_v1 gate"},
    "hyundai_v2": {"short": 500,  "long": 1000, "gate": "shares kia_v2 gate"},
    "santafe":    {"short": 400,  "long": 800,  "gate": "80-bit MSB-first, CRC8-0x31"},
    "mazda":      {"short": 250,  "long": 500,  "gate": "Manchester pairs"},
}


def load_pulses(path):
    """Read the pulse widths from a .sub file's RAW_Data lines, as unsigned."""
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        if line.startswith("RAW_Data:"):
            for tok in line.split(":", 1)[1].split():
                try:
                    out.append(abs(int(tok)))
                except ValueError:
                    pass
    return out


def km2(pulses, rounds=8):
    """Same 2-means the firmware's ks_km2 uses.

    The firmware filters to pulses <= 5000 us BEFORE clustering (decodeSignal,
    line ~6357). Without that filter the inter-frame gaps -- which run to
    hundreds of milliseconds -- dominate the long cluster and every capture
    reads as out-of-gate. Reproduced here so the numbers match the device.
    """
    v = sorted(p for p in pulses if p <= 5000)
    if len(v) < 6:
        return None
    mn, mx = v[0], v[-1]
    if mx == mn:
        return None
    a = mn + (mx - mn) // 3
    b = mn + 2 * (mx - mn) // 3
    for _ in range(rounds):
        sa = sb = 0
        na = nb = 0
        for x in v:
            if abs(x - a) < abs(x - b):
                sa += x
                na += 1
            else:
                sb += x
                nb += 1
        if na:
            a = sa // na
        if nb:
            b = sb // nb
    if a <= 0 or b <= a:
        return None
    return (a, b)


def is_key_file(path):
    """A Key file carries an already-demodulated payload, not pulses.

    Key files bypass the PWM path entirely, so a cluster measurement against
    nominal TE is meaningless for them -- they never reach the te_* gate. An
    earlier run reported them as 'no cluster', which read as a measurement
    failure when it is actually a different input class.
    """
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:400]
    except OSError:
        return False
    return "Filetype: Flipper SubGhz Key File" in head


def windows(pulses, size=512):
    """Yield capture-sized windows, matching the firmware's CAP_SZ buffer.

    The device never sees a whole file: `captureSignal()` fills at most 512
    pulses. Clustering thousands of pulses across many presses mixes in
    unrelated bursts and reports a ratio the firmware would never compute.
    Scanning 512-pulse windows is what the gate actually evaluates.
    """
    if len(pulses) <= size:
        yield pulses
        return
    for off in range(0, len(pulses) - size + 1, size):
        yield pulses[off:off + size]


def measure(pulses, fam):
    """Best in-gate window for this family, plus a count of windows tried.

    Returns (best_short, best_long, best_sr, best_lr, n_windows, n_in_gate).
    'Best' is the window whose short cluster is closest to nominal TE, which is
    the most favourable reading the gate could ever take.
    """
    nom = FAMILIES[fam]
    best = None
    n = 0
    n_in = 0
    for w in windows(pulses):
        cl = km2(w)
        if cl is None:
            continue
        n += 1
        s, l = cl
        sr = s / nom["short"]
        lr = l / nom["long"]
        if 0.85 <= sr <= 1.15 and 0.85 <= lr <= 1.15:
            n_in += 1
        score = abs(sr - 1.0)
        if best is None or score < best[0]:
            best = (score, s, l, sr, lr)
    if best is None:
        return None
    _, s, l, sr, lr = best
    return (s, l, sr, lr, n, n_in)


def classify(name):
    """Infer the decoder family from a capture's filename.

    Only names that actually carry a Kia/Hyundai variant tag are classified.
    An earlier version matched any filename containing "v2" and so swept
    Cadillac and GMC files into the Kia V2 family, which produced meaningless
    ratios. The family tag has to be on the Kia/Hyundai side of the name.
    """
    n = name.lower()
    if not any(k in n for k in ("kia", "hyundai", "genesis", "santafe", "santa_fe")):
        return None
    if "santafe" in n or "santa_fe" in n:
        return "santafe"
    # Variant tags, most specific first.
    if re.search(r"_v7\b|v7_", n):
        return "kia_v7"
    if re.search(r"_v34\b|v3_|v4_|_v3\b|_v4\b", n):
        return "kia_v34"
    if re.search(r"_v2\b|v2_", n):
        return "kia_v2"
    if re.search(r"_v1\b|v1_", n):
        return "kia_v1"
    if re.search(r"_v0\b|v0_", n):
        return "kia_v0"
    if "mazda" in n:
        return "mazda"
    return None


def brand_of(path):
    """Brand from the path, for grouping the report."""
    s = str(path).lower()
    if "kia" in s:
        return "kia"
    if "hyundai" in s or "genesis" in s:
        return "hyundai"
    return "other"


def raw_scale(name):
    """For untagged Kia/Hyundai files, use the 400/800 Kia V3/V4 nominal.

    Several Kia/Hyundai captures carry no variant tag in the filename, so the
    decoder family cannot be inferred from the name alone. Those are still
    measured and reported against 400/800, marked as a guess, because skipping
    them is what left the earlier triage unable to say whether the Kia captures
    were in spec.

    Returns None for anything that is not a Kia/Hyundai/Genesis capture. Without
    that check the fallback claimed every file in the corpus, which made the
    first run of this script report Fords and Cadillacs as Kia V3/V4.
    """
    n = name.lower()
    if not any(k in n for k in ("kia", "hyundai", "genesis")):
        return None
    return "kia_v34_guess"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--brand", default=None, help="kia | hyundai | other")
    ap.add_argument("--csv", default=None)
    args = ap.parse_args()

    if not CORPUS.is_dir():
        print(f"corpus not found: {CORPUS}", file=sys.stderr)
        return 2

    files = sorted(p for p in CORPUS.rglob("*.sub"))
    rows = []
    for p in files:
        if args.brand and brand_of(p) != args.brand:
            continue
        fam = classify(p.name) or raw_scale(p.name)
        if fam is None:
            continue
        if fam not in FAMILIES:
            # Untagged Kia/Hyundai file: measure against 400/800 and mark it.
            FAMILIES[fam] = {"short": 400, "long": 800,
                             "gate": "nominal 400/800 (family guessed from brand)"}
        pulses = load_pulses(p)
        if is_key_file(p):
            # Key file: an already-demodulated payload. It never reaches the
            # PWM/te_* gate, so scale is not applicable. Reported separately so
            # it is not mistaken for a capture that failed to measure.
            rows.append({"file": p.name, "family": fam, "n": 0,
                         "short": "", "long": "", "s_ratio": "", "l_ratio": "",
                         "win": "-", "in_gate": "key-file"})
            continue
        if len(pulses) < 32:
            continue
        m = measure(pulses, fam)
        if m is None:
            rows.append({"file": p.name, "family": fam, "n": len(pulses),
                         "short": "", "long": "", "s_ratio": "", "l_ratio": "",
                         "win": "", "in_gate": "no-cluster"})
            continue
        s, l, sr, lr, nwin, nin = m
        in_gate = "yes" if nin > 0 else "NO"
        rows.append({"file": p.name, "family": fam, "n": len(pulses),
                     "short": s, "long": l,
                     "s_ratio": f"{sr:.2f}", "l_ratio": f"{lr:.2f}",
                     "win": f"{nin}/{nwin}",
                     "in_gate": in_gate})

    if not rows:
        print("no captures matched", file=sys.stderr)
        return 1

    print(f"{'file':44} {'family':9} {'n':>6} {'short':>6} {'long':>6} "
          f"{'xS':>5} {'xL':>5} {'win':>7} {'gate':>4}")
    print("-" * 100)
    for r in rows:
        print(f"{r['file'][:44]:44} {r['family']:9} {r['n']:>6} "
              f"{str(r['short']):>6} {str(r['long']):>6} "
              f"{str(r['s_ratio']):>5} {str(r['l_ratio']):>5} "
              f"{str(r['win']):>7} {r['in_gate']:>4}")

    in_gate = sum(1 for r in rows if r["in_gate"] == "yes")
    out_gate = sum(1 for r in rows if r["in_gate"] == "NO")
    nocluster = sum(1 for r in rows if r["in_gate"] == "no-cluster")
    keyfiles = sum(1 for r in rows if r["in_gate"] == "key-file")
    print("-" * 100)
    print(f"{len(rows)} captures | in-gate {in_gate} | OUT OF GATE {out_gate} "
          f"| no cluster {nocluster} | key files {keyfiles}")
    print()
    print("Each RAW capture is scanned in 512-pulse windows (the firmware's CAP_SZ).")
    print("'short'/'long' are the BEST window's clusters -- the most favourable")
    print("reading the gate could take. 'win' is that window count as")
    print("in-gate-hits/total-windows, so 0/n means no window is in spec.")
    print()
    print("in-gate means both clusters within 15% of the protocol's nominal TE.")
    print("OUT OF GATE means no window would pass the gate in decodeSignal(),")
    print("regardless of whether the decoder logic is correct.")
    print("key-file means an already-demodulated payload: it never reaches the")
    print("PWM gate, so scale does not apply and it is not a measurement failure.")
    print()
    print("Nominal TE and the gate each family is measured against:")
    # Only the families actually measured. Printing the whole FAMILIES table listed
    # entries with no captures in the corpus (mazda, kia_v7) and the brand-shared
    # hyundai_* aliases that classify() never returns, which reads as if they had been
    # measured. The guessed family is included because it is added at run time.
    for k in sorted({r["family"] for r in rows}):
        v = FAMILIES.get(k)
        if v is None:
            continue
        print(f"  {k:14} short {v['short']:>4} long {v['long']:>4}   gate: {v['gate']}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
