#!/usr/bin/env python3
"""Compare two or more .sub captures of the same press, taken on different devices.

Why this exists: the corpus has been the only input this project has had, and research/38
showed its scaling is unreliable -- some Kia captures sit at 2.0x nominal, which is a
capture-method artefact rather than a property of the fob. A single capture cannot show whether
a strange pulse timebase is the fob or the recorder.

Two independently-recorded captures of the same press can. If both devices report the same
cluster widths, the timebase is a property of the fob and a decoder should model it. If they
disagree, the earlier measurement was an artefact of one device's capture path and no decoder
change would have been correct.

Reports per file: header, pulse count, trim result, the dominant widths, and the k-means
values as decodeSignal computes them. Then compares the dominant width clusters across files
and says whether they agree.

Usage:
    python3 tools/compare_captures.py a.sub b.sub [c.sub ...]
    python3 tools/compare_captures.py --tol 0.10 a.sub b.sub
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sub_probe import header_of, parse_sub, build_exe, SKETCH  # noqa: E402


def dominant(widths, top=8):
    """The most common pulse widths, as (width, count), with near-duplicates merged.

    Widths are quantised by the recorder, so 98 and 99 and 100 are the same cluster. Merging
    within 8% keeps a one-microsecond jitter from splitting a cluster in two, which would make
    two captures of the same press look like they disagreed when they did not.
    """
    c = Counter(widths)
    ordered = sorted(c.items(), key=lambda t: -t[1])
    merged = []
    for w, n in ordered:
        for m in merged:
            if abs(w - m["w"]) <= max(2, 0.08 * m["w"]):
                m["n"] += n
                m["w"] = (m["w"] * (m["n"] - n) + w * n) // m["n"]
                break
        else:
            merged.append({"w": w, "n": n})
    merged.sort(key=lambda m: -m["n"])
    return merged[:top]


def probe(exe, tmp, widths, mhz):
    pf = tmp / "in.txt"
    pf.write_text(f"{mhz}\n" + "\n".join(str(w) for w in widths), encoding="utf-8")
    import subprocess
    out = subprocess.run([str(exe), str(pf)], capture_output=True, text=True).stdout
    info = {"raw": out}
    for ln in out.splitlines():
        if ln.startswith("T "):
            m = re.search(r"trim=(\d+) n=(\d+) of raw=(\d+)", ln)
            if m:
                info["trim"], info["n"], info["raw_n"] = (
                    int(m.group(1)), int(m.group(2)), int(m.group(3)))
        elif ln.startswith("K "):
            for kv in ln[2:].split():
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    info[k] = v
        elif ln.startswith("S "):
            for kv in ln[2:].split():
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    info[k] = int(v)
    # widths reported by the probe are from the TRIMMED frame when a trim succeeded, which is
    # the frame a decoder would see, so prefer them for the cluster comparison
    hist = ""
    for ln in out.splitlines():
        if ln.startswith("H "):
            hist = ln[2:].strip()
    pw = []
    for tok in hist.split():
        if ":" in tok:
            w, c = tok.split(":")
            pw.append((int(w), int(c)))
    return info, pw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--tol", type=float, default=0.15,
                    help="relative tolerance for cluster agreement (default 0.15 = 15%%)")
    args = ap.parse_args()

    import tempfile
    src = SKETCH.read_text(encoding="utf-8")

    measured = []
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        exe = build_exe(src, tmp, trim=True)
        for fp in args.files:
            p = Path(fp)
            if not p.is_file():
                print(f"missing: {p}", file=sys.stderr)
                return 2
            widths, mhz = parse_sub(p)
            hdr = header_of(p)
            info, pw = probe(exe, tmp, widths, mhz)
            dom = dominant(widths)
            measured.append({"path": p, "hdr": hdr, "mhz": mhz, "info": info,
                             "widths": widths, "dom": dom, "probe_pw": pw})

    print("=" * 82)
    for i, m in enumerate(measured):
        print(f"[{i}] {m['path'].name}")
        print(f"     {m['hdr'].get('Frequency','?')} Hz  preset={m['hdr'].get('Preset','?')}"
              f"  pulses={len(m['widths'])}")
        if "trim" in m["info"]:
            print(f"     trim={m['info']['trim']} -> {m['info']['n']} of {m['info']['raw_n']} pulses")
        print(f"     dominant widths: " +
              ", ".join(f"{d['w']}us x{d['n']}" for d in m["dom"]))
        k = m["info"]
        print(f"     k-means: cA={k.get('cA','?')} cB={k.get('cB','?')} "
              f"ratio={k.get('ratio','?')} km={k.get('km','?')} "
              f"preamble_pairs={k.get('maxpc','?')} accepted={k.get('accepted','?')}")
        print()

    # ── agreement ────────────────────────────────────────────────────────────
    # Compare the dominant clusters pairwise. The question is whether the SAME set of pulse
    # widths shows up in every capture, which is what makes a timebase a property of the fob.
    if len(measured) > 1:
        print("=" * 82)
        print("cluster agreement  (a width counts as present if some cluster is within "
              f"{args.tol:.0%})")
        base = measured[0]
        base_clusters = base["dom"]
        print(f"  reference: {base['path'].name}")
        for m in measured[1:]:
            matches = []
            for b in base_clusters:
                best = None
                for d in m["dom"]:
                    if b["w"] > 0 and abs(d["w"] - b["w"]) <= args.tol * b["w"]:
                        if best is None or abs(d["w"] - b["w"]) < abs(best - b["w"]):
                            best = d["w"]
                matches.append((b["w"], best))
            hit = sum(1 for _b, mw in matches if mw is not None)
            detail = ", ".join(f"{b}->{mw if mw is not None else 'MISSING'}"
                               for b, mw in matches)
            verdict = ("AGREE" if hit == len(matches) else
                       "PARTIAL" if hit else "DISAGREE")
            print(f"  {m['path'].name}")
            print(f"     {hit}/{len(matches)} clusters matched  [{verdict}]  {detail}")

        print()
        print("Interpretation:")
        print("  AGREE on every cluster  -> the timebase belongs to the fob; a decoder should")
        print("                             model these widths, and the corpus reading was real.")
        print("  DISAGREE / PARTIAL      -> at least one capture path is distorting the pulses;")
        print("                             no decoder change would have been correct.")
        print("  Note: differing COUNTERS do not matter here. This compares pulse widths only,")
        print("        so two presses of a rolling fob are still comparable.")
        # A short capture genuinely cannot exhibit every cluster, so a PARTIAL result from a
        # few hundred pulses is not evidence of a capture-path problem. Say so, because the
        # wrong conclusion here would send someone chasing a fault in their own hardware.
        thin = [m for m in measured if len(m["widths"]) < 600]
        if thin:
            print()
            print("  CAVEAT: these captures have few pulses, so some clusters may simply be "
                  "absent")
            for m in thin:
                print(f"    {m['path'].name}: {len(m['widths'])} pulses")
            print("    A PARTIAL result from a short capture is not evidence of distortion.")
            print("    Re-capture with a longer press before concluding anything.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
