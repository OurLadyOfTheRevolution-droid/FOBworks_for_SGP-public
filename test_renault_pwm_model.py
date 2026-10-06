#!/usr/bin/env python3
"""Falsification suite for the Renault fixed-slot PWM model.

proposed that the Megane/Captur "33 us" captures are a fixed-5T-slot PWM
code. This suite runs tools/renault_pwm_model_test.py and pins the finding that the
model does not hold, and — just as important — that the metric which says so is not
broken, because it finds repeated frames in the FIAT controls from the same corpus.

  * every Renault 33 us capture has zero repeated >=16-symbol runs;
  * the FIAT controls have hundreds of repeated symbols (so the test works);
  * pair sums do not cluster at 5T for any Renault capture;
  * the verdict line says the model does not hold.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "tools/renault_pwm_model_test.py"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def parse_blocks(out):
    """Return {filename: {field: value}} from the tool output."""
    blocks = {}
    name = None
    for line in out.splitlines():
        if line.startswith("=" * 10):
            name = None
            continue
        if line.strip() and not line.startswith(" ") and not line.startswith("Renault 33"):
            if line.rstrip().endswith(".sub") or line.rstrip().endswith(".sub.sub"):
                name = line.strip()
                blocks[name] = {}
                continue
        if name and ":" in line:
            head, _, rest = line.strip().partition(":")
            blocks[name][head.strip()] = rest.strip()
    return blocks


def num(block, key):
    """Pull the first number out of a field."""
    import re
    v = block.get(key, "")
    m = re.search(r"-?\d+(?:\.\d+)?", v)
    return float(m.group(0)) if m else None


def main():
    check("tool present", TOOL.exists())
    if not TOOL.exists():
        return 1

    r = subprocess.run([sys.executable, str(TOOL)], capture_output=True, text=True)
    check("tool runs", r.returncode == 0, r.stderr[:300])
    out = r.stdout
    blocks = parse_blocks(out)
    check("parsed capture blocks", len(blocks) >= 6, f"got {len(blocks)}")

    renault = {k: v for k, v in blocks.items() if "Renault" in k or k.startswith("Ren2")}
    fiat = {k: v for k, v in blocks.items() if "Fiat" in k or "open.sub" in k}

    check("found Renault blocks", len(renault) >= 6, f"got {len(renault)}")
    check("found FIAT controls", len(fiat) >= 2, f"got {len(fiat)}")

    # --- the core finding: no repeated frames in the Renault captures --------
    for name, blk in renault.items():
        rep = num(blk, "REPETITION")
        # block text is "longest repeated >=16-symbol run = N   ACF peak ..."
        check(f"{name}: zero repeated frame runs",
              "run = 0" in blk.get("REPETITION", ""),
              blk.get("REPETITION", ""))

    # --- the metric is not broken: FIAT controls repeat ----------------------
    for name, blk in fiat.items():
        import re
        m = re.search(r"run = (\d+)", blk.get("REPETITION", ""))
        got = int(m.group(1)) if m else -1
        check(f"{name}: control shows repeated frames (>{200})", got > 200, f"got {got}")

    # --- no fixed slot anywhere in the Renault set --------------------------
    for name, blk in renault.items():
        import re
        m = re.search(r"5T = \s*([\d.]+)%", blk.get("FIXED SLOT", ""))
        share = float(m.group(1)) if m else 100.0
        check(f"{name}: pair sums do NOT cluster at 5T (<20%)", share < 20.0, f"got {share}%")

    # --- verdict lines -------------------------------------------------------
    n_bad = out.count("NOT the fixed-slot model")
    check("verdict flags the Renault captures", n_bad >= 5, f"got {n_bad}")
    check("no capture is judged consistent with the model",
          "consistent with the fixed-slot model" not in out)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
