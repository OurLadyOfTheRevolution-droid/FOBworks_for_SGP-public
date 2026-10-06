#!/usr/bin/env python3
"""Tests for the corpus frame-structure scanner (tools/frame_structure_scan.py).

Pins the tallies and the specific separation relies on: the captures that
already have decoders (FIAT, PSA, Renault Trafic Hitag2) score STRONG, while the
frame-less Renault Megane/Captur/Ren2 captures score NONE.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "tools/frame_structure_scan.py"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def run(*args):
    r = subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)
    return r.returncode, r.stdout


def main():
    check("tool present", TOOL.exists())
    if not TOOL.exists():
        return 1

    rc, out = run("--summary")
    check("tool runs", rc == 0)
    check("total is 323", "scanned 323 captures" in out, out.strip().splitlines()[-4:])

    m = re.search(r"STRONG \(>= 64 repeated symbols\): (\d+)", out)
    strong = int(m.group(1)) if m else -1
    check("STRONG count is stable (117)", strong == 117, f"got {strong}")
    check("caveat printed", "NONE is not a verdict" in out)

    rc, ren = run("--path", "renault")
    check("renault slice runs", rc == 0)

    # the four Trafic Hitag2 files are STRONG
    trafic_strong = [ln for ln in ren.splitlines() if "trafic" in ln.lower() and ln.startswith("STRONG")]
    check("Trafic Hitag2 captures are STRONG", len(trafic_strong) == 4, f"got {len(trafic_strong)}")

    # the Megane/Captur/Ren2 files are NONE
    for frag, want in [("Megane_Scenic_2005_lock", "NONE"),
                       ("Captur_2017_Lock_x5.sub.sub", "NONE"),
                       ("Kadjar 2023/Ren2.sub", "NONE")]:
        line = next((ln for ln in ren.splitlines() if frag in ln), None)
        check(f"{frag} scores {want}", line is not None and line.startswith(want),
              line or "missing")

    # controls: FIAT/Punto captures are STRONG
    rc, fiat = run("--path", "punto")
    strong_punto = [ln for ln in fiat.splitlines() if ln.startswith("STRONG")]
    check("Grande Punto captures are STRONG", len(strong_punto) >= 4, f"got {len(strong_punto)}")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
