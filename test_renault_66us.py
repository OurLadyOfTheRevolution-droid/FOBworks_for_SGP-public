#!/usr/bin/env python3
"""Renault ~66 us family reconnaissance suite (tools/renault_66us_family.py).

separated the Renault corpus into one Hitag2 recording and everything
else. This suite pins the characterisation of "everything else" so a future decoder
port starts from measured facts:

  * Captur 2017 and Megane/Scenic 2005 are OOK with a ~33 us base unit and PWM
    symbol widths at 2T/3T/4T/5T (66/100/132/166 us) — NOT Manchester, which is why
    no Hitag2 decoder can claim them;
  * the Kadjar "Ren" files are a different group (a different base unit), so the
    corpus is at least two families, not one;
  * the tool itself runs and reports a candidate base unit per file.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "tools/renault_66us_family.py"
CORPUS = ROOT / "research/sources/corpus_automotive_subghz/European/Renault"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def main():
    if not TOOL.exists():
        check("tool present", False)
        return 1
    r = subprocess.run([sys.executable, str(TOOL)], capture_output=True, text=True)
    check("tool runs", r.returncode == 0, r.stderr[:200])
    out = r.stdout

    # Per-file: find each section and its candidate base unit.
    def base_unit(header):
        i = out.find(header)
        if i < 0:
            return None
        seg = out[i:i + 900]
        m = re.search(r"candidate base unit: (\d+) us", seg)
        return int(m.group(1)) if m else None

    import re
    cap_lock = base_unit("Renault_Captur_2017_Lock_x5.sub.sub")
    meg_lock = base_unit("Renault_Megane_Scenic_2005_lock.sub")
    ren2 = base_unit("Ren2.sub")
    check("Captur 2017 base unit ~33 us", cap_lock == 33, f"got {cap_lock}")
    check("Megane 2005 base unit ~33 us", meg_lock == 33, f"got {meg_lock}")
    check("Kadjar Ren2 is a different family (not 33 us)",
          ren2 is not None and ren2 != 33, f"got {ren2}")

    # Captur must show the 2T/3T/4T/5T symbol set, which rules out Manchester.
    i = out.find("Renault_Captur_2017_Lock_x5.sub.sub")
    seg = out[i:i + 500]
    for w in ("66x", "100x", "132x", "166x"):
        check(f"Captur shows {w.rstrip('x')} us symbol", w in seg)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
