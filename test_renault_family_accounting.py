#!/usr/bin/env python3
"""Renault corpus accounting and family separation.

called the non-Hitag2 Renault captures "the ~66 us family" and counted 22
files. This suite pins the corrections so a future decoder port starts from measured
facts rather than from that framing:

  * the corpus is 10 unique captures, not 22 files — 16 of the 26 Renault-named files
    are byte-identical duplicates;
  * the file filter must tokenise, not substring-match: "captur" as a substring also
    matches "Captured" and pulls in Tesla captures;
  * Ren3 is an FSK capture and is out of scope for OOK pulse-width analysis;
  * Ren2 is a clean ~105 us POM-family capture, distinct from the ~33 us group;
  * the ~33 us group is PWM-shaped (2T/3T/4T/5T), not Manchester.
"""

import hashlib
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "tools/renault_family_accounting.py"
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def renault_paths():
    hints = {"renault", "ren2", "ren3", "renault1",
             "captur", "kadjar", "megane", "trafic", "scenic"}
    out = []
    for p in CORPUS.rglob("*.sub"):
        toks = {t for t in re.split(r"[^a-z0-9]+", p.name.lower()) if t}
        parent = set(t for t in re.split(r"[^a-z0-9]+", str(p.parent).lower()) if t)
        if (toks & hints) or "renault" in parent:
            out.append(p)
    return out


def main():
    check("tool present", TOOL.exists())
    if not TOOL.exists():
        return 1

    r = subprocess.run([sys.executable, str(TOOL)], capture_output=True, text=True)
    check("tool runs", r.returncode == 0, r.stderr[:300])
    out = r.stdout

    # --- corpus accounting -------------------------------------------------
    m = re.search(r"Renault-named files: (\d+)\s+unique by content: (\d+)\s+duplicates: (\d+)", out)
    check("accounting header parses", m is not None, out[:200])
    if m:
        named, uniq, dups = (int(x) for x in m.groups())
        check("26 Renault-named files", named == 26, f"got {named}")
        check("10 unique captures", uniq == 10, f"got {uniq}")
        check("16 duplicates", dups == 16, f"got {dups}")
        check("duplicates + unique == named", uniq + dups == named)

    # Independent verification of the same count, not trusting the tool.
    paths = renault_paths()
    groups = defaultdict(list)
    for p in paths:
        groups[hashlib.md5(p.read_bytes()).hexdigest()].append(p)
    check("independent unique count agrees", len(groups) == 10, f"got {len(groups)}")
    check("independent named count agrees", len(paths) == 26, f"got {len(paths)}")

    # --- the substring trap -------------------------------------------------
    tesla = [p for p in renault_paths() if "tesla" in p.name.lower()]
    check("Tesla files excluded from Renault set", not tesla,
          ", ".join(str(p.name) for p in tesla))

    # --- Ren3 is FSK --------------------------------------------------------
    i = out.find("Ren3.sub")
    seg = out[i:i + 700] if i >= 0 else ""
    check("Ren3 identified as FSK", "FSK preset" in seg)
    check("Ren3 flagged out of scope", "out of scope" in seg)

    # --- Ren2 is the clean 105 us family ------------------------------------
    i = out.find("Ren2.sub")
    seg = out[i:i + 700] if i >= 0 else ""
    check("Ren2 best base unit is 105 us", "best 105us" in seg, seg[:200].replace("\n", " "))

    # --- the 33 us PWM group ------------------------------------------------
    for hdr in ("lock_renault.sub", "Renault_Captur_2017_Lock_x5.sub.sub"):
        i = out.find(hdr)
        seg = out[i:i + 700] if i >= 0 else ""
        check(f"{hdr} best base unit is 33 us", "best 33us" in seg)

    # --- the poor captures are flagged -------------------------------------
    i = out.find("Renault1.sub")
    seg = out[i:i + 900] if i >= 0 else ""
    check("Renault1 flagged as poor capture", "fit below 0.70" in seg)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
