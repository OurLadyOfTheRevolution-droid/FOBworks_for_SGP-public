#!/usr/bin/env python3
"""Gate a staged public tree before it is committed.

Fails on:
  · a bare worklog pointer (, `) left in prose
  · a stranded connective at end of line (", and" / " and")
  · PROMO corpus counts that disagree with docs/CORPUS_SCORECARD.md
  · FW_VER / README / CITATIONS version disagreement
  · a whitelist note missing from research/
  · plaintext manufacturer-key corpus present
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
FAIL: list[str] = []

# Bare numeric id only — not 7_RENAULT_….md (the (?!\d) stops
# backtracking into inside _…).
BARE_REF = re.compile(r"(?<![A-Za-z0-9_/])research/\d+(?!\d)(?!_[A-Za-z0-9])")
WORKLOG = re.compile(r"\bworklog[ \t]*`?\d+", re.I)
# Only the stranded ", and" left after a clause was removed — not a line that
# merely wraps on the word "and".
STRAND = re.compile(r",[ \t]+and[ \t]*$")
VER_FW = re.compile(r'#define\s+FW_VER\s+"FOBworks for SGP v([0-9.]+)"')
VER_README = re.compile(r"Version\s+([0-9.]+)\.")
VER_CITE = re.compile(r"FOBworks for SGP v([0-9.]+)")
PROMO_NEVER = re.compile(r"(\d+)\s+have never fired on the corpus")
PROMO_NONE = re.compile(r"(\d+)\s+of\s+(\d+)\s+captures are matched by none")
SCORE_NEVER = re.compile(r"\| Decoders that never fired \| (\d+) \|")
SCORE_NONE = re.compile(r"\| Captures matched by no decoder \| (\d+) \|")
SCORE_FILES = re.compile(r"\| Captures in the run \| (\d+) \|")


def fail(msg: str) -> None:
    FAIL.append(msg)
    print("FAIL  " + msg)


def ok(msg: str) -> None:
    print("ok    " + msg)


def main() -> int:
    if not (ROOT / "FOBworks_for_SGP.ino").exists():
        fail(f"not a staged tree: {ROOT}")
        return 1

    # whitelist present
    wl = Path(__file__).resolve().parent / "publish_whitelist.txt"
    names = []
    for line in wl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
        p = ROOT / "research" / line
        if not p.exists():
            fail(f"whitelist note missing: research/{line}")
        else:
            ok(f"whitelist present: research/{line}")

    # secrets that must not ship
    if (ROOT / "research/sources/keeloq_mfcodes_public.txt").exists():
        fail("plaintext key corpus is present")
    else:
        ok("plaintext key corpus absent")
    if (ROOT / "research/sources/corpus_regression_result.json").exists():
        fail("raw regression JSON is present (scorecard should ship instead)")
    else:
        ok("raw regression JSON absent")

    # docs
    for rel in ("docs/LIMITATIONS.md", "docs/PUBLISHING.md", "docs/CORPUS_SCORECARD.md"):
        if not (ROOT / rel).exists():
            fail(f"missing {rel}")
        else:
            ok(f"present {rel}")

    # Dangling refs / stranded connectives on the honesty surfaces only.
    # The sketch comments wrap on ", and" constantly; that is not a strip defect.
    # tools/publish_prepare.py documents bare-ref patterns on purpose.
    # Bare worklog ids must not appear on any shipped honesty surface, including
    # the measured-limits notes (cite sibling notes by full filename instead).
    ref_paths = [
        ROOT / "PROMO.md",
        ROOT / "README.md",
        ROOT / "CITATIONS_AND_REFERENCES.md",
        *sorted((ROOT / "docs").glob("*.md")),
        *sorted((ROOT / "research").glob("*.md")),
    ]
    for path in ref_paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(ROOT)
        for i, line in enumerate(text.splitlines(), 1):
            if BARE_REF.search(line) or WORKLOG.search(line):
                fail(f"bare worklog ref {rel}:{i}: {line.strip()[:120]}")

    # Stranded ", and" only on the front-door docs — research notes wrap on
    # ", and" as ordinary prose.
    for path in (ROOT / "PROMO.md", ROOT / "README.md", ROOT / "CITATIONS_AND_REFERENCES.md",
                 *sorted((ROOT / "docs").glob("*.md"))):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(ROOT)
        for i, line in enumerate(text.splitlines(), 1):
            if STRAND.search(line):
                fail(f"stranded connective {rel}:{i}: {line.strip()[:120]}")

    # versions
    sketch = (ROOT / "FOBworks_for_SGP.ino").read_text(encoding="utf-8", errors="replace")
    readme = (ROOT / "README.md").read_text(encoding="utf-8", errors="replace")
    cite = (ROOT / "CITATIONS_AND_REFERENCES.md").read_text(encoding="utf-8", errors="replace")
    fw = VER_FW.search(sketch)
    rm = VER_README.search(readme)
    ct = VER_CITE.search(cite)
    if not (fw and rm and ct):
        fail("could not parse version from sketch/README/CITATIONS")
    elif not (fw.group(1) == rm.group(1) == ct.group(1)):
        fail(f"version mismatch sketch={fw.group(1)} README={rm.group(1)} CITATIONS={ct.group(1)}")
    else:
        ok(f"version aligned at v{fw.group(1)}")

    # PROMO vs scorecard
    promo = (ROOT / "PROMO.md").read_text(encoding="utf-8", errors="replace")
    score = (ROOT / "docs/CORPUS_SCORECARD.md").read_text(encoding="utf-8", errors="replace")
    pn, pnone, pfiles = PROMO_NEVER.search(promo), PROMO_NONE.search(promo), None
    sn, snone, sfiles = SCORE_NEVER.search(score), SCORE_NONE.search(score), SCORE_FILES.search(score)
    if not (pn and pnone and sn and snone and sfiles):
        fail("could not parse PROMO/scorecard corpus counts")
    else:
        if int(pn.group(1)) != int(sn.group(1)):
            fail(f"never-fire PROMO={pn.group(1)} scorecard={sn.group(1)}")
        elif int(pnone.group(1)) != int(snone.group(1)) or int(pnone.group(2)) != int(sfiles.group(1)):
            fail(f"unmatched PROMO={pnone.group(1)}/{pnone.group(2)} "
                 f"scorecard={snone.group(1)}/{sfiles.group(1)}")
        else:
            ok(f"PROMO matches scorecard "
               f"({pn.group(1)} never-fire, {pnone.group(1)}/{pnone.group(2)} unmatched)")

    print()
    if FAIL:
        print(f"{len(FAIL)} check(s) failed")
        return 1
    print("publish_check: all gates green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
