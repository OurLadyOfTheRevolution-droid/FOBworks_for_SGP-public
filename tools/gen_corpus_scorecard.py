#!/usr/bin/env python3
"""Build docs/CORPUS_SCORECARD.md from research/sources/corpus_regression_result.json."""
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "research/sources/corpus_regression_result.json"
OUT = ROOT / "docs/CORPUS_SCORECARD.md"


def main():
    if not SRC.exists():
        print(f"missing {SRC}; run tools/corpus_regression.py --json {SRC}", file=sys.stderr)
        return 1
    d = json.loads(SRC.read_text(encoding="utf-8"))
    decoders = d["decoders"]
    never = sorted(d["never_fire"])
    none = d["matched_none"]
    per = d["per_file"]
    rows = sorted(((n, len(f)) for n, f in decoders.items()), key=lambda kv: (-kv[1], kv[0]))
    fired = [r for r in rows if r[1] > 0]

    lines = [
        "# Corpus scorecard",
        "",
        f"Generated from `research/sources/corpus_regression_result.json` on {date.today().isoformat()}.",
        "Re-run with `python3 tools/corpus_regression.py --json research/sources/corpus_regression_result.json`",
        "then `python3 tools/gen_corpus_scorecard.py`.",
        "",
        "This is the public ledger behind the decoder-coverage claims in `PROMO.md`.",
        "It is counts and names only — no keys, no hopping codes.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Captures in the run | {len(per)} |",
        f"| Decoder functions exercised | {len(decoders)} |",
        f"| Decoders that fired on at least one file | {len(fired)} |",
        f"| Decoders that never fired | {len(never)} |",
        f"| Captures matched by no decoder | {len(none)} |",
        "",
        "## Decoders that fire (by file count)",
        "",
        "| Decoder | Files |",
        "| --- | ---: |",
    ]
    for name, n in fired:
        lines.append(f"| `{name}` | {n} |")
    lines += ["", "## Decoders that never fire", ""]
    for name in never:
        lines.append(f"- `{name}`")
    lines += [
        "",
        "## Notes",
        "",
        "- A fire is a decode the firmware's own gates would accept; the harness",
        "  reproduces `decodeSignal` preprocessing, so host-only false positives are",
        "  not counted.",
        "- Cross-brand fires (a decoder claiming another brand's file) are a separate",
        "  triage; see `research/36_CORPUS_REGRESSION_TRIAGE.md` and",
        "  `research/93_GATE_DECODER_FALSE_POSITIVES.md` when those notes are present.",
        "- The unmatched set is mostly car captures this firmware has no decoder for,",
        "  plus gate/garage protocols that sit in the never-fire list.",
        "",
    ]
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
