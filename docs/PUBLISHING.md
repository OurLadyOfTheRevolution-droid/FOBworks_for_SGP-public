# What the published tree is

The public repository is a **disclosure variant** of the development tree, not a
filtered mirror. Three things differ on purpose:

1. **Manufacturer-key literals are masked.** The sketch still carries the 73-entry
   table, but each value is stored transformed and read through `ks_unmaskMfrKey()`.
   Shipping the plaintext corpus file would undo that, so it stays out.
2. **Most of the engineering worklog stays private.** The numbered `research/*.md`
   notes are design history, attack catalog, and round-by-round bench logs. They are
   not part of the published source tree.
3. **A measured-limits subset ships.** Notes that back a public claim — hardware
   audits, falsified models, corpus triage, self-jam measurements — are listed in
   `tools/publish_whitelist.txt` and kept by `tools/publish_stage.sh`. The corpus
   scorecard in `docs/CORPUS_SCORECARD.md` is the ledger behind the decoder-coverage
   numbers in `PROMO.md`.

## What to read first

| Document | Role |
| --- | --- |
| `docs/LIMITATIONS.md` | Measured / host-only / hardware-blocked / falsified |
| `docs/CORPUS_SCORECARD.md` | Live decoder fire counts on the 301-capture corpus |
| `README.md` § Hardware limits | Board pin and radio constraints |
| `PROMO.md` § What this revision can and cannot do | Product-facing limits |

## How a release is staged

```bash
tools/publish_stage.sh main /tmp/pubtree
python3 tools/publish_check.py /tmp/pubtree
```

`publish_check.py` fails the tree if a worklog pointer was left dangling, if the
PROMO corpus counts disagree with the scorecard, or if the firmware version and
`CITATIONS_AND_REFERENCES.md` disagree.
