# Corpus scorecard

Generated from `research/sources/corpus_regression_result.json` on 2026-10-06.
Re-run with `python3 tools/corpus_regression.py --json research/sources/corpus_regression_result.json`
then `python3 tools/gen_corpus_scorecard.py`.

This is the public ledger behind the decoder-coverage claims in `PROMO.md`.
It is counts and names only — no keys, no hopping codes.

## Summary

| Metric | Value |
| --- | ---: |
| Captures in the run | 301 |
| Decoder functions exercised | 44 |
| Decoders that fired on at least one file | 9 |
| Decoders that never fired | 35 |
| Captures matched by no decoder | 270 |

## Decoders that fire (by file count)

| Decoder | Files |
| --- | ---: |
| `ks_decodePSA` | 7 |
| `ks_decodeToyota` | 7 |
| `ks_decodeChrysler` | 6 |
| `ks_decodeFiatV1` | 4 |
| `ks_decodeKiaV34` | 4 |
| `ks_decodeKiaV1` | 3 |
| `ks_decodeFAAC64` | 2 |
| `ks_decodeEV1527` | 1 |
| `ks_decodeHKR` | 1 |

## Decoders that never fire

- `ks_decodeAnMotors`
- `ks_decodeBMWCAS4`
- `ks_decodeBeninca`
- `ks_decodeCame12`
- `ks_decodeCame24`
- `ks_decodeCameAtomo`
- `ks_decodeCameTwn30`
- `ks_decodeCardin`
- `ks_decodeDEA`
- `ks_decodeFAACSlh`
- `ks_decodeFordV0`
- `ks_decodeHT12E`
- `ks_decodeHormann`
- `ks_decodeKiaV0`
- `ks_decodeKiaV2`
- `ks_decodeKiaV7`
- `ks_decodeLD3`
- `ks_decodeLinear10`
- `ks_decodeMarantec`
- `ks_decodeMazda`
- `ks_decodeNice`
- `ks_decodeNiceFlo`
- `ks_decodePT2240`
- `ks_decodePT2262`
- `ks_decodePhoenixV2`
- `ks_decodeRenaultHitag2`
- `ks_decodeSantaFe`
- `ks_decodeSecPlus`
- `ks_decodeSecPlusV2`
- `ks_decodeSomfy`
- `ks_decodeSommer`
- `ks_decodeSubaru`
- `ks_decodeSubaruV2`
- `ks_decodeV2Phox`
- `ks_decodeVAG`

## Notes

- A fire is a decode the firmware's own gates would accept; the harness
  reproduces `decodeSignal` preprocessing, so host-only false positives are
  not counted.
- Cross-brand fires (a decoder claiming another brand's file) are a separate
  triage; see `research/36_CORPUS_REGRESSION_TRIAGE.md` and
  `research/93_GATE_DECODER_FALSE_POSITIVES.md` when those notes are present.
- The unmatched set is mostly car captures this firmware has no decoder for,
  plus gate/garage protocols that sit in the never-fire list.
