# 93 — The gate decoders were claiming noise, and the fix is geometric, not content

Status: closed, host-verified. The corpus regression (`36`) found the `te_*` gates that
admit the Somfy, Nice and FAAC64 decoders were letting them fire on captures of other
brands. Two of the three then reported mutually exclusive identities for the *same* Tesla
waveform. This is the "confident-but-wrong" class the project exists to remove: a wrong
labelled decode is worse than no decode, because it puts a fake address into the history
ring and a fake prediction in front of a locksmith.

Read with `36` (the false-positive triage this closes part of), `40` (the same defect shape
in the Toyota gate — a guard that admitted the wrong population), and `63` (the per-slice
consensus vote reused here).

## 1. What the regression measured

`tools/corpus_regression.py` runs the real C++ decoders, extracted verbatim from the sketch,
over all 301 corpus captures with `decodeSignal`'s own preprocessing and gates. Three gate
decoders were committing on non-brand captures:

| decoder | files | brands | distinct ids |
| --- | --- | --- | --- |
| `ks_decodeSomfy` | 9 | 6 (Tesla, Nissan, VW, Audi, Mercedes…) | 4 |
| `ks_decodeNice` | 6 | 4 (Tesla, Nissan/Subaru, Renault) | 3 |
| `ks_decodeFAAC64` | 2 | 1 (Chrysler Pacifica) | — |

The Somfy and Nice sets overlap on the two Tesla files and the Subaru file: one waveform, two
confident identities. That is the same signature `36` used to condemn the KiaV2 and FordV0
false positives, and the reason the project treats a firing decoder as a claim to verify, not
a result.

## 2. The accept-rate measurement that framed everything

Before touching a threshold, the decoders were run against random bit strings to find out how
much rejecting power they actually have. A decoder that accepts almost everything cannot be
fixed by narrowing its geometry; it needs a second, independent signal.

| decoder | window | random-bit accept rate |
| --- | --- | --- |
| `ks_decodeSomfy` | 56-bit, nibble-XOR checksum | **6.18%** |
| `ks_decodeNice` | 52-bit, "40–60% ones" entropy | **99.99%** |
| `ks_decodeFAAC64` | 64-bit, several skew/uniformity guards | **99.997%** |

The Nice and FAAC64 "entropy gates" reject essentially nothing — a random window passes them
almost always. That single number explains why they fire wherever their `te_*` gate opens,
and it fixed the shape of the remedy: for those two, a geometric window cannot separate a
real frame from noise, because the decoder is nearly blind to content.

## 3. Two discriminators measured and falsified

The obvious content fixes were tried and rejected on evidence, and the measurements are kept
here so nobody re-derives them.

**`maxAltRun`** — the longest strictly-alternating run in the bit stream, on the theory that
the false captures are carrier-toned (the Tesla head is 56 bits of `1010…`). It does separate
the *whole capture* (Tesla 448, left-blink van 508, Renault 25). It fails on genuine frames:
a Somfy frame built by `buildSomfyRTS` decodes to an 87-bit stream whose `maxAltRun` is
**82**, and a Nice frame to **130/131**. PWM symbols through `ks_mkBits` are themselves
alternating, so "nearly alternating" does not distinguish noise from a real frame. No window
exists.

**Transition density** — the fraction of adjacent differing bits. Same overlap: false
captures 0.81–0.98, genuine frames 0.71–0.99. This is the "nearly alternating noise" bound
`40` §4 flagged as a possible future tightening for Toyota; measured here, it does not
separate for these decoders.

Both are recorded as negative results. The lesson repeats a standing one from `00`: a fix
that "looks obviously right" was not applied until it was measured, and twice it was wrong.

## 4. The fix that survived measurement

Two controls, both measured against the corpus and against the shipping builders.

**A ratio window.** Every sibling `te_*` PWM gate carries a `ratio` bound — `te_came`,
`te_faac`, `te_pt`, `te_v2ph`, `te_faacslh`. `te_somf` and `te_nice` did not. The commit
geometries:

| population | cA | ratio | bLen |
| --- | --- | --- | --- |
| Somfy false commits | 444–628 | 1.95–2.01 and 4.45–6.48 | 512 |
| **genuine Somfy** (`buildSomfyRTS`) | 772–863 | **3.15–3.52** | 87–97 |
| Nice false commits | 486–520 | 1.95 and 3.66 | 512 |
| **genuine Nice** (`buildNiceFlor`) | 500 | **2.00** | 183 |

A window of `[2.4, 4.0]` on `te_somf` drops all seven Somfy false commits and keeps every
genuine frame. `[1.6, 2.4]` on `te_nice` drops the Renault commit (3.66) and the Audi/VW
cluster, and keeps genuine Nice.

**Per-slice consensus.** The vote is the correct control for what geometry cannot
reach. Three Nice commits sit at ratio 2.0, exactly where genuine Nice lives — geometrically
inseparable, and the vote demotes them instead. FAAC64 has no usable geometry at all
(99.997% accept), so the vote is its *only* control. New adapters `ks_consSomfy`,
`ks_consNice`, `ks_consFAAC64` supply the `(serial, button)` shape the vote needs, and all
three commit blocks now report `consensus: agree/total` and demote to `candidate` when
`total>=2 && agree<2 && agree<total`.

## 5. On the Somfy vote, and a limit that is documented rather than hidden

The Somfy vote conservatively abstains. A Somfy frame's own 2T sync pulses are 1208 µs, above
`ks_repeatSlices`' 1000 µs separator threshold, so a frame does not slice cleanly and the
vote returns `total<2`. By the contract that makes **no** demotion claim, which
is the safe outcome — it cannot mis-demote a genuine Somfy frame. Somfy's defence is
therefore the ratio window, which is measured and strong; the vote is a safety net that
happens to abstain. This is stated so the abstention is not later mistaken for the vote
working.

## 6. Result

After the change the regression reports:

| | before | after |
| --- | --- | --- |
| `ks_decodeSomfy` fires on | 9 files | **0** |
| `ks_decodeNice` fires on | 6 files | **0** |
| `ks_decodeFAAC64` fires on | 2 files | 2 (demoted at runtime, not gated) |
| captures matched by >1 decoder | 7 | 4 |

FAAC64 still *commits* on the two Chrysler files. That is expected and correct: gating it
would also reject genuine FAAC frames, so the fix there is the runtime demotion, not
geometry. It is written down rather than papered over.

## 7. Verification

| item | result |
| --- | --- |
| `test_gate_decoder_false_positives.py` (new, 45th suite) | pass |
| full host suite | 45/45 pass |
| genuine frames still decode (`buildSomfyRTS`, `buildNiceFlor`) | Somfy 6/6, Nice 6/6 |
| firmware compile | 58% flash, 51% RAM |
| corpus regression | Somfy 0, Nice 0, FAAC64 2 demoted |

## 8. What this does not do

The corpus has no genuine garage captures, so the positive control for Somfy and Nice is the
shipping builders, not a recorded fob. When a real gate remote is on the bench, the ratio
windows should be re-measured against it before wider trust — the encoder's symbol grouping
is what puts genuine Somfy at 3.1–3.5 rather than 2.0, and a different RTS revision could
move it. The windows are deliberately wide to tolerate that. This is the same "blocked on a
capture, not on analysis" status as the garage half of `85`.
