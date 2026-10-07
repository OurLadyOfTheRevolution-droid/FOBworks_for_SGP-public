# 36 — Corpus regression: 41 decoders against 301 real captures

## 0. Verdict

§5 steps 1–2 are done. The harness exists (`tools/corpus_regression.py`), it runs
the **real C++ decoders** extracted from the sketch, and it reproduces the one known-good result
exactly: `ks_decodeKiaV34` decodes `Kia_V3_N1_RAW` as **ctr 38** and `Kia_V4_N1_RAW` as
**ctr 19**, the values A2 documented. That is the harness's positive control and it is a hard
gate — if it fails, the run aborts rather than reporting zeros.

Firmware is untouched this round. No hardware used.

### Headline

| question | answer |
|---|---|
| decoders that never fire | **31 of 41** |
| captures matched by more than one decoder | **8 of 301** |
| captures matched by no decoder | **258 of 301** |
| decoders with a non-brand fire | 6, of which **2 are confirmed false positives** (§3.3) |

The single most important number is this: **only 10 of 41 decoders fire at all**, and of
those only `KiaV34` fires exclusively on its own brand. `35` §3.2 predicted exactly this shape.

---

## 1. Why the harness compiles the real functions

`35` §3.2 said "generalise `a2_kia_v34.py`". A Python generalisation would have been a
*reimplementation* of 41 decoders, and this project has already been burned by that: doc `09`'s
Python model of the Kia encoder disagreed with the running code and cost a round to untangle.

So the harness **extracts the real functions from `FOBworks_for_SGP.ino` and compiles them**:

```
pulses -> klTrimToFrame (via rjTrimKiaV34) -> ks_km2 clusters -> te_* gates
       -> ks_mkBits -> ks_Manchester (for the 7 Manchester-fed decoders) -> ks_decode*()
```

Every stage is the firmware's own code, transcribed by extraction rather than by hand. The
helper closure is computed transitively (69 functions + 1 data table).

### 1.1 It reproduces the firmware's dispatch, gates and all

Order matters and so do the gates. `decodeSignal()` tries the 41 decoders in sequence and stops
at the first success, but each is guarded by a `te_*` classification gate. A harness that called
decoders ungated would let an early decoder fire on a frame the firmware would never offer it.

That is not hypothetical — it was the first version of this harness, and it reported
`ks_decodeFordV0` firing on **243 files**. The cause: a regex cannot brace-match a dispatch block
that itself contains braces, so the nested blocks (`FordV0`, `KiaV2`, `BMWCAS4`, `KiaV1`,
`KiaV7`, the Manchester fallbacks) never matched the pattern and fell through to an ungated
fallback list. Brace-matching fixed it and `FordV0` dropped to **3 files**.

### 1.2 The input shape differs per decoder

Eleven call sites do not pass the raw bit string — they pass the **Manchester-decoded** buffer
(`ks_decodeFordV0(mbFV, mlFV, ...)`). Feeding those decoders raw bits made them decode noise, which
is a second source of the same inflated count. The harness now records, per dispatch, both the
gate and whether the first argument is the Manchester buffer.

---

## 2. Validation: the positive control, and four bugs it caught

The harness refuses to report unless `Kia_V3_N1_RAW` and `Kia_V4_N1_RAW` both decode with
`ks_decodeKiaV34` as the *first* hit. Four separate defects each presented the same way — "every
decoder fires on nothing", which is indistinguishable from a working harness over a hard corpus:

| bug | symptom | cause |
|---|---|---|
| helper closure incomplete | would not compile | `[^;{]*?` rejected one-line bodies; a non-greedy return-type match stopped short of `ks_bit` |
| sort key found call sites | referenced before declared | `src.find(" name(")` finds the first *mention*; `ks_bit` is called 127 KB before its definition |
| constants were decimal-only | `validate=0`, ctr 6200 | `KIA_V34_MF_KEY` was dropped (the OEM constant), leaving `ks_klDecrypt` keyless |
| gates unapplied | `FordV0` on 243 files | regex could not brace-match nested dispatch blocks |

The third is the most instructive. The harness fed the *correct 183-pulse frame*, the Python
mirror decoded it, and C refused with a plausible-looking but wrong counter (6200). The bytes
matched the mirror exactly — only the **key** was missing. A harness that reported "KiaV34: 0"
there would have looked like a finding about the decoder.

After the fixes: `Kia_V3_N1_RAW` -> ctr 38, `Kia_V4_N1_RAW` -> ctr 19, both as first hit.

---

## 3. Triage

### 3.1 Decoders that never fire — 31 of 41

```
ks_decodeSubaru      ks_decodeMazda       ks_decodeVAG         ks_decodeSantaFe
ks_decodeBMWCAS4     ks_decodeKiaV0       ks_decodeKiaV1       ks_decodeKiaV7
ks_decodeSubaruV2    ks_decodeCame12      ks_decodeMarantec    ks_decodePT2262
ks_decodeLinear10    ks_decodePT2240      ks_decodeHT12E       ks_decodeCameTwn30
ks_decodeLD3         ks_decodeHormann     ks_decodeSommer      ks_decodeBeninca
ks_decodeCardin      ks_decodeV2Phox      ks_decodeSecPlus     ks_decodeDEA
ks_decodeAnMotors    ks_decodeCame24      ks_decodeNiceFlo     ks_decodeFAACSlh
ks_decodePhoenixV2   ks_decodeCameAtomo   ks_decodeSecPlusV2
```

**Two readings, and the harness can separate them.** The corpus is mostly *vehicle* remotes,
while most of these decoders are **gate/garage** protocols (CAME, FAAC, Somfy, Nice, Marantec,
Hormann, Sommer, Beninca, Cardin, DEA, AN-Motors). Their absence may simply mean the corpus has
no such remote — which is a statement about the corpus, not the decoder.

A widened-window sensitivity run (`HARDCAP=4096`, i.e. *not* limited to the firmware's 512-pulse
capture) moved only one decoder into the firing set and moved one out:

- `ks_decodeCameAtomo` fires only with the wider window -> **window-limited, not decoder-limited**
- `ks_decodeHKR` fires at 512 but not 4096 -> the wider window changes the cluster statistics the
  `te_*` gates are computed from, so the wider run is *not* a strict superset and cannot be read
  as "what more pulses would unlock"
- 30 decoders fire at **neither** cap

So for 30 of the 31 the honest statement is: **their protocol is absent from this corpus, or the
decoder is broken — this run cannot distinguish the two.** Distinguishing them needs a capture
of the relevant protocol, which is a corpus-acquisition task.

### 3.2 Captures matched by no decoder — 258 of 301

The dominant gaps, by count:

| brand | unmatched | note |
|---|---|---|
| toyota | 56 | largest single gap; `ks_decodeToyota` fires on 12, so the Toyota family is partly covered |
| unknown | 27 | no brand inferred from the path |
| psa | 24 | Peugeot/Citroen — no decoder at all |
| renault | 22 | no decoder at all |
| kia | 20 | `KiaV34` covers 4; the V0/V1/V7 decoders never fire despite Kia captures being present |
| honda | 13 | no decoder |
| nissan | 12 | no decoder |
| fiat | 12 | no decoder |
| gm / vag | 11 / 11 | `Chrysler` and `VAG` do not reach the GM/VW captures |
| byd / mazda / suzuki | 9 each | no decoder |

Two of these are worth flagging as *decoder* questions rather than backlog:

- **`kia` 20 unmatched while V0/V1/V7 never fire.** The corpus *does* contain 24 Kia captures
  carrying `RAW_Data`, and only 4 decode. They include named captures for the variants whose
  decoders are silent — `Kia_V1_N1_RAW.sub`, `Hyundai_V1_N1_RAW.sub`, `Kia_V5_N1_RAW.sub` — so
  a Kia decoder that never fires on any of 24 Kia captures is a decoder question, not a corpus
  gap. §3.2.1 checks one of them and finds a capture defect, not a decoder defect.
- **`unknown` 27** is an artifact of brand inference, not a protocol gap. Brand is derived from
  the folder path by keyword; 27 files live under `Unknown/` or a path with no recognisable make.

### 3.2.1 `Kia_V1_N1_RAW` is a 2x-quantized capture, not a V1 frame

This is a concrete, checkable result and it changes how the `kia` row should be read.
`ks_decodeKiaV1` is gated on `te_kv1 = (mhz<320 && cA>=350 && cA<=700 && ...)`, i.e. it expects
the KIA V1 nominal **400/800 µs** PWM. The file measures:

| file | short-cluster mean | long-cluster mean | scale vs nominal 400/800 |
|---|---|---|---|
| `Kia_V1_N1_RAW.sub` | 807 µs | 1611 µs | **2.02x / 2.01x** |
| `Kia_V5_N1_RAW.sub` | 212 µs | 1456 µs | 0.53x / 1.82x (different scale again) |

So `Kia_V1_N1_RAW`'s pulses are almost exactly **twice** the protocol's nominal widths, putting
`cA` at ~807 µs — outside `te_kv1`'s 350–700 µs window. The gate refuses it, correctly: the
capture is not in the waveform the decoder models. This is the RSSI-quantization family of
defect from doc `13`, present in the corpus rather than on the bench.

**The honest conclusion:** `Kia_V1_N1_RAW` proves nothing about `ks_decodeKiaV1`. The other 19
unmatched Kia files have not been checked individually. "Sweep the unmatched captures for a
scale factor against their protocol's nominal te" is a concrete next step (§6.3).

### 3.3 Decoders with a non-brand fire — 6

| decoder | fires | on | assessment |
|---|---|---|---|
| `ks_decodeToyota` | 8 first / 12 all | ford, kia, tesla, vag | **band-consistent, but broad.** All 12 hits are genuinely in-band (314.98–315.00 MHz), so the band gate is working. The 4 Kia co-fires are benign (§3.4). The other 8 — 2 Ford `Escape`, 5 Tesla, 1 VW `Atlas` — are 315 MHz captures Toyota wins outright, which on a 315 MHz band with a Toyota/Denso-shaped frame is *possible*, not proof of a defect. Flagged for inspection, not called a bug |
| `ks_decodeKiaV2` | 7 first / 7 all | tesla | **confirmed false positive, and structurally so.** All 7 are Tesla **433.92 MHz** captures, all yielding **1 distinct identifier** — the pattern-matching signature, not device identification |
| `ks_decodeChrysler` | 6 | chrysler, ford | 4 are genuine Chrysler-file matches; 3 Ford `Escape` captures also decode as Chrysler |
| `ks_decodeFordV0` | 3 first / 3 all | vag | **confirmed false positive.** All 3 are VW **434.42 MHz** `Polo` captures (`Lock2`, `Lock3`, `Unlock1`), all yielding **1 distinct identifier** |
| `ks_decodeHKR` | 0 first / 1 all | vag | never the winner; a co-fire with Toyota on `vw_atlas_l2_u2_t2_rs_2` |
| `ks_decodeSomfy` / `ks_decodeNice` | 9 / 6 | many | overlap with each other on 4 files (§3.4) |

Two false positives are **confirmed**, and they share the exact shape `04` §I4 predicted: a decoder
firing on captures from a brand it does not belong to, all yielding **one identifier**. Both are
gated on pulse geometry (`te_kv2`, `te_frdv0`), both satisfy that gate on these files, and neither
rejects the frame. `ks_decodeKiaV2` — a **Kia** decoder, firing on **seven Tesla 433.92 MHz**
captures — is the clearest actionable result in this report.

> **Correction (`39`):** the diagnosis above is right about the gates and wrong about the cause.
> Instrumenting the two decoders shows the `KiaV2` problem is not permissive validation but an
> **incorrect** CRC4 — the formula was missing its final `+ 1`, so the decoder rejected every
> genuine KIA/HYU V2 frame and accepted a specific family of noise. The Tesla windows are not
> degenerate (32 transitions in 53 bits, a normal Manchester density), so no modulation guard
> would have been right. `FordV0` is the opposite case and genuinely under-validated: it accepts
> unmodulated constant runs. Both are fixed in `39`; the band remark in `37` §4.1 is a red
> herring, since `te_kv2` requires `eu433` and the band gate was working.

Toyota is a weaker case and is *not* called a bug here: its hits are all in-band, so the failure
mode (if any) is too-permissive frame validation at 315 MHz, not a broken band filter. Separating
"a Tesla 315 MHz frame that genuinely resembles Toyota/Denso" from "a Toyota decoder accepting a
non-Toyota frame" needs a frame-level comparison, not this harness.

`KiaV2`'s 7-for-1 is the cleanest finding here: **one identifier across seven captures from a
brand it does not belong to** is what a structural match looks like, and it is exactly the
false-positive class `04` §I4 predicted.

### 3.4 Captures matched by more than one decoder — 8 of 301

```
kia     KiaV34 + Toyota        Kia_3_5cl_5op_5tr.sub, Kia_4_5cl_5op_5tr.sub,
                               Kia_V3_N1_RAW.sub, Kia_V4_N1_RAW.sub
tesla   Somfy + Nice           Tesla_433_AM650_EU_AUS.sub, Tesla_EU_Y.sub
nissan  Somfy + Nice           Subaru_Impreza RAW .sub        (filed under Nissan)
vag     Toyota + HKR           vw_atlas_l2_u2_t2_rs_2.sub
```

The `KiaV34 + Toyota` overlap is **benign**: `KiaV34` is dispatched first (index 0) and wins, so
the firmware reports KIA-V3/V4. Toyota's co-fire is a second decoder also returning true on the
same frame — recorded, but it does not change what the dashboard shows.

`Somfy + Nice` on 4 files is the same shape: both are 433 MHz gate protocols with similar PWM
geometries.

---

## 4. Coverage, stated honestly

```
323 .sub files in the corpus
 -17  no RAW_Data line at all
=306  RAW captures            <- the number 35 §3.2 quotes
  -5  shorter than 32 pulses (Lamborghini_Trunk 30, four Volvo entries 10-16)
=301  actually scanned
```

`35` §3.2 says "306 RAW captures". That is the right count for *files carrying RAW_Data*, but a
harness can only run on 301 of them. The five excluded are listed in §3.2's table by omission —
they are recorded in the JSON result.

### 4.1 What the harness deliberately does not do

| not done | why |
|---|---|
| use the firmware's RSSI capture path | there is no hardware in this loop; the corpus *is* the input |
| widen the window by default | `CAP_SZ=512` is the firmware's real capture buffer, so the default run is faithful to what a real capture would hold. The wider run is a labelled sensitivity probe, not a better result |
| verify the trim on non-Kia files | `rjTrimKiaV34` is Kia-specific; for every other brand it finds nothing and the harness falls back to the first 512 pulses, exactly as `fbkAppend` does |
| judge `KiaV34`'s identifier count | `KiaV34` writes a **struct** out-param, not a `uint32`, so the distinct-id column reads `n/a` rather than a meaningless 0. Same for `Chrysler` (array) and `FAAC64` (`uint64`) |

---

## 5. Status

| item | status |
|---|---|
| Corpus regression harness | **built** — `tools/corpus_regression.py`, real C++ decoders, positive control |
| Decoders validated on real RF | **1 of 41** confirmed (KiaV34); **10 of 41 fire at all** |
| Receiver actuation | **blocked** — no paired receiver (recorded in `00`) |
| Firmware changed | **no** — analysis only |
| Existing suites | all pass, no regression |

---

## 6. Recommended next steps

1. **Inspect `ks_decodeKiaV2`.** Seven captures — all seven Tesla 433.92 MHz — one identifier,
   zero Kia captures. Its `te_kv2` gate admits them and the frame check does not reject them.
   This is the highest-value single fix the run surfaced.
2. **Inspect `ks_decodeFordV0`.** The same shape at smaller scale: three VW 434.42 MHz `Polo`
   captures (`Lock2`, `Lock3`, `Unlock1`), one identifier.
3. **Sweep the unmatched captures for a scale factor** against their protocol's nominal te
   (§3.2.1). `Kia_V1_N1_RAW` is exactly 2.0x nominal, which makes it undecodable by design. If
   most unmatched captures share that property then section B is telling us about the **corpus**,
   not the decoders — and the priority order changes completely. This is the cheapest way to
   decide whether "258 unmatched" is a decoder backlog or a corpus-quality problem.
4. **Then `35` §3.3's transmit round-trip**: every decoder that fires can now be re-encoded and
   transmitted, with the Flipper as the independent decoder.
5. **Gate/garage captures would settle 20+ of the 31 silent decoders** in one acquisition step,
   since that is what most of them decode. Worth doing when I next have remotes to hand.
6. **Toyota is flagged, not accused.** Its 8 wins are all in-band at 314.98–315.00 MHz, so whether
   they are legitimate 315 MHz Toyota/Denso frames or over-permissive validation needs
   frame-level comparison, not this harness.

## 7. Reproducing this

```
python3 tools/corpus_regression.py                      # 301 captures, faithful 512-pulse window
python3 tools/corpus_regression.py --json out.json      # machine-readable result
HARDCAP=4096 python3 tools/corpus_regression.py         # sensitivity probe (NOT a better result)
HDBG=1 python3 tools/corpus_regression.py               # per-file cluster/decoder internals
HKEEP=1 ...                                             # keep the generated harness for inspection
```

No hardware, no network. Needs only a C++ compiler. Runtime is ~2 s for the full corpus.
The run aborts if the Kia positive control fails, so a green run means the harness is sound.
