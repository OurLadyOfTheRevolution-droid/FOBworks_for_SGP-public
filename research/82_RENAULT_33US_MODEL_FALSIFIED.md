# 82 — The Renault "33 µs family" is not a frame code: fixed-slot PWM model falsified

Status: closed with a concrete, promised next step — "Port the PWM model
above and validate on counter walk." This pass did the reconnaissance that step
requires first, and the model does not survive. The Megane/Scenic 2005 and Captur 2017
captures carry no fixed bit slot, no repeated frame, and no periodic burst timing. They
are not a two-symbol PWM code with a preamble and payload; as recorded on disk they are
not decodable by any frame-based decoder. What follows is the evidence, the control that
proves the test is sound, and the corrected plan.

## The claim being tested

read the symbol histogram of the Megane/Captur captures, saw widths at
roughly 66 / 99 / 133 / 166 µs (`2T / 3T / 4T / 5T` on `T ≈ 33.3 µs`), and proposed:

> each bit is a fixed-length `5T` slot carrying a pulse of `2T` (one) or `4T` (zero),
> with `3T` / `5T` appearing as boundary and inter-frame markers.

That model makes two hard, checkable predictions. A fixed-slot code has pair sums
(mark + following space) clustered at one value. A repeated-frame code produces the same
long run of pulses more than once inside a capture. Both were tested against the files.

## Test one: there is no fixed slot

If a bit occupies `5T ≈ 166 µs`, then `mark + space` should land near `166 µs` for
almost every pair. Measured share of pair sums within ±15% of `5T`:

| capture | base unit | pair sums near 5T |
|---|---|---|
| Megane/Scenic 2005 lock | 33.3 µs | 1.1 % |
| Megane/Scenic 2005 unlock | 33.3 µs | 1.3 % |
| Megane/Scenic 2005 trunk | 33.3 µs | 1.6 % |
| Captur 2017 lock | 33.3 µs | 2.6 % |
| Captur 2017 unlock | 33.3 µs | 2.8 % |
| Kadjar `Ren2` | 104.7 µs | 4.8 % |

A fixed slot would give a majority, not a few percent. The pair sums instead occupy
124–166 separate 20 µs buckets — they are a near-continuum, not a lattice with a slot.
The earlier note called the Megane/Captur widths `2T/4T` PWM on the strength of the
width histogram alone; the histogram is real, but it describes a *distribution* of pulse
widths, not an alphabet of two symbols inside a fixed frame.

## Test two: there is no repeated frame

The Captur filename says `x5` — a fob that repeats its frame five times per press. If
these were frame captures, the same run of symbols should appear repeatedly. Measured
longest run of ≥16 identical symbol-units that appears at least twice in a capture, and
the normalised unit autocorrelation peak:

| capture | longest repeated run | ACF peak |
|---|---|---|
| Megane/Scenic 2005 lock | **0** | 0.266 |
| Megane/Scenic 2005 unlock | **0** | 0.261 |
| Megane/Scenic 2005 trunk | **0** | 0.253 |
| Captur 2017 lock | **0** | 0.219 |
| Captur 2017 unlock | **0** | 0.144 |
| Kadjar `Ren2` | **0** | 0.073 |

Zero for every Renault capture. The low ACF peaks are consistent with chance structure
in a short symbol string, not with periodicity.

## The control that makes the test trustworthy

The same metric, run on FIAT captures from the *same corpus* that shipped decoders
already read, behaves completely differently:

| capture | longest repeated run | ACF peak |
|---|---|---|
| FIAT Grande Punto `open` | **357** | 0.301 |
| FIAT Bravo 2010 | **600** | 0.389 |

A real repeated-frame OOK capture yields hundreds of repeated symbols. The metric is
sound; the Renault captures are simply empty of frame structure. This also removes the
alternative explanation that the tool is too strict: the exact same code finds the FIAT
frames without tuning.

## Corroborating evidence

Three further measurements all point the same way and are worth recording because they
each independently rule out a different "maybe the encoding is just unusual" escape:

1. **The widths are clean.** Bin standard deviations run `cv ≈ 0.007–0.015` (Megane 66 µs
   bin: sd 0.9 µs). The hardware captured sharply. This is not a noise problem that
   re-capture would fix — the numbers are precise, they simply do not form frames.
2. **The bursts are not frames.** Splitting at >4 ms silence gives 38 bursts in the
   Captur lock capture with modal lengths of 1 (21 times), 1548, 683, 3210, 1003 …
   There is no common burst length apart from single stray pulses.
3. **The inter-burst timing is not periodic.** Captur lock gap spacings cluster at
   14/16 ms and 57 ms, but with a long tail to 185 ms and no fixed frame period. A
   repeated-frame fob has a stable inter-frame gap; this does not.
4. **`Ren2` is the same story.** Its pair sums fit a `105 µs` lattice (residual 9.6% of
   the unit) better than anything else in the corpus, but it too has zero repeated
   symbols and an ACF peak of 0.073. Both halves of every pair are quantised
   (marks and spaces each span 1–19 units), which is what a long PWM-ish capture looks
   like, but there is no frame.

## What this changes

The recommended port was aimed at a protocol that is not present in the
files. Shipping a `2T/4T` fixed-slot decoder would produce garbage on these captures and
would be unverifiable on air, so it should not be written. The corrected reading:

* **The Megane/Scenic 2005 and Captur 2017 files are not usable frame captures.** They
  are dense, sharply quantised captures of *something* that is not a repeated fixed-slot
  frame — most consistent with a much wider/lower-rate modulation than the 33 µs guess,
  or with a capture window that never contained a whole coherent frame. Either way the
  existing files cannot support a decoder.
* **The next real step is a controlled re-capture**, not a port: known fob, known
  button, known distance, `OOK650`, with a capture window long enough to hold a whole
  press. Only then does the frame become visible and the question "which pulse widths
  encode bits" become answerable.
* **`Ren2` needs the same treatment** before its `105 µs` lattice means anything.
* Everything –81 established about Hitag2 (Trafic 2011) is untouched — that
  capture *does* repeat, and its Layer-2 closure stands.

## Corpus-wide triage: which remaining families are worth a decoder

The repeated-frame metric is not specific to Renault. Applied to all 323 captures it
separates them cleanly, and — importantly — it agrees with the decoders that already
ship. The FIAT Grande Punto and Bravo captures (which `test_fiat_decoder.py` reads) and
the PSA C3 captures (which `test_psa_decoder.py` reads) and the Renault Trafic Hitag2
captures (which `test_renault_hitag2.py` reads) all score `STRONG`. Whole-corpus tally
with `tools/frame_structure_scan.py`:

| band | repeated symbols | captures |
|---|---|---|
| STRONG | ≥ 64 | 117 |
| WEAK | 16–63 | 39 |
| NONE | < 16 | 167 |

Where the Renault families land:

| family | rep score | band |
|---|---|---|
| Trafic 2011 Hitag2 (×4) | 509–550 | STRONG |
| Kadjar `Renault1` (×3) | 35 | WEAK |
| Megane/Scenic 2005 lock/unlock (×6) | 12–13 | NONE |
| Megane/Scenic 2005 trunk, Captur 2017, `Ren2`, `Ren3` (×12) | 0 | NONE |

**The caveat matters and is printed by the tool:** a high score is a reliable *positive*
(a file with repeated frames is worth decoder work), but a low score is not proof of
junk. A protocol whose fob transmits once per press decodes fine from a single frame and
still scores low — Kia V3/V4 is one such family, and it is already handled. So `NONE`
means "needs a look or a re-capture", which is exactly the Megane/Captur situation:
those files are not frames at all, while the Kia ones are frames that simply are not
repeated.

## Tools

- `tools/renault_pwm_model_test.py` — tests the fixed-slot and repeated-frame
  predictions on any `.sub` file, with the FIAT captures as built-in controls. Reports
  pair-sum clustering, longest repeated symbol run, ACF peak, and burst statistics.
- `tools/frame_structure_scan.py` — applies the repeated-frame metric across the whole
  corpus and prints STRONG / WEAK / NONE tallies, for picking the next decoder target
  from evidence.

## What is open

* **A controlled Renault re-capture.** Without one, no decoder for Megane/Captur/`Ren2`
  can be built from this corpus.
* **`Ren3`.** Still needs an FSK capture and the FSK path.
* **Key recovery** — unchanged.
* **The board GDO0 question** — unchanged; on-air work still waits on it.
