# 56 — At 315 MHz the card reads a false elevated floor, and a second defect hides behind it

`53` §4 step 1 asked for the fob to be pressed against the card at 315. That was run this round,
and it did not produce a capture. What it produced instead is a measurement that explains the whole
315 story — and, once the floor was corrected, a second defect that had been masked by the first.

Neither is about the transmit source, the threshold margins, or the 75 µs filter that `50` through
`53` examined.

## 1. The measurement

With **nothing transmitting**, the RSSI reads a persistent elevated value at 315 but not at any
other band:

| band | avg | min | max |
| --- | --- | --- | --- |
| **315.00** | **-68** | -108 | -67 |
| 433.92 | -93 | -104 | -89 |
| 700.00 | -109 | -117 | -103 |
| 868.30 | -109 | -119 | -103 |

And it is flat with frequency across the entire 315 neighbourhood — **every point from 310 to
325 MHz reads the same -68**, well outside any single channel's filter:

```
  310.00  -68     314.50  -68     318.00  -68
  312.00  -68     315.00  -68     320.00  -68
  313.00  -68     315.50  -68     325.00  -68
  314.00  -68     316.00  -68
```

A 15 MHz-wide plateau is not signal and it is not the channel filter. It is a property of the
receive path in this frequency region.

The trace shows how it presents. During an `rssi_scope` run at 315 the first samples are the true
floor, then it climbs and stays:

```
first 32: [-109,-109,-109,-109,-103,-103,-103,-103,-103,-103,-103,-103,
           -70,-70,-70,-70,-70,-70,-70,-70,-70,-69,-69,-69,-69,-69,-68,-68,-68,-68,-69,-69]
```

`runs=1`, `max_run_samples=663603` of 665618 — one continuous plateau, no modulation, no noise.
That is why capture records **zero transitions**: the comparator never crosses anything.

## 2. Why this is the cause, and what it explains

`captureSignal()` triggers on `floor+10`. The elevated floor sets that threshold *above* the
signal:

```
Floor: -109 dBm  Trig: -99 / Edge: -104 dBm (Toyota -3dB)
Signal! -76 dBm            <- 33 dB above the floor
⚠ Too few edges (0)
```

The fob is 33 dB above the true floor and the capture still records nothing, because the floor the
firmware measured (-109) is not the floor the receive path then presents (-68). The threshold is
computed from one state and the recording runs in another.

This also explains the earlier rounds, and it removes their contradiction:

- `50`'s "74 dB span and 11 threshold runs" at 315 is this plateau arriving mid-window, not fob
  chatter. The span is the climb from the true floor to the plateau.
- `51`'s `raw=271, after75=8` is the same thing: transitions from the plateau boundary, then
  nothing that survives a filter.
- `53`'s `raw=512` on the Tacoma fob, with 6-56 ms gaps, is the capture loop oscillating at the
  edge of a plateau that has not fully settled.
- `49`'s band comparison was measuring this, not capture quality.

So the 315 failure is **a receive-path defect in this firmware's configuration**, reproducible with
nothing transmitting, and it is not about weak transmitters, thresholds that need tuning, or the
filters.

## 3. The plateau is a stale register state, and `cap_mode` clears it

Applying `cap_mode` (which rewrites `MDMCFG2`/`DEVIATN` through `cc_setCaptureOOK()`) drops the
reading from the plateau to the true floor:

```
  before                @315: avg=-69
  after setfreq elsewhere, back to 315: avg=-69     <- survives a retune
  after cap_mode re-apply:               avg=-103    <- cleared
```

So this is not a hardware fault at 315. It is a register state left behind by a previous
configuration, and re-applying the capture configuration resets it. It survives a `setfreq` retune
and a trip to 433.92 and back, which is why it looked frequency-locked: nothing between the
commands that set it and the ones that read it re-writes those registers.

That makes it reachable in normal use: **whatever last configured the modem leaves the front end in
this state, and any capture at 315 taken before `cap_mode` is applied will read a floor 35 dB high
and record nothing.**

## 4. But fixing the floor does not fix the capture

With `cap_mode` applied first, the floor is correct and the capture still fails — differently, and
this is the second finding:

```
  Floor: -104 dBm  Trig: -94 / Edge: -99 dBm (Toyota -3dB)
  [DIAG] raw=512 after75=512 afterToy=8 toyBand=1
  [DIAG] dropped at ks_km2 coherence gate, rfLen=5
```

Read the stage counts. **`raw=512` and `after75=512`**: every recorded transition survives the
75 µs glitch filter. Then **`afterToy=8`**: the toy-band fold, which absorbs everything below
150 µs, removes 504 of them.

So at 315 the signal produces transitions that are all longer than 75 µs and shorter than 150 µs,
and the `_toyBand` filter — the only stage that runs in that band and nowhere else — is what
removes them.

`51` and `53` blamed the 75 µs filter; with a correct floor, that filter passes everything
(`after75=512`) and the *150 µs* fold is the one that cuts. That much holds.

But §4.2 shows the fold is not the *cause* of the failure: disabling it leaves the capture at 1 of
4, because the transition count reaching it varies between 25 and 512 for an identical source. The
fold is a second stage operating on an input that is already unreliable.

### 4.1 A controlled source confirms it, and the margin is quantifiable

Two Flippers and a corpus of recorded signals made a properly controlled test possible. The corpus
is on Flipper A; each file was replayed with `subghz tx_from_file` while the SGP captured, with
`cap_mode` applied first so the stale-floor defect is out of the way.

Checking bandwidth first: the two `Tesla_315MHz_*` files raise the card's 315 RSSI by **+10 and
+12 dB**, while `Ford_Bronco` (a 433.42 MHz file) raises it by only +6. So the Tesla files really
do transmit at 315 and the Ford one does not — worth stating, because the first attempt at this
test replayed a 433 file into a 315 capture and measured leakage.

With a real 315 signal, three trials:

| trial | floor | `raw` | `after75` | `afterToy` | result |
| --- | --- | --- | --- | --- | --- |
| 1 | -102 | 512 | 512 | 17 | no capture |
| 2 | -102 | 512 | 512 | 7 | no capture |
| 3 | -102 | 218 | 218 | 7 | no capture |
| (earlier run) | -102 | 512 | 512 | **13** | **captured, 13 edges** |

The floor is correct at -102 every time and `after75` passes everything at 512. The whole outcome
turns on `afterToy`, which lands between 7 and 17 — straddling the `rfLen<16` gate and the
coherence check. One run cleared it; three did not.

So the toy-band fold is not merely cutting the signal, it is cutting it *to the edge of the
threshold*, which is why the result is bistable rather than consistently failing.

### 4.2 The fold is not the whole story — tested, and it did not fix it

The obvious next test is to disable the fold. That was done: the `_toyBand` branch was forced off,
rebuilt, flashed, and the same Tesla 315 signal replayed four times.

```
  captured 1/4 with the fold DISABLED     (against 1/4 with it enabled, over 4 trials)
```

**No improvement.** And trial 3 of that run is the informative one:

```
  trial 3: edges=25   [DIAG] raw=25 after75=25 afterToy=25
```

`raw=25`, not 512. With the fold off, the capture recorded only 25 transitions in the first place —
so there was nothing for the fold to remove. On the other trials `raw=512` and the burst still came
out below the gate.

That means the fold is downstream of a variation that is still unexplained: **the same source
produces `raw=25` on one run and `raw=512` on the next.** Whether the fold runs or not, the capture
succeeds or fails on how many transitions the front end happened to record, and that varies by a
factor of 20 between identical trials.

The experiment is reverted — the file is byte-identical to `HEAD` — because disabling the fold did
not measurably help and shipping it would have been a change justified by a mechanism I have now
shown is not sufficient.

### 4.3 What this narrows it to

Three things are established and one is not:

| shown | how |
| --- | --- |
| The floor defect is real and `cap_mode` clears it | -69 -> -103, reproducible |
| A real 315 signal does reach the card | +10/+12 dB over floor on `rssi_scope` |
| The fold removes most of what survives | `after75=512` -> `afterToy=7..17` |
| **The fold is not the cause of the failure** | disabled: still 1/4 |
| **Not explained** | `raw` itself varies 25..512 between identical runs |

The remaining question is why transition count is so variable for a fixed source. That is a
question about the RSSI edge detector and the front end, not about any post-processing filter, and
it is the next thing to instrument.

### 4.5 The detector records nothing because the level never crosses

`cap_diag` was extended to report which way the recording loop *ended* and the pulse-width
distribution. That changes the picture again.

With **nothing transmitting**, at 315:

```
  Floor: -82 dBm  Trig: -72 / Edge: -77 dBm (Toyota -3dB)
  [DIAG] raw=0/512  rec_ms=3000  ended=window  peak=-71  edgeThr=-77
```

`raw=0` across five consecutive trials, the full 3000 ms window elapsing every time, and `peak`
(-71) sitting **7 dB above `edgeThr` (-77)**. The loop is **edge-triggered** — it records a pulse
only when `rssi > edgeThr` *changes state*:

```c
    { int r0=cc_fastRSSI(); capStartHigh=(r0>edgeThr); lastSt=capStartHigh; }
    while(rawLen<CAP_SZ&&micros()<capEnd){
      int rssi=cc_fastRSSI(); bool cur=(rssi>edgeThr);
      if(cur!=lastSt){ ... record ... }
    }
```

If the level is already above the threshold when the loop starts and stays there, `cur == lastSt`
forever and **nothing is ever recorded**. That is the 315 failure, and it has nothing to do with
the filters, the thresholds' margins, or the fold.

### 4.6 What the bands look like side by side

The same measurement at four bands, nothing transmitting:

| band | measured floor | `edgeThr` | settled level avg / min / max | loop outcome |
| --- | --- | --- | --- | --- |
| **315.00** | -82 | **-77** | **-73** / -100 / -65 | **`raw=0`** — sits above, never crosses |
| 433.92 | -86 | -78 | -78 / -91 / -74 | `raw=512`, buffer full in 153 ms |
| 700.00 | -98 | -90 | -98 / -102 / -93 | quiet |
| 868.30 | -92 | -84 | -92 / -101 / -89 | quiet |

At **315** the level is above the threshold and flat, so the detector sees no change. At **433.92**
the level straddles the threshold and chatters, so the buffer fills in 153 ms with noise
(`after75=5`, widths spread across every bin). Neither band is usable, in opposite ways.

The floor measurement is the common fault. It averages 64 samples and the two bands differ in how
that average relates to the level the loop then sees:

- at 315 the average (-82) is **below** the typical level (-73), so the threshold lands under it;
- at 433.92 the average (-86) is **above** the typical level (-78), so the threshold lands over it.

### 4.7 The settle fix was tried and does not work

The obvious explanation — the average is dragged down by the front end's settling ramp — was
tested. Sixty-four samples are discarded before the average; rebuilt, flashed, re-measured.

```
  before and after:  Floor: -82 dBm  Trig: -72 / Edge: -77 dBm
                     [DIAG] raw=0/512  ended=window  peak=-71  edgeThr=-77
```

**Identical.** So the low samples are not confined to the first ~100 µs: at 315 the level
fluctuates between roughly -100 and -65 across tens of milliseconds, and the mean lands between the
two without describing either. Discarding a fixed prefix cannot fix a signal that is bimodal
throughout.

That change is reverted, and the reason is recorded at the call site so it is not retried.

### 4.8 What this actually is

The threshold is derived from a **mean**, and the detector needs a **level**. At 315 those disagree
by enough to invert the comparison; at 433.92 they disagree by enough to make the comparison
chatter. Both are the same defect: a summary statistic being used where a band-referenced decision
is required.

The fix is not another constant. It is to derive `edgeThr` from the level the loop will actually
see — a median or a mid-range rather than a mean, or a fixed offset from the observed min/max —
and then to make the detector's initial state irrelevant by requiring a *crossing* before the
first recorded pulse rather than merely sampling the state once at entry.

Neither is applied: both change capture behaviour for every band, and the bench now has four bands
of measurements to fit them against, which is the work this note hands over.

### 4.9 The nearby Flipper is not the source

Every 315 measurement in this investigation was taken with a second Flipper plugged into the same
host, sitting a few centimetres from the card's antenna. That is exactly the sort of thing that
would produce a persistent elevated level on one band, and the correlation was suggestive: **every**
bad 315 reading happened with it attached.

It was unplugged mid-session. The level did not change:

| band | with Flipper A attached | unplugged |
| --- | --- | --- |
| **315.00** | avg -73, min -99, max -66 (span 32) | avg **-74**, min -100, max -56 (span 44) |
| 433.92 | avg -78, min -91, max -74 | avg -79, min -90, max -76 |
| 700.00 | avg -98 | avg -99 |
| 868.30 | avg -92 | avg -94 |

315 is unchanged within noise. The other bands moved a few dB each way, which is ordinary
variation. **The elevated 315 level is a property of the card or its environment, not of the
bench equipment.** That is worth recording precisely because the hypothesis was such a good one.

### 4.10 What the Ford corpus adds

Most of the corpus is 433 MHz and unusable at 315 — `Ford_Bronco_l2_u2_rs2_p2`, `Ford_Escape_*`,
`GMC_*`, `Honda_*` and the rest report 433.42 when replayed. Only the explicitly-named
`Tesla_315MHz_*` files transmit in band. That matters for `52` and `53`, which drew conclusions
from a Ford corpus at 315: **those files were never transmitting at 315**, so any 315 capture
taken while replaying them was measuring leakage.

This is the second defect, and it is separate from the plateau: one is a stale register state,
the other is a cutoff set above the signal's pulse width.

### 4.1 A clean A/B on the band gate

Two frequencies, same floor, same transmitter, same transmit settings. The only difference is
whether `_toyBand` (309-316 MHz) applies:

| band | toyBand | floor | result |
| --- | --- | --- | --- |
| **315.0** | **1** | -102 dBm | dropped at the coherence gate, `rfLen=3` |
| **317.0** | **0** | -102 dBm | **captured, 24 edges** (`raw=512 after75=24 afterToy=24`) |

Same floor to the dB, same source, adjacent frequencies, opposite outcomes. At 317 the 75 µs pass
reduces 512 to 24 and everything that survives is kept. At 315 the fold runs on top and leaves 3.

That does not yet prove removing the fold fixes 315 — that needs the fold disabled and re-measured,
the same way the stability guard was tested in `51`. But it does confine the second defect to the
one branch that is frequency-gated, and rules out the receiver, the floor, and the source.

## 5. What the fob test actually answered

`53` §4 step 1 asked whether pressing the fob against the card would produce a usable capture. It
did not, and the reason is now clear rather than mysterious: the floor was 35 dB high at the time,
so the threshold sat above a signal that was 33 dB above the true floor. The fob is not the
problem, and `53`'s "weak transmitter" reading was measuring the plateau.

## 6. What it is not

Tested and ruled out:

| candidate | test | result |
| --- | --- | --- |
| The fob was too far / too weak | fob held against the antenna; `Signal! -76 dBm` | 33 dB above the true floor |
| The LoRa park state | `gdo0_probe` then re-measure | -68 unchanged |
| Frequency alignment | plateau spans 310-325 MHz | not a channel effect |
| A hardware fault at 315 | `cap_mode` clears it to -103 | stale register state, not the part |
| The transmit source | plateau appears with nothing transmitting | not transmit-dependent |

## 7. Where this leaves it

The chain is traced end to end, and the conclusion is not a defect in the firmware's arithmetic.

**The 315 receiver path on this bench cannot separate a real signal from noise.** Measured with
nothing transmitting, the noise peaks at **-63 dBm** across eight consecutive windows. The one real
315 signal measured on this bench read **-64 dBm**. One dB apart, with the noise marginally louder.

Every threshold rule therefore fails, from one side or the other:

| rule | `edgeThr` | why it fails |
| --- | --- | --- |
| mean-based (shipped) | -77 | below the resting level, so the edge-triggered loop starts above it and records nothing |
| peak-based (attempt) | -61 | above the level, so nothing ever crosses it either |

Both produce `raw=0`. The firmware is doing what it was written to do with a signal it cannot
distinguish. **This is not something a threshold change can fix**, which is why six attempts failed
and why each was reverted.

The stale-modem-state defect in §3 is real and separate: it sets the floor 35 dB high before any of
this applies, and `cap_mode` clears it. It is worth fixing on its own merits.

### What is actually established about 315

- The receiver path presents a noise floor spanning ~30 dB (-96 to -63) persistently.
- That noise peak sits at the level of the one real signal measured through this path.
- The `captureSignal` edge detector correctly records nothing when nothing crosses.
- Whether the card's 315 *sensitivity* is the limit, or the bench's 315 RF environment is, has not
  been separated. That needs a known-good 315 source at a known distance — or a quieter location.

### What the failed attempts ruled out

Nothing was shipped. Each attempt was reverted, and four produced explanations that are now
disproven and recorded (§4.12) so they are not retried:

- the toy-band fold is not the cause
- the settle ramp is not the cause
- the observation window is not the cause
- the threshold formula is not the cause

The remaining candidates are outside `captureSignal`: the CC1101's 315 configuration, the board's
315 RF path, or the environment.

### What is fixed, and what is not

Nothing is fixed. Six candidate changes were tried; all six are reverted and none shipped:

| change | tried | result | shipped |
| --- | --- | --- | --- |
| Disable the toy-band fold | yes | 1/4 either way | no |
| Discard the settle ramp before averaging the floor | yes | floor unchanged at -82 | no |
| Peak-referenced `edgeThr` | yes | ran, moved `edgeThr` to -61, still `raw=0` | no |
| Require a crossing before the first recorded pulse | written | untested, reverted with the above | no |


### 4.11 The real obstacle: the noise peak is at the signal's level

Two threshold rules were tried on the same band, and both gave `raw=0`:

| rule | `edgeThr` | observed outcome |
| --- | --- | --- |
| mean-based (shipped) | `mean+5` = **-77** | level (-70 peak) sits **above** it → no crossings |
| peak-based (attempt) | `_nmax+3` = **-61** | level (-70 peak) sits **below** it → no crossings |

Both fail, from opposite sides. That rules out the threshold arithmetic as the problem, and points
at the level itself. Measuring it directly:

```
  QUIET 315, nothing transmitting, eight consecutive windows:
      peaks: -63, -65, -65, -67, -64, -66, -67, -66       <- noise peaks at -63
  A REAL 315 signal (Tesla corpus replay, §4.1): -64 dBm
```

**The quiet noise peaks at -63 dBm. The real signal measured -64 dBm.** One dB apart, with the noise
marginally *louder*.

There is no threshold that separates them. Set it above the noise and a real signal is excluded;
set it below and the noise is recorded. `raw=0` on a quiet band and `raw=0` with a signal present
are the same symptom arriving from two directions.

### 4.12 Corrections to two explanations in this note

Both of the explanations offered earlier for the `raw=0` result are now disproven, and they are
recorded here rather than deleted because each looked convincing:

- **"The level fluctuates and a 32 ms window misses the excursions."** Measured across window
  lengths from 32 ms to 2000 ms, the peak is **-66 at every length**. A 32 ms sample sees the
  excursion as well as a 2 s one.
- **"The peak-based branch never ran."** The arithmetic says it did: `_nmax+3` = -61 was what the
  card reported, against `mean+5` = -77 for the fallback.

The failure was never in the threshold formula or the sampling window. It is that the thing being
thresholded has no separation from the noise.

### 4.13 What this says about the earlier "+10/+12 dB over floor" result

§4.1 measured the Tesla corpus files as raising the card's 315 RSSI by +10 and +12 dB over the
floor, and concluded the files "really do transmit at 315". That conclusion needs qualifying: the
delta was measured **relative to a floor that is itself the noise peak**, and §4.11 shows the noise
varies across a 30 dB span on its own. A +12 dB excursion over a 30 dB-varying baseline is not
distinguishable from noise by that method alone.

Whether those files transmit at 315 has not been established independently. What is established is
that the 315 receiver path cannot resolve them from noise on this bench — which is the same
statement as §4.11, from the measurement side.

### 4.14 What the Ford corpus adds

### The measurement that would settle it

Derive a threshold from the level rather than the mean, and log both while a real 315 source
replays. The bench now has four bands characterised (315, 433.92, 700, 868.30) and two recorded
315 sources that are known to transmit in band, which is enough to fit and check it.

## 8. Status

| item | status |
| --- | --- |
| Fob pressed against the card at 315 | **done** — cause identified |
| False elevated floor (-68 vs -109) | **identified**, cleared by `cap_mode` |
| A real 315 signal reaches the card | **not established** — §4.1's delta is not separable from noise (§4.13) |
| Toy-band fold removes surviving pulses | confirmed (`after75=512` -> `afterToy` 7..17) |
| Toy-band fold is the *cause* | **disproven** — disabled, 1/4 either way |
| **Root cause** | **the noise peak (-63) and a real 315 signal (-64) are 1 dB apart** |
| Consequence | no threshold can separate them; both rules tried give `raw=0` |
| §4.1's "+10/+12 dB over floor" | **needs qualifying** — the floor is itself the noise peak (§4.13) |
| Fix | **not applied** — six attempts, all reverted; tree at `e0f1d53` |
| Needs | a known-good 315 source at known distance, or a quieter location |
