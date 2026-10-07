# 58 — A latched front-end state, induced by the sensor rail and cleared by the modem writes

The 315 MHz failure has a mechanism, and it is not a threshold, a filter, or the environment. The
card enters a **latched** state in which the reported noise floor sits about 35 dB high across
roughly 310-370 MHz. The state persists until the modem configuration registers are rewritten.

This note records the induce/clear pair that identifies it, and corrects `57`, whose central
spectrum was taken entirely inside this state and therefore describes the fault rather than the
environment.

## 1. What was seen first

The floor at 315 read **-72 dBm** while and `57` had both recorded the chip's quiet
state near **-100**. A fine sweep with the sweep paused put the shape in one line:

```
  300.00     -87    min -100  max  -74
  310.00     -66    min  -67   max  -66
  315.00     -67    min  -99   max  -70
  320.00     -66    min -111   max  -66
  330.00     -66    min  -67   max  -66
  340.00     -66    min -115   max  -66
  350.00     -66    min  -67   max  -66
  360.00     -66    min  -67   max  -66
  370.00     -66    min  -67   max  -66
  380.00     -85    min  -86   max  -85
  400.00     -81    min  -81   max  -81
  410.00     -92    min  -95   max  -92
  433.92     -92    min  -93   max  -92
  470.00     -91    min -100   max  -91
  600.00     -97    min -102   max  -93
  868.30     -98    min -101   max  -93
```

Three things in that table matter.

**It is a plateau, not noise.** The median holds at exactly -66 across eight consecutive 10 MHz
steps. Real interference does not hold a value to the dB across 60 MHz.

**It has edges.** Below 310 and above 370 the reading drops immediately to -85/-81/-92. The state
covers roughly 310-370 MHz and stops.

**It is not the low band.** 433.92 was clean throughout — a 150-window run at that frequency
produced 150 samples inside a 1 dB band, no excursions at all. Whatever this is, it does not act
on band 2 the way `57` concluded.

## 2. The floor is bimodal, which is why six earlier rounds could not pin it

`samples:110948, us_per_sample:9.01, min:-99, max:-68, runs:1, max_run_samples:110440` over a
one-second window. One run means the level crossed its threshold once and stayed there for 995 ms.
The `first64` array shows the entry: four samples at -99, two at -81, two at -72, then two at -68,
and from there it holds between -70 and -74.

So the true floor is reached, briefly, and then the level parks 30 dB above it. In a 150-window run
at 315, 143 windows read -66/-67 and 6 read between -109 and -112.

That split is the whole difficulty. A long average lands between the two states and describes
neither, and a short average returns one or the other unpredictably. Every earlier round averaged
across the split, and the two failure modes — "the floor is too high to trigger on" and "the floor
is fine" — are both correct readings of the same chip a second apart.

## 3. The induce/clear pair

The state can be created and removed on demand, which is what makes it identifiable rather than
merely observed.

**Induced by `lora_sleep_check`**, three times out of three. That handler releases `PIN_LORA_RST`,
reads the SX1278 registers, and — the part that matters — drives `PIN_SENSOR_CE` LOW for 150 ms
and then HIGH again. `gdo0_rail_test` does the same thing and produces the same result.

```
  start                        315 = -101
  INDUCE  lora_sleep_check     ->        -67
  CLEAR   rx_floor_check       ->       -101
  INDUCE  lora_sleep_check     ->        -67
          capture attempt      ->        -67     (does not clear)
  INDUCE  lora_sleep_check     ->        -67
```

`PIN_SENSOR_CE` (GPIO6) is not a LoRa-only rail. `gdo0_rail_test` answers the question directly:
with the rail down the CC1101 stops answering SPI (`version_rail_off: 0`). The rail powers the
CC1101, the SX1278, and the RGB level shifter together. Cutting it browns out the radio.

**Cleared by the modem writes only.** Inducing the state and then running single handlers
separates the candidates cleanly:

| handler | registers touched | result |
| --- | --- | --- |
| `rssi_path_check` | frequency, SIDLE/SRX | -67, **no effect** |
| `gdo0_probe` | IOCFG0 (0x02) | -67, **no effect** |
| `cap_mode` (OOK) | **MDMCFG2 (0x12), DEVIATN (0x15)** | **-103, cleared** |
| `rx_floor_check` | **MDMCFG2, DEVIATN** + AGCCTRL2 sweep | **-101, cleared** |

Frequency changes do not clear it. `IOCFG0` does not clear it. Re-entering RX does not clear it.
Writing `0x12`/`0x15` clears it, and those are the only two registers common to both successful
handlers.

## 4. What the latch most likely is

The evidence points at the AGC/FREND state rather than the PLL or the frequency registers:

- **A brown-out during a rail cycle** returns the CC1101 toward a power-on-reset condition, where
  `AGCCTRL2` (0x1B) and `FREND0` (0x22) hold their reset values rather than the capture
  configuration. already established that `AGCCTRL2.MAGN_TARGET` moves the reading
  across about 15 dB by itself, so a register block left at reset values is a sufficient cause for
  a large floor error.
- **`MDMCFG2`/`DEVIATN` clearing it** is consistent with that if the writes are what re-run the
  demodulator calibration, or if the strobe sequence around them (`SIDLE` then `SRX`) is what
  re-lands the AGC. The two registers are also part of the same configuration block `cc_init()`
  writes, so a rewrite of the pair is a partial re-init.
- **310-370 MHz** is inside the CC1101's band 1 (300-348) and the start of band 2. `cc_init()`
  writes no explicit band-select register; the CC1101 derives the band from the frequency word, so
  a wrong FREND0/AGC state would be expected to affect the band the last frequency word selected,
  which is consistent with a plateau that has edges rather than a spike.

**This is inference, not measurement.** What is measured is that the rail cycle creates it and the
modem writes remove it. The register-level mechanism is the most consistent reading of the
induce/clear pair and , and it is recorded as that.

## 5. Correction to 57

`57`'s §1 spectrum, §2 survey, §3 modulation control, and §4 closet comparison were all taken with
the state active. That changes what those numbers mean.

**What survives.** The *shape* — low bands sitting 15-35 dB above band 3 — is real, and the
independence from modulation is real (`-20.6` OOK against `-20.0` FSK) because both readings were
inside the same latched state. What `57` concluded from that shape was reasonable given the data:
that it was upstream of the modulator settings. It was. It was upstream in the AGC block.

**What does not survive.** `57` §4.5 proposed a second-CC1101 comparison to decide between "the
card" and "the location". That comparison was run: a Flipper Zero in the same room read **-87 at
315** while the card read **-72** in the same state, and the Flipper's own worst deviation was at
868 — the band where the card is quietest. Read at the time as evidence that the elevation follows
the card and is therefore card-specific physics, it is better explained as evidence that the card
was in a state the Flipper was not. The Flipper was the cleaner receiver, and the card was latched.

**`56` is unaffected.** Its 1 dB margin between the noise peak and the one real 315 signal was
measured with the state active, which is the condition the card is usually in. The margin is real;
its cause is now partly the latch.

## 6. What this changes for the 56/57 conclusion

Both notes treated the elevated floor as either an environment property or a receiver property, and
neither could separate them because both were inside the elevation. The separation was never
available from the spectrum, because the spectrum was the fault.

With the state cleared, 315 reads **-101 to -105** across ten minutes of continuous sampling — 75
windows, no excursion outside 4 dB, no pedestal. The card is a quiet receiver at 315. It reported
otherwise because it was latched.

The band-1 elevation in `57` is withdrawn as an environmental finding. It is a latched-state
finding.

## 7. Status

| item | status |
| --- | --- |
| The floor sits ~35 dB high across ~310-370 MHz in a latched state | **measured** |
| The state is bimodal within a window (143 of 150 high, 6 at true floor) | **measured** |
| 433.92 MHz is unaffected by the state | **measured** — 1 dB spread over 150 windows |
| Cycling the sensor rail induces the state | **measured** — 3 of 3 |
| Rewriting MDMCFG2/DEVIATN clears the state | **measured** — 2 of 2 |
| Frequency writes, IOCFG0, or re-entering RX clear it | **disproven** — all left it at -67 |
| A capture attempt clears it | **disproven** — left it at -67 |
| The clearance is why `57`'s second draft read the environment as ruled out | **corrected** |
| The register-level mechanism is AGC/FREND at reset values | **inferred**, consistent with `48` |
| Cleared, 315 holds -101 to -105 over 10 minutes | **measured** |

## 7.1 Caveat added after on-hardware validation: this is not one state

The fix was validated on the card, and it works — but only against one form of the elevation,
and the picture is narrower than §1–§6 imply.

**Validated.** From a clean floor, `lora_sleep_check` raised 315 to -65 and the next
`captureSignal()` returned it to **-104**, a 39 dB clear:

```
  baseline      315 =  -73   433.92 =  -72
  induced       315 =  -65   433.92 =  -91     (lora_sleep_check)
  after capture 315 = -104   433.92 =  -97     *** capture cleared it ***
```

**Not validated.** Repeated `lora_sleep_check` calls push the card into a *second*, broader
elevation that capture does **not** clear, and which reaches 433.92:

```
  300   315   320   360   390   420  433.92  464   600   700   868   915
  -75   -73   -67   -62   -88   -89   -72    -75   -99   -99   -98   -96
```

Three `capture` attempts in this state returned -73 each time — no clearing. This is the shape
`57` measured, and it matches `57`'s numbers closely (315 -72 against -73; 360 -61 against -62;
433.92 -78 against -72). Band 3 stays clean throughout at -96 to -99.

**A mechanism for it.** `lora_sleep_check` drives `PIN_LORA_RST` **HIGH** before its register
reads — it must, because a chip in reset does not answer SPI — and the module is then *awake*
until the `loraParkReset()` at the end of the handler. It also runs `loraHardReset()` after the
reads, which ends by releasing RST and only sleeping the part by register. So the handler leaves
the SX1278 powered and awake for a period, twice, whatever it does at the very end. Whether the
persistent elevation is the module's own emission into the shared front end, or a CC1101 AGC that
has adapted to a strong nearby LO and does not re-adapt on the modem writes, is **not
established**.

**What this means for the fix.** v3.84's unconditional `MDMCFG2`/`DEVIATN` write clears the
shallow form. It does not clear the deep form. The fix is a real improvement and not a complete
one, and the status table in §7 should be read with that limit.

**What this means for 57.** Its spectrum is the *deep* form, not the shallow one, so §5's
correction needs qualifying: `57`'s numbers are a receiver state, but which receiver state is
now open again, and the "environment" reading is not as cleanly excluded as §5 states.

## 7.2 Fine structure of the deep state

A 20-point sweep across 312-456 MHz with the sweep paused shows the deep elevation is not a
uniform rise. It has two hot regions separated by a genuinely quiet gap:

```
   312   -71        384   -84   (quiet)
   320   -67        392   -84   (quiet)
   328   -73        400   -84   (quiet)
   336   -70        408   -84   (quiet)
   344   -77        416   -79
   352   -70        424   -83
   360   -63  hot   432   -77
   368   -70        433.92 -73
   376   -73        440   -62  hot
                    448   -74
                    456   -77
   600   -99   700  -99   868 -99   915 -96   (clean)
```

The two peaks sit at **360 and 440 MHz** (-63 and -62), and the quiet gap 384-424 reads -84,
which is close to band 3's -99 minus the band-1/2 penalty. So this is not one broad elevation but
a shaped response, and a single-frequency test at 315 can miss most of it.

**The harmonic reading does not hold up.** 360 and 440 are both multiples of the ESP32's 40 MHz
crystal (9x and 11x), but so are 320 (8x) and 400 (10x), and those read -67 and -84 — an 17 dB
gap that no single harmonic series explains. The 32 MHz SX1278 series fits no better: 384 (12x)
is the quietest point in the sweep.

**The SX1278-awake hypothesis is therefore untested.** It remains the leading candidate for the
deep state because the rail-cycle handlers leave the module powered and awake, and because band 3
— which the SX1278 also covers — stays clean throughout. Neither claim is a measurement, and the
state persists across repeated `capture` calls and repeated `rx_floor_check` calls, so the
diagnostic that clears the shallow state does not touch this one.

## 8. Tooling

`tools/band_survey.py` and `tools/rssi_trace.py` both pause the sweep and are receive-only, which
is the correct shape for this measurement. What neither does is check for the latch before
measuring, and a survey taken while latched produces a plausible-looking spectrum that is wrong by
35 dB in one band. The practical rule that comes out of this round: **read 315 and 433.92 back to
back, and if 315 is more than 20 dB above 433.92, clear the state before recording anything.** With
the state clear, both sit within a few dB of each other and of band 3.
