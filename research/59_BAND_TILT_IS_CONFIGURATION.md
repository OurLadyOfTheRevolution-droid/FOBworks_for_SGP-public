# 59 — The band tilt: configuration-dependent, and not the LoRa module

`58` left two things open. It recorded a *deep* elevation reaching 433.92 that a capture did not
clear, and it named the SX1278 — left awake by the rail-cycle diagnostics — as the leading
candidate. Both are now settled, and not in the direction `58` guessed.

The elevation is **not a latch and not the module.** It is the board's normal operating state, it
is present from the first boot, and it follows the register configuration rather than anything in
the environment or the radio's surroundings.

## 1. The SX1278 is not the source

`lora_power_floor` measures one frequency with the CC1101 held in a single configuration while the
SX1278 is put through four power states: awake out of reset, held in reset, parked (CS high, RST
low), and unpowered (sensor rail cut). If the module were what the receiver hears, parking it would
drop the floor.

```
   freq     awake   rst_high   parked   rail_off   awake-minus-parked
  360.00      -74       -76      -75       -74            1 dB
  440.00      -94       -94      -95       -94            1 dB
  433.92      -95       -94      -94       -94           -1 dB
  315.00     -109      -109     -109      -109            0 dB
  868.30     -113      -113     -113      -112            0 dB
```

**Every state reads within 1 dB of every other, at every frequency.** 868.30 is outside the
SX1278's 137-525 MHz range and serves as the control; it moves by nothing, as it should. The five
frequencies include the two hot points the deep state had shown (360 and 440).

So the hypothesis `58` §7.1 raised — that the rail-cycle diagnostics raise the floor by leaving
the module powered and awake — is **disproven**. Whatever the module does to the shared GPIO48
line, it does not put energy into the receiver's band.

One useful thing came out of the same run: **during it, every frequency read clean.** 315 at -109,
433.92 at -95, 868 at -113. The probe was measuring a quiet card.

## 2. The elevation is the default, not a latch

Minutes after that run, with no configuration command in between, the same frequencies read:

```
  315.00   -76      360.00   -64      433.92   -74      868.30   -98
```

That is a 34 dB spread where the probe had just measured 4 dB. Two things follow, and they were
tested directly rather than assumed:

- **It is present immediately after a fresh boot.** Opening the port resets the chip, so a fresh
  boot is available on demand. Measuring nothing but the floor after boot gives 315 = -76,
  360 = -64, 433.92 = -74, 868.30 = -98. **34 dB tilt at boot.**
- **It does not drift.** Twenty seconds later: -77, -64, -74, -98. Unchanged.

A latch that is present at power-on and never relaxes is not a latch; it is the configuration.

## 3. What makes the difference

The two states were both measured on the same hardware minutes apart:

| state | 315 | 868 | tilt |
| --- | --- | --- | --- |
| registers at power-on-reset values | -109 | -113 | **4 dB** |
| configuration `cc_init()` writes | -76 | -98 | **22 dB** |
| a Flipper Zero in the same room | -87 | -85 | **2 dB** |

The probe left `AGCCTRL2`, `FREND1` and `FREND0` at the values it swept rather than at the shipped
ones — that is the practical difference between the two rows. So the tilt is a property of the
configuration, not of the board's surroundings, and `58`'s reading of `57` as an "environment"
measurement is now settled the other way: **the tilt is the receiver configured a particular way.**

## 4. Three register fields tested, none of them is the cause

`agc_tilt` swept `MAGN_TARGET` (AGCCTRL2 bits 2:0) across all eight values and three `FREND1`
settings, measuring the floor at 315 and 868.3 for each. `frend0_tilt` swept `FREND0`'s PA_POWER
across all eight values.

```
  MAGN_TARGET  mt=0..7   tilt = [0, 16, 16, 14, 16, 13, 16, 19] dB
  FREND1       0x56, 0x96, 0xB6   tilt = [15, 14, 15] dB
  FREND0 PA    0..7      tilt = [15, 14, 14, 14, 15, 13, 16, 14] dB
```

The shipped values are `MAGN_TARGET`=3, `FREND1`=0xB6, `FREND0`=0x06 (PA_POWER=6), and their
tilts are 14-16 dB. **No setting of any of the three brings the tilt below 13 dB.**

That is a bounded negative result and it is worth stating plainly: the tilt is not reachable from
the front-end gain registers a firmware can write. What remains is the RF matching network — the
balun, the filter and the antenna path — which is hardware, differs between band 1/2 and band 3 by
design, and is not addressable in software.

## 5. Why this matters less than it sounds

The tilt does not by itself break captures, and this is the useful part.

`captureSignal()` sets `trigThr = noiseMax + 10`, where `noiseMax` is the floor it just measured.
A tilted floor of -76 therefore puts the trigger at -66, and the 315 MHz fobs on this bench arrive
near -64. **The margin is about 2 dB rather than the 10 dB the code intends.**

So the tilt costs margin, and the hard failure was the latch: a latched floor of -66 put the
trigger at -56 and nothing near -64 could ever cross it. `v3.84` clears the latch. The tilt is the
residual and it is a margin problem, not a dead path — which is consistent with weak 315 captures
having worked intermittently all along while latched ones never worked at all.

## 6. Corrections

- **`58` §7.1 named the SX1278 as the leading candidate for the deep state.** Disproven here — four
  module power states, five frequencies, all within 1 dB.
- **`58` called the deep state a second "state" alongside the latch.** It is better described as the
  board's normal configuration. The latch is a fault layered on top of it.
- **`57`'s band elevation stands as a measurement and is now fully explained as receiver-side.** It
  is what a CC1101 on this board reads across its two low bands with this configuration. It was
  never the police tower, and `58` was right to withdraw that reading, though for a different
  reason than it gave.

## 7. Status

| item | status |
| --- | --- |
| The SX1278 raises the floor at 315/360/440/433.92 | **disproven** — 1 dB across four power states |
| The elevation is present at first boot | **measured** — 34 dB tilt, no drift over 20 s |
| The elevation follows the register configuration | **measured** — 4 dB versus 22 dB tilt |
| A Flipper Zero in this room reads flat | **measured** — 2 dB tilt |
| `MAGN_TARGET` accounts for the tilt | **disproven** — 13-19 dB across all eight values |
| `FREND1` accounts for the tilt | **disproven** — 14-15 dB across three settings |
| `FREND0` PA_POWER accounts for the tilt | **disproven** — 13-16 dB across all eight values |
| The tilt is the RF matching network | **inferred** — the remaining candidate, not measured |
| The tilt costs capture margin | **measured** — trigger at floor+10 leaves ~2 dB on 315 |
| The tilt is what `57` measured | **established** — same shape, same magnitudes |

## 8. Tooling

Three probes, all receive-only, all restoring the capture configuration on exit:
`lora_power_floor` (module power states), `agc_tilt` (MAGN_TARGET and FREND1), `frend0_tilt`
(PA_POWER).

**A note on reading their replies.** `agc_tilt`'s first version built a thirteen-entry array plus
two long strings and the card accepted the command without emitting anything — consistent with the
concatenation exhausting heap on a board with WiFi and BLE live. Building the same measurement as
eight small fields fixed it. When a handler is silent, check the reply size before suspecting the
handler.

The host side has a matching trap: the reply is emitted correctly but a parser that brace-matches
across a read boundary will corrupt it. Print the raw line before concluding a command did not
answer — `agc_tilt` answered on the first attempt and was reported as silent twice.
