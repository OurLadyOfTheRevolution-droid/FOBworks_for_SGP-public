# 88 — The second radio on the bench: the SX1278 self-jams the CC1101, measured

Status: `87` §5 shipped the SX1278 CW path and the `lora_cw_probe` that measures how far the
CC1101's own floor rises while the second radio transmits beside it, and listed the bench run as
the one thing left. The Flipper and the card were both reachable this session, so the run
happened. It took four fixes to get a trustworthy number, and once the instrument was honest the
answer was unambiguous and the opposite of a close call: on this PCB the SX1278 cannot transmit
without burying the CC1101. The probe's first real answer was not a number, it was `NOT_TX` —
three times in a row, for three different reasons.

## 1. The card was running a build older than the probe

`lora_cw_probe` answered `unknown-cmd` on a card that reported `v4.01`, because the flashed image
predated the handler. The sketch on disk was newer than the binary in flash. Rebuild and flash
first, judge the probe second; the tree was green at 1,830,792 B (58%) / 163,668 B (49%) and the
upload verified.

## 2. The chip was held in reset, so every write went nowhere

The first probe after flashing returned:

```json
{"opmode_readback": 8, "floor_quiet_dbm": -84, "floor_jam_dbm": -83, "rise_db": 1,
 "verdict": "ISOLATED",
 "note": "RegOpMode did not read back in TX (bit1 clear): the mode write did not land"}
```

The guard did its job — it refused to call that an isolation measurement — but the reason was not
a bad register sequence. Since v3.82 the module is parked with `PIN_LORA_RST` held **LOW**
(`loraParkReset`), and a chip held in reset does not answer SPI at all. `lora_cw_probe` raised the
sensor rail but never released RST, so every `loraWriteReg` was shifted into a part that was not
listening. Two existing probes already knew this and show it directly:

| probe | result | meaning |
| --- | --- | --- |
| `lora_rst_check` | `version_rst_high: "12"`, `version_rst_low: "0"` | RST HIGH the SX1278 answers; RST LOW it is dead to SPI |
| `lora_sleep_check` | `spi_live: true`, `sleep_landed: true` | it releases RST before reading, which is why it works |

The fix is one line — release RST before the first write — plus a `RegVersion` (0x42) control so
"the chip is not answering" can never be mistaken for "the write failed". The quiet floor fell
from −84 to −91 dBm the moment the chip came alive, which is itself a small confirmation the part
had been off.

## 3. The mode word was FSTX, not TX, and SLEEP was jumped straight to TX

With SPI live, `lora_version_reg` read `0x12` and the floor dropped, but the mode was still wrong.
Two defects in one function:

- The mode word was `0x02`. Mask `0x07` (Mode) is SLEEP 0, STANDBY 1, **FSTX 2**, **TX 3**, so
  `0x02` was FSTX: the synthesiser runs and the PA stays off. TX is `3`.
- It went SLEEP → TX in a single write. The datasheet state machine only allows
  SLEEP → STANDBY → TX, so the direct write was ignored — read back as `0x08`, the LF band bit
  set with Mode still SLEEP, which is exactly the signature of a rejected transition.

A third, smaller thing: the readback was taken on the SPI word right after the write, which
catches the state the chip is *leaving*. `delayMicroseconds(2000)` before each read fixed it, and
after that the readbacks tracked one-to-one with the writes (`opmode_standby: 9`, then
`opmode_readback: 11` = TX + LF).

## 4. The floor clamp was hiding the size of the effect

Even with the PA on, the sweeps came back *flat*: `floor_jam_dbm: -75` for every offset
(100 kHz–1 MHz) and every power (2–15). A frequency-selective jammer cannot behave that way, and
the reason was in the probe's own floor helper — it applied the capture path's clamp,
`if(v>-60) v=-75;`, which substitutes −75 "because a fob was transmitting". That is right when a
floor is only used to set a trigger threshold and wrong when the floor *is* the measurement: it
pinned the jammed reading to a constant and made the sweep look independent of offset and power.
Removing it, the jammed floor came back at −17 to −31 dBm — far above the −60 that had triggered
the clamp, and far above any level the CC1101 would ever see from a fob.

A saturation note travels with the number now, because `cc_fastRSSI` tops out near −74 dBm by
arithmetic (`r=255 -> (255-256)/2-74`) and the CC1101's RSSI scale ends near −10.5 dBm; a reading
at the rail is reported as pegged rather than as a level.

## 5. The measurement

Listen at 433.92 MHz, SX1278 CW offset above it, `pwr=15`, unclamped:

| offset | jam freq | quiet floor | jammed floor | rise | 
| --- | --- | --- | --- | --- |
| 0 | 433.92 | −83 | −20 | **+63** |
| 300 kHz | 434.22 | −83 | −17 | **+66** |
| 1 MHz | 434.92 | −84 | −31 | **+53** |
| 2 MHz | 435.92 | −84 | −50 | **+34** |
| 4 MHz | 437.92 | −83 | −65 | **+18** |
| 8 MHz | 441.92 | −83 | −65 | **+18** |
| 12 MHz | 445.92 | −84 | −76 | +8 |
| 20 MHz | 453.92 | −83 | −99 | −16 |

Every run confirmed TX at the start *and* the end of the window (`start=0x0B end=0x0B`), so the
carrier held; a start-only readback could not have told that apart from it dropping out.

Two things fall out of the shape:

- **The isolation knee is beyond 8 MHz, and it is not a hard edge.** The rise is still +18 dB at
  8 MHz off, where any real RKE channel 8 MHz away from the jammer is buried. It only reaches
  noise (+8) at 12 MHz. An off-band jammer on this board would have to sit more than 12 MHz away —
  further than the sub-GHz plan has room for between the channels that matter.
- **Power does not matter.** `pwr` 2 through 15 all put the jammed floor at or near −17 dBm at
  300 kHz offset, so there is no low-power setting that jams gently. The coupling is not the PA
  output at all.

## 6. What the coupling actually is, and the control that shows it

`lora_power_floor` was already in the tree as the control, and it is decisive. At 433.92 MHz:

| SX1278 state | CC1101 floor |
| --- | --- |
| awake after reset, **not** transmitting | −83 |
| RST high held | −84 |
| parked | −84 |
| (rail cut) | −74 — meaningless, that rail also powers the CC1101 |

Awake-but-idle moves the floor by 1 dB. Parked is the same as awake. So the 60-plus dB rise is
**not** the chip merely being powered or out of reset — it appears only when the SX1278 is in TX.
The two radios share the 3.3 V sensor rail and their outputs are centimetres apart on the same
PCB, so what the CC1101 sees is the SX1278's PA operating directly into its front end, not a
distant signal the antenna was going to capture anyway.

The Flipper was on the bench too and was used for the external leg the `87` procedure asks for —
is a second, independent receiver hearing only the jammer? The raw `rx_raw` stream at 434.22 MHz
showed plenty of activity during a burst, but the control kills the inference: the same Flipper at
the same frequency counts *more* short pulses when the card is idle. That traffic is ambient 434
MHz, not the SX1278, and **no external confirmation of the transmission was obtained**. The
self-jam number does not depend on it — it is a two-port measurement on the card, and it is the
number the experiment wanted — but the external check is recorded as *not done*, not as passed.

## 7. The answer to P2

The `87` procedure framed P2's question as "whether the CC1101 can still hear a fob while the
SX1278 transmits, and by how much". The measurement answers it: a fob at 1 m puts roughly
−60 to −70 dBm at the CC1101; the jammer puts −17 dBm there, 40-plus dB above it. An SNR that
started at +20 dB becomes −40 dB. On this PCB, with these two radios, **a two-radio RollJam does
not work, and it is not marginal.** Kamkar's original arrangement was two CC1101s in a purpose-built
box; this board's second radio shares a rail and a ground plane with the first, and that is the
whole difference.

That is a negative result, and it is the useful kind: it closes the one hardware experiment `85`
ranked as paying, it stops anyone re-deriving it, and it leaves a calibrated instrument behind for
the next board revision — a shield, a daughterboard, or a part that can actually be separated.
The pieces the failure *does* leave usable:

- `lora_cw_probe` as a self-jam meter: an operator can watch the CC1101's floor while keying the
  second radio and read out isolation directly.
- The transmit path itself works. The same sequence keys a real CW carrier; if a future revision
  distances the two radios, the jammer is already written and host-verified.
- `lora_power_floor` as the awake-versus-transmitting control, so a rise can always be attributed.

## 8. State after this note

| item | state |
| --- | --- |
| P2 SX1278 second radio | **bench run done; negative — self-jam 60+ dB, isolation knee beyond 8 MHz** |
| `lora_cw_probe` instrument | four defects found and fixed (reset, mode word, state order, settle); now reports real levels |
| `lora_power_floor` | confirms the rise is the PA, not the chip being awake |
| External receiver leg | attempted with the Flipper; control shows the observed energy was ambient — **not confirmed** |
| Firmware | v4.02, 58% flash / 49% RAM, 41/41 host suites |

The thresholds that were still guesses in `87` §6 are unchanged by this run — the rise is so far
above any of them that no calibration would change the verdict. What is left open is P3 (needs an
authorised car for a resync dataset) and P5 (needs a car park to calibrate), both still blocked on
a paired receiver, exactly as `85` records.
