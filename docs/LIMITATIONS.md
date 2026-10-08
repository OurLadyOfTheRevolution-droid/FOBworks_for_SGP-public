# Limitations

What this firmware can and cannot do on the May 2026 SGP Card Mini, sorted by how
the claim was established. Read with `PROMO.md` § "What this revision can and cannot
do" and the hardware-limits section of `README.md`.

## Measured on this board

| Limit | Evidence |
| --- | --- |
| CC1101 GDO0 is not on a readable GPIO; GPIO 48 is the SX1278 DIO0 | `research/79_GDO0_HARDWARE_AUDIT.md`, `gdo0_signal` → `RAIL_SHARED_CANNOT_ISOLATE` |
| Lifting Ra-02 DIO0 is reversible and does not free a CC1101 data pin by itself | `research/80_RA02_DIO0_LIFT_REVERSIBLE.md` |
| SX1278 CW at 433.92 MHz lifts the CC1101 floor >60 dB on-channel, ~18 dB at 8 MHz | `research/88_SX1278_SELFJAM_MEASURED.md`, `lora_cw_probe` / `lora_power_floor` |
| 315 MHz capture failures track latched modem / AGC state, not a hard band guard | `research/56_315_FALSE_ELEVATED_FLOOR.md`, `research/58_LATCHED_FRONTEND_STATE.md`, `research/59_BAND_TILT_IS_CONFIGURATION.md` |
| Of 44 decoders, 35 never fire on the 301-capture corpus; 270 captures match none | `docs/CORPUS_SCORECARD.md` |
| A flat four-band floor (spread ≤2 dB, ≤ −95 dBm) is a latched front end, and capture refuses with `capture_refused` instead of arming on nothing | `research/114_TX_SNAP_CAPTURE_GATE_CDC.md`, `cc_reinit` / `capgate` |
| Pre-snapping a body onto its own T/2T grid does not cure the jitter round-trip; the packet encoder already quantises to that grid | `research/114_TX_SNAP_CAPTURE_GATE_CDC.md`, `snapgrid` |

## Host-verified, not car-verified

| Claim | Evidence |
| --- | --- |
| Sequencers, encoders, and frame trim pass host suites | `test_*.py` |
| An external receiver has decoded a transmitted waveform | `PROMO.md` |
| Gate false positives (Somfy/Nice) drop to zero after the ratio windows | `research/93_GATE_DECODER_FALSE_POSITIVES.md` |
| Security+ 2.0 gate width is not the blocker; framing is | `research/94_SECPLUS2_GATE_IS_NOT_THE_BLOCKER.md` |
| Renault ~33 µs "PWM frame" model is falsified on the corpus | `research/82_RENAULT_33US_MODEL_FALSIFIED.md` |
| Hitag2 RKE correlation attack recovers synthetic keys; corpus sits at the attack floor | `research/86_RENAULT_RKE_CORRELATION_ATTACK.md` |

**The firmware has not been tested against a car.** A decoder accepting a waveform is
not the same as a paired vehicle receiver accepting a sequence.

## Hardware-blocked on this revision

| Missing capability | Why |
| --- | --- |
| Edge-accurate OOK capture | GDO0 unrouted; RSSI poll ~1600 µs |
| Simultaneous jam + listen on one CC1101 | Single radio; C1 drops the carrier during capture windows |
| 125 kHz passive-entry / Hitag2 / Megamos / DST40 | No LF front end; CC1101 starts at 300 MHz |
| Off-band jamming from the SX1278 | Shared rail and ground; self-interference dominates |
| PN532 / 13.56 MHz NFC | Present on I2C at 0x24, unused by this firmware; HF, not the 125 kHz LF the immobilisers need |

## Falsified (do not re-derive)

| Hypothesis | Result | Note |
| --- | --- | --- |
| Renault Megane/Captur ~33 µs captures are fixed-slot PWM frames | Falsified | `research/82_RENAULT_33US_MODEL_FALSIFIED.md` |
| Somfy/Nice content metrics (`maxAltRun`, transition density) separate noise | Falsified | `research/93_GATE_DECODER_FALSE_POSITIVES.md` |
| Security+ 2.0 needs a wider ratio gate | Falsified — framing, not gate | `research/94_SECPLUS2_GATE_IS_NOT_THE_BLOCKER.md` |
| SX1278 can jam while the CC1101 listens cleanly on an adjacent channel | Falsified on this PCB | `research/88_SX1278_SELFJAM_MEASURED.md` |

## Deliberately not claimed

- Manufacturer-key derivation from a single air capture
- RollJam / RollBack success against a paired vehicle
- Coverage of every protocol named in the decoder list (see the never-fire table)
- That a confident decode is a correct identity — consensus demotion and gate windows
  exist because wrong labels are worse than silence
