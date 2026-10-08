# FOBworks for SGP

This firmware targets the SGP Card Mini stock acquired in May 2026: an ESP32-S3-MINI-1-N8 with 8 MB flash and no PSRAM. It uses the card's CC1101 for sub-GHz work. The board also carries a Ra-02 SX1278. GPIO 48 is connected to the SX1278's DIO0; the CC1101's GDO0 is not routed to a readable GPIO, and putting the SX1278 to sleep does not restore that connection. This firmware targets this board revision only.

The card creates a Wi-Fi network named `SGP Card Mini` and serves its dashboard at `http://192.168.4.1`. At startup, it prints the Wi-Fi credentials and access code over USB serial. The same code is used by the separate React dashboard, which can connect over USB or Wi-Fi. That dashboard is not included in this repository; see `README.md` for the connection steps.

The home screen lists four modes. Tap **Mode** in the header to return to the list. Hold the user button for 3 seconds to put the card to sleep; hold it again for 3 seconds to wake it.

FOBcatch and FOBback are guided transmit sequences. C1 and C2 are their respective sequencers. Each requires an explicit arm, consumes it after one shot, and refuses to run if its preconditions are not met.

## FOBscan

FOBscan is the workbench for capture, sweep, decode, prediction, key management, and the signal library. These tools are arranged across seven tabs: Capture, Scan, Decode, Predict, Keys, Library, and Instruments.

**Capture** starts and stops listening, selects OOK or 2FSK, and shows the latest burst. **Scan** cycles through the card's channels or stays on one channel. **Decode** reports the protocol, serial, button, counter, and frame-check result. **Predict** shows the next counter inferred from frames in memory. **Keys** is where a saved manufacturer key is added, tested, or cleared. **Library** lists captures stored on the card, grouped by protocol and serial.

From idle, one button tap starts FOBscan without the screen. The LED pulses orange; a kept decode flashes the pixel white before orange pulsing resumes. Tap again to stop.

## FOBclone

A guided scan for a selected vehicle. Choose the make, model, and year; the card sets the profile's band and modulation and waits for a fob press. The screen lists captured frames and can send a saved frame back, including the next predicted counter when the decoder can provide one.

From idle, two taps start this scan without the dashboard. The LED pulses blue while the card listens. After it recognizes a fob, one tap sends the saved frame. Before recognition, one tap changes the band preset. Two taps stop the scan.

## FOBcatch

FOBcatch listens using a selected vehicle profile. Choose the make, model, and year, then press the fob. The screen keeps the capture and allows naming it; **Replay** sends the saved frame.

## FOBback

FOBback is a guided resynchronization sequence for receivers that accept a short run of saved codes. Choose the make and vehicle, then press the fob until the card has enough frames. **Replay** sends the saved frames in capture order. The card holds its frequency while collecting them.

FOBback uses the C2 RollBack sequencer. It sends exactly two codes, older first, with a configurable gap of 40–2000 ms. A shorter gap can look like a single press; a longer one may exceed the receiver's resynchronization window. The sequencer refuses to run when:

- fewer than two codes are available;
- the counters are equal or out of order. Sending the same code twice cannot resynchronize the receiver, so the sequencer reports the problem instead of transmitting.

Before storage, each capture is trimmed to one frame. A physical press usually repeats the frame; replaying a three-repeat block could appear to the receiver as three presses, advancing its counter by three and breaking the sequence.

A stored frame can also be loaded through `fbk_import`, using a FOBworks RAW file or a `.sub` capture. That path tests a transmit without making a live capture.

## Signal library

Kept decodes appear here, grouped by protocol and serial. The card writes each to the microSD as a FOBworks RAW file and reads the library back for display. Groups that contain readings from the same fob can be merged, captures that no decoder matched can be hidden, and the library can be exported as JSON. Exported filenames begin with `fobworks_library_`.

A standalone FOBworks RAW file contains a short header, frequency, and pulse list. Send the file back to the card to transmit those pulses at the frequency recorded in it.

## Key recovery

Key recovery is intended for an owned KeeLoq fob. Press the same button two to five times while the card listens. Recovery checks the built-in table and any keys saved on the card. It keeps a candidate only if every press decrypts to the same serial and button with a counter that advances. A match to a filler pattern in the built-in table is labeled **pattern match**; a saved key is reported separately. If no key matches, recovery reports no match. It does not derive a manufacturer key from a transmission.

The built-in table contains 73 entries. Of this firmware's 44 decoders, 35 have never fired on the corpus, and 270 of 301 captures are matched by none — mostly because the corpus is car fobs while the never-fire set is largely gate and garage protocols (Came, Nice, FAAC, Hörmann, Sommer, and the like). Kia is the exception worth naming: both V1 and V34 match, and after the claim-bug fix the V1 decoder runs on the card as well as in the host harness; the four Kia decoders that still find nothing are V0, V2, V7, and SantaFe. The live ledger is `docs/CORPUS_SCORECARD.md`, regenerated from `tools/corpus_regression.py`.

Recovery reports a candidate only when it decrypts two consecutive frames consistently. A single frame is not enough: this check uses 12 bits, so a wrong key may match one frame about once in 4,000 tries. Transmitting a code derived from a wrong key could desynchronize the fob.

The serial command `key_probe` tests one candidate key against recent KeeLoq frames without starting a full recovery. `key_recover_offline` runs the same recovery against a supplied hop list, without using the radio.

## C1 RollJam

The C1 capture-and-replay sequence is exposed through the `rolljam_*` serial commands and the dashboard. It jams the first fob press so the receiver does not hear it, then captures it. During the second press, it jams and captures again, then replays the **first** code during the second jamming window. The intended result is that the door unlocks on the second press while the card retains the second, unused code.

Because RollJam jams and transmits, it has several safeguards:

- It requires an explicit arm. Arming is refused while a sequence is running, and one start consumes the arm so a double tap cannot trigger another run.
- Both captures must decode to different counters in the expected order. Otherwise, it reports the reason and does not transmit.
- Jamming stops on every exit path: timeout, capture failure, same-code refusal, transmission, success, and boot. Stopping it before other boot work begins limits the risk of a jam continuing through a reset.

The CC1101 cannot jam and listen simultaneously. The sequence drops the carrier during each capture window; that timing still needs to be confirmed on hardware. Jamming uses packet-mode TX from the FIFO, and `jam_status` reports underruns. Check it when a sequence fails: a gap in the carrier is different from a receiver rejecting a frame.

## Bluetooth

Bluetooth is reachable over the HTTP API, not the card dashboard. `GET /api/ble_scan?duration=N` starts a passive advertisement scan of one to thirty seconds and returns immediately; `GET /api/ble_results` polls the list of up to twenty advertisers — MAC address, name, RSSI, service UUIDs, and the first sixteen bytes of manufacturer data. Names and UUIDs are matched against known car-security and smart-lock systems. **Pair** opens a short GATT advertising window named `SGP Card Mini` so a phone can bond (`/api/ble_pair_start`, `/api/ble_pair_status`, `/api/ble_pair_stop`); **Paired devices** lists bonded-device metadata (`/api/ble_paired_devices`). The card does not expose identity keys.

## Diagnostics

Four read-outs run alongside the modes, and the dashboard's Instruments tab draws all four from their endpoints: the claim trace, the resync curve, the parked RollJam watchdog, and the clone-chip classifier. Each has a serial command and an HTTP route, so the raw JSON is reachable over the `{"cmd":…}` path as well. Two further read-outs — the hop-XOR strip and the second-radio CW probe — are decode-side and bench read-outs rather than tab panels.

**Claim trace.** The last eight decodes, newest first, each with the timing it decoded at, the pulse count, the timing spread, which gate ran, and the protocol label it produced. The gate reads `loose` for a bare claim, `gate` for a candidate, `known` for a confirmed decode. This is the view that shows a mis-gated frame next to the timing that produced it. `{"cmd":"claim_trace"}`, `{"cmd":"claim_trace","clear":true}`, or `GET /api/claim_trace`.

**Resync curve.** A receiver's resynchronization window drawn as a curve rather than a single ramp: forward offsets, a backward step, and a replay of an already-seen code. Each probe transmits, then listens after a settle gap; a reply is marked only when the band rises 8 dB over idle for three samples. A body controller that does not acknowledge over RF yields `unknown`, not `reject`, and a probe can be marked by hand after watching the car. `{"cmd":"resync_curve"}`, `{"cmd":"resync_curve_status"}`, `{"cmd":"resync_mark","r":"accept"}`, `GET /api/resync_curve`.

**Parked RollJam watchdog.** With the card parked and listening, this watches the idle noise floor against a fast-attack, slow-decay baseline and looks for the RollJam shape: the floor lifted by a jammer, then two KeeLoq frames from the same fob and button with consecutive counters inside 1.2 s. A passing car keying up is a spike and moves nothing; a jammer held on is a plateau. The score rides along on the next KeeLoq decode as `rolljam_ids`, `rolljam_jam` and `rolljam_floor_db`, and `{"cmd":"p5_ids"}` or `GET /api/p5_ids` reports it directly.

**Clone-chip classifier.** For the held KeeLoq frames, this judges key-free whether the transmitter's hop field behaves like a cipher or like a counter in disguise. Counter-linearity is a proof — when the hop XOR equals the counter XOR, the part is not running a cipher — while hop-XOR sparsity is a statistic that separates a counter-tracking clone from real KeeLoq. `{"cmd":"clone_class"}` reports it, `GET /api/clone_class` serves the same, and every KeeLoq decode carries `clone_class`.

**Hop-XOR strip.** For two same-button KeeLoq hops the XOR is key-independent — it equals the XOR of the two encoded plaintexts, not of the hopping codes — so the Decode tab shows it as a bit strip without recovering a key first. Read it as a fingerprint of two presses, not as a decode.

**Second-radio CW probe.** `{"cmd":"lora_cw_probe"}` keys the SX1278 as a continuous-wave carrier and reads the rise back at the CC1101, measuring how much the second radio lifts the CC1101's own floor. It is a bench measurement, not a mode.

**What the bench measured.** Run against the card with the two radios side by side, the second radio is not usable as an off-band jammer. Keyed at 433.92 MHz it lifts the CC1101's floor by more than 60 dB on-channel and is still 18 dB up at 8 MHz away; the two radios share a rail and a ground plane, so the coupling is the PA operating into the neighbouring front end, not a distant signal. The probe and the control (`lora_power_floor`) are what establish that; the write-up is `research/88_SX1278_SELFJAM_MEASURED.md`.

## A basic capture workflow

1. Connect the SGP Card Mini over USB and read the access code from the serial log at 115200 baud.
2. Join `SGP Card Mini` and open `http://192.168.4.1`. If the separate React dashboard is available, connect over USB or Wi-Fi instead; `README.md` has the instructions.
3. Enter the access code to reach the mode picker.
4. Open FOBscan, leave the sweep running, and press a button on an owned fob near the card.
5. Check the decoded protocol family, serial, button, and counter.
6. Save the capture to the library. Export the library when a copy off the card is needed.

The basic workflow is to capture a transmission, inspect the decode, and save it.

## What this revision can and cannot do

Replay, jamming, and both sequencers drive the CC1101's power amplifier from its TX FIFO. A separate receiver decoded one transmitted frame as a Kia unlock and identified its protocol and button. A stored frame's identity can be read back without transmitting (`fbk_ident`), so a replay is checked against the frame actually held rather than the frame the caller asked for.

Capture currently falls back to polling RSSI at roughly 1600 µs because the CC1101's demodulated data output is not connected to a readable GPIO. That is slower than a 400 µs Kia V3/V4 short pulse, so captures may contain uniform pulses without bit edges. The firmware rejects them with `no-bit-edges` rather than passing them to the decoders. If the front end is latched first — every band reading within 2 dB of a flat floor — capture refuses outright with `capture_refused` and names `cc_reinit`, instead of arming on nothing. Routing GDO0 or GDO2 to an available GPIO would improve capture.

The board has no low-frequency front end. The CC1101 cannot handle 125 kHz passive-entry wake-up or Hitag2, Megamos, and DST40 immobilisers below 300 MHz.

**The firmware has not been tested against a car.** The sequences, encoders, and frame trimming have host-side tests, and an external receiver has decoded the transmitted waveform. Whether a paired vehicle receiver accepts any sequence remains untested. Decoding a waveform does not establish acceptance: a decoder has no paired state and cannot distinguish a receiver's acceptance from rejection.
