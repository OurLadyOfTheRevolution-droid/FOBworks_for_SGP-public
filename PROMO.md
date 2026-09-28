# FOBworks for SGP

This firmware targets the SGP Card Mini stock acquired in May 2026: an ESP32-S3-MINI-1-N8 with 8 MB flash and no PSRAM. It uses the card's CC1101 for sub-GHz work. The board also carries a Ra-02 SX1278. GPIO 48 is connected to the SX1278's DIO0; the CC1101's GDO0 is not routed to a readable GPIO, and putting the SX1278 to sleep does not restore that connection. This firmware targets this board revision only.

The card creates a Wi-Fi network named `SGP Card Mini` and serves its dashboard at `http://192.168.4.1`. At startup, it prints the Wi-Fi credentials and access code over USB serial. The same code is used by the separate React dashboard, which can connect over USB or Wi-Fi. That dashboard is not included in this repository; see `README.md` for the connection steps.

The home screen lists four modes. Tap **Mode** in the header to return to the list. Hold the user button for 3 seconds to put the card to sleep; hold it again for 3 seconds to wake it.

FOBcatch and FOBback are guided transmit sequences. C1 and C2 are their respective sequencers. Each requires an explicit arm, consumes it after one shot, and refuses to run if its preconditions are not met.

## FOBscan

FOBscan is the workbench for capture, sweep, decode, prediction, key management, the signal library, and Bluetooth. These tools are arranged across six tabs.

**Capture** starts and stops listening, selects OOK or 2FSK, and shows the latest burst. **Scan** cycles through the card's channels or stays on one channel. **Decode** reports the protocol, serial, button, counter, and frame-check result. **Predict** shows the next counter inferred from frames in memory. **Keys** lets you add, test, or clear a saved manufacturer key. **Library** lists captures stored on the card, grouped by protocol and serial.

From idle, one button tap starts FOBscan without the screen. The LED pulses orange; a kept decode flashes the pixel white before orange pulsing resumes. Tap again to stop.

## FOBclone

A guided scan for a selected vehicle. Choose the make, model, and year; the card sets the profile's band and modulation and waits for a fob press. The screen lists captured frames and can send a saved frame back, including the next predicted counter when the decoder can provide one.

From idle, two taps start this scan without the dashboard. The LED pulses blue while the card listens. After it recognizes a fob, one tap sends the saved frame. Before recognition, one tap changes the band preset. Two taps stop the scan.

## FOBcatch

FOBcatch listens using a selected vehicle profile. Choose the make, model, and year, then press the fob. The screen keeps the capture and lets you name it; **Replay** sends the saved frame.

## FOBback

FOBback is a guided resynchronization sequence for receivers that accept a short run of saved codes. Choose the make and vehicle, then press the fob until the card has enough frames. **Replay** sends the saved frames in capture order. The card holds its frequency while collecting them.

FOBback uses the C2 RollBack sequencer. It sends exactly two codes, older first, with a configurable gap of 40–2000 ms. A shorter gap can look like a single press; a longer one may exceed the receiver's resynchronization window. The sequencer refuses to run when:

- fewer than two codes are available;
- the counters are equal or out of order. Sending the same code twice cannot resynchronize the receiver, so the sequencer reports the problem instead of transmitting.

Before storage, each capture is trimmed to one frame. A physical press usually repeats the frame; replaying a three-repeat block could appear to the receiver as three presses, advancing its counter by three and breaking the sequence.

You can also load a stored frame through `fbk_import`, using a FOBworks RAW file or a `.sub` capture. This lets you test a transmit without making a live capture.

## Signal library

Kept decodes appear here, grouped by protocol and serial. The card writes each to the microSD as a FOBworks RAW file and reads the library back for display. You can merge groups that contain readings from the same fob, hide captures that no decoder matched, and export the library as JSON. Exported filenames begin with `fobworks_library_`.

A standalone FOBworks RAW file contains a short header, frequency, and pulse list. Send the file back to the card to transmit those pulses at the frequency recorded in it.

## Key recovery

Key recovery is intended for a KeeLoq fob you own. Press the same button two to five times while the card listens. Recovery checks the built-in table and any keys saved on the card. It keeps a candidate only if every press decrypts to the same serial and button with a counter that advances. A match to a filler pattern in the built-in table is labeled **pattern match**; a saved key is reported separately. If no key matches, recovery reports no match. It does not derive a manufacturer key from a transmission.

The built-in table contains 73 entries. In the corpus used for this project, four Kia decoders have not matched a real capture; 31 of 41 decoders have no match at all, mostly because the corpus contains few gate and garage signals. `tools/corpus_regression.py` reproduces these counts, and its header comment records the results.

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

**Scan** lists advertisements the card can hear. **Pair** opens a short advertising window named `SGP Card Mini` so a phone can bond. **Paired devices** shows the bond list. The card does not expose identity keys.

## A basic capture workflow

1. Connect the SGP Card Mini over USB and read the access code from the serial log at 115200 baud.
2. Join `SGP Card Mini` and open `http://192.168.4.1`. If the separate React dashboard is available, you can connect over USB or Wi-Fi instead; `README.md` has the instructions.
3. Enter the access code to reach the mode picker.
4. Open FOBscan, leave the sweep running, and press a button on a fob you own near the card.
5. Check the decoded protocol family, serial, button, and counter.
6. Save the capture to the library. Export the library if you need a copy off the card.

The basic workflow is to capture a transmission, inspect the decode, and save it.

## What this revision can and cannot do

Replay, jamming, and both sequencers drive the CC1101's power amplifier from its TX FIFO. A separate receiver decoded one transmitted frame as a Kia unlock and identified its protocol and button.

Capture currently falls back to polling RSSI at roughly 1600 µs because the CC1101's demodulated data output is not connected to a readable GPIO. That is slower than a 400 µs Kia V3/V4 short pulse, so captures may contain uniform pulses without bit edges. The firmware rejects them with `no-bit-edges` rather than passing them to the decoders. Routing GDO0 or GDO2 to an available GPIO would improve capture.

The board has no low-frequency front end. The CC1101 cannot handle 125 kHz passive-entry wake-up or Hitag2, Megamos, and DST40 immobilisers below 300 MHz.

**The firmware has not been tested against a car.** The sequences, encoders, and frame trimming have host-side tests, and an external receiver has decoded the transmitted waveform. Whether a paired vehicle receiver accepts any sequence remains untested. Decoding a waveform does not establish acceptance: a decoder has no paired state and cannot distinguish a receiver's acceptance from rejection.
