# FOBworks for SGP

Standalone firmware for the SGP Card Mini, written for the May 2026 card. The module is an ESP32-S3-MINI-1-N8 with 8 MB of flash and no PSRAM. The radio in use is the CC1101 on the card. The LoRa module on this stock is a Ra-02 SX1278, and this firmware only puts it to sleep so the CC1101 can use the shared data pin. I wrote this firmware for that board and nothing else.

The card opens its own network, named `SGP Card Mini`, and serves the dashboard at `http://192.168.4.1`. The access code is printed on USB serial the first time the card boots. The same code opens the React dashboard, over USB or over WiFi. `README.md` has the connection steps for both.

The home screen is a mode picker with four modes. Mode, in the header, brings that picker back. Hold the user button for 3 seconds to sleep. Hold it for 3 seconds to wake.

Two of the four modes are guided attacks, and both transmit. C1 and C2 below are the sequencers behind FOBcatch and FOBback. They are built to be hard to fire by accident: each needs an explicit arm, consumes that arm on one shot, and refuses when its preconditions are not met.

## FOBscan

The workbench. Capture, sweep, decode, prediction, keys, the library, and Bluetooth all live here, on six tabs.

Capture starts and stops a listen, picks OOK or 2FSK, and shows the last burst the radio heard. Scan walks the channels on the card, or locks one channel. Decode is the read-out: protocol, serial, button, counter, and whether the frame checked. Predict shows the next counter the decoder expects from the frames already in memory. Keys is where a saved manufacturer key is added, tested, or cleared. Library is every capture still on the card, grouped by protocol and serial.

One tap of the card button, from idle, runs FOBscan with the screen dark. The LED breathes orange. A kept decode flashes the pixel white, then the orange breathe returns. Another tap stops it.

## FOBclone

A guided pass for one vehicle. I pick make, then model, then year. The card sets the band and the modulation for that entry and waits. I press the fob near the card. The screen lists each frame it kept and offers to send a saved frame back, including the next predicted counter when the decoder has one.

Two taps from idle start the same listen without the dashboard. The LED breathes blue while it is searching. One tap, once a fob has been recognized, sends the saved frame. While it is still searching, one tap steps the band preset. Two taps stop it.

## FOBcatch

A guided listen on one vehicle profile. I pick make, model, and year. The card arms that profile. I press the fob. The screen holds that capture, names it if I want a bookmark, and Replay sends the saved frame.

## FOBback

A guided resync for receivers that accept a short run of saved codes. I pick the make and the vehicle. The card listens. I press the fob until the screen says it has enough frames. Replay sends that saved run, in the order it was captured. The card does not change frequency while it is collecting.

The sequence itself is the C2 RollBack sequencer. It sends exactly two codes, the older one first, with a configurable gap — bounded to 40–2000 ms, because too short reads as one press and too long can exceed the receiver's resync window. Two things it refuses rather than guessing:

- fewer than two held codes.
- a pair whose counters are the same, or not in order. A same-code pair cannot resync anything, so it declines and says so instead of transmitting.

A capture is trimmed to one frame before it is stored. A real press emits the frame several times over, and replaying a three-repeat block looks to the receiver like three presses, which would advance its counter by three instead of one and break the sequence the attack depends on.

Codes can also be loaded from a stored frame — a FOBworks RAW file or a `.sub` capture — through `fbk_import`, which is how a transmit can be tested without a live capture.

## Signal library

Every decode I keep lands here, grouped by protocol and serial. The card writes each one to the microSD as a FOBworks RAW file, and the screen reads that library back. I can merge two groups when they are the same fob read two different ways, hide raw captures that never matched a decoder, and export the library as JSON. The file name starts with `fobworks_library_`.

A capture can also be saved as a FOBworks RAW file: a short header, the frequency, and the pulse list. I can post that file back to the card and it will transmit those pulses on the frequency written in the file.

## Key recovery

For a KeeLoq fob I already own. I press the same button two to five times while the card is listening. Recovery tries the built-in table and any key I have saved, and it keeps a candidate only when every press decrypts to the same serial, the same button, and a counter that steps forward. A hit on a filler pattern in the built-in table is labeled a pattern match. A key I saved on the card is the one that counts. A miss stays a miss. The card does not invent a manufacturer key from the air.

The table is 73 real entries, not invented patterns. Four Kia decoders in this firmware have never fired on a real capture, and 31 of the 41 decoders are silent against the corpus I have — most of those are gate and garage protocols the corpus does not contain. `tools/corpus_regression.py` reproduces that tally, and its header comment records what it found.

A candidate must decrypt identically across two consecutive frames before it is reported as found. One frame is not enough: the check is 12 bits, so a single frame can be matched by a wrong key about 1 time in 4000, and transmitting a code derived from a wrong key desynchronises the real fob.

`key_probe` on serial tests one candidate I already have against the last few KeeLoq frames, without starting a full recovery. `key_recover_offline` runs the same recovery on a hop list I paste in, with no radio involved.

## C1 RollJam

The capture-and-replay sequence, exposed as `rolljam_*` on serial and in the dashboard. It jams the fob's first press so the receiver never hears it, captures that press, jams again while the fob is pressed a second time, captures the second, and then replays the **first** code into the second jamming window. The owner sees the door unlock on the second press. The card keeps the second code, valid and unused.

Guards, because this one jams and transmits:

- an explicit arm, refused while a sequence is already running, and consumed by one start so a double tap cannot re-fire it.
- both captures must decode to different counters in the right order, or nothing is transmitted and the reason is reported.
- the jam stops on **every** exit path — timeout, either capture failing, the same-code refusal, the transmit path, and success — and on boot, before anything that could hang. A jam that outlives a reset is the worst failure mode this feature has.

Two limits worth knowing. One CC1101 cannot jam and listen at the same time, so the sequence drops the carrier for each capture window and the timing of that interleave is the part that has to hold on real hardware. And on this board the jam runs from the TX FIFO in packet mode, with `jam_status` reporting underruns — read that first if a sequence fails, because a carrier that gapped is a different problem from a receiver that refused.

## Bluetooth

Scan lists advertisements the card can hear. Pair starts a short advertising window under the name `SGP Card Mini` so a phone can bond. Paired devices shows the bond list. The card does not hand out identity keys.

## A workflow I actually use

1. I plug the SGP Card Mini into USB and read the access code at 115200 baud.
2. I join `SGP Card Mini` and open `http://192.168.4.1`. Or I run the React dashboard and connect over USB or WiFi — `README.md` has both.
3. I enter the access code. The mode picker is waiting.
4. I open FOBscan, leave the sweep on, and press a button on my own fob next to the card.
5. Decode shows the family, the serial, the button, and the counter.
6. I save that capture into the library and, if I want a copy off the card, I export the library.

That is the whole loop: hear the fob, read it, keep it.

## What this revision can and cannot do

Worth saying plainly, because two of these shape everything else.

**Transmit works.** Replay, jamming, and both sequencers drive the CC1101's own PA from its TX FIFO. A transmitted frame was decoded by a separate receiver as a valid Kia unlock, protocol and button identified.

**Capture is coarse.** The CC1101's demodulated data output is not connected to a readable pin on this board, so capture falls back to polling RSSI at roughly 1600 µs. That is slower than a Kia V3/V4 short pulse of 400 µs, so a capture can come back as uniform pulses with no bit edges. The firmware refuses those and says `no-bit-edges` rather than handing them to the decoders. Routing GDO0 or GDO2 to a free GPIO is the fix.

**There is no low-frequency front end.** 125 kHz passive-entry wake-up, and the Hitag2, Megamos and DST40 immobilisers, are below what this radio covers.

**Nothing here has been tested against a car.** The sequences, the encoders and the frame trimming are tested host-side and the waveform is verified externally, but "does a paired receiver accept it" is untested — I do not have one. A decoder is not a receiver: it has no paired state, so an independent decode of a transmitted frame cannot tell an accept from a reject. That boundary is stated precisely because it is the one claim this project does not make.
