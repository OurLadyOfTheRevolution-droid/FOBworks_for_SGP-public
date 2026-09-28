# FOBworks for SGP

This is firmware I wrote for the SGP Card Mini — the May 2026 stock, which is an
ESP32-S3-MINI-1-N8 with 8 MB of flash and no PSRAM. It uses the CC1101 that is already on the
card. There is also a Ra-02 SX1278 on there, and the firmware puts it to sleep so the CC1101
can have the data pin to itself. I wrote it for this board and nothing else.

When it boots, the card brings up its own network called `SGP Card Mini` and serves a dashboard
at `http://192.168.4.1`. The access code it wants is printed to USB serial on first boot; the
same code gets you into the React dashboard, over USB or over WiFi. Both sets of steps are in
`README.md`.

The home screen is a mode picker, and there are four modes. The word "Mode" in the header
brings the picker back. Holding the user button for three seconds puts the card to sleep, and
holding it for three seconds wakes it again.

Two of the four modes are guided attacks that transmit. Those are C1 and C2, the sequencers
behind FOBcatch and FOBback. I built them so they are hard to set off by accident: each one
needs an explicit arm, the arm is spent by a single start, and if the preconditions are not met
it refuses rather than trying to make do.

## FOBscan

This is the workbench, and most of what the card does lives on its six tabs: capture, sweep,
decode, prediction, keys, library, and Bluetooth.

Capture starts and stops a listen, picks OOK or 2FSK, and shows you the last burst the radio
heard. Scan walks through the card's channels, or you can lock it to one. Decode is the
read-out — protocol, serial, button, counter, and whether the frame actually checked. Predict
shows the next counter the decoder expects, based on the frames it still has in memory. Keys is
where you add, test, or clear a saved manufacturer key. Library lists every capture still on
the card, grouped by protocol and serial.

From idle, one tap of the card button starts FOBscan with the screen dark. The LED breathes
orange. When a decode sticks, the pixel flashes white and then goes back to breathing. Another
tap stops it.

## FOBclone

This walks you through one vehicle. You pick a make, then a model, then a year, and the card
sets the band and modulation for that entry and waits. You press the fob near the card. The
screen lists each frame it kept, and it will offer to send a saved frame back, including the
next predicted counter when the decoder has worked one out.

If you would rather not open the dashboard, two taps from idle start the same listen. The LED
breathes blue while it searches. Once a fob has been recognised, one tap sends the saved frame.
While it is still searching, one tap steps the band preset, and two taps stop it.

## FOBcatch

A quieter version of FOBclone, without the send-back step. Pick the make, model, and year, and
the card arms that profile. Press the fob. The screen holds the capture and lets you name it if
you want a bookmark. Replay sends the saved frame.

## FOBback

A guided resync, for receivers that will accept a short run of saved codes. Pick the make and
the vehicle, and the card listens while you press the fob until it says it has enough frames.
Replay then sends that run back in the order it was captured. The card does not change
frequency while it is collecting.

The sequence underneath is the C2 RollBack sequencer. It sends exactly two codes, the older one
first, with a gap you can set between 40 and 2000 ms. That range is not arbitrary: too short
and the receiver reads it as one press, too long and you fall outside its resync window.

It will refuse two things rather than guess at them. If it is holding fewer than two codes,
there is nothing to send. And if the pair it has share a counter, or the counters are not in
order, a same-code pair cannot resync anything — so it declines and tells you why instead of
transmitting.

Captures get trimmed down to a single frame before they are stored. A real press puts the frame
out several times over, and if you replay a three-repeat block the receiver sees three presses,
advances its counter by three, and the sequence the attack depends on is gone.

Codes can also come from a stored frame — a FOBworks RAW file or a `.sub` capture — through
`fbk_import`. That is how I test a transmit without needing a live capture.

## Signal library

Every decode you keep lands here, grouped by protocol and serial. The card writes each one to
the microSD as a FOBworks RAW file and the screen reads that library back. You can merge two
groups when they turn out to be the same fob read two different ways, hide the raw captures
that never matched a decoder, and export the lot as JSON. The file name starts with
`fobworks_library_`.

A capture can also be saved as a FOBworks RAW file on its own: a short header, the frequency,
and the pulse list. Post that file back to the card and it will transmit those pulses on the
frequency written in the file.

## Key recovery

This is for a KeeLoq fob you already own. You press the same button two to five times while the
card listens. Recovery tries the built-in table and any key you have saved, and it only keeps a
candidate if every press decrypts to the same serial, the same button, and a counter that steps
forward. A hit on a filler pattern in the built-in table is labelled as a pattern match, not a
result. A key you saved on the card is the one that counts. A miss stays a miss — the card does
not invent a manufacturer key out of thin air.

The table it works from has 73 real entries in it, not invented patterns. Four of the Kia
decoders in this firmware have never fired on a real capture, and 31 of the 41 decoders are
silent against the corpus I have — most of those are gate and garage protocols the corpus does
not contain. `tools/corpus_regression.py` reproduces that tally, and its header comment records
what it found.

A candidate has to decrypt identically across two consecutive frames before it is reported as
found. One frame is not enough, because the check is only 12 bits — a single frame can be
matched by a wrong key roughly one time in four thousand, and transmitting a code derived from
a wrong key desynchronises the real fob.

On serial, `key_probe` tests one candidate you already have against the last few KeeLoq frames
without starting a full recovery, and `key_recover_offline` runs the same recovery over a hop
list you paste in, with no radio involved at all.

## C1 RollJam

The capture-and-replay sequence, exposed as `rolljam_*` on serial and in the dashboard. It jams
the fob's first press so the receiver never hears it, captures that press, jams again while the
fob is pressed a second time, captures the second one, and then replays the **first** code into
the second jamming window. The owner sees the door unlock on the second press, and the card is
left holding the second code — valid, and unused.

Because this one both jams and transmits, it has more guards than the rest:

- An explicit arm, refused while a sequence is already running, and spent by a single start so a
  double tap cannot fire it twice.
- Both captures have to decode to different counters in the right order. If they do not, nothing is
  transmitted and you get the reason.
- The jam stops on **every** exit path — timeout, either capture failing, the same-code refusal,
  the transmit path, and success — and on boot, before anything that could hang. A jam that
  outlives a reset is the worst thing this feature could do, so that path gets checked first.

Two things limit it. One CC1101 cannot jam and listen at the same time, so the sequence drops
the carrier for each capture window; that interleave is the part that has to hold up on real
hardware. And on this board the jam runs out of the TX FIFO in packet mode, with
`jam_status` reporting underruns — read that first if a sequence fails, because a carrier that
gapped and a receiver that refused look identical from the outside and are not the same
problem.

## Bluetooth

Scan lists the advertisements the card can hear. Pair opens a short advertising window under
the name `SGP Card Mini` so a phone can bond. Paired devices shows the bond list. The card does
not hand out identity keys.

## Using it

There is nothing exotic about the way I run it. The card goes on USB and the access code comes
off the serial log at 115200 baud. After that it is the same few steps every time.

1. Join `SGP Card Mini` and open `http://192.168.4.1` — or run the React dashboard and connect over
   USB or WiFi. `README.md` covers both.
2. Enter the access code, and the mode picker appears.
3. Open FOBscan, leave the sweep running, and press a button on my own fob next to the card.
4. Decode shows the family, the serial, the button, and the counter.
5. Save the capture into the library. If I want a copy off the card, export the library.

Everything else in the firmware is a variation on those five steps.

## What this revision can and cannot do

The first two matter most.

**Transmit works.** Replay, jamming, and both sequencers drive the CC1101's own PA from its TX
FIFO. A frame transmitted this way was picked up and decoded by a separate receiver as a valid
Kia unlock, protocol and button identified.

**Capture is coarse.** The CC1101's demodulated data output is not connected to anything
readable on this board, so capture falls back to polling RSSI at about 1600 µs. That is slower
than a Kia V3/V4 short pulse of 400 µs, which means a capture can come back as uniform pulses
with no bit edges in them at all. The firmware refuses those and reports `no-bit-edges` rather
than passing them to the decoders. Routing GDO0 or GDO2 to a free GPIO is what fixes it.

**There is no low-frequency front end.** The 125 kHz passive-entry wake-up, and the Hitag2,
Megamos, and DST40 immobilisers, all sit below what this radio covers.

**Nothing here has been tested against a car.** The sequences, the encoders, and the frame
trimming are tested host-side, and the waveform is verified externally. Whether a paired receiver
accepts any of it is untested — I do not have one to try. The Flipper can confirm that a frame
came out correct, but it is not paired to anything and has no counter to check, so it will parse
the same frame whether the receiver on the other end would open or refuse.
