# 80 — Reversible DIO0 isolation on the Ra-02 (lift, not cut)

Status: and /79 establish that GPIO48 is the SX1278's DIO0 and that
the pin stays sunk with the LoRa asleep or held in reset, so the CC1101 has no free
path to that pin while the LoRa is populated. The fix is to take the Ra-02's DIO0
lead off the net. The earlier write-up assumed a trace cut; this note does it the
reversible way — lift the module's own lead and leave the board intact, so the mod
can be undone with nothing more than solder.

## Why lift rather than cut

A cut into the module or the mother trace is permanent and, on a board this small,
easy to overshoot into a neighbouring net. Lifting only the Ra-02's castellated lead
separates the same two nodes and is undone by re-soldering the joint. There is also
a diagnostic benefit: while the lead is off, both sides of the break can be probed
independently, which is the only way to tell "GDO0 is routed but masked" from "GDO0
is truly unrouted" — the question could not settle from firmware.

## What the lift fixes, and what it does not

Two outcomes are possible and the lift is the correct first step for both:

1. **GDO0 is routed to pin 48** (the V1 shared-net reading of `SGP_HACKER1.ino`,
   which declares both `PIN_CC1101_GDO0 48` and `PIN_LORA_DIO0 48`). Then lifting
   DIO0 leaves pin 48 driven by the CC1101 alone and the job is done.
2. **GDO0 is not routed at all** (the schematic-verified V2 header, "GDO0/GDO2 no
   cableados al ESP32"). Then lifting DIO0 leaves pin 48 floating and empty, and the
   second half of the job is a bridge wire from the CC1101's GDO0 to pin 48 — the
   mod the vendor PDF itself describes as "Suelda un puente entre GDO0 (CC1101 pin
   6) y un GPIO libre".

Either way the SX1278 contention has to go first, so the lift is not wasted work if
outcome 2 turns out to be the truth.

## Tools

- Multimeter with a continuity/beep mode and a fine probe tip.
- Soldering iron, fine chisel or knife tip, ~300 °C, or hot air at ~300–330 °C on
  low flow.
- Fine solder wick, good flux (gel or no-clean pen), 0.3–0.5 mm leaded or
  lead-free solder, isopropyl and a brush.
- Magnifier or a phone camera close-up for verification.
- No power: battery lead off **and** USB unplugged before any probing or rework.

## Step 0 — baseline the firmware state first

Do this *before* touching the board, so there is a before-image to compare against.
With the board powered and the serial console up, capture:

- `{"cmd":"status"}`
- `{"cmd":"lora_rst_check"}` — expect pin 48 to stay sunk, `drivable_while_rst_low=0`.
- `{"cmd":"gdo0_isolate"}` — expect verdict `SX1278_HOLDING`.
- `{"cmd":"gdo0_rail_test"}` — expect `SPI_DIES_WITH_RAIL_DOWN`, i.e. the CC1101 and
  the LoRa share the 3.3 V sensor rail gated by `PIN_SENSOR_CE` (GPIO6).

Save the four JSON lines. After the mod, `gdo0_isolate` and `lora_rst_check` are the
two that must change; if they do not, the lead is not fully lifted.

## Step 1 — power the board down completely

Battery connector off and USB out. Confirm with the meter that the 3.3 V rail reads
zero before putting a probe anywhere near a pad.

## Step 2 — anchor the pad row before counting

The Ra-02's component-side pads, starting at the corner next to the U.FL antenna
jack, are ordered:

```
1 GND   2 GND   3 3V3   4 RESET   5 DIO0   6 DIO1   7 DIO2   8 DIO3
(opposite row: 9 GND  10 DIO4  11 DIO5  12 SCK  13 MISO  14 MOSI  15 NSS  16 GND)
```

So DIO0 is the fifth pad counting from the jack end. To be sure which end is the
jack end and that the count is not off by one, use continuity to find the anchors:

- The first one or two pads at the jack corner should beep to ground.
- The third pad should beep to the 3.3 V rail (through the `PIN_SENSOR_CE` switch,
  so it may not show a hard short — it will still read low resistance, unlike a
  floating pad).
- The fourth pad is RESET.

That gives three independent checkpoints (GND, GND, 3V3) confirming the count
direction before counting to five.

## Step 3 — confirm the target before the iron

The pad intended for the lift should:

- **Not** beep to ground, and **not** beep to the 3.3 V rail. If it does, the count is one
  or more pads off and DIO0 is further along the row.
- Optionally, beep it against the CC1101's GDO0 (pin 6 on the QFN). If those ring to
  each other, the shared net in outcome 1 is confirmed and the lift will complete the
  fix by itself. If the CC1101's pin 6 is not reachable, skip this check — it is
  confirmatory, not required.

If nothing along the row gives a clean "not ground, not 3V3, in the fifth position"
answer, stop and re-anchor rather than guess. One pad of error puts the iron on RESET
or a supply.

## Step 4 — lift the lead

1. Flux the pad generously.
2. Heat one pad only. With hot air, keep flow low and the nozzle just off the pad so
   neighbours are not disturbed; with an iron, use a fine tip and wick rather than
   pulling.
3. Draw the solder off the joint until the module's lead is free of the mother pad,
   then nudge the lead up a hair so it cannot bridge back.
4. Clean the flux and inspect under magnification. The lead should be visibly clear of
   the pad with no wicking to the adjacent castellation.

Do not run a knife between the lead and the pad; that is the cut this procedure exists
to avoid.

## Step 5 — verify the break

With the board still unpowered:

- Continuity from the Ra-02's lifted lead to the mother pad / ESP32 side of the same
  net must now read open.
- Continuity from the lifted lead to its neighbours must read open.
- Ground and 3V3 anchors must still read as before, confirming they were not disturbed.

## Step 6 — power up and re-run the diagnostics

- `{"cmd":"gdo0_isolate"}` — should flip from `SX1278_HOLDING` to `PIN_ALREADY_FREE`.
- `{"cmd":"lora_rst_check"}` — `drivable_while_rst_low` should now read 1.
- `{"cmd":"gdo0_signal"}` — this is the decisive test.
  - `GDO0_REACHES_PIN48`: outcome 1. The CC1101 was there all along and the LoRa was
    masking it. Nothing further to wire.
  - `GDO0_NOT_ROUTED`: outcome 2. The pin is now free but empty; add the bridge from
    the CC1101's GDO0 to pin 48, then re-run. `gdo0_signal` doubles as the
    bridge-quality check — if the clock appears, the bridge is good; if not, it is not.

Note that `gdo0_signal` still reports `RAIL_SHARED_CANNOT_ISOLATE` if the rail cut
kills the CC1101 too; that is the shared-rail finding and is
expected on this board. It is not a failure of the lift.

## Step 7 — tell the firmware the pin is now usable

With pin 48 cleared of the LoRa, the compile-time state should be:

```c
#define PIN_GDO0         48
#define PIN_LORA_DIO0    -1   // DIO0 lifted off the net
bool gdo0Routed = true;       //: SX1278 contention removed
```

Rebuild and flash. This turns on the async TX bit-bang path and the GDO0 digital-edge
capture that the RSSI-edge fallback has been standing in for.

**Tradeoff to note:** lifting DIO0 takes away the LoRa's interrupt line. Anything on
this board that relies on the SX1278's IRQ — including the false-capture path tracked
— stops working until the lead is put back. If both radios are needed
at once, the correct long-term fix is a bridge to a *different* free GPIO rather than
reusing 48, so the CC1101 and the LoRa no longer share a pin.

## Reversal

Re-flux the joint, lay the lead back down, and re-solder it. Alternatively bridge the
lead to its pad with a short wire or a 0 Ω link if the lead has been damaged. The
mother trace is untouched, so the board returns to stock. After reversal, set
`gdo0Routed = false` and restore `PIN_LORA_DIO0 48` in the header.

## Re-checking the archive: the vendor's own schematic reading said 48 twice

Re-opening the vendor archive turned up a file did not weigh. The
`2026-04-30 - SGP Diagnostic/SGP_DIAGNOSTIC.ino` header states its pin map is

```
// VERIFIED FROM: SCH_Schematic2_2026-03-18.pdf (5 PAGES)
```

and lists, in the same component table:

```
*   ✅ CC1101 Sub-GHz (SPI)     - CS:34, GDO0:48
*   ✅ LoRa Ra-02 SX1278 (SPI)  - CS:38, RST:47, DIO0:48
```

That is a different kind of claim from the `SGP_HACKER1.ino` duplication. There the
two macros on 48 could be dismissed as a copy-paste; here the author says the value
came off the schematic sheet, and assigns pin 48 to *both* the CC1101's GDO0 and the
Ra-02's DIO0 — which is exactly what a shared net looks like on a schematic. The
comment on the macro reinforces it: `IO48/DID0 also labeled GDO0 (shared net check)`.

The archive contains no schematic PDF itself (only the user manual), so the sheet
cannot be re-read here. But the sequence now reads:

- **2026-03-18 schematic** → read as "48 = GDO0 = DIO0" (shared net) by the author of
  the diagnostic.
- **2026-04-30** sketches → both macros on 48, consistent with that reading.
- **2026-05-25** corrected header → "GDO0 NO está cableado", i.e. the author later
  concluded GDO0 is not wired.

So the two positions are both the vendor's, at different dates. The later note is not
automatically the better one: it may be a correction of the earlier mislabelling, or
it may itself be the V2-board description applied to a V1 board. The lift answers the
question empirically instead of choosing between the two documents, which is the whole
reason it is still the right first move.

## The back of the board exposes a labelled GPIO48 test point

The reverse side carries a full field of silkscreen test points (`TP1`–`TP27`, marked
`3V3`, `5V`, `B+`, `Solar +`, and per-chip nets). Two matter here:

- A test point with a silk label that reads as **`IO48`** (confirm with a loupe), which
  would be the ESP32's GPIO48 brought out for probing.
- **`TP23`, labelled `3V3`**, a convenient power-rail reference.

If the `IO48` leg is really GPIO48, it removes the hardest part of the procedure: there
is no need to reach the ESP32-S3 module's own pads at all. The module is a
castellated-can part on the front and its pins are not probeable from the back, which
is why "find the ESP32 pads" dead-ends. The labelled test point replaces it.

### The test, restated for the back-side access

Board unpowered. Continuity mode.

1. Beep the `IO48` test point against `TP23` (`3V3`) — must be **open**.
2. Beep `IO48` against a known ground — must be **open**.
3. Beep `IO48` against each pad of the Ra-02's left column in turn. The pad that
   **beeps is DIO0**.
4. Beep `IO48` against the CC1101's GDO0 (`pin 6` on the QFN20). If it
   **beeps, GDO0 is routed to 48** and the lift alone completes the fix. If it is
   **open, GDO0 is not routed** and the bridge wire is also needed.

Step 4 is the one no firmware test on this board can perform, and it is now a
two-probe measurement.

## Sources

- Vendor archive: `2026-04-30 - SGP Diagnostic/SGP_DIAGNOSTIC.ino` (pin map
  "VERIFIED FROM: SCH_Schematic2_2026-03-18.pdf", both GDO0 and DIO0 on 48),
  `2026-04-30 .../SGP_HACKER1.ino` (both macros on 48),
  `2026-05-25 .../SGP_CardMini.ino` (schematic-verified V2 header, bridge
  instruction), `2026-05-25 ... Manual de usuario.pdf`.
- Ai-Thinker Ra-02 datasheet pad numbering.
- Board, live: `status`, `lora_rst_check`, `gdo0_isolate`, `gdo0_rail_test`,
  `gdo0_signal`.
