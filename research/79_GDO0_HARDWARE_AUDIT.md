# 79 — GDO0 on the SGP Card Mini: not routed, and why firmware cannot settle it

Status: left the GDO0 question as "the CC1101's GDO0 does not reach a
readable GPIO", inferred from a sunk pin and a vendor note. The user asked whether
that is actually true or whether the pin is merely unused, and supplied the vendor
archive plus a board that reports as the **V1/SX1278** generation rather than the
PCB V2 the factory firmware targets. This note records what the vendor sources say,
what the board says, and the one experiment the earlier probes never ran — including
the reason it is inconclusive, which is itself the answer.

## The vendor sources disagree by revision

The archive is titled "SGP Card Mini" but its firmware is written for **PCB V2**
("HARDWARE PIN MAP - SGP CARD MINI PCB V2 (VERIFIED FROM SCHEMATIC)"). Within it,
two generations say different things about pin 48:

* **V1-era sketches** (2026-04-30, `SGP_HACKER1.ino`, `SGP_CLOUD.ino`):
  `#define PIN_CC1101_GDO0 48` *and* `#define PIN_LORA_DIO0 48`, with LoRa treated
  as a **Ra-02 SX1278**. Both macros on one pin is the origin of the "GDO0 = 48"
  claim, and it was never more than a copy-paste of the LoRa IRQ across two headers.
* **The corrected header** (2026-05-25 `SGP_CardMini.ino`, "esquema v3.6 — Rajj
  Engineering JLCPCB-002"):

  ```
  *   CC1101:       CS=34   GDO0/GDO2 no cableados al ESP32
  *   LoRa SX1262:  CS=38   RST=47  DIO1=48  BUSY=26

  #define PIN_CC1101_GDO0  -1   // GDO0 NO está cableado al ESP32 en este PCB.
                                // Antes era 48, pero 48 es DIO0 del LoRa.
                                // Sin GDO0 no se puede hacer replay bit-bang;
  #define PIN_LORA_DIO0    48   // IO48 — DIO0/DIO1 (en SX1262 es DIO1)
  ```

  This is the vendor stating the answer outright, and its comment ("GDO0 is not
  wired to the ESP32 on this PCB") is the same sentence our README already carried.
* **The 2026-10-01 "LAB" build** reverts to `#define PIN_CC1101_GDO0 48` while its
  own header calls the module an **SX1262 on DIO1=48** — it declares GDO0 the same
  pin as the LoRa IRQ again, which is a regression in the newest file, not evidence.
* The Drone Hunter `INSTRUCTIONS.md` repeats a pin table with "CC1101 GDO0 | 48",
  but the table is stale: the same generation of sketches has no working GDO0 path.

So the documentation is internally contradictory, but only because earlier files
duplicated the LoRa IRQ pin into the CC1101 header. The one file that says it was
verified against the schematic is unambiguous, and it is the correction.

## What this board actually is

The V2 firmware expects an **SX1262** (the NiceRF LoRa1262, FCC ID 2AD66-1262; see
the 2026-06-30 LoRa README: "el chip es un SX1262 (no SX1276)", "DIO1 = GPIO48",
"BUSY = GPIO26", and "DIO0=48 del código viejo es en realidad DIO1=48"). This
board is **not** that. Live diagnostics:

* `status` reports `cc1101:true` with VERSION `0x14` — a modern CC1101.
* `lora_sleep_check` reads LoRa `RegVersion (0x42) = 0x12` — that value is an
  **SX1278**. An SX1262 does not answer register `0x42` at all.
* `lora_rst_check`: RST actually resets it (`version_rst_high=12`,
  `version_rst_low=0`), and `drivable_while_rst_low=0` — pin 48 stays sunk in reset.

So this is the **SX1278 generation**: the board the V2 header describes when it
says "48 es DIO0 del LoRa". The user's "I think I have the V1 pcb" is consistent
with the hardware reporting; the practical point is that on both generations pin 48
belongs to the LoRa IRQ, not to the CC1101.

## Why the earlier probes could not have been decisive

Every prior GDO0 probe ran with the LoRa merely **asleep or held in reset**, and
`gdo0_isolate` tri-states the CC1101 at the moment it would need to drive. Two
outputs on one net behave like open-drain: whichever sinks LOW wins, and the other's
HIGH is masked. So a reading of "pin 48 sunk while the CC1101 is tri-stated" only
shows that *something* sinks it; it cannot show that the CC1101 fails to drive it,
because a LoRa holding the line low would hide a CC1101 driving it. `gdo0_probe`'s
`clock_edges=0` looked decisive but that test also ran with DIO0 live. The gap was
real, and it was worth one new experiment.

## The experiment: `gdo0_signal`

New serial command. It configures the CC1101's GDO0 to `CLK_XOSC/192`
(`IOCFG0=0x3F`, `SRX` so the crystal runs), then counts transitions on pin 48 while
the sensor rail is cut so the SX1278 is gone. It observes only the clock, transmits
nothing, and restores the rail and `IOCFG0` before returning. Positive controls are
built in: `IOCFG0` must read back `0x3F` and `MARCSTATE` must read `0x0D` (RX) or the
result is declared `TEST_INVALID`; an ESP32 loopback confirms the read path is good.

Result, reproducible across runs:

```
version_on=14  version_off=0
iocfg0_readback_on=3f  iocfg0_readback_off=0
marcstate_on=0d        marcstate_off=0
esp_loop_on=0          esp_loop_off=1
clock_edges_rail_on=0  clock_edges_rail_off=0
verdict = RAIL_SHARED_CANNOT_ISOLATE
```

The `version_off=0` is the finding. **Cutting the sensor rail removes the CC1101's
power as well as the LoRa's** — they share the rail (this is why `gdo0_rail_test`
reports `SPI_DIES_WITH_RAIL_DOWN`). A rail cut therefore cannot isolate the two
outputs, so the routing question cannot be settled from firmware on this board at
all. Note also that `gdo0_rail_test` earlier returned `cc1101_version_rail_off=14`
on a prior run; re-running it on the same firmware now returns `0`. The `14` was not
reproducible, which is exactly why `gdo0_signal` treats a chip-dead rail-off sample
as `RAIL_SHARED_CANNOT_ISOLATE` rather than as evidence either way.

What *is* solidly established, all in the powered state:

1. With the CC1101 told to emit its XOSC clock on GDO0 and the LoRa live,
   `clock_edges_rail_on=0`. An unrouted GDO0 and a routed-but-masked GDO0 both look
   like this, so this alone is not proof.
2. The vendor's schematic-verified file says GDO0 is not wired, and instructs the
   user to solder a bridge: "Suelda un puente entre GDO0 (CC1101 pin 6) y un GPIO
   libre, y cambia PIN_CC1101_GDO0 al GPIO que uses."
3. The SX1278 asserts DIO0 on pin 48 whenever powered, and neither sleep nor reset
   releases it (`lora_rst_check`, `gdo0_isolate`), so even if GDO0 were routed to
   pin 48 the LoRa would fight it.

Nothing short of a bodge wire can separate output-routing from masking here, so the
README's conclusion stands as the best-supported position, with the honest caveat
that it rests on the vendor's note plus the LoRa contention rather than on a direct
firmware measurement. The escape hatch is unchanged and cheap: bridge GDO0 (CC1101
pin 6) or GDO2 (pin 3) to a free GPIO, at which point `gdo0_signal` becomes a direct
test — if the clock appears, GDO0 is routed; if not, the bridge is bad.

## What this changes for the on-air leg

Nothing, on the current hardware. Async TX and digital-edge capture both need a
routed GDO0, and it is not available without a wire. Packet-mode TX (which does not
use GDO0) remains the only transmit path, and RSSI-edge capture remains the only
receive path — the same conclusion now with the revision ambiguity
resolved and a control-hardened probe to re-test the moment a wire is added.

## Sources

* Vendor archive `SGP Card Mini-*.zip`: `2026-05-25 - SGP Card Mini - Demo Android/
  SGP_CardMini.ino` (corrected header), `2026-04-30 - SGP Hacker/SGP_HACKER1.ino`
  (V1-era), `2026-10-01 - SGP Card Mini - Firmware/SGPCard_Mini/SGPCard_Mini.ino`
  (LAB regression), `2026-06-30 - LoRa 2/README.md` (SX1262 identification),
  `2026-05-25 - ... Manual de usuario.pdf`.
* Online: sgpcard.com product docs confirm ESP32-S3 + CC1101 + LoRa but publish no
  schematic or GDO0 pinout; no V1/V2 pin map is available publicly.
* Live, this board: `status`, `gdo0_probe`, `gdo0_isolate`, `gdo0_rail_test`,
  `lora_sleep_check`, `lora_rst_check`, `gdo0_signal`.
