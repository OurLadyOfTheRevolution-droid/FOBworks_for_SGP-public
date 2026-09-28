# FOBworks for SGP

FOBworks for SGP is standalone firmware I wrote for the SGP Card Mini. The card is an existing third-party board. This firmware is its own project. Version 3.75.

This copy is written for the card I bought in May 2026. That stock is an ESP32-S3-MINI-1-N8: dual-core LX7 at 240 MHz, 8 MB quad flash, no PSRAM, Wi-Fi 802.11 b/g/n, and BLE 5. The radio I use is the CC1101 already on the card, OOK and 2FSK, on the 39 channels the sketch lists inside 300–348, 387–464, and 779–928 MHz. The LoRa module on this card is a Ra-02 SX1278. The firmware resets it and writes it to sleep so DIO0 releases GPIO 48 for the CC1101. GPIO 26 is reserved on the PCB for a later SX1262 and stays unused. The fuel gauge is a MAX17048 at I2C address 0x36. A kept decode is written to the microSD as a FOBworks RAW file, and the dashboard reads that library back. The CC1101 is accepted only when its version register is 0x04 or 0x14, and that byte is shown on the status chip.

There are **two** dashboards. The card serves one itself. The other is a React app that runs on your computer. Both talk to the same firmware and both need the same access code.

| | Card's own dashboard | React dashboard |
| --- | --- | --- |
| Where it runs | on the card | on your computer |
| How you reach it | `http://192.168.4.1` | `http://localhost:5173` |
| Transport | HTTP, port 80 | **USB Serial** (Chrome/Edge) or **WebSocket, port 81** |
| Source | inside `FOBworks_for_SGP.ino` | `FOBworks_SGP_Dashboard/` |
| Needs a computer | no — any phone works | yes |

The access point name is `SGP Card Mini`. The Bluetooth name is `SGP Card Mini`. Hold the user button for 3 seconds to sleep, and hold it for 3 seconds to wake.

## Connecting to a dashboard

### The access code

Both dashboards need it, and it is the same value for both. It is printed **once**, on the USB serial log, the first time the card boots:

```
[SECURITY] Per-device credentials (USB serial only)
[SECURITY] WiFi SSID: SGP Card Mini
[SECURITY] WiFi password: <16 chars>
[SECURITY] Dashboard access code: <26 chars>
```

It is generated on the card and kept in its own memory, so it **survives reflashing**. If you have lost it, wipe the card's `dev-auth` NVS namespace or use `{"cmd":"reinit"}` to have it regenerate.

The firmware rejects every command without this code — serial, WebSocket, and HTTP alike — with `{"ok":false,"error":"unauthorized"}`.

### Card's own dashboard

1. Plug the card into USB.
2. On your phone or computer, join the `SGP Card Mini` network with the WiFi password from the boot log.
3. Open `http://192.168.4.1`.
4. Enter the access code.

The card runs a captive portal, so on most phones the dashboard opens by itself once you join.

### React dashboard over USB

The React app is a local web page that talks to the card through the browser's **Web Serial** API. Nothing is served by the card for this path.

1. **Plug the card into USB.**
2. **Close anything else holding the serial port.** This is the most common failure — see below.
3. Start the dashboard:

   ```bash
   cd FOBworks_SGP_Dashboard/artifacts/sgp-scanner-dashboard
   PORT=5173 BASE_PATH=/ pnpm run dev
   ```

   Both environment variables are required; the Vite config throws without them.

4. Open **`http://localhost:5173`** in **Chrome or Edge**. Safari and Firefox do not implement Web Serial, and the USB button is disabled with a "Requires Chrome or Edge" tooltip.
5. Choose **USB Serial**, paste the **Device Access Code**, click **Connect via USB**.
6. Your browser shows a port picker. **Pick the `usbmodem` port**, not the `usbserial` one. The ESP32-S3's native USB CDC is the one the firmware writes JSON to; the UART bridge is silent.

**If the picker opens empty:** another program has the port. On macOS:

```bash
lsof /dev/cu.usbmodem*
```

The usual culprit is the **Arduino IDE's Serial Monitor** — click its magnifier icon to toggle it off. `screen`, `cu`, and `minicom` will do it too. A browser reports an empty picker as `No port selected by the user`, which reads like you cancelled it; it usually means the port was busy.

### React dashboard over WiFi

Same app, no cable. The firmware serves a WebSocket command/event transport on **port 81** for exactly this.

1. Join the `SGP Card Mini` network.
2. Start the dashboard the same way (`pnpm run dev`, then open `http://localhost:5173`).
3. Choose **WiFi AP**, enter the access code, and leave the device IP as `192.168.4.1`.
4. Click **Connect via WiFi**.

Both transports run through the same command dispatcher on the card, so a command behaves identically either way.

One caveat: if you serve the dashboard over **HTTPS**, the browser blocks plain `ws://` connections as mixed content. Use `http://localhost:5173` as documented.

## What is in this folder

| File | What it is |
| --- | --- |
| `FOBworks_for_SGP.ino` | The sketch. This is what I flash. The card's own dashboard is the page inside this file. |
| `html_page.h` | The card's dashboard page. One copy. |
| `loop_stack.cpp` | **Required companion file.** Raises the loop task stack from the 8 KB Arduino default to 12 KB — the decode path needs more than 8 KB on a real frame. It lives in a separate translation unit because `SET_LOOP_TASK_STACK_SIZE()` expands to a function *definition*, and the sketch preprocessor hoists generated prototypes above the sketch's `#include`s, which breaks the build. Keep it in this folder. |
| `PROMO.md` | The four modes, what each one does, and the workflow I use. |
| `CITATIONS_AND_REFERENCES.md` | The documents this sketch is written against. |
| `LICENSE` | GNU General Public License v3.0. |
| `bench_*.py` | Serial-side bench helpers: `bench_serial_log.py` logs and filters the card's JSON stream, `bench_send.py` sends commands, `bench_c2_capture.py` drives a capture. |
| `test_*.py` | 15 host-side checks. See **Tests** below. |

`FOBworks_SGP_Dashboard/` is the React dashboard, unpacked from its source archive. It is not needed to flash or use the firmware over WiFi with the card's own page.

## Flash it

Arduino IDE, ESP32 core 3.x. I compiled this sketch with core 3.3.12.

- Board: ESP32S3 Dev Module
- CPU frequency: 240 MHz
- Flash size: 8 MB
- PSRAM: Disabled
- Partition scheme: Huge APP (3 MB No OTA / 1 MB SPIFFS)
- USB mode: Hardware CDC and JTAG
- USB CDC on boot: Enabled
- Upload speed: 921600

PSRAM stays off. Turning on OPI PSRAM would take GPIO 33–37, which are the CC1101 SPI bus and the user button.

Libraries: Adafruit NeoPixel 1.12 or newer, ArduinoJson 7.x. SD, SPI, Wire, Preferences, DNSServer, WiFi, and `esp_http_server` come with the ESP32 core.

Open `FOBworks_for_SGP.ino` from this folder and upload it to the SGP Card Mini. `loop_stack.cpp` must be in the same folder or the build will not link.

Current build: **56% flash, 45% RAM.**

## First run

Plug the card into USB. At 115200 baud the serial log prints the WiFi SSID, the WiFi password, and the access code. Join the `SGP Card Mini` network and open `http://192.168.4.1`, or point the React dashboard at the card.

The card's home screen is a picker with four modes: FOBscan, FOBclone, FOBcatch, and FOBback. Capture, Scan, Decode, Predict, Keys, and Library are tabs inside FOBscan, and so is Bluetooth. `PROMO.md` is the description of each mode and the workflow I use.

Serial commands are JSON and carry the same access code:

```json
{"cmd":"status","token":"<access code>"}
```

## Serial commands

The same command set is accepted over USB serial and over the port-81 WebSocket. `{"cmd":"status","token":"…"}` is the liveness check; it returns firmware version, heap and stack watermarks, the reset reason, and the current radio state.

Beyond the four modes' commands (`capture`, `decode`, `replay`, `replay_predicted`, `replay_seq`, `scan_toggle`, `setfreq`, `squelch`, `sweep_range`, `cap_range`, `cap_mode`, `save`, `keys`, `key_add`, `key_del`, `key_list`, `key_clear`, `play_key`, `del_key`, `jam_start`, `jam_stop`, `fast_hop`, `set_filter`, `dual_band_replay`, `lib_replay`), these are worth knowing:

**Key recovery** — `key_recover_start`, `key_recover_cancel`, `key_probe`, `key_recover_offline`. The last takes a comma-separated hop list and runs recovery without the radio.

**FOBback / RollBack** — `fbk_arm`, `fbk_disarm`, `fbk_status`, `fbk_replay`, `fbk_import`. `fbk_import` takes a FOBworks RAW or a `.sub` capture body and loads a stored frame into the replay buffer, which is how you can test a transmit without a live capture. It searches the whole body for a frame and refuses with `no-frame-in-body` if there is none.

**C2 RollBack** — `rollback_arm`, `rollback_fire`, `rollback_status`. Transmits two held codes in order with a configurable gap.

**C1 RollJam** — `rolljam_arm`, `rolljam_start`, `rolljam_abort`, `rolljam_status`, `rolljam_replay`.

**Diagnostics** — `rssi_path_check`, `rx_floor_check`, `tx_fifo_test`, `pa_check`, `jam_status`, `gdo0_probe`. These exist because the CC1101's GDO0 is **not** routed to a readable GPIO on this revision. See **Hardware limits** below.

**Maintenance** — `hs_list`, `hs_clear`, `headless`, `freq_preset`, `fobclone_scan`. Regenerating credentials is HTTP-only: `GET /api/reinit`.

## Tests

15 Python suites, all host-side, no hardware and no network. Each one greps or extracts the real firmware source rather than trusting a summary, so they fail when the source stops matching the documentation.

```bash
cd FOBworks_for_SGP
for t in test_*.py; do python3 "$t"; done
```

| Test | What it guards |
| --- | --- |
| `test_control_surface_auth.py` | Every HTTP route is behind the access code, and **both** transports dispatch through the token gate |
| `test_keeloq_key_table.py` | KeeLoq boot self-test against published vectors; the 73-entry key table matches the leaked corpus; version strings agree |
| `test_tx_packet_mode.py` | Packet-mode TX registers: MARCSTATE constants, FIFO bounds, PA table levels |
| `test_frame_trim.py` | Frame trimming against a real capture, 161 frames |
| `test_replay_encode.py` | The FIFO frame encoder: symbol period from `te`, ratio preserved |
| `test_rolljam_exec.py`, `test_rollback_exec.py` | C1/C2 state machines, extracted and compiled against a mock radio |
| `test_rollback_samecode.py` | C2 refuses a same-code pair |
| `test_fbk_import.py` | Stored-frame import trims, decodes, and carries a counter |
| `test_limit_strings.py` | Every `max_bytes` string equals its constant; one buffer per purpose |
| `test_raw_polarity.py` | Capture polarity survives export and replay |
| `test_a2_reporting.py` | The Kia V3/V4 verdict is not overstated; duplicates collapse |
| `test_hexstr_bounds.py`, `test_sub_replay_body_limit.py` | Buffer bounds |

## Hardware limits on this revision

Worth stating plainly, because two of these shape what the tool can do.

**GDO0 is not connected.** The CC1101's demodulated data output is not routed to a readable GPIO on this board — GPIO 48 is the SX1278's DIO0. The vendor's own firmware says so (`"GDO0 NO está cableado al ESP32 en este PCB"`). Consequences:

- **Capture falls back to polling RSSI**, which samples at roughly 1600 µs. That is slower than a Kia V3/V4 short pulse of 400 µs, so a capture can come back as uniform pulses with no bit edges in it. The firmware refuses those with `no-bit-edges` rather than feeding them to the decoders.
- **Transmit does not depend on GDO0.** Packet mode drives the CC1101's own PA from the TX FIFO, so replay, jamming and the sequencers work. This was verified by an external receiver decoding a transmitted frame.
- Routing GDO0 (chip pin 6) or GDO2 (pin 3) to a free GPIO fixes capture quality. GDO2 is easier to reach but is output-only, so it gives capture without transmit.

**There is no low-frequency front end.** The CC1101 covers 300–928 MHz. Passive-entry LF wake-up at 125 kHz, and the Hitag2, Megamos and DST40 immobilisers below 300 MHz, are out of reach on this hardware.

**RAM is at 45%.** The two biggest consumers are the decode path and the WebSocket inbound queue. Check `stack_hwm` and `heap_free` from `status` before extending the decode path.

## Development notes

The `test_*.py` suites at the repository root pin the parser boundaries, the safety guards, and the JSON formatting. `tools/corpus_regression.py` runs the firmware's own decoders — extracted and compiled, not reimplemented — against a corpus of real captures:

```bash
python3 tools/corpus_regression.py
```

It aborts if its known-good control fails, so a green run means the harness is sound.

## License

Copyright (C) 2026 OurLady.

FOBworks for SGP is free software under the GNU General Public License v3.0. The full license is in `LICENSE`.
