# FOBworks for SGP

FOBworks for SGP is standalone firmware for the SGP Card Mini, a third-party board. Version 3.79.

This build targets the SGP Card Mini stock acquired in May 2026: an ESP32-S3-MINI-1-N8 with a dual-core LX7 at 240 MHz, 8 MB quad flash, no PSRAM, Wi-Fi 802.11 b/g/n, and BLE 5. The sub-GHz radio is the onboard CC1101, using OOK and 2FSK across the 39 channels listed in the sketch between 300–348, 387–464, and 779–928 MHz. The board also has a Ra-02 SX1278 LoRa module. GPIO 48 is connected to the SX1278's DIO0; the CC1101's GDO0 is not routed to a readable GPIO. Resetting or sleeping the SX1278 does not provide a CC1101 data connection. GPIO 26 is reserved on the PCB for a future SX1262 and is unused. The MAX17048 fuel gauge is at I2C address `0x36`. Kept decodes are written to the microSD card as FOBworks RAW files, which the dashboard can read back. The firmware accepts CC1101 version-register values `0x04` and `0x14`; the detected value appears in the status chip.

The card serves its own dashboard. A separate React dashboard can run on a computer. Both connect to the same firmware and require the same access code.

| | Card's own dashboard | React dashboard |
| --- | --- | --- |
| Where it runs | on the card | on your computer |
| How you reach it | `http://192.168.4.1` | `http://localhost:5173` |
| Transport | HTTP, port 80 | **USB Serial** (Chrome/Edge) or **WebSocket, port 81** |
| Source | `FOBworks_for_SGP.ino` | Separate project; not included here |
| Needs a computer | no — any phone works | yes |

The Wi-Fi access point and Bluetooth device are both named `SGP Card Mini`. Hold the user button for 3 seconds to sleep or wake the card.

## Connecting to a dashboard

### The access code

Both dashboards use the same access code. The card prints the Wi-Fi credentials and access code to USB serial at startup:

```
[SECURITY] Per-device credentials (USB serial only)
[SECURITY] WiFi SSID: SGP Card Mini
[SECURITY] WiFi password: <16 chars>
[SECURITY] Dashboard access code: <26 chars>
```

The card generates the code and stores it in its own memory, so reflashing does not erase it. To replace a lost code, erase the card's `dev-auth` NVS namespace and reboot; the firmware creates new credentials at startup.

Without this code, commands over serial, WebSocket, and HTTP are rejected with `{"ok":false,"error":"unauthorized"}`.

### Card's own dashboard

1. Plug the card into USB.
2. On your phone or computer, join the `SGP Card Mini` network with the WiFi password from the boot log.
3. Open `http://192.168.4.1`.
4. Enter the access code.

The card provides a captive portal. On most phones, its dashboard opens after you join the network.

### React dashboard over USB

The computer dashboard communicates with the card through the browser's **Web Serial** API. The card does not serve the React app; you must have its separate source available locally. It is not included in this firmware repository.

1. Plug the card into USB.
2. Close any other program using its serial port; this is the most common reason the connection fails.
3. Start the dashboard:

   ```bash
   cd FOBworks_SGP_Dashboard/artifacts/sgp-scanner-dashboard
   PORT=5173 BASE_PATH=/ pnpm run dev
   ```

   Both environment variables are required. The Vite configuration exits with an error if either is missing.

4. In **Chrome or Edge**, open **`http://localhost:5173`**. Safari and Firefox do not support Web Serial; the USB button is disabled there and shows a "Requires Chrome or Edge" tooltip.
5. Select **USB Serial**, enter the **Device Access Code**, then click **Connect via USB**.
6. In the browser's port picker, choose `usbmodem`, not `usbserial`. Firmware JSON is sent over the ESP32-S3's native USB CDC port; the UART bridge does not carry it.

If the port picker is empty, another program may already have the port open. On macOS, find the process with:

```bash
lsof /dev/cu.usbmodem*
```

The Arduino IDE's Serial Monitor is a common cause; close it with the magnifier button. `screen`, `cu`, and `minicom` can also hold the port. An empty picker may be reported as `No port selected by the user`, even when the port is busy.

### React dashboard over WiFi

The React app can also connect over Wi-Fi. The firmware exposes its command and event WebSocket on **port 81**.

1. Join the `SGP Card Mini` network.
2. Start the dashboard the same way (`pnpm run dev`, then open `http://localhost:5173`).
3. Choose **WiFi AP**, enter the access code, and leave the device IP as `192.168.4.1`.
4. Click **Connect via WiFi**.

USB and Wi-Fi commands use the same dispatcher, so both transports have the same command behavior.

When the dashboard is served over **HTTPS**, browsers block the card's plain `ws://` connection as mixed content. Use `http://localhost:5173` instead.

## What is in this folder

| File | What it is |
| --- | --- |
| `FOBworks_for_SGP.ino` | Firmware sketch; includes the card's dashboard. |
| `html_page.h` | The card dashboard's HTML, CSS, and JavaScript. |
| `loop_stack.cpp` | Required companion file. Raises the Arduino loop-task stack from 8 KB to 12 KB for the decode path. It must remain separate from the sketch: `SET_LOOP_TASK_STACK_SIZE()` expands to a function definition, while the sketch preprocessor places generated prototypes before the sketch's includes, which breaks the build. |
| `PROMO.md` | A tour of the four modes, their behavior, and the documented workflow. |
| `CITATIONS_AND_REFERENCES.md` | Sources for the firmware's protocol, board, and radio details. |
| `LICENSE` | GNU General Public License v3.0. |
| `bench_*.py` | Serial-side bench helpers: `bench_serial_log.py` logs and filters the card's JSON stream, `bench_send.py` sends commands, `bench_c2_capture.py` drives a capture. |
| `test_*.py` | 16 host-side checks. See **Tests** below. |

This repository contains neither the React dashboard nor its source archive. The connection steps above apply if you have the dashboard source separately and unpack it into `FOBworks_SGP_Dashboard/`. You can flash and use the firmware over Wi-Fi without it; the card serves its own dashboard.

## Flash it

Use Arduino IDE with ESP32 core 3.x. This sketch was compiled with core 3.3.12.

- Board: ESP32S3 Dev Module
- CPU frequency: 240 MHz
- Flash size: 8 MB
- PSRAM: Disabled
- Partition scheme: Huge APP (3 MB No OTA / 1 MB SPIFFS)
- USB mode: Hardware CDC and JTAG
- USB CDC on boot: Enabled
- Upload speed: 921600

Leave PSRAM disabled. Enabling OPI PSRAM would claim GPIO 33–37, which this board uses for the CC1101 SPI bus and the user button.

Libraries: Adafruit NeoPixel 1.12 or newer, ArduinoJson 7.x. SD, SPI, Wire, Preferences, DNSServer, WiFi, and `esp_http_server` come with the ESP32 core.

Open `FOBworks_for_SGP.ino` from this folder and upload it to the SGP Card Mini. Keep `loop_stack.cpp` beside it; otherwise, the build will not link.

Current build: **56% flash, 45% RAM.**

## First run

Plug the card into USB and open the serial log at 115200 baud to get the Wi-Fi credentials and access code. Then join `SGP Card Mini` and open `http://192.168.4.1`. If you have the separate React dashboard, you can connect it to the card instead.

The home screen offers four modes: FOBscan, FOBclone, FOBcatch, and FOBback. FOBscan contains the Capture, Scan, Decode, Predict, Keys, Library, and Bluetooth tabs. See `PROMO.md` for an overview of each mode.

Serial commands are JSON and carry the same access code:

```json
{"cmd":"status","token":"<access code>"}
```

## Serial commands

USB serial and the port-81 WebSocket accept the same commands. Use `{"cmd":"status","token":"…"}` to check the connection; the response includes the firmware version, heap and stack watermarks, reset reason, and radio state.

The mode commands include `capture`, `decode`, `replay`, `replay_predicted`, `replay_seq`, `scan_toggle`, `setfreq`, `squelch`, `sweep_range`, `cap_range`, `cap_mode`, `save`, `keys`, `key_add`, `key_del`, `key_list`, `key_clear`, `play_key`, `del_key`, `jam_start`, `jam_stop`, `fast_hop`, `set_filter`, `dual_band_replay`, and `lib_replay`. Other useful commands:

**Key recovery:** `key_recover_start`, `key_recover_cancel`, `key_probe`, and `key_recover_offline`. The last command takes a comma-separated hop list and runs recovery without the radio.

**FOBback / RollBack:** `fbk_arm`, `fbk_disarm`, `fbk_status`, `fbk_replay`, and `fbk_import`. The import command accepts a FOBworks RAW file or `.sub` capture body and loads a stored frame into the replay buffer for testing without a live capture. It searches the full body and returns `no-frame-in-body` if it finds no frame.

**C2 RollBack:** `rollback_arm`, `rollback_fire`, and `rollback_status`. Sends two held codes in order, with a configurable gap.

**C1 RollJam:** `rolljam_arm`, `rolljam_start`, `rolljam_abort`, `rolljam_status`, and `rolljam_replay`.

**Diagnostics:** `rssi_path_check`, `rx_floor_check`, `tx_fifo_test`, `pa_check`, `jam_status`, and `gdo0_probe`. The GDO0 probe is useful because this board does **not** route the CC1101's GDO0 to a readable GPIO. See **Hardware limits** below.

**Maintenance:** `hs_list`, `hs_clear`, `headless`, `freq_preset`, and `fobclone_scan`. `GET /api/reinit` reinitializes the radio; it does not regenerate credentials.

## Tests

The 16 Python test suites run on the host; they do not require the card or a network connection. Depending on the test, they inspect or extract code from the firmware, compile state-machine logic against a mock radio, or check recorded captures.

```bash
cd FOBworks_for_SGP
for t in test_*.py; do python3 "$t"; done
```

| Test | What it guards |
| --- | --- |
| `test_control_surface_auth.py` | Every HTTP route is behind the access code, and **both** transports dispatch through the token gate |
| `test_keeloq_key_table.py` | KeeLoq boot self-test against published vectors; the 73-entry key table matches the public reference corpus; version strings agree |
| `test_tx_packet_mode.py` | Packet-mode TX registers: MARCSTATE constants, FIFO bounds, PA table levels |
| `test_frame_trim.py` | Frame trimming against a real capture, 161 frames |
| `test_replay_encode.py` | The FIFO frame encoder: symbol period from `te`, ratio preserved |
| `test_rolljam_exec.py`, `test_rollback_exec.py` | C1/C2 state machines, extracted and compiled against a mock radio |
| `test_rollback_c2.py` | C2 guard rails, sequencing, and dashboard labels |
| `test_rollback_samecode.py` | C2 refuses a same-code pair |
| `test_fbk_import.py` | Stored-frame import trims, decodes, and carries a counter |
| `test_limit_strings.py` | Every `max_bytes` string equals its constant; one buffer per purpose |
| `test_raw_polarity.py` | Capture polarity survives export and replay |
| `test_a2_reporting.py` | The Kia V3/V4 verdict is not overstated; duplicates collapse |
| `test_review_v373_fixes.py` | Source-level checks for review fixes; hardware behavior is not proved by these checks |
| `test_hexstr_bounds.py`, `test_sub_replay_body_limit.py` | Buffer bounds |

## Hardware limits on this revision

The CC1101's GDO0 output is not connected to a readable GPIO on this board. GPIO 48 is wired to the SX1278's DIO0 instead; resetting or sleeping the SX1278 does not reconnect the CC1101. The vendor's own firmware also notes that GDO0 is not wired (`"GDO0 NO está cableado al ESP32 en este PCB"`). In practice:

- **Capture falls back to polling RSSI**, which samples at roughly 1600 µs. That is slower than a Kia V3/V4 short pulse of 400 µs, so a capture can come back as uniform pulses with no bit edges in it. The firmware refuses those with `no-bit-edges` rather than feeding them to the decoders.
- **Transmit does not depend on GDO0.** Packet mode drives the CC1101's own PA from the TX FIFO, so replay, jamming and the sequencers work. This was verified by an external receiver decoding a transmitted frame.
- Routing GDO0 (chip pin 6) or GDO2 (pin 3) to a free GPIO fixes capture quality. GDO2 is easier to reach but is output-only, so it gives capture without transmit.

**There is no 125 kHz LF front end.** The CC1101 covers 300–928 MHz, so 125 kHz passive-entry wake-up and the below-300 MHz immobilisers (Hitag2, Megamos, DST40) are out of reach on this board.

**The board does have a 13.56 MHz HF front end, and this firmware does not use it.** A PN532 sits on the shared I2C bus at address 0x24, alongside the MAX17048 gauge at 0x36. The stock tool for it drives ISO14443A passive-target reads; nothing in FOBworks touches it, and no command, decode or replay path depends on it. If NFC is wanted here, it is a separate feature rather than an extension of the sub-GHz work.

The current build uses **45% of RAM**. The decode path and WebSocket inbound queue are the largest consumers. Check `stack_hwm` and `heap_free` in the `status` response before extending the decode path.

## Development notes

`research/sources/` holds the capture corpus the decoder regression runs against, and the tooling that reads it. The working notes themselves are kept separately and are not part of this repository.

The `test_*.py` suites check parser boundaries, safety guards, and JSON formatting. `tools/corpus_regression.py` extracts and compiles the firmware's decoders, then runs them against a corpus of real captures:

```bash
python3 tools/corpus_regression.py
```

The harness stops if its known-good control fails. A passing run therefore includes that control check.

## License

Copyright (C) 2026 OurLadyOfTheRevolution.

FOBworks for SGP is free software under the GNU General Public License v3.0. The full license is in `LICENSE`.
