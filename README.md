# FOBworks for SGP

FOBworks for SGP is standalone firmware for the SGP Card Mini, a third-party board. Version 4.05.

The published tree is a disclosure variant of the development tree: manufacturer-key literals are masked, the private engineering worklog stays private, and a measured-limits subset of research notes plus the corpus scorecard ship so the claims in `PROMO.md` and the hardware-limits section are checkable. See `docs/PUBLISHING.md` and `docs/LIMITATIONS.md`.

This build targets the SGP Card Mini stock acquired in May 2026: an ESP32-S3-MINI-1-N8 with a dual-core LX7 at 240 MHz, 8 MB quad flash, no PSRAM, Wi-Fi 802.11 b/g/n, and BLE 5. The sub-GHz radio is the onboard CC1101, using OOK and 2FSK across the 39 channels listed in the sketch between 300–348, 387–464, and 779–928 MHz. The board also has a Ra-02 SX1278 LoRa module. GPIO 48 is connected to the SX1278's DIO0; the CC1101's GDO0 is not routed to a readable GPIO. Resetting or sleeping the SX1278 does not provide a CC1101 data connection. GPIO 26 is reserved on the PCB for a future SX1262 and is unused. The MAX17048 fuel gauge is at I2C address `0x36`. Kept decodes are written to the microSD card as FOBworks RAW files, which the dashboard can read back. The firmware accepts CC1101 version-register values `0x04` and `0x14`; the detected value appears in the status chip.

The card serves its own dashboard. A separate React dashboard can run on a computer. Both connect to the same firmware and require the same access code.

| | Card's own dashboard | React dashboard |
| --- | --- | --- |
| Where it runs | on the card | on a computer |
| How to reach it | `http://192.168.4.1` | `http://localhost:5173` |
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
2. On a phone or computer, join the `SGP Card Mini` network with the WiFi password from the boot log.
3. Open `http://192.168.4.1`.
4. Enter the access code.

The card provides a captive portal. On most phones, its dashboard opens after joining the network.

### React dashboard over USB

The computer dashboard communicates with the card through the browser's **Web Serial** API. The card does not serve the React app; its separate source has to be available locally. It is not included in this firmware repository.

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
| `test_*.py` | 46 host-side checks. See **Tests** below. |

This repository contains neither the React dashboard nor its source archive. The connection steps above apply when the dashboard source is available separately and unpacked into `FOBworks_SGP_Dashboard/`. The firmware can be flashed and used over Wi-Fi without it; the card serves its own dashboard.

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

`CDCOnBoot` is not optional. This board's USB is the chip's own USB-Serial-JTAG, so with `USB CDC on boot` left at its default the sketch's `Serial` output goes to the UART pins and the card looks dead over USB: no boot log, no reply to commands, nothing. Every board symptom described in the worklog turned out to be this setting, so check it before diagnosing anything else.

The whole set as one command line, for `arduino-cli`:

```
arduino-cli compile --fqbn "esp32:esp32:esp32s3:FlashSize=8M,PartitionScheme=huge_app,PSRAM=disabled,CDCOnBoot=cdc,USBMode=hwcdc" .
arduino-cli upload  -p /dev/cu.usbmodem1101 \
   --fqbn "esp32:esp32:esp32s3:FlashSize=8M,PartitionScheme=huge_app,PSRAM=disabled,CDCOnBoot=cdc,USBMode=hwcdc" .
```

A full-image flash erases NVS, which regenerates the Wi-Fi password and dashboard access code. Read the new ones from the boot log; an old token answers `{"ok":false,"error":"unauthorized"}`, which is the card working, not failing.

Libraries: Adafruit NeoPixel 1.12 or newer, ArduinoJson 7.x. SD, SPI, Wire, Preferences, DNSServer, WiFi, and `esp_http_server` come with the ESP32 core.

Open `FOBworks_for_SGP.ino` from this folder and upload it to the SGP Card Mini. Keep `loop_stack.cpp` beside it; otherwise, the build will not link.

Current build: **58% flash, 49% RAM.**

## First run

Plug the card into USB and open the serial log at 115200 baud to get the Wi-Fi credentials and access code. Then join `SGP Card Mini` and open `http://192.168.4.1`. The separate React dashboard, when available, can connect to the card instead.

The home screen offers four modes: FOBscan, FOBclone, FOBcatch, and FOBback. FOBscan's tabs are Capture, Scan, Decode, Predict, Keys, Library, and Instruments — the last drawing the claim trace, resync curve and parked RollJam IDS. Bluetooth scanning and pairing are reached over the HTTP API rather than through the card dashboard: `GET /api/ble_scan`, `GET /api/ble_results`, and the `/api/ble_pair_start`, `/api/ble_pair_status`, `/api/ble_pair_stop`, and `/api/ble_paired_devices` routes. See `PROMO.md` for an overview of each mode.

Serial commands are JSON and carry the same access code:

```json
{"cmd":"status","token":"<access code>"}
```

## Serial commands

USB serial and the port-81 WebSocket accept the same commands. Use `{"cmd":"status","token":"…"}` to check the connection; the response includes the firmware version, heap and stack watermarks, reset reason, and radio state.

The mode commands include `capture`, `decode`, `replay`, `replay_predicted`, `replay_seq`, `scan_toggle`, `setfreq`, `squelch`, `sweep_range`, `cap_range`, `cap_mode`, `save`, `keys`, `key_add`, `key_del`, `key_list`, `key_clear`, `play_key`, `del_key`, `jam_start`, `jam_stop`, `fast_hop`, `set_filter`, `dual_band_replay`, and `lib_replay`. Other useful commands:

**Key recovery:** `key_recover_start`, `key_recover_cancel`, `key_probe`, and `key_recover_offline`. The last command takes a comma-separated hop list and runs recovery without the radio.

**FOBback / RollBack:** `fbk_arm`, `fbk_disarm`, `fbk_status`, `fbk_replay`, and `fbk_import`. The import command accepts a FOBworks RAW file or `.sub` capture body and loads a stored frame into the replay buffer for testing without a live capture. It searches the full body and returns `no-frame-in-body` if it finds no frame. Over serial, a large body should arrive in chunks: `fbk_pulses_begin` (with `freq`), then `fbk_pulses_add` with `pulses` slices of up to 48 values (each line stays ~240 bytes, half the measured heap boundary), then `fbk_pulses_end` to run the import over the assembled body. The one-shot `fbk_import` form is heap-bound near ~130 pulses. An add that carries a `pulses` field but stages none replies `ok:false` with `reason:"empty-pulses"` rather than passing silently.

**C2 RollBack:** `rollback_arm`, `rollback_fire`, and `rollback_status`. Sends two held codes in order, with a configurable gap.

**C1 RollJam:** `rolljam_arm`, `rolljam_start`, `rolljam_abort`, `rolljam_status`, and `rolljam_replay`.

**Diagnostics:** `rssi_path_check`, `rx_floor_check`, `tx_fifo_test`, `pa_check`, `jam_status`, `gdo0_probe`, `gdo0_isolate`, `gdo0_rail_test`, and `gdo0_signal`. The GDO0 set exists because this board does **not** route the CC1101's GDO0 to a readable GPIO. `gdo0_signal` is the decisive one: it cuts the LoRa's power so the SX1278's DIO0 is gone, then asks the CC1101 to emit its crystal clock on GDO0 and counts edges on pin 48 — the only test that can tell "unrouted" apart from "the LoRa was masking it". It is documented in **Hardware limits** below.

**Instrumentation:** `claim_trace` (with `clear`) reports the last eight decodes — timing, gate, spread, and the protocol each claimed — and `GET /api/claim_trace` serves the same. `resync_curve`, `resync_curve_status`, `resync_mark`, and `resync_curve_clear` drive the resync-window profiler (`GET /api/resync_curve`). `p5_ids` arms, clears, or reports the parked RollJam watchdog (`GET /api/p5_ids`). `lora_cw_probe` keys the SX1278 as a continuous-wave carrier and measures the rise at the CC1101; release of the reset line is required first, the mode writes are read back one step each (STANDBY then TX), and a `meter_pegged` flag marks a reading at the RSSI rail. `clone_class` classifies the held KeeLoq frames as a clone chip or a cipher-running part without the key, key-free — counter-linearity is a proof, hop-XOR sparsity a statistic (`GET /api/clone_class`). The hop-XOR strip appears on each KeeLoq decode as `hop_xor`, and the same decode carries `clone_class`. The Instruments tab draws the claim trace, the resync curve, the RollJam IDS read-out, and the clone-chip classifier directly from those endpoints.

**Maintenance:** `hs_list`, `hs_clear`, `headless`, `freq_preset`, and `fobclone_scan`. `GET /api/reinit` reinitializes the radio; it does not regenerate credentials.

## Tests

The 46 Python test suites run on the host; they do not require the card or a network connection. Depending on the test, they inspect or extract code from the firmware, compile state-machine logic against a mock radio, or check recorded captures. `test_serial_fuzz.py` additionally drives the card over USB when one is attached; `python3 test_serial_fuzz.py host` runs its source-level half alone.

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
| `test_decoder_false_positives.py` | Decoder guards against cross-brand false positives on the corpus |
| `test_gate_decoder_false_positives.py` | Somfy/Nice/FAAC64 gates no longer claim other brands' captures; genuine frames still decode |
| `test_toyota_reachability.py` | The Toyota decoder fires on its own captures, not only foreign ones |
| `test_review_v373_fixes.py` | Source-level checks for review fixes; hardware behavior is not proved by these checks |
| `test_hexstr_bounds.py`, `test_sub_replay_body_limit.py` | Buffer bounds |
| `test_consensus_guard.py` | Intra-capture repeat consensus: slice splitting on a real Kia window, alias demotion, adapter wiring |
| `test_psa_decoder.py` | PSA FM0 decoder on the corpus: five clean captures decode (same-fob prefix check), VW/FIAT/Renault/Skoda rejected |
| `test_fiat_decoder.py` | FIAT V1 decoder on the corpus: 8/12 FIAT captures decode (Grande Punto uid B6AB9928 btn 1/2, Panda uid A4A02529, sequential counters), VW/Renault/Skoda/other-FIAT-variant rejected; gate, dispatch and consensus adapter wired |
| `test_renault_hitag2.py` | Renault V1 (Hitag2) Layer-1 decoder on the corpus: the one genuine Hitag2 recording decodes (Trafic 2011 sn 3270FD2B btn 2 ctr 0x15C), the near-miss Renault families and VW/Skoda reject, a synthetic known frame round-trips, and the gate/dispatch/ordering are wired |
| `test_renault_layer2.py` | Renault V1 Layer-2 closure: hopseq extracts all five frames (counter walks 0x15C..0x160), the exhaustive 2^32 IV searcher is self-consistent (recovers a known IV), the FIAT known-key dictionary yields zero hits on the real frames, and the chance fixed-point IVs share no seed byte — so the epoch/seed model is falsified rather than merely unsearched |
| `test_renault_family_accounting.py` | Renault corpus accounting and family split: the 26 Renault-named files are 10 unique captures (16 duplicates), the file filter tokenises so "captur" does not match "Captured", Ren3 is FSK and out of scope for OOK width work, Ren2 is a clean 105 µs family distinct from the 33 µs PWM group, and degraded captures are flagged rather than classified |
| `test_renault_pwm_model.py` | Renault fixed-slot PWM model falsification: every Megane/Captur/`Ren2` capture has zero repeated ≥16-symbol runs and pair sums that do not cluster at 5T, while the FIAT controls from the same corpus show 357 and 600 repeated symbols — so the metric works and the fixed-slot decoder target does not exist in the files |
| `test_kia_v1_decoder.py` | KIA/HYU V1 decoder: the three on-brand 315 MHz V1 captures decode (Kia_V1_N1_RAW and Kia_V1_5cl_5op both sn B444706E btn 1 ctr 091, Hyundai_V1_N1_RAW sn 555B4447 btn 6 ctr 1E0), the Toyota Estima 2000 near-miss family rejects, and the gate/preamble/dispatch are wired — the fixes being a `te_kv1` window widened to the reference 800/1600 µs TE, a 140-pulse `te_long` preamble gate, and (v4.01) excluding a Kia V1 frame from the loose KeeLoq gate that claimed it before its own branch could run |
| `test_frame_structure_scan.py` | Corpus frame-structure triage: the scanner reports 323 captures (117 STRONG / 39 WEAK / 167 NONE), the Renault Trafic Hitag2 and FIAT Grande Punto captures score STRONG, and the frame-less Megane/Captur/`Ren2` captures score NONE — a reliable positive for repeated-frame protocols with an explicit caveat that NONE is not a verdict |
| `test_gdo0_audit.py` | GDO0 hardware audit: the control-hardened `gdo0_signal` probe is wired and observes only (no TX strobe), reads VERSION/MARCSTATE as status registers, and the note/README record the V1/V2 document contradiction, the SX1278 board identity, and the shared-rail `RAIL_SHARED_CANNOT_ISOLATE` finding |
| `test_renault_66us.py` | Renault ~66 us family reconnaissance: Captur 2017 and Megane/Scenic 2005 are OOK at a ~33 us base with 66/100/132/166 us PWM symbols (not Manchester), and the Kadjar Ren files are a distinct base unit |
| `test_n11_n12_n13.py` | The research arc: press-correlation scoring thresholds, rolljam-detector echo guard / event ring / 60 s drain, timing-fingerprint quantizer (same fob sticks, different fobs separate) |
| `test_gap_arm.py` | Frame-gap arming: the state machine extracted from the capture path, compiled and driven against synthetic RSSI traces — plateau arms on quiet, fob press falls back, oscillation never arms, wait bounded |
| `test_serial_fuzz.py` | Serial dispatcher fuzz: adversarial lines (truncated JSON, wrong types, deep nesting, oversize, 24 random mutations) must each produce exactly one JSON reply or one named error — never silence, never a crash. Source half pins the intake/dispatch guarantees; live half runs them through the card |
| `test_hop_xor.py` | Hop-XOR telemetry: the XOR of two same-button KeeLoq hops equals `E(ptA)^E(ptB)` and is order-symmetric (the property that makes rollback validation key-independent); ring wrap order stays oldest-first |
| `test_keeloq_slide_lab.py` | KeeLoq related-key / clone-key lab: the host cipher is pinned to the card's published vectors and to the extracted `ks_klEncrypt`/`ks_klDecrypt` compiled with clang++; hop-XOR acts as a per-candidate filter; a clone-batch key (repeated byte / small alphabet / tiled pattern) is recovered and a random 64-bit key is shown unreachable |
| `test_clone_classifier.py` | Clone-chip classifier: the real `ks_cloneClassify()` extracted from the sketch and the host tool `tools/clone_classifier.py` agree on all 26 synthetic cases (verdict, median, pair count, counter-linearity, discrimination flag); counter-linearity (`hop_xor == ctr_xor`) proves a non-cipher clone, the hop-XOR sparsity bands separate a counter-tracking clone (median 2) from real KeeLoq (median 16), twenty random OEM keys are never called a clone, and a drifting discrimination field across one counter run is caught while two fobs in the ring are not |
| `test_brute_tick.py` | The brute sequencers: arming bounds, the counter/address sequence built in order, one transmit per tick with the inter-frame delay, single-flight refusal, progress and done events, `ok:false` on a failed transmit — and a source check that neither route blocks any more |
| `test_ws_fuzz.py` | The WebSocket transport's intake: host-only structural checks (frame cap replies `ws-frame-too-long`, the `{` gate, drop-on-full queue, reply generation+auth guards, handshake/close), plus a stdlib WebSocket client that drives the same adversarial corpus the serial suite uses. Live pass is hardware-gated (`--ap`/`--host`); the client itself is verified against `tools/_ws_echo_server.py`. |
| `test_claim_trace.py` | Live claim trace: the shipped eight-deep ring against the real ArduinoJson the sketch builds with — wrap order, newest-first render, an unclaimed decode carrying no protocol key, and the spread field being the shipped `ks_teStddev` as a percentage |
| `test_resync_curve.py` | Resync curve profiler: probe-plan generation (forward, backward, replay), the RF reply threshold (`RC_REPLY_DB` over the idle floor for `RC_REPLY_HITS` samples), hand-mark overrides, and separate accept/reject/unknown accounting that never folds silence into a rejection |
| `test_p5_ids.py` | Parked RollJam watchdog: the fast-attack, slow-decay floor tracker (a passing spike moves nothing, a sustained lift clears the threshold), the press-pair window and button/counter checks, and the score-to-JSON shape |
| `test_lora_cw.py` | SX1278 second-radio CW path: the `Frf` register carrier math at 433.92 and 868.0 MHz, the LF/HF mode bit, `PA_BOOST`, the safe power-down order, and the corrected state-machine sequence — STANDBY is written before TX so SLEEP never jumps straight to TX, and the mode word is TX (Mode=3) rather than FSTX |
| `test_renault_rke_crack.py` | The Hitag2 correlation attack: the ported proxmark3 `ht2crack4` recovers synthetic keys, the cipher matches the paper's vectors, and the corpus's five consecutive Trafic frames are scored at the attack's measured floor |
| `test_publish_transform.py` | The publication transform in `tools/publish_prepare.py`: the key table is masked and every read is unwrapped, no masked value equals its plaintext, the Kia literal is gone from the transformed sketch, the tidy rule preserves zero-argument calls (the regression that once shipped a check which could not fail), every suite asserting on a private worklog is in the gate list, and the final leak gate fires on a planted key |
| `tools/publish_check.py` | Gate on a staged public tree: whitelist notes present, no plaintext key corpus, PROMO corpus counts match `docs/CORPUS_SCORECARD.md`, FW/README/CITATIONS versions agree, no bare worklog pointers on the honesty surfaces |
| `test_flipper_pull.py` | The Flipper SD puller (`tools/flipper_pull.py`): the listing parser reads `[D]`/`[F] name <n>b` entries without mistaking the echoed command for a directory, `storage read` framing is stripped back to the exact payload, a short read is rejected rather than kept, and the payload is clipped to the size the listing reported. The live half walks the attached card and skips cleanly when none is present |

## Hardware limits on this revision

The CC1101's GDO0 output is not connected to a readable GPIO on this board. GPIO 48 is wired to the LoRa module's IRQ — the SX1278's DIO0 on this board (it reports LoRa `RegVersion 0x12`), or DIO1 on the later SX1262 revision — and resetting or sleeping the LoRa does not reconnect the CC1101. The vendor's own corrected header states it (`"GDO0 NO está cableado al ESP32 en este PCB"`, and its 2026-05-25 file sets `PIN_CC1101_GDO0` to `-1` with the note "Antes era 48, pero 48 es DIO0 del LoRa"); the older sketches that declare `GDO0 48` also declare the LoRa IRQ on 48 and simply copied one into the other. The full audit is `research/79_GDO0_HARDWARE_AUDIT.md`. In practice:

- **Capture falls back to polling RSSI**, which samples at roughly 1600 µs. That is slower than a Kia V3/V4 short pulse of 400 µs, so a capture can come back as uniform pulses with no bit edges in it. The firmware refuses those with `no-bit-edges` rather than feeding them to the decoders.
- **Transmit does not depend on GDO0.** Packet mode drives the CC1101's own PA from the TX FIFO, so replay, jamming and the sequencers work. This was verified by an external receiver decoding a transmitted frame.
- **Firmware cannot fully separate "unrouted" from "masked".** `gdo0_signal` is the attempt: it cuts the sensor rail so the LoRa is gone and asks the CC1101 to put its XOSC clock on GDO0. On this board the verdict is `RAIL_SHARED_CANNOT_ISOLATE` — the rail also powers the CC1101 (`VERSION` goes from `0x14` to `0x00` with the rail down), so the two outputs cannot be isolated without a wire. The conclusion therefore rests on the vendor's schematic note and on the LoRa's un-releasable DIO0 contention, not on a direct measurement.
- Routing GDO0 (chip pin 6) or GDO2 (pin 3) to a free GPIO fixes capture quality and makes `gdo0_signal` a direct test: if the clock appears on the bridged pin, GDO0 was routed; if not, the bridge is bad. GDO2 is easier to reach but is output-only, so it gives capture without transmit.

**There is no 125 kHz LF front end.** The CC1101 covers 300–928 MHz, so 125 kHz passive-entry wake-up and the below-300 MHz immobilisers (Hitag2, Megamos, DST40) are out of reach on this board.

**The board's only other radio is a 13.56 MHz HF front end, and it is not an LF path.** A PN532 sits on the shared I2C bus at address 0x24, alongside the MAX17048 gauge at 0x36, and the stock tool for it drives ISO14443A passive-target reads. That is 13.56 MHz, an order of magnitude above the 125 kHz the automotive immobilisers use, so it does not read Hitag2, Megamos or DST40 and does not provide the LF leg of a passive-entry relay — those need a 125 kHz coil, which this revision does not have. Nothing in FOBworks touches the PN532, and no command, decode or replay path depends on it. If 13.56 MHz NFC is wanted here, it is a separate feature rather than an extension of the sub-GHz work.

The current build uses **49% of RAM** for statics. The decode path and WebSocket inbound queue are the largest consumers. Runtime idle heap was 62,188 B after BLE was made lazy (v3.95) — before that, the BLE stack alone took ~71 KB and left ~1 KB, so no command could be parsed. Check `stack_hwm` and `heap_free` in the `status` response before extending the decode path.

## Development notes

`research/sources/` holds the capture corpus the decoder regression runs against, and the tooling that reads it. A measured-limits subset of the research notes ships with the published tree (see `docs/PUBLISHING.md`); the rest of the engineering worklog stays private. The decoder-coverage ledger is `docs/CORPUS_SCORECARD.md`.

The `test_*.py` suites check parser boundaries, safety guards, and JSON formatting. `tools/corpus_regression.py` extracts and compiles the firmware's decoders, then runs them against a corpus of real captures:

```bash
python3 tools/corpus_regression.py
```

The harness stops if its known-good control fails. A passing run therefore includes that control check.

## License

Copyright (C) 2026 OurLadyOfTheRevolution.

FOBworks for SGP is free software under the GNU General Public License v3.0. The full license is in `LICENSE`.
