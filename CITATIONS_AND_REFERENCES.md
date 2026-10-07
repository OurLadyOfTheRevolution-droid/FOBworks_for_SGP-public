# Citations and references

This list covers the sources used for FOBworks for SGP v4.02, which targets the May 2026 SGP Card Mini. It includes the KeeLoq references, radio and board datasheets, the board's own vendor documentation and firmware, documentation for the WebSocket transport, and the repositories this project drew protocol work from.

## KeeLoq

Three note numbers in the source do not identify a published Microchip KeeLoq document. The table maps each source label to the document relevant to that code path.

**Status (v4.02):** the comments the v3.71 KeeLoq work touched now cite the real notes directly, and the fix that replaced the wrong labels in the live encryption and decryption comments landed in v3.61 (the `AN1064` algorithm description, the decrypt path, the mode list). The three wrong labels below still appear in dated changelog entries, which are a record of what past releases said and are kept as written. No live code path cites them.

The firmware's 73-entry manufacturer-key table comes from the public list at `github.com/HiennNek/non-flipper-rolling-code-support` (`keeloq_mfcodes_user`). The source file is not included here because it contains the same keys already present in the firmware. Each entry's learning type (see `enum KLLearn` in the sketch) determines which derivation is used.

| Label in this sketch | What the code uses it for | Published document |
| --- | --- | --- |
| DS50033B | Manufacturer-code programming and the reference keys in the table | Microchip DS50033B, *Programming KEELOQ Devices with the PRO MATE II Device Programmer* |
| AN1064 | Normal-learn and decrypt paths, and the encrypt routine | There is no KeeLoq note with this number. Microchip AN1064 is *IR Remote Control Transmitter*, a PIC10F206 note for Philips RC5 and Sony SIRC. The KeeLoq normal-learn scheme this firmware follows is TB003 and AN742, below. |
| AN1031 | Secure-learn path, flag nibble 0x40 | There is no Microchip KeeLoq note AN1031. The secure-learn decoder note is AN662. |
| AN1130B | Discrimination-bit check when a candidate key is scored | There is no Microchip KeeLoq note AN1130B. The PIC16C56 decoder note with that bit layout is AN661. |

1. Microchip Technology, DS50033B, *Programming KEELOQ Devices with the PRO MATE II Device Programmer*. Covers manufacturer codes, encoder programming, and the factory-key concepts relevant to the reference entries in the table.
2. Microchip Technology, TB003, DS91002, *An Introduction to KeeLoq Code Hopping*. Describes normal learn from the serial number and secure learn from the seed; it is the published reference for both learning paths.
3. Microchip Technology, AN742, DS00742, *Modular PICmicro Mid-Range MCU Code Hopping Decoder*. Describes normal-learn key generation, refers to TB003 for the scheme, and points to TB001, DS91000, *Secure Learning RKE Systems using KEELOQ Encoders*, for the seed-based scheme.
4. Microchip Technology, AN661, DS00661C, *KEELOQ Code Hopping Decoder Using a PIC16C56*. Describes the discrimination bits checked after decryption. The sketch labels this check AN1130B.
5. Microchip Technology, AN662, DS00662, *KEELOQ Code Hopping Decoder Using Secure Learn*. Describes the path labeled AN1031 in the sketch.
6. Microchip Technology, *HCS300* and *HCS301 KEELOQ Code Hopping Encoder* datasheets. These describe the 66-bit frame parsed by the firmware: a 32-bit hopping code, button and status bits, serial discriminator, and sync counter. The header also lists HCS360, HCS361, HCS512, and HCS515 encoders in the same family.
7. Thomas Eisenbarth, Timo Kasper, Amir Moradi, Christof Paar, Mahmoud Salmasizadeh, and Mohammad T. Manzuri Shalmani, “Physical Cryptanalysis of KeeLoq Code Hopping Applications,” IACR ePrint 2008/058. The work also appeared at CRYPTO 2008 as “On the Power of Power Analysis in the Real World: A Complete Break of the KeeLoq Code Hopping Scheme,” LNCS 5157, pp. 203–220. The firmware's key-table comment cites the ePrint.

## Radio and the May 2026 card

8. Texas Instruments, *CC1101 Low-Power Sub-1 GHz RF Transceiver*, SWRS061. `cc_reset` follows the power-on sequence in section 10.1. This datasheet also defines the asynchronous OOK and 2FSK setup and packet-mode transmit registers in §24 (PATABLE) and §15 (MARCSTATE, TX FIFO). Three register details matter in practice: OOK needs both PATABLE levels programmed at indices 0 and 1, or logic-1 pulses transmit at zero power even as the FIFO drains; index 1 must be written as part of a **burst**, because the index counter advances only within a burst; and transmit states are MARCSTATE 19/20, not 17 (RXFIFO_OVERFLOW).
9. Semtech, *SX1276/77/78/79 Datasheet*. The May 2026 board uses a Ra-02 module with an SX1278. Hold reset low for at least 100 µs, then wait at least 5 ms before SPI access. Sleep is set by writing `0x00` to RegOpMode. On this board, the SX1278's DIO0 is connected to GPIO 48; an older pinout mislabeled the same line as CC1101 GDO0. Measurements and the vendor firmware show that the CC1101's GDO0 is not connected. Resetting or putting the SX1278 to sleep does not create that missing CC1101 connection.
10. Espressif Systems, *ESP32-S3-MINI-1 & ESP32-S3-MINI-1U Datasheet*. The N8 order code specifies 8 MB quad flash and no PSRAM. The module has dual-core LX7, Wi-Fi 802.11 b/g/n, and BLE 5. The sketch header uses matching flash settings.
11. Analog Devices, *MAX17048/MAX17049 Data Sheet*. VCELL is register `0x02`, state of charge is register `0x04`, and the gauge on this card responds at I2C address `0x36`.

### The board vendor's own material

The board's vendor ships a documentation set and a firmware collection for this hardware. Both were used directly, and one of them settles a question the register measurements could only narrow. They are distributed with the board rather than in this repository, so obtain them from the vendor: the documentation is the board's own pinout page and user manual, and the firmware is the vendor's sample sketch for this card.

12. **Vendor firmware**, the board's sample sketch for this card (`SGP_CardMini`). Decisive for the GDO0 question. Its pin block states the hardware reality directly:

```c
#define PIN_CC1101_GDO0  -1   // GDO0 NO está cableado al ESP32 en este PCB.
                              // Antes era 48, pero 48 es DIO0 del LoRa.
                              // Sin GDO0 no se puede hacer replay bit-bang;
                              // se hará via FIFO/PA del CC1101.
#define PIN_CC1101_GDO2  -1   // Tampoco está cableado.
```

Two things come from this comment. The CC1101's GDO0 and GDO2 are not wired at all on this revision, which three independent register measurements during the bench rounds had established; the vendor states it outright. And the FIFO/PA route is the vendor's own intended firmware workaround for the missing GDO0, which is why the bench work can conclude that C1/C2 transmit was never hardware-blocked. `GDO2` is `-1` as well, so the "wire GDO2 instead" option README.md mentions is not one this firmware takes.

13. **Vendor board documentation**, the board's pinout page and user manual. The pinout is the source for the two I2C devices on the shared bus: the PN532 NFC controller at `0x24` and the MAX17048 gauge at `0x36`. A caveat worth recording rather than smoothing over: the vendor's pinout labels GPIO 48 as "GDO0 shared with LoRa DIO0", which the vendor's own firmware contradicts. The measurements side with the firmware, so this project treats the pinout label as the stale of the two. That disagreement is written up in the worklog rather than resolved here.

## Repositories this project drew from

Each of these contributed protocol detail that is actually in the firmware; the note against each says what was taken. Repositories consulted but not drawn from are not listed: a citations document credits sources, and naming material that left no trace in the code would suggest a debt that does not exist.

14. **Flipper-ARF** (`D4C1-Labs`). The RollJam protocol set's `kia_v2.c` is the reference for the KIA/HYU V2 CRC4. This firmware's `ks_decodeKiaV2` had the formula wrong until v3.77: the check is `(xor of the twelve data nibbles + 1) & 0x0F`, and the missing `+ 1` is why the decoder rejected every genuine V2 frame while accepting a family of noise. The derivation and the corpus evidence are in the worklog.
15. **ProtoPirate**. Cross-listed source for the Kia/Hyundai V3/V4 manufacturer key used by `ks_decodeKiaV34`, alongside the key-availability table and the URH-NG crypto toolkit. Cross-checked rather than taken from one place, per the manufacturer-key survey.
16. **RocketGods-SubGHz-Toolkit**. Its "export keys" function writes the decrypted `keeloq_mfcodes` table to `/ext/subghz/analysis/keeloq_keys.txt`, the documented route other projects use to obtain that table from a Flipper's secure enclave. This firmware does not embed the decrypted table; it carries 73 keys from the public list in item 17. Listed because the manufacturer-key survey assesses it as the practical route to keys not in any firmware, and that assessment is part of the reasoning here.

## WebSocket transport (v3.73)

17. Espressif Systems, *ESP HTTP Server*, `esp_http_server.h`. The port-81 transport uses `httpd_start`, `httpd_register_uri_handler` with `is_websocket`, `httpd_ws_recv_frame`, and `httpd_ws_send_frame_async`. Arduino `WebServer` cannot upgrade a connection, so the firmware uses this server instead. It requires `CONFIG_HTTPD_WS_SUPPORT`, enabled in the ESP32 core 3.3.12 SDK for this target.
18. Espressif Systems, *ESP-IDF FreeRTOS*, `portmacro.h`. On this port, `portSTACK_TYPE` is `uint8_t`, so `uxTaskGetStackHighWaterMark()` returns **bytes**, not words. The status command reports `stack_hwm` in bytes. An earlier calculation multiplied the value by four and overstated the remaining stack.
19. Espressif Systems, *ESP32 Arduino core*, `cores/esp32/main.cpp` and `Arduino.h`. `ARDUINO_LOOP_STACK_SIZE` defaults to 8192 bytes; `SET_LOOP_TASK_STACK_SIZE()` overrides it. The macro expands to a function definition, so it belongs in `loop_stack.cpp`, not in the sketch. See the note in that file.

## Automotive RKE background

20. Garcia, Oswald, Kasper, Pavlides, *Lock It and Still Lose It — On the (In)Security of Automotive Remote Keyless Entry Systems*, USENIX Security 2016. Describes the RollBack mechanism implemented by the C2 sequencer and the Hitag2 correlation attack.
21. Eisenbarth, Kasper, Moradi, Paar, Salmasizadeh, Manzuri Shalmani, *Physical Cryptanalysis of KeeLoq Code Hopping Applications*, IACR ePrint 2008/058; CRYPTO 2008, LNCS 5157, pp. 203–220. See item 7 above.
22. Bianchi, Brighente, Conti, Pavan, *SoK: Stealing Cars Since Remote Keyless Entry Introduction and How to Defend From It*, USENIX VehicleSec 2025. Surveys more than 35 attacks and 13 defenses.
23. *Attacking Automotive RKE Security: How Smart are your 'Smart' Keys?* IACR ePrint 2024/1816. Surveys RollJam and RollBack attacks on Honda, Toyota, Maruti-Suzuki, and Mahindra vehicles.
24. RfidResearchGroup, *proxmark3*, `tools/hitag2crack/`. `ht2crack4` and `ht2crack5` implement fast-correlation key recovery for Hitag2, and `tools/renault_hitag2_rke_crack.py` is a faithful port of `ht2crack4`. Informs the estimate of 4–8 captured pairs.
25. Benadjila, Renard, Lopes-Esteves, Kasper, *One Car, Two Frames: Attacks on Hitag-2 Remote Keyless Entry Systems Revisited*, USENIX WOOT 2017. Proves the equivalent-key property that lets the Renault counter-high half be zeroed, so a key equivalent under the unknown high counter bits reproduces the genuine keystream. `tools/renault_hitag2_rke_crack.py` relies on it rather than guessing `CNTRH`, and it is why the attack runs against the five-frame corpus at all.
26. *Rolling-PWN* — CVE-2021-46145. Covers a rolling-code replay in which a previously seen code is accepted again after a forward jump. The resync curve's replay leg reproduces this against a receiver I own; the note is.
27. *RollBack* — CVE-2022-37418, and the RollBack mechanism in item 20. Covers acceptance of a code sent *backward* from the expected counter. The resync curve's backward step is this axis.
28. Indesteege, Keller, Biham, Dunkelman, Preneel, *A Practical Attack on KeeLoq*, EUROCRYPT 2008, LNCS 4965, pp. 1–18. The slide / meet-in-the-middle attack that needs 2^16 known plaintexts and recovers the key of a KeeLoq cipher. `tools/keeloq_slide_lab.py` reports its alignment condition and birthday cost but does not run it — an OEM fob cannot supply that many known plaintexts, so the note treats it as documented rather than executed. The same tool's practical half is the constrained clone-batch search, using the same hop-XOR identity RollBack validates sequences with.
29. Bogdanov, *Attacks on the KeeLoq Block Cipher and Authentication Systems*, and the CHES 2008 cryptanalysis line, as background for the KeeLoq round structure. Not used numerically; the round description in `tools/keeloq_slide_lab.py` follows the Microchip normal-learn scheme in items 2 and 3.
30. **X-Stuff / CudaKeeloq** (`X-Stuff/CudaKeeloq` on GitHub). Its `alphabet` and `pattern` search modes constrain a brute force to keys built from a small byte alphabet or a repeating pattern, which is the clone-vendor key habit item 20's supply-chain note describes. `tools/keeloq_slide_lab.py` reproduces those constrained spaces CPU-side at clone-batch scale; nothing is taken from the GPU code itself.

