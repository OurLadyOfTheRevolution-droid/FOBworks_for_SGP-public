# Citations and references

This list covers the sources used for FOBworks for SGP v3.76, which targets the May 2026 SGP Card Mini. It includes the KeeLoq references, radio and board datasheets, and documentation for the WebSocket transport.

## KeeLoq

Three note numbers in the source do not identify a published Microchip KeeLoq document. The table maps each source label to the document relevant to that code path.

As of v3.71, current KeeLoq comments cite the correct notes. Some dated changelog entries retain the old labels as a record of past releases; the table maps each label to the relevant publication.

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

## WebSocket transport (v3.73)

12. Espressif Systems, *ESP HTTP Server*, `esp_http_server.h`. The port-81 transport uses `httpd_start`, `httpd_register_uri_handler` with `is_websocket`, `httpd_ws_recv_frame`, and `httpd_ws_send_frame_async`. Arduino `WebServer` cannot upgrade a connection, so the firmware uses this server instead. It requires `CONFIG_HTTPD_WS_SUPPORT`, enabled in the ESP32 core 3.3.12 SDK for this target.
13. Espressif Systems, *ESP-IDF FreeRTOS*, `portmacro.h`. On this port, `portSTACK_TYPE` is `uint8_t`, so `uxTaskGetStackHighWaterMark()` returns **bytes**, not words. The status command reports `stack_hwm` in bytes. An earlier calculation multiplied the value by four and overstated the remaining stack.
14. Espressif Systems, *ESP32 Arduino core*, `cores/esp32/main.cpp` and `Arduino.h`. `ARDUINO_LOOP_STACK_SIZE` defaults to 8192 bytes; `SET_LOOP_TASK_STACK_SIZE()` overrides it. The macro expands to a function definition, so it belongs in `loop_stack.cpp`, not in the sketch. See the note in that file.

## Automotive RKE background

15. Garcia, Oswald, Kasper, Pavlides, *Lock It and Still Lose It — On the (In)Security of Automotive Remote Keyless Entry Systems*, USENIX Security 2016. Describes the RollBack mechanism implemented by the C2 sequencer and the Hitag2 correlation attack.
16. Eisenbarth, Kasper, Moradi, Paar, Salmasizadeh, Manzuri Shalmani, *Physical Cryptanalysis of KeeLoq Code Hopping Applications*, IACR ePrint 2008/058; CRYPTO 2008, LNCS 5157, pp. 203–220. See item 7 above.
17. Bianchi, Brighente, Conti, Pavan, *SoK: Stealing Cars Since Remote Keyless Entry Introduction and How to Defend From It*, USENIX VehicleSec 2025. Surveys more than 35 attacks and 13 defenses.
18. *Attacking Automotive RKE Security: How Smart are your 'Smart' Keys?* IACR ePrint 2024/1816. Surveys RollJam and RollBack attacks on Honda, Toyota, Maruti-Suzuki, and Mahindra vehicles.
19. RfidResearchGroup, *proxmark3*, `tools/hitag2crack/`. `ht2crack4` and `ht2crack5` implement fast-correlation key recovery for Hitag2 and inform the estimate of 4–8 captured pairs.

