# Citations and references

These are the documents FOBworks for SGP v3.75 is written against. The firmware is standalone, for the May 2026 SGP Card Mini. The names below are the notes and datasheets the sketch's KeeLoq paths, radio init, board, and WebSocket transport actually use.

## KeeLoq

The source labels three derivation paths with note numbers that do not match a published Microchip KeeLoq document. The table below is the published note for each label, so the comment in the sketch can be followed to the right PDF.

**Status (v3.71):** the comments the v3.71 KeeLoq work touched now cite the real notes directly. The three wrong labels below still appear in dated changelog entries and in comments not yet revisited; that cleanup is item F3 in the worklog. This table stays until F3 is finished.

The manufacturer key table is the real 73-entry corpus, from the public list at `github.com/HiennNek/non-flipper-rolling-code-support` (`keeloq_mfcodes_user`). That file is not shipped here: it holds the same keys the firmware already carries, so publishing it would add nothing. Each entry carries its learning type (see `enum KLLearn` in the sketch), which decides which derivation the key uses.

| Label in this sketch | What the code uses it for | Published document |
| --- | --- | --- |
| DS50033B | Manufacturer-code programming and the reference keys in the table | Microchip DS50033B, *Programming KEELOQ Devices with the PRO MATE II Device Programmer* |
| AN1064 | Normal-learn and decrypt paths, and the encrypt routine | There is no KeeLoq note with this number. Microchip AN1064 is *IR Remote Control Transmitter*, a PIC10F206 note for Philips RC5 and Sony SIRC. The KeeLoq normal-learn scheme this firmware follows is TB003 and AN742, below. |
| AN1031 | Secure-learn path, flag nibble 0x40 | There is no Microchip KeeLoq note AN1031. The secure-learn decoder note is AN662. |
| AN1130B | Discrimination-bit check when a candidate key is scored | There is no Microchip KeeLoq note AN1130B. The PIC16C56 decoder note with that bit layout is AN661. |

1. Microchip Technology, DS50033B, *Programming KEELOQ Devices with the PRO MATE II Device Programmer*. Manufacturer code, encoder programming, and the factory key concepts behind the reference entries in the key table.
2. Microchip Technology, TB003, DS91002, *An Introduction to KeeLoq Code Hopping*. Normal learn from the serial number, and secure learn from the seed. This is the published description of the normal-learn and secure-learn paths.
3. Microchip Technology, AN742, DS00742, *Modular PICmicro Mid-Range MCU Code Hopping Decoder*. Normal-learn key generation. It points back to TB003 for the scheme and to TB001, DS91000, *Secure Learning RKE Systems using KEELOQ Encoders*, for the seed-based scheme.
4. Microchip Technology, AN661, DS00661C, *KEELOQ Code Hopping Decoder Using a PIC16C56*. Discrimination bits after decrypt. The sketch comment calls this check AN1130B.
5. Microchip Technology, AN662, DS00662, *KEELOQ Code Hopping Decoder Using Secure Learn*. The sketch comment calls this path AN1031.
6. Microchip Technology, *HCS300* and *HCS301 KEELOQ Code Hopping Encoder* datasheets. The 66-bit frame the parser reads: 32-bit hopping code, button and status bits, serial discriminator, and sync counter. The header also names the HCS360, HCS361, HCS512, and HCS515 encoders as part of the same family.
7. Thomas Eisenbarth, Timo Kasper, Amir Moradi, Christof Paar, Mahmoud Salmasizadeh, and Mohammad T. Manzuri Shalmani, “Physical Cryptanalysis of KeeLoq Code Hopping Applications,” IACR ePrint 2008/058. The published venue is CRYPTO 2008, under the title “On the Power of Power Analysis in the Real World: A Complete Break of the KeeLoq Code Hopping Scheme,” LNCS 5157, pp. 203–220. The key-table comment names this ePrint.

## Radio and the May 2026 card

8. Texas Instruments, *CC1101 Low-Power Sub-1 GHz RF Transceiver*, SWRS061. `cc_reset` follows the power-on reset in section 10.1. The same datasheet is the register map for the async OOK and 2FSK setup, and for the packet-mode TX path in §24 (PATABLE) and §15 (MARCSTATE, TX FIFO). Three things in it were found the hard way and are worth naming here: OOK requires both PATABLE levels programmed — logic 0 and logic 1 at index 0 and 1 — or a logic 1 transmits at zero power while the FIFO still drains; reaching index 1 needs a **burst** write, because the index counter only advances within a burst; and TX is MARCSTATE 19/20, not 17, which is RXFIFO_OVERFLOW.
9. Semtech, *SX1276/77/78/79 Datasheet*. The May 2026 module is a Ra-02, an SX1278. Reset is held low for at least 100 µs, then the chip needs at least 5 ms before SPI. Sleep is RegOpMode written to 0x00. On this board the SX1278's DIO0 shares GPIO 48 with what the older pinout documents called the CC1101's GDO0; measurement and the vendor firmware both show the CC1101's GDO0 is not connected at all, and neither SPI sleep nor hardware reset releases the SX1278's hold on the line.
10. Espressif Systems, *ESP32-S3-MINI-1 & ESP32-S3-MINI-1U Datasheet*. The N8 order code is 8 MB quad flash and no PSRAM. Dual-core LX7, Wi-Fi 802.11 b/g/n, BLE 5. Flash settings in the sketch header match that module.
11. Analog Devices, *MAX17048/MAX17049 Data Sheet*. VCELL is register 0x02 and state of charge is register 0x04. The gauge on this card answers at I2C address 0x36.

## WebSocket transport (v3.73)

12. Espressif Systems, *ESP HTTP Server*, `esp_http_server.h`. The port-81 transport uses `httpd_start`, `httpd_register_uri_handler` with `is_websocket`, `httpd_ws_recv_frame`, and `httpd_ws_send_frame_async`. Built on this rather than the Arduino `WebServer`, which cannot upgrade a connection. Requires `CONFIG_HTTPD_WS_SUPPORT`, which is enabled in the ESP32 core 3.3.12 SDK for this target.
13. Espressif Systems, *ESP-IDF FreeRTOS*, `portmacro.h`. `portSTACK_TYPE` is `uint8_t` on this port, so `uxTaskGetStackHighWaterMark()` returns **bytes**, not words. The status command's `stack_hwm` field is in bytes. An earlier reading multiplied by four and reported more free stack than the task had, which is what exposed it.
14. Espressif Systems, *ESP32 Arduino core*, `cores/esp32/main.cpp` and `Arduino.h`. `ARDUINO_LOOP_STACK_SIZE` defaults to 8192 bytes, and `SET_LOOP_TASK_STACK_SIZE()` is the documented override. It expands to a function *definition*, which is why it lives in `loop_stack.cpp` rather than the sketch — see the note in that file.

## Automotive RKE background

15. Garcia, Oswald, Kasper, Pavlides, *Lock It and Still Lose It — On the (In)Security of Automotive Remote Keyless Entry Systems*, USENIX Security 2016. The RollBack mechanism the C2 sequencer implements, and the Hitag2 correlation attack.
16. Eisenbarth, Kasper, Moradi, Paar, Salmasizadeh, Manzuri Shalmani, *Physical Cryptanalysis of KeeLoq Code Hopping Applications*, IACR ePrint 2008/058; CRYPTO 2008, LNCS 5157, pp. 203–220. See item 7 above.
17. Bianchi, Brighente, Conti, Pavan, *SoK: Stealing Cars Since Remote Keyless Entry Introduction and How to Defend From It*, USENIX VehicleSec 2025. Systematises 35+ attacks and 13 defences.
18. *Attacking Automotive RKE Security: How Smart are your 'Smart' Keys?* IACR ePrint 2024/1816. The RollJam and RollBack surveys over Honda, Toyota, Maruti-Suzuki and Mahindra.
19. RfidResearchGroup, *proxmark3*, `tools/hitag2crack/`. `ht2crack4` and `ht2crack5` implement the Hitag2 fast-correlation key recovery, and are the reference for the 4–8 captured pairs figure.

