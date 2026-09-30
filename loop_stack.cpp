// Keep the loop-task stack override in this separate translation unit.
//
// SET_LOOP_TASK_STACK_SIZE() expands to a function definition. Arduino's sketch
// preprocessor inserts generated prototypes before the sketch's includes, so placing
// the macro in the .ino put that definition before ArduinoJson, WebServer, and the
// project types it needs. A normal .cpp file avoids that ordering problem.
//
// The ESP32 core's 8192-byte default was not enough to decode a real frame. Importing
// a Kia V3 capture produced:
//
//   Guru Meditation Error: Core 1 panic'ed (Unhandled debug exception)
//   Debug exception reason: Stack canary watchpoint triggered (loopTask)
//
// The crash occurred during decode, not import:
//
//   loop() -> handleSerial() -> fbkImportFrame() -> decodeSignal()
//     -> ArduinoJson operator=<String> -> heap alloc
//
// Live captures use the same decodeSignal() path, so the fault was never import-specific.
// The board's unwired GDO0 had hidden it: RSSI captures did not produce decodable frames.
// The earlier "silent import" symptom was this crash and reboot, not a dropped line.
//
// 12 KB, MEASURED -- not 32 KB. An earlier version used 32 KB as "a common figure for
// decode-heavy sketches", which turned out to be actively harmful: the loop task stack is
// heap-allocated, so +24 KB of stack took 24 KB from the heap, and the heap then could not
// serve an 822-byte JSON document. The symptom was "bad-json / NoMemory" on the import --
// the stack override was CAUSING the failure it was meant to prevent.
//
// Measured on hardware, and the two readings must not be confused:
//
//   no-decode baseline : 29860 B free of a 32768-byte stack -> ~2908 B used
//                        (taken BEFORE the import could reach the decoder, so it excludes it)
//   after a decode     :  7664 B free of the 12288-byte stack -> 4624 B used
//                        (research/31: stack_hwm == stack_hwm_after_decode == 7664)
//
// The decode adds ~1716 B beyond the no-decode baseline. So the baseline must NOT be used to
// size the decode path -- an earlier version of this comment did exactly that
// (12288 - 2908 = "~9.4 KB"), overstating the real margin by 1716 B while the correct measured
// figure was already in hand. It is kept above as information, not as a basis.
//
// 12 KB therefore gives 12288 - 4624 = 7664 B free after the deepest decode, while returning
// 20,480 B to the heap against the 32 KB override. If stack_hwm_after_decode later shows the
// margin is thin, raise this against the measured heap cost rather than guessing again.
#include <Arduino.h>
SET_LOOP_TASK_STACK_SIZE(12 * 1024);
