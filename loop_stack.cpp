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
// Live captures use the same decodeSignal() path. The board's unwired GDO0 had hidden
// the problem: RSSI captures did not produce decodable frames. The earlier "silent import"
// was this crash and reboot, not a dropped line.
//
// Use 12 KB, not the earlier 32 KB guess. The loop stack comes from the heap; the
// larger setting left too little room for an 822-byte JSON document and caused
// "bad-json / NoMemory" during import.
//
// These hardware readings are from different stack sizes:
//
//   before decode: 29,860 B free of 32,768 B (~2,908 B used)
//   after decode:   7,664 B free of 12,288 B (4,624 B used)
//
// The first reading predates decode and understates peak use by about 1,716 B; use
// the second when sizing this path.
//
// The 12 KB setting leaves 7,664 B after the deepest measured decode and returns
// 20,480 B to the heap compared with the old 32 KB setting. Recheck both margins if
// the decode path grows.
#include <Arduino.h>
SET_LOOP_TASK_STACK_SIZE(12 * 1024);
