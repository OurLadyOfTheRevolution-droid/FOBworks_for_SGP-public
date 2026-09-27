// Loop task stack size for this sketch.
//
// Why this exists as a separate translation unit: SET_LOOP_TASK_STACK_SIZE() expands to a
// FUNCTION DEFINITION, and the Arduino sketch preprocessor hoists generated prototypes above
// the sketch's #includes. Placing it in the .ino made the definition appear before
// ArduinoJson / WebServer / the project's own types were declared, which failed to compile.
// A plain .cpp in the sketch folder is compiled normally and has no such ordering problem.
//
// Why not the 8192-byte default: the Arduino core gives loopTask 8192 bytes by default
// (cores/esp32/main.cpp: ARDUINO_LOOP_STACK_SIZE). That is not enough for the decode chain
// on a real frame. Measured on the bench -- importing a real Kia V3 frame produced
//
//   Guru Meditation Error: Core 1 panic'ed (Unhandled debug exception)
//   Debug exception reason: Stack canary watchpoint triggered (loopTask)
//
// with the decoded backtrace in the decoder, not the import:
//
//   loop() -> handleSerial() -> fbkImportFrame() -> decodeSignal()
//     -> ArduinoJson operator=<String> -> heap alloc
//
// So it is not import-specific: decodeSignal() is the same function a LIVE capture calls, so
// any capture that decoded would have hit it too. The absent GDO0 has been masking it,
// because RSSI captures never produced a decodable frame. It also explains the earlier
// "silent import" symptom -- that was this crash and reboot, not a dropped line.
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
//                        (worklog: stack_hwm == stack_hwm_after_decode == 7664)
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
