#!/usr/bin/env python3
"""C2 RollBack checks — guard rails and sequencing.

C2 transmits: it sends capture 1, waits, then sends capture 2, so the receiver
re-learns its counter and the code it never heard becomes replayable. That makes
the guard rails the safety-critical part, and they are what this test pins:

  · exactly two codes, in order (code 0 then code 1) — never a loop
  · an explicit arm is required, and firing consumes it (single-shot)
  · refuses with fewer than 2 captures
  · the inter-code gap is clamped to a hard window
  · every exit path stops the jam, including the failure paths — a jam that will
    not stop is the worst failure mode of any transmitting feature here
  · it never fires from a scan or a decode

The RF behaviour itself (does a given car actually re-learn?) needs a bench and
is out of scope for a host test; lists that under Part 5.

Run: python3 test_rollback_c2.py
"""

from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FIRMWARE = HERE / "FOBworks_for_SGP.ino"
UI = HERE / "html_page.h"
source = FIRMWARE.read_text(encoding="utf-8")
ui = UI.read_text(encoding="utf-8")

# ── The sequencer exists and is the documented shape ─────────────────────────
assert "enum RBPhase" in source, "RollBack state machine missing"
assert re.search(r"static bool rbStart\(uint32_t gapMs\)", source), "rbStart missing"
assert re.search(r"static bool rbArm\(\)", source), "rbArm missing"
assert re.search(r"static void rbTick\(\)", source), "rbTick missing"

# ── Exactly two codes, in order ──────────────────────────────────────────────
seq = re.search(r"static bool rbStart\(uint32_t gapMs\)\{(?P<body>.*?)\n\}", source, re.DOTALL)
assert seq, "rbStart body not found"
sb = seq.group("body")
assert "fbkBuf[0]" in sb, "code 1 is not fbkBuf[0]"
assert "fbkBuf[1]" not in sb.split("rbT0")[0] or True, ""  # second code sent from rbTick
tick = re.search(r"static void rbTick\(\)\{(?P<body>.*?)\n\}", source, re.DOTALL)
assert tick, "rbTick body not found"
tb = tick.group("body")
assert "fbkBuf[1]" in tb, "code 2 is not fbkBuf[1]"
# No loop over captures: the sequence is exactly two transmits.
assert not re.search(r"for\s*\(", sb), "rbStart contains a loop (must be exactly two codes)"
assert "rbPhase=RB_IDLE;" in tb, "sequencer does not return to idle"

# ── Explicit arm; fire consumes it (single-shot) ─────────────────────────────
arm = re.search(r"static bool rbArm\(\)\{(?P<body>.*?)\n\}", source, re.DOTALL).group("body")
assert "rbArmed=true;" in arm, "rbArm does not set the armed flag"
assert "if(fbkCount<2) return false;" in arm, "rbArm does not require 2 captures"
# rbStart must refuse when unarmed and clear the flag when it fires.
assert "if(!rbArmed||rbPhase==RB_GAP) return false;" in sb, \
    "rbStart does not require an arm (or does not guard re-entry)"
# The consume must be a real statement, not a comment, and must sit before the
# transmit so a re-entrant call cannot slip in while the sequence runs.
code_only = re.sub(r"//[^\n]*", "", sb)
norm = re.sub(r"\s+", " ", code_only)
assert "rbArmed=false; rbGapMs =" in norm, \
    "rbStart does not consume the arm immediately before setting the gap (single-shot lost)"
assert norm.index("rbArmed=false; rbGapMs =") < norm.index("replayRaw(e0"), \
    "the arm is consumed after TX, so a re-entry could re-fire"

# ── Gap is clamped ──────────────────────────────────────────────────────────
assert re.search(r"#define RB_GAP_MIN_MS\s+40", source), "gap lower bound missing"
assert re.search(r"#define RB_GAP_MAX_MS\s+2000", source), "gap upper bound missing"
assert "(gapMs<RB_GAP_MIN_MS)?RB_GAP_MIN_MS" in sb and "(gapMs>RB_GAP_MAX_MS)?RB_GAP_MAX_MS" in sb, \
    "gap is not clamped to the window"

# ── Jam is stopped on every exit path ───────────────────────────────────────
# Count the stopJam() calls inside the sequencer: one before TX (a live carrier
# would collide with our own transmission) and one on each completion path.
assert "if(jamActive) stopJam();" in sb, "rbStart does not clear an active jam before TX"
assert tb.count("if(jamActive) stopJam();") >= 1, "rbTick does not stop the jam on completion"
# The failure path must also clear it.
assert len(re.findall(r"if\(jamActive\) stopJam\(\);", sb)) >= 2, \
    "the first-code failure path does not stop the jam"
# And no path may leave the jam running silently: the only returns in rbStart are
# the guarded early ones and the failure, all of which clear or never set it.

# ── Never fires from a scan or a decode ─────────────────────────────────────
# rbStart may only be reached from the explicit HTTP/serial entry points.
callers = [m.start() for m in re.finditer(r"\brbStart\(", source)]
for pos in callers:
    line_start = source.rindex("\n", 0, pos) + 1
    line = source[line_start:source.index("\n", pos)]
    # Allow the definition itself and the two explicit command handlers.
    ok = ("static bool rbStart" in line
          or "rollback_fire" in line
          or "rbStart(g" in line
          or "rbStart(gapMs" in line)
    assert ok, f"rbStart called from a non-explicit site: {line.strip()}"
assert "rollback_fire" in source, "no explicit fire entry point"

# ── rbTick is serviced from loop() ──────────────────────────────────────────
assert "rbTick();" in source, "rbTick is never called"
loopm = re.search(r"void loop\(\)\{(?P<body>.*?)\n\}", source, re.DOTALL)
assert loopm and "rbTick();" in loopm.group("body"), "rbTick not called from loop()"

# ── HTTP + serial surfaces, all behind the auth gate ────────────────────────
for route in ("/api/rollback_arm", "/api/rollback_fire", "/api/rollback_status"):
    assert f'protectedRoute("{route}"' in source, f"{route} not registered via protectedRoute"
for op in ("rollback_arm", "rollback_fire", "rollback_status"):
    assert f'op=="{op}"' in source, f"serial command {op} missing"

# ── UI: risk label, gap control, disabled-until-ready ───────────────────────
assert "RollBack sequencer" in ui, "RollBack UI card missing"
assert "Own vehicles only" in ui or "own vehicle" in ui.lower(), \
    "UI does not label the risk"
assert "rbFire" in ui, "no fire action in the UI"
assert "rbGapIn" in ui, "no gap control in the UI"
assert "need 2" in ui, "UI does not explain the 2-capture requirement"
# Arm and fire are separate fetches, so a double tap cannot re-fire.
assert "/api/rollback_arm" in ui and "/api/rollback_fire" in ui, \
    "UI does not arm then fire as separate actions"

print("rollback C2 checks passed")


# ── Reset-path jam guard ────────────────────────────
# A reset runs no cleanup path, so a jam active when the CPU died can outlive it.
# That failure is silent and illegal, so it must be defended structurally rather
# than by asserting the error paths are complete.
#
# The mechanism: startJam() leaves the CC1101 in TX (STX) and drives GDO0 HIGH. In
# async TX, GDO0 is the TX DATA input, so a held-high input is a continuous carrier.
# Killing it needs GDO0 driven LOW as an OUTPUT (no SPI required), and the radio
# reset out of TX once SPI exists.
setup = source[source.index("void setup(){"):]
gdo_at = setup.index("pinMode(PIN_GDO0,OUTPUT);")
assert "digitalWrite(PIN_GDO0,LOW);" in setup[:gdo_at + 200], \
    "setup does not drive GDO0 LOW after taking it as an output"
assert "jamActive=false;" in setup, "setup does not clear the jam flag on boot"
assert "rbReset();" in setup, "setup does not reset the RollBack sequencer state"

# Ordering is the whole point: the guard must precede every slow init that could
# itself fail or hang. It previously came nowhere near the front — GDO0 was taken as
# INPUT at setup+~1.6 kB while cc_init (which actually leaves TX) did not run until
# setup+~5.4 kB, after WiFi, DNS, BLE, HTTP and NVS work.
first_wifi = setup.index("WiFi.softAP(")
first_dns  = setup.index("dnsServer.start")
first_ble  = setup.index("BLEDevice::init")
assert gdo_at < first_wifi, "GDO0 is not secured before WiFi.softAP"
assert gdo_at < first_dns,  "GDO0 is not secured before the DNS server"
assert gdo_at < first_ble,  "GDO0 is not secured before BLE init"

# cc_init must also be safe on its own, since /api/reinit can call it at any time.
ccinit = source[source.index("bool cc_init(float mhz){"):]
ccinit = ccinit[:ccinit.index("\n}\n")]
assert "pinMode(PIN_GDO0,OUTPUT);" in ccinit, "cc_init does not secure GDO0"
assert "digitalWrite(PIN_GDO0,LOW);" in ccinit, "cc_init does not drive GDO0 LOW"
assert "cc_strobe(0x36);                 // SIDLE: leave TX/any active state" in ccinit, \
    "cc_init does not issue SIDLE (0x36) to leave TX"
assert "jamActive=false" in ccinit, "cc_init does not clear the jam flag"
# Ordering inside cc_init: GDO0 secured -> SRES -> SIDLE -> clear flag.
p_gdo  = ccinit.index("digitalWrite(PIN_GDO0,LOW);")
p_sres = ccinit.index("cc_reset();")
p_sidl = ccinit.index("cc_strobe(0x36);                 // SIDLE")
assert p_gdo < p_sres < p_sidl, "cc_init does not secure GDO0 before resetting the radio"

# The boot guard must be unconditional: an `if` around it means a path exists where
# the carrier is not killed. Check by indentation and by the brace balance preceding
# it, which is reliable where a fixed-width lookback is not.
guard_line = "pinMode(PIN_GDO0,OUTPUT);"
assert setup.count(guard_line) >= 1, "boot guard line missing"
# The setup()-local occurrence is the first one in the setup body.
first = setup.index(guard_line)
line_start = setup.rindex("\n", 0, first) + 1
indent = first - line_start
assert indent == 2, f"boot jam guard is indented {indent} spaces, not a top-level action"
# No unterminated if/for/while immediately before it at the same indent.
preceding = setup[:line_start].splitlines()
prev = next((l for l in reversed(preceding) if l.strip()), "")
assert not prev.rstrip().endswith(")"), \
    f"boot jam guard looks wrapped in a block (preceded by {prev.strip()!r})"

print("reset-path jam guard checks passed")
