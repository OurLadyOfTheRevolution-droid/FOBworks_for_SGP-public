#!/usr/bin/env python3
"""Static checks for the FOBworks for SGP control surface."""

from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
FIRMWARE = HERE / "FOBworks_for_SGP.ino"
EMBEDDED_UI = HERE / "html_page.h"

firmware = FIRMWARE.read_text(encoding="utf-8")
embedded_ui = EMBEDDED_UI.read_text(encoding="utf-8")
released_default = bytes.fromhex("7367706861636b6572")

checked_files = [FIRMWARE, EMBEDDED_UI]

for path in checked_files:
    if path.is_file():
        assert released_default not in path.read_bytes(), f"released credential remains in {path}"

# Every concrete API handler must use the shared gate. Unknown API paths must
# also authenticate instead of falling through to the captive-portal redirect.
assert not re.search(r'srv\.on\("/api/', firmware), "unprotected API route registration"
protected_routes = re.findall(r'protectedRoute\("(/api/[^"]+)"', firmware)
# 51 at v3.66. +3 for the C2 RollBack routes (rollback_arm/fire/status).
# +5 for the C1 RollJam routes (rolljam_arm/start/abort/status/replay).
# Count-based assertions break every time a route is added, which is noise rather than a
# check. What matters is that the count is plausible and that the auth wrapper is still used
# for every route, so assert a floor plus the real invariant below.
assert len(protected_routes) >= 59, f"expected at least 59 protected API routes, found {len(protected_routes)}"
assert "/api/library" in protected_routes
assert len(protected_routes) == len(set(protected_routes)), "duplicate protected API route"
for dangerous in (
    "/api/jam_start",
    "/api/replay",
    "/api/replay_predicted",
    "/api/sub_replay",
    "/api/add_user_key",
    "/api/del_user_key",
    "/api/clear_user_keys",
    "/api/rollback_arm",
    "/api/rollback_fire",
    "/api/rolljam_arm",
    "/api/rolljam_start",
    "/api/rolljam_replay",
):
    assert dangerous in protected_routes, f"dangerous route is not protected: {dangerous}"
assert 'srv.uri().startsWith("/api/")' in firmware
assert "if(!requireRequestAuth()) return;" in firmware

# BLE IRKs are authentication-related identity material. The bonded-device
# endpoint may return non-secret metadata, but must never serialize its IRK.
paired_devices_handler = re.search(
    r'protectedRoute\("/api/ble_paired_devices",\[\]\(\)\{(.*?)'
    r'\n  \}\);\n\n  // /api/can_init',
    firmware,
    re.DOTALL,
)
assert paired_devices_handler, "ble_paired_devices handler not found"
assert "bond_key.pid_key.irk" not in paired_devices_handler.group(1)
assert '\\"irk\\"' not in paired_devices_handler.group(1)
assert 'j+="}";}' in paired_devices_handler.group(1)

# AP credentials and the API token are hardware-random, NVS-backed, and never
# replaced with another compile-time password.
assert "esp_random()" in firmware
assert 'authPrefs.begin("dev-auth",false)' in firmware
assert 'authPrefs.putString("ap-pass",apPassword)' in firmware
assert 'authPrefs.putString("api-token",apiToken)' in firmware
soft_ap_calls = re.findall(r"WiFi\.softAP\(([^;]+)\);", firmware)
assert len(soft_ap_calls) == 2
assert all("deviceApPassword.c_str()" in call for call in soft_ap_calls)

# The embedded UI keeps the access code only for the browser session and adds a
# bearer header centrally to every existing /api/* fetch.
assert "sessionStorage.setItem('fobworks_access_code',code)" in embedded_ui
assert "headers.set('Authorization','Bearer '+_deviceAccessCode)" in embedded_ui
assert "localStorage.setItem('fobworks_access_code'" not in embedded_ui

# USB serial commands use the same per-device bearer secret and fail closed
# before the first command branch. The secret comparison must not short-circuit.
assert "static bool serialTokenMatches(const JsonDocument& command)" in firmware
assert 'command["token"].is<const char*>()' in firmware
assert "constantTimeDeviceTokenMatches" in firmware
assert "diff|=" in firmware
# The gate and the dispatch chain live in processCommandLine(), which BOTH transports call
# (USB serial via handleSerial(), WiFi WebSocket via wsPump() -> processCommandLine()).
# Asserting it there covers the WiFi path too, which the old handleSerial-scoped check did not.
assert "static void processCommandLine(const String& ln)" in firmware, \
    "shared command dispatcher is missing — one transport would bypass the token gate"
dispatcher = firmware[firmware.index("static void processCommandLine(const String& ln){"):]
serial_gate = dispatcher.index("if(!serialTokenMatches(jcmd))")
first_command = dispatcher.index('if(op=="status")')
assert serial_gate < first_command, "serial authorization must precede command dispatch"
# Both transports must reach the same gated dispatcher.
assert "processCommandLine(ln);" in firmware, "handleSerial no longer dispatches"
assert "processCommandLine(line);" in firmware, "wsPump does not dispatch through the gate"
assert 'serialEmit("{\\"ok\\":false,\\"error\\":\\"unauthorized\\"}")' in firmware
replay_wait_start = firmware.index("int replaySeqWait(unsigned long waitMs)")
replay_wait_end = firmware.index("// Helper: build a frame", replay_wait_start)
replay_wait = firmware[replay_wait_start:replay_wait_end]
replay_gate = replay_wait.index("if(!serialTokenMatches(jj))")
assert replay_gate < replay_wait.index('if(rop=="replay_stop")')
assert replay_gate < replay_wait.index('if(rop=="replay_next")')

# CAN pin parsing is strict and only the board-approved TX=17/RX=16 pair can
# reach the TWAI driver. Validation must happen before stopping an active driver.
can_handler_start = firmware.index('protectedRoute("/api/can_init"')
can_handler_end = firmware.index('// /api/can_start', can_handler_start)
can_handler = firmware[can_handler_start:can_handler_end]
assert "#define CAN_SAFE_TX_PIN 17U" in firmware
assert "#define CAN_SAFE_RX_PIN 16U" in firmware
assert "parseStrictUint32" in can_handler
assert '.toInt()' not in can_handler
assert "requestedTx!=CAN_SAFE_TX_PIN||requestedRx!=CAN_SAFE_RX_PIN" in can_handler
assert can_handler.index("unsafe_can_pins") < can_handler.index("twai_stop()")
assert can_handler.index("unsupported_baud") < can_handler.index("twai_stop()")
assert "already_initialized" in can_handler

print(f"control-surface auth checks passed ({len(protected_routes)} protected routes)")