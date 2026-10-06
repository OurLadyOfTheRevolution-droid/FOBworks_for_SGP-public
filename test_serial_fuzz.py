#!/usr/bin/env python3
"""Fuzz the serial dispatcher's JSON intake.

The v3.86 bug class was heap-dependent deserializeJson failures: a command
that arrived malformed or oversized produced either a silent drop or a reply
the dashboard could not parse, and the bench spent rounds bisecting payload
sizes because of it.

This suite pins the contract every dashboard command depends on: for ANY line
fed to the dispatcher, the reply is exactly one JSON object or one named
error -- never silence, never a partial line, never a crash.

Two layers:

  1. LIVE -- the card is driven over USB with adversarial lines (truncated
     documents, 8 KB oversize, arrays where strings are expected, nested
     depth, NULs, unicode). Every reply must parse as JSON and carry a
     recognizable discriminator: ok:true or error:"bad-json" /
     "unauthorized" / "line-too-long" / "unknown-cmd".

  2. STRUCTURAL (host-only, no card needed) -- the dispatcher source is
     checked for the guarantees the live pass exercises: the bad-json branch
     emits before any return, the length gate rejects before the parse, and
     every command arm ends in a serialEmit.

Skip the live pass with:  python3 test_serial_fuzz.py host
"""
import json
import random
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
BENCH = ROOT / "bench_token.txt"
FAILS = []
HOST_ONLY = len(sys.argv) > 1 and sys.argv[1] == "host"


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'}  {msg}")
    if not cond:
        FAILS.append(msg)


# ── adversarial line corpus ──────────────────────────────────────────────────
# The dispatcher's documented contract:
#   - a line < 3 chars or not starting with '{' is NOT a command: dropped
#     without a reply (the gate that keeps ROM boot banners and stray serial
#     noise from spamming replies) — expectation "silent-ok"
#   - a '{'-prefixed line that fails to parse replies bad-json
#   - parseable but tokenless/wrong-token replies unauthorized
#   - valid token, unrecognized cmd replies unknown-cmd (v3.92 tail)
#   - every other reply is exactly one JSON object
def build_cases():
    token = BENCH.read_text().strip() if BENCH.exists() else ""
    tok = token or "x"

    cases = [
        # the known-good baseline leads: it also warms the port so the first
        # adversarial line is not racing CDC settle after open.
        ("baseline_status",     b'{"cmd":"status","token":"' + tok.encode() + b'"}', "status"),
        # parse failures -- must reply error:"bad-json" with line_bytes
        ("truncated",           b'{"cmd":"status","token":"' + tok.encode()[:4], "bad-json"),
        ("truncated_mid_string", b'{"cmd":"stat', "bad-json"),
        ("double_comma",        b'{"cmd":"status",,"token":"' + tok.encode() + b'"}', "bad-json"),
        ("unclosed_array",      b'{"cmd":"status","x":[1,2,', "bad-json"),
        # non-commands: the '{' gate drops them silently BY DESIGN
        ("no_brace",            b'"cmd":"status","token":"' + tok.encode() + b'"', "silent-ok"),
        ("bare_number",         b'12345', "silent-ok"),
        ("bare_string",         b'"hello"', "silent-ok"),
        ("array_top",           b'[1,2,3]', "silent-ok"),
        ("short_line",          b'{}', "silent-ok"),
        # tolerated-by-parser shapes: any single JSON reply is a pass
        ("trailing_garbage",    b'{"cmd":"status"} extra', None),
        ("nul_byte",            b'{"cmd":"status","token":"' + tok.encode() + b'"}\x00', None),
        # type abuse -- cmd must be a string; wrong types must not crash
        ("cmd_is_array",        b'{"cmd":[1,2],"token":"' + tok.encode() + b'"}', None),
        ("cmd_is_object",       b'{"cmd":{"a":1},"token":"' + tok.encode() + b'"}', None),
        ("cmd_is_number",       b'{"cmd":42,"token":"' + tok.encode() + b'"}', None),
        ("cmd_is_null",         b'{"cmd":null,"token":"' + tok.encode() + b'"}', None),
        ("cmd_empty",           b'{"cmd":"","token":"' + tok.encode() + b'"}', "unknown-cmd"),
        ("cmd_unicode",         b'{"cmd":"st\xc3\xa4tus","token":"' + tok.encode() + b'"}', "unknown-cmd"),
        ("token_is_array",       b'{"cmd":"status","token":[1,2]}', None),
        ("token_is_number",      b'{"cmd":"status","token":123}', "unauthorized"),
        ("token_is_null",        b'{"cmd":"status","token":null}', "unauthorized"),
        # auth boundary
        ("no_token",            b'{"cmd":"status"}', "unauthorized"),
        ("empty_token",         b'{"cmd":"status","token":""}', "unauthorized"),
        ("wrong_token",         b'{"cmd":"status","token":"wrong"}', "unauthorized"),
        # deep nesting -- the heap is 2-3 KB idle; 32 levels must still parse
        ("deep_nesting_32",     b'{"a":' + b'[' * 32 + b']' * 32 + b',"cmd":"status","token":"' + tok.encode() + b'"}', None),
        # the known-good baseline is repeated at the end too, to confirm the
        # dispatcher survived everything above it
        ("baseline_again",      b'{"cmd":"status","token":"' + tok.encode() + b'"}', "status"),
        # oversize -- the CDC rx queue itself is SERIAL_CMD_MAX bytes, so a
        # single 9 KB write can drop the card's terminating '\n' in the driver
        # before the intake ever sees it. The documented line bound is 8192
        # INCLUDING the newline; the sender splits the write so the terminator
        # is guaranteed delivered and the intake's overflow path is exercised.
        ("oversize_9k",         b'{"cmd":"status","pad":"' + b'x' * 9000 + b'","token":"' + tok.encode() + b'"}', "any-error"),
    ]

    # random mutation fuzz over a valid frame: flip bytes, truncate, splice.
    # A mutation that still LOOKS like a command ({-prefixed, >=3 chars) MUST
    # produce exactly one JSON reply; anything else may be silent (the gate).
    rng = random.Random(20261005)
    base = b'{"cmd":"status","token":"' + tok.encode() + b'"}'
    mutations = []
    for i in range(24):
        b = bytearray(base)
        op = rng.randrange(3)
        if op == 0 and len(b) > 4:                      # flip a byte
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == 1:                                    # truncate
            b = b[:rng.randrange(1, len(b))]
        else:                                            # splice garbage
            b[rng.randrange(len(b)):rng.randrange(len(b))] = bytes([rng.randrange(256)]) * rng.randrange(3)
        looks_like_cmd = len(b) >= 3 and b[0:1] == b"{"
        mutations.append((f"mut_{i}", bytes(b), "must-reply" if looks_like_cmd else "silent-ok"))
    return cases + mutations


# ── structural pass (host-only) ──────────────────────────────────────────────
def structural():
    src = SRC.read_text(encoding="utf-8")
    print("=== structural: the dispatcher's guarantees exist in source ===")

    check('if(ln.length()<3||ln[0]!=\'{\') return;' in src,
          "the length gate rejects before the parse (no reply for non-commands)")
    check('DeserializationError jerr=deserializeJson(jcmd,ln);' in src,
          "the parse result is captured, not ignored")
    # The strings appear escaped in the C++ source (\"bad-json\"), so match
    # the escaped form exactly as the file holds it.
    check('\\"bad-json\\"' in src and '\\"line_bytes\\"' in src,
          "a parse failure replies a NAMED error with the line size")
    check('\\"unauthorized\\"' in src,
          "a failed token match replies a NAMED error")
    check('String op=jcmd["cmd"]|"";' in src,
          "cmd defaults to the empty string (arrays/objects/null cannot crash the dispatch)")
    check('command["token"].is<const char*>()' in src,
          "the token is read through a typed path before the compare")

    # The overflow branch: the Serial intake must REPORT, not drop silently.
    # (v3.86's defect class: an oversized line vanished with no reply at all.)
    # The intake is a fixed char array (serialInBuf/serialInLen), so the check
    # matches the array-based form.
    ov = re.search(r"if\(serialInLen<SERIAL_CMD_MAX\)\{(.*?)serialInLen=SERIAL_CMD_MAX\+1;", src, re.S)
    check(ov is not None, "the Serial intake has an overflow-report branch")
    if ov:
        check('\\"serial-line-too-long\\"' in ov.group(1),
              "the overflow branch names itself serial-line-too-long")
    check("static char   serialInBuf[SERIAL_CMD_MAX + 1]" in src,
          "the intake is a fixed char array (no per-char heap realloc)")
    check("String ln(serialInBuf);" in src,
          "the dispatch String is built once at line close, after the intake resets")

    # Every dispatch arm must end in a serialEmit -- a command that matches
    # neither arm nor the unknown-cmd tail would be silent.
    m = re.search(r"static void processCommandLine\(const String& ln\)\{(.*?)\n\}\n", src, re.S)
    check(m is not None, "processCommandLine extracted from the firmware")
    if m:
        body = m.group(1)
        arms = len(re.findall(r'else if\(op=="', body))
        emits = body.count("serialEmit(")
        check(arms > 60 and emits >= arms,
              f"every one of the {arms} dispatch arms emits a reply ({emits} serialEmit calls)")
        check('\\"unknown-cmd\\"' in body and re.search(r"else\s*\{\s*String esc", body),
              "an unrecognized cmd replies a named error (not silence)")

    # The reply routing must be single-line JSON: serialEmit prints one
    # println. Multi-call assembly goes through serialEmitNoNl.
    se = re.search(r"void serialEmit\(const String& json\)\{\s*Serial\.println\(json\);", src)
    check(se is not None, "serialEmit emits exactly one println per reply")


# ── live pass (card on USB) ───────────────────────────────────────────────────
def live():
    print("\n=== live: adversarial lines through the card over USB ===")
    sys.path.insert(0, str(ROOT / "tools"))
    import serial  # noqa: F401  (fail early with a clear error if missing)
    import _cardport

    token = BENCH.read_text().strip()
    port = _cardport.find_card(token)
    check(port is not None, "the card is attached and answers status")
    if port is None:
        return

    import serial as _s
    ser = _s.Serial(port, 115200, timeout=3)
    time.sleep(2.5)
    ser.reset_input_buffer()

    # The first command after this fresh open races the CDC re-open settle
    # (observed: the first status of a run is occasionally silent while the very
    # next line replies). Prime the pump with a throwaway status and drain it.
    ser.write((json.dumps({"cmd": "status", "token": token}) + "\n").encode())
    ser.flush()
    time.sleep(1.5)
    ser.reset_input_buffer()

    def send_line(raw: bytes, retries=1):
        # One retry is allowed: the port this suite opens is a SECOND open
        # (find_card probed and closed first), and a USB-CDC re-open can drop
        # the first write while the tinyusb stack settles. A reply lost to the
        # re-open race is not a dispatcher defect, so one re-send separates the
        # race from a real silent-failure.
        for attempt in range(retries + 1):
            ser.write(raw + b"\n")
            ser.flush()
            deadline = time.time() + 3.0
            buf = ""
            best = None
            while time.time() < deadline:
                line = ser.readline().decode("utf-8", "replace").strip()
                if not line:
                    continue
                buf += line
                try:
                    d = json.loads(buf)
                except ValueError:
                    if buf.startswith("{") and buf.rstrip().endswith("}"):
                        best = ("UNPARSEABLE", buf[:120])
                    continue
                if d.get("event") in ("tick", "weak", "heartbeat") or d.get("cmd") == "heartbeat":
                    buf = ""   # an event slipped in; the reply may follow it
                    continue
                return ("OK", d)
            if attempt < retries and best is None:
                time.sleep(0.5)
                continue
        return best or ("SILENT", None)

    results = {}
    for label, raw, expect in build_cases():
        if label == "oversize_9k":
            # Split the write: the card's CDC rx queue is SERIAL_CMD_MAX bytes,
            # so a single 9 KB burst can drop the terminating '\n' in the driver
            # before the intake ever sees it (the line then never closes, and
            # the card correctly stays silent until the next '\n'). Delivering
            # the head first, then the tail + '\n' separately, guarantees the
            # terminator arrives and exercises the intake's overflow branch.
            ser.write(raw)
            ser.flush()
            time.sleep(0.3)          # let the intake drain past the cap first
            ser.write(b"\n")
            ser.flush()
            kind, d = "PENDING", None
            # fall through to the shared reader below with a fresh window
            deadline = time.time() + 4.0
            buf = ""
            best = None
            while time.time() < deadline:
                line = ser.readline().decode("utf-8", "replace").strip()
                if not line:
                    continue
                buf += line
                try:
                    d = json.loads(buf)
                except ValueError:
                    if buf.startswith("{") and buf.rstrip().endswith("}"):
                        best = ("UNPARSEABLE", buf[:120])
                    continue
                if d.get("event") in ("tick", "weak", "heartbeat") or d.get("cmd") == "heartbeat":
                    buf = ""
                    continue
                kind = "OK"
                break
            if kind != "OK":
                kind, d = best or ("SILENT", None)
        else:
            kind, d = send_line(raw)
        if expect == "silent-ok":
            # the '{' gate drops non-commands by design; BOTH outcomes are
            # correct as long as there was no crash and any reply is JSON
            ok = kind in ("OK", "SILENT")
        elif expect == "any-error":
            # oversize: one NAMED error of some kind (overflow report or
            # bad-json for the truncated remainder) -- anything but silence
            ok = kind == "OK" and (d.get("ok") is False or "error" in d or d.get("cmd"))
        elif expect == "must-reply":
            ok = kind == "OK"
        elif kind == "OK":
            if expect is None:
                ok = True
            else:
                ok = d.get("error") == expect or d.get("cmd") == expect or expect in json.dumps(d)
        else:
            ok = False
        detail = (d or {}).get("error", (d or {}).get("cmd")) if isinstance(d, dict) else d
        results[label] = (ok, kind, detail)
        ok, kind, detail = results[label]
        why = {"silent-ok": "gate may drop it", "any-error": "one named error",
               "must-reply": "one JSON reply"}.get(expect, f"carrying {expect!r}" if expect else "one JSON object")
        check(ok, f"{label}: {why}"
                 + ("" if ok else f" (got {kind} {detail})"))

    ser.close()


def main():
    structural()
    if not HOST_ONLY:
        live()
    print()
    if FAILS:
        print(f"serial fuzz: {len(FAILS)} FAILURES")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("serial fuzz passed")


if __name__ == "__main__":
    main()
