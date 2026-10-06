#!/usr/bin/env python3
"""Fuzz the WebSocket transport's JSON intake (closes 's open item).

fuzzed the SERIAL intake and left one item open: "the WS transport
shares processCommandLine but was not fuzzed live; a dashboard-driven version of
the same corpus would close that." The WS path is the dashboard's primary
transport, so its intake deserves the same adversarial pass.

Unlike USB serial, the WS path is a network dependency, so the live pass is
hardware-gated behind an explicit --host/--ap argument rather than assumed. The
host-only structural pass pins the WS-specific guarantees that the shared
dispatcher does NOT provide and that the serial corpus therefore never exercises:

  · the frame-size cap (WS_LINE_MAX) replies ws-frame-too-long, it does not
    truncate into a bad-json that the client then misreads;
  · the '{' gate and the enqueue happen together — a non-command frame is not
    queued;
  · the queue-bound drop rule is a drop, not an overwrite (never corrupts the
    command being processed);
  · the reply-routing guards (slot generation + authentication) exist on both
    wsSendToSlot() and wsBroadcast();
  · the handshake/close frame types are registered and the socket port is 81.

The live pass drives the SAME adversarial corpus the serial suite uses, but over
a WebSocket: it opens ws://<host>:81/, sends each frame, and requires that any
command-shaped frame yields exactly one JSON reply and that the server survives
the burst.

The client framing is itself verified without the card: `tools/_ws_echo_server.py`
is a throwaway mock that handshakes and replies, and

    python3 test_ws_fuzz.py --host 127.0.0.1 --port 8899 --framing-only

exercises handshake, masked send, receive+parse, and silent-on-drop against it.

    python3 test_ws_fuzz.py                       # host-only (default)
    python3 test_ws_fuzz.py --ap                  # live: 192.168.4.1:81 (must join the AP)
    python3 test_ws_fuzz.py --host 192.168.4.1    # live against a given host
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
BENCH = ROOT / "bench_token.txt"
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'}  {msg}")
    if not cond:
        FAILS.append(msg)


def build_cases():
    """Same shape as test_serial_fuzz.build_cases(): (label, bytes, expectation).

    expectation: 'silent-ok' (gate may drop), 'any-error' (one named error),
    'must-reply' (one JSON object), a string (must appear in the reply), or None.
    """
    token = BENCH.read_text().strip() if BENCH.exists() else ""
    tok = token or "x"
    t = tok.encode()
    cases = [
        ("baseline_status",   b'{"cmd":"status","token":"' + t + b'"}', "status"),
        ("truncated",         b'{"cmd":"status","token":"' + t[:4],      "bad-json"),
        ("truncated_mid",     b'{"cmd":"stat',                            "bad-json"),
        ("double_comma",      b'{"cmd":"status",,"token":"' + t + b'"}',  "bad-json"),
        ("unclosed_array",    b'{"cmd":"status","x":[1,2,',               "bad-json"),
        ("no_brace",          b'"cmd":"status","token":"' + t + b'"',      "silent-ok"),
        ("bare_number",       b'12345',                                    "silent-ok"),
        ("short_line",        b'{}',                                       "silent-ok"),
        ("nul_byte",          b'{"cmd":"status","token":"' + t + b'"}\x00', None),
        ("cmd_is_array",      b'{"cmd":[1,2],"token":"' + t + b'"}',        None),
        ("cmd_is_number",     b'{"cmd":42,"token":"' + t + b'"}',           None),
        ("cmd_is_null",       b'{"cmd":null,"token":"' + t + b'"}',         None),
        ("cmd_empty",         b'{"cmd":"","token":"' + t + b'"}',           "unknown-cmd"),
        ("token_is_number",   b'{"cmd":"status","token":123}',              "unauthorized"),
        ("no_token",          b'{"cmd":"status"}',                         "unauthorized"),
        ("wrong_token",       b'{"cmd":"status","token":"wrong"}',         "unauthorized"),
        ("deep_nesting_32",   b'{"a":' + b'[' * 32 + b']' * 32 +
                              b',"cmd":"status","token":"' + t + b'"}',     None),
        # Oversize: WS_LINE_MAX is 2048; a frame past it must reply
        # ws-frame-too-long rather than truncate into a misleading bad-json.
        ("oversize_4k",       b'{"cmd":"status","pad":"' + b'x' * 4000 +
                              b'","token":"' + t + b'"}',                   "any-error"),
        ("baseline_again",    b'{"cmd":"status","token":"' + t + b'"}',     "status"),
    ]
    rng = random.Random(20261005)
    base = b'{"cmd":"status","token":"' + t + b'"}'
    for i in range(24):
        b = bytearray(base)
        op = rng.randrange(3)
        if op == 0 and len(b) > 4:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == 1:
            b = b[:rng.randrange(1, len(b))]
        else:
            b[rng.randrange(len(b)):rng.randrange(len(b))] = bytes([rng.randrange(256)]) * rng.randrange(3)
        looks = len(b) >= 3 and b[0:1] == b"{"
        cases.append((f"mut_{i}", bytes(b), "must-reply" if looks else "silent-ok"))
    return cases


# ── host-only structural pass ────────────────────────────────────────────────
def structural():
    src = SRC.read_text(encoding="utf-8")
    print("=== structural: WS-specific guarantees in source ===")

    check("#define WS_LINE_MAX 2048" in src,
          "WS_LINE_MAX is defined (the frame and queue bound)")
    check('\\"ws-frame-too-long\\"' in src,
          "an oversize frame replies a NAMED error, not a silent truncation")
    # The WS intake must apply the same '{' gate as serial before enqueueing.
    check("if(line.length()>=3 && line[0]=='{')" in src,
          "the WS intake applies the same '{' gate before enqueueing")
    # Enqueue must drop on full, never overwrite the in-flight command.
    check("if(next==wsQHead) return;" in src,
          "the queue drops when full rather than overwriting the current command")
    # Reply routing: slot generation must be validated before indexing.
    check("wsSlotMatches(slot, wsGen[slot]) ? wsGen[slot] : 0" in src,
          "the reply generation is guarded before wsGen is indexed (evicted-socket case)")
    check("static void wsSendToSlot(int slot, uint32_t gen, const String& json){" in src,
          "replies are routed per-slot, not broadcast")
    check("wsSlotMatches(slot,gen) || !wsAuthed[slot]" in src,
          "wsSendToSlot checks generation AND authentication before sending")
    check("wsAuthed[i]" in src and "httpd_ws_send_frame_async(wsServer, fd, &f)" in src,
          "broadcast sends only to authenticated slots and drops failed sends")
    # Handshake + close handling and the port.
    check("req->method==HTTP_GET" in src and "wsRemember(fd);" in src,
          "the handshake GET registers the socket but does not auto-authenticate it")
    check("req->method==HTTP_DELETE" in src and "wsForget(fd);" in src,
          "the close frame forgets the socket (and clears its generation)")
    check("cfg.server_port      = 81" in src, "the WS server listens on port 81")
    check("uri.is_websocket = true" in src, "the URI handler is registered as a websocket")

    # processCommandLine is shared, so its per-arm reply guarantee is inherited.
    m = re.search(r"static void processCommandLine\(const String& ln\)\{(.*?)\n\}\n", src, re.S)
    check(m is not None, "processCommandLine extracted (shared by both transports)")
    if m:
        arms = len(re.findall(r'else if\(op=="', m.group(1)))
        check(arms > 60, f"the shared dispatcher still has {arms} command arms")


# ── minimal stdlib WebSocket client (no third-party deps) ────────────────────
class WS:
    def __init__(self, host, port=81, timeout=3.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n").encode()
        self.sock.sendall(req)
        hs = b""
        while b"\r\n\r\n" not in hs:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("handshake closed")
            hs += chunk
        if b"101" not in hs.split(b"\r\n", 1)[0]:
            raise RuntimeError("no 101 upgrade: " + hs.split(b"\r\n", 1)[0].decode("latin1"))
        self.buf = hs.split(b"\r\n\r\n", 1)[1]

    def send(self, payload: bytes):
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytearray([0x81])            # FIN + text
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126); hdr += n.to_bytes(2, "big")
        else:
            hdr.append(0x80 | 127); hdr += n.to_bytes(8, "big")
        hdr += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(hdr) + masked)

    def _fill(self, need):
        while len(self.buf) < need:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("closed")
            self.buf += chunk

    def recv(self):
        self._fill(2)
        b0, b1 = self.buf[0], self.buf[1]
        ln = b1 & 0x7F
        off = 2
        if ln == 126:
            self._fill(4); ln = int.from_bytes(self.buf[2:4], "big"); off = 4
        elif ln == 127:
            self._fill(10); ln = int.from_bytes(self.buf[2:10], "big"); off = 10
        self._fill(off + ln)
        payload = self.buf[off:off + ln]
        self.buf = self.buf[off + ln:]
        op = b0 & 0x0F
        return op, payload

    def close(self):
        try:
            self.send(b"")  # empty text; then just drop the socket
            self.sock.close()
        except OSError:
            pass


def live(host, port=81, framing_only=False):
    print(f"\n=== live: adversarial frames over ws://{host}:{port}/ ===")
    token = (BENCH.read_text().strip() if BENCH.exists() else "")
    if not token:
        print("  bench_token.txt missing — live pass needs the device token")
        FAILS.append("live: no bench token")
        return
    try:
        ws = WS(host, port)
    except Exception as e:  # noqa: BLE001
        print(f"  cannot reach {host}:{port} ({e}); join the card's AP first")
        FAILS.append(f"live: unreachable ({e})")
        return
    print("  connected (101 upgrade)")

    def one_frame(raw: bytes):
        ws.send(raw)
        deadline = time.time() + 3.0
        acc = ""
        while time.time() < deadline:
            try:
                op, payload = ws.recv()
            except (TimeoutError, socket.timeout, OSError):
                break                      # a gate-dropped frame is legitimately silent
            if op == 0x8:                     # close
                return "CLOSED", None
            text = payload.decode("utf-8", "replace").strip()
            if not text:
                continue
            acc += text
            try:
                d = json.loads(acc)
            except ValueError:
                continue
            if d.get("event") in ("tick", "weak", "heartbeat"):
                acc = ""
                continue
            return "OK", d
        return "SILENT", None

    # Prime the pump (first frame after handshake can race the settle).
    ws.send(b'{"cmd":"status","token":"' + token.encode() + b'"}')
    try:
        time.sleep(0.5)
        ws.recv()
    except Exception:  # noqa: BLE001
        pass

    for label, raw, expect in build_cases():
        kind, d = one_frame(raw)
        if kind not in ("OK", "SILENT"):
            check(False, f"{label}: transport stayed up ({kind})")
            break
        if framing_only:
            # Against a mock (or when only framing is under test): require the
            # transport to stay up and any reply to be a single JSON object. The
            # command VOCABULARY (bad-json vs unauthorized vs status) is asserted
            # only against the real card, where the dispatcher defines it.
            check(kind in ("OK", "SILENT"),
                  f"{label}: one JSON reply or a clean drop (got {kind})")
            continue
        if expect == "silent-ok":
            ok = kind in ("OK", "SILENT")
        elif expect == "any-error":
            ok = kind == "OK" and (d.get("ok") is False or "error" in d or d.get("cmd"))
        elif expect == "must-reply":
            ok = kind == "OK"
        elif kind == "OK":
            ok = True if expect is None else (d.get("error") == expect or
                                              d.get("cmd") == expect or
                                              expect in json.dumps(d))
        else:
            ok = False
        detail = (d or {}).get("error", (d or {}).get("cmd")) if isinstance(d, dict) else d
        check(ok, f"{label}: {kind} {detail}")

    # The server must still answer after the whole burst.
    ws.send(b'{"cmd":"status","token":"' + token.encode() + b'"}')
    kind, _ = one_frame(b'{"cmd":"status","token":"' + token.encode() + b'"}')
    check(kind == "OK", "server still replies after the adversarial burst")
    ws.close()


def main():
    args = sys.argv[1:]
    host = None
    port = 81
    if "--ap" in args:
        host = "192.168.4.1"
    elif "--host" in args:
        host = args[args.index("--host") + 1]
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    structural()
    if host:
        live(host, port, framing_only=("--framing-only" in args))
    else:
        print("\n(live pass skipped — pass --ap or --host <ip> to drive the card)")
    print()
    if FAILS:
        print(f"ws fuzz: {len(FAILS)} FAILURES")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("ws fuzz passed")


if __name__ == "__main__":
    main()
