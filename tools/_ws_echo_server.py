#!/usr/bin/env python3
"""Ephemeral WebSocket echo server to self-test test_ws_fuzz.py's live client.

This is a throwaway verification aid, not part of the shipped toolset. It
handshakes, replies to any command-shaped TEXT frame with one JSON object, and
replies to an oversize frame with a named error, so the client's send/receive
framing is exercised without the card. Delete after use.

    python3 tools/_ws_echo_server.py 8899 &
    python3 test_ws_fuzz.py --host 127.0.0.1 --port 8899
"""
import base64
import hashlib
import socket
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _frame(payload):
    out = bytearray([0x81])
    n = len(payload)
    if n < 126:
        out.append(n)
    elif n < 65536:
        out.append(126); out += n.to_bytes(2, "big")
    else:
        out.append(127); out += n.to_bytes(8, "big")
    return bytes(out) + payload


def handle(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        c = conn.recv(4096)
        if not c:
            return
        data += c
    head, rest = data.split(b"\r\n\r\n", 1)
    key = ""
    for line in head.decode("latin1").split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").encode())
    buf = rest

    def fill(n):
        nonlocal buf
        while len(buf) < n:
            c = conn.recv(4096)
            if not c:
                raise RuntimeError("closed")
            buf += c

    try:
        while True:
            fill(2)
            b0, b1 = buf[0], buf[1]
            ln = b1 & 0x7F
            off = 2
            if ln == 126:
                fill(4); ln = int.from_bytes(buf[2:4], "big"); off = 4
            elif ln == 127:
                fill(10); ln = int.from_bytes(buf[2:10], "big"); off = 10
            masked = b1 & 0x80
            fill(off + (4 if masked else 0) + ln)
            mkey = buf[off:off + 4] if masked else b"\x00\x00\x00\x00"
            start = off + (4 if masked else 0)
            payload = bytes(b ^ mkey[i % 4] for i, b in enumerate(buf[start:start + ln]))
            buf = buf[start + ln:]
            if (b0 & 0x0F) == 0x8:
                conn.close()
                return
            text = payload.decode("utf-8", "replace")
            if len(payload) > 2048:
                reply = b'{"ok":false,"error":"ws-frame-too-long","max_bytes":2047}'
            elif len(text) < 3 or text[0] != "{":
                continue
            else:
                # Mimic the dispatcher's named-error vocabulary so the client's
                # expectation matching is exercised without the card.
                try:
                    import json as _j
                    d = _j.loads(text)
                except ValueError:
                    reply = b'{"ok":false,"error":"bad-json"}'
                else:
                    tok = d.get("token")
                    if not isinstance(tok, str) or not tok:
                        reply = b'{"ok":false,"error":"unauthorized"}'
                    elif not d.get("cmd"):
                        reply = b'{"cmd":"","error":"unknown-cmd"}'
                    else:
                        reply = b'{"cmd":"status","ok":true}'
            conn.sendall(_frame(reply))
    except (RuntimeError, OSError):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    print(f"ws echo on 127.0.0.1:{port}", flush=True)
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
