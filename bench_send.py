#!/usr/bin/env python3
"""Send one JSON command to the card over USB serial and print what comes back.

The card's serial handler takes the same command set as the HTTP API, authed with
the per-device dashboard access code printed at boot:

    {"cmd":"...", "token":"<access code>", ...}

Because the console is USB-only (see [SECURITY] Per-device credentials), the token
is already visible to anyone with the cable; this helper reads it from
bench_token.txt (gitignored) rather than embedding it, so it never lands in a commit.

    python3 bench_send.py setfreq --f 315.000
    python3 bench_send.py fbk_arm
    python3 bench_send.py rollback_status
    python3 bench_send.py status --listen 3

Anything after the command name becomes a JSON field; values are coerced to
int/float/bool where they look like one.
"""

import argparse
import json
import os
import select
import sys
import termios
import time
from pathlib import Path

PORT = "/dev/cu.usbmodem101"
TOKEN_FILE = Path(__file__).resolve().parent / "bench_token.txt"

# Routine telemetry that would otherwise drown the response we asked for. These are
# event names, so the filter can compare exactly rather than substring-matching a whole
# line (which let a heartbeat fragment through and hid the real reply).
NOISE_EVENTS = frozenset({"tick", "weak", "heartbeat", "sweep"})


def token():
    tok = os.environ.get("FOBWORKS_TOKEN", "").strip()
    if tok:
        return tok
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    sys.exit(f"no token: set FOBWORKS_TOKEN or write {TOKEN_FILE.name}")


def coerce(v):
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    for cast in (int, float):
        try:
            return cast(v)
        except ValueError:
            pass
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd")
    ap.add_argument("fields", nargs="*", help="key=value pairs")
    ap.add_argument("--listen", type=float, default=2.0,
                    help="seconds to keep reading after sending (default 2)")
    ap.add_argument("--port", default=PORT)
    # parse_intermixed_args, not parse_args: callers put the optional flags after the
    # key=value positionals ("setfreq f=315 --listen 3"), which plain parse_args
    # rejects once the star-positional has started consuming.
    args = ap.parse_intermixed_args()

    payload = {"cmd": args.cmd, "token": token()}
    for f in args.fields:
        if "=" not in f:
            sys.exit(f"field must be key=value: {f}")
        k, v = f.split("=", 1)
        payload[k] = coerce(v)

    fd = os.open(args.port, os.O_RDWR | os.O_NOCTTY)
    a = termios.tcgetattr(fd)
    a[1] = 0
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[3] = 0
    a[4] = a[5] = termios.B115200
    a[6][termios.VMIN] = 0
    a[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    termios.tcflush(fd, termios.TCIOFLUSH)

    line = json.dumps(payload) + "\n"
    # Echo the command with the token masked, so pasted output is safe.
    shown = json.dumps({**payload, "token": "***"})
    print(f">>> {shown}")
    os.write(fd, line.encode())

    buf = b""
    t0 = time.monotonic()
    replies = []
    while time.monotonic() - t0 < args.listen:
        r, _, _ = select.select([fd], [], [], 0.3)
        if not r:
            continue
        try:
            buf += os.read(fd, 8192)
        except OSError:
            print("[port dropped]")
            break
        # The card terminates lines with CR, not LF. Normalise both, or many JSON
        # objects merge into one string and the noise filter swallows the real reply.
        buf = buf.replace(b"\r", b"\n")
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            s = raw.decode("utf-8", "replace").strip()
            if not s:
                continue
            # Show the reply to our own command, plus any event that is not routine
            # scan telemetry. tick/heartbeat/weak/sweep arrive continuously and would
            # bury the answer.
            keep = False
            try:
                obj = json.loads(s)
                if obj.get("cmd") == args.cmd:
                    keep = True
                elif "event" in obj and obj["event"] not in NOISE_EVENTS:
                    keep = True
            except json.JSONDecodeError:
                keep = False
            if not keep:
                continue
            replies.append(s)
            print(f"<<< {s}")
    os.close(fd)

    if not replies:
        print(f"(no reply in {args.listen}s — is the card booted and idle?)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
