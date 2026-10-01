#!/usr/bin/env python3
"""Measure the ambient floor at a band before trusting any capture result.

Why this exists: a capture that does not trigger emits no diagnostics, and reading the previous
capture's decode object makes it look as though one fired. In research/52 and 53 that produced two
contradictory readings of the same setup, and one of them was wrong. Measuring the baseline first
removes the ambiguity: if ambient captures nothing, any subsequent capture is signal.

Three trials, no transmitter. Reports the floor, whether the trigger fired, and the stage counts.

Drains are bounded by elapsed time. The card streams ticks and heartbeats continuously, so a loop
that waits for select() to go idle never exits; that fault held the port in research/46 and 52.

Usage:
    python3 tools/ambient_baseline.py 315.0
    python3 tools/ambient_baseline.py 433.92 --trials 5
"""

import argparse
import fcntl
import json
import os
import re
import select
import struct
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = "/dev/cu.usbmodem1101"


def token():
    f = ROOT / "bench_token.txt"
    if f.is_file():
        return f.read_text(encoding="utf-8").strip()
    raise SystemExit("no token: write bench_token.txt or set it in the environment")


def openraw(path):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0
    a[1] = 0
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[3] = 0
    a[4] = termios.B115200
    a[5] = termios.B115200
    termios.tcsetattr(fd, termios.TCSANOW, a)
    return fd


def drain(fd, seconds):
    """Time-bounded. Never idle-bounded: this card never goes quiet."""
    buf = b""
    t0 = time.time()
    while time.time() - t0 < seconds:
        r, _, _ = select.select([fd], [], [], 0.2)
        if not r:
            continue
        try:
            x = os.read(fd, 4096)
        except OSError:
            break
        if x:
            buf += x
    return buf


def parse(txt):
    """Absent fields mean no capture fired. They must not be filled in from a previous one."""
    out = {"floor": None, "trigger": None, "diag": None, "edges": None, "fail": None}
    for ln in txt.splitlines():
        s = ln.strip()
        m = re.search(r"Floor: (-?\d+) dBm  Trig: (-?\d+)", s)
        if m:
            out["floor"] = int(m.group(1))
            out["trigger"] = int(m.group(2))
        m = re.search(r"\[DIAG\] raw=(\d+) after75=(\d+) afterToy=(\d+)", s)
        if m:
            out["diag"] = tuple(int(g) for g in m.groups())
        m = re.search(r"✓ (\d+) edges", s)
        if m:
            out["edges"] = int(m.group(1))
        if "No signal" in s:
            out["fail"] = "no-signal"
        m = re.search(r"Too few edges \((\d+)\)", s)
        if m:
            out["fail"] = f"too-few({m.group(1)})"
        if "Incoherent" in s:
            out["fail"] = "incoherent"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mhz", type=float)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--seconds", type=int, default=8)
    ap.add_argument("--port", default=PORT)
    args = ap.parse_args()

    tok = token()
    fd = openraw(args.port)
    try:
        fcntl.ioctl(fd, termios.TIOCMBIC, struct.pack("I", termios.TIOCM_RTS))
        time.sleep(0.3)
        drain(fd, 1.0)

        os.write(fd, (json.dumps({"cmd": "status", "token": tok}) + "\n").encode())
        st = drain(fd, 3).decode("utf-8", "replace")
        if re.search(r'"scan":true', st):
            os.write(fd, (json.dumps({"cmd": "scan_toggle", "token": tok}) + "\n").encode())
            drain(fd, 2)
            print("scan parked")
        os.write(fd, (json.dumps({"cmd": "setfreq", "f": args.mhz, "token": tok}) + "\n").encode())
        drain(fd, 1.5)
        os.write(fd, (json.dumps({"cmd": "cap_diag", "on": True, "token": tok}) + "\n").encode())
        drain(fd, 1.5)

        print(f"\nambient baseline at {args.mhz} MHz, nothing transmitting, "
              f"{args.trials} trials\n")
        fired = 0
        for i in range(1, args.trials + 1):
            # discard anything queued, so a stale decode cannot be read as this trial's
            drain(fd, 1.0)
            os.write(fd, (json.dumps({"cmd": "capture", "t": args.seconds * 1000,
                                      "token": tok}) + "\n").encode())
            txt = drain(fd, args.seconds + 5).decode("utf-8", "replace")
            r = parse(txt)
            if r["diag"] or r["edges"]:
                fired += 1
            print(f"  trial {i}: floor={r['floor']} trig={r['trigger']} "
                  f"diag={r['diag']} edges={r['edges']} fail={r['fail']}")

        print(f"\n  captures fired with nothing transmitting: {fired} of {args.trials}")
        if fired == 0:
            print("  -> ambient is quiet here; any later capture at this band is signal")
        else:
            print("  -> ambient is NOT quiet; compare against this before trusting a capture")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
