#!/usr/bin/env python3
"""Bench harness for C1 RollJam / C2 RollBack against real hardware.

C1 has been through five rounds of review and two behavioural suites and has never
driven a radio (worklog §3 P3). This logs the card's serial JSON verbatim with
timestamps and calls out the events that matter for a bench pass — arm, phase
changes, jam on/off, each capture, and every transmit — so there is evidence the
sequence actually ran, independent of what the dashboard appeared to show.

The card's serial stream is unauthenticated (ticks, heartbeat, events), so this is
passive: drive the sequence from the dashboard, and watch here.

    python3 bench_serial_log.py                     # log the running device
    python3 bench_serial_log.py --out bench_c1.log
    python3 bench_serial_log.py --port /dev/cu.usbmodem101

Press the card's reset button first if you want a clean boot log. Ctrl-C to stop;
a summary of the events that mattered is printed on exit.
"""

import argparse
import os
import select
import sys
import termios
import time
from datetime import datetime

BAUD = getattr(termios, "B115200")

# Substrings that mark a line as benchmark-relevant. Matched lowercase.
WATCH = (
    "rolljam", "rollback", "jam", "tx", "aborted", "armed",
    "capture", "replay", "selftest", "untrimmed",
)


def open_port(path):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
    attrs = termios.tcgetattr(fd)
    # 8N1, no flow control, raw: the card emits one JSON object per line.
    attrs[0] = attrs[0] & ~termios.IGNBRK
    attrs[1] = 0                                   # no input flags (no IXON/ICRNL)
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0                                   # no output post-processing
    attrs[4] = attrs[5] = BAUD
    attrs[6][termios.VMIN] = 0
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/cu.usbmodem101")
    ap.add_argument("--out", default=None, help="also write every line to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="only print the watched lines, not the tick/heartbeat stream")
    args = ap.parse_args()

    if not os.path.exists(args.port):
        print(f"no such port: {args.port}", file=sys.stderr)
        return 2

    fd = open_port(args.port)
    out = open(args.out, "w", encoding="utf-8") if args.out else None
    if out:
        print(f"logging to {args.out}")

    t0 = time.monotonic()
    buf = b""
    hits = []          # (rel_seconds, line) for watched lines
    nlines = 0
    port_dropped = False

    print(f"listening on {args.port} @ 115200. Ctrl-C to stop.\n")
    try:
        while True:
            r, _, _ = select.select([fd], [], [], 0.5)
            if not r:
                continue
            try:
                chunk = os.read(fd, 8192)
            except OSError:
                # A reflash or reset drops the CDC endpoint; report it rather than
                # dying silently, so a lost run is not mistaken for a quiet one.
                port_dropped = True
                print("\n[port dropped — reflashed or reset? stopping]", file=sys.stderr)
                break
            if not chunk:
                continue
            # The card terminates lines with CR, not LF; without this every object
            # merges into one line and the watchdog substrings stop matching.
            buf += chunk.replace(b"\r", b"\n")
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                nlines += 1
                rel = time.monotonic() - t0
                stamp = f"[{rel:8.3f}s]"
                low = line.lower()
                hit = any(w in low for w in WATCH)
                if hit:
                    hits.append((rel, line))
                    print(f"{stamp} >>> {line}")
                elif not args.quiet:
                    print(f"{stamp} {line}")
                sys.stdout.flush()
                if out:
                    out.write(f"{datetime.now().isoformat()} {rel:9.3f} "
                              f"{'EVENT' if hit else '     '} {line}\n")
                    out.flush()
    except KeyboardInterrupt:
        print("\n[stopped by user]")
    finally:
        os.close(fd)
        if out:
            out.close()

    print(f"\n=== summary: {nlines} lines, {len(hits)} watched events ===")
    if not hits:
        print("No arm/capture/jam/tx events were seen. If the dashboard said it ran,")
        print("that is itself the finding: the sequence never reached serial.")
    for rel, line in hits:
        print(f"  {rel:8.3f}s  {line}")
    if port_dropped:
        print("\nNOTE: the port dropped mid-run — the log ends where the device reset.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
