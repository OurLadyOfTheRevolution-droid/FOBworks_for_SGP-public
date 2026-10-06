#!/usr/bin/env python3
"""Capture at a frequency and print the WHOLE stream, waiting for a fob press.

Why this exists: `bench_send.py` filters for lines containing `cmd`, and the capture
path's diagnostics (`Floor:`, `Signal!`, `[DIAG]`) go through `addLog`, so a successful
capture can look like silence. `53` §5 and `50` §3 both record that trap. This prints
everything and keys on nothing.

Also: the drain loop here is bounded by elapsed time, never by "until select() times out"
-- the card streams ticks continuously, so such a loop never exits. That fault held the
port in `46` and `52`.

Usage:
    python3 tools/cap_whole_stream.py 315.00 [seconds]

It enables cap_diag for the run and turns it off afterwards, and prints a prompt so the
fob is pressed inside the capture window.
"""
import json
import sys
import time
from pathlib import Path

import serial

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _cardport import find_card  # noqa: E402

TOKEN_FILE = Path(__file__).resolve().parent.parent / "bench_token.txt"
MHZ = float(sys.argv[1]) if len(sys.argv) > 1 else 315.00
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 20

TOKEN = TOKEN_FILE.read_text(encoding="utf-8").strip()


def send(ser, cmd, **kw):
    ser.write((json.dumps({"cmd": cmd, "token": TOKEN, **kw}) + "\n").encode())
    ser.flush()


def main():
    port = find_card(TOKEN)
    if not port:
        print("  no SGP card found on /dev/cu.usbmodem* -- is it plugged in?")
        sys.exit(1)
    print(f"  card on {port}")
    ser = serial.Serial(port, 115200, timeout=0.3)
    try:
        ser.reset_input_buffer()
        time.sleep(0.6)

        send(ser, "cap_diag", on=True)
        time.sleep(0.5)
        ser.reset_input_buffer()

        print(f"  capturing {MHZ} MHz for {SECS}s")
        print("  >>> PRESS THE FOB NOW, holding it against the antenna <<<\n", flush=True)
        send(ser, "capture", f=MHZ, t=SECS * 1000)

        end = time.time() + SECS + 8
        while time.time() < end:
            line = ser.readline().decode("utf-8", "replace").strip()
            if not line:
                continue
            if line.startswith('{"event":"tick"') or line.startswith('{"event":"heartbeat"}'):
                continue
            print(f"    {line[:190]}", flush=True)
            if '"cmd":"capture"' in line or '"edges":' in line:
                break

        time.sleep(0.5)
        send(ser, "cap_diag", on=False)
        time.sleep(0.2)
    finally:
        ser.close()


if __name__ == "__main__":
    main()
