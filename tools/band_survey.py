#!/usr/bin/env python3
"""Survey the card's RSSI at several bands over time, with the sweep paused.

Why this exists
---------------
The bench sits across from a police station radio tower. A strong
nearby transmitter desensitises a receiver's front end, which raises the noise floor AND
compresses the range between noise and signal. That is a plausible read of everything
measured at 315: a floor 40 dB above normal, with the noise peak landing 1 dB from the
signal.

A *constant* raised floor and an *intermittent* one mean different things -- one points
at front-end blocking, the other at discrete nearby transmitters -- and only a time series
separates them. A single average cannot.

Receive-only. Pauses the background sweep for the duration and restores it.

Usage:
    python3 tools/band_survey.py [seconds] [interval_s]
"""
import json
import sys
import time
from pathlib import Path

import serial

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _cardport import find_card  # noqa: E402

TOKEN = (Path(__file__).resolve().parent.parent / "bench_token.txt").read_text("utf-8").strip()
SECS = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0
IVAL = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
BANDS = [315.0, 433.92, 700.0, 868.3]
SAMPLE_MS = 250


def main():
    port = find_card(TOKEN)
    if not port:
        print("  no SGP card found on /dev/cu.usbmodem* -- is it plugged in?")
        sys.exit(1)
    print(f"  card on {port}")
    ser = serial.Serial(port, 115200, timeout=0.3)
    scan_was_on = True
    try:
        ser.reset_input_buffer()
        time.sleep(0.6)

        def send(cmd, **kw):
            ser.write((json.dumps({"cmd": cmd, "token": TOKEN, **kw}) + "\n").encode())
            ser.flush()

        def wait(cmd, t=8):
            end = time.time() + t
            while time.time() < end:
                l = ser.readline().decode("utf-8", "replace").strip()
                if '"cmd":"%s"' % cmd in l:
                    try:
                        return json.loads(l)
                    except ValueError:
                        pass
            return None

        st = wait("status", 6) if send("status") is None else None
        scan_was_on = bool(st and st.get("scan"))
        if scan_was_on:
            send("scan_toggle")
            time.sleep(0.8)

        print(f"  {SECS:.0f}s survey, {IVAL:.0f}s interval, {SAMPLE_MS}ms window per sample")
        print(f"  {'t':>5}  " + "  ".join(f"{b:>16.2f}" for b in BANDS))
        print(f"  {'':>5}  " + "  ".join(f"{'avg/min/max':>16}" for _ in BANDS))

        t0 = time.time()
        while time.time() - t0 < SECS:
            row = []
            for b in BANDS:
                send("rssi_scope", f=b, ms=SAMPLE_MS, thr=-200)
                o = wait("rssi_scope", 6)
                row.append(f"{o['avg']:>5}/{o['min']:>5}/{o['max']:>5}" if o else "  -- /  -- /  --")
                time.sleep(0.15)
            print(f"  {time.time()-t0:>4.0f}s  " + "  ".join(row), flush=True)
            time.sleep(IVAL)
    finally:
        if scan_was_on:
            send("scan_toggle")
            time.sleep(0.4)
            print("\n  scan restored")
        ser.close()


if __name__ == "__main__":
    main()
