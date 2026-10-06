#!/usr/bin/env python3
"""One-shot receive-only spectrum dump, compared against the desk baseline.

Purpose: test whether the elevated 300-464 MHz floor is
the location or the card. Run this at the desk, run it in the closet, and compare.
The separation column is the number that matters.

No transmission. Sweep paused for the run and restored after.

Usage:
    python3 tools/spectrum_compare.py            # compare against the desk baseline
    python3 tools/spectrum_compare.py --save     # print only, no comparison
"""
import glob
import json
import sys
import time
from pathlib import Path

import serial

TOKEN = (Path(__file__).resolve().parent.parent / "bench_token.txt").read_text("utf-8").strip()


def find_card():
    """Locate the SGP card without hardcoding a port name.

    The card re-enumerates when it is unplugged and moved, and the Flippers also appear
    as /dev/cu.usbmodem* -- so a hardcoded path fails for the wrong reason after exactly
    the experiment this tool exists to support. Probe each candidate with a status command
    and use the first that answers like the card.
    """
    for p in sorted(glob.glob("/dev/cu.usbmodem*")):
        if "flip" in p.lower():
            continue
        try:
            with serial.Serial(p, 115200, timeout=0.4) as s:
                s.reset_input_buffer()
                time.sleep(0.3)
                s.write((json.dumps({"cmd": "status", "token": TOKEN}) + "\n").encode())
                s.flush()
                end = time.time() + 2.5
                while time.time() < end:
                    line = s.readline().decode("utf-8", "replace").strip()
                    if '"cmd":"status"' in line and "cc1101" in line:
                        return p
        except (OSError, serial.SerialException):
            continue
    return None

# Desk baseline, measured at the bench and §1.
# band 1 (300-348) and band 2 (387-464) are elevated against band 3 (779-928).
BASELINE = {
    300.0: -73, 310.0: -77, 315.0: -72, 320.0: -66, 330.0: -79, 345.0: -73,
    360.0: -61, 390.0: -80, 420.0: -83, 433.92: -77, 450.0: -81, 500.0: -80,
    868.3: -94, 900.0: -97, 915.0: -96, 928.0: -97,
}
LOW = [300.0, 310.0, 315.0, 320.0, 330.0, 345.0, 360.0, 390.0, 420.0, 433.92, 450.0]
HIGH = [868.3, 900.0, 915.0, 928.0]


def main():
    compare = "--save" not in sys.argv
    port = find_card()
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

        def wait(cmd, t=7):
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

        got = {}
        for f in sorted(set(list(BASELINE) + LOW + HIGH)):
            send("rssi_scope", f=f, ms=300, thr=-200)
            o = wait("rssi_scope", 7)
            if o:
                got[f] = o["avg"]
            time.sleep(0.12)

        print("\n  RSSI, nothing transmitting, sweep paused\n")
        if compare:
            print(f"  {'freq':>9}  {'now':>6}  {'desk':>6}  {'diff':>6}")
            print("  " + "-" * 34)
        else:
            print(f"  {'freq':>9}  {'now':>6}")
            print("  " + "-" * 18)
        for f in sorted(got):
            if compare and f in BASELINE:
                d = got[f] - BASELINE[f]
                flag = "  <-- quieter" if d >= 8 else ("  <-- louder" if d <= -8 else "")
                print(f"  {f:>7.2f}  {got[f]:>6}  {BASELINE[f]:>6}  {d:>+6}{flag}")
            else:
                print(f"  {f:>7.2f}  {got[f]:>6}")

        lo = [got[f] for f in LOW if f in got]
        hi = [got[f] for f in HIGH if f in got]
        if lo and hi:
            lo_m = sum(lo) / len(lo)
            hi_m = sum(hi) / len(hi)
            sep = hi_m - lo_m
            print(f"\n  low-band mean {lo_m:.1f}   band-3 mean {hi_m:.1f}")
            print(f"  band3 minus low-band = {sep:+.1f} dB     (desk baseline: -20.6 dB)")
            print("\n  A large negative value means the low bands sit well above band 3.")
            print("  Read it as MAGNITUDE: |sep| near 20 dB = same shape as the desk.")
            print("  |sep| much smaller = the low-band elevation is gone, so it was local RF.")
            print("  |sep| unchanged = the elevation follows the card, not the room.")
            print("\n  Note: a repeat run at the desk today gave -17.9 dB, so allow a few dB")
            print("  of session-to-session drift before treating a change as real.")
    finally:
        if scan_was_on:
            send("scan_toggle")
            time.sleep(0.4)
        ser.close()


if __name__ == "__main__":
    main()
