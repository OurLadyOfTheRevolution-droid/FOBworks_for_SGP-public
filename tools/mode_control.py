#!/usr/bin/env python3
"""Receive-only. The free receiver-side control §3.1.

Samples the same frequencies in OOK and in FSK and compares the SHAPE.

Why: part of the 300-464 MHz elevation is receiver-side --
the modulation alone moves 360 MHz by 8 dB. If the shape (band 1 and 2 high, band 3
clean) survives a modulation change, then the shape is not a configuration artifact.
If it moves with the mode, most of it is.

No transmission. Sweep is paused for the run.
"""
import json
import sys
import time
from pathlib import Path

import serial

PORT = "/dev/cu.usbmodem1101"
TOKEN = (Path(__file__).resolve().parent.parent / "bench_token.txt").read_text("utf-8").strip()
BANDS = [310.0, 320.0, 345.0, 360.0, 390.0, 420.0, 433.92, 450.0, 868.3, 915.0]


def main():
    ser = serial.Serial(PORT, 115200, timeout=0.3)
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

        results = {}
        for mode, fsk in (("OOK", False), ("FSK", True)):
            send("cap_mode", fsk=fsk)
            time.sleep(0.7)
            results[mode] = {}
            for f in BANDS:
                send("rssi_scope", f=f, ms=250, thr=-200)
                o = wait("rssi_scope", 7)
                if o:
                    results[mode][f] = o["avg"]
                time.sleep(0.12)

        print("  same frequencies, two modulator configurations, nothing transmitting\n")
        print(f"  {'freq':>9}  {'OOK avg':>8}  {'FSK avg':>8}  {'delta':>6}")
        print("  " + "-" * 40)
        for f in BANDS:
            a = results["OOK"].get(f)
            b = results["FSK"].get(f)
            d = f"{a-b:+d}" if (a is not None and b is not None) else "   -"
            print(f"  {f:>7.2f}  {str(a):>8}  {str(b):>8}  {d:>6}")

        # the shape question: is band 3 still the quietest in both?
        low = [f for f in BANDS if f <= 464.0]
        high = [f for f in BANDS if f >= 779.0]
        for mode in ("OOK", "FSK"):
            r = results[mode]
            lo = [r[f] for f in low if f in r]
            hi = [r[f] for f in high if f in r]
            if lo and hi:
                print(f"\n  {mode}: band1/2 mean {sum(lo)/len(lo):.1f}  "
                      f"band3 mean {sum(hi)/len(hi):.1f}  "
                      f"separation {sum(hi)/len(hi) - sum(lo)/len(lo):+.1f} dB")
    finally:
        send("cap_mode", fsk=False)
        time.sleep(0.3)
        if scan_was_on:
            send("scan_toggle")
            time.sleep(0.4)
            print("  scan restored")
        ser.close()


if __name__ == "__main__":
    main()
