#!/usr/bin/env python3
"""Sample the RSSI trace at 315 while a fob is pressed.

Prints the raw sample distribution, so a sustained carrier (flat, high, few runs) can be
told from real modulation (alternating, many runs).

Usage: python3 tools/rssi_trace.py 315.00 [seconds]
"""
import json
import sys
import time
from pathlib import Path

import serial

PORT = "/dev/cu.usbmodem1101"
TOKEN_FILE = Path(__file__).resolve().parent.parent / "bench_token.txt"
MHZ = float(sys.argv[1]) if len(sys.argv) > 1 else 315.00
MS = int(float(sys.argv[2]) * 1000) if len(sys.argv) > 2 else 4000

TOKEN = TOKEN_FILE.read_text(encoding="utf-8").strip()


def main():
    ser = serial.Serial(PORT, 115200, timeout=0.3)
    try:
        ser.reset_input_buffer()
        time.sleep(0.6)

        # quiet pass: establishes the floor without the fob
        ser.write((json.dumps({"cmd": "rssi_scope", "token": TOKEN, "f": MHZ, "ms": 700}) + "\n").encode())
        ser.flush()
        quiet = None
        end = time.time() + 6
        while time.time() < end and quiet is None:
            line = ser.readline().decode("utf-8", "replace").strip()
            if '"cmd":"rssi_scope"' in line:
                quiet = json.loads(line)
        if quiet:
            print(f"  QUIET   avg={quiet['avg']} span={quiet['span']} max={quiet['max']}")

        # signal pass: thresholded at the quiet floor + 5 (the toy-band edge margin)
        thr = (quiet["avg"] + 5) if quiet else None
        print(f"\n  >>> PRESS THE FOB NOW and hold it against the antenna <<<\n", flush=True)
        payload = {"cmd": "rssi_scope", "token": TOKEN, "f": MHZ, "ms": MS}
        if thr is not None:
            payload["thr"] = thr
        ser.write((json.dumps(payload) + "\n").encode())
        ser.flush()

        end = time.time() + MS / 1000.0 + 6
        sig = None
        while time.time() < end and sig is None:
            line = ser.readline().decode("utf-8", "replace").strip()
            if '"cmd":"rssi_scope"' in line:
                sig = json.loads(line)
        if sig:
            print(f"  SIGNAL  avg={sig['avg']} min={sig['min']} max={sig['max']} span={sig['span']}")
            print(f"  samples={sig['samples']}  {sig['us_per_sample']} us/sample")
            if thr is not None:
                print(f"  threshold={thr}  runs={sig.get('runs')} "
                      f"runs>=100us={sig.get('runs_ge100us')} runs<100us={sig.get('runs_lt100us')}")
                print(f"  max_run_samples={sig.get('max_run_samples')}")
            f = sig.get("first64", [])
            print(f"  first 32: {f[:32]}")
    finally:
        ser.close()


if __name__ == "__main__":
    main()
