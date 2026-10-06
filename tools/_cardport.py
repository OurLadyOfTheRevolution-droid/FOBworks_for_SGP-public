#!/usr/bin/env python3
"""Locate the SGP Card Mini's serial port without hardcoding its name.

Why this exists: the card re-enumerates when it is moved, and the Flippers also appear
as `/dev/cu.usbmodem*`. A hardcoded path therefore fails for the wrong reason after
exactly the experiment the bench tools exist to support — carrying the card somewhere
else to measure. Six tools had `/dev/cu.usbmodem1101` baked in.

`find_card()` probes each candidate with a `status` command and returns the first that
answers like the card. `find_flipper()` does the same for a Flipper Zero, skipping any
port already claimed as the card.

Both return None rather than raising, so a caller can report a missing device in its own
words instead of a traceback. Note that None means "nothing attached or answering", not
"the probe is wrong" -- an earlier note in this file guessed the banner timeout was at
fault when a Flipper was simply unplugged. Check the port exists before suspecting the
probe.
"""
import glob
import json
import time

import serial

# Flippers name their USB CDC port usbmodemflip<something>; the card does not.
FLIPPER_GLOB = "/dev/cu.usbmodemflip*"
CANDIDATE_GLOB = "/dev/cu.usbmodem*"


def _probe(port, token, want_flipper):
    """True if `port` answers like the device we want."""
    try:
        with serial.Serial(port, 115200, timeout=0.4) as s:
            s.reset_input_buffer()
            time.sleep(0.3)
            if want_flipper:
                # A Flipper's CLI banner is the cheapest positive.
                s.write(b"\r\n")
                s.flush()
                end = time.time() + 2.0
                buf = b""
                while time.time() < end:
                    c = s.read(4096)
                    if c:
                        buf += c
                    if b"Flipper" in buf or b">: " in buf:
                        return True
                return False
            s.write((json.dumps({"cmd": "status", "token": token}) + "\n").encode())
            s.flush()
            end = time.time() + 2.5
            while time.time() < end:
                line = s.readline().decode("utf-8", "replace").strip()
                if '"cmd":"status"' in line and "cc1101" in line:
                    return True
            return False
    except (OSError, serial.SerialException):
        return False


def find_card(token):
    """The SGP card's port, or None."""
    for p in sorted(glob.glob(CANDIDATE_GLOB)):
        if "flip" in p.lower():
            continue
        if _probe(p, token, want_flipper=False):
            return p
    return None


def find_flipper():
    """A Flipper Zero's port whose CLI is answering, or None.

    None is the normal result when no Flipper is attached. Verify
    /dev/cu.usbmodemflip* exists before concluding the probe is at fault.
    """
    for p in sorted(glob.glob(FLIPPER_GLOB)):
        if _probe(p, None, want_flipper=True):
            return p
    return None
