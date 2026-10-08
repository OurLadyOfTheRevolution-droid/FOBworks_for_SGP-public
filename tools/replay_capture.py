#!/usr/bin/env python3
"""Replay a recorded signal from Flipper A while the SGP captures, N times.

This is the loop -`56` kept re-writing by hand. It exists as a tool so the
drain is bounded correctly, `cap_diag` is applied and cleared, and the results are printed
in one place.

It reads the access code from `bench_token.txt` beside this file (the same file the other
bench tools use) and sends it as the command token. It does not print it.

Why the sequence matters:
  * `cap_mode` is applied FIRST. Without it the front end can be left reading ~35 dB high
    , which makes every capture at 315 fail for the wrong reason.
  * `cap_mode` must MATCH the replay file's modulation. An OOK capture path demodulating a
    2-FSK transmission sees a constant envelope with no amplitude edges to slice — the
    modulation carries its data in frequency, so the RSSI envelope is flat.
    The tool now reads the file's `Preset:` header over the Flipper CLI and selects FSK or
    OOK capture to match. Firing a 2-FSK recording into an OOK path was the cause of a 0/4
    run. Override with `--fsk on|off` only for a deliberate mismatch.
  * Operate at ~2 m, not 5 cm. Close range drives the front end to about -30 dBm, the AGC
    plateau never dips, and gap-arming exhausts its retries on a signal it cannot slice
. At 2 m the peak lands near -74 dBm and the recorder fills from a frame
    boundary.
  * The replay is started on a thread. `subghz tx_from_file` blocks the Flipper's CLI for
    the whole transmission, so sampling after it returns would only ever see silence.
  * The card drain is bounded by elapsed time. The card streams ticks continuously, so a
    drain that waits for an idle condition never exits. That fault held the port in


Usage:
    python3 tools/replay_capture.py "<path on flipper A>" [card_mhz] [trials] [arm=off] [--fsk on|off]
"""
import json
import re
import sys
import threading
import time
from pathlib import Path

import serial

FLIP = "/dev/cu.usbmodemflip_Ari0on41"
TOKEN = (Path(__file__).resolve().parent.parent / "bench_token.txt").read_text("utf-8").strip()

# The card re-enumerates when moved; probe for it instead of hardcoding (61).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _cardport  # noqa: E402

SGP = _cardport.find_card(TOKEN)

SUBFILE = sys.argv[1] if len(sys.argv) > 1 else \
    "/ext/subghz/fob_signals_corpus/American__Tesla__Tesla_315MHz_AM650_Tesla-Long.sub"
CARD_MHZ = float(sys.argv[2]) if len(sys.argv) > 2 else 315.00
TRIALS = int(sys.argv[3]) if len(sys.argv) > 3 else 4
# Gap-arming (N16): arm the edge buffer on the frame-gap signature rather than
# first energy, so the Flipper RAW's carrier plateau does not fill it with
# non-frame transitions. Default ON — the tool exists to exercise leg 2 of
# and that is the leg the arming fixes. `arm=off` on argv[4]
# reproduces the pre-fix behaviour for A/B comparison.
ARM_GAP = not (len(sys.argv) > 4 and sys.argv[4] == "off")
# Modulation of the replay file, set from its `Preset:` header (or --fsk on|off). An OOK
# capture path cannot slice a 2-FSK transmission: the envelope is constant and there are no
# amplitude edges, so the capture fills with nothing. None means
# "detect from the file".
FSK_OVERRIDE = None
for i, a in enumerate(sys.argv):
    if a == "--fsk" and i + 1 < len(sys.argv):
        FSK_OVERRIDE = sys.argv[i + 1].lower() in ("on", "true", "1", "yes")
    elif a.startswith("--fsk="):
        FSK_OVERRIDE = a.split("=", 1)[1].lower() in ("on", "true", "1", "yes")


def parse_preset(header_text):
    """Return True for a 2FSK preset header, False for OOK, None if absent.

    Split out from the serial walk so it can be unit-tested without a Flipper: the
    header parsing is the part that was wrong, not the transport.
    """
    for line in header_text.splitlines():
        if line.startswith("Preset:"):
            val = line.split(":", 1)[1].strip().lower()
            return ("2fsk" in val) or ("fsk" in val and "ook" not in val)
    return None


def file_is_fsk(flip, path):
    """Read the .sub header over the CLI and return True for a 2FSK/FSK preset.

    The Flipper's `storage read` streams the whole file, so the header arrives in the
    first reads and the transfer is abandoned with Ctrl-C once `Preset:` is seen. A
    Flipper whose CLI has hung answers nothing; the window below returns
    None rather than blocking, and the caller defaults to OOK.
    """
    flip.reset_input_buffer()
    flip.write((f"storage read {path}\r\n").encode())
    flip.flush()
    end = time.time() + 6.0
    buf = bytearray()
    while time.time() < end:
        chunk = flip.read(4096)
        if chunk:
            buf += chunk
            if b"Preset:" in buf:
                break
    flip.write(b"\x03")
    flip.flush()
    time.sleep(0.4)
    flip.read(4096)
    return parse_preset(buf.decode("utf-8", "replace"))


def main():
    card = serial.Serial(SGP, 115200, timeout=0.3)
    flip = serial.Serial(FLIP, 115200, timeout=0.3)

    def send(cmd, **kw):
        card.write((json.dumps({"cmd": cmd, "token": TOKEN, **kw}) + "\n").encode())
        card.flush()

    try:
        card.reset_input_buffer()
        time.sleep(0.6)

        # Match the card's capture modulation to the replay file. Getting this wrong is
        # silent: the capture just never fills, and it looks like a link problem.
        if FSK_OVERRIDE is None:
            detected = file_is_fsk(flip, SUBFILE)
            fsk = bool(detected) if detected is not None else False
            src = f"file preset {'2FSK' if fsk else 'OOK'}" if detected is not None \
                else "undetected, defaulting to OOK"
        else:
            fsk = FSK_OVERRIDE
            src = "--fsk override"
        print(f"  replaying {SUBFILE.split('/')[-1]}")
        print(f"  capture modulation: {'2FSK' if fsk else 'OOK'}  ({src})")
        print(f"  capturing at {CARD_MHZ} MHz, {TRIALS} trials\n")

        ok = 0
        for trial in range(1, TRIALS + 1):
            send("cap_mode", fsk=fsk)
            time.sleep(0.5)
            send("cap_diag", on=True)
            time.sleep(0.4)
            if ARM_GAP:
                send("gaparm", on=True)
                time.sleep(0.3)
            else:
                send("gaparm", on=False)
                time.sleep(0.3)

            lines = []

            def pump(dur):
                end = time.time() + dur
                while time.time() < end:
                    l = card.readline().decode("utf-8", "replace").strip()
                    if l:
                        lines.append(l)

            card.reset_input_buffer()
            if ARM_GAP:
                send("capture", f=CARD_MHZ, t=12000, arm="gap")
            else:
                send("capture", f=CARD_MHZ, t=12000)
            t = threading.Thread(target=pump, args=(20,))
            t.start()
            time.sleep(1.6)

            flip.write((f"subghz tx_from_file {SUBFILE} 5 0\r\n").encode())
            time.sleep(4.0)
            t.join(timeout=24)

            edges = None
            for l in lines:
                if '"edges":' in l:
                    try:
                        edges = json.loads(l).get("edges")
                    except ValueError:
                        pass
            if edges:
                ok += 1
            print(f"  trial {trial}: edges={edges}  {'CAPTURED' if edges else 'no capture'}")
            for l in lines:
                if "[DIAG]" in l or "Floor:" in l or "Signal!" in l or "Too few" in l or "Gap-" in l:
                    print(f"      {l.strip()[:150]}")
            time.sleep(0.3)

        print(f"\n  captured {ok}/{TRIALS}")
        send("cap_diag", on=False)
        time.sleep(0.2)
    finally:
        flip.close()
        card.close()


if __name__ == "__main__":
    main()
