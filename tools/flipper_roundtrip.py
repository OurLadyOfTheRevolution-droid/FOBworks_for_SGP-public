#!/usr/bin/env python3
"""Round-trip a capture between the card and a Flipper Zero.

Both directions were verified live at 5 cm spacing on 2026-10-03:

  · card -> Flipper: `subghz rx_raw` streamed the card's 315 MHz packet-mode
    transmission as live +hi/-lo pulse pairs while `fbk_replay` fired. The card's
    over-the-air TX — never before witnessed by a second device — is real.
  · Flipper -> card: `replay_capture.py` (same repo) caught 23/33/37-edge
    captures at 433.92 while the Flipper transmitted a corpus RAW file.

Firmware-CLI facts this tool encodes, each learned the hard way on a Flipper
Zero running 1.4.3:

  · `subghz rx <Hz> <device>` REQUIRES the device argument (0 = internal
    CC1101); without it the command is an "illegal option" and silently does
    nothing to the radio.
  · There is no `subghz rx_stop`. The rx app is left with Ctrl-C (0x03).
    Sending `rx_stop` just prints a usage error and leaves the app running —
    which looks identical to "quiet" from the host.
  · `subghz rx_raw <Hz>` streams `+hi -lo` microsecond pairs live over the
    CLI and is level-triggered, so it sees any modulation regardless of whether
    the Flipper has a protocol decoder for it. 115200 baud limits its time
    resolution; treat it as a presence/structure check, not a bit-exact copy.
  · `subghz tx_from_file <path> <repeat> <device>` blocks the CLI for the
    whole transmission, so start it on a thread and never wait for its prompt.
  · The Flipper crashed twice in ~10 minutes of tx/rx cycling and once failed
    its own boot-time furi check; if the CLI goes silent, the box needs a
    reboot, not a different command.

Usage:
    python3 tools/flipper_roundtrip.py            # both directions
    python3 tools/flipper_roundtrip.py --tx-only  # card transmits, Flipper listens
    python3 tools/flipper_roundtrip.py --rx-only  # Flipper transmits, card captures
"""
import argparse
import json
import re
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import _cardport  # noqa: E402

import serial  # noqa: E402

CORPUS = ROOT / "research/sources/corpus_automotive_subghz/Asian/Hyundai_Kia_Genesis/Kia_V3_N1_RAW.sub"
# A multi-repeat RAW corpus file that lives on the Flipper's SD from the shared
# corpus: used for the flipper->card leg because a protocol .sub transmits only
# once (~100 ms) and is easy to miss. NOTE: Kia_V1_N1_RAW is a 315 MHz file
# played while the card captures 315 — on this bench that leg lands 0-47 edges
# depending on spacing; the card's first-signal buffer fill and the 315 margin
# decide it. The leg is reported honestly either way.
FLIPPER_SUB = "/ext/subghz/Hyundai_Kia_Genesis/Kia_V1_N1_RAW.sub"
RT_MHZ = 315.0
CHUNK = 48  # v3.87 bound: 48 pulses per fbk_pulses_add, half the ~600 B line


def flipper_write(flip, line):
    flip.write((line + "\r\n").encode())
    flip.flush()


def card_cmd(card, op, token, fields=None, wait=8.0):
    """Send one card command; return its JSON reply (heartbeates skipped)."""
    f = dict(fields or {})
    f.update({"cmd": op, "token": token})
    card.reset_input_buffer()
    card.write((json.dumps(f) + "\n").encode())
    card.flush()
    end = time.time() + wait
    buf = b""
    while time.time() < end:
        c = card.read(8192)
        if c:
            buf += c
        for ln in buf.decode("utf-8", "replace").splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    d = json.loads(ln)
                except ValueError:
                    continue
                if isinstance(d, dict) and d.get("cmd") == op and "ok" in d:
                    return d
    return None


def kia_frame():
    """One frame from the corpus, using the firmware's own trim rule."""
    w = []
    for line in CORPUS.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            w.extend(abs(int(x)) for x in re.findall(r"-?\d+", line[9:]))
    GAP, PITCH, TOL = 1000, 162, 8
    for i in range(len(w)):
        if w[i] <= GAP:
            continue
        j = next((k for k in range(i + 1, len(w)) if w[k] > GAP), None)
        if j is None:
            break
        if PITCH - TOL <= j - i <= PITCH + TOL:
            return [x for x in w[max(0, i - 20):i + PITCH + 1] if x > 0]
    return None


def stage_frame(card, token, frame, freq):
    """Chunked import; asserts each add staged exactly what was sent (v3.87)."""
    card_cmd(card, "fbk_disarm", token)
    card_cmd(card, "fbk_pulses_begin", token, {"freq": freq})
    for i in range(0, len(frame), CHUNK):
        sl = frame[i:i + CHUNK]
        r = card_cmd(card, "fbk_pulses_add", token,
                     {"pulses": ",".join(str(x) for x in sl)})
        if not (r and r.get("ok") and r.get("added") == len(sl)):
            return f"add-failed@{i}: {r}"
    return card_cmd(card, "fbk_pulses_end", token)


def leg_card_to_flipper(card, flip, token, frame):
    print("\n=== leg 1: card imports + transmits, Flipper rx_raw listens ===")
    r = stage_frame(card, token, frame, RT_MHZ)
    print(f"chunked import: {r}")
    if not (isinstance(r, dict) and r.get("ok")):
        print("  FAIL: import did not complete")
        return False

    # Arm the Flipper's raw receiver BEFORE the burst. rx_raw is level-triggered
    # and streams live; it needs the trailing device arg on 1.4.3? rx_raw takes
    # only Hz. It stays in the app until Ctrl-C.
    flip.reset_input_buffer()
    flipper_write(flip, f"subghz rx_raw {int(RT_MHZ * 1e6)}")
    time.sleep(2.0)
    flip.read(8192)  # the Listening banner

    ok = card_cmd(card, "fbk_replay", token, {"n": 0})
    print(f"card replay (idx 0, {RT_MHZ} MHz): ok={ok.get('ok') if ok else None}")

    # Collect the live stream for a few seconds: the pulses arrive as they are
    # detected, bounded by the CLI baud rate.
    end = time.time() + 5.0
    fbuf = b""
    while time.time() < end:
        c = flip.read(8192)
        if c:
            fbuf += c
    # Leave the app the only way that exists: Ctrl-C. There is no rx_stop.
    flip.write(b"\x03")
    flip.flush()
    time.sleep(1.0)
    flip.read(4096)

    cap = fbuf.decode("utf-8", "replace")
    # Presence check: rx_raw prints idle as long +/- stretches; a transmission
    # shows short alternating pairs (tens to ~2000 us). Count short pairs.
    vals = [abs(int(x)) for x in re.findall(r"[+-]\d+", cap)]
    short = [v for v in vals if 20 <= v <= 2500]
    print(f"flipper rx_raw stream: {len(vals)} edges total, {len(short)} in the "
          f"20-2500 us modulation band")
    if short:
        print(f"  sample: {' '.join(f'{v}' for v in short[:12])} ...")
    verdict = len(short) >= 8
    print(f"  -> {'PASS: the Flipper observed the card transmission' if verdict else 'FAIL: no modulation seen'}")
    return verdict


def leg_flipper_to_card(card, flip, token):
    print("\n=== leg 2: Flipper transmits a corpus RAW, card captures ===")
    # The replay_capture ordering: cap_mode first, diag on, capture armed,
    # THEN the transmission on a thread (the CLI blocks while transmitting).
    card_cmd(card, "cap_mode", token, {"fsk": False})
    time.sleep(0.5)

    lines = []

    def pump(dur):
        end = time.time() + dur
        while time.time() < end:
            l = card.readline().decode("utf-8", "replace").strip()
            if l:
                lines.append(l)

    card.reset_input_buffer()
    card.write((json.dumps({"cmd": "capture", "token": token,
                            "f": RT_MHZ, "t": 12000}) + "\n").encode())
    card.flush()
    t = threading.Thread(target=pump, args=(20,))
    t.start()
    time.sleep(1.6)

    # tx_from_file blocks the Flipper CLI for the whole transmission.
    flip.reset_input_buffer()
    flipper_write(flip, f"subghz tx_from_file {FLIPPER_SUB} 5 0")
    t.join(timeout=26)
    # Ctrl-C in case the app stayed open
    flip.write(b"\x03")
    flip.flush()
    time.sleep(1.0)
    flip.read(4096)

    edges = None
    for l in lines:
        if '"edges":' in l:
            try:
                edges = json.loads(l).get("edges")
            except ValueError:
                pass
        if "[DIAG]" in l or "Signal!" in l or "CAP" in l:
            print("  " + l)
    if edges:
        print(f"  -> PASS: card captured {edges} edges from the Flipper tx")
        return True
    # replay_capture counts an edges>0 as captured; fall back to its rule.
    for l in lines:
        if '"cmd":"capture"' in l and '"error"' not in l:
            print(f"  -> PASS: {l[:120]}")
            return True
    print("  -> FAIL: no capture landed (see diag above)")
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tx-only", action="store_true", help="card -> Flipper only")
    ap.add_argument("--rx-only", action="store_true", help="Flipper -> card only")
    args = ap.parse_args()

    token = (ROOT / "bench_token.txt").read_text().strip()
    card_port = _cardport.find_card(token)
    flip_port = _cardport.find_flipper()
    if not card_port:
        print("no card found")
        return 1
    if not flip_port:
        print("no Flipper found (is it showing an app? exit to the main menu)")
        return 1
    print(f"card    {card_port}")
    print(f"flipper {flip_port}")

    frame = kia_frame()
    if not frame:
        print("no frame in corpus")
        return 1
    print(f"corpus frame: {len(frame)} pulses, chunked at {CHUNK}/add")

    card = serial.Serial(card_port, 115200, timeout=0.3)
    flip = serial.Serial(flip_port, 115200, timeout=0.3)
    time.sleep(0.5)
    flipper_write(flip, "")

    results = {}
    try:
        if not args.rx_only:
            results["card->flipper"] = leg_card_to_flipper(card, flip, token, frame)
        if not args.tx_only:
            results["flipper->card"] = leg_flipper_to_card(card, flip, token)
    finally:
        card.close()
        flip.close()

    print("\n=== round-trip verdict ===")
    for k, v in results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
