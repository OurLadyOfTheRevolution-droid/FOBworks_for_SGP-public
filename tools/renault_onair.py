#!/usr/bin/env python3
"""On-air validation of the Renault V1 (Hitag2) Layer-1 decoder.

The v3.98 decoder was proven against the corpus file and a synthetic round-trip,
but never against a transmission the card observed itself. This drives the one
leg that was missing: the Flipper transmits a Renault Hitag2 RAW file, the card
captures at 433.92 with frame-gap arming, and the reply is checked for a named
Renault-V1/Hitag2 decode with the expected serial.

The RAW file it sends is /tmp/ren_h2_min.sub (staged to the Flipper SD separately):
the genuine Trafic frame, trimmed so its first sync pair is at pulse 0 -- which is
what makes it land inside the card's 512-pulse capture window at all.

  python3 tools/renault_onair.py [trials]
"""
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

SUBFILE = "/ext/subghz/ren_h2_min.sub"
MHZ = 433.92
EXPECT_SN = 0x3270FD2B


def card_send(card, token, **fields):
    f = {"token": token}
    f.update(fields)
    card.write((json.dumps(f) + "\n").encode())
    card.flush()


def collect(card, dur):
    """Read lines for `dur` seconds; return raw lines and parsed decode dicts."""
    lines = []
    end = time.time() + dur
    while time.time() < end:
        l = card.readline().decode("utf-8", "replace").strip()
        if l:
            lines.append(l)
    decodes = []
    for l in lines:
        if l.startswith("{") and '"event"' not in l:
            try:
                d = json.loads(l)
            except ValueError:
                continue
            if isinstance(d, dict):
                decodes.append(d)
    return lines, decodes


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    token = (ROOT / "bench_token.txt").read_text().strip()
    card_port = _cardport.find_card(token)
    flip_port = _cardport.find_flipper()
    if not card_port or not flip_port:
        print(f"missing device: card={card_port} flipper={flip_port}")
        return 1
    print(f"card    {card_port}\nflipper {flip_port}\nsending {SUBFILE} @ {MHZ} MHz\n")

    card = serial.Serial(card_port, 115200, timeout=0.25)
    flip = serial.Serial(flip_port, 115200, timeout=0.25)
    time.sleep(0.5)

    # Configure the capture path: AM, per-stage diag, gap-arming default on.
    card_send(card, token, cmd="cap_mode", fsk=False)
    time.sleep(0.4)
    card_send(card, token, cmd="cap_diag", on=True)
    time.sleep(0.3)
    card_send(card, token, cmd="gaparm", on=True)
    time.sleep(0.3)
    card.reset_input_buffer()

    hits = 0
    for trial in range(1, trials + 1):
        card.reset_input_buffer()
        card_send(card, token, cmd="capture", f=MHZ, t=12000, arm="gap")
        pump_lines = []

        def pump(dur):
            end = time.time() + dur
            while time.time() < end:
                l = card.readline().decode("utf-8", "replace").strip()
                if l:
                    pump_lines.append(l)

        t = threading.Thread(target=pump, args=(14,))
        t.start()
        time.sleep(1.6)  # let the arm settle before TX

        flip.reset_input_buffer()
        flip.write((f"subghz tx_from_file {SUBFILE} 5 0\r\n").encode())
        flip.flush()
        t.join(timeout=20)
        flip.write(b"\x03")
        flip.flush()
        time.sleep(0.4)

        decodes = []
        for l in pump_lines:
            if l.startswith("{") and '"event"' not in l:
                try:
                    decodes.append(json.loads(l))
                except ValueError:
                    pass
        named = [d for d in decodes if d.get("proto") not in (None, "OOK-raw")]
        ren = [d for d in named if "Renault" in str(d.get("proto", ""))]
        edges = None
        for d in decodes:
            if "edges" in d:
                edges = d.get("edges")
        print(f"trial {trial}: edges={edges}  named={[(d.get('proto')) for d in named]}")
        for d in named:
            hexv = d.get("hex")
            sn = None
            if hexv and len(hexv) >= 8:
                sn = int(hexv[:8], 16)
            tag = ""
            if sn == EXPECT_SN:
                tag = "  <-- EXPECTED SERIAL 0x3270FD2B"
            elif d.get("proto") and "Renault" in str(d.get("proto")):
                tag = f"  serial=0x{sn:08X}" if sn is not None else ""
            print(f"    proto={d.get('proto')} te={d.get('te_us')} bits={d.get('bitlen')} "
                  f"hex={hexv}{tag}")
        if ren and any(int(d.get("hex", "0")[:8] or "0", 16) == EXPECT_SN for d in ren):
            hits += 1
        time.sleep(0.5)

    card_send(card, token, cmd="cap_diag", on=False)
    card.close()
    flip.close()
    print(f"\nverdict: {hits}/{trials} trials decoded as Renault-V1/Hitag2 with SN 0x{EXPECT_SN:08X}")
    return 0 if hits else 2


if __name__ == "__main__":
    sys.exit(main())
