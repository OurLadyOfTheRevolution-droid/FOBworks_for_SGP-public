#!/usr/bin/env python3
"""GDO0 hardware audit suite.

The user asked whether the CC1101's GDO0 is really unrouted or merely unused, and
supplied the vendor archive. This suite keeps the audit's findings honest:

  1. the firmware carries the control-hardened `gdo0_signal` probe, and its verdict
     vocabulary distinguishes "unrouted" from "the rail is shared so we cannot tell";
  2. the probe reads VERSION and MARCSTATE as STATUS registers (the bug that made an
     earlier readback look wrong is guarded);
  3. records the V1/V2 document contradiction, the board's SX1278
     identity (LoRa RegVersion 0x12), and the shared-rail finding;
  4. the README's Hardware limits section states the same caveat rather than
     overclaiming a direct measurement.

The archive itself is not vendored, so the document-side checks assert the note's
conclusions, not the vendor files.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SKETCH = ROOT / "FOBworks_for_SGP.ino"
NOTE = ROOT / "research/79_GDO0_HARDWARE_AUDIT.md"
README = ROOT / "README.md"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def block(src, name):
    pat = re.compile(r"^(?:static\s+)?[\w\s\*&]*\b" + re.escape(name) +
                     r"\s*\([^;{]*?\)\s*\{", re.M | re.S)
    m = pat.search(src)
    if not m:
        return None
    i = src.index("{", m.start())
    depth = 0
    j = i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():j + 1]
        j += 1
    return None


def main():
    src = SKETCH.read_text()

    # ── 1. the probe exists and reports the right vocabulary ──────────
    check('gdo0_signal arm present', 'op=="gdo0_signal"' in src)
    for tok in ("RAIL_SHARED_CANNOT_ISOLATE", "GDO0_REACHES_PIN48",
                "GDO0_NOT_ROUTED", "TEST_INVALID"):
        check(f'verdict token {tok}', tok in src)
    # the probe must observe, not transmit: it must not strobe TX (STX = 0x35).
    # 0x35 also appears as the MARCSTATE status register, so match the strobe form.
    arm = src[src.find('op=="gdo0_signal"'):]
    arm = arm[:arm.find("else if(")]
    check("gdo0_signal does not transmit (no cc_strobe(0x35))",
          "cc_strobe(0x35)" not in arm)

    # ── 2. status registers read via the status path ──────────────────
    check("reads VERSION 0x31 via cc_readStatus", "ccStatus(0x31)" in arm)
    check("reads MARCSTATE 0x35 via cc_readStatus", "ccStatus(0x35)" in arm)
    check("uses IOCFG0 CLK_XOSC/192 (0x3F)", "cc_writeReg(0x02,0x3F)" in arm)
    check("cuts the sensor rail (PIN_SENSOR_CE LOW)", "digitalWrite(PIN_SENSOR_CE,LOW)" in arm)
    check("restores IOCFG0 to 0x0D", "cc_writeReg(0x02,0x0D)" in arm)
    check("defines its own WIN", "const uint16_t WIN" in arm)

    # ── 3. the note ───────────────────────────────────────────────────
    # is a private worklog and is not published; skip its note checks
    # when it is absent so a fresh clone still gets a green suite.
    if not NOTE.exists():
        print(" note: skipped (worklog not published)")
    else:
        t = NOTE.read_text()
        check("note records the V1/V2 contradiction",
              "GDO0/GDO2 no cableados" in t and "PIN_CC1101_GDO0 48" in t)
        check("note records the SX1278 identity", "0x12" in t and "SX1278" in t)
        check("note records the shared-rail finding",
              "RAIL_SHARED_CANNOT_ISOLATE" in t and "share the rail" in t.lower())
        check("note names the bodge-wire escape hatch",
              "pin 6" in t and "GPIO" in t)

    # ── 4. the README caveat ────────────────────���─────────────────────
    rd = README.read_text()
    check("README states the cannot-isolate caveat",
          "RAIL_SHARED_CANNOT_ISOLATE" in rd or "cannot be isolated" in rd.lower())

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
