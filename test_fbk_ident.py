#!/usr/bin/env python3
"""A stored frame's identity can be read back from its own pulses.

§6: the bench needs to know WHICH frame a replay will send,
and the only honest answer is one derived from the stored pulses rather than from what a
caller believes it staged. This checks the wiring statically (the identity computation is
exercised on hardware, where the KeeLoq parser chain runs against real captures).
"""

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "FOBworks_for_SGP.ino"
src = SRC.read_text(encoding="utf-8")
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


print("=== FbkEntry carries the identity fields ===")
m = re.search(r"struct FbkEntry \{(?P<body>.*?)\};", src, re.DOTALL)
check(m is not None, "FbkEntry found")
if m:
    body = m.group("body")
    for f in ("idHop", "idSn", "idBtn", "idCtr", "idOk"):
        check(f in body, f"FbkEntry carries {f}")

print("\n=== fbkIdentify() derives identity from pulses ===")
check("static bool fbkIdentify(" in src, "fbkIdentify declared")
# It must reuse the decode path, not invent a second parser.
ident = re.search(r"static bool fbkIdentify\(.*?\n\}", src, re.DOTALL)
check(ident is not None, "fbkIdentify body found")
if ident:
    ib = ident.group(0)
    for want, why in (("ks_km2", "clusters the body"),
                      ("ks_klPwm", "reuses the PWM extractor"),
                      ("ks_parseKL", "reuses the KeeLoq parser")):
        check(want in ib, f"fbkIdentify {why} ({want})")

print("\n=== the identity is computed at store time and reported ===")
check("e.idOk = fbkIdentify(" in src,
      "fbkAppend records the identity of the stored (trimmed) body")
check('op=="fbk_ident"' in src, "fbk_ident serial command exists")
check('\\"cmd\\":\\"fbk_ident\\"' in src, "fbk_ident emits a cmd-tagged reply")
# fbk_replay must echo the identity it sent, in both the serial and HTTP paths.
check(src.count('\\"ident_ok\\"') >= 3,
      "identity is reported by fbk_ident, fbk_replay and fbk_status")
check('op=="fbk_replay"' in src and 'protectedRoute("/api/fbk_replay"' in src,
      "both fbk_replay paths are present")

print("\n=== fbk_ident reports without transmitting ===")
# The readback must not call replayRaw; only fbk_replay does.
ident_cmd = re.search(r'op=="fbk_ident"\)\{(?P<body>.*?)\n  \}\n  //', src, re.DOTALL)
if ident_cmd is None:
    ident_cmd = re.search(r'op=="fbk_ident"\)\{(?P<body>.*?)else if\(op==', src, re.DOTALL)
check(ident_cmd is not None, "fbk_ident body found")
if ident_cmd:
    check("replayRaw" not in ident_cmd.group("body"),
          "fbk_ident does not transmit (no replayRaw in its body)")

print()
if FAILS:
    print(f"FBK IDENT CHECKS FAILED ({len(FAILS)} failures)")
    sys.exit(1)
print("stored-frame identity checks passed")
