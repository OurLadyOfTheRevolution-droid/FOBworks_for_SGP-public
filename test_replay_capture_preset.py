#!/usr/bin/env python3
"""Guard the replay-modulation detection in tools/replay_capture.py.

The tool used to force `cap_mode fsk=False` for every replay. Half the Kia/Hyundai RAW
corpus is recorded 2-FSK , and an OOK capture path cannot slice a 2-FSK
transmission — the envelope is constant and there are no amplitude edges to trigger on
. Firing a 2-FSK file into an OOK capture produced a clean 0/4 that read like a
link problem and was not one.

The fix reads the replay file's `Preset:` header and selects the capture modulation to
match. This test pins the header parsing, which is the part that can silently regress: the
transport (reading the header over the Flipper CLI) needs hardware, the parser does not.

Run: python3 test_replay_capture_preset.py
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "tools" / "replay_capture.py"

# A header-shaped string is enough; the parser only looks for the `Preset:` line.
CASES = [
    # (description, header text, expected file_is_fsk value)
    ("2FSK Dev476, 315 MHz Kia RAW",
     "Filetype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 315000000\n"
     "Preset: FuriHalSubGhzPreset2FSKDev476Async\nProtocol: RAW\n", True),
    ("OOK 650, 315 MHz Kia RAW",
     "Filetype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 315000000\n"
     "Preset: FuriHalSubGhzPresetOok650Async\nProtocol: RAW\n", False),
    ("OOK 270, 433 MHz Genesis",
     "Preset: FuriHalSubGhzPresetOok270Async\n", False),
    ("2FSK Dev238, the SD KeeLoq capture",
     "Preset: FuriHalSubGhzPreset2FSKDev238Async\n", True),
    ("GFSK is frequency modulation too",
     "Preset: FuriHalSubGhzPresetGFSK9_99KbAsync\n", True),
    ("no Preset line at all",
     "Filetype: Flipper SubGhz RAW File\nVersion: 1\n", None),
]


def load_tool(argv=None):
    """Import the tool without running main(); argv defaults to no arguments."""
    sys.argv = ["replay_capture.py"] + list(argv or [])
    spec = importlib.util.spec_from_file_location("replay_capture", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    mod = load_tool()
    if not hasattr(mod, "parse_preset"):
        print("FAIL: tools/replay_capture.py has no parse_preset() to test")
        return 1

    failures = 0
    for desc, header, expect in CASES:
        got = mod.parse_preset(header)
        ok = got == expect
        if not ok:
            failures += 1
        print(f"  {'ok  ' if ok else 'FAIL'} {desc:38s} got={got!s:5s} want={expect!s:5s}")

    # The override must beat detection: a deliberate mismatch is a supported A/B case.
    # Real usage puts the positional args first (subfile, MHz, trials), then the flag.
    PREFIX = ["/ext/subghz/x/Kia_V1_N1_RAW.sub", "315.00", "1"]
    cases = [
        ("--fsk on", PREFIX + ["--fsk", "on"], True),
        ("--fsk off", PREFIX + ["--fsk", "off"], False),
        ("--fsk=true", PREFIX + ["--fsk=true"], True),
        ("--fsk=false", PREFIX + ["--fsk=false"], False),
    ]
    for desc, argv, expect in cases:
        m = load_tool(argv)
        ok = m.FSK_OVERRIDE == expect
        if not ok:
            failures += 1
        print(f"  {'ok  ' if ok else 'FAIL'} override {desc:31s} "
              f"got={m.FSK_OVERRIDE!s:5s} want={expect!s:5s}")

    total = len(CASES) + len(cases)
    print(f"\n  {total - failures}/{total} cases pass")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
