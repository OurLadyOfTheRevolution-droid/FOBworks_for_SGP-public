#!/usr/bin/env python3
"""Assert every reported limit string in the source matches its constant.

§3.1: the suite missed two defects because neither was logic — both were a value
that had stopped describing reality. Two routes reported `max_bytes:8192` while enforcing
`SUB_REPLAY_MAX_BODY_BYTES=16384`, so a caller told "8192" who sent 9000 bytes was refused by
a message that understated the limit. That is the same class of error as the FIFO count that
reported success while the PA was silent, and the MARCSTATE 17 that made a working carrier
look dead.

This is the standing guard the review asked for: for each limit constant, any literal that
appears in a message about it must either match, or be emitted from the constant.
"""

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "FOBworks_for_SGP.ino"
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the limit constants ===")
    body = re.search(r"SUB_REPLAY_MAX_BODY_BYTES\s*=\s*(\d+)", src)
    pulses = re.search(r"#define\s+SUB_REPLAY_MAX_PULSES\s+(\d+)", src)
    cap = re.search(r"#define\s+CAP_SZ\s+(\d+)", src)
    check(body is not None, "SUB_REPLAY_MAX_BODY_BYTES is defined")
    check(pulses is not None, "SUB_REPLAY_MAX_PULSES is defined")
    check(cap is not None, "CAP_SZ is defined")
    if not (body and pulses and cap):
        return 1
    body_v, pulses_v, cap_v = int(body.group(1)), int(pulses.group(1)), int(cap.group(1))
    print(f"    SUB_REPLAY_MAX_BODY_BYTES = {body_v}")
    print(f"    SUB_REPLAY_MAX_PULSES     = {pulses_v}")
    print(f"    CAP_SZ                    = {cap_v}")

    print("\n=== no message quotes a stale max_bytes literal ===")
    # Any `"max_bytes":<literal>` must equal the constant it describes, or be the constant.
    bad = []
    for m in re.finditer(r'max_bytes\\?"\s*:\s*(\d+)', src):
        lit = int(m.group(1))
        if lit != body_v:
            line = src.count("\n", 0, m.start()) + 1
            bad.append((line, lit))
    check(not bad,
          f"every max_bytes literal equals the constant ({body_v})"
          + ("" if not bad else f" — stale at lines {bad}"))
    # And prefer emitting the constant so this cannot drift again.
    emitted = len(re.findall(r'max_bytes\\?"\s*:\s*"\s*\+\s*String\(SUB_REPLAY_MAX_BODY_BYTES\)', src))
    check(emitted >= 2,
          f"both body-cap routes emit the constant rather than a literal ({emitted} found)")

    print("\n=== the pulse cap is used consistently ===")
    # The serial import once looped to CAP_SZ (512) while its buffer was 3740, silently
    # truncating. Any loop bounded by a pulse limit should use the same constant.
    stale = []
    for m in re.finditer(r"ic<(?:\(int\))?\s*CAP_SZ", src):
        line = src.count("\n", 0, m.start()) + 1
        stale.append(line)
    check(not stale,
          "no pulse-count loop caps at CAP_SZ where it means the body limit"
          + ("" if not stale else f" — lines {stale}"))

    print("\n=== the buffer consolidation holds ===")
    # §2: four copies of a 3740-entry array cost 29.9 KB and took RAM to 47%.
    # One body stage + one frame stage is the intent; assert nothing re-grew a copy.
    big = re.findall(r"(?:static\s+)?uint16_t\s+\w+\s*\[\s*SUB_REPLAY_MAX_PULSES\s*\]", src)
    check(len(big) == 1,
          f"exactly one buffer is sized SUB_REPLAY_MAX_PULSES (found {len(big)}: {big})")
    check("impFrame[CAP_SZ]" in src,
          "the frame stage is sized CAP_SZ (one trimmed frame, not the whole body)")
    # The three handlers must alias the shared stage, not declare their own.
    for name in ("sb", "ib", "ip"):
        check(f"uint16_t* {name}=impStage" in src,
              f"{name} aliases the shared body stage rather than allocating a copy")

    print("\n=== the import staging comment matches the code beside it ===")
    # §2: a file-scope comment described the abandoned in-place design -- "the
    # SAME array ... writes frameStage over it in place" -- directly above two declarations of
    # SEPARATE arrays, and pointed at a call-site note saying the opposite. No test can judge
    # prose, but a comment that *contradicts the declaration beside it* is detectable, and
    # this class (a statement that stopped being true) has produced a defect in four rounds.
    block = re.search(r"(// TWO buffers.*?)static uint16_t impStage", src, re.S)
    check(block is not None, "the staging comment block is present")
    if block:
        text = block.group(1)
        check("SAME array" not in text,
              "the comment no longer claims the two arrays are the same")
        check("in place" not in text.lower() or "abandoned" in text.lower()
              or "not used" in text.lower() or "two separate" in text.lower(),
              "if in-place is mentioned, it is described as not used")
        # And it must agree with the declarations: two arrays, distinct sizes.
        check("Two separate arrays" in text,
              "the comment states the two arrays are separate")
    # The declarations themselves: two distinct arrays, so the comment cannot alias.
    check(len(re.findall(r"static uint16_t impStage\[", src)) == 1 and
          len(re.findall(r"static uint16_t impFrame\[", src)) == 1,
          "impStage and impFrame are declared as two distinct arrays")

    print("\n=== the dead flen guard is documented as dead ===")
    # §2.1: klTrimToFrame clamps to outCap, and the call passes CAP_SZ, so this
    # check cannot fire. It was noted rather than deleted; assert the note exists so a reader
    # is not misled into thinking it protects something.
    m = re.search(r"(// Note: this cannot fire\..*?)\n\s*if\(flen>\(int\)CAP_SZ\)", src, re.S)
    check(m is not None,
          "the flen>CAP_SZ check carries a note that it cannot fire")

    print()
    if FAILS:
        print(f"LIMIT STRING CHECKS FAILED ({len(FAILS)} failures)")
        return 1
    print("limit string and buffer checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
