#!/usr/bin/env python3
"""Tests for the Flipper pull helper (tools/flipper_pull.py).

Two halves. The parser half pins the CLI decoding rules against the exact
strings a Flipper 1.4.3 prints — `[D]`/`[F] name <n>b` listings and a
`storage read` payload bracketed by the echoed command and the `>: ` prompt —
because those are the only interface the tool has and a silent mis-parse would
drop or truncate captures. The live half walks the attached card when one is
present, and skips cleanly when it is not.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

import flipper_pull as fp  # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


# A verbatim listing block, echo line and all, as the CLI prints it.
LISTING = (
    "storage list /ext/subghz\r\n"
    "\t[D] assets\r\n"
    "\t[D] Honda_Acura\r\n"
    "\t[F] Holtek-HT6P20_000D3E1A_c0.sub 1404b\r\n"
    "\t[F] raw_31500_54876.sub 214b\r\n"
    "\t[F] .gitattributes 66b\r\n"
    ">: "
)


def parse_listing(text):
    """Mirror the tool's listing parser without touching a serial port."""
    dirs, files = [], []
    for ln in text.splitlines():
        ln = ln.rstrip()
        m = fp.FILE_RE.match(ln)
        if m:
            files.append((m.group(1), int(m.group(2))))
            continue
        m = fp.LIST_RE.match(ln)
        if m and m.group(1) == "D":
            dirs.append(m.group(2))
    return dirs, files


def read_body(raw, path, size):
    """Mirror read_file's framing without a serial port."""
    head = f"storage read {path}".encode()
    body = raw.split(head, 1)[1] if head in raw else raw
    if body.endswith(b">: "):
        body = body[:-3]
    body = body.strip(b"\r")
    while body.startswith(b"\n"):
        body = body[1:]
    if body.endswith(b"\n\n"):
        body = body[:-2]
    if len(body) < size:
        return None
    return body[:size]


def main():
    check("tool present", (ROOT / "tools/flipper_pull.py").exists())

    dirs, files = parse_listing(LISTING)
    check("directories parsed", dirs == ["assets", "Honda_Acura"], str(dirs))
    check("files parsed with sizes",
          files == [("Holtek-HT6P20_000D3E1A_c0.sub", 1404),
                    ("raw_31500_54876.sub", 214),
                    (".gitattributes", 66)], str(files))
    check("echo line is not a directory", "storage list /ext/subghz" not in dirs)

    # read_file framing: echoed command, leading CRLF, trailing CRLFCRLF + prompt.
    payload = b"Filetype: Flipper SubGhz RAW File\nVersion: 1\nRAW_Data: 1 -2 3\n"
    raw = b"storage read /ext/subghz/x.sub\r\n" + payload + b"\r\n\r\n>: "
    got = read_body(raw, "/ext/subghz/x.sub", len(payload))
    check("read strips echo and prompt", got == payload,
          f"got {got!r}")

    # A short read (prompt missed, payload truncated) must be reported, not kept.
    short = b"storage read /ext/subghz/x.sub\r\n" + payload[:10] + b"\r\n\r\n>: "
    check("short read is rejected", read_body(short, "/ext/subghz/x.sub", len(payload)) is None)

    # Trailing banner the CLI appends to some reads is not part of the payload.
    banner = (b"storage read /ext/subghz/y.sub\r\n" + payload +
              b"\r\n\r\nFiletype: Flipper SubGhz RAW File\r\n>: ")
    got = read_body(banner, "/ext/subghz/y.sub", len(payload))
    check("payload clipped to the listed size", got == payload, f"got {got!r}")

    # Live half: only if the card answers.
    if Path(fp.DEFAULT_PORT).exists():
        try:
            flip = fp.open_cli(fp.DEFAULT_PORT)
            dirs, files = fp.listing(flip, "/ext/subghz")
            flip.close()
            check("live listing returns entries", bool(files),
                  f"{len(dirs)} dirs, {len(files)} files")
            names = {n for n, _ in files}
            check("live listing sees a known capture",
                  any(n.endswith(".sub") for n in names), f"{len(names)} names")
        except Exception as exc:  # noqa: BLE001 - report, do not crash the suite
            check("live listing", False, repr(exc))
    else:
        print("SKIP live half — no Flipper on " + fp.DEFAULT_PORT)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
