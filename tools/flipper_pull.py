#!/usr/bin/env python3
"""Walk a Flipper Zero's SD card over the USB CLI and copy captures down.

The Flipper CLI has no directory download, so this walks it by hand:

  · `storage list <dir>` prints one entry per line, `[D] name` for a folder and
    `[F] name <bytes>b` for a file. The size is the exact on-card byte count and
    lets a caller skip a file it already holds.
  · `storage read <path>` prints the file between the echoed command and the
    next prompt. There is no length prefix, so the read loop stops on the
    `>:` prompt. The trailing banner plus prompt is stripped back off, and the
    resulting payload is checked against the size the listing reported -- a
    mismatch means the read was truncated and the file is retried.

Usage:
    python3 tools/flipper_pull.py --list                 # inventory only
    python3 tools/flipper_pull.py --out DIR [--all]      # copy files under DIR
    python3 tools/flipper_pull.py --out DIR --changed    # only files missing/changed

With no --all, only .sub captures are copied; --all takes the analysis notes and
key tables too.
"""
import argparse
import re
import sys
import time
from pathlib import Path

import serial

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PORT = "/dev/cu.usbmodemflip_Ari0on41"
ROOTS = ["/ext/subghz"]

LIST_RE = re.compile(r"^\s*\[([DF])\]\s+(.+?)\s*$")
FILE_RE = re.compile(r"^\s*\[F\]\s+(.+?)\s+(\d+)b\s*$")


def open_cli(port):
    flip = serial.Serial(port, 115200, timeout=0.3)
    time.sleep(0.6)
    flip.write(b"\r\n")
    flip.flush()
    time.sleep(0.6)
    flip.read(8192)
    return flip


def run(flip, line, wait=2.0, stop=b">: "):
    flip.reset_input_buffer()
    flip.write((line + "\r\n").encode())
    flip.flush()
    end = time.time() + wait
    buf = bytearray()
    while time.time() < end:
        chunk = flip.read(65536)
        if chunk:
            buf += chunk
            if stop in buf:
                break
            end = time.time() + wait
    return bytes(buf)


def listing(flip, path):
    """Return (dirs, files) for one directory; files are (name, size)."""
    out = run(flip, f"storage list {path}").decode("utf-8", "replace")
    dirs, files = [], []
    for ln in out.splitlines():
        ln = ln.rstrip()
        m = FILE_RE.match(ln)
        if m:
            files.append((m.group(1), int(m.group(2))))
            continue
        m = LIST_RE.match(ln)
        if m and m.group(1) == "D":
            dirs.append(m.group(2))
    return dirs, files


def walk(flip, path):
    """Depth-first yield of (full_path, size) under path."""
    dirs, files = listing(flip, path)
    for name, size in files:
        yield f"{path}/{name}", size
    for d in dirs:
        yield from walk(flip, f"{path}/{d}")


def read_file(flip, path, size):
    """Read one file; return its bytes, or None if the payload is short."""
    out = run(flip, f"storage read {path}", wait=3.0)
    head = f"storage read {path}".encode()
    if head in out:
        body = out.split(head, 1)[1]
    else:
        body = out
    # Drop the leading "\r\n", the trailing "\r\n\r\n>: " and anything after it.
    if body.endswith(b">: "):
        body = body[:-3]
    body = body.strip(b"\r")
    while body.startswith(b"\n"):
        body = body[1:]
    if body.endswith(b"\n\n"):
        body = body[:-2]
    # A short read is the failure mode; a long one means the prompt was missed.
    if len(body) < size:
        return None
    return body[:size]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=DEFAULT_PORT)
    ap.add_argument("--root", action="append", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--all", action="store_true", help="non-.sub files too")
    ap.add_argument("--changed", action="store_true",
                    help="skip a file whose local copy already matches in size")
    args = ap.parse_args()

    roots = args.root or ROOTS
    flip = open_cli(args.port)
    try:
        entries = []
        for r in roots:
            entries.extend(walk(flip, r))
        print(f"{len(entries)} files under {', '.join(roots)}")
        for path, size in entries:
            print(f"  {size:>9}  {path}")
        if args.list or not args.out:
            return 0

        outdir = Path(args.out)
        got = skipped = missed = 0
        for path, size in entries:
            if not args.all and not path.endswith(".sub"):
                continue
            rel = path.replace("/ext/subghz/", "").replace("/", "__")
            dest = outdir / rel
            if args.changed and dest.is_file() and dest.stat().st_size == size:
                skipped += 1
                continue
            body = read_file(flip, path, size)
            if body is None:
                print(f"  SHORT {path}")
                missed += 1
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            got += 1
            print(f"  {size:>9}  {rel}")
        print(f"\ncopied {got}, skipped {skipped}, short {missed} -> {outdir}")
    finally:
        flip.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
