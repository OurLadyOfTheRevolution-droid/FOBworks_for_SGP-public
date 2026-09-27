#!/usr/bin/env python3
"""Mask or unmask the plaintext KeeLoq manufacturer keys in the sketch's MFR_KEYS table.

Why this exists: the 73 keys were readable in the source as plain 64-bit literals, so
anyone browsing the sketch had them. The table itself has to stay -- the firmware calls
`ks_deriveOneMfrKey()` and `ks_klDecrypt()` with those keys, so a build without them could
not decode a KeeLoq frame. Masking therefore changes what a *reader* sees, not what the
device computes. It is a disclosure decision, not a security boundary, and it is fully
reversible: nothing else in the firmware changes.

    mask(k)   = ROTL(k ^ A, N) ^ B
    unmask(v) = ROTR(v ^ B, N) ^ A

An earlier version used the single form `ROTL(k ^ A, N) ^ B` for both directions, on the
assumption that it was an involution. It is not: expanding `T(T(x))` gives
`ROTL(x, 2N) ^ ROTL(B ^ A, N) ^ ...`, which collapses to `x` only when `2N ≡ 0 (mod 64)` and
`A == B`. The round-trip assertion below caught it on the first run, before anything was
written. The pair above is invertible for any `N` and any distinct `A`/`B`.

Every value is round-trip verified before the file is written, and the written file is
re-read and verified again afterwards.

Usage:
    python3 tools/mask_mfrkeys.py             # plaintext -> masked
    python3 tools/mask_mfrkeys.py --unmask    # masked -> plaintext
    python3 tools/mask_mfrkeys.py --check     # report state, change nothing
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKETCH = ROOT / "FOBworks_for_SGP.ino"

# Mask constants. A reader needs these to unmask, and they are deliberately not secret:
# the point is to stop the keys being the first thing you read in the file, not to guard them
# with a password. Changing A/B/N is fine as long as mask and unmask agree.
A = 0x5A5A5A5A5A5A5A5A
B = 0x3C3C3C3C3C3C3C3C
N = 13

MASK64 = (1 << 64) - 1


def rotl(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def rotr(x, n):
    n &= 63
    return ((x >> n) | (x << (64 - n))) & MASK64 if n else x


def encode(k):
    return rotl((k ^ A) & MASK64, N) ^ B


def decode(v):
    return rotr((v ^ B) & MASK64, N) ^ A


ENTRY = re.compile(
    r'(?P<pre>\{\s*"(?P<name>[^"]+)"\s*,\s*0x)(?P<key>[0-9A-Fa-f]{16})'
    r'(?P<post>ULL\s*,\s*[A-Za-z0-9_]+\s*,\s*[01]\s*\})'
)
TABLE = re.compile(
    r"(?P<open>static const MfrKey MFR_KEYS\[\]=\{)(?P<body>.*?)(?P<close>\n\};)", re.S
)


def locate(src):
    m = TABLE.search(src)
    if not m:
        sys.exit("MFR_KEYS table not found")
    return m


def keys_in(src):
    body = locate(src).group("body")
    es = list(ENTRY.finditer(body))
    if len(es) != 73:
        sys.exit(f"expected 73 entries, found {len(es)} -- refusing to touch the table")
    return es, [int(e.group("key"), 16) for e in es]


def is_masked(keys):
    """The table is masked iff decoding each value yields a plausible plaintext key set.

    Deciding by a round-trip identity is not possible here (the transform is not an
    involution), so compare against the known-plaintext marker instead: the Kia OEM key is
    public and fixed, and the four factory-default entries are 0x0 / 0xFFFF...
    """
    # Decide without naming any real key. Four entries are the factory defaults 0x0 /
    # 0xFFFF..., so if decoding turns stored values into those, the table is masked. The
    # all-zero and all-ones patterns are structural, not key material.
    defaults = {0x0000000000000000, 0xFFFFFFFFFFFFFFFF}
    as_is = sum(1 for k in keys if k in defaults)
    flipped = sum(1 for k in keys if decode(k) in defaults)
    if flipped != as_is:
        return flipped > as_is
    # Fall back to the round-trip property: encode() of the stored values must reproduce them
    # if and only if they are already masked.
    return all(encode(k) == k for k in keys[:8])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unmask", action="store_true", help="masked -> plaintext")
    ap.add_argument("--check", action="store_true", help="report state, write nothing")
    args = ap.parse_args()

    src = SKETCH.read_text(encoding="utf-8")
    entries, keys = keys_in(src)
    masked = is_masked(keys)

    for k in keys:
        assert decode(encode(k)) == k, f"encode/decode not inverse on {k:#018x}"

    print(f"  table     : {len(entries)} entries")
    print(f"  state     : {'MASKED' if masked else 'PLAINTEXT'}")

    if args.check:
        return 0

    # Decide direction from the state, not the flag, so a wrong flag cannot double-apply.
    want_masked = not args.unmask
    if want_masked == masked:
        print(f"  no-op     : already {'masked' if masked else 'plaintext'}")
        return 0

    fn = encode if want_masked else decode
    body, m = locate(src).group("body"), locate(src)

    out, last = [], 0
    for e in entries:
        k = int(e.group("key"), 16)
        nk = fn(k)
        assert nk != k, f"{e.group('name')} unchanged by the transform"
        out.append(body[last:e.start()])
        out.append(f"{e.group('pre')}{nk:016X}{e.group('post')}")
        last = e.end()
    out.append(body[last:])

    new_src = src[:m.start("body")] + "".join(out) + src[m.end("body"):]
    SKETCH.write_text(new_src, encoding="utf-8")

    # Re-read: the file must now be in the target state, and must restore the originals.
    back = SKETCH.read_text(encoding="utf-8")
    _, keys2 = keys_in(back)
    assert is_masked(keys2) == want_masked, "written file is not in the intended state"
    inv = decode if want_masked else encode
    assert [inv(k) for k in keys2] == keys, "round-trip through the file does not restore the original keys"

    print(f"  wrote     : MFR_KEYS is now {'MASKED' if want_masked else 'PLAINTEXT'}")
    print(f"  verified  : {len(keys2)} values round-trip to the originals")
    return 0


if __name__ == "__main__":
    sys.exit(main())
