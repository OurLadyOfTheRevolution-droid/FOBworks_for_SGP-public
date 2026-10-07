#!/usr/bin/env python3
"""KeeLoq related-key / clone-key lab.

Three things a bench can actually do with a clone fob and two of its hops:

  1. Cipher check. The KeeLoq NLFSR the card runs, reproduced on the host and
     checked against the three published vectors the firmware also self-tests on.
     If this fails nothing below it means anything.

  2. Same-key oracle. Two hops from one button give E(ptA) ^ E(ptB) with both
     plaintexts known (counter, serial and button are on the wire). A candidate key
     predicts that XOR with two encryptions, so the observed XOR is a one-bit-per-key
     filter over a candidate set. This is the hop-XOR strip used as a
     *test*, not a picture — the observable is the same, the use is the point N15
     raised.

  3. Clone-batch harvest. Cheap clone chips rarely use a real 64-bit key; the vendors
     build them from a small alphabet or a repeating pattern. With one
     hop-XOR filter in hand, the whole constrained space is a few thousand candidates
     instead of 2^64, and it recovers. This is a real, bounded, end-to-end key recovery
     for the clone case — and only the clone case.

What this is not: a break of an OEM KeeLoq fob. The full slide/meet-in-the-middle of
Indesteege (EUROCRYPT 2008) wants 2^16 known plaintexts and is not run here; the tool
reports the alignment condition and the cost so a reader can see where the wall is
rather than read a claim that is not backed. An OEM fob cannot be mashed for 65536
plaintexts; a clone fob on the bench can.
"""

from __future__ import annotations

import argparse
import itertools
import struct
import sys
import time
from dataclasses import dataclass

# ─── the cipher (matches FOBworks_for_SGP.ino ks_klEncrypt / ks_klDecrypt) ──────
# Microchip TB003 / AN742 normal-learn scheme. NLF taps plaintext bits 1,9,20,26,31;
# key bit i%64 is used directly each round; the new bit enters at bit 31.

NLF = 0x3A5C742E


def _nlf(x: int) -> int:
    return (NLF >> (x & 31)) & 1


def _bit(x: int, n: int) -> int:
    return (x >> n) & 1


def key_bit(key: int, i: int) -> int:
    return (key >> (i % 64)) & 1


def encrypt(plain: int, key: int) -> int:
    plain &= 0xFFFFFFFF
    for i in range(528):
        g = _nlf(_bit(plain, 1) | _bit(plain, 9) << 1 | _bit(plain, 20) << 2
                 | _bit(plain, 26) << 3 | _bit(plain, 31) << 4)
        b = (plain ^ (plain >> 16) ^ key_bit(key, i) ^ g) & 1
        plain = (plain >> 1) | (b << 31)
    return plain & 0xFFFFFFFF


def decrypt(cipher: int, key: int) -> int:
    cipher &= 0xFFFFFFFF
    for i in range(527, -1, -1):
        b = (cipher >> 31) & 1
        cipher = (cipher << 1) & 0xFFFFFFFF
        g = _nlf(_bit(cipher, 1) | _bit(cipher, 9) << 1 | _bit(cipher, 20) << 2
                 | _bit(cipher, 26) << 3 | _bit(cipher, 31) << 4)
        bit0 = (b ^ _bit(cipher, 16) ^ key_bit(key, i) ^ g) & 1
        cipher = (cipher & ~1) | bit0
    return cipher & 0xFFFFFFFF


# The same three vectors the card latches at boot (ks_klSelfTest).
TEST_VECTORS = [
    (0x2000C022, 0xBEEFDEADBEEFDEAD, 0x054C90C2),
    (0xF741E2DB, 0x5CEC6701B79FD949, 0xE44F4CDF),
    (0x0CA69B92, 0x5CEC6701B79FD949, 0xA6AC0EA2),
]


def self_test() -> tuple[int, int]:
    """Return (passed, total). Both directions, every vector."""
    passed = 0
    for plain, key, cipher in TEST_VECTORS:
        if encrypt(plain, key) == cipher and decrypt(cipher, key) == plain:
            passed += 1
    return passed, len(TEST_VECTORS)


# ─── frame layout ──────────────────────────────────────────────────────────────
# A plaintext is ctr[15:0] | serial[9:0]<<16 | btn[3:0]<<28, the layout the Kia V3/V4
# builder uses. A wire frame gives serial and button directly; the counter the
# receiver sees is the low 16 bits, which is what a hop-XOR pair advances by one.

@dataclass(frozen=True)
class Hop:
    """One observed hop: the wire fields plus the 32-bit hopping code."""
    serial: int
    button: int
    counter: int
    hop: int

    def plain(self) -> int:
        return (self.counter & 0xFFFF) | ((self.serial & 0x3FF) << 16) | ((self.button & 0xF) << 28)


def observed_xor(a: Hop, b: Hop) -> int:
    """The hop-XOR a receiver-agnostic observer sees: E(ptA) ^ E(ptB)."""
    return (a.hop ^ b.hop) & 0xFFFFFFFF


def candidate_xor(pt_a: int, pt_b: int, key: int) -> int:
    return encrypt(pt_a, key) ^ encrypt(pt_b, key)


def key_matches_xor(a: Hop, b: Hop, key: int) -> bool:
    """One candidate, one XOR test. The whole oracle: two encryptions per key."""
    return candidate_xor(a.plain(), b.plain(), key) == observed_xor(a, b)


# ─── same-key oracle across more than two hops ─────────────────────────────────
# Two hops give one 32-bit equation, which is a strong but not unique filter. A third
# hop adds another equation from the same key; the intersection is where a candidate
# set collapses. Order matters for neither the XOR nor the test.

def key_matches_all(hops: list[Hop], key: int) -> bool:
    if len(hops) < 2:
        raise ValueError("need at least two hops")
    for i in range(len(hops) - 1):
        if not key_matches_xor(hops[i], hops[i + 1], key):
            return False
    return True


# ─── clone-batch keyspace ─────────────────────────────────────
# Clone vendors build keys from a small alphabet or a repeating pattern. Enumerate the
# constrained space, not 2^64.

def keys_from_alphabet(alphabet: bytes) -> set[int]:
    """Every 8-byte key whose bytes are drawn from `alphabet`. |alphabet|^8 keys."""
    return {int.from_bytes(bytes(t), "big") for t in itertools.product(alphabet, repeat=8)}


def keys_from_pattern(pattern: bytes, length: int = 8) -> set[int]:
    """Keys that are `pattern` tiled to `length` bytes."""
    if not pattern:
        return set()
    tiled = (pattern * (length // len(pattern) + 1))[:length]
    return {int.from_bytes(tiled, "big")}


def keys_from_repeated_byte() -> set[int]:
    """The single-repeated-byte family — 256 keys, the classic clone default."""
    return {0x0101010101010101 * b for b in range(256)}


def harvest(hops: list[Hop], candidates: set[int], limit: int = 16) -> list[int]:
    """Return every candidate key consistent with the observed hop-XOR chain."""
    hits = []
    for k in candidates:
        if key_matches_all(hops, k):
            hits.append(k)
            if len(hits) >= limit:
                break
    return hits


# ─── the wall: Indesteege slide / MITM alignment (documented, not executed) ─────
# KeeLoq is a 528-round NLFSR whose round key is bit i%64 of the 64-bit key. Two keys
# k and k' are a slide pair candidate when the round-key sequences line up: if
# k' = rot(k, r) then round i of k uses the same bit as round i+r of k'. This is the
# necessary structural condition; the attack then needs 2^16 known plaintexts to find
# a slid pair by birthday. Reported so the cost is visible, not claimed.

def rotation_shift(k0: int, k1: int, max_shift: int = 63) -> int | None:
    """If k1 == rot_right(k0, r) for some r in 1..max_shift, return r, else None."""
    for r in range(1, max_shift + 1):
        rot = ((k0 >> r) | (k0 << (64 - r))) & 0xFFFFFFFFFFFFFFFF
        if rot == k1:
            return r
    return None


def slide_cost(known_plaintexts: int) -> dict:
    """The birthday cost of finding a slid pair, and whether this run is near it."""
    # A slid pair turns up once ~2^16 plaintexts are seen (32-bit block, birthday).
    threshold = 1 << 16
    return {
        "known_plaintexts": known_plaintexts,
        "birthday_threshold": threshold,
        "fraction_of_threshold": known_plaintexts / threshold,
        "practical_on_laptop": known_plaintexts >= threshold,
        "note": ("an OEM fob cannot be mashed for this many plaintexts; a clone fob on "
                 "the bench can, which is why N6's constrained search is the practical "
                 "half and this is the documented half"),
    }


# ─── synthetic fob, for the self-test and the demo ─────────────────────────────

def synth_hops(serial: int, button: int, counter0: int, key: int, n: int = 3) -> list[Hop]:
    hops = []
    for i in range(n):
        ctr = counter0 + i
        h = Hop(serial, button, ctr, encrypt(
            (ctr & 0xFFFF) | ((serial & 0x3FF) << 16) | ((button & 0xF) << 28), key))
        hops.append(h)
    return hops


# ─── CLI ───────────────────────────────────────────────────────────────────────

def _fmt_key(k: int) -> str:
    return f"0x{k:016X}"


def _cmd_selftest() -> int:
    p, t = self_test()
    print(f"KeeLoq self-test: {p}/{t} vectors pass")
    return 0 if p == t else 1


def _cmd_oracle(args: argparse.Namespace) -> int:
    """Is this candidate the key? Feed it hops, get a yes/no per key."""
    hops = [Hop(args.serial, args.button, args.counter + i, 0) for i in range(0)]
    hops = synth_hops(args.serial, args.button, args.counter, args.key, args.hops)
    cand = args.candidate
    ok = key_matches_all(hops, cand)
    print(f"observed hops: {args.hops}")
    for h in hops:
        print(f"  ctr {h.counter:5d}  hop 0x{h.hop:08X}")
    print(f"candidate {_fmt_key(cand)}: {'MATCH' if ok else 'no match'}")
    return 0 if ok else 1


def _cmd_harvest(args: argparse.Namespace) -> int:
    """Recover a clone key from its hops within a constrained keyspace."""
    key = args.key
    hops = synth_hops(args.serial, args.button, args.counter, key, args.hops)
    if args.alphabet:
        space = keys_from_alphabet(bytes(args.alphabet.encode()))
        label = f"alphabet {args.alphabet!r} ({len(space)} keys)"
    elif args.pattern:
        space = keys_from_pattern(bytes.fromhex(args.pattern))
        label = f"pattern {args.pattern} ({len(space)} keys)"
    else:
        space = keys_from_repeated_byte()
        label = f"repeated byte ({len(space)} keys)"
    print(f"target key {_fmt_key(key)}   space: {label}   hops: {args.hops}")
    t0 = time.time()
    hits = harvest(hops, space)
    dt = time.time() - t0
    print(f"searched {len(space)} candidates in {dt*1000:.1f} ms; {len(hits)} consistent")
    for k in hits:
        mark = "  <- target" if k == key else ""
        print(f"  {_fmt_key(k)}{mark}")
    return 0 if key in hits else 1


def _cmd_slide(args: argparse.Namespace) -> int:
    """Report the slide alignment condition and the cost of going further."""
    k0, k1 = args.k0, args.k1
    r = rotation_shift(k0, k1)
    print(f"k0 {_fmt_key(k0)}\nk1 {_fmt_key(k1)}")
    if r is None:
        print("no rotation alignment: k0 and k1 are not a slide pair by rotation")
    else:
        print(f"rotation alignment at r={r}: round i of k0 shares a key bit with "
              f"round i+{r} of k1")
    cost = slide_cost(args.plaintexts)
    print(f"known plaintexts {cost['known_plaintexts']} "
          f"({cost['fraction_of_threshold']:.3%} of the 2^16 birthday threshold)")
    print(cost["note"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="KeeLoq related-key / clone-key lab")
    sub = p.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("selftest", help="cipher vectors")
    st.set_defaults(func=lambda a: _cmd_selftest())

    o = sub.add_parser("oracle", help="test one candidate key against synthetic hops")
    o.add_argument("--serial", type=lambda s: int(s, 0), default=0x0A1B2CE7)
    o.add_argument("--button", type=int, default=3)
    o.add_argument("--counter", type=int, default=0x100)
    o.add_argument("--key", type=lambda s: int(s, 0), default=0xBEEFDEADBEEFDEAD)
    o.add_argument("--candidate", type=lambda s: int(s, 0), required=True)
    o.add_argument("--hops", type=int, default=3)
    o.set_defaults(func=_cmd_oracle)

    h = sub.add_parser("harvest", help="recover a clone key within a constrained space")
    h.add_argument("--serial", type=lambda s: int(s, 0), default=0x0A1B2CE7)
    h.add_argument("--button", type=int, default=3)
    h.add_argument("--counter", type=int, default=0x100)
    h.add_argument("--key", type=lambda s: int(s, 0), required=True)
    h.add_argument("--alphabet", type=str, default=None, help="e.g. 'AB' -> A,B bytes")
    h.add_argument("--pattern", type=str, default=None, help="hex, e.g. 'deadbeef'")
    h.add_argument("--hops", type=int, default=3)
    h.set_defaults(func=_cmd_harvest)

    s = sub.add_parser("slide", help="rotation alignment and slide cost")
    s.add_argument("--k0", type=lambda s: int(s, 0), required=True)
    s.add_argument("--k1", type=lambda s: int(s, 0), required=True)
    s.add_argument("--plaintexts", type=int, default=1 << 16)
    s.set_defaults(func=_cmd_slide)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
