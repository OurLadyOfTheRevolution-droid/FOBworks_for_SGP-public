#!/usr/bin/env python3
"""Host harness for the KeeLoq related-key / clone-key lab.

Two independent things are pinned here:

  1. The lab's Python cipher is the card's cipher. `tools/keeloq_slide_lab.py` is a
     fresh implementation, so it is checked against the firmware's own published
     vectors AND against the shipped `ks_klEncrypt`/`ks_klDecrypt`, extracted from the
     .ino and compiled with clang++ into a tiny oracle. If the host tool ever drifts
     from the card, that fails here rather than at the bench.

  2. The hop-XOR oracle recovers a constrained (clone-batch) key, and only a
     constrained key — the point of N15 is that the observable is a *filter*, and the
     point of N6 is that the clone case is small enough for the filter to finish.
     The OEM case is asserted to stay out of reach: a random 64-bit key is NOT in any
     repeated-byte/pattern space the tool searches, so the tool must not claim it is.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
sys.path.insert(0, str(ROOT / "tools"))

import keeloq_slide_lab as lab  # noqa: E402

FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def extract_fn(src, signature):
    pat = re.compile(r"^static\s+[^\n(]*?\b" + re.escape(signature) +
                     r"\s*\([^{;]*?\)\s*\{", re.M | re.S)
    m = pat.search(src)
    if not m:
        return None
    i = src.index("{", m.start())
    depth = 0
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    return None


def main():
    src = SRC.read_text(encoding="utf-8")
    print("=== the lab cipher matches the card's published vectors ===")
    p, t = lab.self_test()
    check(p == t == 3, f"all {t} KeeLoq vectors pass in the host implementation")
    check("#define KL_NLF    0x3A5C742EUL" in src, "NLF constant matches the firmware")

    print("\n=== the lab cipher matches the shipped ks_klEncrypt byte for byte ===")
    enc = extract_fn(src, "ks_klEncrypt")
    dec = extract_fn(src, "ks_klDecrypt")
    check(enc is not None, "ks_klEncrypt extracted from the firmware")
    check(dec is not None, "ks_klDecrypt extracted from the firmware")
    if enc and dec:
        harness = (
            "#include <stdio.h>\n#include <stdint.h>\n"
            "#define KL_NLF 0x3A5C742EUL\n"
            "static inline uint32_t ks_nlf(uint32_t x){return (KL_NLF>>(x&31))&1;}\n"
            "static inline uint32_t ks_bit(uint32_t x,uint8_t n){return (x>>n)&1;}\n"
            + enc + "\n" + dec + "\n"
            + "int main(void){\n"
            "  uint32_t pts[3] = {0x2000C022UL, 0xF741E2DBUL, 0x0CA69B92UL};\n"
            "  uint64_t ks[3] = {0xBEEFDEADBEEFDEADULL, 0x5CEC6701B79FD949ULL, 0x5CEC6701B79FD949ULL};\n"
            "  for(int i=0;i<3;i++) printf(\"%08lX\\n\", (unsigned long)ks_klEncrypt(pts[i],ks[i]));\n"
            "  // and a round-trip on one extra pair\n"
            "  uint32_t c = ks_klEncrypt(0x2000C022UL, 0xBEEFDEADBEEFDEADULL);\n"
            "  printf(\"%08lX\\n\", (unsigned long)ks_klDecrypt(c, 0xBEEFDEADBEEFDEADULL));\n"
            "  return 0;\n}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp) / "t.cpp"
            tp.write_text(harness)
            exe = str(Path(tmp) / "t")
            r = subprocess.run(["clang++", "-O1", "-std=c++17", "-o", exe, str(tp)],
                               capture_output=True, text=True)
            check(r.returncode == 0, f"firmware cipher harness compiles {r.stderr[:160]}")
            if r.returncode == 0:
                out = subprocess.run([exe], capture_output=True, text=True).stdout.split()
                card = [int(x, 16) for x in out[:3]]
                host = [lab.encrypt(pl, k) for pl, k in
                        zip((0x2000C022, 0xF741E2DB, 0x0CA69B92),
                            (0xBEEFDEADBEEFDEAD, 0x5CEC6701B79FD949, 0x5CEC6701B79FD949))]
                check(card == host, "card and host agree on all three encrypted vectors")
                check(int(out[3], 16) == 0x2000C022,
                      "card decrypt round-trips the extra pair (sanity on the extracted code)")

    print("\n=== the hop-XOR oracle is a real filter ===")
    synth = 0xBEEFDEADBEEFDEAD  # synthetic; the lab never needs a real manufacturer key
    hops = lab.synth_hops(0x0A1B2CE7, 3, 0x100, synth, 3)
    check(lab.key_matches_all(hops, synth), "the true key passes the XOR filter")
    check(not lab.key_matches_all(hops, (synth ^ 1) & 0xFFFFFFFFFFFFFFFF),
          "a one-bit neighbour fails it — the filter bites")

    print("\n=== clone-batch harvest: a constrained key is recovered ===")
    # A clone key built from a two-byte alphabet — the N6 case.
    clone = int.from_bytes(b"ABABABAB", "big")
    chops = lab.synth_hops(0x0A1B2CE7, 3, 0x100, clone, 3)
    space = lab.keys_from_alphabet(b"AB")
    check(len(space) == 256, "a two-byte alphabet is a 256-key space")
    hits = lab.harvest(chops, space)
    check(hits == [clone], "the harvest returns exactly the clone key")
    # repeated-byte family
    rbkey = 0x7E7E7E7E7E7E7E7E
    rbh = lab.harvest(lab.synth_hops(0x0A1B2CE7, 3, 0x100, rbkey, 3),
                      lab.keys_from_repeated_byte())
    check(rbkey in rbh, "the repeated-byte family recovers a repeated-byte key")
    # tiled pattern
    pk = int.from_bytes(bytes.fromhex("deadbeefdeadbeef"), "big")
    pkh = lab.harvest(lab.synth_hops(0x0A1B2CE7, 3, 0x100, pk, 3),
                      lab.keys_from_pattern(bytes.fromhex("deadbeef")))
    check(pk in pkh, "the pattern family recovers a tiled-pattern key")

    print("\n=== an OEM key stays out of reach (honesty check) ===")
    oem = 0x5CEC6701B79FD949  # a random-looking 64-bit key
    ohops = lab.synth_hops(0x0A1B2CE7, 3, 0x100, oem, 3)
    all_space = set()
    all_space |= lab.keys_from_alphabet(b"AB")
    all_space |= lab.keys_from_repeated_byte()
    all_space |= lab.keys_from_pattern(bytes.fromhex("deadbeef"))
    check(oem not in all_space, "a random 64-bit key is not in the clone space (by construction)")
    check(lab.harvest(ohops, all_space) == [],
          "the clone space yields no key for an OEM-style key — no false claim")

    print("\n=== the slide half is documented, and its cost is reported ===")
    k0 = 0xBEEFDEADBEEFDEAD
    k1 = ((k0 >> 8) | (k0 << 56)) & 0xFFFFFFFFFFFFFFFF  # rot_right by 8
    check(lab.rotation_shift(k0, k1) == 8, "a rotation pair is detected at r=8")
    check(lab.rotation_shift(k0, k0 ^ 0xDEAD) is None,
          "an unrelated key reports no alignment")
    cost = lab.slide_cost(1 << 16)
    check(cost["practical_on_laptop"] is True, "2^16 plaintexts meets the slide threshold")
    check(lab.slide_cost(1000)["practical_on_laptop"] is False,
          "a handful of captures does not — the tool does not pretend it does")

    if FAILS:
        print(f"\nFAILURES: {len(FAILS)}")
        for f in FAILS:
            print("  -", f)
        return 1
    print("\nall KeeLoq slide-lab checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
