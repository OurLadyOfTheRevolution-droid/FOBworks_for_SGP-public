#!/usr/bin/env python3
"""A2 — Kia V3/V4 real-capture acceptance test (Python mirror).

This is a faithful transcription of the shipped C decoder, not a reimplementation
from the spec. Each function below mirrors its counterpart in FOBworks_for_SGP.ino:

    ks_kiaV34IsPulse      <- ±te_delta absolute tolerance
    ks_kiaV34PwmAt        <- preamble scan + PWM pair decode
    ks_kiaV34Pwm          <- offset scan, first full frame wins
    ks_kiaV34BitsToBytes  <- big-endian bits within bytes
    ks_kiaV34Extract      <- rev8 per byte, V3 inversion, masked top serial byte
    ks_kiaV34Validate     <- ks_klDecrypt + the 12-bit check
    ks_kiaV34Match        <- 4-bit button + 8-bit serial LSB
    ks_decodeKiaV34       <- V4 (no invert) then V3 (invert)

Before it judges anything it must reproduce BOTH firmware KAT vectors. A mirror
that disagrees with the firmware proves nothing about either, so `--kat` runs
first and `--scan` refuses to report A2 unless the KAT passed.

Usage:
    a2_kia_v34.py --kat                       # verify the mirror against the KAT
    a2_kia_v34.py --scan DIR                  # A2/A3 over DIR (recursive)
    a2_kia_v34.py --scan DIR --json OUT.json  # also write machine-readable results
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

# ── Constants, mirroring the sketch ──────────────────────────────────────────
# Stored masked, matching the firmware's MFR_KEYS entry (see tools/mask_mfrkeys.py).
_KIA_STORED = 0xCC88E6C23CEC0269
_MK_A, _MK_B, _MK_N = 0x5A5A5A5A5A5A5A5A, 0x3C3C3C3C3C3C3C3C, 13
_M64 = (1 << 64) - 1
_x = (_KIA_STORED ^ _MK_B) & _M64
KIA_V34_MF_KEY = (((_x >> _MK_N) | (_x << (64 - _MK_N))) & _M64) ^ _MK_A
# Self-check the inverse structurally, without writing the key out: re-encoding the
# recovered value must return the stored form.
_re = (((KIA_V34_MF_KEY ^ _MK_A) & _M64) << _MK_N | ((KIA_V34_MF_KEY ^ _MK_A) & _M64) >> (64 - _MK_N))
assert (((_re & _M64) ^ _MK_B) & _M64) == _KIA_STORED, "the masked Kia key does not invert"
TE_SHORT = 400
TE_LONG = 800
TE_DELTA = 150
KIA_V34_MIN_BITS = 68
KL_NLF = 0x3A5C742E

# The firmware KAT vectors (both). Vector 2 pins the 10-bit mask: serial[9:8]!=0,
# so an 8-bit mask yields a different plaintext.
KAT = [
    # serial,      btn, ctr,    plaintext,   encrypted
    (0x0A1B2CE7, 0x3, 0x4D2, 0x30E704D2, 0x8686900B),
    (0x0A1B2FE7, 0x3, 0x4D2, 0x33E704D2, 0x10944604),
]

# Published KeeLoq vectors for the cipher self-check (encrypt direction).
KL_VECTORS = [
    (0x2000C022, 0xBEEFDEADBEEFDEAD, 0x054C90C2),
    (0xF741E2DB, 0x5CEC6701B79FD949, 0xE44F4CDF),
    (0x0CA69B92, 0x5CEC6701B79FD949, 0xA6AC0EA2),
]


# ── Cipher: ks_klEncrypt / ks_klDecrypt ──────────────────────────────────────
def ks_nlf(x: int) -> int:
    return (KL_NLF >> (x & 31)) & 1


def ks_kl_encrypt(plain: int, key: int) -> int:
    """Mirror of ks_klEncrypt: 528 rounds, NLF on bits {1,9,20,26,31}."""
    x = plain & 0xFFFFFFFF
    for i in range(528):
        idx = (((x >> 1) & 1) | (((x >> 9) & 1) << 1) | (((x >> 20) & 1) << 2)
               | (((x >> 26) & 1) << 3) | (((x >> 31) & 1) << 4))
        g = ks_nlf(idx)
        b = ((x ^ (x >> 16) ^ (key >> (i % 64)) ^ g) & 1)
        x = ((x >> 1) | (b << 31)) & 0xFFFFFFFF
    return x


def ks_kl_decrypt(cipher: int, key: int) -> int:
    """Mirror of ks_klDecrypt: reverse round order, same key indexing."""
    x = cipher & 0xFFFFFFFF
    for i in range(527, -1, -1):
        b = (x >> 31) & 1
        x = (x << 1) & 0xFFFFFFFF
        idx = (((x >> 1) & 1) | (((x >> 9) & 1) << 1) | (((x >> 20) & 1) << 2)
               | (((x >> 26) & 1) << 3) | (((x >> 31) & 1) << 4))
        g = ks_nlf(idx)
        bit0 = (b ^ ((x >> 16) & 1) ^ (key >> (i % 64)) ^ g) & 1
        x = (x & ~1) | bit0
    return x


# ── Frame helpers ────────────────────────────────────────────────────────────
def ks_kia_v34_rev8(v: int) -> int:
    """8-bit reverse. Mirrors ks_kiaV34Rev8."""
    v &= 0xFF
    v = ((v >> 4) | (v << 4)) & 0xFF
    v = (((v & 0xCC) >> 2) | ((v & 0x33) << 2)) & 0xFF
    v = (((v & 0xAA) >> 1) | ((v & 0x55) << 1)) & 0xFF
    return v


def ks_kia_v34_match(dec: int, btn: int, serial: int) -> bool:
    """Mirror of ks_kiaV34Match: 4-bit button + 8-bit serial LSB."""
    return ((dec >> 28) & 0xF) == (btn & 0xF) and ((dec >> 16) & 0xFF) == (serial & 0xFF)


def ks_kia_v34_build_plain(btn: int, serial: int, ctr: int) -> int:
    """Mirror of ks_kiaV34BuildPlain: cnt | ((serial & 0x3FF) << 16) | (btn << 28)."""
    return ((ctr & 0xFFFF) | ((serial & 0x3FF) << 16) | ((btn & 0xF) << 28)) & 0xFFFFFFFF


def ks_kia_v34_extract(b: bytes, crc_byte: int, invert: bool) -> dict:
    """Mirror of ks_kiaV34Extract."""
    w = [(~x & 0xFF) if invert else x for x in b]
    c = (~crc_byte & 0xFF) if invert else crc_byte
    out = {}
    out["crc"] = (c >> 4) & 0xF
    out["encrypted"] = ((ks_kia_v34_rev8(w[3]) << 24) | (ks_kia_v34_rev8(w[2]) << 16)
                        | (ks_kia_v34_rev8(w[1]) << 8) | ks_kia_v34_rev8(w[0]))
    out["serial"] = ((ks_kia_v34_rev8(w[7] & 0xF0) << 24) | (ks_kia_v34_rev8(w[6]) << 16)
                     | (ks_kia_v34_rev8(w[5]) << 8) | ks_kia_v34_rev8(w[4]))
    out["btn"] = (ks_kia_v34_rev8(w[7]) & 0xF0) >> 4
    return out


def ks_kia_v34_validate(f: dict) -> bool:
    """Mirror of ks_kiaV34Validate."""
    f["decrypted"] = ks_kl_decrypt(f["encrypted"], KIA_V34_MF_KEY)
    if not ks_kia_v34_match(f["decrypted"], f["btn"], f["serial"]):
        f["validated"] = False
        return False
    f["ctr"] = f["decrypted"] & 0xFFFF
    f["validated"] = True
    return True


def ks_kia_v34_is_pulse(v: int, ref: int) -> bool:
    """Mirror of ks_kiaV34IsPulse: absolute ±TE_DELTA."""
    return abs(v - ref) <= TE_DELTA


def ks_kia_v34_is_sync(v: int) -> bool:
    """Mirror of ks_kiaV34IsSync."""
    return 1000 < v < 1500


def ks_kia_v34_pwm_at(buf: list[int], n: int, off: int, parity_high: int,
                      max_bits: int = 1024) -> tuple[str, bool]:
    """Mirror of ks_kiaV34PwmAt.

    One bit per HIGH pulse (te_short -> 0, te_long -> 1); LOW pulses carry
    nothing. Data begins after the SYNC pulse, whose level sets the version.
    Levels are recovered from index parity: the capture starts at a HIGH pulse,
    so indices with (i % 2) == parity_high are HIGH.
    """
    i = off
    hdr = 0
    while (i + 1 < n and ks_kia_v34_is_pulse(buf[i], TE_SHORT)
           and ks_kia_v34_is_pulse(buf[i + 1], TE_SHORT)):
        hdr += 1
        i += 2
    if hdr < 8:
        return "", False

    j = i
    while j < n and not ks_kia_v34_is_sync(buf[j]):
        if not ks_kia_v34_is_pulse(buf[j], TE_SHORT):
            return "", False
        j += 1
    if j >= n:
        return "", False

    sync_high = ((j % 2) == parity_high)
    v3 = not sync_high

    out = []
    k = j + 1
    while k < n and len(out) < max_bits:
        w = buf[k]
        if ks_kia_v34_is_sync(w):
            break
        if (k % 2) == parity_high:
            if ks_kia_v34_is_pulse(w, TE_SHORT):
                out.append("0")
            elif ks_kia_v34_is_pulse(w, TE_LONG):
                out.append("1")
            else:
                break
        k += 1
        if len(out) >= KIA_V34_MIN_BITS + 16:
            break
    if len(out) < KIA_V34_MIN_BITS:
        return "", False
    return "".join(out), v3


def ks_kia_v34_pwm(buf: list[int], n: int) -> tuple[str, bool]:
    """Mirror of ks_kiaV34Pwm: offset and parity scan, first full frame wins."""
    off = 0
    while off + 2 * KIA_V34_MIN_BITS <= n:
        for ph in (0, 1):
            bits, v3 = ks_kia_v34_pwm_at(buf, n, off, ph)
            if bits:
                return bits, v3
        off += 1
    return "", False


def ks_kia_v34_bits_to_bytes(bits: str, nb: int) -> bytes:
    """Mirror of ks_kiaV34BitsToBytes: big-endian within bytes."""
    out = bytearray(9)
    lim = min(nb, 72)
    for i in range(lim):
        if bits[i] == "1":
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)


def ks_decode_kia_v34(buf: list[int], n: int) -> Optional[dict]:
    """Mirror of ks_decodeKiaV34: sync-derived version tried first, then the other."""
    bits, v3_hint = ks_kia_v34_pwm(buf, n)
    if not bits:
        return None
    b = ks_kia_v34_bits_to_bytes(bits, len(bits))
    for pass_ in (0, 1):
        invert = v3_hint if pass_ == 0 else (not v3_hint)
        f = ks_kia_v34_extract(b, b[8], invert)
        f["v3"] = invert
        if ks_kia_v34_validate(f):
            f["nbits"] = len(bits)
            return f
    return None


# ── Content identity ─────────────────────────────────────────────────────────
def md5_of(path: Path) -> str:
    """Content hash, so a capture stored under two names counts once.

    The corpus stores several captures twice; counting them as separate files
    inflated the earlier corroboration line into something that read as
    independent confirmation (doc 09 §1.2).
    """
    h = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── .sub parsing ─────────────────────────────────────────────────────────────
def parse_sub(path: Path) -> dict:
    """Parse a Flipper .sub. Returns metadata plus the unsigned width array.

    RAW_Data holds alternating signed durations: abs() of each entry is the width
    array the decoder sees. Key files carry a decoded payload instead (Protocol /
    Bit / Key / CRC) and have no pulses; see decode_keyfile().
    """
    meta = {"file": path.name, "freq": None, "preset": None, "protocol": None,
            "filetype": None, "key": None, "bits": None, "crc": None, "raw": []}
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("Frequency:"):
                meta["freq"] = int(line.split(":", 1)[1].strip())
            elif line.startswith("Preset:"):
                meta["preset"] = line.split(":", 1)[1].strip()
            elif line.startswith("Protocol:"):
                meta["protocol"] = line.split(":", 1)[1].strip()
            elif line.startswith("Filetype:"):
                meta["filetype"] = line.split(":", 1)[1].strip()
            elif line.startswith("Key:"):
                meta["key"] = line.split(":", 1)[1].strip()
            elif line.startswith("Bit:"):
                meta["bits"] = int(line.split(":", 1)[1].strip())
            elif line.startswith("CRC:"):
                meta["crc"] = int(line.split(":", 1)[1].strip(), 0)
            elif line.startswith("RAW_Data:"):
                meta["raw"].extend(abs(int(x)) for x in re.findall(r"-?\d+", line[9:]))
    return meta


def decode_keyfile(meta: dict) -> Optional[dict]:
    """Decode a Flipper Key file, which stores an already-demodulated payload.

    A Key file holds no pulses, so it exercises the crypto and field-extraction
    path (ks_kiaV34Extract + validate) but NOT the PWM path. That makes it
    complementary evidence rather than a substitute for a RAW capture: it can show
    the key check works on a second device, but not that pulse decoding does.

    Flipper serializes generic.data as b[0]<<56 | b[1]<<48 | ... | b[7], so the
    "Key:" hex is the eight payload bytes in order — exactly the `b[0..7]` that
    ks_kiaV34Extract consumes. The trailing "CRC:" nibble goes in b[8]'s high half.
    CRC4 is never validated (see the firmware header), so this only reproduces the
    stored value for reporting.
    """
    if not meta.get("key"):
        return None
    hexstr = re.sub(r"[^0-9A-Fa-f]", "", meta["key"])
    if len(hexstr) != 16:
        return None                       # not a single 8-byte payload
    b = bytes.fromhex(hexstr)
    crc_byte = ((meta.get("crc") or 0) & 0xF) << 4
    for invert in (False, True):
        f = ks_kia_v34_extract(b, crc_byte, invert)
        f["v3"] = invert
        if ks_kia_v34_validate(f):
            f["nbits"] = meta.get("bits")
            return f
    return None


# ── Verification ─────────────────────────────────────────────────────────────
def verify_kat() -> bool:
    """The mirror must reproduce both KAT vectors and the 3 published vectors."""
    ok = True
    print("=== cipher: 3 published vectors (encrypt direction) ===")
    for i, (pt, key, ct) in enumerate(KL_VECTORS):
        enc = ks_kl_encrypt(pt, key)
        dec = ks_kl_decrypt(ct, key)
        good = (enc == ct) and (dec == pt)
        print(f"  v{i}: enc=0x{enc:08X} want 0x{ct:08X}  dec=0x{dec:08X} want 0x{pt:08X}  "
              f"{'OK' if good else 'FAIL'}")
        ok &= good

    print("\n=== KAT: both firmware vectors ===")
    for i, (serial, btn, ctr, want_pt, want_enc) in enumerate(KAT, 1):
        pt = ks_kia_v34_build_plain(btn, serial, ctr)
        enc = ks_kl_encrypt(pt, KIA_V34_MF_KEY)
        good = (pt == want_pt) and (enc == want_enc)
        print(f"  vector {i}: serial=0x{serial:08X} [9:8]={(serial >> 8) & 3}  "
              f"pt=0x{pt:08X} want 0x{want_pt:08X}  enc=0x{enc:08X} want 0x{want_enc:08X}  "
              f"{'OK' if good else 'FAIL'}")
        ok &= good

    # A mirror that passes the KAT but is blind to the mask is worthless; prove the
    # mask actually matters by checking vector 2 distinguishes 10-bit from 8-bit.
    serial2 = KAT[1][0]
    pt10 = ks_kia_v34_build_plain(0x3, serial2, 0x4D2)
    pt8 = (((0x4D2) | ((serial2 & 0xFF) << 16) | (0x3 << 28)) & 0xFFFFFFFF)
    print(f"\n  mask sensitivity on vector 2: 10-bit=0x{pt10:08X}  8-bit=0x{pt8:08X}  "
          f"{'distinct (good)' if pt10 != pt8 else 'IDENTICAL (vector is useless)'}")
    ok &= (pt10 != pt8)

    print("\nMIRROR KAT " + ("PASS" if ok else "FAIL"))
    return ok


# ── A2 / A3 ──────────────────────────────────────────────────────────────────
KIA_HINTS = ("kia", "hyundai", "genesis", "sportage", "sorento", "spectra",
             "cerato", "carnival", "santa", "sonata", "tucson", "elantra")


def scan(roots: list[Path]) -> dict:
    files: list[Path] = []
    for r in roots:
        files.extend(sorted(r.rglob("*.sub")))

    results = []
    n_raw = n_valid = n_kia_named = n_kia_valid = 0
    n_keyfile = 0
    reached = 0
    # Content hashes so duplicated files cannot be counted as independent
    # corroboration. The corpus stores several captures twice under different
    # names; counting those as separate files overstates the result (doc 09 §1.2).
    seen_hash: dict[str, str] = {}   # md5 -> first filename seen

    for path in files:
        meta = parse_sub(path)
        digest = md5_of(path)
        rec = {"file": str(path), "name": path.name, "freq": meta["freq"],
               "preset": meta["preset"], "protocol": meta["protocol"],
               "n_pulses": len(meta["raw"]), "validated": False,
               "md5": digest, "duplicate_of": seen_hash.get(digest)}
        if digest not in seen_hash:
            seen_hash[digest] = path.name
        rec["unique"] = (rec["duplicate_of"] is None)
        low = path.name.lower()
        rec["kia_named"] = any(h in low for h in KIA_HINTS)

        if meta["raw"]:
            n_raw += 1
            bits, _ = ks_kia_v34_pwm(meta["raw"], len(meta["raw"]))
            if len(bits) >= KIA_V34_MIN_BITS:
                reached += 1
                rec["n_bits"] = len(bits)
            out = ks_decode_kia_v34(meta["raw"], len(meta["raw"]))
            if out:
                n_valid += 1
                rec.update(validated=True, version="V3" if out["v3"] else "V4",
                           serial=out["serial"], btn=out["btn"], ctr=out["ctr"],
                           crc=out["crc"], encrypted=out["encrypted"],
                           decrypted=out["decrypted"], source="raw")
                if rec["kia_named"]:
                    n_kia_valid += 1
        else:
            # Key file: an already-demodulated payload. Exercises the crypto and
            # field-extraction path but NOT the PWM path, so it is recorded as a
            # separate evidence class and never counted as a RAW validation.
            out = decode_keyfile(meta)
            if out:
                n_valid += 1
                n_keyfile += 1
                rec.update(validated=True, version="V3" if out["v3"] else "V4",
                           serial=out["serial"], btn=out["btn"], ctr=out["ctr"],
                           crc=out["crc"], encrypted=out["encrypted"],
                           decrypted=out["decrypted"], source="keyfile",
                           n_bits=out.get("nbits"))
                if rec["kia_named"]:
                    n_kia_valid += 1
                rec["raw"] = []
        if rec["kia_named"]:
            n_kia_named += 1
        results.append(rec)

    n_valid_unique = sum(1 for r in results if r["validated"] and r["unique"])
    n_kia_valid_unique = sum(1 for r in results
                             if r["validated"] and r["kia_named"] and r["unique"])
    return {"files": len(files), "raw": n_raw, "reached68": reached,
            "validated": n_valid, "validated_unique": n_valid_unique,
            "keyfile_validated": n_keyfile,
            "kia_named": n_kia_named,
            "kia_named_validated": n_kia_valid,
            "kia_named_validated_unique": n_kia_valid_unique,
            "results": results}


def report(summary: dict, verbose: bool) -> int:
    # Headline counts are given for both files and distinct content, because
    # duplicated captures inflate the file count without adding evidence.
    print(f"\nfiles={summary['files']} raw={summary['raw']} "
          f"reached-68-bits={summary['reached68']} validated={summary['validated']} "
          f"({summary['validated_unique']} unique)")
    print(f"kia-named={summary['kia_named']} kia-named-validated="
          f"{summary['kia_named_validated']} "
          f"({summary['kia_named_validated_unique']} unique) "
          f"keyfile-validated={summary.get('keyfile_validated', 0)}")
    if summary.get("keyfile_validated"):
        print("  (key files exercise the crypto + field extraction only, not the PWM path)")

    hits = [r for r in summary["results"] if r["validated"]]
    if hits:
        print("\nvalidated captures:")
        for r in hits:
            tag = "" if r["kia_named"] else "   <-- NOT Kia-named: A3 VIOLATION"
            dup = f"  == duplicate of {r['duplicate_of']}" if r["duplicate_of"] else ""
            src = " [key]" if r.get("source") == "keyfile" else ""
            print(f"  {r['name']:<36} {r['version']} sn=0x{r['serial']:08X} "
                  f"btn={r['btn']:X} ctr=0x{r['ctr']:04X} crc=0x{r['crc']:X} "
                  f"freq={r['freq']}{src}{tag}{dup}")

    # Files that produced a full-length frame but failed the 12-bit crypto check.
    # This is the A3 evidence: the check discriminates rather than accepting every
    # PWM-shaped burst. Printed unconditionally, because an empty verbose section
    # reads as a reporting bug rather than as a clean rejection.
    near = [r for r in summary["results"] if r.get("n_bits") and not r["validated"]]
    if near:
        print(f"\nreached 68 bits but crypto-rejected ({len(near)} files) "
              f"— this is the A3 discrimination at work:")
        shown = near if verbose else near[:5]
        for r in shown:
            print(f"  {r['name']:<36} nbits={r['n_bits']} freq={r['freq']} "
                  f"preset={r['preset']}")
        if len(near) > len(shown):
            print(f"  ... and {len(near) - len(shown)} more (use --verbose for all)")

    # Unique serials, not files: two files holding the same capture are one fob.
    a3 = (summary["validated"] - summary["kia_named_validated"]) == 0
    a2 = summary["kia_named_validated_unique"] > 0
    print()
    print(f"A3 (no false positives) : {'PASS' if a3 else 'FAIL'}")
    if a2:
        print("A2 (real Kia validated) : PASS")
    elif summary["kia_named"]:
        print("A2 (real Kia validated) : FAIL (Kia files present, none validated)")
    else:
        print("A2 (real Kia validated) : NOT RUN (no Kia-named file in corpus)")

    if a2:
        # Corroboration must be per distinct capture, not per file. Group by serial
        # and then by content hash, so a capture stored twice contributes once.
        by_serial: dict[int, dict[str, dict]] = {}
        for r in hits:
            if r["kia_named"]:
                by_serial.setdefault(r["serial"], {})[r["md5"]] = r
        for sn, uniq in by_serial.items():
            n_uniq = len(uniq)
            ctrs = sorted(x["ctr"] for x in uniq.values())
            if n_uniq > 1:
                print(f"\ncorroboration: serial 0x{sn:08X} validated on {n_uniq} "
                      f"distinct capture(s); counters {[hex(c) for c in ctrs]}")
                if len(set(ctrs)) == 1:
                    print("  note: identical counters — these may be one press recorded twice")
            else:
                print(f"\nserial 0x{sn:08X}: 1 distinct capture "
                      f"(counter 0x{ctrs[0]:04X}); no independent corroboration")

        # Breadth. A capture only proves anything about the checked bits: the button
        # nibble and serial&0xFF (ks_kiaV34Match). Two captures that agree on that
        # field are indistinguishable to this decoder, so they cannot count as
        # independent evidence even when their serials differ elsewhere — the
        # difference lies in bits the protocol never verifies (doc 09 §1.2).
        verified = {(r["btn"], r["serial"] & 0xFF) for r in hits if r["kia_named"]}
        n_serials = len(by_serial)
        print(f"\nbreadth: {n_serials} distinct serial(s) validated, "
              f"{len(verified)} distinct verified field(s) (btn, serial LSB).")
        if len(verified) == 1:
            v = next(iter(verified))
            print(f"  All captures agree on btn={v[0]:X} and serial&0xFF=0x{v[1]:02X} "
                  "— those are the ONLY bits this decoder checks, so these captures")
            print("  are not independent evidence. They may be one fob captured twice.")
            print("  Breadth across vehicles needs a capture whose verified field differs.")
        else:
            print("  Distinct verified fields present, so these are independent devices.")
    return 0 if a2 and a3 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kat", action="store_true", help="verify the mirror against the KAT")
    ap.add_argument("--scan", nargs="+", metavar="DIR", help="scan DIR(s) recursively")
    ap.add_argument("--json", metavar="OUT", help="write results as JSON")
    ap.add_argument("--verbose", action="store_true", help="list files that reached 68 bits")
    a = ap.parse_args()

    if not a.kat and not a.scan:
        ap.print_help()
        return 2

    kat_ok = verify_kat()
    if a.kat and not a.scan:
        return 0 if kat_ok else 1

    if not kat_ok:
        # Refuse to judge captures with a mirror that disagrees with the firmware.
        print("\nREFUSING TO SCAN: the mirror does not reproduce the firmware KAT.")
        print("A mirror that disagrees with the firmware proves nothing about either.")
        return 1

    roots = [Path(d) for d in a.scan]
    summary = scan(roots)
    if a.json:
        Path(a.json).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"wrote {a.json}")
    rc = report(summary, a.verbose)

    # The KAT has already passed by this point, so a clean run is interpretable.
    return rc


if __name__ == "__main__":
    sys.exit(main())
