#!/usr/bin/env python3
"""A2 reporting checks — the harness must not overstate its own result.

A2 passed against real Kia captures, but the first version of the harness reported
it dishonestly in two ways (worklog §1.2):

  1. The corpus stores the same capture under two filenames, so "validated=4"
     counted 2 distinct captures twice. The corroboration line then read as
     independent confirmation when it was one file counted twice.
  2. The two captures agree on the ONLY bits this decoder verifies — the button
     nibble and serial&0xFF — so they are not independent evidence of breadth,
     even though their serials differ elsewhere. The differing bit (bit 24) lies
     outside the checked field and is unverified.

This test pins the honest behaviour: distinct-content counts, per-capture
corroboration, the crypto-rejected list, and the breadth statement.

Run: python3 test_a2_reporting.py
"""

from pathlib import Path
import hashlib
import importlib.util
import io
import contextlib

HERE = Path(__file__).resolve().parent
MIRROR = HERE / "research" / "sources" / "a2_kia_v34.py"
CAPS = HERE / "research" / "sources" / "captures" / "kia"

assert MIRROR.is_file(), f"mirror not found: {MIRROR}"

spec = importlib.util.spec_from_file_location("a2mirror", MIRROR)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# ── Static: the honest-reporting machinery is present ────────────────────────
src = MIRROR.read_text(encoding="utf-8")
assert "def md5_of(" in src, "no content hashing — duplicates would be counted twice"
assert '"validated_unique"' in src, "no distinct-content count for validated"
assert '"kia_named_validated_unique"' in src, "no distinct-content count for Kia-validated"
# Corroboration must group by content, not by file.
assert 'by_serial.setdefault(r["serial"], {})[r["md5"]] = r' in src, \
    "corroboration is not de-duplicated by content"
# A2 must key off the unique count, so duplicates cannot make it pass.
assert 'a2 = summary["kia_named_validated_unique"] > 0' in src, \
    "A2 does not require a distinct validating capture"
# The crypto-rejected list must print without --verbose, since an empty verbose
# section reads as a reporting bug rather than a clean rejection.
assert "crypto-rejected" in src, "crypto-rejected files are not reported"
assert "distinct verified field(s)" in src, "breadth caveat not reported"

# ── Behavioural: run the mirror and inspect the actual output ────────────────
if not CAPS.is_dir():
    print(f"note: {CAPS} absent; skipped the behavioural half")
    print("a2 reporting checks passed (static only)")
    raise SystemExit(0)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    summary = m.scan([CAPS])
out = buf.getvalue()
with contextlib.redirect_stdout(buf):
    m.report(summary, verbose=False)
out = buf.getvalue() + out
# report() prints; capture it properly
buf2 = io.StringIO()
with contextlib.redirect_stdout(buf2):
    m.report(summary, verbose=False)
report_text = buf2.getvalue()

# The two supplied captures: distinct content, so file count > unique count.
assert summary["validated"] == 2, f"expected 2 validating files, got {summary['validated']}"
assert summary["validated_unique"] == 2, \
    f"expected 2 distinct validating captures, got {summary['validated_unique']}"
# KIA V3/V4 differ in content, so both are unique here.
assert summary["kia_named_validated_unique"] == 2

# Reporting must show both figures, so a reader cannot mistake files for captures.
assert "validated=2 (2 unique)" in report_text, \
    "report does not distinguish files from distinct captures"

# ── The duplicate case: same content twice must collapse to one ─────────────
# Build a temp dir with one capture copied under a second name and confirm the
# unique count stays at 1 while the file count rises.
import tempfile
import shutil

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    one = next(p for p in sorted(CAPS.glob("*.sub")) if p.stat().st_size > 1000)
    # Kia-named so the A2 path is exercised; the point is the content, not the name.
    shutil.copy(one, td / "Kia_dup_a.sub")
    shutil.copy(one, td / "Kia_dup_b.sub")
    s2 = m.scan([td])
    assert s2["validated"] == 2, f"expected 2 validating files, got {s2['validated']}"
    assert s2["validated_unique"] == 1, \
        f"identical content did not collapse: unique={s2['validated_unique']} (must be 1)"
    # And it must be labelled as a duplicate of the first seen.
    dups = [r for r in s2["results"] if r["validated"] and r["duplicate_of"]]
    assert len(dups) == 1, "the duplicated file is not labelled as a duplicate"

    # A2 must still pass on one distinct capture, but the breadth line must say
    # it is not independent evidence.
    b2 = io.StringIO()
    with contextlib.redirect_stdout(b2):
        m.report(s2, verbose=False)
    t2 = b2.getvalue()
    assert "A2 (real Kia validated) : PASS" in t2
    assert "1 distinct verified field(s)" in t2, "breadth caveat missing"
    assert "not independent evidence" in t2, \
        "report does not warn that identical verified fields are not corroboration"

# ── The verified-field logic itself ─────────────────────────────────────────
# These two captures agree on the only bits the decoder checks.
A, B = 0x00C0ED06, 0x01C0ED06
assert (A & 0xFF) == (B & 0xFF), "serial LSB differs — the breadth caveat would not apply"
assert ((A >> 28) & 0xF) == ((B >> 28) & 0xF), "button nibble differs"
# Their difference lies outside the verified field, which is why they are not
# independent evidence.
assert (A ^ B) == 0x01000000, "expected the difference at bit 24 (unverified)"
print("a2 reporting checks passed")


# ── Key-file evidence and breadth (worklog §1.3 / §5.2) ───────────────────────
# A Key file stores an already-demodulated payload, so it exercises the crypto and
# field-extraction path but NOT the PWM path. It is therefore recorded as a
# separate evidence class: it can show the key check works on a second device, but
# it cannot stand in for a RAW capture.
CORPUS = HERE / "research" / "sources" / "corpus_automotive_subghz" / "Asian" / "Hyundai_Kia_Genesis"

if CORPUS.is_dir():
    keyfiles = {}
    for f in sorted(CORPUS.glob("*.sub")):
        meta = m.parse_sub(f)
        if not meta["raw"] and meta.get("key"):
            keyfiles[f.name] = m.decode_keyfile(meta)

    assert keyfiles, "no key files found in the corpus"

    # Exactly one must validate: the KIA/HYU V4 file. Every other variant uses a
    # different format or key and must be rejected — this is A3 at the key-file
    # level, and it is the strongest negative control available without a radio.
    validated = {k for k, v in keyfiles.items() if v}
    assert validated == {"Hyundai_V4_N1.sub"}, \
        f"unexpected key-file validations: {sorted(validated)}"

    # V5 and V6 are the tempting confusions: same brand, similar framing, different
    # protocol. Pin them explicitly.
    for must_reject in ("Kia_V5_N3.sub", "Test_New_Kia_Hyundai.sub",
                        "Hyundai_V6_Test.sub", "Kia_V6_N2.sub",
                        "Hyundai_V0_N1.sub", "Hyundai_V2_N1.sub"):
        assert must_reject in keyfiles, f"{must_reject} not parsed as a key file"
        assert keyfiles[must_reject] is None, f"{must_reject} must NOT validate"

    # Independent breadth: the validating V4 key file's verified field differs from
    # the RAW captures'. That is what makes it separate evidence rather than one
    # more recording of the same fob.
    v4 = keyfiles["Hyundai_V4_N1.sub"]
    v4_field = (v4["btn"], v4["serial"] & 0xFF)
    raw_fields = set()
    if CAPS.is_dir():
        for f in sorted(CAPS.glob("*.sub")):
            meta = m.parse_sub(f)
            if meta["raw"]:
                out = m.ks_decode_kia_v34(meta["raw"], len(meta["raw"]))
                if out:
                    raw_fields.add((out["btn"], out["serial"] & 0xFF))
    assert v4_field not in raw_fields, \
        f"V4 key-file field {v4_field} duplicates the RAW captures' — no breadth"
    print(f"  breadth: key-file device field {v4_field} differs from RAW fields "
          f"{sorted(raw_fields)} -> independent device")

    # The V4 name in the file matches what the decoder reports.
    assert v4["v3"] is False, "the KIA/HYU V4 key file decoded as V3"
else:
    print("note: corpus absent; skipped key-file checks")
print("a2 keyfile + breadth checks passed")
