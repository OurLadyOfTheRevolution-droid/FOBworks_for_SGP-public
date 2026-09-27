#!/usr/bin/env python3
"""Static regression checks for the KeeLoq self-test (F2) and the real
manufacturer key table (F1).

These are source-level assertions, not a substitute for running the cipher. The
cipher itself is verified against the three published vectors by the host
harness described in the header of this file's sibling doc; what is checked here
is that the firmware still wires the right pieces together:

  * the self-test exists, covers all three vectors, and latches its verdict;
  * the verdict reaches /api/status and the serial status command;
  * the key table is the real 73-entry corpus, not the old invented fillers;
  * every entry carries a learning type, and unconfirmed entries are flagged;
  * the derivations live in one helper, so the decoder, the recovery analyzer,
    and the HTTP tester cannot drift apart.
"""

from pathlib import Path
import os
import re

HERE = Path(__file__).resolve().parent
FIRMWARE = HERE / "FOBworks_for_SGP.ino"

# The manufacturer-key corpus is a local research fixture and is deliberately NOT published:
# it is the same 73 keys the firmware already embeds in plaintext, so shipping the file would
# add nothing a reader of the sketch does not already have. Read it from research/sources/ when
# it is present locally, or from FOBWORKS_MFCODES. The cross-check below is skipped when it is
# absent, so the rest of this suite still runs in a fresh clone.
_env = os.environ.get("FOBWORKS_MFCODES")
CORPUS = Path(_env).expanduser() if _env else HERE / "research" / "sources" / "keeloq_mfcodes_public.txt"

source = FIRMWARE.read_text(encoding="utf-8")

# ── F2: the self-test ─────────────────────────────────────────────────────────
selftest = re.search(
    r"static bool ks_klSelfTest\(\)\{(?P<body>.*?)\n\}", source, re.DOTALL
)
assert selftest, "ks_klSelfTest() is missing"
body = selftest.group("body")

# The three published vectors must all be present, encrypt and decrypt both way.
assert body.count("0x") >= 9, "self-test vector table looks truncated"
assert "0xBEEFDEADBEEFDEADULL" in body
assert "0x5CEC6701B79FD949ULL" in body
assert "0x2000C022UL" in body and "0x054C90C2UL" in body
assert "ks_klEncrypt" in body and "ks_klDecrypt" in body
assert "pass == 3" in body, "self-test does not require all three vectors to pass"

# The verdict is latched in file scope so the HTTP route can read it.
assert re.search(r"static bool klSelfTestOK\s*=\s*false", source), "verdict not latched"
assert re.search(r"static uint8_t klSelfTestPass\s*=\s*0", source), "pass count not latched"

# It is called at boot, and the failure path is loud.
assert "ks_klSelfTest();" in source, "self-test is never called"
assert "[kl] selftest fail" in source.lower(), "no failure log line"
assert "[kl] selftest pass" in source.lower(), "no success log line"

# Published on /api/status and on the serial status command.
assert source.count("kl_selftest") >= 3, "self-test verdict not published"
assert "kl_selftest_pass" in source
api_status = re.search(r'protectedRoute\("/api/status",\[\]\(\)\{(.*?)\n  \}\);', source, re.DOTALL)
assert api_status, "/api/status handler not found"
assert "kl_selftest" in api_status.group(1)
assert "klSelfTestOK" in api_status.group(1)
serial_status = re.search(r'if\(op=="status"\)\{(.*?)\n      \}', source, re.DOTALL)
assert serial_status, "serial status handler not found"
assert "kl_selftest" in serial_status.group(1)

# Dashboard must be able to grey out the Keys tab: the flag is read, the banner
# exists, and the key tester refuses to run when the cipher is failing.
ui = (HERE / "html_page.h").read_text(encoding="utf-8")
assert "kl_selftest" in ui, "dashboard never reads the self-test verdict"
assert re.search(r"id=klWarn", ui), "Keys-tab self-test warning banner missing"
assert "KeeLoq self-test failed" in ui, "banner text missing"
assert "if(!_klOk)" in ui, "key tester does not refuse to run on a failed cipher"

# ── F1: the key table ─────────────────────────────────────────────────────────
assert 'struct MfrKey  { const char* name; uint64_t key; uint8_t learn; uint8_t suspect; };' in source, \
    "MfrKey must carry a learning type and a suspect flag"

# Every entry in the firmware table must match the corpus it claims to come
# from. Parse both and compare as sets of (name, key, learn).
table = re.search(r"static const MfrKey MFR_KEYS\[\]=\{(?P<body>.*?)\n\};", source, re.DOTALL)
assert table, "MFR_KEYS table not found"
table_body = table.group("body")

# The invented fillers must be gone from the table itself. These names had no
# real key behind them; a stale copy would again produce false positives.
# (The changelog records their removal by name, so only the table is checked.)
for invented in ("OEM-A", "OEM-B", "Generic-A", "Generic-F", "Clone-1111",
                 "Clone-EEEE", "OEM-lo32only", "OEM-hi32only", "HCS-demo1",
                 "Clone-5A5A", "OEM-C", "OEM-D"):
    assert f'"{invented}"' not in table_body, f"invented filler entry still present: {invented}"

# Table size is derived and asserted, so a silent truncation is impossible.
assert "sizeof(MFR_KEYS)/sizeof(MFR_KEYS[0])" in source
assert "static_assert(N_MFR_KEYS == 73" in source, "key count is not asserted"
# The learn field is written either as a digit or as its KL_* enum label.
KL_VALUE = {
    "KL_UNKNOWN": 0, "KL_SIMPLE": 1, "KL_NORMAL": 2, "KL_SECURE": 3,
    "KL_MAGIC_XOR1": 4, "KL_FAAC": 5, "KL_MAGIC_SER1": 6, "KL_MAGIC_SER2": 7,
    "KL_MAGIC_SER3": 8, "KL_BENINCA_ARC": 9, "KL_KINGGATES": 10,
    "KL_JAROLIFT": 11, "KL_HEURISTIC": 12,
}
raw = re.findall(
    r'\{\s*"([^"]+)"\s*,\s*0x([0-9A-Fa-f]{16})ULL\s*,\s*([A-Za-z0-9_]+)\s*,\s*([01])\s*\}',
    table.group("body"),
)

# ── the stored keys are masked ───────────────────────────────────────────────
# The table holds the affine transform of each key rather than the key itself, so the
# plaintext is not the first thing a reader sees. The firmware inverts this on the way into
# every derivation (ks_unmaskMfrKey), and the corpus comparison below needs the plaintext, so
# this suite has to invert it too -- which also makes the cross-check double as a test that the
# mask is consistent between the sketch and this file.
assert "static inline uint64_t ks_unmaskMfrKey(uint64_t v){" in source, \
    "the unmask helper is missing; the table cannot be read"
assert "ks_deriveOneMfrKey(sn, ks_unmaskMfrKey(MFR_KEYS[k].key), dk)" in source, \
    "the derivation loop does not unmask the table"
assert "ks_klDecrypt(f.hop,ks_unmaskMfrKey(MFR_KEYS[i].key))" in source, \
    "the recovery analyzer does not unmask the table"
assert "TRY_KEY(MFR_KEYS[i].name, ks_unmaskMfrKey(MFR_KEYS[i].key)" in source, \
    "/api/mfr_test does not unmask the table"

# Read the constants the sketch actually uses, so this cannot drift from them.
_c = re.search(r"#define MFR_KEY_A\s+(0x[0-9A-Fa-f]+)ULL", source)
assert _c, "MFR_KEY_A not found"
MASK_A = int(_c.group(1), 16)
_c = re.search(r"#define MFR_KEY_B\s+(0x[0-9A-Fa-f]+)ULL", source)
assert _c, "MFR_KEY_B not found"
MASK_B = int(_c.group(1), 16)
_c = re.search(r"#define MFR_KEY_N\s+(\d+)", source)
assert _c, "MFR_KEY_N not found"
MASK_N = int(_c.group(1), 16 if False else 10)


def unmask(v):
    x = (v ^ MASK_B) & 0xFFFFFFFFFFFFFFFF
    return (((x >> MASK_N) | (x << (64 - MASK_N))) & 0xFFFFFFFFFFFFFFFF) ^ MASK_A


def encode(k):
    """The forward transform, as tools/mask_mfrkeys.py applies it."""
    x = (k ^ MASK_A) & 0xFFFFFFFFFFFFFFFF
    return (((x << MASK_N) | (x >> (64 - MASK_N))) & 0xFFFFFFFFFFFFFFFF) ^ MASK_B


# Keep the stored (masked) values so the transparency checks below can test the inverse.
raw_original = raw
raw = [(n, f"{unmask(int(k, 16)):016X}", t, s) for n, k, t, s in raw]

# The Kia OEM key is public, but there is no reason to write it out: take it from the
# masked constant the sketch ships and invert it, which also re-checks the inverse.
_kia_stored = int(re.search(r"#define KIA_V34_MF_KEY\s+0x([0-9A-Fa-f]{16})ULL", source).group(1), 16)
PUBLIC_KIA = unmask(_kia_stored)
# The table entry and the decoder constant are two copies of the same key; both must invert
# to the same plaintext, or one of them was masked wrong.
_kia_tbl = next(k for n, k, _t, _s in raw_original if n == "Kia_V3_V4_OEM")
assert unmask(int(_kia_tbl, 16)) == PUBLIC_KIA, "Kia key paths disagree"

def learn_value(tok):
    return int(tok) if tok.isdigit() else KL_VALUE.get(tok, -1)
entries = [(n, k, learn_value(t), int(s)) for n, k, t, s in raw]
assert len(entries) == 73, f"expected 73 real keys, found {len(entries)}"
assert all(l >= 0 for _, _, l, _ in entries), "unknown learning-type token in the table"

# The corpus is a local research fixture and is NOT published, so this comparison is skipped
# when it is absent. The table's own shape (73 entries, learning types, suspect flags) is
# asserted above and does not depend on the file.
corpus = []
if CORPUS.is_file():
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([0-9A-Fa-f]{16}):(\d+):(.+)$", line)
        if m:
            corpus.append((m.group(3).strip(), m.group(1).upper(), int(m.group(2))))

if corpus:
    # The Kia entry is not in the corpus file (it comes from the open-source Kia
    # decoders, see worklog). Everything else must match the corpus exactly — name, key,
    # and learning type — so a transcription slip cannot slip through.
    corpus_set = {(n, k, l) for n, k, l in corpus}
    table_set = {(n.strip(), k.upper(), l) for n, k, l, _ in entries}

    extra = table_set - corpus_set - {("Kia_V3_V4_OEM", f"{PUBLIC_KIA:016X}", 1)}
    assert not extra, f"firmware entries that do not match the corpus: {sorted(extra)}"
    missing = corpus_set - table_set
    assert not missing, f"corpus entries absent from the firmware table: {sorted(missing)}"
    assert ("Kia_V3_V4_OEM", f"{PUBLIC_KIA:016X}", 1) in table_set, "the public OEM KeeLoq key is missing"
    print(f"  corpus cross-check: {len(corpus)} entries matched")
else:
    print(f"  corpus cross-check: skipped ({CORPUS.name} not present; set FOBWORKS_MFCODES to run it)")

# ── the mask must be transparent ─────────────────────────────────────────────
# The stored keys are transformed, so the one thing that could break silently is the inverse.
# Assert the properties that matter: the transform is invertible on every entry, no entry is a
# fixpoint (a fixpoint would mean the "masked" value equals the key), and the Kia entry -- the
# one key whose plaintext is public and checkable -- inverts to exactly that value.
for name, stored_hex, _learn, _suspect in raw_original:
    stored = int(stored_hex, 16)
    assert unmask(encode(stored)) == stored, f"{name}: mask is not invertible"
    assert encode(stored) != stored, f"{name}: the stored value is a transform fixpoint"

_kia_masked = next(k for n, k, _t, _s in raw_original if n == "Kia_V3_V4_OEM")
assert unmask(int(_kia_masked, 16)) == PUBLIC_KIA, \
    "the Kia table entry does not unmask to the public Kia key"

# The firmware must invert at every point where the table is read, or those paths would
# silently derive keys from masked values. Each of these is a real call site.
for call in ("ks_deriveOneMfrKey(sn, ks_unmaskMfrKey(MFR_KEYS[k].key), dk)",
             "ks_klDecrypt(f.hop,ks_unmaskMfrKey(MFR_KEYS[i].key))",
             "CAND_ADD(MFR_KEYS[i].name, ks_unmaskMfrKey(MFR_KEYS[i].key)",
             "TRY_KEY(MFR_KEYS[i].name, ks_unmaskMfrKey(MFR_KEYS[i].key)"):
    assert call in source, f"a table read skips the unmask: {call}"

# And the decoder's own key constant must be stored masked and unmasked on use, so that one
# of the 73 is not left sitting in the clear.
assert f"0x{PUBLIC_KIA:016X}ULL" not in source, \
    "the Kia key is still plaintext somewhere in the sketch"
assert "ks_unmaskMfrKey(KIA_V34_MF_KEY)" in source, \
    "KIA_V34_MF_KEY is used without unmasking"
print("  mask transparency: invertible, no fixpoints, every read unmasked")

# Learning types must be real enum values, not raw 0/1/2 in the source.
assert "enum KLLearn : uint8_t" in source
assert "KL_SIMPLE, 0}" in source, "table does not use the learning-type enum"
for label in ("KL_SIMPLE", "KL_NORMAL", "KL_SECURE", "KL_MAGIC_XOR1", "KL_FAAC",
              "KL_MAGIC_SER1", "KL_MAGIC_SER2", "KL_MAGIC_SER3"):
    assert label in source, f"learning type missing: {label}"
assert "KL_HEURISTIC" in source, "heuristic derivations must be distinguishable"

# Unconfirmed entries: factory defaults and untyped entries must be flagged, so a
# match cannot be reported as an identification.
for name, key, learn, suspect in entries:
    want = 1 if (int(learn) == 0 or key.upper() in ("0000000000000000", "FFFFFFFFFFFFFFFF")) else 0
    assert int(suspect) == want, f"suspect flag wrong for {name}: {suspect} (want {want})"

# A heuristic derivation must never be reported as a confident identification.
assert "KL_MODE_LEARN[(_mode)] == KL_HEURISTIC" in source, \
    "heuristic modes are not treated as unconfirmed in the derived-key path"
assert "KL_MODE_LEARN[_m] == KL_HEURISTIC" in source, \
    "heuristic modes are not treated as unconfirmed in the recovery analyzer"

# ── one source of truth for the derivations ──────────────────────────────────
assert "static uint8_t ks_deriveOneMfrKey(" in source, "shared derivation helper missing"
assert "ks_deriveOneMfrKey(sn, ks_unmaskMfrKey(MFR_KEYS[k].key), dk)" in source, "table generator bypasses helper"
assert "ks_deriveOneMfrKey(sn32, mfrKey, dk)" in source, "/api/mfr_test bypasses helper"
assert re.search(r"ks_deriveOneMfrKey\(KR\.frames\[0\]\.sn, _mk, _dks\)", source), \
    "recovery analyzer bypasses helper"
assert "N_KL_DERIV_MODES 14" in source, "mode count is not fixed at 14"

# The old duplicated 15-mode macro must be gone; a second copy is how the
# analyzer and the decoder drift apart.
assert 'bestMode="xor-type1"' not in source, "duplicated derivation macro still present"
assert 'bestMode="magic-serial-3"' not in source, "duplicated derivation macro still present"

print("keeloq self-test and key-table checks passed")


# ── V1/V2/V3: frame parsing, the match predicate, and the agreement gate ──────
# These guard the defects fixed alongside F1/F2. Each assertion corresponds to a
# case proven broken on the host before the fix.

# The 66-bit frame must be read field-by-field from the bit string. Accumulating
# it into a uint64_t drops the top 2 bits of the 32-bit hop, so any hop with bit
# 31 or 30 set (3 of every 4 codes) was unparseable.
parse_kl = re.search(r"static bool ks_parseKL\((?P<body>.*?)\n\}", source, re.DOTALL)
assert parse_kl, "ks_parseKL not found"
body = parse_kl.group("body")
assert "ks_bitsToU32" in body, "hop is not read directly from the bit string"
assert "uint64_t frame" not in body, "66-bit frame is still accumulated into a uint64_t"
assert "frame>>34" not in body, "the lossy shift is still present"

# The match predicate must compare the 12-bit discriminator that actually exists
# in both values: dec[27:16] against sn[15:4]. sn is at most 0xFFFF, so any test
# of sn&0xFFFF0000 is a test of a constant zero.
match = re.search(r"static inline bool ks_klSnMatch\((?P<body>.*?)\n\}", source, re.DOTALL)
assert match, "ks_klSnMatch not found"
mbody = match.group("body")
assert "(dec>>16) & 0xFFF" in mbody, "predicate does not read dec[27:16]"
assert "(sn>>4) & 0xFFF" in mbody, "predicate does not read sn[15:4]"
assert "0xFFFF0000" not in mbody, "predicate still compares the always-zero sn high half"

# No call site may reintroduce the old predicate. Checked against code with
# comments stripped, since the docs deliberately quote the old form to explain
# why it was wrong.
code = re.sub(r"//[^\n]*", "", source)
assert code.count("0xFFFF0000") == 0, "old predicate reappeared in live code"

# Predicted hops must carry the real discriminator, not zero.
assert "ks_klBuildPlain" in source, "prediction plaintext builder missing"
assert "f.sn&0xFFF0000UL)>>4" not in source, "prediction still zeroes the discriminator"
assert "ks_klBuildPlain(f.btn,f.sn,(uint16_t)nextC" in source, "prediction does not use the builder"
bp = re.search(r"static inline uint32_t ks_klBuildPlain\((?P<body>.*?)\n\}", source, re.DOTALL)
assert bp and "((sn>>4)&0xFFFu)<<16" in bp.group("body"), "builder drops the discriminator"

# V1: the agreement gate. A 12-bit predicate over ~1095 candidates accepts a wrong
# key on ~27% of frames, so an identification requires the same key twice.
assert "ks_klAgreeHas" in source and "ks_klAgreeCommit" in source, "agreement gate missing"
assert "bool candidate;" in source, "KLPred cannot express the candidate state"
assert "p.candidate = (unconfirmed >= 0 || ncand > 0);" in source, "candidate state not set"
# The gate must verify the serial and the hop, not just the key.
ah = re.search(r"static bool ks_klAgreeHas\((?P<body>.*?)\n\}", source, re.DOTALL)
assert ah, "ks_klAgreeHas not found"
ahb = ah.group("body")
assert "sn != KL_PREV_SN" in ahb, "gate does not reject a different serial"
assert "hop == KL_PREV_HOP" in ahb, "gate does not reject a duplicate decode of one press"
assert "ks_klAgreeHas(f.sn, cand[i].key, f.hop)" in source, "gate called without the serial"

# V2: the derivation self-test, latched and published.
assert "static bool ks_klDerivSelfTest()" in source, "derivation self-test missing"
assert "ks_klSnMatch(dec, sn)" in source, "derivation test does not exercise the predicate"
assert re.search(r"static bool klDerivOK\s*=\s*false", source), "derivation verdict not latched"
assert "ks_klDerivSelfTest();" in source, "derivation self-test never called"
assert "kl_deriv_ok" in source, "derivation verdict not published"

# Parser self-test must cover hops with the top bits set.
pt = re.search(r"static bool ks_klParseSelfTest\(\)\{(?P<body>.*?)\n\}", source, re.DOTALL)
assert pt, "parser self-test missing"
ptb = pt.group("body")
assert "0xC0000001" in ptb, "parser self-test lacks a hop with both top bits set"
assert "0xFFFFFFFF" in ptb, "parser self-test lacks an all-ones hop"
assert "ks_parseKL(bits,66,f)" in ptb, "parser self-test does not call the real parser"
assert "static bool klParseOK" in source, "parse verdict not latched"
# It must reach BOTH status surfaces: the HTTP route and the serial command.
assert source.count("kl_parse_ok") == 2, "parse verdict not published on both status surfaces"
assert source.count("klParseOK?") == 2, "parse verdict value not emitted on both surfaces"

# V3: mode count pinned so the per-mode tables cannot disagree.
assert 'static_assert(N_KL_DERIV_MODES == 14' in source, "mode count not pinned"
assert 'static_assert(MAX_DERIVED_KEYS == 73 * 14' in source, "derived budget not pinned"
for sym in ("KL_MODE_LEARN", "KL_MODE_NAME"):
    m = re.search(r"%s\[N_KL_DERIV_MODES\]\s*=\s*\{(?P<body>.*?)\};" % sym, source, re.DOTALL)
    assert m, f"{sym} table missing"
    n = len([v for v in m.group("body").replace("\n", " ").split(",") if v.strip()])
    assert n == 14, f"{sym} has {n} initialisers, expected 14"

print("keeloq frame/predicate/gate checks passed")


# ── F5: Kia V3/V4 decoder ────────────────────────────────────────────────────
# The decoder must have its own parser and its own predicate. Routing it through
# the HCS helpers silently corrupts every field: the frame is 68 bits not 66, the
# serial is a 28-bit field rather than a 12-bit discriminator, and every payload
# byte is bit-reversed.

# Its own parser, not ks_parseKL.
kia_decode = re.search(r"static bool ks_decodeKiaV34\((?P<body>.*?)\n\}", source, re.DOTALL)
assert kia_decode, "Kia V3/V4 decoder missing"
kd = kia_decode.group("body")
assert "ks_kiaV34Pwm(" in kd, "Kia decoder does not use its own PWM extractor"
assert "ks_parseKL" not in kd, "Kia decoder routes through the HCS parser"

# The extractor must not touch ks_parseKL either.
pwm = re.search(r"static uint16_t ks_kiaV34PwmAt\((?P<body>.*?)\n\}", source, re.DOTALL)
assert pwm, "Kia PWM extractor missing"
assert "ks_parseKL" not in pwm.group("body"), "Kia PWM extractor routes through ks_parseKL"

# Its own predicate: 4-bit button + 8-bit serial LSB. Not ks_klSnMatch.
pred = re.search(r"static inline bool ks_kiaV34Match\((?P<body>.*?)\n\}", source, re.DOTALL)
assert pred, "ks_kiaV34Match missing"
pb = pred.group("body")
assert "(dec >> 28) & 0x0F" in pb, "Kia predicate does not check the button nibble"
assert "(dec >> 16) & 0xFF" in pb, "Kia predicate does not check the serial LSB"
assert "ks_klSnMatch" not in pb, "Kia predicate delegates to the HCS discriminator check"

# V3 and V4 differ by the SYNC PULSE'S LEVEL, and the decoder must derive the
# version from it (the reference's is_v3_sync). Trying both inversions blindly
# reports a V3 frame as V4, which is what A2 on real captures exposed.
assert "ks_kiaV34IsSync" in source, "sync-pulse detector missing"
assert "*outV3 = !syncHigh" in source, "version is not derived from the sync level"
assert re.search(r"ks_kiaV34Extract\(b,b\[8\],invert,f\)", source), \
    "decoder does not apply the sync-derived inversion"
ext = re.search(r"static void ks_kiaV34Extract\((?P<body>.*?)\n\}", source, re.DOTALL)
assert ext and "~b[i]" in ext.group("body"), "V3 frame inversion not implemented"

# One bit per HIGH pulse, not per pulse pair. Pairing recovers the right serial on
# a clean V4 capture but misreads the version, and cannot cross the sync at all.
at = re.search(r"static uint16_t ks_kiaV34PwmAt\((?P<body>.*?)\n\}", source, re.DOTALL)
assert at, "ks_kiaV34PwmAt missing"
atb = at.group("body")
assert "parityHigh" in atb, "extractor does not use index parity to recover pulse level"
assert "ks_kiaV34IsPulse(w,KIA_V34_TE_SHORT))      bits[b++]=\'0\'" in atb or \
       "bits[b++]='0'" in atb, "extractor does not emit one bit per high pulse"
assert "buf[i+1]" in atb, "extractor lost its preamble pair scan"

# The byte reversal and the masked top serial byte are load-bearing.
assert "ks_kiaV34Rev8" in source, "per-byte bit reversal missing"
assert "(uint8_t)(w[7] & 0xF0)" in source, "serial top byte is not masked to 0xF0 before reversal"

# The encryption plaintext is cnt | (serial & 0x3FF) << 16 | (btn << 28) — NOT the
# on-air serial framing. The on-air form loses the top serial bits and overwrites
# the button nibble, and a round-trip cannot detect that (the 12-bit check reads
# only serial[7:0], which both layouts place at bits[23:16]).
bp = re.search(r"static inline uint32_t ks_kiaV34BuildPlain\((?P<body>.*?)\n\}", source, re.DOTALL)
assert bp, "Kia plaintext builder missing"
assert "serial & 0x3FFUL" in bp.group("body"), \
    "Kia plaintext must mask the serial to 10 bits (the on-air form uses 28)"
assert "serial & 0x0FFFFFFFUL) << 16" not in bp.group("body"), \
    "Kia plaintext uses the on-air 28-bit serial layout"

# Known-answer tests must pin that layout, because the round-trip cannot. Two are
# required: vector 1 has serial[9:8]=0 so it cannot distinguish the 10-bit mask
# from an 8-bit one; vector 2 (serial[9:8]=11) is what pins the mask width.
assert "0x30E704D2UL" in source, "Kia KAT vector 1 plaintext missing"
assert "0x8686900BUL" in source, "Kia KAT vector 1 ciphertext missing"
assert "0x0A1B2FE7UL" in source, "Kia KAT vector 2 serial missing (needed to pin the mask width)"
assert "0x33E704D2UL" in source, "Kia KAT vector 2 plaintext missing"
assert "0x10944604UL" in source, "Kia KAT vector 2 ciphertext missing"
# Both vectors' serials must differ in serial[9:8], or vector 2 is pointless.
assert (0x0A1B2CE7 >> 8) & 3 != (0x0A1B2FE7 >> 8) & 3, "KAT vectors do not differ in serial[9:8]"

# Own confirmation state, not the HCS gate (different serial namespace).
assert "ks_kiaV34Confirm" in source, "Kia confirmation gate missing"
assert "KIA34_LAST_SN" in source and "KIA34_LAST_HOP" in source, "Kia gate state missing"

# Gate and ordering.
assert re.search(r"bool te_kv34\s*=", source), "te_kv34 gate missing"
assert "if(!decoded && te_kv34){" in source, "Kia decoder is not gated"
# It must run before the generic KeeLoq block, which commits on parse success.
te_kv34_pos = source.index("if(!decoded && te_kv34){")
te_kl_skip_pos = source.index("bool te_kl_skip = ")
assert te_kv34_pos < te_kl_skip_pos, \
    "Kia V3/V4 must be attempted before the generic KeeLoq path consumes the frame"

# A1 self-test wired, latched and published.
assert "static bool ks_kiaV34SelfTest()" in source, "A1 self-test missing"
assert "ks_kiaV34SelfTest();" in source, "A1 self-test never called"
assert re.search(r"static bool kiaV34SelfTestOK\s*=\s*false", source), "A1 verdict not latched"
# Counted in code only: the changelog also names this field.
_c = re.sub(r"//[^\n]*", "", source)
assert _c.count("kia_v34_ok") == 2, "A1 verdict not published on both status surfaces"

# The CRC4 must be extracted and reported, never used to reject a frame: the
# polynomial is unpublished, and guessing it would reject valid frames.
x = re.search(r"static void ks_kiaV34Extract\((?P<body>.*?)\n\}", source, re.DOTALL)
assert x and "out.crc" in x.group("body"), "CRC4 field not extracted"
v = re.search(r"static bool ks_kiaV34Validate\((?P<body>.*?)\n\}", source, re.DOTALL)
assert v, "Kia validate missing"
assert ".crc" not in v.group("body"), "CRC4 is being validated (polynomial is unpublished)"

print("kia v3/v4 decoder checks passed")


# ── v3.65 version pin ────────────────────────────────────────────────────────
# Version-agnostic: assert the version exists and is internally consistent (the FW_VER
# define, the boot banner and the newest changelog header all agree), rather than pinning a
# literal that has to be edited every release. The previous form asserted v3.71 specifically
# and broke the moment the version was bumped, which is noise rather than a real check.
_vm = re.search(r'#define\s+FW_VER\s+"FOBworks for SGP v(\d+\.\d+)"', source)
assert _vm, "FW_VER is not defined in the expected form"
_ver = _vm.group(1)
assert f"// v{_ver} " in source, f"no changelog entry for the current FW_VER (v{_ver})"
print(f"version check: FW_VER v{_ver} has a matching changelog entry")
# The file header must agree with FW_VER too, not just the changelog.
assert f"// Version  : FOBworks for SGP v{_ver}" in source, \
    f"file header version does not match FW_VER v{_ver}"
print(f"header check: file header agrees with FW_VER v{_ver}")
print("version checks passed")
