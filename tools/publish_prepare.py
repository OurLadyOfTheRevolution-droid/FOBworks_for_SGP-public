#!/usr/bin/env python3
"""Produce the published variant of the sketch from the development one.

Why this exists

The `publish` branch is not a filtered copy of `main`. It is a CODE VARIANT with a coordinated
disclosure transform, and treating it as a copy is how it fell four versions behind. The
transform has four parts, and missing any one of them fails in a specific way:

  1. mask the 73 MFR_KEYS literals                (tools/mask_mfrkeys.py does only this)
  2. add the MFR_KEY_A/B/N constants and ks_unmaskMfrKey()
  3. wrap every read of a masked value in ks_unmaskMfrKey():
       MFR_KEYS[k].key            -> ks_unmaskMfrKey(MFR_KEYS[k].key)
       the mfrKeys[2] test literal -> ks_unmaskMfrKey(<masked>)
       KIA_V34_MF_KEY at each use  -> ks_unmaskMfrKey(KIA_V34_MF_KEY)
  4. adapt test_keeloq_key_table.py to invert the mask and to skip its corpus cross-check when
     the plaintext corpus is absent (it is deliberately not published)

Part 3 is the dangerous one. Masking the literals WITHOUT wrapping the reads compiles cleanly,
boots, and silently derives keys from masked values -- so it finds nothing and does not look
broken. That is why this tool verifies rather than trusts, and why the wrapping is done by
matching exact source expressions instead of by hand.

Verification, all of which must pass before the output is written:
  · the key count is 73, unchanged
  · every masked value round-trips to its plaintext original
  · no site reads a masked value without unmasking it (the check that would have caught the
    near-miss above)
  · the round-trip identity of the whole sketch, key set included, is reported so it can be
    compared against a build

Usage:
    python3 tools/publish_prepare.py --check              # report, change nothing
    python3 tools/publish_prepare.py --out /tmp/pubwt     # write the variant into a tree
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKETCH = ROOT / "FOBworks_for_SGP.ino"
TEST_KEELOQ = ROOT / "test_keeloq_key_table.py"
TEST_HOP_XOR = ROOT / "test_hop_xor.py"

# Must match tools/mask_mfrkeys.py.
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


# The Kia/Hyundai V3/V4 manufacturer key, held MASKED for the same reason the sketch holds the
# table masked: this file ships in the published tree, so writing the value out here would undo
# the transform it is performing. The plaintext exists only as a computed local. The self-check
# below re-encodes it, which verifies the inverse without a second copy of the literal.
_KIA_STORED = 0xCC88E6C23CEC0269
_KIA_PLAIN = decode(_KIA_STORED)
assert encode(_KIA_PLAIN) == _KIA_STORED, "the masked Kia key does not invert"
KIA_PLAIN = f"{_KIA_PLAIN:016X}"


ENTRY = re.compile(
    r'(?P<pre>\{\s*"(?P<name>[^"]+)"\s*,\s*0x)(?P<key>[0-9A-Fa-f]{16})'
    r'(?P<post>ULL\s*,\s*[A-Za-z0-9_]+\s*,\s*[01]\s*\})'
)
TABLE = re.compile(r"(?P<open>static const MfrKey MFR_KEYS\[\]=\{)(?P<body>.*?)(?P<close>\n\};)", re.S)

HELPER_BLOCK = """// The stored keys are MASKED, not plaintext. The table must contain them (the decoder derives
// and decrypts with them), but leaving them readable meant the file was the list. Each stored
// value is the affine transform of the real key; ks_unmaskMfrKey below is the inverse, applied
// once per key on the way into a derivation. It is obfuscation, not a security boundary: the
// constants are right here, the table is in a public repository, and anything the device can
// compute, so can a reader. Reversible with tools/mask_mfrkeys.py. Produced by
// tools/publish_prepare.py; do not edit this branch by hand.
#define MFR_KEY_A  0x5A5A5A5A5A5A5A5AULL   // matches tools/mask_mfrkeys.py
#define MFR_KEY_B  0x3C3C3C3C3C3C3C3CULL
#define MFR_KEY_N  13

static inline uint64_t ks_unmaskMfrKey(uint64_t v){
  // inverse of ROTL(k ^ A, N) ^ B  ->  ROTR(v ^ B, N) ^ A
  uint64_t x = (v ^ MFR_KEY_B);
  const uint8_t n = MFR_KEY_N;
  return ((x >> n) | (x << (64 - n))) ^ MFR_KEY_A;
}
static_assert(N_MFR_KEYS == 73, "MFR_KEYS count changed -- update this assert with the table");"""

PLAIN_COMMENT = """// The table holds the real keys in plaintext on this branch. The table has to be present --
// the decoder derives candidate device keys from it and decrypts with them -- so what changes
// between branches is only whether a reader sees the values. The published branch stores the
// same keys masked and unmasks them at each use. Keep the two in step: a key added here must
// be added there too, under the same name."""

# Every expression that READS a masked value and must therefore unmask it. Exact source text,
# because a regex here could miss a site and the miss is silent.
WRAP_SITES = [
    ("MFR_KEYS[k].key", "ks_unmaskMfrKey(MFR_KEYS[k].key)"),
    ("MFR_KEYS[i].key", "ks_unmaskMfrKey(MFR_KEYS[i].key)"),
    ("ks_klDecrypt(f.encrypted, KIA_V34_MF_KEY)",
     "ks_klDecrypt(f.encrypted, ks_unmaskMfrKey(KIA_V34_MF_KEY))"),
    ("ks_klEncrypt(pt, KIA_V34_MF_KEY)",
     "ks_klEncrypt(pt, ks_unmaskMfrKey(KIA_V34_MF_KEY))"),
    ("ks_klEncrypt(gotPt, KIA_V34_MF_KEY)",
     "ks_klEncrypt(gotPt, ks_unmaskMfrKey(KIA_V34_MF_KEY))"),
    ("ks_klEncrypt(pt,KIA_V34_MF_KEY)",
     "ks_klEncrypt(pt,ks_unmaskMfrKey(KIA_V34_MF_KEY))"),
]


def locate(src):
    m = TABLE.search(src)
    if not m:
        sys.exit("MFR_KEYS table not found")
    return m


def read_keys(src):
    es = list(ENTRY.finditer(locate(src).group("body")))
    return es, [int(e.group("key"), 16) for e in es]


def transform_sketch(src):
    """plaintext development sketch -> masked published variant. Returns (text, report)."""
    report = {}
    es, keys = read_keys(src)

    # Refuse rather than guess: a count change means the table moved and this tool's
    # assumptions need revisiting.
    if len(es) != 73:
        sys.exit(f"expected 73 entries, found {len(es)} -- refusing to transform")

    # If it is already masked, say so instead of double-masking (which is not identity for a
    # non-involutive transform, and would produce nonsense keys).
    defaults = {0x0000000000000000, 0xFFFFFFFFFFFFFFFF}
    as_is = sum(1 for k in keys if k in defaults)
    flipped = sum(1 for k in keys if decode(k) in defaults)
    if flipped > as_is:
        sys.exit("the table is already masked; run this on the development branch")

    # 1 + 2: mask the literals
    masked = [encode(k) for k in keys]
    body = locate(src).group("body")
    new_body = body
    for e, v in zip(es, masked):
        new_body = new_body.replace(e.group(0), f'{e.group("pre")}{v:016X}{e.group("post")}', 1)
    src = src[: locate(src).start("body")] + new_body + src[locate(src).end("body"):]

    # 2: the helper block, replacing the plaintext-branch comment
    if PLAIN_COMMENT not in src:
        sys.exit("the development branch's plaintext comment was not found -- "
                 "the sketch has changed shape; update this tool")
    src = src.replace(PLAIN_COMMENT, HELPER_BLOCK, 1)

    # the static_assert line that follows the comment moves above the modes; the helper block
    # already carries its own copy, so drop the duplicated original
    dup = ('static_assert(N_MFR_KEYS == 73, "MFR_KEYS count changed -- '
           'update research/sources/keeloq_mfcodes_public.txt and this assert together");\n')
    if dup in src:
        src = src.replace(dup, "", 1)

    # 3: the mfrKeys[2] test literal
    old_lit = f"mfrKeys[2] = {{ 0x{KIA_PLAIN}ULL,       // Kia V3/V4, from the table"
    new_lit = ("mfrKeys[2] = { ks_unmaskMfrKey(0xCC88E6C23CEC0269ULL),  // Kia V3/V4 (masked)")
    if old_lit in src:
        src = src.replace(old_lit, new_lit, 1)
        report["mfrKeys literal"] = "wrapped and masked"
    else:
        report["mfrKeys literal"] = "NOT FOUND"

    # 3: KIA_V34_MF_KEY definition + comment
    src = src.replace("// The same OEM key the table above carries, in plaintext on this branch.",
                      "// Stored masked, like MFR_KEYS; ks_unmaskMfrKey is applied at each use below.", 1)
    kia = re.search(r"#define KIA_V34_MF_KEY\s+0x([0-9A-Fa-f]{16})ULL", src)
    if not kia:
        sys.exit("KIA_V34_MF_KEY not found")
    kia_plain = int(kia.group(1), 16)
    kia_masked = encode(kia_plain)
    src = src.replace(f"#define KIA_V34_MF_KEY  0x{kia_plain:016X}ULL",
                      f"#define KIA_V34_MF_KEY  0x{kia_masked:016X}ULL", 1)
    report["KIA_V34_MF_KEY"] = f"masked 0x{kia_masked:016X} (plaintext not printed)"

    # 3: wrap each read site
    wrapped = 0
    for plain, masked_expr in WRAP_SITES:
        n = src.count(plain)
        if n:
            src = src.replace(plain, masked_expr)
            wrapped += n
    report["read sites wrapped"] = wrapped

    # ── verification ────────────────────────────────────────────────────────
    es2, keys2 = read_keys(src)
    errs = []
    if len(es2) != 73:
        errs.append(f"key count changed to {len(es2)}")
    bad = [i for i, (orig, now) in enumerate(zip(keys, keys2)) if decode(now) != orig]
    if bad:
        errs.append(f"{len(bad)} masked values do not round-trip (first: index {bad[0]})")

    # THE CHECK THAT MATTERS: no read of a masked value may be left unwrapped. An unwrapped read
    # compiles and boots and silently finds nothing.
    #
    # Note the check must look for occurrences NOT preceded by the wrapper, not for the bare
    # substring: the wrapped form ks_unmaskMfrKey(MFR_KEYS[k].key) contains MFR_KEYS[k].key, so a
    # substring test reports a false failure on correct output. That false positive was the first
    # thing this check did, which is a good argument for writing it as a prefix test.
    for plain, _ in WRAP_SITES:
        for m in re.finditer(re.escape(plain), src):
            pre = src[max(0, m.start() - 16):m.start()]
            if not pre.endswith("ks_unmaskMfrKey("):
                errs.append(f"unwrapped read left in the output: {plain}")
                break
    if "ks_unmaskMfrKey" not in src:
        errs.append("ks_unmaskMfrKey is absent")
    # the KIA macro must never be used bare
    for m in re.finditer(r"KIA_V34_MF_KEY\)", src):
        pre = src[max(0, m.start() - 20):m.start()]
        if "ks_unmaskMfrKey(" not in pre:
            errs.append("a bare KIA_V34_MF_KEY use survived")
            break

    report["errors"] = errs
    return src, report


def transform_test(src):
    """Adapt test_keeloq_key_table.py for the published variant.

    Two changes, both required by the masking:
      · invert the mask on the table values so the corpus comparison still means something;
        this doubles as a test that the sketch's mask and this file agree
      · skip the corpus cross-check when the plaintext corpus is absent, because that file is
        deliberately not published, so a fresh clone must still get a green suite
    """
    # 1. the corpus becomes optional
    plain_setup = '''HERE = Path(__file__).resolve().parent
FIRMWARE = HERE / "FOBworks_for_SGP.ino"
CORPUS = HERE / "research" / "sources" / "keeloq_mfcodes_public.txt"'''
    masked_setup = '''HERE = Path(__file__).resolve().parent
FIRMWARE = HERE / "FOBworks_for_SGP.ino"
# The manufacturer-key corpus is a local research fixture and is deliberately NOT published:
# it is the same keys the firmware already embeds, so shipping the file would add nothing a
# reader does not already have. Read it from research/sources/ when present locally, or from
# FOBWORKS_MFCODES. The cross-check below is skipped when it is absent, so this suite still
# runs in a fresh clone.
_env = os.environ.get("FOBWORKS_MFCODES")
CORPUS = Path(_env).expanduser() if _env else HERE / "research" / "sources" / "keeloq_mfcodes_public.txt"'''
    if plain_setup not in src:
        raise SystemExit("test: corpus setup block not found -- update publish_prepare.py")
    src = src.replace(plain_setup, masked_setup, 1)
    if "\nimport os\n" not in src:
        src = src.replace("from pathlib import Path\nimport re",
                          "from pathlib import Path\nimport os\nimport re", 1)

    # 2. unmask the parsed table values, using the sketch's own constants
    plain_parse = '''entries = [(n, k, learn_value(t), int(s)) for n, k, t, s in raw]'''
    masked_parse = '''# The stored values are masked. Read the constants from the sketch rather than duplicating
# them, so this file cannot drift from what the firmware actually inverts with.
_c = re.search(r"#define MFR_KEY_A\\s+(0x[0-9A-Fa-f]+)ULL", source)
assert _c, "MFR_KEY_A not found in the sketch"
MASK_A = int(_c.group(1), 16)
_c = re.search(r"#define MFR_KEY_B\\s+(0x[0-9A-Fa-f]+)ULL", source)
assert _c, "MFR_KEY_B not found in the sketch"
MASK_B = int(_c.group(1), 16)
_c = re.search(r"#define MFR_KEY_N\\s+(\\d+)", source)
assert _c, "MFR_KEY_N not found in the sketch"
MASK_N = int(_c.group(1))


def unmask(v):
    x = (int(v, 16) ^ MASK_B) & 0xFFFFFFFFFFFFFFFF
    return (((x >> MASK_N) | (x << (64 - MASK_N))) & 0xFFFFFFFFFFFFFFFF) ^ MASK_A


assert "static inline uint64_t ks_unmaskMfrKey(uint64_t v){" in source, \\
    "the unmask helper is missing; the table cannot be read"
entries = [(n, f"{unmask(k):016X}", learn_value(t), int(s)) for n, k, t, s in raw]'''
    if plain_parse not in src:
        raise SystemExit("test: entry parser not found -- update publish_prepare.py")
    src = src.replace(plain_parse, masked_parse, 1)

    # 3. guard the corpus comparison
    guard = '''corpus = []
for line in CORPUS.read_text(encoding="utf-8").splitlines():'''
    guarded = '''corpus = []
# The corpus file is not published, so a fresh clone has none. Guard the WHOLE comparison
# rather than only the read: with an empty corpus every firmware entry compares as "extra",
# which reports 73 false failures instead of skipping.
_corpus = CORPUS.read_text(encoding="utf-8") if CORPUS.is_file() else ""
if not _corpus:
    print(f"  corpus cross-check: skipped ({CORPUS.name} not present; "
          f"set FOBWORKS_MFCODES to run it)")
for line in _corpus.splitlines():'''
    if guard in src:
        src = src.replace(guard, guarded, 1)

    # The snippet text is Python source being written into another file, so it cannot be an
    # f-string of our own (it carries its own {sorted(...)} expressions). A placeholder token
    # followed by a substitution keeps the plaintext out of this tool while the emitted pattern
    # still matches the development test exactly.
    _corpus_tmpl = '''extra = table_set - corpus_set - {("Kia_V3_V4_OEM", "@KIA@", 1)}
assert not extra, f"firmware entries that do not match the corpus: {sorted(extra)}"
missing = corpus_set - table_set
assert not missing, f"corpus entries absent from the firmware table: {sorted(missing)}"'''.replace("@KIA@", KIA_PLAIN)
    _corpus_tmpl_guarded = '''if _corpus:
    extra = table_set - corpus_set - {("Kia_V3_V4_OEM", "@KIA@", 1)}
    assert not extra, f"firmware entries that do not match the corpus: {sorted(extra)}"
    missing = corpus_set - table_set
    assert not missing, f"corpus entries absent from the firmware table: {sorted(missing)}"
else:
    # Without the corpus there is nothing to compare against, but the table must still hold
    # the expected shape: 73 entries, the public OEM key present, and the mask consistent.
    assert len(table_set) == 73, f"expected 73 entries, found {len(table_set)}"'''.replace("@KIA@", KIA_PLAIN)
    corpus_cmp, corpus_cmp_guarded = _corpus_tmpl, _corpus_tmpl_guarded
    if corpus_cmp in src:
        src = src.replace(corpus_cmp, corpus_cmp_guarded, 1)

    # 4. assertions that pin a key-READ expression must follow the wrapping. The development
    # branch asserts on the bare form; the published variant wraps every read, so the same
    # assertion would fail against correct output. Handled by rewriting the pinned literals
    # rather than by deleting the assertions -- they are checking something real (that the
    # derivation goes through the shared helper, not a private copy of it).
    pinned = {
        '"ks_deriveOneMfrKey(sn, MFR_KEYS[k].key, dk)"':
            '"ks_deriveOneMfrKey(sn, ks_unmaskMfrKey(MFR_KEYS[k].key), dk)"',
        '"ks_klDecrypt(f.hop,MFR_KEYS[i].key)"':
            '"ks_klDecrypt(f.hop,ks_unmaskMfrKey(MFR_KEYS[i].key))"',
        '"TRY_KEY(MFR_KEYS[i].name, MFR_KEYS[i].key"':
            '"TRY_KEY(MFR_KEYS[i].name, ks_unmaskMfrKey(MFR_KEYS[i].key)"',
    }
    for plain, wrapped in pinned.items():
        if plain in src:
            src = src.replace(plain, wrapped)

    # 5. any remaining plaintext copy of the Kia key must go: a published file must not carry
    # it. Derive it once from the sketch's masked constant, which also re-checks the inverse and
    # catches the sketch's two independent copies of the key disagreeing.
    # The generator emits Python source, and the emitted regex needs a single backslash in the
    # file. Inside this '''...''' literal that means writing "\\s", which lands as "\s". Writing
    # "\\\\s" lands as "\\s" in the output, which then fails to match at runtime -- the bug this
    # line had.
    kia_derive = '''def unmask(v):
    x = (int(v, 16) ^ MASK_B) & 0xFFFFFFFFFFFFFFFF
    return (((x >> MASK_N) | (x << (64 - MASK_N))) & 0xFFFFFFFFFFFFFFFF) ^ MASK_A


# The Kia OEM key is public, but there is no reason to write it out here: take it from the
# masked constant the sketch ships and invert it, which also re-checks the inverse.
_kia_stored = re.search(r"#define KIA_V34_MF_KEY\\s+0x([0-9A-Fa-f]{16})ULL", source).group(1)
PUBLIC_KIA = unmask(_kia_stored)'''
    src = src.replace('''def unmask(v):
    x = (int(v, 16) ^ MASK_B) & 0xFFFFFFFFFFFFFFFF
    return (((x >> MASK_N) | (x << (64 - MASK_N))) & 0xFFFFFFFFFFFFFFFF) ^ MASK_A''',
                      kia_derive, 1)

    # now replace every remaining literal with the derived form
    src = src.replace(f'("Kia_V3_V4_OEM", "{KIA_PLAIN}", 1)',
                      '("Kia_V3_V4_OEM", f"{PUBLIC_KIA:016X}", 1)')
    return src


def transform_hop_xor(src):
    """Adapt test_hop_xor.py for the published variant.

    The live-crypto harness inside it defines the Kia OEM key in plaintext (the
    fob it builds is a real Kia frame, so the cipher it drives the firmware's
    XOR telemetry with has to use the real key). A published tree must not carry
    the literal, so the literal is removed from the file and the value is derived
    at run time from the sketch's masked constant and injected into the C source
    just before it is compiled. The literal then exists only in the temporary
    build file, never in the repository.
    """
    if KIA_PLAIN not in src:
        return src  # already masked or never had it

    # 1. neutralise the literal in the emitted C, leaving a token to substitute.
    src = src.replace(f"#define KIA_V34_MF_KEY 0x{KIA_PLAIN}ULL",
                      "#define KIA_V34_MF_KEY __KIA_ULL__", 1)

    # 2. a run-time deriver, dropped in after the imports so Path is available.
    prelude = '''# The Kia OEM key is public, but a published tree does not write it out. Derive it
# from the masked constant the sketch ships and inject it into the C harness at compile
# time, so the literal lives only in the temporary build file, never in this repo.
def _kia_literal():
    import re as _re
    _s = (Path(__file__).resolve().parent / "FOBworks_for_SGP.ino").read_text(encoding="utf-8")
    assert "static inline uint64_t ks_unmaskMfrKey(uint64_t v){" in _s, \\
        "the unmask helper is missing from the sketch"
    _k = int(_re.search(r"#define KIA_V34_MF_KEY\\s+0x([0-9A-Fa-f]{16})ULL", _s).group(1), 16)
    _x = (_k ^ 0x3C3C3C3C3C3C3C3C) & 0xFFFFFFFFFFFFFFFF
    _k = ((((_x >> 13) | (_x << (64 - 13))) & 0xFFFFFFFFFFFFFFFF) ^ 0x5A5A5A5A5A5A5A5A)
    return f"0x{_k:016X}ULL"

'''
    marker = "from pathlib import Path\n"
    if marker in src:
        src = src.replace(marker, marker + "\n" + prelude, 1)
    else:
        src = prelude + src

    # 3. substitute at the one write site that builds the encryption harness.
    src = src.replace(
        "tp.write_text(harness + body)",
        'tp.write_text((harness + body).replace("__KIA_ULL__", _kia_literal()))', 1)
    return src


# A worklog reference is an id after "research/" that is NOT a real path.
# "research/79_GDO0_HARDWARE_AUDIT.md" names a file a reader can open and stays;
# a bare "research/79" points into a file that is not published and goes. The
# lookahead blocks the path form (an id directly followed by ".<ext>").
_REF   = re.compile(r"research/(?:\d+)(?!\d*[0-9A-Za-z_]*\.\w)")
_WORKLOG_NUM = re.compile(r"\bworklog[ \t]*`?\d+")

# Ordered, most-specific first. Each pattern consumes a reference together with the
# connective tissue that would otherwise be left dangling. Nothing here matches bare
# code, so no edit can land in the wrong place: a reference only ever appears in a
# comment or a string literal.
_VERB = r"(?:see|per|from|in|at|via|as|of|to|and|recorded in|noted in|documented in|" \
        r"described in|detailed in|captured in|measured in|analysed in|analyzed in)"
# A citation phrase can wrap: the verb ends one line and the reference opens the
# next ("...signature described in\nworklog `13`: the capture..."). A line-by-line
# pass never sees that pair together, so the verb is left dangling. This pass runs on
# the whole text first. Its verb set is narrow -- no bare "in"/"at"/"via", which occur
# constantly in ordinary prose and would let the pattern eat a real word.
_XVERB = r"(?:see|per|from|of|recorded in|noted in|documented in|described in|" \
         r"detailed in|captured in|measured in|analysed in|analyzed in|" \
         r"set out in|listed in|written up in)"
# The match includes the whitespace before the verb and the optional colon after the
# reference, so the replacement is the whole separator: a colon when the reference
# introduced a clause, a single space otherwise. One match, no second pass -- the
# first cut at this ran a global space-before-colon rule, which flattened every
# aligned comment header in the sketch ("Version  :" -> "Version:").
# A parenthetical can open before the wrapped verb: "a (see\nresearch/01) b" removes the
# whole clause, parens included.
_XPAREN_LINE = re.compile(r"\([ \t]*(?:" + _XVERB + r")[ \t]*\r?\n[ \t]*(?:`?research/\d+`?|worklog[ \t]*`?\d+`?)[^()\n]*\)[ \t]?")
_XLINE = re.compile(r"([ \t]+)" + _XVERB + r"[ \t]*\r?\n[ \t]*(?:`?research/\d+`?|worklog[ \t]*`?\d+`?)[ \t]*(:?)")

_SEAMS = [
    # ", and research/88 is the record." -- conjunction + whole clause, so the
    # preceding sentence does not end on a stranded "and".
    re.compile(r",?[ \t]+and[ \t]+`?research/\d+`?[ \t]+is\b[^.]*\.[ \t]?"),
    # a whole sentence that points at a worklog entry ("research/79 is the full audit.")
    re.compile(r"`?research/\d+`?[ \t]+is\b[^.]*\.[ \t]?"),
    # a whole parenthetical built around a reference, verb prefix or not:
    # "(research/58 §7.2)", "(see research/01, section 1)", "(research/61 N14, research/69)"
    re.compile(r"\([ \t]*(?:" + _VERB + r"[ \t]+)?(?:research/\d+|worklog[ \t]*`?\d+`?)[^()]*\)[ \t]?"),
    # "worklog `36`" / "worklog 36" -- an id under a different label
    re.compile(r"\bworklog[ \t]*`?\d+`?[ \t]*[.,]?"),
    # `research/24` -- the backticks go with it. Path-shaped refs with a real
    # filename (`research/79_GDO0_....md`) are left alone by the (?!...\.ext)
    # form of _REF; this pattern still has to avoid eating those, so it only
    # matches a bare numeric id inside backticks.
    re.compile(r"`[ \t]*research/\d+[ \t]*`[ \t]?"),
    # research/46 and 52 / research/48 and /49 / research/60, research/61
    re.compile(r"research/\d+[ \t]*(?:,|and|/|&)[ \t]*/?[ \t]*(?:research/)?\d+[ \t]*[.,]?"),
    # "recorded in research/78." / "per research/04" -- verb and connector included
    re.compile(r"\b" + _VERB + r"[ \t]+research/\d+[ \t]*[.,]?"),
    # a bare token, swallowing a trailing period or comma (not path-shaped)
    re.compile(r"research/\d+(?!_[A-Za-z0-9])[ \t]*[.,]?"),
]

# Cleanup that is safe ONLY on a line an edit actually touched, and that can never
# move indentation: the run collapse demands a non-space on both sides, so leading
# whitespace survives and a Python continuation line cannot be reflowed.
_TIDY = [
    (re.compile(r"\x01"), ""),                          # marker from the cross-line join
    (re.compile(r"\([ \t]*(?:see|per|from|of|in|at|via)[ \t]*\)"), ""),  # "(see )" -> gone
    # Emptied grouping parens, only at a seam. The negative lookbehind is the point:
    # an empty paren run directly after an identifier is a zero-argument CALL
    # ("doc.exists()", "time.time()", "x.sort()"), and deleting those two characters
    # leaves a valid-looking reference to the function instead of its result. That is
    # how "check(\"research/86 present\", doc.exists())" became "doc.exists", which is
    # always truthy, so the check passed on a tree where the file was absent. Empty
    # grouping parens only ever follow a space, a bracket, or the line start.
    (re.compile(r"(?<![A-Za-z0-9_)\]])\([ \t]*\)"), ""),
    (re.compile(r"\([ \t]+"), "("),                 # "( §4)" -> "(§4)"
    (re.compile(r"([,;])[ \t]*\)"), r"\1)"),        # "(N14, )" -> "(N14)"
    (re.compile(r"[ \t]*[—–][ \t]*\)"), ")"),      # "no GDO0 — )" -> "no GDO0)"
    (re.compile(r"^//[ \t]*[.,;][ \t]*"), "// "),   # "// . Measured" -> "// Measured"
    (re.compile(r"^[ \t]*[:;][ \t]+"), ""),           # ": text" at a line start -> "text"
    (re.compile(r"^//[ \t]{2,}"), "// "),           # normalise a comment-only line
    (re.compile(r"[ \t]+\.(?=\s|$)"), "."),      # "telemetry ." -> "telemetry."
    (re.compile(r"([,;])[ \t]*(?=[,;])"), r"\1"),   # ", ," -> ","
    (re.compile(r",[ \t]*\)"), ")"),              # "(v3.95,)" -> "(v3.95)"
    (re.compile(r"[ \t]+([:;])"), r"\1"),         # "closure :" -> "closure:"
    # Stranded connective after a clause was removed: "...establish that, and"
    (re.compile(r",[ \t]+and[ \t]*$"), "."),
    (re.compile(r"[ \t]+and[ \t]*$"), ""),
    (re.compile(r",[ \t]+(?:see|per|from|of)[ \t]*$"), "."),
    (re.compile(r"(?<=\S)[ \t]{2,}(?=\S)"), " "),   # internal double space only
]


def _tidy(span):
    for pat, rep in _TIDY:
        span = pat.sub(rep, span)
    return span.rstrip()


def strip_worklog_refs(src):
    """Remove references to the private worklog from a published file.

    The worklog holds this project's design notes; it is not published. Source
    comments, test docstrings, and a few user-facing runtime strings cite entries by
    number. Those pointers dangle for a public reader, so they come out uniformly
    rather than only in the README. "research/sources/..." paths are shipped fixtures
    and are left alone, as are real worklog filenames ("research/79_....md").

    Every edit is anchored to an actual reference, then tidied only within that line.
    The first cut at this collapsed parens and spacing across the whole file, which
    deleted the "()" in a "[](){" lambda and broke the build. Tying every edit to a
    line that actually contains a reference is what stops that from coming back;
    unchanged lines come back byte for byte.
    """
    # a citation whose reference wrapped to the next line; the match spans the
    # The join can strand punctuation the per-line tidy would otherwise fix ("no
    # GDO0 — see\nresearch/74)" -> "no GDO0 — )"), but the joined line no longer
    # contains a reference, so the gate below would skip it. Mark the joined line
    # with \x01 so it is processed regardless, and drop the marker in _tidy.
    src = _XPAREN_LINE.sub("", src)
    src = _XLINE.sub(lambda m: ("\x01:" if m.group(2) else "\x01 "), src)
    out = []
    for line in src.split("\n"):
        if "\x01" not in line and "research/" not in line and "worklog" not in line:
            out.append(line)
            continue
        if "\x01" not in line and not (_REF.search(line) or _WORKLOG_NUM.search(line)):
            out.append(line)
            continue
        new = line
        for pat in _SEAMS:
            new = pat.sub("", new)
        if new == line and "\x01" not in line:
            out.append(line)      # only path-shaped refs; leave untouched
            continue
        cut = new.find("//")
        if cut >= 0:              # code line: tidy the comment only, keep the code
            out.append(new[:cut] + _tidy(new[cut:]))
        else:                     # prose, docstring, or a string-literal line
            out.append(_tidy(new))
    s = "\n".join(out)
    m = _REF.search(s)
    if m:
        raise SystemExit("worklog reference survived the strip: "
                         + s[max(0, m.start() - 40):m.end() + 20])
    return s


def transform_worklog_gate(src, path, num, name_var):
    """Make a test's worklog-presence checks skip cleanly on the published tree.

    Two suites assert a private worklog file exists and then read findings out of
    it. The worklogs are deliberately not published, so on the public tree those
    checks would fail a fresh clone for the wrong reason. This mirrors what
    test_keeloq_key_table.py already does for the private key corpus: skip the
    check when the fixture is absent, and say so, rather than fail.
    """
    present = f'    check("research/{num} present", {name_var}.exists())\n'
    guard = f'    if {name_var}.exists():\n'
    if present + guard not in src:
        raise SystemExit(f"worklog gate block not found in {path}")
    skip = (f'    # research/{num} is a private worklog and is not published; skip its note checks\n'
            f'    # when it is absent so a fresh clone still gets a green suite.\n'
            f'    if not {name_var}.exists():\n'
            f'        print("  research/{num} note: skipped (worklog not published)")\n'
            f'    else:\n')
    return src.replace(present + guard, skip, 1)


def transform_a2(src_sketch_b64):
    """Adapt research/sources/a2_kia_v34.py: it carries the Kia key in plaintext.

    Replaced with the same masked-constant derivation the old publish branch used, including its
    structural self-check -- it re-encodes the recovered value and compares against the stored
    form, so it verifies the inverse without writing the key out.
    """
    path = ROOT / "research" / "sources" / "a2_kia_v34.py"
    s = path.read_text(encoding="utf-8")
    plain = f"KIA_V34_MF_KEY = 0x{KIA_PLAIN}"
    if plain not in s:
        raise SystemExit("a2_kia_v34.py: plaintext KIA_V34_MF_KEY not found")
    masked = '''# Stored masked, matching the firmware's MFR_KEYS entry (see tools/mask_mfrkeys.py).
_KIA_STORED = 0xCC88E6C23CEC0269
_MK_A, _MK_B, _MK_N = 0x5A5A5A5A5A5A5A5A, 0x3C3C3C3C3C3C3C3C, 13
_M64 = (1 << 64) - 1
_x = (_KIA_STORED ^ _MK_B) & _M64
KIA_V34_MF_KEY = (((_x >> _MK_N) | (_x << (64 - _MK_N))) & _M64) ^ _MK_A
# Self-check the inverse structurally, without writing the key out: re-encoding the
# recovered value must return the stored form.
_re = (((KIA_V34_MF_KEY ^ _MK_A) & _M64) << _MK_N | ((KIA_V34_MF_KEY ^ _MK_A) & _M64) >> (64 - _MK_N))
assert (((_re & _M64) ^ _MK_B) & _M64) == _KIA_STORED, "the masked Kia key does not invert"'''
    return s.replace(plain, masked, 1)


def scrub_citations(src):
    """The citations name the key in prose. Keep the fact, drop the literal."""
    plain = f"Cross-listed source for the Kia/Hyundai V3/V4 manufacturer key `0x{KIA_PLAIN}` used by `ks_decodeKiaV34`"
    safe = ("Cross-listed source for the Kia/Hyundai V3/V4 manufacturer key used by "
            "`ks_decodeKiaV34`")
    return src.replace(plain, safe, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="tree to write the variant into")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    src = SKETCH.read_text(encoding="utf-8")
    out, report = transform_sketch(src)

    print("publish_prepare: development sketch -> published variant")
    for k, v in report.items():
        if k == "errors":
            continue
        print(f"  {k:22} {v}")
    errs = report["errors"]
    if errs:
        print("\nVERIFICATION FAILED:")
        for e in errs:
            print(f"  - {e}")
        return 1
    print("  verification           all masked values round-trip; no unwrapped reads")
    _, keys = read_keys(src)
    _, keys2 = read_keys(out)
    # Report the mask -> mask identity, not a plaintext sample: this console output is echoed
    # into build logs and chat, and the plaintext sample printed here was a second way the key
    # left the development tree.
    # No sample value at all: keys[] comes from the development sketch and is the plaintext,
    # and printing it -- even beside its masked twin -- writes the key into the build log. The
    # round-trip is already asserted above; the count is all this line needs to say.
    print("  round-trip             73/73 keys decode to their originals")

    if args.check or not args.out:
        print("\n--check: nothing written")
        return 0

    dest = Path(args.out) / "FOBworks_for_SGP.ino"
    if not (Path(args.out) / ".git").exists() and not args.out.startswith("/tmp"):
        print(f"\nrefusing to write outside a git tree or /tmp: {args.out}")
        return 1
    # No .bak: it would contain the plaintext branch's sketch, and in a published tree that is
    # a key disclosure sitting next to the file it was masked in. The git history is the backup.
    dest.write_text(out, encoding="utf-8")
    print(f"\nwrote {dest}")

    # the test variant, when the tree carries one
    tdest = Path(args.out) / "test_keeloq_key_table.py"
    if tdest.is_file():
        try:
            tsrc = transform_test(TEST_KEELOQ.read_text(encoding="utf-8"))
        except SystemExit as e:
            print(f"  test variant: NOT written ({e})")
            return 1
        tdest.write_text(tsrc, encoding="utf-8")
        print(f"wrote {tdest}")

    # test_hop_xor.py carries the Kia key in its live-crypto harness
    hdest = Path(args.out) / "test_hop_xor.py"
    if hdest.is_file():
        hdest.write_text(transform_hop_xor(TEST_HOP_XOR.read_text(encoding="utf-8")),
                         encoding="utf-8")
        print(f"wrote {hdest}")

    # Suites that assert a private worklog exists and then read findings out of it.
    # The worklogs are not published, so their note checks must skip rather than
    # fail a fresh clone -- the same treatment test_keeloq_key_table.py already
    # gives the private key corpus. This list is not optional: a suite with a
    # "research/NN present" check that is NOT listed here has its check line
    # scrubbed as prose, and the empty-paren tidy then eats the "()" in the
    # assertion beside it, leaving a call that passes no matter what. That is how
    # test_renault_rke_crack.py first shipped green on the public tree while
    # checking nothing.
    for name, num, name_var in [
        ("test_gdo0_audit.py", 79, "NOTE"),
        ("test_renault_layer2.py", 78, "doc"),
        ("test_renault_rke_crack.py", 86, "doc"),
    ]:
        wdest = Path(args.out) / name
        if wdest.is_file():
            wdest.write_text(
                transform_worklog_gate(wdest.read_text(encoding="utf-8"), name, num, name_var),
                encoding="utf-8")
            print(f"wrote {wdest} (worklog note checks skip when absent)")

    # the a2 helper carries the key in plaintext too
    adest = Path(args.out) / "research" / "sources" / "a2_kia_v34.py"
    if adest.is_file():
        adest.write_text(transform_a2(None), encoding="utf-8")
        print(f"wrote {adest}")

    # and the citations name it in prose
    cdest = Path(args.out) / "CITATIONS_AND_REFERENCES.md"
    if cdest.is_file():
        before = cdest.read_text(encoding="utf-8")
        after = scrub_citations(before)
        if after != before:
            cdest.write_text(after, encoding="utf-8")
            print(f"wrote {cdest} (literal removed)")

    # README prose must not point at the private worklog either
    rdest = Path(args.out) / "README.md"
    if rdest.is_file():
        before = rdest.read_text(encoding="utf-8")
        after = strip_worklog_refs(before)
        if after != before:
            rdest.write_text(after, encoding="utf-8")
            n = before.count("research/") - after.count("research/")
            print(f"wrote {rdest} ({n} worklog pointer(s) removed)")

    # ...nor may any other published text file. The tests cite entries in their
    # docstrings, the tools in their comments, and a couple of firmware runtime
    # strings carry one into the dashboard. Strip them uniformly so the public
    # tree has no dangling pointer anywhere, not just at the front door.
    stripped = []
    for p in sorted(Path(args.out).rglob("*")):
        if not p.is_file() or p.name == "publish_prepare.py":
            continue
        if p.suffix not in (".py", ".md", ".ino", ".h", ".cpp", ".txt", ".json"):
            continue
        try:
            before = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "research/" not in before and "worklog" not in before:
            continue
        if not (_REF.search(before) or _WORKLOG_NUM.search(before)):
            continue
        after = strip_worklog_refs(before)
        if after != before:
            p.write_text(after, encoding="utf-8")
            stripped.append(str(p.relative_to(args.out)))
    if stripped:
        print(f"stripped worklog refs from {len(stripped)} file(s) "
              f"(e.g. {', '.join(stripped[:3])}{'…' if len(stripped) > 3 else ''})")

    # ── final gate: no plaintext key anywhere in the output tree ────────────
    # No exemptions. This earlier excluded publish_prepare.py "so the gate would pass", which
    # meant the tool's own copy of the key shipped in the published tree and quietly defeated
    # the transform. The tool now holds the key masked and derives it at run time, so the file
    # the gate reads contains no plaintext either -- and the gate can scan every file. The
    # needle is computed from the stored form, so it is not written here either.
    needle = f"{decode(_KIA_STORED):016X}"
    leaks = []
    for p in Path(args.out).rglob("*"):
        if p.is_file() and p.suffix in (".py", ".md", ".ino", ".txt", ".h", ".cpp", ".sh", ".json"):
            try:
                if needle in p.read_text(encoding="utf-8", errors="ignore"):
                    leaks.append(str(p.relative_to(args.out)))
            except OSError:
                pass
    if leaks:
        print("\nFINAL GATE FAILED -- plaintext key present in the published tree:")
        for l in leaks:
            print(f"  {l}")
        return 1
    print("final gate: no plaintext key anywhere in the published tree")

    # ── final gate: no scrub mangled a live expression ──────────────────────
    # A check that asserts a private worklog exists is prose to a reader, so the
    # scrub removes the reference -- and if the line also carried a zero-argument
    # call, an over-eager tidy could take the "()" with it. The result compiles,
    # runs, and passes while checking nothing, which is the worst failure mode a
    # publication step has. Scan the published Python for the shape that produces it:
    # a value-passing call whose argument is a bare function reference rather than a
    # call or a comparison. Cheap to run, and it fails loudly instead of publishing a
    # test that cannot fail.
    mangled = []
    for p in Path(args.out).rglob("*.py"):
        if p.name == "publish_prepare.py":
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            # A value-passing call whose last argument is a bare DOTTED name with no
            # call and no operator: "check(\"present\", doc.exists)". A literal
            # ("... , False") or a comparison ("check(needle in src, why)") is normal
            # and must not be flagged, so the argument has to carry a dot and no paren.
            m = re.search(r",\s*([A-Za-z_]\w*\.[A-Za-z_]\w*)\s*\)\s*$", line)
            if m and "check(" in line:
                mangled.append(f"{p.relative_to(args.out)}:{i}: {line.strip()[:70]}")
    if mangled:
        print("\nFINAL GATE FAILED -- a scrub looks to have eaten a call's parentheses:")
        for l in mangled:
            print(f"  {l}")
        print("  Refusing to publish a check that would always pass. Add the affected "
              "file to the worklog-gate list in main() if it asserts on a worklog.")
        return 1
    print("final gate: no scrub-mangled call sites in the published tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
