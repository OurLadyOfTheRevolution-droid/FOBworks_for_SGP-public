#!/usr/bin/env python3
"""Host checks for the publication transform in tools/publish_prepare.py.

The public branch is not a filtered copy of this one; it is a code variant with a
coordinated disclosure transform, and every part of that transform fails in a way
that is quiet unless something checks it:

  1. masking the key table without wrapping the reads compiles, boots, and derives
     keys from masked values -- it finds nothing and does not look broken;
  2. a key literal left in prose, a test, or a tool undoes the masking the sketch
     does, because the reader only needs the one value;
  3. the worklog scrub edits text near live expressions, and an over-broad tidy
     rule can take a zero-argument call's parentheses with the reference, leaving
     "check(..., doc.exists)" -- always truthy, so the check passes while checking
     nothing.

Case 3 is real: it shipped once in test_renault_rke_crack.py, on a tree where the
file it asserted was deliberately absent. Nothing in the host set exercised the
transform, so nothing noticed. These checks run the transform against the current
sketch and scan its output, rather than trusting that it still does what it says.
"""

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("  ok   " if ok else "  FAIL ") + name + (f" — {detail}" if detail else ""))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    pp = load(TOOLS / "publish_prepare.py", "publish_prepare")
    sketch = (ROOT / "FOBworks_for_SGP.ino").read_text(encoding="utf-8")

    # Which tree am I in? Ask the tool's own question: a table whose values invert to
    # the filler defaults is already masked, so this is the published tree and the
    # transform has nothing to do. Use the tool's own predicate rather than a marker
    # so the two cannot disagree about what "masked" means.
    _, keys = pp.read_keys(sketch)
    defaults = {0x0000000000000000, 0xFFFFFFFFFFFFFFFF}
    published = (sum(1 for k in keys if pp.decode(k) in defaults)
                 > sum(1 for k in keys if k in defaults))
    print(f"tree: {'published (table already masked)' if published else 'development'}")

    # The Kia OEM key is public, but a file that ships does not write it out. On the
    # development tree the constant is the plaintext; on the published tree it is the
    # masked form, so invert it to recover the value the gate must not find. Either
    # way this file never carries the literal.
    m = re.search(r"#define KIA_V34_MF_KEY\s+0x([0-9A-Fa-f]{16})ULL", sketch)
    check("the sketch defines KIA_V34_MF_KEY", bool(m))
    stored = int(m.group(1), 16)
    KIA = pp.decode(stored) if published else stored
    KIA_HEX = f"{KIA:016X}"

    if published:
        # Verify the shipped variant directly. This is the tree a reader gets, so
        # these are the properties that actually matter: masked values, wrapped reads.
        print("\n=== the shipped variant masks the table and wraps every read ===")
        check("the key count is 73", len(keys) == 73, f"{len(keys)}")
        check("the stored table is masked, not plaintext", published)
        check("the unmask helper is present",
              "static inline uint64_t ks_unmaskMfrKey(uint64_t v){" in sketch)
        unwrapped = []
        for plain, _ in pp.WRAP_SITES:
            for mm in re.finditer(re.escape(plain), sketch):
                if not sketch[max(0, mm.start() - 16):mm.start()].endswith("ks_unmaskMfrKey("):
                    unwrapped.append(plain)
        check("no read of a masked value is left unwrapped", not unwrapped,
              ", ".join(sorted(set(unwrapped))[:3]))
        check("no bare KIA_V34_MF_KEY use survives",
              all("ks_unmaskMfrKey(" in sketch[max(0, mm.start() - 20):mm.start()]
                  for mm in re.finditer(r"KIA_V34_MF_KEY\)", sketch)))
        check("the plaintext Kia key is absent from the shipped sketch",
              KIA_HEX not in sketch)
    else:
        print("\n=== the transform runs and reports no error ===")
        out, report = pp.transform_sketch(sketch)
        check("the transform completes", isinstance(out, str) and len(out) > 1000)
        check("no verification errors", not report.get("errors"),
              str(report.get("errors"))[:120])
        check("all read sites were wrapped", report.get("read sites wrapped", 0) >= 8,
              f"{report.get('read sites wrapped')} sites")

        print("\n=== masking is complete, not cosmetic ===")
        _, keys_out = pp.read_keys(out)
        check("the key count is unchanged at 73", len(keys_out) == 73, f"{len(keys_out)}")
        check("every masked value round-trips to its original",
              all(pp.decode(v) == k for k, v in zip(keys, keys_out)))
        check("no masked value equals its plaintext (the transform is not identity)",
              all(v != k for k, v in zip(keys, keys_out)))
        # the one that matters: a masked value read without unmasking finds nothing
        unwrapped = []
        for plain, _ in pp.WRAP_SITES:
            for mm in re.finditer(re.escape(plain), out):
                if not out[max(0, mm.start() - 16):mm.start()].endswith("ks_unmaskMfrKey("):
                    unwrapped.append(plain)
        check("no read of a masked value is left unwrapped", not unwrapped,
              ", ".join(sorted(set(unwrapped))[:3]))
        check("the unmask helper is present",
              "static inline uint64_t ks_unmaskMfrKey(uint64_t v){" in out)
        check("no bare KIA_V34_MF_KEY use survives",
              all("ks_unmaskMfrKey(" in out[max(0, mm.start() - 20):mm.start()]
                  for mm in re.finditer(r"KIA_V34_MF_KEY\)", out)))
        check("the plaintext Kia key is gone from the transformed sketch",
              KIA_HEX not in out)

    print("\n=== the tidy rule cannot eat a call's parentheses (the regression) ===")
    # the exact line that was corrupted, plus the general shape
    for src, why in [
        (' check("present", doc.exists())', "the line that shipped broken"),
        ("    if not doc.exists():", "a guarded call"),
        ("    x = f()", "a bare assignment from a call"),
        ("    TOOL = Path(__file__).resolve().parent / \"tools/x.py\"", "a Path join"),
    ]:
        check(f"tidy preserves: {why}", pp._tidy(src) == src,
              f"{src!r} -> {pp._tidy(src)!r}")

    print("\n=== no published suite can assert on a worklog without being gated ===")
    # Every test file that carries a "research/NN present" assertion gets the
    # skip-gate treatment. If a file is missed, its check line is scrubbed as prose
    # and -- before the tidy fix -- the assertion beside it lost its call. Read the
    # gate list from the tool itself so this cannot drift from what ships.
    gate_src = (TOOLS / "publish_prepare.py").read_text(encoding="utf-8")
    listed = set(re.findall(r'\("(test_[a-z0-9_]+\.py)",\s*\d+,', gate_src))
    carriers = set()
    for p in sorted(ROOT.glob("test_*.py")):
        # This suite necessarily contains the pattern it searches for, so it would
        # always report itself. Self-exclusion, the same as publish_prepare's own
        # exclusion from the plaintext-key gate.
        if p.name == Path(__file__).name:
            continue
        text = p.read_text(encoding="utf-8")
        if re.search(r'check\(\s*"research/\d+ present"', text):
            carriers.add(p.name)
    missing = carriers - listed
    check("every suite asserting a worklog is in the gate list", not missing,
          f"ungated: {sorted(missing)}")
    if not published:
        # On the development tree the two sets must match exactly: a listed suite that
        # no longer asserts on a worklog means the gate list has drifted. On the
        # published tree the checks have been rewritten into skip-gates, so there are
        # no carriers left to compare against and only the direction above applies.
        check("no entry in the gate list is stale", not (listed - carriers),
              f"listed but no assertion: {sorted(listed - carriers)}")
    else:
        check("no published suite is left asserting on a worklog", not carriers,
              f"still asserting: {sorted(carriers)}")

    print("\n=== the final gate still fires on a planted leak ===")
    # A guard that cannot fail is decoration. Plant the Kia key in a throwaway tree
    # and confirm main()'s leak scan would catch it. The scan is inlined here rather
    # than run through main(), which would re-read the whole tree.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / "ok.py").write_text("x = 1\n")
        (t / "leak.md").write_text(f"the key is 0x{KIA_HEX}\n")
        found = []
        for p in t.rglob("*"):
            if p.is_file() and p.suffix in (".py", ".md", ".ino", ".txt"):
                if KIA_HEX in p.read_text(encoding="utf-8", errors="ignore"):
                    found.append(p.name)
        check("planted plaintext key is detected", found == ["leak.md"], str(found))

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
