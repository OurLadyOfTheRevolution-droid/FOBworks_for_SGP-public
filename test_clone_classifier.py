#!/usr/bin/env python3
"""Host harness for the N28 clone-chip classifier.

The classifier is firmware logic, so the test extracts the real ks_cloneClassify()
from the sketch, compiles it with the ring it reads, and drives it with frame
bursts. Two things are being checked at once:

  1. The C function and the host tool tools/clone_classifier.py agree on the SAME
     synthetic frames. If either drifts, this fails — the same discipline
     test_keeloq_slide_lab.py uses to pin the host cipher to the card's.

  2. The statistical leg is calibrated: over many random REAL KeeLoq keys the
     verdict stays "cipher-consistent", and a counter-linear hop is always caught.
     The bands (8 / 12) are only honest if that separation holds.
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
sys.path.insert(0, str(ROOT / "tools"))
from clone_classifier import Frame, classify, gen_frames, SPARSE_MAX, OEM_MIN  # noqa: E402
from keeloq_slide_lab import encrypt  # noqa: E402

FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def extract_body(src, sig):
    """Return the full definition of a function by brace-matching from its
    declaration. `sig` must be the declaration prefix (return type + name), so a
    bare mention of the name in a comment is not mistaken for the definition."""
    idx = src.find(sig)
    if idx < 0:
        return None
    start = src.rfind("\n", 0, idx) + 1
    brace = src.find("{", idx)
    if brace < 0:
        return None
    depth = 0
    i = brace
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
        i += 1
    return None


def c_frames(frames):
    rows = ",".join(f"{{{f['sn']}u,{f['hop']}u,{f['btn']},{f.get('sts', 0)},{f['ctr']}u}}"
                    for f in frames)
    return "{" + rows + "}"


def build_cases():
    """(label, frames) for every verdict band, plus two-fob and drift rings."""
    cases = []
    cases.append(("oem", [f.__dict__ for f in gen_frames("oem")]))
    cases.append(("clone-noncipher", [f.__dict__ for f in gen_frames("clone-noncipher")]))
    cases.append(("clone-xorconst", [f.__dict__ for f in gen_frames("clone-xorconst")]))
    cases.append(("clone-cipher", [f.__dict__ for f in gen_frames("clone-cipher")]))
    cases.append(("disc-zero", [f.__dict__ for f in gen_frames("clone-disc-zero")]))
    cases.append(("disc-drift", [f.__dict__ for f in gen_frames("clone-disc-drift")]))
    # 20 random real keys: the statistical leg must hold for all of them.
    for i in range(20):
        key = int.from_bytes(os.urandom(8), "big")
        cases.append((f"oem-key{i}", [f.__dict__ for f in gen_frames("oem", key=key)]))
    return cases


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the classifier exists and is wired ===")
    body = extract_body(src, "static const char* ks_cloneClassify")
    check(body is not None, "ks_cloneClassify extracted")
    emit = extract_body(src, "static void ks_cloneClassEmit")
    check(emit is not None, "ks_cloneClassEmit extracted")
    check("#define CC_SPARSE_MAX 8" in src, "sparse band defined at 8")
    check("#define CC_OEM_MIN    12" in src, "cipher band defined at 12")
    check('{"cmd":"clone_class"}' in src or '"clone_class"' in src,
          "clone_class serial command present")
    check('protectedRoute("/api/clone_class"' in src, "/api/clone_class route present")
    check('doc["clone_class"]' in src, "per-decode clone_class field written")
    check("const char* ks_cloneClassify" in src, "classifier signature intact")
    if not body:
        print("\nCLONE CLASSIFIER CHECKS FAILED (extraction)")
        return 1

    print("\n=== the C function and the host tool agree ===")
    # The ring size is a firmware constant; read it rather than hardcode it, so the
    # harness cannot silently diverge from the card. Test cases are truncated to
    # the ring, because the card only ever classifies what is in the ring.
    m = re.search(r"#define KL_RECENT_MAX (\d+)", src)
    ring = int(m.group(1)) if m else 5
    cases = [(lbl, fr[:ring]) for lbl, fr in build_cases()]
    cases_c = ",\n".join(
        f'{{"{lbl}", {c_frames(fr)}, {len(fr)}}}' for lbl, fr in cases)
    harness = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define KL_RECENT_MAX """ + str(ring) + r"""
#define CC_SPARSE_MAX 8
#define CC_OEM_MIN 12
#define CC_MIN_PAIRS 3
struct KLFrame { uint32_t sn,hop; uint8_t btn,sts; uint32_t rawCtr; };
static KLFrame  KL_RECENT_BUF[KL_RECENT_MAX];
static uint8_t  KL_RECENT_HEAD = 0;
static uint8_t  KL_RECENT_CNT  = 0;
static uint8_t ks_hopRingStart(){ return (KL_RECENT_HEAD + KL_RECENT_MAX - KL_RECENT_CNT) % KL_RECENT_MAX; }
static const KLFrame& ks_hopRingAt(uint8_t i){ return KL_RECENT_BUF[(ks_hopRingStart()+i)%KL_RECENT_MAX]; }
""" + body + r"""
typedef struct { const char* label; KLFrame f[8]; int n; } Case;
static Case CASES[] = {
""" + cases_c + r"""
};
#define NCASE ((int)(sizeof(CASES)/sizeof(CASES[0])))
int main(void){
  for(int c=0;c<NCASE;c++){
    // load the ring oldest-first
    KL_RECENT_HEAD=0; KL_RECENT_CNT=0;
    for(int i=0;i<CASES[c].n;i++){
      KL_RECENT_BUF[KL_RECENT_HEAD]=CASES[c].f[i];
      KL_RECENT_HEAD=(KL_RECENT_HEAD+1)%KL_RECENT_MAX;
      if(KL_RECENT_CNT<KL_RECENT_MAX) KL_RECENT_CNT++;
    }
    const char* note; int med; uint8_t pairs, discBad; bool ctrLin;
    const char* v = ks_cloneClassify(&note,&med,&pairs,&ctrLin,&discBad);
    printf("%s|%s|%d|%d|%d|%d\n", CASES[c].label, v, med, (int)pairs,
           ctrLin?1:0, (int)discBad);
  }
  return 0;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "t.cpp"
        tp.write_text(harness)
        exe = str(Path(tmp) / "t")
        r = subprocess.run(["clang++", "-std=c++17", "-O1", "-o", exe, str(tp)],
                           capture_output=True, text=True)
        check(r.returncode == 0, f"classifier harness compiles {r.stderr[:160]}")
        if r.returncode != 0:
            print("\nCLONE CLASSIFIER CHECKS FAILED (compile)")
            return 1
        p = subprocess.run([exe], capture_output=True, text=True)
        got = {}
        for line in p.stdout.strip().splitlines():
            lbl, v, med, pairs, cl, db = line.split("|")
            got[lbl] = dict(verdict=v, med=int(med), pairs=int(pairs),
                            ctr_lin=bool(int(cl)), disc_bad=bool(int(db)))
        agree = 0
        for lbl, frames in cases:
            py = classify([Frame(**f) for f in frames])
            c = got.get(lbl)
            if c is None:
                check(False, f"{lbl}: no C verdict")
                continue
            same = (c["verdict"] == py.verdict and c["med"] == py.med_flip
                    and c["pairs"] == py.pairs and c["ctr_lin"] == py.counter_linear
                    and c["disc_bad"] == bool(py.disc_bad))
            agree += same
            check(same, f"{lbl}: C={c['verdict']} py={py.verdict} "
                        f"(med {c['med']}/{py.med_flip})")
        print(f"    {agree}/{len(cases)} cases agree between the card and the host tool")

    print("\n=== the verdicts are the ones the bands promise ===")
    # Rebuild the named cases (the ring-truncated ones are for the C comparison).
    named = dict(build_cases()[:6])
    for lbl, frames in named.items():
        py = classify([Frame(**f) for f in frames])
        want = {
            "oem": "cipher-consistent",
            "clone-noncipher": "non-cipher-clone",
            "clone-xorconst": "non-cipher-clone",
            "clone-cipher": "cipher-consistent",
            "disc-zero": "clone-suspect",
            "disc-drift": "clone-suspect",
        }[lbl]
        check(py.verdict == want, f"{lbl} -> {py.verdict} (want {want})")

    print("\n=== the statistical separation over 20 random real keys ===")
    # A real fob must NEVER be called a clone. It may come back `unknown` on a short
    # burst — with four pairs the median can dip, and the classifier says so rather
    # than guessing — so the invariant is "never a clone verdict", plus the majority
    # being `cipher-consistent`.
    oem_verdicts = [classify([Frame(**f) for f in frames]).verdict
                    for lbl, frames in cases if lbl.startswith("oem-key")]
    bad = [v for v in oem_verdicts if v in ("non-cipher-clone", "clone-suspect")]
    check(not bad, f"no random OEM key is ever called a clone (bad: {bad})")
    dense = sum(1 for v in oem_verdicts if v == "cipher-consistent")
    check(dense >= 17, f"at least 17/20 random OEM keys are cipher-consistent ({dense}/20)")
    # The raw one-step flip counts sit in the dense band. A single pair can drift
    # low (the cipher's output difference is not bounded below), which is exactly
    # why the classifier uses a median over several pairs and not one pair — so the
    # invariant to assert is the mean and the low-tail rate, not the minimum.
    flips = []
    for _ in range(2000):
        key = int.from_bytes(os.urandom(8), "big")
        a = encrypt(0x100 | (0x5A3 << 16) | (3 << 28), key)
        b = encrypt(0x101 | (0x5A3 << 16) | (3 << 28), key)
        flips.append(bin(a ^ b).count("1"))
    mean = sum(flips) / len(flips)
    low = sum(1 for w in flips if w <= SPARSE_MAX) / len(flips)
    check(abs(mean - 16.0) < 0.4, f"real hop-XOR mean flip is ~16 (measured {mean:.2f})")
    check(low < 0.02, f"under 2% of real pairs fall at or below {SPARSE_MAX} "
                      f"(measured {low:.3%})")

    print("\n=== a counter-linear hop is sparse by median, not by every pair ===")
    # A +1 counter step flips the carry chain, so most steps flip one bit and the
    # worst flips a whole 16-bit word. The classifier's handle is the median over
    # several pairs; that is the invariant, and it is far below the band.
    cw = [bin((c & 0xFFFF) ^ ((c + 1) & 0xFFFF)).count("1") for c in range(2000)]
    med = sorted(cw)[len(cw) // 2]
    check(med <= SPARSE_MAX, f"counter-linear median flip is <= {SPARSE_MAX} (measured {med})")
    check(max(cw) <= 16, f"no single +1 counter step exceeds the counter width (max {max(cw)})")
    # A run of four consecutive presses gives the classifier four pairs; the
    # verdict must be the clone one from any starting counter.
    for start in (0, 0x7FF, 0xFFFF - 3):
        fr = [Frame((0x5A3 << 4) | 3, (start + i) & 0xFFFF, 3, (start + i) & 0xFFFF)
              for i in range(4)]
        check(classify(fr).verdict == "non-cipher-clone",
              f"counter-linear burst from 0x{start:04X} is non-cipher-clone")

    print()
    if FAILS:
        print(f"CLONE CLASSIFIER CHECKS FAILED ({len(FAILS)} failures)")
        return 1
    print("clone classifier checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
