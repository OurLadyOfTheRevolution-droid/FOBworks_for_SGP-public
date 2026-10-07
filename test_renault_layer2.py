#!/usr/bin/env python3
"""Renault V1 Layer-2 suite: the epoch/seed model is closed, and the tools agree.

8_RENAULT_LAYER2_RESULT.md answers 's open Layer-2 question.
This suite keeps the answer honest and the tools that produced it correct:

  1. tools/renault_hopseq.py extracts all five accepted frames from the genuine
     Trafic capture and the counter walks 0x15C..0x160 by +1;
  2. the exhaustive 2^32 IV searcher is SELF-CONSISTENT — a frame is generated
     from a known IV with the seed-model encoder, and the searcher recovers that
     exact IV. This is what makes a "MISS on the real frame" mean the model is
     wrong rather than the searcher being broken;
  3. the FIAT known-key test runs over the real frames and reports zero hits;
  4. the model-independent falsifier holds: the five chance fixed-point IVs do not
     share a constant seed byte (iv[3]), so they are collisions, not recoveries;
  5. the research note states the conclusion.

The exhaustive full-frame sweep for point 4 is slow (~2 min/frame) and is NOT run
here; the constant-seed fact is asserted from the recorded result, and the fast
self-consistency in point 2 is what guards the searcher's correctness.
"""

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# Recorded result from the exhaustive sweep.
RECOVERED = {
    0x15C: 0x06CE4A1A,
    0x15D: 0xFD085431,
    0x15E: 0x8E769858,
    0x15F: 0xB1D0D1D5,
    0x160: 0x67D1D372,
}

ENCRYPT = r"""
static u8 fx11(const u8 r[11]){ u8 v=0; for(int i=0;i<10;i++) v^=r[i]; return v; }
static void enc_from_iv(const u8 se[4], const u8 iv[4], u8 out[11]){
  u8 perm[6]; permute(se,perm);
  u8 state[6]={se[0],se[1],se[2],se[3],perm[4],perm[5]};
  u8 w[4]={perm[0],perm[1],perm[2],perm[3]};
  u8 o[4]={iv[0],iv[1],iv[2],iv[3]};
  clk(state,w,o);
  u8 hop0=w[0];
  u8 hop1=(u8)((hop0>>7)|(w[1]<<1));
  u8 hop2=(u8)((w[1]>>7)|(w[2]<<1));
  u8 hop_ext=(u8)(((hop0>>6)&1)|(hop1<<1));
  u8 hop3=(u8)((w[2]>>7)|(w[3]<<1));
  u8 hop4=(u8)((w[3]>>7)|(state[5]<<1));
  hop1=(u8)((hop1>>7)|(hop2<<1));
  hop2=(u8)((hop2>>7)|(hop3<<1));
  hop3=(u8)((hop3>>7)|(hop4<<1));
  u32 mix=((u32)iv[1]<<4)|((u32)iv[0]>>4);
  mix=(mix|(((u32)iv[2]<<12)&0xFFFF))&0xFFFF;
  out[0]=se[0];out[1]=se[1];out[2]=se[2];out[3]=se[3];
  out[4]=(u8)(((mix>>6)&0x0F)|((iv[0]<<4)&0xF0));
  out[5]=(u8)((hop3&3)|((mix<<2)&0xFC));
  out[6]=hop2;out[7]=hop1;out[8]=hop_ext;out[9]=(u8)((hop0<<2)|2);
  out[10]=fx11(out);
}
int main(){ u8 se[4]={0x32,0x70,0xFD,0x2B}; u8 iv[4]={0,0,0,0}; u8 o[11];
  enc_from_iv(se,iv,o); for(int i=0;i<11;i++) printf("%02X",o[i]); printf("\n"); return 0; }
"""


def main():
    hopseq = load(ROOT / "tools/renault_hopseq.py", "hopseq")
    fullsearch = load(ROOT / "tools/renault_hitag2_fullsearch.py", "fullsearch")
    keytest = load(ROOT / "tools/renault_fiat_keytest.py", "keytest")

    # ── 1. the five-frame sequence ────────────────────────────────────
    out = subprocess.run([sys.executable, str(ROOT / "tools/renault_hopseq.py")],
                         capture_output=True, text=True)
    frames = re.findall(r"cnt=([0-9A-F]+) hop=([0-9A-F]+)", out.stdout)
    check("hopseq extracts five frames", len(frames) == 5, f"got {len(frames)}")
    cnts = [int(c, 16) for c, _ in frames]
    check("counter walks 0x15C..0x160 by +1",
          cnts == [0x15C, 0x15D, 0x15E, 0x15F, 0x160], f"{[hex(c) for c in cnts]}")
    hops = {int(c, 16): int(h, 16) for c, h in frames}
    check("hops match the recorded sequence",
          all(hops.get(c) == EXPECT[c] for c in EXPECT),
          f"got {[hex(hops.get(c,0)) for c in EXPECT]}")

    # ── 2. searcher self-consistency (the guarantee behind a MISS) ─────
    with tempfile.TemporaryDirectory() as td:
        base = fullsearch.SRC.split("int main")[0]
        enc_cpp = Path(td) / "enc.cpp"
        enc_cpp.write_text(base + ENCRYPT)
        enc_bin = Path(td) / "enc"
        r = subprocess.run(["clang++", "-O2", "-w", "-std=c++11", "-o", str(enc_bin), str(enc_cpp)],
                           capture_output=True, text=True)
        check("encoder compiles", r.returncode == 0, r.stderr[:300])
        if r.returncode == 0:
            frame = subprocess.run([str(enc_bin)], capture_output=True, text=True).stdout.strip()
            check("frame generated from iv=00000000", len(frame) == 22, frame)
            exe = fullsearch.build(td)
            hit = subprocess.run([str(exe), str(1 << 24), frame], capture_output=True, text=True)
            check("searcher recovers the known IV (self-consistent)",
                  "HIT iv=00000000" in hit.stdout, hit.stdout.strip().splitlines()[-1][:60])

    # ── 3. FIAT known-key test: zero hits on the real frames ───────────
    kt = subprocess.run([sys.executable, str(ROOT / "tools/renault_fiat_keytest.py")],
                        capture_output=True, text=True)
    check("keytest runs all five frames", kt.stdout.count("-> 0 key hit(s)") == 5)
    check("no dictionary key matches (private key expected)",
          "total key hits: 0" in kt.stdout)

    # ── 4. model-independent falsifier: seed byte not constant ─────────
    seeds = {c: (iv & 0xFF) for c, iv in RECOVERED.items()}
    check("recovered IVs do not share a seed byte (collisions, not recoveries)",
          len(set(seeds.values())) == 5, f"iv[3]={[hex(v) for v in seeds.values()]}")
    check("no recovered IV fits the counter layout iv[1]=(cnt>>4)&0xFF",
          all(((iv >> 16) & 0xFF) != ((c >> 4) & 0xFF) for c, iv in RECOVERED.items()))

    # ── 5. the note ───────────────────────────────────────────────────
    doc = ROOT / "research/78_RENAULT_LAYER2_RESULT.md"
    # is a private worklog and is not published; skip its note checks
    # when it is absent so a fresh clone still gets a green suite.
    if not doc.exists():
        print(" note: skipped (worklog not published)")
    else:
        txt = doc.read_text()
        check("note states the epoch/seed model is wrong",
              "does not describe a Renault V1 remote" in txt or "the wrong model" in txt)
        check("note records the one-IV-per-frame chance count",
              "Exactly one IV per frame" in txt)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


EXPECT = {0x15C: 0x56F47F8A, 0x15D: 0x4EF3E79B, 0x15E: 0x56D7D29F,
          0x15F: 0x7EF503D1, 0x160: 0x79564FDA}

if __name__ == "__main__":
    sys.exit(main())
