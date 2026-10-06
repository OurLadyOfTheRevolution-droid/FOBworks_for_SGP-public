#!/usr/bin/env python3
"""KIA/HYU V1 decoder suite.

flagged the four silent Kia decoders against 33 on-brand captures as
the sharpest finding in the corpus triage. This suite proves the shipping
ks_decodeKiaV1 now decodes the on-brand 315 MHz V1 captures, and — just as
important — stays off the family that shares its physical layer.

Two defects were found and fixed to get here; both are pinned by tests below.

  1. TE mis-stated. The gate comment said 500/1000µs and the window was
     cA 350-700µs, but the reference kia_v1.c is te_short=800 / te_long=1600
     (delta 200, min 57 bits). The on-brand captures cluster at cA≈807 /
     cB≈1610 (ratio 2.00) — exactly the reference TE — and so landed above the
     700µs ceiling and never reached the decoder. Same class of defect as the
     te_sub2 cA-floor fix recorded in the sketch header (v3.60).

  2. No preamble gate. ks_decodeKiaV1 slides a 57-bit window at every bit
     alignment, and CRC4 is only a 1-in-16 filter, so any long capture sharing
     the 800/1600µs timing passes by chance. The reference only commits after
     >70 consecutive te_long pairs. A Toyota Estima 2000 capture at 314.35 MHz
     is a genuine near-miss (cA 770 / cB 1545, ratio 2.01, 193-pulse SHORT
     preamble) and was decoded as Kia V1 until ks_kia_v1_preamble was added.

Decode expectations come from tools/corpus_regression.py: KiaV1 fires on 3 of
the 3 on-brand 315 MHz V1 captures with zero non-brand fires across all 301
scanned captures, and the corpus matched-by-none count drops 261 -> 258.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SKETCH = ROOT / "FOBworks_for_SGP.ino"
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

CC = "clang++"

PASS = []
FAIL = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def block(src, name):
    """Brace-matched extraction; skips forward declarations (trailing ;)."""
    pat = re.compile(r"^(?:static\s+)?[\w\s\*&]*\b" + re.escape(name) +
                     r"\s*\([^;{]*?\)\s*\{", re.M | re.S)
    m = pat.search(src)
    while m:
        i = src.index("{", m.start())
        depth = 0
        j = i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    return src[m.start():j + 1]
            j += 1
        m = pat.search(src, m.end())
    return None


def parse_signed(path, cap=8192):
    raw = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            raw.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
        if len(raw) >= cap:
            break
    return raw[:cap]


def main():
    src = SKETCH.read_text()

    dec = block(src, "ks_decodeKiaV1")
    crc = block(src, "ks_kia_v1_crc4")
    pre = block(src, "ks_kia_v1_preamble")
    check("ks_decodeKiaV1 extracted", dec is not None)
    check("ks_kia_v1_crc4 extracted", crc is not None)
    check("ks_kia_v1_preamble extracted", pre is not None)
    if not (dec and crc and pre):
        return 1

    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "kia_v1_harness.cpp"
        km = block(src, "ks_km2")
        mkb = block(src, "ks_mkBits")
        man = block(src, "ks_manchester")
        check("ks_km2 extracted", km is not None)
        check("ks_mkBits extracted", mkb is not None)
        check("ks_manchester extracted", man is not None)
        if not (km and mkb and man):
            return 1
        harness.write_text(f"""
#include <cstdint>
#include <cstdio>
#include <cstdlib>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define CAP_SZ 512
{crc}
{km}
{mkb}
{man}
{pre}
// The gate form the firmware ships: te_kv1 widened to the reference TE, plus the
// preamble structure check. Mirrored here so a regression in either is caught.
static bool gate_kv1(u32 cA, float ratio, int bLen, double mhz, const u32* buf, int cnt){{
  bool te_kv1 = (mhz<320.0 && cA>=600 && cA<=1000 && ratio>=1.6f && ratio<=2.5f && bLen>=50);
  bool te_kv1p = ks_kia_v1_preamble(buf, cnt);
  return te_kv1 && te_kv1p;
}}
{dec}
int main(int argc,char**argv){{
  static u32 w[8192]; int n=0; int v;
  FILE*f=fopen(argv[1],"r");
  while(n<8192&&fscanf(f,"%d",&v)==1) w[n++]=(u32)(v<0?-v:v);
  fclose(f);
  if(n<50){{printf("REJECT\\n");return 0;}}
  // decodeSignal's preprocessing, reproduced with the sketch's own helpers:
  // clip >5000us, k-means short/long clusters, threshold, bit string, Manchester.
  static u32 kbuf[8192]; int kn=0;
  for(int i=0;i<n;i++) if(w[i]<=5000) kbuf[kn++]=w[i];
  u32 cA=0,cB=0;
  if(!ks_km2(kn>=6?kbuf:w, kn>=6?kn:n, cA, cB)){{printf("REJECT\\n");return 0;}}
  float ratio=(float)cB/(float)cA;
  u32 thr=(cA+cB)/2;
  static char bits[CAP_SZ*4+16]; static char mb[CAP_SZ/2+1];
  u16 bLen=ks_mkBits(w,n,bits,thr);
  u16 ml=ks_manchester(bits,bLen,mb);
  if(ml<57){{printf("REJECT\\n");return 0;}}
  if(!gate_kv1(cA,ratio,bLen,atof(argv[2]),w,n)){{printf("REJECT gate\\n");return 0;}}
  u32 sn=0; u16 ctr=0; u8 btn=0; bool var=false;
  if(!ks_decodeKiaV1(mb,ml,sn,ctr,btn,var)){{printf("REJECT decode\\n");return 0;}}
  printf("OK sn=%08lX btn=%X ctr=%03X\\n",(unsigned long)sn,btn,ctr);
  return 0;
}}
""")
        binp = Path(td) / "kia_v1_harness"
        r = subprocess.run([CC, "-O1", "-o", str(binp), str(harness)],
                           capture_output=True, text=True)
        check("harness compiles", r.returncode == 0, r.stderr[:300])
        if r.returncode:
            return 1

        def freq(rel):
            p = CORPUS / rel
            for line in p.read_text(errors="replace").splitlines():
                if line.startswith("Frequency:"):
                    return float(line.split(":")[1]) / 1e6
            return 0.0

        def run(rel):
            p = CORPUS / rel
            if not p.exists():
                return None
            raw = parse_signed(p)
            pf = Path(td) / "in.txt"
            pf.write_text("\n".join(str(x) for x in raw))
            o = subprocess.run([str(binp), str(pf), str(freq(rel))],
                               capture_output=True, text=True)
            return o.stdout.strip()

        # ── the three on-brand 315 MHz V1 captures must decode ────────────
        ok_cases = [
            "Asian/Hyundai_Kia_Genesis/Kia_V1_N1_RAW.sub",
            "Asian/Hyundai_Kia_Genesis/Kia_V1_5cl_5op.sub",
            "Asian/Hyundai_Kia_Genesis/Hyundai_V1_N1_RAW.sub",
        ]
        n_ok = 0
        for rel in ok_cases:
            got = run(rel)
            if got is None:
                continue
            ok = got.startswith("OK")
            n_ok += ok
            check(f"decode {Path(rel).name}", ok, got[:60])
        check("decode all on-brand V1 captures", n_ok == 3, f"{n_ok}/3")

        # ── the near-miss family that shares the 800/1600µs timing ────────
        # Toyota Estima 2000: cA 770 / cB 1545 (ratio 2.01) but a 193-pulse
        # SHORT preamble. CRC4 alone let it through; the preamble gate must not.
        reject_cases = [
            ("Asian/Lexus_Toyota/Toyota_Estima_2000_lock3.sub", "Estima 2000 (near-miss TE)"),
            ("Asian/Toyota/Estima 2000/Toyota_Estima_2000#3.sub", "Estima 2000 #3"),
            ("Asian/Toyota/Estima 2000/Toyota_Estima_20003.sub", "Estima 2000 3"),
            ("American/Tesla/Tesla_433_AM270_EU_AUS.sub", "Tesla (other band)"),
        ]
        for rel, label in reject_cases:
            got = run(rel)
            if got is None:
                continue
            check(f"reject {label}", got.startswith("REJECT"), got[:60])

    # ── wiring: gate, preamble helper, dispatch ──────────────────────────
    check("te_kv1p gate defined", "bool te_kv1p=ks_kia_v1_preamble(buf,cnt);" in src)
    check("KiaV1 dispatch uses the preamble gate",
          "if(!decoded&&te_kv1&&te_kv1p)" in src)
    check("KIA-V1 dispatch wired", 'doc["proto"]="KIA-V1"' in src)
    check("te_kv1 covers the reference TE (cA up to 1000µs)",
          "bool te_kv1 =(mhz<320.f&&cA>=600&&cA<=1000" in src)
    check("hist proto id 30 used", ",30,mhz,nowMs}" in src)

    # ── the te_kl_loose claim fix (v4.01) ────────────────────────────────
    # Before v4.01 the loose KeeLoq gate (cA 70-1000, ratio 1.3-2.9) claimed a
    # Kia V1 frame on the card and committed sn=0xFFFF/btn=0xF/ctr=0xFFFF,
    # 180 lines before the KIA-V1 branch could run. The V1 preamble predicate
    # now excludes the frame from that gate. These assertions pin the fix: a
    # regression would silently re-break the decoder on hardware only.
    check("te_kl_skip excludes a Kia V1 frame",
          "|| (te_kv1 && te_kv1p)" in src)
    check("te_kl_skip exclusion is paired with the loose gate",
          "!te_kl_skip" in src and "te_kl_loose" in src)
    # The exclusion must sit in the same statement that builds te_kl_skip, so
    # it is impossible to detach from the gate it protects.
    import re as _re
    _m = _re.search(r"bool te_kl_skip\s*=\s*(.*?);", src, _re.S)
    check("te_kl_skip statement carries the Kia V1 exclusion",
          bool(_m) and "te_kv1" in _m.group(1) and "te_kv1p" in _m.group(1))

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
