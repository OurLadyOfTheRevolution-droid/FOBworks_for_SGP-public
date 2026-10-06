#!/usr/bin/env python3
"""FIAT V1 decoder suite.

§2.6 named FIAT (12 captures) among the highest-value missing
decoders. This suite proves the shipping ks_decodeFiatV1:

  1. decodes the Grande Punto pair set and the Panda RAW capture -- eight of
     the twelve FIAT files -- extracting VERBATIM from the sketch and compiling
     them, the same harness style as test_psa_decoder;
  2. rejects the near-miss families that share TE or frequency: VW Polo,
     Renault Megane/Captur, Skoda Fabia, and the FIAT Bravo/Tipo (which are a
     different, non-V1 variant);
  3. the te_fiatv1 gate, the dispatch, and the ks_consFiatV1 consensus adapter
     exist and are wired (grep-level, like test_key_table_docs).

Decode expectations come from tools/corpus_regression.py's corpus sweep: FIAT V1
is the only one of the three ProtoPirate FIAT references (V0, V1, V2) that fires
on-brand, and it fired on 8/12 with zero false positives across all 306 captures.
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

    dec = block(src, "ks_decodeFiatV1")
    fx = block(src, "ks_fv1_xor")
    fv = block(src, "ks_fv1_frameValid")
    tw = block(src, "ks_fv1_tryWindow")
    check("ks_decodeFiatV1 extracted", dec is not None)
    check("ks_fv1_xor extracted", fx is not None)
    check("ks_fv1_frameValid extracted", fv is not None)
    check("ks_fv1_tryWindow extracted", tw is not None)
    if not (dec and fx and fv and tw):
        return 1

    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "fiat_harness.cpp"
        harness.write_text(f"""
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define CAP_SZ 512
{fx}
{fv}
{tw}
{dec}
// Harness entry: read SIGNED pulse widths (Flipper RAW: sign = level); the
// decoder takes absolute widths, exactly like the firmware's rfBuf.
int main(int argc,char**argv){{
  FILE*f=fopen(argv[1],"r");
  static u16 w[8192]; int n=0; int v;
  while(n<8192&&fscanf(f,"%d",&v)==1){{int a=v<0?-v:v; w[n]=(u16)(a>0xFFFF?0xFFFF:a); n++;}}
  fclose(f);
  u32 sn=0,hop=0; u8 btn=0,var=0; u16 ctr=0;
  if(!ks_decodeFiatV1(w,n,sn,btn,ctr,hop,var)){{printf("REJECT\\n");return 0;}}
  printf("OK sn=%08lX btn=%X ctr=%02X hop=%08lX var=%d\\n",
         (unsigned long)sn,btn,ctr,(unsigned long)hop,var);
  return 0;
}}
""")
        binp = Path(td) / "fiat_harness"
        r = subprocess.run([CC, "-O1", "-o", str(binp), str(harness)],
                           capture_output=True, text=True)
        check("harness compiles", r.returncode == 0, r.stderr[:200])
        if r.returncode:
            return 1

        def run(rel):
            p = CORPUS / rel
            if not p.exists():
                return None
            raw = parse_signed(p)
            pf = Path(td) / "in.txt"
            pf.write_text("\n".join(str(x) for x in raw))
            o = subprocess.run([str(binp), str(pf)], capture_output=True, text=True)
            return o.stdout.strip()

        # Grande Punto: the same fob, uid B6AB9928, button 1=Close / 2=Open with
        # sequential counters. Panda: uid A4A02529, button 2.
        ok_cases = [
            ("European/FIAT/Grande Punto/Close.sub", "B6AB9928", "1"),
            ("European/FIAT/Grande Punto/close1.sub", "B6AB9928", "1"),
            ("European/FIAT/Grande Punto/close3.sub", "B6AB9928", "1"),
            ("European/FIAT/Grande Punto/open.sub", "B6AB9928", "2"),
            ("European/FIAT/Grande Punto/open2.sub", "B6AB9928", "2"),
            ("European/FIAT/Grande Punto/open3.sub", "B6AB9928", "2"),
            ("European/FIAT/Grande Punto/open4.sub", "B6AB9928", "2"),
            ("European/FIAT/Panda/FiatPandaRAW.sub", "A4A02529", "2"),
        ]
        n_ok = 0
        for rel, want_sn, want_btn in ok_cases:
            got = run(rel)
            if got is None:
                continue
            ok = got.startswith("OK") and f"sn={want_sn}" in got and f"btn={want_btn}" in got
            n_ok += ok
            check(f"decode {Path(rel).name}", ok, got[:60])

        # Near-miss families sharing TE / frequency must not fire.
        reject_cases = [
            ("European/VW_Audi_Skoda_Seat/VW_Polo_Lock1.sub", "VW Polo lock"),
            ("European/Renault/Renault_Megane_Scenic_2005_lock.sub", "Megane 2005"),
            ("European/Renault/Captur 2017/Renault_Captur_2017_Lock_x5.sub.sub", "Captur 2017"),
            ("European/Skoda/Fabia 2006/Skoda_fabbia_2006.sub", "Skoda Fabia"),
            ("European/FIAT/Fiat Bravo 2010 S.Croce 433.88 am650.sub", "FIAT Bravo (other variant)"),
        ]
        for rel, label in reject_cases:
            got = run(rel)
            if got is None:
                continue
            check(f"reject {label}", got == "REJECT", got[:60])

        check("decode majority of FIAT corpus", n_ok >= 7, f"{n_ok}/{len(ok_cases)}")

    # ── wiring: gate, dispatch, adapter ──────────────────────────────────
    check("te_fiatv1 gate defined", "bool te_fiatv1=" in src)
    check("FIAT dispatch wired", 'doc["proto"]="FIAT-V1"' in src)
    check("ks_consFiatV1 adapter defined", "static bool ks_consFiatV1(" in src)
    check("FIAT consensus vote wired",
          "ks_consensusVote(rfBuf,rfLen,ks_consFiatV1," in src)
    check("hist proto id 36 used", ",36,mhz,nowMs}" in src)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
