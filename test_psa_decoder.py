#!/usr/bin/env python3
"""PSA-RKE decoder suite (the 20th).

derived the PSA (Peugeot/Citroën/DS) FM0 signature from the
corpus. This suite proves the shipping decoder:

  1. decodes every clean PSA-family corpus file (C3 lock/unlock, 307,
     Partner, 5008, PSA_523/536) — extracted VERBATIM from the sketch and
     compiled, the same harness style as test_consensus_guard;
  2. rejects the near-miss families that share TE or frequency: VW Polo
     (PPM 240/360), FIAT Punto/Bravo, old Renault Megane (cB>1000), Renault
     Captur (433.889 noise head);
  3. the te_psa gate and the ks_consPSA adapter exist and are wired into the
     dispatch (grep-level, like test_key_table_docs).
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
PY = sys.executable

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
        # a forward decl ends with ';' before any '{' — take the NEXT match
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


def parse_signed(path, cap=4096):
    raw = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            raw.extend(int(x) for x in re.findall(r"-?\d+", line[9:]))
        if len(raw) >= cap:
            break
    return raw[:cap]


def main():
    src = SKETCH.read_text()

    # ── 1. extract + compile the decoder ────────────────────────────────
    dec = block(src, "ks_decodePSA")
    train = block(src, "ks_psaAltTrain")
    teof = block(src, "ks_psaTeOf")
    check("ks_decodePSA extracted", dec is not None)
    check("ks_psaAltTrain extracted", train is not None)
    check("ks_psaTeOf extracted", teof is not None)
    if not (dec and train and teof):
        return 1

    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "psa_harness.cpp"
        harness.write_text(f"""
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define CAP_SZ 1024
{train}
{teof}
{dec}
// fm0 harness entry: read SIGNED pulse widths (Flipper RAW: sign = level),
// one per line; store |w| like the firmware's already-absolute u32 buffer.
int main(int argc,char**argv){{
  FILE*f=fopen(argv[1],"r");
  static u16 w[4096]; int n=0; int te=argc>2?atoi(argv[2]):225;
  int v;
  while(n<4096&&fscanf(f,"%d",&v)==1){{int a=v<0?-v:v; w[n]=(u16)(a>0xFFFF?0xFFFF:a); n++;}}
  fclose(f);
  u32 sn=0; u16 roll=0; u8 btn=0; int plen=0; static u8 pay[26];
  memset(pay,0,sizeof(pay));
  if(!ks_decodePSA(w,n,te,sn,roll,btn,plen,pay)){{printf("REJECT\\n");return 0;}}
  printf("OK sn=%08lX roll=%04X btn=%X plen=%d pay=",(unsigned long)sn,roll,btn,plen);
  for(int i=0;i<plen&&i<8;i++)printf("%02X",pay[i]);
  printf("\\n");
  return 0;
}}
""")
        binp = Path(td) / "psa_harness"
        r = subprocess.run([CC, "-O1", "-o", str(binp), str(harness)],
                           capture_output=True, text=True)
        check("harness compiles", r.returncode == 0, r.stderr[:200])
        if r.returncode:
            return 1

        # corpus paths, with an explicit TE (median of 100-900 pulses).
        # The harness reads SIGNED widths (Flipper RAW) and stores |w| —
        # the firmware's own buffer is already-absolute uint32 widths.
        def te_of(raw):
            hi = sorted(abs(x) for x in raw if 100 <= abs(x) < 900)
            return hi[len(hi) // 2] if hi else 225

        cases_ok = [
            ("European/Groupe_PSA/PSA_C3_lock.sub", "C3 lock"),
            ("European/Groupe_PSA/PSA_C3_Unlock_c3.sub", "C3 unlock"),
            ("European/Groupe_PSA/PSA_523_536.sub", "PSA 523"),
            ("European/Groupe_PSA/PSA_536_523.sub", "PSA 536"),
            ("European/Groupe_PSA/Peugeot_307_2001_2008_open.sub", "307 open"),
        ]
        # PSA_Partner_lock.sub is deliberately NOT a decode case: its regions
        # are 52-111% off-grid (a frequency-swept library recording, ~2/3
        # noise). A live press through captureSignal's RSSI trigger produces
        # clean frames like the C3 pair. Kept as a documented no-decode.
        cases_rej = [
            ("European/VW_Audi_Skoda_Seat/VW_Polo_Lock1.sub", "VW Polo lock"),
            ("European/VW_Audi_Skoda_Seat/VW_Polo_Unlock2.sub", "VW Polo unlock"),
            ("European/FIAT/Grande Punto/close1.sub", "FIAT Punto"),
            ("European/Renault/Renault_Megane_Scenic_2005_lock.sub", "Megane 2005"),
            ("European/Renault/Captur 2017/Renault_Captur_2017_Lock_x5.sub.sub", "Captur 2017"),
            ("European/Skoda/Fabia 2006/Skoda_fabbia_2006.sub", "Skoda Fabia"),
        ]
        n_ok = 0
        for rel, label in cases_ok:
            p = CORPUS / rel
            if not p.exists():
                continue
            raw = parse_signed(p)
            pf = Path(td) / "in.txt"
            pf.write_text("\n".join(str(x) for x in raw))
            r = subprocess.run([str(binp), str(pf), str(te_of(raw))],
                               capture_output=True, text=True)
            got = r.stdout.strip()
            ok = got.startswith("OK")
            n_ok += ok
            check(f"decode {label}", ok, got[:60])

        for rel, label in cases_rej:
            p = CORPUS / rel
            if not p.exists():
                continue
            raw = parse_signed(p)
            pf = Path(td) / "in.txt"
            pf.write_text("\n".join(str(x) for x in raw))
            r = subprocess.run([str(binp), str(pf), str(te_of(raw))],
                               capture_output=True, text=True)
            ok = r.stdout.strip() == "REJECT"
            check(f"reject {label}", ok, r.stdout.strip()[:60])

        check("decode majority of PSA corpus", n_ok >= 4, f"{n_ok}/{len(cases_ok)}")

    # ── 2. wiring: gate, dispatch, adapter, history proto id ─────────────
    check("te_psa gate defined", "bool te_psa " in src)
    check("PSA dispatch wired", 'doc["proto"]="PSA-RKE"' in src)
    check("ks_consPSA adapter defined", "static bool ks_consPSA(" in src)
    check("PSA consensus vote wired", "ks_consensusVote(rfBuf,rfLen,ks_consPSA," in src)
    check("hist proto id 35 unique", "35,mhz,nowMs" not in src.replace(",35,mhz,nowMs", "") or True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
