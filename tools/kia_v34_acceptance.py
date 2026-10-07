#!/usr/bin/env python3
"""Kia V3/V4 acceptance runner — A2 (real capture) and A3 (no false positives).

Drives the ACTUAL shipped decoder, not a reimplementation. The functions are
extracted verbatim from FOBworks_for_SGP.ino, compiled, and run over Flipper
`.sub` files. A Python mirror of the decoder would only test the mirror.

Usage:
    tools/kia_v34_acceptance.py --scan DIR        # A2 + A3 over DIR/*.sub
    tools/kia_v34_acceptance.py --gen DIR         # write synthetic Kia .subs to DIR
    tools/kia_v34_acceptance.py --selftest        # validate the runner itself

`--selftest` is not a formality. Before trusting a "no Kia file found" result on a
corpus, prove the runner detects a Kia frame when one is present. It generates
synthetic V3 and V4 captures with the reference encoder logic, then requires the
scanner to validate them and to NOT validate non-Kia fixtures.

A2 passes when at least one real Kia file validates.
A3 passes when no non-Kia file validates.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SKETCH = REPO / "FOBworks_for_SGP.ino"

# Functions the harness needs, in dependency order. Extracted by brace matching so
# the harness always tracks the shipped source.
FUNCS = [
    "static inline uint8_t ks_kiaV34Rev8(uint8_t v){",
    "static inline bool ks_kiaV34Match(uint32_t dec,uint8_t btn,uint32_t serial){",
    "static void ks_kiaV34Extract(uint8_t b[8],uint8_t crcByte,bool invert,KiaV34Frame& out){",
    "static bool ks_kiaV34Validate(KiaV34Frame& f){",
    "static inline uint32_t ks_kiaV34BuildPlain(uint8_t btn,uint32_t serial,uint16_t ctr){",
    "static inline bool ks_kiaV34IsPulse(uint32_t v,uint32_t ref){",
    "static bool ks_kiaV34IsSync(uint32_t v){",
    "static uint16_t ks_kiaV34PwmAt(const uint32_t* buf,int n,int off,int parityHigh,",
    "static uint16_t ks_kiaV34Pwm(const uint32_t* buf,int n,char* bits,bool* outV3){",
    "static void ks_kiaV34BitsToBytes(const char* bits,int nb,uint8_t out[9]){",
    "static bool ks_decodeKiaV34(const uint32_t* buf,int cnt,KiaV34Frame& out){",
]
STRUCT = "struct KiaV34Frame {"
# The cipher. Taken from the sketch so the runner tests the shipped implementation.
CIPHER = [
    "static inline uint32_t ks_nlf(uint32_t x){",
    "static inline uint32_t ks_bit(uint32_t x,uint8_t n){",
    "static uint32_t ks_klEncrypt(uint32_t plain,uint64_t key){",
    "static uint32_t ks_klDecrypt(uint32_t cipher,uint64_t key){",
]


def extract_block(src: str, marker: str) -> str:
    """Return the full definition starting at `marker`, brace-matched, incl. a
    trailing ';' when the definition is a type."""
    i = src.index(marker)
    i = src.rindex("\n", 0, i) + 1
    j = src.index("{", i)
    depth, k = 0, j
    while k < len(src):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    end = k + 1
    if end < len(src) and src[end] == ";":
        end += 1
    return src[i:end] + "\n"


def extract_define(src: str, name: str) -> str:
    i = src.index(f"#define {name}")
    return src[i : src.index("\n", i) + 1]


def build_harness() -> str:
    src = SKETCH.read_text(encoding="utf-8")
    parts = [
        """// Extracted by tools/kia_v34_acceptance.py — do not edit.
// Functions are extracted verbatim from FOBworks_for_SGP.ino.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dirent.h>
#define KL_NLF 0x3A5C742EUL
#define CAP_SZ 4096

""",
        extract_block(src, STRUCT),
        extract_define(src, "KIA_V34_MF_KEY"),
        extract_define(src, "KIA_V34_TE_SHORT"),
        extract_define(src, "KIA_V34_TE_LONG"),
        extract_define(src, "KIA_V34_TE_DELTA"),
        extract_define(src, "KIA_V34_MIN_BITS"),
    ]
    for m in CIPHER + FUNCS:
        parts.append(extract_block(src, m))
    parts.append(HARNESS_MAIN)
    return "".join(parts)


HARNESS_MAIN = r"""
// ── .sub parsing ────────────────────────────────────────────────────────────
static uint32_t pw[CAP_SZ];

// Flipper RAW_Data holds alternating signed pulse durations; the decoder wants
// unsigned widths, so abs() each entry.
static int loadSub(const char* path, long* freqOut, int* rawLines, int* parsedLines){
  FILE* f = fopen(path,"r");
  if(!f) return -1;
  static char line[262144];
  int n=0, nl=0, pl=0;
  *freqOut=0;
  while(fgets(line,sizeof line,f)){
    if(strncmp(line,"Frequency:",10)==0){ *freqOut=strtol(line+10,NULL,10); continue; }
    if(strncmp(line,"RAW_Data:",9)!=0){ continue; }
    nl++;
    char* p=line+9;
    while(*p && n<CAP_SZ){
      while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
      if(!*p) break;
      char* end; long v=strtol(p,&end,10);
      if(end==p) break;
      p=end;
      pw[n++]=(uint32_t)(v<0?-v:v);
    }
  }
  fclose(f);
  *rawLines=nl; *parsedLines=n;
  return n;
}

// ── generator: synthetic Kia capture from the reference encoder logic ───────
// Writes a .sub that a real Kia V3/V4 fob would produce, so the scanner can be
// validated before it is trusted on a corpus.
// onAirBtn lets the caller transmit a button nibble that differs from the one
// inside the encrypted word. That is the only way to build an honest negative
// control: a frame generated consistently is a *valid* frame, and the 12-bit
// check is right to accept it. -1 means "consistent".
static int writeSub(const char* path, uint32_t serial, uint8_t btn, uint16_t ctr,
                    bool v3, long freq, int repeats, int onAirBtn){
  // Encrypted word: the reference plaintext layout (serial masked to 10 bits).
  uint32_t pt  = (uint32_t)(ctr & 0xFFFF) | ((serial & 0x3FFUL) << 16) | ((uint32_t)(btn & 0x0F) << 28);
  uint32_t enc = ks_klEncrypt(pt, KIA_V34_MF_KEY);

  uint8_t raw[8];
  raw[0]=ks_kiaV34Rev8((uint8_t)(enc & 0xFF));
  raw[1]=ks_kiaV34Rev8((uint8_t)((enc >> 8) & 0xFF));
  raw[2]=ks_kiaV34Rev8((uint8_t)((enc >> 16) & 0xFF));
  raw[3]=ks_kiaV34Rev8((uint8_t)((enc >> 24) & 0xFF));
  // Bytes 4..7 carry the ON-AIR framing: full 28-bit serial + button nibble.
  uint8_t txb = (onAirBtn < 0) ? (uint8_t)(btn & 0x0F) : (uint8_t)(onAirBtn & 0x0F);
  uint32_t sb = (serial & 0x0FFFFFFFUL) | ((uint32_t)txb << 28);
  raw[4]=ks_kiaV34Rev8((uint8_t)(sb & 0xFF));
  raw[5]=ks_kiaV34Rev8((uint8_t)((sb >> 8) & 0xFF));
  raw[6]=ks_kiaV34Rev8((uint8_t)((sb >> 16) & 0xFF));
  raw[7]=ks_kiaV34Rev8((uint8_t)((sb >> 24) & 0xFF));

  // V3 inverts the whole frame on air; V4 does not.
  uint8_t pay[9];
  for(int i=0;i<8;i++) pay[i] = v3 ? (uint8_t)~raw[i] : raw[i];
  pay[8] = 0;   // CRC nibble; the reference never validates it

  char bits[80]; int k=0;
  for(int i=0;i<68;i++) bits[k++] = ((pay[i>>3] >> (7-(i&7))) & 1) ? '1':'0';
  bits[k]=0;

  // PWM levels: V4 leads low, V3 leads high. Flipper RAW stores a signed
  // duration per level, so the leading level decides the sign sequence.
  FILE* f=fopen(path,"w");
  if(!f) return -1;
  fprintf(f,"Filetype: Flipper SubGhz RAW File\n");
  fprintf(f,"Version: 1\n");
  fprintf(f,"Frequency: %ld\n", freq);
  fprintf(f,"Preset: FuriHalSubGhzPresetOok650Async\n");
  fprintf(f,"Protocol: RAW\n");

  long vals[8192]; int m=0;
  for(int r=0;r<repeats;r++){
    // Preamble: 12 short+short pairs, HIGH then LOW.
    for(int i=0;i<12;i++){ vals[m++]=(long)KIA_V34_TE_SHORT; vals[m++]=-(long)KIA_V34_TE_SHORT; }
    // Sync. Its level encodes the version and must land on an even (HIGH) index,
    // so V3 (LOW sync) needs a HIGH filler pulse ahead of it. 1188us sits inside
    // ks_kiaV34IsSync's 1000-1500 window.
    if(v3){ vals[m++]=(long)KIA_V34_TE_SHORT; vals[m++]=-1188; }
    else  { vals[m++]=1188; vals[m++]=-(long)KIA_V34_TE_SHORT; }
    // Data: one bit per HIGH pulse (short -> 0, long -> 1), each followed by a
    // LOW that carries nothing. 68 bits = 64 payload + 4 CRC.
    for(int i=0;i<68;i++){
      uint32_t hi = (bits[i]=='1') ? KIA_V34_TE_LONG : KIA_V34_TE_SHORT;
      vals[m++]=(long)hi; vals[m++]=-(long)KIA_V34_TE_SHORT;
    }
  }
  for(int i=0;i<m;i++){
    if(i%40==0){ if(i) fprintf(f,"\n"); fprintf(f,"RAW_Data:"); }
    fprintf(f," %ld", vals[i]);
  }
  fprintf(f,"\n");
  fclose(f);
  return 0;
}

// ── modes ───────────────────────────────────────────────────────────────────
static int isSub(const char* n){
  size_t L=strlen(n);
  return L>4 && strcmp(n+L-4,".sub")==0;
}

static int scanDir(const char* dir){
  DIR* d=opendir(dir);
  if(!d){ fprintf(stderr,"cannot open %s\n",dir); return 2; }
  int files=0, parsed=0, validated=0, reached68=0, kiaNamed=0, kiaValidated=0;
  struct dirent* e;
  while((e=readdir(d))){
    if(!isSub(e->d_name)) continue;
    char path[2048];
    snprintf(path,sizeof path,"%s/%s",dir,e->d_name);
    long freq=0; int nl=0, pl=0;
    int n=loadSub(path,&freq,&nl,&pl);
    files++;
    int looksKia = (strcasestr(e->d_name,"kia")||strcasestr(e->d_name,"hyundai")||
                    strcasestr(e->d_name,"genesis")||strcasestr(e->d_name,"sportage")||
                    strcasestr(e->d_name,"spectra")||strcasestr(e->d_name,"cerato")||
                    strcasestr(e->d_name,"rio")||strcasestr(e->d_name,"sorento"))?1:0;
    if(looksKia) kiaNamed++;
    if(n<10){ continue; }
    parsed++;
    static char bits[CAP_SZ/2+1];
    bool v3hint=false;
    uint16_t nb=ks_kiaV34Pwm(pw,n,bits,&v3hint);
    if(nb>=KIA_V34_MIN_BITS) reached68++;
    KiaV34Frame o;
    if(ks_decodeKiaV34(pw,n,o)){
      validated++;
      if(looksKia) kiaValidated++;
      printf("  VALID  %-34s %s sn=0x%08lX btn=%X ctr=0x%04X crc=0x%X freq=%ld%s\n",
             e->d_name, o.v3?"V3":"V4", (unsigned long)o.serial, o.btn, o.ctr, o.crc, freq,
             looksKia?"  <- Kia-named (A2 candidate)":"  <- NOT Kia-named (A3 violation)");
    } else if(looksKia){
      printf("  no-hit %-34s (Kia-named, did not validate) freq=%ld\n", e->d_name, freq);
    }
  }
  closedir(d);
  printf("\nfiles=%d parsed=%d reached-68-bits=%d validated=%d\n",files,parsed,reached68,validated);
  printf("kia-named=%d  kia-named-validated=%d\n",kiaNamed,kiaValidated);
  // A3: nothing validated that is not Kia-named.
  int a3 = (validated - kiaValidated) == 0;
  // A2: at least one Kia-named file validated.
  int a2 = kiaValidated > 0;
  printf("A3 (no false positives) : %s\n", a3?"PASS":"FAIL");
  printf("A2 (real Kia validated) : %s\n", a2?"PASS":(kiaNamed?"FAIL (Kia files present but none validated)":
                                                    "NOT RUN (no Kia file in corpus)"));
  return a2 && a3 ? 0 : 0;   // informational; the driver parses the lines
}

static int genDir(const char* dir){
  char path[2048];
  // name, serial, btn, ctr, v3, freq, repeats, onAirBtn (-1 = consistent)
  struct { uint32_t sn; uint8_t btn; uint16_t ctr; int v3; long freq; int rep; int txb; const char* name; } g[] = {
    { 0x0A1B2CE7UL, 0x3, 0x4D2, 0, 433920000, 2, -1, "synthetic_kia_v4_433.sub" },
    { 0x0A1B2CE7UL, 0x3, 0x4D3, 1, 433920000, 2, -1, "synthetic_kia_v3_433.sub" },
    { 0x0A1B2FE7UL, 0x3, 0x4D2, 0, 315000000, 2, -1, "synthetic_kia_v4_315.sub" },
    { 0x0A1B2FE7UL, 0x3, 0x4D3, 1, 315000000, 2, -1, "synthetic_kia_v3_315.sub" },
    // NEGATIVE CONTROL: same serial and counter, but the on-air button nibble is
    // tampered so it disagrees with the encrypted one. The 12-bit check must
    // reject this. A frame generated consistently would be valid, which is why
    // the mismatch has to be injected rather than chosen by picking another button.
    { 0x0A1B2CE7UL, 0x3, 0x4D2, 0, 433920000, 2, 0x5, "kia_negative_control.sub" },
  };
  for(unsigned i=0;i<sizeof(g)/sizeof(g[0]);i++){
    snprintf(path,sizeof path,"%s/%s",dir,g[i].name);
    writeSub(path,g[i].sn,g[i].btn,g[i].ctr,g[i].v3!=0,g[i].freq,g[i].rep,g[i].txb);
    printf("wrote %s\n",g[i].name);
  }
  return 0;
}

int main(int argc,char** argv){
  if(argc>=3 && strcmp(argv[1],"--scan")==0) return scanDir(argv[2]);
  if(argc>=3 && strcmp(argv[1],"--gen")==0)  return genDir(argv[2]);
  fprintf(stderr,"usage: %s --scan DIR | --gen DIR\n",argv[0]);
  return 2;
}
"""


def compile_harness(workdir: Path) -> Path:
    src = workdir / "kia_runner.cpp"
    src.write_text(build_harness(), encoding="utf-8")
    exe = workdir / "kia_runner"
    cxx = shutil.which("c++") or shutil.which("clang++") or "c++"
    r = subprocess.run([cxx, "-O2", "-std=c++17", "-w", str(src), "-o", str(exe)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("compile failed:\n" + r.stderr, file=sys.stderr)
        sys.exit(2)
    return exe


def run(cmd: list[str]) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout + r.stderr
    return out


def summary(out: str) -> dict:
    d = {}
    for key in ("A2", "A3"):
        m = re.search(rf"^{key} \([^)]*\)\s*:\s*(.+)$", out, re.M)
        if m:
            d[key] = m.group(1).strip()
    m = re.search(r"^files=(\d+) parsed=(\d+) reached-68-bits=(\d+) validated=(\d+)$", out, re.M)
    if m:
        d["counts"] = tuple(int(x) for x in m.groups())
    m = re.search(r"^kia-named=(\d+)\s+kia-named-validated=(\d+)$", out, re.M)
    if m:
        d["kia"] = tuple(int(x) for x in m.groups())
    return d


def selftest() -> int:
    print("=== runner self-test ===")
    print("Generates synthetic Kia captures, then requires the scanner to detect")
    print("them and to reject the negative control. Validates the runner, not the")
    print("decoder alone.\n")
    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        exe = compile_harness(wd)
        cap = wd / "caps"
        cap.mkdir()
        gen = run([str(exe), "--gen", str(cap)])
        print(gen.strip())
        out = run([str(exe), "--scan", str(cap)])
        print(out)
        s = summary(out)
        ok = True
        nvalid = s.get("counts", (0, 0, 0, 0))[3]
        kia = s.get("kia", (0, 0))
        print(f"validated={nvalid} of 5 synthetic files (4 genuine + 1 negative control)")
        if kia[1] < 4:
            print("FAIL: expected the 4 genuine Kia files to validate")
            ok = False
        if nvalid != 4:
            print(f"FAIL: expected exactly 4 validations, got {nvalid} "
                  "(the tampered-button negative control must not validate)")
            ok = False
        print("\n" + ("RUNNER SELF-TEST PASS" if ok else "RUNNER SELF-TEST FAIL"))
        return 0 if ok else 1


def scan(dirpath: str) -> int:
    with tempfile.TemporaryDirectory() as td:
        exe = compile_harness(Path(td))
        out = run([str(exe), "--scan", dirpath])
        print(out)
        s = summary(out)
        a2, a3 = s.get("A2", "?"), s.get("A3", "?")
        print("=" * 66)
        print(f"A2 (real Kia capture decodes) : {a2}")
        print(f"A3 (no false positives)       : {a3}")
        if a2.startswith("NOT RUN"):
            print("\nA2 is NOT RUN: no Kia-named capture is present in the corpus.")
            print("The decoder remains unproven on real RF. Supply Kia V3/V4 .sub")
            print("files (315 or 433.92 MHz) and re-run --scan.")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--scan", metavar="DIR", help="A2+A3: scan DIR/*.sub")
    g.add_argument("--gen", metavar="DIR", help="write synthetic Kia .sub files to DIR")
    g.add_argument("--selftest", action="store_true", help="validate the runner itself")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if a.gen:
        with tempfile.TemporaryDirectory() as td:
            exe = compile_harness(Path(td))
            print(run([str(exe), "--gen", a.gen]).strip())
        return 0
    return scan(a.scan)


if __name__ == "__main__":
    sys.exit(main())
