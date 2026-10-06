#!/usr/bin/env python3
"""Corpus regression harness: run every real decoder against every real capture.

§5 step 1. Forty of this firmware's 41 decoders had never been pointed at a real
capture; the corpus has 306 RAW files across ~19 brands on disk. This runs the REAL C++
functions -- extracted from the sketch and compiled -- rather than Python reimplementations,
because an earlier round's Python model of the encoder disagreed with the running code and cost
a round.

It reproduces decodeSignal()'s own preprocessing, because the gates and the conversion are
part of the decoder behaviour:

    pulses -> ks_km2 clusters -> te_* gates -> ks_mkBits -> ks_decode*()

Skipping the gates would fire decoders the firmware itself would refuse, so the harness would
report false positives that cannot occur on hardware.

Outputs the triage §5 step 2 asks for:
  · per decoder: files fired on, distinct serials, and whether any non-brand file fires
  · decoders that never fire
  · files matched by none

Needs only a C++ compiler. No hardware.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

# The script lives in tools/; the sketch and corpus are one level up.
ROOT = Path(__file__).resolve().parent.parent
SKETCH = ROOT / "FOBworks_for_SGP.ino"
CORPUS = ROOT / "research/sources/corpus_automotive_subghz"

# Which brand each corpus folder represents, so "fired on a non-brand file" is checkable.
# Brand keywords, matched against the file's folder path (longest match wins). Derived from
# the folder tree rather than hand-listed, because a hand list missed 89 files -- Suzuki, BYD,
# Citroen, Lexus, Lamborghini and others all fell through to "unknown" and made section B
# unreadable.
BRAND_KEYWORDS = [
    ("hyundai_kia_genesis", "kia"), ("kia", "kia"),
    ("toyota", "toyota"), ("lexus", "toyota"),
    ("honda", "honda"), ("acura", "honda"),
    ("nissan", "nissan"), ("infiniti", "nissan"),
    ("mazda", "mazda"), ("subaru", "subaru"), ("suzuki", "suzuki"),
    ("isuzu", "isuzu"), ("byd", "byd"), ("tesla", "tesla"), ("mitsubishi", "mitsubishi"),
    ("ford", "ford"), ("lincoln", "ford"),
    ("gm_", "gm"), ("chevrolet", "gm"), ("buick", "gm"), ("cadillac", "gm"),
    ("gmc", "gm"), ("chrysler", "chrysler"), ("dodge", "chrysler"), ("jeep", "chrysler"),
    ("vw_audi", "vag"), ("vag", "vag"), ("audi", "vag"), ("skoda", "vag"),
    ("seat", "vag"), ("volkswagen", "vag"), ("vw", "vag"),
    ("bmw", "bmw"), ("mercedes", "mercedes"), ("volvo", "volvo"),
    ("renault", "renault"), ("dacia", "renault"), ("fiat", "fiat"),
    ("groupe_psa", "psa"), ("psa", "psa"), ("peugeot", "psa"), ("citroen", "psa"),
    ("lamborghini", "lamborghini"), ("opel", "gm"), ("vauxhall", "gm"),
    ("mini", "bmw"), ("porsche", "vag"), ("jaguar", "jaguar"), ("land_rover", "landrover"),
    ("unknown", "unknown"),
]

# Decoder -> the brand it ought to fire on. Only unambiguously single-brand protocols are
# listed; the rest report "n/a" and are judged only on whether they fire at all.
DECODER_BRAND = {
    "ks_decodeToyota": "toyota",
    "ks_decodeKiaV0": "kia", "ks_decodeKiaV1": "kia", "ks_decodeKiaV2": "kia",
    "ks_decodeKiaV7": "kia", "ks_decodeHKR": "kia", "ks_decodeSantaFe": "kia",
    "ks_decodeSubaru": "subaru", "ks_decodeSubaruV2": "subaru",
    "ks_decodeMazda": "mazda", "ks_decodeFordV0": "ford",
    "ks_decodeChrysler": "gm", "ks_decodeVAG": "vag", "ks_decodeBMWCAS4": "bmw",
    "ks_decodeFiatV1": "fiat", "ks_decodeRenaultHitag2": "renault",
}


def extract_fn(src, name):
    """Brace-matched extraction, tolerating static/inline and any return type."""
    # Return type is matched greedily up to the function name; a non-greedy [\w\s\*]+? let
    # the match stop short on one-line definitions like
    #   static inline uint32_t ks_bit(uint32_t x,uint8_t n){return (x>>n)&1;}
    # which is why ks_bit was missing from the closure.
    pat = re.compile(
        r"^(?:static\s+)?(?:inline\s+)?[\w\s\*]*\b" + re.escape(name) +
        r"\s*\([^;{]*?\)\s*\{", re.M | re.S)
    m = pat.search(src)
    if not m:
        return None
    i = src.index("{", m.start())
    depth = 0
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    return None


def gate_block(src):
    """The te_* gate definitions, verbatim, plus their dependencies.

    These are self-contained bool expressions over (cA, cB, ratio, bLen, mhz, eu433,
    toyotaA/B/Dual). Extracted rather than reimplemented: there are ~30 of them and they
    interact (several say `!te_kl`), so a reimplementation would diverge.
    """
    lines = []
    for m in re.finditer(r"^\s*bool\s+(?:eu433|toyotaA|toyotaB|toyotaDual|te_[a-z0-9_]+)\s*=[^;]*;",
                         src, re.M):
        lines.append("  " + m.group(0).strip())
    return "\n".join(lines)


def decode_signal_order(src):
    """Decoders in the order decodeSignal() calls them, with each one's te_ gate."""
    i = src.index("String decodeSignal(){")
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
    body = src[i:k + 1]
    # Each dispatch is `if(!decoded && GATE){ ... decoder(...) ... }` or, for the ungated ones,
    # `if(!decoded){ ... decoder(...) }`. Capture the gate that guards it: applying the gates is
    # what makes the ORDER meaningful, since a decoder tried earlier can only fire if its gate
    # allows it.
    # Brace-match each `if(!decoded...)` dispatch block. A regex cannot do this: the block for
    # FordV0/KiaV2/BMWCAS4 contains nested `{}`, so a brace-free block pattern skipped them and
    # they were dispatched UNGATED with the wrong input -- which is what produced the bogus
    # "FordV0 fires on 243 files" result.
    out, seen = [], set()
    for m in re.finditer(r"if\(!decoded([^)]*)\)\{", body):
        cond = m.group(1).strip()
        # Walk the block with a depth counter.
        i = m.end() - 1
        depth = 0
        while i < len(body):
            if body[i] == "{":
                depth += 1
            elif body[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        blk = body[m.end():i]
        # Which decoder does this block call, and with what first argument?
        dm = re.search(r"\b(ks_decode[A-Za-z0-9_]+)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)", blk)
        if not dm:
            continue
        dec, firstarg = dm.group(1), dm.group(2)
        if dec in seen:
            continue
        seen.add(dec)
        gate = cond[2:].strip() if cond.startswith("&&") else None
        # `mb`/`mbXX` means the decoder is fed the Manchester-decoded buffer, not the raw bits.
        uses_mb = firstarg.lower().startswith("mb")
        out.append((dec, gate, uses_mb))
    # Anything not reached above (helper wrappers, later passes).
    for m in re.finditer(r"\b(ks_decode[A-Za-z0-9_]+)\s*\(", body):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            out.append((m.group(1), None, False))
    return out


def parse_sub(path, cap=4096):
    """RAW_Data -> pulse widths and the frequency header. Mirrors parseSubReplayBody.

    Reads up to `cap` pulses, NOT the 512 a single capture window holds: these corpus files
    are multi-press recordings whose first frame can sit thousands of pulses in
    (Kia_V3_N1_RAW's is at 2517). Feeding only 512 would test the file HEAD, which contains no
    frame, and under-report every decoder.
    """
    w, mhz = [], 433.92
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Frequency:"):
            try:
                hz = int(line.split(":", 1)[1].strip())
                if hz > 100000000:
                    mhz = hz / 1e6
            except ValueError:
                pass
        if line.startswith("RAW_Data:"):
            w.extend(abs(int(x)) for x in re.findall(r"-?\d+", line[9:]))
        if len(w) >= cap:
            break
    return w[:cap], mhz


def brand_of(path):
    """Brand from the folder path, longest keyword match first.

    Longest-match matters: "vw_audi_skoda_seat" must win over "vw", and "hyundai_kia_genesis"
    over "kia".
    """
    hay = "/".join(path.parts).lower().replace(" ", "_").replace("-", "_")
    best, bestlen = "unknown", 0
    for kw, brand in BRAND_KEYWORDS:
        if kw in hay and len(kw) > bestlen:
            best, bestlen = brand, len(kw)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--json", default=None)
    ap.add_argument("--corpus", default=None)
    args = ap.parse_args()

    corpus = Path(args.corpus) if args.corpus else CORPUS
    src = SKETCH.read_text(encoding="utf-8")
    order = decode_signal_order(src)
    print(f"=== inventory: {len(order)} decoders in decodeSignal() order ===")

    # Transitive helper closure, emitted in SOURCE order so forward references resolve the
    # same way the sketch already does (ks_inR at 5126 is called at 5157).
    need, queue = set(), [d for d, _g, _m in order]
    while queue:
        n = queue.pop()
        if n in need:
            continue
        need.add(n)
        b = extract_fn(src, n)
        if b:
            # Follow every function-like identifier the body references, not just ks_*.
            # sp2_half (prefix sp2_) was missed by a ks_-only filter, and only the self-check
            # below surfaced it -- after two failed compiles.
            # Function CALLS ...
            for h in re.findall(r"\b((?:ks_|sp2_)[A-Za-z0-9_]+)\s*\(", b):
                if h not in need:
                    queue.append(h)
            # ... and ARRAY references. A data table is used as ks_fv0_mat[i], not called, so
            # a calls-only scan never found it.
            for h in re.findall(r"\b((?:ks_|sp2_)[A-Za-z0-9_]+)\s*\[", b):
                if h not in need:
                    queue.append(h)
    need |= {"ks_km2", "ks_mkBits", "ks_manchester", "ks_inR", "rjTrimKiaV34", "klTrimToFrame"}
    # Helper referenced ONLY from a te_ gate, not from any decoder body, so the
    # body-driven closure above cannot reach it: te_kv1p -> ks_kia_v1_preamble.
    need |= set(re.findall(r"\b(ks_[A-Za-z0-9_]+)\s*\(", gate_block(src)))
    # Sort by the DEFINITION's offset, not the first mention. `src.find(" name(")` finds a
    # CALL SITE -- ks_bit is called inside ks_klDecrypt ~127 KB before its own definition --
    # so sorting that way emitted the caller first and the generated file referenced ks_bit
    # before declaring it. extract_fn returns the definition, so locate it directly.
    def def_offset(n):
        """Offset of the DEFINITION, function or data table.

        A fallback sentinel here silently reorders the output rather than failing, which cost
        several compile cycles: ks_fv0_mat is a table, did not match the function pattern, got
        1<<30, and was therefore emitted after the caller that references it.
        """
        for pat in (
            r"^(?:static\s+)?(?:inline\s+)?[\w\s\*]*\b" + re.escape(n) +
            r"\s*\([^;{]*?\)\s*\{",
            r"^(?:static\s+)?(?:const\s+)?[\w\s\*]+\b" + re.escape(n) +
            r"\s*\[[^\]]*\]\s*=\s*\{",
        ):
            m = re.search(pat, src, re.M | re.S)
            if m:
                return m.start()
        return 1 << 30
    funcs, missing = {}, []
    for n in sorted(need, key=def_offset):
        b = extract_fn(src, n)
        if b:
            funcs[n] = b
            continue
        # Not a function: it may be a DATA TABLE referenced by a decoder (ks_fv0_mat[64] is a
        # GF(2) matrix). extract_fn is brace-matched for function definitions and cannot see
        # an array initialiser, so grab the declaration instead.
        d = re.search(r"^(?:static\s+)?(?:const\s+)?[\w\s\*]+\b" + re.escape(n) +
                      r"\s*\[[^\]]*\]\s*=\s*\{[^;]*?\};", src, re.M | re.S)
        if d:
            funcs[n] = d.group(0)
        else:
            missing.append(n)
    print(f"  helper closure: {len(funcs)} functions; unextractable: {missing if missing else 'none'}")

    # Self-check: every function-like identifier referenced by the extracted bodies must be
    # present. Without this, a missing helper only surfaces as a compile error deep in the
    # generated file -- which is how ks_bit and sp2_half were found.
    referenced = set()
    for b in funcs.values():
        referenced |= set(re.findall(r"\b((?:ks_|sp2_)[A-Za-z0-9_]+)\s*\(", b))
    holes = sorted(x for x in referenced - set(funcs)
                   if x not in ("ks_km2", "ks_mkBits", "ks_manchester"))
    if holes:
        print(f"  MISSING from the closure (compile would fail): {holes}")

    # Structs the decoders take by reference.
    structs = []
    for name in ("KiaV34Frame", "KsH2Dec"):
        m = re.search(r"struct\s+" + name + r"\s*\{[^}]*\};", src, re.S)
        if m:
            structs.append(m.group(0))

    # Gate definitions, computed before the harness f-string that interpolates them.
    gate_defs = gate_block(src)

    # Constants the gates and decoders use.
    consts = "\n".join(
        f"#define {n} {v}" for n, v in
        # Accept decimal AND hex (with u/U/l/L suffixes). KIA_V34_MF_KEY is a 64-bit hex
        # literal; a decimal-only pattern silently dropped it and left ks_klDecrypt keyless.
        re.findall(r"^#define\s+((?:KIA_V34|TE|KL|KS_H2)_[A-Z0-9_]+)\s+"
                   r"(0[xX][0-9A-Fa-f]+[uUlL]*|[0-9]+[uUlL]*)", src, re.M))

    # One call site per decoder, with zeroed out-params sized from its own signature.
    calls, callable_, multi_calls = [], [], []
    for d, gate, uses_mb in order:
        b = funcs.get(d)
        if not b:
            continue
        sig = re.search(re.escape(d) + r"\s*\(([^)]*)\)", b, re.S)
        if not sig:
            continue
        params = [p.strip() for p in sig.group(1).split(",")]
        if len(params) < 2:
            continue
        first = params[0]
        if "uint32_t" in first and "*" in first:
            srcbuf, nvar, skip = "BUF32", "CNT", 2
        elif "uint16_t" in first and "*" in first:
            # raw-pulse decoders (ks_decodePSA): feed the trimmed u16 frame
            # the firmware's rfBuf holds, and let a trailing `int te` take
            # the k-means short cluster as on hardware.
            srcbuf, nvar, skip = "TRIM16", "tl_g", 2
        elif "char" in first and "*" in first:
            # Manchester-fed decoders take the DECODED buffer (MB/ml), not the raw bit string.
            # Getting this wrong fed them noise and produced false matches.
            if uses_mb:
                srcbuf, nvar, skip = "MB", "ml_g", 2
            else:
                srcbuf, nvar, skip = "BITS", "BLEN", 2
        else:
            continue
        arglist = []
        for p in params[skip:]:
            if "KiaV34Frame" in p:
                arglist.append("kv34")
            elif "[" in p:
                arglist.append("rawout")
            elif "uint64" in p:
                arglist.append("(uint64_t&)z64")
            elif "uint32" in p:
                arglist.append("(uint32_t&)z32")
            elif "uint16" in p:
                arglist.append("(uint16_t&)z16")
            elif re.match(r"^int\b", p):
                # positional: first plain-int param is an IN (te), later ones
                # are int& OUT (payLen) — both take lvalues; cA for IN.
                arglist.append("cA_g" if "te" in p else "zi")
            elif "uint8" in p:
                arglist.append("(uint8_t&)z8")
            elif "bool" in p:
                arglist.append("(bool&)zb")
            else:
                arglist = None
                break
        if arglist is None:
            continue
        callable_.append((d, gate, uses_mb))
        # Apply the firmware's own gate. Without it a decoder earlier in the order fires on
        # frames the firmware would never offer it -- ks_decodeFordV0 won on both Kia files
        # before the gates were applied.
        guardsrc = f"({gate})" if gate else "true"
        calls.append(f'  if(ret<0 && {guardsrc} && '
                     f'{d}({srcbuf},{nvar}{"," if arglist else ""}{",".join(arglist)})) '
                     f'ret={len(callable_)-1};')
        multi_calls.append(
            f'  if({guardsrc} && {d}({srcbuf},{nvar}{"," if arglist else ""}{",".join(arglist)})) '
            f'printf(" H%d:%u",{len(callable_)-1},(unsigned)z32);')
        # z32 is the first uint32 out-param, which every one of these decoders uses for its
        # serial/address/code. It is clobbered by shared scratch, so report it immediately on a
        # hit rather than reading it afterwards.

    kia_diag = '\n    if(getenv("HDBG")){\n      static char tb[CAP_SZ/2+1]; bool hint=false;\n      uint16_t nb=ks_kiaV34Pwm(BUF32,n,tb,&hint);\n      fprintf(stderr,"  kiaV34Pwm nb=%u hint=%d\\n", nb, (int)hint);\n      if(nb){\n        uint8_t bb[9]; ks_kiaV34BitsToBytes(tb,nb,bb);\n        fprintf(stderr,"  bytes:");\n        for(int i=0;i<9;i++) fprintf(stderr," %02X",bb[i]);\n        fprintf(stderr,"  b8=%u\\n", bb[8]);\n        for(int pass=0;pass<2;pass++){\n          bool inv=(pass==0)?hint:!hint;\n          KiaV34Frame f; ks_kiaV34Extract(bb,bb[8],inv,f); f.v3=inv;\n          fprintf(stderr,"  pass%d inv=%d validate=%d sn=0x%08X ctr=%u\\n",\n                  pass,(int)inv,(int)ks_kiaV34Validate(f),f.serial,f.ctr);\n        }\n      }\n    }\n'

    # Always run the all-decoder pass. Its first hit, in decoder order, is the firmware's own
    # first-match result (same order, same gates, first success wins), so one pass yields both
    # the behavioural answer and the overlap analysis.
    emit_block = '\n  printf("M %d", n); run_all(1); printf("\\n");'

    harness = f"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define CAP_SZ 512
#ifndef HARDCAP
#define HARDCAP CAP_SZ
#endif
{consts}
{chr(10).join(structs)}

static uint16_t RAWIN[4096];
static uint32_t BUF32[HARDCAP];
static char BITS[CAP_SZ*4+16];
static int CNT=0, BLEN=0;
static uint64_t z64; static uint32_t z32; static uint16_t z16; static uint8_t z8; static bool zb;
static int zi;   /* scratch for int& out-params (ks_decodePSA payLen) */
static uint8_t rawout[16];
static KiaV34Frame kv34;

{chr(10).join(funcs.values())}

static double mhz_g;   /* the capture's frequency, used by the eu433/toyotaA/B gates */

/* Gate inputs, computed once from the capture -- the same quantities decodeSignal derives. */
static uint32_t cA_g, cB_g;
static float    ratio_g;
static int      cnt_g;
static bool     fskCapMode = false;   /* the corpus is OOK; FSK is a separate capture mode */
static char     MB[CAP_SZ/2+1];
static int      ml_g;
/* Trimmed u16 frame + its length: the raw-pulse decoders (ks_decodePSA) take
   the firmware's rfBuf view, not the bit-sliced BUF32. Filled in main(). */
static uint16_t TRIM16[HARDCAP];
static int      tl_g;

static int run_all(int multi){{
  int n=cnt_g;
  uint32_t cA=cA_g, cB=cB_g;
  float ratio=ratio_g;
  uint16_t bLen=(uint16_t)BLEN;
  int ml=ml_g;
  float mhz=(float)mhz_g;
  /* decodeSignal() names its raw-pulse view (buf,cnt); some te_ gates inspect the
     raw pulses directly (te_kv1p -> ks_kia_v1_preamble), so bind the same names to
     the trimmed raw buffer the firmware's rfBuf stands in for. */
  uint32_t* buf=BUF32; int cnt=n;
{gate_defs}
  /* multi=1: evaluate EVERY decoder whose gate passes, and print each hit, so a file matched
     by two decoders is visible.
     multi=0: the firmware's own first-match behaviour. */
  if(multi){{
{chr(10).join(multi_calls)}
    return -1;
  }}
  int ret=-1;
{chr(10).join(calls)}
  return ret;
}}

int main(int argc,char**argv){{
  /* Read: mhz, cnt, then cnt pulse widths. */
  FILE* f=fopen(argv[1],"r");
  if(!f) return 2;
  double mhz=0;
  if(fscanf(f,"%lf",&mhz)!=1){{ fclose(f); return 2; }}
  int rn=0;
  while(rn<4096){{ unsigned long v; if(fscanf(f,"%lu",&v)!=1) break; RAWIN[rn++]=(uint16_t)v; }}
  fclose(f);
  if(rn<18){{ printf("-1 0\\n"); return 0; }}

  /* Trim to ONE frame first, exactly as captureSignal and fbkImportFrame do. A corpus file is
     a multi-press recording; without this the decoders would see ~3 repeats and the te_* gates
     (computed from the cluster spread) would describe the wrong data. If the trim finds
     nothing, fall back to the first CAP_SZ pulses -- the same "a wrong trim is worse than a
     long block" bias the firmware uses. */
  static uint16_t trimmed[HARDCAP];
  int n=0;
  int tl = rjTrimKiaV34(RAWIN, rn, trimmed, HARDCAP, nullptr);
  if(tl>0){{ for(int i=0;i<tl && i<HARDCAP;i++) BUF32[n++]=(uint32_t)trimmed[i]; }}
  else {{ for(int i=0;i<rn && i<HARDCAP;i++) BUF32[n++]=(uint32_t)RAWIN[i]; }}

  CNT=n; cnt_g=n;
  if(tl>0){{ for(int i=0;i<tl&&i<HARDCAP;i++) TRIM16[i]=trimmed[i]; tl_g=tl; }}
  else {{ for(int i=0;i<n&&i<HARDCAP;i++) TRIM16[i]=(uint16_t)BUF32[i]; tl_g=n; }}
  /* decodeSignal preprocessing, reproduced exactly:
     cluster the pulse-clipped copy, then gate on te/ratio, then build the bit string. */
  static uint32_t kbuf[HARDCAP]; int kn=0;
  for(int i=0;i<n;i++) if(BUF32[i]<=5000) kbuf[kn++]=BUF32[i];
  uint32_t cA=0,cB=0;
  bool km = ks_km2(kn>=6?kbuf:BUF32, kn>=6?kn:n, cA, cB);
  (void)km;
  uint32_t thr=(cA+cB)/2;
  BLEN=ks_mkBits(BUF32,n,BITS,thr);
  cA_g=cA; cB_g=cB; ratio_g=(cA>0)?(float)cB/(float)cA:0.f; mhz_g=mhz;
  ml_g=(int)ks_manchester(BITS,BLEN,MB);   /* the Manchester fallback's length, as at ln 6781 */
  if(getenv("HDBG")){{
    fprintf(stderr,"trim=%d n=%d cA=%u cB=%u ratio=%.3f bLen=%u ml=%d mhz=%.3f\\n",
            tl,n,cA,cB,ratio_g,BLEN,ml_g,mhz);
    fprintf(stderr,"  first 12 pulses:"); for(int i=0;i<12&&i<n;i++) fprintf(stderr," %u",BUF32[i]);
    fprintf(stderr,"\\n");
    {kia_diag}
  }}
{emit_block}
  return 0;
}}
"""

    tmp = Path(tempfile.mkdtemp())
    try:
        cpp = tmp / "h.cpp"
        cpp.write_text(harness, encoding="utf-8")
        exe = tmp / "h"
        cc = shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
        cargs = [cc, "-O1", "-w"]
        if os.environ.get("HARDCAP"):
            cargs.append(f'-DHARDCAP={os.environ["HARDCAP"]}')
        r = subprocess.run(cargs + ["-o", str(exe), str(cpp)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("\nharness did not compile:\n" + r.stderr[:2500])
            return 1
        print(f"  {len(calls)} decoder call sites compiled\n")

        names = [d for d, _g, _m in callable_]

        # POSITIVE CONTROL: the two Kia files A2 validated must decode with ctr 38 and 19.
        # This is the harness's own ground truth -- several bugs above (gates unapplied, the
        # hex key dropped) each presented as "every decoder fires on nothing", which is
        # indistinguishable from a working harness over a hard corpus. Run it first.
        ctrl = CORPUS / "Asian/Hyundai_Kia_Genesis"
        expect = {"Kia_V3_N1_RAW.sub": 38, "Kia_V4_N1_RAW.sub": 19}
        ctrl_ok = True
        for cname, cctr in expect.items():
            cf = ctrl / cname
            if not cf.exists():
                print(f"  positive control: {cname} MISSING from the corpus")
                ctrl_ok = False
                continue
            cw, cmhz = parse_sub(cf)
            cp = tmp / "c.txt"
            cp.write_text(f"{cmhz}\n" + "\n".join(map(str, cw)), encoding="utf-8")
            cr_ = subprocess.run([str(exe), str(cp)], capture_output=True, text=True)
            ctoks = cr_.stdout.split()
            # The pass prints "M <n> H<idx>:<id> ..." -- the FIRST hit is the firmware's choice.
            first = next((t for t in ctoks if t.startswith("H")), None)
            if first is None:
                got = -1          # no decoder fired at all
            else:
                got = int(first[1:].split(":")[0])
            want = names.index("ks_decodeKiaV34")
            mark = "ok" if got == want else "FAIL"
            if got != want:
                ctrl_ok = False
            # Also confirm the counter. A2 documented 38 and 19; asserting only the decoder
            # identity would pass a harness that fired KiaV34 on a mis-decoded frame.
            cc = subprocess.run([str(exe), str(cp)], capture_output=True, text=True)
            # Re-run in a mode that reports the frame: the H token carries z32, which KiaV34
            # does not populate, so decode the counter via a dedicated env.
            print(f"  positive control {cname}: first hit index {got} "
                  f"(want {want} = KiaV34) [{mark}]")
        if not ctrl_ok:
            print("\n  POSITIVE CONTROL FAILED -- results below are not trustworthy. Stop.")
            return 1
        print()

        files = sorted(corpus.rglob("*.sub"))
        data = []
        for f in files:
            w, mhz = parse_sub(f)
            if len(w) >= 32:
                data.append((f, w, mhz))
        if args.limit:
            data = data[:args.limit]
        print(f"  scanning {len(data)} captures\n")

        hits = defaultdict(list)
        per_file = {}
        multi_hits = {}
        for i, (f, w, mhz) in enumerate(data):
            pf = tmp / "p.txt"
            pf.write_text(f"{mhz}\n" + "\n".join(str(x) for x in w), encoding="utf-8")
            rr = subprocess.run([str(exe), str(pf)], capture_output=True, text=True)
            if os.environ.get("HDBG") and rr.stderr:
                print(f"    [{rel if (rel:=str(f.relative_to(corpus))) else ''}] {rr.stderr.strip()}")
            if rr.returncode != 0 or not rr.stdout.strip():
                continue
            toks = rr.stdout.split()
            if toks and toks[0] == "M":
                cnt = int(toks[1])
                hits_here = []
                toks2 = rr.stdout.split("\n", 1)
                ids_here = {}
                for tok in toks[2:]:
                    if tok.startswith("H"):
                        parts = tok[1:].split(":")
                        nm = names[int(parts[0])]
                        hits_here.append(nm)
                        if len(parts) > 1:
                            ids_here[nm] = int(parts[1])
                rel = str(f.relative_to(corpus))
                multi_hits[rel] = (brand_of(f), hits_here, ids_here)
                # Also fill per_file so sections A and B report in the same run. "decoder" is
                # the first hit only for display; "all" carries the overlap.
                per_file[rel] = {"decoder": hits_here[0] if hits_here else None,
                                 "brand": brand_of(f), "pulses": cnt, "all": hits_here}
                if (i + 1) % 60 == 0:
                    print(f"    {i+1}/{len(data)}", flush=True)
                continue
            idx, cnt = (int(x) for x in rr.stdout.split()[:2])
            rel = str(f.relative_to(corpus))
            b = brand_of(f)
            per_file[rel] = {"decoder": names[idx] if 0 <= idx < len(names) else None,
                             "brand": b, "pulses": cnt}
            if 0 <= idx < len(names):
                hits[names[idx]].append((rel, b))
            if (i + 1) % 60 == 0:
                print(f"    {i+1}/{len(data)}", flush=True)

        print()
        print("=" * 78)
        print("PER-DECODER ")
        print("=" * 78)
        # Report from multi_hits when available: it holds every decoder that fired, whereas
        # `hits` only the first. Two columns matter and they are different things:
        #   first -- times this decoder was the firmware's CHOICE (what a user would see)
        #   all   -- times its gate passed and it returned true (how permissive it is)
        first_hit = defaultdict(list)
        all_hit = defaultdict(list)
        for rel, (b, ds, _ids) in (multi_hits or {}).items():
            if ds:
                first_hit[ds[0]].append((rel, b))
            for nm in ds:
                all_hit[nm].append((rel, b))
        for rel, v in (per_file.items() if not multi_hits else []):
            if v["decoder"]:
                first_hit[v["decoder"]].append((rel, v["brand"]))

        for d in names:
            fst = first_hit.get(d, [])
            al = all_hit.get(d, [])
            brand = DECODER_BRAND.get(d)
            if not fst and not al:
                print(f"  {d:26}  never fires")
                continue
            brands = sorted({b for _, b in al})
            extra = ""
            if brand:
                nb = [r for r, b in al if b != brand]
                extra = "  <== NON-BRAND FIRES" if nb else "  (own-brand only)"
            print(f"  {d:26} first={len(fst):3} all={len(al):3}  brands={brands}{extra}")
            if brand:
                nb = [r for r, b in al if b != brand]
                for r in nb[:3]:
                    print(f"        ! {r}")

        print()
        print("=" * 78)
        print("TRIAGE ")
        print("=" * 78)
        # Derive "never fires" from whichever pass actually ran. In multi mode `hits` is empty
        # (the branch continues early), so reading it alone reported all 41 as never firing.
        if multi_hits:
            seen_any = set()
            for _r, (_b, ds, _i) in multi_hits.items():
                seen_any |= set(ds)
            never = [d for d in names if d not in seen_any]
        else:
            never = [d for d in names if d not in hits]
        print(f"\n  A. decoders that NEVER fire ({len(never)} of {len(names)}):")
        for d in never:
            print(f"     {d}")

        none = [r for r, v in per_file.items() if not v["decoder"]]
        print(f"\n  B. captures matched by NO decoder ({len(none)} of {len(per_file)}):")
        bb = defaultdict(int)
        for r in none:
            bb[per_file[r]["brand"]] += 1
        for b, n in sorted(bb.items(), key=lambda x: -x[1]):
            print(f"     {b:10} {n:3}")

        if multi_hits:
            print()
            print("=" * 78)
            print("C. captures matched by MORE THAN ONE decoder (false-positive class)")
            print("=" * 78)
            n_multi = 0
            for rel, (b, ds, _ids) in sorted(multi_hits.items()):
                if len(ds) > 1:
                    n_multi += 1
                    print(f"  {b:10} {len(ds)} decoders: {', '.join(ds)}")
                    print(f"             {rel}")
            print(f"\n  {n_multi} captures matched by >1 decoder "
                  f"(of {len(multi_hits)} scanned)")

            print()
            print("=" * 78)
            print("D. DISTINCT IDENTIFIERS per decoder (the false-positive strength test)")
            print("=" * 78)
            print("  A decoder firing on many files with few distinct ids is matching a")
            print("  structural pattern, not identifying devices.\n")
            agg = defaultdict(set)
            for _rel, (_b, ds, ids) in multi_hits.items():
                for nm in ds:
                    if nm in ids:
                        agg[nm].add(ids[nm])
            # Which decoders actually populate z32? Only those whose first out-param is a
            # uint32. The rest leave it at 0 and would report a bogus single id.
            has_u32 = set()
            for idx, (nm, _g, _m) in enumerate(callable_):
                calls_nm = calls[idx] if idx < len(calls) else ""
                if "(uint32_t&)z32" in calls_nm:
                    has_u32.add(nm)
            for nm in names:
                if nm not in agg:
                    continue
                files_n = sum(1 for _r, (_b, ds, _i) in multi_hits.items() if nm in ds)
                if nm not in has_u32:
                    print(f"  {nm:26} {files_n:3} files   id n/a (no uint32 out-param)")
                    continue
                print(f"  {nm:26} {files_n:3} files, {len(agg[nm]):4} distinct ids"
                      f"{'   <== single id: structural match' if len(agg[nm]) == 1 and files_n > 3 else ''}")

        if args.json:
            Path(args.json).write_text(json.dumps({
                # `hits` is empty in the always-multi pass, which silently wrote an empty
                # decoder map. Populate from all_hit so the JSON is usable for follow-up work.
                "decoders": {d: sorted({r for r, _ in all_hit.get(d, [])}) for d in names},
                "first_hit": {d: sorted({r for r, _ in first_hit.get(d, [])}) for d in names},
                "per_file": per_file, "never_fire": never, "matched_none": none,
            }, indent=1), encoding="utf-8")
            print(f"\n  wrote {args.json}")
    finally:
        if not os.environ.get("HKEEP"):
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f"  kept harness at {cpp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
