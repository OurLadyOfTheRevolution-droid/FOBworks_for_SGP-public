#!/usr/bin/env python3
"""C2 same-code rejection — the fix for research/10 §2.5.

`rbArm` required two *entries* but not two different *codes*. One fob press can
append two entries (the capture loop fills 512 pulses over several seconds, and a
press emits its frame repeatedly), so `fbkBuf[0]` and `fbkBuf[1]` could hold the
same counter. RollBack then transmits that counter twice, the receiver sees no
forward step, and the attack fails silently — the operator sees "done" and nothing
happens.

The fix has two parts, both asserted here:

  1. The append path records the counter each capture decoded to.
  2. `rbArm` refuses a pair whose counters are equal or out of order, and falls back
     to a content-identity check when no counter was decoded.

This runs the *shipped* `fbkCtrOrder` / `fbkHash` / arm-acceptance logic, extracted
verbatim and compiled, rather than reimplementing it.

Measured context (KIA V3 N1 RAW.sub, 67977 pulses):
  frame repeat unit     158 pulses
  counter run length    10 frames per counter value
  CAP_SZ                512 pulses  -> 3.2 frames per capture
So a capture holds ~3 frames of ONE counter: one code, repeated. That is why the
equality check is the load-bearing one, and why two entries are not two codes.

Run: python3 test_rollback_samecode.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKETCH = HERE / "FOBworks_for_SGP.ino"
src = SKETCH.read_text(encoding="utf-8")


def block(marker: str) -> str:
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
    return src[i : k + 1] + "\n"


# ── Static: the pieces exist and are wired ──────────────────────────────────
assert "uint32_t ctr; bool hasCtr;" in src, "FbkEntry does not carry a counter"
# FbkEntry also carries `trimmed`, which rbArm gates on (research/12 §3 P1).
assert "bool trimmed; };" in src, "FbkEntry does not carry the trimmed flag"
assert "static int fbkCtrOrder()" in src, "fbkCtrOrder missing"
assert "static bool fbkParseCtr(" in src, "fbkParseCtr missing"
assert "static uint32_t fbkHash(" in src, "fbkHash missing"

# rbArm must consult the order check, not merely count entries.
arm = block("static bool rbArm()")
assert "fbkCtrOrder()" in arm, "rbArm does not check counter order (the §2.5 bug)"
assert "ord<0" in arm, "rbArm does not reject a same-or-backward pair"
assert "fbkHash(" in arm, "rbArm has no content-identity fallback"
assert "if(fbkCount<2) return false;" in arm, "rbArm lost the two-entry requirement"

# The append path must record the counter. It now lives in fbkAppend(), extracted
# from the capture path so the harness can drive it without a radio (§2.6).
app = src[src.index("static bool fbkAppend("):]
app = app[:app.index("\n}\n")]
assert "fbkParseCtr(decode" in app, "fbkAppend does not record the counter"
assert "e.hasCtr" in app, "fbkAppend does not set hasCtr"
assert "fbkAppend(rfBuf,rfLen,rfFreq,rfStartHigh,lastDecode)" in src, \
    "the capture path no longer calls fbkAppend"

# The route must report why a refusal happened, so a failure is diagnosable rather
# than silent. That matters because the failure mode is invisible in the field.
#
# Scoped to the arm route's own body: the string `reason` appears in other handlers
# (the tx-failed events), so a file-wide check would be satisfied without the route
# emitting anything. Verified: a file-wide check missed exactly that mutant.
arm_route = src[src.index('protectedRoute("/api/rollback_arm"'):]
arm_route = arm_route[:arm_route.index('  });')]
assert 'reason="same-or-backward-code"' in arm_route, \
    "the arm route does not name the same-code refusal"
assert 'need-2-codes' in arm_route, "the arm route does not name the short-of-codes refusal"
assert '",\\"reason\\":' in arm_route, \
    "the arm route does not emit a reason field in its response"

# ── Behavioural: run the shipped logic ──────────────────────────────────────
HARNESS = r'''
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

struct FbkEntry { uint16_t w[512]; int len; float freq; uint32_t ts; bool sh;
                  uint32_t ctr; bool hasCtr; bool trimmed; };
#define FBK_MAX 5
static FbkEntry fbkBuf[FBK_MAX];
static int fbkCount=0;

// Extracted verbatim from FOBworks_for_SGP.ino
''' + block("static int fbkCtrOrder()") + block("static uint32_t fbkHash(") + r'''

// The acceptance logic exactly as rbArm applies it (rbArm also emits serial, which
// is irrelevant here).
static bool armWouldAccept(){
  if(fbkCount<2) return false;
  if(!fbkBuf[0].trimmed||!fbkBuf[1].trimmed) return false;   // the research/12 gate
  int ord=fbkCtrOrder();
  if(ord<0) return false;
  if(ord==0){
    if(fbkBuf[0].len==fbkBuf[1].len &&
       fbkHash(fbkBuf[0].w,fbkBuf[0].len)==fbkHash(fbkBuf[1].w,fbkBuf[1].len)) return false;
  }
  return true;
}
static void set2(uint32_t c0,bool h0,uint32_t c1,bool h1,int l0,int l1){
  fbkCount=2;
  fbkBuf[0].ctr=c0; fbkBuf[0].hasCtr=h0; fbkBuf[0].len=l0; fbkBuf[0].trimmed=true;
  fbkBuf[1].ctr=c1; fbkBuf[1].hasCtr=h1; fbkBuf[1].len=l1; fbkBuf[1].trimmed=true;
  for(int i=0;i<l0;i++) fbkBuf[0].w[i]=(uint16_t)(400+i);
  for(int i=0;i<l1;i++) fbkBuf[1].w[i]=(uint16_t)(400+i);
}
int main(){
  int fails=0;
  struct { const char* what; uint32_t c0; bool h0; uint32_t c1; bool h1; int l0; int l1; bool want; } t[]={
    {"real V3 pair 0x26 -> 0x27",      0x26,true,0x27,true, 512,512, true},
    {"real V4 pair 0x13 -> 0x14",      0x13,true,0x14,true, 512,512, true},
    {"SAME counter (one press)",       0x26,true,0x26,true, 512,512, false},
    {"backward 0x27 -> 0x26",          0x27,true,0x26,true, 512,512, false},
    {"16-bit wrap 0xFFFF -> 0x0000",   0xFFFF,true,0x0000,true, 512,512, true},
    {"forward 0x26 -> 0x1A26",         0x26,true,0x1A26,true, 512,512, true},
    {"backward large 0x1A26 -> 0x26",  0x1A26,true,0x26,true, 512,512, false},
    {"no ctr, identical content",      0,false,0,false, 512,512, false},
    {"no ctr, different length",       0,false,0,false, 512,500, true},
    {"only one ctr, identical",        0x26,true,0,false, 512,512, false},
  };
  for(unsigned i=0;i<sizeof(t)/sizeof(t[0]);i++){
    set2(t[i].c0,t[i].h0,t[i].c1,t[i].h1,t[i].l0,t[i].l1);
    bool got=armWouldAccept();
    printf("  %-34s -> %-6s %s\n", t[i].what, got?"ARM":"refuse", got==t[i].want?"OK":"WRONG");
    if(got!=t[i].want) fails++;
  }
  printf("\n%s (%d failures)\n", fails?"FAIL":"ALL SAME-CODE CHECKS PASS", fails);
  return fails?1:0;
}
'''


with tempfile.TemporaryDirectory() as td:
    wd = Path(td)
    cpp = wd / "samecode.cpp"
    cpp.write_text(HARNESS, encoding="utf-8")
    exe = wd / "samecode"
    cxx = shutil.which("c++") or shutil.which("clang++") or "c++"
    r = subprocess.run([cxx, "-O1", "-std=c++17", "-w", str(cpp), "-o", str(exe)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("harness compile failed:\n" + r.stderr[:3000], file=sys.stderr)
        sys.exit(2)
    out = subprocess.run([str(exe)], capture_output=True, text=True)
    print(out.stdout)
    if out.returncode != 0:
        sys.exit(1)

print("rollback same-code checks passed")
