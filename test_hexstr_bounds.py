#!/usr/bin/env python3
"""Catch unbounded writes into caller-supplied buffers (the hexbuf overflow).

Field failure this reproduces:

    Stack smashing protect failure!
    __stack_chk_fail -> decodeSignal() -> scanTick() -> loop()

decodeSignal() had a stack `char hexbuf[128]` filled by ks_hexStr(bits, bLen, hexbuf)
with bLen up to CAP_SZ (512). 512 bits encodes to (512+3)/4 = 128 hex chars, and
ks_hexStr always writes a NUL after them: 129 bytes into 128. A one-byte stack
overflow that only fires when a capture is long enough (bLen >= 509), so it sat
dormant until a strong 315 MHz burst filled the bit buffer.

A source grep would not have caught it — the call looks reasonable. So this compiles
the real ks_hexStr against a canary-guarded buffer and asserts the canary is intact
for every length up to CAP_SZ, and that the call site clamps its input.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parent / "FOBworks_for_SGP.ino"
FAILS = []


def check(cond, msg):
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        FAILS.append(msg)


def extract(src, pattern, what):
    m = re.search(pattern, src, re.S)
    if not m:
        print(f"  FAIL could not extract {what} from the firmware")
        FAILS.append(f"extract {what}")
        return None
    return m.group(0)


def _worst_case_len(fmt):
    """Formatted length of `fmt`, or None when it contains %s (unbounded by design).

    Conservative: a literal is 1 char, "%NNx" is NN chars, a bare "%x" is 1, "%%" is 1.
    Overestimating is the safe direction — a false alarm is better than a missed
    truncation.
    """
    if "%s" in fmt:
        return None
    n, i = 0, 0
    while i < len(fmt):
        if fmt[i] != "%":
            n += 1
            i += 1
            continue
        if i + 1 < len(fmt) and fmt[i + 1] == "%":
            n += 1
            i += 2
            continue
        j = i + 1
        while j < len(fmt) and fmt[j] in "-+ #0":
            j += 1
        w = ""
        while j < len(fmt) and fmt[j].isdigit():
            w += fmt[j]
            j += 1
        while j < len(fmt) and fmt[j] in "lh":
            j += 1
        if j < len(fmt) and fmt[j] in "diuxX":
            n += int(w) if w else 1
            j += 1
        i = j
    return n


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== signature is bounded ===")
    sig = extract(src, r"static void ks_hexStr\(([^)]*)\)", "ks_hexStr signature")
    if sig:
        # cap must be present, or the fix is not in place.
        check("size_t cap" in sig, "ks_hexStr takes an explicit capacity")
    body = extract(src, r"static void ks_hexStr\([^)]*\)\s*\{.*?\n\}", "ks_hexStr body")
    if body:
        check(">=cap" in body, "ks_hexStr refuses to write past the capacity")

    print("\n=== call site clamps its input ===")
    # Anchor on the real declaration (`={0};`) — the doc comment above it also quotes
    # "char hexbuf[128]", so a looser pattern matches the prose instead of the code.
    call = re.search(r"char hexbuf\[128\]=\{0\}[^\n]*\n(?:[^\n]*\n){1,3}", src)
    check(call is not None, "found the hexbuf call site")
    if call:
        txt = call.group(0)
        check("hexLen" in txt and "508" in txt,
              "hexbuf call clamps the length to what 128 bytes can hold")
        check("sizeof(hexbuf)" in txt, "hexbuf call passes its own sizeof")

    print("\n=== the writer cannot overflow, at any length ===")
    # Build a host harness around the REAL ks_hexStr, so a re-introduced off-by-one
    # fails here. Canary bytes after the buffer must survive.
    fn = extract(src, r"static void ks_hexStr\([^)]*\)\s*\{.*?\n\}", "ks_hexStr")
    if not fn:
        return 1
    harness = r"""
#include <stdio.h>
#include <string.h>
#include <stddef.h>
""" + fn + r"""
int main(void){
  char bits[513];
  for(int i=0;i<512;i++) bits[i] = (i%3)?'0':'1';   // exercise both nibble paths
  bits[512]=0;
#define CAP 128
  /* Canary sits immediately after the buffer; an off-by-one lands on it. */
  static unsigned char guard[CAP+16];
  int bad = 0;
  for(int len=0; len<=512; len++){
    memset(guard, 0xAA, sizeof(guard));
    char* buf = (char*)guard;
    ks_hexStr(bits, len, buf, CAP);
    for(size_t i=CAP; i<sizeof(guard); i++)
      if(guard[i] != 0xAA){ printf("len=%d wrote past cap at +%zu\n", len, i-CAP); bad++; break; }
    if(strnlen(buf, CAP) >= CAP){ printf("len=%d no NUL within cap\n", len); bad++; }
  }
  /* Also confirm no NUL termination before a full-length fill. */
  static unsigned char g2[CAP+16];
  memset(g2, 0xAA, sizeof(g2));
  ks_hexStr(bits, 512, (char*)g2, CAP);
  if(strlen((char*)g2) != CAP-1){ printf("full fill truncated wrongly: %zu\n", strlen((char*)g2)); bad++; }
  if(bad==0) printf("OK\n");
  return bad?1:0;
}
"""
    tmp = Path(tempfile.mkdtemp())
    try:
        c = tmp / "t.c"
        c.write_text(harness, encoding="utf-8")
        cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        check(cc is not None, "a C compiler is available")
        if cc:
            r = subprocess.run([cc, "-O0", "-fstack-protector-all", "-o",
                                str(tmp / "t"), str(c)], capture_output=True, text=True)
            if r.returncode != 0:
                print("  FAIL harness did not compile:\n" + r.stderr[:800])
                FAILS.append("harness compile")
            else:
                p = subprocess.run([str(tmp / "t")], capture_output=True, text=True)
                ok = p.returncode == 0 and "OK" in p.stdout
                check(ok, "no write past the cap for any length 0..512 (canary intact)")
                if not ok:
                    print("    " + (p.stdout + p.stderr).strip()[:400])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== the old form would have failed this test ===")
    # Mutation: revert to the unbounded write and confirm the canary trips. This proves
    # the test has teeth rather than passing because the buffer happens to be big enough.
    old = """static void ks_hexStr(const char* bits,int len,char* out){
  int o=0,chunks=(len+3)/4;
  for(int c=0;c<chunks;c++){
    int v=0; for(int b=0;b<4&&c*4+b<len;b++) v=(v<<1)|(bits[c*4+b]=='1'?1:0);
    out[o++]="0123456789ABCDEF"[v];
  }
  out[o]=0;
}"""
    mutant_src = src
    m = re.search(r"static void ks_hexStr\([^)]*\)\s*\{.*?\n\}", src, re.S)
    if m:
        mutant_src = src[:m.start()] + old + src[m.end():]
    mfn = extract(mutant_src, r"static void ks_hexStr\([^)]*\)\s*\{.*?\n\}", "old ks_hexStr")
    if mfn:
        tmp = Path(tempfile.mkdtemp())
        try:
            c = tmp / "t.c"
            c.write_text(harness.replace(fn, mfn.replace("static void", "static void")),
                         encoding="utf-8")
            cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
            if cc:
                # The old signature has no cap; drop the argument at the call sites.
                txt = c.read_text(encoding="utf-8").replace(", CAP);", ");")
                c.write_text(txt, encoding="utf-8")
                r = subprocess.run([cc, "-O0", "-o", str(tmp / "t"), str(c)],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    print("  ok   old form does not compile against the new harness (cap required)")
                else:
                    p = subprocess.run([str(tmp / "t")], capture_output=True, text=True)
                    caught = p.returncode != 0 or "wrote past cap" in p.stdout
                    check(caught, "unbounded ks_hexStr writes past the cap (test has teeth)")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== every bounded snprintf has room for its worst-case output ===")
    # snprintf cannot overflow, but if the declared size is too small it TRUNCATES,
    # which stores a wrong value silently. Three sites did exactly that: a code/serial
    # lost its last hex digit because the buffer was one byte short of "0x"+digits+NUL.
    pat = re.compile(r'char\s+(\w+)\s*\[\s*(\d+)\s*\][^;]*;\s*'
                     r'snprintf\s*\(\s*\1\s*,\s*(\d+)\s*,\s*"([^"]*)"')
    truncating, checked = [], 0
    for m in pat.finditer(src):
        name, decl, size, fmt = m.groups()
        need = _worst_case_len(fmt)
        if need is None:
            continue
        checked += 1
        if need + 1 > int(decl) or need + 1 > int(size):
            truncating.append((name, decl, size, fmt, need + 1))
    check(not truncating,
          f"no truncating snprintf among {checked} bounded sites"
          + ("" if not truncating else f" — {truncating}"))
    if truncating:
        for t in truncating:
            print(f"       {t[0]}[{t[1]}] size={t[2]} \"{t[3]}\" needs {t[4]}")

    print()
    if FAILS:
        print(f"HEXSTR BOUNDS FAILED ({len(FAILS)} failures)")
        return 1
    print("hex string bounds checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
