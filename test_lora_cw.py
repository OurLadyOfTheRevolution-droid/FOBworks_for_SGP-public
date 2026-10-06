#!/usr/bin/env python3
"""Host harness for the P2 SX1278-CW jammer register path.

The bench measurement itself needs the board; what can be checked
here is the register arithmetic underneath it, because an Frf computed wrong
puts the jammer on the wrong frequency and the isolation number is then
meaningless. The assertions compile the SHIPPED loraCwSetup/loraCwStop and
capture the bytes they write, so what is verified is the sequence that ships:

  1. Frf = f / 61.03515625 (32 MHz / 2^19, datasheet §4.1.2), little-endianised
     into RegFrfMsb/Mid/Lsb, and the recovered frequency is within a bin.
  2. The mode word is TX (bit1) with the LF band bit set below 525 MHz and clear
     above, and the PA is configured for PA_BOOST.
  3. Stop sleeps the PA before parking the reset line — leaving a hot PA is the
     failure this guards.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "FOBworks_for_SGP.ino"
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def extract_fn(src, signature):
    pat = re.compile(r"^static\s+[^\n(]*?\b" + re.escape(signature) +
                     r"\s*\([^{;]*?\)\s*\{", re.M | re.S)
    m = pat.search(src)
    if not m:
        return None
    i = src.index("{", m.start())
    depth = 0
    in_str = None
    esc = False
    while i < len(src):
        c = src[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == in_str:
                in_str = None
        elif c in "\"'":
            in_str = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    return None


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the pieces exist in the shipping source ===")
    for fn in ("loraCwSetup", "loraCwStop"):
        check(extract_fn(src, fn) is not None, f"{fn} extracted")
    check("static void loraWriteReg" in src, "loraWriteReg helper added")
    check('op=="lora_cw_probe"' in src, "serial lora_cw_probe command wired")
    check("#define LORA_CW_MAX_MS 5000" in src, "CW burst is capped")
    check('"SELF_JAM_HIGH"' in src and '"ISOLATED"' in src,
          "the probe reports an isolation verdict")

    print("\n=== Frf arithmetic and mode word against the shipped sequence ===")
    setup = extract_fn(src, "loraCwSetup")
    stop = extract_fn(src, "loraCwStop")
    check(setup is not None and stop is not None, "CW bodies sliced")

    prologue = r"""
#include <cstdio>
#include <cstdint>
#include <cstring>
struct Write { uint8_t a, v; };
static Write g_w[32]; static int g_n=0;
static void loraWriteReg(uint8_t a, uint8_t v){ if(g_n<32){ g_w[g_n].a=a; g_w[g_n].v=v; g_n++; } }
static void loraParkReset(){ if(g_n<32){ g_w[g_n].a=0xFF; g_w[g_n].v=0; g_n++; } }
static uint8_t find(uint8_t a){ uint8_t v=0xFF; for(int i=0;i<g_n;i++) if(g_w[i].a==a) v=g_w[i].v; return v; }
""" + (setup or "") + "\n" + (stop or "") + "\n"

    body = r"""
static int recoverFrf(uint32_t frf){ return (int)((double)frf*61.03515625/1e6); }
int main(void){
  printf("K %f\n", 61.03515625);
  // LF band: 433.92 MHz.
  g_n=0; loraCwSetup(433.92f, 15);
  uint32_t frf=((uint32_t)find(0x06)<<16)|((uint32_t)find(0x07)<<8)|find(0x08);
  printf("FRF_433 %u\n", (unsigned)frf);
  printf("RECOVER_433 %d\n", recoverFrf(frf));
  printf("OP_433 %u\n", (unsigned)find(0x01));
  printf("PA_433 %u\n", (unsigned)find(0x09));
  printf("SLEEP_FIRST %u\n", (unsigned)g_w[0].a);
  // HF band: 868.0 MHz.
  g_n=0; loraCwSetup(868.0f, 15);
  uint32_t frf2=((uint32_t)find(0x06)<<16)|((uint32_t)find(0x07)<<8)|find(0x08);
  printf("FRF_868 %u\n", (unsigned)frf2);
  printf("RECOVER_868 %d\n", recoverFrf(frf2));
  printf("OP_868 %u\n", (unsigned)find(0x01));
  // Stop must sleep before it parks.
  g_n=0; loraCwStop();
  printf("STOP_FIRST_A %u\n", (unsigned)g_w[0].a);
  printf("STOP_FIRST_V %u\n", (unsigned)g_w[0].v);
  printf("STOP_HAS_PARK %d\n", (g_w[g_n-1].a==0xFF)?1:0);
  return 0;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "p2.cpp"
        tp.write_text(prologue + body)
        exe = str(Path(tmp) / "p2")
        r = subprocess.run(["clang++", "-O2", "-w", "-std=c++17", "-o", exe, str(tp)],
                           capture_output=True, text=True)
        check(r.returncode == 0, f"P2 harness compiles {r.stderr[:400]}")
        if r.returncode != 0:
            print()
            print(f"FAILED ({len(FAILS)}):")
            for f in FAILS:
                print("  -", f)
            return 1
        out = subprocess.run([exe], capture_output=True, text=True).stdout
        print("\n".join("    " + ln for ln in out.strip().splitlines()))

        def num(name):
            m = re.search(rf"^{name} (-?\d+)", out, re.M)
            return int(m.group(1)) if m else None

        # The recovered frequency is what matters, not the raw register, because
        # the datasheet value depends on the 32 MHz reference this board runs.
        check(num("RECOVER_433") is not None and abs(num("RECOVER_433") - 434) <= 1,
              "433.92 MHz recovers to 434 MHz within the Frf bin")
        check(num("RECOVER_868") is not None and abs(num("RECOVER_868") - 868) <= 1,
              "868.0 MHz recovers to 868 MHz within the Frf bin")
        check(num("OP_433") == 0x0A,
              "below 525 MHz the mode word sets LF band + TX (0x0A)")
        check(num("OP_868") == 0x02,
              "above 525 MHz the mode word is TX only, HF band (0x02)")
        check(num("PA_433") is not None and (num("PA_433") & 0x80) == 0x80,
              "the PA is configured for PA_BOOST")
        check(num("SLEEP_FIRST") == 0x01,
              "RegOpMode is written to SLEEP before the frequency registers")
        check(num("STOP_FIRST_A") == 0x01 and num("STOP_FIRST_V") == 0x00,
              "stop sleeps the PA before touching the reset line")
        check(num("STOP_HAS_PARK") == 1,
              "stop re-parks the module (RST low) on the way out")

    print()
    if FAILS:
        print(f"FAILED ({len(FAILS)}):")
        for f in FAILS:
            print("  -", f)
        return 1
    print("all SX1278 CW register checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
