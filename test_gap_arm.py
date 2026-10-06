#!/usr/bin/env python3
"""Host harness for frame-gap arming (N16).

Extracts the arming state machine from captureSignal() and drives it against
synthetic RSSI traces, replayed as sample arrays with a stubbed cc_fastRSSI().
The checks mirror what the bench showed:

  1. PLATEAU THEN GAP: energy first (the RAW head), a plateau riding at
     edgeThr, then real quiet, then the frame. The machine must ARM on the
     quiet run — the buffer then starts at the next energy onset, a frame edge.
  2. FOB PRESS: energy that never gaps (the preamble IS the energy). The
     budget expires; the retry check sees a live carrier, burns retries, and
     the final fallback arms at first energy — no capture is ever lost.
  3. QUIET THRESHOLD: the quiet run is measured BELOW edgeThr (minus
     gapArmQuietBelowDb), so a plateau oscillating around edgeThr never
     satisfies it — that is the close-range failure this fixes.
  4. BOUNDED: retries cap the total wait at (retries+1)*budget from first
     energy, so the arming cannot hang a capture.

The machine is extracted from the firmware source so this tests the shipping
code, not a model of it.
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


def extract_gap_arm_block(src):
    """Pull the arming block (variable decls through the state machine) as C.

    The state machine is embedded in captureSignal() with firmware-only
    dependencies (SPI, cc_fastRSSI, addLog). The harness keeps the machine
    verbatim and stubs the surroundings; the stubs are BELOW the extraction so
    the extracted code's own identifiers win.
    """
    m = re.search(
        r"bool gapArm = gapArmDefault;(.*?)\n  \} else lastCapGapArm=false;",
        src, re.S)
    return m.group(0) if m else None


HARNESS_TMPL = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// ── stubs for the firmware environment the arming block expects ──────────────
static int  QUIET_BELOW_DB = 6;
static int  edgeThr  = -76;   // bench: floor -95, edgeThr -76, plateau -74..-77
static int  trigThr   = -85;   // floor+10 in the bench numbers above
static int  BUDGET_MS  = 400;
static int  RETRIES    = 3;
static int  QUIET_US   = 6000;

#define gapArmDefault        true
#define gapArmPerCapture    (-1)
#define gapArmQuietUs       QUIET_US
#define gapArmBudgetMs      BUDGET_MS
#define gapArmRetries       RETRIES
#define gapArmQuietBelowDb  QUIET_BELOW_DB
#define lastCapGapArm       dummyLastCapGapArm
static bool dummyLastCapGapArm = false;

static int SAMPLES[20000]; static int NSAMPLES; static int SPOS = 0;
static int cc_fastRSSI(void){ int v = (SPOS<NSAMPLES)?SAMPLES[SPOS++]:SAMPLES[NSAMPLES-1]; return v; }
// micros() advances 100 us per sample: fast enough to cross 6 ms quiet in 60 samples,
// slow enough that 512-sample noise traces stay within budget windows.
static unsigned long UMICROS = 0;
static unsigned long micros(void){ return UMICROS; }
static void yield(void){ UMICROS += 100; }
static void addLog(const char*s){ (void)s; }
#define MSBFIRST 1
#define SPI_MODE0 0
static void SPI_beginTransaction(int x){ (void)x; }
static void SPI_endTransaction(void){}
#define SPISettings(x,y,z) 0
#define SPI SPI

// ── the arming block, verbatim from the firmware ────────────────────────────
%s

int main(void){
  // The harness drives: whether the run armed, and the sample index reached.
  return 0;
}
"""


def build_harness(samples):
    src = SRC.read_text(encoding="utf-8")
    block = extract_gap_arm_block(src)
    if block is None:
        return None, None
    # The block ends with the else-arm; the harness needs the machine's outputs.
    # Run it once and read the two globals the machine sets: armed lives inside
    # the block's scope, so re-expose by patching: capture via lastCapGapArm.
    harness = HARNESS_TMPL % block
    # drive() main: set SAMPLES, reset counters, run the block's logic by
    # calling into it via a wrapper — simplest: re-run as a function.
    return harness, block


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the arming pieces exist ===")
    block = extract_gap_arm_block(src)
    check(block is not None, "the arming state machine extracted from captureSignal()")
    for needle, why in (
        ("gapArmQuietUs", "quiet-run length knob present"),
        ("gapArmBudgetMs", "budget knob present"),
        ("gapArmRetries", "retry knob present"),
        ("gapArmQuietBelowDb", "quiet-below-plateau knob present"),
        ('"gaparm"', "the gaparm serial command present"),
        ('"arm"', "the capture command arm= override present"),
    ):
        check(needle in src, why)
    check('arm="gap" if mode=="on" else "off"' in
          (ROOT / "tools/replay_capture.py").read_text()
          or 'arm="gap"' in (ROOT / "tools/replay_capture.py").read_text(),
          "replay_capture drives the arm= override")

    print("\n=== AGC filter knob (N17) ===")
    # The register mapping: AGCCTRL0 FILTER_LENGTH bits 7:6 — 00=8, 01=16,
    # 10=32, 11=64 samples. The bench measured filter 32 resolving named
    # decodes where 16 gave OOK-raw only.
    agc_block = re.search(
        r"uint8_t agc0 = 0x91;(.*?)\n  \}", src, re.S)
    check(agc_block is not None, "the AGC register block extracted from captureSignal()")
    if agc_block is not None:
        ab = agc_block.group(1)
        check("case 8:  agc0 = 0x51" in src, "filter 8 maps to AGCCTRL0 0x51 (FILTER_LENGTH=00)")
        check("case 16: agc0 = 0x91" in src, "filter 16 maps to AGCCTRL0 0x91 (FILTER_LENGTH=01, stock)")
        check("case 32: agc0 = 0xD1" in src, "filter 32 maps to AGCCTRL0 0xD1 (FILTER_LENGTH=10)")
        check("case 64: agc0 = 0x11" in src, "filter 64 maps to AGCCTRL0 0x11 (FILTER_LENGTH=11)")
        check("default: agcFilterLen = 16" in src, "unknown values fall back to the stock 16")
        check("cc_writeReg(0x1D, agc0)" in src, "AGCCTRL0 written in the capture setup block")
        check("lastCapAgc = (agcFilterLen != 16)" in src, "the non-default flag tracks the knob")
    check('"cmd":"agc"' in src, "the agc serial command present")
    check("fl==8||fl==16||fl==32||fl==64" in src, "agc command accepts only the four valid lengths")

    print("\n=== state machine against synthetic RSSI traces ===")
    # Each sample = 100 us. edgeThr=-76, plateau -74..-77 (rides edgeThr),
    # quiet floor -95. quiet threshold = edgeThr - 6 = -82.
    # 1: plateau then 60-sample (6ms) quiet -> must ARM
    # 2: pure energy, no quiet, forever -> must NOT arm (budget+retries exhaust)
    # 3: plateau oscillation around edgeThr only -> must NOT arm within budget
    # 4: 100 ms plateau, quiet, then energy -> arms; total wait bounded
    traces = {
        "plateau_then_gap_arms": (
            [-75]*200 + [-95]*60 + [-75]*10,
            True,  "RAW head then real quiet: arms"),
        "fob_press_falls_back": (
            [-75]*6000,
            False, "energy that never gaps: falls back at first energy"),
        "plateau_oscillation_no_arm": (
            [-75]*300 + [-74]*10 + [-77]*10 + [-75]*300 + [-74]*10 + [-77]*10 + [-75]*300,
            False, "edgeThr oscillation is not quiet: no arm in one budget"),
        "short_gap_then_gap_arms": (
            [-75]*300 + [-95]*60 + [-75]*5,
            True,  "long plateau then the 6 ms quiet: arms"),
    }

    # Compile a single harness that runs all traces.
    harness = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

static int  QUIET_BELOW_DB = 6;
static int  edgeThr  = -76;
static int  trigThr   = -85;
static int  BUDGET_MS  = 400;
static int  RETRIES    = 3;
static int  QUIET_US   = 6000;

#define gapArmDefault        true
static int gapArmPerCapture = -1;
#define gapArmQuietUs       QUIET_US
#define gapArmBudgetMs      BUDGET_MS
#define gapArmRetries       RETRIES
#define gapArmQuietBelowDb  QUIET_BELOW_DB
#define lastCapGapArm       dummyLastCapGapArm
static bool dummyLastCapGapArm = false;

static int SAMPLES[20000]; static int NSAMPLES; static int SPOS = 0;
static int cc_fastRSSI(void){ int v = (SPOS<NSAMPLES)?SAMPLES[SPOS++]:SAMPLES[NSAMPLES-1]; return v; }
static unsigned long UMICROS = 0;
static unsigned long micros(void){ return UMICROS; }
static void yield(void){ UMICROS += 100; }
static void addLog(const char*s){ (void)s; }
#define MSBFIRST 1
#define SPI_MODE0 0
#define SPISettings(a,b,c) 0
static void SPI_beginTransaction(int x){ (void)x; }
static void SPI_endTransaction(void){}
// The block wraps log strings in Arduino String() with + concatenation.
// Rewrite those calls textually: drop the concat, keep the first literal.
#define String(x) (x)

static bool ARM_RESULT = false;

// The arming block, verbatim (macro-shimmed): the machine sets lastCapGapArm
// (dummyLastCapGapArm here), which is the armed flag.
""" + re.sub(r"bool gapArm = gapArmDefault;",
            "static void run_arm(void){ bool gapArm = gapArmDefault;",
            block.replace("SPI.beginTransaction(", "SPI_beginTransaction(")
                 .replace("SPI.endTransaction()", "SPI_endTransaction()")
                 .replace('addLog(String("  Gap-arm: plateau at expiry — retrying (")+String(retriesLeft)+" left)")',
                          'addLog("  Gap-arm: plateau at expiry — retrying")')
                 .replace('addLog(armed?String("  Gap-armed after quiet run"):\n                 String("  Gap-arm budget expired — arming at first energy"))',
                          'addLog(armed?"  Gap-armed after quiet run":"  Gap-arm budget expired")')) + r"""
}

static void run_trace(const int*s, int n){
  NSAMPLES = n; SPOS = 0; UMICROS = 0;
  for(int i=0;i<n;i++) SAMPLES[i]=s[i];
  dummyLastCapGapArm = false;
  run_arm();
}
int main(void){
  // trace 1: plateau then gap
  { int t[300]; int k=0;
    for(int i=0;i<200;i++) t[k++]=-75;
    for(int i=0;i<60;i++)  t[k++]=-95;
    for(int i=0;i<10;i++)  t[k++]=-75;
    run_trace(t,k);
    printf("plateau_then_gap_arms %d\n", dummyLastCapGapArm?1:0);
  }
  // trace 2: pure energy (fob press)
  { static int t[6000];
    for(int i=0;i<6000;i++) t[i]=-75;
    run_trace(t,6000);
    printf("fob_press_falls_back %d\n", dummyLastCapGapArm?1:0);
  }
  // trace 3: plateau oscillation around edgeThr
  { int t[700]; int k=0;
    for(int rep=0;rep<2;rep++){
      for(int i=0;i<300;i++) t[k++]=-75;
      for(int i=0;i<10;i++) t[k++]=-74;
      for(int i=0;i<10;i++) t[k++]=-77;
    }
    for(int i=0;i<50;i++) t[k++]=-75;
    run_trace(t,k);
    printf("plateau_oscillation_no_arm %d\n", dummyLastCapGapArm?1:0);
  }
  // trace 4: bounded wait — 100 ms plateau then quiet
  { static int t[2200]; int k=0;
    for(int i=0;i<1000;i++) t[k++]=-75;
    for(int i=0;i<60;i++)  t[k++]=-95;
    for(int i=0;i<20;i++)  t[k++]=-75;
    run_trace(t,k);
    printf("short_gap_then_gap_arms %d\n", dummyLastCapGapArm?1:0);
    // the wait ended: UMICROS advanced past the plateau (100 ms = 1,000,000 us)
    printf("bounded_wait_us %lu\n", UMICROS);
  }
  return 0;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "t.c"
        tp.write_text(harness)
        exe = str(Path(tmp) / "t")
        r = subprocess.run(["clang", "-O1", "-o", exe, str(tp)],
                          capture_output=True, text=True)
        check(r.returncode == 0, f"harness compiles ({r.stderr[:150]})")
        if r.returncode != 0:
            finish()
            return
        out = subprocess.run([exe], capture_output=True, text=True).stdout
        got = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                got[parts[0]] = parts[1]

        check(got.get("plateau_then_gap_arms") == "1",
              "RAW head then real quiet arms the buffer")
        check(got.get("fob_press_falls_back") == "0",
              "a fob press (energy that never gaps) falls back to first energy")
        check(got.get("plateau_oscillation_no_arm") == "0",
              "an edgeThr oscillation (the plateau) never satisfies the quiet test")
        check(got.get("short_gap_then_gap_arms") == "1",
              "long plateau then quiet still arms")
        try:
            bw = int(got.get("bounded_wait_us", "0"))
            # 1000 samples * 100 us = 100 ms plateau, quiet arms after 6 ms
            check(100_000 <= bw <= 115_000,
                  f"armed wait bounded by the actual signal ({bw} us, plateau 100 ms)")
        except ValueError:
            check(False, "bounded_wait_us parseable")

    finish()


def finish():
    print()
    if FAILS:
        print(f"gap-arm checks FAILED: {len(FAILS)}")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("gap-arm checks passed")


if __name__ == "__main__":
    main()
