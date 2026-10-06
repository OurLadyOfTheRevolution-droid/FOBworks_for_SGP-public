#!/usr/bin/env python3
"""Host harness for the P5 parked RollJam IDS.

VehicleSec 2025 names Relay and RollJam as the unsolved pair in the field and
asks for defences a parked sensor can actually run. This detector is that: the
idle noise floor, the shape of the press pair, and the score they add up to.
None of it needs a key, a decoder guess, or a paired BCM.

The assertions run against the SHIPPED code. The detector's ring, baseline and
scoring are extracted from the firmware source and linked with stubs for the
three things the sketch provides at runtime (String, addLog, millis), so what is
exercised is the body that ships, not a re-implementation:

  1. The floor baseline is a rolling mean, and only a lift that HOLDS reads as a
     jammer. A one-off spike against a quiet baseline does not.
  2. A press pair needs the same fob, the same button, and consecutive counters
     inside the grab window. Same fob across a button change is two presses.
  3. The score is the conjunction the note describes: jam+pair=3, either alone
     scores lower, neither scores nothing and is not recorded.
  4. The JSON snapshot renders the pair so an operator can see both hops.
"""
import json
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
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    return None


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the pieces exist in the shipping source ===")
    for fn in ("p5FeedFloor", "p5OnKeeLoq", "p5IdsJson", "p5IdsReset"):
        check(extract_fn(src, fn) is not None, f"{fn} extracted")
    check('op=="p5_ids"' in src, "serial p5_ids command wired")
    check('protectedRoute("/api/p5_ids"' in src, "HTTP /api/p5_ids route wired")
    check('#define P5_IDS_JAM_DB 6' in src, "jam threshold is 6 dB")
    check('#define P5_PRESS_WIN_MS 1200UL' in src, "grab window is 1.2 s")
    check('doc["rolljam_ids"]' in src, "score lands on the KeeLoq decode")
    check('p5OnKeeLoq(f.sn,f.hop,f.rawCtr,f.btn,p5IdleFloorDelta)' in src,
          "commit path feeds the detector the parsed frame")
    check("p5IdleFloorDelta = p5FeedFloor(noiseMax);" in src,
          "capture path feeds the detector the idle floor")
    check('{"cmd":"p5_ids"}' in src, "command documented in the serial header")

    print("\n=== floor baseline + press pair against the shipped bodies ===")
    # Constants are hoisted near ClaimRec, the detector body lives near N12; the
    # harness needs both plus the runtime stubs.
    defs = re.search(r"#define P5_IDS_EV_MAX\s+16.*?#define P5_FLOOR_DECAY_MS\s+30000UL",
                     src, re.S)
    check(defs is not None, "P5 constants sliced from source")
    a = src.index("// \u2500\u2500\u2500 P5: parked RollJam IDS")
    b = src.index("// \u2500\u2500\u2500 N11: UHF-press")
    region = src[a:b]
    check("p5OnKeeLoq" in region and "p5IdsJson" in region,
          "detector region sliced whole")

    prologue = r"""
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
class String {
public:
  std::string v;
  String(){}
  String(const char* s):v(s?s:""){}
  String(int x){char b[32];snprintf(b,32,"%d",x);v=b;}
  String(uint32_t x){char b[32];snprintf(b,32,"%lu",(unsigned long)x);v=b;}
  String& operator+=(const String& o){v+=o.v;return *this;}
  String& operator+=(char c){v+=c;return *this;}
  String operator+(const String& o) const {String r=*this;r.v+=o.v;return r;}
  const char* c_str() const {return v.c_str();}
};
static void addLog(const String&){}
static String operator+(const char* a, const String& b){ return String(a)+b; }
static uint32_t g_ms=0;
static uint32_t millis(){ return g_ms; }
""" + (defs.group(0) if defs else "") + "\n" + region + "\n"

    body = r"""
int main(void){
  p5IdsReset();
  // 1) A quiet band seeds and holds its baseline: delta 0 thereafter.
  int lastD = 0;
  for(int i=0;i<20;i++){ g_ms += 1000; lastD = p5FeedFloor(-95); }
  printf("QUIET_D %d\n", lastD);
  printf("QUIET_BASE %d\n", (int)p5FloorBase);

  // 2) One spike against the quiet baseline reads loud, but the baseline does
  //    not follow it: a spike is not a plateau.
  int spikeD = p5FeedFloor(-60);
  printf("SPIKE_D %d\n", spikeD);
  printf("SPIKE_BASE %d\n", (int)p5FloorBase);

  // 3) A HELD lift: the band sits at -88 while time passes in 5 s steps. The
  //    baseline may creep up at most 1 dB per 30 s, so over a grab-length hold
  //    the lift stays well above the threshold. This is the jammer signature.
  int heldD = 0; int heldBase = 0;
  for(int i=0;i<10;i++){ g_ms += 5000; heldD = p5FeedFloor(-88); }
  heldBase = (int)p5FloorBase;
  printf("HELD_D %d\n", heldD);
  printf("HELD_BASE %d\n", heldBase);

  // 3b) A short spike with no accumulated credit does not move the baseline.
  p5IdsReset();
  g_ms += 1000000;
  for(int i=0;i<4;i++){ g_ms += 1000; p5FeedFloor(-95); }
  g_ms += 2000;                       // 2 s of a spurious loud reading
  int briefD = p5FeedFloor(-70);
  printf("BRIEF_D %d\n", briefD);
  printf("BRIEF_BASE %d\n", (int)p5FloorBase);

  // 3b) A spike that DECAYS (band returns quiet) resets the baseline at once,
  //     so a passing car does not leave a permanent offset.
  g_ms += 1000;
  int decayD = p5FeedFloor(-95);
  printf("DECAY_D %d\n", decayD);
  printf("DECAY_BASE %d\n", (int)p5FloorBase);

  // 4) Pair detection: same fob, same button, counters stepping by 1 inside 1.2 s.
  p5HaveLast = false;
  p5IdsReset();
  g_ms = 100000;
  uint8_t s1 = p5OnKeeLoq(0x0A1B2CE7UL, 0x11223344UL, 0x0100, 0x3, 0);
  printf("PAIR_EVN1 %u\n", (unsigned)p5EvN);
  g_ms = 100400;   // 400 ms later — inside the grab window
  uint8_t s2 = p5OnKeeLoq(0x0A1B2CE7UL, 0x55667788UL, 0x0101, 0x3, 0);
  printf("PAIR_S1 %u\n", (unsigned)s1);
  printf("PAIR_S2 %u\n", (unsigned)s2);
  printf("PAIR_EVN2 %u\n", (unsigned)p5EvN);
  printf("PAIR_FLAG %d\n", (int)p5Ev[p5EvN-1].pair);
  printf("PAIR_H1 %08lX\n", (unsigned long)p5Ev[p5EvN-1].hop1);
  printf("PAIR_H2 %08lX\n", (unsigned long)p5Ev[p5EvN-1].hop2);

  // 5) Jam AND pair together must score 3. Build the held lift first, then use
  //    the delta it reports at the moment the frames land. The hold must last
  //    longer than the jam threshold needs; 5 s steps for 30 s is a sustained
  //    lift that has only just begun to creep the baseline.
  p5IdsReset(); p5HaveLast = false;
  g_ms = 2000000;
  for(int i=0;i<4;i++){ g_ms += 5000; p5FeedFloor(-95); }
  int lift = 0;
  for(int i=0;i<6;i++){ g_ms += 5000; lift = p5FeedFloor(-88); }
  g_ms += 100;
  p5OnKeeLoq(0x0A1B2CE7UL, 0x11223344UL, 0x0200, 0x3, lift);
  g_ms += 300;
  uint8_t s3 = p5OnKeeLoq(0x0A1B2CE7UL, 0x55667788UL, 0x0201, 0x3, lift);
  printf("JAMPAIR_REPORTED_D %d\n", lift);
  printf("JAMPAIR_S %u\n", (unsigned)s3);

  // 6) Different button: not a pair, so a raised floor alone scores 2.
  p5IdsReset(); p5HaveLast = false;
  g_ms = 300000;
  p5OnKeeLoq(0x0A1B2CE7UL, 0x11223344UL, 0x0300, 0x3, lift);
  g_ms += 100;
  uint8_t s4 = p5OnKeeLoq(0x0A1B2CE7UL, 0x55667788UL, 0x0301, 0x5, lift);
  printf("BTN_S %u\n", (unsigned)s4);
  printf("BTN_PAIR %d\n", (int)p5Ev[p5EvN-1].pair);

  // 7) Counter step of 2 is two transmissions, not a pair.
  p5IdsReset(); p5HaveLast = false;
  g_ms = 400000;
  p5OnKeeLoq(0x0A1B2CE7UL, 0x11223344UL, 0x0400, 0x3, 0);
  g_ms += 200;
  uint8_t s5 = p5OnKeeLoq(0x0A1B2CE7UL, 0x55667788UL, 0x0402, 0x3, 0);
  printf("STEP_S %u\n", (unsigned)s5);
  printf("STEP_EVN %u\n", (unsigned)p5EvN);

  // 8) Outside the 1.2 s window: two ordinary presses.
  p5IdsReset(); p5HaveLast = false;
  g_ms = 500000;
  p5OnKeeLoq(0x0A1B2CE7UL, 0x11223344UL, 0x0500, 0x3, 0);
  g_ms += 2000;   // 2 s later
  uint8_t s6 = p5OnKeeLoq(0x0A1B2CE7UL, 0x55667788UL, 0x0501, 0x3, 0);
  printf("LATE_S %u\n", (unsigned)s6);

  // 9) Different fob entirely: not a pair.
  p5IdsReset(); p5HaveLast = false;
  g_ms = 800000;
  p5OnKeeLoq(0x11111111UL, 0x11223344UL, 0x0600, 0x3, 0);
  g_ms += 100;
  uint8_t s7 = p5OnKeeLoq(0x22222222UL, 0x55667788UL, 0x0601, 0x3, 0);
  printf("FOB_S %u\n", (unsigned)s7);

  // 10) A plain quiet press pair is recorded once (score 1), and the JSON renders.
  p5IdsReset(); p5HaveLast = false;
  g_ms = 900000;
  p5OnKeeLoq(0x0A1B2CE7UL, 0xDEADBEEFUL, 0x0700, 0x3, 0);
  g_ms += 100;
  p5OnKeeLoq(0x0A1B2CE7UL, 0xCAFEBABEUL, 0x0701, 0x3, 0);
  String j = p5IdsJson();
  printf("JSON %s\n", j.c_str());
  printf("JSON_EVENTS %u\n", (unsigned)p5EvCount);

  return 0;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "p5.cpp"
        tp.write_text(prologue + body)
        exe = str(Path(tmp) / "p5")
        r = subprocess.run(["clang++", "-O1", "-std=c++17", "-o", exe, str(tp)],
                           capture_output=True, text=True)
        check(r.returncode == 0, f"P5 harness compiles {r.stderr[:300]}")
        if r.returncode != 0:
            print()
            print(f"FAILED ({len(FAILS)}):")
            for f in FAILS:
                print("  -", f)
            return 1
        run = subprocess.run([exe], capture_output=True, text=True)
        out = run.stdout
        print("\n".join("    " + ln for ln in out.strip().splitlines()))

        def num(name):
            m = re.search(rf"^{name} (-?\d+)", out, re.M)
            return int(m.group(1)) if m else None

        check(num("QUIET_D") == 0, "a quiet band holds a zero delta")
        check(num("QUIET_BASE") == -95, "the baseline tracks the quiet floor")
        check(num("SPIKE_D") is not None and num("SPIKE_D") >= 6,
              "a one-off spike reads loud against the baseline")
        check(num("SPIKE_D") == 35, "the spike delta matches the raw lift")
        check(num("SPIKE_BASE") == -95,
              "a spike does not drag the baseline up with it")
        check(num("HELD_BASE") is not None and num("HELD_BASE") > -95,
              "a sustained lift does creep the baseline upward")
        check(num("HELD_D") is not None and num("HELD_D") >= 6,
              "but the sustained lift still clears the jam threshold")
        check(num("BRIEF_BASE") == -95 and num("BRIEF_D") >= 6,
              "a brief spike reads loud without moving the baseline")
        check(num("DECAY_D") == 0 and num("DECAY_BASE") == -95,
              "a decaying spike resets the baseline immediately")

        check(num("PAIR_S1") == 0 and num("PAIR_EVN1") == 0,
              "a lone first frame scores nothing and is not recorded")
        check(num("PAIR_S2") == 1 and num("PAIR_EVN2") == 1,
              "the second frame inside the window pairs and is recorded once")
        check(num("PAIR_FLAG") == 1, "the event records the pair")
        check("PAIR_H1 11223344" in out and "PAIR_H2 55667788" in out,
              "the pair keeps both hops, first and second")

        check(num("JAMPAIR_REPORTED_D") is not None and
              num("JAMPAIR_REPORTED_D") >= 6, "the held lift feeds the detector")
        check(num("JAMPAIR_S") == 3, "jam + pair is the top score")

        check(num("STEP_S") == 0 and num("STEP_EVN") == 0,
              "a counter step other than +/-1 is not a pair and is not recorded")
        check(num("BTN_S") == 2 and num("BTN_PAIR") == 0,
              "a button change is not a pair; a raised floor alone scores 2")
        check(num("LATE_S") == 0, "presses outside the window are not a grab")
        check(num("FOB_S") == 0, "two different fobs are not a pair")

        m = re.search(r"^JSON (\{.*\})$", out, re.M)
        check(m is not None, "the snapshot renders JSON")
        if m:
            d = json.loads(m.group(1))
            check(d.get("floor_base") is not None and "floor_db" in d,
                  "the snapshot reports the floor and its baseline")
            suspects = d.get("suspects", [])
            check(len(suspects) >= 1, "the plain pair is recorded as a suspect")
            if suspects:
                s = suspects[-1]
                check(s.get("pair") is True and s.get("score") == 1,
                      "the plain pair renders with its score")
                check(s.get("hop1") == "0xDEADBEEF" and
                      s.get("hop2") == "0xCAFEBABE",
                      "both hops render so an operator can compare them")
        check(num("JSON_EVENTS") is not None and num("JSON_EVENTS") >= 1,
              "the event counter advances")

    print()
    if FAILS:
        print(f"FAILED ({len(FAILS)}):")
        for f in FAILS:
            print("  -", f)
        return 1
    print("all parked RollJam IDS checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
