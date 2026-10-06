#!/usr/bin/env python3
"""Host harness for the P3 resync curve profiler.

resync_probe answers one question — does a forward ramp take. The curve answers
the three the CVEs are named for: which forward offsets a receiver accepts, the
RollBack backward step (CVE-2022-37418), and the Rolling-PWN replay
(CVE-2021-46145). This suite drives the shipped plan builder, the shipped listen
logic and the shipped renderer, with stubs for the three runtime pieces the
sketch provides (String, millis, the radio).

Because the radio cannot be present on the host, the harness models it as a
threshold the test sets: the reply-hits counter is fed readings either side of
the idle floor + RC_REPLY_DB, and the assertions check that the listen logic
turns those readings into the right accept/unknown decision. What is under test
is the decision rule, which is the part that would otherwise be a silent bug.

  1. The plan is the curve: a forward ramp, then backward steps, then a replay
     of an already-seen code — in that order, bounded by RC_MAX_PROBES.
  2. A sustained reply above floor+RC_REPLY_DB for RC_REPLY_HITS samples reads
     as a reply; a level below the threshold, or too few samples, does not.
  3. A hand mark overrides the radio; "auto" clears it back.
  4. The renderer separates accept / reject / unknown, and "unknown" is not
     quietly folded into "reject" — that distinction is the finding.
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
    in_str = None
    esc = False
    # Brace-match while skipping string/char literals: the renderer builds JSON
    # by concatenating literal "{" and "}" into Strings, and a naive counter
    # would treat those as code braces.
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
    for fn in ("rcArm", "rcTick", "rcMark", "rcStatusJson", "rcReset",
               "rcKindName", "rcOutcome", "rcIdleFloor"):
        check(extract_fn(src, fn) is not None, f"{fn} extracted")
    check('op=="resync_curve"' in src, "serial resync_curve command wired")
    check('op=="resync_mark"' in src, "serial resync_mark command wired")
    check('op=="resync_curve_status"' in src, "serial status command wired")
    check('protectedRoute("/api/resync_curve"' in src, "HTTP route wired")
    check("rcTick(millis());" in src, "rcTick driven from loop()")
    check("#define RC_MAX_PROBES 24" in src, "probe budget is bounded")
    check("#define RC_REPLY_DB   8" in src, "reply threshold is 8 dB over floor")
    check("#define RC_REPLY_HITS 3" in src, "reply needs 3 samples, not a spike")
    check('{"cmd":"resync_curve","sn":N}' in src, "command documented in the header")

    print("\n=== plan + listen + renderer against the shipped bodies ===")
    hoist = re.search(r"// \u2500\u2500\u2500 Resync-curve probe record \(P3\).*?struct RcProbe \{[^}]*\};",
                      src, re.S)
    check(hoist is not None, "RcProbe hoisted above the prototype block")
    a = src.index("// \u2500\u2500\u2500 P3: resync curve profiler")
    b = src.index("//   +1  ctr[1] follows ctr[0]")
    region = src[a:b]
    check("rcArm" in region and "rcTick" in region and "rcStatusJson" in region,
          "curve region sliced whole")
    defs = re.search(r"#define RC_MAX_PROBES 24.*?#define RC_FWD_DEFAULT 8",
                     src, re.S)
    check(defs is not None, "RC constants sliced from source")

    # The listen logic reads the radio through cc_fastRSSI(); the harness stands
    # in a scripted value, and the test moves it across the threshold.
    prologue = r"""
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <cmath>
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
  bool operator==(const char* s) const { return v==(s?s:""); }
  bool operator!=(const char* s) const { return !(*this==s); }
  const char* c_str() const {return v.c_str();}
};
static String operator+(const char* a, const String& b){ return String(a)+b; }
static const int MSBFIRST=1, SPI_MODE0=0;
struct SPISettings { SPISettings(int=0,int=0,int=0){} };
struct SpiStub { void beginTransaction(SPISettings){} void endTransaction(){} };
static SpiStub SPI;
static void serialEmit(const String&){}
static uint32_t g_ms=0;
static uint32_t millis(){ return g_ms; }
static int g_rssi=-100;                 // what the scripted radio reports
static int g_listenSamples=0;           // samples taken inside a listen
static void delayMicroseconds(unsigned){}
static int cc_fastRSSI(){ if(g_listenSamples<200) g_listenSamples++; return g_rssi; }
// buildForProto/replayRaw are the transmit path; rcTick calls them, and the
// harness counts the transmits so the plan can be verified.
static int g_txCount=0;
static uint16_t g_txBuf[300]; static int g_txLen[64];
static int buildForProto(const String&, uint32_t, uint32_t, uint16_t, uint8_t,
                         uint16_t* b, int){ b[0]=1; b[1]=2; return 2; }
static bool replayRaw(float, const uint16_t*, int nl, int, bool){ (void)nl; return true; }
static bool bruteBusy(){ return false; }
""" + (hoist.group(0) if hoist else "") + "\n" + (defs.group(0) if defs else "") + "\n" + region + "\n"

    body = r"""
static void note(const char*);   // no serialEmit on the host
static void listen_n(int n, int rssi){
  // Drive rcTick through a listen: transmit, then feed n in-band samples.
  g_ms += 1000;                 // past any gap
  rcTick(g_ms);                 // this transmits and opens the listen
  for(int i=0;i<n;i++){
    g_ms += 10;                 // inside RC_LISTEN_MS (60)
    rcTick(g_ms);
  }
  g_ms += 200;                  // past the listen window: closes and records
  rcTick(g_ms);
}
int main(void){
  // 1) The plan: forward ramp n=6, then 4 backward steps, then a replay.
  rcArm(433.92f, String("KeeLoq"), 0x0A1B2CE7UL, 1000, 360, 3, 6);
  printf("PLAN_N %d\n", rcN);
  printf("PLAN_KIND0 %s\n", rcKindName(rcPlan[0].kind));
  printf("PLAN_OFF0 %d\n", (int)rcPlan[0].off);
  printf("PLAN_OFF5 %d\n", (int)rcPlan[5].off);
  printf("PLAN_KIND6 %s\n", rcKindName(rcPlan[6].kind));
  printf("PLAN_OFF6 %d\n", (int)rcPlan[6].off);
  printf("PLAN_KIND10 %s\n", rcKindName(rcPlan[10].kind));
  printf("PLAN_OFF10 %d\n", (int)rcPlan[10].off);
  if(rcN>0) printf("PLAN_ACTIVE %d\n", rcActive?1:0);

  // 2a) A strong sustained reply reads as accept.
  rcReset();
  rcArm(433.92f, String("KeeLoq"), 0x0A1B2CE7UL, 1000, 360, 3, 2);
  rcFloorDbm=-95;
  g_rssi=-95+RC_REPLY_DB+2;     // clears the threshold
  listen_n(6, g_rssi);
  printf("REPLY_ACCEPT %d\n", (int)rcOutcome(rcPlan[0])[0]=='a'?1:0);
  printf("REPLY_HITS0 %d\n", (int)rcPlan[0].reply);

  // 2b) A level below the threshold does NOT read as a reply.
  rcReset();
  rcArm(433.92f, String("KeeLoq"), 0x0A1B2CE7UL, 1000, 360, 3, 2);
  rcFloorDbm=-95;
  g_rssi=-95+RC_REPLY_DB-2;     // just under: noise, not a reply
  listen_n(6, g_rssi);
  printf("REPLY_WEAK %d\n", (int)rcPlan[0].reply);

  // 2c) Too few in-band samples (a spike) does NOT read as a reply.
  rcReset();
  rcArm(433.92f, String("KeeLoq"), 0x0A1B2CE7UL, 1000, 360, 3, 2);
  rcFloorDbm=-95;
  g_rssi=-95+RC_REPLY_DB+2;
  listen_n(RC_REPLY_HITS-1, g_rssi);   // fewer than the required run
  printf("REPLY_SPIKE %d\n", (int)rcPlan[0].reply);

  // 3) Hand mark overrides the radio, and "auto" clears it.
  rcReset();
  rcArm(433.92f, String("KeeLoq"), 0x0A1B2CE7UL, 1000, 360, 3, 1);
  rcFloorDbm=-95; g_rssi=-95; listen_n(2, g_rssi);   // records with no reply
  printf("MARK_BEFORE %s\n", rcOutcome(rcPlan[0]));
  rcMark(String("accept"));
  printf("MARK_AFTER %s\n", rcOutcome(rcPlan[0]));
  rcMark(String("reject"));
  printf("MARK_REJECT %s\n", rcOutcome(rcPlan[0]));
  rcMark(String("auto"));
  printf("MARK_AUTO %s\n", rcOutcome(rcPlan[0]));

  // 4) The renderer separates the three outcomes and does not collapse unknown.
  rcReset();
  rcArm(433.92f, String("KeeLoq"), 0x0A1B2CE7UL, 1000, 360, 3, 3);
  rcFloorDbm=-95;
  // probe 0: accept via RF
  g_rssi=-95+RC_REPLY_DB+2; listen_n(6, g_rssi);
  // probe 1: unknown (no reply)
  g_rssi=-95;               listen_n(2, g_rssi);
  // probe 2: completes with no reply, then hand-marked reject
  g_rssi=-95;               listen_n(2, g_rssi);
  rcMark(String("reject"));
  printf("RENDER_JSON %s\n", rcStatusJson(true).c_str());
  return 0;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp) / "p3.cpp"
        tp.write_text(prologue + body)
        exe = str(Path(tmp) / "p3")
        r = subprocess.run(["clang++", "-O2", "-w", "-std=c++17", "-o", exe, str(tp)],
                           capture_output=True, text=True)
        check(r.returncode == 0, f"P3 harness compiles {r.stderr[:400]}")
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

        def sval(name):
            m = re.search(rf"^{name} (\S+)", out, re.M)
            return m.group(1) if m else None

        check(num("PLAN_N") == 11, "plan is n forward + 4 back + 1 replay")
        check(sval("PLAN_KIND0") == "fwd" and num("PLAN_OFF0") == 1,
              "the ramp starts at offset +1")
        check(num("PLAN_OFF5") == 6, "the ramp ends at the requested offset")
        check(sval("PLAN_KIND6") == "back" and num("PLAN_OFF6") == -1,
              "backward steps start at -1 (RollBack axis)")
        check(sval("PLAN_KIND10") == "replay" and num("PLAN_OFF10") == 0,
              "the replay probe is last, at the base counter (Rolling-PWN axis)")
        check(num("PLAN_ACTIVE") == 1, "arming sets the active flag")

        check(num("REPLY_ACCEPT") == 1 and num("REPLY_HITS0") == 1,
              "a sustained reply above the floor reads as a reply")
        check(num("REPLY_WEAK") == 0,
              "a level under the threshold does not read as a reply")
        check(num("REPLY_SPIKE") == 0,
              "a run shorter than RC_REPLY_HITS is a spike, not a reply")

        check(sval("MARK_BEFORE") == "unknown", "with no reply and no mark: unknown")
        check(sval("MARK_AFTER") == "accept", "a hand accept overrides the radio")
        check(sval("MARK_REJECT") == "reject", "a hand reject overrides in turn")
        check(sval("MARK_AUTO") == "unknown", "'auto' clears back to the radio")

        m = re.search(r"^RENDER_JSON (\{.*\})$", out, re.M)
        check(m is not None, "the renderer produces JSON")
        if m:
            d = json.loads(m.group(1))
            check(d.get("accept") == 1 and d.get("reject") == 1 and
                  d.get("unknown") == 1,
                  "accept, reject and unknown are counted separately")
            probes = d.get("probes", [])
            check(len(probes) == 3, "one row per completed probe")
            kinds = [p.get("kind") for p in probes]
            check(kinds == ["fwd", "fwd", "fwd"],
                  "each row carries its axis")
            check(probes[0].get("outcome") == "accept" and
                  probes[1].get("outcome") == "unknown" and
                  probes[2].get("outcome") == "reject",
                  "unknown is not folded into reject")

    print()
    if FAILS:
        print(f"FAILED ({len(FAILS)}):")
        for f in FAILS:
            print("  -", f)
        return 1
    print("all resync curve profiler checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
