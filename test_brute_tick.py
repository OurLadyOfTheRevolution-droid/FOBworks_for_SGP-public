#!/usr/bin/env python3
"""§2.7 — the brute routes become tick-driven sequencers.

`/api/resync_probe` and `/api/fixed_bruteforce` used to run their whole transmit
loop inside the WebServer callback. At the maximum (1024 addresses x 20 ms) that
held the loop for ~20 s: the dashboard's status polling stalled and browsers
dropped the request. The rewrite moves both loops into a sequencer driven from
`loop()` — the same shape `rbTick()`/`rjTick()` already use.

This test extracts the shipped `resyncArm` / `fixedBruteArm` / `bruteTick` /
`bruteStatusJson` verbatim, compiles them against mocks for `buildForProto`,
`replayRaw`, `serialEmit` and `millis`, and asserts:

  · arming is single-flight — a second arm while one runs is refused
  · the counter / address sequence each frame is built with, in order
  · one transmit per tick, honouring the inter-frame delay
  · a progress event at every BRUTE_PROGRESS_STEP, and a done event at the end
  · a failed transmit flips ok:false in the done event
  · range/n bounds are enforced at arm time

Source-level assertions pin that the routes no longer block and that bruteTick
is called from loop().
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKETCH = HERE / "FOBworks_for_SGP.ino"
src = SKETCH.read_text(encoding="utf-8")
FAILS = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def block(marker: str) -> str:
    pos = 0
    while True:
        i = src.index(marker, pos)
        i = src.rindex("\n", 0, i) + 1
        j = src.index("{", i)
        semi = src.find(";", i, j)
        if semi < 0:
            break
        pos = semi + 1
    depth, k = 0, j
    while k < len(src):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    return src[i:k + 1] + "\n"


def route_body(path: str) -> str:
    i = src.index(f'protectedRoute("{path}"')
    j = src.index("});", i) + 3
    return src[i:j]


print("=== source: the routes no longer block ===")
for path in ("/api/resync_probe", "/api/fixed_bruteforce"):
    body = route_body(path)
    check("delay(" not in body and "replayRaw(" not in body and "for(" not in body,
          f"{path} has no blocking transmit loop")
    check("Arm(" in body, f"{path} arms a sequencer instead of looping")
    check('"queued\\":\\"' in body or "queued" in body,
          f"{path} replies that the work was queued")
check('protectedRoute("/api/brute_status"' in src, "/api/brute_status route registered")
loopm = src[src.index("void loop(){"):]
check("bruteTick(millis());" in loopm[:loopm.index("\n}\n")],
      "bruteTick() is called from loop()")
check('op=="brute_status"' in src, "serial brute_status command wired")
for d in ("#define BRUTE_MAX_N", "#define BRUTE_PROGRESS_STEP", "#define BRUTE_TICK_BUDGET_MS"):
    check(d in src, f"{d} defined")

print("\n=== behavioural: state machine extracted and compiled ===")

DECLS = src[src.index("#define BRUTE_MAX_N"):src.index("static void bruteTick(")]
TICK = block("static void bruteTick(")
STATUS = block("static String bruteStatusJson(")

HARNESS = r'''
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <string>
#include <vector>
using std::string;

#define HEX 16

struct StringStub {
  string s;
  StringStub(){}
  StringStub(const char* c):s(c){}
  StringStub(int v){ char b[24]; snprintf(b,sizeof b,"%d",v); s=b; }
  StringStub(unsigned v){ char b[24]; snprintf(b,sizeof b,"%u",v); s=b; }
  StringStub(long v){ char b[24]; snprintf(b,sizeof b,"%ld",v); s=b; }
  StringStub(unsigned long v){ char b[24]; snprintf(b,sizeof b,"%lu",v); s=b; }
  StringStub(unsigned long v,int base){ char b[32]; if(base==16) snprintf(b,sizeof b,"%lX",v); else snprintf(b,sizeof b,"%lu",v); s=b; }
  StringStub(float v){ char b[32]; snprintf(b,sizeof b,"%.3f",v); s=b; }
  StringStub(double v){ char b[32]; snprintf(b,sizeof b,"%.3f",v); s=b; }
  StringStub(float v,int d){ char b[32]; snprintf(b,sizeof b,"%.*f",d,(double)v); s=b; }
  StringStub& operator=(const char* c){ s=c; return *this; }
  StringStub& operator=(const string& o){ s=o; return *this; }
  StringStub operator+(const StringStub& o) const { StringStub r; r.s=s+o.s; return r; }
  StringStub operator+(const char* c) const { StringStub r; r.s=s+c; return r; }
  StringStub& operator+=(const char* c){ s+=c; return *this; }
  StringStub& operator+=(const StringStub& o){ s+=o.s; return *this; }
  unsigned length() const { return (unsigned)s.size(); }
  const char* c_str() const { return s.c_str(); }
};
static StringStub operator+(const char* a, const StringStub& b){ StringStub r; r.s=string(a)+b.s; return r; }
using String = StringStub;

// ── mocks ────────────────────────────────────────────────────────────────
static uint32_t g_now = 1000;
static uint32_t millis(){ return g_now; }

static std::vector<StringStub> g_emitted;
static void serialEmit(const StringStub& s){ g_emitted.push_back(s); }

// buildForProto records what each frame was built from; returns a nonzero len.
struct BuildCall { string proto; uint32_t sn; uint32_t ctr; };
static std::vector<BuildCall> g_builds;
static int g_buildLen = 10;
static int buildForProto(const String& proto, uint32_t sn, uint32_t newCtr,
                         uint16_t, uint8_t, uint16_t* out, int maxLen){
  g_builds.push_back({proto.s, sn, newCtr});
  for(int i=0;i<g_buildLen && i<maxLen;i++) out[i]=(uint16_t)(400+ (i%2)*400);
  return g_buildLen;
}

static int  g_txCount=0;
static bool g_txOk=true;
static bool replayRaw(float,uint16_t*,int,int,bool){ g_txCount++; return g_txOk; }

''' + DECLS + TICK + STATUS + r'''

static string lastOf(const char* needle){
  string r;
  for(auto& e : g_emitted) if(e.s.find(needle)!=string::npos) r=e.s;
  return r;
}
static bool anyOf(const char* needle){
  for(auto& e : g_emitted) if(e.s.find(needle)!=string::npos) return true;
  return false;
}

int main(){
  int fails=0;
  auto ck=[&](bool c,const char* m){ printf("  %s %s\n", c?"ok  ":"FAIL", m); if(!c) fails++; };

  // ── arm-time bounds ────────────────────────────────────────────────────
  ck(!resyncArm(315.0f,"KeeLoq",1,100,400,0,0),  "resync n=0 refused");
  ck(!resyncArm(315.0f,"KeeLoq",1,100,400,0,65), "resync n>64 refused");
  ck(!resyncArm(50.0f ,"KeeLoq",1,100,400,0,8),  "resync bad freq refused");
  ck(!fixedBruteArm(315.0f,"EV1527",0xAA,0,2,360),    "fixed range<4 refused");
  ck(!fixedBruteArm(315.0f,"EV1527",0xAA,0,2000,360), "fixed range>1024 refused");
  ck(!bruteBusy(), "still idle after the refused arms");

  // ── resync: sequence + cadence + progress + done ───────────────────────
  g_emitted.clear(); g_builds.clear();
  int N=51;                                   // > BRUTE_PROGRESS_STEP so a progress fires
  ck(resyncArm(315.0f,"KeeLoq",0x1234,1000,400,0,N), "resync armed (n=51)");
  ck(bruteBusy(), "busy after resync arm");
  ck(!resyncArm(315.0f,"KeeLoq",1,1,400,0,8), "second resync arm refused (single-flight)");
  ck(!fixedBruteArm(315.0f,"EV1527",0xAA,0,8,360), "fixed arm refused while resync runs");

  g_now=1000; bruteTick(g_now);
  ck(g_builds.size()==1, "one build per tick");
  ck(g_builds.size()==1 && g_builds[0].ctr==1000, "first frame built with ctr=1000");
  // 10 ms later: before the 30 ms resync delay, no second transmit.
  g_now=1010; bruteTick(g_now);
  ck(g_builds.size()==1, "tick before the inter-frame delay does nothing");
  g_now=1030; bruteTick(g_now);
  ck(g_builds.size()==2 && g_builds[1].ctr==1001, "next tick advances the counter to 1001");

  // Drive to completion.
  int guard=0;
  while(bruteBusy() && guard++ < 10000){ g_now += 30; bruteTick(g_now); }
  ck(!bruteBusy(), "resync completes and returns to idle");
  ck((int)g_builds.size()==N, "exactly N=51 frames were built");
  bool seqOk=true;
  for(int i=0;i<(int)g_builds.size();i++)
    if(g_builds[i].ctr != (uint32_t)(1000+i)) seqOk=false;
  ck(seqOk, "resync counter sequence is 1000..1050 in order");
  ck(anyOf("brute_progress"), "a brute_progress event was emitted");
  ck(anyOf("resync_done"), "a resync_done event was emitted");
  {
    string d=lastOf("resync_done");
    ck(d.find("\"ok\":true")!=string::npos, "done event reports ok:true");
    ck(d.find("\"sent\":51")!=string::npos, "done event reports sent=51");
  }

  // ── fixed: address sequence ────────────────────────────────────────────
  g_emitted.clear(); g_builds.clear(); g_txCount=0;
  int M=10;
  ck(fixedBruteArm(315.0f,"EV1527",0x1000,3,M,360), "fixed armed (range=10)");
  guard=0;
  while(bruteBusy() && guard++ < 10000){ g_now += 20; bruteTick(g_now); }
  ck(!bruteBusy(), "fixed completes and returns to idle");
  ck((int)g_builds.size()==M, "exactly range=10 frames were built");
  {
    bool sok=true;
    for(int i=0;i<(int)g_builds.size();i++){
      int32_t want=(int32_t)0x1000 + (i - M/2);
      if((int32_t)g_builds[i].sn != want) sok=false;
    }
    ck(sok, "fixed address sweep spans base-5..base+4 in order");
    ck(!g_builds.empty() && g_builds[0].ctr==0, "fixed frames carry counter 0");
  }
  ck(anyOf("fixed_bruteforce_done"), "a fixed_bruteforce_done event was emitted");

  // ── failed transmit flips ok:false ─────────────────────────────────────
  g_emitted.clear(); g_txOk=false;
  resyncArm(315.0f,"KeeLoq",1,100,400,0,4);
  guard=0;
  while(bruteBusy() && guard++ < 1000){ g_now += 30; bruteTick(g_now); }
  {
    string d=lastOf("resync_done");
    ck(d.find("\"ok\":false")!=string::npos, "a failed transmit reports ok:false");
    ck(d.find("\"sent\":0")!=string::npos, "nothing counted as sent when tx fails");
  }

  // ── status json ────────────────────────────────────────────────────────
  ck(bruteStatusJson().s.find("\"active\":false")!=string::npos, "status idle reports active:false");
  resyncArm(315.0f,"KeeLoq",7,5,400,0,8);
  bruteTick(g_now);
  {
    string st=bruteStatusJson().s;
    ck(st.find("\"active\":true")!=string::npos, "status active reports active:true");
    ck(st.find("\"kind\":\"resync\"")!=string::npos, "status names the kind");
    ck(st.find("\"of\":8")!=string::npos, "status carries the total");
  }

  printf("\n%s\n", fails? "BRUTE-TICK HARNESS FAILED" : "brute-tick behaviour all pass");
  return fails?1:0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    tp = Path(tmp) / "t.cpp"
    tp.write_text(HARNESS)
    exe = str(Path(tmp) / "t")
    r = subprocess.run(["clang++", "-O1", "-std=c++17", "-o", exe, str(tp)],
                       capture_output=True, text=True)
    check(r.returncode == 0, f"harness compiles {r.stderr[:400]}")
    if r.returncode == 0:
        run = subprocess.run([exe], capture_output=True, text=True)
        for ln in run.stdout.rstrip().splitlines():
            print("  " + ln if not ln.startswith("  ") else ln)
            if ln.strip().startswith("FAIL"):
                FAILS.append(ln.strip())
        check(run.returncode == 0, "harness exits 0")
        if run.stderr.strip():
            print("  stderr:", run.stderr[:300])

print()
if FAILS:
    print(f"FAILED ({len(FAILS)}):")
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("all brute-tick checks pass")
