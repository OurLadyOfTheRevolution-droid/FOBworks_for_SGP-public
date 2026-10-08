#!/usr/bin/env python3
"""C2 RollBack — executable state-machine test.

`test_rollback_c2.py` greps the source; this one *runs* the sequencer. It extracts
the shipped `rbArm` / `rbStart` / `rbTick` from FOBworks_for_SGP.ino verbatim,
compiles them against a mock `replayRaw` that records each transmission, and drives
the state machine to assert the behaviour a static check cannot reach:

  · code 1 transmits, then code 2, in that order — never the reverse
  · the gap is honoured: code 2 does not fire before rbGapMs has elapsed
  · a second fire without a re-arm transmits nothing
  · a jam never survives any exit path, including both TX failures
  · the sequencer returns to idle so a repeat needs a fresh arm
  · with fewer than 2 captures, nothing transmits at all

The mock is deliberate: `replayRaw` needs a CC1101, so the harness substitutes a
recorder. Everything else is the real code.

Run: python3 test_rollback_exec.py
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

# ── Pull the shipped sequencer out verbatim ──────────────────────────────────
src = SKETCH.read_text(encoding="utf-8")


def block(marker: str) -> str:
    """Return the definition starting at `marker`, brace-matched.

    Skips forward declarations (marker lines ending in ';' before the '{'),
    which sit above the definitions since the N10 consensus work.
    """
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
    end = k + 1
    if end < len(src) and src[end] == ";":
        end += 1
    return src[i:end] + "\n"


def line(marker: str) -> str:
    i = src.index(marker)
    return src[i : src.index("\n", i) + 1]


FRAME_CONSTS = ["#define KIA_V34_FRAME_GAP_US 1000u\n",
                "#define KIA_V34_FRAME_PITCH_PULS  162\n",
                "#define KIA_V34_FRAME_PITCH_TOL     8\n"]
pieces = [
    # state
    src[src.index("enum RBPhase"):src.index("\n\n// Gap bounds")],
    block("static void rbReset()"),
    block("static bool fbkParseCtr("),
    # fbkAppend now trims to one frame before storing , so the trim
    # helper and its constants must come with it.
    block("static int klTrimToFrame("),
    block("static int rjTrimKiaV34("),
    block("static bool fbkAppend("),
    block("static int fbkCtrOrder()"),
    block("static uint32_t fbkHash("),
    block("static bool rbArm()"),
    block("static bool rbStart(uint32_t gapMs)"),
    block("static void rbTick()"),
]
defines = "\n".join([line("#define RB_GAP_MIN_MS"),
                      line("#define RB_GAP_MAX_MS")])
sequencer = "".join(FRAME_CONSTS) + "\n" + defines + "\n" + "\n".join(pieces)

# The three TX-triggering statements must all have survived extraction, or the
# harness would silently test a stub.
for must in ("replayRaw(e0", "replayRaw(e1", "if(jamActive) stopJam()",
             "fbkCtrOrder()", "fbkHash(", "fbkAppend(",
             "e.hasCtr = fbkParseCtr(decode,c);"):
    assert must in sequencer, f"extraction missed {must!r} — harness would be vacuous"
# The §2.5 same-code rejection must be present, or this harness would pass while
# testing an rbArm that accepts a pair of identical codes.
assert "ord<0" in sequencer, "extraction missed the same-code rejection"

HARNESS = r'''
// Extracted by test_rollback_exec.py — do not edit.
// The RollBack sequencer is extracted verbatim from FOBworks_for_SGP.ino; only
// its hardware dependencies are mocked.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <string>
using std::string;

#define CAP_SZ 512
// Defined here because the mock below instantiates a buffer of this size before
// the sequencer section (which also defines it) is emitted.
#ifndef FBK_MAX
#define FBK_MAX 5
#endif

// ── Mocked hardware surface ──────────────────────────────────────────────────
struct ReplayCall { float mhz; int len; bool startHigh; };

static ReplayCall g_calls[64];
static int   g_nCalls   = 0;
static int   g_failAt    = -1;      // call index that should fail, -1 = none
static int   g_jamOnAt   = -1;      // call index during which a jam starts
static int   g_stopJamN  = 0;
static bool  jamActive   = false;
static bool  scanActive  = true;
static uint32_t g_now    = 1000;    // mock millis()

static uint32_t millis(){ return g_now; }
static void    setLed(int,int,int) {}
struct StringStub {
  string s;
  StringStub(){}
  StringStub(const char* c):s(c){}
  StringStub(int v){ char b[24]; snprintf(b,sizeof b,"%d",v); s=b; }
  StringStub(unsigned v){ char b[24]; snprintf(b,sizeof b,"%u",v); s=b; }
  StringStub& operator=(const char* c){ s=c; return *this; }
  StringStub& operator=(const string& o){ s=o; return *this; }
  StringStub operator+(const StringStub& o) const { StringStub r; r.s=s+o.s; return r; }
  StringStub operator+(const char* c) const { StringStub r; r.s=s+c; return r; }
  StringStub& operator+=(const char* c){ s+=c; return *this; }
  StringStub& operator+=(const StringStub& o){ s+=o.s; return *this; }
  // The Arduino String surface the shipped helpers use.
  unsigned length() const { return (unsigned)s.size(); }
  const char* c_str() const { return s.c_str(); }
  void trim(){
    size_t a=s.find_first_not_of(" \t\r\n");
    size_t b=s.find_last_not_of(" \t\r\n");
    s = (a==std::string::npos) ? std::string() : s.substr(a,b-a+1);
  }
};
// The sketch builds messages as "literal" + String(x) + "literal", so the
// left-hand operand can be a C string. Provide that overload.
static StringStub operator+(const char* a, const StringStub& b){ StringStub r; r.s=string(a)+b.s; return r; }
using String = StringStub;
static void serialEmit(const String&) {}
static void addLog(const String&) {}

// fbkParseCtr() reads the decode's "ctr" field via jsonRawField(). Minimal stand-in
// with the same contract: return the token after "ctr": up to , or }.
static String jsonRawField(const String& j,const char* key){
  String k="\""; k+=key; k+="\":";
  int i=j.s.find(k.s);
  if(i==(int)std::string::npos) return String("");
  size_t s0=(size_t)i+k.s.size();
  size_t e0=j.s.find_first_of(",}",s0);
  if(e0==std::string::npos) e0=j.s.size();
  String out; out.s=j.s.substr(s0,e0-s0); return out;
}

// A captured "code" the sequencer can transmit.
struct FbkEntry { uint16_t w[CAP_SZ]; int len; float freq; uint32_t ts; bool sh;
                  uint32_t ctr; bool hasCtr; bool trimmed;
                  uint32_t idHop; uint32_t idSn; uint8_t idBtn; uint32_t idCtr; bool idOk; };
static FbkEntry fbkBuf[FBK_MAX];
static int      fbkCount = 0;

// fbkAppend() now derives each entry's identity from its pulses. The identity itself is
// irrelevant to the RollBack sequencing under test, so stub it out; the real one needs the
// full KeeLoq parser chain (ks_km2/ks_klPwm/ks_parseKL) that this harness does not extract.
static bool fbkIdentify(const uint16_t*,int,float,uint32_t&,uint32_t&,uint8_t&,uint32_t&){
  return false;
}

// The one mocked transmit. Records the call so the test can assert order and count.
bool replayRaw(float mhz,uint16_t* data,int len,int reps=3,bool startHigh=true){
  if(g_nCalls < 64){
    g_calls[g_nCalls].mhz = mhz;
    g_calls[g_nCalls].len = len;
    g_calls[g_nCalls].startHigh = startHigh;
  }
  int idx = g_nCalls++;
  // A jam can begin during a transmit (e.g. a concurrent jam command lands while
  // the bit-bang is running). That is the only situation in which the
  // failure-path stopJam() is load-bearing, so the mock must be able to express it.
  if(idx == g_jamOnAt) jamActive = true;
  if(idx == g_failAt) return false;
  return true;
}
void stopJam(){ g_stopJamN++; jamActive=false; }

// ── The shipped sequencer, verbatim ─────────────────────────────────────────
''' + sequencer + r'''

// ── Test scaffolding ────────────────────────────────────────────────────────
static int g_fails = 0;
#define CHECK(cond, ...) do{ if(!(cond)){ printf("  FAIL " __VA_ARGS__); printf("\n"); g_fails++; } }while(0)

static void resetAll(){
  g_nCalls=0; g_failAt=-1; g_jamOnAt=-1; g_stopJamN=0; jamActive=false; scanActive=true;
  for(int i=0;i<FBK_MAX;i++){ fbkBuf[i].ctr=0; fbkBuf[i].hasCtr=false; fbkBuf[i].trimmed=false; }
  g_now=1000;
  rbReset();
  fbkCount=0;
}

// Fixtures must now look like two DIFFERENT codes, because rbArm rejects a pair
// carrying the same counter. Each call assigns the next counter
// so a normal two-code fixture is accepted, and the width arrays differ by counter
// so the content-identity fallback also sees them as distinct.
static void addCode(int len, float mhz, bool sh){
  fbkBuf[fbkCount].len=len; fbkBuf[fbkCount].freq=mhz; fbkBuf[fbkCount].sh=sh;
  fbkBuf[fbkCount].ctr=0x1000+(uint32_t)fbkCount;   // 0x1000, 0x1001, ...
  fbkBuf[fbkCount].hasCtr=true;
  // Mark as frame-trimmed. rbArm now gates on this, because a multi-repeat block makes
  // C2 transmit several presses of each code. The synthetic-capture
  // section below sets it from the real trim result instead.
  fbkBuf[fbkCount].trimmed=true;
  for(int i=0;i<len&&i<CAP_SZ;i++) fbkBuf[fbkCount].w[i]=(uint16_t)(400+i+fbkCount);
  fbkCount++;
}

int main(){
  // ��─ 1. Order: code 1 then code 2, and nothing else ────────────────────────
  printf("=== order and count ===\n");
  resetAll();
  addCode(120, 315.0f, true);
  addCode(140, 315.0f, false);
  CHECK(rbArm(), "arm should succeed with 2 codes");
  CHECK(rbStart(100), "fire should succeed when armed");
  CHECK(g_nCalls==1, "expected exactly 1 TX after start, got %d", g_nCalls);
  if(g_nCalls==1){
    CHECK(g_calls[0].len==120, "first TX should be code 1 (len 120), got %d", g_calls[0].len);
  }
  // gap not yet elapsed -> no second TX
  g_now += 99;
  rbTick();
  CHECK(g_nCalls==1, "code 2 fired before the gap elapsed (%d calls)", g_nCalls);
  // gap elapsed -> code 2
  g_now += 2;
  rbTick();
  CHECK(g_nCalls==2, "expected code 2 after the gap, got %d calls", g_nCalls);
  if(g_nCalls==2){
    CHECK(g_calls[1].len==140, "second TX should be code 2 (len 140), got %d", g_calls[1].len);
    CHECK(g_calls[1].startHigh==false, "code 2 should use its own stored polarity");
  }
  // no further TX from extra ticks
  rbTick(); rbTick();
  CHECK(g_nCalls==2, "extra ticks transmitted again (%d calls)", g_nCalls);
  printf("  order: code1(len %d) -> gap -> code2(len %d); total %d TX\n",
         g_calls[0].len, g_nCalls>1?g_calls[1].len:-1, g_nCalls);

  // ── 2. Gap bounds are enforced ────────────────────────────────────────────
  printf("\n=== gap clamping ===\n");
  for(int g : {10, 40, 500, 2000, 9999}){
    resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
    rbArm(); rbStart((uint32_t)g);
    printf("  requested %4d ms -> applied %4u ms (%s)\n", g, rbGapMs,
           (rbGapMs>=RB_GAP_MIN_MS && rbGapMs<=RB_GAP_MAX_MS) ? "in range" : "OUT OF RANGE");
    CHECK(rbGapMs>=RB_GAP_MIN_MS && rbGapMs<=RB_GAP_MAX_MS, "gap %d not clamped", g);
  }

  // ── 3. Single-shot: a second fire without a re-arm transmits nothing ─────
  printf("\n=== single-shot ===\n");
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  rbArm(); rbStart(50);
  int afterFirst = g_nCalls;
  g_now += 100; rbTick();                 // complete the sequence
  int afterComplete = g_nCalls;
  CHECK(!rbStart(50), "fire without a re-arm must be refused");
  CHECK(g_nCalls==afterComplete, "refused fire still transmitted (%d -> %d)", afterComplete, g_nCalls);
  // A refused fire must also not leave the sequencer able to fire later: after the
  // refusal, ticking must not transmit. This is the case a mutant that drops the
  // arm-consume can still pass, because the completion path also clears the flag —
  // so assert on the arm-consume *before* any completion happens instead.
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  rbArm();
  // Fire once; the consume must happen before the transmit, so a second fire in the
  // same gap window is refused. If the consume were absent, this second call would
  // be accepted and would transmit code 1 again.
  CHECK(rbStart(500), "first armed fire should succeed");
  int nAfterOne = g_nCalls;
  bool secondAccepted = rbStart(500);
  CHECK(!secondAccepted, "second fire was accepted without a re-arm");
  CHECK(g_nCalls==nAfterOne, "second fire transmitted (%d -> %d)", nAfterOne, g_nCalls);
  printf("  single-shot: first fire TX=%d, second accepted=%d, TX=%d\n",
         nAfterOne, (int)secondAccepted, g_nCalls);
  // The consume's only *observable* effect is the reported arm flag during the gap.
  // While the sequence runs, rbPhase==RB_GAP refuses any re-fire anyway, and rbTick
  // clears the arm at completion, so a mutant that drops the consume behaves
  // identically through rbStart/rbTick — verified. But /api/rollback_status reports
  // `armed`, and the UI shows it: with the consume missing the tool claims to still
  // be armed while it is mid-sequence, which is misleading. Assert the flag here.
  CHECK(!rbArmed, "arm was not consumed: status would report 'armed' mid-sequence");
  // The decisive case. While the sequence is mid-gap the rbPhase guard alone
  // refuses a second fire, so a missing arm-consume is invisible there. Once the
  // sequence COMPLETES the guard is gone, and only the consumed arm prevents a
  // re-fire without a fresh arm. Without the consume, rbArmed is still true and
  // this fire would transmit a whole second sequence.
  g_now += 600; rbTick();            // let the sequence complete
  int nAfterComplete2 = g_nCalls;
  bool postComplete = rbStart(500);
  CHECK(!postComplete, "fire accepted after completion without a re-arm");
  CHECK(g_nCalls==nAfterComplete2, "post-completion fire transmitted (%d -> %d)",
        nAfterComplete2, g_nCalls);
  printf("  single-shot after completion: accepted=%d, TX=%d (must be 0 TX)\n",
         (int)postComplete, g_nCalls);
  // and a duplicate fire while mid-sequence is refused too
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  rbArm(); rbStart(1000);
  CHECK(!rbStart(1000), "fire while mid-sequence must be refused");
  CHECK(g_nCalls==1, "mid-sequence re-fire transmitted (%d calls)", g_nCalls);
  printf("  refused re-fire: TX stayed at %d\n", g_nCalls);

  // ── 4. Jam never survives any exit path ─────────────────────────────────
  printf("\n=== jam cleared on every exit ===\n");
  // The invariant is that jamActive is false after every exit path. Whether
  // stopJam() is *called* depends on whether a jam was running, so the jam is set
  // while it genuinely can be: during the gap, between the two transmits. That is
  // the window where a jam that outlives the sequence would keep the carrier on.
  // (a) jam active before a successful fire
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  jamActive=true; rbArm(); rbStart(50);
  CHECK(!jamActive, "jam survived rbStart");
  CHECK(g_stopJamN>=1, "stopJam not called on the success path");
  // re-assert a jam during the gap: completion must still clear it
  jamActive=true;
  g_now+=100; rbTick();
  CHECK(!jamActive, "jam survived rbTick completion");
  CHECK(g_stopJamN>=2, "stopJam not called on completion while a jam was active");
  printf("  jam active at start and during gap -> stopJam x%d, jamActive=%d after completion\n",
         g_stopJamN, (int)jamActive);

  // (b) first TX fails, with a jam beginning DURING that transmit. The pre-TX
  // stopJam cannot have cleared it, so only the failure-path stopJam saves us.
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  g_failAt=0; g_jamOnAt=0; rbArm(); bool ok=rbStart(50);
  CHECK(!ok, "fire should report failure when code 1 fails");
  CHECK(!jamActive, "jam survived a failed first TX");
  CHECK(g_stopJamN>=1, "stopJam not called when the first TX fails");
  CHECK(rbPhase==RB_IDLE, "phase should be idle after a failed first TX, got %d", (int)rbPhase);
  CHECK(!rbArmed, "arm should be consumed even on failure");
  printf("  first TX fails -> stopJam x%d, phase=%d, armed=%d\n",
         g_stopJamN, (int)rbPhase, (int)rbArmed);

  // (c) second TX fails, with a jam active during the gap
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  rbArm(); g_failAt=1; rbStart(50);
  jamActive=true;                       // jam appears during the gap
  g_now+=100; rbTick();
  CHECK(!jamActive, "jam survived a failed second TX");
  CHECK(g_stopJamN>=1, "stopJam not called when the second TX fails with a jam active");
  CHECK(rbPhase==RB_IDLE, "phase should return to idle after a failed second TX");
  printf("  second TX fails with jam active -> stopJam x%d, phase=%d, jamActive=%d\n",
         g_stopJamN, (int)rbPhase, (int)jamActive);

  // ── 4b. Same-code refusal ────────────────────────────
  // One press can append two entries, so two entries are NOT two codes. If both
  // carry the same counter, RollBack transmits one code twice and the receiver sees
  // no forward step: the attack fails silently. rbArm must refuse.
  printf("\n=== same-code refusal ===\n");
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  fbkBuf[1].ctr = fbkBuf[0].ctr;          // force the §2.5 case
  CHECK(!rbArm(), "arm accepted two entries with the SAME counter");
  CHECK(!rbArmed, "same-code pair left the sequencer armed");
  CHECK(!rbStart(50), "same-code pair was allowed to transmit");
  CHECK(g_nCalls==0, "same-code pair transmitted (%d)", g_nCalls);
  printf("  same counter -> refused, 0 TX\n");

  // Backward order is equally unusable.
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  uint32_t tmp=fbkBuf[0].ctr; fbkBuf[0].ctr=fbkBuf[1].ctr; fbkBuf[1].ctr=tmp;
  CHECK(!rbArm(), "arm accepted a backward counter pair");
  printf("  backward counters -> refused\n");

  // With no decoded counter, byte-identical blocks must still be refused, because
  // they are certainly the same code.
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  fbkBuf[0].hasCtr=false; fbkBuf[1].hasCtr=false;
  for(int i=0;i<100;i++) fbkBuf[1].w[i]=fbkBuf[0].w[i];   // make content identical
  CHECK(!rbArm(), "arm accepted byte-identical blocks with no counter");
  printf("  no counter + identical content -> refused\n");

  // A valid forward pair must still be accepted, so the check is not over-strict.
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  CHECK(rbArm(), "a valid forward counter pair was refused");
  printf("  valid forward pair (0x%X -> 0x%X) -> accepted\n", fbkBuf[0].ctr, fbkBuf[1].ctr);

  // ── 4c. An untrimmed block must be refused ───────
  // C2 is only correct for protocols whose captures reduce to one frame. For every
  // other protocol the raw multi-repeat block is kept, and transmitting it sends
  // several presses of each code — a failure the operator cannot see. Refuse instead.
  printf("\n=== untrimmed-block refusal ===\n");
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  fbkBuf[0].trimmed=false;                 // simulate a non-Kia protocol
  CHECK(!rbArm(), "arm accepted an untrimmed (multi-repeat) block");
  CHECK(!rbArmed, "untrimmed refusal left the sequencer armed");
  CHECK(!rbStart(50), "untrimmed pair was allowed to transmit");
  CHECK(g_nCalls==0, "untrimmed pair transmitted (%d)", g_nCalls);
  // One untrimmed entry is enough to refuse, even if the other is fine.
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  fbkBuf[1].trimmed=false;
  CHECK(!rbArm(), "arm accepted a pair with one untrimmed block");
  printf("  untrimmed -> refused, 0 TX\n");

  // ── 5. Refuses with fewer than 2 captures ───────────────────────────────
  printf("\n=== insufficient captures ===\n");
  resetAll(); addCode(100,315.0f,true);
  CHECK(!rbArm(), "arm must be refused with 1 code");
  CHECK(g_nCalls==0, "nothing should transmit with 1 code");
  resetAll();
  CHECK(!rbArm(), "arm must be refused with 0 codes");
  CHECK(!rbStart(50), "fire must be refused with 0 codes");
  CHECK(g_nCalls==0, "no TX with 0 codes (%d)", g_nCalls);
  printf("  1 code / 0 codes -> arm refused, 0 TX\n");

  // ── 6. Returns to idle so a repeat needs a re-arm ───────────────────────
  printf("\n=== returns to idle ===\n");
  resetAll(); addCode(100,315.0f,true); addCode(100,315.0f,true);
  rbArm(); rbStart(50); g_now+=100; rbTick();
  CHECK(rbPhase==RB_IDLE, "phase should be idle after completion, got %d", (int)rbPhase);
  CHECK(!rbArmed, "arm should be consumed after completion");
  CHECK(rbArm(), "a fresh arm should be accepted after completion");
  printf("  after completion: phase=%d armed=%d; fresh arm accepted\n",
         (int)rbPhase, (int)rbArmed);

  // ── 7. The path §2.6 says was never exercised: a synthetic
  //       multi-repeat capture pushed through the real append, then arm/fire. ──
  printf("\n=== synthetic multi-repeat capture -> append -> arm -> fire ===\n");
  // Build a capture the way a real one arrives: N repeats of one frame (same
  // counter) inside a single capture, which is what a press emits. Measured on
  // KIA V3 N1 RAW.sub: 158-pulse frame unit, 10 repeats per counter, CAP_SZ=512
  // so a capture holds ~3 repeats of ONE counter.
  {
    resetAll();
    // Capture 1: a 512-pulse block of 400/800 PWM carrying counter 0x26.
    static uint16_t cap1[CAP_SZ];
    // Build a realistic multi-repeat capture: 400/800 PWM with a ~1188us sync every
    // 162 pulses, which is what the frame trim anchors on. Without the separator the
    // trim correctly keeps the raw block and this test could not observe it.
    for(int i=0;i<CAP_SZ;i++) cap1[i] = (i%2)? 800 : 400;
    for(int b=21;b<CAP_SZ;b+=162) cap1[b]=1188;
    // The decode a KeeLoq-family capture would report.
    String dec1 = String("{\"proto\":\"KeeLoq\",\"sn\":12345,\"ctr\":38}");   // 0x26
    bool a1=fbkAppend(cap1,CAP_SZ,315.0f,true,dec1);
    CHECK(a1, "append of capture 1 failed");
    CHECK(fbkCount==1, "append did not add an entry");
    CHECK(fbkBuf[0].hasCtr, "append did not record the counter");
    CHECK(fbkBuf[0].ctr==0x26, "counter parsed as 0x%X, want 0x26", fbkBuf[0].ctr);
    printf("  capture 1 appended: len=%d ctr=0x%X hasCtr=%d\n",
           fbkBuf[0].len, fbkBuf[0].ctr, (int)fbkBuf[0].hasCtr);
    // The append must store ONE frame, not the raw multi-repeat block (
    // F2). CAP_SZ is 512 and one frame is 183, so a stored 512 means the trim was
    // skipped — and C2 would then transmit ~3 presses instead of one.
    CHECK(fbkBuf[0].trimmed, "append did not mark the entry as trimmed");
    CHECK(fbkBuf[0].len<512, "append stored the raw block (%d), not one frame",
          fbkBuf[0].len);
    CHECK(fbkBuf[0].len>=60 && fbkBuf[0].len<=220,
          "appended length %d is not one frame", fbkBuf[0].len);

    // Arm with only ONE entry: must be refused (the multi-repeat case).
    CHECK(!rbArm(), "arm accepted a single capture (which holds repeats of ONE code)");

    // Capture 2 with the SAME counter: still must be refused. This is exactly the
    // §2.5 failure — two entries, one code.
    static uint16_t cap2[CAP_SZ];
    for(int i=0;i<CAP_SZ;i++) cap2[i] = (i%2)? 800 : 400;
    for(int b=21;b<CAP_SZ;b+=162) cap2[b]=1188;
    String dec2same = String("{\"proto\":\"KeeLoq\",\"sn\":12345,\"ctr\":38}");
    bool a2=fbkAppend(cap2,CAP_SZ,315.0f,true,dec2same);
    CHECK(a2, "append of capture 2 failed");
    CHECK(fbkCount==2, "second append did not add an entry");
    CHECK(!rbArm(), "arm accepted two captures carrying the SAME counter (§2.5)");
    printf("  two captures, same counter 0x26 -> arm refused\n");

    // An append that CANNOT be reduced to one frame must record trimmed=false. Without
    // this the flag could be set unconditionally and the gate would pass everything.
    // A block with no separator is exactly the non-Kia case the gate exists for.
    resetAll();
    static uint16_t noSep[CAP_SZ];
    for(int i=0;i<CAP_SZ;i++) noSep[i]=(i%2)?800:400;   // no >1000us pulse anywhere
    CHECK(fbkAppend(noSep,CAP_SZ,315.0f,true,dec1), "append of a separator-free block failed");
    CHECK(!fbkBuf[0].trimmed, "an untrimmable block was marked trimmed");
    printf("  untrimmable block -> trimmed=%d (must be 0)\n", (int)fbkBuf[0].trimmed);

    // Capture 2 with the NEXT counter: now it is a genuine pair and must arm.
    resetAll();
    fbkAppend(cap1,CAP_SZ,315.0f,true,dec1);
    String dec2next = String("{\"proto\":\"KeeLoq\",\"sn\":12345,\"ctr\":39}");
    fbkAppend(cap2,CAP_SZ,315.0f,true,dec2next);
    CHECK(rbArm(), "genuine two-counter pair was refused");
    CHECK(rbStart(50), "genuine pair failed to fire");
    g_now+=100; rbTick();
    CHECK(g_nCalls==2, "genuine pair transmitted %d times, want 2", g_nCalls);
    printf("  captures 0x26 -> 0x27 -> armed and fired, %d TX\n", g_nCalls);
  }

  printf("\n%s (%d failures)\n", g_fails? "FAIL":"ALL C2 BEHAVIOURAL CHECKS PASS", g_fails);
  return g_fails?1:0;
}
'''


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        cpp = wd / "rb_exec.cpp"
        cpp.write_text(HARNESS, encoding="utf-8")
        exe = wd / "rb_exec"
        cxx = shutil.which("c++") or shutil.which("clang++") or "c++"
        r = subprocess.run([cxx, "-O1", "-std=c++17", "-w", str(cpp), "-o", str(exe)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("harness compile failed:\n" + r.stderr[:4000], file=sys.stderr)
            return 2
        out = subprocess.run([str(exe)], capture_output=True, text=True)
        print(out.stdout)
        if out.stderr:
            print(out.stderr, file=sys.stderr)
        if out.returncode != 0:
            return 1

    # The extraction assertions already proved the real sequencer is under test.
    print("rollback C2 executable checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
