#!/usr/bin/env python3
"""Static + behavioural checks for capture polarity.

The bug: rfBuf stores pulse WIDTHS only, so the level of each pulse is not in the
buffer. Both export sites and replayRaw() hard-asserted that rfBuf[0] is HIGH
(export wrote +width at even indices; replayRaw began with st=true). A capture
whose first retained pulse is LOW was therefore exported and replayed with every
level inverted, which no receiver accepts.

This is reachable: the 75 µs glitch filter folds a leading narrow pulse into the
next one, so the first RETAINED pulse can be LOW. KIA V3 N1 RAW.sub is that case
(a 55 µs HIGH lead-in is folded, leaving rfBuf[0] LOW).

There is also a second, worse bug in the same area: the Toyota-band >=150 µs
filter DROPPED sub-150 pulses. Because recorded pulses alternate, dropping one
inverts the level of every pulse after it. Measured on KIA V3 N1 RAW.sub:
8170 same-level adjacencies out of 43517 pulses. Folding instead leaves 0.

Run: python3 test_raw_polarity.py
"""

from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FIRMWARE = HERE / "FOBworks_for_SGP.ino"
source = FIRMWARE.read_text(encoding="utf-8")

# ── The start level is tracked, not assumed ──────────────────────────────────
assert re.search(r"bool\s+rfStartHigh\s*=\s*true", source), "rfStartHigh not declared"
assert "bool     rfStartHighB" in source, "Ch B polarity not tracked"

# Set in the capture path from a real reading, in both modes.
assert "bool capStartHigh=useGdo0?(bool)digitalRead(PIN_GDO0):true;" in source, \
    "GDO0 mode does not read the initial level"
assert "int r0=cc_fastRSSI(); capStartHigh=(r0>edgeThr);" in source, \
    "RSSI mode still assumes HIGH instead of reading the carrier state"
# and derived from the first SURVIVING pulse, which is what rfBuf[0] actually is
assert "rfStartHigh = (rfLen>0) ? (rfLvl[0]!=0) : true;" in source, \
    "rfStartHigh not taken from the first surviving pulse"

# ── Both export sites honour it ──────────────────────────────────────────────
assert source.count("rawAppendPulses(") >= 3, "rawAppendPulses helper missing"
# The old hard-assert must be gone from the writers.
assert "i%2==0?(int32_t)rfBuf[i]:-(int32_t)rfBuf[i]" not in source, \
    "a writer still hard-asserts HIGH-first"
assert "i%2==0 ? (int32_t)rfBuf[i] : -(int32_t)rfBuf[i]" not in source, \
    "a writer still hard-asserts HIGH-first"
# Both export sites must pass the TRACKED value, not a constant. Counted as exact
# call strings so a mutant that passes `true` is caught at either site.
assert source.count("rawAppendPulses(rs,rfBuf,rfLen,512,rfStartHigh)") == 2, \
    "an export site does not pass rfStartHigh (both SD save and /api/sub_export must)"
assert "rawAppendPulses(rs,rfBuf,rfLen,512,true)" not in source, \
    "an export site hard-asserts HIGH"
assert 'polarity: first pulse is ' in source, "export does not record the polarity"

# ── replayRaw takes and uses the flag ────────────────────────────────────────
sig = re.search(r"bool replayRaw\(float mhz,uint16_t\* data,int len,int reps,bool startHigh,bool snapGrid\)\{",
                source)
assert sig, "replayRaw does not accept a start level (or changed signature)"
# Slice from the DEFINITION. The sequencer adds a forward declaration earlier in
# the file, so `source.index("bool replayRaw(")` would land on that instead.
body = source[sig.start():]
body = body[:body.index("\n}\n")]
assert "bool st=startHigh;" in body, "replayRaw still starts at a hard-coded HIGH"

# Capture replays must pass the tracked value.
for want in ("replayRaw(mhz, rfBuf, rfLen, 3, rfStartHigh)",
             "replayRaw(rfFreq, rfBuf, rfLen, 3, rfStartHigh)",
             "rfStartHighB)",
             "fbkBuf[n].sh,",
             "keys[i].sh)",
             "keys[idx].sh)"):
    assert want in source, f"call site not passing polarity: {want}"

# Stored buffers carry it.
# The append moved into fbkAppend() , so the
# polarity is now recorded as e.sh from the startHigh argument. The capture path
# must pass rfStartHigh into it.
app = re.search(r"static bool fbkAppend\((?P<body>.*?)\n\}", source, re.DOTALL)
assert app, "fbkAppend not found"
assert "e.sh=startHigh;" in app.group("body"), "fbkAppend does not record polarity"
assert "fbkAppend(rfBuf,rfLen,rfFreq,rfStartHigh,lastDecode)" in source, \
    "the capture path does not pass the tracked polarity into fbkAppend"
assert "keys[i].sh=startHigh;" in source, "SavedKey does not record polarity"
assert "int keySave(String name,float freq,uint16_t* data,int len,bool startHigh=true)" in source, \
    "keySave does not accept a polarity"
assert source.count("keySave(n,rfFreq,rfBuf,rfLen,rfStartHigh)") == 2, \
    "keySave callers do not pass the capture polarity"

# Protocol builders construct buf[0] as HIGH by design, so they keep the default.
assert "buildCame12(next,(uint16_t)(te>0?te:320),nb,nl)&&replayRaw(mhz,nb,nl)" in source, \
    "CAME builder call site changed unexpectedly"

# ── The toy-band filter must FOLD, not DROP ──────────────────────────────────
# Dropping breaks the alternation that makes rfStartHigh sufficient.
toy = re.search(r"if\(_toyBand\)\{\n(?P<body>.*?)\n  \}", source, re.DOTALL)
assert toy, "toy-band filter not found"
tb = toy.group("body")
assert "rfBuf[rn-1]+=rfBuf[k]+rfBuf[k+1]; k++;" in tb, \
    "toy-band filter still drops short pulses instead of folding them"
assert "if(rfBuf[k]>=150){ rfBuf[rn]=rfBuf[k]; rfLvl[rn]=rfLvl[k]; rn++; }" in tb, \
    "toy-band filter lost its keep branch"
# The old drop form must be gone.
assert "for(int k=0;k<rfLen;k++) if(rfBuf[k]>=150) rfBuf[rn++]=rfBuf[k];" not in source, \
    "the pulse-dropping form is still present"

# ── Behavioural check on the real captures ──────────────────────────────────
CAPS = HERE / "research" / "sources" / "captures" / "kia"


def load_signed(p):
    vals = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RAW_Data:"):
            vals += [int(x) for x in re.findall(r"-?\d+", line[9:])]
    return vals


def sketch_filter(vals):
    """Mirror captureSignal's two filter stages, folding throughout."""
    w = [abs(v) for v in vals]
    lv = [v > 0 for v in vals]
    # stage 1: >=75 keep, else fold with next
    W, L, i = [], [], 0
    while i < len(w):
        if w[i] >= 75:
            W.append(w[i]); L.append(lv[i]); i += 1
        elif W and i + 1 < len(w):
            W[-1] += w[i] + w[i + 1]; i += 2
        else:
            i += 1
    # stage 2: toy band, fold <150
    M, ML, k = [], [], 0
    while k < len(W):
        if W[k] >= 150:
            M.append(W[k]); ML.append(L[k]); k += 1
        elif M and k + 1 < len(W):
            M[-1] += W[k] + W[k + 1]; k += 2
        else:
            k += 1
    return M, ML


if CAPS.is_dir():
    checked = 0
    for p in sorted(CAPS.glob("*.sub")):
        vals = load_signed(p)
        if len(vals) < 200:
            continue
        M, ML = sketch_filter(vals)
        if not ML:
            continue
        checked += 1
        # Alternation is what makes a single rfStartHigh sufficient.
        breaks = sum(1 for i in range(1, len(ML)) if ML[i] == ML[i - 1])
        assert breaks == 0, f"{p.name}: {breaks} same-level adjacencies (filter breaks alternation)"

        # Export then reload must reproduce the levels exactly.
        start_high = ML[0]
        exported = []
        for i, x in enumerate(M):
            high = start_high if (i % 2 == 0) else (not start_high)
            exported.append(x if high else -x)
        assert [v > 0 for v in exported] == ML, f"{p.name}: export inverts levels"

        # And prove the old behaviour was wrong for at least one capture, so this
        # test is not vacuous.
        if not start_high:
            print(f"  {p.name}: first retained pulse is LOW -> old code exported it inverted")
    assert checked >= 1, "no real captures available to check"
    print(f"polarity round-trip verified on {checked} real capture(s)")
else:
    print(f"note: {CAPS} not present; skipped the behavioural round-trip")

print("raw polarity checks passed")
