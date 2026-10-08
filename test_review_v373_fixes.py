#!/usr/bin/env python3
"""Regression checks for the four review findings, against the published tree.

These are source-level assertions, not behavioural tests: the WebSocket recipient leak and the
GPIO routing question both need hardware (two clients; a board where GDO0 is actually wired) to
prove at runtime, and neither is available here. What is checkable is that the code no longer
contains the constructs that caused each finding.

Each assertion names the finding it pins, so a future edit that reintroduces the old shape fails
with an explanation rather than just a line number.
"""

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
FW = HERE / "FOBworks_for_SGP.ino"
src = FW.read_text(encoding="utf-8")


def has(needle):
    return needle in src


# ── Finding 1: WebSocket recipients were never authenticated ─────────────���──────────────────
# A client could connect, supply no token, and still receive every event -- including decode
# results and key-related replies produced by an authenticated client.

assert has("if(fd<0||!wsAuthed[i]) continue;"), \
    "wsBroadcast no longer skips unauthenticated slots (finding 1)"

# The handshake must register the socket WITHOUT subscribing it. The old shape was
# wsRemember(fd) followed immediately by a broadcast to everyone.
assert "wsRemember(fd);\n    addLog(\"[WS] socket open" in src, \
    "the handshake appears to subscribe the client again (finding 1)"

assert "wsMarkAuthed(fd);" in src, \
    "nothing promotes a slot to authenticated (finding 1)"
assert "deserializeJson(jc,line)==DeserializationError::Ok && serialTokenMatches(jc)" in src, \
    "the slot is promoted without a token check (finding 1)"

# A command reply must go to its requester only.
assert "int slot=wsReplyTo;" in src and "if(slot>=0) wsSendToSlot(slot,wsReplyToGen,json);" in src, \
    "command replies are broadcast rather than routed to the requester (finding 1)"
assert "wsReplyTo=from;" in src and "wsReplyTo=-1;" in src, \
    "wsReplyTo is not scoped per queued command (finding 1)"

# ── Follow-up review: three edge cases the first pass left open ─────────────────────────────
# ① The capture budget was cleared only after a signal was found, so an attempt that timed out
#    left it set and the next ordinary capture inherited a 250 ms window.
assert "capMaxMsOverride = 0;                   // consume now, whatever path we leave by" in src, \
    "the capture budget is not consumed at the point it is read (follow-up 1)"
assert "capMaxMsOverride=0;   // one-shot" not in src, \
    "the late, exit-dependent clear is still present (follow-up 1)"

# ② A queued command carried a slot index, which is reused, so a reply could reach whichever
#    connection inherited the slot. Replies now carry a generation and require auth.
assert "static uint32_t wsGen[WS_MAX_CLIENTS]" in src and "wsGenNext" in src, \
    "slots have no generation, so a reused slot can still be addressed (follow-up 2)"
assert "static bool wsSlotMatches(int slot, uint32_t gen){" in src, \
    "there is no identity check for a queued reply (follow-up 2)"
assert "if(!wsServer || !wsSlotMatches(slot,gen) || !wsAuthed[slot]) return;" in src, \
    "wsSendToSlot does not verify the destination is the requester and is authenticated (follow-up 2)"
assert "wsGen[i]=0;" in src, \
    "a departed socket does not invalidate its generation (follow-up 2)"

# ②b A fifth connection evicts slot 0. If that evicted socket then sends a frame, wsSlotFor()
#     returns -1 -- and the generation lookup was an ARGUMENT to wsSlotMatches(), so it indexed
#     wsGen[-1] before the call could apply its own guard. Verified with UBSan: the old shape
#     reports "index -1 out of bounds for type 'uint32_t[4]'".
assert "uint32_t gen = (slot >= 0) && wsSlotMatches(slot, wsGen[slot])" in src, \
    "the generation lookup is not guarded against slot == -1 (out-of-bounds read)"
assert "wsSlotMatches(slot,wsGen[slot])" not in src, \
    "an unguarded wsGen[slot] index survives (the argument is evaluated before the call)"

# ③ Capture still selected the GDO0 path from a bare GPIO48 toggle, which on this revision can
#    be the SX1278's DIO0.
assert "bool gdo0Routed = false;" in src, \
    "the board-routing opt-in is missing or not off by default (follow-up 3)"
assert "if(gdo0Routed){\n    unsigned long _gt=micros();" in src, \
    "captureSignal still probes GPIO48 without the routing flag (follow-up 3)"
assert "if(gdo0ForceAsync){" not in src, \
    "the old TX-only flag name survives, so capture is not covered by the same gate (follow-up 3)"

# ④ The published prose must agree with FW_VER.
_ver = re.search(r'#define\s+FW_VER\s+"FOBworks for SGP v(\d+\.\d+)"', src).group(1)
_readme = (HERE / "README.md").read_text(encoding="utf-8")
assert f"Version {_ver}." in _readme, f"README does not state the current version (v{_ver})"

# The old unconditional broadcast from the handshake is gone.
assert 'wsBroadcast(String("{\\"event\\":\\"ws_open\\"' not in src, \
    "the handshake still broadcasts to every connected socket (finding 1)"

# ── Finding 2: the GDO0 toggle test cannot prove the CC1101 path ────────────────────────────
# On this revision GPIO 48 is the SX1278's DIO0 and the CC1101's GDO0 is not routed, so a
# toggle can come from the LoRa side. Selecting the async path on that basis transmits nothing.

assert "bool gdo0Routed = false;" in src, \
    "the board-routing opt-in is missing or not off by default (finding 2)"

# Neither selection site may probe the pin unless the board routes GDO0.
for site, marker in (
    ("startJam", "if(gdo0Routed){\n    pinMode(PIN_GDO0,INPUT);"),
    ("replayRaw", "if(gdo0Routed){\n    // Force-pins the async TX input"),
):
    assert marker in src, f"{site} still selects the async path from a bare toggle (finding 2)"

# The FIFO path must remain the default in both.
assert "bool ok=replayViaFifo(mhz,data,len,startHigh,reps,snapGrid);" in src, \
    "the packet-mode fallback is gone (finding 2)"
assert "jamUseFifo" in src, "the FIFO jam path is gone (finding 2)"

# ── Finding 3: the edge capture overran the requested window ────────────────────────────────
# timeoutMs bounds the wait for a signal, not the recording. The recording window was hardcoded
# at 3 s, so a 250 ms request could record for three seconds.

assert "unsigned long capEnd=capStart+(unsigned long)capMaxMs*1000UL;" in src, \
    "the edge deadline is hardcoded again (finding 3)"
assert "uint32_t capMaxMsOverride = 0;" in src, \
    "there is no per-call edge budget (finding 3)"
assert "capMaxMsOverride=250;" in src and "bool chbOk=captureSignal(3000);" in src, \
    "the Ch-B capture does not set a short recording budget (finding 3)"
# The budget must be one-shot, and consumed at the read rather than after the signal wait --
# the later form missed every early exit. See follow-up ① above for the positive assertion.

# ── Finding 4: /api/can_send echoed unvalidated input into JSON ──────────────────────────────
# The raw query text went into the response unescaped, and strtoul's partial parse accepted
# non-hex suffixes.

assert "if(h.length()==0||h.length()>8) {" in src, \
    "the id length is not validated (finding 4)"
assert "bool hexOk=(c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');" in src, \
    "non-hex characters are accepted in the id (finding 4)"
assert 'snprintf(idHex,sizeof(idHex),"0x%lX",(unsigned long)id);' in src, \
    "the response does not echo a canonical id (finding 4)"
assert '+",\\"id\\":\\""+idStr' not in src, \
    "the raw id string is still echoed into JSON (finding 4)"

# ── no published doc may point at something this tree does not contain ──────────────────────
# Two stale pointers survived earlier rounds: CITATIONS named the key corpus (deliberately not
# published) and (the worklog, not published). A reader cannot open either.
# This checks the PUBLISHED docs against the PUBLISHED file list.
#
# Scope notes, learned from the first version of this check: only the files this branch actually
# ships are inspected (the worklog lives on other branches and legitimately cites itself), and a
# reference must look like a path on a single line -- a backtick span containing newlines is a
# code block, not a reference.
#
# Second correction: the first version only checked that a cited path exists in the LOCAL tree,
# so a doc could point at a file this repository will never publish and still pass. README.md
# did exactly that, naming the worklog index, and it went unnoticed until the publish branch was
# compared against main. Existence and publishability are different properties, so both are
# checked here. The unpublished set is not a guess: it is what the publish branch excludes.
_PUB_DOCS = ["README.md", "PROMO.md", "CITATIONS_AND_REFERENCES.md"]
_REF = re.compile(r"`((?:research|tools)/[A-Za-z0-9_./ -]+)`")
_UNPUBLISHED = re.compile(r"^research/[0-9][0-9]_|^research/sources/keeloq_mfcodes_public\.txt$")
_bad = []
for _f in _PUB_DOCS:
    _p = HERE / _f
    if not _p.is_file():
        continue
    for _i, _line in enumerate(_p.read_text(encoding="utf-8").split("\n"), 1):
        for _m in _REF.finditer(_line):
            _r = _m.group(1).strip()
            if _r.endswith("/"):                      # a directory or an upstream project path
                continue
            if not (HERE / _r).exists() and not (HERE / _r.rstrip("/")).is_dir():
                _bad.append(f"{_f}:{_i} -> {_r} (not in this tree)")
            elif _UNPUBLISHED.match(_r):
                _bad.append(f"{_f}:{_i} -> {_r} (not published; a reader cannot open it)")
# Third correction, prompted by the citations listing repositories that live in the untracked
# `reference sources/` folder. That folder is gitignored, so it is absent from every clone, and
# naming it -- or any path inside it -- sends a reader looking for something they cannot have.
# The check above missed this entirely because it only matched spans beginning `research/` or
# `tools/`. This pass is deliberately broader: ANY backticked span that names a gitignored path,
# or looks like a file inside one, is a defect.
#
# A citation should credit a source, not inventory a private folder, so the fix is to name the
# upstream project rather than the local copy of it.
_IGNORED = []
for _line in (HERE / ".gitignore").read_text(encoding="utf-8").split("\n"):
    _line = _line.split("#")[0].strip()
    if _line:
        _IGNORED.append(_line.strip("/"))
_ANY = re.compile(r"`([^`\n]{2,120})`")
_private = []
for _f in _PUB_DOCS:
    _p = HERE / _f
    if not _p.is_file():
        continue
    for _i, _line in enumerate(_p.read_text(encoding="utf-8").split("\n"), 1):
        for _m in _ANY.finditer(_line):
            _s = _m.group(1).strip()
            for _ig in _IGNORED:
                if _ig and (_s == _ig or _s.startswith(_ig + "/")):
                    _private.append(f"{_f}:{_i} -> {_s} (inside gitignored `{_ig}`)")
                    break
assert not _private, (
    f"published docs point at gitignored paths a reader cannot obtain: {_private}")
print(f"  private-path check: no published doc names anything inside a gitignored folder")

print(f"review-finding checks passed on v{_ver} (websocket auth, GDO0 routing, capture budget, can_send)")
