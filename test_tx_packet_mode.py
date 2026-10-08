#!/usr/bin/env python3
"""Verify the packet-mode TX path's register values against the CC1101 datasheet.

§4 step 1: packet mode drives the PA from the chip's own TX FIFO, so it needs
no GDO0 — which is the whole point on this board. But the whole thing rests on a handful of
register numbers being correct, and if any is wrong the test would report a false failure
on hardware and send the investigation somewhere useless. So they are checked here first,
against values taken from the TI datasheet (SWRS061I).

This is a static check. It cannot prove a carrier is emitted — that needs the board and a
receiver. It proves the firmware is asking the chip for the right things.
"""

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "FOBworks_for_SGP.ino"
FAILS = []



def extract_fn(src, signature):
    """Return the full text of a function, using brace matching.

    Regex is the wrong tool here and cost me two attempts: an anchored `.*?}` grabs the
    forward DECLARATION when one exists (giving a 297 KB slice of the whole file, and
    assertions that pass by accident), while a lazy match to a comment can swallow other
    functions. Counting braces from the definition's opening brace is unambiguous.
    """
    # Find the DEFINITION (line ending in `{`), not the forward declaration (`;`).
    # Anchor on a DEFINITION. A looser pattern matched a call site
    # (`if(captureSignal(...))`) and extracted unrelated code, which made assertions pass
    # or fail for the wrong reason. A definition starts at column 0 with a type, and the
    # closing paren is followed only by `{`.
    pat = re.compile(r"^(?:static\s+)?(?:bool|void|int|uint\d+_t|float|String|const\s+char\*)\s+"
                     + re.escape(signature) + r"\([^;{]*?\)\s*\{", re.M | re.S)
    m = pat.search(src)
    if not m:
        return None
    start = m.start()
    i = src.index("{", m.start())
    depth = 0
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
        i += 1
    return None


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        FAILS.append(msg)


def main():
    src = SRC.read_text(encoding="utf-8")

    print("=== the packet TX functions exist ===")
    for fn in ("cc_writeBurst", "cc_txPacket", "cc_txCarrier"):
        check(f"{fn}(" in src, f"{fn}() is defined")

    # Isolate cc_txPacket's body so we test the TX path, not the capture path.
    body = extract_fn(src, "cc_txPacket")
    check(body is not None, "cc_txPacket body extracted (brace-matched)")
    if not body:
        return 1
    check(len(body) < 8000, f"extraction is the function, not the file (got {len(body)} chars)")

    print("\n=== register values, against datasheet SWRS061I ===")
    # PKTCTRL0 (0x08) = 0x00 -> PKT_FORMAT=00 normal/FIFO, CRC_EN=1, LENGTH_CONFIG=00 fixed
    # Datasheet: 0x08 PKTCTRL0, bits 5:4 PKT_FORMAT, bit 2 CRC_EN, bits 1:0 LENGTH_CONFIG.
    check(re.search(r"cc_writeReg\(0x08,\s*0x00\)", body) is not None,
          "PKTCTRL0=0x00 selects packet mode with CRC (was 0x30 async, which needs GDO0)")
    # PKTCTRL0 is deliberately restored to 0x30 (async) at the END so capture still
    # works. The requirement is that nothing sets async mode BEFORE the STX strobe:
    # the transmit itself must happen in packet mode or the FIFO is not used.
    code = re.sub(r"//.*", "", body)
    stx = code.find("cc_strobe(0x35)")
    check(stx != -1, "STX strobe present in the TX path")
    if stx != -1:
        before = code[:stx]
        check("0x30" not in before,
              "PKTCTRL0 is still packet mode at the moment of STX (async restore happens only after)")
        check("cc_writeReg(0x08,0x00)" in before,
              "packet mode is set before transmitting")
    # PKTLEN (0x06)
    check(re.search(r"cc_writeReg\(0x06,\s*n\)", body) is not None,
          "PKTLEN=0x06 is set to the payload length")
    # PKTCTRL1 (0x07) = 0x00 -> no address check, no append status
    check(re.search(r"cc_writeReg\(0x07,\s*0x00\)", body) is not None,
          "PKTCTRL1=0x00 disables address filtering")
    # CHANNR (0x0A)
    check(re.search(r"cc_writeReg\(0x0A,\s*chan\)", body) is not None, "CHANNR=0x0A is set")

    print("\n=== command strobes ===")
    check(re.search(r"cc_strobe\(0x35\)", body) is not None, "STX=0x35 strobed to transmit")
    check(re.search(r"cc_strobe\(0x3B\)", body) is not None, "SFTX=0x3B flushes the TX FIFO")
    check(re.search(r"cc_strobe\(0x36\)", body) is not None, "SIDLE=0x36 leaves TX afterwards")

    print("\n=== TX FIFO access ===")
    # Datasheet: 0x3F single-byte TX FIFO, 0x7F burst TX FIFO. cc_writeBurst adds 0x40.
    check(re.search(r"cc_writeBurst\(0x3F,", body) is not None,
          "payload written to 0x3F (TX FIFO); cc_writeBurst ORs 0x40 for burst -> 0x7F")

    print("\n=== safety ===")
    # A wedged radio must not leave a carrier running or hang the caller.
    check("millis()-t0<" in body, "the FIFO drain wait is bounded by a timeout")
    # SIDLE must happen on every exit path, and the capture config restored.
    # Counting SIDLEs is too weak: the function has one before SFTX too, so removing the
    # post-transmit one still leaves the count at 2. What matters for safety is a SIDLE
    # AFTER the transmit, so the carrier cannot be left running.
    code2 = re.sub(r"//.*", "", body)
    stx_i = code2.find("cc_strobe(0x35)")
    after_stx = code2[stx_i:] if stx_i != -1 else ""
    check("cc_strobe(0x36)" in after_stx,
          "SIDLE is issued AFTER the STX strobe, so the carrier cannot be left running")
    check(re.search(r"cc_writeReg\(0x08,\s*0x30\)", body) is not None,
          "PKTCTRL0 restored to async (0x30) so the next capture still works")
    check(re.search(r"cc_writeReg\(0x02,\s*0x0D\)", body) is not None,
          "IOCFG0 restored to 0x0D for the capture path")

    print("\n=== no GDO0 dependency in the TX path ===")
    stripped = re.sub(r"//.*", "", body)
    check("pinMode(PIN_GDO0,OUTPUT)" not in stripped,
          "packet TX never drives GDO0 as an output (the pin is absent on this board)")
    check("digitalWrite(PIN_GDO0" not in stripped,
          "packet TX never bit-bangs GDO0")

    print("\n=== the bit-bang path is left intact for boards that do have GDO0 ===")
    check("bool replayRaw(" in src, "replayRaw() still exists")
    # replayRaw may still use GDO0 bit-bang; that path is for boards where it works.
    rr = extract_fn(src, "replayRaw")
    check(rr is not None, "replayRaw body extracted")
    if rr:
        check(len(rr) < 8000, f"replayRaw extraction is the function (got {len(rr)} chars)")
        check("delayMicroseconds(data[i])" in rr,
              "replayRaw() still bit-bangs, so boards with GDO0 keep arbitrary-RAW TX")

    print("\n=== OOK needs BOTH PA levels programmed, or TX is invisible ===")
    # This is the bug that produced a false pass. tx_fifo_test said TX_FIFO_WORKING while
    # PATABLE read "c0,0,0,0,0,0,0,0" and FREND0.PA_POWER=1, so an OOK logic 1 went out at
    # ZERO POWER. The FIFO still drains, so the test looked like a success. The datasheet
    # requires (OOK) "the logic 0 and logic 1 power levels shall be programmed to index 0
    # and 1 respectively", and reaching index 1 needs a BURST write.
    pat = re.search(r"uint8_t pat\[2\]=\{([^}]*)\}", src)
    check(pat is not None, "the PATABLE is written with a multi-level (burst) write")
    if pat:
        vals = [v.strip() for v in pat.group(1).split(",")]
        check(len(vals) >= 2,
              f"at least 2 PATABLE entries are written (got {len(vals)})")
        nonzero = [v for v in vals if v not in ("0x00", "0")]
        check(len(nonzero) >= 2,
              f"both OOK levels are non-zero ({vals}) so a logic 1 actually radiates")
    # A single-byte 0x3E write cannot reach index 1 and is the original defect.
    check(re.search(r"cc_writeReg\(0x3E,", src) is None,
          "no single-byte 0x3E write remains (it cannot reach PATABLE index 1)")
    check("cc_writeBurst(0x3E," in src,
          "the PATABLE is written via cc_writeBurst (the index counter only advances in a burst)")

    print("\n=== MARCSTATE constants match the datasheet ===")
    # The datasheet state diagram (§19) is authoritative:
    #   SLEEP 0  IDLE 1  XOFF 2  MANCAL 3-5  FS_WAKEUP 6-7  CALIBRATE 8  SETTLING 9-11
    #   RX 13-15  TXRX_SETTLING 16  RXFIFO_OVERFLOW 17  FSTXON 18  TX 19-20
    #   RXTX_SETTLING 21  TXFIFO_UNDERFLOW 22
    # An earlier version tested 17 for TX, which is RXFIFO_OVERFLOW, so a working
    # transmission was reported as a failure for several rounds.
    car = extract_fn(src, "cc_txCarrier")
    check(car is not None, "cc_txCarrier extracted")
    if car:
        body_c = re.sub(r"//.*", "", car)
        check(re.search(r"lastMarc\s*==\s*19", body_c) is not None,
              "TX is tested as MARCSTATE 19 (datasheet: TX = 19,20)")
        check("lastMarc==17" not in body_c.replace(" ", ""),
              "no test for MARCSTATE 17, which is RXFIFO_OVERFLOW, not TX")

    print("\n=== the TX FIFO is 64 bytes and is fed in chunks ===")
    # Writing more than 64 bytes in one burst silently drops the excess: the FIFO is 64 B.
    if car:
        body_c = re.sub(r"//.*", "", car)
        check("uint8_t ones[64]" in body_c,
              "the carrier payload buffer is 64 bytes (the TX FIFO size)")
        check(re.search(r"cc_writeBurst\(0x3F,\s*ones\s*,\s*(64|56)\)", body_c) is not None,
              "burst writes never exceed 64 bytes in one go")

    print("\n=== the test command reports from the chip, not from assumptions ===")
    ti = re.search(r'else if\(op=="tx_fifo_test"\)\s*\{.*?\n      \}', src, re.S)
    check(ti is not None, "tx_fifo_test command exists")
    if ti:
        t = ti.group(0)
        check("cc_readStatus(0x3A)" in t, "reads TXBYTES (0x3A) to see the FIFO drain")
        check("cc_readStatus(0x35)" in t, "reads MARCSTATE (0x35) to see the state machine")
        check("cc_readStatus(0x31)" in t, "reads VERSION (0x31) as a control")
    check('op=="pa_check"' in src,
          "pa_check exists, so the PA table can be read back on the device")

    print("=== emitted commands do not contain a doubled comma ===")
    # The defect that cost real time: a dropped `+` produced
    #   "path":"gdo0",,"marcstate":-1
    # which is emitted but unparseable, so every jam_status poll silently returned nothing
    # while the command looked fine.
    #
    # Two earlier attempts at a general JSON assembler were themselves buggy (a truncated
    # span, then a search that matched inside a string literal) and reported "0 checked"
    # while passing — the same vacuous-check trap. So this checks the specific artefact
    # directly, and the self-test below proves it has teeth.
    doubled = []
    for m in re.finditer(r'",\s*"\s*\+\s*",', src):
        line = src.count("\n", 0, m.start()) + 1
        doubled.append(line)
    check(not doubled,
          "no emit concatenation produces ,,  (a doubled comma)"
          + ("" if not doubled else f" — lines {doubled[:5]}"))
    # Confirm the specific line that had the defect is well formed now: the path literal
    # must end the JSON fragment with `",` and the next line must OPEN with `"marcstate"`.
    # (An earlier version of this assertion searched the HTTP route instead of the serial
    # handler and failed on correct code — the same wrong-target mistake as the vacuous
    # JSON check, so it now names the exact concatenation.)
    check(re.search(r'\+\"\\\",\"\+\s*\n\s*\"\\\"marcstate\\\":\"', src) is not None,
          "jam_status serial emit: path ends with \", and marcstate opens the next fragment")

    print("\n=== replayRaw refuses on a dead TX path ===")
    rr2 = extract_fn(src, "replayRaw")
    check(rr2 is not None, "replayRaw extracted")
    if rr2:
        body_r = re.sub(r"//.*", "", rr2)
        # The defect: it returned true unconditionally. There must be a path-liveness test
        # before the bit-bang and at least one refusal.
        # Assert the CONDITION, not merely that an identifier exists: a mutation replacing
        # `if(!txPathLive)` with `if(false)` must be caught. So require the guard to be a
        # real test of txPathLive and the refusal to sit inside it.
        check(re.search(r"if\s*\(\s*!\s*txPathLive\s*\)", body_r) is not None,
              "replayRaw guards on `if(!txPathLive)`, not a constant")
        # The guard branch must DO something truthful. In §5 step 4 it now
        # routes to packet mode (a real transmission) and only refuses if that cannot work —
        # so the requirement is that the branch calls replayViaFifo and cannot silently
        # succeed without one of the two outcomes being named.
        gi = body_r.find("if(!txPathLive)")
        seg = body_r[gi:gi+900] if gi != -1 else ""
        check("replayViaFifo" in seg,
              "the no-GDO0 branch routes to packet-mode replay rather than doing nothing")
        check(("return false" in seg) or ("return ok" in seg),
              "the no-GDO0 branch returns an honest result")
        check('tx_path_dead' in rr2, "replayRaw reports reason tx_path_dead")
        # The chip-side confirmation must also exist.
        check("cc_readStatus(0x35)" in body_r,
              "replayRaw confirms TX chip-side (MARCSTATE) rather than assuming the burst ran")
        # And it must NOT be possible to reach `return true` without passing those guards,
        # which we approximate by requiring the guards to appear before the bit-bang loop.
        i_live = body_r.find("txPathLive")
        i_bb   = body_r.find("digitalWrite(PIN_GDO0,st?HIGH:LOW)")
        check(i_live != -1 and i_bb != -1 and i_live < i_bb,
              "the liveness guard precedes the bit-bang loop")

    print("\n=== captures without bit edges are refused ===")
    cs = extract_fn(src, "captureSignal")
    check(cs is not None, "captureSignal extracted")
    if cs:
        body_c2 = re.sub(r"//.*", "", cs)
        check("no-bit-edges" in cs, "captureSignal reports reason no-bit-edges")
        # The predicate was factored into ks_noBitEdges so the live capture
        # and the stored-frame import apply the SAME test. Assert the call site and the
        # predicate separately; a mutation to `if(false)` is still caught because the call
        # must be present, and the arithmetic is checked on the predicate itself.
        check(re.search(r"if\s*\(\s*ks_noBitEdges\s*\(", body_c2) is not None,
              "captureSignal refuses on `if(ks_noBitEdges(...))`, not a constant")
        ui = body_c2.find("ks_noBitEdges(")
        check(ui != -1 and "return false" in body_c2[ui:ui+900],
              "the no-bit-edges refusal sits inside the predicate branch")
        pred = extract_fn(src, "ks_noBitEdges")
        check(pred is not None, "ks_noBitEdges extracted (shared predicate)")
        if pred:
            check(re.search(r"mx\s*\*\s*100\s*<\s*(?:\(uint32_t\)\s*)?mn\s*\*\s*110",
                            pred) is not None,
                  "the shared predicate compares max against min width")
        # It must only apply to the RSSI path: with real GDO0 edges the widths legitimately
        # vary and the test would be meaningless.
        check("lastCapGdo0" in body_c2,
              "the uniform check is gated on the RSSI fallback (not applied to GDO0 captures)")

    print("\n=== the OOK PA pair is an off/on envelope, not one value twice ===")
    # The fault 113 records: PATABLE written {0xC0,0xC0} put OOK logic 0 and logic 1 at the
    # same full power, so the PA never keyed down and the chip radiated a flat carrier with
    # no modulation while every layer reported ok. An OOK envelope needs the two entries to
    # DIFFER, and the guard must refuse a request that would collapse them.
    arm = extract_fn(src, "cc_armOokPA")
    check(arm is not None, "cc_armOokPA extracted")
    if arm:
        body_a = re.sub(r"//.*", "", arm)
        check(re.search(r"\{\s*ookPatLow\s*,\s*ookPatHigh\s*\}", body_a) is not None,
              "the PA table is written from the ookPatLow/ookPatHigh pair, not a literal")
        check("pa[0]!=pa[1]" in body_a.replace(" ", ""),
              "the read-back refuses a pair whose two levels are equal")
    check("ookPatLow" in src and "ookPatHigh" in src,
          "the OOK level pair exists as settings the boot and TX paths share")
    check(re.search(r"uint8_t\s+ookPatLow\s*=\s*0x00", src) is not None
          and re.search(r"uint8_t\s+ookPatHigh\s*=\s*0xC0", src) is not None,
          "the pair defaults to an off/on level (0x00 / 0xC0), which differ")
    # cc_init must write the same pair, not a literal that could drift from the guard's.
    ci = extract_fn(src, "cc_init")
    if ci:
        check(re.search(r"\{\s*ookPatLow\s*,\s*ookPatHigh\s*\}", re.sub(r"//.*", "", ci)) is not None,
              "cc_init writes the same OOK pair as the TX guard")
    # pa_check must expose the envelope verdict, and the live setter must refuse L==H.
    check('envelope_ok' in src, "pa_check reports envelope_ok")
    check("OOK_LEVELS_EQUAL_NO_ENVELOPE" in src,
          "pa_check names the equal-levels (flat-carrier) fault, which PA_LEVELS_PRESENT missed")
    check('op=="ookpa"' in src, "the ookpa command exists to set the pair live")
    op = src.find('op=="ookpa"')
    seg_op = src[op:op+1600] if op != -1 else ""
    check("levels-equal" in seg_op,
          "ookpa refuses a request whose levels are equal rather than flattening the envelope")

    print("\n=== changelog records the packet-mode round ===")
    # Version-agnostic: the packet-mode round introduced this content, and it must still be
    # documented under SOME changelog header. Pinning v3.72 broke the moment v3.73 was
    # released, which is noise rather than a check — the same mistake the keeloq test fixed.
    check("v3.72" in src, "the v3.72 (packet-mode) changelog entry still exists")
    for k in ("patable", "MARCSTATE 19", "tx_path_dead", "no-bit-edges", "FIFO"):
        check(k.lower() in src.lower() or k in src, f"the changelog/round mentions {k}")
    # FW_VER must name a version that has a changelog header, whatever that version is.
    import re as _re
    _m = _re.search(r'#define\s+FW_VER\s+"FOBworks for SGP v(\d+\.\d+)"', src)
    check(bool(_m), "FW_VER is defined in the expected form")
    if _m:
        check(f"// v{_m.group(1)} " in src,
              f"FW_VER v{_m.group(1)} matches a changelog entry")

    print()
    if FAILS:
        print(f"PACKET TX CHECKS FAILED ({len(FAILS)} failures)")
        return 1
    print("packet-mode TX register checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
