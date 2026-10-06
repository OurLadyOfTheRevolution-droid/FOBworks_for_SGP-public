#!/usr/bin/env python3
"""Renault V1 RKE correlation-attack suite: the port is correct and the corpus
negative is quantified.

research/86_RENAULT_RKE_CORRELATION_ATTACK.md tests the keyed PCF7946/7947 model
that never tried. This suite keeps the two claims honest:

  1. the cipher in tools/renault_hitag2_rke_crack.py matches the paper's boolean
     tables (the classic place to get Hitag2 wrong) — checked over random states;
  2. the Section 4.4 attack actually recovers keys it did not generate, so a miss
     on the corpus means the data is thin, not that the instrument is broken;
  3. the corpus scan finds the Trafic frames and nothing else;
  4. the corpus result is a miss, and the tool says so cleanly.

The attack is stochastic, so the round-trip test uses a fixed seed and a trace
count above the attack's floor (eight spread-counter traces), where recovery is
reliable. The corpus is five consecutive traces, which the tool measures at ~12%;
that is asserted as "a miss happens", not as "a key is found".
"""

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" — {detail}" if detail else ""))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def compile_tool(td):
    tool = load(ROOT / "tools/renault_hitag2_rke_crack.py", "rke_crack")
    cpp = Path(td) / "crack.cpp"
    cpp.write_text(tool.SRC)
    exe = Path(td) / "crack"
    r = subprocess.run(["clang++", "-O3", "-std=c++17", "-pthread", "-w",
                        "-o", str(exe), str(cpp)], capture_output=True, text=True)
    return tool, exe, r


def main():
    with tempfile.TemporaryDirectory() as td:
        tool, exe, comp = compile_tool(td)
        check("tool compiles", comp.returncode == 0, comp.stderr[:300])
        if comp.returncode != 0:
            print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
            print("failed:", ", ".join(FAIL))
            return 1

        # ── 1. cipher sanity: tables must match the pipelined filter ───────
        out = subprocess.run([str(exe), "syn", "--ntr", "1", "--trials", "0"],
                             capture_output=True, text=True)
        check("cipher matches the paper's boolean tables (0 mismatches)",
              "cipher sanity: ok" in out.stderr, out.stderr.strip().splitlines()[0][:80])

        # ── 2. the attack recovers keys it did not generate ───────────────
        out = subprocess.run([str(exe), "syn", "--ntr", "8", "--trials", "3"],
                             capture_output=True, text=True)
        m = re.search(r"selftest: (\d+)/(\d+) recovered \(ntraces=8, spread\)", out.stdout)
        ok = bool(m) and int(m.group(1)) >= 2
        check("attack recovers synthetic keys (8 spread traces)", ok,
              m.group(0) if m else out.stdout.strip()[-80:])

        # a 5-consecutive-trace run is the corpus case: assert the tool runs and
        # reports a result, not that it wins (it usually does not).
        out5 = subprocess.run([str(exe), "syn", "--ntr", "5", "--consec",
                               "--trials", "4"], capture_output=True, text=True)
        check("attack runs the 5-consecutive (corpus) case to completion",
              "selftest:" in out5.stdout and "ntraces=5, consecutive" in out5.stdout)

        # ── 3. the corpus scan finds the Trafic frames and nothing else ───
        scan = subprocess.run([sys.executable,
                               str(ROOT / "tools/renault_hitag2_rke_crack.py"),
                               "--scan"], capture_output=True, text=True)
        check("scan decodes the Trafic Hitag2 frames",
              "5 frame(s)" in scan.stdout and "Trafic 2011" in scan.stdout,
              scan.stdout.splitlines()[1] if len(scan.stdout.splitlines()) > 1 else "")
        check("scan finds no other Hitag2 capture",
              scan.stdout.count("frame(s)") == 2, f"{scan.stdout.count('frame(s)')} entries")

        # ── 4. the corpus attack reports a clean miss ─────────────────────
        run = subprocess.run([sys.executable,
                              str(ROOT / "tools/renault_hitag2_rke_crack.py"),
                              "--tbl", "400000"], capture_output=True, text=True)
        check("corpus attack decodes five frames", "frames decoded: 5" in run.stdout)
        check("corpus attack completes all conventions without a key",
              "no key from any convention" in run.stdout, run.stdout.strip().splitlines()[-1][:60])

    # ── 5. the note ───────────────────────────────────────────────────
    doc = ROOT / "research/86_RENAULT_RKE_CORRELATION_ATTACK.md"
    # is a private worklog and is not published; skip its note checks
    # when it is absent so a fresh clone still gets a green suite.
    if not doc.exists():
        print(" note: skipped (worklog not published)")
    else:
        txt = doc.read_text()
        check("note names the keyed PCF7946/7947 model",
              "PCF7946" in txt and "correlation" in txt)
        check("note records the measured 5-consecutive success",
              "1/8" in txt and "consecutive" in txt)
        check("note records the corpus miss as expected, not a tool failure",
              "expected result" in txt)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
