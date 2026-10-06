#!/usr/bin/env python3
"""Run the C2 RollBack capture bench against a real fob.

Needs a Kia/Hyundai/Genesis V3 or V4 fob and the card tuned to 315 MHz — that is
where the frame trim has measured constants. For any other protocol expect
reason="untrimmed-block", which is the gate working, not a bug.

Typical run:

    python3 bench_c2_capture.py                    # capture + arm, report only
    python3 bench_c2_capture.py --fire             # also transmit the pair
    python3 bench_c2_capture.py --freq 433.92      # other band

What it checks and prints:
  1. the card's self-tests, so a bad image is caught before interpreting anything
  2. each captured entry's `trimmed` — whether the block is ONE frame or several
  3. the rollback_arm reason, which names the check that failed

Transmitting is opt-in because `--fire` puts RF on the air at the target's own
frequency; arming alone is read-only.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEND = HERE / "bench_send.py"


def send(cmd, listen=2.5, **fields):
    """Invoke bench_send.py and return (dict_of_replies, raw_text)."""
    argv = [sys.executable, str(SEND), cmd, "--listen", str(listen)]
    argv += [f"{k}={v}" for k, v in fields.items()]
    p = subprocess.run(argv, capture_output=True, text=True)
    replies = []
    for line in p.stdout.splitlines():
        if line.startswith("<<< "):
            body = line[4:].strip()
            if body.startswith("{"):
                try:
                    replies.append(json.loads(body))
                except json.JSONDecodeError:
                    pass
    return replies, p.stdout


def pick(replies, key):
    """Newest reply that actually carries `key` — the serial stream interleaves."""
    for r in reversed(replies):
        if key in r:
            return r
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--freq", type=float, default=315.0)
    ap.add_argument("--fire", action="store_true",
                    help="transmit the pair after arming (puts RF on the air)")
    ap.add_argument("--gap-ms", type=int, default=120)
    ap.add_argument("--wait", type=int, default=90,
                    help="seconds to wait for two captures (default 90)")
    args = ap.parse_args()

    print("=" * 68)
    print(" C2 RollBack bench — real fob, real capture")
    print("=" * 68)

    # 1. Confirm the image is good before trusting anything else.
    replies, _ = send("status")
    st = pick(replies, "kl_selftest")
    if not st:
        print("FAIL: no status reply. Is the card booted and the token current?")
        return 1
    checks = {
        "kl_selftest": st.get("kl_selftest"),
        "kl_parse_ok": st.get("kl_parse_ok"),
        "kl_deriv_ok": st.get("kl_deriv_ok"),
        "kia_v34_ok": st.get("kia_v34_ok"),
    }
    print(f"\n[1] self-tests: {', '.join(f'{k}={v}' for k, v in checks.items())}")
    if not all(checks.values()):
        print("    FAIL: a boot self-test is red. Do not interpret the capture.")
        return 1
    print("    all green")

    # 2. Tune to the band the Kia trim constants were measured in.
    replies, _ = send("setfreq", f=f"{args.freq:.3f}")
    got = pick(replies, "sweep_min")
    if not got or abs(got.get("freq", 0) - args.freq) > 0.01:
        print(f"    FAIL: could not tune to {args.freq:.3f} MHz")
        return 1
    print(f"\n[2] tuned to {got['freq']:.3f} MHz "
          f"(sweep {got.get('sweep_min')}-{got.get('sweep_max')})")

    # 3. Arm FOBback and wait for two presses.
    send("fbk_arm")
    print(f"\n[3] FOBback armed. PRESS THE KIA FOB TWICE, ~1 s apart.")
    print(f"    waiting up to {args.wait}s ...")
    n = 0
    deadline = time.monotonic() + args.wait
    while time.monotonic() < deadline:
        replies, _ = send("fbk_status", listen=1.5)
        st = pick(replies, "sigs")
        if st is None:
            time.sleep(1.0)
            continue
        n = st.get("n", 0)
        print(f"      captured {n}/2", end="\r", flush=True)
        if n >= 2:
            break
        time.sleep(1.0)
    print()

    replies, _ = send("fbk_status", listen=2.0)
    st = pick(replies, "sigs")
    if not st or st.get("n", 0) < 2:
        print(f"    FAIL: only {n} capture(s). Press twice more; if it stays 0 the "
              f"fob may be FSK or outside {args.freq:.2f} +/- 0.15 MHz.")
        return 1

    # 4. This is the result the doc's P1 gate is about.
    print(f"\n[4] captures ({st['n']}):")
    all_trimmed = True
    for sig in st["sigs"]:
        t = sig.get("trimmed")
        all_trimmed &= bool(t)
        print(f"      idx={sig['idx']} freq={sig['freq']} len={sig['len']:4d} "
              f"trimmed={t} has_ctr={sig.get('has_ctr')}")
    if all_trimmed:
        print("    -> both blocks are ONE frame: the trim applied, so the fob is")
        print("       consistent with the measured Kia V3/V4 pitch.")
    else:
        print("    -> at least one block is MULTI-REPEAT. This fob is not at the")
        print("       measured pitch. The arm gate must now refuse it.")

    # 5. Arm. Read-only; nothing transmits here.
    replies, _ = send("rollback_arm")
    arm = pick(replies, "armed")
    print(f"\n[5] rollback_arm -> {json.dumps(arm)}")
    if not arm or not arm.get("ok"):
        reason = (arm or {}).get("reason")
        print(f"    REFUSED, reason={reason!r}")
        if reason == "untrimmed-block":
            print(" This is the gate doing its job: before it, the card")
            print("    would have transmitted a 3-repeat block with no indication.")
            print("    The trim needs this fob's pitch measured before it can work.")
        return 0
    print("    armed")

    if not args.fire:
        print("\n[5b] not firing (pass --fire to transmit). Arm state is read-only.")
        send("rollback_arm")   # harmless re-arm note
        return 0

    # 6. Transmit. This is the transmit path C1/C2 were built around.
    print(f"\n[6] rollback_fire gap_ms={args.gap_ms} — TRANSMITTING on "
          f"{args.freq:.3f} MHz. Watch your receiver now.")
    replies, _ = send("rollback_fire", listen=4.0, gap_ms=args.gap_ms)
    fired = pick(replies, "state")
    print(f"    -> {json.dumps(fired)}")
    if fired and fired.get("state") == "sent1":
        print("    code 1 sent; code 2 follows after the gap")
        time.sleep(args.gap_ms / 1000.0 + 3.0)
    replies, _ = send("rollback_status", listen=3.0)
    fin = pick(replies, "phase")
    print(f"    final: {json.dumps(fin)}")
    print("\n    If your receiver acted on the pair, C2 works. If it did nothing and")
    print("    the codes were trimmed from a real rolling fob, suspect the replay")
    print("    timing or that the receiver had already moved on.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
