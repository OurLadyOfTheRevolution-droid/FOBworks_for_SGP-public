#!/usr/bin/env python3
"""Clone-chip classifier for KeeLoq bursts.

The question: given a handful of frames from one fob, can a receiver say whether
the transmitter is a clone chip rather than an OEM HCS part, without the key?

Three legs, in order of how much they prove:

  1. Counter-linearity (exact). Every KeeLoq field except the hop is plaintext,
     and two presses of one button differ only in the counter, so
     hop_xor = E(ptA) ^ E(ptB) and ctr_xor = ctrA ^ ctrB. For a real cipher the
     two are equal only by a 2^-32 accident. For a *clone that never runs the
     cipher* — hop = counter, or hop = counter ^ constant — they are equal on
     every pair, because XOR with a constant cancels. hop_xor == ctr_xor is
     therefore a structural proof that the hop field is an XOR function of the
     counter, not a cipher output.

  2. Sparsity (statistical). Even when the clone adds an arithmetic constant or
     a weak mixer, the hop still tracks the counter, so popcount(hop_xor) stays
     tiny. Real KeeLoq is a 32-bit block cipher: for two plaintexts one apart the
     output difference is essentially uniform, so popcount(hop_xor) is Binomial(32,
     1/2) — mean 16, and the chance of 8 or fewer flipped bits is under 1%. The
     classifier measures the median over same-button pairs and separates the two
     bands.

  3. Discrimination and consensus (bookkeeping). A real HCS encoder keeps a fixed
     non-zero 12-bit discrimination value and a fixed status field across presses
     (Microchip AN661); a sloppy clone sometimes drops or drifts them. The vote is
     the same one the firmware runs for intra-burst consensus (N10).

What this does NOT do: catch a competent clone that runs the real KeeLoq cipher
with a clone key. Such a device has a dense hop_xor identical in distribution to
an OEM part, so no structural test from the wire can tell them apart — the only
handle is recovering the (constrained) clone key, which is `tools/keeloq_slide_lab.py`
and is a separate, key-space test. The classifier says this out loud and routes a
"cipher-consistent" verdict at the harvest rather than claiming an OEM pass means
"genuine".

The tool is self-contained: it generates synthetic OEM / clone frames for the
self-test and the demo, and can also score frames the card already decoded.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from keeloq_slide_lab import encrypt  # the same cipher the card runs

# Bands, in flipped-bit counts. Real KeeLoq sits at Binomial(32, 1/2); a clone
# whose hop tracks a +1 counter sits near 2. The gap is the classifier.
SPARSE_MAX = 8    # median <= this -> the hop is not a cipher output
OEM_MIN = 12      # median >= this -> dense, cipher-consistent
MIN_PAIRS = 3     # same-button consecutive pairs needed before the median means much


@dataclass
class Frame:
    """One decoded KeeLoq frame, in the fields the receiver already has.

    sn packs (disc<<4)|btn exactly as the firmware does, so disc and btn are
    recoverable from a real capture without the key.
    """
    sn: int
    hop: int
    btn: int
    ctr: int
    sts: int = 0

    @property
    def disc(self) -> int:
        return (self.sn >> 4) & 0xFFF


def _disc_drift(frames: list[Frame]) -> bool:
    """True if a consecutive counter run carries more than one discrimination value.

    One device pressing one button advances its counter by one, so a run of steps
    of 1 is one device; if the discrimination field changes across that run, the
    encoder is drifting it, which a real HCS part does not do. Walking the sorted
    counters is what makes unique (non-repeated) drift detectable — there is no
    pair of equal discs to compare.
    """
    if len(frames) < 2:
        return False
    order = sorted(frames, key=lambda f: f.ctr)
    for a, b in zip(order, order[1:]):
        step = (b.ctr - a.ctr) & 0xFFFF
        if (step == 1 or step == 0xFFFF) and a.disc != b.disc:
            return True
    return False


@dataclass
class Report:
    verdict: str
    note: str
    have: bool = False
    pairs: int = 0
    step_pairs: int = 0
    sparse_pairs: int = 0
    med_flip: int = 0
    counter_linear: bool = False
    disc_bad: int = 0
    foreign: int = 0
    legs: dict = field(default_factory=dict)


# ─── synthetic devices, for the self-test and the demo ─────────────────────────

def gen_frames(kind: str, disc: int = 0x5A3, btn: int = 3, c0: int = 0x100,
               n: int = 6, key: int = 0xBEEFDEADBEEFDEAD,
               xorconst: int = 0x5A5A) -> list[Frame]:
    """Build a burst for a named device class.

    kind is one of:
      oem               real KeeLoq, real fixed discrimination
      clone-noncipher   hop = counter (no cipher at all)
      clone-xorconst    hop = counter ^ constant
      clone-cipher      real KeeLoq under a clone key (indistinguishable here)
      clone-disc-zero   real cipher, but the discrimination field is dropped
      clone-disc-drift  real cipher, but the discrimination field changes per press
    """
    frames = []
    for i in range(n):
        ctr = (c0 + i) & 0xFFFF
        d = disc
        if kind == "clone-disc-zero":
            d = 0
        elif kind == "clone-disc-drift":
            d = (disc + i) & 0xFFF
        pt = (ctr & 0xFFFF) | ((d & 0xFFF) << 16) | ((btn & 0xF) << 28)
        if kind in ("oem", "clone-cipher", "clone-disc-zero", "clone-disc-drift"):
            hop = encrypt(pt, key)
        elif kind == "clone-noncipher":
            hop = ctr
        elif kind == "clone-xorconst":
            hop = (ctr ^ xorconst) & 0xFFFFFFFF
        else:
            raise ValueError(f"unknown device kind {kind!r}")
        frames.append(Frame(sn=((d & 0xFFF) << 4) | (btn & 0xF), hop=hop, btn=btn, ctr=ctr))
    return frames


# ─── the classifier ────────────────────────────────────────────────────────────

def classify(frames: list[Frame]) -> Report:
    rep = Report(verdict="unknown", note="")
    if len(frames) < 2:
        rep.note = "need at least two frames from the same fob"
        return rep

    # Modal discrimination value scopes the pair analysis: a ring may hold more
    # than one fob, and pairs across different discriminators are not hop-XOR
    # observations.
    discs = [f.disc for f in frames]
    modal = max(set(discs), key=discs.count)
    rep.foreign = sum(1 for f in frames if f.disc != modal)
    rep.disc_bad = 1 if modal == 0 else 0
    if not rep.disc_bad and _disc_drift(frames):
        rep.disc_bad = 1

    # Pair analysis: consecutive presses that share button AND discrimination.
    flips = []
    counter_linear = False
    for a, b in zip(frames, frames[1:]):
        if a.disc != modal or b.disc != modal:
            continue
        if a.btn != b.btn:
            continue
        hop_xor = a.hop ^ b.hop
        ctr_xor = a.ctr ^ b.ctr
        if hop_xor == ctr_xor:
            counter_linear = True
        flips.append(bin(hop_xor).count("1"))

    rep.pairs = len(flips)
    rep.counter_linear = counter_linear
    rep.sparse_pairs = sum(1 for w in flips if w <= SPARSE_MAX)
    # Median computed before any short-circuit, so the emitted med_flip is the
    # same number the verdict rests on. Upper-middle on an even count, matching
    # ks_cloneClassify()'s s[nf/2] exactly — statistics.median averages the two
    # middle values, which would put the host tool a bit off the card.
    med = sorted(flips)[len(flips) // 2] if flips else 0
    rep.med_flip = med
    rep.step_pairs = sum(
        1 for a, b in zip(frames, frames[1:])
        if a.disc == modal and b.disc == modal and a.btn == b.btn
        and ((b.ctr - a.ctr) & 0xFFFF) in (1, 0xFFFF))

    rep.have = rep.pairs >= MIN_PAIRS
    rep.legs = {
        "counter_linear": counter_linear,
        "med_flip": med,
        "sparse_pairs": rep.sparse_pairs,
        "step_pairs": rep.step_pairs,
        "disc_bad": rep.disc_bad,
        "foreign": rep.foreign,
    }

    # Verdict, most-proven first, in the same order ks_cloneClassify() uses.
    if counter_linear:
        rep.verdict = "non-cipher-clone"
        rep.note = ("hop_xor equals ctr_xor on a same-button pair: the hop field is the "
                    "counter under XOR, not a cipher output — structural proof, key-free")
    elif rep.disc_bad:
        rep.verdict = "clone-suspect"
        rep.note = ("discrimination field is zero or drifts across presses of one device; "
                    "a real HCS encoder keeps it fixed and non-zero (AN661)")
    elif not rep.have:
        rep.verdict = "unknown"
        rep.note = f"only {rep.pairs} same-button pair(s); need {MIN_PAIRS} for a median"
    elif med <= SPARSE_MAX:
        rep.verdict = "non-cipher-clone"
        rep.note = (f"median hop_xor is {med} bits: too sparse for a cipher "
                    f"(real KeeLoq sits near 16); the hop tracks the counter")
    elif med >= OEM_MIN:
        rep.verdict = "cipher-consistent"
        rep.note = ("hop_xor is dense (median >= 12): consistent with real KeeLoq; a clone "
                    "running the real cipher is NOT distinguishable here — try the hop-XOR "
                    "harvest to test a constrained clone keyspace")
    elif rep.sparse_pairs * 2 >= rep.pairs:
        rep.verdict = "non-cipher-clone"
        rep.note = "median sits between the bands but most pairs are sparse"
    else:
        rep.verdict = "unknown"
        rep.note = (f"median hop_xor is {med} bits, between the clone and cipher "
                    f"bands; more presses or a cleaner capture would settle it")
    return rep


# ─── CLI ───────────────────────────────────────────────────────────────────────

def _report_text(rep: Report) -> str:
    out = [
        f"verdict: {rep.verdict}",
        f"  {rep.note}",
        f"  pairs={rep.pairs} step_pairs={rep.step_pairs} sparse_pairs={rep.sparse_pairs}",
        f"  med_flip={rep.med_flip} counter_linear={rep.counter_linear} "
        f"disc_bad={rep.disc_bad} foreign={rep.foreign}",
    ]
    return "\n".join(out)


def _cmd_selftest() -> int:
    """Every synthetic class must land on the verdict it was built for."""
    expect = {
        "oem": "cipher-consistent",
        "clone-cipher": "cipher-consistent",   # honest: not distinguishable
        "clone-noncipher": "non-cipher-clone",
        "clone-xorconst": "non-cipher-clone",
        "clone-disc-zero": "clone-suspect",
        "clone-disc-drift": "clone-suspect",   # one counter run, disc moves: caught here
    }
    ok = True
    for kind, want in expect.items():
        rep = classify(gen_frames(kind))
        good = rep.verdict == want
        ok &= good
        print(f"  {'ok  ' if good else 'FAIL'} {kind:18s} -> {rep.verdict:16s} "
              f"(want {want}, med_flip={rep.med_flip})")
    # The statistical leg must hold across many random keys.
    for _ in range(20):
        key = int.from_bytes(os.urandom(8), "big")
        rep = classify(gen_frames("oem", key=key))
        if rep.verdict != "cipher-consistent":
            print(f"  FAIL random OEM key {key:016X} -> {rep.verdict} (med_flip={rep.med_flip})")
            ok = False
    print(f"  {'ok  ' if ok else 'FAIL'} 20 random OEM keys stay cipher-consistent")
    return 0 if ok else 1


def _cmd_demo(args: argparse.Namespace) -> int:
    for kind in ("oem", "clone-noncipher", "clone-xorconst", "clone-cipher"):
        print(f"== {kind} ==")
        print(_report_text(classify(gen_frames(kind))))
    return 0


def _cmd_frames(args: argparse.Namespace) -> int:
    """Score frames the card already decoded, from a JSON file.

    Accepts either the firmware's hop_xor dump ({frames:[{sn,hop,btn,ctr,...}]}) or
    a bare list of {sn,hop,btn,ctr}. Discriminator may be supplied as `disc`.
    """
    doc = json.loads(Path(args.json).read_text())
    rows = doc["frames"] if isinstance(doc, dict) and "frames" in doc else doc
    frames = []
    for r in rows:
        sn = r.get("sn")
        if sn is None and "disc" in r:
            sn = ((r["disc"] & 0xFFF) << 4) | (r.get("btn", 0) & 0xF)
        frames.append(Frame(sn=int(sn), hop=int(r["hop"], 0) if isinstance(r["hop"], str)
                            else int(r["hop"]),
                            btn=int(r.get("btn", 0)), ctr=int(r.get("ctr", 0))))
    rep = classify(frames)
    if args.json_out:
        print(json.dumps(rep.__dict__, indent=2))
    else:
        print(_report_text(rep))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Clone-chip classifier for KeeLoq bursts (N28)")
    sub = p.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("selftest", help="every synthetic class lands on its verdict")
    st.set_defaults(func=lambda a: _cmd_selftest())

    d = sub.add_parser("demo", help="print a verdict for each synthetic class")
    d.set_defaults(func=_cmd_demo)

    f = sub.add_parser("frames", help="score frames from a JSON file")
    f.add_argument("--json", required=True, help="card hop_xor dump or a list of frames")
    f.add_argument("--json-out", action="store_true", help="emit the report as JSON")
    f.set_defaults(func=_cmd_frames)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
