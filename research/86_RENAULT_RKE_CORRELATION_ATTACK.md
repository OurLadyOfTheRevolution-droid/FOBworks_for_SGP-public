# 86 — Renault V1 Layer 2: the correlation attack, ported and measured

Status: closed Layer 2 with two negative results — the ProtoPirate
epoch/seed model is exhausted over all 2^32 IVs, and none of the reference's eight
dictionary keys reproduces a hop — and concluded that "the wire cannot yield it"
and that side-channel key extraction is the only route. This note records the one
model that was never tested and what happens when it is. The short version: the
correct model is the keyed PCF7946/7947 rolling code, the correlation attack of
Garcia et al. is the right instrument, the port is validated end to end, and the
corpus is one capture short of the attack's floor — by measurement, not assumption.

## What the earlier notes missed

The wire frames are not a seed/epoch scheme. A 2011 Trafic remote is an NXP
PCF7946/7947: an 8-bit µC with a Hitag2 stream cipher, and its rolling code is
*keyed*. That scheme is documented in Garcia, Oswald, Kasper & Pavlides ("Lock It
and Still Lose It", USENIX Security 2016, Section 4) and revisited in Benadjila et
al. ("One Car, Two Frames", WOOT'17, Section 3.3). The packet is 104 bits:

```
SYNC(16) UID(32) BTN(4) CNTRL(10) KS(32) CHK(8)
```

The cipher is seeded with the 32-bit UID and the low 16 key bits; the 32-bit IV is
`iv = (CNTRH || CNTRL || BTN)`, i.e. `((CNTRH<<10 | CNTRL) << 4) | BTN`; the wire
`KS` is the first 32 keystream bits. The corpus frames carry UID, BTN, CNTRL and
KS; only `CNTRH` (18 bits) and the 48-bit key are secret. Garcia et al. recover the
key from four to eight such frames. The corpus has five, with a counter walk of +1.

The counter-high guess is not even needed. WOOT'17 proves an equivalent-key
property: the cipher run with IV `(CNTRH||CNTRL||BTN)` and key `k` gives the same
keystream as the run with IV `(0||CNTRL||BTN)` and key `k' = k ^ (0^16 || CNTRH || 0^14)`.
Zeroing the unknown high part yields an *equivalent* key that reproduces the
genuine keystream while `CNTRH` is unchanged — and five consecutive presses live
inside one 1024-press block, so `CNTRH` is constant across them. So the attack
needs no counter-age guess and no 2^18 sweep. That is the piece did not
have, and it is why "the wire cannot yield it" was the wrong conclusion to draw.

## The tool

`tools/renault_hitag2_rke_crack.py` is self-contained: it embeds a C++ program that
implements the cipher from the paper's own definition (Definition 4.4 / Appendix A)
and the Section 4.4 correlation attack, and drives both from a capture. The attack
loop is a faithful port of proxmark3's `ht2crack4` (`tools/hitag2crack/crack4`)
with the one change the RKE scheme forces: the IV is public — it is the button and
the counter, both on the wire — and is inserted in plain, where the immobilizer
version recovers it from an encrypted reader nonce.

Three modes:

* `--selftest` — generate random keys, identifiers and counter runs, compute the
  keystream with the paper's cipher, and require the attack to return the key. This
  is the honesty check: a pass means a corpus negative is a statement about the
  corpus, not about the code.
* the default — decode the capture and run the attack over the small set of
  plausible wire conventions (UID byte/bit order, KS bit order and complement, and
  the two IV layouts seen in the field).
* `--scan` — walk every capture in the corpus and report how many Hitag2 frames
  each yields, so the question "is there a better capture than the Trafic one" is
  answered from the data.

## Validation

Two independent checks, both in the shipped tool:

1. **Cipher sanity.** The twenty-bit filter built from the paper's boolean tables
   (`fa = 0xA63C`, `fb = 0xA770`, `fc = 0xD949CBB0`, index read most-significant
   bit first) must agree with the pipelined form and with the packed form on
   200,000 random states. It does: 0 mismatches. This is what pins the reading of
   the table convention, which is the classic place to get Hitag2 wrong.
2. **Round trip.** The attack recovers the key from keystream it did not generate.

Measured recovery on synthetic data (8-bit and 17-bit runs above the floor, table
400k, consecutive-counter traces like the corpus):

| traces | consecutive (corpus case) | recovered |
|--------|---------------------------|-----------|
| 5      | yes                       | 1/8       |
| 6      | yes                       | 1/8       |
| 8      | yes                       | 3/8       |
| 8      | spread over the counter   | 2/3       |

Enlarging the table does not change the consecutive case: 5 traces at table 2M is
still 1/12. This matches the paper's own caveat that consecutive traces "often only
differ in a few bits from each other, thus providing less correlation information",
with the number needed "usually eight". The attack's floor is data, not compute.

## Result on the corpus

`--scan` finds exactly two captures in the whole 323-file corpus that decode as
Hitag2 — the two copies of the Trafic 2011 file — and both yield the same five
consecutive frames (`uid 3270FD2B btn 2 cnt 15C..160`). Running the attack:

```
frames decoded: 5
running the Section 4.4 correlation attack (table=400000, traces=5)
no key from any convention
```

Swept: 4 UID readings × 2 KS bit orders × 2 KS complements × 2 IV layouts = 32
conventions, every one validated against all five frames. Then table sizes up to
5M (12× the reference default). No hit.

This is the expected result, not a failure of the instrument. The corpus is a
single hand-bench recording of one remote. Its five frames are *consecutive*, which
is precisely the case the paper says is hardest, and the measured success at five
consecutive traces is ~12%. A miss was the most likely single outcome; the point of
this pass is that the miss is now quantified and the tool is correct, so the way
forward is a capture, not more analysis.

## What is actually open now

* **Capture more frames.** The correlation attack wants eight distinct frames (or
  fewer if the counters are spread out). Eight consecutive presses of one remote is
  the whole gap — a five-minute job with a compatible receiver, and the reason the
  paper's "selective jamming during the final checksum byte" trick exists: it makes
  the owner press repeatedly while the code is captured but not accepted.
* **The receive path.** This board still cannot capture a Hitag2 frame on air
  (RSSI-edge mode, unrouted GDO0). The live leg is blocked on
  hardware, unchanged.
* **The 20-file ~66 µs Renault family.** Physically distinct from Hitag2 and still
  unidentified. Unrelated to this result.

The tool takes a capture argument, so any future `.sub` — from this bench once the
receive path allows, or from any other receiver — drops straight in:

```
python3 tools/renault_hitag2_rke_crack.py /path/to/capture.sub
python3 tools/renault_hitag2_rke_crack.py --selftest --ntr 8   # validate the port
python3 tools/renault_hitag2_rke_crack.py --scan               # size up the corpus
```
