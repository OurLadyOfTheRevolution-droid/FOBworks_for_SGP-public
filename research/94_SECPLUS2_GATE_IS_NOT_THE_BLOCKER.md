# 94 — The Security+ 2.0 gate was never the blocker; the bit-slicer is

Status: closed, host-verified, no firmware change. `89` recorded the last open P9 item as
"the Security+ 2.0 gate width": the three Chamberlain/LiftMaster raw pulls (`893LM`,
`893MAX` at 390 MHz, `2668A` at 315 MHz) score `cA` inside the gate's 200–320 window but
measure `ratio` 10.5–12.4 against a ceiling of 2.5, so `ks_decodeSecPlusV2` never fires and
the note left open whether the gate was too narrow or whether the decoder wanted a
pre-trimmed symbol pair.

It wants neither. The captures are fine; they carry the full data pulse set at roughly
250 µs and 500 µs. What defeats the decoder is upstream of the gate, in the shared capture
front-end: the sparse long pulses that separate the packets drag the second `k-means`
centroid past 2.8 ms, the `ks_mkBits` threshold that centroid implies sits above *every*
data pulse, every symbol is sliced to one bit, the bit stream turns alternating, and
`ks_manchester` — which resets its accumulator the moment it sees two equal consecutive
bits — emits 8–50 bits instead of 124. The decoder is then never called. `ratio` 10.5–12.4
is a symptom of exactly that, so widening the gate could not help even in principle.

Read with `89` (which found the three captures and left this open) and `40` (the same
defect shape in the Toyota gate: a guard measured against the wrong population).

## 1. The symbol geometry the captures actually hold

Pulse-width histogram of the first 2048 pulses, bucketed to 50 µs below 600 µs, 500 µs
above:

| capture | MHz | ~200–300 µs | ~450–550 µs | 1.0–4.5 ms | > 5 ms (gap) |
| --- | --- | --- | --- | --- | --- |
| `893LM` raw | 390 | 1242 | 365 | 43 | 65 |
| `893MAX` raw | 390 | 921 | 319 | 48 | 49 |
| `2668A` | 315 | 1543 | 457 | 0 | 26 |

Two well-populated symbol clusters a factor of two apart — precisely the shape the gate
wants (it was written for `ratio` 1.5–2.5) — plus a long, thin tail of 1.0–4.5 ms
separators and the multi-millisecond inter-frame gaps. The 2:1 split is the Security+ 2.0
symbol convention: a Manchester half-bit near 250 µs and a doubled one near 500 µs.

## 2. What the shipped preprocessing does to it

`decodeSignal` clusters with pulses `<= 5000 µs` retained and derives the bit-slicer
threshold as `(cA + cB) / 2`. On the whole 2048-pulse window the separators are dense
enough to anchor `cB`:

| capture | `cA` | `cB` | `ratio` | `thr = (cA+cB)/2` | `bLen` | `ml` |
| --- | --- | --- | --- | --- | --- | --- |
| `893LM` raw | 246 | 2848 | 11.58 | 1547 | 512 (cap) | 8 |
| `893MAX` raw | 280 | 3484 | 12.44 | 1882 | 512 (cap) | 18 |
| `2668A` | 311 | 3280 | 10.55 | 1795 | 512 (cap) | 50 |

`thr` of 1547–1882 µs is above every data pulse in the capture (the largest symbol is
~500 µs; the largest non-gap pulse under 5 ms is ~4.5 ms and is rare). So `ks_mkBits`
marks each symbol `reps = 1`, one bit per symbol, and starts `hi = true` — the stream is
alternating by construction. `ks_manchester` needs `10` then `01`; strict alternation
gives it `10` then `10` and it resets on the second pair, yielding 8–50 bits. The gate at
line ~9341 requires `ml >= 124` before it will even call the decoder, so the decoder is
unreachable on all three.

The `ratio` ceiling is not a second, independent defect — it is the same separator tail
seen through the cluster ratio. Both symptoms have one cause: the front-end assumes the
capture's second cluster is a symbol width, and here it is a separator.

## 3. The decoder is correct; only the front-end is wrong

Two host measurements isolate the fault. Extracted verbatim from the sketch and driven by
a small harness:

- **Direct 124-bit stream.** A stream built from two `sp2_half`-passing 62-bit halves
  decodes through `ks_manchester(124)` + `ks_decodeSecPlusV2`, and the exactly-aligned
  pair recovers serial and button to the bit (`sn=0xCE92A530`, `btn=159`, matching the
  expected values from `sp2_half`). The base-3 unpack, mix inversion, mix order, and
  serial assembly are all correct given a well-formed stream.
- **Corrected preprocessing.** Re-clustering on the dense population only (`<= 1000 µs`,
  which excludes the separator tail) puts `cB` back on a symbol width rather than a
  separator. On the 2048-pulse window the dense clusters are `cA` 195–306, `cB` 517–974,
  `ratio` 2.28–3.18 — the second centroid returns to hundreds of µs instead of the
  multi-millisecond separator cluster the whole-window clustering produces. (The figure is
  window-sensitive because the capture fronts are noisy, but in every window `cB` is a
  symbol width again; the number that matters is that, not the exact ratio.) A `thr`
  between the two symbols then lets `ks_mkBits` emit one Manchester half-bit per symbol.

So the whole decode chain is sound. The failure is entirely `thr` being computed from a
`cB` that a separator tail displaced, over a 1000 µs-plus window. Widening the Sec+ 2.0
gate cannot fix it; the fix, if it is made, belongs in how `thr` is chosen and how the
window is bounded.

## 4. Even a perfect slicer runs out of capture

With `thr` correct, `ks_manchester` still returns only 8–78 bits, because `ks_mkBits` caps
at `CAP_SZ` and the shipped capture buffers truncate the window to that many pulses. A
single Sec+ 2.0 transmission is 40 symbols of preamble (each 3 symbols) plus two
interleaved 62-bit packets plus the per-packet separators: on the order of 370 pulses, and
`ks_manchester` needs two input bits per output bit, so ≥ 248 sliced bits — and it must
start on a code half-bit, not a preamble or separator. The 2048-pulse pull is enough by
about 5×, but the `CAP_SZ`-bounded front-end window is not, and the capture must be
trimmed to a single packet's start. That is the "trimmed input" `89` suspected, but it is
needed for length and alignment, not because the gate is narrow.

## 5. Why no change was shipped

The only lever that would help — moving `thr` off the separator cluster or re-clustering on
the dense population — is the shared front-end that every PWM decoder in the sketch
depends on. Re-tuning it for Sec+ 2.0 risks the KeeLoq, CAME, Somfy, Nice and Toyota
paths that were each tuned against the corpus in `40`, `78`, `93`. That is a
corpus-wide refactor with a full regression before/after, not a targeted fix, and this
capture set cannot validate it: the pulls are single packets of one button with no known
serial ground truth (the Flipper `_code` files turn out to carry neither the decoded key
nor a Manchester payload — they hold 17–18 raw pulse times and a `Secplus_packet_1:`
header that is truncated mid-packet, so there is nothing to compare a decode against). A
change here would be unfalsifiable on this evidence.

What is recorded instead, so nobody re-derives it:

- The Sec+ 2.0 gate width is **not** an open item. The gate is correct for its input; the
  input is misframed.
- `cB`/`ratio` 10.5–12.4 on these captures is the separator tail, not the symbol pair.
- The decoder is verified correct against a synthetic well-formed stream.
- A real fix needs (a) separator-robust clustering, (b) a window trimmed to a single
  packet, and (c) a real fob or a published Sec+ 2.0 frame to validate against. Absent
  (c), a change is unverifiable.

This keeps `89`'s diagnostic observation (the 315 MHz `2668A` pull also satisfies the
Toyota soft-path frequency window and would be claimed by Toyota ahead of SecPlus in the
dispatch order) on the record, but reclassifies the gate item from "unresolved gate width"
to "resolved: gate not at fault".
