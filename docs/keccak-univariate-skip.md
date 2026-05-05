# Univariate Skip for the Keccak GKR Prover

**Status:** Implemented and tested for skip=1..4. Produces the same transcript format as the
standard prover (degree-2 MLE-check for every variable), so the verifier is unchanged.

## Motivation

After the first sumcheck round, the `FusedRoundProver` expands u64 words (200 bytes/instance)
to GF(2^128) block tables (25,600 bytes/instance) — a 128x memory blowup. The idea is to keep
data in u64 word form for multiple sumcheck rounds ("skipping" the expansion), deferring the
block-table creation until fewer instances remain.

With skip=k, the block-table phase starts with h/2^k instances instead of h/2, reducing memory
footprint by 2^(k-1). For k=3, that's a 4x reduction in block-table instances.

## How It Works

### Standard approach (skip=0)

```
Round 0: evaluate from h word pairs → fold to h/2 block-table instances
Rounds 1..n-1: evaluate from blocks → fold → ...
```

### With skip=k

```
Round 0: standard word-pair evaluation (fast popcount path)
Rounds 1..k-1: fold 2^j sub-instances per virtual pair using lookup table → block-pair eval
After round k-1: fold all k challenges at once → h/2^k block-table instances
Rounds k..n-1: standard block-table evaluation
```

The key insight is that after virtually binding variable n-1 with challenge r₀, the round-1
evaluation for variable n-2 involves groups of 4 original instances. Each virtual "lo" value
is a linear combination `(1+r₀)·word_a + r₀·word_b`, which is a field element — not a u64
word. But since each input bit is binary, the folded field value for each bit position depends
only on the *pattern* of bits across the sub-instances.

For round j (processing variable n-1-j), each virtual pair involves 2^j sub-instances per
half. The sub-instance bits form a 2^j-bit pattern, and the folded value is looked up from
a precomputed `2^(2^j)`-entry table indexed by that pattern.

### Lookup table construction

Given j previous challenges (r₀, ..., r_{j-1}), the folding weight for sub-instance v is:

```
w_v = ∏ᵢ eq₁(rᵢ, vᵢ) = ∏ᵢ (rᵢ·vᵢ + (1+rᵢ)·(1+vᵢ))
```

The lookup table maps each 2^j-bit pattern p to the folded field value:

```
table[p] = Σ_{j: bit j of p is 1} w_j
```

Table construction uses the recurrence `table[p] = table[p ^ lsb(p)] + w_{lsb(p)}`,
which runs in O(2^(2^j)) time.

### Instance addressing

For round j of the skip, the 2^j sub-instances per virtual half are at offsets determined
by the strides of the j previously processed variables:

```
stride_i = 2^(n-1-i)   for i = 0, ..., j-1
```

Sub-instance v within a virtual half at base index `base` has original index:

```
base + Σᵢ vᵢ · stride_i
```

### Table sizes

| Skip round j | Sub-instances per half | Table entries |
|---:|---:|---:|
| 0 | 1 | 2 (trivial, not used) |
| 1 | 2 | 4 |
| 2 | 4 | 16 |
| 3 | 8 | 256 |
| 4 | 16 | 65,536 |

For k ≤ 4, all tables fit comfortably in L1 cache.

## Verifier

The skip prover produces the same transcript as the standard prover: one degree-2
round polynomial per variable, using the standard MLE-check format. The verifier
(`verify_round_with_skip`) calls `mlecheck::verify` with degree=2 exactly as the
standard verifier does. No verifier changes are needed.

## Files

- [`crates/keccak-check/src/skip_round.rs`](../crates/keccak-check/src/skip_round.rs) — skip-aware
  prover and verifier for one fused round
- [`crates/keccak-check/src/protocol.rs`](../crates/keccak-check/src/protocol.rs) — `prove_skip` and
  `verify_skip` protocol-level drivers

## Performance Model

For skip=k at batch h = 2^n:

**Standard prover cost:**
- Round 0 (word-based): h/2 pairs × ~600 field muls ≈ 300h
- Rounds 1..n-1 (block-based): ~2h pairs total × ~6500 field muls ≈ 13000h
- Block creation: h/2 blocks × ~6400 ops ≈ 3200h

**Skip-k prover cost:**
- Round 0 (word-based): h/2 pairs × ~600 field muls ≈ 300h
- Rounds 1..k-1 (word+lookup): Σ_{j=1}^{k-1} h/2^{j+1} pairs × (1600·2^j + 6500) ops
- Block creation: h/2^k blocks × ~6400·2^k ops
- Remaining block rounds: ~2h/2^{k-1} pairs × ~6500 ops

The skip saves by reducing the block-table instance count from h/2 to h/2^k, cutting
the dominant block-table allocation and cache pressure. The lookup-table overhead is
small relative to the field-arithmetic savings on the block rounds.
