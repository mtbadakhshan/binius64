# SIMD Optimization for the Keccak GKR Prover

## Background

### Keccak-f[1600]

Keccak-f is the permutation at the heart of the SHA-3 / Keccak-256 hash function. It operates on
a 1600-bit state organized as a 5×5 matrix of 64-bit **lanes** (25 lanes total). Each call applies
24 identical rounds (differing only in a round constant). Each round has five steps:

- **θ (Theta):** XOR each lane with its column parity and a rotated neighbor parity.
- **ρ (Rho):** Rotate bits within each lane by a fixed offset.
- **π (Pi):** Shuffle lane positions (pure relabeling).
- **χ (Chi):** The only nonlinear step: `χ[i,j] = B[i,j] ⊕ B[i+2,j] ⊕ (B[i+1,j] · B[i+2,j])`.
- **ι (Iota):** XOR a round constant into lane (0,0).

Over GF(2) (binary field), θ/ρ/π/ι are all **linear** (degree 1). Only χ has a multiplication
(AND gate), making it **degree 2**. This is why the entire round can be expressed as a single
degree-2 polynomial in the input lanes.

### Multilinear Extensions (MLEs)

To prove Keccak computations using the sumcheck protocol, we represent each lane as a
**multilinear polynomial** (MLE). For `h` parallel Keccak instances, each lane becomes an
`n`-variate polynomial where `n = 6 + log₂(h)`:

```
A[x,y](v₁, ..., v₆, v₇, ..., vₙ)
       ├─ 6 "low" variables ─┤ ├─ log(h) "high" variables ─┤
         index 64 bit positions    index which instance
```

On Boolean inputs `b ∈ {0,1}ⁿ`, the MLE returns the actual bit value:

```
A[x,y](b₁,...,b₆, b₇,...,bₙ) = bit ⟨b₁...b₆⟩ of lane (x,y) in instance ⟨b₇...bₙ⟩
```

The MLE is constructed via the **eq polynomial** (Lagrange basis on the Boolean hypercube):

```
Ã(x) = Σ_{b ∈ {0,1}ⁿ} A(b) · eq(x, b)
```

where `eq(x, b) = ∏ᵢ (xᵢ·bᵢ + (1+xᵢ)(1+bᵢ))`. On Boolean inputs, `eq(a, b)` is the
Kronecker delta (1 if a=b, 0 otherwise). On non-Boolean inputs from GF(2¹²⁸), it produces
arbitrary 128-bit field elements that serve as interpolation weights.

### Why GF(2¹²⁸)?

The sumcheck protocol requires the verifier to sample random challenge points from a large field.
The soundness error per round is `degree / |field|`. Over GF(2), that's 2/2 = 100% — no security.
Over GF(2¹²⁸), it's 2/2¹²⁸ ≈ 0 — negligible. So the sumcheck must operate over GF(2¹²⁸) even
though the Keccak computation itself is over GF(2) (single bits).

This means the prover must **evaluate lane MLEs at random GF(2¹²⁸) points**. Each evaluation
requires multiplying bit values (0 or 1) by GF(2¹²⁸) weights (the eq-indicator values) and
summing them. This bit-to-field conversion is where the bottleneck lies.

### The Sumcheck Protocol in the GKR Prover

The GKR prover runs 24 sequential sumchecks (one per Keccak round). Each sumcheck has `log₂(h)`
interactive rounds. In each round, the prover must:

1. Split the instances into two halves (lo and hi).
2. For each instance pair `(lo[i], hi[i])`, evaluate the fused polynomial
   `chi(linear(input))` at the current challenge point.
3. Accumulate the results weighted by the eq-indicator expansion (`Gruen32`).
4. Send the round polynomial coefficients to the verifier.

Step 2 is the hot inner loop. It calls `fused_chi_linear_word_pair_eval`, which has two phases:

- **Phase 1 (fast):** Compute theta+rho+pi+chi using native u64 bitwise operations.
- **Phase 2 (slow):** Convert the u64 result bits into a weighted GF(2¹²⁸) sum.

## The Bottleneck

### Current implementation

Phase 2 extracts set bits one at a time and accumulates their GF(2¹²⁸) weights:

```rust
// In fused_round.rs, lines 381-386
let mut bits_1 = chi_bits_1;
while bits_1 != 0 {
    let bit = bits_1.trailing_zeros() as usize;
    acc_1 += weight * bit_weights[bit];     // scalar GF(2¹²⁸) multiply (PCLMUL)
    bits_1 &= bits_1 - 1;                   // clear lowest set bit
}
```

**What `bit_weights[bit]` is:** The Lagrange basis weight for bit position `bit` at the verifier's
random challenge point. Mathematically:

```
bit_weights[b] = eq(α₁,...,α₆, b₁,...,b₆)
               = ∏ᵢ₌₁⁶ (αᵢ·bᵢ + (1+αᵢ)(1+bᵢ))
```

where `⟨b₁...b₆⟩ = b` and `α₁,...,α₆` are random GF(2¹²⁸) elements sampled by the verifier.
Each weight is a full 128-bit field element with no special structure.

**What the loop computes:** The weighted MLE evaluation `Σ_{b: word[b]=1} bit_weights[b]`.
This equals `Ã(α)` — the lane MLE evaluated at the random challenge point, restricted to the
current instance.

**Why it's slow:** Each iteration does a GF(2¹²⁸) multiply (PCLMUL instruction), with
data-dependent branching (`trailing_zeros`). With ~32 bits set on average per u64, and 50 such
loops per instance pair (25 lanes × 2 accumulators), that's **~1600 scalar PCLMUL operations
per instance pair**, executed with unpredictable branching that prevents SIMD vectorization.

### Same pattern in all four protocol variants

| File | Function | Pattern |
|------|----------|---------|
| `fused_round.rs:382` | `fused_chi_linear_word_pair_eval` | `while bits != 0 { trailing_zeros; acc += w * bw[bit]; }` |
| `fused_round.rs:389` | same, inf accumulator | identical pattern |
| `fused_round.rs:592` | `FusedRoundProver::finish` | identical pattern |
| `chi_iota.rs:354` | `compose_chi_iota_from_low_vectors` | `for bit in 0..64 { acc += bw[bit] * (...); }` |
| `chi_iota.rs:382` | `compose_chi_iota_pair_from_blocks` | same with lo/hi pairs |
| `oblong_round.rs:101` | `mixed_fused_round_residual_base_from_words` | `while diff != 0 { trailing_zeros; ... }` |

None of the four approaches attempted SIMD optimization for this pattern.

## The Optimization: Byte Lookup Table

### Core idea

Instead of extracting bits one at a time with `trailing_zeros`, decompose the u64 into 8 bytes
and use a precomputed lookup table. For each possible byte value (0..256), the table stores the
precomputed sum of the corresponding `bit_weights` entries.

### The lookup table

```rust
struct ByteWeightTable<F> {
    tables: [[F; 256]; 8],
}
```

For byte position `k` (0..8) and byte value `v` (0..256):

```
tables[k][v] = Σ_{j=0..7, bit j of v is set} bit_weights[8*k + j]
```

Building cost: for each of the 8 byte positions, iterate over 256 values and sum the appropriate
weights. That's 8 × 256 × ~4 additions = ~8192 field additions. Field addition in GF(2¹²⁸) is
just XOR — extremely fast. Rebuild once per `execute()` call (not per instance).

### Using the table

```rust
fn word_dot<F: Field>(word: u64, table: &ByteWeightTable<F>) -> F {
    let mut acc = F::ZERO;
    for k in 0..8 {
        let byte_val = ((word >> (k * 8)) & 0xFF) as usize;
        acc += table.tables[k][byte_val];
    }
    acc
}
```

**8 table lookups + 8 additions** replace **~32 multiplies + branches**.

### Why this is faster

- Field addition (XOR) is ~10x cheaper than PCLMUL on GF(2¹²⁸).
- Fixed 8 iterations instead of variable ~32 iterations.
- No data-dependent branching.
- Cache-friendly: each 256-entry table is 256 × 16 = 4 KB, and all 8 fit comfortably in L1.

### Expected impact

Estimated **~1.7x overall speedup** for the GKR prover, pushing the crossover point with the
CircuitBuilder from ~2¹⁰ to ~2¹⁴–2¹⁵ batch size while maintaining the GKR's ~45x smaller
proof size.

## Files Modified

| File | Change |
|------|--------|
| `crates/keccak-check/src/fused_round.rs` | Added `ByteWeightTable`, replaced bit-extraction loops in `fused_chi_linear_word_pair_eval` and `FusedRoundProver::finish` |
| `crates/keccak-check/src/chi_iota.rs` | Replaced bit-extraction loop in `evaluate_lane_low_vectors_from_words` |
| `crates/keccak-check/src/oblong_round.rs` | Replaced bit-extraction loop in `mixed_fused_round_residual_base_from_words` |

No protocol changes, no mathematical changes, no API changes. Pure inner-loop optimization.

## Experimental Results Summary

All experiments were run on Apple Silicon (AArch64) with `RUSTFLAGS="-C target-cpu=native"`.

### Optimization attempts and outcomes

| Optimization | Hypothesis | Result | Why |
|---|---|---|---|
| Byte lookup table | Bit extraction is the bottleneck | No change | PMULL is already fast on ARM |
| Multiply hoisting | Too many PMULL ops per lane | No change | ~32 PMULLs per lane is cheap at ~4 cycles each |
| Compressed fold | 128x memory blowup causes cache misses | No change | ARM prefetcher handles large sequential scans well |
| **k-depth grouping** | 24 sequential sumchecks have per-sumcheck overhead | **~40% faster at 2^8, ~26% at 2^10** | Reduces sumcheck count from 24 to 6 |
| Univariate skip | Block-table expansion is costly | Slightly worse | Extra scan passes cost more than expansion savings |

### k-depth grouped round benchmark (cleaned)

| Batch | Circuit (ms) | GKR k=1 (ms) | GKR k=4 (ms) | k=4 speedup | k=1 proof | k=4 transcript |
|---:|---:|---:|---:|---:|---:|---:|
| 2^8 | 63.9 | 46.6 | **28.0** | **1.66x** | 6.00 KB | 1.50 KB |
| 2^10 | 90.0 | 86.0 | **63.4** | **1.36x** | 7.50 KB | 1.88 KB |
| 2^12 | 153.6 | 208.5 | **178.8** | **1.17x** | 9.00 KB | 2.25 KB |
| 2^14 | 411.0 | 677.2 | **664.3** | **1.02x** | 10.50 KB | 2.62 KB |

### Important caveats

**Proof size is transcript-only.** The "k=4 transcript" column above counts only the sumcheck
round coefficients sent by the prover. It does NOT include polynomial commitment (PCS) costs.

In a real deployed system with BaseFold commitments:
- **k=1** commits to input + output only = **50 polynomials** (2 states x 25 lanes)
- **k>1** requires ALL intermediate states to be committed = **625 polynomials** (25 states x 25 lanes)

The 625-polynomial PCS opening proof would likely be much larger than the 8 KB saved in the
sumcheck transcript. Therefore, **k=1 produces the smallest total proof** in a real system.

The k=4 grouped approach is beneficial only when **prover speed matters more than proof size**,
and the batch size is small to medium (< 2^12).

**No commitment to the GKR circuit input.** The standalone keccak-check protocol does not
include a PCS commitment layer. The "verifier" in these benchmarks receives the full
`CompactTrace` as input — all 24 round states are verifier-side data, not part of the proof.
In a real system, the input and output states would be committed via BaseFold, and intermediate
states (for k>1) would also require commitments. The proving time benchmarks above measure
only the sumcheck/MLE-check work, not the commitment overhead.
