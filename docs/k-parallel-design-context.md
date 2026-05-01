# k-Parallel Keccak GKR Prover: Design Context

This document provides full context for implementing the k-parallel grouped Keccak GKR
prover. It summarizes two days of investigation into the keccak-check crate on the
`autoresearch/engineering/keccak-prove-chi-iota-stable` branch.

## The Keccak GKR Protocol (what exists)

### What keccak-f is

Keccak-f[1600] is a permutation on 1600 bits, organized as 25 lanes of 64 bits each
(a 5x5 matrix). It applies 24 identical rounds, each with 5 steps:

- **Theta:** XOR each lane with column parities + rotated neighbor parity (linear)
- **Rho:** Rotate bits within each lane by fixed offsets (linear)
- **Pi:** Shuffle lane positions in the 5x5 grid (free, just relabeling)
- **Chi:** `out[x] = in[x] XOR ((NOT in[x+1]) AND in[x+2])` — the ONLY nonlinear step (degree 2)
- **Iota:** XOR a round constant into lane (0,0) (linear)

Over GF(2), theta/rho/pi/iota are all degree 1 (linear). Only chi has a multiplication
(AND gate), making it degree 2. This is why the entire round can be fused into a single
degree-2 polynomial.

### How the GKR prover works

For h independent keccak-f instances batched together:

1. Each lane becomes a multilinear polynomial (MLE) with `n = 6 + log(h)` variables:
   - 6 low variables index the 64 bit positions within a lane
   - log(h) high variables index which of the h instances

2. The protocol works backward from the output (State_24) to the input (State_0).
   For each of the 24 Keccak rounds, one fused degree-2 MLE-check sumcheck proves:
   ```
   chi_iota(linear(State_t)) = State_{t+1}
   ```
   where `linear = theta + rho + pi` is substituted directly into the chi formula.

3. The sumcheck has `log(h)` interactive rounds (the 6 bit variables are pre-collapsed
   at the boundary via `bit_challenge`). Each round binds one instance variable.

4. After the sumcheck, `finish()` returns 25 lane evaluations of State_t at the
   reduced point. These evaluations chain to the next round's output claim.

5. The intermediate states (State_1 through State_23) are **virtual** — never
   materialized. Only State_0 and State_24 need PCS commitments.

### Key performance characteristics

Benchmarked on Apple Silicon (M-series), release build, `RUSTFLAGS="-C target-cpu=native"`:

| Batch | Circuit (ms) | GKR k=1 (ms) | GKR proof | Circuit proof |
|------:|-------------:|--------------:|----------:|--------------:|
|   2^8 |         63.9 |          46.6 |   6.00 KB |      265.8 KB |
|  2^10 |         90.0 |          86.0 |   7.50 KB |      304.0 KB |
|  2^12 |        153.6 |         208.5 |   9.00 KB |      404.8 KB |
|  2^14 |        411.0 |         677.2 |  10.50 KB |      457.4 KB |

The GKR wins at small batches (faster + 45x smaller proofs) but loses at large batches
(24 sequential sumcheck passes vs CircuitBuilder's single pass).

### Why the GKR is slow at large batches

Each round takes ~24ms uniformly. The bottleneck is:

1. **24 sequential passes** over the data (one per Keccak round)
2. After the first fold, each bit becomes a GF(2^128) element (128x memory blowup)
3. The sumcheck operates over GF(2^128) for soundness — this is unavoidable

The CircuitBuilder avoids the 128x blowup by collapsing the 64 bit positions into one
scalar BEFORE folding instances (Phase 1 of AND reduction). The GKR can't do this cheaply
because its fused chi+linear polynomial is too complex to evaluate at 64 domain points.

### What we tried and didn't work

1. **Byte lookup table:** Replace bit extraction with table lookup — no improvement (PMULL fast)
2. **Multiply hoisting:** Factor weight out of inner loop — no improvement
3. **Compressed fold:** Store folded data as u8 indices into lookup table — no improvement
   (indirection overhead cancels cache benefit)
4. **Univariate skip:** Bind multiple sumcheck variables at once — no improvement / slightly worse
5. **k-flat grouping** (implemented, kept): Group k rounds, batch-check k transitions in one
   sumcheck with materialized intermediates. 1.66x faster at 2^8, neutral at 2^14.

## The k-flat approach (what we implemented)

Module: `crates/keccak-check/src/grouped_round.rs`

Groups k consecutive rounds. Within each group, all k transitions are batch-checked in
ONE degree-2 sumcheck. The intermediate states are provided as data (materialized).
Groups chain sequentially (each group's output claim depends on the previous group).

The batched polynomial:
```
f(x) = chi_iota_{last}(State_{last}(x))
     + Σ_{r=0}^{k-2} tw[r] * (chi_iota_r(State_{t+r}(x)) - State_{t+r+1}(x))
```

The residuals `chi(State_{t+r}) - State_{t+r+1}` are the XOR/equality checks. They
must be zero on boolean inputs for correct transitions.

### Data flow for k=4, Group 5 (rounds 20-23):

- Input data: State_20, State_21, State_22, State_23 (4 arrays from CompactTrace)
- Output claim: on State_24 (from chain or initial commitment)
- The verifier reads `round_inputs[r+1]` for the residual checks
- `group_output_words` (State_24) is passed but only validated, not used in computation
- `finish()` returns State_20 evaluations, which chain to Group 4

### What's virtual vs materialized:

- Group boundaries (S_4, S_8, S_12, S_16, S_20): **virtual** (chained between groups)
- Within-group intermediates (S_1,S_2,S_3, S_5,S_6,S_7, etc.): **materialized** (needed for residual checks)
- PCS commitments: 500 polynomials (20 states × 25 lanes) vs 50 for k=1

### Limitation:

Groups run sequentially — each group's output claim depends on the previous group. This
is the same sequential chain as k=1, just with fewer, heavier sumcheck invocations. There
is NO parallelism. The speedup comes only from reduced per-sumcheck overhead (Gruen32 init,
challenge sampling).

## The k-parallel approach (IMPLEMENTED)

> **Note:** This section was written as a design sketch before implementation.
> The actual implementation in `parallel_groups.rs` uses a single
> `BatchedParallelProver` that batch-combines all groups via random linear
> combination into one degree-2 sumcheck per layer, rather than running
> individual per-group provers in lockstep. See `k-depth-grouped-round.md`
> for the authoritative description of the implemented scheme.

### Architecture

Split 24 rounds into 6 groups of 4. Each group runs a standard k=1 GKR chain internally
(4 sequential sumchecks, virtual intermediates). All 6 groups run **in lockstep** with
shared Fiat-Shamir:

```
Fiat-Shamir Round 1:
  Group0 runs execute() for its keccak round 3 → sends poly₀
  Group1 runs execute() for its keccak round 7 → sends poly₁
  ...
  Group5 runs execute() for its keccak round 23 → sends poly₅
  Hash all 6 polynomials → shared challenge r₁
  All 6 groups fold with r₁

Fiat-Shamir Round 2:
  All 6 groups run execute() for their next keccak round → send polys
  Hash → r₂, fold

Fiat-Shamir Round 3: → r₃
Fiat-Shamir Round 4: → r₄ → all groups finish, send final evals
```

### What this achieves

- **Sequential Fiat-Shamir depth: 4 rounds** (not 24)
- Within-group intermediates are **virtual** (standard k=1 GKR per group)
- Boundary commitments: S_0, S_4, S_8, S_12, S_16, S_20, S_24 = **175 polynomials**
- Proof size: `group_size × 2 × log(h)` field elements (smaller than both k=1 and k-flat)
- Prover work per Fiat-Shamir round: 6x more polynomials (one per group), parallelizable

### Inter-group consistency

The boundary states (S_0, S_4, ..., S_24) are committed. Each group's output claim comes
from the committed boundary state. Group 5 starts with a claim on committed S_24 and
reduces to S_20; Group 4 starts with a claim on committed S_20 and reduces to S_16; etc.

Since both Group 5 and Group 4 reference the SAME committed S_20, consistency is
automatic — the commitment enforces equality.

In the standalone protocol (no PCS), the verifier has the full CompactTrace, so the
boundary states are verified by recomputation.

### How to implement

#### New module: `crates/keccak-check/src/parallel_groups.rs`

Core function:
```rust
pub fn prove_parallel<P, Channel>(
    trace: &CompactTrace,
    group_size: usize,  // must divide 24
    channel: &mut Channel,
) -> Result<BitIndexedEndpointClaims<P::Scalar>, Error>
```

The key difference from `prove_grouped`: instead of running groups sequentially in a loop,
all groups at each layer are batch-combined via random linear combination into a **single**
degree-2 sumcheck. The actual implementation uses a `BatchedParallelProver` struct:

```rust
for layer in 0..group_size {
    // Sample batch_weights (one per group) and residual_weights (layer 0 only)
    let batch_weights: Vec<F> = (0..n_groups).map(|_| channel.sample()).collect();
    let residual_weights: Vec<F> = if layer == 0 {
        (0..n_groups - 1).map(|_| channel.sample()).collect()
    } else { Vec::new() };

    // One batched sumcheck across all groups at this layer
    let prover = BatchedParallelProver::new_with_boundaries(
        group_words, bit_weights, group_lane_weights,
        batch_weights, rounds, high_point, batched_eval,
        boundary_words, residual_weights,  // boundaries only at layer 0
    );
    let proof_output = prove_single_mlecheck(prover, channel)?;

    // Update all group claims from the n_groups × 25 input evaluations
    for g in 0..n_groups {
        group_claims[g] = bit_indexed_claim_from_evals(..., input_evals[g]);
    }
}
```

At layer 0, boundary zerocheck residuals `β_g · (fused_g(x) - S_boundary(x))` are
included in the batched polynomial, enforcing inter-group consistency within the
sumcheck. The boundary is degree 1 (multilinear), so it only contributes to y_1 —
the sumcheck degree stays at 2.

Sequential depth: 4 layers × log(h) rounds = 4 × log(h) total Fiat-Shamir rounds
(vs original: 24 × log(h))

#### Modified: `crates/keccak-check/src/protocol.rs`

Add `prove_parallel` / `verify_parallel`.

#### Modified: `crates/keccak-check/src/lib.rs`

Add `pub mod parallel_groups;` and re-exports.

#### Benchmark

Add to `compare_provers.rs` alongside existing benchmarks.

### Naming convention

- `k=1` (original): `prove` / `verify` — 24 sequential sumchecks
- `k-flat` (existing): `prove_grouped` / `verify_grouped` — fewer sumchecks, materialized intermediates
- `k-parallel` (new): `prove_parallel` / `verify_parallel` — groups in lockstep, virtual intermediates

### Expected performance

At batch 2^14 (log(h) = 14):
- Original: 24 × 14 = 336 sequential Fiat-Shamir rounds, ~677ms
- k-parallel (k=4): 4 × 14 = 56 sequential Fiat-Shamir rounds
- Each round: 6 groups' execute() + fold (parallelizable)
- Expected: ~677ms / 6 ≈ 113ms with perfect parallelism, ~200-300ms realistic

The speedup depends on how well rayon parallelizes the 6 groups' work. The total
computation is the same (24 chi evaluations per instance), but spread across 6x fewer
sequential steps.

### Files to read before implementing

1. `crates/keccak-check/src/fused_round.rs` — `FusedRoundProver` struct, `execute()`, `fold()`, `finish()`
2. `crates/keccak-check/src/protocol.rs` — `prove()` for the k=1 chain, `prove_grouped()` for k-flat
3. `crates/keccak-check/src/grouped_round.rs` — k-flat for comparison
4. `crates/keccak-check/src/lib.rs` — types: `BitIndexedMixedClaim`, `FusedRoundReduction`, `FusedRoundOutput`
5. `crates/keccak-check/src/trace.rs` — `CompactTrace` structure
6. `crates/keccak-check/examples/compare_provers.rs` — benchmark harness
7. `crates/keccak-check/docs/k-depth-grouped-round.md` — k-flat documentation
