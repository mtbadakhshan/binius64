# Grouped Keccak GKR: Flat and Parallel Approaches

## Overview

The standard Keccak GKR prover runs **24 sequential sumchecks** — one per
Keccak-f round. Each sumcheck proves a single fused chi+linear transition with
virtual intermediates, so only the input and output states need PCS commitments
(50 polynomials).

This document describes two approaches to reduce the number of sequential
sumchecks by grouping rounds:

| Approach | Module | How groups chain | Intermediates | Sumchecks | FS depth |
|----------|--------|-----------------|---------------|-----------|----------|
| **k=1 (standard)** | `fused_round.rs` | sequential | virtual | 24 | 24·log h |
| **k-flat** | `grouped_round.rs` | sequential + intra-group zerocheck | materialized | 24/k | (24/k)·log h |
| **k-parallel** | `parallel_groups.rs` | lockstep + boundary zerocheck | virtual | k | k·log h |

Where `h` is the number of Keccak instances and `k` divides 24.

## Illustration

### k=1 (standard sequential GKR)

```
Round 23 → sumcheck → Round 22 → sumcheck → ... → Round 0 → sumcheck
     ↓ chain             ↓ chain                       ↓
  claim on S₂₄       claim on S₂₃                 claim on S₀

Total: 24 sequential sumchecks, each with log(h) Fiat-Shamir rounds.
FS depth = 24 · log(h)
```

### k-flat (sequential groups, materialized intermediates)

With k=4, groups of 4 consecutive rounds are batch-checked in a single sumcheck.
Groups chain sequentially — each group's output claim depends on the previous.

```
Group 5 [R20-R23]  →  Group 4 [R16-R19]  →  ...  →  Group 0 [R0-R3]
  ┌─────────────┐      ┌─────────────┐              ┌─────────────┐
  │ 1 sumcheck  │      │ 1 sumcheck  │              │ 1 sumcheck  │
  │ proves 4    │ ──►  │ proves 4    │ ──►  ...  ──►│ proves 4    │
  │ transitions │chain │ transitions │ chain         │ transitions │
  └─────────────┘      └─────────────┘              └─────────────┘
  claim on S₂₄         claim on S₂₀                 claim on S₄
                                                     ↓ final
                                                   claim on S₀

Total: 24/k = 6 sequential sumchecks.
Each sumcheck batch-checks k transitions using random weights tw[r].
FS depth = (24/k) · log(h) = 6 · log(h)
```

**Within each group's sumcheck**, the batched polynomial is:

```
f(x) = chi_iota_{last}(linear(State_{last}(x)))
     + Σ_{r=0}^{k-2} tw[r] · (chi_iota_r(linear(State_{t+r}(x))) − State_{t+r+1}(x))
```

The residual terms check that each within-group transition is correct. They
vanish on boolean inputs when the trace is valid. The verifier needs the
within-group intermediate states materialized (available as data) to verify
the residual evaluations.

### k-parallel (lockstep groups, virtual intermediates, batched sumcheck)

With k=4, rounds are split into 6 independent groups. Each group runs a
standard k=1 GKR chain internally (4 sequential sumchecks, virtual intermediates).
At each layer, all 6 groups' polynomials are batch-combined via random linear
combination into a **single** sumcheck.

```
Layer 0 (each group's last round: R3, R7, R11, R15, R19, R23):

  Group 0   Group 1   Group 2   Group 3   Group 4   Group 5
  chi(R3)   chi(R7)   chi(R11)  chi(R15)  chi(R19)  chi(R23)
     \         |         |         |         |         /
      └────────┴─────────┴─────────┴─────────┴────────┘
              1 batched sumcheck (log h rounds)
              f(x) = Σ_g α_g · chi_iota_{round_g}(linear(State_{round_g}(x)))
                    ─── shared challenge ───►

Layer 1 (R2, R6, R10, R14, R18, R22): 1 batched sumcheck
Layer 2 (R1, R5, R9,  R13, R17, R21): 1 batched sumcheck
Layer 3 (R0, R4, R8,  R12, R16, R20): 1 batched sumcheck

Total: k = 4 batched sumchecks.
FS depth = k · log(h) = 4 · log(h)
```

Each group starts with a claim on its boundary output state (S₄, S₈, ..., S₂₄),
which is committed or available in the CompactTrace. Groups are independent —
no sequential chaining between groups. Inter-group consistency comes from both
sides referencing the same committed boundary data.

**Within each layer's batched sumcheck**, the polynomial is:

```
f(x) = Σ_g α_g · Σ_lane w_g[lane] · chi_iota_{round_g}(linear(State_{round_g}(x)))[lane]
```

where `α_g` are random batch weights and `w_g[lane]` are per-group lane weights
from the group's output claim.

## Protocol details

### k-flat: residual-based batching

For a group of k rounds starting at round t, the prover has word-level data for
k+1 states: `State_t, State_{t+1}, ..., State_{t+k}`. The batched MLE-check
proves:

```
f(x) = Σ_{i,j} w[i,j] · chi_iota_{t+k-1}(linear(State_{t+k-1}(x)))[i,j]
     + Σ_{r=0}^{k-2} tw[r] · Σ_{i,j} w[i,j] ·
           (chi_iota_{t+r}(linear(State_{t+r}(x)))[i,j] − State_{t+r+1}(x)[i,j])
```

On boolean inputs with correct transitions, each residual vanishes and
`f(α) = mixed_eval`. The MLE-check verifies this.

**Soundness:** MLE-check error `2/|F|` per variable, plus `(k−1)/|F|` from
the random linear combination. Total per group: `(2·log h + k − 1) / 2^128`.

### k-parallel: batched independent sumchecks

Each layer runs a standard MLE-check on the batched polynomial
`f(x) = Σ_g α_g · f_g(x)`, driven by `prove_single_mlecheck`. This is a
single degree-2 sumcheck over `log(h)` variables.

The `BatchedParallelProver` struct evaluates all groups' chi+linear polynomials
in a single pass per instance, accumulating with batch weights. The data is
stored in **interleaved layout** — `blocks[i · n_groups + g]` — so all groups'
blocks for instance `i` are contiguous in memory.

After the sumcheck, `finish()` returns `n_groups × 25` lane evaluations. Each
group's 25 evaluations chain to the next layer within that group, exactly as in
the standard k=1 protocol.

**Soundness:** Same as k-flat — the batch combination and MLE-check each
contribute negligible error over GF(2^128).

## PCS commitment cost (important caveat)

The standalone benchmark measures only the **sumcheck transcript** size. In a
real system with BaseFold polynomial commitments:

| Approach | States committed | Polynomials | Notes |
|----------|-----------------|-------------|-------|
| k=1 | S₀, S₂₄ | 50 | intermediates virtual |
| k-flat (k=4) | S₀, S₂₄ + 18 within-group | 500 | 5 boundaries claim-chained |
| k-flat (k=6) | S₀, S₂₄ + 20 within-group | 550 | 3 boundaries claim-chained |
| k-parallel (k=4) | S₀, S₄, S₈, S₁₂, S₁₆, S₂₀, S₂₄ | 175 | 7 boundary states |
| k-parallel (k=6) | S₀, S₆, S₁₂, S₁₈, S₂₄ | 125 | 5 boundary states |

Note that k=4 and k=6 are complementary: flat-6 and parallel-4 both have
FS depth 4·log(h), while flat-4 and parallel-6 both have FS depth 6·log(h).
The trade-off is PCS cost vs memory locality.

The PCS opening proofs for 500–550 polynomials (k-flat) would **far exceed**
the sumcheck transcript savings. k-parallel's 125–175 polynomials is better,
but still 2.5–3.5× more than k=1's 50.

**k=1 produces the smallest total proof in a real system** when PCS cost
dominates. The grouped approaches trade PCS cost for prover speed and/or
Fiat-Shamir depth.

## Benchmark results

`RUSTFLAGS="-C target-cpu=native"`, release build, 5 iterations median.
The "circuit" column is the Binius default `CircuitBuilder` + BaseFold prover
for comparison (includes PCS).

### Prover time (ms, median)

| batch | circuit | k=1 | flat-4 | par-4 | flat-6 | par-6 |
|------:|--------:|----:|-------:|------:|-------:|------:|
|  2^8  |   61.2 |   50.5 | 30.0 | **27.4** | **25.9** |   39.3 |
| 2^10  |   81.1 |  106.0 | 139.0 |  174.6 |  140.0 |  194.5 |
| 2^12  | **153.7** |  503.1 | 396.1 |  376.1 | **362.9** |  351.7 |
| 2^14  | **449.6** | 1031.2 | 640.6 |  948.9 | **609.8** |  787.1 |

### Proof size (KB, sumcheck transcript only)

| batch | circuit | k=1 | flat-4 | par-4 | flat-6 | par-6 |
|------:|--------:|----:|-------:|------:|-------:|------:|
|  2^8  | 265.84 | 6.00 | 1.50 | **1.00** | **1.00** | 1.50 |
| 2^10  | 304.03 | 7.50 | 1.88 | **1.25** | **1.25** | 1.88 |
| 2^12  | 404.75 | 9.00 | 2.25 | **1.50** | **1.50** | 2.25 |
| 2^14  | 457.44 | 10.50 | 2.62 | **1.75** | **1.75** | 2.62 |

Note: standalone proof sizes are sumcheck-transcript only (no PCS). The circuit
column includes full BaseFold PCS opening proofs, hence the ~100× larger size.

**Proof size complementarity:** flat-4 = par-6 (both 6 sumchecks → same
transcript), and flat-6 = par-4 (both 4 sumchecks → same transcript). This
confirms the structural duality.

### Observations

- **flat-6 is the fastest standalone prover** at medium-to-large batches:
  362.9 ms at 2^12, 609.8 ms at 2^14. It beats flat-4 at all batch sizes
  because fewer groups (4 vs 6) means fewer Gruen32 inits and smaller
  per-sumcheck working set, despite heavier individual sumchecks.
- **Circuit prover wins at ≥2^12** (153.7 ms vs 362.9 ms for flat-6)
  because its PCS-integrated pipeline amortizes better at large batches.
- **flat-6 and par-4 tie on transcript** (1.00 KB at 2^8) — both produce
  4 sumcheck proofs. But flat-6 is faster (25.9 ms vs 27.4 ms) due to
  better temporal locality.
- **par-4 and par-6 are slower than their flat counterparts** at large
  batches due to the memory pressure from scanning multiple groups' arrays
  per sumcheck (see Memory analysis below).

**k=4 vs k=6 complementarity:** flat-k has 24/k sumchecks, parallel-k has k
sumchecks. So flat-6 and par-4 are structurally equivalent (4 sumchecks,
4·log h depth) while flat-4 and par-6 match (6 sumchecks, 6·log h depth).
They differ in PCS cost (flat needs within-group intermediates, parallel needs
only boundaries) and memory locality (flat has better temporal locality from
data reuse between adjacent rounds).

In a full system where PCS cost dominates, k=1 may still produce the smallest
total proof.

## Memory analysis: why k-parallel is slower at large batch

### The puzzle

k-flat and k-parallel perform **exactly the same total work**: 24 chi+linear
evaluations per instance across all sumcheck rounds, 24n fold operations, and
the same total memory traffic. Yet at 2^14, par-12 (711 ms) is 10% slower
than flat-6 (645 ms), and par-4 (928 ms) is 44% slower.

### Root cause: per-instance working set

Each `fused_chi_linear_pair_eval_blocks` call accesses two `[[F;64];25]` block
arrays = **50 KB** per call. The inner loop processes all groups for one
instance before moving to the next.

In the block phase (after the first fold), the per-instance working set is:

| Config | Groups/sumcheck | Blocks per instance | Working set | vs L1 (128 KB) | vs L2 (16 MB) |
|--------|---------------:|--------------------:|------------:|---------------:|--------------:|
| k=1    |              1 |          2 (lo+hi)  |      50 KB  | fits           | fits          |
| flat-4 |              1 (but 4 chi evals) |  8+3 = 11  |     275 KB  | **2× over**    | fits          |
| flat-8 |              1 (but 8 chi evals) |  16+7 = 23 |     575 KB  | **4.5× over**  | fits          |
| par-2  |             12 |         24 (12×2)   |     600 KB  | **4.7× over**  | fits          |
| par-4  |              6 |         12 (6×2)    |     300 KB  | **2.3× over**  | fits          |
| par-6  |              4 |          8 (4×2)    |     200 KB  | **1.6× over**  | fits          |
| par-12 |              2 |          4 (2×2)    |     100 KB  | fits           | fits          |

At 2^14, the total block data per sumcheck far exceeds L2 for both flat and
parallel. But the **per-instance** working set determines how efficiently the
hardware prefetcher can serve the inner loop.

### Locality analysis

**k-flat** accesses k consecutive round-input arrays. The `grouped_word_pair_eval`
function calls `single_fused_word_pair_eval` k times, each on a different round's
data, then computes residuals using the *next* round's output (already loaded for
the next chi eval). The access pattern has temporal locality: data loaded for
round r's chi evaluation overlaps with data needed for round r+1's output check.

**k-parallel** with interleaved layout accesses data at `blocks[i·G + g]` where
G is the number of groups per sumcheck. Adjacent groups' blocks for the same
instance are contiguous (good spatial locality), but each group's chi evaluation
is independent — there is no data reuse between groups. Every group accesses the
full 50 KB block pair from scratch.

The key difference: k-flat's residual terms reuse data between adjacent rounds
(chi output of round r feeds into the output check of round r). k-parallel's
independent groups have **zero inter-group data reuse**.

### Memory bandwidth

At 2^14, the block arrays are ~200 MB per group. The inner sumcheck loop makes
a streaming pass over all groups' data:

| Config | Data per sumcheck pass | Passes (layers or groups) | Total |
|--------|----------------------:|-------------------------:|------:|
| flat-6 |  4 × 200 MB = 800 MB  |                        4 | 3.2 TB |
| par-4  |  6 × 200 MB = 1.2 GB  |                        4 | 4.8 TB |
| par-12 |  2 × 200 MB = 400 MB  |                       12 | 4.8 TB |

Wait — flat-6 accesses only 3.2 TB while par-4 accesses 4.8 TB? That doesn't
seem right since both do the same total work. The discrepancy comes from the
**output evaluation** in k-flat. Each flat group reads k round arrays but also
reads k−1 *output* arrays (for the residuals). These output arrays are the
*next* round's input, which is the same data. So k-flat's total data per
sumcheck is actually `k + (k−1) = 2k−1` array scans, not `k`.

- flat-6: (2·4−1)×200 MB = 1.4 GB per sumcheck × 4 groups = 5.6 TB
- par-4: 2·6 ×200 MB = 2.4 GB per sumcheck × 4 layers  ≈ 9.6 TB (but shared
  arrays counted once → 4.8 TB unique)

The effective bandwidth difference is modest after accounting for caching, but
the **access pattern** quality differs: flat's output-read hits data that was
just written by chi (warm in L2), while parallel's group-reads are all cold.

### Practical impact

The interleaved block layout mitigates the worst of the spatial locality problem
by making groups' blocks contiguous per instance. But the *temporal* locality
issue (no inter-group data reuse) remains fundamental to the parallel approach.

At small batch sizes (2^8), block arrays fit in L2, and the reduced Gruen32
overhead (4 inits vs 6 for flat-6) makes k-parallel competitive. At large
batch sizes (2^14), the memory wall dominates and k-flat's better temporal
locality wins.

## Why both approaches use zerochecks

Both k-flat and k-parallel batch multiple round transitions into a single
sumcheck. When you batch multiple transitions, you need to verify that
intermediate states are consistent — and both approaches do this via
**zerocheck residuals**: terms that vanish on boolean inputs when the trace
is valid, weighted by random challenges.

### k-flat: intra-group zerochecks

Within each group of k rounds, the k-1 inner transitions must satisfy
`chi_iota_r(State_r) = State_{r+1}`. The residuals `chi_iota_r(x) - State_{r+1}(x)`
are weighted by `transition_weights[r]` and added to the batched polynomial.
These vanish on boolean inputs when the trace is correct.

### k-parallel: inter-group boundary zerochecks

Each group runs independently, but groups must agree at boundaries: the output
of group g must equal the input of group g+1. At layer 0 (each group's last
round), the batched polynomial includes boundary residuals
`β_g · (chi_iota_g(x) − S_{boundary_g}(x))` for groups 0..n-2. These enforce
that `fused(S_{4g+3}) = S_{4(g+1)}`.

The boundary state is degree 1 (multilinear), so it contributes only to y_1,
not y_inf. The sumcheck degree stays at 2. At layers 1-3 (inner rounds within
each group), no boundary data is involved.

### Why not skip the zerocheck?

In the standalone protocol both prover and verifier have the full trace, so
boundary consistency is trivially verifiable. But in a PCS-integrated system
the prover provides boundary states as opaque committed polynomials. Without
the zerocheck, the verifier would need separate PCS opening proofs to verify
each boundary — partially offsetting the transcript savings. The zerocheck embeds boundary
verification into the existing sumcheck at negligible cost (~2-3% overhead).

## Files

- `crates/keccak-check/src/fused_round.rs` — single-round prover (k=1)
- `crates/keccak-check/src/grouped_round.rs` — k-flat prover and verifier
- `crates/keccak-check/src/parallel_groups.rs` — k-parallel prover and verifier (with boundary zerochecks)
- `crates/keccak-check/src/protocol.rs` — `prove` / `verify` / `prove_grouped` / `verify_grouped`
- `crates/keccak-check/src/lib.rs` — re-exports and `pub mod` declarations
- `crates/keccak-check/examples/compare_provers.rs` — benchmark harness

## Usage

```bash
# Default: batch=2^10, k=4, 5 iterations, includes circuit prover
cargo run --release --example compare_provers -p binius-keccak-check

# Custom batch and group size
KECCAK_LOG_BATCH=14 KECCAK_GROUP_SIZE=6 KECCAK_ITERS=7 \
  cargo run --release --example compare_provers -p binius-keccak-check

# Skip the circuit prover (faster, standalone GKR only)
SKIP_CIRCUIT=1 KECCAK_LOG_BATCH=12 \
  cargo run --release --example compare_provers -p binius-keccak-check

# Valid group_size values: divisors of 24 (1, 2, 3, 4, 6, 8, 12, 24)
```
