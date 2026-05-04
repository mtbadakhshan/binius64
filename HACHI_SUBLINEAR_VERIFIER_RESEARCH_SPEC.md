# Hachi Succinct End-to-End Sublinear Verifier Research Spec

Date: 2026-05-04

## Summary

The current `hachi-succinct` bridge is succinct for the committed witness oracle, but the production verifier is not yet fully sublinear end-to-end. The remaining linear work is verifier-side processing of the public transparent coefficients used in the terminal Binius relation:

```text
y = sum_i t_i * w_i in B128
```

Hachi already gives a succinct verifier for committed Hachi polynomials. The missing piece is a sound sublinear way to verify the selected-bit mask relation induced by the public Binius coefficients `t_i`.

The target of this research task is:

```text
For every Binius64 program lowered through the standard terminal relation, the hachi-succinct verifier should avoid scanning the full transparent coefficient table while preserving the B128 soundness argument.
```

## Current State

The bridge commits to a Hachi-field bit table for the Binius witness words:

```text
B(i, j) = bit_j(w_i)
```

For a terminal Binius claim, each output bit of `t_i * w_i` is a parity of selected witness bits. After batching output bits by a Hachi challenge `alpha`, the selected mask is:

```text
M_alpha(i, j) = sum_k alpha^k * bit_k(t_i * basis_j)
```

The selected-sum product check proves:

```text
sum_{i,j} B(i,j) * M_alpha(i,j) = sum_k alpha^k S_k
```

The verifier must know the final value of the multilinear extension of `M_alpha` at the selected-sumcheck point. Today, for production relations, it obtains that value by materializing or scanning the transparent coefficient table.

## Why Hachi Succinctness Does Not Automatically Solve This

Hachi proves openings of committed Hachi polynomials succinctly. It does not automatically give the verifier a sublinear way to derive a public mask whose entries are nonlinear bit functions of Binius coefficients.

The production transparent relation is:

```text
t = rs_eq_ind + batch_coeff * eq(pubcheck_point || 0, .)
```

The Binius MLE `T(r)` for this relation is sublinearly evaluable using ring-switch and public-input equality formulas. But the Hachi mask relation needs `bit_k(t_i * basis_j)` for each Boolean index `i`. In general:

```text
MLE(i -> mask(t_i))(r) != mask(MLE(i -> t_i)(r))
```

The obstruction is the bit extraction after B128 multiplication. It is not a linear or affine operation over the Hachi field, and it does not follow from the ability to evaluate `T(r)`.

## Soundness Requirements

Any replacement for a full transparent-table scan must satisfy one of:

- The verifier recomputes it from a public, typed relation descriptor.
- The prover commits to it with a binding commitment and provides a proof tying it to the public relation descriptor.

The prover must never be allowed to provide unchecked selected-mask values, parity bounds, or mask commitments. A committed mask only proves consistency with itself; it does not prove that the mask equals the one derived from `t_i`.

The following checks must remain intact:

- The Hachi bit-table commitment is binding.
- Weighted Booleanity proves committed table values are bits.
- Bounded parity ties integer sums `S_k` to the claimed B128 output bits.
- The selected-sum product check uses the same committed bit table.
- Any auxiliary mask commitment is tied to the public relation before it is trusted.
- Fiat-Shamir order binds commitments before challenges that depend on them.

## Candidate Research Paths

### Path A: Exact Structured Mask Evaluator

Goal: derive a closed-form or recursive evaluator for:

```text
sum_{i,j} eq(r_i, i) * eq(r_j, j) * M_alpha(i,j)
```

for the production relation:

```text
t_i = rs_eq_ind(i) + beta * pubcheck_eq(i)
```

This is the cleanest outcome. It keeps the proof small and preserves a pure verifier-owned relation path.

Possible angles:

- Exploit ring-switch tensor structure before bit extraction.
- Express multiplication-by-basis and bit extraction as fixed binary linear maps over B1, then look for a way to push the random equality weights through the tensor algebra.
- Split the public-input patch from the ring-switch term only if the bit-level map admits a controlled decomposition.
- Search for special structure in `rs_eq_ind(i)` values: they are not arbitrary table entries, but tensor-folded B1-derived values.
- Investigate whether `eq_r_double_prime` basis expansion has low-rank structure that survives multiplication by `basis_j`.

Major obstacle:

```text
bit_k((a_i + beta * p_i) * basis_j)
```

does not decompose into independent functions of `a_i` and `p_i` over the Hachi field. This path may require a new algebraic insight.

Soundness status:

Safe if the evaluator is exact and tested against materialized tables on small instances. Unsafe if it approximates or assumes linearity that is not present.

Efficiency target:

- Verifier: polylogarithmic or low-degree polynomial in `log n`.
- Proof size: unchanged from current compact `hachi-succinct`.
- Prover: unchanged or modest overhead.

### Path B: Proof-Backed Dense Mask Commitment

Goal: commit to the dense selected-mask polynomial and open it at the selected-sum final point, while proving that the committed mask equals the public relation-derived mask.

Protocol outline:

1. Prover and verifier derive `alpha`.
2. Prover commits to `M_alpha` as a dense Hachi polynomial.
3. Commitment is absorbed before selected-sumcheck challenges.
4. Product sumcheck uses `B(i,j) * M_alpha(i,j)`.
5. Prover opens `M_alpha` at the selected-sum final point.
6. Verifier checks the product final claim using the opened mask value.
7. A separate consistency argument proves the committed mask equals the mask derived from public `t_i`.

The current code has an opt-in scaffold for this style, but production does not enable it because the consistency check still falls back to materialization. Enabling it without a sublinear consistency proof increases proof size and verifier time without solving the core problem.

Possible consistency proofs:

- Random evaluation check against an exact structured evaluator. This reduces to Path A for the random point.
- A sumcheck proving each mask entry is computed by a fixed bit-decomposition circuit from the public coefficient descriptor.
- A lookup-style argument for fixed multiplication-by-basis bit maps, with the transparent coefficients supplied by a public descriptor.
- A recursive Binius proof that the Hachi mask commitment was generated correctly from the public relation, then verified succinctly.

Soundness status:

Safe only if the consistency proof is binding to the public relation. A mask commitment with no tie is unsound.

Efficiency target:

- Verifier: sublinear if the consistency proof is sublinear.
- Proof size: higher than Path A due to at least one mask commitment and openings.
- Prover: higher due to committing/proving dense mask data already materialized today.

### Path C: Transparent Relation Commitment With Verifiable Bit Map

Goal: commit to the transparent coefficients `t_i` or to their bit-decomposed products, then prove the selected mask is correctly derived.

This treats public transparent data as a committed object rather than a verifier-only table.

Possible design:

1. Prover commits to `T(i) = t_i` or bit-decompositions of `t_i * basis_j`.
2. Verifier checks random openings against the public relation descriptor.
3. A proof ties the selected-mask commitment to the transparent commitment via fixed linear maps and bit extraction.

Advantages:

- Separates the problem into public relation evaluation and mask derivation.
- May reuse Hachi commitments and openings for both transparent and mask polynomials.

Risks:

- Committing public data can increase proof size substantially.
- Random opening checks are not enough unless combined with a low-degree identity argument.
- The bit extraction relation is over B128 bits but checked in Hachi's odd-prime field, requiring Booleanity and range discipline.

Soundness status:

Potentially sound, but only with a complete derivation proof. This is a heavier protocol extension.

### Path D: Change The Bridge Encoding

Goal: avoid the nonlinear selected-mask relation entirely by changing the way Binius terminal claims are transported into Hachi.

Possible directions:

- Use a prime-field-linear encoding of the B128 terminal relation that avoids per-coefficient bit extraction.
- Introduce a ring-switch or CRT bridge that proves the B128 multiplication relation in a way Hachi can check linearly.
- Batch terminal claims in a representation where transparent coefficients enter as verifier-evaluable field elements rather than bit-derived masks.

This is the most ambitious path, but it may be the only path that yields clean inherited sublinearity for arbitrary Binius programs without relation-specific mask evaluators.

Risks:

- Direct canonical lifts from B128 to Hachi are not field-homomorphic.
- Any replacement must preserve B128 addition and multiplication semantics.
- A flawed bridge would be a soundness break, not just an optimization bug.

Soundness status:

Research only. Requires a formal proof before implementation.

### Path E: Hybrid Descriptor Library

Goal: achieve practical coverage by building exact descriptors for the finite set of terminal transparent relation families emitted by the Binius compiler.

This is not fully generic in the mathematical sense, but it may be enough if all Binius64 programs lower to a small number of relation shapes.

Approach:

- Inventory every terminal transparent relation emitted by the verifier/compiler.
- For each relation family, implement `eval_binius`, safe bounds, and either exact `eval_selected_mask` or a proof-backed consistency argument.
- Make the verifier reject `hachi-succinct` sublinear mode for unsupported relation families.

Soundness status:

Good if unsupported relations fail closed and every supported descriptor is tested against materialization.

Efficiency target:

Strong for covered applications. This may be the best incremental path if Path A is only possible for specific structures.

## Recommended Research Strategy

The best strategy is staged:

1. Preserve the current compact production path as the sound baseline.
2. Keep the descriptor API as the public interface for inherited sublinearity.
3. Treat proof-backed dense masks as an opt-in experimental backend, not the production default.
4. Focus research on an exact selected-mask evaluator or a succinct consistency proof for the production ring-switch relation.
5. Only enable end-to-end sublinear production mode after small-instance equivalence tests and adversarial mutation tests pass.

Immediate next milestones:

1. Formalize the production relation coefficient formula at Boolean indices.
2. Build a standalone test harness that materializes small ring-switch/public-input relations and compares any candidate mask evaluator against the legacy table.
3. Try to express `M_alpha` as a low-rank or tensor-foldable function of the ring-switch descriptor.
4. If that fails, design a mask consistency sumcheck that proves the dense committed mask was derived from the descriptor.
5. Benchmark proof size and verifier time for each candidate before integrating.

## Acceptance Criteria

A proposed solution should not be considered complete unless all of the following hold:

- The production verifier no longer materializes `transparent_values` for `hachi-succinct`.
- The selected-mask value used by the product-sumcheck is either verifier-computed exactly or opened from a commitment with a verified consistency proof.
- The verifier remains sublinear in the transparent table size.
- The same committed witness bit table is used for selected-sum and Booleanity checks.
- Proof-mode and Fiat-Shamir ordering tests still pass.
- Small-instance tests compare against full materialization for many random challenges.
- Negative tests catch mutated mask openings, mutated mask commitments, mutated consistency proofs, and wrong relation descriptors.
- One-block Keccak proof size and verifier time remain within an acceptable target envelope set before implementation.

## Open Questions

- Does the ring-switch equality indicator have enough tensor structure after B128 bit extraction to support an exact evaluator?
- Can the selected-mask derivation be expressed as a small arithmetic circuit over Hachi with manageable degree?
- Is a lookup argument over multiplication-by-basis bit maps cheaper than a dense mask commitment?
- Can the Binius compiler emit richer relation descriptors that avoid the current nonlinear mask map?
- What proof-size budget is acceptable for fully sublinear verification if the compact path remains available?

## Current Recommendation

Do not claim generic end-to-end sublinear verification yet.

The shortest safe path is to keep the compact `hachi-succinct` production verifier as the baseline, continue using descriptors as the API boundary, and research Path A first. If Path A fails for the production relation, pursue Path B with a real consistency sumcheck, accepting that proof size will increase unless Hachi batching or a more compact mask argument is found.
