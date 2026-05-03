# Hachi Integration Soundness Audit

Date: 2026-05-02

## Executive Summary

This audit reviewed the Hachi integration paths added to Binius64, with the specific goal of identifying whether a malicious prover can produce an accepting proof for a false Binius statement.

The conservative `hachi-full-open` path appears sound: it reveals the terminal Binius oracle and verifies the native `B128` inner-product relation directly.

Update: the critical `hachi-succinct` Booleanity gap described below has been remediated. The succinct bridge now uses a verifier-random equality-weighted degree-3 Booleanity sumcheck:

```text
sum_x eq(r, x) * B(x) * (B(x) - 1) = 0
```

The verifier samples `r` after the Hachi commitment is transcript-bound and checks the final claim as `eq(r, z) * B(z) * (B(z) - 1)` against the Hachi opening of `B(z)`. This removes the cancellation attack surface from the previous unweighted global sum, assuming the Hachi PCS remains binding for the committed field polynomial.

## Scope

Audited areas:

- Binius Hachi bridge algebra in `crates/iop/src/hachi_bridge.rs`.
- Full-opening verifier/prover channels in `crates/iop/src/hachi_full_open_channel.rs` and `crates/iop-prover/src/hachi_full_open_channel.rs`.
- Succinct verifier/prover channels in `crates/iop/src/hachi_succinct_channel.rs` and `crates/iop-prover/src/hachi_succinct_channel.rs`.
- Hachi transcript wire helpers in `crates/iop/src/hachi_wire.rs`.
- End-to-end verifier/prover integration in `crates/verifier/src/verify.rs` and `crates/prover/src/prove.rs`.
- Local Hachi dependency patterns in `../lz-hachi`.
- Comparable Jolt one-hot and batching patterns in `../jolt`.

Validation commands run:

```bash
cargo test -p binius-iop --features hachi -- --nocapture
cargo test -p binius-iop-prover --features hachi -- --nocapture
cargo test -p binius-examples --features hachi --lib -- --nocapture
cargo test -p binius-prover --features hachi hachi_proof_mode_mismatches_reject -- --nocapture
cargo run -p binius-examples --features hachi --example keccak -- --max-len-bytes 32 --message-len 32 --compression hachi-succinct
cargo run -p binius-examples --features hachi --example keccak -- --max-len-bytes 256 --message-len 256 --compression hachi-succinct
```

All commands passed after remediation.

## Findings

### Critical: Succinct Booleanity Check Is Not Pointwise

Status: remediated.

Relevant code:

- `crates/iop/src/hachi_bridge.rs`
  - `WeightedBooleanitySumcheckProof`
  - `prove_weighted_booleanity_sumcheck_transcript`
  - `verify_weighted_booleanity_sumcheck_transcript`
  - `evaluate_hachi_eq`
- `crates/iop/src/hachi_succinct_channel.rs`
  - `HachiSuccinctVerifierChannel::verify_oracle_relations`
- `crates/iop-prover/src/hachi_succinct_channel.rs`
  - `HachiSuccinctProverChannel::prove_oracle_relations`

The succinct bridge attempts to prove that the committed bit table is Boolean by checking:

```text
sum_x B(x) * (B(x) - 1) = 0
```

Over an odd-prime field, this global sum can be zero even when many `B(x)` values are not `0` or `1`, because the nonzero products can cancel. Therefore the current check does not prove that the committed Hachi table represents binary bits.

This is fatal to the bridge argument. The bounded parity check is sound only if each committed table entry is a bit. Without pointwise Booleanity, selected sums over Hachi's prime field no longer correspond to integer sums of selected bits, and the parity argument no longer implies the native `B128` terminal relation.

Plausible exploit sketch:

1. Commit to a non-Boolean prime-field table `B`.
2. Choose bounded integers `S_k` whose parities match the target false Binius claim.
3. Arrange the selected-sum random linear combination and the global Booleanity sum to pass by using the many degrees of freedom in `B`.
4. Produce valid Hachi openings for this non-Boolean table.

Jolt comparison:

Jolt does not rely on an unweighted global Booleanity sum for this style of constraint. Its Booleanity checks are randomly weighted, typically with equality-polynomial weights and batching challenges, so cancellation in an unweighted aggregate is not enough.

Implemented remediation:

- The unweighted Booleanity check was replaced with a randomly weighted degree-3 Booleanity sumcheck:

```text
sum_x eq(r, x) * B(x) * (B(x) - 1) = 0
```

- `r` is sampled from the Binius transcript after the commitment is fixed.
- The verifier discharges the final sumcheck claim with the existing Hachi opening at the Booleanity point, checking `eq(r, z) * B(z) * (B(z) - 1)`.
- A regression test now constructs a non-Boolean table with cancelling unweighted `sum B(B - 1)` and confirms the weighted claim is nonzero.

### High: Hachi `OneHotPoly` Is a Prover-Side Optimization, Not a Verifier-Side Constraint

Status: remediated by explicit verifier-side Booleanity; documented as an implementation-only optimization.

Relevant code:

- `crates/iop-prover/src/hachi_succinct_channel.rs`
  - `BitTablePoly = OneHotPoly<HachiScalar, D, u8>`
  - `send_oracle`
- `../lz-hachi/src/protocol/hachi_poly_ops/onehot.rs`
  - `OneHotPoly::new`
- `../lz-hachi/src/protocol/commitment_scheme.rs`
  - `HachiCommitmentScheme::batched_verify`

The honest prover constructs the bit table with Hachi's `OneHotPoly`, but the verifier receives only a commitment and later opening proof. The verifier checks opening consistency, not that the committed polynomial was generated from `OneHotPoly` or that it is one-hot/Boolean.

This reinforces the critical Booleanity issue: the sparse one-hot encoding improves prover performance but does not by itself constrain a malicious prover's committed message.

Implemented remediation:

- Treat one-hot encoding as an implementation optimization only.
- Add explicit verifier-checked Booleanity through the weighted Booleanity sumcheck.
- Document the distinction in `HACHI_PCS_INTEGRATION.md` and in the succinct prover channel.

### High: Hachi Object Deserialization Does Not Enforce EOF

Status: remediated.

Relevant code:

- `crates/iop/src/hachi_wire.rs`
  - `read_hachi`

`read_hachi` reads a prover-supplied length, deserializes the Hachi object from that byte slice, and returns the parsed value. It does not check that the deserializer consumed the entire slice.

If Hachi deserializers accept trailing bytes, a prover can create multiple transcript encodings of the same semantic message. Because the raw bytes are observed by the transcript, trailing ignored bytes can change later Fiat-Shamir challenges while leaving the parsed object unchanged.

This is not by itself a complete false-proof exploit, but it weakens the Fiat-Shamir soundness argument and creates a challenge-grinding/malleability surface.

Implemented remediation:

- `read_hachi` now deserializes through a cursor and rejects unless the cursor is at EOF.
- `read_hachi` rejects length prefixes above a conservative maximum before allocation.
- Tests cover trailing bytes on a Hachi scalar payload and oversized payload rejection.

### Medium: Proof Mode Is Not Bound In-Proof

Status: remediated.

Relevant code:

- `crates/verifier/src/verify.rs`
  - `Verifier::verify`
  - `Verifier::verify_hachi_full_open`
  - `Verifier::verify_hachi_succinct`
- `crates/examples/src/lib.rs`
  - `CompressionType`

The proof mode is selected by the API method or CLI option, not encoded into the transcript. A native BaseFold proof, full-open Hachi proof, and succinct Hachi proof are expected to be verified by different verifier entry points.

This does not appear to create a silent false-proof issue because mode mismatches should fail parsing or transcript finalization. However, applications must externally bind proof bytes to the expected verification mode.

Implemented remediation:

- Added explicit top-level transcript mode tags for BaseFold, `hachi-full-open`, and `hachi-succinct`.
- Added mode-mismatch tests covering BaseFold/full-open/succinct verifier entry points.

### Medium: No Adversarial End-to-End Tests For `hachi-succinct`

Status: partially remediated.

Existing tests cover many components:

- parity bounds,
- compact `S_k` packing,
- selected-sum consistency,
- Booleanity happy path,
- lazy mask evaluation,
- Hachi opening round trips.

Missing high-value end-to-end tests:

- Mutate compact `S_k` while preserving parity but breaking selected sum.
- Mutate nonzero compact padding.
- Mutate selected-sum round polynomials.
- Mutate Booleanity round polynomials.
- Mutate selected and Boolean opening claims.
- Mutate the Hachi commitment.
- Mutate the Hachi proof bytes.
- Append trailing bytes to Hachi-serialized objects.
- Use a non-Boolean table with cancelling `sum B(B - 1)`.
- Verify proof-mode mismatches.

Added high-value tests:

- Non-Boolean cancelling table for the old unweighted Booleanity claim.
- Hachi trailing-byte and oversized-payload rejection.
- Proof-mode mismatch rejection.
- Representative byte-mutation rejection for `hachi-succinct` proofs.

Remaining useful coverage would be field-specific mutation helpers that target each transcript segment by semantic name rather than by representative byte offsets.

### Low: `hachi` Feature Can Panic During Setup For Small Circuits

Status: remediated.

Relevant code:

- `crates/verifier/src/verify.rs`
  - `Verifier::setup`
- `crates/iop/src/hachi_succinct_channel.rs`
  - `HachiSuccinctSetup::new`

When the `hachi` feature is enabled, `Verifier::setup` always constructs `HachiSuccinctSetup`, even if the caller only intends to use BaseFold or `hachi-full-open`. `HachiSuccinctSetup::new` asserts `log_msg_len >= 7`.

This can panic for small circuits. It is not a false-statement soundness issue, but it is a configuration footgun.

Implemented remediation:

- `Verifier::setup` now stores `Option<Arc<HachiSuccinctSetup>>`.
- Unsupported small-oracle configurations no longer panic during BaseFold or `hachi-full-open` setup.
- `prove_hachi_succinct` and `verify_hachi_succinct` now fail with structured errors when the succinct Hachi bridge does not support the oracle shape.

### Low: Prover-Controlled Hachi Object Lengths Can Cause DoS

Status: remediated with a conservative cap.

Relevant code:

- `crates/iop/src/hachi_wire.rs`
  - `read_hachi`

`read_hachi` allocates a `Vec<u8>` of prover-controlled length. This can be abused for memory exhaustion against services verifying untrusted proofs.

Implemented remediation:

- `read_hachi` rejects length prefixes above a conservative maximum before allocation.
- A tighter future improvement would derive per-object limits from the verifier-side Hachi proof shape.

### Low: Hachi Challenge Sampling Has Small Bias

Status: remediated.

Relevant code:

- `crates/iop/src/hachi_wire.rs`
  - `sample_hachi_scalar`
  - `verify_sample_hachi_scalar`

Previously, Hachi challenges were sampled by taking a Binius `B128` transcript sample and reducing the canonical `u128` into Hachi's `fp128` field. Because the Hachi modulus is slightly below `2^128`, this introduced a small bias.

The bridge now uses rejection sampling with `from_canonical_u128_checked`, preserving transcript determinism while removing the modulo-reduction bias.

## Sound Components

### Full-Opening Path

The `hachi-full-open` path appears sound as a conservative reference implementation.

The verifier:

- reads the full terminal Binius oracle,
- reads the transparent vector,
- checks bounded parity,
- recomputes the native `B128` inner product,
- checks the transparent closure against a random point.

Because the native terminal relation is checked directly over `B128`, this path does not rely on the succinct bridge's Booleanity argument.

### Native Binius Reductions Remain In Place

Both Hachi verifier entry points call the same `IOPVerifier::verify` flow used by BaseFold. The Hachi integration replaces only the final oracle relation check.

The following reductions still run:

- public input observation,
- IntMul reduction,
- BitAnd reduction,
- shift reduction,
- public input check,
- ring-switch verification,
- terminal batched claim construction.

### Direct Canonical Lift Is Not Used As A PCS Bridge

`CanonicalU128Bridge` explicitly documents and tests that the raw `u128` lift from `B128` into Hachi `fp128` is not field-homomorphic. The current succinct bridge uses selected-bit integer parity instead of relying on this invalid lift.

### Bounded Parity Is Sound If Inputs Are Boolean

The compact `S_k` optimization is sound under the intended Boolean table invariant.

The verifier:

- derives public bounds from transparent coefficients,
- decodes every `S_k` canonically,
- rejects out-of-range values,
- rejects nonzero padding bits,
- checks `S_k mod 2 == claim_bit`.

Removing quotient witnesses is fine because the verifier receives and range-checks each exact integer `S_k`.

### Selected-Sum Mask And Coordinate Order Look Consistent

The selected-sum mask uses the same raw `B128` basis as the terminal relation:

- `BiniusScalar::new(1u128 << input_bit)`,
- native `coefficient * basis`,
- output bits from `value.val()`.

The flattened table order is `(oracle_index, bit_index)`. The lazy verifier-side mask evaluation uses the first seven variables for bit index and the remaining variables for oracle index, matching the materialized table tests.

The Hachi one-hot selector coordinate is prepended with value `1`, consistently opening the bit-table value rather than its complement.

### Hachi Batched Openings Appear Statement-Bound

The Hachi verifier path absorbs batch shape, commitments, opening points, and opening values before deriving its internal batching challenges. This part looks sound assuming the Hachi PCS itself is binding for the committed field polynomial.

### Structured Transparent Relation Path Is Verifier-Owned

Status: partially implemented.

The `hachi-succinct` verifier can now take an optional structured transparent relation alongside the legacy transparent MLE closure. In the structured path, the verifier derives parity-sum bounds, selected-mask evaluation, and transparent MLE evaluation from verifier-owned code rather than from prover advice. The verifier also samples a final Binius point and checks the legacy transparent closure against the structured `eval_binius` result.

This is sound for implemented structured relations whose helper methods exactly match the materialized coefficient table. The current implementation includes a constant-coefficient relation and tests it against full materialization for:

- `eval_binius(point)`,
- `parity_sum_bounds()`,
- `eval_selected_mask(alpha, point)`.

It also includes a Hachi succinct negative test where an honest proof for one constant relation is verified against a different structured relation and is rejected.

The production terminal transparent relation remains on the legacy materialized fallback. Its coefficients are the ring-switch equality indicator plus a public-input equality patch. Although that relation's Binius MLE is sublinearly evaluable, the Hachi selected-mask table is a per-index nonlinear bit functional of each coefficient. No exact sublinear selected-mask evaluator has been implemented for that production relation.

Required next work before enabling the production structured path:

- derive and test an exact selected-mask evaluator for the ring-switch/public-input relation, or
- commit to an auxiliary selected-mask polynomial and prove it is tied to the public relation, or
- redesign the bridge so the selected-mask check is linear over verifier-evaluable public data.

Until then, using any shortcut for the production selected-mask value would be unsound. The legacy materialized path is intentionally preserved as the safe fallback.

## Remediation Summary

1. Fixed succinct Booleanity with a randomly weighted degree-3 Booleanity sumcheck.
2. Treated one-hot encoding as prover-only optimization and documented the verifier-side constraint.
3. Hardened Hachi wire decoding with EOF enforcement, a length cap, and trailing-byte tests.
4. Added top-level proof mode tags and mode-mismatch tests.
5. Made Hachi succinct setup optional/fallible for unsupported small circuits.
6. Replaced modulo-reduced Hachi challenge sampling with rejection sampling.
7. Added a verifier-owned structured transparent relation path for exact sublinear helper evaluation, currently implemented and tested for constant coefficient tables.

## Final Assessment

`hachi-full-open`: no confirmed soundness issue found.

`hachi-succinct`: the confirmed critical Booleanity gap has been fixed. The selected-sum and bounded-parity bridge now has an explicit verifier-checked Booleanity argument for the committed table. The structured transparent relation path is sound for implemented exact relation types, but the production ring-switch relation still uses the legacy materialized transparent table. The remaining soundness assumption is that the Hachi PCS is binding for the committed field polynomial and the stated openings.

