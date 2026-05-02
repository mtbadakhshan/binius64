# Hachi Integration Soundness Audit

Date: 2026-05-02

## Executive Summary

This audit reviewed the Hachi integration paths added to Binius64, with the specific goal of identifying whether a malicious prover can produce an accepting proof for a false Binius statement.

The conservative `hachi-full-open` path appears sound: it reveals the terminal Binius oracle and verifies the native `B128` inner-product relation directly.

The `hachi-succinct` path should be treated as **not production-sound in its current form**. The main issue is that its Booleanity proof is a single unweighted global sum over Hachi's odd-prime field:

```text
sum_x B(x) * (B(x) - 1) = 0
```

This does not imply pointwise Booleanity because nonzero terms can cancel in a prime field. Since the characteristic-2-to-prime bridge is sound only when the committed table is actually Boolean, this creates a plausible false-proof attack surface for the succinct bridge.

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
cargo run -p binius-examples --features hachi --example keccak -- --max-len-bytes 32 --message-len 32 --compression hachi-succinct
```

All commands passed. The tests do not cover the most important adversarial succinct-proof cases listed below.

## Findings

### Critical: Succinct Booleanity Check Is Not Pointwise

Status: confirmed soundness gap in the Binius-side succinct bridge.

Relevant code:

- `crates/iop/src/hachi_bridge.rs`
  - `booleanity_table_sumcheck_inputs`
  - `verify_product_sumcheck_transcript`
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

Recommended remediation:

- Replace the unweighted Booleanity check with a randomly weighted Booleanity sumcheck, for example proving:

```text
sum_x eq(r, x) * B(x) * (B(x) - 1) = 0
```

for verifier-sampled `r` after the commitment is fixed.

- Alternatively, use a PCS/admissible-message proof that verifier-side enforces the committed object is one-hot/Boolean. The current use of `OneHotPoly` is an honest-prover representation and should not be treated as verifier-enforced unless Hachi explicitly proves that property.

### High: Hachi `OneHotPoly` Is a Prover-Side Optimization, Not a Verifier-Side Constraint

Status: confirmed dependency gap.

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

Recommended remediation:

- Treat one-hot encoding as an implementation optimization only.
- Add explicit verifier-checked Booleanity or one-hot constraints.
- Document the distinction in `HACHI_PCS_INTEGRATION.md` and any API docs.

### High: Hachi Object Deserialization Does Not Enforce EOF

Status: confirmed malleability and Fiat-Shamir hardening issue.

Relevant code:

- `crates/iop/src/hachi_wire.rs`
  - `read_hachi`

`read_hachi` reads a prover-supplied length, deserializes the Hachi object from that byte slice, and returns the parsed value. It does not check that the deserializer consumed the entire slice.

If Hachi deserializers accept trailing bytes, a prover can create multiple transcript encodings of the same semantic message. Because the raw bytes are observed by the transcript, trailing ignored bytes can change later Fiat-Shamir challenges while leaving the parsed object unchanged.

This is not by itself a complete false-proof exploit, but it weakens the Fiat-Shamir soundness argument and creates a challenge-grinding/malleability surface.

Recommended remediation:

- Change `read_hachi` to deserialize through a cursor and reject unless the cursor is at EOF.
- Add tests that append trailing bytes to each Hachi scalar/proof object before a challenge is sampled and assert rejection.
- Consider fixed-size length checks for scalar types and bounded maximum lengths for proof objects.

### Medium: Proof Mode Is Not Bound In-Proof

Status: confirmed API hardening issue.

Relevant code:

- `crates/verifier/src/verify.rs`
  - `Verifier::verify`
  - `Verifier::verify_hachi_full_open`
  - `Verifier::verify_hachi_succinct`
- `crates/examples/src/lib.rs`
  - `CompressionType`

The proof mode is selected by the API method or CLI option, not encoded into the transcript. A native BaseFold proof, full-open Hachi proof, and succinct Hachi proof are expected to be verified by different verifier entry points.

This does not appear to create a silent false-proof issue because mode mismatches should fail parsing or transcript finalization. However, applications must externally bind proof bytes to the expected verification mode.

Recommended remediation:

- Add an explicit mode/domain tag to the top-level transcript.
- Add mode-mismatch tests:
  - BaseFold proof under `verify_hachi_succinct`.
  - Full-open proof under `verify_hachi_succinct`.
  - Succinct proof under `verify_hachi_full_open`.

### Medium: No Adversarial End-to-End Tests For `hachi-succinct`

Status: confirmed test gap.

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

These tests should be added before treating the succinct bridge as security-critical.

### Low: `hachi` Feature Can Panic During Setup For Small Circuits

Status: confirmed availability issue.

Relevant code:

- `crates/verifier/src/verify.rs`
  - `Verifier::setup`
- `crates/iop/src/hachi_succinct_channel.rs`
  - `HachiSuccinctSetup::new`

When the `hachi` feature is enabled, `Verifier::setup` always constructs `HachiSuccinctSetup`, even if the caller only intends to use BaseFold or `hachi-full-open`. `HachiSuccinctSetup::new` asserts `log_msg_len >= 7`.

This can panic for small circuits. It is not a false-statement soundness issue, but it is a configuration footgun.

Recommended remediation:

- Lazily initialize succinct setup only for `verify_hachi_succinct`.
- Or return a structured setup error instead of asserting.

### Low: Prover-Controlled Hachi Object Lengths Can Cause DoS

Status: confirmed robustness issue.

Relevant code:

- `crates/iop/src/hachi_wire.rs`
  - `read_hachi`

`read_hachi` allocates a `Vec<u8>` of prover-controlled length. This can be abused for memory exhaustion against services verifying untrusted proofs.

Recommended remediation:

- Add maximum encoded sizes derived from verifier-side proof shape.
- Reject oversized Hachi object lengths before allocation.

### Low: Hachi Challenge Sampling Has Small Bias

Status: confirmed soundness-accounting issue.

Relevant code:

- `crates/iop/src/hachi_wire.rs`
  - `sample_hachi_scalar`
  - `verify_sample_hachi_scalar`

Hachi challenges are sampled by taking a Binius `B128` transcript sample and reducing the canonical `u128` into Hachi's `fp128` field. Because the Hachi modulus is slightly below `2^128`, this introduces a small bias.

This is unlikely to matter practically for the current degree checks, but it should be accounted for in the formal soundness bound or replaced with rejection sampling/domain-native Hachi scalar sampling.

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

## Recommended Fix Plan

1. Fix succinct Booleanity before using `hachi-succinct` for sound proofs.
   - Add a randomly weighted Booleanity check.
   - Or add verifier-enforced one-hot/admissible-message proofs in Hachi.

2. Harden Hachi wire decoding.
   - Enforce EOF after deserializing each length-prefixed object.
   - Add maximum object lengths.
   - Add trailing-byte malleability tests.

3. Add adversarial end-to-end tests.
   - Start with proof mutation tests for `hachi-succinct`.
   - Include non-Boolean cancellation witnesses if practical.

4. Add top-level mode tags.
   - Bind `basefold`, `hachi-full-open`, and `hachi-succinct` into the transcript.

5. Make Hachi succinct setup lazy or fallible.
   - Avoid panics for small circuits in `--features hachi` builds.

## Final Assessment

`hachi-full-open`: no confirmed soundness issue found.

`hachi-succinct`: not sound as currently written, due to the unweighted global Booleanity check. The selected-sum and bounded-parity bridge can be sound only after the verifier has a real pointwise Booleanity or one-hot guarantee for the committed table.

