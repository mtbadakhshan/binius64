# [HISTORICAL] Upstream Bug Report: `OneHotPoly` `block_len` mismatch in `AkitaCommitmentScheme::batched_prove` at `max_num_vars >= 19` with shared commitments

> **This is a historical record of a RESOLVED upstream issue. It is preserved
> for traceability and is NOT a pending bug. For the currently-open Akita
> issue affecting our bridge, see `docs/akita-k2-onehot-bug-report.md`.**

**Status**: **RESOLVED** in upstream commit `0873a7f19b45acfa3724a652a3861f946fac8add` on the `taghi/fix/shared-commitment-multipoint-opening` branch of `lz-hachi` (post-`53d7083`). The fix adds a new `CommitmentProver::commit_for_multipoint` API plus commitment-pointer-identity dedup in `prover_claims_to_incidence` / `verifier_claims_to_incidence`. Our bridge was updated to use the new pattern.

**Note on caller-side follow-up**: when our bridge was first updated to use the new `commit_for_multipoint` API plus the upstream regression test's clone pattern, an honest end-to-end roundtrip *still* failed at every size with a different symptom — Akita's `batched_verify` returned `InvalidProof`. This turned out to be **two caller-side bugs**, NOT additional upstream issues:

1. An off-by-one in our schedule-driven shape derivation (`hachi_succinct_opening_shape` / `hachi_claim_reduced_opening_shape`) that miscounted the recursive fold levels by 1.
2. A prover/verifier disagreement on Akita's pointer-identity dedup: the prover used clones (two `&Commitment` pointers ⇒ `num_groups = 2`), the verifier used a shared reference (one pointer ⇒ `num_groups = 1`).

Bug 1 was missed in the pre-fix port; Bug 2 was missed because the regression test asserted only **negative** outcomes (wrong-mode rejection / tamper rejection) — an always-erroring verifier trivially passes such assertions. Both are documented in detail in `docs/hachi-bridge-akita-port-audit-log.md::Audit #005`. The upstream fix itself was correct; our bridge just hadn't fully aligned with the new contract until after these bugs were diagnosed.

## Summary

`AkitaCommitmentScheme::batched_prove` panics with an internal `OneHotPoly::fold_blocks` `InvalidInput` error when called with two opening points that share a single committed `OneHotPoly`, at `max_num_vars >= 19`. The panic occurs deep in Akita's lattice-commitment machinery, before any caller-side state can intervene.

The same configuration succeeds at `max_num_vars = 18`, so this is a size-dependent regression that becomes visible only above a threshold.

## Environment

- Akita commit: `53d7083` (2026-05-08, `Thread commitment mode through ZK hiding (#67)`)
- Akita workspace path: `/Users/taghi.badakhshan/Projects/lz-hachi/`
- Binius consumer: `binius-iop` / `binius-iop-prover` on the `taghi/learn-e2e` branch of `binius64`, with the `hachi` feature flag enabled.
- Cargo features: `akita-config/planner` enabled (required for on-the-fly schedule derivation).
- Rust: 1.95.0, target `aarch64-apple-darwin`.

## Symptom

```
thread 'main' panicked at /Users/.../lz-hachi/crates/akita-prover/src/backend/onehot.rs:915:14:
OneHotPoly::fold_blocks: invalid block_len for this polynomial:
InvalidInput("OneHotPoly was first used with block_len=512 but is now being used
              with block_len=256; all ops on the same polynomial must share a single layout")
```

The panic site is `akita-prover/src/backend/onehot.rs:915`, inside `OneHotPoly::fold_blocks`. The polynomial in question is the bit-table `OneHotPoly` that the Binius Hachi bridge commits in `iop-prover/src/hachi_succinct_channel.rs::send_oracle`.

## Reproducer

From the binius64 repository on the `taghi/learn-e2e` branch with `lz-hachi` cloned at `../lz-hachi`:

```bash
# Fails:
cargo run --release -p binius-examples --features hachi --example keccak -- \
    --max-len-bytes 512 --message-len 512 --compression hachi-succinct

# Also fails:
cargo run --release -p binius-examples --features hachi --example sha256 -- \
    --max-len-bytes 256 --message-len 256 --compression hachi-succinct

# Also fails:
cargo run --release -p binius-examples --features hachi --example ethsign -- \
    --max-msg-len-bytes 256 --compression hachi-succinct
```

The following sizes succeed:

```bash
# Works (max_num_vars=18):
cargo run --release -p binius-examples --features hachi --example keccak -- \
    --max-len-bytes 256 --message-len 256 --compression hachi-succinct

# Works (max_num_vars=20):
cargo run --release -p binius-examples --features hachi --example keccak -- \
    --max-len-bytes 1024 --message-len 1024 --compression hachi-succinct
```

The pattern is **odd `max_num_vars` (19, 21, 25, ...)** fail; **even `max_num_vars` (18, 20, ...)** succeed, with the exception of some smaller sizes whose schedule structure differs.

## Trigger conditions

All of the following hold in the failing cases:

1. `max_num_vars >= 19`
2. Two opening points (`num_points = 2`) — in the Binius bridge these are the `selected_point` and `bool_point` used for the parity-bridge sumcheck and the booleanity sumcheck respectively.
3. Both opening points reference the **same** committed `OneHotPoly` (one polynomial commit, opened twice — `&data.commitment` is shared between the two `CommittedPolynomials` entries in `ProverClaims`).
4. The schedule planner has been invoked with `(max_num_vars=19, num_claims=2, num_groups=2, num_points=2)` (or analogous at higher sizes), producing a `fold_levels=4` (or higher) schedule.

## Expected vs actual behavior

**Expected**: `AkitaCommitmentScheme::batched_prove` produces a valid `AkitaBatchedProof` that can be deserialized by the verifier using the shape derived from `(max_num_vars, num_claims, num_groups, num_points)`, regardless of whether the two opening points happen to share a commitment.

**Actual**: `OneHotPoly::fold_blocks` panics because the same `OneHotPoly` is being used with `block_len=512` somewhere and `block_len=256` somewhere else within the same `batched_prove` invocation.

## Evidence from logs

The Akita schedule planner runs **four** times during setup, computing schedules for all four `(num_groups, num_points)` combinations at the same `max_num_vars`:

```
schedule planner: ... max_num_vars: 19, ..., num_commitment_groups: 1, num_points: 1, total_bytes: 64136, fold_levels: 4
schedule planner: ... max_num_vars: 19, ..., num_commitment_groups: 1, num_points: 2, total_bytes: 67296, fold_levels: 4
schedule planner: ... max_num_vars: 19, ..., num_commitment_groups: 2, num_points: 1, total_bytes: 64240, fold_levels: 4
schedule planner: ... max_num_vars: 19, ..., num_commitment_groups: 2, num_points: 2, total_bytes: 67416, fold_levels: 4
```

This suggests Akita internally consults multiple sub-schedules during one `batched_prove` invocation. At small sizes the resulting block_lens happen to coincide; at `max_num_vars >= 19` they diverge, and the `OneHotPoly` invariant fires.

## Suspected root cause

Hypothesis: the `OneHotPoly` `block_len` is derived from one of the sub-schedules at commit time, but at opening time `batched_prove` picks a different sub-schedule whose layout would require a different `block_len`. The internal layout choice may depend non-trivially on the relationship between `max_num_vars`, `num_groups`, and `num_points`.

Possible loci (not yet pinpointed):
- `akita-prover/src/backend/onehot.rs:915` — where the panic fires.
- `AkitaCommitmentScheme::batched_prove` in `akita-scheme/src/lib.rs` — top-level orchestration.
- `prover_claims_to_incidence` in `akita-prover/src/protocol/flow.rs:168` — flattens `ProverClaims` into the incidence graph; no dedup on commitment pointer.

The `OneHotPoly` consistency assertion is the right invariant; the question is which call site is responsible for the inconsistency.

## Caller-side workaround

Hachi full-open mode (`prove_hachi_full_open` / `verify_hachi_full_open`) is unaffected; it works at every tested size. The Binius bridge's full-open path commits and opens differently and does not share the `OneHotPoly` between operations in the way that triggers this bug.

For consumers needing the succinct path at `max_num_vars >= 19`, no caller-side workaround has been found. Committing the polynomial twice (once per opening point) was considered but would defeat the point of multi-point batched opening.

## Caller-side soundness posture

The Binius Hachi bridge has a post-deserialization safety-net check:

```rust
if proof.shape() != expected_shape {
    return Err(Error::ProofEmpty);
}
```

This catches any case where our caller-side shape derivation diverges from Akita's prover-side derivation. The check did NOT fire in the failing scenarios — confirming that **our shape derivation is correct**; the issue is genuinely upstream-internal.

## What we tried in our deep-dive

1. **Hypothesis: caller-side `HACHI_OPENING_GROUPS = 2` was wrong** — disproven by reading `verifier_claims_to_incidence` (`akita-types/src/proof/incidence.rs:48`) and `prover_claims_to_incidence` (`akita-prover/src/protocol/flow.rs:168`): both append a new group per `CommittedOpenings`/`CommittedPolynomials` entry with no deduplication on commitment pointer. Two entries ⇒ two groups, regardless of whether they share a commitment.

2. **Hypothesis: caller-side shape derivation is wrong at `max_num_vars >= 19`** — disproven by adding diagnostic `eprintln!` at every check site in our verifier (`hachi_succinct_opening_shape` returning early, `read_hachi` failing, the `proof.shape() != expected_shape` safety net firing). None of them fire on the failing case because Akita panics in `batched_prove` before our verifier code runs.

## References

- Caller code: `crates/iop/src/hachi_succinct_channel.rs` and `crates/iop-prover/src/hachi_succinct_channel.rs` on the `taghi/learn-e2e` branch of `binius64`.
- Caller-side audit log: `docs/hachi-bridge-akita-port-audit-log.md` (Audit #003-A).
- Caller-side port plan: `docs/hachi-bridge-akita-port-plan.md`.

## Resolution status

1. **Triage**: ✅ resolved — confirmed as a real Akita-internal bug and fixed in commit `0873a7f`.
2. **Fix or document**: ✅ resolved — fixed via the new `commit_for_multipoint` API + pointer-identity dedup.
3. **Re-expose `batched_proof_shape_for_lookup_key`** (low priority, **still open**): third-party callers like the Binius Hachi bridge currently transcribe Akita's test-internal `expected_same_point_batched_shape` to derive proof shapes from public parameters. A public function would let callers avoid touching test-internal code. Worth filing as a small additive PR.

### Subsequent unrelated finding

A separate Akita issue, the `OneHotPoly K=2` failure at large `max_num_vars`, was identified during validation of this bug's fix. It has its own dedicated report: `docs/akita-k2-onehot-bug-report.md`.
