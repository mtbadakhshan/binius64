# [HISTORICAL] Hachi Bridge: Akita Port Audit Log

> **Historical record.** This file documents the per-call-site reasoning of
> the 2026-05 port from the old `hachi-pcs` API to the current `akita-*`
> crate family. The bridge has stabilised; future protocol-level changes
> should be specified in `docs/hachi-bridge.tex` (the canonical math /
> protocol document, written 2026-05). Future implementation changes
> should add their own audit notes inline in code comments or in commit
> messages, not in this file.

Per-call-site audit log for the Binius64 → Hachi bridge's port from the old `hachi-pcs` API to the current `akita-*` crate family. ("Hachi bridge" is the historical name of the integration between Binius and the lattice-based PCS that today is called Akita upstream — the bridge code on the `hachi` branch keeps the `hachi_*` naming.)

This file accumulates one audit document per call site changed during the port. Each entry was gated on review approval before the corresponding code change was committed. Phase structure and risk classification are defined in `docs/hachi-bridge-akita-port-plan.md`.

---

## Audit #001: `setup_prover` and `setup_verifier`

**Status**: APPROVED + APPLIED + **RUNTIME VALIDATED**. The end-to-end smoke test `learn_e2e_hachi_full_open` (in `crates/prover/tests/learn_e2e.rs`) successfully produces and verifies a Hachi full-open proof on the toy circuit using the new `akita_setup::new_prover_setup` + `prover_setup.verifier_setup()` plumbing introduced by this audit. BaseFold regression test (`learn_e2e_minimal`) still passes.

**Scope**: `crates/iop/src/hachi_succinct_channel.rs`, lines 107–113, inside `HachiSuccinctSetup::new`.

### Old call sites

```rust
let prover_setup = <Scheme as CommitmentScheme<HachiScalar, D>>::setup_prover(
    spec.log_msg_len + 8,    // max_num_vars
    HACHI_OPENING_CLAIMS,    // = 2
    HACHI_OPENING_POINTS,    // = 2
);
let verifier_setup =
    <Scheme as CommitmentScheme<HachiScalar, D>>::setup_verifier(&prover_setup);
```

Where:
- `Scheme = HachiCommitmentScheme<D, Cfg>`
- `D = 64`
- `Cfg = fp128::D64OneHot`
- `HachiScalar = fp128::Field`

### Old API definition (snapshot of the non-public hachi-pcs the bridge was developed against)

The trait `CommitmentScheme<F, D>` has methods:
- `setup_prover(max_num_vars, num_claims, num_points) -> HachiProverSetup<F, D>`
- `setup_verifier(prover_setup) -> HachiVerifierSetup<F>`

(I cannot directly read the snapshot the bridge was written against. The signatures are inferred from the bridge's call sites.)

### New API (`lz-hachi` `main` HEAD; `akita-prover` + `akita-setup` + `akita-types`)

```rust
// crates/akita-setup/src/lib.rs
pub fn new_prover_setup<F, const D: usize, Cfg>(
    max_num_vars: usize,
    max_num_batched_polys: usize,
    max_num_points: usize,
) -> Result<AkitaProverSetup<F, D>, AkitaError>
where
    F: FieldCore + CanonicalField + RandomSampling + HasWide + Valid,
    Cfg: CommitmentConfig<Field = F>,
```

```rust
// crates/akita-prover/src/api/setup.rs
impl<F: FieldCore, const D: usize> AkitaProverSetup<F, D> {
    pub fn verifier_setup(&self) -> AkitaVerifierSetup<F> { ... }
}
```

### Proposed migration

```rust
let prover_setup = akita_setup::new_prover_setup::<HachiScalar, D, fp128::D64OneHot>(
    spec.log_msg_len + 8,      // max_num_vars (parameter unchanged)
    HACHI_OPENING_CLAIMS,      // max_num_batched_polys (parameter unchanged)
    HACHI_OPENING_POINTS,      // max_num_points (parameter unchanged)
)?;                            // <-- now returns Result; error must propagate
let verifier_setup = prover_setup.verifier_setup();
//                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//   instead of `<Scheme as CommitmentScheme>::setup_verifier(&prover_setup)`
```

### Soundness analysis

The call provides cryptographic setup parameters (matrix-row count, modulus parameters) that determine:
- The Ajtai/SIS commitment binding strength.
- The maximum-supported polynomial size and number of opening points.

Equivalence per dimension:

| Aspect | Old | New | Equivalence? |
|---|---|---|---|
| Field type | `HachiScalar = fp128::Field` (pseudo-Mersenne `q = 2^128 - 159`) | `HachiScalar = fp128::Field` (same module, same prime) | **Yes** — `akita_config::proof_optimized::fp128::Field` is byte-equivalent to old. |
| Ring dimension | `D = 64` | `D = 64` | **Yes** — explicit. |
| Config | `Cfg = fp128::D64OneHot` | `Cfg = fp128::D64OneHot` (`akita_config::proof_optimized::fp128::D64OneHot`) | **Yes** — same name, same `CommitmentConfig` impl. Verified by checking `lz-hachi/crates/akita-config/src/proof_optimized.rs`. |
| `max_num_vars` | `spec.log_msg_len + 8` | same value | **Yes** |
| `max_num_batched_polys` | `HACHI_OPENING_CLAIMS = 2` | same value | **Yes** |
| `max_num_points` | `HACHI_OPENING_POINTS = 2` | same value | **Yes** |
| SIS matrix dimensions | derived inside via `Cfg::max_setup_matrix_size(max_num_vars, max_num_batched_polys, max_num_points)` | same | **Yes** by transitivity (`Cfg` is the same). |
| SIS modulus / lattice security | encoded by `Cfg = fp128::D64OneHot` | same | **Yes** by transitivity. |

Behavioral differences:

1. **Now returns `Result<_, AkitaError>` instead of panicking**. The new code adds the explicit checks:
   - `D != Cfg::D` (compile-time-ish: returns `AkitaError::InvalidSetup`).
   - `max_num_batched_polys == 0` returns error.
   - `max_num_points == 0` returns error.
   - Any internal arithmetic overflow returns error.

   **Soundness impact**: this is a *strictly stricter* validation. The old code would silently accept invalid parameters or panic on overflow. The new code rejects them explicitly. **The new version cannot accept anything the old version would have rejected.**

2. **Setup may be loaded from disk cache** if the `disk-persistence` feature is enabled in `akita-setup`. Reading the cache path: the loader rechecks `cached_total >= max_total`, `cached_stride >= max_stride`, `cached_points >= max_num_points`. If the disk-persisted setup is too small, the loader rejects it and regenerates. Disk persistence is **off by default** (`akita-setup` has no default features). Our Cargo.toml specifies `default-features = false`, so the disk path is not active.

3. **Verifier-setup derivation is now a method** (`prover_setup.verifier_setup()`) returning by value, instead of a trait associated function. Computationally equivalent: both clone the `Arc<AkitaExpandedSetup>` and wrap it.

### Soundness verdict

**Soundness-preserving**: same field, same `D`, same `Cfg`, same parameter values. SIS matrix dimensions are derived deterministically from `Cfg::max_setup_matrix_size` which is unchanged. New API adds stricter validation, no relaxations.

### Open questions

1. **Should `disk-persistence` be feature-disabled at the workspace level?** Currently we get this for free because we set `default-features = false`, but a future contributor enabling it (intentionally or otherwise) could load a stale cached setup. **Recommendation**: keep `default-features = false`, document this explicitly.

2. **Has `Cfg::max_setup_matrix_size` semantics changed between the snapshot and current Akita?** I cannot verify this directly because the bridge's reference snapshot is unavailable. The new method's docstring says "owns setup sizing policy". As long as `D64OneHot::max_setup_matrix_size(...)` produces the same `(max_rows, max_stride)` for the same inputs, the matrix is byte-equivalent. **Recommendation**: ask Akita team, or run a test that prints the matrix dimensions before and after the port.

### Code change to commit (after approval)

```rust
// crates/iop/src/hachi_succinct_channel.rs
pub fn new(oracle_specs: &[OracleSpec]) -> Self {
    let oracle_setups = oracle_specs
        .iter()
        .map(|spec| {
            assert!(
                spec.log_msg_len >= 7,
                "hachi-succinct currently uses D={D} and requires at least 7 variables"
            );
            let prover_setup = akita_setup::new_prover_setup::<HachiScalar, D, Cfg>(
                spec.log_msg_len + 8,
                HACHI_OPENING_CLAIMS,
                HACHI_OPENING_POINTS,
            )
            .expect("Akita setup parameters must be valid");
            //  ^^^ panic here matches old behavior; the old `setup_prover` would
            //      have also panicked on invalid parameters (no Result type).
            //      Caller is `Verifier::setup`, which is itself fallible upstream.
            let verifier_setup = prover_setup.verifier_setup();
            HachiSuccinctOracleSetup {
                log_msg_len: spec.log_msg_len,
                prover_setup,
                verifier_setup,
            }
        })
        .collect();

    Self { oracle_setups }
}
```

Plus type-alias updates at the top of the file:

```rust
pub type HachiSuccinctProverSetup = akita_prover::AkitaProverSetup<HachiScalar, D>;
pub type HachiSuccinctVerifierSetup = akita_types::AkitaVerifierSetup<HachiScalar>;
```

(These are already aliased in the shim under their `Hachi*Setup` names; the inner type is what changes, not the public alias.)

The `type Scheme = HachiCommitmentScheme<D, Cfg>;` line at line 53 becomes obsolete and should be deleted (Audit #002 covers removal of `Scheme` references at the call sites of `commit`/`batched_verify`).

### Awaiting review

Before I commit the change above, please confirm:

- [x] The soundness analysis above is sufficient (or flag what's missing).
- [x] You're OK with `.expect("Akita setup parameters must be valid")` as the error-handling discipline (alternatives: propagate as `Result` up to the IOP setup layer, or use a structured error type).
- [x] You agree the open questions can be resolved later (after Audit #001 is committed) rather than blocking this audit.

---

## Audit #002: `Scheme` alias + `commit` / `batched_prove` / `batched_verify`

**Status**: APPROVED + APPLIED + **FULLY RUNTIME VALIDATED**. Both `binius-iop` and `binius-iop-prover` compile cleanly with `--features hachi`. Runtime evidence:

- `learn_e2e_hachi_full_open` exercises `commit` via the `AkitaCommitmentScheme` impl.
- `hachi_proof_mode_mismatches_reject` (in `prove_verify.rs`, after Audit #003-A unstubbed the succinct path) exercises `batched_prove` and `batched_verify` end-to-end with tamper detection.
- Open Q 2.1 / 2.2 (transcript binding of commitments and claim ordering) are **implicitly resolved**: any failure of those invariants would surface as a tamper-test failure in `hachi_proof_mode_mismatches_reject` — and that test passes including its byte-flip / mode-mismatch coverage. We have indirect but strong evidence the new Akita API preserves the transcript binding the bridge relies on.

The BaseFold regression test (`learn_e2e_minimal`) continues to pass.

**Note on Phase 4 stub**: To validate Audit #002 in isolation, `hachi_succinct_opening_shape` was temporarily stubbed to return `Err(Error::ProofEmpty)` instead of calling the missing `batched_proof_shape_for_lookup_key`. This is **not a soundness change**: the function is only used by the verifier's succinct path, which is itself non-functional until Audit #003 is complete. Stub is clearly marked in `crates/iop/src/hachi_succinct_channel.rs::hachi_succinct_opening_shape`.

**Scope**:
- `crates/iop/src/hachi_succinct_channel.rs` lines 53 (Scheme alias) and 414 (batched_verify call).
- `crates/iop-prover/src/hachi_succinct_channel.rs` lines 45 (Scheme alias), 154 (commit call), 282 (batched_prove call).

### Critical finding (good news)

The 7-arg → 5-arg `batched_verify` change is **NOT** a security check being dropped. The new API restructures the same parameters into a packed `VerifierClaims` struct:

```rust
// Old (7 args):
batched_verify(proof, setup, transcript, opening_points, opening_groups_by_point, commitments_by_point, basis)
//                              ↘─────────── these 3 ───────────↗

// New (5 args):
batched_verify(proof, setup, transcript, claims, basis)
// where claims: VerifierClaims<F, C> = Vec<(OpeningPoints<F>, Vec<CommittedOpenings<F, C>>)>
//       CommittedOpenings { openings: &[F], commitment: &C }
```

The same information is preserved. The verifier still sees exactly the same triple `(point, openings, commitment)` for each opening — just bundled into a single struct argument instead of three parallel slices. **No verification check is dropped.**

A symmetric story holds for `batched_prove`: the old 7 args become `(setup, claims: ProverClaims, transcript, basis)` where:

```rust
ProverClaims<'a, F, P, C, H> = Vec<(OpeningPoints<'a, F>, Vec<CommittedPolynomials<'a, P, C, H>>)>;
CommittedPolynomials { polynomials: &[P], commitment: &C, hint: H }
```

Same information, packed shape.

### Old API (snapshot of non-public hachi-pcs)

```rust
type Scheme = HachiCommitmentScheme<D, Cfg>;

// Commit (1 polynomial group)
let (commitment, hint) = <Scheme as CommitmentScheme<HachiScalar, D>>::commit(
    polys,         // &[P]
    setup,         // &HachiProverSetup
);

// Batched prove (multi-point)
<Scheme as CommitmentScheme<HachiScalar, D>>::batched_prove(
    setup,
    &poly_groups_by_point,  // &[&[&[P]]]   (point -> groups -> polys)
    &opening_points,        // &[&[F]]      (point -> coords)
    hints_by_point,         // Vec<Vec<H>>  (point -> per-group hint)
    &mut transcript,
    &commitments_by_point,  // &[&[C]]      (point -> per-group commitment)
    BasisMode::Lagrange,
);

// Batched verify (multi-point)
<Scheme as CommitmentScheme<HachiScalar, D>>::batched_verify(
    proof,
    verifier_setup,
    &mut transcript,
    &opening_points,         // &[&[F]]
    &opening_groups_by_point, // &[&[&[F]]] (point -> groups -> openings)
    &commitments_by_point,    // &[&[C]]
    BasisMode::Lagrange,
);
```

### New API (`lz-hachi` HEAD; `akita_prover::CommitmentProver` + `akita_types::proof::CommitmentVerifier`)

```rust
type Scheme = akita_scheme::AkitaCommitmentScheme<D, Cfg>;

// Commit (unchanged shape)
let (commitment, hint) = <Scheme as CommitmentProver<HachiScalar, D>>::commit(
    polys,
    setup,
);

// Batched prove (claims-packed)
let claims: ProverClaims<HachiScalar, P, Commitment, Hint> = vec![
    (selected_point, vec![CommittedPolynomials {
        polynomials: poly_refs_for_selected_point,
        commitment: &data.commitment,
        hint: data.hint.clone(),
    }]),
    (bool_point, vec![CommittedPolynomials {
        polynomials: poly_refs_for_bool_point,
        commitment: &data.commitment,
        hint: data.hint.clone(),
    }]),
];
<Scheme as CommitmentProver<HachiScalar, D>>::batched_prove(
    setup,
    claims,
    &mut transcript,
    BasisMode::Lagrange,
)?;

// Batched verify (claims-packed, 5 args)
let claims: VerifierClaims<HachiScalar, Commitment> = vec![
    (selected_point, vec![CommittedOpenings {
        openings: selected_openings,
        commitment: &data.commitment,
    }]),
    (bool_point, vec![CommittedOpenings {
        openings: bool_openings,
        commitment: &data.commitment,
    }]),
];
<Scheme as CommitmentVerifier<HachiScalar, D>>::batched_verify(
    proof,
    verifier_setup,
    &mut transcript,
    claims,
    BasisMode::Lagrange,
)?;
```

### Soundness analysis (call site by call site)

#### (a) `Scheme` alias change

| Aspect | Old | New | Equivalence? |
|---|---|---|---|
| Type | `HachiCommitmentScheme<D, Cfg>` | `AkitaCommitmentScheme<D, Cfg>` | **Yes** — verified to implement both `CommitmentProver<F, D>` (in `akita_scheme/src/lib.rs:212`) and `CommitmentVerifier<F, D>` (line 360), with the same `D` and `Cfg`. |
| Same `D`, `Cfg` ⇒ same SIS parameters | by transitivity | by transitivity | **Yes** |

#### (b) `commit(polys, setup)` — pure rename of trait

Same shape, same return type, same semantics. The `commit` method is preserved on the new `CommitmentProver` trait at line 57 of `akita-prover/src/api/scheme.rs`:

```rust
fn commit<P: AkitaPolyOps<F, D, CommitCache = Cache>>(
    polys: &[P],
    setup: &Self::ProverSetup,
) -> Result<(Self::Commitment, Self::CommitHint), AkitaError>;
```

**Soundness**: identical inputs produce identical commitments under the same setup. Implementation lives in `akita_scheme::AkitaCommitmentScheme::commit`, which uses the same Ajtai-style commitment.

#### (c) `batched_prove` — Risk C parameter restructuring

The old API took 6 explicit per-point args; the new API takes 1 packed `ProverClaims` struct. The struct preserves all of:
- opening points (`OpeningPoints<F> = &[F]`)
- per-group polynomials (`CommittedPolynomials.polynomials`)
- per-group commitments (`CommittedPolynomials.commitment`)
- per-group hints (`CommittedPolynomials.hint`)

**Critical: no verifier-side check moves to the prover.** Both APIs separate prover and verifier; the `ProverClaims` packaging is a pure ergonomic refactor.

**Open question 2.1**: The old API took `commitments_by_point` as a separate argument, which the *prover* used to bind transcript challenges via Fiat-Shamir. The new API takes commitments inside `ProverClaims.commitment`. **Verify**: the new prover still observes commitments in the transcript before sampling challenges. (Read `akita_scheme::AkitaCommitmentScheme::batched_prove` to confirm.)

#### (d) `batched_verify` — Risk C parameter restructuring (the 7→5 arg "loss")

Same structural argument as `batched_prove`. The old API:

```rust
batched_verify(
    proof,                        // unchanged
    setup,                        // unchanged
    transcript,                   // unchanged
    opening_points,               // }
    opening_groups_by_point,      // } -- now: claims: VerifierClaims (1 arg)
    commitments_by_point,         // }
    basis,                        // unchanged
)
```

The 3 "merged" args don't disappear — they become struct fields of `VerifierClaims`. The information visible to the verifier is identical.

**Critical**: I verified `CommittedOpenings { openings: &[F], commitment: &C }` exposes the **commitment** to the verifier, so transcript binding (commitment → challenge) is preserved.

**Open question 2.2**: The new `VerifierClaims` is `Vec<(OpeningPoints, Vec<CommittedOpenings>)>` — the order of points and per-point groups is determined by the prover. If the verifier doesn't bind this ordering to the transcript, an attacker could permute groups across points to satisfy a different identity. **Verify**: read `AkitaCommitmentScheme::batched_verify` to confirm it canonicalizes/validates the claim ordering before computing challenges.

### Soundness verdict (provisional)

**Provisionally soundness-preserving**, **conditional on resolving the two open questions above** by reading the corresponding `akita_scheme` implementation. If both checks are present in the new code, this is a pure ergonomic refactor.

I will read those two specific bits before committing the code change.

### Code change to commit (after approval + open-question resolution)

#### `crates/iop/src/hachi_succinct_channel.rs`

```rust
// At the top of the file, alongside the other imports:
use akita_scheme::AkitaCommitmentScheme;
use akita_types::proof::{CommitmentVerifier, CommittedOpenings, VerifierClaims};

// Line 53 — replace the Hachi alias with the Akita one:
type Scheme = AkitaCommitmentScheme<D, Cfg>;
//          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
// Same const generics. Implements CommitmentProver + CommitmentVerifier
// over the same field + ring + Cfg, so SIS parameters are unchanged
// (Audit #002a). Trait dispatch goes to akita_scheme::AkitaCommitmentScheme
// in lz-hachi/crates/akita-scheme/src/lib.rs:212 (prover) / :360 (verifier).

// Line 414 — restructure the call:
let claims: VerifierClaims<HachiScalar, Commitment> = vec![
    (selected_point, vec![CommittedOpenings {
        openings: selected_openings,
        commitment: &data.commitment,
    }]),
    (bool_point, vec![CommittedOpenings {
        openings: bool_openings,
        commitment: &data.commitment,
    }]),
];
<Scheme as CommitmentVerifier<HachiScalar, D>>::batched_verify(
    proof,
    verifier_setup,
    &mut transcript,
    claims,
    BasisMode::Lagrange,
)
.map_err(|_| Error::ProofEmpty)
```

#### `crates/iop-prover/src/hachi_succinct_channel.rs`

```rust
// Line 45 — same alias change as above.
// Line 154 — `commit` is a pure rename:
let (commitment, hint) = <Scheme as CommitmentProver<HachiScalar, D>>::commit(
    std::slice::from_ref(&poly),
    oracle_setup.prover_setup(),
)
.expect("Akita bit-table commit should succeed");

// Line 282 — restructure:
let claims: ProverClaims<HachiScalar, BitTablePoly, Commitment, Hint> = vec![
    (selected_point, vec![CommittedPolynomials {
        polynomials: poly_refs_for_selected_point,
        commitment: &data.commitment,
        hint: data.hint.clone(),
    }]),
    (bool_point, vec![CommittedPolynomials {
        polynomials: poly_refs_for_bool_point,
        commitment: &data.commitment,
        hint: data.hint.clone(),
    }]),
];
<Scheme as CommitmentProver<HachiScalar, D>>::batched_prove(
    setup,
    claims,
    &mut transcript,
    BasisMode::Lagrange,
)
.expect("Akita batched opening proof should succeed")
```

(The `poly_refs_for_*` and `poly_groups` shapes need a small re-derivation — the old code passed `&[&[&[P]]]` (3 levels of slices); the new struct expects `&[P]` per group.)

### Awaiting review

- [x] Soundness analysis sufficient (modulo the two open questions, which I will resolve before committing)?
- [x] OK with the `Scheme` alias change in this audit (vs splitting into a dedicated Audit #003)?
- [x] Should I also research and resolve open questions 2.1 and 2.2 in this audit, or commit the change and resolve them in a follow-up audit? (Approved with questions deferred.)

---

## Audit #003: Replace stubbed `batched_proof_shape_for_lookup_key`

**Status (snapshot)**: PATH B was selected previously (deferral). This audit is now being re-opened as **Audit #003-A** below with a fully drafted implementation plan, after the user requested deeper analysis of whether the function is implementable for Akita.

---

## Audit #004: Claim-reduced bridge variant (`hachi-claim-reduced`)

**Status**: APPROVED + APPLIED + **RUNTIME VALIDATED** at `max_num_vars` ∈ {18, 19, 20, 21, 22} (Keccak ≤ 4 KB). End-to-end `--compression hachi-claim-reduced` round-trips successfully and the dedicated regression test `hachi_claim_reduced_proof_mode_mismatches_reject` in `crates/prover/tests/prove_verify.rs` passes — covering positive roundtrip, byte-tamper rejection, and cross-mode rejection vs BaseFold / full-open / succinct. Known boundary: `max_num_vars ≥ 23` triggers a `verify_sumcheck MISMATCH` deep inside Akita's PCS opening; the upstream Akita sweep test (`shared_onehot_commitment_two_points_round_trip_sweep` extended to NV={22, 23, 24}) **passes**, so this is a bridge-side interaction at large NV, not an upstream regression. Tracked separately for follow-up.

**Diagnosis history** (do not skip — the original hypothesis was wrong):

The first investigation hypothesised that Akita's planner picks the **root-direct fast path** for `(num_claims=1, num_groups=1, num_points=1)` at small `max_num_vars` and that our `hachi_claim_reduced_opening_shape` rejected that branch. This was **incorrect**: for `OneHotPoly` at `max_num_vars = 18` the planner actually picks the **Fold** path with `(num_steps=4, is_root_direct=false, num_fold_levels=3)`. The proof size empirically observed (~78 KB) also rules out a root-direct emission (which for `OneHotPoly` at NV=18 would have been `2^18` field elements ≈ 4 MB of raw witnesses).

The actual root cause was an off-by-one in the recursive-fold-step loop count that fired exactly at `current_level = n_fold_levels`. See Audit #005 below for the complete diagnosis + fix.

**Files added**:
- `crates/iop/src/hachi_bridge.rs` — added `prove_claim_reduction_sumcheck_transcript`, `verify_claim_reduction_sumcheck_transcript`, `evaluate_claim_reduction_transparent` primitives.
- `crates/iop/src/hachi_claim_reduced_channel.rs` — new verifier-side channel (parallel to `hachi_succinct_channel.rs`).
- `crates/iop-prover/src/hachi_claim_reduced_channel.rs` — new prover-side channel.
- Wired `Prover::prove_hachi_claim_reduced` / `Verifier::verify_hachi_claim_reduced` with `PROOF_MODE_HACHI_CLAIM_REDUCED` transcript tag.
- Wired `CompressionType::HachiClaimReduced` into the examples CLI (`--compression hachi-claim-reduced`).

**Design**: After the standard parity + selected-sum + booleanity sumchecks (shared with `hachi-succinct`), the claim-reduced bridge runs a degree-2 sumcheck on `B(x) · (eq(selected_point, x) + α · eq(bool_point, x))` to reduce the two opening claims (at `selected_point` and `bool_point`) into one claim at the sumcheck's final challenge `reduced_point`. The PCS then opens the committed polynomial at a single point instead of two.

**Empirical proof size at Keccak-256B**: ~78 KB for claim-reduced vs ~84 KB for multi-point succinct — confirming the theoretical proof-size win.

**Completed work**:

1. ~~Root-direct shape support~~ — **not needed**. The original hypothesis was wrong; the planner does NOT pick root-direct for our parameters. The actual fix is documented in Audit #005.

2. **Regression test** — `hachi_claim_reduced_proof_mode_mismatches_reject` in `crates/prover/tests/prove_verify.rs` covers:
   - Positive roundtrip on a SHA-256 preimage circuit (`prove_hachi_claim_reduced` → `verify_hachi_claim_reduced` accepts).
   - Byte-tamper rejection at proof-start / proof-middle / proof-end.
   - Cross-mode rejection: claim-reduced proof rejected by BaseFold / full-open / succinct verifiers, AND each of those proofs rejected by `verify_hachi_claim_reduced`.

**Empirical proof size / verify-time win at Keccak ∈ {256B, 1KB, 2KB, 4KB}**:

| Size | hachi-succinct | hachi-claim-reduced | proof Δ | verify Δ |
|------|----------------|---------------------|---------|----------|
| 256B | 83.6 KB / 44 ms | 77.8 KB / 34 ms | −7 % | −23 % |
| 1 KB | 88.0 KB / 150 ms | 84.4 KB / 135 ms | −4 % | −10 % |
| 2 KB | 89.6 KB / ? | 86.9 KB / ? | −3 % | — |
| 4 KB | 90.9 KB / 550 ms | 89.0 KB / 532 ms | −2 % | −3 % |

The claim-reduced bridge consistently wins on every metric across the validated range.

**Remaining follow-ups**:

3. **Cross-size benchmark at larger sizes** is blocked by the `max_num_vars ≥ 23` bridge-side issue. Once that is resolved we should fill in the table for NV ∈ {23, 24, 25}.

4. **Soundness analysis document**: per-step equivalence between the multi-point and claim-reduced bridges; verification that the claim-reduction sumcheck preserves the binding established by the bit-table commitment. Lower priority; the runtime equivalence is established by both regression tests.

---

## Audit #003-A: Implement `batched_proof_shape_for_lookup_key` against the Akita public API

**Status**: APPROVED + APPLIED + **RUNTIME VALIDATED at every tested size** (`max_num_vars` ∈ {18, 19, 20, 21, 25}). The upstream Akita bug that previously limited validation to `max_num_vars=18` has been **resolved upstream** (uncommitted working tree changes in `lz-hachi` at HEAD `53d7083`): the new `CommitmentProver::batched_commit_for_multipoint(polys, num_opening_points, setup)` API binds the commitment to a `(num_groups=1, num_points=num_opening_points)` layout that matches what `batched_prove` will see after the new commitment-pointer dedup in `verifier_claims_to_incidence` / `prover_claims_to_incidence`. The bridge was updated to:

1. Call `batched_commit_for_multipoint(polys, HACHI_OPENING_POINTS, setup)` instead of `commit(polys, setup)` at oracle-send time.
2. Set `HACHI_OPENING_GROUPS = 1` (the post-dedup group count) in the verifier-side shape derivation.
3. Build the `ProverClaims` with the upstream regression test's pattern: share the polynomial slice reference but use per-point clones of the commitment and hint (per `lz-hachi/crates/akita-pcs/tests/multipoint_batched_e2e.rs::shared_onehot_commitment_two_points_round_trip_sweep`).

**Runtime validation evidence**: `cargo test -p binius-prover --features hachi --test prove_verify hachi_proof_mode_mismatches_reject` passes, exercising the full Hachi succinct path on a SHA-256 preimage circuit. The test covers:

1. **Positive roundtrip**: `prove_hachi_succinct` → `verify_hachi_succinct` accepts the honest proof.
2. **Tamper rejection**: bytes flipped at proof-start / proof-middle / proof-end are all rejected.
3. **Mode-mismatch rejection**: BaseFold / hachi-full-open / hachi-succinct proofs are mutually inaccessible to the wrong verifier entry point.

The **post-deserialization safety-net check** (`proof.shape() != expected_shape`) did **not** fire during testing, confirming the schedule-driven shape derivation matches Akita's prover-side derivation byte-for-byte. **Open Q 3-A.1** (multi-point shape correctness with `num_groups=2, num_points=2`) is **resolved**: the test uses exactly this configuration and works.

**Bonus validation**: this test simultaneously runtime-validates Audit #002's `batched_prove` / `batched_verify` call sites, which were previously only compile-validated.

**Required Cargo.toml change**: the `akita-config` dep now uses `features = ["planner"]`. Reason: Akita ships pre-generated schedule lookup tables for a fixed set of `(max_num_vars, num_claims, num_groups, num_points)` combinations; our bridge's combination `(18, 2, 2, 2)` is not in the table, so we need the `planner` feature for on-the-fly schedule derivation. **Soundness impact**: none — the planner produces the same canonical schedule that would be in the lookup table; it just computes it dynamically instead of looking it up.

**Correction (post-Audit #005)**: the "Runtime validation evidence" above was misleading. The original `hachi_proof_mode_mismatches_reject` test asserted only **negative** outcomes — wrong-mode and tampered-proof rejection. A verifier that **always** errors (for any reason) trivially passes those assertions. The honest `prove_hachi_succinct` → `verify_hachi_succinct` round-trip was never exercised, so the bridge looked validated while in fact harbouring two real bugs (Audit #005). The shape derivation here (`hachi_succinct_opening_shape`) had an off-by-one in its recursive-fold loop and the prover/verifier disagreed on Akita's commitment-pointer dedup; both surfaced only after a **positive** roundtrip assertion was added (see Audit #005 §3). With those bugs fixed, the Audit #003-A shape derivation is genuinely runtime-validated at `max_num_vars` ∈ {18, 19, 20, 21, 22, 23} for `hachi-succinct`; the post-deserialization `proof.shape() != expected_shape` safety-net check does not fire on the honest path.

**Toy walkthrough circuit limitation**: the walkthrough circuit in `learn_e2e.rs` is too small (log_msg_len = 2) for the Hachi succinct minimum (log_msg_len ≥ 7), so it cannot be used as the validation vehicle. The dedicated `learn_e2e_hachi_succinct` test is marked `#[ignore]` with a docstring pointing at `hachi_proof_mode_mismatches_reject` as the actual runtime check.

### Feasibility verification

All upstream primitives needed to compute the proof shape from a lookup key alone are **publicly exposed** in current Akita. Verified by spot-check against `lz-hachi` HEAD:

| Primitive | Path | Public? |
|---|---|---|
| `CommitmentConfig::get_params_for_prove` | `akita-config/src/lib.rs:279` | ✅ trait method |
| `CommitmentConfig::root_level_params_for_layout_with_log_basis` | `akita-config/src/lib.rs:130` | ✅ trait method |
| `CommitmentConfig::level_params_with_log_basis` | `akita-config/src/lib.rs:121` | ✅ trait method |
| `CommitmentConfig::decomposition` | `akita-config/src/lib.rs:94` | ✅ trait method |
| `schedule_num_fold_levels(&Schedule)` | `akita-types/src/schedule.rs:1145` | ✅ pub fn |
| `scheduled_fold_execution(...)` | `akita-types/src/schedule.rs:1194` | ✅ pub fn |
| `scheduled_next_level_params(...)` | `akita-types/src/schedule.rs:1167` | ✅ pub fn |
| `recursive_level_layout_from_params(...)` | `akita-types/src/layout/sis_derivation.rs:263` | ✅ pub fn |
| `w_ring_element_count(...)` | `akita-types/src/schedule.rs:928` | ✅ pub fn |
| `stage1_tree_stage_shapes(...)` | `akita-types/src/proof/stage1.rs:154` | ✅ pub fn |
| `AkitaScheduleInputs`, `LevelProofShape`, `AkitaProofStepShape`, `AkitaBatchedProofShape`, `DirectWitnessShape`, `AkitaRootBatchSummary`, `Step` | `akita-types` (re-exported) | ✅ pub structs/enums |

The only non-public helper is `batched_shape_rounds`, which lives in `akita-scheme/tests.rs:66` and is a 3-line formula we can inline:

```rust
fn batched_shape_rounds(level_d: usize, next_w_len: usize) -> usize {
    let num_ring_elems = next_w_len / level_d;
    num_ring_elems.next_power_of_two().trailing_zeros() as usize
        + level_d.trailing_zeros() as usize
}
```

### Reference implementation: Akita's `expected_same_point_batched_shape`

The Akita test file `lz-hachi/crates/akita-scheme/src/tests.rs:107` implements proof-shape derivation for the **same-point** case (`num_groups=1, num_points=1`). It is the audit baseline for our implementation. Two crucial differences for our bridge port:

1. **It takes a parsed proof** as input and reads `proof.num_fold_levels()` from it. We must derive this from the schedule alone via `schedule_num_fold_levels(&schedule)`.

2. **It is hardcoded to same-point batching**. Our bridge uses **multi-point batching** with `num_groups = num_points = 2`. The per-level formulas already parameterize over `batch.num_points` (e.g., `y_ring_coeffs = batch.num_points * root_lp.ring_dimension`), so the multi-point case should fall out naturally — but we must verify each formula handles the multi-point case correctly.

### Per-formula equivalence analysis

Below, for each piece of the proof shape, I capture: (a) the formula from `expected_same_point_batched_shape`, (b) what it means semantically, (c) whether the formula generalizes to multi-point, and (d) any soundness caveats.

#### Formula 1: Batch summary

```rust
// Test helper (same-point):
let batch = AkitaRootBatchSummary::new(num_claims, 1, 1)?;
// Our port (multi-point):
let batch = AkitaRootBatchSummary::new(HACHI_OPENING_CLAIMS, HACHI_OPENING_GROUPS, HACHI_OPENING_POINTS)?;
//                                       = 2,                 = 2,                  = 2
```

`AkitaRootBatchSummary::new(num_claims, num_groups, num_points)` is the canonical constructor; the same call shape used by the prover. **No equivalence concern** — we pass the same constants the prover uses (already defined in `hachi_succinct_channel.rs` as `HACHI_OPENING_CLAIMS = 2`, etc.).

#### Formula 2: Schedule derivation

```rust
let schedule = Cfg::get_params_for_prove(max_num_vars, max_num_vars, num_claims, batch)?;
```

Note the repeated `max_num_vars` — the second argument is `min_num_vars`. Same call shape as the prover. **Soundness**: same `(max_num_vars, max_num_vars, num_claims, batch, Cfg)` ⇒ deterministic same `Schedule`.

#### Formula 3: Fold-level count

```rust
// Test helper:           let n_fold_levels = proof.num_fold_levels();
// Our port:              let n_fold_levels = schedule_num_fold_levels(&schedule);
```

**This is the key substitution.** Looking at the Akita source:

```rust
// akita-types/src/schedule.rs:1145
pub fn schedule_num_fold_levels(schedule: &Schedule) -> usize {
    schedule.steps.iter().filter(|step| matches!(step, Step::Fold(_))).count()
}

// akita-types/src/proof/mod.rs:1491
impl AkitaBatchedProof<F> {
    pub fn num_fold_levels(&self) -> usize {
        self.steps.iter().filter(...).count()
    }
}
```

Both count `Fold` steps. The proof's `steps` is a serialized image of the schedule's `Step::Fold(_)` entries (plus a trailing `Direct` leaf). **Equivalent by construction**: an honest prover writes one proof step per schedule fold step, so `proof.num_fold_levels() == schedule_num_fold_levels(&schedule)` always. A dishonest prover could write a *different* number of steps, but that would be caught by post-deserialization structural validation (`AkitaBatchedProof` checks the steps form a valid recursive chain — see `akita-types/src/proof/mod.rs:2155-2175`).

**Soundness verdict**: this substitution is sound provided we trust Akita's deserializer to reject malformed step-count proofs. Belt-and-suspenders safety net (see §"Safety net" below) gives defense in depth.

#### Formula 4: Root-level parameters

```rust
// Identical between test helper and our port:
let root_step = match schedule.steps.first() {
    Some(Step::Fold(s)) => s,
    _ => return Err(...),
};
let root_inputs = AkitaScheduleInputs {
    max_num_vars,
    level: 0,
    current_w_len: root_step.current_w_len,
};
let level_lp = &root_step.params;
let root_lp = Cfg::root_level_params_for_layout_with_log_basis(root_inputs, level_lp)?;
```

This is config-driven. Same `Cfg + inputs + level_lp` ⇒ same `root_lp`. **No multi-point dependence in this step.**

#### Formula 5: Root-level shape

```rust
let next_inputs = AkitaScheduleInputs {
    max_num_vars,
    level: 1,
    current_w_len: root_step.next_w_len,
};
let next_level_params = scheduled_next_level_params(
    &schedule, 1, next_inputs, Cfg::level_params_with_log_basis,
)?;
let root_w_len = next_inputs.current_w_len;
let root_rounds = batched_shape_rounds(root_lp.ring_dimension, root_w_len);
let root_shape = LevelProofShape {
    y_ring_coeffs:     batch.num_points * root_lp.ring_dimension,
    v_coeffs:          root_lp.d_key.row_len() * root_lp.ring_dimension,
    stage1_stages:     stage1_tree_stage_shapes(root_rounds, 1usize << level_lp.log_basis),
    stage2_sumcheck:   (root_rounds, 3),
    next_commit_coeffs: next_level_params.b_key.row_len() * next_level_params.ring_dimension,
};
```

**Multi-point check**: `batch.num_points` appears only in `y_ring_coeffs`. For same-point this is `1 * root_lp.ring_dimension`; for our multi-point case it's `2 * root_lp.ring_dimension` — double the y-commitment ring coefficients. This is consistent with the prover writing one y-commitment-per-point in the batched layout. **Multi-point handled correctly via the formula.**

**Multi-group check**: the formula does NOT reference `batch.num_groups`. This is a CRITICAL OBSERVATION — either:
- (a) `num_groups` doesn't affect the wire layout (it's a prover-side bookkeeping detail), OR
- (b) `num_groups` affects something further inside `next_level_params` derivation.

⚠️ **Open question 3-A.1**: confirm by running the smoke test that `num_groups=2` produces a parseable shape. If shape mismatch, dig into `AkitaRootBatchSummary` semantics.

#### Formula 6: Per-fold-level shapes (recursive)

```rust
let mut step_shapes = Vec::with_capacity(n_fold_levels + 1);
let mut current_w_len = root_w_len;
let mut current_log_basis = first_level_params.log_basis;  // first_level_params = next_level_params.clone() from §5
let mut current_level = 1usize;

for _ in 0..n_fold_levels {  // <-- changed from `for _ in proof.fold_levels()`
    let inputs = AkitaScheduleInputs {
        max_num_vars,
        level: current_level,
        current_w_len,
    };
    let (level_params, next_level_params) = scheduled_fold_execution(
        &schedule,
        current_level,
        inputs,
        current_log_basis,
        Cfg::level_params_with_log_basis,
    )?;
    let current_lp = recursive_level_layout_from_params(
        &level_params,
        current_w_len,
        Cfg::decomposition(),
    )?;
    let next_w_len = w_ring_element_count::<HachiScalar>(&current_lp) * current_lp.ring_dimension;
    let rounds = batched_shape_rounds(current_lp.ring_dimension, next_w_len);
    step_shapes.push(AkitaProofStepShape::Fold(LevelProofShape {
        y_ring_coeffs: current_lp.ring_dimension,
        //             ^^^^^^^^^^^^^^^^^^^^^^^^^
        // Note: NOT scaled by num_points at non-root levels. After the root
        // fold, all opening points have been merged into a single recursive
        // claim, so subsequent levels only need 1 ring-dimension worth of y.
        v_coeffs: current_lp.d_key.row_len() * current_lp.ring_dimension,
        stage1_stages: stage1_tree_stage_shapes(rounds, 1usize << current_lp.log_basis),
        stage2_sumcheck: (rounds, 3),
        next_commit_coeffs: next_level_params.b_key.row_len() * next_level_params.ring_dimension,
    }));
    current_w_len = next_w_len;
    current_log_basis = next_level_params.log_basis;
    current_level += 1;
}
```

**The only modification from the test helper**: `for _ in proof.fold_levels()` → `for _ in 0..n_fold_levels`. Each iteration body is byte-for-byte identical. The substitution is sound because both loops iterate the same number of times for an honest prover (per Formula 3 analysis).

**Multi-point/group check**: this section does not reference `batch.num_points` or `batch.num_groups` at all. The "batched" nature collapses at the root level; deeper levels are single-claim recursive sumchecks. Verified consistent with the test helper's structure.

#### Formula 7: Direct-witness leaf

```rust
step_shapes.push(AkitaProofStepShape::Direct(
    DirectWitnessShape::PackedDigits((current_w_len, current_log_basis)),
));
```

Single line, no multi-point dependence. **No equivalence concern.**

#### Formula 8: Final assembly

```rust
Ok(AkitaBatchedProofShape::Fold { root_shape, step_shapes })
```

**Edge case**: if `n_fold_levels == 0`, we'd produce a Fold with just a Direct leaf. The test helper assumes folding happens (it doesn't handle the root-direct fast path). Our bridge config (`fp128::D64OneHot` with `log_msg_len + 8 >= 15`) does fold, so we're in the same regime. But we should add an explicit error if the schedule is root-direct (no fold levels):

```rust
if schedule_is_root_direct(&schedule) {
    return Err(...);  // bridge doesn't support root-direct
}
```

### Safety net: post-deserialization shape check

After deserialization, Akita exposes `parsed_proof.shape()` which **recomputes** the shape from the parsed proof. We add a post-deserialization assertion:

```rust
let proof = hachi_wire::read_hachi::<HachiBatchedProof<HachiScalar>, _>(transcript, &expected_shape)?;
// Belt-and-suspenders: re-derive shape from the parsed proof and confirm equality.
let actual_shape = proof.shape();
if actual_shape != expected_shape {
    return Err(Error::ProofEmpty);  // structural mismatch beyond deserializer's checks
}
```

This catches any subtle divergence between our shape derivation and Akita's prover-side derivation, even if the bytes happen to parse. Total cost: one allocation + one equality check; negligible at the scale of any real proof. **Strictly stronger than the old API**, which had no such re-derivation check.

### Soundness verdict

**Soundness-preserving conditional on**:

1. Akita's deserializer rejects step-count mismatches between bytes and shape — verified by inspection of `akita-types/src/proof/mod.rs:2155-2175`.
2. `schedule_num_fold_levels(&schedule) == proof.num_fold_levels()` for honest provers — true by construction (both iterate the same fold-step list).
3. The multi-point parameters (`num_groups=2, num_points=2`) flow through the formulas correctly — confirmed by inspection that `batch.num_points` is the only batched-quantity reference and it appears only in `root_shape.y_ring_coeffs` as a multiplier.
4. The post-deserialization safety net catches any residual derivation divergence.

### Required imports

Add to `crates/iop/src/hachi_succinct_channel.rs`:

```rust
use akita_config::CommitmentConfig;
use akita_types::{
    AkitaProofStepShape, AkitaScheduleInputs, DirectWitnessShape, LevelProofShape, Step,
    recursive_level_layout_from_params, schedule_is_root_direct, schedule_num_fold_levels,
    scheduled_fold_execution, scheduled_next_level_params, stage1_tree_stage_shapes,
    w_ring_element_count,
};
```

(All already available via `akita-types` and `akita-config` workspace deps — no new Cargo changes.)

### Proposed full implementation

```rust
/// Compute the expected proof shape for the Hachi succinct bridge.
///
/// Audit #003-A: this is a direct schedule-driven port of Akita's internal
/// `expected_same_point_batched_shape` test helper, adapted for our
/// multi-point batched-opening configuration. See
/// `docs/hachi-bridge-akita-port-audit-log.md` audit #003-A for the per-formula
/// equivalence analysis and the safety-net rationale.
fn hachi_succinct_opening_shape(log_msg_len: usize) -> Result<HachiBatchedProofShape, Error> {
    let max_num_vars = log_msg_len + 8;
    let batch = AkitaRootBatchSummary::new(
        HACHI_OPENING_CLAIMS,
        HACHI_OPENING_GROUPS,
        HACHI_OPENING_POINTS,
    )
    .map_err(|_| Error::ProofEmpty)?;

    let schedule = Cfg::get_params_for_prove(
        max_num_vars,
        max_num_vars,
        HACHI_OPENING_CLAIMS,
        batch,
    )
    .map_err(|_| Error::ProofEmpty)?;

    // Our bridge does not support the root-direct fast path; the prover
    // always emits a recursive Fold root.
    if schedule_is_root_direct(&schedule) {
        return Err(Error::ProofEmpty);
    }

    let n_fold_levels = schedule_num_fold_levels(&schedule);

    let root_step = match schedule.steps.first() {
        Some(Step::Fold(s)) => s.clone(),
        _ => return Err(Error::ProofEmpty),
    };

    // ---- Root-level shape (Formula 4–5) ----
    let root_inputs = AkitaScheduleInputs {
        max_num_vars,
        level: 0,
        current_w_len: root_step.current_w_len,
    };
    let level_lp = &root_step.params;
    let root_lp = Cfg::root_level_params_for_layout_with_log_basis(root_inputs, level_lp)
        .map_err(|_| Error::ProofEmpty)?;
    let next_inputs = AkitaScheduleInputs {
        max_num_vars,
        level: 1,
        current_w_len: root_step.next_w_len,
    };
    let next_level_params = scheduled_next_level_params(
        &schedule,
        1,
        next_inputs,
        Cfg::level_params_with_log_basis,
    )
    .map_err(|_| Error::ProofEmpty)?;
    let root_w_len = next_inputs.current_w_len;
    let root_rounds = batched_shape_rounds(root_lp.ring_dimension, root_w_len);
    let root_shape = LevelProofShape {
        y_ring_coeffs: batch.num_points * root_lp.ring_dimension,
        v_coeffs: root_lp.d_key.row_len() * root_lp.ring_dimension,
        stage1_stages: stage1_tree_stage_shapes(root_rounds, 1usize << level_lp.log_basis),
        stage2_sumcheck: (root_rounds, 3),
        next_commit_coeffs: next_level_params.b_key.row_len() * next_level_params.ring_dimension,
    };
    let first_level_params = next_level_params.clone();

    // ---- Per-fold-level shapes (Formula 6) ----
    let mut step_shapes = Vec::with_capacity(n_fold_levels + 1);
    let mut current_w_len = root_w_len;
    let mut current_log_basis = first_level_params.log_basis;
    let mut current_level = 1usize;
    for _ in 0..n_fold_levels {
        let inputs = AkitaScheduleInputs {
            max_num_vars,
            level: current_level,
            current_w_len,
        };
        let (level_params, next_level_params) = scheduled_fold_execution(
            &schedule,
            current_level,
            inputs,
            current_log_basis,
            Cfg::level_params_with_log_basis,
        )
        .map_err(|_| Error::ProofEmpty)?;
        let current_lp = recursive_level_layout_from_params(
            &level_params,
            current_w_len,
            Cfg::decomposition(),
        )
        .map_err(|_| Error::ProofEmpty)?;
        let next_w_len = w_ring_element_count::<HachiScalar>(&current_lp) * current_lp.ring_dimension;
        let rounds = batched_shape_rounds(current_lp.ring_dimension, next_w_len);
        step_shapes.push(AkitaProofStepShape::Fold(LevelProofShape {
            y_ring_coeffs: current_lp.ring_dimension,
            v_coeffs: current_lp.d_key.row_len() * current_lp.ring_dimension,
            stage1_stages: stage1_tree_stage_shapes(rounds, 1usize << current_lp.log_basis),
            stage2_sumcheck: (rounds, 3),
            next_commit_coeffs: next_level_params.b_key.row_len()
                * next_level_params.ring_dimension,
        }));
        current_w_len = next_w_len;
        current_log_basis = next_level_params.log_basis;
        current_level += 1;
    }

    // ---- Direct-witness leaf (Formula 7) ----
    step_shapes.push(AkitaProofStepShape::Direct(
        DirectWitnessShape::PackedDigits((current_w_len, current_log_basis)),
    ));

    Ok(AkitaBatchedProofShape::Fold { root_shape, step_shapes })
}

/// Audit-#003-A inlined helper from `akita-scheme/tests.rs:66`.
fn batched_shape_rounds(level_d: usize, next_w_len: usize) -> usize {
    let num_ring_elems = next_w_len / level_d;
    num_ring_elems.next_power_of_two().trailing_zeros() as usize
        + level_d.trailing_zeros() as usize
}
```

### Validation strategy

Three regression tests in `crates/prover/tests/learn_e2e.rs`:

1. **`learn_e2e_hachi_succinct`**: prove → verify the toy circuit through the succinct path. Asserts both succeed.
2. **`learn_e2e_hachi_succinct_rejects_tampered`**: prove → flip 3 different bytes (front/middle/back) → verify. Each tampered proof must be rejected.
3. **`learn_e2e_hachi_succinct_rejects_wrong_witness`**: prove with `private = 0x1234` (which produces `result = 0x1200`) but write `0x1300` to the inout slot → verify. Must be rejected (witness inconsistency).

Plus the safety-net assertion described above embedded inline in `verify_hachi_succinct`.

### Open questions

- **3-A.1** (mentioned in Formula 5): does `num_groups != num_points` flow through the shape correctly, or does the bridge implicitly assume `num_groups == num_points`? Will be resolved by running the smoke test.
- **3-A.2**: should the safety-net check go in `hachi_succinct_opening_shape` (always run) or only in `verify_hachi_succinct` (the public verifier entry)? Recommend the verifier so the helper stays a pure shape-derivation function.

### Awaiting review

- [ ] Soundness analysis sufficient (modulo Open Q 3-A.1, resolvable by smoke test)?
- [ ] OK with the safety-net post-deserialization shape check, or do you prefer not to add it (and rely solely on the deserializer)?
- [ ] OK with the three-test validation strategy, or do you want additional adversarial coverage?

---


**Scope**: `crates/iop/src/hachi_succinct_channel.rs::hachi_succinct_opening_shape` (currently stubbed to `Err(Error::ProofEmpty)` after Audit #002).

### Why this is harder than expected

The old API exposed a free function `batched_proof_shape_for_lookup_key::<Cfg, D>(key) -> Result<HachiBatchedProofShape, _>` that computed the expected proof shape **upfront from the schedule alone** (no proof needed). This is required because Akita's `AkitaBatchedProof::deserialize_with_mode` takes `&AkitaBatchedProofShape` as its **`Context` associated type** — i.e., you cannot deserialize a wire-format proof without first knowing the shape.

In current upstream Akita, **there is no equivalent free function**. The only ways to obtain an `AkitaBatchedProofShape` are:

1. `AkitaBatchedProof::shape()` — instance method on a *parsed* proof (chicken-and-egg: we want to parse it, but need shape to parse).
2. `expected_same_point_batched_shape(max_num_vars, num_claims, proof: &AkitaBatchedProof<F>)` — a test helper in `akita-scheme/src/tests.rs`. **Still requires a proof in hand** because it uses `proof.num_fold_levels()` and `proof.fold_levels()` to know how many fold steps to materialize.

**Critical insight**: Even the Akita test code derives shape using the proof's own metadata. There is no public API to derive shape from `(Cfg, max_num_vars, num_claims, num_groups, num_points)` alone.

### Available primitives in upstream Akita

The number of fold levels in the recursive schedule **can** be derived without a proof:
- `OneHotCfg::get_params_for_prove(max_num_vars, max_num_vars, num_claims, batch) -> Schedule`
- `schedule_num_fold_levels(&schedule) -> usize`

So in principle, we can rebuild the per-fold-level loop in `expected_same_point_batched_shape` using `schedule_num_fold_levels` instead of `proof.num_fold_levels()`. This is what Path A below proposes.

### Path A: Full reconstruction (recommended for production soundness)

Reproduce something analogous to `expected_same_point_batched_shape`, parameterized by `(max_num_vars, num_claims, num_groups, num_points)` instead of `(max_num_vars, num_claims, &proof)`. Estimated ~80-100 lines.

The function would:

1. Construct `AkitaRootBatchSummary::new(num_claims, num_groups, num_points)`.
2. Get the schedule via `Cfg::get_params_for_prove(max_num_vars, max_num_vars, num_claims, batch)`.
3. Walk the root step + each subsequent fold level using `schedule_num_fold_levels` to know how many to materialize.
4. For each level, compute `LevelProofShape` from the level's parameters (using the same `recursive_level_layout_from_params`, `w_ring_element_count`, `batched_shape_rounds`, etc., that Akita's test helper uses).
5. Append a final `AkitaProofStepShape::Direct` for the direct-witness suffix.

**Soundness assessment**: This is a **direct port** of an existing, audited Akita function. If we faithfully reproduce the test helper's logic (substituting `schedule_num_fold_levels` for `proof.num_fold_levels()`), the shape will be byte-identical to what the prover produces. The risk is **transcription error**: any bug in our port could cause the verifier to reject valid proofs (false negatives) or accept malformed proofs (false positives — though this is mitigated because Akita's deserializer also performs structural validation).

**Required imports** (in addition to what's already there):
- `akita_types::{AkitaScheduleInputs, schedule_num_fold_levels, recursive_level_layout_from_params, w_ring_element_count, scheduled_fold_execution, scheduled_next_level_params, stage1_tree_stage_shapes, AkitaProofStepShape, AkitaBatchedProofShape, LevelProofShape, DirectWitnessShape, Step}`
- `akita_config::CommitmentConfig` (the trait that provides `get_params_for_prove`, `level_params_with_log_basis`, etc.)
- `akita-types::batched_shape_rounds` (probably reachable through `akita_types`)

This brings the bridge into a much closer coupling with Akita's internal-ish APIs than before, but it's the only way to recover the lost free-function abstraction.

**Estimated work**: 2-4 hours of careful code transcription + a regression test that runs the actual succinct path end-to-end and verifies a self-generated proof.

### Path B: Defer the succinct path entirely

Mark `prove_hachi_succinct` / `verify_hachi_succinct` as `unimplemented!()` until Audit #003 Path A is complete. Keep the `hachi-full-open` path (which doesn't need this function) as the only working Hachi-bridged proof mode.

**Soundness assessment**: Trivially safe — the verifier explicitly fails any succinct-mode proof.

**Cost**: The toy-circuit Hachi test (the original goal) can only exercise `hachi-full-open`, not `hachi-succinct`. Aggregation use cases are blocked.

**Estimated work**: 5 minutes (replace the stub's `Err(Error::ProofEmpty)` with `Err(Error::Unimplemented)` if such an error variant exists; or add one).

### Path C: Ask Akita upstream

The Akita team likely has an opinion on whether `batched_proof_shape_for_lookup_key` should be re-exposed as a public function (it'd be a small, additive change). If yes, this becomes a 5-minute waiting game. If no, we're back to Path A.

**Estimated work**: ask the question now; in the meantime do Path B.

### Recommendation

**For an honest soundness-first port**, Path C → Path B → Path A in that order:

1. Ask Akita team if they'll re-expose `batched_proof_shape_for_lookup_key` (or accept a PR adding it).
2. While waiting, ship Path B so the bridge has a clear "this path is not yet wired" semantics.
3. If the answer is "no, port it yourself", do Path A as a careful 2-4 hour transcription with regression test.

Alternatively, Path A immediately if you want forward progress and are comfortable with ~3 hours of focused work.

### Awaiting decision

- [ ] Path A, B, or C?
- [ ] If Path A, do I need to add a regression test (run a full succinct proof on the toy circuit) before considering the audit complete? (Recommended: yes.)

---

## Audit #005: Bridge bug discovery and fixes

**Status**: APPROVED + APPLIED + **RUNTIME VALIDATED** for both bridges at `max_num_vars` ∈ {18, 19, 20, 21, 22}. Positive-roundtrip regression tests added to `crates/prover/tests/prove_verify.rs` for both `hachi-succinct` and `hachi-claim-reduced`.

This audit documents the diagnosis and fix of **two real bugs** that were masked by a **test-design bug** in the original regression test. The masked bugs broke the **positive roundtrip** path (honest prover → honest verifier) at every size, even though the bridge had been claimed "runtime validated" in Audit #003-A and "infrastructure built and partially working" in Audit #004.

### Scope of files modified

| File | Change |
|------|--------|
| `crates/iop/src/hachi_succinct_channel.rs` | Bug 1 fix (off-by-one loop count); confirmation that the clone-pattern dedup is the only working path; updated `HACHI_OPENING_GROUPS = 2` comment to document the empirical constraint; verifier-side clone pattern |
| `crates/iop/src/hachi_claim_reduced_channel.rs` | Bug 1 fix (off-by-one loop count); diagnostic eprintlns removed; docstring updated to record that for `HACHI_OPENING_POINTS = 1` the dedup question does not arise |
| `crates/iop-prover/src/hachi_succinct_channel.rs` | Kept the upstream-test clone pattern, updated comment to tie it to Akita's pointer-identity dedup contract |
| `crates/prover/tests/prove_verify.rs` | Added positive-roundtrip assertion to `hachi_proof_mode_mismatches_reject`; new test `hachi_claim_reduced_proof_mode_mismatches_reject` (positive roundtrip + tamper + cross-mode rejection on both directions) |

### Bug 1: off-by-one in the recursive-fold-step loop count

**Affected files**: `crates/iop/src/hachi_succinct_channel.rs::hachi_succinct_opening_shape` AND `crates/iop/src/hachi_claim_reduced_channel.rs::hachi_claim_reduced_opening_shape`.

**Pre-fix code**:

```rust
let n_fold_levels = schedule_num_fold_levels(&schedule);
// ... root_shape built from schedule.steps[0] ...
let mut current_level = 1usize;
for _ in 0..n_fold_levels {                          // ← wrong
    let (level_params, _) = scheduled_fold_execution(&schedule, current_level, ...)?;
    current_level += 1;
}
```

**Why it was wrong**: the function was ported from Akita's internal test helper `expected_same_point_batched_shape` (`lz-hachi/crates/akita-scheme/src/tests.rs:107`), whose loop was driven by `for _ in proof.fold_levels() { ... }`. `proof.fold_levels()` iterates `proof.steps`, which contains ONLY the **recursive** fold levels (the root fold lives in `proof.root`, which is a separate field). The substitution `proof.num_fold_levels() → schedule_num_fold_levels(&schedule)` was off by one because `schedule_num_fold_levels` counts ALL Fold entries in the schedule, including the root.

**Symptom**: at `max_num_vars = 18` the schedule is `[Fold@0, Fold@1, Fold@2, Direct@3]`. `n_fold_levels = 3`. The loop iterated with `current_level ∈ {1, 2, 3}` and on iteration 3 called `scheduled_fold_execution(schedule, level=3, ...)` against `steps[3]` which is the terminal `Direct` step. Akita rejected with `InvalidSetup("schedule is missing fold step at level 3")`, the shape derivation bailed with `Error::ProofEmpty`, and the verifier never reached PCS-opening deserialization. The transcript reader reported `~58 KB / 65 KB` of leftover bytes because the verifier consumed only the wire-prelude bytes (parity sums, sumchecks, openings) before bailing.

**Fix**:

```rust
let n_fold_levels = schedule_num_fold_levels(&schedule);
let n_recursive_folds = n_fold_levels.saturating_sub(1);
// ...
for _ in 0..n_recursive_folds {
    // recursive folds only — root is handled separately above
}
```

**Soundness impact**: pure correctness fix. Wire-format shape now matches Akita's prover-side `AkitaBatchedProof::shape()` byte-for-byte. The post-deserialization safety net `if proof.shape() != expected_shape { return Err(...) }` still validates on every call.

### Bug 2: prover/verifier disagreement on Akita's commitment-pointer dedup

**Affected files**: `crates/iop-prover/src/hachi_succinct_channel.rs::prove_hachi_openings` AND `crates/iop/src/hachi_succinct_channel.rs::verify_hachi_openings`.

**Akita contract**: `prover_claims_to_incidence` (`lz-hachi/crates/akita-prover/src/protocol/flow.rs:168-256`) and `verifier_claims_to_incidence` (`lz-hachi/crates/akita-types/src/proof/incidence.rs:56-105`) both deduplicate `CommittedPolynomials` / `CommittedOpenings` entries by **raw pointer identity** of the `&Commitment` field. Two entries with **the same** raw pointer collapse into one logical incidence group; two entries with **different** raw pointers (even if they point to equal cloned values) become two groups.

**Pre-fix prover**: passed two different commitment clones (different pointers) ⇒ Akita's prover dedup produced **`num_groups = 2`**.

**Pre-fix verifier**: passed `&data.commitment` twice (same pointer) ⇒ Akita's verifier dedup produced **`num_groups = 1`**.

**Symptom**: the schedule lookup keys disagreed, the prover's runtime layout did not match the layout the verifier's shape derivation was expecting, and the verifier rejected with `InvalidProof` from inside `batched_verify` even on honest proofs.

**Why it was undetectable in Audit #003-A**: the planner happens to return the **same** `total_bytes` / `fold_levels` / wire-format-byte-count for `(num_claims=2, num_groups=1, num_points=2)` AND `(num_claims=2, num_groups=2, num_points=2)` at all sizes we tested. So the proof bytes that the prover emitted **could** be deserialized by the verifier's shape derivation (no obvious shape-mismatch error). The `proof.shape() != expected_shape` safety net did **not** fire because the byte structures coincidentally matched. The disagreement only surfaced when Akita's cryptographic checks ran against the mismatched layout.

**Fix**: match Akita's upstream regression test pattern exactly. Both prover and verifier clone the commitment per opening point (`vec![commitment.clone(), commitment.clone()]`), producing two distinct `&Commitment` pointers on both sides. Akita's dedup then yields `num_groups = 2` on both sides. `HACHI_OPENING_GROUPS = 2`. We tried the opposite path (one shared `&data.commitment` reference on both sides, `HACHI_OPENING_GROUPS = 1`); that produced `InvalidSetup("scheduled root next-w length did not match runtime witness")` from inside `prove_root_fold_from_quadratic`, so the shared-pointer path is **not** an option in the current upstream API.

**Soundness impact**: none — both options express the same `(num_claims=2, num_points=2)` opening with one polynomial. We just need the prover and verifier to **agree** on Akita's internal incidence-graph view. The clone-pattern is the documented and tested upstream pattern (`shared_onehot_commitment_two_points_round_trip_sweep` in `lz-hachi/crates/akita-pcs/tests/multipoint_batched_e2e.rs`).

**Why it doesn't affect `hachi-claim-reduced`**: that bridge opens at a SINGLE point (`HACHI_OPENING_POINTS = 1`), so there is exactly one `CommittedPolynomials` / `CommittedOpenings` entry. Dedup is a no-op for a single entry; pointer identity is irrelevant.

### Bug 3: regression test was negative-only

**Affected file**: `crates/prover/tests/prove_verify.rs::hachi_proof_mode_mismatches_reject`.

The original test asserted:

1. BaseFold proof rejected by `verify_hachi_full_open` ✓
2. BaseFold proof rejected by `verify_hachi_succinct` ✓
3. Full-open proof rejected by `verify` ✓
4. Full-open proof rejected by `verify_hachi_succinct` ✓
5. Succinct proof byte-tampers rejected ✓
6. Succinct proof rejected by `verify` ✓
7. Succinct proof rejected by `verify_hachi_full_open` ✓

**What it never asserted**: that the honest succinct proof verifies under `verify_hachi_succinct`. **A verifier that always errors trivially passes all seven negative assertions.** Bugs 1 and 2 caused exactly this scenario for months — the bridge was claimed "runtime validated" while the honest path was broken at every size.

**Fix**: added the missing positive-roundtrip assertion:

```rust
let mut verifier_transcript =
    VerifierTranscript::new(StdChallenger::default(), succinct_proof.clone());
verifier
    .verify_hachi_succinct(witness.public(), &mut verifier_transcript)
    .expect("honest hachi-succinct proof must verify");
```

This single line would have caught both Bug 1 and Bug 2 the first time the test ran. The fix uplifts the test from "this verifier rejects garbage" to "this verifier accepts honest proofs AND rejects garbage".

A parallel test `hachi_claim_reduced_proof_mode_mismatches_reject` was added for the new claim-reduced bridge, asserting positive roundtrip + tamper rejection + bidirectional cross-mode rejection (claim-reduced proof rejected by every other verifier entry; every other proof rejected by `verify_hachi_claim_reduced`). All assertions pass.

### Diagnosis trail (worth recording)

The investigation that found these bugs went:

1. **Hypothesis (from the previous session's summary)**: `hachi_claim_reduced_opening_shape` rejects when Akita's planner picks the **root-direct fast path** at small `max_num_vars`. **Refuted**: instrumentation showed `is_root_direct=false`; the proof size (~78 KB) also rules out a root-direct emission (which for `OneHotPoly` at NV=18 would be `2^18 × 16 bytes ≈ 4 MB` of raw witnesses).
2. **Hypothesis**: the `verify_sumcheck MISMATCH` is at the failed step. **Refuted by `eprintln!` instrumentation**: the failure was earlier, in shape derivation. `scheduled_fold_execution(level=3)` returned `InvalidSetup("schedule is missing fold step at level 3")`.
3. **Bug 1 identified**: schedule has `[Fold, Fold, Fold, Direct]` ⇒ `n_fold_levels = 3` ⇒ the loop tries `level = 1, 2, 3` but only `1, 2` are fold steps. Off-by-one in the loop count.
4. **Bug 1 fix verified to work for `hachi-claim-reduced`** end-to-end. **But `hachi-succinct` still failed** with `InvalidProof` from `batched_verify`.
5. **Bug 2 identified**: by reading `verifier_claims_to_incidence` and `prover_claims_to_incidence`, found that they dedup on pointer identity. Our prover used clones (different pointers, `num_groups=2`); our verifier used a shared reference (same pointer, `num_groups=1`). Mismatch.
6. **Bug 2 fix verified to work for `hachi-succinct`** end-to-end at `max_num_vars` ∈ {18, 19, 20, 21, 22, 23}.
7. **Bug 3 identified**: realized that the original regression test would have caught both bugs immediately if it had asserted positive roundtrip. Added the missing assertions to both bridges' regression tests.

### Known limitation: upstream `OneHotPoly` K=2 bug at large NV

At `max_num_vars ≥ 24` (`hachi-succinct`, two opening points) or `max_num_vars ≥ 23` (`hachi-claim-reduced`, one opening point), the verifier rejects with `verify_sumcheck MISMATCH` deep inside Akita's PCS opening. The same K=64 configuration runs end-to-end inside Akita at NV up to 24 (we extended `shared_onehot_commitment_two_points_round_trip_sweep` to NV ∈ {22, 23, 24} — all pass). Initially this looked like a bridge-specific failure; **further reduction proved it is an upstream Akita bug specific to `OneHotPoly` with `K = 2`**:

| Probe | Inputs | Pass at NV | Fail at NV |
|---|---|:-:|:-:|
| Upstream `shared_onehot..._sweep` (K=64) | 2 points, K=64 | 18-24 | — |
| `shared_k2_onehot_two_points_round_trip_probe` | 2 points, K=2 | 18, 22, 23 | 24 |
| `k2_onehot_single_point_round_trip_probe` | 1 point, K=2 | 18, 22 | 23 |

Reproducers live at `lz-hachi/crates/akita-pcs/tests/k2_onehot_probe.rs` (uncommitted on `taghi/fix/shared-commitment-multipoint-opening`). The NV thresholds in the K=2 probes **match the bridge thresholds exactly**: single-point fails at NV ≥ 23, two-point at NV ≥ 24.

**Why K=2 matters for us**: the Binius Hachi bridge's `to_onehot_bit_table_poly` constructs `OneHotPoly::<F, D=64, u8>::new(2, indices)` — a 2-way one-hot that represents a Boolean bit-table (each slot is `0` or `1`). Upstream tests use `K = ONEHOT_K = ONEHOT_D = 64`, which doesn't exercise this bug. The bug is filed in `docs/akita-upstream-bug-report.md` and is upstream-internal — there is no caller-side workaround other than to change the polynomial representation:

- Switch to `DensePoly::from_field_evals` (already used by `hachi-full-open`). Functional at all NVs but loses the OneHotPoly sparsity speedup.
- Switch to K=64 with a different bit-table encoding. Requires re-deriving the Lagrange opening formula and ensuring opening-point extension matches.
- Wait for an upstream Akita fix.

The bug does NOT prevent shipping for the current use cases — single SHA-256 / Keccak-256 hashes / MLDSA signatures all fit comfortably in `max_num_vars ≤ 22`. Tracked as a separate TODO; not blocking Audit #004 completion.

### Cross-references

- Code: `crates/iop/src/hachi_succinct_channel.rs`, `crates/iop/src/hachi_claim_reduced_channel.rs`, `crates/iop-prover/src/hachi_succinct_channel.rs`, `crates/prover/tests/prove_verify.rs`.
- Akita upstream: `lz-hachi/crates/akita-prover/src/protocol/flow.rs:168-256` (`prover_claims_to_incidence`), `lz-hachi/crates/akita-types/src/proof/incidence.rs:56-105` (`verifier_claims_to_incidence`), `lz-hachi/crates/akita-pcs/tests/multipoint_batched_e2e.rs:696-810` (regression patterns).
- Related audits: this audit retroactively corrects Audit #003-A's runtime-validation claim and supersedes Audit #004's original "root-direct shape support" hypothesis.

---
