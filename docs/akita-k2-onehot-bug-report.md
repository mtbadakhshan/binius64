# [RESOLVED] Bug Report: `OneHotPoly` with `K < D` fails verification at large `max_num_vars`

**Status**: ✅ **RESOLVED** in upstream `lz-hachi` on branch `taghi/fix/onehot-multi-chunk-overflow` (fix in `crates/akita-prover/src/backend/onehot.rs`). Verified end-to-end through the Binius64 Akita bridge on 2026-05-11.
**Original report date**: 2026-05-11.
**Originally affected Akita commit**: `0873a7f19b45acfa3724a652a3861f946fac8add` on `taghi/fix/shared-commitment-multipoint-opening`.

---

## Resolution verification

With the fix applied, both bridges round-trip cleanly far beyond the previous limits:

| Configuration | Pre-fix range | Post-fix range |
|---|---|---|
| K=2 single-point (`akita-claim-reduced`) on Keccak | NV ∈ {18, …, 22} | NV ∈ {18, …, 26} ✓ (verified up to Keccak 64 KB) |
| K=2 two-point (`akita-succinct`) on Keccak | NV ∈ {18, …, 23} | NV ∈ {18, …, 26} ✓ (verified up to Keccak 64 KB) |

End-to-end proof sizes (Keccak, log_inv_rate=1):

| Size | NV | akita-succinct | akita-claim-reduced |
|---|:-:|---:|---:|
| 256 B | 18 | 83,650 B | 77,786 B |
| 1 KB | 20 | 88,008 B | 84,418 B |
| 4 KB | 22 | 90,957 B | 89,019 B |
| 8 KB | 23 | 92,519 B | 90,700 B (previously failed) |
| 16 KB | 24 | 93,831 B (previously failed) | 92,102 B (previously failed) |
| 32 KB | 25 | 95,047 B | 93,750 B |
| 64 KB | 26 | 96,048 B | 95,123 B |

All caller-side regression tests (`akita_proof_mode_mismatches_reject`, `akita_claim_reduced_proof_mode_mismatches_reject`) continue to pass against the fixed upstream.

---

## Original report (preserved for traceability)

## TL;DR

`AkitaCommitmentScheme<D=64, fp128::D64OneHot>::batched_verify` rejects honest proofs with `AkitaError::InvalidProof` (`verify_sumcheck MISMATCH` log line) whenever the committed polynomial is a `OneHotPoly` with **`K = 2`** (i.e. `K < D = 64`) and `max_num_vars` is large enough:

| Configuration | Last NV that **passes** | First NV that **fails** |
|---|:-:|:-:|
| K = 2, single opening point | 22 | **23** |
| K = 2, two opening points (shared commitment) | 23 | **24** |
| K = 64, two opening points (shared commitment) | ≥ 24 (verified) | — (not reproduced up to NV=24) |

The K=64 path used by every existing Akita regression test works fine at the same NVs. The bug appears specific to the **`K < D` storage layout** (`MultiChunkEntry`) at high recursive-fold depth.

The downstream impact is that **the Binius64 Hachi bridge can only round-trip up to `max_num_vars = 22`**, even though `setup_prover` was sized for larger circuits. The bridge uses `K = 2` because it is the tight, natural encoding for a Boolean bit-table (each block is `[1 - bit, bit]`, exactly one `1`).

We have a focused 1-test reproducer (~120 lines) included at the end of this report.

---

## Environment

- Akita commit: `0873a7f19b45acfa3724a652a3861f946fac8add` (`taghi/fix/shared-commitment-multipoint-opening`).
- Config: `fp128::D64OneHot` with `D = 64`, `ONEHOT_D = 64`, `ONEHOT_K = 64` (config-level — distinct from the runtime `K` we vary here).
- Cargo features: `akita-config/planner` enabled (the failing `(num_claims, num_groups, num_points)` combinations are not in the pre-generated schedule tables).
- Rust 1.95.0, target `aarch64-apple-darwin`.

---

## Symptom

The verifier returns `AkitaError::InvalidProof` from `<AkitaCommitmentScheme as CommitmentVerifier>::batched_verify`. Tracing reveals the failure originates in `akita-sumcheck/src/drivers.rs:370`, inside `check_sumcheck_output_claim`:

```
verify_sumcheck input_claim, is_zero: false, num_rounds: 22, prefix_rounds: 0
verify_sumcheck MISMATCH, rounds: 22, degree_bound: 3, diff_is_zero: false
```

I.e. `final_claim != verifier.expected_output_claim(challenges)` after the sumcheck rounds. The per-round consistency checks `g_i(0) + g_i(1) == prev_claim` all pass; only the closing equality between the prover's claim chain and the verifier's reconstruction of the expected value disagrees. This is the recursive-fold stage-2 sumcheck (`degree_bound = 3`).

Notes:

- The proof bytes are structurally well-formed: `AkitaBatchedProof::deserialize_compressed` succeeds with the caller-side-derived shape, and the post-deserialization `proof.shape() == expected_shape` check holds. So the failure is not a length / framing / shape-derivation issue.
- The wire-level Fiat–Shamir state is consistent between prover and verifier up to the failing sumcheck (per-round absorb / sample succeed at the right call sites).
- The failure is fully deterministic and reproduces with `RAYON_NUM_THREADS=1`, so it's not a concurrency issue.

---

## Minimal reproducer

Drop the following file into `crates/akita-pcs/tests/k2_onehot_probe.rs`. It mirrors the existing `shared_onehot_commitment_two_points_round_trip` pattern exactly, with **the single change of `K = 2` instead of `K = ONEHOT_K = 64`**.

```rust
// crates/akita-pcs/tests/k2_onehot_probe.rs

mod common;

use akita_pcs::AkitaCommitmentScheme;
use akita_prover::{CommitmentProver, OneHotPoly};
use akita_serialization::{AkitaDeserialize, AkitaSerialize};
use akita_transcript::Blake2bTranscript;
use akita_types::{
    AkitaBatchedProof, BasisMode, RingCommitment, proof::CommitmentVerifier,
};
use common::{
    F, ONEHOT_D, OneHotCfg, init_rayon_pool, prove_inputs_from_groups, random_point,
    run_on_large_stack, verify_inputs_from_groups,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn run_shared_k2_onehot_two_points_round_trip(nv: usize, transcript_label: &[u8]) {
    let total_claims: usize = 2;
    let num_points: usize = 2;
    let onehot_k: usize = 2;

    // For K=2 we have indices.len() * K = 2^nv  ⇒  indices.len() = 2^(nv-1).
    let num_indices = 1usize << (nv - 1);
    let mut rng = StdRng::seed_from_u64(0xdead_beef);
    let indices: Vec<Option<u8>> = (0..num_indices)
        .map(|_| Some(rng.gen_range(0..onehot_k) as u8))
        .collect();
    let poly = OneHotPoly::<F, ONEHOT_D, u8>::new(onehot_k, indices.clone())
        .expect("K=2 OneHotPoly construction");

    let setup = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::setup_prover(nv, total_claims, num_points);
    let verifier_setup = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::setup_verifier(&setup);

    let polys_singleton: Vec<OneHotPoly<F, ONEHOT_D, u8>> = vec![poly];
    let (commitment, hint) = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::commit_for_multipoint(&polys_singleton, num_points, &setup)
    .expect("K=2 multipoint onehot commit");

    let pt0_owned = random_point(nv, 0xaaaa_1900);
    let pt1_owned = random_point(nv, 0xbbbb_1900);
    let y0 = k_onehot_lagrange_opening(&indices, &pt0_owned, onehot_k);
    let y1 = k_onehot_lagrange_opening(&indices, &pt1_owned, onehot_k);

    let polys_slice: &[OneHotPoly<F, ONEHOT_D, u8>] = polys_singleton.as_slice();
    let polys_by_point: Vec<&[OneHotPoly<F, ONEHOT_D, u8>]> = vec![polys_slice, polys_slice];
    let commitments_by_point: Vec<RingCommitment<F, ONEHOT_D>> =
        vec![commitment.clone(), commitment.clone()];
    let hints_by_point: Vec<_> = vec![hint.clone(), hint.clone()];
    let opening_points: Vec<&[F]> = vec![&pt0_owned, &pt1_owned];

    let mut prover_transcript = Blake2bTranscript::<F>::new(transcript_label);
    let proof = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::batched_prove(
        &setup,
        prove_inputs_from_groups(
            &opening_points,
            &polys_by_point,
            &commitments_by_point,
            hints_by_point,
        ),
        &mut prover_transcript,
        BasisMode::Lagrange,
    )
    .unwrap_or_else(|e| panic!("K=2 OneHotPoly batched_prove failed at NV={nv}: {e:?}"));

    let openings_by_point_owned: Vec<Vec<F>> = vec![vec![y0], vec![y1]];
    let openings_by_point: Vec<&[F]> =
        openings_by_point_owned.iter().map(Vec::as_slice).collect();

    let mut serialized = Vec::new();
    let proof_shape = proof.shape();
    proof.serialize_compressed(&mut serialized).expect("serialize");
    let decoded = AkitaBatchedProof::<F>::deserialize_compressed(
        &mut std::io::Cursor::new(serialized),
        &proof_shape,
    )
    .expect("deserialize");

    let mut verifier_transcript = Blake2bTranscript::<F>::new(transcript_label);
    let verify_result = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentVerifier<
        F,
        ONEHOT_D,
    >>::batched_verify(
        &decoded,
        &verifier_setup,
        &mut verifier_transcript,
        verify_inputs_from_groups(&opening_points, &openings_by_point, &commitments_by_point),
        BasisMode::Lagrange,
    );
    assert!(
        verify_result.is_ok(),
        "K=2 OneHotPoly verification failed at NV={nv}: {:?}",
        verify_result.err()
    );
}

// Lagrange opening for a K-way OneHotPoly: each slot's hot index addresses
// one of K consecutive field positions, so the global field position is
// `chunk_idx * K + hot_idx`.
fn k_onehot_lagrange_opening(indices: &[Option<u8>], point: &[F], onehot_k: usize) -> F {
    assert_eq!(indices.len() * onehot_k, 1usize << point.len());
    indices
        .iter()
        .enumerate()
        .filter_map(|(chunk_idx, hot_idx)| {
            hot_idx.map(|hot_idx| chunk_idx * onehot_k + hot_idx as usize)
        })
        .fold(F::zero(), |acc, field_pos| {
            acc + point
                .iter()
                .enumerate()
                .fold(F::one(), |weight, (bit, &r)| {
                    if ((field_pos >> bit) & 1) == 1 {
                        weight * r
                    } else {
                        weight * (F::one() - r)
                    }
                })
        })
}

// Single-point variant (mirrors `hachi-claim-reduced` which uses one opening point).
fn run_k2_onehot_single_point_round_trip(nv: usize, transcript_label: &[u8]) {
    let total_claims: usize = 1;
    let num_points: usize = 1;
    let onehot_k: usize = 2;

    let num_indices = 1usize << (nv - 1);
    let mut rng = StdRng::seed_from_u64(0xdead_beef);
    let indices: Vec<Option<u8>> = (0..num_indices)
        .map(|_| Some(rng.gen_range(0..onehot_k) as u8))
        .collect();
    let poly = OneHotPoly::<F, ONEHOT_D, u8>::new(onehot_k, indices.clone())
        .expect("K=2 OneHotPoly construction");

    let setup = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::setup_prover(nv, total_claims, num_points);
    let verifier_setup = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::setup_verifier(&setup);

    let polys_singleton: Vec<OneHotPoly<F, ONEHOT_D, u8>> = vec![poly];
    let (commitment, hint) = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::commit_for_multipoint(&polys_singleton, num_points, &setup)
    .expect("K=2 single-point commit");

    let pt0_owned = random_point(nv, 0xaaaa_1900);
    let y0 = k_onehot_lagrange_opening(&indices, &pt0_owned, onehot_k);

    let polys_slice: &[OneHotPoly<F, ONEHOT_D, u8>] = polys_singleton.as_slice();
    let polys_by_point: Vec<&[OneHotPoly<F, ONEHOT_D, u8>]> = vec![polys_slice];
    let commitments_by_point: Vec<RingCommitment<F, ONEHOT_D>> = vec![commitment.clone()];
    let hints_by_point: Vec<_> = vec![hint.clone()];
    let opening_points: Vec<&[F]> = vec![&pt0_owned];

    let mut prover_transcript = Blake2bTranscript::<F>::new(transcript_label);
    let proof = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentProver<
        F,
        ONEHOT_D,
    >>::batched_prove(
        &setup,
        prove_inputs_from_groups(
            &opening_points,
            &polys_by_point,
            &commitments_by_point,
            hints_by_point,
        ),
        &mut prover_transcript,
        BasisMode::Lagrange,
    )
    .unwrap_or_else(|e| panic!("K=2 single-point prove failed at NV={nv}: {e:?}"));

    let openings_by_point_owned: Vec<Vec<F>> = vec![vec![y0]];
    let openings_by_point: Vec<&[F]> =
        openings_by_point_owned.iter().map(Vec::as_slice).collect();

    let mut serialized = Vec::new();
    let proof_shape = proof.shape();
    proof.serialize_compressed(&mut serialized).expect("serialize");
    let decoded = AkitaBatchedProof::<F>::deserialize_compressed(
        &mut std::io::Cursor::new(serialized),
        &proof_shape,
    )
    .expect("deserialize");

    let mut verifier_transcript = Blake2bTranscript::<F>::new(transcript_label);
    let verify_result = <AkitaCommitmentScheme<ONEHOT_D, OneHotCfg> as CommitmentVerifier<
        F,
        ONEHOT_D,
    >>::batched_verify(
        &decoded,
        &verifier_setup,
        &mut verifier_transcript,
        verify_inputs_from_groups(&opening_points, &openings_by_point, &commitments_by_point),
        BasisMode::Lagrange,
    );
    assert!(
        verify_result.is_ok(),
        "K=2 single-point verification failed at NV={nv}: {:?}",
        verify_result.err()
    );
}

#[test]
fn shared_k2_onehot_two_points_round_trip_probe() {
    init_rayon_pool();
    run_on_large_stack(|| {
        // 18, 22, 23 pass on the working tree;  24 fails.
        for nv in [18usize, 22, 23] {
            run_shared_k2_onehot_two_points_round_trip(
                nv,
                format!("shared_k2_onehot_two_points_probe_nv{nv}").as_bytes(),
            );
        }
        // Expected to fail:
        run_shared_k2_onehot_two_points_round_trip(24, b"shared_k2_onehot_two_points_probe_nv24");
    });
}

#[test]
fn k2_onehot_single_point_round_trip_probe() {
    init_rayon_pool();
    run_on_large_stack(|| {
        // 18, 22 pass; 23+ fail.
        for nv in [18usize, 22, 23, 24] {
            run_k2_onehot_single_point_round_trip(
                nv,
                format!("k2_onehot_single_point_probe_nv{nv}").as_bytes(),
            );
        }
    });
}
```

Run with:

```bash
cargo test --release -p akita-pcs --test k2_onehot_probe -- --nocapture
```

The single-point probe fails at NV=23; the two-point probe fails at NV=24. The K=64 sweep in `multipoint_batched_e2e.rs::shared_onehot_commitment_two_points_round_trip_sweep` passes at all of NV ∈ {18, 19, 20, 21}; we extended it to NV ∈ {22, 23, 24} ad-hoc and it passed there too.

---

## Threshold matrix

Aggregating all the probes we have run:

| Configuration | NV=18 | 19 | 20 | 21 | 22 | 23 | 24 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| K=2, single point (`commit_for_multipoint` + `batched_prove(num_points=1)`) | ✅ | — | — | — | ✅ | ❌ | ❌ |
| K=2, two points (`commit_for_multipoint` + `batched_prove(num_points=2)`) | ✅ | — | — | — | ✅ | ✅ | ❌ |
| K=64, single point | ✅ | ✅ | ✅ | ✅ | (assumed ✅) | (assumed ✅) | (assumed ✅) |
| K=64, two points (existing `shared_onehot_..._sweep`) | ✅ | ✅ | ✅ | ✅ | ✅ † | ✅ † | ✅ † |

† Verified ad hoc by extending the upstream sweep test to NV ∈ {22, 23, 24} on a local working tree (not committed). All three NVs passed for K=64.

---

## What we checked

1. **It's not the bit-table content.** The reproducer above uses uniformly-random `indices`, identical to the random-onehot data the existing K=64 sweep uses. The only difference between the two probes is `K = 2` vs `K = 64` (and the resulting `indices.len()` to keep the total polynomial size at `2^nv`).

2. **It's not the opening points.** The reproducer uses `common::random_point(nv, seed)` exactly like the K=64 sweep test. No structured / sumcheck-derived points.

3. **It's not the new shared-commitment-dedup contract.** The probe uses the canonical pattern from `0873a7f`: shared `polys_slice` reference across all points, per-point cloned commitments / hints, single `commit_for_multipoint(num_opening_points=num_points)` call. (The K=64 sweep uses the same pattern and works.)

4. **It's not a Fiat–Shamir / transcript desync.** The `verify_sumcheck` per-round absorb/sample sequence completes successfully — `degree_bound = 3` is respected at every round and `g_i(0) + g_i(1) = prev_claim` holds at every round. Only the final `check_sumcheck_output_claim` disagrees.

5. **It's not a structural / framing issue.** `AkitaBatchedProof::deserialize_compressed` succeeds with the caller-side-derived shape, and the post-deserialization `proof.shape() == expected_shape` invariant holds.

6. **It's not concurrency.** Reproduces with `RAYON_NUM_THREADS=1`.

7. **It's not a one-off NV peculiarity.** The single-point and two-point thresholds (NV=23 and NV=24 respectively) are consistent across multiple runs with different `transcript_label` seeds, and they line up with the threshold our downstream Binius64 bridge hits in production.

---

## Hypothesis

`OneHotPoly` has two internal storage backends (per the module-level docstring in `akita-prover/src/backend/onehot.rs`):

- `SingleChunkEntry` — chosen when `K >= D` and `D | K`. Each ring element of dimension `D` covers at most one hot element. One block ↔ one ring element.
- `MultiChunkEntry` — chosen when `K < D` and `K | D`. One ring element covers `D / K = 32` chunks. Selected by `FlatBlocks::<MultiChunkEntry>::from_indices`.

The K=2 path goes through `MultiChunkEntry`; the K=64 path goes through `SingleChunkEntry`. **All of Akita's existing regression tests use `K = ONEHOT_K = ONEHOT_D = 64`**, exercising only the `SingleChunkEntry` backend. The K=2 probe is, as far as we can tell, the first test that hits `MultiChunkEntry` end-to-end.

Concrete guesses about where the inconsistency lives (untriaged, ordered by our subjective likelihood):

1. **Recursive fold re-encoding.** Each fold level transforms the `MultiChunkEntry` data layout. We suspect at some recursive depth `≥ 4` the transformation produces ring-element coefficients that disagree with what the verifier's `expected_output_claim` reconstructs. The fold-count thresholds in the empirical data line up:

   - NV=22 / single-point: 4 fold levels — passes.
   - NV=23 / single-point: 5 fold levels — fails.
   - NV=23 / two-point: 5 fold levels (planner adds one extra root step for `num_points=2`) — passes.
   - NV=24 / two-point: 6 fold levels — fails.

   The pattern suggests a "fails at fold-level ≥ 5" trigger.

2. **`log_K`-dependent parameter.** Something computed from `log2(K)` (=6 for K=64, =1 for K=2) used as a fixed constant somewhere. The 5-bit difference matches the 5-fold-level threshold above.

3. **`chunks_per_ring = D / K` (= 1 for K=64, = 32 for K=2) used in coefficient indexing.** A loop bound or stride that's correct for `chunks_per_ring = 1` but wraps incorrectly for `chunks_per_ring = 32` at depth.

Likely culprit files: `akita-prover/src/backend/onehot.rs` (the `MultiChunkEntry` reconstruction during fold), `akita-prover/src/protocol/ring_switch.rs` (`build_w_coeffs` and friends — its trace shows `total_ring`, `total_field`, `z_pre_planes`, etc.; some of these scale with the layout), and `akita-prover/src/protocol/sumcheck/akita_stage2.rs` (the verifier's expected-output-claim reconstruction).

---

## Caller context (Binius64 Hachi bridge)

For context on why we use `K = 2`: the Binius Hachi bridge commits to a **Boolean bit-table** — a flat vector of `0`s and `1`s representing the 128 bit-slices of `2^log_msg_len` packed B128 values. We encode each bit as a 2-element one-hot pair `[1 - bit, bit]` and represent the whole table as a single `OneHotPoly` with `K = 2`. The number of variables is `n = log_msg_len + 7 + log2(K) = log_msg_len + 8`. To recover the original bit-table at point `(r_1, …, r_{n-1})`, the bridge opens at `(r_1, …, r_{n-1}, 1)` — the trailing `1` selects the `bit` half of each pair.

The K=2 choice is the tightest possible encoding for a Boolean bit-table:

- **K = 1**: degenerate; one `Option<u8>` per bit position equals the storage cost of the bit itself.
- **K = 2**: each bit's pair `[1 - bit, bit]` has exactly one `1`, automatically satisfying the OneHotPoly invariant. Each bit costs 1 `Option<u8>` metadata (= 1 byte) plus its position in the polynomial.
- **K ≥ 4**: each bit would need to be padded with `K - 2` zeros to fit the one-hot constraint, increasing the polynomial's variable count by `log2(K) - 1` without adding information. E.g. K=64 means padding each bit to a 64-element block with 62 zeros, blowing up the polynomial by 32× and shifting `n` from `log_msg_len + 8` to `log_msg_len + 13`.

We considered switching to `DensePoly::from_field_evals` as a workaround. `DensePoly` works at all NVs in our existing tests, but it stores each bit as a full `fp128` element (16 bytes) instead of `OneHotPoly`'s 1-byte `Option<u8>` per block. We'd lose ~16× in commit-hint memory and proportionally in commit time.

Bridge files (for reference):

- `crates/iop/src/hachi_bridge.rs::BitSliceOracle::to_onehot_bit_table_poly` constructs the `OneHotPoly<F, D=64, u8>::new(K=2, indices)`.
- `crates/iop-prover/src/hachi_succinct_channel.rs::send_oracle` calls `commit_for_multipoint(&[poly], num_opening_points = 2, &setup)`.
- `crates/iop-prover/src/hachi_succinct_channel.rs::prove_hachi_openings` calls `batched_prove(...)` with the upstream-test pattern (shared polys slice, per-point cloned commitments).

Branch: `taghi/learn-e2e` on `binius64`.

---

## Asks for the Akita team

We'd love feedback on any of the following — even rough guidance is helpful.

### 1. Triage: is this a real bug, or is `K < D` documented as unsupported?

The module-level docstring on `OneHotPoly` describes both `SingleChunkEntry` (`K >= D && D | K`) and `MultiChunkEntry` (`K < D && K | D`) as valid configurations, and `OneHotPoly::new` accepts them without warning. But every existing test uses `K = D`. Is `K < D` officially supported, or is it scaffolding that hasn't been validated end-to-end?

### 2. If supported: would you accept a regression test + bug fix?

We have a minimal failing test (the reproducer above) that we'd be happy to upstream as `crates/akita-pcs/tests/onehot_small_k.rs` (or wherever you'd prefer). Once that's in, the bug surface is clear and the fix can be developed against it.

If the team would rather investigate independently, we'd appreciate a pointer once the root cause is found — we'll re-validate our bridge against the fixed working tree.

### 3. If not supported: which `K` should the bridge use for a Boolean bit-table?

This is the most useful question for us. If `K < D` is not the intended use case, please advise on the alternative that:

- Preserves the sparsity speedup of `OneHotPoly` over `DensePoly` (we don't want to commit one full `fp128` element per bit).
- Stays within Akita's tested / supported configurations.

Candidates we've considered:

- **K = D = 64, with per-bit padding** to 64-element blocks `[1 - bit, bit, 0, 0, …, 0]`. Functional but inflates the polynomial by 32× (`n` increases by 5), which negates the sparsity benefit and lands the small-circuit cases right at the NV where Akita's behaviour is less validated.
- **A different Cfg preset** — e.g. `fp128::D32OneHot` (`D = 32`) or `fp128::D128OneHot` (`D = 128`). Would `K = 2` work cleanly in any of those? Or is there a Cfg specifically intended for `K < D` workloads?
- **A completely different representation** for Boolean bit-tables that you'd recommend — e.g. a small-field commit using one of the `*_small_field_preset` configs.

We're open to any of these; we mostly want to pick a path the Akita team is willing to support long-term.

### 4. Are there other invariants we may be implicitly violating?

The K=2 probe above passes Akita's structural checks at commit time and at prove time; the failure surfaces only in the verifier's stage-2 closing equality. If there are layout invariants the caller is supposed to maintain (e.g. minimum NV for `K < D`, alignment of `indices.len()` with some internal constant, etc.) that aren't enforced by `OneHotPoly::new`, we'd like to know so we can either satisfy them or surface a clear error earlier.

---

## Suggested next steps (from our side)

We can:

- Stand up the reproducer as a real test in a PR against `taghi/fix/shared-commitment-multipoint-opening` (or main), gated `#[ignore]` until the fix lands.
- Test patch candidates against the Binius64 Hachi bridge (we have full end-to-end coverage via `hachi_proof_mode_mismatches_reject` and `hachi_claim_reduced_proof_mode_mismatches_reject` on the bridge side; the positive-roundtrip assertions there catch the bug today and would catch regressions).
- Migrate the bridge to whichever K / Cfg combination you recommend, once we have guidance.

---

Filed by: (your name / handle)
