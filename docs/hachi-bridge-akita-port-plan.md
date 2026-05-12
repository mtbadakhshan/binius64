# [HISTORICAL] Hachi Bridge: Akita Port Plan

> **Historical record.** This document was the original plan for the
> 2026-05 port of the Hachi bridge from the old `hachi-pcs` API to the
> current `akita-*` crate family. The port is complete; the bridge is
> stable. For the canonical math / protocol specification, see
> `docs/hachi-bridge.tex` (written 2026-05). For implementation reasoning,
> see inline code comments and `docs/hachi-bridge-akita-port-audit-log.md`
> (also historical).

Security-aware plan for porting the Binius64 → Hachi bridge from the old `hachi-pcs` API to the current `akita-*` crate family. ("Hachi bridge" is the historical name of the integration between Binius and the lattice-based PCS that today is called Akita upstream — the bridge code on the `hachi` branch keeps the `hachi_*` naming.)

Status: **historical / complete** — see the front-matter note above.

## Goal

Port the Binius64 bridge code to the current upstream Akita API such that:

1. The end-to-end Akita-backed proof flow compiles and runs against the actual upstream `lz-hachi` repository.
2. **No soundness property of the existing audited bridge is silently weakened** by the port.
3. Every changed call site is **explicitly justified**: what soundness property it relies on, and why the new Akita API preserves (or strengthens) that property.

This is not a mechanical rename. The Akita API has been **decomposed** (single `CommitmentScheme` trait → separate `CommitmentProver` + `CommitmentVerifier` + `AkitaCommitmentScheme` orchestrator) and signatures have changed, which means call sites must be re-derived rather than translated literally.

## Source-of-Truth Soundness Inventory

Before changing anything, we need to know what the existing bridge depends on for soundness. The codebase has its own audit (`HACHI_SOUNDNESS_AUDIT.md` on the `hachi` branch). Distilled from that audit:

### 1. Binding commitment to the bit-table polynomial
- The Hachi PCS commitment must bind the prover to a specific committed polynomial, even adversarially.
- **Bridge call site**: `<Scheme as CommitmentScheme>::commit(...)` in `hachi_succinct_channel.rs`.
- **Akita equivalent**: `<C as CommitmentProver>::commit(...)` in `akita_prover`. **Must verify**: same SIS-hardness assumption, same lattice dimension, same modulus.

### 2. Pointwise Booleanity via random-weighted sumcheck
- The remediated `WeightedBooleanitySumcheckProof` proves `sum_x eq(r, x) * B(x) * (B(x)-1) = 0` where `r` is sampled **after** the commitment is transcript-bound.
- **Bridge call site**: `prove_weighted_booleanity_sumcheck_transcript` in `hachi_bridge.rs`.
- **Akita equivalent**: This is bridge-internal logic, not Akita-internal. Likely unchanged. **Must verify**: random `r` is sampled from a transcript that observed the commitment first.

### 3. Bounded-parity terminal check
- The verifier checks `S_k ≤ bound_k` AND `S_k mod 2 == bit_k(claim)` for each output bit `k`.
- **Bridge call site**: `BatchedParityBridgeProof::verify_with_bounds`.
- **Akita equivalent**: Bridge-internal logic. Likely unchanged.

### 4. Proof-mode binding
- Top-level transcript byte tag (`PROOF_MODE_BASEFOLD` / `PROOF_MODE_HACHI_FULL_OPEN` / `PROOF_MODE_HACHI_SUCCINCT`) prevents cross-mode proof confusion.
- **Bridge call site**: `Prover::prove*` methods in `crates/prover/src/prove.rs`.
- **Akita equivalent**: Unchanged — this is Binius-internal.

### 5. EOF-enforced deserialization of opaque Akita objects
- `read_hachi` rejects trailing bytes after a length-prefixed Hachi object.
- **Bridge call site**: `crates/iop/src/hachi_wire.rs::read_hachi`.
- **Akita equivalent**: Akita's serialization (`AkitaSerialize` / `AkitaDeserialize`) replaces `HachiSerialize`. **Must verify**: Akita's deserialization API still supports cursor-based EOF enforcement (or we must enforce EOF ourselves around the Akita call).

### 6. Bias-free transcript sampling of Akita scalars
- `sample_hachi_scalar` uses rejection sampling to avoid modulo bias when reducing a 128-bit transcript output to `fp128`.
- **Bridge call site**: `crates/iop/src/hachi_wire.rs::sample_hachi_scalar`.
- **Akita equivalent**: Likely unchanged — this is bridge-side rejection sampling, independent of Akita's internals.

### 7. Length-bounded Akita object allocation (DoS guard)
- `read_hachi` rejects length prefixes above a conservative cap.
- **Bridge call site**: `crates/iop/src/hachi_wire.rs::read_hachi`.
- **Akita equivalent**: Bridge-side; unchanged.

## Audit-Risk Classification of Each Call Site

For each `hachi_pcs::*` call site, classify the porting risk:

| Risk | What it means | How to handle |
|---|---|---|
| **A. Pure rename** | Type/trait was renamed, but semantics + signatures identical. | Mechanical edit, no audit needed. |
| **B. API-decomposed** | Functionality was split into multiple new types/traits. Need to verify the new orchestration matches the old monolithic call. | Read both the old and new implementations side-by-side. Document the equivalence in a comment. |
| **C. Signature-changed** | Same conceptual operation, different parameters. Need to verify the new call provides equivalent or stronger constraints. | Re-derive the call from first principles using the Akita API docs / source. Comment justifying the parameter choices. |
| **D. Missing equivalent** | Symbol doesn't exist in Akita (e.g., `batched_proof_shape_for_lookup_key`). | Read Binius bridge usage to understand semantic intent. Either reconstruct via composition of Akita primitives, or surface the gap as an upstream-Akita feature request. |

## Inventory of Call Sites to Port

Based on a survey of `hachi_pcs::*` and `<Scheme as CommitmentScheme>::*` references:

### `crates/iop/src/hachi_bridge.rs`

| Lines | Symbol/Call | Risk |
|---|---|---|
| 12 | `use hachi_pcs::protocol::commitment::presets::fp128;` | A |
| 13 | `use hachi_pcs::protocol::hachi_poly_ops::{DensePoly, OneHotPoly};` | A |
| 14 | `use hachi_pcs::{CanonicalField, FieldCore, FromSmallInt};` | A (FromSmallInt → FromPrimitiveInt is a rename) |
| 154, 177, 188 | `Result<_, hachi_pcs::HachiError>` | A |
| 1180–1184 | Test imports | A |
| 1225–1226 | `<Scheme as CommitmentScheme<HachiScalar, D>>::setup_prover/setup_verifier(14, 128, 1)` | **C** — `akita_setup::new_prover_setup(14, 128, 1, &cfg)` adds a config parameter; semantics must be re-derived |
| 1230 | `<Scheme as CommitmentScheme>::commit(...)` | **B** — now `CommitmentProver::commit` |
| 1250 | `<Scheme as CommitmentScheme>::batched_prove(...)` | **B** + **C** — now `CommitmentProver::batched_prove` with possibly different signature |
| 1262 | `<Scheme as CommitmentScheme>::batched_verify(...)` | **C** — signature changed (7 args → 5 args) |

### `crates/iop/src/hachi_succinct_channel.rs`

| Lines | Symbol/Call | Risk |
|---|---|---|
| 12–23 | `use hachi_pcs::{...}` (BasisMode, CommitmentScheme, FromSmallInt, Transcript, RingCommitment, batched_proof_shape_for_lookup_key, presets::fp128, HachiCommitmentScheme, HachiBatchedProof, HachiBatchedProofShape, HachiVerifierSetup, HachiScheduleLookupKey, HachiRootBatchSummary) | A (most), **D** (`batched_proof_shape_for_lookup_key` — no Akita equivalent yet found) |
| 40 | `type Scheme = HachiCommitmentScheme<D, Cfg>;` | A — `AkitaCommitmentScheme<D, Cfg>` |
| 44 | `pub type HachiSuccinctProverSetup = hachi_pcs::protocol::setup::HachiProverSetup<HachiScalar, D>;` | A |
| 94 | `<Scheme as CommitmentScheme>::setup_prover(...)` | **C** |
| 100 | `<Scheme as CommitmentScheme>::setup_verifier(...)` | **C** |
| 384 | `hachi_pcs::protocol::transcript::Blake2bTranscript::<HachiScalar>::new(...)` | A |
| 387 | `<Scheme as CommitmentScheme>::batched_verify(...)` | **C** |

### `crates/iop-prover/src/hachi_succinct_channel.rs`

| Lines | Symbol/Call | Risk |
|---|---|---|
| 25–34 | Imports (similar to `iop`) | A + **D** |
| 39 | `type Scheme = HachiCommitmentScheme<D, Cfg>;` | A |
| 273 | `hachi_pcs::protocol::transcript::Blake2bTranscript::<HachiScalar>::new(...)` | A |
| (multiple) | `<Scheme as CommitmentScheme>::commit(...)`, `batched_prove(...)` | **B** + **C** |

### `crates/iop/src/hachi_full_open_channel.rs` and `crates/iop-prover/src/hachi_full_open_channel.rs`

The full-open path is "send the entire witness verbatim" — algebraically simpler. Most call sites likely Risk A.

### `crates/iop/src/hachi_wire.rs`

| Lines | Symbol/Call | Risk |
|---|---|---|
| 9 | `use hachi_pcs::{...}` (HachiSerialize, primitives::serialization::Compress) | A (HachiSerialize → AkitaSerialize); **D** for Compress (need to locate or reconstruct) |
| 320 | Test import | A |

## Phased Execution Plan

I recommend executing the port in **four sequential phases**, with a checkpoint review after each:

### Phase 0 (foundation, ~30 min)
- Update `Cargo.toml` files to depend on `akita-*` crates.
- Resolve any transitive dependency conflicts (rand, blake2, etc.) at the workspace level.
- Verify `cargo metadata --features hachi` produces output (sanity check the dependency graph resolves).
- **Commit**: `chore(iop): replace hachi-pcs dep with akita-* crates (Cargo only)`.
- **Soundness impact**: None — Cargo plumbing only.

### Phase 1 (Risk A — pure renames, ~1-2 hrs)
- Update all import paths and type names that are pure renames (per the Risk A entries in the inventory).
- Add a `type` alias or re-export module if helpful, e.g., `mod hachi_pcs { pub use akita_field::*; pub use akita_types::*; ... }` as a temporary compatibility shim.
- After this phase, the file-level surface should compile against Akita; only the API-decomposed and signature-changed call sites should remain broken.
- **Commit**: `refactor(iop): rename hachi-pcs imports to akita-* equivalents`.
- **Soundness impact**: Zero by construction (renames only). Verify by diffing the renamed types' definitions in lz-hachi between the pre- and post-rename commits to confirm they are byte-equivalent.

### Phase 2 (Risk B — API-decomposed call sites, audit per call)
For each Risk B call site, produce a **call-site audit document** capturing:

```
Call site: <file>:<line>
Old call: <Scheme as CommitmentScheme>::commit(...)
Old soundness: provided by Akita SIS commitment under setup parameters X, Y, Z
New call: <C as CommitmentProver>::commit(...)
New soundness: provided by ___ (read akita-prover source to verify)
Equivalence justification: ___
Risk if wrong: ___
```

Discuss each audit document together before committing the change. Concrete call sites:
- All `<Scheme as CommitmentScheme>::commit(...)`.
- All `<Scheme as CommitmentScheme>::batched_prove(...)`.
- All `<Scheme as CommitmentScheme>::setup_prover/setup_verifier(...)` (also Risk C).
- **Commit per call site, with the audit document linked in the commit message**.

### Phase 3 (Risk C — signature changes, deeper audit)
The most security-critical phase. Specifically:
- The new `batched_verify` takes 5 args vs the old 7. Determine which 2 arguments were dropped, **why**, and whether they corresponded to soundness-relevant constraints. If they did, the loss must be compensated for by other Akita-side checks — and we must verify those checks exist.
- The `setup_prover(log_msg_len, claims, points)` → `new_prover_setup(max_vars, polys, points, &cfg)` change — the new `&cfg` parameter encapsulates security-relevant settings (SIS modulus, lattice dimension). Determine: are the defaults equivalent to the old hardcoded settings?

This phase requires reading both:
- The audit document from `HACHI_SOUNDNESS_AUDIT.md` (which call sites were soundness-critical).
- The Akita API documentation/source for the corresponding new types.

### Phase 4 (Risk D — missing equivalents)
Address each symbol with no upstream Akita equivalent:
- `hachi_pcs::batched_proof_shape_for_lookup_key`: read its Binius usage to determine semantic intent. Reconstruct via Akita primitives, or document as a missing-feature gap.
- `hachi_pcs::algebra::poly::multilinear_eval`: locate equivalent (likely in `akita_algebra` or `akita_types`).
- `hachi_pcs::primitives::serialization::Compress`: locate equivalent or reconstruct.

## Per-Phase Output Format

Each phase produces:
1. A **commit** (or commit series) with the actual code changes.
2. A **per-call-site audit document** appended to this file (or to a sibling `HACHI_TO_AKITA_AUDIT.md`) capturing the soundness reasoning.
3. A **test demonstration** where applicable — e.g., the existing `hachi_proof_mode_mismatches_reject` test on the `hachi` branch should continue to pass after each phase.

## Open Questions / Items for Upstream

These should probably be raised as questions with the Akita team:

1. **Is `batched_proof_shape_for_lookup_key` exposed in any form in Akita, or did it move into a different abstraction?**
2. **Are the old `HachiCommitmentScheme<D, Cfg>` security parameters (e.g., for `Cfg = fp128::D64OneHot`) preserved in `AkitaCommitmentScheme<D, Cfg>`?** Specifically: lattice dimension, SIS bound, modulus.
3. **Did the `batched_verify` signature change drop any verifier-side check, or were the dropped arguments redundant?**
4. **Is there a recommended migration guide from the old `hachi-pcs` API to Akita?** (Even draft notes would help.)

## Where to Resume

When ready to begin:
1. Start with **Phase 0** (Cargo.toml only). This is fully reversible and unblocks everything.
2. Verify `cargo metadata --features hachi` resolves cleanly. If it hangs (as it did during the prototype attempt), investigate transitive dep conflicts before proceeding.
3. Begin **Phase 1** (pure renames) and confirm at the end that Risk B/C/D call sites are the **only** remaining compile errors.
4. For Phase 2 onward, do **one call site at a time** with an audit document review checkpoint between each.

This is a multi-day undertaking done correctly. There is no shortcut that preserves soundness rigor.
