// Copyright 2026 The Binius Developers

//! In-circuit ML-DSA (FIPS 204 / Dilithium) verifier and N-aggregate verifier
//! on top of Binius64.
//!
//! ## Status: Phase 0 (scaffolding)
//!
//! This crate ships the building blocks that the Phase 1+ verifier circuits
//! will compose:
//!
//! - [`params`] — Dilithium2 (ML-DSA-44) parameter constants from FIPS 204.
//! - [`zq`] — `Z_q` (Q = 8 380 417, 23 bits) field arithmetic gadgets
//!   (`add`, `sub`, `mul`, `from_u64_witness`).
//! - [`shake`] — A SHAKE256 wrapper over the existing
//!   `binius-circuits::keccak::permutation::Permutation::keccak_f1600`.
//!
//! The single-signature [`verifier::MlDsaVerifier`] and the N-aggregate
//! [`aggregate::AggregateMlDsaVerifier`] are intentionally `unimplemented!()`
//! stubs; the full architecture, sub-relation decomposition (R1–R7), and
//! per-phase TODO checklists live in
//! `docs/aggregate-mldsa-design.md` at the workspace root.
//!
//! ## Reference architecture (two-track Binius64 + Akita-lattice)
//!
//! ML-DSA verification splits into seven sub-relations. R2 (`tr, μ`) and
//! R4 (`A = ExpandA(ρ)`) are pure hashes of public inputs and are hoisted
//! to the verifier (no proof cost). The remaining five split as:
//!
//! - Binius64 track: R1 (`sigDecode` + `‖z‖ < γ₁ − β`), R3 (`SampleInBall`),
//!   R6 (`Decompose` + `UseHint` + `w1Encode`), R7 (final SHAKE256
//!   `c̃' == H(μ ‖ w₁')`).
//! - Akita-lattice track: R5 (`w = A·z − c·t₁·2^D` in `Z_q[X]/(X²⁵⁶+1)`).
//! - Cross-field bridges: `z` (Binius → Akita), `c` (Binius → Akita),
//!   `wApprox` (Akita → Binius).
//!
//! For N-aggregation, Phase 4 plans flat composition first and folding-based
//! IVC (Nova / Protogalaxy) once N grows past the flat threshold.
//!
//! ## Related crates
//!
//! - `binius-circuits` — provides the Keccak-f[1600] permutation that
//!   [`shake`] wraps, plus the bignum primitives.
//! - `binius-akita-bridge` / `binius-akita-bridge-prover` — the lattice-PCS
//!   bridge that R5 will eventually ride.

#![warn(rustdoc::missing_crate_level_docs)]

pub mod aggregate;
pub mod params;
pub mod polyw1;
pub mod polyz;
pub mod rounding;
pub mod shake;
pub mod sigdecode;
pub mod verifier;
pub mod zq;
