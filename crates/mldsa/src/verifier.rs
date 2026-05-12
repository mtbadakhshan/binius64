// Copyright 2026 The Binius Developers

//! Single-signature ML-DSA (FIPS 204 / Dilithium) verifier circuit.
//!
//! ## Status: Phase 0 stub
//!
//! This module is intentionally an `unimplemented!()` skeleton; the type
//! shape is fixed so that Phase 1 can fill in the constraint logic without
//! breaking any downstream call sites in `aggregate` or in tests.
//!
//! ## What Phase 1 lands here
//!
//! Per the sub-relation table in `docs/aggregate-mldsa-design.md`, Phase 1
//! wires up the four Binius64-track sub-relations against constants from
//! [`crate::params::Mode2`] using the [`crate::zq`] field gadgets and the
//! [`crate::shake`] SHAKE256 wrapper:
//!
//! - **R1** — `sigDecode(σ)` and `‖z‖ < γ₁ − β` range check
//!   (`L · 256 = 1024` independent range checks for Dilithium2).
//! - **R3** — `c = SampleInBall(c̃)` via SHAKE256 + Fisher-Yates with
//!   rejection sampling. Output: a sparse polynomial with `τ = 39`
//!   non-zero `±1` coefficients.
//! - **R6** — `Decompose` + `UseHint` + `w1Encode` over the `K · 256 =
//!   1024` coefficients of `wApprox`. Reads `wApprox` as a bridged value
//!   from R5 (Phase 2 wires the bridge; Phase 1 takes it as a public
//!   input).
//! - **R7** — `c̃' = SHAKE256(μ ‖ w₁')` and the binding equality
//!   `c̃' == c̃`.
//!
//! R5 (`w = A·z − c·t₁·2^D` in `Z_q[X]/(X²⁵⁶+1)`) is the lattice-track
//! sub-relation; it lives in a separate Phase 2 module that talks to the
//! Akita PCS.
//!
//! ## What stays out of this module
//!
//! - **R2 (`tr, μ`)** and **R4 (`A = ExpandA(ρ)`)** are pure hashes of
//!   public inputs and are hoisted to the verifier (no proof cost). They
//!   are computed natively by the caller using the `sha3` crate.
//! - **R5** lives in a future `crate::lattice` module that will use the
//!   Akita PCS; see Phase 2 in the design doc.

use binius_frontend::{CircuitBuilder, Wire};

use crate::params::Mode;

/// Single-signature ML-DSA verifier circuit. Phase 0 stub — see module
/// docs for what Phase 1 lands.
#[derive(Debug)]
pub struct MlDsaVerifier {
	/// Selected ML-DSA parameter set (only `Mode::Mode2` accepted in
	/// Phase 0; will gain `Mode3`/`Mode5` in Phase 5).
	pub mode: Mode,
	/// Public-input wires for `c̃` (32 bytes packed as 4 × 64-bit).
	pub c_tilde: [Wire; 4],
}

impl MlDsaVerifier {
	/// Construct an in-circuit verifier for one ML-DSA signature.
	///
	/// # Panics
	///
	/// Phase 0: always panics with [`unimplemented!`]. Phase 1 will
	/// allocate the public-input wires for `(pk, sig, μ, c, A, t₁·2^D,
	/// wApprox)` and emit the R1 / R3 / R6 / R7 constraint subcircuits.
	pub fn new(_b: &CircuitBuilder, mode: Mode) -> Self {
		assert!(matches!(mode, Mode::Mode2), "Phase 0 only supports Mode2");
		unimplemented!(
			"binius-mldsa Phase 1: see `docs/aggregate-mldsa-design.md` \
			 for the sub-relation breakdown that this constructor wires up"
		);
	}
}
