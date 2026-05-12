// Copyright 2026 The Binius Developers

//! Single-signature ML-DSA (FIPS 204 / Dilithium2) verifier circuit —
//! Phase 1 R5-hoisted variant.
//!
//! ## What this Phase 1 verifier wires
//!
//! ```text
//!  σ (signature byte stream)  ──►  unpack_c_tilde  ──►  c̃ (4 lanes)
//!                              ──►  unpack_z       ──►  z (L=4 polys)
//!                                                       ──► assert_norm_centered
//!                              ──►  unpack_h       ──►  hint (K=4 polys)
//!  μ (8 lanes, public hoisted)
//!  wApprox (K=4 polys, public hoisted)  ──►  assert_r7  (uses c̃ + hint from above)
//! ```
//!
//! That is, R1 (`sigDecode` for `c̃`, `z`, and `h`, plus the
//! `‖z‖∞ < γ₁ − β` norm check) is fully emitted in-circuit, R7 (the
//! final-hash binding equality) is emitted in-circuit, and R5 — the
//! Akita-lattice ring arithmetic — is "hoisted" out of the circuit
//! (the off-circuit verifier supplies `wApprox` and `μ` as public
//! inputs).
//!
//! ## Phase 1 limitations (each tracked in `docs/aggregate-mldsa-design.md`)
//!
//! - **`wApprox` is hoisted from R5.** In the canonical FIPS-204
//!   verifier, `wApprox = A · z − c · t₁ · 2^D` is computed in the
//!   `Z_q[X]/(X²⁵⁶ + 1)` ring. Phase 2 brings this in-circuit via the
//!   Akita lattice PCS bridge. For Phase 1 the off-circuit verifier
//!   computes it natively (using its own SampleInBall + ExpandA + NTT)
//!   and feeds it as a public input. In particular the *signature
//!   binding* of `wApprox` — that it actually equals
//!   `A·z − c·t₁·2^D` for the supplied `z` and the `c̃`-derived `c` —
//!   is not yet enforced by these constraints.
//! - **R3 SampleInBall is not constrained.** With R5 hoisted, the
//!   in-circuit polynomial `c` would be unused (it's R5's only
//!   consumer), so we don't allocate or constrain it. R3 will land in
//!   Phase 2 alongside R5, where the cascade actually carries it.
//!
//! ## What R7 cascade still gets us
//!
//! Even with R5 hoisted, R7's binding equality
//! `c̃ == SHAKE256(μ ‖ PackW1(use_hint(wApprox, hint)))` ties together
//! the part of the chain that's actually in-circuit: tampering `c̃`,
//! `μ`, `wApprox`, the hint section of `σ`, or producing a `z` that's
//! out of norm — is detected. The pieces that aren't in-circuit (the
//! `wApprox <-> z` and `c <-> c̃` bindings) become assumptions the
//! off-circuit verifier carries; Phase 2 retires those.

use binius_frontend::{CircuitBuilder, Wire};

use crate::{
	hint::unpack_h,
	params::{MODE2, N},
	polyz::assert_norm_centered,
	r7::{C_TILDE_LANES, MU_LANES, assert_r7},
	sigdecode::{SIG_PACKED_LANES, unpack_c_tilde, unpack_z},
};

const L: usize = MODE2.l;
const K: usize = MODE2.k;

/// In-circuit single-signature ML-DSA-44 (Dilithium2) verifier.
///
/// All three input slices are caller-supplied wires; the constructor
/// emits the R1 + R7 constraint subcircuits (deriving `hint` from `σ`
/// internally via `unpack_h`) and exposes the signature-extracted
/// `c̃`, `z`, and `hint` as fields for downstream use (e.g. the
/// upcoming aggregator).
#[derive(Debug, Clone)]
pub struct MlDsaVerifier {
	/// `c̃` extracted from `σ` — 4 LE 64-bit lanes (32 bytes).
	pub c_tilde: [Wire; C_TILDE_LANES],
	/// `z` extracted from `σ` — L = 4 polynomials of N = 256 centered
	/// coefficients each (each in `[0, 2γ₁ − 1]`, post-norm-check).
	pub z: [[Wire; N]; L],
	/// `hint` extracted from `σ`'s `h` section — K = 4 polynomials of
	/// N = 256 0/1 wires each. Range-checked + cardinality-bound +
	/// strict-ordering by `unpack_h`.
	pub hint: [[Wire; N]; K],
}

impl MlDsaVerifier {
	/// Build the Phase 1 ML-DSA-44 verifier circuit on top of the
	/// supplied input wires.
	///
	/// Inputs:
	///
	/// - `sig` — the 2420-byte packed signature, as 303 LE 64-bit
	///   lanes.
	/// - `mu_lanes` — `μ` (the hoisted message hash from R2), as 8
	///   LE 64-bit lanes.
	/// - `w_approx` — `K = 4` polynomials of `N = 256` Z_q
	///   coefficients each (the hoisted R5 output). Each coefficient
	///   is assumed canonical `[0, Q − 1]`; the supplier should use
	///   [`crate::zq::from_u64_witness`] when allocating.
	///
	/// On return, the struct exposes the unpacked `c̃` (4 lanes), `z`
	/// polynomials (L × N centered coefficients), and `hint` polyvec
	/// (K × N bits) as wires the caller can read for downstream
	/// wiring (e.g. aggregation, or Phase 2 that binds `wApprox` back
	/// to `(z, c, A, t₁)`).
	pub fn new(
		b: &CircuitBuilder,
		sig: &[Wire; SIG_PACKED_LANES],
		mu_lanes: &[Wire; MU_LANES],
		w_approx: &[[Wire; N]; K],
	) -> Self {
		// R1: sigDecode (c̃, z, h) + norm check on z.
		let c_tilde = unpack_c_tilde(sig);
		let z = unpack_z(b, sig);
		for poly in &z {
			assert_norm_centered(b, poly);
		}
		let hint = unpack_h(b, sig);

		// R7: c̃ == SHAKE256(μ ‖ PackW1(use_hint(wApprox, hint))).
		assert_r7(b, w_approx, &hint, mu_lanes, &c_tilde);

		Self { c_tilde, z, hint }
	}
}
