// Copyright 2026 The Binius Developers

//! R7 — final-hash binding equality
//! `c̃ == SHAKE256(μ ‖ PackW1(w₁'))` for Dilithium2.
//!
//! This module composes the gadgets we already have into the full R7
//! constraint subcircuit:
//!
//! ```text
//! (wApprox_K, hint_K, μ_lanes, c̃_lanes)
//!     │  R6: per-coefficient use_hint
//!     ▼
//! w₁'_K  =  use_hint(wApprox_K[k][i], hint_K[k][i])  for k ∈ [0,K), i ∈ [0,N)
//!     │  R6 packing: K × polyw1_pack
//!     ▼
//! packed_w₁  ∈  768 bytes  =  96 LE 64-bit lanes
//!     │  Concatenate with μ
//!     ▼
//! hash_input ∈ 832 bytes = 104 LE 64-bit lanes
//!     │  R7 hash: shake256
//!     ▼
//! computed_c̃  ∈  32 bytes  =  4 lanes
//!     │  R7 binding
//!     ▼
//! assert_eq(computed_c̃, c̃_lanes)  for every lane
//! ```
//!
//! Per the FIPS 204 §6.2 verifier, this is the final binding equation:
//! if it accepts, all of R5/R6 must have been computed honestly (modulo
//! the soundness arguments documented in [`crate::rounding`] for
//! decompose's boundary uniqueness).

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

use crate::{
	params::{MODE2, N},
	polyw1::{POLYW1_PACKED_BYTES, POLYW1_PACKED_LANES, polyw1_pack},
	rounding::use_hint,
	shake::shake256,
};

const K: usize = MODE2.k;

/// Bytes occupied by `PackW1(w₁')` for the full `K = 4` polynomial vector
/// (Dilithium2): `K · POLYW1_PACKED_BYTES = 768`.
pub const POLYVECK_W1_PACKED_BYTES: usize = K * POLYW1_PACKED_BYTES;
/// Same as 64-bit lanes: `768 / 8 = 96`.
pub const POLYVECK_W1_PACKED_LANES: usize = POLYVECK_W1_PACKED_BYTES / 8;

/// Bytes of `μ` consumed by R7 (the hoisted message hash from R2).
pub const MU_BYTES: usize = 64;
/// Same as 64-bit lanes: `64 / 8 = 8`.
pub const MU_LANES: usize = MU_BYTES / 8;

/// Total bytes hashed by R7: `μ ‖ PackW1(w₁')` = 64 + 768 = 832.
pub const HASH_INPUT_BYTES: usize = MU_BYTES + POLYVECK_W1_PACKED_BYTES;
/// Same as 64-bit lanes: `832 / 8 = 104`.
pub const HASH_INPUT_LANES: usize = HASH_INPUT_BYTES / 8;

/// `c̃` size in 64-bit lanes (32 bytes = 4 lanes for Mode 2).
pub const C_TILDE_LANES: usize = 4;

const _: () = assert!(POLYVECK_W1_PACKED_BYTES == 768);
const _: () = assert!(HASH_INPUT_BYTES == 832);
const _: () = assert!(POLYVECK_W1_PACKED_BYTES.is_multiple_of(8));
const _: () = assert!(MU_BYTES.is_multiple_of(8));

// ─── In-circuit gadgets ─────────────────────────────────────────────────

/// Apply `use_hint` per coefficient over the full `K = 4` polynomial
/// vector. Returns the `K · N = 1024` wires of `w₁'`.
///
/// Each of the 1024 outputs is constrained by the call to
/// [`use_hint`], which in turn constrains both the per-coefficient
/// decomposition (via `decompose`) and the hint bit (`< 2`).
pub fn use_hint_polyvec(
	b: &CircuitBuilder,
	w_approx: &[[Wire; N]; K],
	hint: &[[Wire; N]; K],
) -> [[Wire; N]; K] {
	std::array::from_fn(|k| std::array::from_fn(|i| use_hint(b, w_approx[k][i], hint[k][i])))
}

/// Pack the full `K = 4` `w₁'` polynomial vector into 96 little-endian
/// 64-bit lanes by concatenating `K` calls to
/// [`crate::polyw1::polyw1_pack`].
///
/// Output lane layout: lanes `[0, 24)` are polynomial 0, lanes
/// `[24, 48)` are polynomial 1, etc. Matches the byte layout the C
/// reference's `polyveck_pack_w1` produces.
pub fn pack_w1_polyvec(
	b: &CircuitBuilder,
	w1: &[[Wire; N]; K],
) -> [Wire; POLYVECK_W1_PACKED_LANES] {
	let zero = b.add_constant(Word::ZERO);
	let mut out: [Wire; POLYVECK_W1_PACKED_LANES] = [zero; POLYVECK_W1_PACKED_LANES];
	for (k, w1_poly) in w1.iter().enumerate() {
		let packed = polyw1_pack(b, w1_poly);
		let off = k * POLYW1_PACKED_LANES;
		out[off..off + POLYW1_PACKED_LANES].copy_from_slice(&packed);
	}
	out
}

/// Constrain the R7 binding equality
/// `c̃ == SHAKE256(μ ‖ PackW1(w₁'))` end-to-end, where `w₁'` is derived
/// from `wApprox` and `hint` via per-coefficient `use_hint`.
///
/// All four input slices are caller-supplied wires:
///
/// - `w_approx` — `K × N = 1024` Z_q wires (assumed canonical
///   `[0, Q − 1]`; the verifier produces these from the hoisted R5
///   computation).
/// - `hint` — `K × N` 0/1 wires (each constrained `< 2` inside
///   `use_hint`).
/// - `mu_lanes` — 8 lanes carrying the 64-byte hoisted message hash.
/// - `c_tilde_lanes` — 4 lanes carrying `c̃` from the signature.
pub fn assert_r7(
	b: &CircuitBuilder,
	w_approx: &[[Wire; N]; K],
	hint: &[[Wire; N]; K],
	mu_lanes: &[Wire; MU_LANES],
	c_tilde_lanes: &[Wire; C_TILDE_LANES],
) {
	// R6: per-coefficient `use_hint` over the polyvec.
	let w1 = use_hint_polyvec(b, w_approx, hint);

	// R6 packing: K × polyw1_pack into 96 lanes.
	let packed_w1 = pack_w1_polyvec(b, &w1);

	// R7 hash input: μ (8 lanes) ‖ packed_w1 (96 lanes) = 104 lanes.
	let mut hash_input: [Wire; HASH_INPUT_LANES] =
		[b.add_constant(Word::ZERO); HASH_INPUT_LANES];
	hash_input[..MU_LANES].copy_from_slice(mu_lanes);
	hash_input[MU_LANES..].copy_from_slice(&packed_w1);

	// R7 hash: shake256(input, 832 bytes, 4 lanes).
	let computed = shake256(b, &hash_input, HASH_INPUT_BYTES, C_TILDE_LANES);

	// R7 binding: per-lane equality. Failure of *any* lane is
	// equivalent to the entire signature being rejected per FIPS 204.
	for i in 0..C_TILDE_LANES {
		b.assert_eq(format!("R7: c_tilde[{i}] == computed[{i}]"), computed[i], c_tilde_lanes[i]);
	}
}

// (The end-to-end native reference `r7_native` lives in
// `crates/mldsa/tests/r7.rs` because it depends on the `sha3` crate,
// which `binius-mldsa` only carries as a dev-dependency.)
