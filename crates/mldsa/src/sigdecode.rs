// Copyright 2026 The Binius Developers

//! Top-level signature decoder: pulls `c̃`, `z`, and (eventually) `h` out
//! of a Dilithium2 signature byte stream.
//!
//! The reference C implementation is `dilithium/ref/packing.c::unpack_sig`.
//! Phase 0 / Phase 1a only carry the byte-aligned parts (`c̃` and `z`) —
//! the variable-length hint encoding `h` lands in a follow-up.
//!
//! ## Byte layout (Dilithium2, `CRYPTO_BYTES = 2420`)
//!
//! | offset (bytes) | length (bytes) | section | lanes | parser |
//! |---|---|---|---|---|
//! | 0      | 32   | `c̃` (challenge hash)            | 4   | [`unpack_c_tilde`] (trivial slice) |
//! | 32     | 2304 | `z` (4 × 576-byte polynomials)   | 288 | [`unpack_z`] (4 × `polyz_unpack_centered`) |
//! | 2336   | 84   | `h` (hint, OMEGA + K bytes)      | 11  | TODO (Phase 1, separate task)      |
//!
//! The full signature is therefore `2420 = 8·303 − 4` bytes, occupying
//! [`SIG_PACKED_LANES`] = 303 little-endian 64-bit lanes whose final
//! 32 bits are zero-padding. Section boundaries are byte-aligned, so the
//! top-level `unpack_*` functions can hand fixed-size lane slices to the
//! per-section parsers without any cross-lane shifting.

use binius_frontend::{CircuitBuilder, Wire};

use crate::{
	params::{MODE2, N},
	polyz::{POLYZ_PACKED_BYTES, POLYZ_PACKED_LANES, polyz_unpack_centered},
};

const L: usize = MODE2.l;
const K: usize = MODE2.k;

/// Bytes occupied by `c̃` in the signature.
pub const SIG_C_TILDE_BYTES: usize = 32;
/// Bytes occupied by `z` in the signature: `L · POLYZ_PACKED_BYTES`.
pub const SIG_Z_BYTES: usize = L * POLYZ_PACKED_BYTES;
/// Bytes occupied by `h` in the signature: `OMEGA + K`.
pub const SIG_H_BYTES: usize = MODE2.omega + K;

/// Total signature size in bytes (Dilithium2 `CRYPTO_BYTES`).
pub const SIG_PACKED_BYTES: usize = SIG_C_TILDE_BYTES + SIG_Z_BYTES + SIG_H_BYTES;
/// Total signature size in 64-bit little-endian lanes (rounded up).
pub const SIG_PACKED_LANES: usize = SIG_PACKED_BYTES.div_ceil(8);

/// Lane index where the `c̃` section begins.
pub const SIG_C_TILDE_LANE_OFFSET: usize = 0;
/// Lane index where the `z` section begins.
pub const SIG_Z_LANE_OFFSET: usize = SIG_C_TILDE_BYTES / 8;
/// Lane index where the `h` section begins.
pub const SIG_H_LANE_OFFSET: usize = SIG_Z_LANE_OFFSET + L * POLYZ_PACKED_LANES;

const _: () = assert!(SIG_C_TILDE_BYTES.is_multiple_of(8), "c~ section must be lane-aligned");
const _: () = assert!(SIG_Z_BYTES.is_multiple_of(8), "z section must be lane-aligned");

// Sanity: the lane offsets had better match the FIPS 204 byte numbering.
const _: () = assert!(SIG_C_TILDE_LANE_OFFSET == 0);
const _: () = assert!(SIG_Z_LANE_OFFSET == 4);
const _: () = assert!(SIG_H_LANE_OFFSET == 4 + 4 * 72);
const _: () = assert!(SIG_H_LANE_OFFSET == 292);

// ─── Per-section parsers ────────────────────────────────────────────────

/// Extract the `c̃` section (32 bytes = 4 LE 64-bit lanes) from a packed
/// signature. Trivial slice — the section is already lane-aligned and
/// no bit-twiddling is needed.
pub fn unpack_c_tilde(sig: &[Wire; SIG_PACKED_LANES]) -> [Wire; 4] {
	std::array::from_fn(|i| sig[SIG_C_TILDE_LANE_OFFSET + i])
}

/// Extract the `z` section into `L` polynomials of `N` centered
/// coefficient wires each. Each coefficient is in `[0, 2γ₁ − 1]`; apply
/// [`crate::polyz::assert_norm_centered`] separately to enforce R1's
/// `‖z‖∞ < γ₁ − β` bound.
pub fn unpack_z(b: &CircuitBuilder, sig: &[Wire; SIG_PACKED_LANES]) -> [[Wire; N]; L] {
	std::array::from_fn(|p| {
		let off = SIG_Z_LANE_OFFSET + p * POLYZ_PACKED_LANES;
		let poly_lanes: [Wire; POLYZ_PACKED_LANES] = std::array::from_fn(|i| sig[off + i]);
		polyz_unpack_centered(b, &poly_lanes)
	})
}

// ─── Native (out-of-circuit) reference helpers ──────────────────────────

/// Pack `(c̃, z)` into the byte layout that
/// [`unpack_c_tilde`] / [`unpack_z`] consume. The `h` section is
/// zero-filled and the remaining lane is also zero-padded; both fields
/// are not touched by the Phase 1a parsers, so this matches what callers
/// will populate as witness for tests and (later) for the verifier
/// circuit.
///
/// Mirrors the byte ordering of `dilithium/ref/packing.c::unpack_sig`
/// for the `(c̃, z)` portion. The `h` portion is left as
/// `[0u8; SIG_H_BYTES]`, which is **not** a valid encoding under the
/// strict FIPS 204 rules (it implies an empty hint, which is technically
/// valid only when every per-poly offset is zero — true here since the
/// bytes are all zero) — that's intentional for tests that only exercise
/// the c̃/z parsers.
pub fn pack_signature_native(
	c_tilde: &[u8; SIG_C_TILDE_BYTES],
	z_centered: &[[u32; N]; L],
) -> [u8; SIG_PACKED_BYTES] {
	use crate::polyz::polyz_pack_centered_native;
	let mut out = [0u8; SIG_PACKED_BYTES];
	out[..SIG_C_TILDE_BYTES].copy_from_slice(c_tilde);
	for (p, poly) in z_centered.iter().enumerate() {
		let packed_poly = polyz_pack_centered_native(poly);
		let lo = SIG_C_TILDE_BYTES + p * POLYZ_PACKED_BYTES;
		out[lo..lo + POLYZ_PACKED_BYTES].copy_from_slice(&packed_poly);
	}
	// `h` section deliberately left zero.
	out
}

/// Convert a 2420-byte signature into the 303-lane LE encoding consumed
/// by [`unpack_c_tilde`] / [`unpack_z`]. The trailing 4 padding bytes of
/// the last lane are zero.
pub fn signature_to_lanes(packed: &[u8; SIG_PACKED_BYTES]) -> [u64; SIG_PACKED_LANES] {
	let mut padded = [0u8; SIG_PACKED_LANES * 8];
	padded[..SIG_PACKED_BYTES].copy_from_slice(packed);
	std::array::from_fn(|i| {
		let mut w = [0u8; 8];
		w.copy_from_slice(&padded[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(w)
	})
}
