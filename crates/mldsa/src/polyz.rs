// Copyright 2026 The Binius Developers

//! `polyz` — Dilithium2 response-vector polynomial bit-packing/unpacking and
//! the `‖z‖ < γ₁ − β` norm check.
//!
//! Each `z` polynomial is 256 coefficients in `[-(γ₁ − 1), γ₁]`. The byte
//! encoding (FIPS 204 §5.1, see also `dilithium/ref/poly.c::polyz_pack`)
//! uses 9 bytes per group of 4 coefficients. For Dilithium2 (γ₁ = 2¹⁷),
//! this gives `N · 18 / 8 = 576` bytes per polynomial.
//!
//! The reference C `polyz_unpack` returns the **signed** coefficient
//! `c = γ₁ − centered`. To stay compatible with the rest of the
//! `binius-mldsa` gadgets (which work in canonical `Z_q` form), this
//! module exposes the **centered** value `centered = γ₁ − c` directly:
//!
//! - `centered ∈ [0, 2γ₁ − 1] = [0, 2¹⁸ − 1]` after unpacking.
//! - `centered ∈ (β, 2γ₁ − β) = (78, 262066)` iff the original signed
//!   coefficient satisfies `|c| < γ₁ − β` — that is, exactly the R1 norm
//!   check.
//!
//! Conversion to the `Z_q` canonical form (when needed by R5 / R6) is a
//! single `zq::sub(γ₁_const, centered)` call.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

use crate::params::{MODE2, N};

/// Bytes per packed Dilithium2 `z` polynomial: `N · 18 / 8 = 576`.
pub const POLYZ_PACKED_BYTES: usize = N * 18 / 8;
/// Same value as 64-bit lanes: `576 / 8 = 72`.
pub const POLYZ_PACKED_LANES: usize = POLYZ_PACKED_BYTES / 8;

// ─── In-circuit gadgets ─────────────────────────────────────────────────

/// Unpack one Dilithium2 `z` polynomial from its 576-byte / 72-lane
/// little-endian byte encoding into 256 **centered** coefficient wires
/// (`centered = γ₁ − c ∈ [0, 2γ₁ − 1]`).
///
/// `packed[i]` is interpreted as bytes `[8i, 8(i+1))` of the polyz
/// encoding in little-endian order. The high `64 − 18 = 46` bits of every
/// returned coefficient wire are zero.
///
/// This gadget does *not* assert that the high bits of the input lanes
/// are zero; the caller is responsible for that constraint (typically by
/// allocating the lanes via `from_u64_witness`-style range checks if the
/// encoding does not naturally fill the lane). For the standard signature
/// layout where the L `z` polynomials occupy a contiguous 2304-byte
/// section, every lane is full so no extra range check is needed.
pub fn polyz_unpack_centered(b: &CircuitBuilder, packed: &[Wire; POLYZ_PACKED_LANES]) -> [Wire; N] {
	let mut coeffs = [b.add_constant(Word::ZERO); N];
	let mask_2 = b.add_constant_64(0x03);
	let mask_4 = b.add_constant_64(0x0F);
	let mask_6 = b.add_constant_64(0x3F);

	for g in 0..N / 4 {
		// 9 raw bytes for this 4-coefficient group.
		let bytes: [Wire; 9] = std::array::from_fn(|k| get_byte(b, packed, 9 * g + k));

		// coeff[0]: bits  0..18 = b0 | (b1 << 8) | ((b2 & 0x03) << 16)
		let p1 = b.shl(bytes[1], 8);
		let b2_lo2 = b.band(bytes[2], mask_2);
		let p2 = b.shl(b2_lo2, 16);
		coeffs[4 * g] = b.bxor_multi(&[bytes[0], p1, p2]);

		// coeff[1]: bits 18..36 = (b2 >> 2) | (b3 << 6) | ((b4 & 0x0F) << 14)
		let b2_hi6 = b.shr(bytes[2], 2);
		let p3 = b.shl(bytes[3], 6);
		let b4_lo4 = b.band(bytes[4], mask_4);
		let p4 = b.shl(b4_lo4, 14);
		coeffs[4 * g + 1] = b.bxor_multi(&[b2_hi6, p3, p4]);

		// coeff[2]: bits 36..54 = (b4 >> 4) | (b5 << 4) | ((b6 & 0x3F) << 12)
		let b4_hi4 = b.shr(bytes[4], 4);
		let p5 = b.shl(bytes[5], 4);
		let b6_lo6 = b.band(bytes[6], mask_6);
		let p6 = b.shl(b6_lo6, 12);
		coeffs[4 * g + 2] = b.bxor_multi(&[b4_hi4, p5, p6]);

		// coeff[3]: bits 54..72 = (b6 >> 6) | (b7 << 2) | (b8 << 10)
		let b6_hi2 = b.shr(bytes[6], 6);
		let p7 = b.shl(bytes[7], 2);
		let p8 = b.shl(bytes[8], 10);
		coeffs[4 * g + 3] = b.bxor_multi(&[b6_hi2, p7, p8]);
	}

	coeffs
}

/// Assert that every centered coefficient of a `z` polynomial satisfies
/// the Dilithium2 norm bound `‖c‖∞ < γ₁ − β`, i.e. equivalently
/// `β < centered < 2γ₁ − β` for every coefficient.
///
/// Two range-check constraints per coefficient (`centered > β` and
/// `centered < 2γ₁ − β`) ⇒ `2 · N = 512` `icmp_ult`/`assert_true` pairs
/// per polynomial.
pub fn assert_norm_centered(b: &CircuitBuilder, coeffs: &[Wire; N]) {
	let beta = b.add_constant_64(MODE2.beta as u64);
	// 2γ₁ − β fits in 19 bits, well inside u64.
	let upper = b.add_constant_64(2 * MODE2.gamma1 as u64 - MODE2.beta as u64);
	for c in coeffs {
		let lo_ok = b.icmp_ult(beta, *c);
		b.assert_true("polyz.norm: centered > beta", lo_ok);
		let hi_ok = b.icmp_ult(*c, upper);
		b.assert_true("polyz.norm: centered < 2*gamma1 - beta", hi_ok);
	}
}

// ─── Native (out-of-circuit) reference helpers ──────────────────────────

/// Native `polyz_pack`: pack 256 centered coefficients into the standard
/// 576-byte little-endian encoding. Mirrors `dilithium/ref/poly.c`'s
/// `polyz_pack` for `GAMMA1 == (1 << 17)`, but takes the *centered* (not
/// signed) representation so it composes with [`polyz_unpack_centered`].
///
/// # Panics
///
/// Panics if any coefficient is `≥ 2γ₁` (the encoding's domain).
pub fn polyz_pack_centered_native(coeffs: &[u32; N]) -> [u8; POLYZ_PACKED_BYTES] {
	let mut out = [0u8; POLYZ_PACKED_BYTES];
	for i in 0..N / 4 {
		let t: [u32; 4] = std::array::from_fn(|k| {
			assert!(coeffs[4 * i + k] < 2 * MODE2.gamma1, "centered coeff out of range");
			coeffs[4 * i + k]
		});
		out[9 * i] = t[0] as u8;
		out[9 * i + 1] = (t[0] >> 8) as u8;
		out[9 * i + 2] = (t[0] >> 16) as u8;
		out[9 * i + 2] |= (t[1] << 2) as u8;
		out[9 * i + 3] = (t[1] >> 6) as u8;
		out[9 * i + 4] = (t[1] >> 14) as u8;
		out[9 * i + 4] |= (t[2] << 4) as u8;
		out[9 * i + 5] = (t[2] >> 4) as u8;
		out[9 * i + 6] = (t[2] >> 12) as u8;
		out[9 * i + 6] |= (t[3] << 6) as u8;
		out[9 * i + 7] = (t[3] >> 2) as u8;
		out[9 * i + 8] = (t[3] >> 10) as u8;
	}
	out
}

/// Inverse of [`polyz_pack_centered_native`] — useful as a reference
/// oracle in tests. Mirrors the C ref but skips the final
/// `c = γ₁ − centered` transformation.
pub fn polyz_unpack_centered_native(packed: &[u8; POLYZ_PACKED_BYTES]) -> [u32; N] {
	let mut coeffs = [0u32; N];
	for i in 0..N / 4 {
		let a = &packed[9 * i..9 * i + 9];
		coeffs[4 * i] =
			(a[0] as u32) | ((a[1] as u32) << 8) | ((a[2] as u32 & 0x03) << 16);
		coeffs[4 * i + 1] =
			((a[2] as u32) >> 2) | ((a[3] as u32) << 6) | ((a[4] as u32 & 0x0F) << 14);
		coeffs[4 * i + 2] =
			((a[4] as u32) >> 4) | ((a[5] as u32) << 4) | ((a[6] as u32 & 0x3F) << 12);
		coeffs[4 * i + 3] =
			((a[6] as u32) >> 6) | ((a[7] as u32) << 2) | ((a[8] as u32) << 10);
	}
	coeffs
}

/// Convert 576 packed bytes into 72 little-endian 64-bit lanes. Used by
/// callers (and tests) populating the witness for
/// [`polyz_unpack_centered`].
pub fn pack_to_lanes(packed: &[u8; POLYZ_PACKED_BYTES]) -> [u64; POLYZ_PACKED_LANES] {
	std::array::from_fn(|i| {
		let mut w = [0u8; 8];
		w.copy_from_slice(&packed[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(w)
	})
}

// ─── Internal helpers ───────────────────────────────────────────────────

fn get_byte(b: &CircuitBuilder, packed: &[Wire], byte_idx: usize) -> Wire {
	let lane = byte_idx / 8;
	let pos = (byte_idx % 8) as u32;
	b.extract_byte(packed[lane], pos)
}
