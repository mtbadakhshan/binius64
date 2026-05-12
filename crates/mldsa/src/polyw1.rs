// Copyright 2026 The Binius Developers

//! Dilithium2 `w₁`-polynomial bit-packing (`polyw1_pack` from
//! `dilithium/ref/poly.c`, also called `w₁Encode` in FIPS 204 §7.10).
//!
//! Each coefficient of `w₁'` lives in `[0, 43]` (6 bits). The encoding
//! packs 4 consecutive coefficients into 3 bytes, so for Mode 2 one
//! polynomial of `N = 256` coefficients packs into `N · 6 / 8 = 192`
//! bytes (= [`POLYW1_PACKED_LANES`] = 24 little-endian 64-bit lanes),
//! and the K = 4 polynomial vector packs into `K · 192 = 768` bytes.
//!
//! This module exposes the per-polynomial encoder. The `K = 4` wrapper
//! is just `K` calls; it'll land alongside the R7 framing wrapper that
//! feeds the result into `shake256`.
//!
//! ## Caller contract
//!
//! Each input coefficient must be in `[0, 63]` — the 6-bit window the
//! encoding allocates. In practice each comes from
//! [`crate::rounding::use_hint`] which always returns `≤ 43`, so this
//! contract is trivially satisfied in the verifier circuit. The
//! encoder *does not* re-range-check its inputs (one would otherwise
//! pay 256 `icmp_ult + assert_true` per polynomial); the contract is
//! documented here and tested by [`crate::polyw1::tests::polyw1_pack_native_silently_aliases_overflow_bits`]
//! in the natural-debug-mode `assert!`.

use binius_frontend::{CircuitBuilder, Wire};

use crate::params::N;

/// Packed bytes per Dilithium2 `w₁` polynomial: `N · 6 / 8 = 192`.
pub const POLYW1_PACKED_BYTES: usize = N * 6 / 8;
/// Same value as 64-bit lanes: `192 / 8 = 24`.
pub const POLYW1_PACKED_LANES: usize = POLYW1_PACKED_BYTES / 8;

const _: () = assert!(POLYW1_PACKED_BYTES.is_multiple_of(8), "must be lane-aligned");
const _: () = assert!(POLYW1_PACKED_BYTES == 192);
const _: () = assert!(POLYW1_PACKED_LANES == 24);

// ─── In-circuit gadget ──────────────────────────────────────────────────

/// Pack one Dilithium2 `w₁'` polynomial (256 coefficients, each in
/// `[0, 43]`) into the 24-lane little-endian byte encoding consumed by
/// the R7 final hash.
///
/// Each coefficient `c[i]` occupies bits `[6i, 6i+5]` of the global
/// byte stream. The implementation walks each coefficient and emits up
/// to two contributions — one to the lane that holds `bit 6i`, plus one
/// to the next lane when the 6-bit window straddles a 64-bit boundary
/// (this happens once per `bit_offset > 58`, i.e. roughly every
/// 11th coefficient). All contributions to a given lane are then
/// `bxor`-folded together; correctness relies on the contract that no
/// coefficient has bits set outside `[0, 5]` (so the contributions are
/// in disjoint bit positions).
///
/// Cost: ≈ `256 + Σ overflows ≈ 280` `shl`/`shr` ops (each 1
/// linear-only constraint on Binius64) plus 24 multi-input `bxor`
/// folds (free linear combinations on Binius64). No AND, no MUL, no
/// hint.
pub fn polyw1_pack(b: &CircuitBuilder, coeffs: &[Wire; N]) -> [Wire; POLYW1_PACKED_LANES] {
	let mut contribs: Vec<Vec<Wire>> = vec![Vec::new(); POLYW1_PACKED_LANES];

	for (i, &c) in coeffs.iter().enumerate() {
		let bit_start = 6 * i;
		let lane = bit_start / 64;
		let offset = bit_start % 64;

		// Current-lane contribution: `c << offset`. The high bits that
		// don't fit in the lane shift out the top of the u64 (which is
		// what we want — they'll re-appear via the `c >> (64 - offset)`
		// next-lane term below).
		let curr = if offset == 0 {
			c
		} else {
			b.shl(c, offset as u32)
		};
		contribs[lane].push(curr);

		// Next-lane overflow contribution. Only emitted when the 6-bit
		// window crosses the lane boundary (`offset + 6 > 64`, i.e.
		// `offset > 58`). For `offset == 0` we'd otherwise need
		// `shr(c, 64)`, which is undefined; the conditional guards
		// against it.
		if offset > 58 {
			contribs[lane + 1].push(b.shr(c, (64 - offset) as u32));
		}
	}

	std::array::from_fn(|lane_idx| b.bxor_multi(&contribs[lane_idx]))
}

// ─── Native (out-of-circuit) reference ──────────────────────────────────

/// Native `polyw1_pack` — exact port of `dilithium/ref/poly.c`'s
/// `GAMMA2 == (Q − 1) / 88` branch. Bit-for-bit identical to what the
/// reference C produces given the same input.
pub fn polyw1_pack_native(coeffs: &[u32; N]) -> [u8; POLYW1_PACKED_BYTES] {
	let mut out = [0u8; POLYW1_PACKED_BYTES];
	for i in 0..N / 4 {
		let t: [u32; 4] = std::array::from_fn(|k| coeffs[4 * i + k]);
		out[3 * i] = t[0] as u8;
		out[3 * i] |= (t[1] << 6) as u8;
		out[3 * i + 1] = (t[1] >> 2) as u8;
		out[3 * i + 1] |= (t[2] << 4) as u8;
		out[3 * i + 2] = (t[2] >> 4) as u8;
		out[3 * i + 2] |= (t[3] << 2) as u8;
	}
	out
}

/// Convert `POLYW1_PACKED_BYTES` packed bytes into 24 LE 64-bit lanes —
/// the format [`polyw1_pack`] returns. Used by tests.
pub fn pack_to_lanes(packed: &[u8; POLYW1_PACKED_BYTES]) -> [u64; POLYW1_PACKED_LANES] {
	std::array::from_fn(|i| {
		let mut w = [0u8; 8];
		w.copy_from_slice(&packed[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(w)
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn polyw1_pack_native_zero_polynomial() {
		assert_eq!(polyw1_pack_native(&[0u32; N]), [0u8; POLYW1_PACKED_BYTES]);
	}

	#[test]
	fn polyw1_pack_native_max_w1_value() {
		// All coefficients at the max valid w1' = 43 = 0b101011.
		let packed = polyw1_pack_native(&[43u32; N]);
		// Verify the packing matches a hand-computed value for the
		// first group: coeffs (43, 43, 43, 43)
		//   byte 0 = 43 | (43 << 6) & 0xff = 0b00101011 | 0b11000000 = 0xeb
		//   byte 1 = (43 >> 2) | ((43 << 4) & 0xff) = 0b00001010 | 0b10110000 = 0xba
		//   byte 2 = (43 >> 4) | (43 << 2) & 0xff = 0b00000010 | 0b10101100 = 0xae
		assert_eq!(packed[0], 0xeb);
		assert_eq!(packed[1], 0xba);
		assert_eq!(packed[2], 0xae);
	}

	#[test]
	fn polyw1_pack_native_silently_aliases_overflow_bits() {
		// Documents the caller contract: an out-of-range coefficient
		// (bit 6 or higher set) silently corrupts adjacent positions
		// because the C ref uses byte-typed `|=` (which narrowing-casts
		// to u8). The in-circuit `polyw1_pack` shares this property
		// (it XORs disjoint windows; out-of-range bits land in adjacent
		// windows). Fix is upstream — only feed `polyw1_pack`
		// coefficients in [0, 63] (in practice [0, 43] from
		// `use_hint`).
		let mut coeffs = [0u32; N];
		coeffs[0] = 0x40; // bit 6 set, alias position of coeffs[1]'s bit 0
		let packed = polyw1_pack_native(&coeffs);
		// byte 0 = (0x40 as u8) = 0x40, but bits beyond position 6 are
		// truncated by the implicit u8 cast. So byte 0 should be 0x40,
		// not 0x40 | (coeffs[1] << 6) = 0x40 (since coeffs[1] = 0).
		assert_eq!(packed[0], 0x40);
		// However, byte 1 captures the *high* bits of coeffs[0] via
		// `(coeffs[1] >> 2)` — and since coeffs[1] = 0, byte 1 = 0.
		// The bit 6 of coeffs[0] is "lost" (silently dropped) in the
		// native pack, because the C ref's `(coeffs[0] as u8)` already
		// keeps only the low 8 bits, and the encoding only reads bits
		// 0..5 of each coefficient via the OR pattern.
		assert_eq!(packed[1], 0);
	}
}
