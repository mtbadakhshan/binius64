// Copyright 2026 The Binius Developers

//! `unpack_h` — variable-length hint parser from the Dilithium2
//! signature's `h` section.
//!
//! ## Wire format (FIPS 204 §5.1, `dilithium/ref/packing.c::unpack_sig`)
//!
//! The h section occupies the last `OMEGA + K = 84` bytes of the
//! signature (bytes `[2336, 2420)` for Mode 2):
//!
//! - bytes `[0, OMEGA) = [0, 80)`: a *contiguous* list of nonzero
//!   hint indices, partitioned across the K = 4 polynomials by the
//!   per-polynomial offsets below.
//! - bytes `[OMEGA, OMEGA + K) = [80, 84)`: cumulative offsets
//!   `k_0, k_1, k_2, k_3`. Polynomial `i` owns the index bytes
//!   `[k_{i-1}, k_i)` (with `k_{-1} = 0`).
//!
//! Validity (strong-unforgeability per FIPS 204):
//!
//! - `0 ≤ k_0 ≤ k_1 ≤ k_2 ≤ k_3 ≤ OMEGA`.
//! - Within each polynomial, the index bytes are strictly increasing.
//! - Bytes `[k_3, OMEGA)` (the trailing "dead" bytes) must all be zero.
//!
//! This parser emits all of those checks in-circuit, plus the
//! consistency check that the supplied `K · N = 1024` hint bits are
//! exactly the indicator vectors implied by the encoded byte stream.
//!
//! ## Witness shape
//!
//! The K hint polynomials are witnessed by the prover (via
//! `add_witness` per bit) and constrained against the byte stream
//! supplied via `sig_lanes`. Each bit is range-checked `< 2`, the
//! per-byte cascade enforces the bit-vs-byte consistency, and a
//! cardinality sum enforces `Σ h[i][p] == k_3`.
//!
//! ## Cost
//!
//! ≈ 88 000 cells per `unpack_h` call (the bulk is `OMEGA · K = 320`
//! 256-way `single_wire_multiplex` lookups for the per-byte hint-bit
//! reads). Heavy but tractable; this is the most expensive R1 piece.
//! Optimisation is left as a Phase 2 follow-up if profiling demands it.

use binius_circuits::multiplexer::single_wire_multiplex;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

use crate::{
	params::{MODE2, N},
	sigdecode::{SIG_H_LANE_OFFSET, SIG_PACKED_LANES},
};

const K: usize = MODE2.k;
/// Number of "index" bytes (positions of nonzero hint coefficients,
/// concatenated across K polynomials).
pub const HINT_INDEX_BYTES: usize = MODE2.omega;
/// Number of "offset" bytes (cumulative counts `k_0, …, k_{K-1}`).
pub const HINT_OFFSET_BYTES: usize = K;
/// Total hint section bytes: `OMEGA + K = 84`.
pub const HINT_SECTION_BYTES: usize = HINT_INDEX_BYTES + HINT_OFFSET_BYTES;

const _: () = assert!(HINT_SECTION_BYTES == 84);

// ─── In-circuit gadget ──────────────────────────────────────────────────

/// Decode the K hint polynomials from the signature's `h` section.
///
/// `sig_lanes` is the full 303-lane Dilithium2 signature. The `h`
/// section starts at byte `SIG_H_LANE_OFFSET * 8 = 2336` and the
/// parser reads exactly `HINT_SECTION_BYTES = 84` bytes from there
/// (bytes beyond byte 2419 are zero-padding from the signature's
/// 4-byte tail and are never accessed).
///
/// Returns the K hint polynomials as `[[Wire; N]; K]`, each a vector
/// of N range-checked 0/1 wires.
pub fn unpack_h(b: &CircuitBuilder, sig_lanes: &[Wire; SIG_PACKED_LANES]) -> [[Wire; N]; K] {
	let h_byte_offset = SIG_H_LANE_OFFSET * 8;

	// Witness K * N hint bits and range-check each `< 2`.
	let h: [[Wire; N]; K] = std::array::from_fn(|_| {
		std::array::from_fn(|_| {
			let bit = b.add_witness();
			let two = b.add_constant_64(2);
			let in_range = b.icmp_ult(bit, two);
			b.assert_true("hint bit < 2", in_range);
			bit
		})
	});

	// Read the K offset bytes from sig.
	let k_offsets: [Wire; K] = std::array::from_fn(|i| {
		get_sig_byte(b, sig_lanes, h_byte_offset + HINT_INDEX_BYTES + i)
	});

	// Read the OMEGA index bytes from sig.
	let bytes: [Wire; HINT_INDEX_BYTES] =
		std::array::from_fn(|j| get_sig_byte(b, sig_lanes, h_byte_offset + j));

	let zero = b.add_constant(Word::ZERO);
	let one = b.add_constant_64(1);
	let omega_const = b.add_constant_64(MODE2.omega as u64);
	let k_const = b.add_constant_64(K as u64);

	// Range-check offsets: monotone non-decreasing AND `k_{K-1} ≤ OMEGA`.
	for i in 1..K {
		let mono = b.icmp_ule(k_offsets[i - 1], k_offsets[i]);
		b.assert_true("hint offsets monotone", mono);
	}
	let last_in_range = b.icmp_ule(k_offsets[K - 1], omega_const);
	b.assert_true("k_{K-1} <= OMEGA", last_in_range);

	// Per-byte cascade.
	//
	// For each j ∈ [0, OMEGA) we compute:
	//   - poly_at_j = number of {k_i : k_i ≤ j} = the polynomial this byte
	//     belongs to (or K = "dead" if it's past `k_{K-1}`).
	//   - live_j    = (poly_at_j < K).
	//
	// And constrain:
	//   - live: `h[poly_at_j][b_j] == 1` (per-poly 256-way mux + 4-way
	//     poly select + conditional assert).
	//   - dead: `b_j == 0`.
	//   - strict ordering within a polynomial: if `poly_at_j ==
	//     poly_at_{j-1}` AND `live_j`, then `b_j > b_{j-1}`.
	let mut prev_poly_at_j = zero;
	let mut prev_byte = zero;

	for j in 0..HINT_INDEX_BYTES {
		let j_wire = b.add_constant_64(j as u64);
		let b_j = bytes[j];

		// poly_at_j = sum over i of (k_i ≤ j).
		let mut poly_at_j = zero;
		for i in 0..K {
			let cond = b.icmp_ule(k_offsets[i], j_wire);
			let bit = b.select(cond, one, zero);
			poly_at_j = b.iadd(poly_at_j, bit).0;
		}

		let live_j = b.icmp_ult(poly_at_j, k_const);
		let dead_j = b.icmp_ule(k_const, poly_at_j);

		// Read h[poly_at_j][b_j].
		let per_poly_lookups: Vec<Wire> = (0..K)
			.map(|i| single_wire_multiplex(b, &h[i], b_j))
			.collect();
		let h_at = single_wire_multiplex(b, &per_poly_lookups, poly_at_j);

		// If live: assert `h_at == 1`.
		b.assert_eq_cond("live h[poly_at_j][b_j] == 1", h_at, one, live_j);

		// If dead: assert `b_j == 0`. Implementation: the violation
		// `dead AND (b_j != 0)` must be MSB-false.
		let b_j_is_zero = b.icmp_ult(b_j, one); // b_j < 1 ⇔ b_j == 0
		let bad_dead = b.band(dead_j, b.bnot(b_j_is_zero));
		b.assert_false("dead byte must be zero", bad_dead);

		// Strict ordering within a polynomial.
		if j > 0 {
			let same_poly_xor = b.bxor(poly_at_j, prev_poly_at_j);
			let same_poly = b.icmp_ult(same_poly_xor, one);
			let must_order = b.band(same_poly, live_j);
			let prev_geq = b.icmp_ule(b_j, prev_byte); // violation: b_j ≤ prev_byte
			let bad_order = b.band(must_order, prev_geq);
			b.assert_false("hint indices strictly increasing within polynomial", bad_order);
		}

		prev_poly_at_j = poly_at_j;
		prev_byte = b_j;
	}

	// Cardinality: total number of set hint bits == k_{K-1}.
	let mut total = zero;
	for poly in h.iter() {
		for &bit in poly.iter() {
			total = b.iadd(total, bit).0;
		}
	}
	b.assert_eq("hint cardinality == k_{K-1}", total, k_offsets[K - 1]);

	h
}

// ─── Native (out-of-circuit) helpers ────────────────────────────────────

/// Native packer: turn K hint polynomials into the 84-byte hint section
/// per `dilithium/ref/packing.c::pack_sig`. Used by tests to construct
/// signatures that `unpack_h` must accept.
///
/// `h_polyvec[i]` has `N` entries, each 0 or 1. The total Hamming weight
/// must be `≤ OMEGA`, otherwise this panics (the encoding has no room).
pub fn pack_h_native(h_polyvec: &[[u8; N]; K]) -> [u8; HINT_SECTION_BYTES] {
	let mut out = [0u8; HINT_SECTION_BYTES];
	let mut k = 0usize;
	for (i, poly) in h_polyvec.iter().enumerate() {
		for (p, &bit) in poly.iter().enumerate() {
			assert!(bit < 2, "hint bit out of range");
			if bit == 1 {
				assert!(k < MODE2.omega, "hint vector exceeds OMEGA non-zeros");
				out[k] = p as u8;
				k += 1;
			}
		}
		out[MODE2.omega + i] = k as u8;
	}
	// Bytes [k, OMEGA) and offsets after the K we wrote stay 0.
	out
}

// ─── Internal helpers ───────────────────────────────────────────────────

fn get_sig_byte(b: &CircuitBuilder, sig_lanes: &[Wire], byte_idx: usize) -> Wire {
	let lane = byte_idx / 8;
	let pos = (byte_idx % 8) as u32;
	b.extract_byte(sig_lanes[lane], pos)
}
