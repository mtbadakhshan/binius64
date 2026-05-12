// Copyright 2026 The Binius Developers

//! In-circuit `hint::unpack_h` cross-validated against the native pack
//! reference. Covers acceptance for several hint distributions plus a
//! battery of tamper rejections (one per FIPS 204 validity rule).

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	hint::{HINT_SECTION_BYTES, pack_h_native, unpack_h},
	params::{MODE2, N},
	sigdecode::{SIG_H_LANE_OFFSET, SIG_PACKED_BYTES, SIG_PACKED_LANES, signature_to_lanes},
};
use rand::{Rng, SeedableRng, rngs::StdRng};

const K: usize = MODE2.k;

/// Embed an 84-byte hint section into a 2420-byte signature (with the
/// other sections zero-filled), then convert to the 303-lane LE
/// representation used by `unpack_h`.
fn embed_hint_section(h_bytes: &[u8; HINT_SECTION_BYTES]) -> [u64; SIG_PACKED_LANES] {
	let mut sig = [0u8; SIG_PACKED_BYTES];
	let h_byte_offset = SIG_H_LANE_OFFSET * 8;
	sig[h_byte_offset..h_byte_offset + HINT_SECTION_BYTES].copy_from_slice(h_bytes);
	signature_to_lanes(&sig)
}

/// Override individual bytes of an honest hint section. Used by tamper
/// tests to mutate a known-good encoding.
fn embed_hint_section_with_overrides(
	mut h_bytes: [u8; HINT_SECTION_BYTES],
	overrides: &[(usize, u8)],
) -> [u64; SIG_PACKED_LANES] {
	for &(idx, val) in overrides {
		h_bytes[idx] = val;
	}
	embed_hint_section(&h_bytes)
}

/// Build a circuit that runs `unpack_h` on the supplied signature
/// lanes, populates the returned hint-bit witness wires with
/// `witnessed_h`, and returns whether the resulting witness satisfies
/// the circuit's constraints.
///
/// `witnessed_h` is what the prover claims the hint vector is. For
/// honest tests it's the bit pattern that `pack_h_native` encoded
/// into `sig_lanes`. For tamper tests it can be any other bit pattern
/// — the in-circuit cascade decides whether to accept.
fn run_unpack(
	sig_lanes: &[u64; SIG_PACKED_LANES],
	witnessed_h: &[[u8; N]; K],
) -> Result<(), ()> {
	let builder = CircuitBuilder::new();
	let sig_wires: [Wire; SIG_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let extracted = unpack_h(&builder, &sig_wires);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in sig_wires.iter().zip(sig_lanes) {
		filler[*w] = Word(v);
	}
	// `extracted[k][p]` are the witness wires `unpack_h` allocated for
	// the prover-supplied hint bits; the prover (test) drives them.
	for k in 0..K {
		for p in 0..N {
			filler[extracted[k][p]] = Word(witnessed_h[k][p] as u64);
		}
	}
	if circuit.populate_wire_witness(&mut filler).is_err() {
		return Err(());
	}
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).map_err(|_| ())
}

// ─── Native sanity ──────────────────────────────────────────────────────

#[test]
fn native_pack_and_offsets_consistent() {
	let mut h = [[0u8; N]; K];
	h[0][5] = 1;
	h[0][100] = 1;
	h[1][0] = 1;
	h[2][255] = 1;
	let packed = pack_h_native(&h);
	// Three nonzeros in poly 0 and 1 (= 3 total), then 4 in poly 2 (= 4 total).
	assert_eq!(packed[0], 5);
	assert_eq!(packed[1], 100);
	assert_eq!(packed[2], 0);
	assert_eq!(packed[3], 255);
	assert_eq!(packed[MODE2.omega], 2); // k_0
	assert_eq!(packed[MODE2.omega + 1], 3); // k_1
	assert_eq!(packed[MODE2.omega + 2], 4); // k_2
	assert_eq!(packed[MODE2.omega + 3], 4); // k_3 (poly 3 has zero nonzeros)
}

// ─── Acceptance: various honest distributions ──────────────────────────

#[test]
fn unpack_h_accepts_all_zero() {
	let h = [[0u8; N]; K];
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);
	run_unpack(&sig_lanes, &h).expect("all-zero hint must be accepted");
}

#[test]
fn unpack_h_accepts_one_per_poly() {
	let mut h = [[0u8; N]; K];
	for k in 0..K {
		h[k][k * 60 + 17] = 1;
	}
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);
	run_unpack(&sig_lanes, &h).expect("1-per-poly hint must be accepted");
}

#[test]
fn unpack_h_accepts_one_polynomial_only() {
	let mut h = [[0u8; N]; K];
	// 20 nonzeros, all in polynomial 0.
	for p in (0..20).map(|i| i * 13) {
		h[0][p] = 1;
	}
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);
	run_unpack(&sig_lanes, &h).expect("single-poly hint must be accepted");
}

#[test]
fn unpack_h_accepts_omega_full_density() {
	// Maximum-density hint: all OMEGA = 80 nonzero slots used.
	// Distribute roughly evenly across K = 4 polynomials (20 each).
	let mut h = [[0u8; N]; K];
	for k in 0..K {
		for j in 0..20 {
			h[k][j * 12] = 1;
		}
	}
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);
	run_unpack(&sig_lanes, &h).expect("OMEGA-density hint must be accepted");
}

#[test]
fn unpack_h_accepts_random_seeded() {
	for seed in 0..3 {
		let mut rng = StdRng::seed_from_u64(seed);
		let mut h = [[0u8; N]; K];
		// Distribute some random count in [0, OMEGA] across K polys,
		// at random distinct positions per poly.
		let total_nonzeros = rng.random_range(0..=MODE2.omega);
		let mut placed = 0usize;
		for k in 0..K {
			if placed >= total_nonzeros {
				break;
			}
			let this_count = rng.random_range(0..=(total_nonzeros - placed).min(40));
			let mut positions: Vec<usize> = (0..N).collect();
			// Fisher-Yates partial shuffle, then take first `this_count`,
			// then sort. Guarantees distinct positions.
			for i in 0..this_count.min(positions.len()) {
				let j = rng.random_range(i..positions.len());
				positions.swap(i, j);
			}
			let mut chosen: Vec<usize> = positions[..this_count].to_vec();
			chosen.sort_unstable();
			for p in chosen {
				h[k][p] = 1;
			}
			placed += this_count;
		}
		let packed = pack_h_native(&h);
		let sig_lanes = embed_hint_section(&packed);
		run_unpack(&sig_lanes, &h)
			.unwrap_or_else(|_| panic!("seed {seed} random hint must be accepted"));
	}
}

// ─── Tamper rejection: each FIPS 204 validity rule has a test ──────────

#[test]
fn unpack_h_rejects_non_monotone_offsets() {
	// Honest distribution: one nonzero per polynomial → offsets 1, 2, 3, 4.
	let mut h = [[0u8; N]; K];
	for k in 0..K {
		h[k][k * 50] = 1;
	}
	let packed = pack_h_native(&h);
	// Tamper: swap k_0 and k_1 so offsets become non-monotone (2, 1, ...).
	let sig_lanes = embed_hint_section_with_overrides(
		packed,
		&[(MODE2.omega, 2), (MODE2.omega + 1, 1)],
	);
	assert!(
		run_unpack(&sig_lanes, &h).is_err(),
		"non-monotone offsets must be rejected",
	);
}

#[test]
fn unpack_h_rejects_offset_above_omega() {
	let mut h = [[0u8; N]; K];
	h[0][7] = 1;
	let packed = pack_h_native(&h);
	// Tamper: k_3 = 81 > OMEGA = 80.
	let sig_lanes =
		embed_hint_section_with_overrides(packed, &[(MODE2.omega + K - 1, 81)]);
	assert!(
		run_unpack(&sig_lanes, &h).is_err(),
		"offset > OMEGA must be rejected",
	);
}

#[test]
fn unpack_h_rejects_non_strict_ordering() {
	// Construct a poly with two nonzeros at positions 5 and 10.
	let mut h = [[0u8; N]; K];
	h[0][5] = 1;
	h[0][10] = 1;
	let packed = pack_h_native(&h);
	// Tamper: swap the two index bytes so the order is 10, 5 (descending,
	// violating "strict ascending" within poly 0).
	let sig_lanes = embed_hint_section_with_overrides(packed, &[(0, 10), (1, 5)]);
	assert!(
		run_unpack(&sig_lanes, &h).is_err(),
		"non-strict ordering within a polynomial must be rejected",
	);
}

#[test]
fn unpack_h_rejects_duplicate_index_within_polynomial() {
	let mut h = [[0u8; N]; K];
	h[0][5] = 1;
	h[0][10] = 1;
	let packed = pack_h_native(&h);
	// Tamper: change index 1 from "10" to "5" (same as index 0).
	// Strict ordering also fails (5 == 5 isn't > 5), so rejected.
	let sig_lanes = embed_hint_section_with_overrides(packed, &[(1, 5)]);
	assert!(
		run_unpack(&sig_lanes, &h).is_err(),
		"duplicate index within a polynomial must be rejected (violates strict ordering)",
	);
}

#[test]
fn unpack_h_rejects_nonzero_dead_byte() {
	let mut h = [[0u8; N]; K];
	h[0][7] = 1;
	let packed = pack_h_native(&h);
	// k_3 = 1, so byte index 1 is the first dead byte. Tamper: set it to 42.
	let sig_lanes = embed_hint_section_with_overrides(packed, &[(1, 42)]);
	assert!(
		run_unpack(&sig_lanes, &h).is_err(),
		"non-zero dead byte must be rejected",
	);
}

#[test]
fn unpack_h_rejects_bit_count_mismatch() {
	// Honest packed has k_3 = 2 ones; if the prover witnesses 1 bit, the
	// cardinality assertion fails (and the per-byte h-lookup either
	// passes or fails, but cardinality at minimum triggers).
	let mut h = [[0u8; N]; K];
	h[0][7] = 1;
	h[0][20] = 1;
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);

	// Tamper the EXPECTED hint vector (the witness): drop one bit so the
	// witnessed h has cardinality 1 while the encoded byte stream has
	// cardinality 2.
	let mut tampered_h = h;
	tampered_h[0][20] = 0;
	assert!(
		run_unpack(&sig_lanes, &tampered_h).is_err(),
		"witnessed-bit-count mismatch with encoded offset must be rejected",
	);
}

#[test]
fn unpack_h_rejects_wrong_position_with_correct_count() {
	// Honest: bit at position 7 in poly 0.
	// Tamper the witness: bit at position 8 instead. Cardinality
	// matches (both are 1) but the per-byte h_at lookup at b_0 = 7
	// reads h[0][7] = 0 (since prover witnessed h[0][8] = 1), which
	// violates "live h_at == 1".
	let mut h = [[0u8; N]; K];
	h[0][7] = 1;
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);

	let mut tampered_h = [[0u8; N]; K];
	tampered_h[0][8] = 1;
	assert!(
		run_unpack(&sig_lanes, &tampered_h).is_err(),
		"wrong hint position (cardinality preserved) must be rejected",
	);
}

#[test]
fn unpack_h_rejects_h_bit_geq_2() {
	let mut h = [[0u8; N]; K];
	h[0][7] = 1;
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);

	// Tamper: witness h[0][7] as 2 instead of 1 (out of bit range).
	let mut tampered_h = h;
	tampered_h[0][7] = 2;
	assert!(
		run_unpack(&sig_lanes, &tampered_h).is_err(),
		"hint bit > 1 must be rejected by the per-bit `< 2` range check",
	);
}

// ─── Sanity: index byte equal to its `j` position must NOT confuse parser ─

#[test]
fn unpack_h_handles_index_byte_equal_to_byte_position() {
	// Edge case: each index byte happens to equal its byte position
	// (b_0 = 0 for poly 0, b_1 = 1, …). The strict-ordering check
	// (b_j > b_{j-1}) and the dead-byte-zero check (which sees b_0 = 0
	// for the dead-byte case) both involve comparing values that look
	// confusingly similar; this test pins that nothing leaks.
	let mut h = [[0u8; N]; K];
	for j in 0..4 {
		h[0][j] = 1;
	}
	let packed = pack_h_native(&h);
	let sig_lanes = embed_hint_section(&packed);
	run_unpack(&sig_lanes, &h)
		.expect("ascending index sequence at small positions must be accepted");
}
