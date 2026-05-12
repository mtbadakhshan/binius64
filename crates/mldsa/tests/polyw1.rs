// Copyright 2026 The Binius Developers

//! In-circuit `polyw1::polyw1_pack` cross-validated against the native
//! C-equivalent reference.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	params::N,
	polyw1::{
		POLYW1_PACKED_LANES, pack_to_lanes, polyw1_pack, polyw1_pack_native,
	},
};
use rand::{Rng, SeedableRng, rngs::StdRng};

const ALPHA: u32 = 44;

/// Build a circuit that allocates 256 coefficient witness wires, runs
/// `polyw1_pack`, and asserts each lane equals the native reference.
fn check_pack(coeffs: &[u32; N]) {
	let expected_lanes = pack_to_lanes(&polyw1_pack_native(coeffs));

	let builder = CircuitBuilder::new();
	let coeff_wires: [Wire; N] = std::array::from_fn(|_| builder.add_witness());
	let extracted = polyw1_pack(&builder, &coeff_wires);
	let expected_wires: [Wire; POLYW1_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	for i in 0..POLYW1_PACKED_LANES {
		builder.assert_eq(format!("polyw1[{i}]"), extracted[i], expected_wires[i]);
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in coeff_wires.iter().zip(coeffs) {
		filler[*w] = Word(v as u64);
	}
	for (w, &v) in expected_wires.iter().zip(&expected_lanes) {
		filler[*w] = Word(v);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("polyw1_pack must accept honest in-bound witness");
}

// ─── Direct cross-validation with the native ref ────────────────────────

#[test]
fn polyw1_pack_zeros() {
	check_pack(&[0u32; N]);
}

#[test]
fn polyw1_pack_max_w1_value() {
	check_pack(&[ALPHA - 1; N]);
}

#[test]
fn polyw1_pack_constant_per_position() {
	// One coefficient per group at the max valid w1' = 43, others zero.
	// Mirrors the polyz "isolation" test: catches any bit-leakage
	// between adjacent 6-bit windows.
	for k in 0..4 {
		let mut coeffs = [0u32; N];
		for g in 0..N / 4 {
			coeffs[4 * g + k] = ALPHA - 1;
		}
		check_pack(&coeffs);
	}
}

#[test]
fn polyw1_pack_random_seeded() {
	let mut rng = StdRng::seed_from_u64(0xfeedface);
	let coeffs: [u32; N] = std::array::from_fn(|_| rng.random_range(0..ALPHA));
	check_pack(&coeffs);
}

#[test]
fn polyw1_pack_full_window_values() {
	// Every coefficient at the largest 6-bit value (63), still within
	// the caller contract (< 64). The C ref produces a specific
	// pattern; cross-check.
	check_pack(&[0x3f; N]);
}

// ─── Bit-leakage and lane-boundary stress ──────────────────────────────

#[test]
fn polyw1_pack_alternating_extremes() {
	// Alternate 0 and 43 across consecutive coefficients. Within one
	// group of 4: (0, 43, 0, 43) and (43, 0, 43, 0). Catches errors in
	// either even or odd positions of the 4-coefficient encoding.
	let mut coeffs = [0u32; N];
	for i in 0..N {
		coeffs[i] = if i.is_multiple_of(2) { 43 } else { 0 };
	}
	check_pack(&coeffs);
	for i in 0..N {
		coeffs[i] = if i.is_multiple_of(2) { 0 } else { 43 };
	}
	check_pack(&coeffs);
}

#[test]
fn polyw1_pack_one_set_at_each_lane_boundary() {
	// Lane boundaries at coefficient indices: i where bit_offset > 58
	// (i.e. the 6-bit window straddles the next lane). For Mode 2 these
	// are i ≡ 10, 21, 32, 42, 53, 64, ... (each ~11 apart). Set just
	// these "straddling" coefficients to 43, others zero, to specifically
	// stress the next-lane overflow contribution.
	let mut coeffs = [0u32; N];
	for i in 0..N {
		let off = (6 * i) % 64;
		if off > 58 {
			coeffs[i] = 43;
		}
	}
	check_pack(&coeffs);
}
