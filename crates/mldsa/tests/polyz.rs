// Copyright 2026 The Binius Developers

//! End-to-end tests for the in-circuit `polyz_unpack_centered` and
//! `assert_norm_centered` gadgets.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	params::{MODE2, N},
	polyz::{
		POLYZ_PACKED_LANES, assert_norm_centered, pack_to_lanes,
		polyz_pack_centered_native, polyz_unpack_centered, polyz_unpack_centered_native,
	},
};
use proptest::prelude::*;
use rand::{Rng, SeedableRng, rngs::StdRng};

const TWO_GAMMA1: u32 = 2 * MODE2.gamma1;

/// Builds a circuit that allocates witness wires for the 72 packed lanes
/// of one z polynomial, runs `polyz_unpack_centered`, asserts every
/// extracted coefficient equals a corresponding witness, and
/// `verify_constraints` accepts. Returns the in-circuit-extracted
/// coefficient values via the asserted-equal expected wires.
fn check_unpack(centered: &[u32; N]) {
	let packed = polyz_pack_centered_native(centered);
	let lanes = pack_to_lanes(&packed);

	let builder = CircuitBuilder::new();
	let packed_wires: [Wire; POLYZ_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let expected_wires: [Wire; N] = std::array::from_fn(|_| builder.add_witness());

	let extracted = polyz_unpack_centered(&builder, &packed_wires);
	for i in 0..N {
		builder.assert_eq(format!("polyz unpack[{i}]"), extracted[i], expected_wires[i]);
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in packed_wires.iter().zip(&lanes) {
		filler[*w] = Word(v);
	}
	for (w, &v) in expected_wires.iter().zip(centered) {
		filler[*w] = Word(v as u64);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("polyz_unpack_centered must accept honest witness");
}

/// Builds a circuit that runs `polyz_unpack_centered` followed by
/// `assert_norm_centered`. Returns Ok if the constraints accept, Err
/// (silently — caller chooses how to interpret) otherwise.
fn try_unpack_and_norm(centered: &[u32; N]) -> Result<(), ()> {
	let packed = polyz_pack_centered_native(centered);
	let lanes = pack_to_lanes(&packed);

	let builder = CircuitBuilder::new();
	let packed_wires: [Wire; POLYZ_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let extracted = polyz_unpack_centered(&builder, &packed_wires);
	assert_norm_centered(&builder, &extracted);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in packed_wires.iter().zip(&lanes) {
		filler[*w] = Word(v);
	}
	if circuit.populate_wire_witness(&mut filler).is_err() {
		return Err(());
	}
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).map_err(|_| ())
}

// ─── Native pack/unpack round-trip (sanity check on the ref) ────────────

#[test]
fn native_pack_then_unpack_round_trips() {
	let mut rng = StdRng::seed_from_u64(0);
	let coeffs: [u32; N] = std::array::from_fn(|_| rng.random_range(0..TWO_GAMMA1));
	let packed = polyz_pack_centered_native(&coeffs);
	let recovered = polyz_unpack_centered_native(&packed);
	assert_eq!(coeffs, recovered);
}

// ─── In-circuit unpack matches native unpack ────────────────────────────

#[test]
fn polyz_unpack_zeros() {
	check_unpack(&[0u32; N]);
}

#[test]
fn polyz_unpack_max_centered() {
	check_unpack(&[TWO_GAMMA1 - 1; N]);
}

#[test]
fn polyz_unpack_random_seeded() {
	let mut rng = StdRng::seed_from_u64(0xc0ffee);
	let coeffs: [u32; N] = std::array::from_fn(|_| rng.random_range(0..TWO_GAMMA1));
	check_unpack(&coeffs);
}

#[test]
fn polyz_unpack_independent_per_index() {
	// One coefficient per group at the maximum value, all others zero.
	// Makes sure no group leaks bits into its neighbours.
	for k in 0..4 {
		let mut coeffs = [0u32; N];
		for g in 0..N / 4 {
			coeffs[4 * g + k] = TWO_GAMMA1 - 1;
		}
		check_unpack(&coeffs);
	}
}

// ─── Norm check accepts in-bound, rejects boundary violations ───────────

#[test]
fn norm_accepts_all_zero_centered_around_gamma1() {
	// centered = γ₁ ⇒ signed coeff = 0, well inside the norm.
	let coeffs = [MODE2.gamma1; N];
	try_unpack_and_norm(&coeffs).expect("γ₁ centered must satisfy the norm bound");
}

#[test]
fn norm_accepts_inner_boundary_lower() {
	// centered = β + 1 ⇒ |signed coeff| = γ₁ − β − 1, the largest
	// allowed magnitude.
	let mut coeffs = [MODE2.gamma1; N];
	coeffs[0] = MODE2.beta + 1;
	try_unpack_and_norm(&coeffs).expect("centered = β + 1 must satisfy the norm bound");
}

#[test]
fn norm_accepts_inner_boundary_upper() {
	// centered = 2γ₁ − β − 1 ⇒ same magnitude as above, opposite sign.
	let mut coeffs = [MODE2.gamma1; N];
	coeffs[0] = 2 * MODE2.gamma1 - MODE2.beta - 1;
	try_unpack_and_norm(&coeffs).expect("centered = 2γ₁ − β − 1 must satisfy the norm bound");
}

#[test]
fn norm_rejects_centered_equal_beta() {
	// |signed coeff| = γ₁ − β, exactly the bound, must be rejected.
	let mut coeffs = [MODE2.gamma1; N];
	coeffs[42] = MODE2.beta;
	assert!(
		try_unpack_and_norm(&coeffs).is_err(),
		"centered = β must violate the strict norm bound",
	);
}

#[test]
fn norm_rejects_centered_equal_2gamma1_minus_beta() {
	// Mirror of the above on the high side.
	let mut coeffs = [MODE2.gamma1; N];
	coeffs[7] = 2 * MODE2.gamma1 - MODE2.beta;
	assert!(
		try_unpack_and_norm(&coeffs).is_err(),
		"centered = 2γ₁ − β must violate the strict norm bound",
	);
}

#[test]
fn norm_rejects_centered_equal_zero() {
	// Largest possible |signed coeff| = γ₁, well outside the bound.
	let mut coeffs = [MODE2.gamma1; N];
	coeffs[1] = 0;
	assert!(try_unpack_and_norm(&coeffs).is_err(), "centered = 0 must violate the norm bound");
}

#[test]
fn norm_rejects_centered_equal_max() {
	let mut coeffs = [MODE2.gamma1; N];
	coeffs[N - 1] = TWO_GAMMA1 - 1;
	assert!(
		try_unpack_and_norm(&coeffs).is_err(),
		"centered = 2γ₁ − 1 must violate the norm bound",
	);
}

// ─── Property-based ─────────────────────────────────────────────────────

fn arb_centered() -> impl Strategy<Value = u32> {
	(0u32..TWO_GAMMA1).boxed()
}

fn arb_in_norm_centered() -> impl Strategy<Value = u32> {
	(MODE2.beta + 1..2 * MODE2.gamma1 - MODE2.beta).boxed()
}

proptest! {
	#![proptest_config(ProptestConfig {
		// Each circuit build + verify of a 256-coefficient polynomial
		// runs in well under a second; keep the case count modest.
		cases: 4,
		.. ProptestConfig::default()
	})]

	#[test]
	fn unpack_matches_native_random(coeffs in proptest::collection::vec(arb_centered(), N..=N)) {
		let arr: [u32; N] = coeffs.try_into().unwrap();
		check_unpack(&arr);
	}

	#[test]
	fn norm_accepts_uniformly_in_bound(
		coeffs in proptest::collection::vec(arb_in_norm_centered(), N..=N),
	) {
		let arr: [u32; N] = coeffs.try_into().unwrap();
		try_unpack_and_norm(&arr).unwrap();
	}
}
