// Copyright 2026 The Binius Developers

//! Cross-validation of the in-circuit `Z_q` field gadgets against the
//! native `u64` reference implementation.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	params::Q,
	zq::{add, add_native, from_u64_witness, mul, mul_native, sub, sub_native},
};
use proptest::prelude::*;

/// Builds a circuit that constrains `expected = op(a, b)` for the given
/// in-circuit binary operation `op`, populates the witness with `(a, b,
/// expected)`, and runs `verify_constraints`. Panics if the constraint
/// system is unsatisfied.
fn check_binop<F>(op: F, a: u32, b: u32, expected: u32)
where
	F: Fn(&CircuitBuilder, Wire, Wire) -> Wire,
{
	assert!(a < Q && b < Q && expected < Q);

	let builder = CircuitBuilder::new();
	let a_w = from_u64_witness(&builder);
	let b_w = from_u64_witness(&builder);
	let exp_w = from_u64_witness(&builder);
	let result = op(&builder, a_w, b_w);
	builder.assert_eq("expected == result", result, exp_w);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	filler[a_w] = Word(a as u64);
	filler[b_w] = Word(b as u64);
	filler[exp_w] = Word(expected as u64);

	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("zq op constraints must be satisfied for the honest witness");
}

/// Builds a circuit that constrains `expected = op(a, b)` and asserts the
/// system **rejects** the witness — used to confirm the gadget is not
/// silently accepting a wrong claim.
fn check_binop_rejects<F>(op: F, a: u32, b: u32, wrong_expected: u32)
where
	F: Fn(&CircuitBuilder, Wire, Wire) -> Wire,
{
	assert!(a < Q && b < Q && wrong_expected < Q);

	let builder = CircuitBuilder::new();
	let a_w = from_u64_witness(&builder);
	let b_w = from_u64_witness(&builder);
	let exp_w = from_u64_witness(&builder);
	let result = op(&builder, a_w, b_w);
	builder.assert_eq("expected == result", result, exp_w);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	filler[a_w] = Word(a as u64);
	filler[b_w] = Word(b as u64);
	filler[exp_w] = Word(wrong_expected as u64);

	// `populate_wire_witness` may itself flag the inconsistency, but the
	// authoritative check is `verify_constraints`. Either is an
	// acceptable rejection; an honest accept would be a soundness break.
	let populated = circuit.populate_wire_witness(&mut filler);
	if populated.is_ok() {
		assert!(
			verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).is_err(),
			"zq gadget accepted wrong witness for ({a}, {b}) -> {wrong_expected}",
		);
	}
}

// ─── Edge cases (deterministic) ─────────────────────────────────────────

#[test]
fn add_edge_cases() {
	for (a, b) in [
		(0, 0),
		(0, Q - 1),
		(Q - 1, 0),
		(Q - 1, Q - 1),       // 2(Q-1) requires the conditional sub
		(1, Q - 1),           // wraps to 0
		(Q / 2, Q / 2 + 1),   // sum exactly Q (boundary)
		(Q / 3, 2 * Q / 3),
	] {
		check_binop(add, a, b, add_native(a, b));
	}
}

#[test]
fn sub_edge_cases() {
	for (a, b) in [
		(0, 0),
		(Q - 1, Q - 1),
		(0, Q - 1),     // wraps via +Q
		(Q - 1, 0),
		(5, 7),
		(Q / 2, Q / 2 + 1),
	] {
		check_binop(sub, a, b, sub_native(a, b));
	}
}

#[test]
fn mul_edge_cases() {
	for (a, b) in [
		(0, 0),
		(0, Q - 1),
		(Q - 1, 0),
		(1, Q - 1),
		(Q - 1, Q - 1),       // largest possible product
		(2, Q.div_ceil(2)),   // 2 * ceil(Q/2) = Q + 1 ≡ 1
		(12345, 67890),
	] {
		check_binop(mul, a, b, mul_native(a, b));
	}
}

#[test]
fn add_rejects_off_by_one() {
	let a = 12345;
	let b = 67890;
	let correct = add_native(a, b);
	check_binop_rejects(add, a, b, correct.wrapping_add(1) % Q);
}

#[test]
fn sub_rejects_off_by_one() {
	let a = 12345;
	let b = 67890;
	let correct = sub_native(a, b);
	check_binop_rejects(sub, a, b, (correct + 1) % Q);
}

#[test]
fn mul_rejects_off_by_one() {
	let a = 12345;
	let b = 67890;
	let correct = mul_native(a, b);
	check_binop_rejects(mul, a, b, (correct + 1) % Q);
}

// ─── Property-based ─────────────────────────────────────────────────────

fn arb_zq() -> impl Strategy<Value = u32> {
	(0u32..Q).boxed()
}

proptest! {
	#![proptest_config(ProptestConfig {
		// Each circuit build + verify is a few ms; keep the case count
		// small enough to run in well under a second per gadget.
		cases: 16,
		.. ProptestConfig::default()
	})]

	#[test]
	fn add_matches_native(a in arb_zq(), b in arb_zq()) {
		check_binop(add, a, b, add_native(a, b));
	}

	#[test]
	fn sub_matches_native(a in arb_zq(), b in arb_zq()) {
		check_binop(sub, a, b, sub_native(a, b));
	}

	#[test]
	fn mul_matches_native(a in arb_zq(), b in arb_zq()) {
		check_binop(mul, a, b, mul_native(a, b));
	}
}

// ─── from_u64_witness range check ───────────────────────────────────────

#[test]
fn from_u64_witness_rejects_out_of_range() {
	let builder = CircuitBuilder::new();
	let w = from_u64_witness(&builder);
	let circuit = builder.build();

	for bad in [Q, Q + 1, u32::MAX, ((1u64 << 32) - 1) as u32] {
		let mut filler = circuit.new_witness_filler();
		filler[w] = Word(bad as u64);
		let populated = circuit.populate_wire_witness(&mut filler);
		if populated.is_ok() {
			assert!(
				verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).is_err(),
				"from_u64_witness accepted out-of-range value {bad} (>= Q={Q})",
			);
		}
	}
}

#[test]
fn from_u64_witness_accepts_in_range() {
	let builder = CircuitBuilder::new();
	let w = from_u64_witness(&builder);
	let circuit = builder.build();

	for good in [0u32, 1, Q / 2, Q - 1] {
		let mut filler = circuit.new_witness_filler();
		filler[w] = Word(good as u64);
		circuit.populate_wire_witness(&mut filler).unwrap();
		verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
			.expect("from_u64_witness must accept in-range value");
	}
}
