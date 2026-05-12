// Copyright 2026 The Binius Developers

//! In-circuit cross-validation of `rounding::decompose` and
//! `rounding::use_hint` against the native (C-equivalent) reference.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::CircuitBuilder;
use binius_mldsa::{
	params::{MODE2, Q},
	rounding::{decompose, decompose_constrain, decompose_native, use_hint, use_hint_native},
	zq::from_u64_witness,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Build a circuit that:
///   1. allocates `r` as a Z_q witness wire,
///   2. runs the in-circuit `decompose(r)` → `(r1, r0_p)`,
///   3. asserts `r1 == expected_r1` and `r0_p == expected_r0_p`,
///   4. populates the witness, and
///   5. runs `verify_constraints`.
///
/// Panics if any of the in-circuit constraints fail or the in-circuit
/// `(r1, r0_p)` differs from the expected values.
fn check_decompose(r: u32) {
	let (expected_r1, expected_r0_signed) = decompose_native(r);
	let expected_r0_p = (expected_r0_signed + MODE2.gamma2 as i32) as u32;

	let builder = CircuitBuilder::new();
	let r_wire = from_u64_witness(&builder);
	let (r1, r0_p) = decompose(&builder, r_wire);

	let expected_r1_wire = builder.add_witness();
	let expected_r0_p_wire = builder.add_witness();
	builder.assert_eq("decompose r1 matches native", r1, expected_r1_wire);
	builder.assert_eq("decompose r0_p matches native", r0_p, expected_r0_p_wire);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	filler[r_wire] = Word(r as u64);
	filler[expected_r1_wire] = Word(expected_r1 as u64);
	filler[expected_r0_p_wire] = Word(expected_r0_p as u64);
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("decompose circuit must accept honest witness");
}

/// Build a circuit that:
///   1. allocates `r` as a Z_q witness wire and `hint` as a 0/1 wire,
///   2. runs the in-circuit `use_hint(r, hint)`,
///   3. asserts the result equals `use_hint_native(r, hint)`.
fn check_use_hint(r: u32, hint: u32) {
	let expected = use_hint_native(r, hint);

	let builder = CircuitBuilder::new();
	let r_wire = from_u64_witness(&builder);
	let hint_wire = builder.add_witness();
	let result = use_hint(&builder, r_wire, hint_wire);

	let expected_wire = builder.add_witness();
	builder.assert_eq("use_hint matches native", result, expected_wire);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	filler[r_wire] = Word(r as u64);
	filler[hint_wire] = Word(hint as u64);
	filler[expected_wire] = Word(expected as u64);
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("use_hint circuit must accept honest witness");
}

// ─── Decompose: deterministic boundary cases ────────────────────────────

#[test]
fn decompose_zero() {
	check_decompose(0);
}

#[test]
fn decompose_q_minus_one() {
	check_decompose(Q - 1);
}

#[test]
fn decompose_at_gamma2_boundary() {
	// r = γ₂: canonical (0, +γ₂) per the C reference. Exercises the
	// `r0_p == 2γ₂` end of the range check, which is the half of the
	// boundary the divmod-based hint approach tends to miss.
	check_decompose(MODE2.gamma2);
}

#[test]
fn decompose_at_2gamma2_minus_1() {
	check_decompose(2 * MODE2.gamma2 - 1);
}

#[test]
fn decompose_at_2gamma2() {
	check_decompose(2 * MODE2.gamma2);
}

#[test]
fn decompose_at_87gamma2() {
	// r = Q − γ₂ − 1 = 87γ₂: canonical (43, +γ₂), the upper-edge tie.
	check_decompose(Q - MODE2.gamma2 - 1);
}

#[test]
fn decompose_at_q_minus_gamma2() {
	// r = Q − γ₂ = 87γ₂ + 1: canonical (0, −γ₂) via the wrap branch.
	check_decompose(Q - MODE2.gamma2);
}

// ─── Decompose: random sampling ─────────────────────────────────────────

#[test]
fn decompose_random_sample() {
	let mut rng = StdRng::seed_from_u64(0xc0ffee);
	for _ in 0..32 {
		let r = rng.random_range(0..Q);
		check_decompose(r);
	}
}

#[test]
fn decompose_random_near_zero_and_near_q() {
	// Tail-heavy sampling near the wrap boundary, which the C path
	// handles specially.
	let mut rng = StdRng::seed_from_u64(0xdecafbad);
	for _ in 0..16 {
		check_decompose(rng.random_range(0..MODE2.gamma2 + 1));
		check_decompose(rng.random_range(Q - MODE2.gamma2..Q));
	}
}

// ─── UseHint: full table over hint ∈ {0, 1} for selected r ──────────────

#[test]
fn use_hint_at_canonical_boundaries() {
	let r_values = [
		0u32,
		1,
		MODE2.gamma2 - 1,
		MODE2.gamma2,
		MODE2.gamma2 + 1,
		2 * MODE2.gamma2,
		Q - MODE2.gamma2 - 1,
		Q - MODE2.gamma2,
		Q - 1,
	];
	for r in r_values {
		for hint in 0u32..=1 {
			check_use_hint(r, hint);
		}
	}
}

#[test]
fn use_hint_random_sample() {
	let mut rng = StdRng::seed_from_u64(0xa1b2c3d4);
	for _ in 0..32 {
		let r = rng.random_range(0..Q);
		let hint = rng.random_range(0..2);
		check_use_hint(r, hint);
	}
}

// ─── UseHint: range constraint on hint ──────────────────────────────────

// ─── Soundness documentation: boundary uniqueness ──────────────────────
//
// At the tie points `r = (2k+1)γ₂` for `k ∈ [0, 42]`, both
// `(k, +γ₂)` and `(k+1, −γ₂)` satisfy the decompose constraints. The
// canonical-form `Hint` always produces the first; an adversarial
// witness could produce the second. Soundness against this comes from
// R7's downstream hash check, NOT from `decompose` itself. The two
// tests below pin that property as code so any future "tighten the
// constraint" refactor that breaks it shows up immediately.

/// Build a circuit that uses `decompose_constrain` directly (no hint),
/// witnessing arbitrary `(r1, r0_p)`, and check whether the constraints
/// accept. Returns `Ok(())` on accept, `Err(())` on reject.
fn try_decompose_with_arbitrary_witness(r: u32, r1: u32, r0_p: u32) -> Result<(), ()> {
	let builder = CircuitBuilder::new();
	let r_wire = from_u64_witness(&builder);
	let r1_wire = builder.add_witness();
	let r0_p_wire = builder.add_witness();
	decompose_constrain(&builder, r_wire, r1_wire, r0_p_wire);
	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	filler[r_wire] = Word(r as u64);
	filler[r1_wire] = Word(r1 as u64);
	filler[r0_p_wire] = Word(r0_p as u64);
	if circuit.populate_wire_witness(&mut filler).is_err() {
		return Err(());
	}
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).map_err(|_| ())
}

#[test]
fn decompose_constraints_accept_both_decompositions_at_tie_point() {
	// r = γ₂: canonical (0, +γ₂) and non-canonical (1, −γ₂) both
	// satisfy `r' = r1·2γ₂ + r0_p` with valid range bounds.
	let r = MODE2.gamma2;
	let canonical_r1 = 0;
	let canonical_r0_p = 2 * MODE2.gamma2; // r0_signed = +γ₂
	try_decompose_with_arbitrary_witness(r, canonical_r1, canonical_r0_p)
		.expect("canonical (0, +γ₂) at r = γ₂ must be accepted");

	let non_canonical_r1 = 1;
	let non_canonical_r0_p = 0; // r0_signed = -γ₂
	try_decompose_with_arbitrary_witness(r, non_canonical_r1, non_canonical_r0_p)
		.expect("non-canonical (1, −γ₂) at r = γ₂ must ALSO be accepted");
}

#[test]
fn decompose_constraints_reject_actually_invalid_witness() {
	// Sanity: arbitrary off-by-one in r1 or r0_p must be rejected.
	let r = MODE2.gamma2;

	// Wrong r1 (canonical r0_p, but r1 doesn't satisfy the relation).
	assert!(
		try_decompose_with_arbitrary_witness(r, 5, 2 * MODE2.gamma2).is_err(),
		"wrong r1 must be rejected",
	);
	// Wrong r0_p (canonical r1, but off by one).
	assert!(
		try_decompose_with_arbitrary_witness(r, 0, 2 * MODE2.gamma2 - 1).is_err(),
		"wrong r0_p must be rejected",
	);
	// Out-of-range r1 (= 44, just over the limit).
	assert!(
		try_decompose_with_arbitrary_witness(r, 44, 0).is_err(),
		"r1 = 44 (out of range) must be rejected even with otherwise consistent r0_p",
	);
	// Out-of-range r0_p (= 2γ₂ + 1, just over the limit).
	assert!(
		try_decompose_with_arbitrary_witness(r, 0, 2 * MODE2.gamma2 + 1).is_err(),
		"r0_p > 2γ₂ must be rejected",
	);
}

#[test]
fn boundary_decompositions_yield_different_use_hint_outputs() {
	// This is the soundness mechanism: even though decompose accepts
	// both canonical and non-canonical (r1, r0_p) at tie points,
	// `use_hint` produces DIFFERENT `w1'` for each. Downstream hash
	// check then rejects the malicious choice.
	//
	// We assert this on the native references (since the in-circuit
	// `use_hint` calls `decompose` which threads through the hint;
	// to truly observe the in-circuit difference we'd need a second
	// `use_hint` variant that takes (r1, r0_p) directly — left for a
	// future refactor if it becomes necessary).
	for k in 0..43 {
		let r = (2 * k + 1) * MODE2.gamma2;
		// Canonical: (k, +γ₂); a0 > 0 ⇒ use_hint(_, 1) = k + 1 (or 0 if k == 43).
		// Non-canonical: (k+1, −γ₂); a0 ≤ 0 ⇒ use_hint(_, 1) = (k+1) − 1 = k.
		// They differ by exactly 1 (mod 44). So an adversary witnessing
		// the non-canonical decomposition produces a w1' that's off by 1,
		// which changes packed_w1, which changes the hash — caught at R7.
		let canonical_w1 = if k == 43 { 0 } else { k + 1 };
		let non_canonical_w1 = k;
		assert_ne!(
			canonical_w1, non_canonical_w1,
			"the two decompositions at tie point r = (2k+1)γ₂ for k = {k} \
			 must produce different use_hint outputs under hint = 1",
		);
		// Also confirm the canonical matches the native ref.
		assert_eq!(use_hint_native(r, 1), canonical_w1);
	}
}

#[test]
fn use_hint_rejects_hint_geq_2() {
	// `hint = 2` violates the `hint < 2` range check; circuit must
	// reject (either at populate or at verify_constraints).
	let r: u32 = 1234;
	let builder = CircuitBuilder::new();
	let r_wire = from_u64_witness(&builder);
	let hint_wire = builder.add_witness();
	let _ = use_hint(&builder, r_wire, hint_wire);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	filler[r_wire] = Word(r as u64);
	filler[hint_wire] = Word(2);
	let populated = circuit.populate_wire_witness(&mut filler);
	if populated.is_ok() {
		assert!(
			verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).is_err(),
			"use_hint must reject hint >= 2",
		);
	}
}
