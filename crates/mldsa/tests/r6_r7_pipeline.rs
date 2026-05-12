// Copyright 2026 The Binius Developers

//! Cross-cutting integration test for the R6 → R7 hash-input pipeline:
//!
//!   `(wApprox, h, μ)` ──► `decompose_each` ──► `use_hint_each`
//!                          ──► `polyw1_pack` ──► `shake256(μ ‖ packed_w1)`
//!
//! For each random `(wApprox, h, μ)` we compute the expected SHAKE256
//! output natively (composing the per-gadget native references) and
//! verify the in-circuit composition produces the same bytes. This is
//! the highest-value correctness/soundness check we can write today —
//! it catches inter-gadget API drift across the entire pipeline that
//! R7 will eventually wrap up, and it documents that the per-gadget
//! contracts compose cleanly end-to-end.
//!
//! The test runs at K = 1 (one polynomial of `N = 256` coefficients)
//! rather than the production K = 4 to keep the witness/constraint
//! count modest. The K = 4 wrapper is just a parallel composition over
//! the K poly-slot indices and is structurally identical.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	params::{N, Q},
	polyw1::{POLYW1_PACKED_BYTES, polyw1_pack, polyw1_pack_native},
	rounding::{use_hint, use_hint_native},
	shake::shake256,
	zq::from_u64_witness,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha3::{
	Shake256,
	digest::{ExtendableOutput, Update, XofReader},
};

/// μ size in bytes (Dilithium2 R7 input prefix). Keep small — the R7
/// "real" μ is 64 bytes, but for a one-poly K=1 toy pipeline test we
/// can use any size.
const MU_BYTES: usize = 64;
const MU_LANES: usize = MU_BYTES / 8;
/// Hash-input bytes: μ (64 B) + packed_w1 (192 B for K=1) = 256 B.
const HASH_INPUT_BYTES: usize = MU_BYTES + POLYW1_PACKED_BYTES;
const HASH_INPUT_LANES: usize = HASH_INPUT_BYTES / 8;
/// SHAKE output we compare on (32 B = 4 lanes — matches `c̃` in
/// Dilithium2).
const OUT_LANES: usize = 4;

/// End-to-end native reference: `shake256(μ ‖ polyw1_pack(use_hint(decompose(wApprox), h)))`.
fn pipeline_native(
	w_approx: &[u32; N],
	hint: &[u32; N],
	mu: &[u8; MU_BYTES],
) -> [u64; OUT_LANES] {
	let w1: [u32; N] = std::array::from_fn(|i| use_hint_native(w_approx[i], hint[i]));
	let packed = polyw1_pack_native(&w1);
	let mut hash_input = vec![0u8; HASH_INPUT_BYTES];
	hash_input[..MU_BYTES].copy_from_slice(mu);
	hash_input[MU_BYTES..].copy_from_slice(&packed);

	let mut hasher = Shake256::default();
	hasher.update(&hash_input);
	let mut reader = hasher.finalize_xof();
	let mut out_bytes = [0u8; OUT_LANES * 8];
	reader.read(&mut out_bytes);
	std::array::from_fn(|i| {
		let mut w = [0u8; 8];
		w.copy_from_slice(&out_bytes[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(w)
	})
}

/// In-circuit pipeline: build the entire `(wApprox, h, μ) → SHAKE256`
/// chain on top of the gadgets we have, populate witness, run
/// `verify_constraints`, and assert the four output lanes match the
/// native reference computed for the same inputs.
fn check_pipeline(w_approx: &[u32; N], hint: &[u32; N], mu: &[u8; MU_BYTES]) {
	let expected = pipeline_native(w_approx, hint, mu);

	let builder = CircuitBuilder::new();

	// --- Allocate inputs as canonical-Z_q witnesses (wApprox) +
	//     0/1 witnesses (hint) + raw byte-packed lanes (μ).
	let w_approx_wires: [Wire; N] =
		std::array::from_fn(|_| from_u64_witness(&builder));
	let hint_wires: [Wire; N] = std::array::from_fn(|_| builder.add_witness());

	// μ is supplied as 8 little-endian 64-bit lanes (8 bytes each = 64 B).
	let mu_wires: [Wire; MU_LANES] = std::array::from_fn(|_| builder.add_witness());

	// --- R6: per-coefficient use_hint(wApprox[i], hint[i]) → w1[i].
	let w1_wires: [Wire; N] = std::array::from_fn(|i| {
		use_hint(&builder, w_approx_wires[i], hint_wires[i])
	});

	// --- R6 packing: polyw1_pack(w1) → 24 lanes.
	let packed_w1_wires = polyw1_pack(&builder, &w1_wires);

	// --- R7 hash input: concatenate μ (8 lanes) + packed_w1 (24 lanes)
	//     into 32 contiguous lanes. Both are byte-aligned at 64-bit
	//     boundaries so this is a flat slice.
	let mut hash_input_wires: Vec<Wire> = Vec::with_capacity(HASH_INPUT_LANES);
	hash_input_wires.extend(mu_wires.iter().copied());
	hash_input_wires.extend(packed_w1_wires.iter().copied());
	assert_eq!(hash_input_wires.len(), HASH_INPUT_LANES);

	// --- R7 hash: shake256.
	let computed = shake256(&builder, &hash_input_wires, HASH_INPUT_BYTES, OUT_LANES);

	// Assert each output lane matches the native reference.
	let expected_wires: [Wire; OUT_LANES] = std::array::from_fn(|_| builder.add_witness());
	for i in 0..OUT_LANES {
		builder.assert_eq(format!("pipeline shake[{i}]"), computed[i], expected_wires[i]);
	}

	// --- Build, populate, verify.
	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in w_approx_wires.iter().zip(w_approx) {
		filler[*w] = Word(v as u64);
	}
	for (w, &v) in hint_wires.iter().zip(hint) {
		filler[*w] = Word(v as u64);
	}
	for (w, lane_idx) in mu_wires.iter().zip(0..MU_LANES) {
		let mut lane_bytes = [0u8; 8];
		lane_bytes.copy_from_slice(&mu[8 * lane_idx..8 * (lane_idx + 1)]);
		filler[*w] = Word(u64::from_le_bytes(lane_bytes));
	}
	for (w, &v) in expected_wires.iter().zip(&expected) {
		filler[*w] = Word(v);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("R6→R7 pipeline must accept honest witness");
}

// ─── Positive: random + edge-case inputs all match native end-to-end ───

#[test]
fn pipeline_zeros() {
	check_pipeline(&[0u32; N], &[0u32; N], &[0u8; MU_BYTES]);
}

#[test]
fn pipeline_random_with_random_hints() {
	let mut rng = StdRng::seed_from_u64(0x0b1d_6efa);
	let w_approx: [u32; N] = std::array::from_fn(|_| rng.random_range(0..Q));
	let hint: [u32; N] = std::array::from_fn(|_| rng.random_range(0..2));
	let mu: [u8; MU_BYTES] = std::array::from_fn(|_| rng.random());
	check_pipeline(&w_approx, &hint, &mu);
}

#[test]
fn pipeline_all_hints_set() {
	// Stress the `r0 > 0 ? +1 : −1` path by forcing every hint = 1.
	let mut rng = StdRng::seed_from_u64(0xa11_5e7);
	let w_approx: [u32; N] = std::array::from_fn(|_| rng.random_range(0..Q));
	let hint = [1u32; N];
	let mu: [u8; MU_BYTES] = std::array::from_fn(|_| rng.random());
	check_pipeline(&w_approx, &hint, &mu);
}

#[test]
fn pipeline_inputs_at_decompose_boundaries() {
	// w_approx values that hit the decompose boundary cases (a tie
	// point and the wrap edge), spread across the polynomial. Catches
	// any boundary-handling bug in the composition.
	let mut w_approx = [0u32; N];
	let gamma2 = binius_mldsa::params::MODE2.gamma2;
	for i in 0..N {
		w_approx[i] = match i % 5 {
			0 => 0,
			1 => gamma2,                    // r = γ₂ → (0, +γ₂)
			2 => 2 * gamma2,                // r = 2γ₂ → (1, 0)
			3 => Q - gamma2,                // wrap: (0, −γ₂)
			_ => Q - 1,                     // (0, −1)
		};
	}
	let hint = [1u32; N];
	let mu = [0u8; MU_BYTES];
	check_pipeline(&w_approx, &hint, &mu);
}

// ─── Soundness: tamper rejection across the pipeline ───────────────────

#[test]
fn pipeline_rejects_tampered_hint() {
	// Honest witness for everything except hint[0], which is flipped.
	// The flip changes w1'[0], which changes packed_w1's first byte,
	// which changes the SHAKE output. The expected lanes are computed
	// from the *honest* hint, so the in-circuit shake won't match.
	// The circuit must reject.
	let mut rng = StdRng::seed_from_u64(0xfa11);
	let w_approx: [u32; N] = std::array::from_fn(|_| rng.random_range(0..Q));
	let hint: [u32; N] = std::array::from_fn(|_| rng.random_range(0..2));
	let mu: [u8; MU_BYTES] = std::array::from_fn(|_| rng.random());

	let expected = pipeline_native(&w_approx, &hint, &mu);

	let builder = CircuitBuilder::new();
	let w_approx_wires: [Wire; N] =
		std::array::from_fn(|_| from_u64_witness(&builder));
	let hint_wires: [Wire; N] = std::array::from_fn(|_| builder.add_witness());
	let mu_wires: [Wire; MU_LANES] = std::array::from_fn(|_| builder.add_witness());
	let w1_wires: [Wire; N] = std::array::from_fn(|i| {
		use_hint(&builder, w_approx_wires[i], hint_wires[i])
	});
	let packed_w1_wires = polyw1_pack(&builder, &w1_wires);
	let mut hash_input_wires: Vec<Wire> = Vec::with_capacity(HASH_INPUT_LANES);
	hash_input_wires.extend(mu_wires.iter().copied());
	hash_input_wires.extend(packed_w1_wires.iter().copied());
	let computed = shake256(&builder, &hash_input_wires, HASH_INPUT_BYTES, OUT_LANES);
	let expected_wires: [Wire; OUT_LANES] = std::array::from_fn(|_| builder.add_witness());
	for i in 0..OUT_LANES {
		builder.assert_eq(format!("pipeline shake[{i}]"), computed[i], expected_wires[i]);
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in w_approx_wires.iter().zip(&w_approx) {
		filler[*w] = Word(v as u64);
	}
	// Tamper: flip hint[0] from honest value.
	let mut tampered_hint = hint;
	tampered_hint[0] = 1 - tampered_hint[0];
	for (w, &v) in hint_wires.iter().zip(&tampered_hint) {
		filler[*w] = Word(v as u64);
	}
	for (w, lane_idx) in mu_wires.iter().zip(0..MU_LANES) {
		let mut lane_bytes = [0u8; 8];
		lane_bytes.copy_from_slice(&mu[8 * lane_idx..8 * (lane_idx + 1)]);
		filler[*w] = Word(u64::from_le_bytes(lane_bytes));
	}
	for (w, &v) in expected_wires.iter().zip(&expected) {
		filler[*w] = Word(v);
	}
	let populated = circuit.populate_wire_witness(&mut filler);
	if populated.is_ok() {
		assert!(
			verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).is_err(),
			"pipeline must reject tampered hint",
		);
	}
}
