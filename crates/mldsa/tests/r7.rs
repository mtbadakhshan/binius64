// Copyright 2026 The Binius Developers

//! Full R7 binding-equality circuit at production K = 4 dimensions:
//! `c̃ == SHAKE256(μ ‖ PackW1(w₁'))`.
//!
//! This is the strongest soundness battery so far in `binius-mldsa`:
//! tamper rejection across each of the four R7 inputs (`c̃`, `wApprox`,
//! `hint`, `μ`). Each test:
//!
//! 1. Generates a random honest `(wApprox, hint, μ)` for K = 4.
//! 2. Computes the honest `c̃` natively (via `r7_native`).
//! 3. Builds the in-circuit R7 subcircuit (via `assert_r7`).
//! 4. Either asserts the honest witness is accepted, or tampers one
//!    input and asserts the witness is rejected.
//!
//! The K = 4 circuit emits ≈ 1024 `use_hint` invocations + 96-lane
//! `polyw1_pack` + a 7-permutation SHAKE256(832 B input, 32 B output)
//! plus the 4-lane equality check. Each test builds and verifies in
//! ≈ 100 ms.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	params::{MODE2, N, Q},
	polyw1::{POLYW1_PACKED_BYTES, polyw1_pack_native},
	r7::{
		C_TILDE_LANES, HASH_INPUT_BYTES, MU_BYTES, MU_LANES, assert_r7,
	},
	rounding::use_hint_native,
	zq::from_u64_witness,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha3::{
	Shake256,
	digest::{ExtendableOutput, Update, XofReader},
};

const K: usize = MODE2.k;

/// Native end-to-end R7: given `wApprox`, `hint`, and `μ`, compute the
/// expected `c̃` lanes that an honest signer would have produced.
fn r7_native(
	w_approx: &[[u32; N]; K],
	hint: &[[u32; N]; K],
	mu: &[u8; MU_BYTES],
) -> [u64; C_TILDE_LANES] {
	let mut hash_input = vec![0u8; HASH_INPUT_BYTES];
	hash_input[..MU_BYTES].copy_from_slice(mu);
	for k in 0..K {
		let w1: [u32; N] =
			std::array::from_fn(|i| use_hint_native(w_approx[k][i], hint[k][i]));
		let packed = polyw1_pack_native(&w1);
		let off = MU_BYTES + k * POLYW1_PACKED_BYTES;
		hash_input[off..off + POLYW1_PACKED_BYTES].copy_from_slice(&packed);
	}

	let mut hasher = Shake256::default();
	hasher.update(&hash_input);
	let mut reader = hasher.finalize_xof();
	let mut out_bytes = [0u8; C_TILDE_LANES * 8];
	reader.read(&mut out_bytes);
	std::array::from_fn(|i| {
		let mut w = [0u8; 8];
		w.copy_from_slice(&out_bytes[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(w)
	})
}

/// Pack a 64-byte μ into 8 LE 64-bit lanes.
fn mu_to_lanes(mu: &[u8; MU_BYTES]) -> [u64; MU_LANES] {
	std::array::from_fn(|i| {
		let mut w = [0u8; 8];
		w.copy_from_slice(&mu[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(w)
	})
}

/// Build the full R7 circuit, populate it with the supplied
/// `(wApprox, hint, μ, c̃)` witness, run `verify_constraints`, and
/// return whether the constraints accept (`Ok`) or reject (`Err`).
///
/// The `c̃` parameter is the *witnessed* value — if the test passes
/// the honest c̃ here, the circuit should accept; if it passes a
/// tampered c̃, the circuit should reject.
fn run_r7(
	w_approx: &[[u32; N]; K],
	hint: &[[u32; N]; K],
	mu: &[u8; MU_BYTES],
	c_tilde: &[u64; C_TILDE_LANES],
) -> Result<(), ()> {
	let builder = CircuitBuilder::new();

	// All inputs are caller-supplied wires; tests simulate them with
	// witness wires.
	let w_approx_wires: [[Wire; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| from_u64_witness(&builder)));
	let hint_wires: [[Wire; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| builder.add_witness()));
	let mu_wires: [Wire; MU_LANES] = std::array::from_fn(|_| builder.add_witness());
	let c_tilde_wires: [Wire; C_TILDE_LANES] =
		std::array::from_fn(|_| builder.add_witness());

	assert_r7(&builder, &w_approx_wires, &hint_wires, &mu_wires, &c_tilde_wires);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for k in 0..K {
		for i in 0..N {
			filler[w_approx_wires[k][i]] = Word(w_approx[k][i] as u64);
			filler[hint_wires[k][i]] = Word(hint[k][i] as u64);
		}
	}
	let mu_lanes = mu_to_lanes(mu);
	for (w, &v) in mu_wires.iter().zip(&mu_lanes) {
		filler[*w] = Word(v);
	}
	for (w, &v) in c_tilde_wires.iter().zip(c_tilde) {
		filler[*w] = Word(v);
	}

	if circuit.populate_wire_witness(&mut filler).is_err() {
		return Err(());
	}
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).map_err(|_| ())
}

/// Generate a deterministic random honest `(wApprox, hint, μ)`.
fn random_honest_witness(seed: u64) -> ([[u32; N]; K], [[u32; N]; K], [u8; MU_BYTES]) {
	let mut rng = StdRng::seed_from_u64(seed);
	let w_approx: [[u32; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| rng.random_range(0..Q)));
	let hint: [[u32; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| rng.random_range(0..2)));
	let mu: [u8; MU_BYTES] = std::array::from_fn(|_| rng.random());
	(w_approx, hint, mu)
}

// ─── Positive: honest witness is accepted ───────────────────────────────

#[test]
fn r7_accepts_honest_random_zero() {
	let (w_approx, hint, mu) = random_honest_witness(0);
	let c_tilde = r7_native(&w_approx, &hint, &mu);
	run_r7(&w_approx, &hint, &mu, &c_tilde).expect("honest R7 must be accepted");
}

#[test]
fn r7_accepts_honest_random_seed_1() {
	let (w_approx, hint, mu) = random_honest_witness(1);
	let c_tilde = r7_native(&w_approx, &hint, &mu);
	run_r7(&w_approx, &hint, &mu, &c_tilde).expect("honest R7 must be accepted");
}

#[test]
fn r7_accepts_zero_inputs() {
	// All-zero (wApprox, hint, μ) is a valid (if degenerate) R7 input;
	// makes sure the circuit doesn't have a zero-input fast path that
	// short-circuits the binding equality.
	let w_approx = [[0u32; N]; K];
	let hint = [[0u32; N]; K];
	let mu = [0u8; MU_BYTES];
	let c_tilde = r7_native(&w_approx, &hint, &mu);
	run_r7(&w_approx, &hint, &mu, &c_tilde).expect("zero-input R7 must be accepted");
}

#[test]
fn r7_accepts_inputs_at_decompose_boundaries() {
	// `wApprox` at canonical decompose boundary points, hint set to 1
	// everywhere — exercises the use_hint wrap branches across the
	// full polyvec, then composes through to the hash.
	let mut w_approx = [[0u32; N]; K];
	let gamma2 = MODE2.gamma2;
	for k in 0..K {
		for i in 0..N {
			w_approx[k][i] = match (k * N + i) % 5 {
				0 => 0,
				1 => gamma2,
				2 => 2 * gamma2,
				3 => Q - gamma2,
				_ => Q - 1,
			};
		}
	}
	let hint = [[1u32; N]; K];
	let mu = [0u8; MU_BYTES];
	let c_tilde = r7_native(&w_approx, &hint, &mu);
	run_r7(&w_approx, &hint, &mu, &c_tilde)
		.expect("decompose-boundary R7 must be accepted");
}

// ─── Tamper rejection: each input flipped, R7 must reject ──────────────

#[test]
fn r7_rejects_tampered_c_tilde() {
	// Honest everything; just flip one bit of c̃. R7 binding equality
	// must reject.
	let (w_approx, hint, mu) = random_honest_witness(2);
	let mut c_tilde = r7_native(&w_approx, &hint, &mu);
	c_tilde[0] ^= 1;
	assert!(
		run_r7(&w_approx, &hint, &mu, &c_tilde).is_err(),
		"R7 must reject tampered c̃",
	);
}

#[test]
fn r7_accepts_w_approx_perturbed_within_hint_slack() {
	// ML-DSA's whole point: `use_hint(r, h)` depends on `r` only
	// through `(a1, sign(a0))` from `decompose(r)`. Two different `r`
	// values that decompose to the same (a1, sign(a0)) produce the
	// SAME `w₁'`, hence the same packed_w1, hence the same hash, hence
	// the same `c̃`. This is by design — it's why the hint mechanism
	// exists, and it's the prover-verifier agreement margin that lets
	// ML-DSA be secure with non-determinism in the signing protocol.
	//
	// This test pins that property: we deliberately perturb wApprox by
	// an amount that does NOT change the use_hint output, and confirm
	// R7 still accepts. A future bug that makes R7 over-strict (e.g. by
	// constraining the actual wApprox bits rather than just w₁') would
	// fail this test.
	let (w_approx, hint, mu) = random_honest_witness(3);
	let honest_c_tilde = r7_native(&w_approx, &hint, &mu);

	let mut perturbed = w_approx;
	let original_w1 = use_hint_native(w_approx[0][0], hint[0][0]);
	let mut try_value = (w_approx[0][0] + 1) % Q;
	while use_hint_native(try_value, hint[0][0]) != original_w1 || try_value == w_approx[0][0]
	{
		try_value = (try_value + 1) % Q;
	}
	perturbed[0][0] = try_value;
	assert_ne!(perturbed[0][0], w_approx[0][0], "must actually have perturbed");

	run_r7(&perturbed, &hint, &mu, &honest_c_tilde).expect(
		"R7 must accept wApprox perturbations within the hint slack — this is the whole \
		 point of ML-DSA hints, not a soundness bug",
	);
}

#[test]
fn r7_rejects_w_approx_perturbed_outside_hint_slack() {
	// Counterpart to the above: perturb wApprox by an amount that
	// DOES change the use_hint output. R7 must reject because the
	// resulting w₁' (and hence the hash) differs from the honest one.
	let (mut w_approx, hint, mu) = random_honest_witness(3);
	let honest_c_tilde = r7_native(&w_approx, &hint, &mu);

	let original_w1 = use_hint_native(w_approx[0][0], hint[0][0]);
	let mut try_value = (w_approx[0][0] + 1) % Q;
	while use_hint_native(try_value, hint[0][0]) == original_w1 {
		try_value = (try_value + 1) % Q;
	}
	w_approx[0][0] = try_value;
	assert_ne!(use_hint_native(try_value, hint[0][0]), original_w1);

	assert!(
		run_r7(&w_approx, &hint, &mu, &honest_c_tilde).is_err(),
		"R7 must reject wApprox tampers that change use_hint output",
	);
}

#[test]
fn r7_rejects_tampered_hint() {
	let (w_approx, mut hint, mu) = random_honest_witness(4);
	let honest_c_tilde = r7_native(&w_approx, &hint, &mu);
	hint[0][0] = 1 - hint[0][0];
	assert!(
		run_r7(&w_approx, &hint, &mu, &honest_c_tilde).is_err(),
		"R7 must reject tampered hint",
	);
}

#[test]
fn r7_rejects_tampered_mu() {
	let (w_approx, hint, mut mu) = random_honest_witness(5);
	let honest_c_tilde = r7_native(&w_approx, &hint, &mu);
	mu[0] ^= 0x55;
	assert!(
		run_r7(&w_approx, &hint, &mu, &honest_c_tilde).is_err(),
		"R7 must reject tampered μ",
	);
}

// ─── Tamper rejection at the polyvec interior ──────────────────────────
//
// The above four tests all tamper at index `[0][0]` — i.e. the very
// first coefficient of the very first polynomial. The tests below
// tamper deeper into the polyvec to confirm the rejection comes from
// the actual mismatch (not, say, from a buggy "only check the first
// few wires" bug somewhere).

#[test]
fn r7_rejects_w_approx_perturbed_outside_hint_slack_at_polyvec_interior() {
	// Same property as above, but tampering at the very last polyvec
	// slot — confirms the rejection comes from the actual mismatch
	// (not, say, from a buggy "only check the first few wires" bug
	// somewhere). Like the per-position polyz isolation test.
	let (mut w_approx, hint, mu) = random_honest_witness(6);
	let honest_c_tilde = r7_native(&w_approx, &hint, &mu);

	let last_k = K - 1;
	let last_i = N - 1;
	let original_w1 = use_hint_native(w_approx[last_k][last_i], hint[last_k][last_i]);
	let mut try_value = (w_approx[last_k][last_i] + 1) % Q;
	while use_hint_native(try_value, hint[last_k][last_i]) == original_w1 {
		try_value = (try_value + 1) % Q;
	}
	w_approx[last_k][last_i] = try_value;

	assert!(
		run_r7(&w_approx, &hint, &mu, &honest_c_tilde).is_err(),
		"R7 must reject wApprox tampering at the very last polyvec slot",
	);
}

#[test]
fn r7_rejects_tampered_hint_at_polyvec_interior() {
	let (w_approx, mut hint, mu) = random_honest_witness(7);
	let honest_c_tilde = r7_native(&w_approx, &hint, &mu);
	hint[K / 2][N / 2] = 1 - hint[K / 2][N / 2];
	assert!(
		run_r7(&w_approx, &hint, &mu, &honest_c_tilde).is_err(),
		"R7 must reject tampered hint at the polyvec midpoint",
	);
}

// ─── Range-check coverage ──────────────────────────────────────────────

#[test]
fn r7_rejects_hint_geq_2() {
	// hint must be 0 or 1 — this is enforced inside `use_hint`, not
	// at the R7 layer. Confirms the cascade.
	let (w_approx, mut hint, mu) = random_honest_witness(8);
	let honest_c_tilde = r7_native(&w_approx, &hint, &mu);
	hint[0][0] = 2;
	assert!(
		run_r7(&w_approx, &hint, &mu, &honest_c_tilde).is_err(),
		"R7 must reject hint = 2 (caught by use_hint's range check)",
	);
}
