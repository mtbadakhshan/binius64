// Copyright 2026 The Binius Developers

//! End-to-end Phase 1 verifier integration tests for `MlDsaVerifier`.
//!
//! Each test:
//!
//!   1. Generates a random honest `(z, hint, w_approx, μ)` for
//!      Dilithium2 (with `z` strictly inside the norm bound).
//!   2. Computes the *expected* `c̃` natively as
//!      `SHAKE256(μ ‖ PackW1(use_hint(w_approx, hint)))` (this is what
//!      the off-circuit "signer" would have produced under R7).
//!   3. Packs the synthetic signature
//!      `σ = (c̃, z, h_zeros)` into the 2420-byte byte stream.
//!   4. Allocates the 4 input slices (sig, μ, w_approx, hint) as
//!      witness wires, builds the `MlDsaVerifier` circuit, populates,
//!      and runs `verify_constraints`.
//!
//! For the **honest** case we assert the circuit accepts. For the
//! **tamper** cases we mutate exactly one input, leave the rest honest,
//! and assert the circuit rejects.
//!
//! ## What this validates end-to-end
//!
//! - `unpack_c_tilde` slices the right 4 lanes out of the signature.
//! - `unpack_z` extracts the right 4 polynomials.
//! - `assert_norm_centered` enforces `‖z‖ < γ₁ − β` per coefficient.
//! - `assert_r7` chains `use_hint_polyvec` → `pack_w1_polyvec` →
//!   `shake256(μ ‖ packed)` → `assert_eq` against `c̃` extracted from the
//!   signature.
//! - All Phase 1-bridged inputs (μ, wApprox, hint) are wired through
//!   the full chain and tampering any of them is caught.
//!
//! ## What this does NOT validate (Phase 2 work)
//!
//! - The `wApprox <-> z` binding (R5 lattice arithmetic).
//! - The `c <-> c̃` binding (R3 SampleInBall + R5 ring multiplication).
//! - The `h_bytes <-> hint` binding (R1 unpack_h variable-length parser).
//!
//! The Phase 1 verifier is "trust-the-hoisted-inputs"; the tests here
//! pin that whatever IS in-circuit (R1 sigDecode-of-c̃-and-z, the norm
//! check, and the full R7 cascade) catches the corresponding tampers.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	params::{MODE2, N, Q},
	polyw1::polyw1_pack_native,
	r7::{MU_BYTES, MU_LANES},
	rounding::use_hint_native,
	sigdecode::{
		SIG_C_TILDE_BYTES, SIG_PACKED_BYTES, SIG_PACKED_LANES, pack_signature_native,
		signature_to_lanes,
	},
	verifier::MlDsaVerifier,
	zq::from_u64_witness,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha3::{
	Shake256,
	digest::{ExtendableOutput, Update, XofReader},
};

const L: usize = MODE2.l;
const K: usize = MODE2.k;

/// Fully-specified synthetic Phase 1 verifier witness — the four
/// inputs the in-circuit verifier consumes plus the signature byte
/// stream those inputs encode.
struct Phase1Witness {
	/// Packed 2420-byte signature, derived from `c_tilde + z_centered`.
	sig_lanes: [u64; SIG_PACKED_LANES],
	/// μ (8 lanes = 64 bytes), public input.
	mu: [u8; MU_BYTES],
	/// wApprox (K = 4 polynomials), public input.
	w_approx: [[u32; N]; K],
	/// hint (K = 4 polynomials of 0/1), public input.
	hint: [[u32; N]; K],
}

/// Native end-to-end derivation of an honest Phase 1 witness from
/// random `(z, hint, w_approx, μ)`. The signer's `c̃` is computed via
/// the same R7 native pipeline the in-circuit `assert_r7` runs.
fn build_honest_witness(seed: u64) -> Phase1Witness {
	let mut rng = StdRng::seed_from_u64(seed);

	// z: random centered values strictly inside the norm bound
	// `(β, 2γ₁ − β)`. Same range our `assert_norm_centered` accepts.
	let z_centered: [[u32; N]; L] = std::array::from_fn(|_| {
		std::array::from_fn(|_| rng.random_range(MODE2.beta + 1..2 * MODE2.gamma1 - MODE2.beta))
	});

	// w_approx, hint, μ: random.
	let w_approx: [[u32; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| rng.random_range(0..Q)));
	let hint: [[u32; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| rng.random_range(0..2)));
	let mu: [u8; MU_BYTES] = std::array::from_fn(|_| rng.random());

	// c̃ = R7's native output — the only honest c̃ that satisfies the
	// in-circuit R7 binding.
	let c_tilde = r7_native(&w_approx, &hint, &mu);

	// Pack σ = (c̃, z, h_zeros) into the 2420-byte byte stream the
	// verifier consumes. The `h` section is left zero (it doesn't get
	// parsed in Phase 1 — `hint` is supplied as separate witness).
	let packed = pack_signature_native(&c_tilde, &z_centered);
	let sig_lanes = signature_to_lanes(&packed);

	Phase1Witness { sig_lanes, mu, w_approx, hint }
}

/// Native R7 reference (lifted out of `tests/r7.rs` so this file is
/// self-contained).
fn r7_native(
	w_approx: &[[u32; N]; K],
	hint: &[[u32; N]; K],
	mu: &[u8; MU_BYTES],
) -> [u8; SIG_C_TILDE_BYTES] {
	use binius_mldsa::polyw1::POLYW1_PACKED_BYTES;

	const HASH_INPUT_BYTES: usize = MU_BYTES + K * POLYW1_PACKED_BYTES;
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
	let mut out = [0u8; SIG_C_TILDE_BYTES];
	reader.read(&mut out);
	out
}

/// Build the Phase 1 verifier circuit, populate the witness, and
/// return whether `verify_constraints` accepts (`Ok(())`) or rejects.
fn run_verifier(w: &Phase1Witness) -> Result<(), ()> {
	let builder = CircuitBuilder::new();

	let sig_wires: [Wire; SIG_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let mu_wires: [Wire; MU_LANES] = std::array::from_fn(|_| builder.add_witness());
	let w_approx_wires: [[Wire; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| from_u64_witness(&builder)));
	let hint_wires: [[Wire; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| builder.add_witness()));

	let _verifier =
		MlDsaVerifier::new(&builder, &sig_wires, &mu_wires, &w_approx_wires, &hint_wires);

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (wire, &v) in sig_wires.iter().zip(&w.sig_lanes) {
		filler[*wire] = Word(v);
	}
	let mu_lanes: [u64; MU_LANES] = std::array::from_fn(|i| {
		let mut bytes = [0u8; 8];
		bytes.copy_from_slice(&w.mu[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(bytes)
	});
	for (wire, &v) in mu_wires.iter().zip(&mu_lanes) {
		filler[*wire] = Word(v);
	}
	for k in 0..K {
		for i in 0..N {
			filler[w_approx_wires[k][i]] = Word(w.w_approx[k][i] as u64);
			filler[hint_wires[k][i]] = Word(w.hint[k][i] as u64);
		}
	}
	if circuit.populate_wire_witness(&mut filler).is_err() {
		return Err(());
	}
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).map_err(|_| ())
}

/// Mutate one byte of the `c̃` section of the packed signature and
/// re-derive the lanes. Used by tamper tests.
fn flip_sig_byte(sig_lanes: &mut [u64; SIG_PACKED_LANES], byte_offset: usize) {
	assert!(byte_offset < SIG_PACKED_BYTES);
	let lane_idx = byte_offset / 8;
	let bit = (byte_offset % 8) * 8;
	sig_lanes[lane_idx] ^= 1u64 << bit;
}

// ─── Honest acceptance ──────────────────────────────────────────────────

#[test]
fn phase1_verifier_accepts_honest_synthetic_signature() {
	let w = build_honest_witness(0);
	run_verifier(&w).expect("honest synthetic Phase 1 witness must verify");
}

#[test]
fn phase1_verifier_accepts_multiple_seeds() {
	for seed in 1..4 {
		let w = build_honest_witness(seed);
		run_verifier(&w)
			.unwrap_or_else(|_| panic!("seed {seed} honest witness must verify"));
	}
}

// ─── Tamper rejection — c̃ section of the signature ────────────────────

#[test]
fn phase1_verifier_rejects_tampered_c_tilde_byte() {
	// Flip one byte of c̃ inside the signature. unpack_c_tilde extracts
	// the tampered c̃; assert_r7 computes the honest c̃ from
	// (μ, wApprox, hint) and the equality fails.
	let mut w = build_honest_witness(10);
	flip_sig_byte(&mut w.sig_lanes, 7); // byte 7 of c̃
	assert!(
		run_verifier(&w).is_err(),
		"Phase 1 verifier must reject c̃ tampering",
	);
}

// ─── Tamper rejection — z section (out-of-norm) ────────────────────────

#[test]
fn phase1_verifier_rejects_z_out_of_norm() {
	// Flip the high bit of one z byte to push the centered value out of
	// the (β, 2γ₁ − β) range that `assert_norm_centered` accepts.
	// Specifically: z's first coefficient occupies bytes [32, 35) of the
	// signature; setting byte 32 to 0x00 and the next bits to 0 gives
	// centered = 0, which violates the strict `centered > β` check.
	let mut w = build_honest_witness(11);
	let z_first_lane = 4; // z section begins at byte 32 = lane 4
	w.sig_lanes[z_first_lane] = 0; // every centered coeff in this lane = 0
	assert!(
		run_verifier(&w).is_err(),
		"Phase 1 verifier must reject out-of-norm z (centered = 0 violates β < centered)",
	);
}

// ─── Tamper rejection — hoisted inputs (μ, wApprox, hint) ───────────────

#[test]
fn phase1_verifier_rejects_tampered_mu() {
	let mut w = build_honest_witness(12);
	w.mu[0] ^= 0x55;
	assert!(
		run_verifier(&w).is_err(),
		"Phase 1 verifier must reject tampered μ (R7 binding fails)",
	);
}

#[test]
fn phase1_verifier_rejects_tampered_w_approx() {
	// Pick a w_approx tamper that's guaranteed to change use_hint
	// output (otherwise R7 deliberately accepts; see the
	// `r7_accepts_w_approx_perturbed_within_hint_slack` test in
	// `tests/r7.rs`).
	let mut w = build_honest_witness(13);
	let original_w1 = use_hint_native(w.w_approx[0][0], w.hint[0][0]);
	let mut try_value = (w.w_approx[0][0] + 1) % Q;
	while use_hint_native(try_value, w.hint[0][0]) == original_w1 {
		try_value = (try_value + 1) % Q;
	}
	w.w_approx[0][0] = try_value;
	assert!(
		run_verifier(&w).is_err(),
		"Phase 1 verifier must reject wApprox tamper that changes use_hint output",
	);
}

#[test]
fn phase1_verifier_rejects_tampered_hint() {
	let mut w = build_honest_witness(14);
	w.hint[0][0] ^= 1;
	assert!(
		run_verifier(&w).is_err(),
		"Phase 1 verifier must reject tampered hint",
	);
}

// ─── Tamper rejection — deep interior positions ────────────────────────

#[test]
fn phase1_verifier_rejects_tampered_w_approx_at_deep_interior() {
	let mut w = build_honest_witness(15);
	let last_k = K - 1;
	let last_i = N - 1;
	let original_w1 = use_hint_native(w.w_approx[last_k][last_i], w.hint[last_k][last_i]);
	let mut try_value = (w.w_approx[last_k][last_i] + 1) % Q;
	while use_hint_native(try_value, w.hint[last_k][last_i]) == original_w1 {
		try_value = (try_value + 1) % Q;
	}
	w.w_approx[last_k][last_i] = try_value;
	assert!(
		run_verifier(&w).is_err(),
		"Phase 1 verifier must reject wApprox tamper at the deepest polyvec slot",
	);
}

#[test]
fn phase1_verifier_rejects_tampered_z_at_polyvec_interior() {
	// Flip one byte deep in the z section (last z polynomial). norm
	// check should reject if the value goes out of bounds.
	let mut w = build_honest_witness(16);
	// z section ends at byte 2336. The last z poly's last coefficient
	// occupies bytes around [2335, 2336). Set the entire last lane of z
	// to all-ones, which gives centered values likely > 2γ₁ - β.
	let z_last_lane = 4 + (L - 1) * 72 + 71; // 4 (c~) + 3 polys * 72 + last lane of poly 3
	w.sig_lanes[z_last_lane] = u64::MAX;
	assert!(
		run_verifier(&w).is_err(),
		"Phase 1 verifier must reject out-of-norm z at the last polyvec slot",
	);
}

// ─── Acceptance: hint-slack invariance flows through Phase 1 ────────────

#[test]
fn phase1_verifier_accepts_w_approx_perturbed_within_hint_slack() {
	// ML-DSA hint mechanism: a wApprox perturbation that keeps
	// use_hint output unchanged is accepted. This pins that R7's
	// hint-slack invariance (already tested at the R7 layer) carries
	// through to the full Phase 1 verifier.
	let mut w = build_honest_witness(17);
	let original_w1 = use_hint_native(w.w_approx[0][0], w.hint[0][0]);
	let mut perturbed = (w.w_approx[0][0] + 1) % Q;
	while use_hint_native(perturbed, w.hint[0][0]) != original_w1 || perturbed == w.w_approx[0][0]
	{
		perturbed = (perturbed + 1) % Q;
	}
	w.w_approx[0][0] = perturbed;
	run_verifier(&w).expect(
		"Phase 1 verifier must accept wApprox perturbations within the hint slack \
		 — this is the same correctness property as `r7_accepts_w_approx_perturbed_within_hint_slack`",
	);
}
