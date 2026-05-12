// Copyright 2026 The Binius Developers

//! End-to-end Phase 1 verifier through the full Binius64 prover and
//! verifier pipeline.
//!
//! Where `phase1_verifier.rs` validates the `MlDsaVerifier` circuit at
//! the *constraint-system* level (via `verify_constraints`), this file
//! exercises the same circuit through the production transcript flow:
//!
//!   `CircuitBuilder` → `Prover::prove` → bytes → `Verifier::verify`.
//!
//! It pins three production-path properties:
//!
//!   1. **Compatibility** — the circuit dimensions are within the
//!      BaseFold PCS's supported regime (`Verifier::setup` and
//!      `Prover::setup` succeed).
//!   2. **End-to-end soundness** — an honest synthetic ML-DSA witness
//!      both populates *and* round-trips through prove/verify cleanly.
//!   3. **Proof-tamper rejection** — flipping bytes in the produced
//!      proof transcript causes `Verifier::verify` (or
//!      `verifier_transcript.finalize`) to fail. This is the
//!      Fiat-Shamir / PCS soundness backstop, independent of the
//!      circuit-level checks tested elsewhere.
//!
//! The diagnostic test `e2e_phase1_print_baseline_stats` (run with
//! `cargo test -- --nocapture e2e_phase1_print_baseline_stats`) reports
//! the constraint count, witness size, proof size, and wall-clock
//! prover / verifier times. These numbers anchor the Phase 1 baseline
//! before Phase 2 brings R5 in-circuit.

use std::time::Instant;

use binius_core::word::Word;
use binius_field::arch::OptimalPackedB128;
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	hint::{HINT_SECTION_BYTES, pack_h_native},
	params::{MODE2, N, Q},
	polyw1::polyw1_pack_native,
	r7::{MU_BYTES, MU_LANES},
	rounding::use_hint_native,
	sigdecode::{
		SIG_C_TILDE_BYTES, SIG_H_LANE_OFFSET, SIG_PACKED_LANES, pack_signature_native,
		signature_to_lanes,
	},
	verifier::MlDsaVerifier,
	zq::from_u64_witness,
};
use binius_prover::{Prover, hash::parallel_compression::ParallelCompressionAdaptor};
use binius_transcript::ProverTranscript;
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha3::{
	Shake256,
	digest::{ExtendableOutput, Update, XofReader},
};

const L: usize = MODE2.l;
const K: usize = MODE2.k;

const LOG_INV_RATE: usize = 1;

/// A fully-specified synthetic Phase 1 witness (Dilithium2, K=L=4),
/// honest by construction.
struct HonestWitness {
	sig_lanes: [u64; SIG_PACKED_LANES],
	mu: [u8; MU_BYTES],
	w_approx: [[u32; N]; K],
	hint: [[u32; N]; K],
}

/// Build an honest synthetic Phase 1 witness for the given seed. The
/// signer's c̃ is the native R7 hash output, so the in-circuit R7
/// binding holds by construction.
fn build_honest_witness(seed: u64) -> HonestWitness {
	let mut rng = StdRng::seed_from_u64(seed);

	let z_centered: [[u32; N]; L] = std::array::from_fn(|_| {
		std::array::from_fn(|_| rng.random_range(MODE2.beta + 1..2 * MODE2.gamma1 - MODE2.beta))
	});
	let w_approx: [[u32; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| rng.random_range(0..Q)));
	let hint = random_sparse_hint(&mut rng);
	let mu: [u8; MU_BYTES] = std::array::from_fn(|_| rng.random());

	let c_tilde = r7_native(&w_approx, &hint, &mu);
	let mut packed = pack_signature_native(&c_tilde, &z_centered);

	let h_polyvec_u8: [[u8; N]; K] = std::array::from_fn(|k| {
		std::array::from_fn(|p| hint[k][p] as u8)
	});
	let h_section = pack_h_native(&h_polyvec_u8);
	let h_byte_offset = SIG_H_LANE_OFFSET * 8;
	packed[h_byte_offset..h_byte_offset + HINT_SECTION_BYTES].copy_from_slice(&h_section);
	let sig_lanes = signature_to_lanes(&packed);

	HonestWitness { sig_lanes, mu, w_approx, hint }
}

fn random_sparse_hint(rng: &mut StdRng) -> [[u32; N]; K] {
	let total = rng.random_range(0..=MODE2.omega);
	let mut placed = 0usize;
	let mut h = [[0u32; N]; K];
	for poly in h.iter_mut() {
		if placed >= total {
			break;
		}
		let this_count = rng.random_range(0..=(total - placed).min(40));
		let mut positions: Vec<usize> = (0..N).collect();
		for i in 0..this_count.min(positions.len()) {
			let j = rng.random_range(i..positions.len());
			positions.swap(i, j);
		}
		for &p in &positions[..this_count] {
			poly[p] = 1;
		}
		placed += this_count;
	}
	h
}

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

/// Build the Phase 1 verifier circuit and populate its witness from
/// the honest synthetic data. Returns the constraint system + the
/// populated `ValueVec` ready for `prove`.
#[allow(clippy::type_complexity)]
fn build_circuit_and_witness(
	w: &HonestWitness,
) -> (binius_core::constraint_system::ConstraintSystem, binius_core::constraint_system::ValueVec) {
	let builder = CircuitBuilder::new();

	let sig_wires: [Wire; SIG_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let mu_wires: [Wire; MU_LANES] = std::array::from_fn(|_| builder.add_witness());
	let w_approx_wires: [[Wire; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| from_u64_witness(&builder)));

	let verifier =
		MlDsaVerifier::new(&builder, &sig_wires, &mu_wires, &w_approx_wires);

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
			filler[verifier.hint[k][i]] = Word(w.hint[k][i] as u64);
		}
	}
	circuit
		.populate_wire_witness(&mut filler)
		.expect("honest witness must populate cleanly");

	(circuit.constraint_system().clone(), filler.into_value_vec())
}

/// Run the full prove → verify pipeline. Returns the proof bytes on
/// success.
fn prove_verify(
	cs: binius_core::constraint_system::ConstraintSystem,
	witness: binius_core::constraint_system::ValueVec,
) -> Vec<u8> {
	let verifier =
		Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default())
			.expect("verifier setup");

	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.expect("prover setup");

	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.expect("prove");
	let proof_bytes = prover_transcript.finalize();

	// Replay the proof through the verifier with a fresh transcript so
	// we exercise the same wire format the production verifier sees.
	let verifier_transcript = binius_transcript::VerifierTranscript::new(
		StdChallenger::default(),
		proof_bytes.clone(),
	);
	let mut verifier_transcript = verifier_transcript;
	verifier
		.verify(witness.public(), &mut verifier_transcript)
		.expect("verify");
	verifier_transcript.finalize().expect("verify finalize");

	proof_bytes
}

// ─── Tests ────────────────────────────────────────────────────────────

#[test]
fn e2e_phase1_prove_verify_accepts_honest_signature() {
	let w = build_honest_witness(0);
	let (cs, witness) = build_circuit_and_witness(&w);
	let proof = prove_verify(cs, witness);
	assert!(!proof.is_empty(), "non-empty proof bytes");
}

#[test]
fn e2e_phase1_prove_verify_rejects_tampered_proof_byte() {
	let w = build_honest_witness(1);
	let (cs, witness) = build_circuit_and_witness(&w);

	let verifier =
		Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default())
			.expect("verifier setup");
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.expect("prover setup");

	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.expect("prove");
	let mut proof_bytes = prover_transcript.finalize();

	// Flip a byte somewhere in the middle of the proof — too early
	// (just header) or too late (might land in unread padding) can
	// avoid the dispatch. The middle of the transcript carries the
	// PCS commitment / sumcheck challenges and is robustly checked.
	let target = proof_bytes.len() / 2;
	proof_bytes[target] ^= 0x55;

	let mut verifier_transcript =
		binius_transcript::VerifierTranscript::new(StdChallenger::default(), proof_bytes);
	let verify_result = verifier.verify(witness.public(), &mut verifier_transcript);
	let finalize_result = verifier_transcript.finalize();

	assert!(
		verify_result.is_err() || finalize_result.is_err(),
		"verifier must reject a proof with a flipped middle byte (got verify={verify_result:?}, finalize={finalize_result:?})",
	);
}

/// Diagnostic: prints the Phase 1 verifier's circuit / proof / timing
/// baseline. Run with `cargo test -p binius-mldsa -- --nocapture
/// e2e_phase1_print_baseline_stats` to see the numbers.
#[test]
fn e2e_phase1_print_baseline_stats() {
	let w = build_honest_witness(2);

	let t_build = Instant::now();
	let (cs, witness) = build_circuit_and_witness(&w);
	let build_ms = t_build.elapsed().as_secs_f64() * 1000.0;

	let n_and = cs.n_and_constraints();
	let n_mul = cs.n_mul_constraints();
	let n_values = witness.size();

	let t_setup = Instant::now();
	let verifier =
		Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default())
			.expect("verifier setup");
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.expect("prover setup");
	let setup_ms = t_setup.elapsed().as_secs_f64() * 1000.0;

	let t_prove = Instant::now();
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.expect("prove");
	let proof_bytes = prover_transcript.finalize();
	let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
	let proof_size = proof_bytes.len();

	let t_verify = Instant::now();
	let mut verifier_transcript =
		binius_transcript::VerifierTranscript::new(StdChallenger::default(), proof_bytes);
	verifier
		.verify(witness.public(), &mut verifier_transcript)
		.expect("verify");
	verifier_transcript.finalize().expect("verify finalize");
	let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

	println!("\n──── Phase 1 MlDsaVerifier baseline (Dilithium2, K=L=4) ────");
	println!("  circuit build         : {build_ms:>10.2} ms");
	println!("  setup (prover+verifier): {setup_ms:>10.2} ms");
	println!("  prove                  : {prove_ms:>10.2} ms");
	println!("  verify                 : {verify_ms:>10.2} ms");
	println!("  AND constraints        : {n_and:>10}");
	println!("  MUL constraints        : {n_mul:>10}");
	println!("  total ValueVec entries : {n_values:>10}");
	println!("  proof size             : {proof_size:>10} bytes");
	println!("───────────────────────────────────────────────────────────");
}
