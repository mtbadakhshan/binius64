// Copyright 2026 The Binius Developers

//! Cross-mode roundtrip matrix for the four Binius64 proof paths.
//!
//! For each test circuit, this file proves with each of:
//!   1. BaseFold (`Prover::prove`)
//!   2. Akita full-open  (`Prover::prove_akita_full_open`)
//!   3. Akita succinct   (`Prover::prove_akita_succinct`)
//!   4. Akita claim-reduced (`Prover::prove_akita_claim_reduced`)
//!
//! and asserts that the matching verifier accepts each honest proof.
//! It also asserts cross-mode rejection (a proof from path X must NOT verify
//! under any other path's verifier) and tamper rejection (a single byte flip
//! in the middle of an honest proof must be rejected).
//!
//! Modes 2–4 are gated behind the `akita` feature. Modes 3–4 additionally
//! require the witness oracle to satisfy `log_msg_len >= 7` (i.e., the
//! committed trace must contain at least 2^7 = 128 packed B128 elements,
//! ≈ 256 64-bit words). Smaller circuits are skipped for those modes via the
//! `min_log_msg_len_for_succinct` gate.

use binius_circuits::{
	keccak::fixed_length::keccak256,
	sha256::{Compress, Sha256 as Sha256Circuit, State},
};
use binius_core::{
	constraint_system::{ConstraintSystem, ValueVec},
	word::Word,
};
use binius_field::arch::OptimalPackedB128;
use binius_frontend::{CircuitBuilder, Wire};
use binius_prover::{Prover, hash::parallel_compression::ParallelCompressionAdaptor};
use binius_transcript::ProverTranscript;
#[cfg(feature = "akita")]
use binius_transcript::VerifierTranscript;
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

const LOG_INV_RATE: usize = 1;

/// Smallest `log_msg_len` for which the Akita succinct / claim-reduced modes
/// can run. Mirrors the assertion inside `AkitaSuccinctSetup::new`.
const MIN_LOG_MSG_LEN_FOR_SUCCINCT: usize = 7;

/// Bundles a constraint system, witness, and oracle size for matrix testing.
struct TestCircuit {
	name: &'static str,
	cs: ConstraintSystem,
	witness: ValueVec,
}

fn setup(
	cs: ConstraintSystem,
) -> (
	Verifier<StdDigest, StdCompression>,
	Prover<OptimalPackedB128, ParallelCompressionAdaptor<StdCompression>, StdDigest>,
) {
	let verifier = Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default())
		.expect("verifier setup");
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.expect("prover setup");
	(verifier, prover)
}

/// Runs all four proof paths against the same circuit/witness. Returns the
/// honest proof bytes per mode for further (cross-mode / tamper) testing.
fn run_all_modes(test: &TestCircuit) {
	let (verifier, prover) = setup(test.cs.clone());
	let log_witness_elems = verifier.log_witness_elems();
	let supports_succinct = log_witness_elems >= MIN_LOG_MSG_LEN_FOR_SUCCINCT;

	println!(
		"\n==== [{}] log_witness_elems={} (succinct/claim-reduced supported: {})",
		test.name, log_witness_elems, supports_succinct
	);

	// 1. BaseFold path — always supported.
	{
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover
			.prove(test.witness.clone(), &mut t)
			.expect("basefold prove");
		let proof = t.finalize();
		println!("    [basefold]      proof size: {:>8} bytes", proof.len());

		let mut vt = binius_transcript::VerifierTranscript::new(
			StdChallenger::default(),
			proof.clone(),
		);
		verifier
			.verify(test.witness.public(), &mut vt)
			.expect("basefold verify");
		vt.finalize().expect("basefold transcript finalize");
	}

	#[cfg(feature = "akita")]
	{
		// 2. Akita full-open — always supported.
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover
			.prove_akita_full_open(test.witness.clone(), &mut t)
			.expect("akita full-open prove");
		let proof = t.finalize();
		println!("    [akita-full]    proof size: {:>8} bytes", proof.len());

		let mut vt = VerifierTranscript::new(StdChallenger::default(), proof.clone());
		verifier
			.verify_akita_full_open(test.witness.public(), &mut vt)
			.expect("akita full-open verify");
		vt.finalize().expect("akita full-open transcript finalize");
	}

	#[cfg(feature = "akita")]
	if supports_succinct {
		// 3. Akita succinct (multi-point opening).
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover
			.prove_akita_succinct(test.witness.clone(), &mut t)
			.expect("akita succinct prove");
		let proof = t.finalize();
		println!("    [akita-succ]    proof size: {:>8} bytes", proof.len());

		let mut vt = VerifierTranscript::new(StdChallenger::default(), proof.clone());
		verifier
			.verify_akita_succinct(test.witness.public(), &mut vt)
			.expect("akita succinct verify");
		vt.finalize().expect("akita succinct transcript finalize");

		// 4. Akita claim-reduced (single-point opening via claim reduction).
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover
			.prove_akita_claim_reduced(test.witness.clone(), &mut t)
			.expect("akita claim-reduced prove");
		let proof = t.finalize();
		println!("    [akita-claim]   proof size: {:>8} bytes", proof.len());

		let mut vt = VerifierTranscript::new(StdChallenger::default(), proof.clone());
		verifier
			.verify_akita_claim_reduced(test.witness.public(), &mut vt)
			.expect("akita claim-reduced verify");
		vt.finalize()
			.expect("akita claim-reduced transcript finalize");
	} else {
		println!(
			"    [akita-succ]    SKIPPED (log_witness_elems={} < {})",
			log_witness_elems, MIN_LOG_MSG_LEN_FOR_SUCCINCT
		);
		println!(
			"    [akita-claim]   SKIPPED (log_witness_elems={} < {})",
			log_witness_elems, MIN_LOG_MSG_LEN_FOR_SUCCINCT
		);
	}
}

/// Runs cross-mode rejection: a proof made by mode `prover_mode` must not
/// verify under any of the other entry points. Tamper rejection: a single
/// byte flip in the middle of the honest proof must also be rejected.
#[cfg(feature = "akita")]
fn run_cross_mode_and_tamper(test: &TestCircuit) {
	let (verifier, prover) = setup(test.cs.clone());
	let log_witness_elems = verifier.log_witness_elems();
	let supports_succinct = log_witness_elems >= MIN_LOG_MSG_LEN_FOR_SUCCINCT;

	let basefold_proof = {
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover.prove(test.witness.clone(), &mut t).unwrap();
		t.finalize()
	};
	let full_open_proof = {
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover
			.prove_akita_full_open(test.witness.clone(), &mut t)
			.unwrap();
		t.finalize()
	};
	let succinct_proof = supports_succinct.then(|| {
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover
			.prove_akita_succinct(test.witness.clone(), &mut t)
			.unwrap();
		t.finalize()
	});
	let claim_reduced_proof = supports_succinct.then(|| {
		let mut t = ProverTranscript::new(StdChallenger::default());
		prover
			.prove_akita_claim_reduced(test.witness.clone(), &mut t)
			.unwrap();
		t.finalize()
	});

	// Each (proof_label, proof) must verify under exactly one entry point and
	// be rejected by the other three.
	let mut all_proofs: Vec<(&str, Vec<u8>)> = vec![
		("basefold", basefold_proof),
		("full-open", full_open_proof),
	];
	if let Some(p) = succinct_proof {
		all_proofs.push(("succinct", p));
	}
	if let Some(p) = claim_reduced_proof {
		all_proofs.push(("claim-reduced", p));
	}

	let entry_points: &[&str] =
		&["basefold", "full-open", "succinct", "claim-reduced"];
	for (proof_label, proof_bytes) in &all_proofs {
		for &verify_label in entry_points {
			let mut vt =
				VerifierTranscript::new(StdChallenger::default(), proof_bytes.clone());
			let result = match verify_label {
				"basefold" => verifier.verify(test.witness.public(), &mut vt),
				"full-open" => {
					verifier.verify_akita_full_open(test.witness.public(), &mut vt)
				}
				"succinct" => {
					if !supports_succinct {
						continue;
					}
					verifier.verify_akita_succinct(test.witness.public(), &mut vt)
				}
				"claim-reduced" => {
					if !supports_succinct {
						continue;
					}
					verifier
						.verify_akita_claim_reduced(test.witness.public(), &mut vt)
				}
				_ => unreachable!(),
			};
			if proof_label == &verify_label {
				result.unwrap_or_else(|e| {
					panic!(
						"[{}] honest {} proof must verify under verify_{}: {:?}",
						test.name, proof_label, verify_label, e
					)
				});
			} else {
				assert!(
					result.is_err(),
					"[{}] {} proof must NOT verify under verify_{}",
					test.name,
					proof_label,
					verify_label,
				);
			}
		}
	}

	// Tamper rejection: middle-byte flip on each honest proof must be rejected.
	for (proof_label, proof_bytes) in &all_proofs {
		let mid = proof_bytes.len() / 2;
		let mut tampered = proof_bytes.clone();
		tampered[mid] ^= 1;
		let mut vt = VerifierTranscript::new(StdChallenger::default(), tampered);
		let result = match *proof_label {
			"basefold" => verifier.verify(test.witness.public(), &mut vt),
			"full-open" => {
				verifier.verify_akita_full_open(test.witness.public(), &mut vt)
			}
			"succinct" => {
				verifier.verify_akita_succinct(test.witness.public(), &mut vt)
			}
			"claim-reduced" => {
				verifier.verify_akita_claim_reduced(test.witness.public(), &mut vt)
			}
			_ => unreachable!(),
		};
		assert!(
			result.is_err(),
			"[{}] mid-byte tampered {} proof must be rejected",
			test.name,
			proof_label,
		);
	}
	println!("    [{}] cross-mode + middle-byte tamper rejection: OK", test.name);
}

// ============================================================================
// Test circuits
// ============================================================================

/// Toy circuit: `private & 0xFF00 == 0x1200`. Only ~one AND constraint, so
/// the witness oracle is too small for `succinct`/`claim-reduced` and only
/// the BaseFold + full-open paths exercise it.
fn toy_and_mask_circuit() -> TestCircuit {
	let b = CircuitBuilder::new();
	let mask = b.add_constant_64(0xFF00);
	let private = b.add_witness();
	let output = b.add_inout();
	let result = b.band(private, mask);
	b.assert_eq("masked_result", result, output);
	let circuit = b.build();
	let mut w = circuit.new_witness_filler();
	w[private] = Word(0x1234);
	w[output] = Word(0x1200);
	circuit.populate_wire_witness(&mut w).unwrap();
	TestCircuit {
		name: "toy_and_mask",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

/// SHA-256 single-block preimage of "abc". Mirrors the existing
/// `sha256_preimage_circuit` helper in `prove_verify.rs` so the matrix test
/// shares the same workload but goes through every mode.
fn sha256_abc_circuit() -> TestCircuit {
	let mut preimage = [0u8; 64];
	preimage[0..3].copy_from_slice(b"abc");
	preimage[3] = 0x80;
	preimage[63] = 0x18;
	#[rustfmt::skip]
	let expected_state: [u32; 8] = [
		0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
		0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
	];

	let circuit = CircuitBuilder::new();
	let state = State::iv(&circuit);
	let input: [Wire; 16] = std::array::from_fn(|_| circuit.add_witness());
	let output: [Wire; 8] = std::array::from_fn(|_| circuit.add_inout());
	let compress = Compress::new(&circuit, state, input);

	let mask32 = circuit.add_constant(Word::MASK_32);
	for (actual_x, expected_x) in compress.state_out.0.iter().zip(output) {
		circuit.assert_eq("eq", circuit.band(*actual_x, mask32), expected_x);
	}

	let circuit = circuit.build();
	let mut w = circuit.new_witness_filler();
	compress.populate_m(&mut w, preimage);
	for (i, &out) in output.iter().enumerate() {
		w[out] = Word(expected_state[i] as u64);
	}
	circuit.populate_wire_witness(&mut w).unwrap();
	TestCircuit {
		name: "sha256_compress_abc",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

/// Full SHA-256 (with in-circuit padding) over a short message. Uses the
/// `Sha256` gadget rather than a single `Compress`, exercising a different
/// (and larger) code path than `sha256_abc_circuit`.
fn sha256_full_short_circuit() -> TestCircuit {
	let message = b"Hello, Binius64!";

	let mut hasher = Sha256::new();
	hasher.update(message);
	let expected_digest: [u8; 32] = hasher.finalize().into();

	let b = CircuitBuilder::new();
	// Match the upstream test helper: max_len=64 bytes, so 8 message wires.
	let len = b.add_witness();
	let digest: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
	let message_wires: Vec<Wire> = (0..8).map(|_| b.add_inout()).collect();
	let sha = Sha256Circuit::new(&b, len, digest, message_wires);
	let circuit = b.build();

	let mut w = circuit.new_witness_filler();
	sha.populate_len_bytes(&mut w, message.len());
	sha.populate_message(&mut w, message);
	sha.populate_digest(&mut w, expected_digest);
	circuit.populate_wire_witness(&mut w).unwrap();

	TestCircuit {
		name: "sha256_full_short",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

/// Keccak-256 of a fixed 32-byte message (= 4 wires). Different non-linearity
/// from SHA-256 so it exercises the bridge against a structurally different
/// AND/MUL pattern.
fn keccak256_circuit() -> TestCircuit {
	let message_bytes: [u8; 32] = *b"binius64 + akita bridge matrix !";
	let mut hasher = Keccak256::new();
	hasher.update(message_bytes);
	let expected_digest: [u8; 32] = hasher.finalize().into();

	let b = CircuitBuilder::new();
	let n_words = message_bytes.len().div_ceil(8);
	let message_wires: Vec<Wire> = (0..n_words).map(|_| b.add_witness()).collect();
	let expected_digest_wires: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
	let computed = keccak256(&b, &message_wires, message_bytes.len());
	for i in 0..4 {
		b.assert_eq(format!("digest[{i}]"), computed[i], expected_digest_wires[i]);
	}
	let circuit = b.build();
	let mut w = circuit.new_witness_filler();
	for (i, chunk) in message_bytes.chunks(8).enumerate() {
		let mut word_bytes = [0u8; 8];
		word_bytes[..chunk.len()].copy_from_slice(chunk);
		w[message_wires[i]] = Word(u64::from_le_bytes(word_bytes));
	}
	for (i, chunk) in expected_digest.chunks(8).enumerate() {
		w[expected_digest_wires[i]] = Word(u64::from_le_bytes(chunk.try_into().unwrap()));
	}
	circuit.populate_wire_witness(&mut w).unwrap();
	TestCircuit {
		name: "keccak256_32bytes",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

// ============================================================================
// Tests — positive roundtrip per circuit, all modes
// ============================================================================

#[test]
fn matrix_toy_and_mask() {
	run_all_modes(&toy_and_mask_circuit());
}

#[test]
fn matrix_sha256_compress_abc() {
	run_all_modes(&sha256_abc_circuit());
}

#[test]
fn matrix_sha256_full_short() {
	run_all_modes(&sha256_full_short_circuit());
}

#[test]
fn matrix_keccak256_32bytes() {
	run_all_modes(&keccak256_circuit());
}

// ============================================================================
// Tests — cross-mode rejection + tamper rejection (akita-only)
// ============================================================================

#[cfg(feature = "akita")]
#[test]
fn cross_mode_and_tamper_toy_and_mask() {
	run_cross_mode_and_tamper(&toy_and_mask_circuit());
}

#[cfg(feature = "akita")]
#[test]
fn cross_mode_and_tamper_sha256_compress_abc() {
	run_cross_mode_and_tamper(&sha256_abc_circuit());
}

#[cfg(feature = "akita")]
#[test]
fn cross_mode_and_tamper_keccak256_32bytes() {
	run_cross_mode_and_tamper(&keccak256_circuit());
}

// ============================================================================
// Tests — bad-witness rejection across all modes
// ============================================================================

/// Construct a SHA-256 preimage circuit but fill in the WRONG digest as the
/// public output. All four prover paths produce proofs whose verifier must
/// reject them, since the `assert_eq` constraint between the computed and
/// claimed digest is not satisfied.
fn sha256_bad_digest_circuit() -> TestCircuit {
	let mut preimage = [0u8; 64];
	preimage[0..3].copy_from_slice(b"abc");
	preimage[3] = 0x80;
	preimage[63] = 0x18;

	let circuit = CircuitBuilder::new();
	let state = State::iv(&circuit);
	let input: [Wire; 16] = std::array::from_fn(|_| circuit.add_witness());
	let output: [Wire; 8] = std::array::from_fn(|_| circuit.add_inout());
	let compress = Compress::new(&circuit, state, input);

	let mask32 = circuit.add_constant(Word::MASK_32);
	for (actual_x, expected_x) in compress.state_out.0.iter().zip(output) {
		circuit.assert_eq("eq", circuit.band(*actual_x, mask32), expected_x);
	}

	let circuit = circuit.build();
	let mut w = circuit.new_witness_filler();
	compress.populate_m(&mut w, preimage);
	// Wrong digest (all zeros instead of the real SHA-256 of "abc").
	for &out in output.iter() {
		w[out] = Word(0);
	}
	// Allow `populate_wire_witness` to fail silently — we explicitly want a
	// witness that fails the public-output assert_eq below.
	let _ = circuit.populate_wire_witness(&mut w);
	TestCircuit {
		name: "sha256_compress_bad_digest",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

#[test]
fn bad_witness_rejected_basefold() {
	let test = sha256_bad_digest_circuit();
	let (verifier, prover) = setup(test.cs.clone());
	let mut t = ProverTranscript::new(StdChallenger::default());
	let prove_result = prover.prove(test.witness.clone(), &mut t);
	// The prover may itself error out (constraints unsatisfiable) OR produce
	// a proof that the verifier rejects. Either is a sound outcome; an
	// "honest verifier accepts" would be a soundness break.
	if prove_result.is_ok() {
		let proof = t.finalize();
		let mut vt =
			binius_transcript::VerifierTranscript::new(StdChallenger::default(), proof);
		assert!(
			verifier.verify(test.witness.public(), &mut vt).is_err(),
			"basefold verifier accepted bad-witness proof — soundness break",
		);
	}
}

#[cfg(feature = "akita")]
#[test]
fn bad_witness_rejected_akita_full_open() {
	let test = sha256_bad_digest_circuit();
	let (verifier, prover) = setup(test.cs.clone());
	let mut t = ProverTranscript::new(StdChallenger::default());
	let prove_result = prover.prove_akita_full_open(test.witness.clone(), &mut t);
	if prove_result.is_ok() {
		let proof = t.finalize();
		let mut vt = VerifierTranscript::new(StdChallenger::default(), proof);
		assert!(
			verifier
				.verify_akita_full_open(test.witness.public(), &mut vt)
				.is_err(),
			"akita-full-open verifier accepted bad-witness proof — soundness break",
		);
	}
}

#[cfg(feature = "akita")]
#[test]
fn bad_witness_rejected_akita_succinct() {
	let test = sha256_bad_digest_circuit();
	let (verifier, prover) = setup(test.cs.clone());
	let mut t = ProverTranscript::new(StdChallenger::default());
	let prove_result = prover.prove_akita_succinct(test.witness.clone(), &mut t);
	if prove_result.is_ok() {
		let proof = t.finalize();
		let mut vt = VerifierTranscript::new(StdChallenger::default(), proof);
		assert!(
			verifier
				.verify_akita_succinct(test.witness.public(), &mut vt)
				.is_err(),
			"akita-succinct verifier accepted bad-witness proof — soundness break",
		);
	}
}

#[cfg(feature = "akita")]
#[test]
fn bad_witness_rejected_akita_claim_reduced() {
	let test = sha256_bad_digest_circuit();
	let (verifier, prover) = setup(test.cs.clone());
	let mut t = ProverTranscript::new(StdChallenger::default());
	let prove_result = prover.prove_akita_claim_reduced(test.witness.clone(), &mut t);
	if prove_result.is_ok() {
		let proof = t.finalize();
		let mut vt = VerifierTranscript::new(StdChallenger::default(), proof);
		assert!(
			verifier
				.verify_akita_claim_reduced(test.witness.public(), &mut vt)
				.is_err(),
			"akita-claim-reduced verifier accepted bad-witness proof — soundness break",
		);
	}
}
