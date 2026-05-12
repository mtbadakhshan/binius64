// Copyright 2025 Irreducible Inc.

use binius_circuits::sha256::{Compress, State};
use binius_core::{
	constraint_system::{ConstraintSystem, ValueVec},
	word::Word,
};
use binius_field::arch::OptimalPackedB128;
use binius_frontend::{CircuitBuilder, Wire};
use binius_prover::{
	Prover, hash::parallel_compression::ParallelCompressionAdaptor, zk_config::ZKProver,
};
use binius_transcript::ProverTranscript;
#[cfg(feature = "akita")]
use binius_transcript::VerifierTranscript;
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
	zk_config::ZKVerifier,
};
use rand::{SeedableRng, rngs::StdRng};

fn prove_verify(cs: ConstraintSystem, witness: ValueVec) {
	const LOG_INV_RATE: usize = 1;

	let verifier =
		Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default()).unwrap();

	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.unwrap();

	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.unwrap();

	let mut verifier_transcript = prover_transcript.into_verifier();
	verifier
		.verify(witness.public(), &mut verifier_transcript)
		.unwrap();
	verifier_transcript.finalize().unwrap();
}

fn prove_verify_zk(cs: ConstraintSystem, witness: ValueVec) {
	const LOG_INV_RATE: usize = 1;

	let zk_verifier =
		ZKVerifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default()).unwrap();

	let zk_prover = ZKProver::<OptimalPackedB128, _, StdDigest>::setup(
		zk_verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.unwrap();

	let mut rng = StdRng::seed_from_u64(0);
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	zk_prover
		.prove(witness.clone(), &mut rng, &mut prover_transcript)
		.unwrap();

	let mut verifier_transcript = prover_transcript.into_verifier();
	zk_verifier
		.verify(witness.public(), &mut verifier_transcript)
		.unwrap();
	verifier_transcript.finalize().unwrap();
}

fn sha256_preimage_circuit() -> (ConstraintSystem, ValueVec) {
	// Use the test-vector for SHA256 single block message: "abc".
	let mut preimage: [u8; 64] = [0; 64];
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

	// Mask to only low 32-bit.
	let mask32 = circuit.add_constant(Word::MASK_32);
	for (actual_x, expected_x) in compress.state_out.0.iter().zip(output) {
		circuit.assert_eq("eq", circuit.band(*actual_x, mask32), expected_x);
	}

	let circuit = circuit.build();
	let mut w = circuit.new_witness_filler();

	// Populate the input message for the compression function.
	compress.populate_m(&mut w, preimage);

	for (i, &output) in output.iter().enumerate() {
		w[output] = Word(expected_state[i] as u64);
	}
	circuit.populate_wire_witness(&mut w).unwrap();

	(circuit.constraint_system().clone(), w.into_value_vec())
}

#[test]
fn test_prove_verify_sha256_preimage() {
	let (cs, witness) = sha256_preimage_circuit();
	prove_verify(cs, witness);
}

#[test]
fn test_zk_prove_verify_sha256_preimage() {
	let (cs, witness) = sha256_preimage_circuit();
	prove_verify_zk(cs, witness);
}

#[cfg(feature = "akita")]
#[test]
fn akita_proof_mode_mismatches_reject() {
	const LOG_INV_RATE: usize = 1;

	let (cs, witness) = sha256_preimage_circuit();
	let verifier =
		Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default()).unwrap();
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.unwrap();

	let mut basefold_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut basefold_transcript)
		.unwrap();
	let basefold_proof = basefold_transcript.finalize();
	let mut verifier_transcript =
		VerifierTranscript::new(StdChallenger::default(), basefold_proof.clone());
	assert!(
		verifier
			.verify_akita_full_open(witness.public(), &mut verifier_transcript)
			.is_err()
	);
	let mut verifier_transcript = VerifierTranscript::new(StdChallenger::default(), basefold_proof);
	assert!(
		verifier
			.verify_akita_succinct(witness.public(), &mut verifier_transcript)
			.is_err()
	);

	let mut full_open_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove_akita_full_open(witness.clone(), &mut full_open_transcript)
		.unwrap();
	let full_open_proof = full_open_transcript.finalize();
	let mut verifier_transcript =
		VerifierTranscript::new(StdChallenger::default(), full_open_proof.clone());
	assert!(
		verifier
			.verify(witness.public(), &mut verifier_transcript)
			.is_err()
	);
	let mut verifier_transcript =
		VerifierTranscript::new(StdChallenger::default(), full_open_proof);
	assert!(
		verifier
			.verify_akita_succinct(witness.public(), &mut verifier_transcript)
			.is_err()
	);

	let mut succinct_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove_akita_succinct(witness.clone(), &mut succinct_transcript)
		.unwrap();
	let succinct_proof = succinct_transcript.finalize();
	// Positive roundtrip: an honest `prove_akita_succinct` proof MUST verify
	// under `verify_akita_succinct`. A buggy verifier that rejects everything
	// would trivially pass the negative-only assertions below; this positive
	// roundtrip is the only assertion that actually exercises the honest
	// shape-derivation + PCS opening path end to end.
	{
		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), succinct_proof.clone());
		verifier
			.verify_akita_succinct(witness.public(), &mut verifier_transcript)
			.expect("honest akita-succinct proof must verify");
	}
	for offset in [
		succinct_proof.len() / 4,
		succinct_proof.len() / 2,
		succinct_proof.len() - 1,
	] {
		let mut tampered = succinct_proof.clone();
		tampered[offset] ^= 1;
		let mut verifier_transcript = VerifierTranscript::new(StdChallenger::default(), tampered);
		assert!(
			verifier
				.verify_akita_succinct(witness.public(), &mut verifier_transcript)
				.is_err()
		);
	}
	let mut verifier_transcript =
		VerifierTranscript::new(StdChallenger::default(), succinct_proof.clone());
	assert!(
		verifier
			.verify(witness.public(), &mut verifier_transcript)
			.is_err()
	);
	let mut verifier_transcript = VerifierTranscript::new(StdChallenger::default(), succinct_proof);
	assert!(
		verifier
			.verify_akita_full_open(witness.public(), &mut verifier_transcript)
			.is_err()
	);
}

/// Regression test for the `akita-claim-reduced` proof mode.
///
/// Asserts that:
/// 1. **Positive roundtrip**: an honest `prove_akita_claim_reduced` proof
///    verifies under `verify_akita_claim_reduced`. This is the only assertion
///    that actually exercises the honest end-to-end path; the previous
///    `akita_proof_mode_mismatches_reject` test was negative-only and silently
///    accepted a verifier that always errored, which masked an off-by-one
///    bug in the shape derivation and a prover/verifier disagreement on
///    Akita's commitment-pointer dedup for months.
/// 2. **Tamper rejection**: byte-flipped versions of an honest claim-reduced
///    proof must be rejected at proof-start / proof-middle / proof-end.
/// 3. **Cross-mode rejection**: a `prove_akita_claim_reduced` proof must NOT
///    verify under any other entry point (`verify`, `verify_akita_full_open`,
///    `verify_akita_succinct`), and vice versa: BaseFold, full-open, and
///    succinct proofs must NOT verify under `verify_akita_claim_reduced`.
///    The `PROOF_MODE_*` transcript tag guarantees this; the test confirms
///    the guarantee is wired correctly.
#[cfg(feature = "akita")]
#[test]
fn akita_claim_reduced_proof_mode_mismatches_reject() {
	const LOG_INV_RATE: usize = 1;

	let (cs, witness) = sha256_preimage_circuit();
	let verifier =
		Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default()).unwrap();
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.unwrap();

	// 1. Positive roundtrip — honest claim-reduced proof must verify.
	let mut claim_reduced_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove_akita_claim_reduced(witness.clone(), &mut claim_reduced_transcript)
		.unwrap();
	let claim_reduced_proof = claim_reduced_transcript.finalize();
	{
		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), claim_reduced_proof.clone());
		verifier
			.verify_akita_claim_reduced(witness.public(), &mut verifier_transcript)
			.expect("honest akita-claim-reduced proof must verify");
	}

	// 2. Tamper rejection — byte flips at proof-start / proof-middle /
	// proof-end must all be rejected.
	for offset in [
		claim_reduced_proof.len() / 4,
		claim_reduced_proof.len() / 2,
		claim_reduced_proof.len() - 1,
	] {
		let mut tampered = claim_reduced_proof.clone();
		tampered[offset] ^= 1;
		let mut verifier_transcript = VerifierTranscript::new(StdChallenger::default(), tampered);
		assert!(
			verifier
				.verify_akita_claim_reduced(witness.public(), &mut verifier_transcript)
				.is_err()
		);
	}

	// 3a. Cross-mode rejection — claim-reduced proof must NOT verify under
	// the BaseFold / full-open / succinct entry points.
	for verify_fn in [
		"verify",
		"verify_akita_full_open",
		"verify_akita_succinct",
	] {
		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), claim_reduced_proof.clone());
		let result = match verify_fn {
			"verify" => verifier.verify(witness.public(), &mut verifier_transcript),
			"verify_akita_full_open" => {
				verifier.verify_akita_full_open(witness.public(), &mut verifier_transcript)
			}
			"verify_akita_succinct" => {
				verifier.verify_akita_succinct(witness.public(), &mut verifier_transcript)
			}
			_ => unreachable!(),
		};
		assert!(
			result.is_err(),
			"claim-reduced proof must be rejected by {verify_fn}",
		);
	}

	// 3b. Cross-mode rejection — BaseFold / full-open / succinct proofs must
	// NOT verify under `verify_akita_claim_reduced`.
	let mut basefold_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut basefold_transcript)
		.unwrap();
	let basefold_proof = basefold_transcript.finalize();
	let mut verifier_transcript =
		VerifierTranscript::new(StdChallenger::default(), basefold_proof);
	assert!(
		verifier
			.verify_akita_claim_reduced(witness.public(), &mut verifier_transcript)
			.is_err(),
		"BaseFold proof must be rejected by verify_akita_claim_reduced"
	);

	let mut full_open_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove_akita_full_open(witness.clone(), &mut full_open_transcript)
		.unwrap();
	let full_open_proof = full_open_transcript.finalize();
	let mut verifier_transcript =
		VerifierTranscript::new(StdChallenger::default(), full_open_proof);
	assert!(
		verifier
			.verify_akita_claim_reduced(witness.public(), &mut verifier_transcript)
			.is_err(),
		"akita-full-open proof must be rejected by verify_akita_claim_reduced"
	);

	let mut succinct_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove_akita_succinct(witness.clone(), &mut succinct_transcript)
		.unwrap();
	let succinct_proof = succinct_transcript.finalize();
	let mut verifier_transcript =
		VerifierTranscript::new(StdChallenger::default(), succinct_proof);
	assert!(
		verifier
			.verify_akita_claim_reduced(witness.public(), &mut verifier_transcript)
			.is_err(),
		"akita-succinct proof must be rejected by verify_akita_claim_reduced"
	);
}
