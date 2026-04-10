// Copyright 2026 The Binius Developers

use binius_field::BinaryField;
use binius_ip::channel::IPVerifierChannel;
use binius_ip_prover::channel::IPProverChannel;

use crate::{
	BitIndexedEndpointClaims, Error, FusedRoundReduction, bit_indexed_claim_from_evals,
	bit_indexed_lane_claim_from_words, fused_round,
	trace::CompactTrace,
};

/// Prove the full standalone 24-round KeccakCheck over a compact word-level trace.
pub fn prove<P, Channel>(
	trace: &CompactTrace,
	channel: &mut Channel,
) -> Result<BitIndexedEndpointClaims<P::Scalar>, Error>
where
	P: binius_field::PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_compact_trace(trace)?;
	let n_instances = trace.n_instances();
	let _prove_guard = tracing::info_span!(
		"KeccakCheck Prove",
		operation = "keccak_check_prove",
		perfetto_category = "operation",
		n_rounds = 24,
		n_instances
	)
	.entered();

	let output_bit_challenge = channel.sample();
	let output_high_point = channel.sample_many(trace.log_n_instances());
	let output_weights = channel.sample_array::<25>();
	let output_claim = bit_indexed_lane_claim_from_words(
		&trace.final_output,
		output_bit_challenge,
		&output_high_point,
		output_weights,
	);
	let mut carried_output_claim = output_claim.clone();

	for round in (0..24).rev() {
		let _round_guard = tracing::info_span!(
			"[phase] Keccak Round Prove",
			phase = "keccak_round_prove",
			perfetto_category = "phase",
			round
		)
		.entered();
		let fused_output = fused_round::prove_round_from_words::<P, _>(
			&trace.round_inputs[round],
			&FusedRoundReduction {
				output_claim: carried_output_claim,
				round,
			},
			channel,
		)?;

		if round > 0 {
			let next_output_weights = channel.sample_array::<25>();
			carried_output_claim = bit_indexed_claim_from_evals(
				output_bit_challenge,
				fused_output.reduced_high_point,
				next_output_weights,
				fused_output.input_evals,
			);
		} else {
			let input_weights = channel.sample_array::<25>();
			let input_claim = bit_indexed_claim_from_evals(
				output_bit_challenge,
				fused_output.reduced_high_point,
				input_weights,
				fused_output.input_evals,
			);

			return Ok(BitIndexedEndpointClaims {
				output_claim,
				input_claim,
			});
		}
	}

	Err(Error::InvalidClaim("trace must contain at least one round"))
}

/// Verify the full standalone 24-round KeccakCheck over a compact word-level trace.
pub fn verify<F, Channel>(
	trace: &CompactTrace,
	channel: &mut Channel,
) -> Result<BitIndexedEndpointClaims<F>, Error>
where
	F: BinaryField,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	validate_compact_trace(trace)?;
	let n_instances = trace.n_instances();
	let _verify_guard = tracing::info_span!(
		"KeccakCheck Verify",
		operation = "keccak_check_verify",
		perfetto_category = "operation",
		n_rounds = 24,
		n_instances
	)
	.entered();

	let output_bit_challenge = channel.sample();
	let output_high_point = channel.sample_many(trace.log_n_instances());
	let output_weights = channel.sample_array::<25>();
	let output_claim = bit_indexed_lane_claim_from_words(
		&trace.final_output,
		output_bit_challenge,
		&output_high_point,
		output_weights,
	);
	let mut carried_output_claim = output_claim.clone();

	for round in (0..24).rev() {
		let _round_guard = tracing::info_span!(
			"[phase] Keccak Round Verify",
			phase = "keccak_round_verify",
			perfetto_category = "phase",
			round
		)
		.entered();
		let fused_output = fused_round::verify_round_from_words::<F, _>(
			&trace.round_inputs[round],
			&FusedRoundReduction {
				output_claim: carried_output_claim,
				round,
			},
			channel,
		)?;

		if round > 0 {
			let next_output_weights = channel.sample_array::<25>();
			carried_output_claim = bit_indexed_claim_from_evals(
				output_bit_challenge,
				fused_output.reduced_high_point,
				next_output_weights,
				fused_output.input_evals,
			);
		} else {
			let input_weights = channel.sample_array::<25>();
			let input_claim = bit_indexed_claim_from_evals(
				output_bit_challenge,
				fused_output.reduced_high_point,
				input_weights,
				fused_output.input_evals,
			);

			return Ok(BitIndexedEndpointClaims {
				output_claim,
				input_claim,
			});
		}
	}

	Err(Error::InvalidClaim("trace must contain at least one round"))
}

fn validate_compact_trace(trace: &CompactTrace) -> Result<(), Error> {
	if trace.round_inputs.len() != 24 {
		return Err(Error::InvalidClaim("trace must contain exactly 24 rounds"));
	}

	let n_instances = trace.round_inputs[0].len();
	if !n_instances.is_power_of_two() {
		return Err(Error::InvalidClaim("number of instances must be a power of two"));
	}
	if !trace
		.round_inputs
		.iter()
		.all(|round| round.len() == n_instances)
	{
		return Err(Error::InvalidClaim("all rounds must have the same number of instances"));
	}
	if trace.final_output.len() != n_instances {
		return Err(Error::InvalidClaim("final output must have the same number of instances"));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::arch::{OptimalB128, OptimalPackedB128};
	use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::HasherChallenger};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::trace::compact_trace_from_inputs;

	type F = OptimalB128;
	type P = OptimalPackedB128;
	type StdChallenger = HasherChallenger<sha2::Sha256>;

	#[test]
	fn test_protocol_prove_verify() {
		let mut rng = StdRng::seed_from_u64(10);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output = prove::<P, _>(&trace, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output = verify::<F, _>(&trace, &mut verifier_transcript).unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
	}

	#[test]
	fn test_protocol_rejects_corrupted_trace() {
		let mut rng = StdRng::seed_from_u64(11);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);
		let mut corrupted_trace = trace.clone();
		corrupted_trace.round_inputs[5][0][0] ^= 1;

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove::<P, _>(&corrupted_trace, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(verify::<F, _>(&trace, &mut verifier_transcript).is_err());
	}

	#[test]
	fn test_protocol_rejects_corrupted_final_output() {
		let mut rng = StdRng::seed_from_u64(12);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);
		let mut corrupted_trace = trace.clone();
		corrupted_trace.final_output[0][0] ^= 1;

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove::<P, _>(&trace, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(verify::<F, _>(&corrupted_trace, &mut verifier_transcript).is_err());
	}
}
