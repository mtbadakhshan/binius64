// Copyright 2026 The Binius Developers

use binius_field::{Field, PackedField};
use binius_ip::channel::IPVerifierChannel;
use binius_ip_prover::channel::IPProverChannel;

use crate::{
	ChiIotaReduction, EndpointClaims, Error, FullTrace, LinearRoundReduction, chi_iota,
	linear_round, mixed_claim_from_evals, mixed_lane_claim,
};

/// Prove the full standalone 24-round KeccakCheck over an explicit public trace.
pub fn prove<P, Channel>(
	trace: &FullTrace<P>,
	channel: &mut Channel,
) -> Result<EndpointClaims<P::Scalar>, Error>
where
	P: PackedField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_trace(trace)?;
	let n_instances = 1usize << trace.rounds[0].input[0].log_len().saturating_sub(6);
	let _prove_guard = tracing::info_span!(
		"KeccakCheck Prove",
		operation = "keccak_check_prove",
		perfetto_category = "operation",
		n_rounds = trace.rounds.len(),
		n_instances
	)
	.entered();

	let output_round = trace
		.rounds
		.last()
		.ok_or(Error::InvalidClaim("trace must contain 24 rounds"))?;
	let output_point = channel.sample_many(output_round.output[0].log_len());
	let output_weights = channel.sample_array::<25>();
	let output_claim = mixed_lane_claim(&output_round.output, &output_point, output_weights);
	let mut carried_output_claim = output_claim.clone();

	for round in (0..trace.rounds.len()).rev() {
		let _round_guard = tracing::info_span!(
			"[phase] Keccak Round Prove",
			phase = "keccak_round_prove",
			perfetto_category = "phase",
			round
		)
		.entered();
		let chi_iota_output = chi_iota::prove_round::<P, _>(
			&trace.rounds[round].pre_chi,
			&ChiIotaReduction {
				output_claim: carried_output_claim,
				round,
			},
			channel,
		)?;

		let pre_chi_weights = channel.sample_array::<25>();
		let pre_chi_claim = mixed_claim_from_evals(
			chi_iota_output.reduced_point,
			pre_chi_weights,
			chi_iota_output.pre_chi_evals,
		);
		let linear_output = linear_round::prove_round::<P, _>(
			&trace.rounds[round].input,
			&LinearRoundReduction { pre_chi_claim },
			channel,
		)?;

		if round > 0 {
			let next_output_weights = channel.sample_array::<25>();
			carried_output_claim = mixed_claim_from_evals(
				linear_output.reduced_point,
				next_output_weights,
				linear_output.input_evals,
			);
		} else {
			let input_weights = channel.sample_array::<25>();
			let input_claim = mixed_claim_from_evals(
				linear_output.reduced_point,
				input_weights,
				linear_output.input_evals,
			);

			return Ok(EndpointClaims {
				output_claim,
				input_claim,
			});
		}
	}

	Err(Error::InvalidClaim("trace must contain at least one round"))
}

/// Verify the full standalone 24-round KeccakCheck over an explicit public trace.
pub fn verify<F, P, Channel>(
	trace: &FullTrace<P>,
	channel: &mut Channel,
) -> Result<EndpointClaims<F>, Error>
where
	F: Field,
	P: PackedField<Scalar = F>,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	validate_trace(trace)?;
	let n_instances = 1usize << trace.rounds[0].input[0].log_len().saturating_sub(6);
	let _verify_guard = tracing::info_span!(
		"KeccakCheck Verify",
		operation = "keccak_check_verify",
		perfetto_category = "operation",
		n_rounds = trace.rounds.len(),
		n_instances
	)
	.entered();

	let output_round = trace
		.rounds
		.last()
		.ok_or(Error::InvalidClaim("trace must contain 24 rounds"))?;
	let output_point = channel.sample_many(output_round.output[0].log_len());
	let output_weights = channel.sample_array::<25>();
	let output_claim = mixed_lane_claim(&output_round.output, &output_point, output_weights);
	let mut carried_output_claim = output_claim.clone();

	for round in (0..trace.rounds.len()).rev() {
		let _round_guard = tracing::info_span!(
			"[phase] Keccak Round Verify",
			phase = "keccak_round_verify",
			perfetto_category = "phase",
			round
		)
		.entered();
		let chi_iota_output = chi_iota::verify_round(
			&ChiIotaReduction {
				output_claim: carried_output_claim,
				round,
			},
			channel,
		)?;

		let pre_chi_weights = channel.sample_array::<25>();
		let pre_chi_claim = mixed_claim_from_evals(
			chi_iota_output.reduced_point,
			pre_chi_weights,
			chi_iota_output.pre_chi_evals,
		);
		let linear_output = linear_round::verify_round::<F, P, _>(
			&trace.rounds[round].input,
			&LinearRoundReduction { pre_chi_claim },
			channel,
		)?;

		if round > 0 {
			let next_output_weights = channel.sample_array::<25>();
			carried_output_claim = mixed_claim_from_evals(
				linear_output.reduced_point,
				next_output_weights,
				linear_output.input_evals,
			);
		} else {
			let input_weights = channel.sample_array::<25>();
			let input_claim = mixed_claim_from_evals(
				linear_output.reduced_point,
				input_weights,
				linear_output.input_evals,
			);

			return Ok(EndpointClaims {
				output_claim,
				input_claim,
			});
		}
	}

	Err(Error::InvalidClaim("trace must contain at least one round"))
}

fn validate_trace<P: PackedField>(trace: &FullTrace<P>) -> Result<(), Error> {
	if trace.rounds.len() != 24 {
		return Err(Error::InvalidClaim("trace must contain exactly 24 rounds"));
	}

	let log_len = trace.rounds[0].input[0].log_len();
	if !trace.rounds.iter().all(|round| {
		round.input.iter().all(|lane| lane.log_len() == log_len)
			&& round.pre_chi.iter().all(|lane| lane.log_len() == log_len)
			&& round.output.iter().all(|lane| lane.log_len() == log_len)
	}) {
		return Err(Error::InvalidClaim("all trace tables must share the same dimension"));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::{
		Field,
		arch::{OptimalB128, OptimalPackedB128},
	};
	use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::HasherChallenger};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::trace::trace_from_inputs;

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
		let trace = trace_from_inputs::<P>(&inputs);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output = prove(&trace, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output = verify::<F, P, _>(&trace, &mut verifier_transcript).unwrap();
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
		let trace = trace_from_inputs::<P>(&inputs);
		let mut corrupted_trace = trace.clone();
		let current = corrupted_trace.rounds[5].pre_chi[0].get(0);
		let flipped = if current == F::ZERO { F::ONE } else { F::ZERO };
		corrupted_trace.rounds[5].pre_chi[0].set(0, flipped);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove(&corrupted_trace, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(verify::<F, P, _>(&trace, &mut verifier_transcript).is_err());
	}
}
