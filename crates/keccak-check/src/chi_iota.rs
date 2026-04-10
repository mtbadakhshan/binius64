// Copyright 2026 The Binius Developers

use std::array;

use binius_field::{Field, PackedField};
use binius_ip::{channel::IPVerifierChannel, mlecheck};
use binius_ip_prover::{
	channel::IPProverChannel,
	sumcheck::{prove_single_mlecheck, quadratic_mle::QuadraticMleCheckProver},
};

use crate::{
	Error, MixedClaim,
	rotation::round_constant_eval,
	trace::{LaneTables, idx},
};

/// One-round `chi+iota` reduction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiIotaReduction<F> {
	/// Mixed claim on the round output lanes.
	pub output_claim: MixedClaim<F>,
	/// Keccak round index.
	pub round: usize,
}

/// Output of a one-round `chi+iota` reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiIotaRoundOutput<F> {
	/// Reduced point for the pre-chi lane evaluations, in low-to-high variable order.
	pub reduced_point: Vec<F>,
	/// Claimed evaluations of the 25 pre-chi lane multilinears at `reduced_point`.
	pub pre_chi_evals: [F; 25],
	/// Mixed evaluation of the `chi+iota` composition at `reduced_point`.
	pub reduced_eval: F,
}

/// Run the prover side of one `chi+iota` round reduction.
///
/// # Preconditions
///
/// - `reduction.round < 24`
/// - every lane in `pre_chi` must have the same dimension as `reduction.output_claim.point`
/// - `reduction.output_claim.point.len() >= 6`
pub fn prove_round<P, Channel>(
	pre_chi: &LaneTables<P>,
	reduction: &ChiIotaReduction<P::Scalar>,
	channel: &mut Channel,
) -> Result<ChiIotaRoundOutput<P::Scalar>, Error>
where
	P: PackedField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_reduction(pre_chi, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak ChiIota Prove",
		phase = "keccak_chi_iota_prove",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.point.len()
	)
	.entered();

	let multilinears = array::from_fn(|index| pre_chi[index].clone());

	let lane_weights = reduction.output_claim.lane_weights;
	let packed_lane_weights = array::from_fn(|lane| P::broadcast(lane_weights[lane]));
	let round = reduction.round;
	let eval_point = reduction.output_claim.point.clone();
	let eval_claim = chi_claim_eval(
		reduction.output_claim.mixed_eval,
		&lane_weights,
		round,
		&reduction.output_claim.point,
	);

	let prover = QuadraticMleCheckProver::<P, _, _, 25>::new(
		multilinears,
		move |vals: [P; 25]| compose_chi_packed(vals, &packed_lane_weights),
		move |vals: [P; 25]| compose_chi_infinity_packed(vals, &packed_lane_weights),
		eval_point,
		eval_claim,
	)?;
	let proof_output = prove_single_mlecheck(prover, channel)?;

	let pre_chi_evals = array::from_fn(|lane| proof_output.multilinear_evals[lane]);
	channel.send_many(&pre_chi_evals);

	let mut reduced_point = proof_output.challenges;
	reduced_point.reverse();
	let reduced_eval =
		compose_chi_iota_scalar(&pre_chi_evals, &lane_weights, round, &reduced_point);

	Ok(ChiIotaRoundOutput {
		reduced_point,
		pre_chi_evals,
		reduced_eval,
	})
}

/// Run the verifier side of one `chi+iota` round reduction.
///
/// # Preconditions
///
/// - `reduction.round < 24`
/// - `reduction.output_claim.point.len() >= 6`
pub fn verify_round<F, Channel>(
	reduction: &ChiIotaReduction<F>,
	channel: &mut Channel,
) -> Result<ChiIotaRoundOutput<F>, Error>
where
	F: Field,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	assert!(reduction.round < 24, "precondition: round must be < 24");
	assert!(
		reduction.output_claim.point.len() >= 6,
		"precondition: point must have at least 6 coordinates"
	);
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak ChiIota Verify",
		phase = "keccak_chi_iota_verify",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.point.len()
	)
	.entered();

	let chi_claim = chi_claim_eval(
		reduction.output_claim.mixed_eval,
		&reduction.output_claim.lane_weights,
		reduction.round,
		&reduction.output_claim.point,
	);
	let mlecheck_output = mlecheck::verify(&reduction.output_claim.point, 2, chi_claim, channel)?;
	let pre_chi_evals = channel
		.recv_many(25)?
		.try_into()
		.map_err(|_| Error::InvalidClaim("expected 25 pre-chi evaluations"))?;

	let mut reduced_point = mlecheck_output.challenges;
	reduced_point.reverse();
	let reduced_eval = compose_chi_iota_scalar(
		&pre_chi_evals,
		&reduction.output_claim.lane_weights,
		reduction.round,
		&reduced_point,
	);
	let reduced_chi_eval = chi_claim_eval(
		reduced_eval,
		&reduction.output_claim.lane_weights,
		reduction.round,
		&reduced_point,
	);
	channel.assert_zero(reduced_chi_eval - mlecheck_output.eval)?;

	Ok(ChiIotaRoundOutput {
		reduced_point,
		pre_chi_evals,
		reduced_eval,
	})
}

fn validate_reduction<P: PackedField>(
	pre_chi: &LaneTables<P>,
	reduction: &ChiIotaReduction<P::Scalar>,
) -> Result<(), Error> {
	if reduction.round >= 24 {
		return Err(Error::InvalidRound(reduction.round));
	}

	if reduction.output_claim.point.len() < 6 {
		return Err(Error::InvalidClaim("point must have at least 6 coordinates"));
	}

	if !pre_chi
		.iter()
		.all(|lane_table| lane_table.log_len() == reduction.output_claim.point.len())
	{
		return Err(Error::InvalidClaim("point length must match all pre-chi lane dimensions"));
	}

	Ok(())
}

fn compose_chi_packed<P: PackedField>(vals: [P; 25], lane_weights: &[P; 25]) -> P {
	(0..5)
		.flat_map(|y| (0..5).map(move |x| (x, y)))
		.fold(P::zero(), |acc, (x, y)| {
			let a = vals[idx(x, y)];
			let b = vals[idx((x + 1) % 5, y)];
			let c = vals[idx((x + 2) % 5, y)];
			let weight = lane_weights[idx(x, y)];

			acc + weight * (a + c + b * c)
		})
}

fn compose_chi_infinity_packed<P: PackedField>(vals: [P; 25], lane_weights: &[P; 25]) -> P {
	(0..5)
		.flat_map(|y| (0..5).map(move |x| (x, y)))
		.fold(P::zero(), |acc, (x, y)| {
			let b = vals[idx((x + 1) % 5, y)];
			let c = vals[idx((x + 2) % 5, y)];
			let weight = lane_weights[idx(x, y)];
			acc + weight * b * c
		})
}

fn chi_claim_eval<F: Field>(mixed_eval: F, lane_weights: &[F; 25], round: usize, point: &[F]) -> F {
	mixed_eval - lane_weights[idx(0, 0)] * round_constant_eval(round, point)
}

fn compose_chi_iota_scalar<F: Field>(
	pre_chi_evals: &[F; 25],
	lane_weights: &[F; 25],
	round: usize,
	point: &[F],
) -> F {
	let round_constant_eval = round_constant_eval(round, point);

	(0..5)
		.flat_map(|y| (0..5).map(move |x| (x, y)))
		.fold(F::ZERO, |acc, (x, y)| {
			let a = pre_chi_evals[idx(x, y)];
			let b = pre_chi_evals[idx((x + 1) % 5, y)];
			let c = pre_chi_evals[idx((x + 2) % 5, y)];
			let weight = lane_weights[idx(x, y)];
			let iota_term = if x == 0 && y == 0 {
				weight * round_constant_eval
			} else {
				F::ZERO
			};

			acc + weight * (a + c + b * c) + iota_term
		})
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::{
		Field, Random,
		arch::{OptimalB128, OptimalPackedB128},
	};
	use binius_math::{
		multilinear::evaluate::evaluate,
		test_utils::{index_to_hypercube_point, random_scalars},
	};
	use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::HasherChallenger};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{mixed_lane_claim, trace::trace_from_inputs};

	type F = OptimalB128;
	type P = OptimalPackedB128;
	type StdChallenger = HasherChallenger<sha2::Sha256>;

	#[test]
	fn test_one_round_chi_iota_prove_verify() {
		let mut rng = StdRng::seed_from_u64(4);
		let input_state = array::from_fn(|_| rng.random::<u64>());
		let trace = trace_from_inputs::<P>(&[input_state]);
		let round_trace = &trace.rounds[0];

		let point = random_scalars::<F>(&mut rng, 6);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = mixed_lane_claim(&round_trace.output, &point, lane_weights);
		let reduction = ChiIotaReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove_round::<P, _>(&round_trace.pre_chi, &reduction, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output = verify_round(&reduction, &mut verifier_transcript).unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
		let expected_pre_chi = array::from_fn(|lane| {
			evaluate(&round_trace.pre_chi[lane], &prover_output.reduced_point)
		});
		assert_eq!(prover_output.pre_chi_evals, expected_pre_chi);
	}

	#[test]
	fn test_one_round_chi_iota_rejects_corrupted_pre_chi() {
		let mut rng = StdRng::seed_from_u64(5);
		let input_state = array::from_fn(|_| rng.random::<u64>());
		let trace = trace_from_inputs::<P>(&[input_state]);
		let round_trace = &trace.rounds[0];

		let mut corrupted_pre_chi = round_trace.pre_chi.clone();
		let current = corrupted_pre_chi[0].get(0);
		let flipped = if current == F::ZERO { F::ONE } else { F::ZERO };
		corrupted_pre_chi[0].set(0, flipped);

		let point = random_scalars::<F>(&mut rng, 6);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = mixed_lane_claim(&round_trace.output, &point, lane_weights);
		let reduction = ChiIotaReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_round::<P, _>(&corrupted_pre_chi, &reduction, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(verify_round(&reduction, &mut verifier_transcript).is_err());
	}

	#[test]
	fn test_one_round_chi_iota_boolean_point() {
		let mut rng = StdRng::seed_from_u64(6);
		let input_state = array::from_fn(|_| rng.random::<u64>());
		let trace = trace_from_inputs::<P>(&[input_state]);
		let round_trace = &trace.rounds[0];
		let point = index_to_hypercube_point::<F>(6, 17);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = mixed_lane_claim(&round_trace.output, &point, lane_weights);
		let reduction = ChiIotaReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove_round::<P, _>(&round_trace.pre_chi, &reduction, &mut prover_transcript).unwrap();

		assert_eq!(
			prover_output.reduced_eval,
			compose_chi_iota_scalar(
				&prover_output.pre_chi_evals,
				&reduction.output_claim.lane_weights,
				0,
				&prover_output.reduced_point
			)
		);
	}
}
