// Copyright 2026 The Binius Developers

use std::array;

use binius_field::{BinaryField, Field, PackedField};
use binius_ip::{channel::IPVerifierChannel, mlecheck, sumcheck::RoundCoeffs};
use binius_ip_prover::{
	channel::IPProverChannel,
	sumcheck::{
		Error as SumcheckError,
		common::{MleCheckProver, SumcheckProver},
		gruen32::Gruen32,
		prove_single_mlecheck,
	},
};
use rayon::prelude::*;

use crate::{
	BIT_INDEX_SIZE, BitIndexedMixedClaim, Error, LOG_BIT_INDEX_VARS,
	chi_iota::{
		compose_chi_iota_from_low_vectors, compose_chi_iota_infinity_from_low_vectors,
		evaluate_lane_low_vectors, evaluate_lane_low_vectors_from_words,
		fold_block_tables_inplace, fold_low_vectors, interpolate_round_coeffs,
		lane_block_tables, words_to_block_tables,
	},
	linear_round::{coeff_from_count, linear_recipe_static},
	rotation::bit_lagrange_weights,
	trace::LaneTables,
};

/// Input to the fused `chi+iota+theta+rho+pi` round reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusedRoundReduction<F> {
	/// Bit-indexed mixed claim on the round output lanes.
	pub output_claim: BitIndexedMixedClaim<F>,
	/// Keccak round index.
	pub round: usize,
}

/// Output of the fused round reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusedRoundOutput<F> {
	/// Reduced point for the remaining high instance variables.
	pub reduced_high_point: Vec<F>,
	/// Evaluations of the 25 folded input lanes at `reduced_high_point`.
	pub input_evals: [F; 25],
}

/// Prove one fused `chi+iota+theta+rho+pi` round reduction.
pub fn prove_round<P, Channel>(
	input: &LaneTables<P>,
	reduction: &FusedRoundReduction<P::Scalar>,
	channel: &mut Channel,
) -> Result<FusedRoundOutput<P::Scalar>, Error>
where
	P: PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_reduction(input, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Fused Round Prove",
		phase = "keccak_fused_prove",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.high_point.len()
	)
	.entered();

	let bit_weights = bit_lagrange_weights(reduction.output_claim.bit_challenge);
	let prover: FusedRoundProver<P> = FusedRoundProver::new(
		lane_block_tables(input),
		bit_weights,
		reduction.output_claim.lane_weights,
		reduction.round,
		reduction.output_claim.high_point.clone(),
		reduction.output_claim.mixed_eval,
	)?;
	let proof_output = prove_single_mlecheck(prover, channel)?;
	let input_evals: [P::Scalar; 25] = proof_output
		.multilinear_evals
		.try_into()
		.map_err(|_| Error::InvalidClaim("expected 25 folded input evaluations"))?;
	let mut reduced_high_point = proof_output.challenges;
	reduced_high_point.reverse();

	Ok(FusedRoundOutput {
		reduced_high_point,
		input_evals,
	})
}

/// Verify one fused `chi+iota+theta+rho+pi` round reduction.
pub fn verify_round<F, P, Channel>(
	input: &LaneTables<P>,
	reduction: &FusedRoundReduction<F>,
	channel: &mut Channel,
) -> Result<FusedRoundOutput<F>, Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	validate_reduction(input, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Fused Round Verify",
		phase = "keccak_fused_verify",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.high_point.len()
	)
	.entered();

	let mlecheck_output = mlecheck::verify(
		&reduction.output_claim.high_point,
		2,
		reduction.output_claim.mixed_eval,
		channel,
	)?;
	let mut reduced_high_point = mlecheck_output.challenges;
	reduced_high_point.reverse();
	let bit_weights = bit_lagrange_weights(reduction.output_claim.bit_challenge);
	let input_low_vectors = evaluate_lane_low_vectors(input, &reduced_high_point);
	let input_evals = fold_low_vectors(&input_low_vectors, &bit_weights);
	let pre_chi_low_vectors = apply_linear_recipe_to_low_vectors(&input_low_vectors);
	let fused_eval = compose_chi_iota_from_low_vectors(
		&pre_chi_low_vectors,
		&reduction.output_claim.lane_weights,
		reduction.round,
		&bit_weights,
	);
	channel.assert_zero(fused_eval - mlecheck_output.eval)?;

	Ok(FusedRoundOutput {
		reduced_high_point,
		input_evals,
	})
}

/// Prove one fused round from word-level input data.
///
/// Converts the `u64` words to block tables on the fly, avoiding the need
/// for pre-expanded `LaneTables`.
pub fn prove_round_from_words<P, Channel>(
	input_words: &[[u64; 25]],
	reduction: &FusedRoundReduction<P::Scalar>,
	channel: &mut Channel,
) -> Result<FusedRoundOutput<P::Scalar>, Error>
where
	P: PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_reduction_from_words(input_words, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Fused Round Prove",
		phase = "keccak_fused_prove",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.high_point.len()
	)
	.entered();

	let bit_weights = bit_lagrange_weights(reduction.output_claim.bit_challenge);
	let prover: FusedRoundProver<P> = FusedRoundProver::new(
		words_to_block_tables(input_words),
		bit_weights,
		reduction.output_claim.lane_weights,
		reduction.round,
		reduction.output_claim.high_point.clone(),
		reduction.output_claim.mixed_eval,
	)?;
	let proof_output = prove_single_mlecheck(prover, channel)?;
	let input_evals: [P::Scalar; 25] = proof_output
		.multilinear_evals
		.try_into()
		.map_err(|_| Error::InvalidClaim("expected 25 folded input evaluations"))?;
	let mut reduced_high_point = proof_output.challenges;
	reduced_high_point.reverse();

	Ok(FusedRoundOutput {
		reduced_high_point,
		input_evals,
	})
}

/// Verify one fused round from word-level input data.
///
/// Computes multilinear evaluations directly from `u64` words without
/// expanding to `LaneTables`.
pub fn verify_round_from_words<F, Channel>(
	input_words: &[[u64; 25]],
	reduction: &FusedRoundReduction<F>,
	channel: &mut Channel,
) -> Result<FusedRoundOutput<F>, Error>
where
	F: BinaryField,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	validate_reduction_from_words(input_words, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Fused Round Verify",
		phase = "keccak_fused_verify",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.high_point.len()
	)
	.entered();

	let mlecheck_output = mlecheck::verify(
		&reduction.output_claim.high_point,
		2,
		reduction.output_claim.mixed_eval,
		channel,
	)?;
	let mut reduced_high_point = mlecheck_output.challenges;
	reduced_high_point.reverse();
	let bit_weights = bit_lagrange_weights(reduction.output_claim.bit_challenge);
	let input_low_vectors =
		evaluate_lane_low_vectors_from_words(input_words, &reduced_high_point);
	let input_evals = fold_low_vectors(&input_low_vectors, &bit_weights);
	let pre_chi_low_vectors = apply_linear_recipe_to_low_vectors(&input_low_vectors);
	let fused_eval = compose_chi_iota_from_low_vectors(
		&pre_chi_low_vectors,
		&reduction.output_claim.lane_weights,
		reduction.round,
		&bit_weights,
	);
	channel.assert_zero(fused_eval - mlecheck_output.eval)?;

	Ok(FusedRoundOutput {
		reduced_high_point,
		input_evals,
	})
}

fn validate_reduction_from_words<F: BinaryField>(
	input_words: &[[u64; 25]],
	reduction: &FusedRoundReduction<F>,
) -> Result<(), Error> {
	if reduction.round >= 24 {
		return Err(Error::InvalidRound(reduction.round));
	}

	let expected_n_instances = 1usize << reduction.output_claim.high_point.len();
	if input_words.len() != expected_n_instances {
		return Err(Error::InvalidClaim(
			"input word count must match 2^high_point.len()",
		));
	}

	Ok(())
}

fn validate_reduction<F: BinaryField, P: PackedField<Scalar = F>>(
	input: &LaneTables<P>,
	reduction: &FusedRoundReduction<F>,
) -> Result<(), Error> {
	if reduction.round >= 24 {
		return Err(Error::InvalidRound(reduction.round));
	}

	let expected_log_len = reduction.output_claim.high_point.len() + LOG_BIT_INDEX_VARS;
	if !input
		.iter()
		.all(|lane_table| lane_table.log_len() == expected_log_len)
	{
		return Err(Error::InvalidClaim(
			"input lane dimensions must match the bit-indexed high-point length",
		));
	}

	Ok(())
}

fn apply_linear_recipe_to_low_vectors<F: Field>(
	input_low_vectors: &[[F; BIT_INDEX_SIZE]; 25],
) -> [[F; BIT_INDEX_SIZE]; 25] {
	let static_recipe = linear_recipe_static();
	array::from_fn(|output_lane| {
		let mut pre_chi = [F::ZERO; BIT_INDEX_SIZE];
		for &(rv_idx, count) in &static_recipe.recipe_counts[output_lane] {
			let coeff = coeff_from_count::<F>(count);
			if coeff == F::ZERO {
				continue;
			}
			let rv = &static_recipe.rot_views[rv_idx];
			for b in 0..BIT_INDEX_SIZE {
				let input_bit = (b + BIT_INDEX_SIZE - rv.rot as usize) % BIT_INDEX_SIZE;
				pre_chi[b] += coeff * input_low_vectors[rv.lane][input_bit];
			}
		}
		pre_chi
	})
}

fn apply_linear_recipe_to_blocks<F: Field>(
	input_blocks: &[[F; BIT_INDEX_SIZE]; 25],
) -> [[F; BIT_INDEX_SIZE]; 25] {
	apply_linear_recipe_to_low_vectors(input_blocks)
}

struct FusedRoundProver<P: PackedField> {
	input_blocks: [Vec<[P::Scalar; BIT_INDEX_SIZE]>; 25],
	bit_weights: [P::Scalar; BIT_INDEX_SIZE],
	lane_weights: [P::Scalar; 25],
	last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
	round: usize,
	gruen32: Gruen32<P>,
}

impl<F: Field, P: PackedField<Scalar = F>> FusedRoundProver<P> {
	fn new(
		input_blocks: [Vec<[F; BIT_INDEX_SIZE]>; 25],
		bit_weights: [F; BIT_INDEX_SIZE],
		lane_weights: [F; 25],
		round: usize,
		eval_point: Vec<F>,
		mixed_eval: F,
	) -> Result<Self, SumcheckError> {
		let expected_len = 1usize << eval_point.len();
		if input_blocks
			.iter()
			.any(|blocks| blocks.len() != expected_len)
		{
			return Err(SumcheckError::MultilinearSizeMismatch);
		}

		let gruen32 = Gruen32::new(&eval_point);

		Ok(Self {
			input_blocks,
			bit_weights,
			lane_weights,
			last_coeffs_or_eval: RoundCoeffsOrEval::Eval(mixed_eval),
			round,
			gruen32,
		})
	}
}

impl<F: Field, P: PackedField<Scalar = F>> SumcheckProver<F> for FusedRoundProver<P> {
	fn n_vars(&self) -> usize {
		self.gruen32.n_vars_remaining()
	}

	fn n_claims(&self) -> usize {
		1
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, SumcheckError> {
		let last_eval = match self.last_coeffs_or_eval {
			RoundCoeffsOrEval::Eval(eval) => eval,
			RoundCoeffsOrEval::Coeffs(_) => return Err(SumcheckError::ExpectedFold),
		};
		let n_vars_remaining = self.gruen32.n_vars_remaining();
		let alpha = self.gruen32.next_coordinate();
		let split = 1usize << n_vars_remaining.saturating_sub(1);
		let eq_scalars: Vec<F> =
			self.gruen32.eq_expansion().iter_scalars().take(split).collect();

		let (y_1, y_inf) = eq_scalars
			.into_par_iter()
			.enumerate()
			.map(|(i, eq_i)| {
				let input_1: [_; 25] =
					array::from_fn(|lane| self.input_blocks[lane][split + i]);
				let pre_chi_1 = apply_linear_recipe_to_blocks(&input_1);

				let input_inf: [_; 25] = array::from_fn(|lane| {
					array::from_fn(|bit| {
						self.input_blocks[lane][i][bit]
							+ self.input_blocks[lane][split + i][bit]
					})
				});
				let pre_chi_inf = apply_linear_recipe_to_blocks(&input_inf);

				let contrib_1 = eq_i
					* compose_chi_iota_from_low_vectors(
						&pre_chi_1,
						&self.lane_weights,
						self.round,
						&self.bit_weights,
					);
				let contrib_inf = eq_i
					* compose_chi_iota_infinity_from_low_vectors(
						&pre_chi_inf,
						&self.lane_weights,
						&self.bit_weights,
					);
				(contrib_1, contrib_inf)
			})
			.reduce(
				|| (F::ZERO, F::ZERO),
				|(a1, ai), (b1, bi)| (a1 + b1, ai + bi),
			);

		let round_coeffs = interpolate_round_coeffs(last_eval, alpha, y_1, y_inf);
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), SumcheckError> {
		let coeffs = match &self.last_coeffs_or_eval {
			RoundCoeffsOrEval::Coeffs(coeffs) => coeffs,
			RoundCoeffsOrEval::Eval(_) => return Err(SumcheckError::ExpectedExecute),
		};

		fold_block_tables_inplace(&mut self.input_blocks, challenge);
		self.gruen32.fold(challenge);
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Eval(coeffs.evaluate(challenge));
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, SumcheckError> {
		if self.gruen32.n_vars_remaining() > 0 {
			return Err(match self.last_coeffs_or_eval {
				RoundCoeffsOrEval::Coeffs(_) => SumcheckError::ExpectedFold,
				RoundCoeffsOrEval::Eval(_) => SumcheckError::ExpectedExecute,
			});
		}

		Ok(self
			.input_blocks
			.into_iter()
			.map(|blocks| {
				std::iter::zip(&blocks[0], &self.bit_weights)
					.fold(F::ZERO, |acc, (val, weight)| acc + *val * *weight)
			})
			.collect())
	}
}

impl<F: Field, P: PackedField<Scalar = F>> MleCheckProver<F> for FusedRoundProver<P> {
	fn eval_point(&self) -> &[F] {
		let n = self.gruen32.n_vars_remaining();
		&self.gruen32.eval_point()[..n]
	}
}

#[derive(Debug, Clone)]
enum RoundCoeffsOrEval<F: Field> {
	Coeffs(RoundCoeffs<F>),
	Eval(F),
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::{
		Random,
		arch::{OptimalB128, OptimalPackedB128},
	};
	use binius_math::test_utils::random_scalars;
	use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::HasherChallenger};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{bit_indexed_lane_claim, trace::trace_from_inputs};

	type F = OptimalB128;
	type P = OptimalPackedB128;
	type StdChallenger = HasherChallenger<sha2::Sha256>;

	#[test]
	fn test_fused_round_prove_verify() {
		let mut rng = StdRng::seed_from_u64(20);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let output = trace.round_output(0);

		let bit_challenge = F::random(&mut rng);
		let high_point = random_scalars::<F>(&mut rng, 1);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = bit_indexed_lane_claim(output, bit_challenge, &high_point, lane_weights);
		let reduction = FusedRoundReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove_round::<P, _>(&trace.rounds[0].input, &reduction, &mut prover_transcript)
				.unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output = verify_round::<F, P, _>(
			&trace.rounds[0].input,
			&reduction,
			&mut verifier_transcript,
		)
		.unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
	}

	#[test]
	fn test_fused_round_rejects_corrupted_input() {
		let mut rng = StdRng::seed_from_u64(21);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let output = trace.round_output(0);

		let mut corrupted_input = trace.rounds[0].input.clone();
		let current = corrupted_input[0].get(0);
		let flipped = if current == F::ZERO { F::ONE } else { F::ZERO };
		corrupted_input[0].set(0, flipped);

		let bit_challenge = F::random(&mut rng);
		let high_point = random_scalars::<F>(&mut rng, 1);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = bit_indexed_lane_claim(output, bit_challenge, &high_point, lane_weights);
		let reduction = FusedRoundReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_round::<P, _>(&corrupted_input, &reduction, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(verify_round::<F, P, _>(
			&trace.rounds[0].input,
			&reduction,
			&mut verifier_transcript,
		)
		.is_err());
	}

	#[test]
	fn test_apply_linear_recipe_matches_explicit_pre_chi() {
		let mut rng = StdRng::seed_from_u64(22);
		let input_state = array::from_fn(|_| rng.random::<u64>());
		let trace = trace_from_inputs::<P>(&[input_state]);
		let input_blocks = lane_block_tables::<F, P>(&trace.rounds[0].input);
		let pre_chi_blocks = lane_block_tables::<F, P>(&trace.rounds[0].pre_chi);

		let input_single: [_; 25] = array::from_fn(|lane| input_blocks[lane][0]);
		let computed_pre_chi = apply_linear_recipe_to_blocks(&input_single);
		let expected_pre_chi: [_; 25] = array::from_fn(|lane| pre_chi_blocks[lane][0]);

		assert_eq!(computed_pre_chi, expected_pre_chi);
	}
}
