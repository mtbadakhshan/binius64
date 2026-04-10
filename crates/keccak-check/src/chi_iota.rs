// Copyright 2026 The Binius Developers

use std::array;

use binius_field::{BinaryField, Field, PackedField};
use binius_ip::{channel::IPVerifierChannel, mlecheck, sumcheck::RoundCoeffs};
use binius_ip_prover::{
	channel::IPProverChannel,
	sumcheck::{
		Error as SumcheckError,
		common::{MleCheckProver, SumcheckProver},
		prove_single_mlecheck,
	},
};
use binius_math::multilinear::eq::eq_ind_partial_eval_scalars;

use crate::{
	BIT_INDEX_SIZE, BitIndexedMixedClaim, Error, LOG_BIT_INDEX_VARS,
	rotation::{bit_lagrange_weights, round_constant_from_bit_weights},
	trace::{LaneTables, idx},
};

/// One-round `chi+iota` reduction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiIotaReduction<F> {
	/// Bit-indexed mixed claim on the round output lanes.
	pub output_claim: BitIndexedMixedClaim<F>,
	/// Keccak round index.
	pub round: usize,
}

/// Output of a one-round `chi+iota` reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiIotaRoundOutput<F> {
	/// Reduced point for the remaining high instance variables.
	pub reduced_high_point: Vec<F>,
	/// Claimed evaluations of the 25 folded pre-chi lane multilinears at `reduced_high_point`.
	pub pre_chi_evals: [F; 25],
	/// Mixed output evaluation at `reduced_high_point` under the current output weights.
	pub reduced_eval: F,
}

/// Run the prover side of one `chi+iota` round reduction.
///
/// # Preconditions
///
/// - `reduction.round < 24`
/// - every lane in `output` and `pre_chi` must have the same dimension
/// - each lane must have `LOG_BIT_INDEX_VARS + reduction.output_claim.high_point.len()` variables
pub fn prove_round<P, Channel>(
	output: &LaneTables<P>,
	pre_chi: &LaneTables<P>,
	reduction: &ChiIotaReduction<P::Scalar>,
	channel: &mut Channel,
) -> Result<ChiIotaRoundOutput<P::Scalar>, Error>
where
	P: PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_reduction(output, pre_chi, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak ChiIota Prove",
		phase = "keccak_chi_iota_prove",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.high_point.len()
	)
	.entered();

	let bit_weights = bit_lagrange_weights(reduction.output_claim.bit_challenge);
	let prover = ChiBitIndexedProver::new(
		lane_block_tables(output),
		lane_block_tables(pre_chi),
		bit_weights,
		reduction.output_claim.lane_weights,
		reduction.round,
		reduction.output_claim.high_point.clone(),
	)?;
	let proof_output = prove_single_mlecheck(prover, channel)?;
	let pre_chi_evals: [P::Scalar; 25] = proof_output
		.multilinear_evals
		.try_into()
		.map_err(|_| Error::InvalidClaim("expected 25 folded pre-chi evaluations"))?;
	let mut reduced_high_point = proof_output.challenges;
	reduced_high_point.reverse();
	let output_low_vectors = evaluate_lane_low_vectors(output, &reduced_high_point);
	let reduced_eval = mixed_output_from_low_vectors(
		&output_low_vectors,
		&reduction.output_claim.lane_weights,
		&bit_weights,
	);

	Ok(ChiIotaRoundOutput {
		reduced_high_point,
		pre_chi_evals,
		reduced_eval,
	})
}

/// Run the verifier side of one `chi+iota` round reduction.
///
/// # Preconditions
///
/// - `reduction.round < 24`
/// - the explicit output/pre-chi tables must match `reduction.output_claim.high_point.len() + 6`
pub fn verify_round<F, P, Channel>(
	output: &LaneTables<P>,
	pre_chi: &LaneTables<P>,
	reduction: &ChiIotaReduction<F>,
	channel: &mut Channel,
) -> Result<ChiIotaRoundOutput<F>, Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	assert!(reduction.round < 24, "precondition: round must be < 24");
	validate_reduction(output, pre_chi, reduction)?;
	validate_output_claim_against_tables(output, reduction)?;
	verify_round_assuming_valid_output_claim(output, pre_chi, reduction, channel)
}

/// Verify one `chi+iota` round assuming the enclosing protocol has already established that
/// `reduction.output_claim` matches `output`.
///
/// This is only sound when the caller derives `reduction.output_claim` itself from prior verified
/// reductions and separately checks explicit round chaining.
pub(crate) fn verify_round_with_protocol_validated_output_claim<F, P, Channel>(
	output: &LaneTables<P>,
	pre_chi: &LaneTables<P>,
	reduction: &ChiIotaReduction<F>,
	channel: &mut Channel,
) -> Result<ChiIotaRoundOutput<F>, Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	assert!(reduction.round < 24, "precondition: round must be < 24");
	validate_reduction(output, pre_chi, reduction)?;
	verify_round_assuming_valid_output_claim(output, pre_chi, reduction, channel)
}

fn validate_output_claim_against_tables<F: BinaryField, P: PackedField<Scalar = F>>(
	output: &LaneTables<P>,
	reduction: &ChiIotaReduction<F>,
) -> Result<(), Error> {
	let expected_output_claim = crate::bit_indexed_lane_claim(
		output,
		reduction.output_claim.bit_challenge,
		&reduction.output_claim.high_point,
		reduction.output_claim.lane_weights,
	);
	if reduction.output_claim != expected_output_claim {
		return Err(Error::InvalidClaim("output claim does not match the explicit output tables"));
	}

	Ok(())
}

fn verify_round_assuming_valid_output_claim<F, P, Channel>(
	output: &LaneTables<P>,
	pre_chi: &LaneTables<P>,
	reduction: &ChiIotaReduction<F>,
	channel: &mut Channel,
) -> Result<ChiIotaRoundOutput<F>, Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak ChiIota Verify",
		phase = "keccak_chi_iota_verify",
		perfetto_category = "phase",
		round = reduction.round,
		n_vars = reduction.output_claim.high_point.len()
	)
	.entered();

	let mlecheck_output =
		mlecheck::verify(&reduction.output_claim.high_point, 2, F::ZERO, channel)?;
	let mut reduced_high_point = mlecheck_output.challenges;
	reduced_high_point.reverse();
	let bit_weights = bit_lagrange_weights(reduction.output_claim.bit_challenge);
	let output_low_vectors = evaluate_lane_low_vectors(output, &reduced_high_point);
	let pre_chi_low_vectors = evaluate_lane_low_vectors(pre_chi, &reduced_high_point);
	let pre_chi_evals = fold_low_vectors(&pre_chi_low_vectors, &bit_weights);
	let output_eval = mixed_output_from_low_vectors(
		&output_low_vectors,
		&reduction.output_claim.lane_weights,
		&bit_weights,
	);
	let reduced_eval = compose_chi_iota_from_low_vectors(
		&pre_chi_low_vectors,
		&reduction.output_claim.lane_weights,
		reduction.round,
		&bit_weights,
	);
	channel.assert_zero(output_eval + reduced_eval - mlecheck_output.eval)?;

	Ok(ChiIotaRoundOutput {
		reduced_high_point,
		pre_chi_evals,
		reduced_eval: output_eval,
	})
}

fn validate_reduction<F: BinaryField, P: PackedField<Scalar = F>>(
	output: &LaneTables<P>,
	pre_chi: &LaneTables<P>,
	reduction: &ChiIotaReduction<F>,
) -> Result<(), Error> {
	if reduction.round >= 24 {
		return Err(Error::InvalidRound(reduction.round));
	}

	let expected_log_len = reduction.output_claim.high_point.len() + LOG_BIT_INDEX_VARS;
	if !output
		.iter()
		.all(|lane_table| lane_table.log_len() == expected_log_len)
	{
		return Err(Error::InvalidClaim(
			"output lane dimensions must match the bit-indexed high-point length",
		));
	}

	if !pre_chi
		.iter()
		.all(|lane_table| lane_table.log_len() == expected_log_len)
	{
		return Err(Error::InvalidClaim(
			"pre-chi lane dimensions must match the bit-indexed high-point length",
		));
	}

	Ok(())
}

fn lane_block_tables<F: Field, P: PackedField<Scalar = F>>(
	lane_tables: &LaneTables<P>,
) -> [Vec<[F; BIT_INDEX_SIZE]>; 25] {
	array::from_fn(|lane| {
		lane_tables[lane]
			.iter_scalars()
			.collect::<Vec<_>>()
			.chunks_exact(BIT_INDEX_SIZE)
			.map(|chunk| {
				chunk
					.try_into()
					.expect("each lane block must contain exactly 64 low-bit evaluations")
			})
			.collect()
	})
}

fn evaluate_lane_low_vectors<F: Field, P: PackedField<Scalar = F>>(
	lane_tables: &LaneTables<P>,
	high_point: &[F],
) -> [[F; BIT_INDEX_SIZE]; 25] {
	let high_eq = if high_point.is_empty() {
		vec![F::ONE]
	} else {
		eq_ind_partial_eval_scalars(high_point)
	};

	array::from_fn(|lane| {
		let mut low_vector = [F::ZERO; BIT_INDEX_SIZE];
		for (instance_index, &instance_weight) in high_eq.iter().enumerate() {
			if instance_weight == F::ZERO {
				continue;
			}

			let block = lane_tables[lane].chunk(LOG_BIT_INDEX_VARS, instance_index);
			for (slot, value) in low_vector.iter_mut().zip(block.iter_scalars()) {
				*slot += instance_weight * value;
			}
		}
		low_vector
	})
}

fn fold_low_vectors<F: Field>(
	lane_low_vectors: &[[F; BIT_INDEX_SIZE]; 25],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> [F; 25] {
	array::from_fn(|lane| dot_64(&lane_low_vectors[lane], bit_weights))
}

fn mixed_output_from_low_vectors<F: Field>(
	output_low_vectors: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	let output_lane_evals = fold_low_vectors(output_low_vectors, bit_weights);
	std::iter::zip(lane_weights, output_lane_evals)
		.fold(F::ZERO, |acc, (weight, eval)| acc + *weight * eval)
}

fn compose_chi_iota_from_low_vectors<F: Field>(
	pre_chi_low_vectors: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	round: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	let round_constant_eval = round_constant_from_bit_weights(round, bit_weights);

	(0..5)
		.flat_map(|y| (0..5).map(move |x| (x, y)))
		.fold(F::ZERO, |acc, (x, y)| {
			let weight = lane_weights[idx(x, y)];
			let chi_eval = std::iter::zip(
				std::iter::zip(
					&pre_chi_low_vectors[idx(x, y)],
					&pre_chi_low_vectors[idx((x + 1) % 5, y)],
				),
				std::iter::zip(&pre_chi_low_vectors[idx((x + 2) % 5, y)], bit_weights),
			)
			.fold(F::ZERO, |bit_acc, ((&a, &b), (&c, &bit_weight))| {
				bit_acc + bit_weight * (a + c + b * c)
			});
			let iota_term = if x == 0 && y == 0 {
				weight * round_constant_eval
			} else {
				F::ZERO
			};

			acc + weight * chi_eval + iota_term
		})
}

fn compose_chi_iota_infinity_from_low_vectors<F: Field>(
	pre_chi_inf_vectors: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	(0..5)
		.flat_map(|y| (0..5).map(move |x| (x, y)))
		.fold(F::ZERO, |acc, (x, y)| {
			let weight = lane_weights[idx(x, y)];
			let bc_eval = std::iter::zip(
				std::iter::zip(
					&pre_chi_inf_vectors[idx((x + 1) % 5, y)],
					&pre_chi_inf_vectors[idx((x + 2) % 5, y)],
				),
				bit_weights,
			)
			.fold(F::ZERO, |bit_acc, ((&b, &c), &bit_weight)| bit_acc + bit_weight * b * c);

			acc + weight * bc_eval
		})
}

fn dot_64<F: Field>(lhs: &[F; BIT_INDEX_SIZE], rhs: &[F; BIT_INDEX_SIZE]) -> F {
	std::iter::zip(lhs, rhs).fold(F::ZERO, |acc, (lhs_i, rhs_i)| acc + *lhs_i * *rhs_i)
}

fn fold_block_tables_inplace<F: Field>(
	lane_blocks: &mut [Vec<[F; BIT_INDEX_SIZE]>; 25],
	challenge: F,
) {
	for lane in lane_blocks {
		let split = lane.len() / 2;
		for i in 0..split {
			let lo = lane[i];
			let hi = lane[split + i];
			lane[i] = array::from_fn(|bit| lo[bit] + challenge * (hi[bit] - lo[bit]));
		}
		lane.truncate(split);
	}
}

fn interpolate_round_coeffs<F: Field>(sum: F, alpha: F, y_1: F, y_inf: F) -> RoundCoeffs<F> {
	let y_0 = (sum - y_1 * alpha) * (F::ONE - alpha).invert_or_zero();
	let c_0 = y_0;
	let c_2 = y_inf;
	let c_1 = y_1 - c_0 - c_2;
	RoundCoeffs(vec![c_0, c_1, c_2])
}

struct ChiBitIndexedProver<F: Field> {
	output_blocks: [Vec<[F; BIT_INDEX_SIZE]>; 25],
	pre_chi_blocks: [Vec<[F; BIT_INDEX_SIZE]>; 25],
	bit_weights: [F; BIT_INDEX_SIZE],
	lane_weights: [F; 25],
	last_coeffs_or_eval: RoundCoeffsOrEval<F>,
	eval_point: Vec<F>,
	round: usize,
	n_vars_remaining: usize,
}

impl<F: Field> ChiBitIndexedProver<F> {
	fn new(
		output_blocks: [Vec<[F; BIT_INDEX_SIZE]>; 25],
		pre_chi_blocks: [Vec<[F; BIT_INDEX_SIZE]>; 25],
		bit_weights: [F; BIT_INDEX_SIZE],
		lane_weights: [F; 25],
		round: usize,
		eval_point: Vec<F>,
	) -> Result<Self, SumcheckError> {
		let expected_len = 1usize << eval_point.len();
		if output_blocks
			.iter()
			.any(|blocks| blocks.len() != expected_len)
			|| pre_chi_blocks
				.iter()
				.any(|blocks| blocks.len() != expected_len)
		{
			return Err(SumcheckError::MultilinearSizeMismatch);
		}

		Ok(Self {
			output_blocks,
			pre_chi_blocks,
			bit_weights,
			lane_weights,
			last_coeffs_or_eval: RoundCoeffsOrEval::Eval(F::ZERO),
			n_vars_remaining: eval_point.len(),
			eval_point,
			round,
		})
	}
}

impl<F: Field> SumcheckProver<F> for ChiBitIndexedProver<F> {
	fn n_vars(&self) -> usize {
		self.n_vars_remaining
	}

	fn n_claims(&self) -> usize {
		1
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, SumcheckError> {
		let last_eval = match self.last_coeffs_or_eval {
			RoundCoeffsOrEval::Eval(eval) => eval,
			RoundCoeffsOrEval::Coeffs(_) => return Err(SumcheckError::ExpectedFold),
		};
		let alpha = self.eval_point[self.n_vars_remaining - 1];
		let split = 1usize << self.n_vars_remaining.saturating_sub(1);
		let eq_expansion = if self.n_vars_remaining <= 1 {
			vec![F::ONE]
		} else {
			eq_ind_partial_eval_scalars(&self.eval_point[..self.n_vars_remaining - 1])
		};
		let mut y_1 = F::ZERO;
		let mut y_inf = F::ZERO;

		for (i, eq_i) in eq_expansion.into_iter().enumerate() {
			let output_1 = array::from_fn(|lane| self.output_blocks[lane][split + i]);
			let pre_chi_1 = array::from_fn(|lane| self.pre_chi_blocks[lane][split + i]);
			let pre_chi_inf = array::from_fn(|lane| {
				array::from_fn(|bit| {
					self.pre_chi_blocks[lane][i][bit] + self.pre_chi_blocks[lane][split + i][bit]
				})
			});

			y_1 += eq_i
				* (mixed_output_from_low_vectors(&output_1, &self.lane_weights, &self.bit_weights)
					+ compose_chi_iota_from_low_vectors(
						&pre_chi_1,
						&self.lane_weights,
						self.round,
						&self.bit_weights,
					));
			y_inf += eq_i
				* compose_chi_iota_infinity_from_low_vectors(
					&pre_chi_inf,
					&self.lane_weights,
					&self.bit_weights,
				);
		}

		let round_coeffs = interpolate_round_coeffs(last_eval, alpha, y_1, y_inf);
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), SumcheckError> {
		let coeffs = match &self.last_coeffs_or_eval {
			RoundCoeffsOrEval::Coeffs(coeffs) => coeffs,
			RoundCoeffsOrEval::Eval(_) => return Err(SumcheckError::ExpectedExecute),
		};

		fold_block_tables_inplace(&mut self.output_blocks, challenge);
		fold_block_tables_inplace(&mut self.pre_chi_blocks, challenge);
		self.n_vars_remaining -= 1;
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Eval(coeffs.evaluate(challenge));
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, SumcheckError> {
		if self.n_vars_remaining > 0 {
			return Err(match self.last_coeffs_or_eval {
				RoundCoeffsOrEval::Coeffs(_) => SumcheckError::ExpectedFold,
				RoundCoeffsOrEval::Eval(_) => SumcheckError::ExpectedExecute,
			});
		}

		Ok(self
			.pre_chi_blocks
			.into_iter()
			.map(|blocks| dot_64(&blocks[0], &self.bit_weights))
			.collect())
	}
}

impl<F: Field> MleCheckProver<F> for ChiBitIndexedProver<F> {
	fn eval_point(&self) -> &[F] {
		&self.eval_point[..self.n_vars_remaining]
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
	fn test_one_round_chi_iota_prove_verify() {
		let mut rng = StdRng::seed_from_u64(4);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let round_trace = &trace.rounds[0];
		let output = trace.round_output(0);

		let bit_challenge = F::random(&mut rng);
		let high_point = random_scalars::<F>(&mut rng, 1);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = bit_indexed_lane_claim(output, bit_challenge, &high_point, lane_weights);
		let reduction = ChiIotaReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove_round::<P, _>(output, &round_trace.pre_chi, &reduction, &mut prover_transcript)
				.unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output = verify_round::<F, P, _>(
			output,
			&round_trace.pre_chi,
			&reduction,
			&mut verifier_transcript,
		)
		.unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
		let bit_weights = bit_lagrange_weights(bit_challenge);
		let expected_pre_chi = fold_low_vectors(
			&evaluate_lane_low_vectors(&round_trace.pre_chi, &prover_output.reduced_high_point),
			&bit_weights,
		);
		assert_eq!(prover_output.pre_chi_evals, expected_pre_chi);
	}

	#[test]
	fn test_one_round_chi_iota_rejects_corrupted_pre_chi() {
		let mut rng = StdRng::seed_from_u64(5);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let round_trace = &trace.rounds[0];
		let output = trace.round_output(0);

		let mut corrupted_pre_chi = round_trace.pre_chi.clone();
		let current = corrupted_pre_chi[0].get(0);
		let flipped = if current == F::ZERO { F::ONE } else { F::ZERO };
		corrupted_pre_chi[0].set(0, flipped);

		let bit_challenge = F::random(&mut rng);
		let high_point = random_scalars::<F>(&mut rng, 1);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = bit_indexed_lane_claim(output, bit_challenge, &high_point, lane_weights);
		let reduction = ChiIotaReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_round::<P, _>(output, &corrupted_pre_chi, &reduction, &mut prover_transcript)
			.unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(
			verify_round::<F, P, _>(
				output,
				&round_trace.pre_chi,
				&reduction,
				&mut verifier_transcript,
			)
			.is_err()
		);
	}

	#[test]
	fn test_one_round_chi_iota_domain_point_matches_folded_output_eval() {
		let mut rng = StdRng::seed_from_u64(6);
		let input_state = array::from_fn(|_| rng.random::<u64>());
		let trace = trace_from_inputs::<P>(&[input_state]);
		let round_trace = &trace.rounds[0];
		let output = trace.round_output(0);
		let bit_challenge = {
			use binius_math::BinarySubspace;
			BinarySubspace::<F>::with_dim(LOG_BIT_INDEX_VARS)
				.iter()
				.nth(17)
				.expect("bit domain must contain 64 elements")
		};
		let high_point = Vec::new();
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = bit_indexed_lane_claim(output, bit_challenge, &high_point, lane_weights);
		let reduction = ChiIotaReduction {
			output_claim,
			round: 0,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove_round::<P, _>(output, &round_trace.pre_chi, &reduction, &mut prover_transcript)
				.unwrap();

		assert_eq!(
			prover_output.reduced_eval,
			mixed_output_from_low_vectors(
				&evaluate_lane_low_vectors(output, &prover_output.reduced_high_point),
				&reduction.output_claim.lane_weights,
				&bit_lagrange_weights(bit_challenge),
			)
		);
	}
}
