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
use binius_math::multilinear::eq::eq_ind_partial_eval_scalars;
use rayon::prelude::*;

use crate::{
	BIT_INDEX_SIZE, BitIndexedMixedClaim, Error, LOG_BIT_INDEX_VARS,
	rotation::{bit_lagrange_weights, round_constant_from_bit_weights},
	trace::LaneTables,
};

/// Precomputed chi index triples `(a_lane, b_lane, c_lane)` for each of the 25 output lanes,
/// where `a = idx(x,y)`, `b = idx((x+1)%5, y)`, `c = idx((x+2)%5, y)`.
const CHI_INDICES: [(usize, usize, usize); 25] = {
	let mut table = [(0usize, 0usize, 0usize); 25];
	let mut y = 0;
	while y < 5 {
		let mut x = 0;
		while x < 5 {
			let lane = x + 5 * y;
			let b = (x + 1) % 5 + 5 * y;
			let c = (x + 2) % 5 + 5 * y;
			table[lane] = (lane, b, c);
			x += 1;
		}
		y += 1;
	}
	table
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
	let prover: ChiBitIndexedProver<P> = ChiBitIndexedProver::new(
		lane_block_tables(pre_chi),
		bit_weights,
		reduction.output_claim.lane_weights,
		reduction.round,
		reduction.output_claim.high_point.clone(),
		reduction.output_claim.mixed_eval,
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

	let mlecheck_output = mlecheck::verify(
		&reduction.output_claim.high_point,
		2,
		reduction.output_claim.mixed_eval,
		channel,
	)?;
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
	let chi_iota_eval = compose_chi_iota_from_low_vectors(
		&pre_chi_low_vectors,
		&reduction.output_claim.lane_weights,
		reduction.round,
		&bit_weights,
	);
	channel.assert_zero(chi_iota_eval - mlecheck_output.eval)?;

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

pub(crate) fn lane_block_tables<F: Field, P: PackedField<Scalar = F>>(
	lane_tables: &LaneTables<P>,
) -> Vec<[[F; BIT_INDEX_SIZE]; 25]> {
	let n_instances = lane_tables[0].len() / BIT_INDEX_SIZE;
	(0..n_instances)
		.map(|i| {
			array::from_fn(|lane| {
				let block = lane_tables[lane].chunk(LOG_BIT_INDEX_VARS, i);
				let mut bits = [F::ZERO; BIT_INDEX_SIZE];
				for (slot, val) in bits.iter_mut().zip(block.iter_scalars()) {
					*slot = val;
				}
				bits
			})
		})
		.collect()
}

pub(crate) fn evaluate_lane_low_vectors<F: Field, P: PackedField<Scalar = F>>(
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

/// Evaluate the 25 lane multilinears at a high point, working directly from `u64` words
/// without expanding to field elements.
pub(crate) fn evaluate_lane_low_vectors_from_words<F: Field>(
	words: &[[u64; 25]],
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
			let word = words[instance_index][lane];
			for bit in 0..BIT_INDEX_SIZE {
				if (word >> bit) & 1 == 1 {
					low_vector[bit] += instance_weight;
				}
			}
		}
		low_vector
	})
}

#[inline]
pub(crate) fn fold_low_vectors<F: Field>(
	lane_low_vectors: &[[F; BIT_INDEX_SIZE]; 25],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> [F; 25] {
	array::from_fn(|lane| dot_64(&lane_low_vectors[lane], bit_weights))
}

#[inline]
fn mixed_output_from_low_vectors<F: Field>(
	output_low_vectors: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	let output_lane_evals = fold_low_vectors(output_low_vectors, bit_weights);
	std::iter::zip(lane_weights, output_lane_evals)
		.fold(F::ZERO, |acc, (weight, eval)| acc + *weight * eval)
}

#[inline]
pub(crate) fn compose_chi_iota_from_low_vectors<F: Field>(
	pre_chi_low_vectors: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	round: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	let round_constant_eval = round_constant_from_bit_weights(round, bit_weights);
	let mut acc = lane_weights[0] * round_constant_eval;

	for &(a_lane, b_lane, c_lane) in &CHI_INDICES {
		let weight = lane_weights[a_lane];
		let a_vec = &pre_chi_low_vectors[a_lane];
		let b_vec = &pre_chi_low_vectors[b_lane];
		let c_vec = &pre_chi_low_vectors[c_lane];
		let mut chi_eval = F::ZERO;
		for bit in 0..BIT_INDEX_SIZE {
			chi_eval += bit_weights[bit] * (a_vec[bit] + c_vec[bit] + b_vec[bit] * c_vec[bit]);
		}
		acc += weight * chi_eval;
	}
	acc
}

#[inline]
fn compose_chi_iota_pair_from_blocks<F: Field>(
	pre_chi_lo_blocks: &[[F; BIT_INDEX_SIZE]; 25],
	pre_chi_hi_blocks: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	round: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> (F, F) {
	let round_constant_eval = round_constant_from_bit_weights(round, bit_weights);
	let mut acc_1 = lane_weights[0] * round_constant_eval;
	let mut acc_inf = F::ZERO;
	for &(a_lane, b_lane, c_lane) in &CHI_INDICES {
		let weight = lane_weights[a_lane];
		let a_hi = &pre_chi_hi_blocks[a_lane];
		let b_hi = &pre_chi_hi_blocks[b_lane];
		let c_hi = &pre_chi_hi_blocks[c_lane];
		let b_lo = &pre_chi_lo_blocks[b_lane];
		let c_lo = &pre_chi_lo_blocks[c_lane];
		let mut chi_eval_1 = F::ZERO;
		let mut bc_eval_inf = F::ZERO;
		for bit in 0..BIT_INDEX_SIZE {
			chi_eval_1 += bit_weights[bit] * (a_hi[bit] + c_hi[bit] + b_hi[bit] * c_hi[bit]);
			bc_eval_inf += bit_weights[bit] * (b_lo[bit] + b_hi[bit]) * (c_lo[bit] + c_hi[bit]);
		}
		acc_1 += weight * chi_eval_1;
		acc_inf += weight * bc_eval_inf;
	}
	(acc_1, acc_inf)
}

#[inline]
pub(crate) fn dot_64<F: Field>(lhs: &[F; BIT_INDEX_SIZE], rhs: &[F; BIT_INDEX_SIZE]) -> F {
	std::iter::zip(lhs, rhs).fold(F::ZERO, |acc, (lhs_i, rhs_i)| acc + *lhs_i * *rhs_i)
}

#[inline]
pub(crate) fn fold_block_tables_inplace<F: Field + Send + Sync>(
	blocks: &mut Vec<[[F; BIT_INDEX_SIZE]; 25]>,
	challenge: F,
) {
	let split = blocks.len() / 2;
	let (lo_half, hi_half) = blocks.split_at_mut(split);
	lo_half
		.par_iter_mut()
		.zip(hi_half.par_iter())
		.for_each(|(lo_inst, hi_inst)| {
			for lane in 0..25 {
				let lo = lo_inst[lane];
				let hi = hi_inst[lane];
				lo_inst[lane] = array::from_fn(|bit| lo[bit] + challenge * (hi[bit] - lo[bit]));
			}
		});
	blocks.truncate(split);
}

#[inline]
pub(crate) fn interpolate_round_coeffs<F: Field>(
	sum: F,
	alpha: F,
	y_1: F,
	y_inf: F,
) -> RoundCoeffs<F> {
	let y_0 = (sum - y_1 * alpha) * (F::ONE - alpha).invert_or_zero();
	let c_0 = y_0;
	let c_2 = y_inf;
	let c_1 = y_1 - c_0 - c_2;
	RoundCoeffs(vec![c_0, c_1, c_2])
}

struct ChiBitIndexedProver<P: PackedField> {
	pre_chi_blocks: Vec<[[P::Scalar; BIT_INDEX_SIZE]; 25]>,
	bit_weights: [P::Scalar; BIT_INDEX_SIZE],
	lane_weights: [P::Scalar; 25],
	last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
	round: usize,
	gruen32: Gruen32<P>,
}

impl<F: Field, P: PackedField<Scalar = F>> ChiBitIndexedProver<P> {
	fn new(
		pre_chi_blocks: Vec<[[F; BIT_INDEX_SIZE]; 25]>,
		bit_weights: [F; BIT_INDEX_SIZE],
		lane_weights: [F; 25],
		round: usize,
		eval_point: Vec<F>,
		mixed_eval: F,
	) -> Result<Self, SumcheckError> {
		let expected_len = 1usize << eval_point.len();
		if pre_chi_blocks.len() != expected_len {
			return Err(SumcheckError::MultilinearSizeMismatch);
		}

		let gruen32 = Gruen32::new(&eval_point);

		Ok(Self {
			pre_chi_blocks,
			bit_weights,
			lane_weights,
			last_coeffs_or_eval: RoundCoeffsOrEval::Eval(mixed_eval),
			round,
			gruen32,
		})
	}
}

impl<F: Field, P: PackedField<Scalar = F> + Sync> SumcheckProver<F> for ChiBitIndexedProver<P> {
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
		let eq_chunks = self.gruen32.eq_expansion().as_ref();

		let (y_1, y_inf) = eq_chunks
			.par_iter()
			.enumerate()
			.map(|(packed_idx, eq_chunk)| {
				let base = packed_idx << P::LOG_WIDTH;
				let mut chunk_y_1 = F::ZERO;
				let mut chunk_y_inf = F::ZERO;
				for (offset, eq_i) in eq_chunk.iter().enumerate() {
					let i = base + offset;
					if i >= split {
						break;
					}
					let (contrib_1, contrib_inf) = compose_chi_iota_pair_from_blocks(
						&self.pre_chi_blocks[i],
						&self.pre_chi_blocks[split + i],
						&self.lane_weights,
						self.round,
						&self.bit_weights,
					);
					chunk_y_1 += eq_i * contrib_1;
					chunk_y_inf += eq_i * contrib_inf;
				}
				(chunk_y_1, chunk_y_inf)
			})
			.reduce(|| (F::ZERO, F::ZERO), |(a1, ai), (b1, bi)| (a1 + b1, ai + bi));

		let round_coeffs = interpolate_round_coeffs(last_eval, alpha, y_1, y_inf);
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), SumcheckError> {
		let coeffs = match &self.last_coeffs_or_eval {
			RoundCoeffsOrEval::Coeffs(coeffs) => coeffs,
			RoundCoeffsOrEval::Eval(_) => return Err(SumcheckError::ExpectedExecute),
		};

		fold_block_tables_inplace(&mut self.pre_chi_blocks, challenge);
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

		Ok((0..25)
			.map(|lane| dot_64(&self.pre_chi_blocks[0][lane], &self.bit_weights))
			.collect())
	}
}

impl<F: Field, P: PackedField<Scalar = F>> MleCheckProver<F> for ChiBitIndexedProver<P> {
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
