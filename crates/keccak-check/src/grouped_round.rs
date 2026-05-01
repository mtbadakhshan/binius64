// Copyright 2026 The Binius Developers

//! Batched k-transition sumcheck prover for the k-depth flattened Keccak GKR protocol.
//!
//! Instead of running one sumcheck per Keccak round (24 sequential sumchecks), this module
//! groups k consecutive rounds together and batch-checks all k transitions in a single
//! sumcheck using random linear combination weights.
//!
//! The batched polynomial proved by the MLE-check is:
//!
//! ```text
//! f(x) = Σ_{i,j} w[i,j] * chi_iota_{last}(State_{last}(x))[i,j]
//!      + Σ_{r=0}^{k-2} tw[r] * Σ_{i,j} w[i,j] *
//!            (chi_iota_r(State_{t+r}(x))[i,j] - State_{t+r+1}(x)[i,j])
//! ```
//!
//! On boolean inputs the residual terms vanish and the first term equals the
//! weighted group output, so `f(alpha) = mixed_eval`.

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
	BIT_INDEX_SIZE, BitIndexedMixedClaim, Error,
	chi_iota::{
		compose_chi_iota_from_low_vectors, evaluate_lane_low_vectors_from_words,
		fold_block_tables_inplace, fold_low_vectors, interpolate_round_coeffs,
	},
	fused_round::apply_linear_recipe_to_low_vectors,
	linear_round::linear_recipe_static,
	rotation::bit_lagrange_weights,
	trace::RC,
};

/// Input to the grouped k-transition reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupedRoundReduction<F> {
	pub output_claim: BitIndexedMixedClaim<F>,
	pub round_start: usize,
	pub group_size: usize,
	/// Random weights for the k-1 inner transitions (indices 0..k-2).
	/// The last transition (index k-1) uses the output_claim's lane_weights directly.
	pub transition_weights: Vec<F>,
}

/// Output of the grouped k-transition reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupedRoundOutput<F> {
	pub reduced_high_point: Vec<F>,
	pub input_evals: [F; 25],
}

/// Prove a group of k fused round transitions in a single sumcheck.
pub fn prove_group_from_words<P, Channel>(
	round_inputs: &[&[[u64; 25]]],
	group_output_words: &[[u64; 25]],
	reduction: &GroupedRoundReduction<P::Scalar>,
	channel: &mut Channel,
) -> Result<GroupedRoundOutput<P::Scalar>, Error>
where
	P: PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	let k = reduction.group_size;
	validate_grouped_reduction(round_inputs, group_output_words, reduction)?;

	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Grouped Round Prove",
		phase = "keccak_grouped_prove",
		perfetto_category = "phase",
		round_start = reduction.round_start,
		group_size = k,
		n_vars = reduction.output_claim.high_point.len()
	)
	.entered();

	let bit_weights = bit_lagrange_weights(reduction.output_claim.bit_challenge);
	let prover = GroupedRoundProver::<P>::new_from_words(
		round_inputs,
		bit_weights,
		reduction.output_claim.lane_weights,
		&reduction.transition_weights,
		reduction.round_start,
		k,
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

	Ok(GroupedRoundOutput {
		reduced_high_point,
		input_evals,
	})
}

/// Verify a group of k fused round transitions from word-level data.
pub fn verify_group_from_words<F, Channel>(
	round_inputs: &[&[[u64; 25]]],
	group_output_words: &[[u64; 25]],
	reduction: &GroupedRoundReduction<F>,
	channel: &mut Channel,
) -> Result<GroupedRoundOutput<F>, Error>
where
	F: BinaryField,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	let k = reduction.group_size;
	validate_grouped_reduction(round_inputs, group_output_words, reduction)?;

	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Grouped Round Verify",
		phase = "keccak_grouped_verify",
		perfetto_category = "phase",
		round_start = reduction.round_start,
		group_size = k,
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

	let first_input_low =
		evaluate_lane_low_vectors_from_words(round_inputs[0], &reduced_high_point);
	let input_evals = fold_low_vectors(&first_input_low, &bit_weights);

	// Recompute the batched polynomial at the reduced point and check it matches.
	let last_round = reduction.round_start + k - 1;
	let last_input_low =
		evaluate_lane_low_vectors_from_words(round_inputs[k - 1], &reduced_high_point);
	let last_pre_chi = apply_linear_recipe_to_low_vectors(&last_input_low);
	let mut batched_eval = compose_chi_iota_from_low_vectors(
		&last_pre_chi,
		&reduction.output_claim.lane_weights,
		last_round,
		&bit_weights,
	);

	for r in 0..(k - 1) {
		let round = reduction.round_start + r;
		let input_low =
			evaluate_lane_low_vectors_from_words(round_inputs[r], &reduced_high_point);
		let pre_chi_low = apply_linear_recipe_to_low_vectors(&input_low);
		let chi_iota_eval = compose_chi_iota_from_low_vectors(
			&pre_chi_low,
			&reduction.output_claim.lane_weights,
			round,
			&bit_weights,
		);

		let next_input_low =
			evaluate_lane_low_vectors_from_words(round_inputs[r + 1], &reduced_high_point);
		let next_eval: F = std::iter::zip(
			&reduction.output_claim.lane_weights,
			&fold_low_vectors(&next_input_low, &bit_weights),
		)
		.fold(F::ZERO, |acc, (&w, &e)| acc + w * e);

		batched_eval += reduction.transition_weights[r] * (chi_iota_eval - next_eval);
	}

	channel.assert_zero(batched_eval - mlecheck_output.eval)?;

	Ok(GroupedRoundOutput {
		reduced_high_point,
		input_evals,
	})
}

fn validate_grouped_reduction<F: Field>(
	round_inputs: &[&[[u64; 25]]],
	group_output_words: &[[u64; 25]],
	reduction: &GroupedRoundReduction<F>,
) -> Result<(), Error> {
	let k = reduction.group_size;
	if k == 0 || reduction.round_start + k > 24 {
		return Err(Error::InvalidRound(reduction.round_start + k));
	}
	if round_inputs.len() != k {
		return Err(Error::InvalidClaim("round_inputs.len() must equal group_size"));
	}
	if reduction.transition_weights.len() != k - 1 {
		return Err(Error::InvalidClaim(
			"transition_weights.len() must equal group_size - 1",
		));
	}
	let expected_n_instances = 1usize << reduction.output_claim.high_point.len();
	for inputs in round_inputs.iter() {
		if inputs.len() != expected_n_instances {
			return Err(Error::InvalidClaim(
				"round input count must match 2^high_point.len()",
			));
		}
	}
	if group_output_words.len() != expected_n_instances {
		return Err(Error::InvalidClaim(
			"group output count must match 2^high_point.len()",
		));
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Word-level kernel: evaluates the batched polynomial for one instance pair
// ---------------------------------------------------------------------------

#[inline]
#[allow(clippy::too_many_arguments)]
fn grouped_word_pair_eval<F: Field>(
	round_inputs_lo: &[&[u64; 25]],
	round_inputs_hi: &[&[u64; 25]],
	lane_weights: &[F; 25],
	transition_weights: &[F],
	round_start: usize,
	group_size: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> (F, F) {
	let k = group_size;

	// Last transition: standalone chi_iota (not a residual).
	let last_round = round_start + k - 1;
	let (mut total_1, mut total_inf) = single_fused_word_pair_eval(
		round_inputs_lo[k - 1],
		round_inputs_hi[k - 1],
		lane_weights,
		last_round,
		bit_weights,
	);

	// Inner transitions: residual = chi_iota(input_r) - output_r, weighted by tw[r].
	// The output is degree 1, so it contributes 0 to y_inf (z^2 coefficient).
	for r in 0..(k - 1) {
		let round = round_start + r;
		let (chi_1, chi_inf) = single_fused_word_pair_eval(
			round_inputs_lo[r],
			round_inputs_hi[r],
			lane_weights,
			round,
			bit_weights,
		);

		let out_1 = weighted_output_eval_at_hi(
			round_inputs_hi[r + 1],
			lane_weights,
			bit_weights,
		);

		let tw = transition_weights[r];
		total_1 += tw * (chi_1 - out_1);
		total_inf += tw * chi_inf;
	}

	(total_1, total_inf)
}

#[inline]
fn single_fused_word_pair_eval<F: Field>(
	input_lo: &[u64; 25],
	input_hi: &[u64; 25],
	lane_weights: &[F; 25],
	round: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> (F, F) {
	let static_recipe = linear_recipe_static();
	let rc = RC[round];
	let mut acc_1 = F::ZERO;
	let mut acc_inf = F::ZERO;

	for y in 0..5 {
		let mut row_pre_chi_1 = [0u64; 5];
		let mut row_pre_chi_inf = [0u64; 5];
		for x in 0..5 {
			let out_lane = x + 5 * y;
			for &(src_lane, rot) in &static_recipe.word_recipe[out_lane] {
				let hi = input_hi[src_lane].rotate_left(rot);
				row_pre_chi_1[x] ^= hi;
				row_pre_chi_inf[x] ^= input_lo[src_lane].rotate_left(rot) ^ hi;
			}
		}

		for x in 0..5 {
			let out_lane = x + 5 * y;
			let weight = lane_weights[out_lane];
			let a_1 = row_pre_chi_1[x];
			let b_1 = row_pre_chi_1[(x + 1) % 5];
			let c_1 = row_pre_chi_1[(x + 2) % 5];
			let mut chi_bits_1 = a_1 ^ c_1 ^ (b_1 & c_1);
			if x == 0 && y == 0 {
				chi_bits_1 ^= rc;
			}
			let mut bits_1 = chi_bits_1;
			while bits_1 != 0 {
				let bit = bits_1.trailing_zeros() as usize;
				acc_1 += weight * bit_weights[bit];
				bits_1 &= bits_1 - 1;
			}

			let mut bits_inf = row_pre_chi_inf[(x + 1) % 5] & row_pre_chi_inf[(x + 2) % 5];
			while bits_inf != 0 {
				let bit = bits_inf.trailing_zeros() as usize;
				acc_inf += weight * bit_weights[bit];
				bits_inf &= bits_inf - 1;
			}
		}
	}
	(acc_1, acc_inf)
}

/// Compute `Σ w[lane] * Σ bw[b] * output_hi[lane][b]` — the weighted output evaluation at z=1.
#[inline]
pub(crate) fn weighted_output_eval_at_hi<F: Field>(
	output_hi: &[u64; 25],
	lane_weights: &[F; 25],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	let mut acc = F::ZERO;
	for lane in 0..25 {
		let weight = lane_weights[lane];
		let mut bits = output_hi[lane];
		while bits != 0 {
			let bit = bits.trailing_zeros() as usize;
			acc += weight * bit_weights[bit];
			bits &= bits - 1;
		}
	}
	acc
}

// ---------------------------------------------------------------------------
// Block-table kernel for subsequent sumcheck rounds (after fold)
// ---------------------------------------------------------------------------

#[inline]
#[allow(clippy::too_many_arguments)]
fn grouped_block_pair_eval<F: Field>(
	round_blocks_lo: &[&[[F; BIT_INDEX_SIZE]; 25]],
	round_blocks_hi: &[&[[F; BIT_INDEX_SIZE]; 25]],
	lane_weights: &[F; 25],
	transition_weights: &[F],
	round_start: usize,
	group_size: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> (F, F) {
	let k = group_size;

	let last_round = round_start + k - 1;
	let (mut total_1, mut total_inf) = single_fused_block_pair_eval(
		round_blocks_lo[k - 1],
		round_blocks_hi[k - 1],
		lane_weights,
		last_round,
		bit_weights,
	);

	for r in 0..(k - 1) {
		let round = round_start + r;
		let (chi_1, chi_inf) = single_fused_block_pair_eval(
			round_blocks_lo[r],
			round_blocks_hi[r],
			lane_weights,
			round,
			bit_weights,
		);

		let out_1 = weighted_output_block_eval_at_hi(
			round_blocks_hi[r + 1],
			lane_weights,
			bit_weights,
		);

		let tw = transition_weights[r];
		total_1 += tw * (chi_1 - out_1);
		total_inf += tw * chi_inf;
	}

	(total_1, total_inf)
}

#[inline]
fn single_fused_block_pair_eval<F: Field>(
	input_lo: &[[F; BIT_INDEX_SIZE]; 25],
	input_hi: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	round: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> (F, F) {
	let static_recipe = linear_recipe_static();
	let round_constant_eval =
		crate::rotation::round_constant_from_bit_weights(round, bit_weights);
	let mut acc_1 = lane_weights[0] * round_constant_eval;
	let mut acc_inf = F::ZERO;

	for y in 0..5 {
		let mut row_pre_chi_1 = [[F::ZERO; BIT_INDEX_SIZE]; 5];
		let mut row_pre_chi_inf = [[F::ZERO; BIT_INDEX_SIZE]; 5];
		for x in 0..5 {
			let out_lane = x + 5 * y;
			for &(rv_idx, ref rotated_indices) in &static_recipe.binary_recipe[out_lane] {
				let lane = static_recipe.rot_views[rv_idx].lane;
				for b in 0..BIT_INDEX_SIZE {
					let hi = input_hi[lane][rotated_indices[b]];
					row_pre_chi_1[x][b] += hi;
					row_pre_chi_inf[x][b] += input_lo[lane][rotated_indices[b]] + hi;
				}
			}
		}

		for x in 0..5 {
			let out_lane = x + 5 * y;
			let weight = lane_weights[out_lane];
			let a_1 = &row_pre_chi_1[x];
			let b_1 = &row_pre_chi_1[(x + 1) % 5];
			let c_1 = &row_pre_chi_1[(x + 2) % 5];
			let b_inf = &row_pre_chi_inf[(x + 1) % 5];
			let c_inf = &row_pre_chi_inf[(x + 2) % 5];
			let mut chi_eval_1 = F::ZERO;
			let mut chi_eval_inf = F::ZERO;
			for bit in 0..BIT_INDEX_SIZE {
				chi_eval_1 += bit_weights[bit] * (a_1[bit] + c_1[bit] + b_1[bit] * c_1[bit]);
				chi_eval_inf += bit_weights[bit] * b_inf[bit] * c_inf[bit];
			}
			acc_1 += weight * chi_eval_1;
			acc_inf += weight * chi_eval_inf;
		}
	}
	(acc_1, acc_inf)
}

#[inline]
pub(crate) fn weighted_output_block_eval_at_hi<F: Field>(
	output_hi: &[[F; BIT_INDEX_SIZE]; 25],
	lane_weights: &[F; 25],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	let mut acc = F::ZERO;
	for lane in 0..25 {
		let weight = lane_weights[lane];
		let mut eval = F::ZERO;
		for bit in 0..BIT_INDEX_SIZE {
			eval += bit_weights[bit] * output_hi[lane][bit];
		}
		acc += weight * eval;
	}
	acc
}

// ---------------------------------------------------------------------------
// GroupedRoundProver
// ---------------------------------------------------------------------------

struct GroupedRoundProver<'a, P: PackedField> {
	round_blocks: Vec<Vec<[[P::Scalar; BIT_INDEX_SIZE]; 25]>>,
	round_words: Option<Vec<&'a [[u64; 25]]>>,
	bit_weights: [P::Scalar; BIT_INDEX_SIZE],
	lane_weights: [P::Scalar; 25],
	transition_weights: Vec<P::Scalar>,
	last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
	round_start: usize,
	group_size: usize,
	gruen32: Gruen32<P>,
}

#[allow(clippy::too_many_arguments)]
impl<'a, F: Field, P: PackedField<Scalar = F>> GroupedRoundProver<'a, P> {
	fn new_from_words(
		round_inputs: &[&'a [[u64; 25]]],
		bit_weights: [F; BIT_INDEX_SIZE],
		lane_weights: [F; 25],
		transition_weights: &[F],
		round_start: usize,
		group_size: usize,
		eval_point: Vec<F>,
		mixed_eval: F,
	) -> Result<Self, SumcheckError> {
		let expected_len = 1usize << eval_point.len();
		for inputs in round_inputs {
			if inputs.len() != expected_len {
				return Err(SumcheckError::MultilinearSizeMismatch);
			}
		}

		let gruen32 = Gruen32::new(&eval_point);

		Ok(Self {
			round_blocks: Vec::new(),
			round_words: Some(round_inputs.to_vec()),
			bit_weights,
			lane_weights,
			transition_weights: transition_weights.to_vec(),
			last_coeffs_or_eval: RoundCoeffsOrEval::Eval(mixed_eval),
			round_start,
			group_size,
			gruen32,
		})
	}
}

impl<'a, F: Field + Send + Sync, P: PackedField<Scalar = F> + Sync> SumcheckProver<F>
	for GroupedRoundProver<'a, P>
{
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
		let k = self.group_size;

		let (y_1, y_inf) = if let Some(ref words_vec) = self.round_words {
			eq_chunks
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
						let inputs_lo: Vec<&[u64; 25]> =
							(0..k).map(|r| &words_vec[r][i]).collect();
						let inputs_hi: Vec<&[u64; 25]> =
							(0..k).map(|r| &words_vec[r][split + i]).collect();
						let (contrib_1, contrib_inf) = grouped_word_pair_eval(
							&inputs_lo,
							&inputs_hi,
							&self.lane_weights,
							&self.transition_weights,
							self.round_start,
							k,
							&self.bit_weights,
						);
						chunk_y_1 += eq_i * contrib_1;
						chunk_y_inf += eq_i * contrib_inf;
					}
					(chunk_y_1, chunk_y_inf)
				})
				.reduce(
					|| (F::ZERO, F::ZERO),
					|(a1, ai), (b1, bi)| (a1 + b1, ai + bi),
				)
		} else {
			eq_chunks
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
						let blocks_lo: Vec<&[[F; BIT_INDEX_SIZE]; 25]> =
							(0..k).map(|r| &self.round_blocks[r][i]).collect();
						let blocks_hi: Vec<&[[F; BIT_INDEX_SIZE]; 25]> =
							(0..k).map(|r| &self.round_blocks[r][split + i]).collect();
						let (contrib_1, contrib_inf) = grouped_block_pair_eval(
							&blocks_lo,
							&blocks_hi,
							&self.lane_weights,
							&self.transition_weights,
							self.round_start,
							k,
							&self.bit_weights,
						);
						chunk_y_1 += eq_i * contrib_1;
						chunk_y_inf += eq_i * contrib_inf;
					}
					(chunk_y_1, chunk_y_inf)
				})
				.reduce(
					|| (F::ZERO, F::ZERO),
					|(a1, ai), (b1, bi)| (a1 + b1, ai + bi),
				)
		};

		let round_coeffs = interpolate_round_coeffs(last_eval, alpha, y_1, y_inf);
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), SumcheckError> {
		let coeffs = match &self.last_coeffs_or_eval {
			RoundCoeffsOrEval::Coeffs(coeffs) => coeffs,
			RoundCoeffsOrEval::Eval(_) => return Err(SumcheckError::ExpectedExecute),
		};

		if let Some(words_vec) = self.round_words.take() {
			let split = words_vec[0].len() / 2;
			let lookup = [F::ZERO, F::ONE + challenge, challenge, F::ONE];

			let word_to_blocks = |words: &[[u64; 25]]| -> Vec<[[F; BIT_INDEX_SIZE]; 25]> {
				(0..split)
					.into_par_iter()
					.map(|i| {
						array::from_fn(|lane| {
							let lo_word = words[i][lane];
							let hi_word = words[split + i][lane];
							array::from_fn(|bit| {
								let lo_bit = (lo_word >> bit) & 1;
								let hi_bit = (hi_word >> bit) & 1;
								lookup[(lo_bit | (hi_bit << 1)) as usize]
							})
						})
					})
					.collect()
			};

			self.round_blocks = words_vec.iter().map(|w| word_to_blocks(w)).collect();
		} else {
			for blocks in &mut self.round_blocks {
				fold_block_tables_inplace(blocks, challenge);
			}
		}

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

		if let Some(words_vec) = self.round_words {
			Ok((0..25)
				.map(|lane| {
					let word = words_vec[0][0][lane];
					let mut acc = F::ZERO;
					let mut bits = word;
					while bits != 0 {
						let bit = bits.trailing_zeros() as usize;
						acc += self.bit_weights[bit];
						bits &= bits - 1;
					}
					acc
				})
				.collect())
		} else {
			Ok((0..25)
				.map(|lane| {
					std::iter::zip(&self.round_blocks[0][0][lane], &self.bit_weights)
						.fold(F::ZERO, |acc, (val, weight)| acc + *val * *weight)
				})
				.collect())
		}
	}
}

impl<'a, F: Field, P: PackedField<Scalar = F>> MleCheckProver<F>
	for GroupedRoundProver<'a, P>
{
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
	use binius_transcript::{
		ProverTranscript, VerifierTranscript, fiat_shamir::HasherChallenger,
	};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{bit_indexed_lane_claim_from_words, trace::compact_trace_from_inputs};

	type F = OptimalB128;
	type P = OptimalPackedB128;
	type StdChallenger = HasherChallenger<sha2::Sha256>;

	fn run_grouped_prove_verify(group_size: usize) {
		let mut rng = StdRng::seed_from_u64(100 + group_size as u64);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);

		let round_start = 0;
		let round_inputs: Vec<&[[u64; 25]]> = (0..group_size)
			.map(|r| trace.round_inputs[round_start + r].as_slice())
			.collect();
		let group_output = if round_start + group_size < 24 {
			trace.round_inputs[round_start + group_size].as_slice()
		} else {
			trace.final_output.as_slice()
		};

		let bit_challenge = F::random(&mut rng);
		let high_point = vec![F::random(&mut rng)];
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = bit_indexed_lane_claim_from_words(
			group_output,
			bit_challenge,
			&high_point,
			lane_weights,
		);

		let transition_weights: Vec<F> =
			(0..group_size - 1).map(|_| F::random(&mut rng)).collect();

		let reduction = GroupedRoundReduction {
			output_claim,
			round_start,
			group_size,
			transition_weights,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output = prove_group_from_words::<P, _>(
			&round_inputs,
			group_output,
			&reduction,
			&mut prover_transcript,
		)
		.unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output = verify_group_from_words::<F, _>(
			&round_inputs,
			group_output,
			&reduction,
			&mut verifier_transcript,
		)
		.unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
	}

	#[test]
	fn test_grouped_round_k2() {
		run_grouped_prove_verify(2);
	}

	#[test]
	fn test_grouped_round_k3() {
		run_grouped_prove_verify(3);
	}

	#[test]
	fn test_grouped_round_k4() {
		run_grouped_prove_verify(4);
	}

	#[test]
	fn test_grouped_round_k6() {
		run_grouped_prove_verify(6);
	}

	#[test]
	fn test_grouped_round_k8() {
		run_grouped_prove_verify(8);
	}

	#[test]
	fn test_grouped_round_k12() {
		run_grouped_prove_verify(12);
	}

	#[test]
	fn test_grouped_round_k24() {
		run_grouped_prove_verify(24);
	}

	#[test]
	fn test_grouped_round_rejects_corruption() {
		let mut rng = StdRng::seed_from_u64(200);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);
		let mut corrupted_trace = trace.clone();
		corrupted_trace.round_inputs[1][0][0] ^= 1;

		let group_size = 4;
		let round_inputs: Vec<&[[u64; 25]]> = (0..group_size)
			.map(|r| corrupted_trace.round_inputs[r].as_slice())
			.collect();
		let group_output = corrupted_trace.round_inputs[group_size].as_slice();

		let bit_challenge = F::random(&mut rng);
		let high_point = vec![F::random(&mut rng)];
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let output_claim = bit_indexed_lane_claim_from_words(
			group_output,
			bit_challenge,
			&high_point,
			lane_weights,
		);
		let transition_weights: Vec<F> =
			(0..group_size - 1).map(|_| F::random(&mut rng)).collect();

		let reduction = GroupedRoundReduction {
			output_claim,
			round_start: 0,
			group_size,
			transition_weights,
		};

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_group_from_words::<P, _>(
			&round_inputs,
			group_output,
			&reduction,
			&mut prover_transcript,
		)
		.unwrap();
		let proof_bytes = prover_transcript.finalize();

		let correct_round_inputs: Vec<&[[u64; 25]]> = (0..group_size)
			.map(|r| trace.round_inputs[r].as_slice())
			.collect();
		let correct_output = trace.round_inputs[group_size].as_slice();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(verify_group_from_words::<F, _>(
			&correct_round_inputs,
			correct_output,
			&reduction,
			&mut verifier_transcript,
		)
		.is_err());
	}
}
