// Copyright 2026 The Binius Developers

//! k-parallel Keccak GKR prover: batches multiple groups into a single sumcheck per layer.
//!
//! Splits 24 Keccak rounds into `n_groups = 24 / group_size` groups. Each group runs a
//! standard k=1 GKR chain internally (virtual intermediates). At each layer, all groups'
//! polynomials are batch-combined via random linear combination into a **single** sumcheck,
//! sharing the Fiat-Shamir challenge and reducing proof size.
//!
//! Sequential Fiat-Shamir depth: `group_size × log(h)` (vs `24 × log(h)` for k=1).
//! With `group_size = 4`: 4 sumchecks of `log(h)` rounds each.
//!
//! Proof size: `group_size × 2 × log(h)` field elements — smaller than both k=1 and k-flat.

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
	BIT_INDEX_SIZE, BitIndexedEndpointClaims, BitIndexedMixedClaim, Error,
	bit_indexed_claim_from_evals, bit_indexed_lane_claim_from_words,
	chi_iota::{
		compose_chi_iota_from_low_vectors, evaluate_lane_low_vectors_from_words,
		fold_block_tables_inplace, fold_low_vectors, interpolate_round_coeffs,
	},
	fused_round::{
		apply_linear_recipe_to_low_vectors, fused_chi_linear_pair_eval_blocks,
		fused_chi_linear_word_pair_eval,
	},
	grouped_round::{weighted_output_block_eval_at_hi, weighted_output_eval_at_hi},
	rotation::bit_lagrange_weights,
	trace::CompactTrace,
};

/// Prove the full 24-round KeccakCheck with k-parallel batched sumchecks.
///
/// Groups `group_size` consecutive rounds together. At each layer, all `24 / group_size`
/// groups' fused chi+linear polynomials are batch-combined into a single sumcheck via
/// random linear combination. This reduces sequential depth from `24 × log(h)` to
/// `group_size × log(h)` Fiat-Shamir rounds.
///
/// At layer 0 the batched polynomial includes boundary zerocheck residuals
/// `β_g · (chi_iota_g(x) - S_boundary(x))` for groups 0..n-2, enforcing
/// inter-group boundary consistency within the sumcheck. This is the parallel
/// analog of k-flat's intra-group `transition_weights` zerochecks.
///
/// # Preconditions
///
/// - `group_size` must divide 24 evenly (valid: 1, 2, 3, 4, 6, 8, 12, 24)
pub fn prove_parallel<P, Channel>(
	trace: &CompactTrace,
	group_size: usize,
	channel: &mut Channel,
) -> Result<BitIndexedEndpointClaims<P::Scalar>, Error>
where
	P: PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_parallel_args(trace, group_size)?;

	let n_groups = 24 / group_size;
	let n_instances = trace.n_instances();
	let _prove_guard = tracing::info_span!(
		"KeccakCheck Parallel Prove",
		operation = "keccak_check_parallel_prove",
		perfetto_category = "operation",
		n_groups,
		group_size,
		n_instances
	)
	.entered();

	let bit_challenge: P::Scalar = channel.sample();
	let high_point: Vec<P::Scalar> = channel.sample_many(trace.log_n_instances());

	let mut group_claims: Vec<BitIndexedMixedClaim<P::Scalar>> = Vec::with_capacity(n_groups);
	for g in 0..n_groups {
		let boundary_output = group_boundary_output(trace, g, group_size);
		let weights: [P::Scalar; 25] = channel.sample_array();
		let claim = bit_indexed_lane_claim_from_words(
			boundary_output,
			bit_challenge,
			&high_point,
			weights,
		);
		group_claims.push(claim);
	}

	let output_claim = group_claims[n_groups - 1].clone();

	for layer in 0..group_size {
		let _layer_guard = tracing::info_span!(
			"[phase] Parallel Layer Prove",
			phase = "parallel_layer_prove",
			perfetto_category = "phase",
			layer,
			group_size
		)
		.entered();

		let batch_weights: Vec<P::Scalar> =
			(0..n_groups).map(|_| channel.sample()).collect();

		let is_boundary_layer = layer == 0;
		let residual_weights: Vec<P::Scalar> = if is_boundary_layer {
			(0..n_groups - 1).map(|_| channel.sample()).collect()
		} else {
			Vec::new()
		};

		let bit_weights = bit_lagrange_weights(bit_challenge);
		let rounds: Vec<usize> = (0..n_groups)
			.map(|g| group_round(g, group_size, layer))
			.collect();
		let group_words: Vec<&[[u64; 25]]> = rounds
			.iter()
			.map(|&r| trace.round_inputs[r].as_slice())
			.collect();
		let group_lane_weights: Vec<[P::Scalar; 25]> =
			group_claims.iter().map(|c| c.lane_weights).collect();

		let batched_eval: P::Scalar = batch_weights
			.iter()
			.zip(group_claims.iter())
			.map(|(&bw, claim)| bw * claim.mixed_eval)
			.fold(P::Scalar::ZERO, |a, b| a + b);

		let prover = if is_boundary_layer {
			let boundary_words: Vec<&[[u64; 25]]> = (0..n_groups - 1)
				.map(|g| group_boundary_output(trace, g, group_size))
				.collect();
			BatchedParallelProver::<P>::new_with_boundaries(
				group_words,
				bit_weights,
				group_lane_weights,
				batch_weights.clone(),
				rounds.clone(),
				group_claims[0].high_point.clone(),
				batched_eval,
				boundary_words,
				residual_weights,
			)?
		} else {
			BatchedParallelProver::<P>::new(
				group_words,
				bit_weights,
				group_lane_weights,
				batch_weights.clone(),
				rounds.clone(),
				group_claims[0].high_point.clone(),
				batched_eval,
			)?
		};

		let proof_output = prove_single_mlecheck(prover, channel)?;
		let all_evals = proof_output.multilinear_evals;
		let mut reduced_high_point = proof_output.challenges;
		reduced_high_point.reverse();

		let is_last_layer = layer == group_size - 1;
		for g in 0..n_groups {
			let input_evals: [P::Scalar; 25] = all_evals[g * 25..(g + 1) * 25]
				.try_into()
				.map_err(|_| Error::InvalidClaim("expected 25 folded input evaluations"))?;

			if is_last_layer && g == 0 {
				let input_weights: [P::Scalar; 25] = channel.sample_array();
				let input_claim = bit_indexed_claim_from_evals(
					bit_challenge,
					reduced_high_point.clone(),
					input_weights,
					input_evals,
				);
				return Ok(BitIndexedEndpointClaims {
					output_claim,
					input_claim,
				});
			}

			let next_weights: [P::Scalar; 25] = channel.sample_array();
			group_claims[g] = bit_indexed_claim_from_evals(
				bit_challenge,
				reduced_high_point.clone(),
				next_weights,
				input_evals,
			);
		}
	}

	Err(Error::InvalidClaim("parallel prove should have returned"))
}

/// Verify the full 24-round KeccakCheck with k-parallel batched sumchecks.
pub fn verify_parallel<F, Channel>(
	trace: &CompactTrace,
	group_size: usize,
	channel: &mut Channel,
) -> Result<BitIndexedEndpointClaims<F>, Error>
where
	F: BinaryField,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	validate_parallel_args(trace, group_size)?;

	let n_groups = 24 / group_size;
	let n_instances = trace.n_instances();
	let _verify_guard = tracing::info_span!(
		"KeccakCheck Parallel Verify",
		operation = "keccak_check_parallel_verify",
		perfetto_category = "operation",
		n_groups,
		group_size,
		n_instances
	)
	.entered();

	let bit_challenge: F = channel.sample();
	let high_point: Vec<F> = channel.sample_many(trace.log_n_instances());

	let mut group_claims: Vec<BitIndexedMixedClaim<F>> = Vec::with_capacity(n_groups);
	for g in 0..n_groups {
		let boundary_output = group_boundary_output(trace, g, group_size);
		let weights: [F; 25] = channel.sample_array();
		let claim =
			bit_indexed_lane_claim_from_words(boundary_output, bit_challenge, &high_point, weights);
		group_claims.push(claim);
	}

	let output_claim = group_claims[n_groups - 1].clone();

	for layer in 0..group_size {
		let _layer_guard = tracing::info_span!(
			"[phase] Parallel Layer Verify",
			phase = "parallel_layer_verify",
			perfetto_category = "phase",
			layer,
			group_size
		)
		.entered();

		let batch_weights: Vec<F> = (0..n_groups).map(|_| channel.sample()).collect();

		let is_boundary_layer = layer == 0;
		let residual_weights: Vec<F> = if is_boundary_layer {
			(0..n_groups - 1).map(|_| channel.sample()).collect()
		} else {
			Vec::new()
		};

		let batched_eval: F = batch_weights
			.iter()
			.zip(group_claims.iter())
			.map(|(&bw, claim)| bw * claim.mixed_eval)
			.fold(F::ZERO, |a, b| a + b);

		let mlecheck_output =
			mlecheck::verify(&group_claims[0].high_point, 2, batched_eval, channel)?;

		let mut reduced_high_point = mlecheck_output.challenges;
		reduced_high_point.reverse();
		let bit_weights = bit_lagrange_weights(bit_challenge);

		let mut expected_batched = F::ZERO;
		let mut all_input_evals: Vec<[F; 25]> = Vec::with_capacity(n_groups);

		for g in 0..n_groups {
			let round = group_round(g, group_size, layer);
			let input_low_vectors = evaluate_lane_low_vectors_from_words(
				&trace.round_inputs[round],
				&reduced_high_point,
			);
			let input_evals_arr = fold_low_vectors(&input_low_vectors, &bit_weights);
			let pre_chi_low = apply_linear_recipe_to_low_vectors(&input_low_vectors);
			let fused_eval = compose_chi_iota_from_low_vectors(
				&pre_chi_low,
				&group_claims[g].lane_weights,
				round,
				&bit_weights,
			);

			if is_boundary_layer && g < n_groups - 1 {
				let boundary_output = group_boundary_output(trace, g, group_size);
				let boundary_low =
					evaluate_lane_low_vectors_from_words(boundary_output, &reduced_high_point);
				let boundary_evals = fold_low_vectors(&boundary_low, &bit_weights);
				let boundary_mixed: F = std::iter::zip(
					&group_claims[g].lane_weights,
					&boundary_evals,
				)
				.fold(F::ZERO, |acc, (&w, &e)| acc + w * e);

				let eff = batch_weights[g] + residual_weights[g];
				expected_batched += eff * fused_eval - residual_weights[g] * boundary_mixed;
			} else {
				expected_batched += batch_weights[g] * fused_eval;
			}

			all_input_evals.push(input_evals_arr);
		}

		channel.assert_zero(expected_batched - mlecheck_output.eval)?;

		let is_last_layer = layer == group_size - 1;
		for g in 0..n_groups {
			if is_last_layer && g == 0 {
				let input_weights: [F; 25] = channel.sample_array();
				let input_claim = bit_indexed_claim_from_evals(
					bit_challenge,
					reduced_high_point.clone(),
					input_weights,
					all_input_evals[g],
				);
				return Ok(BitIndexedEndpointClaims {
					output_claim,
					input_claim,
				});
			}

			let next_weights: [F; 25] = channel.sample_array();
			group_claims[g] = bit_indexed_claim_from_evals(
				bit_challenge,
				reduced_high_point.clone(),
				next_weights,
				all_input_evals[g],
			);
		}
	}

	Err(Error::InvalidClaim("parallel verify should have returned"))
}

// ---------------------------------------------------------------------------
// Batched prover: evaluates Σ_g batch_weight_g · f_g(x) in a single sumcheck
// ---------------------------------------------------------------------------

/// Blocks are stored interleaved: `blocks[i * n_groups + g]` holds the block for
/// instance `i`, group `g`. This makes all groups' data for a single instance
/// contiguous in memory, reducing cache/prefetch pressure from `2 * n_groups`
/// scattered streams to just 2 sequential scans (lo half, hi half).
///
/// When boundary zerocheck fields are present (layer 0 of the zc variant),
/// the batched polynomial includes residual terms `β_g · (chi_g(x) - S_boundary(x))`
/// for groups 0..n_groups-2. The boundary state is degree 1, contributing only to y_1.
struct BatchedParallelProver<'a, P: PackedField> {
	interleaved_blocks: Vec<[[P::Scalar; BIT_INDEX_SIZE]; 25]>,
	group_words: Option<Vec<&'a [[u64; 25]]>>,
	bit_weights: [P::Scalar; BIT_INDEX_SIZE],
	group_lane_weights: Vec<[P::Scalar; 25]>,
	batch_weights: Vec<P::Scalar>,
	rounds: Vec<usize>,
	last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
	gruen32: Gruen32<P>,
	boundary_words: Option<Vec<&'a [[u64; 25]]>>,
	boundary_interleaved_blocks: Vec<[[P::Scalar; BIT_INDEX_SIZE]; 25]>,
	residual_weights: Vec<P::Scalar>,
}

impl<'a, F: Field, P: PackedField<Scalar = F>> BatchedParallelProver<'a, P> {
	#[allow(clippy::too_many_arguments)]
	fn new(
		group_words: Vec<&'a [[u64; 25]]>,
		bit_weights: [F; BIT_INDEX_SIZE],
		group_lane_weights: Vec<[F; 25]>,
		batch_weights: Vec<F>,
		rounds: Vec<usize>,
		eval_point: Vec<F>,
		batched_eval: F,
	) -> Result<Self, SumcheckError> {
		let expected_len = 1usize << eval_point.len();
		for words in &group_words {
			if words.len() != expected_len {
				return Err(SumcheckError::MultilinearSizeMismatch);
			}
		}

		let gruen32 = Gruen32::new(&eval_point);

		Ok(Self {
			interleaved_blocks: Vec::new(),
			group_words: Some(group_words),
			bit_weights,
			group_lane_weights,
			batch_weights,
			rounds,
			last_coeffs_or_eval: RoundCoeffsOrEval::Eval(batched_eval),
			gruen32,
			boundary_words: None,
			boundary_interleaved_blocks: Vec::new(),
			residual_weights: Vec::new(),
		})
	}

	#[allow(clippy::too_many_arguments)]
	fn new_with_boundaries(
		group_words: Vec<&'a [[u64; 25]]>,
		bit_weights: [F; BIT_INDEX_SIZE],
		group_lane_weights: Vec<[F; 25]>,
		batch_weights: Vec<F>,
		rounds: Vec<usize>,
		eval_point: Vec<F>,
		batched_eval: F,
		boundary_words: Vec<&'a [[u64; 25]]>,
		residual_weights: Vec<F>,
	) -> Result<Self, SumcheckError> {
		let expected_len = 1usize << eval_point.len();
		for words in &group_words {
			if words.len() != expected_len {
				return Err(SumcheckError::MultilinearSizeMismatch);
			}
		}
		for words in &boundary_words {
			if words.len() != expected_len {
				return Err(SumcheckError::MultilinearSizeMismatch);
			}
		}

		let gruen32 = Gruen32::new(&eval_point);

		Ok(Self {
			interleaved_blocks: Vec::new(),
			group_words: Some(group_words),
			bit_weights,
			group_lane_weights,
			batch_weights,
			rounds,
			last_coeffs_or_eval: RoundCoeffsOrEval::Eval(batched_eval),
			gruen32,
			boundary_words: Some(boundary_words),
			boundary_interleaved_blocks: Vec::new(),
			residual_weights,
		})
	}

	fn has_boundaries(&self) -> bool {
		!self.residual_weights.is_empty()
	}
}

impl<'a, F: Field + Send + Sync, P: PackedField<Scalar = F> + Sync> SumcheckProver<F>
	for BatchedParallelProver<'a, P>
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
		let n_groups = self.rounds.len();

		let has_boundaries = self.has_boundaries();
		let n_boundaries = self.residual_weights.len();

		let (y_1, y_inf) = if let Some(ref words_vec) = self.group_words {
			let boundary_words_ref = self.boundary_words.as_ref();
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
						let mut inst_y_1 = F::ZERO;
						let mut inst_y_inf = F::ZERO;
						for g in 0..n_groups {
							let (c1, cinf) = fused_chi_linear_word_pair_eval(
								&words_vec[g][i],
								&words_vec[g][split + i],
								&self.group_lane_weights[g],
								self.rounds[g],
								&self.bit_weights,
							);
							if has_boundaries && g < n_boundaries {
								let rw = self.residual_weights[g];
								let eff = self.batch_weights[g] + rw;
								let bnd_y1 = weighted_output_eval_at_hi(
									&boundary_words_ref.unwrap()[g][split + i],
									&self.group_lane_weights[g],
									&self.bit_weights,
								);
								inst_y_1 += eff * c1 - rw * bnd_y1;
								inst_y_inf += eff * cinf;
							} else {
								inst_y_1 += self.batch_weights[g] * c1;
								inst_y_inf += self.batch_weights[g] * cinf;
							}
						}
						chunk_y_1 += eq_i * inst_y_1;
						chunk_y_inf += eq_i * inst_y_inf;
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
						let lo_base = i * n_groups;
						let hi_base = (split + i) * n_groups;
						let mut inst_y_1 = F::ZERO;
						let mut inst_y_inf = F::ZERO;
						for g in 0..n_groups {
							let (c1, cinf) = fused_chi_linear_pair_eval_blocks(
								&self.interleaved_blocks[lo_base + g],
								&self.interleaved_blocks[hi_base + g],
								&self.group_lane_weights[g],
								self.rounds[g],
								&self.bit_weights,
							);
							if has_boundaries && g < n_boundaries {
								let rw = self.residual_weights[g];
								let eff = self.batch_weights[g] + rw;
								let bnd_hi_idx = (split + i) * n_boundaries + g;
								let bnd_y1 = weighted_output_block_eval_at_hi(
									&self.boundary_interleaved_blocks[bnd_hi_idx],
									&self.group_lane_weights[g],
									&self.bit_weights,
								);
								inst_y_1 += eff * c1 - rw * bnd_y1;
								inst_y_inf += eff * cinf;
							} else {
								inst_y_1 += self.batch_weights[g] * c1;
								inst_y_inf += self.batch_weights[g] * cinf;
							}
						}
						chunk_y_1 += eq_i * inst_y_1;
						chunk_y_inf += eq_i * inst_y_inf;
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

		if let Some(words_vec) = self.group_words.take() {
			let n_groups = words_vec.len();
			let split = words_vec[0].len() / 2;
			let lookup = [F::ZERO, F::ONE + challenge, challenge, F::ONE];

			self.interleaved_blocks = (0..split * n_groups)
				.into_par_iter()
				.map(|idx| {
					let i = idx / n_groups;
					let g = idx % n_groups;
					let words = words_vec[g];
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
				.collect();

			if let Some(bnd_words) = self.boundary_words.take() {
				let n_boundaries = bnd_words.len();
				self.boundary_interleaved_blocks = (0..split * n_boundaries)
					.into_par_iter()
					.map(|idx| {
						let i = idx / n_boundaries;
						let b = idx % n_boundaries;
						let words = bnd_words[b];
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
					.collect();
			}
		} else {
			fold_block_tables_inplace(&mut self.interleaved_blocks, challenge);
			if !self.boundary_interleaved_blocks.is_empty() {
				fold_block_tables_inplace(&mut self.boundary_interleaved_blocks, challenge);
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

		let n_groups = self.rounds.len();
		let mut evals = Vec::with_capacity(n_groups * 25);

		if let Some(words_vec) = self.group_words {
			for g in 0..n_groups {
				for lane in 0..25 {
					let word = words_vec[g][0][lane];
					let mut acc = F::ZERO;
					let mut bits = word;
					while bits != 0 {
						let bit = bits.trailing_zeros() as usize;
						acc += self.bit_weights[bit];
						bits &= bits - 1;
					}
					evals.push(acc);
				}
			}
		} else {
			for g in 0..n_groups {
				let block = &self.interleaved_blocks[g];
				for lane in 0..25 {
					evals.push(
						std::iter::zip(&block[lane], &self.bit_weights)
							.fold(F::ZERO, |acc, (val, weight)| acc + *val * *weight),
					);
				}
			}
		}

		Ok(evals)
	}
}

impl<'a, F: Field, P: PackedField<Scalar = F>> MleCheckProver<F>
	for BatchedParallelProver<'a, P>
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn group_boundary_output(trace: &CompactTrace, group: usize, group_size: usize) -> &[[u64; 25]] {
	let end_round = (group + 1) * group_size;
	if end_round >= 24 {
		trace.final_output.as_slice()
	} else {
		trace.round_inputs[end_round].as_slice()
	}
}

fn group_round(group: usize, group_size: usize, layer: usize) -> usize {
	group * group_size + (group_size - 1 - layer)
}

fn validate_parallel_args(trace: &CompactTrace, group_size: usize) -> Result<(), Error> {
	if trace.round_inputs.len() != 24 {
		return Err(Error::InvalidClaim("trace must contain exactly 24 rounds"));
	}
	let n_instances = trace.round_inputs[0].len();
	if !n_instances.is_power_of_two() {
		return Err(Error::InvalidClaim(
			"number of instances must be a power of two",
		));
	}
	if !trace
		.round_inputs
		.iter()
		.all(|round| round.len() == n_instances)
	{
		return Err(Error::InvalidClaim(
			"all rounds must have the same number of instances",
		));
	}
	if trace.final_output.len() != n_instances {
		return Err(Error::InvalidClaim(
			"final output must have the same number of instances",
		));
	}
	if group_size == 0 || 24 % group_size != 0 {
		return Err(Error::InvalidClaim("group_size must divide 24 evenly"));
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

	fn run_parallel_prove_verify(group_size: usize, n_instances: usize) {
		let mut rng = StdRng::seed_from_u64(700 + group_size as u64 + n_instances as u64);
		let inputs: Vec<[u64; 25]> = (0..n_instances)
			.map(|_| array::from_fn(|_| rng.random::<u64>()))
			.collect();
		let trace = compact_trace_from_inputs(&inputs);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove_parallel::<P, _>(&trace, group_size, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output =
			verify_parallel::<F, _>(&trace, group_size, &mut verifier_transcript).unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
	}

	#[test]
	fn test_parallel_k2() {
		run_parallel_prove_verify(2, 2);
	}

	#[test]
	fn test_parallel_k3() {
		run_parallel_prove_verify(3, 2);
	}

	#[test]
	fn test_parallel_k4() {
		run_parallel_prove_verify(4, 2);
	}

	#[test]
	fn test_parallel_k6() {
		run_parallel_prove_verify(6, 2);
	}

	#[test]
	fn test_parallel_k8() {
		run_parallel_prove_verify(8, 2);
	}

	#[test]
	fn test_parallel_k12() {
		run_parallel_prove_verify(12, 2);
	}

	#[test]
	fn test_parallel_k24() {
		run_parallel_prove_verify(24, 2);
	}

	#[test]
	fn test_parallel_k4_larger_batch() {
		run_parallel_prove_verify(4, 4);
	}

	#[test]
	fn test_parallel_k4_batch_8() {
		run_parallel_prove_verify(4, 8);
	}

	#[test]
	fn test_parallel_rejects_boundary_corruption() {
		let mut rng = StdRng::seed_from_u64(800);
		let inputs: Vec<[u64; 25]> = (0..2)
			.map(|_| array::from_fn(|_| rng.random::<u64>()))
			.collect();
		let trace = compact_trace_from_inputs(&inputs);
		let mut corrupted_trace = trace.clone();
		corrupted_trace.round_inputs[4][0][0] ^= 1;

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_parallel::<P, _>(&corrupted_trace, 4, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(
			verify_parallel::<F, _>(&trace, 4, &mut verifier_transcript).is_err()
		);
	}

	#[test]
	fn test_parallel_rejects_intermediate_corruption() {
		let mut rng = StdRng::seed_from_u64(801);
		let inputs: Vec<[u64; 25]> = (0..2)
			.map(|_| array::from_fn(|_| rng.random::<u64>()))
			.collect();
		let trace = compact_trace_from_inputs(&inputs);
		let mut corrupted_trace = trace.clone();
		corrupted_trace.round_inputs[5][0][0] ^= 1;

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_parallel::<P, _>(&corrupted_trace, 4, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(
			verify_parallel::<F, _>(&trace, 4, &mut verifier_transcript).is_err()
		);
	}
}
