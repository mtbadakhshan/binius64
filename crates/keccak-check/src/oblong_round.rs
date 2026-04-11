// Copyright 2026 The Binius Developers

//! Experimental oblong-first-round prototypes.
//! These helpers are kept for reference, but are not wired into `protocol::prove` or `protocol::verify`.
//! Benchmarks on this branch showed clear regressions versus the baseline bit-indexed chain.
//! The transcript-only oblong handoff increased `2^14` proving from about `0.7s` to about `3.0s`.
//! The packed per-bit suffix attempt regressed further to about `36s` at `2^14` and about `68s` at `2^16`.

use std::{array, cmp::max};

use binius_field::{BinaryField, Field, PackedField};
use binius_ip::{channel::IPVerifierChannel, sumcheck::RoundCoeffs};
use binius_ip_prover::{
	channel::IPProverChannel,
	sumcheck::{
		Error as SumcheckError,
		common::{MleCheckProver, SumcheckProver},
		gruen32::Gruen32,
		prove_single_mlecheck,
	},
};
use binius_math::{
	BinarySubspace, FieldBuffer,
	multilinear::{eq::eq_ind_partial_eval_scalars, fold::fold_highest_var_inplace},
	univariate::extrapolate_over_subspace,
};
use rayon::prelude::*;

use crate::{
	BIT_INDEX_SIZE, Error, FusedRoundOutput, FusedRoundReduction, LOG_BIT_INDEX_VARS,
	OblongFirstRoundOutput, OblongRoundBoundaryClaim, bit_indexed_lane_claim_from_words,
	chi_iota::{evaluate_lane_low_vectors_from_words, fold_low_vectors},
	fused_round,
	linear_round::linear_recipe_static,
	rotation::{bit_lagrange_weights, round_constant_from_bit_weights},
	trace::RC,
};

/// The additive prover-message domain for a 64-point Keccak bit-index round.
///
/// This is the direct analogue of the 1-extra-dimension domain used by the AND reduction: the
/// base 64-point bit-index domain plus one extension basis vector for the first univariate
/// message.
pub fn prover_message_domain<F: BinaryField>() -> BinarySubspace<F> {
	BinarySubspace::with_dim(LOG_BIT_INDEX_VARS + 1)
}

/// Compute the mixed fused-round residual on the 64-point boolean bit-index domain.
///
/// For each boolean bit index `z in {0,1}^6`, this returns
/// `sum_instance eq(high_point, instance) * sum_lane lane_weights[lane] * residual(lane, z)`,
/// where `residual = output + fused_round(input)` in characteristic two.
pub fn mixed_fused_round_residual_base_from_words<F: BinaryField>(
	input_words: &[[u64; 25]],
	output_words: &[[u64; 25]],
	round: usize,
	high_point: &[F],
	lane_weights: &[F; 25],
) -> Result<[F; BIT_INDEX_SIZE], Error> {
	if round >= 24 {
		return Err(Error::InvalidRound(round));
	}

	let expected_n_instances = 1usize << high_point.len();
	if input_words.len() != expected_n_instances || output_words.len() != expected_n_instances {
		return Err(Error::InvalidClaim("word count must match 2^high_point.len()"));
	}

	let high_eq = if high_point.is_empty() {
		vec![F::ONE]
	} else {
		eq_ind_partial_eval_scalars(high_point)
	};
	let mut residual = [F::ZERO; BIT_INDEX_SIZE];

	for (instance_index, &instance_weight) in high_eq.iter().enumerate() {
		if instance_weight == F::ZERO {
			continue;
		}

		let pre_chi_words = pre_chi_words_from_input(&input_words[instance_index]);

		for y in 0..5 {
			for x in 0..5 {
				let out_lane = x + 5 * y;
				let weight = lane_weights[out_lane];
				if weight == F::ZERO {
					continue;
				}

				let a = pre_chi_words[out_lane];
				let b = pre_chi_words[(x + 1) % 5 + 5 * y];
				let c = pre_chi_words[(x + 2) % 5 + 5 * y];
				let mut expected = a ^ c ^ (b & c);
				if out_lane == 0 {
					expected ^= RC[round];
				}

				let mut diff = output_words[instance_index][out_lane] ^ expected;
				while diff != 0 {
					let bit = diff.trailing_zeros() as usize;
					residual[bit] += instance_weight * weight;
					diff &= diff - 1;
				}
			}
		}
	}

	Ok(residual)
}

/// Extrapolate a 64-point bit-index residual to the extension half of the prover-message domain.
///
/// The returned evaluations are the naive version of the first oblong-round message. They are
/// intentionally computed via direct extrapolation so we can validate the algebra and transcript
/// contract before introducing lookup tables or NTT-specific acceleration.
pub fn residual_extension_evals<F: BinaryField>(
	residual_base: &[F; BIT_INDEX_SIZE],
) -> [F; BIT_INDEX_SIZE] {
	let message_domain = prover_message_domain::<F>();
	let input_domain = message_domain.reduce_dim(LOG_BIT_INDEX_VARS);
	let shift = message_domain.basis()[LOG_BIT_INDEX_VARS];

	array::from_fn(|idx| {
		let point = shift + input_domain.get(idx);
		extrapolate_over_subspace(&input_domain, residual_base, point)
	})
}

/// Compute the naive first oblong-round extension evaluations directly from explicit word traces.
pub fn mixed_fused_round_oblong_message_from_words<F: BinaryField>(
	input_words: &[[u64; 25]],
	output_words: &[[u64; 25]],
	round: usize,
	high_point: &[F],
	lane_weights: &[F; 25],
) -> Result<[F; BIT_INDEX_SIZE], Error> {
	let residual_base = mixed_fused_round_residual_base_from_words(
		input_words,
		output_words,
		round,
		high_point,
		lane_weights,
	)?;
	Ok(residual_extension_evals(&residual_base))
}

/// Prove one explicit oblong first-round message over the bit index.
pub fn prove_fused_round_first_message<F, Channel>(
	input_words: &[[u64; 25]],
	output_words: &[[u64; 25]],
	round: usize,
	boundary_claim: &OblongRoundBoundaryClaim<F>,
	channel: &mut Channel,
) -> Result<OblongFirstRoundOutput<F>, Error>
where
	F: BinaryField,
	Channel: IPProverChannel<F>,
{
	let oblong_message = mixed_fused_round_oblong_message_from_words(
		input_words,
		output_words,
		round,
		&boundary_claim.high_point,
		&boundary_claim.lane_weights,
	)?;
	channel.send_many(&oblong_message);

	let bit_challenge = channel.sample();
	let output_claim = bit_indexed_lane_claim_from_words(
		output_words,
		bit_challenge,
		&boundary_claim.high_point,
		boundary_claim.lane_weights,
	);
	Ok(OblongFirstRoundOutput {
		bit_challenge,
		output_claim,
	})
}

/// Verify one explicit oblong first-round message over the bit index.
pub fn verify_fused_round_first_message<F, Channel>(
	input_words: &[[u64; 25]],
	output_words: &[[u64; 25]],
	round: usize,
	boundary_claim: &OblongRoundBoundaryClaim<F>,
	channel: &mut Channel,
) -> Result<OblongFirstRoundOutput<F>, Error>
where
	F: BinaryField,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	let received_message = channel.recv_many(BIT_INDEX_SIZE)?;
	let expected_message = mixed_fused_round_oblong_message_from_words(
		input_words,
		output_words,
		round,
		&boundary_claim.high_point,
		&boundary_claim.lane_weights,
	)?;
	for (received, expected) in std::iter::zip(received_message, expected_message) {
		channel.assert_zero(received - expected)?;
	}

	let bit_challenge = channel.sample();
	let output_claim = bit_indexed_lane_claim_from_words(
		output_words,
		bit_challenge,
		&boundary_claim.high_point,
		boundary_claim.lane_weights,
	);
	Ok(OblongFirstRoundOutput {
		bit_challenge,
		output_claim,
	})
}

/// Prove one fused Keccak round with an explicit oblong first-round message over the bit index.
///
/// This helper is sound for a single round boundary claim: the prover sends the extension-domain
/// message first, then both sides sample `z` and continue with a packed quadratic suffix over the
/// folded `pre_chi(z, X)` lane multilinears.
pub fn prove_fused_round_with_oblong_message<P, Channel>(
	input_words: &[[u64; 25]],
	output_words: &[[u64; 25]],
	round: usize,
	high_point: &[P::Scalar],
	lane_weights: [P::Scalar; 25],
	channel: &mut Channel,
) -> Result<FusedRoundOutput<P::Scalar>, Error>
where
	P: PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	let first_round = prove_fused_round_first_message(
		input_words,
		output_words,
		round,
		&OblongRoundBoundaryClaim {
			high_point: high_point.to_vec(),
			lane_weights,
		},
		channel,
	)?;
	let bit_weights = bit_lagrange_weights(first_round.bit_challenge);
	let prover: PackedOblongSuffixProver<'_, P> = PackedOblongSuffixProver::new(
		input_words,
		bit_weights,
		first_round.output_claim.lane_weights,
		round,
		first_round.output_claim.high_point.clone(),
		first_round.output_claim.mixed_eval,
	)?;
	let proof_output = prove_single_mlecheck(prover, channel)?;
	let mut reduced_high_point = proof_output.challenges;
	reduced_high_point.reverse();
	let input_low_vectors = evaluate_lane_low_vectors_from_words(input_words, &reduced_high_point);
	let input_evals = fold_low_vectors(&input_low_vectors, &bit_weights);

	Ok(FusedRoundOutput {
		reduced_high_point,
		input_evals,
	})
}

/// Verify one fused Keccak round with an explicit oblong first-round message over the bit index.
pub fn verify_fused_round_with_oblong_message<F, Channel>(
	input_words: &[[u64; 25]],
	output_words: &[[u64; 25]],
	round: usize,
	high_point: &[F],
	lane_weights: [F; 25],
	channel: &mut Channel,
) -> Result<FusedRoundOutput<F>, Error>
where
	F: BinaryField,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	let first_round = verify_fused_round_first_message(
		input_words,
		output_words,
		round,
		&OblongRoundBoundaryClaim {
			high_point: high_point.to_vec(),
			lane_weights,
		},
		channel,
	)?;
	fused_round::verify_round_from_words::<F, _>(
		input_words,
		&FusedRoundReduction {
			output_claim: first_round.output_claim,
			round,
		},
		channel,
	)
}

#[inline]
fn pre_chi_words_from_input(input_state: &[u64; 25]) -> [u64; 25] {
	let static_recipe = linear_recipe_static();
	array::from_fn(|out_lane| {
		static_recipe.word_recipe[out_lane]
			.iter()
			.fold(0u64, |acc, (src_lane, rot)| acc ^ input_state[*src_lane].rotate_left(*rot))
	})
}

#[inline]
fn bit_weight_byte_lookup<F: Field>(bit_weights: &[F; BIT_INDEX_SIZE]) -> [[F; 256]; 8] {
	array::from_fn(|byte_idx| {
		array::from_fn(|byte| {
			(0..8).fold(F::ZERO, |acc, bit| {
				if (byte >> bit) & 1 == 1 {
					acc + bit_weights[8 * byte_idx + bit]
				} else {
					acc
				}
			})
		})
	})
}

#[inline]
fn fold_word_with_byte_lookup<F: Field>(word: u64, byte_lookup: &[[F; 256]; 8]) -> F {
	(0..8).fold(F::ZERO, |acc, byte_idx| {
		acc + byte_lookup[byte_idx][((word >> (8 * byte_idx)) & 0xff) as usize]
	})
}

const PACKED_SUFFIX_MULTILINEARS: usize = 25 * BIT_INDEX_SIZE;

#[inline(always)]
const fn lane_bit_index(lane: usize, bit: usize) -> usize {
	lane * BIT_INDEX_SIZE + bit
}

#[inline]
fn fused_chi_linear_word_pair_eval<F: Field>(
	input_lo: &[u64; 25],
	input_hi: &[u64; 25],
	lane_weights: &[F; 25],
	round: usize,
	byte_lookup: &[[F; 256]; 8],
) -> (F, F) {
	let pre_chi_lo = pre_chi_words_from_input(input_lo);
	let pre_chi_hi = pre_chi_words_from_input(input_hi);
	let mut acc_1 = F::ZERO;
	let mut acc_inf = F::ZERO;

	for y in 0..5 {
		for x in 0..5 {
			let out_lane = x + 5 * y;
			let weight = lane_weights[out_lane];
			let b_lane = (x + 1) % 5 + 5 * y;
			let c_lane = (x + 2) % 5 + 5 * y;
			let mut chi_bits_1 = pre_chi_hi[out_lane]
				^ pre_chi_hi[c_lane]
				^ (pre_chi_hi[b_lane] & pre_chi_hi[c_lane]);
			if out_lane == 0 {
				chi_bits_1 ^= RC[round];
			}
			let bits_inf = (pre_chi_lo[b_lane] ^ pre_chi_hi[b_lane])
				& (pre_chi_lo[c_lane] ^ pre_chi_hi[c_lane]);
			acc_1 += weight * fold_word_with_byte_lookup(chi_bits_1, byte_lookup);
			acc_inf += weight * fold_word_with_byte_lookup(bits_inf, byte_lookup);
		}
	}

	(acc_1, acc_inf)
}

fn materialize_folded_pre_chi_bit_tables_from_word_pairs<P: PackedField>(
	input_words: &[[u64; 25]],
	challenge: P::Scalar,
) -> [FieldBuffer<P>; PACKED_SUFFIX_MULTILINEARS]
where
	P::Scalar: BinaryField,
{
	let split = input_words.len() / 2;
	let lookup = [
		P::Scalar::ZERO,
		P::Scalar::ONE + challenge,
		challenge,
		P::Scalar::ONE,
	];
	let mut bit_values =
		array::from_fn::<_, PACKED_SUFFIX_MULTILINEARS, _>(|_| Vec::with_capacity(split));

	for i in 0..split {
		let pre_chi_lo = pre_chi_words_from_input(&input_words[i]);
		let pre_chi_hi = pre_chi_words_from_input(&input_words[split + i]);
		for lane in 0..25 {
			for bit in 0..BIT_INDEX_SIZE {
				let lo_bit = (pre_chi_lo[lane] >> bit) & 1;
				let hi_bit = (pre_chi_hi[lane] >> bit) & 1;
				bit_values[lane_bit_index(lane, bit)]
					.push(lookup[(lo_bit | (hi_bit << 1)) as usize]);
			}
		}
	}

	bit_values.map(|values| FieldBuffer::from_values(&values))
}

struct PackedOblongSuffixProver<'a, P: PackedField> {
	state: PackedOblongSuffixState<'a, P>,
	bit_weights: [P::Scalar; BIT_INDEX_SIZE],
	lane_weights: [P::Scalar; 25],
	round: usize,
}

enum PackedOblongSuffixState<'a, P: PackedField> {
	Words {
		input_words: &'a [[u64; 25]],
		last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
		gruen32: Gruen32<P>,
	},
	Packed {
		pre_chi_bit_tables: [FieldBuffer<P>; PACKED_SUFFIX_MULTILINEARS],
		last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
		gruen32: Gruen32<P>,
	},
}

impl<'a, F: BinaryField, P: PackedField<Scalar = F>> PackedOblongSuffixProver<'a, P> {
	fn new(
		input_words: &'a [[u64; 25]],
		bit_weights: [F; BIT_INDEX_SIZE],
		lane_weights: [F; 25],
		round: usize,
		eval_point: Vec<F>,
		mixed_eval: F,
	) -> Result<Self, SumcheckError> {
		let expected_len = 1usize << eval_point.len();
		if input_words.len() != expected_len {
			return Err(SumcheckError::MultilinearSizeMismatch);
		}

		Ok(Self {
			state: PackedOblongSuffixState::Words {
				input_words,
				last_coeffs_or_eval: RoundCoeffsOrEval::Eval(mixed_eval),
				gruen32: Gruen32::new(&eval_point),
			},
			bit_weights,
			lane_weights,
			round,
		})
	}
}

impl<'a, F: BinaryField + Send + Sync, P: PackedField<Scalar = F> + Sync> SumcheckProver<F>
	for PackedOblongSuffixProver<'a, P>
{
	fn n_vars(&self) -> usize {
		match &self.state {
			PackedOblongSuffixState::Words { gruen32, .. } => gruen32.n_vars_remaining(),
			PackedOblongSuffixState::Packed { gruen32, .. } => gruen32.n_vars_remaining(),
		}
	}

	fn n_claims(&self) -> usize {
		1
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, SumcheckError> {
		match &mut self.state {
			PackedOblongSuffixState::Words {
				input_words,
				last_coeffs_or_eval,
				gruen32,
			} => {
				let last_eval = match *last_coeffs_or_eval {
					RoundCoeffsOrEval::Eval(eval) => eval,
					RoundCoeffsOrEval::Coeffs(_) => return Err(SumcheckError::ExpectedFold),
				};
				let n_vars_remaining = gruen32.n_vars_remaining();
				let alpha = gruen32.next_coordinate();
				let split = 1usize << n_vars_remaining.saturating_sub(1);
				let eq_chunks = gruen32.eq_expansion().as_ref();
				let byte_lookup = bit_weight_byte_lookup(&self.bit_weights);
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
							let (contrib_1, contrib_inf) = fused_chi_linear_word_pair_eval(
								&input_words[i],
								&input_words[split + i],
								&self.lane_weights,
								self.round,
								&byte_lookup,
							);
							chunk_y_1 += eq_i * contrib_1;
							chunk_y_inf += eq_i * contrib_inf;
						}
						(chunk_y_1, chunk_y_inf)
					})
					.reduce(|| (F::ZERO, F::ZERO), |(a1, ai), (b1, bi)| (a1 + b1, ai + bi));

				let round_coeffs =
					crate::chi_iota::interpolate_round_coeffs(last_eval, alpha, y_1, y_inf);
				*last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
				Ok(vec![round_coeffs])
			}
			PackedOblongSuffixState::Packed {
				pre_chi_bit_tables,
				last_coeffs_or_eval,
				gruen32,
			} => {
				let last_eval = match *last_coeffs_or_eval {
					RoundCoeffsOrEval::Eval(eval) => eval,
					RoundCoeffsOrEval::Coeffs(_) => return Err(SumcheckError::ExpectedFold),
				};
				let n_vars_remaining = gruen32.n_vars_remaining();
				assert!(n_vars_remaining > 0);
				let eq_expansion = gruen32.eq_expansion();
				assert_eq!(eq_expansion.log_len(), n_vars_remaining - 1);

				let (splits_0, splits_1): (Vec<_>, Vec<_>) = pre_chi_bit_tables
					.iter_mut()
					.map(|multilinear| {
						multilinear.truncate(n_vars_remaining);
						multilinear.split_half_ref()
					})
					.unzip();

				const MAX_CHUNK_VARS: usize = 8;
				let chunk_vars = max(MAX_CHUNK_VARS, P::LOG_WIDTH).min(n_vars_remaining - 1);
				let chunk_count = 1 << (n_vars_remaining - 1 - chunk_vars);
				let round_constant_eval =
					round_constant_from_bit_weights(self.round, &self.bit_weights);

				let (packed_y_1, packed_y_inf) = (0..chunk_count)
					.into_par_iter()
					.map(|chunk_index| {
						let eq_chunk = eq_expansion.chunk(chunk_vars, chunk_index);
						let splits_0_chunk = splits_0
							.iter()
							.map(|slice| slice.chunk(chunk_vars, chunk_index))
							.collect::<Vec<_>>();
						let splits_1_chunk = splits_1
							.iter()
							.map(|slice| slice.chunk(chunk_vars, chunk_index))
							.collect::<Vec<_>>();
						let mut y_1 = P::zero();
						let mut y_inf = P::zero();

						for (idx, &eq_i) in eq_chunk.as_ref().iter().enumerate() {
							let mut contrib_1 =
								P::broadcast(self.lane_weights[0] * round_constant_eval);
							let mut contrib_inf = P::zero();
							for y in 0..5 {
								for x in 0..5 {
									let out_lane = x + 5 * y;
									let b_lane = (x + 1) % 5 + 5 * y;
									let c_lane = (x + 2) % 5 + 5 * y;
									let lane_bit_weight = self.lane_weights[out_lane];
									for bit in 0..BIT_INDEX_SIZE {
										let out_idx = lane_bit_index(out_lane, bit);
										let b_idx = lane_bit_index(b_lane, bit);
										let c_idx = lane_bit_index(c_lane, bit);
										let a_1 = splits_1_chunk[out_idx].as_ref()[idx];
										let b_1 = splits_1_chunk[b_idx].as_ref()[idx];
										let c_1 = splits_1_chunk[c_idx].as_ref()[idx];
										let b_inf = splits_0_chunk[b_idx].as_ref()[idx] + b_1;
										let c_inf = splits_0_chunk[c_idx].as_ref()[idx] + c_1;
										let coeff = lane_bit_weight * self.bit_weights[bit];
										contrib_1 += (a_1 + c_1 + b_1 * c_1) * coeff;
										contrib_inf += (b_inf * c_inf) * coeff;
									}
								}
							}
							y_1 += contrib_1 * eq_i;
							y_inf += contrib_inf * eq_i;
						}

						(y_1, y_inf)
					})
					.reduce(|| (P::zero(), P::zero()), |(a1, ai), (b1, bi)| (a1 + b1, ai + bi));

				let alpha = gruen32.next_coordinate();
				let y_1 = packed_y_1.iter().take(1 << n_vars_remaining).sum();
				let y_inf = packed_y_inf.iter().take(1 << n_vars_remaining).sum();
				let round_coeffs =
					crate::chi_iota::interpolate_round_coeffs(last_eval, alpha, y_1, y_inf);
				*last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
				Ok(vec![round_coeffs])
			}
		}
	}

	fn fold(&mut self, challenge: F) -> Result<(), SumcheckError> {
		let replacement_state = match &mut self.state {
			PackedOblongSuffixState::Words {
				input_words,
				last_coeffs_or_eval,
				gruen32,
			} => {
				let coeffs = match last_coeffs_or_eval {
					RoundCoeffsOrEval::Coeffs(coeffs) => coeffs,
					RoundCoeffsOrEval::Eval(_) => return Err(SumcheckError::ExpectedExecute),
				};
				let remaining_eval_point =
					gruen32.eval_point()[..gruen32.n_vars_remaining().saturating_sub(1)].to_vec();
				PackedOblongSuffixState::Packed {
					pre_chi_bit_tables: materialize_folded_pre_chi_bit_tables_from_word_pairs::<P>(
						input_words,
						challenge,
					),
					last_coeffs_or_eval: RoundCoeffsOrEval::Eval(coeffs.evaluate(challenge)),
					gruen32: Gruen32::new(&remaining_eval_point),
				}
			}
			PackedOblongSuffixState::Packed {
				pre_chi_bit_tables,
				last_coeffs_or_eval,
				gruen32,
			} => {
				let coeffs = match last_coeffs_or_eval {
					RoundCoeffsOrEval::Coeffs(coeffs) => coeffs,
					RoundCoeffsOrEval::Eval(_) => return Err(SumcheckError::ExpectedExecute),
				};
				let n_vars_remaining = gruen32.n_vars_remaining();
				for multilinear in pre_chi_bit_tables.iter_mut() {
					multilinear.truncate(n_vars_remaining);
					fold_highest_var_inplace(multilinear, challenge);
				}
				gruen32.fold(challenge);
				*last_coeffs_or_eval = RoundCoeffsOrEval::Eval(coeffs.evaluate(challenge));
				return Ok(());
			}
		};

		self.state = replacement_state;
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, SumcheckError> {
		match self.state {
			PackedOblongSuffixState::Words {
				input_words,
				last_coeffs_or_eval,
				gruen32,
			} => {
				if gruen32.n_vars_remaining() > 0 {
					return Err(match last_coeffs_or_eval {
						RoundCoeffsOrEval::Coeffs(_) => SumcheckError::ExpectedFold,
						RoundCoeffsOrEval::Eval(_) => SumcheckError::ExpectedExecute,
					});
				}
				let pre_chi_words = pre_chi_words_from_input(&input_words[0]);
				Ok((0..25)
					.flat_map(|lane| {
						(0..BIT_INDEX_SIZE).map(move |bit| {
							if (pre_chi_words[lane] >> bit) & 1 == 1 {
								F::ONE
							} else {
								F::ZERO
							}
						})
					})
					.collect())
			}
			PackedOblongSuffixState::Packed {
				mut pre_chi_bit_tables,
				last_coeffs_or_eval,
				gruen32,
			} => {
				if gruen32.n_vars_remaining() > 0 {
					return Err(match last_coeffs_or_eval {
						RoundCoeffsOrEval::Coeffs(_) => SumcheckError::ExpectedFold,
						RoundCoeffsOrEval::Eval(_) => SumcheckError::ExpectedExecute,
					});
				}
				Ok(pre_chi_bit_tables
					.iter_mut()
					.map(|multilinear| multilinear.get(0))
					.collect())
			}
		}
	}
}

impl<'a, F: BinaryField + Send + Sync, P: PackedField<Scalar = F> + Sync> MleCheckProver<F>
	for PackedOblongSuffixProver<'a, P>
{
	fn eval_point(&self) -> &[F] {
		match &self.state {
			PackedOblongSuffixState::Words { gruen32, .. } => {
				&gruen32.eval_point()[..gruen32.n_vars_remaining()]
			}
			PackedOblongSuffixState::Packed { gruen32, .. } => {
				&gruen32.eval_point()[..gruen32.n_vars_remaining()]
			}
		}
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

	use binius_field::{Field, Random, arch::OptimalB128};
	use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::HasherChallenger};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::trace::compact_trace_from_inputs;

	type F = OptimalB128;
	type P = binius_field::arch::OptimalPackedB128;
	type StdChallenger = HasherChallenger<sha2::Sha256>;
	fn round_output_words(trace: &crate::CompactTrace, round: usize) -> &[[u64; 25]] {
		if round + 1 < trace.round_inputs.len() {
			&trace.round_inputs[round + 1]
		} else {
			&trace.final_output
		}
	}

	#[test]
	fn test_mixed_fused_round_residual_vanishes_on_valid_trace() {
		let mut rng = StdRng::seed_from_u64(17);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);
		let round = 7;
		let high_point = vec![F::random(&mut rng)];
		let lane_weights = [F::ONE; 25];

		let residual = mixed_fused_round_residual_base_from_words(
			&trace.round_inputs[round],
			round_output_words(&trace, round),
			round,
			&high_point,
			&lane_weights,
		)
		.unwrap();
		let extension_evals = residual_extension_evals(&residual);

		assert!(residual.iter().all(|&value| value == F::ZERO));
		assert!(extension_evals.iter().all(|&value| value == F::ZERO));
	}

	#[test]
	fn test_mixed_fused_round_residual_detects_corrupted_output() {
		let mut rng = StdRng::seed_from_u64(23);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);
		let round = 3;
		let high_point = vec![F::random(&mut rng)];
		let lane_weights = [F::ONE; 25];
		let mut corrupted_output = round_output_words(&trace, round).to_vec();
		corrupted_output[0][0] ^= 1;

		let residual = mixed_fused_round_residual_base_from_words(
			&trace.round_inputs[round],
			&corrupted_output,
			round,
			&high_point,
			&lane_weights,
		)
		.unwrap();
		let extension_evals = mixed_fused_round_oblong_message_from_words(
			&trace.round_inputs[round],
			&corrupted_output,
			round,
			&high_point,
			&lane_weights,
		)
		.unwrap();

		assert!(residual.iter().any(|&value| value != F::ZERO));
		assert!(extension_evals.iter().any(|&value| value != F::ZERO));
	}

	#[test]
	fn test_oblong_message_matches_zero_extension_for_valid_trace() {
		let mut rng = StdRng::seed_from_u64(29);
		let inputs = vec![array::from_fn(|_| rng.random::<u64>())];
		let trace = compact_trace_from_inputs(&inputs);
		let round = 23;
		let high_point = [];
		let lane_weights = array::from_fn(|_| F::random(&mut rng));

		let extension_evals = mixed_fused_round_oblong_message_from_words(
			&trace.round_inputs[round],
			round_output_words(&trace, round),
			round,
			&high_point,
			&lane_weights,
		)
		.unwrap();

		assert!(extension_evals.iter().all(|&value| value == F::ZERO));
	}

	#[test]
	fn test_prove_verify_fused_round_with_oblong_message() {
		let mut rng = StdRng::seed_from_u64(31);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);
		let round = 0;
		let high_point = vec![F::random(&mut rng)];
		let lane_weights = array::from_fn(|_| F::random(&mut rng));

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output = prove_fused_round_with_oblong_message::<P, _>(
			&trace.round_inputs[round],
			round_output_words(&trace, round),
			round,
			&high_point,
			lane_weights,
			&mut prover_transcript,
		)
		.unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output = verify_fused_round_with_oblong_message::<F, _>(
			&trace.round_inputs[round],
			round_output_words(&trace, round),
			round,
			&high_point,
			lane_weights,
			&mut verifier_transcript,
		)
		.unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
	}

	#[test]
	fn test_oblong_message_round_rejects_corrupted_output() {
		let mut rng = StdRng::seed_from_u64(37);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = compact_trace_from_inputs(&inputs);
		let round = 0;
		let high_point = vec![F::random(&mut rng)];
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let mut corrupted_output = round_output_words(&trace, round).to_vec();
		corrupted_output[0][0] ^= 1;

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_fused_round_with_oblong_message::<P, _>(
			&trace.round_inputs[round],
			round_output_words(&trace, round),
			round,
			&high_point,
			lane_weights,
			&mut prover_transcript,
		)
		.unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(
			verify_fused_round_with_oblong_message::<F, _>(
				&trace.round_inputs[round],
				&corrupted_output,
				round,
				&high_point,
				lane_weights,
				&mut verifier_transcript,
			)
			.is_err()
		);
	}
}
