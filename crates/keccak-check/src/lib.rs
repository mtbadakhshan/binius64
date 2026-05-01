// Copyright 2026 The Binius Developers

//! Standalone binary-field KeccakCheck building blocks.
//!
//! This crate provides the first implementation slices for a Keccak-specific
//! multilinear-check protocol over binary tower fields. It currently focuses on
//! explicit trace materialization, rotation helpers, and a one-round
//! `chi+iota` reduction built on the existing native MLE-check APIs.
//!
//! # When to use this crate
//!
//! Use this crate when experimenting with or validating Keccak-specific proof
//! reductions outside the main `CircuitBuilder` pipeline.
//!
//! # Key types
//!
//! - [`MixedClaim`] - Mixed lane-evaluation claim at a single point
//! - [`trace::RoundTrace`] - Explicit per-round Keccak tables
//! - [`chi_iota::ChiIotaReduction`] - One-round `chi+iota` reduction input
//!
//! # Related crates
//!
//! - `binius-ip` - Verifier-side MLE-check verification
//! - `binius-ip-prover` - Prover-side MLE-check kernels
//! - `binius-math` - Field buffers and multilinear evaluation helpers

#![warn(rustdoc::missing_crate_level_docs)]

use std::{array, iter};

use binius_field::{AESTowerField8b, BinaryField, Field, PackedField};
use binius_math::{FieldBuffer, multilinear::evaluate::evaluate};

pub mod chi_iota;
pub mod fused_round;
pub mod grouped_round;
pub mod linear_round;
pub mod oblong_round;
pub mod parallel_groups;
pub mod protocol;
pub mod rotation;
pub mod trace;

pub use chi_iota::{
	ChiIotaReduction, ChiIotaRoundOutput, prove_round as prove_chi_iota_round,
	verify_round as verify_chi_iota_round,
};
pub use fused_round::{
	FusedRoundOutput, FusedRoundReduction, prove_round as prove_fused_round,
	verify_round as verify_fused_round,
};
pub use linear_round::{
	LinearRecipe, LinearRecipeTerm, LinearRoundOutput, LinearRoundReduction, RotView,
	build_linear_recipe, materialize_mixed_linear_table, prove_round as prove_linear_round,
	verify_round as verify_linear_round,
};
pub use oblong_round::{
	mixed_fused_round_oblong_message_from_words, mixed_fused_round_residual_base_from_words,
	prove_fused_round_first_message, prove_fused_round_with_oblong_message,
	prover_message_domain as oblong_prover_message_domain, residual_extension_evals,
	verify_fused_round_first_message, verify_fused_round_with_oblong_message,
};
pub use grouped_round::{
	GroupedRoundOutput, GroupedRoundReduction, prove_group_from_words,
	verify_group_from_words,
};
pub use parallel_groups::{prove_parallel, verify_parallel};
pub use protocol::{prove, prove_grouped, verify, verify_grouped};
pub use trace::{
	CompactTrace, FullTrace, LaneTables, RoundTrace, RoundTraceWords, compact_trace_from_inputs,
	state_batch_to_lane_tables, trace_from_inputs, trace_words_from_inputs,
};

/// A random linear combination claim over the 25 Keccak lanes at a single point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixedClaim<F> {
	/// Evaluation point in low-to-high variable order.
	pub point: Vec<F>,
	/// Random verifier weights, one per lane.
	pub lane_weights: [F; 25],
	/// Claimed evaluations of the 25 lane multilinears at `point`.
	pub lane_evals: [F; 25],
	/// Mixed claim `sum_i lane_weights[i] * lane_evals[i]`.
	pub mixed_eval: F,
}

/// Endpoint claims exposed by the standalone KeccakCheck driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointClaims<F> {
	pub output_claim: MixedClaim<F>,
	pub input_claim: MixedClaim<F>,
}

/// Number of low variables used to index the 64 Keccak bit positions in each lane.
pub const LOG_BIT_INDEX_VARS: usize = 6;

/// Number of bit positions in a Keccak lane.
pub const BIT_INDEX_SIZE: usize = 1 << LOG_BIT_INDEX_VARS;

/// Number of deterministic small-field batch coordinates appended at the high end of the point.
pub const SMALL_FIELD_SUFFIX_VARS: usize = 3;

/// A mixed claim where the 64 lane-bit positions have already been folded at `bit_challenge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitIndexedMixedClaim<F> {
	/// Fixed univariate challenge used to fold the 64 bit positions.
	pub bit_challenge: F,
	/// Evaluation point for the remaining high instance variables.
	pub high_point: Vec<F>,
	/// Random verifier weights, one per lane.
	pub lane_weights: [F; 25],
	/// Claimed evaluations of the 25 folded lane multilinears at `high_point`.
	pub lane_evals: [F; 25],
	/// Mixed claim `sum_i lane_weights[i] * lane_evals[i]`.
	pub mixed_eval: F,
}

/// Endpoint claims exposed by the bit-indexed standalone KeccakCheck driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitIndexedEndpointClaims<F> {
	pub output_claim: BitIndexedMixedClaim<F>,
	pub input_claim: BitIndexedMixedClaim<F>,
}

/// Experimental endpoint claims for the oblong-first-round prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OblongEndpointClaims<F> {
	pub output_claim: OblongRoundBoundaryClaim<F>,
	pub input_claim: OblongRoundBoundaryClaim<F>,
}

/// Boundary claim for an oblong first round before the bit index has been folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OblongRoundBoundaryClaim<F> {
	/// Evaluation point for the batch variables.
	pub high_point: Vec<F>,
	/// Random verifier weights, one per lane.
	pub lane_weights: [F; 25],
}

/// Output of the oblong first round after the verifier samples the bit challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OblongFirstRoundOutput<F> {
	/// Sampled bit-index challenge used to fold the 64-point bit domain.
	pub bit_challenge: F,
	/// The resulting folded output claim consumed by the suffix prover.
	pub output_claim: BitIndexedMixedClaim<F>,
}

/// Build a mixed lane-evaluation claim by directly evaluating explicit lane tables.
///
/// # Preconditions
///
/// - every lane table must have `point.len()` variables
pub fn mixed_lane_claim<F, P>(
	lane_tables: &trace::LaneTables<P>,
	point: &[F],
	lane_weights: [F; 25],
) -> MixedClaim<F>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	assert!(
		lane_tables
			.iter()
			.all(|lane_table| lane_table.log_len() == point.len()),
		"precondition: point length must match all lane table dimensions"
	);

	let lane_evals = array::from_fn(|lane| evaluate(&lane_tables[lane], point));
	let mixed_eval = iter::zip(&lane_weights, &lane_evals)
		.fold(F::ZERO, |acc, (weight, lane_eval)| acc + *weight * *lane_eval);

	MixedClaim {
		point: point.to_vec(),
		lane_weights,
		lane_evals,
		mixed_eval,
	}
}

/// Build a mixed claim from an existing vector of lane evaluations.
pub fn mixed_claim_from_evals<F: Field>(
	point: Vec<F>,
	lane_weights: [F; 25],
	lane_evals: [F; 25],
) -> MixedClaim<F> {
	let mixed_eval = iter::zip(&lane_weights, &lane_evals)
		.fold(F::ZERO, |acc, (weight, lane_eval)| acc + *weight * *lane_eval);

	MixedClaim {
		point,
		lane_weights,
		lane_evals,
		mixed_eval,
	}
}

/// Build a mixed bit-indexed claim by folding each lane at `bit_challenge` and evaluating at
/// `high_point`.
///
/// # Preconditions
///
/// - every lane table must have `LOG_BIT_INDEX_VARS + high_point.len()` variables
pub fn bit_indexed_lane_claim<F, P>(
	lane_tables: &trace::LaneTables<P>,
	bit_challenge: F,
	high_point: &[F],
	lane_weights: [F; 25],
) -> BitIndexedMixedClaim<F>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	let folded_lanes = fold_lane_tables_at_bit_challenge(lane_tables, bit_challenge);
	let lane_evals = array::from_fn(|lane| evaluate(&folded_lanes[lane], high_point));
	bit_indexed_claim_from_evals(bit_challenge, high_point.to_vec(), lane_weights, lane_evals)
}

/// Build a mixed bit-indexed claim directly from word-level data, avoiding field-element
/// expansion.
pub fn bit_indexed_lane_claim_from_words<F: BinaryField>(
	words: &[[u64; 25]],
	bit_challenge: F,
	high_point: &[F],
	lane_weights: [F; 25],
) -> BitIndexedMixedClaim<F> {
	let bit_weights = rotation::bit_lagrange_weights(bit_challenge);
	let low_vectors = chi_iota::evaluate_lane_low_vectors_from_words(words, high_point);
	let lane_evals = chi_iota::fold_low_vectors(&low_vectors, &bit_weights);
	bit_indexed_claim_from_evals(bit_challenge, high_point.to_vec(), lane_weights, lane_evals)
}

/// Build a mixed bit-indexed claim from word-level data after appending deterministic small-field
/// coordinates at the high end of the batch point.
pub fn bit_indexed_lane_claim_from_words_with_small_field_suffix<F>(
	words: &[[u64; 25]],
	bit_challenge: F,
	high_point: &[F],
	small_field_suffix: &[F],
	lane_weights: [F; 25],
) -> BitIndexedMixedClaim<F>
where
	F: BinaryField,
{
	let full_point = extend_high_point_with_small_field_suffix(high_point, small_field_suffix);
	let bit_weights = rotation::bit_lagrange_weights(bit_challenge);
	let low_vectors = chi_iota::evaluate_lane_low_vectors_from_words(words, &full_point);
	let lane_evals = chi_iota::fold_low_vectors(&low_vectors, &bit_weights);
	bit_indexed_claim_from_evals(bit_challenge, high_point.to_vec(), lane_weights, lane_evals)
}

/// Build a bit-indexed mixed claim from an existing vector of folded lane evaluations.
pub fn bit_indexed_claim_from_evals<F: Field>(
	bit_challenge: F,
	high_point: Vec<F>,
	lane_weights: [F; 25],
	lane_evals: [F; 25],
) -> BitIndexedMixedClaim<F> {
	let mixed_eval = iter::zip(&lane_weights, &lane_evals)
		.fold(F::ZERO, |acc, (weight, lane_eval)| acc + *weight * *lane_eval);

	BitIndexedMixedClaim {
		bit_challenge,
		high_point,
		lane_weights,
		lane_evals,
		mixed_eval,
	}
}

/// Return the deterministic small-field suffix challenges, embedded in the ambient challenge field.
pub fn deterministic_small_field_suffix<F>(len: usize) -> Vec<F>
where
	F: From<AESTowerField8b>,
{
	assert!(
		len <= SMALL_FIELD_SUFFIX_VARS,
		"precondition: len must be at most SMALL_FIELD_SUFFIX_VARS"
	);

	[
		AESTowerField8b::new(2),
		AESTowerField8b::new(4),
		AESTowerField8b::new(16),
	][..len]
		.iter()
		.copied()
		.map(F::from)
		.collect()
}

/// Append deterministic small-field suffix coordinates to a high-point prefix.
pub fn extend_high_point_with_small_field_suffix<F: Field>(
	high_point: &[F],
	small_field_suffix: &[F],
) -> Vec<F> {
	let mut full_point = Vec::with_capacity(high_point.len() + small_field_suffix.len());
	full_point.extend_from_slice(high_point);
	full_point.extend_from_slice(small_field_suffix);
	full_point
}

/// Fold the low 6 bit-index variables of each lane table at a fixed `bit_challenge`.
///
/// # Preconditions
///
/// - every lane table must have at least `LOG_BIT_INDEX_VARS` variables
pub fn fold_lane_tables_at_bit_challenge<F, P>(
	lane_tables: &trace::LaneTables<P>,
	bit_challenge: F,
) -> trace::LaneTables<P>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	let bit_weights = rotation::bit_lagrange_weights(bit_challenge);
	fold_lane_tables_with_bit_weights(lane_tables, &bit_weights)
}

/// Fold the low 6 bit-index variables of each lane table with precomputed weights.
///
/// # Preconditions
///
/// - every lane table must have at least `LOG_BIT_INDEX_VARS` variables
pub fn fold_lane_tables_with_bit_weights<F, P>(
	lane_tables: &trace::LaneTables<P>,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> trace::LaneTables<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	let log_len = lane_tables[0].log_len();
	assert!(
		log_len >= LOG_BIT_INDEX_VARS,
		"precondition: lane tables must have at least 6 variables"
	);
	assert!(
		lane_tables
			.iter()
			.all(|lane_table| lane_table.log_len() == log_len),
		"precondition: all lane tables must have the same dimension"
	);
	let log_h = log_len - LOG_BIT_INDEX_VARS;
	let n_high_evals = 1usize << log_h;

	array::from_fn(|lane| {
		let scalars = (0..n_high_evals)
			.map(|instance_index| {
				let block = lane_tables[lane].chunk(LOG_BIT_INDEX_VARS, instance_index);
				iter::zip(block.iter_scalars(), bit_weights)
					.fold(F::ZERO, |acc, (value, weight)| acc + value * *weight)
			})
			.collect::<Vec<_>>();
		FieldBuffer::from_values(&scalars)
	})
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("sumcheck prover error: {0}")]
	SumcheckProver(#[from] binius_ip_prover::sumcheck::Error),
	#[error("sumcheck verifier error: {0}")]
	SumcheckVerifier(#[from] binius_ip::sumcheck::Error),
	#[error("channel error: {0}")]
	Channel(#[from] binius_ip::channel::Error),
	#[error("invalid claim: {0}")]
	InvalidClaim(&'static str),
	#[error("invalid round index: {0}")]
	InvalidRound(usize),
}

fn scalar_bit<P: PackedField>(word: u64, bit: usize) -> P::Scalar {
	if (word >> bit) & 1 == 1 {
		P::Scalar::ONE
	} else {
		P::Scalar::ZERO
	}
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::{
		BinaryField, Random,
		arch::{OptimalB128, OptimalPackedB128},
	};
	use binius_math::{
		BinarySubspace,
		multilinear::evaluate::evaluate,
		test_utils::{index_to_hypercube_point, random_scalars},
		univariate::lagrange_evals_scalars,
	};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::trace::trace_from_inputs;

	type F = OptimalB128;
	type P = OptimalPackedB128;

	fn bit_domain_element<F: BinaryField>(bit_index: usize) -> F {
		assert!(bit_index < BIT_INDEX_SIZE, "bit index out of range");
		let subspace = BinarySubspace::<F>::with_dim(LOG_BIT_INDEX_VARS);
		subspace
			.iter()
			.nth(bit_index)
			.expect("bit domain must contain 64 elements")
	}

	#[test]
	fn test_fold_lane_tables_at_bit_challenge_matches_direct_definition() {
		let mut rng = StdRng::seed_from_u64(12);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let lane_tables = &trace.rounds[0].input;
		let bit_challenge = F::random(&mut rng);
		let bit_weights = rotation::bit_lagrange_weights(bit_challenge);
		let folded = fold_lane_tables_at_bit_challenge(lane_tables, bit_challenge);
		let high_point =
			random_scalars::<F>(&mut rng, lane_tables[0].log_len() - LOG_BIT_INDEX_VARS);

		for lane in 0..25 {
			let actual = evaluate(&folded[lane], &high_point);
			let expected = (0..BIT_INDEX_SIZE).fold(F::ZERO, |acc, bit_index| {
				let mut point = index_to_hypercube_point::<F>(LOG_BIT_INDEX_VARS, bit_index);
				point.extend(high_point.iter().copied());
				acc + bit_weights[bit_index] * evaluate(&lane_tables[lane], &point)
			});
			assert_eq!(actual, expected, "folded lane evaluation mismatch for lane {lane}");
		}
	}

	#[test]
	fn test_bit_indexed_lane_claim_matches_fold_then_evaluate() {
		let mut rng = StdRng::seed_from_u64(13);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let lane_tables = trace.round_output(0);
		let bit_challenge = F::random(&mut rng);
		let high_point =
			random_scalars::<F>(&mut rng, lane_tables[0].log_len() - LOG_BIT_INDEX_VARS);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let claim = bit_indexed_lane_claim(lane_tables, bit_challenge, &high_point, lane_weights);
		let folded = fold_lane_tables_at_bit_challenge(lane_tables, bit_challenge);

		let expected_lane_evals = array::from_fn(|lane| evaluate(&folded[lane], &high_point));
		assert_eq!(claim.lane_evals, expected_lane_evals);
		assert_eq!(
			claim.mixed_eval,
			iter::zip(&lane_weights, &expected_lane_evals)
				.fold(F::ZERO, |acc, (weight, eval)| acc + *weight * *eval)
		);
	}

	#[test]
	fn test_bit_indexed_lane_claim_selects_boolean_bit_slice_on_domain_point() {
		let mut rng = StdRng::seed_from_u64(14);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let lane_tables = &trace.rounds[0].pre_chi;
		let bit_index = 17usize;
		let bit_challenge = bit_domain_element::<F>(bit_index);
		let high_point =
			random_scalars::<F>(&mut rng, lane_tables[0].log_len() - LOG_BIT_INDEX_VARS);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let claim = bit_indexed_lane_claim(lane_tables, bit_challenge, &high_point, lane_weights);

		for lane in 0..25 {
			let mut point = index_to_hypercube_point::<F>(LOG_BIT_INDEX_VARS, bit_index);
			point.extend(high_point.iter().copied());
			assert_eq!(
				claim.lane_evals[lane],
				evaluate(&lane_tables[lane], &point),
				"domain-point lane selection mismatch for lane {lane}"
			);
		}
	}

	#[test]
	fn test_bit_lagrange_weights_match_direct_math_helper() {
		let mut rng = StdRng::seed_from_u64(15);
		let subspace = BinarySubspace::<F>::with_dim(LOG_BIT_INDEX_VARS);
		let bit_challenge = F::random(&mut rng);
		let actual = rotation::bit_lagrange_weights(bit_challenge);
		let expected: [F; BIT_INDEX_SIZE] = lagrange_evals_scalars(&subspace, bit_challenge)
			.try_into()
			.expect("bit subspace must have 64 elements");

		assert_eq!(actual, expected);
	}
}
