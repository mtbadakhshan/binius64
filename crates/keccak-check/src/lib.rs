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

use binius_field::{Field, PackedField};
use binius_math::multilinear::evaluate::evaluate;

pub mod chi_iota;
pub mod linear_round;
pub mod protocol;
pub mod rotation;
pub mod trace;

pub use chi_iota::{
	ChiIotaReduction, ChiIotaRoundOutput, prove_round as prove_chi_iota_round,
	verify_round as verify_chi_iota_round,
};
pub use linear_round::{
	LinearRecipe, LinearRecipeTerm, LinearRoundOutput, LinearRoundReduction, RotView,
	build_linear_recipe, materialize_mixed_linear_table, prove_round as prove_linear_round,
	verify_round as verify_linear_round,
};
pub use protocol::{prove, verify};
pub use trace::{
	FullTrace, LaneTables, RoundTrace, RoundTraceWords, state_batch_to_lane_tables,
	trace_from_inputs, trace_words_from_inputs,
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
