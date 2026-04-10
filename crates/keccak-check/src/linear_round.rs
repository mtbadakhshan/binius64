// Copyright 2026 The Binius Developers

use std::{array, collections::BTreeMap, sync::OnceLock};

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
use binius_math::{
	FieldBuffer,
	multilinear::{eq::eq_ind_partial_eval_scalars, fold::fold_highest_var_inplace},
};

use crate::{
	BIT_INDEX_SIZE, BitIndexedMixedClaim, Error, LOG_BIT_INDEX_VARS,
	rotation::{bit_lagrange_weights, rotate_bit_lagrange_weights},
	trace::{LaneTables, R, idx},
};

/// A rotated view of one input lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RotView {
	pub lane: usize,
	pub rot: u32,
}

/// One sparse term in the linear round recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearRecipeTerm<F> {
	pub coeff: F,
	pub rot_view_index: usize,
}

/// Sparse per-output-lane recipe for reconstructing `theta+rho+pi`.
pub type LinearRecipe<F> = [Vec<LinearRecipeTerm<F>>; 25];

/// Input to the standalone linear-round reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearRoundReduction<F> {
	/// Bit-indexed mixed claim on the explicit `pre_chi` lanes.
	pub pre_chi_claim: BitIndexedMixedClaim<F>,
}

/// Output of the standalone linear-round reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearRoundOutput<F> {
	/// Reduced point for the remaining high instance variables.
	pub reduced_high_point: Vec<F>,
	/// Evaluations of the 25 folded input lanes at `reduced_high_point`.
	pub input_evals: [F; 25],
	/// Evaluation of the mixed linear round polynomial at `reduced_high_point`.
	pub reduced_eval: F,
}

#[derive(Debug)]
pub(crate) struct LinearRecipeStatic {
	pub(crate) rot_views: Vec<RotView>,
	pub(crate) recipe_counts: [Vec<(usize, u8)>; 25],
	pub(crate) lane_views: [Vec<(u32, usize)>; 25],
	pub(crate) unique_rotations: Vec<u32>,
	pub(crate) rotation_index: BTreeMap<u32, usize>,
}

pub(crate) fn linear_recipe_static() -> &'static LinearRecipeStatic {
	static LINEAR_RECIPE: OnceLock<LinearRecipeStatic> = OnceLock::new();
	LINEAR_RECIPE.get_or_init(|| {
		let mut rot_view_indices = BTreeMap::<RotView, usize>::new();
		let mut rot_views = Vec::new();
		let mut recipe_maps = array::from_fn::<_, 25, _>(|_| BTreeMap::<usize, u8>::new());

		for y in 0..5 {
			for x in 0..5 {
				let source_lane = idx(x, y);
				let output_lane = idx(y, (2 * x + 3 * y) % 5);
				let rotation = R[source_lane] % 64;

				add_recipe_count(
					&mut rot_view_indices,
					&mut rot_views,
					&mut recipe_maps[output_lane],
					RotView {
						lane: source_lane,
						rot: rotation,
					},
				);

				for s in 0..5 {
					add_recipe_count(
						&mut rot_view_indices,
						&mut rot_views,
						&mut recipe_maps[output_lane],
						RotView {
							lane: idx((x + 4) % 5, s),
							rot: rotation,
						},
					);
					add_recipe_count(
						&mut rot_view_indices,
						&mut rot_views,
						&mut recipe_maps[output_lane],
						RotView {
							lane: idx((x + 1) % 5, s),
							rot: (rotation + 1) % 64,
						},
					);
				}
			}
		}

		let recipe_counts = recipe_maps.map(|recipe_map| recipe_map.into_iter().collect());
		let mut lane_views = array::from_fn::<_, 25, _>(|_| Vec::new());
		let mut unique_rotations = Vec::new();
		let mut rotation_index = BTreeMap::new();

		for (rot_view_index, rot_view) in rot_views.iter().copied().enumerate() {
			lane_views[rot_view.lane].push((rot_view.rot, rot_view_index));
			if let std::collections::btree_map::Entry::Vacant(entry) =
				rotation_index.entry(rot_view.rot)
			{
				entry.insert(unique_rotations.len());
				unique_rotations.push(rot_view.rot);
			}
		}

		LinearRecipeStatic {
			rot_views,
			recipe_counts,
			lane_views,
			unique_rotations,
			rotation_index,
		}
	})
}

/// Build the deduplicated rotated-view list and sparse `theta+rho+pi` recipe.
pub fn build_linear_recipe<F: Field>() -> (Vec<RotView>, LinearRecipe<F>) {
	let static_recipe = linear_recipe_static();
	let recipe = static_recipe.recipe_counts.clone().map(|recipe_terms| {
		recipe_terms
			.into_iter()
			.filter_map(|(rot_view_index, count)| {
				let coeff = coeff_from_count::<F>(count);
				(coeff != F::ZERO).then_some(LinearRecipeTerm {
					coeff,
					rot_view_index,
				})
			})
			.collect()
	});

	(static_recipe.rot_views.clone(), recipe)
}

/// Materialize the mixed linear polynomial induced by the current lane weights.
///
/// # Preconditions
///
/// - every input lane must have the same dimension
/// - lane tables must have at least 6 variables
pub fn materialize_mixed_linear_table<P: PackedField>(
	input: &LaneTables<P>,
	bit_weights: &[P::Scalar; BIT_INDEX_SIZE],
	lane_weights: [P::Scalar; 25],
) -> FieldBuffer<P> {
	let log_len = input[0].log_len();
	assert!(
		log_len >= LOG_BIT_INDEX_VARS,
		"precondition: lane tables must have at least 6 variables"
	);
	assert!(
		input
			.iter()
			.all(|lane_table| lane_table.log_len() == log_len),
		"precondition: all lane tables must have the same dimension"
	);
	let _materialize_guard = tracing::info_span!(
		"[phase] Materialize Mixed Linear Table",
		phase = "keccak_linear_materialize",
		perfetto_category = "phase",
		n_vars = log_len - LOG_BIT_INDEX_VARS
	)
	.entered();

	let view_weights = view_weights_from_lane_weights(&lane_weights);
	materialize_weighted_rot_view_sum(input, &view_weights, bit_weights)
}

/// Prove one `theta+rho+pi` linear reduction step.
pub fn prove_round<P, Channel>(
	input: &LaneTables<P>,
	reduction: &LinearRoundReduction<P::Scalar>,
	channel: &mut Channel,
) -> Result<LinearRoundOutput<P::Scalar>, Error>
where
	P: PackedField,
	P::Scalar: BinaryField,
	Channel: IPProverChannel<P::Scalar>,
{
	validate_reduction(input, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Linear Prove",
		phase = "keccak_linear_prove",
		perfetto_category = "phase",
		n_vars = reduction.pre_chi_claim.high_point.len()
	)
	.entered();

	let bit_weights = bit_lagrange_weights(reduction.pre_chi_claim.bit_challenge);
	let mixed_linear_table =
		materialize_mixed_linear_table(input, &bit_weights, reduction.pre_chi_claim.lane_weights);
	let prover = LinearMleCheckProver::new(
		mixed_linear_table,
		reduction.pre_chi_claim.high_point.clone(),
		reduction.pre_chi_claim.mixed_eval,
	)?;
	let proof_output = prove_single_mlecheck(prover, channel)?;
	let reduced_eval = proof_output
		.multilinear_evals
		.first()
		.copied()
		.ok_or(Error::InvalidClaim("expected one mixed linear evaluation"))?;
	let mut reduced_high_point = proof_output.challenges;
	reduced_high_point.reverse();
	let input_evals = evaluate_input_lanes_at_point(input, &reduced_high_point, &bit_weights);

	Ok(LinearRoundOutput {
		reduced_high_point,
		input_evals,
		reduced_eval,
	})
}

/// Verify one `theta+rho+pi` linear reduction step against explicit input tables.
pub fn verify_round<F, P, Channel>(
	input: &LaneTables<P>,
	reduction: &LinearRoundReduction<F>,
	channel: &mut Channel,
) -> Result<LinearRoundOutput<F>, Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	Channel: IPVerifierChannel<F, Elem = F>,
{
	validate_reduction(input, reduction)?;
	let _phase_guard = tracing::info_span!(
		"[phase] Keccak Linear Verify",
		phase = "keccak_linear_verify",
		perfetto_category = "phase",
		n_vars = reduction.pre_chi_claim.high_point.len()
	)
	.entered();

	let mlecheck_output = mlecheck::verify(
		&reduction.pre_chi_claim.high_point,
		1,
		reduction.pre_chi_claim.mixed_eval,
		channel,
	)?;
	let mut reduced_high_point = mlecheck_output.challenges;
	reduced_high_point.reverse();
	let bit_weights = bit_lagrange_weights(reduction.pre_chi_claim.bit_challenge);
	let (input_evals, reduced_eval) = evaluate_input_lanes_and_linear_at_point(
		input,
		&reduction.pre_chi_claim.lane_weights,
		&reduced_high_point,
		&bit_weights,
	);
	channel.assert_zero(reduced_eval - mlecheck_output.eval)?;

	Ok(LinearRoundOutput {
		reduced_high_point,
		input_evals,
		reduced_eval,
	})
}

fn add_recipe_count(
	rot_view_indices: &mut BTreeMap<RotView, usize>,
	rot_views: &mut Vec<RotView>,
	recipe_map: &mut BTreeMap<usize, u8>,
	rot_view: RotView,
) {
	let rot_view_index = if let Some(&existing_index) = rot_view_indices.get(&rot_view) {
		existing_index
	} else {
		let next_index = rot_views.len();
		rot_views.push(rot_view);
		rot_view_indices.insert(rot_view, next_index);
		next_index
	};

	recipe_map
		.entry(rot_view_index)
		.and_modify(|count| *count += 1)
		.or_insert(1);
}

pub(crate) fn coeff_from_count<F: Field>(count: u8) -> F {
	(0..count).fold(F::ZERO, |acc, _| acc + F::ONE)
}

fn view_weights_from_lane_weights<F: Field>(lane_weights: &[F; 25]) -> Vec<F> {
	let static_recipe = linear_recipe_static();
	let mut view_weights = vec![F::ZERO; static_recipe.rot_views.len()];

	for output_lane in 0..25 {
		let output_weight = lane_weights[output_lane];
		for &(rot_view_index, count) in &static_recipe.recipe_counts[output_lane] {
			let coeff = coeff_from_count::<F>(count);
			if coeff != F::ZERO {
				view_weights[rot_view_index] += output_weight * coeff;
			}
		}
	}

	view_weights
}

fn materialize_weighted_rot_view_sum<P: PackedField>(
	input: &LaneTables<P>,
	view_weights: &[P::Scalar],
	bit_weights: &[P::Scalar; BIT_INDEX_SIZE],
) -> FieldBuffer<P> {
	let static_recipe = linear_recipe_static();
	assert_eq!(
		static_recipe.rot_views.len(),
		view_weights.len(),
		"precondition: each rotated view must have a matching weight"
	);

	let log_len = input[0].log_len();
	let log_h = log_len - LOG_BIT_INDEX_VARS;
	let rotated_bit_weights = static_recipe
		.unique_rotations
		.iter()
		.map(|&rot| rotate_bit_lagrange_weights(bit_weights, rot))
		.collect::<Vec<_>>();
	let mut mixed_values = vec![P::Scalar::ZERO; 1 << log_h];
	for lane in 0..25 {
		let active_rotations = static_recipe.lane_views[lane]
			.iter()
			.filter_map(|&(rot, rot_view_index)| {
				let coeff = view_weights[rot_view_index];
				(coeff != P::Scalar::ZERO).then_some((rot, coeff))
			})
			.collect::<Vec<_>>();
		if active_rotations.is_empty() {
			continue;
		}

		for (instance_index, mixed_value) in mixed_values.iter_mut().enumerate() {
			let input_block = input[lane].chunk(6, instance_index);
			*mixed_value += active_rotations
				.iter()
				.fold(P::Scalar::ZERO, |acc, (rot, coeff)| {
					let rotation_index = static_recipe.rotation_index[rot];
					let rotated_weights = &rotated_bit_weights[rotation_index];
					acc + *coeff
						* std::iter::zip(input_block.iter_scalars(), rotated_weights)
							.fold(P::Scalar::ZERO, |block_acc, (value, weight)| {
								block_acc + value * *weight
							})
				});
		}
	}

	FieldBuffer::from_values(&mixed_values)
}

fn evaluate_input_lanes_at_point<F: Field, P: PackedField<Scalar = F>>(
	input: &LaneTables<P>,
	high_point: &[F],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> [F; 25] {
	let lane_low_vectors = evaluate_lane_low_vectors(input, high_point);

	array::from_fn(|lane| dot_64(&lane_low_vectors[lane], bit_weights))
}

fn evaluate_input_lanes_and_linear_at_point<F: Field, P: PackedField<Scalar = F>>(
	input: &LaneTables<P>,
	lane_weights: &[F; 25],
	high_point: &[F],
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> ([F; 25], F) {
	let _eval_guard = tracing::info_span!(
		"[phase] Evaluate Linear Round Point",
		phase = "keccak_linear_point_eval",
		perfetto_category = "phase",
		n_vars = high_point.len()
	)
	.entered();
	let static_recipe = linear_recipe_static();
	let lane_low_vectors = evaluate_lane_low_vectors(input, high_point);
	let input_evals = array::from_fn(|lane| dot_64(&lane_low_vectors[lane], bit_weights));
	let rotated_weights = static_recipe
		.unique_rotations
		.iter()
		.map(|&rot| rotate_bit_lagrange_weights(bit_weights, rot))
		.collect::<Vec<_>>();
	let view_weights = view_weights_from_lane_weights(lane_weights);

	let reduced_eval = static_recipe.rot_views.iter().enumerate().fold(
		F::ZERO,
		|acc, (rot_view_index, rot_view)| {
			let coeff = view_weights[rot_view_index];
			if coeff == F::ZERO {
				return acc;
			}

			let rotation_index = static_recipe.rotation_index[&rot_view.rot];
			acc + coeff * dot_64(&lane_low_vectors[rot_view.lane], &rotated_weights[rotation_index])
		},
	);

	(input_evals, reduced_eval)
}

fn evaluate_lane_low_vectors<F: Field, P: PackedField<Scalar = F>>(
	input: &LaneTables<P>,
	high_point: &[F],
) -> [[F; 64]; 25] {
	let high_eq = if high_point.is_empty() {
		vec![F::ONE]
	} else {
		eq_ind_partial_eval_scalars(high_point)
	};

	array::from_fn(|lane| {
		let mut low_vector = [F::ZERO; 64];
		for (instance_index, &instance_weight) in high_eq.iter().enumerate() {
			if instance_weight == F::ZERO {
				continue;
			}

			let block = input[lane].chunk(6, instance_index);
			for (slot, value) in low_vector.iter_mut().zip(block.iter_scalars()) {
				*slot += instance_weight * value;
			}
		}
		low_vector
	})
}

fn dot_64<F: Field>(lhs: &[F; 64], rhs: &[F]) -> F {
	debug_assert_eq!(rhs.len(), 64);
	std::iter::zip(lhs, rhs).fold(F::ZERO, |acc, (lhs_i, rhs_i)| acc + *lhs_i * *rhs_i)
}

fn validate_reduction<F: Field, P: PackedField<Scalar = F>>(
	input: &LaneTables<P>,
	reduction: &LinearRoundReduction<F>,
) -> Result<(), Error> {
	let log_len = input[0].log_len();
	if log_len < LOG_BIT_INDEX_VARS {
		return Err(Error::InvalidClaim("lane tables must have at least 6 variables"));
	}

	if !input
		.iter()
		.all(|lane_table| lane_table.log_len() == log_len)
	{
		return Err(Error::InvalidClaim("all input lane tables must have the same dimension"));
	}

	if reduction.pre_chi_claim.high_point.len() + LOG_BIT_INDEX_VARS != log_len {
		return Err(Error::InvalidClaim("high-point length must match the input lane dimensions"));
	}

	Ok(())
}

struct LinearMleCheckProver<P: PackedField> {
	multilinear: FieldBuffer<P>,
	last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
	gruen32: Gruen32<P>,
}

impl<F: Field, P: PackedField<Scalar = F>> LinearMleCheckProver<P> {
	fn new(
		multilinear: FieldBuffer<P>,
		eval_point: Vec<F>,
		eval_claim: F,
	) -> Result<Self, SumcheckError> {
		if multilinear.log_len() != eval_point.len() {
			return Err(SumcheckError::MultilinearSizeMismatch);
		}

		Ok(Self {
			multilinear,
			last_coeffs_or_eval: RoundCoeffsOrEval::Eval(eval_claim),
			gruen32: Gruen32::new(&eval_point),
		})
	}
}

impl<F: Field, P: PackedField<Scalar = F>> SumcheckProver<F> for LinearMleCheckProver<P> {
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
		assert!(
			n_vars_remaining > 0,
			"precondition: linear prover must have at least one variable"
		);

		let eq_expansion = self.gruen32.eq_expansion();
		let (_split_0, split_1) = self.multilinear.split_half_ref();
		let y_1_packed = std::iter::zip(eq_expansion.as_ref(), split_1.as_ref())
			.fold(P::zero(), |acc, (eq_i, eval_1)| acc + *eq_i * *eval_1);
		let y_1 = y_1_packed
			.iter()
			.take(1 << n_vars_remaining.saturating_sub(1))
			.sum::<F>();
		let alpha = self.gruen32.next_coordinate();
		let y_0 = (last_eval - y_1 * alpha) * (F::ONE - alpha).invert_or_zero();
		let round_coeffs = RoundCoeffs(vec![y_0, y_1 - y_0]);

		self.last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), SumcheckError> {
		let coeffs = match &self.last_coeffs_or_eval {
			RoundCoeffsOrEval::Coeffs(coeffs) => coeffs,
			RoundCoeffsOrEval::Eval(_) => return Err(SumcheckError::ExpectedExecute),
		};

		let eval = coeffs.evaluate(challenge);
		fold_highest_var_inplace(&mut self.multilinear, challenge);
		self.gruen32.fold(challenge);
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Eval(eval);
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, SumcheckError> {
		if self.n_vars() > 0 {
			let error = match self.last_coeffs_or_eval {
				RoundCoeffsOrEval::Coeffs(_) => SumcheckError::ExpectedFold,
				RoundCoeffsOrEval::Eval(_) => SumcheckError::ExpectedExecute,
			};
			return Err(error);
		}

		Ok(vec![self.multilinear.get(0)])
	}
}

impl<F: Field, P: PackedField<Scalar = F>> MleCheckProver<F> for LinearMleCheckProver<P> {
	fn eval_point(&self) -> &[F] {
		&self.gruen32.eval_point()[..self.n_vars()]
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
		Field, Random,
		arch::{OptimalB128, OptimalPackedB128},
	};
	use binius_math::{
		BinarySubspace, multilinear::evaluate::evaluate, test_utils::random_scalars,
	};
	use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::HasherChallenger};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{bit_indexed_lane_claim, trace::trace_from_inputs};

	type F = OptimalB128;
	type P = OptimalPackedB128;
	type StdChallenger = HasherChallenger<sha2::Sha256>;

	#[test]
	fn test_build_linear_recipe_has_expected_unique_view_count() {
		let (rot_views, recipe) = build_linear_recipe::<F>();
		assert_eq!(rot_views.len(), 274);
		assert_eq!(recipe.iter().map(Vec::len).sum::<usize>(), 275);
	}

	#[test]
	fn test_linear_recipe_reconstructs_pre_chi_on_boolean_points() {
		let mut rng = StdRng::seed_from_u64(7);
		let input_state = array::from_fn(|_| rng.random::<u64>());
		let trace = trace_from_inputs::<P>(&[input_state]);
		let round_trace = &trace.rounds[0];

		for lane in 0..25 {
			let lane_weights =
				array::from_fn(|weight_lane| if weight_lane == lane { F::ONE } else { F::ZERO });
			for bit in 0..64 {
				let bit_challenge = BinarySubspace::<F>::with_dim(LOG_BIT_INDEX_VARS)
					.iter()
					.nth(bit)
					.expect("bit domain must contain 64 elements");
				let bit_weights = bit_lagrange_weights(bit_challenge);
				let reconstructed =
					materialize_mixed_linear_table(&round_trace.input, &bit_weights, lane_weights);
				let expected =
					bit_indexed_lane_claim(&round_trace.pre_chi, bit_challenge, &[], lane_weights);
				assert_eq!(
					reconstructed.get(0),
					expected.mixed_eval,
					"mismatch on lane={lane}, bit={bit}"
				);
			}
		}
	}

	#[test]
	fn test_linear_round_prove_verify() {
		let mut rng = StdRng::seed_from_u64(8);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let round_trace = &trace.rounds[0];
		let bit_challenge = F::random(&mut rng);
		let high_point = random_scalars::<F>(&mut rng, 1);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let pre_chi_claim =
			bit_indexed_lane_claim(&round_trace.pre_chi, bit_challenge, &high_point, lane_weights);
		let reduction = LinearRoundReduction { pre_chi_claim };

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove_round::<P, _>(&round_trace.input, &reduction, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		let verifier_output =
			verify_round::<F, P, _>(&round_trace.input, &reduction, &mut verifier_transcript)
				.unwrap();
		verifier_transcript.finalize().unwrap();

		assert_eq!(prover_output, verifier_output);
		let bit_weights = bit_lagrange_weights(bit_challenge);
		assert_eq!(
			prover_output.reduced_eval,
			evaluate(
				&materialize_mixed_linear_table(
					&round_trace.input,
					&bit_weights,
					reduction.pre_chi_claim.lane_weights,
				),
				&prover_output.reduced_high_point
			)
		);
	}

	#[test]
	fn test_linear_round_rejects_corrupted_input() {
		let mut rng = StdRng::seed_from_u64(9);
		let inputs = vec![
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
			array::from_fn(|_| rng.random::<u64>()),
		];
		let trace = trace_from_inputs::<P>(&inputs);
		let round_trace = &trace.rounds[0];
		let bit_challenge = F::random(&mut rng);
		let high_point = random_scalars::<F>(&mut rng, 2);
		let lane_weights = array::from_fn(|_| F::random(&mut rng));
		let pre_chi_claim =
			bit_indexed_lane_claim(&round_trace.pre_chi, bit_challenge, &high_point, lane_weights);
		let reduction = LinearRoundReduction { pre_chi_claim };

		let mut corrupted_input = round_trace.input.clone();
		for scalar_index in [0usize, 64, 128] {
			let current = corrupted_input[0].get(scalar_index);
			let flipped = if current == F::ZERO { F::ONE } else { F::ZERO };
			corrupted_input[0].set(scalar_index, flipped);
		}

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prove_round::<P, _>(&corrupted_input, &reduction, &mut prover_transcript).unwrap();
		let proof_bytes = prover_transcript.finalize();

		let mut verifier_transcript =
			VerifierTranscript::new(StdChallenger::default(), proof_bytes);
		assert!(
			verify_round::<F, P, _>(&round_trace.input, &reduction, &mut verifier_transcript)
				.is_err()
		);
	}
}
