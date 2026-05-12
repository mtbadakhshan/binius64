// Copyright 2026 The Binius Developers

//! Claim-reduced Akita bridge verifier channel.
//!
//! A succinct-style Akita bridge that, instead of opening the committed
//! polynomial at two distinct points via Akita's multi-point batched opening
//! (the `akita-claim-reduced` channel's strategy), reduces the two opening claims
//! into a single claim via a claim-reduction sumcheck and then opens at one
//! point. See `docs/hachi-bridge-akita-port-audit-log.md (historical)` for the design
//! discussion of the multi-point vs claim-reduced trade-off.
//!
//! Most of this file is structurally identical to `succinct.rs`
//! (oracle storage, transcript handling, parity bridge, selected & booleanity
//! sumchecks). Blocks that are identical to `succinct.rs` are
//! marked `// SHARED: keep in sync with AkitaSuccinct*Channel`. Differences
//! are limited to:
//!   - `send_oracle` uses `commit` (single-point) instead of
//!     a custom multi-point layout policy (via
//!     `akita_prover::commit_with_policy`).
//!   - `verify_oracle_relations` runs the claim-reduction sumcheck after the
//!     booleanity sumcheck, then opens at one point.
//!   - The opening shape constants (`AKITA_OPENING_POINTS = 1` etc.) reflect
//!     the single-point structure.

use akita_config::{CommitmentConfig, proof_optimized::fp128};
use akita_scheme::AkitaCommitmentScheme;
use akita_transcript::Blake2bTranscript;
use akita_types::{
	AkitaBatchedProof, AkitaBatchedProofShape, AkitaProofStepShape, AkitaRootBatchSummary,
	AkitaScheduleInputs, AkitaVerifierSetup, BasisMode, DirectWitnessShape, LevelProofShape,
	RingCommitment, Step,
	proof::{CommitmentVerifier, CommittedOpenings},
	recursive_level_layout_from_params, schedule_is_root_direct, schedule_num_fold_levels,
	scheduled_fold_execution, scheduled_next_level_params, stage1_tree_stage_shapes,
	w_ring_element_count,
};
use binius_field::Field;
use binius_ip::channel::IPVerifierChannel;
use binius_math::{FieldBuffer, multilinear::evaluate::evaluate_inplace};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use binius_iop::channel::{Error, IOPVerifierChannel, OracleLinearRelation, OracleSpec};

use crate::{
	protocol::{
		BINIUS_SCALAR_BITS, BatchedParityBridgeProof, BiniusScalar, AkitaFieldScalar, batched_u64_sum,
		evaluate_batched_selected_sum_table_mask, evaluate_claim_reduction_transparent,
		evaluate_akita_eq, parity_sum_bounds, verify_claim_reduction_sumcheck_transcript,
		verify_product_sumcheck_transcript, verify_weighted_booleanity_sumcheck_transcript,
	},
	wire,
};

type Cfg = fp128::D64OneHot;
const D: usize = 64;
// Claim-reduced bridge opens at exactly ONE point (the claim-reduction
// sumcheck's final challenge), so the Akita opening shape is
// `(num_claims = 1, num_groups = 1, num_points = 1)`. This contrasts with
// the `akita-succinct` bridge, which opens at 2 points.
const AKITA_OPENING_CLAIMS: usize = 1;
const AKITA_OPENING_GROUPS: usize = 1;
const AKITA_OPENING_POINTS: usize = 1;
type Scheme = AkitaCommitmentScheme<D, Cfg>;
type Commitment = RingCommitment<AkitaFieldScalar, D>;

/// Akita prover setup used by the succinct bridge.
pub type AkitaClaimReducedProverSetup = akita_prover::AkitaProverSetup<AkitaFieldScalar, D>;
/// Akita verifier setup used by the succinct bridge.
pub type AkitaClaimReducedVerifierSetup = AkitaVerifierSetup<AkitaFieldScalar>;

/// Per-oracle Akita succinct setup derived from the verifier public parameters.
#[derive(Debug, Clone)]
pub struct AkitaClaimReducedOracleSetup {
	log_msg_len: usize,
	prover_setup: AkitaClaimReducedProverSetup,
	verifier_setup: AkitaClaimReducedVerifierSetup,
}

impl AkitaClaimReducedOracleSetup {
	/// Returns the Binius oracle length this Akita setup supports.
	pub fn log_msg_len(&self) -> usize {
		self.log_msg_len
	}

	/// Returns the reusable Akita prover setup.
	pub fn prover_setup(&self) -> &AkitaClaimReducedProverSetup {
		&self.prover_setup
	}

	/// Returns the reusable Akita verifier setup.
	pub fn verifier_setup(&self) -> &AkitaClaimReducedVerifierSetup {
		&self.verifier_setup
	}
}

/// Reusable setup for all succinct Akita bridge oracles in a verifier.
#[derive(Debug, Clone)]
pub struct AkitaClaimReducedSetup {
	oracle_setups: Vec<AkitaClaimReducedOracleSetup>,
}

impl AkitaClaimReducedSetup {
	/// Returns whether the current one-hot bridge preset supports all oracle specs.
	pub fn supports(oracle_specs: &[OracleSpec]) -> bool {
		oracle_specs.iter().all(|spec| spec.log_msg_len >= 7)
	}

	/// Builds reusable Akita setup from the oracle specs chosen during verifier setup.
	pub fn new(oracle_specs: &[OracleSpec]) -> Self {
		let oracle_setups = oracle_specs
			.iter()
			.map(|spec| {
				assert!(
					spec.log_msg_len >= 7,
					"akita-claim-reduced currently uses D={D} and requires at least 7 variables"
				);
				let prover_setup =
					akita_setup::new_prover_setup::<AkitaFieldScalar, D, Cfg>(
						spec.log_msg_len + 8,
						AKITA_OPENING_CLAIMS,
						AKITA_OPENING_POINTS,
					)
					.expect("Akita setup parameters must be valid");
				// Old: <Scheme as CommitmentScheme<AkitaFieldScalar, D>>::setup_verifier(&prover_setup)
				// New: prover_setup.verifier_setup() — derives verifier setup
				// by cloning the shared Arc<AkitaExpandedSetup>. Computationally
				// equivalent.
				let verifier_setup = prover_setup.verifier_setup();
				AkitaClaimReducedOracleSetup {
					log_msg_len: spec.log_msg_len,
					prover_setup,
					verifier_setup,
				}
			})
			.collect();

		Self { oracle_setups }
	}

	/// Returns the reusable setup for an oracle index.
	pub fn oracle_setup(&self, index: usize) -> &AkitaClaimReducedOracleSetup {
		&self.oracle_setups[index]
	}
}

/// Oracle handle returned by [`AkitaClaimReducedVerifierChannel::recv_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct AkitaClaimReducedOracle {
	index: usize,
}

struct OracleData {
	log_msg_len: usize,
	commitment: Commitment,
}

/// Verifier channel for the succinct Akita bridge.
pub struct AkitaClaimReducedVerifierChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	transcript: &'a mut VerifierTranscript<Challenger_>,
	oracle_specs: &'a [OracleSpec],
	akita_setup: &'a AkitaClaimReducedSetup,
	oracles: Vec<OracleData>,
	next_oracle_index: usize,
}

impl<'a, Challenger_> AkitaClaimReducedVerifierChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	/// Creates a succinct Akita bridge verifier channel.
	pub fn new(
		transcript: &'a mut VerifierTranscript<Challenger_>,
		oracle_specs: &'a [OracleSpec],
		akita_setup: &'a AkitaClaimReducedSetup,
	) -> Self {
		Self {
			transcript,
			oracle_specs,
			akita_setup,
			oracles: Vec::new(),
			next_oracle_index: 0,
		}
	}
}

impl<Challenger_> IPVerifierChannel<BiniusScalar> for AkitaClaimReducedVerifierChannel<'_, Challenger_>
where
	Challenger_: Challenger,
{
	type Elem = BiniusScalar;

	fn recv_one(&mut self) -> Result<BiniusScalar, binius_ip::channel::Error> {
		self.transcript
			.message()
			.read_scalar()
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn recv_many(&mut self, n: usize) -> Result<Vec<BiniusScalar>, binius_ip::channel::Error> {
		self.transcript
			.message()
			.read_scalar_slice(n)
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn recv_array<const N: usize>(
		&mut self,
	) -> Result<[BiniusScalar; N], binius_ip::channel::Error> {
		self.transcript
			.message()
			.read()
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn sample(&mut self) -> BiniusScalar {
		CanSample::sample(&mut self.transcript)
	}

	fn observe_one(&mut self, val: BiniusScalar) -> BiniusScalar {
		self.transcript.observe().write_scalar(val);
		val
	}

	fn observe_many(&mut self, vals: &[BiniusScalar]) -> Vec<BiniusScalar> {
		self.transcript.observe().write_scalar_slice(vals);
		vals.to_vec()
	}

	fn assert_zero(&mut self, val: BiniusScalar) -> Result<(), binius_ip::channel::Error> {
		if val == BiniusScalar::ZERO {
			Ok(())
		} else {
			Err(binius_ip::channel::Error::InvalidAssert)
		}
	}

	fn compute_public_value(
		&mut self,
		inputs: &[BiniusScalar],
		f: impl FnOnce(&[BiniusScalar]) -> BiniusScalar,
	) -> BiniusScalar {
		f(inputs)
	}
}

impl<Challenger_> IOPVerifierChannel<BiniusScalar> for AkitaClaimReducedVerifierChannel<'_, Challenger_>
where
	Challenger_: Challenger,
{
	type Oracle = AkitaClaimReducedOracle;

	fn remaining_oracle_specs(&self) -> &[OracleSpec] {
		&self.oracle_specs[self.next_oracle_index..]
	}

	fn recv_oracle(&mut self) -> Result<Self::Oracle, Error> {
		let index = self.next_oracle_index;
		let spec = self.oracle_specs[index];
		let oracle_setup = self.akita_setup.oracle_setup(index);
		assert_eq!(spec.log_msg_len, oracle_setup.log_msg_len());
		let commitment = wire::read_akita::<Commitment, _>(self.transcript, &())?;
		self.oracles.push(OracleData {
			log_msg_len: spec.log_msg_len,
			commitment,
		});
		self.next_oracle_index += 1;
		Ok(AkitaClaimReducedOracle { index })
	}

	fn verify_oracle_relations<'a>(
		&mut self,
		oracle_relations: impl IntoIterator<Item = OracleLinearRelation<'a, Self::Oracle, Self::Elem>>,
	) -> Result<(), Error> {
		for relation in oracle_relations {
			let data = &self.oracles[relation.oracle.index];
			let oracle_setup = self.akita_setup.oracle_setup(relation.oracle.index);
			let transparent_values =
				transparent_values_from_closure(&relation.transparent, data.log_msg_len);

			let sum_bounds = parity_sum_bounds(&transparent_values).map_err(|_| Error::ProofEmpty)?;
			let opened_sums = read_bounded_u64_array(self.transcript, &sum_bounds)?;
			let parity = BatchedParityBridgeProof { opened_sums };

			let alpha = wire::verify_sample_akita_scalar(self.transcript);
			parity
				.verify_with_bounds(&sum_bounds, relation.claim)
				.map_err(|_| Error::ProofEmpty)?;

			let selected_initial = batched_u64_sum(&parity.opened_sums, alpha);
			let (_selected_proof, selected_point, selected_final_claim) =
				verify_product_sumcheck_transcript(
					selected_initial,
					data.log_msg_len + 7,
					self.transcript,
				)?;

			let bool_weight_point =
				wire::verify_sample_akita_scalar_vec(self.transcript, data.log_msg_len + 7);
			let (_bool_proof, bool_point, bool_final_claim) =
				verify_weighted_booleanity_sumcheck_transcript(
					AkitaFieldScalar::from_u64(0),
					data.log_msg_len + 7,
					self.transcript,
				)?;

			let selected_openings = [wire::read_akita::<AkitaFieldScalar, _>(
				self.transcript,
				&(),
			)?];
			let bool_openings = [wire::read_akita::<AkitaFieldScalar, _>(
				self.transcript,
				&(),
			)?];

			let final_mask_value = evaluate_batched_selected_sum_table_mask(
				&transparent_values,
				alpha,
				&selected_point,
			)
			.map_err(|_| Error::ProofEmpty)?;
			let selected_expected = selected_openings[0] * final_mask_value;
			if selected_expected != selected_final_claim {
				return Err(Error::ProofEmpty);
			}
			let bool_weight =
				evaluate_akita_eq(&bool_weight_point, &bool_point).ok_or(Error::ProofEmpty)?;
			let bool_expected =
				bool_weight * bool_openings[0] * (bool_openings[0] - AkitaFieldScalar::from_u64(1));
			if bool_expected != bool_final_claim {
				return Err(Error::ProofEmpty);
			}

			// === Claim-reduced bridge: opening phase ===
			// Instead of opening the committed polynomial at both
			// `selected_point` and `bool_point` via Akita's multi-point
			// batched opening (the `akita-succinct` strategy), we reduce
			// the two opening claims to a single claim via a degree-2
			// sumcheck and then open at one point.
			//
			// The two opening claims at this stage are:
			//   B(with_one_coordinate(selected_point)) = selected_openings[0]
			//   B(with_one_coordinate(bool_point))     = bool_openings[0]
			// where `with_one_coordinate` prefixes the sumcheck challenges
			// with a `1` to address the high-order one-hot bit of the
			// bit-table polynomial. We run claim reduction on those two
			// extended points.
			// Claim reduction operates on the bit-table polynomial (which
			// has `log_msg_len + 7` variables, NOT log_msg_len + 8). The
			// selected/bool sumchecks above produced points of length
			// `log_msg_len + 7` and `selected_openings[0]` / `bool_openings[0]`
			// are bit-table evaluations at those points.
			let (cr_alpha, _cr_proof, reduced_point, claim_final) =
				verify_claim_reduction_sumcheck_transcript(
					&selected_point,
					&bool_point,
					selected_openings[0],
					bool_openings[0],
					data.log_msg_len + 7,
					self.transcript,
				)?;
			// The sumcheck final claim is `B(reduced_point) · T(reduced_point)`
			// where `T(x) = eq(selected_point, x) + cr_alpha · eq(bool_point, x)`.
			// Compute `T(reduced_point)` from public data and derive the
			// implied `B(reduced_point)`.
			let t_eval = evaluate_claim_reduction_transparent(
				&selected_point,
				&bool_point,
				cr_alpha,
				&reduced_point,
			)
			.map_err(|_| Error::ProofEmpty)?;
			if t_eval == AkitaFieldScalar::from_u64(0) {
				// Pathological: T vanished at the random point. Probability
				// ≤ deg(T)/|F| = (log_msg_len + 7)/2^128, negligible.
				return Err(Error::ProofEmpty);
			}
			let b_final_eval = claim_final * t_eval.inverse().ok_or(Error::ProofEmpty)?;

			// The committed OneHotPoly has one extra leading dimension
			// addressing the one-hot {bit, 1-bit} pair, so the PCS opening
			// point gets prefixed with `1` to select the bit-valued half.
			let extended_reduced_point = with_one_coordinate(&reduced_point);
			// `akita_claim_reduced_opening_shape` only handles the Fold root
			// path. Empirically the Akita planner always picks Fold for
			// `(num_claims=1, num_groups=1, num_points=1)` with `OneHotPoly`
			// K=2 at `max_num_vars >= 18`, so this is fine; if a future
			// config change ever surfaces root-direct, extend the shape
			// function to also handle `AkitaBatchedProofShape::Direct`.
			let shape = akita_claim_reduced_opening_shape(data.log_msg_len)?;
			let proof = wire::read_akita::<AkitaBatchedProof<AkitaFieldScalar>, _>(
				self.transcript,
				&shape,
			)?;
			if proof.shape() != shape {
				return Err(Error::ProofEmpty);
			}
			verify_akita_claim_reduced_opening(
				data,
				oracle_setup.verifier_setup(),
				&extended_reduced_point,
				b_final_eval,
				&proof,
			)?;

			let point: Vec<Self::Elem> =
				CanSample::sample_vec(&mut self.transcript, data.log_msg_len);
			let transparent_eval = (relation.transparent)(&point);
			let transparent_poly =
				FieldBuffer::<BiniusScalar>::from_values(&transparent_values);
			let explicit_eval = evaluate_inplace(transparent_poly, &point);
			self.assert_zero(transparent_eval - explicit_eval)?;
		}
		Ok(())
	}
}

fn with_one_coordinate(point: &[AkitaFieldScalar]) -> Vec<AkitaFieldScalar> {
	let mut extended = Vec::with_capacity(point.len() + 1);
	extended.push(AkitaFieldScalar::from_u64(1));
	extended.extend_from_slice(point);
	extended
}

/// Single-point opening verification for the claim-reduced bridge.
///
/// After the claim-reduction sumcheck, the verifier has a single residual
/// opening claim `B(reduced_point) = b_eval`. This helper calls Akita's
/// `batched_verify` with a `VerifierClaims` of shape `(1 point, 1 group, 1
/// claim)` — the simplest possible structure for the lattice PCS.
fn verify_akita_claim_reduced_opening(
	data: &OracleData,
	verifier_setup: &AkitaClaimReducedVerifierSetup,
	reduced_point: &[AkitaFieldScalar],
	b_eval: AkitaFieldScalar,
	proof: &AkitaBatchedProof<AkitaFieldScalar>,
) -> Result<(), Error> {
	let mut transcript = Blake2bTranscript::<AkitaFieldScalar>::new(
		b"binius/akita-claim-reduced/openings",
	);
	let openings = [b_eval];
	#[allow(clippy::type_complexity)]
	let claims: Vec<(&[AkitaFieldScalar], Vec<CommittedOpenings<'_, AkitaFieldScalar, Commitment>>)> = vec![(
		reduced_point,
		vec![CommittedOpenings {
			openings: &openings,
			commitment: &data.commitment,
		}],
	)];
	<Scheme as CommitmentVerifier<AkitaFieldScalar, D>>::batched_verify(
		proof,
		verifier_setup,
		&mut transcript,
		claims,
		BasisMode::Lagrange,
	)
	.map_err(|_| Error::ProofEmpty)
}

/// Compute the expected proof shape for the claim-reduced bridge.
///
/// Adapted from Akita's internal `expected_same_point_batched_shape` test
/// helper (`lz-hachi/crates/akita-scheme/src/tests.rs:107`). Akita's
/// deserialiser requires `Context = AkitaBatchedProofShape`, so the
/// verifier must derive the shape upfront from public parameters
/// `(max_num_vars, num_claims, num_groups, num_points, Cfg, D)` without a
/// parsed proof in hand. The caller re-checks
/// `parsed_proof.shape() == expected_shape` as a safety net after
/// deserialisation.
///
/// Notes for the claim-reduced bridge:
/// - `AKITA_OPENING_POINTS = 1`, so commitment-pointer dedup does not apply
///   (there is only one `CommittedOpenings` entry); we can pass
///   `&data.commitment` directly without going through clones.
/// - The off-by-one in the recursive-fold loop count is the same as in
///   `akita_succinct_opening_shape` — we iterate `n_fold_levels - 1`
///   recursive folds, where the root fold is handled separately above.
fn akita_claim_reduced_opening_shape(log_msg_len: usize) -> Result<AkitaBatchedProofShape, Error> {
	let max_num_vars = log_msg_len + 8;
	let batch = AkitaRootBatchSummary::new(
		AKITA_OPENING_CLAIMS,
		AKITA_OPENING_GROUPS,
		AKITA_OPENING_POINTS,
	)
	.map_err(|_| Error::ProofEmpty)?;

	// Schedule derivation — identical to the prover's call, so the resulting
	// schedule is byte-equivalent.
	let schedule = <Cfg as CommitmentConfig>::get_params_for_prove(
		max_num_vars,
		max_num_vars,
		AKITA_OPENING_CLAIMS,
		batch,
	)
	.map_err(|_| Error::ProofEmpty)?;

	// Our bridge does not support the root-direct fast path; the prover
	// always emits a recursive Fold root for the configurations we use
	// (`fp128::D64OneHot` with `log_msg_len >= 7`).
	if schedule_is_root_direct(&schedule) {
		return Err(Error::ProofEmpty);
	}

	// `schedule_num_fold_levels(&schedule)` counts ALL Fold steps in the
	// schedule, including the root fold at `schedule.steps[0]`. The root
	// fold is handled separately below (via `root_shape`); the loop further
	// down only processes the RECURSIVE (non-root) folds at indices >= 1.
	// Therefore the number of recursive-fold iterations is
	// `n_fold_levels - 1`.
	//
	// This counts mirror Akita's wire-format split: `AkitaBatchedProof.root`
	// holds the root fold proof, while `AkitaBatchedProof.steps` holds the
	// recursive fold proofs + the terminal direct witness. So
	// `proof.num_fold_levels()` in the original Akita test helper counts the
	// recursive folds only (because `fold_levels()` iterates `proof.steps`,
	// not `proof.root`), which is one less than the full schedule's fold
	// count.
	let n_fold_levels = schedule_num_fold_levels(&schedule);
	let n_recursive_folds = n_fold_levels.saturating_sub(1);

	let root_step = match schedule.steps.first() {
		Some(Step::Fold(s)) => s.clone(),
		_ => return Err(Error::ProofEmpty),
	};

	// ---- Root-level shape (formulas 4-5 of audit #003-A) ----
	let root_inputs = AkitaScheduleInputs {
		max_num_vars,
		level: 0,
		current_w_len: root_step.current_w_len,
	};
	let level_lp = &root_step.params;
	let root_lp = <Cfg as CommitmentConfig>::root_level_params_for_layout_with_log_basis(
		root_inputs,
		level_lp,
	)
	.map_err(|_| Error::ProofEmpty)?;
	let next_inputs = AkitaScheduleInputs {
		max_num_vars,
		level: 1,
		current_w_len: root_step.next_w_len,
	};
	let next_level_params = scheduled_next_level_params(
		&schedule,
		1,
		next_inputs,
		<Cfg as CommitmentConfig>::level_params_with_log_basis,
	)
	.map_err(|_| Error::ProofEmpty)?;
	let root_w_len = next_inputs.current_w_len;
	let root_rounds = batched_shape_rounds(root_lp.ring_dimension, root_w_len);
	let root_shape = LevelProofShape {
		// Note: `batch.num_points * root_lp.ring_dimension` — the only
		// place `num_points` enters the wire layout. For our bridge case
		// `num_points = 2` (selected_point and bool_point), so this is
		// `2 * ring_dimension` worth of y-commitment ring coefficients.
		y_ring_coeffs: batch.num_points * root_lp.ring_dimension,
		v_coeffs: root_lp.d_key.row_len() * root_lp.ring_dimension,
		stage1_stages: stage1_tree_stage_shapes(root_rounds, 1usize << level_lp.log_basis),
		stage2_sumcheck: (root_rounds, 3),
		next_commit_coeffs: next_level_params.b_key.row_len() * next_level_params.ring_dimension,
	};
	let first_level_params = next_level_params.clone();

	// ---- Per-fold-level shapes (formula 6 of audit #003-A) ----
	//
	// Iterate only over the RECURSIVE folds (excluding the root, which is
	// already accounted for by `root_shape` above). The terminal direct
	// witness is appended after the loop. The loop count is
	// `n_recursive_folds = n_fold_levels - 1`, not `n_fold_levels` — see
	// the explanatory comment above the `n_fold_levels` binding.
	let mut step_shapes = Vec::with_capacity(n_recursive_folds + 1);
	let mut current_w_len = root_w_len;
	let mut current_log_basis = first_level_params.log_basis;
	for (current_level, _) in (1usize..).zip(0..n_recursive_folds) {
		let inputs = AkitaScheduleInputs {
			max_num_vars,
			level: current_level,
			current_w_len,
		};
		let (level_params, next_level_params) = scheduled_fold_execution(
			&schedule,
			current_level,
			inputs,
			current_log_basis,
			<Cfg as CommitmentConfig>::level_params_with_log_basis,
		)
		.map_err(|_| Error::ProofEmpty)?;
		let current_lp = recursive_level_layout_from_params(
			&level_params,
			current_w_len,
			<Cfg as CommitmentConfig>::decomposition(),
		)
		.map_err(|_| Error::ProofEmpty)?;
		let next_w_len =
			w_ring_element_count::<AkitaFieldScalar>(&current_lp) * current_lp.ring_dimension;
		let rounds = batched_shape_rounds(current_lp.ring_dimension, next_w_len);
		step_shapes.push(AkitaProofStepShape::Fold(LevelProofShape {
			// Not scaled by num_points at non-root levels: after the root
			// fold, all opening points are merged into a single recursive
			// claim, so subsequent levels only carry 1 ring-dimension worth.
			y_ring_coeffs: current_lp.ring_dimension,
			v_coeffs: current_lp.d_key.row_len() * current_lp.ring_dimension,
			stage1_stages: stage1_tree_stage_shapes(rounds, 1usize << current_lp.log_basis),
			stage2_sumcheck: (rounds, 3),
			next_commit_coeffs: next_level_params.b_key.row_len()
				* next_level_params.ring_dimension,
		}));
		current_w_len = next_w_len;
		current_log_basis = next_level_params.log_basis;
	}

	// ---- Direct-witness leaf (formula 7 of audit #003-A) ----
	step_shapes.push(AkitaProofStepShape::Direct(
		DirectWitnessShape::PackedDigits((current_w_len, current_log_basis)),
	));

	Ok(AkitaBatchedProofShape::Fold {
		root_shape,
		step_shapes,
	})
}

/// Number of stage-2 sumcheck rounds for a given ring dimension and
/// next-level witness length. Inlined from `akita-scheme/tests.rs:66`.
fn batched_shape_rounds(level_d: usize, next_w_len: usize) -> usize {
	let num_ring_elems = next_w_len / level_d;
	num_ring_elems.next_power_of_two().trailing_zeros() as usize
		+ level_d.trailing_zeros() as usize
}

fn read_bounded_u64_array<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
	bounds: &[u64; BINIUS_SCALAR_BITS],
) -> Result<[u64; BINIUS_SCALAR_BITS], Error>
where
	Challenger_: Challenger,
{
	let mut bytes = vec![0; packed_bounded_u64_len(bounds)];
	transcript
		.message()
		.read_bytes(&mut bytes)
		.map_err(|_| Error::ProofEmpty)?;
	unpack_bounded_u64_array(&bytes, bounds).ok_or(Error::ProofEmpty)
}

/// Returns the byte length used to bit-pack 128 bounded `u64` values.
pub fn packed_bounded_u64_len(bounds: &[u64; BINIUS_SCALAR_BITS]) -> usize {
	let bit_len = bounds
		.iter()
		.map(|&bound| bounded_u64_bit_width(bound))
		.sum::<usize>();
	bit_len.div_ceil(8)
}

/// Packs bounded `u64` values into a little-endian bitstream.
pub fn pack_bounded_u64_array(
	values: &[u64; BINIUS_SCALAR_BITS],
	bounds: &[u64; BINIUS_SCALAR_BITS],
) -> Option<Vec<u8>> {
	let mut bytes = vec![0; packed_bounded_u64_len(bounds)];
	let mut bit_offset = 0;
	for (&value, &bound) in values.iter().zip(bounds) {
		if value > bound {
			return None;
		}

		let bit_width = bounded_u64_bit_width(bound);
		for bit in 0..bit_width {
			if (value >> bit) & 1 == 1 {
				bytes[bit_offset / 8] |= 1 << (bit_offset % 8);
			}
			bit_offset += 1;
		}
	}
	Some(bytes)
}

/// Unpacks a little-endian bounded `u64` bitstream and checks canonical bounds.
pub fn unpack_bounded_u64_array(
	bytes: &[u8],
	bounds: &[u64; BINIUS_SCALAR_BITS],
) -> Option<[u64; BINIUS_SCALAR_BITS]> {
	if bytes.len() != packed_bounded_u64_len(bounds) {
		return None;
	}

	let mut values = [0u64; BINIUS_SCALAR_BITS];
	let mut bit_offset = 0;
	for (&bound, value) in bounds.iter().zip(&mut values) {
		let bit_width = bounded_u64_bit_width(bound);
		for bit in 0..bit_width {
			let byte = bytes[bit_offset / 8];
			*value |= (((byte >> (bit_offset % 8)) & 1) as u64) << bit;
			bit_offset += 1;
		}
		if *value > bound {
			return None;
		}
	}

	if let Some(unused_bits) = 8usize.checked_sub(bit_offset % 8).filter(|&bits| bits < 8) {
		let unused_mask = u8::MAX << (8 - unused_bits);
		if bytes.last().copied().unwrap_or_default() & unused_mask != 0 {
			return None;
		}
	}

	Some(values)
}

fn bounded_u64_bit_width(bound: u64) -> usize {
	if bound == 0 {
		0
	} else {
		u64::BITS as usize - bound.leading_zeros() as usize
	}
}

fn transparent_values_from_closure(
	transparent: &binius_iop::channel::TransparentEvalFn<'_, BiniusScalar>,
	log_len: usize,
) -> Vec<BiniusScalar> {
	(0..(1usize << log_len))
		.map(|index| {
			let point = (0..log_len)
				.map(|bit| {
					if (index >> bit) & 1 == 1 {
						BiniusScalar::ONE
					} else {
						BiniusScalar::ZERO
					}
				})
				.collect::<Vec<_>>();
			transparent(&point)
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn bounds_from_prefix(prefix: &[u64]) -> [u64; BINIUS_SCALAR_BITS] {
		let mut bounds = [0u64; BINIUS_SCALAR_BITS];
		bounds[..prefix.len()].copy_from_slice(prefix);
		bounds
	}

	#[test]
	fn bounded_u64_packing_round_trips() {
		let bounds = bounds_from_prefix(&[0, 1, 2, 3, 255, 256, 1023, u64::MAX]);
		let mut values = [0u64; BINIUS_SCALAR_BITS];
		values[..8].copy_from_slice(&[0, 1, 2, 3, 255, 256, 511, u64::MAX]);

		let packed = pack_bounded_u64_array(&values, &bounds).unwrap();
		assert_eq!(packed.len(), packed_bounded_u64_len(&bounds));
		assert_eq!(unpack_bounded_u64_array(&packed, &bounds), Some(values));
	}

	#[test]
	fn bounded_u64_packing_rejects_out_of_range_values() {
		let bounds = bounds_from_prefix(&[3]);
		let mut values = [0u64; BINIUS_SCALAR_BITS];
		values[0] = 4;

		assert_eq!(pack_bounded_u64_array(&values, &bounds), None);
	}

	#[test]
	fn bounded_u64_unpacking_rejects_out_of_range_values() {
		let bounds = bounds_from_prefix(&[2]);
		let packed = [3];

		assert_eq!(unpack_bounded_u64_array(&packed, &bounds), None);
	}

	#[test]
	fn bounded_u64_unpacking_rejects_nonzero_padding() {
		let bounds = bounds_from_prefix(&[1]);
		let packed = [0b1000_0000];

		assert_eq!(unpack_bounded_u64_array(&packed, &bounds), None);
	}
}
