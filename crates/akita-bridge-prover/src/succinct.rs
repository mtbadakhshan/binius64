// Copyright 2026 The Binius Developers

//! Succinct Akita bridge prover channel.

use akita_config::{CommitmentConfig, proof_optimized::fp128};
use akita_prover::{
	CommitmentProver, CommittedPolynomials, OneHotPoly, ProverClaims, commit_with_policy,
};
use akita_scheme::AkitaCommitmentScheme;
use akita_transcript::Blake2bTranscript;
use akita_types::{
	AkitaBatchedProof, AkitaCommitmentHint, AkitaRootBatchSummary, BasisMode, RingCommitment,
};
use binius_field::PackedField;
use binius_akita_bridge::{
	protocol::{
		AkitaFieldScalar, BINIUS_SCALAR_BITS, BatchedParityBridgeProof, BiniusScalar,
		BitSliceOracle, batched_selected_sum_table_mask, batched_u64_sum, parity_sum_bounds,
		prove_product_sumcheck_transcript, prove_terminal_linear_claim,
		prove_weighted_booleanity_sumcheck_transcript,
	},
	succinct::{AkitaSuccinctProverSetup, AkitaSuccinctSetup, pack_bounded_u64_array},
	wire,
};
use binius_iop::channel::OracleSpec;
use binius_ip_prover::channel::IPProverChannel;
use binius_math::{FieldBuffer, FieldSlice, inner_product::inner_product_buffers};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use binius_iop_prover::channel::IOPProverChannel;

type Cfg = fp128::D64OneHot;
const D: usize = 64;
// Mirror of `AKITA_OPENING_POINTS` from the verifier-side `succinct`
// in `binius-iop`. We commit each oracle anticipating it will be opened at
// exactly this many distinct opening points later in `batched_prove`.
// Keep in sync with `binius_akita_bridge::succinct::AKITA_OPENING_POINTS`.
const AKITA_OPENING_POINTS: usize = 2;
type Scheme = AkitaCommitmentScheme<D, Cfg>;
type Commitment = RingCommitment<AkitaFieldScalar, D>;
type Hint = AkitaCommitmentHint<AkitaFieldScalar, D>;
type Setup = AkitaSuccinctProverSetup;
type BitTablePoly = OneHotPoly<AkitaFieldScalar, D, u8>;

/// Oracle handle returned by [`AkitaSuccinctProverChannel::send_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct AkitaSuccinctOracle {
	index: usize,
}

struct OracleData {
	log_msg_len: usize,
	bit_table: Vec<AkitaFieldScalar>,
	poly: BitTablePoly,
	commitment: Commitment,
	hint: Hint,
}

/// Prover channel that commits to Binius oracle bits using the Akita lattice PCS.
pub struct AkitaSuccinctProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	transcript: &'a mut ProverTranscript<Challenger_>,
	oracle_specs: Vec<OracleSpec>,
	akita_setup: &'a AkitaSuccinctSetup,
	oracles: Vec<OracleData>,
	next_oracle_index: usize,
}

impl<'a, Challenger_> AkitaSuccinctProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	/// Creates a succinct Akita bridge prover channel.
	pub fn new(
		transcript: &'a mut ProverTranscript<Challenger_>,
		oracle_specs: Vec<OracleSpec>,
		akita_setup: &'a AkitaSuccinctSetup,
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

impl<Challenger_> IPProverChannel<BiniusScalar> for AkitaSuccinctProverChannel<'_, Challenger_>
where
	Challenger_: Challenger,
{
	fn send_one(&mut self, elem: BiniusScalar) {
		self.transcript.message().write_scalar(elem);
	}

	fn send_many(&mut self, elems: &[BiniusScalar]) {
		self.transcript.message().write_scalar_slice(elems);
	}

	fn observe_one(&mut self, val: BiniusScalar) {
		self.transcript.observe().write_scalar(val);
	}

	fn observe_many(&mut self, vals: &[BiniusScalar]) {
		self.transcript.observe().write_scalar_slice(vals);
	}

	fn sample(&mut self) -> BiniusScalar {
		CanSample::sample(&mut self.transcript)
	}
}

impl<P, Challenger_> IOPProverChannel<P> for AkitaSuccinctProverChannel<'_, Challenger_>
where
	P: PackedField<Scalar = BiniusScalar>,
	Challenger_: Challenger,
{
	type Oracle = AkitaSuccinctOracle;

	fn remaining_oracle_specs(&self) -> &[OracleSpec] {
		&self.oracle_specs[self.next_oracle_index..]
	}

	fn send_oracle(&mut self, buffer: FieldSlice<P>) -> Self::Oracle {
		let index = self.next_oracle_index;
		let spec = self.oracle_specs[index];
		assert_eq!(buffer.log_len(), spec.log_msg_len);
		assert!(
			spec.log_msg_len >= 7,
			"akita-succinct currently uses D={D} and requires at least 7 variables"
		);

		let oracle_values = buffer.iter_scalars().collect::<Vec<_>>();
		let oracle_setup = self.akita_setup.oracle_setup(index);
		assert_eq!(spec.log_msg_len, oracle_setup.log_msg_len());
		let bit_slices = BitSliceOracle::from_binius_oracle(&oracle_values);
		let bit_table = bit_slices.to_bit_table_evals();
		// OneHotPoly is only the honest-prover representation used to speed up Akita
		// operations. The verifier-side Booleanity guarantee is the weighted
		// sumcheck in prove_oracle_relations/verify_oracle_relations.
		let poly = bit_slices
			.to_onehot_bit_table_poly::<D>()
			.expect("bit table one-hot encoding is valid");

		// Multi-point commit layout (uses pre-existing `commit_with_policy`,
		// NOT the newer `commit_for_multipoint` trait method — see note below):
		//
		// We commit the bit-table polynomial ONCE but open it at
		// AKITA_OPENING_POINTS = 2 distinct points later (selected_point and
		// bool_point). The singleton `commit` API silently binds the
		// commitment to a `(num_groups=1, num_points=1)` layout, which then
		// causes Akita's prover to fail (`InvalidSetup` or `OneHotPoly::
		// fold_blocks` block_len mismatch) when `batched_prove` later tries
		// to open the same poly with the multi-point layout.
		//
		// To get the correct layout we use `akita_prover::commit_with_policy`
		// — a stable public API that's been in Akita since pre-`0873a7f` —
		// and supply a policy closure that returns the `LevelParams` for the
		// eventual multi-point batch `(num_claims = num_polys * P, num_groups
		// = 1, num_points = P)` where `P = AKITA_OPENING_POINTS`. This is
		// byte-equivalent to what the newer `commit_for_multipoint` trait
		// method does internally (in fact `commit_for_multipoint_with_policy`
		// is just `commit_with_policy` plus a hardcoded batch shape), but
		// uses the older API surface so the bridge does not depend on the
		// commit-multipoint addition.
		let prover_setup = oracle_setup.prover_setup();
		let setup_max_num_vars = prover_setup.expanded.seed.max_num_vars;
		let (commitment, hint) = commit_with_policy::<AkitaFieldScalar, D, BitTablePoly, _>(
			std::slice::from_ref(&poly),
			prover_setup,
			|num_vars, num_polys| {
				let batch = AkitaRootBatchSummary::new(
					num_polys * AKITA_OPENING_POINTS,
					1,
					AKITA_OPENING_POINTS,
				)?;
				<Cfg as CommitmentConfig>::get_params_for_batched_commitment(
					setup_max_num_vars,
					num_vars,
					batch,
				)
			},
		)
		.expect("Akita bit-table commit should succeed");
		wire::write_akita(self.transcript, &commitment);

		self.oracles.push(OracleData {
			log_msg_len: spec.log_msg_len,
			bit_table,
			poly,
			commitment,
			hint,
		});
		self.next_oracle_index += 1;
		AkitaSuccinctOracle { index }
	}

	fn prove_oracle_relations(
		&mut self,
		oracle_relations: impl IntoIterator<
			Item = (Self::Oracle, FieldBuffer<P>, FieldBuffer<P>, P::Scalar),
		>,
	) {
		for (oracle, message, transparent_poly, eval_claim) in oracle_relations {
			let data = &self.oracles[oracle.index];
			let oracle_setup = self.akita_setup.oracle_setup(oracle.index);
			assert_eq!(message.log_len(), data.log_msg_len);
			let oracle_values = message.iter_scalars().collect::<Vec<_>>();
			let transparent_values = transparent_poly.iter_scalars().collect::<Vec<_>>();

			let (native_claim, parity) =
				prove_terminal_linear_claim(&oracle_values, &transparent_values).unwrap();
			debug_assert_eq!(native_claim, eval_claim);
			let sum_bounds = parity_sum_bounds(&transparent_values).unwrap();
			write_parity(self.transcript, &parity, &sum_bounds);

			let alpha = wire::sample_akita_scalar(self.transcript);

			let selected_mask = batched_selected_sum_table_mask(&transparent_values, alpha);
			let selected_initial = batched_u64_sum(&parity.opened_sums, alpha);
			let (selected_claim, _selected_proof, selected_point, selected_openings, _) =
				prove_product_sumcheck_transcript(
					&[data.bit_table.clone()],
					&[selected_mask],
					self.transcript,
				)
				.unwrap();
			debug_assert_eq!(selected_claim, selected_initial);

			let bool_weight_point =
				wire::sample_akita_scalar_vec(self.transcript, data.log_msg_len + 7);
			let (bool_claim, _bool_proof, bool_point, bool_opening) =
				prove_weighted_booleanity_sumcheck_transcript(
					&data.bit_table,
					&bool_weight_point,
					self.transcript,
				)
				.unwrap();
			debug_assert_eq!(bool_claim, AkitaFieldScalar::from_u64(0));

			for value in &selected_openings {
				wire::write_akita(self.transcript, value);
			}
			wire::write_akita(self.transcript, &bool_opening);

			let proof = prove_akita_openings(
				data,
				oracle_setup.prover_setup(),
				&with_one_coordinate(&selected_point),
				&with_one_coordinate(&bool_point),
			);
			wire::write_akita(self.transcript, &proof);

			let _point: Vec<BiniusScalar> =
				CanSample::sample_vec(&mut self.transcript, data.log_msg_len);
			let actual_eval: BiniusScalar = inner_product_buffers(&message, &transparent_poly);
			debug_assert_eq!(actual_eval, eval_claim);
		}
	}
}

fn with_one_coordinate(point: &[AkitaFieldScalar]) -> Vec<AkitaFieldScalar> {
	let mut extended = Vec::with_capacity(point.len() + 1);
	extended.push(AkitaFieldScalar::from_u64(1));
	extended.extend_from_slice(point);
	extended
}

fn write_parity<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	parity: &BatchedParityBridgeProof,
	sum_bounds: &[u64; BINIUS_SCALAR_BITS],
) where
	Challenger_: Challenger,
{
	write_bounded_u64_array(transcript, &parity.opened_sums, sum_bounds);
}

fn write_bounded_u64_array<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	values: &[u64; BINIUS_SCALAR_BITS],
	bounds: &[u64; BINIUS_SCALAR_BITS],
) where
	Challenger_: Challenger,
{
	let packed = pack_bounded_u64_array(values, bounds)
		.expect("parity bridge values should satisfy public bounds");
	transcript.message().write_bytes(&packed);
}

fn prove_akita_openings(
	data: &OracleData,
	setup: &Setup,
	selected_point: &[AkitaFieldScalar],
	bool_point: &[AkitaFieldScalar],
) -> AkitaBatchedProof<AkitaFieldScalar> {
	let mut transcript = Blake2bTranscript::<AkitaFieldScalar>::new(
		b"binius/akita-succinct/openings",
	);
	// Mirror the pattern of Akita's
	// `shared_onehot_commitment_two_points_round_trip_sweep` regression
	// test: shared `polys` slice reference + per-point cloned commitments
	// and hints. Akita's `prover_claims_to_incidence` deduplicates by raw
	// `&Commitment` pointer identity, so distinct clones yield two
	// incidence groups, matching the verifier's `AKITA_OPENING_GROUPS = 2`.
	let poly_refs: [&BitTablePoly; 1] = [&data.poly];
	let commitments_owned: [Commitment; 2] = [data.commitment.clone(), data.commitment.clone()];
	let claims: ProverClaims<AkitaFieldScalar, &BitTablePoly, Commitment, Hint> = vec![
		(
			selected_point,
			vec![CommittedPolynomials {
				polynomials: &poly_refs,
				commitment: &commitments_owned[0],
				hint: data.hint.clone(),
			}],
		),
		(
			bool_point,
			vec![CommittedPolynomials {
				polynomials: &poly_refs,
				commitment: &commitments_owned[1],
				hint: data.hint.clone(),
			}],
		),
	];
	<Scheme as CommitmentProver<AkitaFieldScalar, D>>::batched_prove(
		setup,
		claims,
		&mut transcript,
		BasisMode::Lagrange,
	)
	.expect("Akita batched opening proof should succeed")
}

#[cfg(test)]
mod tests {
	use binius_akita_bridge::succinct::AkitaSuccinctVerifierChannel;
	use binius_field::{BinaryField128bGhash as B128, PackedBinaryGhash1x128b};
	use binius_hash::StdDigest;
	use binius_iop::channel::{IOPVerifierChannel, OracleLinearRelation, OracleSpec};
	use binius_math::{
		FieldBuffer, inner_product::inner_product_buffers, test_utils::random_field_buffer,
	};
	use binius_transcript::{ProverTranscript, fiat_shamir::HasherChallenger};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	type StdChallenger = HasherChallenger<StdDigest>;
	type P = PackedBinaryGhash1x128b;

	#[test]
	fn akita_succinct_verifier_accepts_structured_constant_relation() {
		let mut rng = StdRng::seed_from_u64(0);
		let log_len = 7;
		let oracle_specs = vec![OracleSpec {
			log_msg_len: log_len,
		}];
		let akita_setup = AkitaSuccinctSetup::new(&oracle_specs);
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let coefficient = B128::new(0x0101_0203_0508_0d15_2237_5990_e979_62db);
		let transparent = FieldBuffer::<P>::from_values(&vec![coefficient; 1 << log_len]);
		let claim = inner_product_buffers(&message, &transparent);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel = AkitaSuccinctProverChannel::new(
			&mut prover_transcript,
			oracle_specs.clone(),
			&akita_setup,
		);
		let oracle = prover_channel.send_oracle(message.to_ref());
		prover_channel.prove_oracle_relations([(oracle, message, transparent, claim)]);

		let mut verifier_transcript = prover_transcript.into_verifier();
		let mut verifier_channel = AkitaSuccinctVerifierChannel::new(
			&mut verifier_transcript,
			&oracle_specs,
			&akita_setup,
		);
		let oracle = verifier_channel.recv_oracle().unwrap();
		verifier_channel
			.verify_oracle_relations([OracleLinearRelation::new(
				oracle,
				Box::new(move |point: &[B128]| {
					assert_eq!(point.len(), log_len);
					coefficient
				}),
				claim,
			)])
			.unwrap();
		verifier_transcript.finalize().unwrap();
	}

	#[test]
	fn akita_succinct_verifier_rejects_wrong_structured_relation() {
		let mut rng = StdRng::seed_from_u64(1);
		let log_len = 7;
		let oracle_specs = vec![OracleSpec {
			log_msg_len: log_len,
		}];
		let akita_setup = AkitaSuccinctSetup::new(&oracle_specs);
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let coefficient = B128::new(0x0101_0203_0508_0d15_2237_5990_e979_62db);
		let transparent = FieldBuffer::<P>::from_values(&vec![coefficient; 1 << log_len]);
		let claim = inner_product_buffers(&message, &transparent);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel = AkitaSuccinctProverChannel::new(
			&mut prover_transcript,
			oracle_specs.clone(),
			&akita_setup,
		);
		let oracle = prover_channel.send_oracle(message.to_ref());
		prover_channel.prove_oracle_relations([(oracle, message, transparent, claim)]);

		let mut verifier_transcript = prover_transcript.into_verifier();
		let mut verifier_channel = AkitaSuccinctVerifierChannel::new(
			&mut verifier_transcript,
			&oracle_specs,
			&akita_setup,
		);
		let oracle = verifier_channel.recv_oracle().unwrap();
		let wrong_coefficient = coefficient + B128::new(1);
		assert!(
			verifier_channel
				.verify_oracle_relations([OracleLinearRelation::new(
					oracle,
					Box::new(move |point: &[B128]| {
						assert_eq!(point.len(), log_len);
						wrong_coefficient
					}),
					claim,
				)])
				.is_err()
		);
	}
}
