// Copyright 2026 The Binius Developers

//! Claim-reduced Akita bridge prover channel.
//!
//! Mirror of the verifier-side `binius_akita_bridge::claim_reduced`.
//! See that module's docstring for the design discussion of the claim-
//! reduction bridge vs the multi-point `akita-succinct` bridge.
//!
//! Most of this file is structurally identical to
//! `succinct.rs`; blocks marked `// SHARED` are duplicated
//! verbatim with the expectation that consolidation will happen once the
//! two bridges' design has stabilized.

use akita_config::proof_optimized::fp128;
use akita_prover::{CommitmentProver, CommittedPolynomials, OneHotPoly, ProverClaims};
use akita_scheme::AkitaCommitmentScheme;
use akita_transcript::Blake2bTranscript;
use akita_types::{AkitaBatchedProof, AkitaCommitmentHint, BasisMode, RingCommitment};
use binius_field::PackedField;
use binius_akita_bridge::{
	claim_reduced::{
		AkitaClaimReducedProverSetup, AkitaClaimReducedSetup, pack_bounded_u64_array,
	},
	protocol::{
		AkitaFieldScalar, BINIUS_SCALAR_BITS, BatchedParityBridgeProof, BiniusScalar,
		BitSliceOracle, batched_selected_sum_table_mask, batched_u64_sum, parity_sum_bounds,
		prove_claim_reduction_sumcheck_transcript, prove_product_sumcheck_transcript,
		prove_terminal_linear_claim, prove_weighted_booleanity_sumcheck_transcript,
	},
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
// Claim-reduced bridge opens the committed polynomial at exactly ONE point
// (the claim-reduction sumcheck's final challenge), so the Akita opening
// shape is `(num_claims=1, num_groups=1, num_points=1)`. The prover uses the
// singleton `commit` API here, so no `AKITA_OPENING_POINTS` constant is
// needed prover-side.
type Scheme = AkitaCommitmentScheme<D, Cfg>;
type Commitment = RingCommitment<AkitaFieldScalar, D>;
type Hint = AkitaCommitmentHint<AkitaFieldScalar, D>;
type Setup = AkitaClaimReducedProverSetup;
type BitTablePoly = OneHotPoly<AkitaFieldScalar, D, u8>;

/// Oracle handle returned by [`AkitaClaimReducedProverChannel::send_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct AkitaClaimReducedOracle {
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
pub struct AkitaClaimReducedProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	transcript: &'a mut ProverTranscript<Challenger_>,
	oracle_specs: Vec<OracleSpec>,
	akita_setup: &'a AkitaClaimReducedSetup,
	oracles: Vec<OracleData>,
	next_oracle_index: usize,
}

impl<'a, Challenger_> AkitaClaimReducedProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	/// Creates a succinct Akita bridge prover channel.
	pub fn new(
		transcript: &'a mut ProverTranscript<Challenger_>,
		oracle_specs: Vec<OracleSpec>,
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

impl<Challenger_> IPProverChannel<BiniusScalar> for AkitaClaimReducedProverChannel<'_, Challenger_>
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

impl<P, Challenger_> IOPProverChannel<P> for AkitaClaimReducedProverChannel<'_, Challenger_>
where
	P: PackedField<Scalar = BiniusScalar>,
	Challenger_: Challenger,
{
	type Oracle = AkitaClaimReducedOracle;

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

		// Claim-reduced bridge: open at exactly ONE point (the claim-reduction
		// sumcheck's final challenge), so the singleton `commit` API
		// suffices. The `(num_claims=1, num_groups=1, num_points=1)`
		// schedule the prover later derives matches what `commit`'s default
		// policy selected at commit time, so no custom layout policy is
		// needed here. The multi-point variant in `succinct`
		// uses `commit_with_policy` instead for that reason.
		let (commitment, hint) = <Scheme as CommitmentProver<AkitaFieldScalar, D>>::commit(
			std::slice::from_ref(&poly),
			oracle_setup.prover_setup(),
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
		AkitaClaimReducedOracle { index }
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

			// === Claim-reduced bridge: run claim reduction sumcheck, then
			//     open the committed polynomial at the single reduced point. ===
			//
			// The bit-table has `log_msg_len + 7` variables (= 2^log_msg_len
			// packed B128 elements × 128 bits each). The selected/bool
			// sumchecks produce points of length `log_msg_len + 7` whose
			// evaluations of the bit-table give us `selected_openings[0]`
			// and `bool_opening`. Claim reduction sumcheck operates on the
			// bit-table at these two points, producing a fresh `reduced_point`
			// also of length `log_msg_len + 7`.
			//
			// The committed PCS object is a OneHotPoly with one extra leading
			// dimension (log_msg_len + 8 vars total) addressing the one-hot
			// {bit, 1-bit} pair. To open the OneHotPoly at the bit-table's
			// `reduced_point`, we prefix a `1` coordinate so the opening
			// selects the bit-valued half of the one-hot encoding (which
			// equals the bit-table at `reduced_point`).
			let (_cr_alpha, _cr_proof, reduced_point, b_final) =
				prove_claim_reduction_sumcheck_transcript(
					&data.bit_table,
					&selected_point,
					&bool_point,
					selected_openings[0],
					bool_opening,
					self.transcript,
				)
				.expect("claim reduction sumcheck should succeed");

			let extended_reduced_point = with_one_coordinate(&reduced_point);
			let proof = prove_akita_claim_reduced_opening(
				data,
				oracle_setup.prover_setup(),
				&extended_reduced_point,
				b_final,
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

/// Single-point opening for the claim-reduced bridge.
///
/// After the claim-reduction sumcheck, the prover has a single residual
/// claim `B(reduced_point) = b_eval` and calls Akita's `batched_prove`
/// with a `ProverClaims` of shape `(1 point, 1 group, 1 claim)`. The
/// `_b_eval` parameter is unused by `batched_prove` directly (Akita derives
/// the eval from the polynomial itself), but is accepted in the signature
/// to mirror the verifier-side `verify_akita_claim_reduced_opening` and to
/// allow honest-prover sanity assertions in future debug builds.
fn prove_akita_claim_reduced_opening(
	data: &OracleData,
	setup: &Setup,
	reduced_point: &[AkitaFieldScalar],
	_b_eval: AkitaFieldScalar,
) -> AkitaBatchedProof<AkitaFieldScalar> {
	let mut transcript = Blake2bTranscript::<AkitaFieldScalar>::new(
		b"binius/akita-claim-reduced/openings",
	);
	// Single opening point — no multi-point batching, no commit/poly
	// duplication required. The simplest `ProverClaims` shape.
	let poly_refs: [&BitTablePoly; 1] = [&data.poly];
	let claims: ProverClaims<AkitaFieldScalar, &BitTablePoly, Commitment, Hint> = vec![(
		reduced_point,
		vec![CommittedPolynomials {
			polynomials: &poly_refs,
			commitment: &data.commitment,
			hint: data.hint.clone(),
		}],
	)];
	<Scheme as CommitmentProver<AkitaFieldScalar, D>>::batched_prove(
		setup,
		claims,
		&mut transcript,
		BasisMode::Lagrange,
	)
	.expect("Akita single-point opening proof should succeed")
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
		let akita_setup = AkitaClaimReducedSetup::new(&oracle_specs);
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let coefficient = B128::new(0x0101_0203_0508_0d15_2237_5990_e979_62db);
		let transparent = FieldBuffer::<P>::from_values(&vec![coefficient; 1 << log_len]);
		let claim = inner_product_buffers(&message, &transparent);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel = AkitaClaimReducedProverChannel::new(
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
		let akita_setup = AkitaClaimReducedSetup::new(&oracle_specs);
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let coefficient = B128::new(0x0101_0203_0508_0d15_2237_5990_e979_62db);
		let transparent = FieldBuffer::<P>::from_values(&vec![coefficient; 1 << log_len]);
		let claim = inner_product_buffers(&message, &transparent);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel = AkitaClaimReducedProverChannel::new(
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
