// Copyright 2026 The Binius Developers

//! Succinct Hachi bridge prover channel.

use binius_field::PackedField;
use binius_iop::{
	channel::OracleSpec,
	hachi_bridge::{
		BINIUS_SCALAR_BITS, BatchedParityBridgeProof, BiniusScalar, BitSliceOracle, HachiScalar,
		batched_selected_sum_table_mask, batched_u64_sum, parity_sum_bounds,
		prove_product_sumcheck_transcript, prove_terminal_linear_claim,
		prove_weighted_booleanity_sumcheck_transcript,
	},
	hachi_succinct_channel::{
		HachiSuccinctProverSetup, HachiSuccinctSetup, pack_bounded_u64_array,
	},
	hachi_wire,
};
use binius_ip_prover::channel::IPProverChannel;
use binius_math::{FieldBuffer, FieldSlice, inner_product::inner_product_buffers};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use hachi_pcs::{
	BasisMode, CommitmentScheme, FromSmallInt, Transcript,
	protocol::{
		commitment::{RingCommitment, presets::fp128},
		commitment_scheme::HachiCommitmentScheme,
		hachi_poly_ops::OneHotPoly,
		proof::{HachiBatchedCommitmentHint, HachiBatchedProof},
	},
};

use crate::channel::IOPProverChannel;

type Cfg = fp128::D64OneHot;
const D: usize = 64;
type Scheme = HachiCommitmentScheme<D, Cfg>;
type Commitment = RingCommitment<HachiScalar, D>;
type Hint = HachiBatchedCommitmentHint<HachiScalar, D>;
type Setup = HachiSuccinctProverSetup;
type BitTablePoly = OneHotPoly<HachiScalar, D, u8>;

/// Oracle handle returned by [`HachiSuccinctProverChannel::send_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct HachiSuccinctOracle {
	index: usize,
}

struct OracleData {
	log_msg_len: usize,
	bit_table: Vec<HachiScalar>,
	poly: BitTablePoly,
	commitment: Commitment,
	hint: Hint,
}

/// Prover channel that commits to Binius oracle bits with Hachi.
pub struct HachiSuccinctProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	transcript: &'a mut ProverTranscript<Challenger_>,
	oracle_specs: Vec<OracleSpec>,
	hachi_setup: &'a HachiSuccinctSetup,
	oracles: Vec<OracleData>,
	next_oracle_index: usize,
}

impl<'a, Challenger_> HachiSuccinctProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	/// Creates a succinct Hachi bridge prover channel.
	pub fn new(
		transcript: &'a mut ProverTranscript<Challenger_>,
		oracle_specs: Vec<OracleSpec>,
		hachi_setup: &'a HachiSuccinctSetup,
	) -> Self {
		Self {
			transcript,
			oracle_specs,
			hachi_setup,
			oracles: Vec::new(),
			next_oracle_index: 0,
		}
	}
}

impl<Challenger_> IPProverChannel<BiniusScalar> for HachiSuccinctProverChannel<'_, Challenger_>
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

impl<P, Challenger_> IOPProverChannel<P> for HachiSuccinctProverChannel<'_, Challenger_>
where
	P: PackedField<Scalar = BiniusScalar>,
	Challenger_: Challenger,
{
	type Oracle = HachiSuccinctOracle;

	fn remaining_oracle_specs(&self) -> &[OracleSpec] {
		&self.oracle_specs[self.next_oracle_index..]
	}

	fn send_oracle(&mut self, buffer: FieldSlice<P>) -> Self::Oracle {
		let index = self.next_oracle_index;
		let spec = self.oracle_specs[index];
		assert_eq!(buffer.log_len(), spec.log_msg_len);
		assert!(
			spec.log_msg_len >= 7,
			"hachi-succinct currently uses D={D} and requires at least 7 variables"
		);

		let oracle_values = buffer.iter_scalars().collect::<Vec<_>>();
		let oracle_setup = self.hachi_setup.oracle_setup(index);
		assert_eq!(spec.log_msg_len, oracle_setup.log_msg_len());
		let bit_slices = BitSliceOracle::from_binius_oracle(&oracle_values);
		let bit_table = bit_slices.to_bit_table_evals();
		// OneHotPoly is only the honest-prover representation used to speed up Hachi
		// operations. The verifier-side Booleanity guarantee is the weighted
		// sumcheck in prove_oracle_relations/verify_oracle_relations.
		let poly = bit_slices
			.to_onehot_bit_table_poly::<D>()
			.expect("bit table one-hot encoding is valid");

		let (commitment, hint) = <Scheme as CommitmentScheme<HachiScalar, D>>::commit(
			std::slice::from_ref(&poly),
			oracle_setup.prover_setup(),
		)
		.expect("Hachi bit-table commit should succeed");
		hachi_wire::write_hachi(self.transcript, &commitment);

		self.oracles.push(OracleData {
			log_msg_len: spec.log_msg_len,
			bit_table,
			poly,
			commitment,
			hint,
		});
		self.next_oracle_index += 1;
		HachiSuccinctOracle { index }
	}

	fn prove_oracle_relations(
		&mut self,
		oracle_relations: impl IntoIterator<
			Item = (Self::Oracle, FieldBuffer<P>, FieldBuffer<P>, P::Scalar),
		>,
	) {
		for (oracle, message, transparent_poly, eval_claim) in oracle_relations {
			let data = &self.oracles[oracle.index];
			let oracle_setup = self.hachi_setup.oracle_setup(oracle.index);
			assert_eq!(message.log_len(), data.log_msg_len);
			let oracle_values = message.iter_scalars().collect::<Vec<_>>();
			let transparent_values = transparent_poly.iter_scalars().collect::<Vec<_>>();

			let (native_claim, parity) =
				prove_terminal_linear_claim(&oracle_values, &transparent_values).unwrap();
			debug_assert_eq!(native_claim, eval_claim);
			let sum_bounds = parity_sum_bounds(&transparent_values).unwrap();
			write_parity(self.transcript, &parity, &sum_bounds);

			let alpha = hachi_wire::sample_hachi_scalar(self.transcript);

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
				hachi_wire::sample_hachi_scalar_vec(self.transcript, data.log_msg_len + 7);
			let (bool_claim, _bool_proof, bool_point, bool_opening) =
				prove_weighted_booleanity_sumcheck_transcript(
					&data.bit_table,
					&bool_weight_point,
					self.transcript,
				)
				.unwrap();
			debug_assert_eq!(bool_claim, HachiScalar::from_u64(0));

			for value in &selected_openings {
				hachi_wire::write_hachi(self.transcript, value);
			}
			hachi_wire::write_hachi(self.transcript, &bool_opening);

			let proof = prove_hachi_openings(
				data,
				oracle_setup.prover_setup(),
				&with_one_coordinate(&selected_point),
				&with_one_coordinate(&bool_point),
			);
			hachi_wire::write_hachi(self.transcript, &proof);

			let _point: Vec<BiniusScalar> =
				CanSample::sample_vec(&mut self.transcript, data.log_msg_len);
			let actual_eval: BiniusScalar = inner_product_buffers(&message, &transparent_poly);
			debug_assert_eq!(actual_eval, eval_claim);
		}
	}
}

fn with_one_coordinate(point: &[HachiScalar]) -> Vec<HachiScalar> {
	let mut extended = Vec::with_capacity(point.len() + 1);
	extended.push(HachiScalar::from_u64(1));
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

fn prove_hachi_openings(
	data: &OracleData,
	setup: &Setup,
	selected_point: &[HachiScalar],
	bool_point: &[HachiScalar],
) -> HachiBatchedProof<HachiScalar> {
	let poly_refs = [&data.poly];
	let poly_groups = [&poly_refs[..]];
	let hints_by_point = vec![vec![data.hint.clone()], vec![data.hint.clone()]];
	let selected_commitments = [data.commitment.clone()];
	let bool_commitments = [data.commitment.clone()];
	let commitments_by_point = [&selected_commitments[..], &bool_commitments[..]];
	let poly_groups_by_point = [&poly_groups[..], &poly_groups[..]];
	let opening_points = [selected_point, bool_point];
	let mut transcript = hachi_pcs::protocol::transcript::Blake2bTranscript::<HachiScalar>::new(
		b"binius/hachi-succinct/openings",
	);
	<Scheme as CommitmentScheme<HachiScalar, D>>::batched_prove(
		setup,
		&poly_groups_by_point,
		&opening_points,
		hints_by_point,
		&mut transcript,
		&commitments_by_point,
		BasisMode::Lagrange,
	)
	.expect("Hachi batched opening proof should succeed")
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash as B128, PackedBinaryGhash1x128b};
	use binius_hash::StdDigest;
	use binius_iop::{
		channel::{IOPVerifierChannel, OracleLinearRelation, OracleSpec},
		hachi_bridge::ConstantTransparentRelation,
		hachi_succinct_channel::HachiSuccinctVerifierChannel,
	};
	use binius_math::{
		FieldBuffer, inner_product::inner_product_buffers, test_utils::random_field_buffer,
	};
	use binius_transcript::{ProverTranscript, fiat_shamir::HasherChallenger};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	type StdChallenger = HasherChallenger<StdDigest>;
	type P = PackedBinaryGhash1x128b;

	#[test]
	fn hachi_succinct_verifier_accepts_structured_constant_relation() {
		let mut rng = StdRng::seed_from_u64(0);
		let log_len = 7;
		let oracle_specs = vec![OracleSpec {
			log_msg_len: log_len,
		}];
		let hachi_setup = HachiSuccinctSetup::new(&oracle_specs);
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let coefficient = B128::new(0x0101_0203_0508_0d15_2237_5990_e979_62db);
		let transparent = FieldBuffer::<P>::from_values(&vec![coefficient; 1 << log_len]);
		let claim = inner_product_buffers(&message, &transparent);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel = HachiSuccinctProverChannel::new(
			&mut prover_transcript,
			oracle_specs.clone(),
			&hachi_setup,
		);
		let oracle = prover_channel.send_oracle(message.to_ref());
		prover_channel.prove_oracle_relations([(oracle, message, transparent, claim)]);

		let mut verifier_transcript = prover_transcript.into_verifier();
		let mut verifier_channel = HachiSuccinctVerifierChannel::new(
			&mut verifier_transcript,
			&oracle_specs,
			&hachi_setup,
		);
		let oracle = verifier_channel.recv_oracle().unwrap();
		let structured_relation = ConstantTransparentRelation::new(log_len, coefficient);
		verifier_channel
			.verify_oracle_relations([OracleLinearRelation::new(
				oracle,
				Box::new(move |point: &[B128]| {
					assert_eq!(point.len(), log_len);
					coefficient
				}),
				claim,
			)
			.with_hachi_structured_transparent(structured_relation)])
			.unwrap();
		verifier_transcript.finalize().unwrap();
	}

	#[test]
	fn hachi_succinct_verifier_rejects_wrong_structured_relation() {
		let mut rng = StdRng::seed_from_u64(1);
		let log_len = 7;
		let oracle_specs = vec![OracleSpec {
			log_msg_len: log_len,
		}];
		let hachi_setup = HachiSuccinctSetup::new(&oracle_specs);
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let coefficient = B128::new(0x0101_0203_0508_0d15_2237_5990_e979_62db);
		let transparent = FieldBuffer::<P>::from_values(&vec![coefficient; 1 << log_len]);
		let claim = inner_product_buffers(&message, &transparent);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel = HachiSuccinctProverChannel::new(
			&mut prover_transcript,
			oracle_specs.clone(),
			&hachi_setup,
		);
		let oracle = prover_channel.send_oracle(message.to_ref());
		prover_channel.prove_oracle_relations([(oracle, message, transparent, claim)]);

		let mut verifier_transcript = prover_transcript.into_verifier();
		let mut verifier_channel = HachiSuccinctVerifierChannel::new(
			&mut verifier_transcript,
			&oracle_specs,
			&hachi_setup,
		);
		let oracle = verifier_channel.recv_oracle().unwrap();
		let wrong_coefficient = coefficient + B128::new(1);
		let wrong_relation = ConstantTransparentRelation::new(log_len, wrong_coefficient);
		assert!(
			verifier_channel
				.verify_oracle_relations([OracleLinearRelation::new(
					oracle,
					Box::new(move |point: &[B128]| {
						assert_eq!(point.len(), log_len);
						wrong_coefficient
					}),
					claim,
				)
				.with_hachi_structured_transparent(wrong_relation)])
				.is_err()
		);
	}
}
