// Copyright 2026 The Binius Developers

//! Succinct Hachi bridge verifier channel.

use binius_field::Field;
use binius_ip::channel::IPVerifierChannel;
use binius_math::{FieldBuffer, multilinear::evaluate::evaluate_inplace};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use hachi_pcs::{
	BasisMode, CommitmentScheme, FromSmallInt, Transcript,
	protocol::{
		commitment::{
			HachiRootBatchSummary, HachiScheduleLookupKey, RingCommitment,
			batched_proof_shape_for_lookup_key, presets::fp128,
		},
		commitment_scheme::HachiCommitmentScheme,
		proof::{HachiBatchedProof, HachiBatchedProofShape},
		setup::HachiVerifierSetup,
	},
};

use crate::{
	channel::{Error, IOPVerifierChannel, OracleLinearRelation, OracleSpec},
	hachi_bridge::{
		BINIUS_SCALAR_BITS, BatchedParityBridgeProof, BiniusScalar, HachiScalar, batched_u64_sum,
		evaluate_batched_selected_sum_table_mask, parity_sum_bounds,
		verify_product_sumcheck_transcript,
	},
	hachi_wire,
};

type Cfg = fp128::D64OneHot;
const D: usize = 64;
const HACHI_OPENING_CLAIMS: usize = 2;
const HACHI_OPENING_GROUPS: usize = 2;
const HACHI_OPENING_POINTS: usize = 2;
type Scheme = HachiCommitmentScheme<D, Cfg>;
type Commitment = RingCommitment<HachiScalar, D>;

/// Hachi prover setup used by the succinct bridge.
pub type HachiSuccinctProverSetup = hachi_pcs::protocol::setup::HachiProverSetup<HachiScalar, D>;
/// Hachi verifier setup used by the succinct bridge.
pub type HachiSuccinctVerifierSetup = HachiVerifierSetup<HachiScalar>;

/// Per-oracle Hachi succinct setup derived from the verifier public parameters.
#[derive(Debug, Clone)]
pub struct HachiSuccinctOracleSetup {
	log_msg_len: usize,
	prover_setup: HachiSuccinctProverSetup,
	verifier_setup: HachiSuccinctVerifierSetup,
}

impl HachiSuccinctOracleSetup {
	/// Returns the Binius oracle length this Hachi setup supports.
	pub fn log_msg_len(&self) -> usize {
		self.log_msg_len
	}

	/// Returns the reusable Hachi prover setup.
	pub fn prover_setup(&self) -> &HachiSuccinctProverSetup {
		&self.prover_setup
	}

	/// Returns the reusable Hachi verifier setup.
	pub fn verifier_setup(&self) -> &HachiSuccinctVerifierSetup {
		&self.verifier_setup
	}
}

/// Reusable setup for all succinct Hachi bridge oracles in a verifier.
#[derive(Debug, Clone)]
pub struct HachiSuccinctSetup {
	oracle_setups: Vec<HachiSuccinctOracleSetup>,
}

impl HachiSuccinctSetup {
	/// Builds reusable Hachi setup from the oracle specs chosen during verifier setup.
	pub fn new(oracle_specs: &[OracleSpec]) -> Self {
		let oracle_setups = oracle_specs
			.iter()
			.map(|spec| {
				assert!(
					spec.log_msg_len >= 7,
					"hachi-succinct currently uses D={D} and requires at least 7 variables"
				);
				let prover_setup = <Scheme as CommitmentScheme<HachiScalar, D>>::setup_prover(
					spec.log_msg_len + 8,
					HACHI_OPENING_CLAIMS,
					HACHI_OPENING_POINTS,
				);
				let verifier_setup =
					<Scheme as CommitmentScheme<HachiScalar, D>>::setup_verifier(&prover_setup);
				HachiSuccinctOracleSetup {
					log_msg_len: spec.log_msg_len,
					prover_setup,
					verifier_setup,
				}
			})
			.collect();

		Self { oracle_setups }
	}

	/// Returns the reusable setup for an oracle index.
	pub fn oracle_setup(&self, index: usize) -> &HachiSuccinctOracleSetup {
		&self.oracle_setups[index]
	}
}

/// Oracle handle returned by [`HachiSuccinctVerifierChannel::recv_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct HachiSuccinctOracle {
	index: usize,
}

struct OracleData {
	log_msg_len: usize,
	commitment: Commitment,
}

/// Verifier channel for the succinct Hachi bridge.
pub struct HachiSuccinctVerifierChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	transcript: &'a mut VerifierTranscript<Challenger_>,
	oracle_specs: &'a [OracleSpec],
	hachi_setup: &'a HachiSuccinctSetup,
	oracles: Vec<OracleData>,
	next_oracle_index: usize,
}

impl<'a, Challenger_> HachiSuccinctVerifierChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	/// Creates a succinct Hachi bridge verifier channel.
	pub fn new(
		transcript: &'a mut VerifierTranscript<Challenger_>,
		oracle_specs: &'a [OracleSpec],
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

impl<Challenger_> IPVerifierChannel<BiniusScalar> for HachiSuccinctVerifierChannel<'_, Challenger_>
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

impl<Challenger_> IOPVerifierChannel<BiniusScalar> for HachiSuccinctVerifierChannel<'_, Challenger_>
where
	Challenger_: Challenger,
{
	type Oracle = HachiSuccinctOracle;

	fn remaining_oracle_specs(&self) -> &[OracleSpec] {
		&self.oracle_specs[self.next_oracle_index..]
	}

	fn recv_oracle(&mut self) -> Result<Self::Oracle, Error> {
		let index = self.next_oracle_index;
		let spec = self.oracle_specs[index];
		let oracle_setup = self.hachi_setup.oracle_setup(index);
		assert_eq!(spec.log_msg_len, oracle_setup.log_msg_len());
		let commitment = hachi_wire::read_hachi::<Commitment, _>(self.transcript, &())?;
		self.oracles.push(OracleData {
			log_msg_len: spec.log_msg_len,
			commitment,
		});
		self.next_oracle_index += 1;
		Ok(HachiSuccinctOracle { index })
	}

	fn verify_oracle_relations<'a>(
		&mut self,
		oracle_relations: impl IntoIterator<Item = OracleLinearRelation<'a, Self::Oracle, Self::Elem>>,
	) -> Result<(), Error> {
		for relation in oracle_relations {
			let data = &self.oracles[relation.oracle.index];
			let oracle_setup = self.hachi_setup.oracle_setup(relation.oracle.index);
			let transparent_values =
				transparent_values_from_closure(&relation.transparent, data.log_msg_len);

			let sum_bounds = parity_sum_bounds(&transparent_values)?;
			let opened_sums = read_bounded_u64_array(self.transcript, &sum_bounds)?;
			let parity = BatchedParityBridgeProof { opened_sums };

			let alpha = hachi_wire::verify_sample_hachi_scalar(self.transcript);
			parity.verify(&transparent_values, relation.claim)?;

			let selected_initial = batched_u64_sum(&parity.opened_sums, alpha);
			let (_selected_proof, selected_point, selected_final_claim) =
				verify_product_sumcheck_transcript(
					selected_initial,
					data.log_msg_len + 7,
					self.transcript,
				)?;

			let (_bool_proof, bool_point, bool_final_claim) = verify_product_sumcheck_transcript(
				HachiScalar::from_u64(0),
				data.log_msg_len + 7,
				self.transcript,
			)?;

			let selected_openings = [hachi_wire::read_hachi::<HachiScalar, _>(
				self.transcript,
				&(),
			)?];
			let bool_openings = [hachi_wire::read_hachi::<HachiScalar, _>(
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
			let bool_expected = bool_openings[0] * (bool_openings[0] - HachiScalar::from_u64(1));
			if bool_expected != bool_final_claim {
				return Err(Error::ProofEmpty);
			}

			let shape = hachi_succinct_opening_shape(data.log_msg_len)?;
			let proof = hachi_wire::read_hachi::<HachiBatchedProof<HachiScalar>, _>(
				self.transcript,
				&shape,
			)?;
			verify_hachi_openings(
				data,
				oracle_setup.verifier_setup(),
				&with_one_coordinate(&selected_point),
				&with_one_coordinate(&bool_point),
				&selected_openings,
				&bool_openings,
				&proof,
			)?;

			let point: Vec<Self::Elem> =
				CanSample::sample_vec(&mut self.transcript, data.log_msg_len);
			let transparent_eval = (relation.transparent)(&point);
			let transparent_poly = FieldBuffer::<BiniusScalar>::from_values(&transparent_values);
			let explicit_eval = evaluate_inplace(transparent_poly, &point);
			self.assert_zero(transparent_eval - explicit_eval)?;
		}
		Ok(())
	}
}

fn with_one_coordinate(point: &[HachiScalar]) -> Vec<HachiScalar> {
	let mut extended = Vec::with_capacity(point.len() + 1);
	extended.push(HachiScalar::from_u64(1));
	extended.extend_from_slice(point);
	extended
}

fn verify_hachi_openings(
	data: &OracleData,
	verifier_setup: &HachiSuccinctVerifierSetup,
	selected_point: &[HachiScalar],
	bool_point: &[HachiScalar],
	selected_openings: &[HachiScalar],
	bool_openings: &[HachiScalar],
	proof: &HachiBatchedProof<HachiScalar>,
) -> Result<(), Error> {
	let selected_opening_groups = [selected_openings];
	let bool_opening_groups = [bool_openings];
	let opening_groups_by_point = [&selected_opening_groups[..], &bool_opening_groups[..]];
	let selected_commitments = [data.commitment.clone()];
	let bool_commitments = [data.commitment.clone()];
	let commitments_by_point = [&selected_commitments[..], &bool_commitments[..]];
	let opening_points = [selected_point, bool_point];
	let mut transcript = hachi_pcs::protocol::transcript::Blake2bTranscript::<HachiScalar>::new(
		b"binius/hachi-succinct/openings",
	);
	<Scheme as CommitmentScheme<HachiScalar, D>>::batched_verify(
		proof,
		verifier_setup,
		&mut transcript,
		&opening_points,
		&opening_groups_by_point,
		&commitments_by_point,
		BasisMode::Lagrange,
	)
	.map_err(|_| Error::ProofEmpty)
}

fn hachi_succinct_opening_shape(log_msg_len: usize) -> Result<HachiBatchedProofShape, Error> {
	let max_num_vars = log_msg_len + 8;
	let batch = HachiRootBatchSummary::new(
		HACHI_OPENING_CLAIMS,
		HACHI_OPENING_GROUPS,
		HACHI_OPENING_POINTS,
	)
	.map_err(|_| Error::ProofEmpty)?;
	let key =
		HachiScheduleLookupKey::with_batch(max_num_vars, max_num_vars, HACHI_OPENING_CLAIMS, batch);
	batched_proof_shape_for_lookup_key::<Cfg, D>(key).map_err(|_| Error::ProofEmpty)
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
	transparent: &crate::channel::TransparentEvalFn<'_, BiniusScalar>,
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
