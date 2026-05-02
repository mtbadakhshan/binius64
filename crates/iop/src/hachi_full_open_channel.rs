// Copyright 2026 The Binius Developers

//! Full-opening verifier channel for the Hachi bridge prototype.
//!
//! This channel is deliberately conservative: the prover reveals the committed
//! Binius oracle and the transparent polynomial, then also sends the batched
//! parity bridge witness. The verifier checks the native Binius inner product
//! directly and checks the bounded parity bridge over Hachi's prime field.

use binius_field::Field;
use binius_ip::channel::IPVerifierChannel;
use binius_math::{FieldBuffer, inner_product::inner_product_buffers};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use crate::{
	channel::{Error, IOPVerifierChannel, OracleLinearRelation, OracleSpec},
	hachi_bridge::{BINIUS_SCALAR_BITS, BatchedParityBridgeProof},
};

/// Oracle handle returned by [`HachiFullOpenVerifierChannel::recv_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct HachiFullOpenOracle {
	index: usize,
}

/// Verifier channel that checks a full-opening Hachi bridge transcript.
pub struct HachiFullOpenVerifierChannel<'a, F, Challenger_>
where
	F: Field,
	Challenger_: Challenger,
{
	transcript: &'a mut VerifierTranscript<Challenger_>,
	oracle_specs: &'a [OracleSpec],
	stored_polynomials: Vec<FieldBuffer<F>>,
	next_oracle_index: usize,
}

impl<'a, F, Challenger_> HachiFullOpenVerifierChannel<'a, F, Challenger_>
where
	F: Field,
	Challenger_: Challenger,
{
	/// Creates a full-opening verifier channel.
	pub fn new(
		transcript: &'a mut VerifierTranscript<Challenger_>,
		oracle_specs: &'a [OracleSpec],
	) -> Self {
		Self {
			transcript,
			oracle_specs,
			stored_polynomials: Vec::new(),
			next_oracle_index: 0,
		}
	}
}

impl<F, Challenger_> IPVerifierChannel<F> for HachiFullOpenVerifierChannel<'_, F, Challenger_>
where
	F: Field,
	Challenger_: Challenger,
{
	type Elem = F;

	fn recv_one(&mut self) -> Result<F, binius_ip::channel::Error> {
		self.transcript
			.message()
			.read_scalar()
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn recv_many(&mut self, n: usize) -> Result<Vec<F>, binius_ip::channel::Error> {
		self.transcript
			.message()
			.read_scalar_slice(n)
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn recv_array<const N: usize>(&mut self) -> Result<[F; N], binius_ip::channel::Error> {
		self.transcript
			.message()
			.read()
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn sample(&mut self) -> F {
		CanSample::sample(&mut self.transcript)
	}

	fn observe_one(&mut self, val: F) -> F {
		self.transcript.observe().write_scalar(val);
		val
	}

	fn observe_many(&mut self, vals: &[F]) -> Vec<F> {
		self.transcript.observe().write_scalar_slice(vals);
		vals.to_vec()
	}

	fn assert_zero(&mut self, val: F) -> Result<(), binius_ip::channel::Error> {
		if val == F::ZERO {
			Ok(())
		} else {
			Err(binius_ip::channel::Error::InvalidAssert)
		}
	}

	fn compute_public_value(&mut self, inputs: &[F], f: impl FnOnce(&[F]) -> F) -> F {
		f(inputs)
	}
}

impl<Challenger_> IOPVerifierChannel<crate::hachi_bridge::BiniusScalar>
	for HachiFullOpenVerifierChannel<'_, crate::hachi_bridge::BiniusScalar, Challenger_>
where
	Challenger_: Challenger,
{
	type Oracle = HachiFullOpenOracle;

	fn remaining_oracle_specs(&self) -> &[OracleSpec] {
		&self.oracle_specs[self.next_oracle_index..]
	}

	fn recv_oracle(&mut self) -> Result<Self::Oracle, Error> {
		assert!(
			!self.remaining_oracle_specs().is_empty(),
			"recv_oracle called but no remaining oracle specs"
		);

		let index = self.next_oracle_index;
		let spec = &self.oracle_specs[index];
		let values = self
			.transcript
			.message()
			.read_scalar_slice(1 << spec.log_msg_len)
			.map_err(|_| Error::ProofEmpty)?;

		self.stored_polynomials
			.push(FieldBuffer::from_values(&values));
		self.next_oracle_index += 1;
		Ok(HachiFullOpenOracle { index })
	}

	fn verify_oracle_relations<'a>(
		&mut self,
		oracle_relations: impl IntoIterator<Item = OracleLinearRelation<'a, Self::Oracle, Self::Elem>>,
	) -> Result<(), Error> {
		for relation in oracle_relations {
			let index = relation.oracle.index;
			assert!(index < self.stored_polynomials.len(), "oracle index {index} out of bounds");

			let log_msg_len = self.oracle_specs[index].log_msg_len;
			let transparent_values = self
				.transcript
				.message()
				.read_scalar_slice(1 << log_msg_len)
				.map_err(|_| Error::ProofEmpty)?;
			let transparent_poly = FieldBuffer::from_values(&transparent_values);

			let opened_sums = read_u64_array::<BINIUS_SCALAR_BITS, _>(self.transcript)?;
			let bridge_proof = BatchedParityBridgeProof { opened_sums };
			bridge_proof.verify(&transparent_values, relation.claim)?;

			let stored_poly = &self.stored_polynomials[index];
			let actual_inner_product =
				inner_product_buffers(&stored_poly.to_ref(), &transparent_poly);
			self.assert_zero(actual_inner_product - relation.claim)?;

			let point: Vec<Self::Elem> = CanSample::sample_vec(&mut self.transcript, log_msg_len);
			let transparent_eval = (relation.transparent)(&point);
			let explicit_eval =
				binius_math::multilinear::evaluate::evaluate_inplace(transparent_poly, &point);
			self.assert_zero(transparent_eval - explicit_eval)?;
		}

		Ok(())
	}
}

fn read_u64_array<const N: usize, Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<[u64; N], Error>
where
	Challenger_: Challenger,
{
	let values = transcript
		.message()
		.read_vec::<u64>(N)
		.map_err(|_| Error::ProofEmpty)?;
	values.try_into().map_err(|_| Error::ProofEmpty)
}
