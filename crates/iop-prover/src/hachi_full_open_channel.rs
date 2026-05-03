// Copyright 2026 The Binius Developers

//! Full-opening prover channel for the Hachi bridge prototype.

use binius_field::PackedField;
use binius_iop::{
	channel::OracleSpec,
	hachi_bridge::{BINIUS_SCALAR_BITS, BiniusScalar, prove_terminal_linear_claim},
};
use binius_ip_prover::channel::IPProverChannel;
use binius_math::{FieldBuffer, FieldSlice, inner_product::inner_product_buffers};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use crate::channel::IOPProverChannel;

/// Oracle handle returned by [`HachiFullOpenProverChannel::send_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct HachiFullOpenOracle {
	index: usize,
}

/// Prover channel that reveals oracle coefficients and sends a batched parity bridge witness.
pub struct HachiFullOpenProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	transcript: &'a mut ProverTranscript<Challenger_>,
	oracle_specs: Vec<OracleSpec>,
	n_committed: usize,
	next_oracle_index: usize,
}

impl<'a, Challenger_> HachiFullOpenProverChannel<'a, Challenger_>
where
	Challenger_: Challenger,
{
	/// Creates a full-opening Hachi bridge prover channel.
	pub fn new(
		transcript: &'a mut ProverTranscript<Challenger_>,
		oracle_specs: Vec<OracleSpec>,
	) -> Self {
		Self {
			transcript,
			oracle_specs,
			n_committed: 0,
			next_oracle_index: 0,
		}
	}
}

impl<Challenger_> IPProverChannel<BiniusScalar> for HachiFullOpenProverChannel<'_, Challenger_>
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

impl<P, Challenger_> IOPProverChannel<P> for HachiFullOpenProverChannel<'_, Challenger_>
where
	P: PackedField<Scalar = BiniusScalar>,
	Challenger_: Challenger,
{
	type Oracle = HachiFullOpenOracle;

	fn remaining_oracle_specs(&self) -> &[OracleSpec] {
		&self.oracle_specs[self.next_oracle_index..]
	}

	fn send_oracle(&mut self, buffer: FieldSlice<P>) -> Self::Oracle {
		let index = self.next_oracle_index;
		assert!(
			index < self.oracle_specs.len(),
			"send_oracle called but no remaining oracle specs"
		);

		let spec_log_msg_len = self.oracle_specs[index].log_msg_len;
		assert_eq!(
			buffer.log_len(),
			spec_log_msg_len,
			"oracle buffer log_len mismatch: expected {spec_log_msg_len}, got {}",
			buffer.log_len()
		);

		self.transcript
			.message()
			.write_scalar_iter(buffer.iter_scalars());

		self.n_committed += 1;
		self.next_oracle_index += 1;

		HachiFullOpenOracle { index }
	}

	fn prove_oracle_relations(
		&mut self,
		oracle_relations: impl IntoIterator<
			Item = (Self::Oracle, FieldBuffer<P>, FieldBuffer<P>, P::Scalar),
		>,
	) {
		for (oracle, message, transparent_poly, eval_claim) in oracle_relations {
			let index = oracle.index;
			assert!(index < self.n_committed, "oracle index {index} out of bounds");

			let log_msg_len = self.oracle_specs[index].log_msg_len;
			assert_eq!(
				message.log_len(),
				log_msg_len,
				"oracle message log_len mismatch: expected {log_msg_len}, got {}",
				message.log_len()
			);

			self.transcript
				.message()
				.write_scalar_iter(transparent_poly.iter_scalars());

			let oracle_values = message.iter_scalars().collect::<Vec<_>>();
			let transparent_values = transparent_poly.iter_scalars().collect::<Vec<_>>();
			let (native_claim, bridge_proof) =
				prove_terminal_linear_claim(&oracle_values, &transparent_values)
					.expect("bridge proof construction should match relation lengths");
			debug_assert_eq!(native_claim, eval_claim);

			self.transcript
				.message()
				.write_slice::<u64>(&bridge_proof.opened_sums[..BINIUS_SCALAR_BITS]);

			let _point: Vec<BiniusScalar> =
				CanSample::sample_vec(&mut self.transcript, log_msg_len);

			let actual_eval: BiniusScalar = inner_product_buffers(&message, &transparent_poly);
			debug_assert_eq!(
				actual_eval, eval_claim,
				"HachiFullOpenProverChannel: eval_claim mismatch for oracle {index}"
			);
		}
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash as B128, Field, PackedBinaryGhash1x128b};
	use binius_hash::StdDigest;
	use binius_iop::{
		channel::{IOPVerifierChannel, OracleLinearRelation, OracleSpec},
		hachi_full_open_channel::HachiFullOpenVerifierChannel,
	};
	use binius_math::{
		FieldBuffer,
		inner_product::inner_product_buffers,
		multilinear::eq::eq_ind_partial_eval,
		test_utils::{random_field_buffer, random_scalars},
	};
	use binius_transcript::{ProverTranscript, fiat_shamir::HasherChallenger};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	type StdChallenger = HasherChallenger<StdDigest>;
	type P = PackedBinaryGhash1x128b;

	#[test]
	fn hachi_full_open_channel_round_trip() {
		let mut rng = StdRng::seed_from_u64(0);
		let log_len = 5;
		let oracle_specs = vec![OracleSpec {
			log_msg_len: log_len,
		}];
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let point = random_scalars::<B128>(&mut rng, log_len);
		let transparent = eq_ind_partial_eval::<P>(&point);
		let claim = inner_product_buffers(&message, &transparent);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel =
			HachiFullOpenProverChannel::new(&mut prover_transcript, oracle_specs.clone());
		let oracle = prover_channel.send_oracle(message.to_ref());
		prover_channel.prove_oracle_relations([(oracle, message, transparent.clone(), claim)]);

		let mut verifier_transcript = prover_transcript.into_verifier();
		let mut verifier_channel =
			HachiFullOpenVerifierChannel::<B128, _>::new(&mut verifier_transcript, &oracle_specs);
		let oracle = verifier_channel.recv_oracle().unwrap();
		verifier_channel
			.verify_oracle_relations([OracleLinearRelation::new(
				oracle,
				Box::new(move |query| binius_math::multilinear::eq::eq_ind(&point, query)),
				claim,
			)])
			.unwrap();
		verifier_transcript.finalize().unwrap();
	}

	#[test]
	#[should_panic]
	fn hachi_full_open_channel_rejects_wrong_prover_claim_in_debug() {
		let mut rng = StdRng::seed_from_u64(1);
		let log_len = 3;
		let oracle_specs = vec![OracleSpec {
			log_msg_len: log_len,
		}];
		let message = random_field_buffer::<P>(&mut rng, log_len);
		let transparent = FieldBuffer::<P>::zeros(log_len);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let mut prover_channel =
			HachiFullOpenProverChannel::new(&mut prover_transcript, oracle_specs);
		let oracle = prover_channel.send_oracle(message.to_ref());
		prover_channel.prove_oracle_relations([(oracle, message, transparent, B128::ONE)]);
	}
}
