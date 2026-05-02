// Copyright 2026 The Binius Developers

//! Wire helpers for embedding Hachi proof objects in a Binius transcript.

use binius_transcript::{
	ProverTranscript, VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use hachi_pcs::{
	CanonicalField, HachiDeserialize, HachiSerialize,
	primitives::serialization::Compress,
	protocol::proof::{
		DirectWitnessShape, HachiBatchedProofShape, HachiProofStepShape, HachiStage1StageShape,
		LevelProofShape,
	},
};
use std::io::Cursor;

use crate::{
	channel::Error,
	hachi_bridge::{BiniusScalar, HachiScalar},
};

/// Maximum bytes accepted for one length-prefixed Hachi object.
///
/// This keeps malformed proofs from forcing unbounded allocations while leaving ample headroom
/// above the current succinct bridge proof sizes.
const MAX_HACHI_ENCODED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Write a Hachi-serializable value to the Binius transcript.
pub fn write_hachi<T, Challenger_>(transcript: &mut ProverTranscript<Challenger_>, value: &T)
where
	T: HachiSerialize,
	Challenger_: Challenger,
{
	let mut bytes = Vec::new();
	value
		.serialize_with_mode(&mut bytes, Compress::Yes)
		.expect("Hachi serialization into Vec should not fail");
	transcript.message().write(&(bytes.len() as u64));
	transcript.message().write_bytes(&bytes);
}

/// Read a Hachi-serializable value from the Binius transcript.
pub fn read_hachi<T, Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
	ctx: &T::Context,
) -> Result<T, Error>
where
	T: HachiDeserialize,
	Challenger_: Challenger,
{
	let len: u64 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
	if len > MAX_HACHI_ENCODED_OBJECT_BYTES {
		return Err(Error::ProofEmpty);
	}
	let mut bytes = vec![0u8; len as usize];
	transcript
		.message()
		.read_bytes(&mut bytes)
		.map_err(|_| Error::ProofEmpty)?;
	let mut cursor = Cursor::new(&bytes);
	let value = T::deserialize_compressed(&mut cursor, ctx).map_err(|_| Error::ProofEmpty)?;
	if cursor.position() != len {
		return Err(Error::ProofEmpty);
	}
	Ok(value)
}

/// Sample a Hachi scalar from the Binius Fiat-Shamir transcript.
pub fn sample_hachi_scalar<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
) -> HachiScalar
where
	Challenger_: Challenger,
{
	loop {
		let sample = CanSample::<BiniusScalar>::sample(transcript).val();
		if let Some(scalar) = HachiScalar::from_canonical_u128_checked(sample) {
			return scalar;
		}
	}
}

/// Sample multiple Hachi scalars from the Binius Fiat-Shamir transcript.
pub fn sample_hachi_scalar_vec<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	len: usize,
) -> Vec<HachiScalar>
where
	Challenger_: Challenger,
{
	(0..len).map(|_| sample_hachi_scalar(transcript)).collect()
}

/// Sample a Hachi scalar from a verifier transcript.
pub fn verify_sample_hachi_scalar<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> HachiScalar
where
	Challenger_: Challenger,
{
	loop {
		let sample = CanSample::<BiniusScalar>::sample(transcript).val();
		if let Some(scalar) = HachiScalar::from_canonical_u128_checked(sample) {
			return scalar;
		}
	}
}

/// Sample multiple Hachi scalars from a verifier transcript.
pub fn verify_sample_hachi_scalar_vec<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
	len: usize,
) -> Vec<HachiScalar>
where
	Challenger_: Challenger,
{
	(0..len)
		.map(|_| verify_sample_hachi_scalar(transcript))
		.collect()
}

/// Write a Hachi batched proof shape.
pub fn write_batched_shape<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	shape: &HachiBatchedProofShape,
) where
	Challenger_: Challenger,
{
	match shape {
		HachiBatchedProofShape::Fold {
			root_shape,
			step_shapes,
		} => {
			transcript.message().write(&0u8);
			write_level_shape(transcript, root_shape);
			transcript.message().write(&(step_shapes.len() as u64));
			for step in step_shapes {
				write_step_shape(transcript, step);
			}
		}
		HachiBatchedProofShape::Direct { witness_shapes } => {
			transcript.message().write(&1u8);
			transcript.message().write(&(witness_shapes.len() as u64));
			for shape in witness_shapes {
				write_direct_shape(transcript, shape);
			}
		}
	}
}

/// Read a Hachi batched proof shape.
pub fn read_batched_shape<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<HachiBatchedProofShape, Error>
where
	Challenger_: Challenger,
{
	let tag: u8 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
	match tag {
		0 => {
			let root_shape = read_level_shape(transcript)?;
			let n_steps: u64 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
			let mut step_shapes = Vec::with_capacity(n_steps as usize);
			for _ in 0..n_steps {
				step_shapes.push(read_step_shape(transcript)?);
			}
			Ok(HachiBatchedProofShape::Fold {
				root_shape,
				step_shapes,
			})
		}
		1 => {
			let n_witnesses: u64 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
			let mut witness_shapes = Vec::with_capacity(n_witnesses as usize);
			for _ in 0..n_witnesses {
				witness_shapes.push(read_direct_shape(transcript)?);
			}
			Ok(HachiBatchedProofShape::Direct { witness_shapes })
		}
		_ => Err(Error::ProofEmpty),
	}
}

fn write_level_shape<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	shape: &LevelProofShape,
) where
	Challenger_: Challenger,
{
	transcript.message().write(&(shape.y_ring_coeffs as u64));
	transcript.message().write(&(shape.v_coeffs as u64));
	transcript
		.message()
		.write(&(shape.stage1_stages.len() as u64));
	for stage in &shape.stage1_stages {
		transcript.message().write(&(stage.sumcheck.0 as u64));
		transcript.message().write(&(stage.sumcheck.1 as u64));
		transcript.message().write(&(stage.child_claims as u64));
	}
	transcript
		.message()
		.write(&(shape.stage2_sumcheck.0 as u64));
	transcript
		.message()
		.write(&(shape.stage2_sumcheck.1 as u64));
	transcript
		.message()
		.write(&(shape.next_commit_coeffs as u64));
}

fn read_level_shape<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<LevelProofShape, Error>
where
	Challenger_: Challenger,
{
	let y_ring_coeffs = read_usize(transcript)?;
	let v_coeffs = read_usize(transcript)?;
	let n_stages = read_usize(transcript)?;
	let mut stage1_stages = Vec::with_capacity(n_stages);
	for _ in 0..n_stages {
		stage1_stages.push(HachiStage1StageShape {
			sumcheck: (read_usize(transcript)?, read_usize(transcript)?),
			child_claims: read_usize(transcript)?,
		});
	}
	let stage2_sumcheck = (read_usize(transcript)?, read_usize(transcript)?);
	let next_commit_coeffs = read_usize(transcript)?;
	Ok(LevelProofShape {
		y_ring_coeffs,
		v_coeffs,
		stage1_stages,
		stage2_sumcheck,
		next_commit_coeffs,
	})
}

fn write_step_shape<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	shape: &HachiProofStepShape,
) where
	Challenger_: Challenger,
{
	match shape {
		HachiProofStepShape::Fold(shape) => {
			transcript.message().write(&0u8);
			write_level_shape(transcript, shape);
		}
		HachiProofStepShape::Direct(shape) => {
			transcript.message().write(&1u8);
			write_direct_shape(transcript, shape);
		}
	}
}

fn read_step_shape<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<HachiProofStepShape, Error>
where
	Challenger_: Challenger,
{
	let tag: u8 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
	match tag {
		0 => Ok(HachiProofStepShape::Fold(read_level_shape(transcript)?)),
		1 => Ok(HachiProofStepShape::Direct(read_direct_shape(transcript)?)),
		_ => Err(Error::ProofEmpty),
	}
}

fn write_direct_shape<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	shape: &DirectWitnessShape,
) where
	Challenger_: Challenger,
{
	match shape {
		DirectWitnessShape::PackedDigits((n, bits)) => {
			transcript.message().write(&0u8);
			transcript.message().write(&(*n as u64));
			transcript.message().write(&(*bits as u64));
		}
		DirectWitnessShape::FieldElements(n) => {
			transcript.message().write(&1u8);
			transcript.message().write(&(*n as u64));
		}
	}
}

fn read_direct_shape<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<DirectWitnessShape, Error>
where
	Challenger_: Challenger,
{
	let tag: u8 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
	match tag {
		0 => Ok(DirectWitnessShape::PackedDigits((
			read_usize(transcript)?,
			read_usize(transcript)? as u32,
		))),
		1 => Ok(DirectWitnessShape::FieldElements(read_usize(transcript)?)),
		_ => Err(Error::ProofEmpty),
	}
}

fn read_usize<Challenger_>(transcript: &mut VerifierTranscript<Challenger_>) -> Result<usize, Error>
where
	Challenger_: Challenger,
{
	let value: u64 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
	Ok(value as usize)
}

#[cfg(test)]
mod tests {
	use super::*;
	use binius_transcript::fiat_shamir::HasherChallenger;
	use hachi_pcs::{FromSmallInt, HachiSerialize, primitives::serialization::Compress};
	use sha2::Sha256;

	type TestChallenger = HasherChallenger<Sha256>;

	fn verifier_transcript_from_hachi_payload(
		payload: &[u8],
	) -> VerifierTranscript<TestChallenger> {
		let mut prover_transcript = ProverTranscript::new(TestChallenger::default());
		prover_transcript.message().write(&(payload.len() as u64));
		prover_transcript.message().write_bytes(payload);
		prover_transcript.into_verifier()
	}

	#[test]
	fn read_hachi_rejects_trailing_bytes() {
		let scalar = HachiScalar::from_u64(42);
		let mut payload = Vec::new();
		scalar
			.serialize_with_mode(&mut payload, Compress::Yes)
			.unwrap();
		payload.push(0);

		let mut verifier_transcript = verifier_transcript_from_hachi_payload(&payload);

		assert!(read_hachi::<HachiScalar, _>(&mut verifier_transcript, &()).is_err());
	}

	#[test]
	fn read_hachi_rejects_oversized_payload_before_allocation() {
		let mut prover_transcript = ProverTranscript::new(TestChallenger::default());
		prover_transcript
			.message()
			.write(&(MAX_HACHI_ENCODED_OBJECT_BYTES + 1));
		let mut verifier_transcript = prover_transcript.into_verifier();

		assert!(read_hachi::<HachiScalar, _>(&mut verifier_transcript, &()).is_err());
	}
}
