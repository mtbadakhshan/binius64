// Copyright 2026 The Binius Developers

//! Wire helpers for embedding Akita proof objects in a Binius transcript.

use std::io::Cursor;

use binius_transcript::{
	ProverTranscript, VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use akita_field::CanonicalField;
use akita_serialization::{AkitaDeserialize, AkitaSerialize, Compress};
use akita_types::{
	AkitaBatchedProofShape, AkitaProofStepShape, AkitaStage1StageShape, DirectWitnessShape,
	LevelProofShape,
};

use binius_iop::channel::Error;

use crate::protocol::{AkitaFieldScalar, BiniusScalar};

/// Maximum bytes accepted for one length-prefixed Akita object.
///
/// This keeps malformed proofs from forcing unbounded allocations while leaving ample headroom
/// above the current succinct bridge proof sizes.
const MAX_AKITA_ENCODED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Write a Akita-serialisable value to the Binius transcript.
pub fn write_akita<T, Challenger_>(transcript: &mut ProverTranscript<Challenger_>, value: &T)
where
	T: AkitaSerialize,
	Challenger_: Challenger,
{
	let mut bytes = Vec::new();
	value
		.serialize_with_mode(&mut bytes, Compress::Yes)
		.expect("Akita serialization into Vec should not fail");
	transcript.message().write(&(bytes.len() as u64));
	transcript.message().write_bytes(&bytes);
}

/// Read a Akita-serialisable value from the Binius transcript.
pub fn read_akita<T, Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
	ctx: &T::Context,
) -> Result<T, Error>
where
	T: AkitaDeserialize,
	Challenger_: Challenger,
{
	let len: u64 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
	if len > MAX_AKITA_ENCODED_OBJECT_BYTES {
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

/// Sample a Akita scalar from the Binius Fiat-Shamir transcript.
pub fn sample_akita_scalar<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
) -> AkitaFieldScalar
where
	Challenger_: Challenger,
{
	loop {
		let sample = CanSample::<BiniusScalar>::sample(transcript).val();
		if let Some(scalar) = AkitaFieldScalar::from_canonical_u128_checked(sample) {
			return scalar;
		}
	}
}

/// Sample multiple Akita scalars from the Binius Fiat-Shamir transcript.
pub fn sample_akita_scalar_vec<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	len: usize,
) -> Vec<AkitaFieldScalar>
where
	Challenger_: Challenger,
{
	(0..len).map(|_| sample_akita_scalar(transcript)).collect()
}

/// Sample a Akita scalar from a verifier transcript.
pub fn verify_sample_akita_scalar<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> AkitaFieldScalar
where
	Challenger_: Challenger,
{
	loop {
		let sample = CanSample::<BiniusScalar>::sample(transcript).val();
		if let Some(scalar) = AkitaFieldScalar::from_canonical_u128_checked(sample) {
			return scalar;
		}
	}
}

/// Sample multiple Akita scalars from a verifier transcript.
pub fn verify_sample_akita_scalar_vec<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
	len: usize,
) -> Vec<AkitaFieldScalar>
where
	Challenger_: Challenger,
{
	(0..len)
		.map(|_| verify_sample_akita_scalar(transcript))
		.collect()
}

/// Write a Akita batched proof shape.
pub fn write_batched_shape<Challenger_>(
	transcript: &mut ProverTranscript<Challenger_>,
	shape: &AkitaBatchedProofShape,
) where
	Challenger_: Challenger,
{
	match shape {
		AkitaBatchedProofShape::Fold {
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
		AkitaBatchedProofShape::Direct { witness_shapes } => {
			transcript.message().write(&1u8);
			transcript.message().write(&(witness_shapes.len() as u64));
			for shape in witness_shapes {
				write_direct_shape(transcript, shape);
			}
		}
	}
}

/// Read a Akita batched proof shape.
pub fn read_batched_shape<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<AkitaBatchedProofShape, Error>
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
			Ok(AkitaBatchedProofShape::Fold {
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
			Ok(AkitaBatchedProofShape::Direct { witness_shapes })
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
		stage1_stages.push(AkitaStage1StageShape {
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
	shape: &AkitaProofStepShape,
) where
	Challenger_: Challenger,
{
	match shape {
		AkitaProofStepShape::Fold(shape) => {
			transcript.message().write(&0u8);
			write_level_shape(transcript, shape);
		}
		AkitaProofStepShape::Direct(shape) => {
			transcript.message().write(&1u8);
			write_direct_shape(transcript, shape);
		}
	}
}

fn read_step_shape<Challenger_>(
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<AkitaProofStepShape, Error>
where
	Challenger_: Challenger,
{
	let tag: u8 = transcript.message().read().map_err(|_| Error::ProofEmpty)?;
	match tag {
		0 => Ok(AkitaProofStepShape::Fold(read_level_shape(transcript)?)),
		1 => Ok(AkitaProofStepShape::Direct(read_direct_shape(transcript)?)),
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
	use binius_transcript::fiat_shamir::HasherChallenger;
	use sha2::Sha256;

	use super::*;
	use akita_serialization::{AkitaSerialize, Compress};

	type TestChallenger = HasherChallenger<Sha256>;

	fn verifier_transcript_from_payload(
		payload: &[u8],
	) -> VerifierTranscript<TestChallenger> {
		let mut prover_transcript = ProverTranscript::new(TestChallenger::default());
		prover_transcript.message().write(&(payload.len() as u64));
		prover_transcript.message().write_bytes(payload);
		prover_transcript.into_verifier()
	}

	#[test]
	fn read_akita_rejects_trailing_bytes() {
		let scalar = AkitaFieldScalar::from_u64(42);
		let mut payload = Vec::new();
		scalar
			.serialize_with_mode(&mut payload, Compress::Yes)
			.unwrap();
		payload.push(0);

		let mut verifier_transcript = verifier_transcript_from_payload(&payload);

		assert!(read_akita::<AkitaFieldScalar, _>(&mut verifier_transcript, &()).is_err());
	}

	#[test]
	fn read_akita_rejects_oversized_payload_before_allocation() {
		let mut prover_transcript = ProverTranscript::new(TestChallenger::default());
		prover_transcript
			.message()
			.write(&(MAX_AKITA_ENCODED_OBJECT_BYTES + 1));
		let mut verifier_transcript = prover_transcript.into_verifier();

		assert!(read_akita::<AkitaFieldScalar, _>(&mut verifier_transcript, &()).is_err());
	}
}
