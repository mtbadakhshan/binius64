// Copyright 2026 The Binius Developers

//! Wall-clock benchmark comparing the four Binius64 proof paths (BaseFold,
//! Akita full-open, Akita succinct, Akita claim-reduced) across a small
//! matrix of test circuits.
//!
//! Mirrors the circuit fixtures from
//! `crates/prover/tests/prove_verify_all_modes.rs` so the proof-size matrix
//! and the wall-clock matrix line up 1:1.
//!
//! Run with:
//!     cargo bench -p binius-prover --features akita --bench akita_modes
//!
//! Modes 2-4 (akita-*) require the `akita` feature; the bench is registered
//! in `Cargo.toml` with `required-features = ["akita"]` so the default
//! `cargo bench` invocation is unaffected.

use binius_circuits::{
	keccak::fixed_length::keccak256,
	sha256::{Compress, Sha256 as Sha256Circuit, State},
};
use binius_core::{
	constraint_system::{ConstraintSystem, ValueVec},
	word::Word,
};
use binius_field::arch::OptimalPackedB128;
use binius_frontend::{CircuitBuilder, Wire};
use binius_prover::{Prover, hash::parallel_compression::ParallelCompressionAdaptor};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

const LOG_INV_RATE: usize = 1;
const MIN_LOG_MSG_LEN_FOR_SUCCINCT: usize = 7;

struct TestCircuit {
	name: &'static str,
	cs: ConstraintSystem,
	witness: ValueVec,
}

#[allow(clippy::type_complexity)]
fn setup(
	cs: ConstraintSystem,
) -> (
	Verifier<StdDigest, StdCompression>,
	Prover<OptimalPackedB128, ParallelCompressionAdaptor<StdCompression>, StdDigest>,
) {
	let verifier = Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default())
		.expect("verifier setup");
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.expect("prover setup");
	(verifier, prover)
}

// ---------------- circuit fixtures ----------------

fn toy_and_mask_circuit() -> TestCircuit {
	let b = CircuitBuilder::new();
	let mask = b.add_constant_64(0xFF00);
	let private = b.add_witness();
	let output = b.add_inout();
	let result = b.band(private, mask);
	b.assert_eq("masked_result", result, output);
	let circuit = b.build();
	let mut w = circuit.new_witness_filler();
	w[private] = Word(0x1234);
	w[output] = Word(0x1200);
	circuit.populate_wire_witness(&mut w).unwrap();
	TestCircuit {
		name: "toy_and_mask",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

fn sha256_compress_abc_circuit() -> TestCircuit {
	let mut preimage = [0u8; 64];
	preimage[0..3].copy_from_slice(b"abc");
	preimage[3] = 0x80;
	preimage[63] = 0x18;
	#[rustfmt::skip]
	let expected_state: [u32; 8] = [
		0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
		0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
	];

	let circuit = CircuitBuilder::new();
	let state = State::iv(&circuit);
	let input: [Wire; 16] = std::array::from_fn(|_| circuit.add_witness());
	let output: [Wire; 8] = std::array::from_fn(|_| circuit.add_inout());
	let compress = Compress::new(&circuit, state, input);

	let mask32 = circuit.add_constant(Word::MASK_32);
	for (actual_x, expected_x) in compress.state_out.0.iter().zip(output) {
		circuit.assert_eq("eq", circuit.band(*actual_x, mask32), expected_x);
	}

	let circuit = circuit.build();
	let mut w = circuit.new_witness_filler();
	compress.populate_m(&mut w, preimage);
	for (i, &out) in output.iter().enumerate() {
		w[out] = Word(expected_state[i] as u64);
	}
	circuit.populate_wire_witness(&mut w).unwrap();
	TestCircuit {
		name: "sha256_compress_abc",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

fn sha256_full_short_circuit() -> TestCircuit {
	let message = b"Hello, Binius64!";
	let mut hasher = Sha256::new();
	hasher.update(message);
	let expected_digest: [u8; 32] = hasher.finalize().into();

	let b = CircuitBuilder::new();
	let len = b.add_witness();
	let digest: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
	let message_wires: Vec<Wire> = (0..8).map(|_| b.add_inout()).collect();
	let sha = Sha256Circuit::new(&b, len, digest, message_wires);
	let circuit = b.build();
	let mut w = circuit.new_witness_filler();
	sha.populate_len_bytes(&mut w, message.len());
	sha.populate_message(&mut w, message);
	sha.populate_digest(&mut w, expected_digest);
	circuit.populate_wire_witness(&mut w).unwrap();
	TestCircuit {
		name: "sha256_full_short",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

fn keccak256_32bytes_circuit() -> TestCircuit {
	let message_bytes: [u8; 32] = *b"binius64 + akita bridge matrix !";
	let mut hasher = Keccak256::new();
	hasher.update(message_bytes);
	let expected_digest: [u8; 32] = hasher.finalize().into();

	let b = CircuitBuilder::new();
	let n_words = message_bytes.len().div_ceil(8);
	let message_wires: Vec<Wire> = (0..n_words).map(|_| b.add_witness()).collect();
	let expected_digest_wires: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
	let computed = keccak256(&b, &message_wires, message_bytes.len());
	for i in 0..4 {
		b.assert_eq(format!("digest[{i}]"), computed[i], expected_digest_wires[i]);
	}
	let circuit = b.build();
	let mut w = circuit.new_witness_filler();
	for (i, chunk) in message_bytes.chunks(8).enumerate() {
		let mut word_bytes = [0u8; 8];
		word_bytes[..chunk.len()].copy_from_slice(chunk);
		w[message_wires[i]] = Word(u64::from_le_bytes(word_bytes));
	}
	for (i, chunk) in expected_digest.chunks(8).enumerate() {
		w[expected_digest_wires[i]] = Word(u64::from_le_bytes(chunk.try_into().unwrap()));
	}
	circuit.populate_wire_witness(&mut w).unwrap();
	TestCircuit {
		name: "keccak256_32bytes",
		cs: circuit.constraint_system().clone(),
		witness: w.into_value_vec(),
	}
}

fn all_circuits() -> Vec<TestCircuit> {
	vec![
		toy_and_mask_circuit(),
		keccak256_32bytes_circuit(),
		sha256_compress_abc_circuit(),
		sha256_full_short_circuit(),
	]
}

// ---------------- benches ----------------

fn bench_prove(c: &mut Criterion) {
	for circuit in all_circuits() {
		let (verifier, prover) = setup(circuit.cs.clone());
		let supports_succinct =
			verifier.log_witness_elems() >= MIN_LOG_MSG_LEN_FOR_SUCCINCT;

		let mut group = c.benchmark_group(format!("prove/{}", circuit.name));
		// Each prove run takes 50-1000 ms; keep the sample_size modest so a
		// full bench finishes in a few minutes.
		group.sample_size(10);

		group.bench_function(BenchmarkId::from_parameter("basefold"), |b| {
			b.iter(|| {
				let mut t = ProverTranscript::new(StdChallenger::default());
				prover.prove(circuit.witness.clone(), &mut t).unwrap();
				t.finalize()
			})
		});

		group.bench_function(BenchmarkId::from_parameter("akita_full_open"), |b| {
			b.iter(|| {
				let mut t = ProverTranscript::new(StdChallenger::default());
				prover
					.prove_akita_full_open(circuit.witness.clone(), &mut t)
					.unwrap();
				t.finalize()
			})
		});

		if supports_succinct {
			group.bench_function(BenchmarkId::from_parameter("akita_succinct"), |b| {
				b.iter(|| {
					let mut t = ProverTranscript::new(StdChallenger::default());
					prover
						.prove_akita_succinct(circuit.witness.clone(), &mut t)
						.unwrap();
					t.finalize()
				})
			});

			group.bench_function(BenchmarkId::from_parameter("akita_claim_reduced"), |b| {
				b.iter(|| {
					let mut t = ProverTranscript::new(StdChallenger::default());
					prover
						.prove_akita_claim_reduced(circuit.witness.clone(), &mut t)
						.unwrap();
					t.finalize()
				})
			});
		}

		group.finish();
	}
}

fn bench_verify(c: &mut Criterion) {
	for circuit in all_circuits() {
		let (verifier, prover) = setup(circuit.cs.clone());
		let supports_succinct =
			verifier.log_witness_elems() >= MIN_LOG_MSG_LEN_FOR_SUCCINCT;

		// Pre-generate honest proofs once per mode; verifier benches reuse them.
		let basefold_proof = {
			let mut t = ProverTranscript::new(StdChallenger::default());
			prover.prove(circuit.witness.clone(), &mut t).unwrap();
			t.finalize()
		};
		let full_open_proof = {
			let mut t = ProverTranscript::new(StdChallenger::default());
			prover
				.prove_akita_full_open(circuit.witness.clone(), &mut t)
				.unwrap();
			t.finalize()
		};
		let succinct_proof = supports_succinct.then(|| {
			let mut t = ProverTranscript::new(StdChallenger::default());
			prover
				.prove_akita_succinct(circuit.witness.clone(), &mut t)
				.unwrap();
			t.finalize()
		});
		let claim_reduced_proof = supports_succinct.then(|| {
			let mut t = ProverTranscript::new(StdChallenger::default());
			prover
				.prove_akita_claim_reduced(circuit.witness.clone(), &mut t)
				.unwrap();
			t.finalize()
		});

		let mut group = c.benchmark_group(format!("verify/{}", circuit.name));

		group.bench_function(BenchmarkId::from_parameter("basefold"), |b| {
			b.iter(|| {
				let mut vt =
					VerifierTranscript::new(StdChallenger::default(), basefold_proof.clone());
				verifier.verify(circuit.witness.public(), &mut vt).unwrap();
			})
		});

		group.bench_function(BenchmarkId::from_parameter("akita_full_open"), |b| {
			b.iter(|| {
				let mut vt =
					VerifierTranscript::new(StdChallenger::default(), full_open_proof.clone());
				verifier
					.verify_akita_full_open(circuit.witness.public(), &mut vt)
					.unwrap();
			})
		});

		if let Some(proof) = succinct_proof.as_ref() {
			group.bench_function(BenchmarkId::from_parameter("akita_succinct"), |b| {
				b.iter(|| {
					let mut vt =
						VerifierTranscript::new(StdChallenger::default(), proof.clone());
					verifier
						.verify_akita_succinct(circuit.witness.public(), &mut vt)
						.unwrap();
				})
			});
		}
		if let Some(proof) = claim_reduced_proof.as_ref() {
			group.bench_function(BenchmarkId::from_parameter("akita_claim_reduced"), |b| {
				b.iter(|| {
					let mut vt =
						VerifierTranscript::new(StdChallenger::default(), proof.clone());
					verifier
						.verify_akita_claim_reduced(circuit.witness.public(), &mut vt)
						.unwrap();
				})
			});
		}

		group.finish();
	}
}

criterion_group!(akita_modes, bench_prove, bench_verify);
criterion_main!(akita_modes);
