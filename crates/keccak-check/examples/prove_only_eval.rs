// Copyright 2026 The Binius Developers

use std::{env, time::Instant};

use binius_field::arch::{OptimalB128, OptimalPackedB128};
use binius_keccak_check::{
	FullTrace, prove as prove_protocol, trace_from_inputs, verify as verify_protocol,
};
use binius_transcript::ProverTranscript;
use binius_verifier::{
	config::StdChallenger, transcript::VerifierTranscript as ProtocolVerifierTranscript,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

type Packed = OptimalPackedB128;
type Scalar = OptimalB128;

fn main() {
	let batch_len = env_usize("KECCAK_PROVE_EVAL_BATCH", 8);
	let runs = env_usize("KECCAK_PROVE_EVAL_RUNS", 7);
	let warmup = env_usize("KECCAK_PROVE_EVAL_WARMUP", 1);
	let states = random_states(batch_len);
	let trace = trace_from_inputs::<Packed>(&states);

	// Keep one untimed prove/verify sanity check so the metric still reflects
	// a valid proof, while the timed loop remains proving-only.
	let baseline_proof = prove_protocol_bytes(&trace);
	let mut verifier_transcript =
		ProtocolVerifierTranscript::new(StdChallenger::default(), baseline_proof.clone());
	verify_protocol::<Scalar, Packed, _>(&trace, &mut verifier_transcript)
		.expect("keccak-check proof should verify");
	verifier_transcript
		.finalize()
		.expect("verifier transcript should finalize");

	for _ in 0..warmup {
		let _ = prove_protocol_bytes(&trace);
	}

	let mut prove_times_ms = Vec::with_capacity(runs);
	for _ in 0..runs {
		let start = Instant::now();
		let _ = prove_protocol_bytes(&trace);
		prove_times_ms.push(start.elapsed().as_secs_f64() * 1_000.0);
	}

	println!("prove_ms: {:.6}", median_ms(&mut prove_times_ms));
	println!("proof_bytes: {}", baseline_proof.len());
	println!("batch_len: {}", batch_len);
	println!("runs: {}", runs);
}

fn env_usize(key: &str, default: usize) -> usize {
	env::var(key)
		.ok()
		.and_then(|raw| raw.parse::<usize>().ok())
		.unwrap_or(default)
}

fn random_states(batch_len: usize) -> Vec<[u64; 25]> {
	let mut rng = StdRng::seed_from_u64(0xB1A1_6400 + batch_len as u64);
	(0..batch_len).map(|_| rng.random::<[u64; 25]>()).collect()
}

fn prove_protocol_bytes(trace: &FullTrace<Packed>) -> Vec<u8> {
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prove_protocol(trace, &mut prover_transcript)
		.expect("keccak-check proof generation should succeed");
	prover_transcript.finalize()
}

fn median_ms(samples: &mut [f64]) -> f64 {
	assert!(!samples.is_empty(), "precondition: samples must be non-empty");
	samples.sort_by(f64::total_cmp);
	let mid = samples.len() / 2;
	if samples.len() % 2 == 1 {
		samples[mid]
	} else {
		(samples[mid - 1] + samples[mid]) * 0.5
	}
}
