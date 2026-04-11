// Copyright 2026 The Binius Developers

use std::{alloc::System, env, time::Instant};

use binius_field::arch::{OptimalB128, OptimalPackedB128};
use binius_keccak_check::{
	CompactTrace, compact_trace_from_inputs, prove as prove_protocol, verify as verify_protocol,
};
use binius_transcript::ProverTranscript;
use binius_verifier::{
	config::StdChallenger, transcript::VerifierTranscript as ProtocolVerifierTranscript,
};
use peakmem_alloc::{PeakAlloc, PeakAllocTrait};
use rand::{Rng, SeedableRng, rngs::StdRng};

type Packed = OptimalPackedB128;
type Scalar = OptimalB128;

#[global_allocator]
static PEAK_ALLOC: PeakAlloc<System> = PeakAlloc::new(System);

fn main() {
	let max_log = env_usize("KECCAK_MAX_LOG_BATCH", 16);
	let min_log = env_usize("KECCAK_MIN_LOG_BATCH", 0);
	let runs = env_usize("KECCAK_PROVE_EVAL_RUNS", 5);
	let warmup = env_usize("KECCAK_PROVE_EVAL_WARMUP", 1);
	let skip_verify = env::var("KECCAK_SKIP_VERIFY")
		.map(|v| v == "1" || v == "true")
		.unwrap_or(false);

	println!(
		"{:>10} {:>14} {:>14} {:>14} {:>14} {:>14} {:>12}",
		"batch", "trace_peak_MB", "prove_peak_MB", "prove_ms", "verify_ms", "proof_KB", "runs"
	);
	println!("{}", "-".repeat(96));

	for log_batch in min_log..=max_log {
		let batch_len = 1usize << log_batch;

		PEAK_ALLOC.reset_peak_memory();
		let states = random_states(batch_len);
		let trace = compact_trace_from_inputs(&states);
		drop(states);
		let trace_peak = PEAK_ALLOC.get_peak_memory();

		let baseline_proof = prove_protocol_bytes(&trace);
		let verify_ms = if !skip_verify {
			let mut verifier_transcript =
				ProtocolVerifierTranscript::new(StdChallenger::default(), baseline_proof.clone());
			let start = Instant::now();
			verify_protocol::<Scalar, _>(&trace, &mut verifier_transcript)
				.expect("keccak-check proof should verify");
			verifier_transcript
				.finalize()
				.expect("verifier transcript should finalize");
			start.elapsed().as_secs_f64() * 1_000.0
		} else {
			f64::NAN
		};

		for _ in 0..warmup {
			let _ = prove_protocol_bytes(&trace);
		}

		let mut prove_times_ms = Vec::with_capacity(runs);
		let mut prove_peak = 0usize;
		for _ in 0..runs {
			PEAK_ALLOC.reset_peak_memory();
			let start = Instant::now();
			let _ = prove_protocol_bytes(&trace);
			prove_times_ms.push(start.elapsed().as_secs_f64() * 1_000.0);
			prove_peak = prove_peak.max(PEAK_ALLOC.get_peak_memory());
		}

		println!(
			"{:>10} {:>14.2} {:>14.2} {:>14.3} {:>14.3} {:>14.2} {:>12}",
			batch_len,
			trace_peak as f64 / (1024.0 * 1024.0),
			prove_peak as f64 / (1024.0 * 1024.0),
			median_ms(&mut prove_times_ms),
			verify_ms,
			baseline_proof.len() as f64 / 1024.0,
			runs,
		);

		drop(trace);
	}
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

fn prove_protocol_bytes(trace: &CompactTrace) -> Vec<u8> {
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prove_protocol::<Packed, _>(trace, &mut prover_transcript)
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
