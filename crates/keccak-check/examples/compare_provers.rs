// Copyright 2026 The Binius Developers

use std::{array, env, time::Instant};

use binius_circuits::keccak::permutation::{Permutation, State};
use binius_core::constraint_system::ValueVec;
use binius_examples::{StdProver, setup_sha256};
use binius_field::arch::OptimalPackedB128;
use binius_frontend::{Circuit, CircuitBuilder};
use binius_keccak_check::{
	compact_trace_from_inputs, prove as prove_protocol,
	prove_grouped as prove_protocol_grouped, prove_parallel as prove_protocol_parallel,
};
use binius_transcript::ProverTranscript as ProtocolProverTranscript;
use binius_verifier::{
	config::StdChallenger, transcript::ProverTranscript as CircuitProverTranscript,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn main() {
	if env::var("KECCAK_TRACE")
		.map(|v| v == "1" || v == "true")
		.unwrap_or(false)
	{
		let _ = tracing_profile::init_tracing();
	}

	let log_batch = env_usize("KECCAK_LOG_BATCH", 10);
	let n_iters = env_usize("KECCAK_ITERS", 5);
	let group_size = env_usize("KECCAK_GROUP_SIZE", 4);
	let skip_circuit = env::var("SKIP_CIRCUIT")
		.map(|v| v == "1" || v == "true")
		.unwrap_or(false);

	let batch_len = 1usize << log_batch;
	let states = random_states(batch_len);

	println!();
	println!("batch = {batch_len} (2^{log_batch}), {n_iters} iterations, median reported");
	println!("{}", "-".repeat(60));

	if !skip_circuit {
		eprintln!("[circuit] setup (batch={batch_len})...");
		let setup_start = Instant::now();
		let (prover, witness_template) = setup_circuit_prover(&states);
		let setup_ms = setup_start.elapsed().as_secs_f64() * 1_000.0;
		eprintln!("[circuit] setup done in {setup_ms:.0}ms");

		let mut prove_times = Vec::with_capacity(n_iters);
		let mut proof_size = 0;
		for i in 0..n_iters {
			let witness = witness_template.clone();
			let start = Instant::now();
			let proof = prove_circuit(&prover, witness);
			let ms = start.elapsed().as_secs_f64() * 1_000.0;
			proof_size = proof.len();
			eprintln!("  circuit prove [{}/{}]: {ms:.1}ms", i + 1, n_iters);
			prove_times.push(ms);
		}
		prove_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
		let median = prove_times[n_iters / 2];
		println!(
			"  circuit:  setup={setup_ms:.1}ms  prove={median:.1}ms (median)  proof={:.2}KB",
			proof_size as f64 / 1024.0
		);
	}

	{
		eprintln!("[protocol] trace (batch={batch_len})...");
		let trace_start = Instant::now();
		let trace = compact_trace_from_inputs(&states);
		let trace_ms = trace_start.elapsed().as_secs_f64() * 1_000.0;
		eprintln!("[protocol] trace done in {trace_ms:.0}ms");

		let mut prove_times = Vec::with_capacity(n_iters);
		let mut proof_size = 0;
		for i in 0..n_iters {
			let start = Instant::now();
			let proof = prove_protocol_bytes(&trace);
			let ms = start.elapsed().as_secs_f64() * 1_000.0;
			proof_size = proof.len();
			eprintln!("  protocol prove [{}/{}]: {ms:.1}ms", i + 1, n_iters);
			prove_times.push(ms);
		}
		prove_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
		let median = prove_times[n_iters / 2];
		println!(
			"  protocol: trace={trace_ms:.1}ms  prove={median:.1}ms (median)  proof={:.2}KB",
			proof_size as f64 / 1024.0
		);

		let mut grouped_times = Vec::with_capacity(n_iters);
		let mut grouped_proof_size = 0;
		for i in 0..n_iters {
			let start = Instant::now();
			let proof = prove_grouped_bytes(&trace, group_size);
			let ms = start.elapsed().as_secs_f64() * 1_000.0;
			grouped_proof_size = proof.len();
			eprintln!(
				"  flat(k={group_size}) prove [{}/{}]: {ms:.1}ms",
				i + 1,
				n_iters
			);
			grouped_times.push(ms);
		}
		grouped_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
		let grouped_median = grouped_times[n_iters / 2];
		println!(
			"  flat(k={group_size}): trace={trace_ms:.1}ms  prove={grouped_median:.1}ms (median)  proof={:.2}KB",
			grouped_proof_size as f64 / 1024.0
		);

		let mut parallel_times = Vec::with_capacity(n_iters);
		let mut parallel_proof_size = 0;
		for i in 0..n_iters {
			let start = Instant::now();
			let proof = prove_parallel_bytes(&trace, group_size);
			let ms = start.elapsed().as_secs_f64() * 1_000.0;
			parallel_proof_size = proof.len();
			eprintln!(
				"  parallel(k={group_size}) prove [{}/{}]: {ms:.1}ms",
				i + 1,
				n_iters
			);
			parallel_times.push(ms);
		}
		parallel_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
		let parallel_median = parallel_times[n_iters / 2];
		println!(
			"  parallel(k={group_size}): trace={trace_ms:.1}ms  prove={parallel_median:.1}ms (median)  proof={:.2}KB",
			parallel_proof_size as f64 / 1024.0
		);

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

fn setup_circuit_prover(states: &[[u64; 25]]) -> (StdProver, ValueVec) {
	let builder = CircuitBuilder::new();
	let permutations: Vec<Permutation> = (0..states.len())
		.map(|_| {
			let input_state = State {
				words: array::from_fn(|_| builder.add_inout()),
			};
			Permutation::new(&builder, input_state)
		})
		.collect();
	let circuit = builder.build();
	let witness = prepare_witness(&circuit, &permutations, states);
	let (_verifier, prover) = setup_sha256(circuit.constraint_system().clone(), 1, None)
		.expect("circuit setup should succeed");
	(prover, witness)
}

fn prepare_witness(
	circuit: &Circuit,
	permutations: &[Permutation],
	states: &[[u64; 25]],
) -> ValueVec {
	let mut filler = circuit.new_witness_filler();
	for (permutation, state) in std::iter::zip(permutations, states.iter().copied()) {
		permutation.populate_state(&mut filler, state);
	}
	circuit
		.populate_wire_witness(&mut filler)
		.expect("witness population should succeed");
	filler.into_value_vec()
}

fn prove_circuit(prover: &StdProver, witness: ValueVec) -> Vec<u8> {
	let mut transcript = CircuitProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness, &mut transcript)
		.expect("circuit proof should succeed");
	transcript.finalize()
}

fn prove_protocol_bytes(trace: &binius_keccak_check::CompactTrace) -> Vec<u8> {
	let mut transcript = ProtocolProverTranscript::new(StdChallenger::default());
	prove_protocol::<OptimalPackedB128, _>(trace, &mut transcript)
		.expect("keccak-check proof should succeed");
	transcript.finalize()
}

fn prove_grouped_bytes(trace: &binius_keccak_check::CompactTrace, group_size: usize) -> Vec<u8> {
	let mut transcript = ProtocolProverTranscript::new(StdChallenger::default());
	prove_protocol_grouped::<OptimalPackedB128, _>(trace, group_size, &mut transcript)
		.expect("grouped keccak-check proof should succeed");
	transcript.finalize()
}

fn prove_parallel_bytes(trace: &binius_keccak_check::CompactTrace, group_size: usize) -> Vec<u8> {
	let mut transcript = ProtocolProverTranscript::new(StdChallenger::default());
	prove_protocol_parallel::<OptimalPackedB128, _>(trace, group_size, &mut transcript)
		.expect("parallel keccak-check proof should succeed");
	transcript.finalize()
}

