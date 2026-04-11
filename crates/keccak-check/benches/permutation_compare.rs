// Copyright 2026 The Binius Developers

use std::{array, env, hint::black_box};

use binius_circuits::keccak::permutation::{Permutation, State};
use binius_core::constraint_system::ValueVec;
use binius_examples::{StdProver, StdVerifier, setup_sha256};
use binius_field::arch::{OptimalB128, OptimalPackedB128};
use binius_frontend::{Circuit, CircuitBuilder};
use binius_keccak_check::{
	CompactTrace, compact_trace_from_inputs, prove as prove_protocol, verify as verify_protocol,
};
use binius_transcript::{
	ProverTranscript as ProtocolProverTranscript, VerifierTranscript as ProtocolVerifierTranscript,
};
use binius_verifier::{
	config::StdChallenger,
	transcript::{
		ProverTranscript as CircuitProverTranscript,
		VerifierTranscript as CircuitVerifierTranscript,
	},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng};

const DEFAULT_BATCHES: &[usize] = &[1, 2, 4, 8];
const DEFAULT_LOG_INV_RATE: usize = 1;

struct CircuitBatchCase {
	states: Vec<[u64; 25]>,
	circuit: Circuit,
	permutations: Vec<Permutation>,
	witness: ValueVec,
	verifier: StdVerifier,
	prover: StdProver,
	proof_bytes: Vec<u8>,
}

impl CircuitBatchCase {
	fn new(states: Vec<[u64; 25]>, log_inv_rate: usize) -> Self {
		let builder = CircuitBuilder::new();
		let permutations = (0..states.len())
			.map(|_| {
				let input_state = State {
					words: array::from_fn(|_| builder.add_inout()),
				};
				Permutation::new(&builder, input_state)
			})
			.collect::<Vec<_>>();
		let circuit = builder.build();
		let witness = prepare_circuit_witness(&circuit, &permutations, &states);
		let (verifier, prover) =
			setup_sha256(circuit.constraint_system().clone(), log_inv_rate, None)
				.expect("keccak permutation circuit setup should succeed");
		let proof_bytes = prove_circuit_bytes(&prover, witness.clone());

		Self {
			states,
			circuit,
			permutations,
			witness,
			verifier,
			prover,
			proof_bytes,
		}
	}

	fn prepare_witness(&self) -> ValueVec {
		prepare_circuit_witness(&self.circuit, &self.permutations, &self.states)
	}

	fn prove_bytes(&self) -> Vec<u8> {
		prove_circuit_bytes(&self.prover, self.witness.clone())
	}

	fn verify(&self) {
		let mut verifier_transcript =
			CircuitVerifierTranscript::new(StdChallenger::default(), self.proof_bytes.clone());
		self.verifier
			.verify(self.witness.public(), &mut verifier_transcript)
			.expect("baseline circuit proof should verify");
		verifier_transcript
			.finalize()
			.expect("baseline circuit transcript should finalize");
	}
}

struct ProtocolBatchCase {
	states: Vec<[u64; 25]>,
	trace: CompactTrace,
	proof_bytes: Vec<u8>,
}

impl ProtocolBatchCase {
	fn new(states: Vec<[u64; 25]>) -> Self {
		let trace = compact_trace_from_inputs(&states);
		let proof_bytes = prove_protocol_bytes(&trace);

		Self {
			states,
			trace,
			proof_bytes,
		}
	}

	fn prepare_trace(&self) -> CompactTrace {
		compact_trace_from_inputs(&self.states)
	}

	fn prove_bytes(&self) -> Vec<u8> {
		prove_protocol_bytes(&self.trace)
	}

	fn verify(&self) {
		let mut verifier_transcript =
			ProtocolVerifierTranscript::new(StdChallenger::default(), self.proof_bytes.clone());
		verify_protocol::<OptimalB128, _>(&self.trace, &mut verifier_transcript)
			.expect("keccak-check proof should verify");
		verifier_transcript
			.finalize()
			.expect("keccak-check transcript should finalize");
	}
}

struct ComparisonCase {
	batch_len: usize,
	circuit: CircuitBatchCase,
	protocol: ProtocolBatchCase,
}

impl ComparisonCase {
	fn new(batch_len: usize, log_inv_rate: usize) -> Self {
		let states = random_states(batch_len);
		let circuit = CircuitBatchCase::new(states.clone(), log_inv_rate);
		let protocol = ProtocolBatchCase::new(states);

		Self {
			batch_len,
			circuit,
			protocol,
		}
	}
}

fn random_states(batch_len: usize) -> Vec<[u64; 25]> {
	let mut rng = StdRng::seed_from_u64(0xB1A1_6400 + batch_len as u64);
	(0..batch_len).map(|_| rng.random::<[u64; 25]>()).collect()
}

fn prepare_circuit_witness(
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
		.expect("baseline circuit witness population should succeed");
	filler.into_value_vec()
}

fn prove_circuit_bytes(prover: &StdProver, witness: ValueVec) -> Vec<u8> {
	let mut prover_transcript = CircuitProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness, &mut prover_transcript)
		.expect("baseline circuit proof generation should succeed");
	prover_transcript.finalize()
}

fn prove_protocol_bytes(trace: &CompactTrace) -> Vec<u8> {
	let mut prover_transcript = ProtocolProverTranscript::new(StdChallenger::default());
	prove_protocol::<OptimalPackedB128, _>(trace, &mut prover_transcript)
		.expect("keccak-check proof generation should succeed");
	prover_transcript.finalize()
}

fn batch_sizes_from_env() -> Vec<usize> {
	env::var("KECCAK_COMPARE_BATCHES")
		.ok()
		.map(|raw| {
			raw.split(',')
				.filter_map(|entry| entry.trim().parse::<usize>().ok())
				.collect::<Vec<_>>()
		})
		.filter(|entries| !entries.is_empty())
		.unwrap_or_else(|| DEFAULT_BATCHES.to_vec())
}

fn log_inv_rate_from_env() -> usize {
	env::var("LOG_INV_RATE")
		.ok()
		.and_then(|raw| raw.parse::<usize>().ok())
		.unwrap_or(DEFAULT_LOG_INV_RATE)
}

fn maybe_init_tracing() -> Option<impl Drop> {
	env::var("KECCAK_COMPARE_TRACE")
		.ok()
		.and_then(|raw| match raw.as_str() {
			"0" | "false" | "off" => None,
			_ => tracing_profile::init_tracing().ok(),
		})
}

fn print_case_summary(case: &ComparisonCase) {
	println!(
		"KECCAK_COMPARE batch={} circuit_proof_bytes={} protocol_proof_bytes={}",
		case.batch_len,
		case.circuit.proof_bytes.len(),
		case.protocol.proof_bytes.len()
	);
}

fn bench_permutation_compare(c: &mut Criterion) {
	let _tracing_guard = maybe_init_tracing();
	let log_inv_rate = log_inv_rate_from_env();
	let batch_sizes = batch_sizes_from_env();
	let cases = batch_sizes
		.into_iter()
		.map(|batch_len| {
			assert!(
				batch_len.is_power_of_two(),
				"KECCAK_COMPARE_BATCHES entries must be powers of two"
			);
			ComparisonCase::new(batch_len, log_inv_rate)
		})
		.collect::<Vec<_>>();

	for case in &cases {
		print_case_summary(case);
	}

	let mut prep_circuit_group = c.benchmark_group("keccak_perm_prepare_circuit");
	for case in &cases {
		prep_circuit_group.throughput(Throughput::Elements(case.batch_len as u64));
		prep_circuit_group.bench_function(BenchmarkId::from_parameter(case.batch_len), |b| {
			b.iter(|| black_box(case.circuit.prepare_witness()))
		});
	}
	prep_circuit_group.finish();

	let mut prep_protocol_group = c.benchmark_group("keccak_perm_prepare_protocol");
	for case in &cases {
		prep_protocol_group.throughput(Throughput::Elements(case.batch_len as u64));
		prep_protocol_group.bench_function(BenchmarkId::from_parameter(case.batch_len), |b| {
			b.iter(|| black_box(case.protocol.prepare_trace()))
		});
	}
	prep_protocol_group.finish();

	let mut prove_circuit_group = c.benchmark_group("keccak_perm_prove_circuit");
	for case in &cases {
		prove_circuit_group.throughput(Throughput::Elements(case.batch_len as u64));
		prove_circuit_group.bench_function(BenchmarkId::from_parameter(case.batch_len), |b| {
			b.iter(|| black_box(case.circuit.prove_bytes()))
		});
	}
	prove_circuit_group.finish();

	let mut prove_protocol_group = c.benchmark_group("keccak_perm_prove_protocol");
	for case in &cases {
		prove_protocol_group.throughput(Throughput::Elements(case.batch_len as u64));
		prove_protocol_group.bench_function(BenchmarkId::from_parameter(case.batch_len), |b| {
			b.iter(|| black_box(case.protocol.prove_bytes()))
		});
	}
	prove_protocol_group.finish();

	let mut verify_circuit_group = c.benchmark_group("keccak_perm_verify_circuit");
	for case in &cases {
		verify_circuit_group.throughput(Throughput::Elements(case.batch_len as u64));
		verify_circuit_group.bench_function(BenchmarkId::from_parameter(case.batch_len), |b| {
			b.iter(|| case.circuit.verify())
		});
	}
	verify_circuit_group.finish();

	let mut verify_protocol_group = c.benchmark_group("keccak_perm_verify_protocol");
	for case in &cases {
		verify_protocol_group.throughput(Throughput::Elements(case.batch_len as u64));
		verify_protocol_group.bench_function(BenchmarkId::from_parameter(case.batch_len), |b| {
			b.iter(|| case.protocol.verify())
		});
	}
	verify_protocol_group.finish();
}

criterion_group!(permutation_compare, bench_permutation_compare);
criterion_main!(permutation_compare);
