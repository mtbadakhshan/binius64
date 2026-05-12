// Copyright 2026 The Binius Developers

//! Phase 1 ML-DSA `MlDsaVerifier` prove / verify wall-clock benchmark.
//!
//! Measures the four moving parts of the Binius64 + Phase 1 ML-DSA
//! pipeline on a synthetic-but-honest Dilithium2 witness:
//!
//!   1. **circuit build** — `MlDsaVerifier::new` + `populate_wire_witness`.
//!   2. **setup** — `Verifier::setup` + `Prover::setup` (one-off cost,
//!      reusable across many proofs in production).
//!   3. **prove** — `Prover::prove` (per-signature in N-aggregate Phase 1).
//!   4. **verify** — `Verifier::verify` + `finalize` (per-signature).
//!
//! These numbers anchor the Phase 1 baseline before we bring R5 lattice
//! arithmetic in-circuit (Phase 2 retires the `wApprox`-hoisted shortcut
//! and is expected to inflate the constraint count substantially).
//!
//! Run with:
//!
//!   cargo bench -p binius-mldsa --bench phase1_verifier
//!
//! Each benchmark uses `sample_size(10)` because a single iteration is
//! already ≥ ~100 ms; we don't need criterion's default 100-sample
//! distribution to track regressions.

use std::time::Duration;

use binius_core::{
	constraint_system::{ConstraintSystem, ValueVec},
	word::Word,
};
use binius_field::arch::OptimalPackedB128;
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	hint::{HINT_SECTION_BYTES, pack_h_native},
	params::{MODE2, N, Q},
	polyw1::polyw1_pack_native,
	r7::{MU_BYTES, MU_LANES},
	rounding::use_hint_native,
	sigdecode::{
		SIG_C_TILDE_BYTES, SIG_H_LANE_OFFSET, SIG_PACKED_LANES, pack_signature_native,
		signature_to_lanes,
	},
	verifier::MlDsaVerifier,
	zq::from_u64_witness,
};
use binius_prover::{Prover, hash::parallel_compression::ParallelCompressionAdaptor};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha3::{
	Shake256,
	digest::{ExtendableOutput, Update, XofReader},
};

const L: usize = MODE2.l;
const K: usize = MODE2.k;
const LOG_INV_RATE: usize = 1;

struct HonestWitness {
	sig_lanes: [u64; SIG_PACKED_LANES],
	mu: [u8; MU_BYTES],
	w_approx: [[u32; N]; K],
	hint: [[u32; N]; K],
}

fn build_honest_witness(seed: u64) -> HonestWitness {
	let mut rng = StdRng::seed_from_u64(seed);
	let z_centered: [[u32; N]; L] = std::array::from_fn(|_| {
		std::array::from_fn(|_| rng.random_range(MODE2.beta + 1..2 * MODE2.gamma1 - MODE2.beta))
	});
	let w_approx: [[u32; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| rng.random_range(0..Q)));
	let hint = random_sparse_hint(&mut rng);
	let mu: [u8; MU_BYTES] = std::array::from_fn(|_| rng.random());
	let c_tilde = r7_native(&w_approx, &hint, &mu);
	let mut packed = pack_signature_native(&c_tilde, &z_centered);
	let h_polyvec_u8: [[u8; N]; K] =
		std::array::from_fn(|k| std::array::from_fn(|p| hint[k][p] as u8));
	let h_section = pack_h_native(&h_polyvec_u8);
	let h_byte_offset = SIG_H_LANE_OFFSET * 8;
	packed[h_byte_offset..h_byte_offset + HINT_SECTION_BYTES].copy_from_slice(&h_section);
	let sig_lanes = signature_to_lanes(&packed);
	HonestWitness { sig_lanes, mu, w_approx, hint }
}

fn random_sparse_hint(rng: &mut StdRng) -> [[u32; N]; K] {
	let total = rng.random_range(0..=MODE2.omega);
	let mut placed = 0usize;
	let mut h = [[0u32; N]; K];
	for poly in h.iter_mut() {
		if placed >= total {
			break;
		}
		let this_count = rng.random_range(0..=(total - placed).min(40));
		let mut positions: Vec<usize> = (0..N).collect();
		for i in 0..this_count.min(positions.len()) {
			let j = rng.random_range(i..positions.len());
			positions.swap(i, j);
		}
		for &p in &positions[..this_count] {
			poly[p] = 1;
		}
		placed += this_count;
	}
	h
}

fn r7_native(
	w_approx: &[[u32; N]; K],
	hint: &[[u32; N]; K],
	mu: &[u8; MU_BYTES],
) -> [u8; SIG_C_TILDE_BYTES] {
	use binius_mldsa::polyw1::POLYW1_PACKED_BYTES;
	const HASH_INPUT_BYTES: usize = MU_BYTES + K * POLYW1_PACKED_BYTES;
	let mut hash_input = vec![0u8; HASH_INPUT_BYTES];
	hash_input[..MU_BYTES].copy_from_slice(mu);
	for k in 0..K {
		let w1: [u32; N] =
			std::array::from_fn(|i| use_hint_native(w_approx[k][i], hint[k][i]));
		let packed = polyw1_pack_native(&w1);
		let off = MU_BYTES + k * POLYW1_PACKED_BYTES;
		hash_input[off..off + POLYW1_PACKED_BYTES].copy_from_slice(&packed);
	}
	let mut hasher = Shake256::default();
	hasher.update(&hash_input);
	let mut reader = hasher.finalize_xof();
	let mut out = [0u8; SIG_C_TILDE_BYTES];
	reader.read(&mut out);
	out
}

fn build_circuit_and_witness(w: &HonestWitness) -> (ConstraintSystem, ValueVec) {
	let builder = CircuitBuilder::new();
	let sig_wires: [Wire; SIG_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let mu_wires: [Wire; MU_LANES] = std::array::from_fn(|_| builder.add_witness());
	let w_approx_wires: [[Wire; N]; K] =
		std::array::from_fn(|_| std::array::from_fn(|_| from_u64_witness(&builder)));
	let verifier =
		MlDsaVerifier::new(&builder, &sig_wires, &mu_wires, &w_approx_wires);
	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (wire, &v) in sig_wires.iter().zip(&w.sig_lanes) {
		filler[*wire] = Word(v);
	}
	let mu_lanes: [u64; MU_LANES] = std::array::from_fn(|i| {
		let mut bytes = [0u8; 8];
		bytes.copy_from_slice(&w.mu[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(bytes)
	});
	for (wire, &v) in mu_wires.iter().zip(&mu_lanes) {
		filler[*wire] = Word(v);
	}
	for k in 0..K {
		for i in 0..N {
			filler[w_approx_wires[k][i]] = Word(w.w_approx[k][i] as u64);
			filler[verifier.hint[k][i]] = Word(w.hint[k][i] as u64);
		}
	}
	circuit
		.populate_wire_witness(&mut filler)
		.expect("honest witness must populate");
	(circuit.constraint_system().clone(), filler.into_value_vec())
}

fn bench_phase1_verifier(c: &mut Criterion) {
	let mut group = c.benchmark_group("mldsa_phase1_dilithium2");
	group.sample_size(10);
	group.measurement_time(Duration::from_secs(8));

	// Build a single honest witness and circuit; reused across benches.
	let honest = build_honest_witness(0xab_cd_42);
	let (cs, witness) = build_circuit_and_witness(&honest);
	let verifier =
		Verifier::<StdDigest, _>::setup(cs.clone(), LOG_INV_RATE, StdCompression::default())
			.expect("verifier setup");
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.expect("prover setup");

	// Diagnostic snapshot — same baseline numbers the integration test
	// prints, surfaced once at criterion start so they're easy to spot.
	eprintln!(
		"[mldsa-phase1] AND={} MUL={} value_vec={} (Dilithium2 K=L=4, LOG_INV_RATE={})",
		cs.n_and_constraints(),
		cs.n_mul_constraints(),
		witness.size(),
		LOG_INV_RATE,
	);

	group.bench_function("circuit_build_and_populate", |b| {
		b.iter(|| {
			let (_cs, _w) = build_circuit_and_witness(&honest);
		});
	});

	group.bench_function("prove", |b| {
		b.iter(|| {
			let mut transcript = ProverTranscript::new(StdChallenger::default());
			prover.prove(witness.clone(), &mut transcript).expect("prove");
			std::hint::black_box(transcript.finalize())
		});
	});

	// Generate one proof, then bench verify_only against the resulting bytes.
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.expect("prove");
	let proof_bytes = prover_transcript.finalize();
	eprintln!("[mldsa-phase1] proof_size={} bytes", proof_bytes.len());

	group.bench_function("verify", |b| {
		b.iter(|| {
			let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof_bytes.clone());
			verifier.verify(witness.public(), &mut transcript).expect("verify");
			transcript.finalize().expect("verify finalize");
		});
	});

	group.finish();
}

criterion_group!(benches, bench_phase1_verifier);
criterion_main!(benches);
