// Copyright 2026 The Binius Developers

use std::time::Instant;

use binius_field::arch::{OptimalB128, OptimalPackedB128};
use binius_ip_prover::{
	channel::IPProverChannel,
	sumcheck::{
		common::{MleCheckProver, SumcheckProver},
		gruen32::Gruen32,
		prove_single_mlecheck,
	},
};
use binius_keccak_check::{
	bit_indexed_claim_from_evals, bit_indexed_lane_claim_from_words, compact_trace_from_inputs,
	fused_round::{self, FusedRoundReduction},
};
use binius_transcript::ProverTranscript;
use binius_verifier::config::StdChallenger;
use rand::{Rng, SeedableRng, rngs::StdRng};

type Packed = OptimalPackedB128;
type F = OptimalB128;

fn main() {
	let log_batch = 14usize;
	let batch_len = 1usize << log_batch;

	eprintln!("Profiling GKR prover at batch=2^{log_batch} ({batch_len} instances)");
	eprintln!("{}", "=".repeat(70));

	let states = random_states(batch_len);

	let t0 = Instant::now();
	let trace = compact_trace_from_inputs(&states);
	let trace_ms = t0.elapsed().as_secs_f64() * 1000.0;
	eprintln!("Trace build:          {trace_ms:>10.1} ms");

	let mut transcript = ProverTranscript::new(StdChallenger::default());
	let channel: &mut ProverTranscript<StdChallenger> = &mut transcript;

	let output_bit_challenge: F = IPProverChannel::sample(channel);
	let output_high_point: Vec<F> = IPProverChannel::sample_many(channel, trace.log_n_instances());
	let output_weights: [F; 25] = IPProverChannel::sample_array(channel);
	let output_claim = bit_indexed_lane_claim_from_words(
		&trace.final_output,
		output_bit_challenge,
		&output_high_point,
		output_weights,
	);
	let mut carried_output_claim = output_claim;

	let mut round_times = Vec::new();

	for round in (0..24).rev() {
		let t_round = Instant::now();
		let fused_output = fused_round::prove_round_from_words::<Packed, _>(
			&trace.round_inputs[round],
			&FusedRoundReduction {
				output_claim: carried_output_claim.clone(),
				round,
			},
			channel,
		)
		.expect("round should prove");
		let round_ms = t_round.elapsed().as_secs_f64() * 1000.0;
		round_times.push((round, round_ms));

		if round > 0 {
			let next_output_weights: [F; 25] = IPProverChannel::sample_array(channel);
			carried_output_claim = bit_indexed_claim_from_evals(
				output_bit_challenge,
				fused_output.reduced_high_point,
				next_output_weights,
				fused_output.input_evals,
			);
		}
	}

	eprintln!();
	eprintln!("Per-round breakdown:");
	eprintln!("{:>8} {:>12}", "round", "prove_ms");
	eprintln!("{}", "-".repeat(22));
	for &(round, ms) in &round_times {
		eprintln!("{round:>8} {ms:>12.1}");
	}
	let total: f64 = round_times.iter().map(|(_, ms)| ms).sum();
	eprintln!("{}", "-".repeat(22));
	eprintln!("{:>8} {:>12.1}", "TOTAL", total);
	eprintln!("{:>8} {:>12.1}", "AVG", total / 24.0);

	let first_round_ms = round_times[0].1;
	let rest_avg: f64 = round_times[1..].iter().map(|(_, ms)| ms).sum::<f64>() / 23.0;
	eprintln!();
	eprintln!("Round 23 (first, uses u64 words):  {first_round_ms:.1} ms");
	eprintln!("Rounds 22-0 avg (field blocks):    {rest_avg:.1} ms");
	eprintln!();
	eprintln!("The first round uses u64 word-level evaluation (no fold/expand).");
	eprintln!("Subsequent rounds use field-element block tables (after fold expands words→fields).");
	eprintln!("If round 23 >> rest: the word→field fold is not the bottleneck.");
	eprintln!("If round 23 << rest: the block-table path is more expensive.");
}

fn random_states(batch_len: usize) -> Vec<[u64; 25]> {
	let mut rng = StdRng::seed_from_u64(0xB1A1_6400 + batch_len as u64);
	(0..batch_len)
		.map(|_| rng.random::<[u64; 25]>())
		.collect()
}
