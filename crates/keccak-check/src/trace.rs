// Copyright 2026 The Binius Developers

use std::array;

use binius_field::PackedField;
use binius_math::FieldBuffer;

use crate::scalar_bit;

/// Keccak-f\[1600\] round constants.
pub const RC: [u64; 24] = [
	0x0000_0000_0000_0001,
	0x0000_0000_0000_8082,
	0x8000_0000_0000_808A,
	0x8000_0000_8000_8000,
	0x0000_0000_0000_808B,
	0x0000_0000_8000_0001,
	0x8000_0000_8000_8081,
	0x8000_0000_0000_8009,
	0x0000_0000_0000_008A,
	0x0000_0000_0000_0088,
	0x0000_0000_8000_8009,
	0x0000_0000_8000_000A,
	0x0000_0000_8000_808B,
	0x8000_0000_0000_008B,
	0x8000_0000_0000_8089,
	0x8000_0000_0000_8003,
	0x8000_0000_0000_8002,
	0x8000_0000_0000_0080,
	0x0000_0000_0000_800A,
	0x8000_0000_8000_000A,
	0x8000_0000_8000_8081,
	0x8000_0000_0000_8080,
	0x0000_0000_8000_0001,
	0x8000_0000_8000_8008,
];

/// Keccak-f\[1600\] rho rotation offsets in lane order `idx(x, y) = x + 5 * y`.
#[rustfmt::skip]
pub const R: [u32; 25] = [
	 0,  1, 62, 28, 27,
	36, 44,  6, 55, 20,
	 3, 10, 43, 25, 39,
	41, 45, 15, 21,  8,
	18,  2, 61, 56, 14,
];

/// Index a Keccak lane in `(x, y)` coordinates.
#[inline(always)]
pub const fn idx(x: usize, y: usize) -> usize {
	x + 5 * y
}

/// Explicit lane tables for one Keccak round.
pub type LaneTables<P> = [FieldBuffer<P>; 25];

/// Explicit batch trace for one Keccak round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundTrace<P: PackedField> {
	/// Input state `A^(t)`.
	pub input: LaneTables<P>,
	/// Pre-chi state `P^(t) = pi(rho(theta(A^(t))))`.
	pub pre_chi: LaneTables<P>,
}

/// Explicit table trace for all 24 Keccak rounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullTrace<P: PackedField> {
	pub rounds: Vec<RoundTrace<P>>,
	pub final_output: LaneTables<P>,
}

impl<P: PackedField> FullTrace<P> {
	/// Return the explicit output tables for `round`.
	///
	/// For rounds `0..23`, the output is the next round's input. The final round output is stored
	/// separately in `final_output`.
	pub fn round_output(&self, round: usize) -> &LaneTables<P> {
		assert!(round < self.rounds.len(), "precondition: round must be in bounds");
		self.rounds
			.get(round + 1)
			.map(|next_round| &next_round.input)
			.unwrap_or(&self.final_output)
	}
}

/// Word-level batch trace for one Keccak round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundTraceWords {
	pub input: Vec<[u64; 25]>,
	pub pre_chi: Vec<[u64; 25]>,
	pub output: Vec<[u64; 25]>,
}

/// Convert a batch of concrete Keccak states into one multilinear table per lane.
///
/// # Preconditions
///
/// - `states` must be non-empty
/// - `states.len()` must be a power of two
pub fn state_batch_to_lane_tables<P: PackedField>(states: &[[u64; 25]]) -> LaneTables<P> {
	assert!(!states.is_empty(), "precondition: states must be non-empty");
	assert!(states.len().is_power_of_two(), "precondition: states.len() must be a power of two");

	array::from_fn(|lane| {
		let scalars = states
			.iter()
			.flat_map(|state| (0..64).map(move |bit| scalar_bit::<P>(state[lane], bit)))
			.collect::<Vec<_>>();
		FieldBuffer::from_values(&scalars)
	})
}

/// Materialize the full 24-round Keccak trace as concrete word batches.
///
/// # Preconditions
///
/// - `inputs` must be non-empty
/// - `inputs.len()` must be a power of two
pub fn trace_words_from_inputs(inputs: &[[u64; 25]]) -> Vec<RoundTraceWords> {
	assert!(!inputs.is_empty(), "precondition: inputs must be non-empty");
	assert!(inputs.len().is_power_of_two(), "precondition: inputs.len() must be a power of two");
	let _trace_guard = tracing::info_span!(
		"Keccak Trace Words",
		operation = "keccak_trace_words",
		perfetto_category = "operation",
		n_instances = inputs.len()
	)
	.entered();

	let mut current_inputs = inputs.to_vec();

	(0..24)
		.map(|round| {
			let pre_chi = current_inputs
				.iter()
				.map(|input_state| {
					let mut state = *input_state;
					theta_rho_pi_words(&mut state);
					state
				})
				.collect::<Vec<_>>();

			let output = pre_chi
				.iter()
				.map(|pre_chi_state| {
					let mut state = *pre_chi_state;
					chi_iota_words(&mut state, round);
					state
				})
				.collect::<Vec<_>>();

			let round_trace = RoundTraceWords {
				input: current_inputs.clone(),
				pre_chi,
				output: output.clone(),
			};

			current_inputs = output;
			round_trace
		})
		.collect()
}

/// Compact word-level trace for all 24 Keccak rounds.
///
/// Stores each round's input as native `u64` words instead of expanded field elements,
/// reducing memory by ~240x compared to [`FullTrace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactTrace {
	/// Word-level round inputs, one `Vec<[u64; 25]>` per round (24 entries).
	pub round_inputs: Vec<Vec<[u64; 25]>>,
	/// Word-level final output state.
	pub final_output: Vec<[u64; 25]>,
}

impl CompactTrace {
	pub fn n_instances(&self) -> usize {
		self.round_inputs[0].len()
	}

	pub fn log_n_instances(&self) -> usize {
		self.n_instances().trailing_zeros() as usize
	}
}

/// Materialize the full 24-round Keccak trace as compact word-level data.
///
/// This stores only the `u64` words for each round's input, avoiding the 128x blowup
/// of expanding every bit into a 128-bit field element.
///
/// # Preconditions
///
/// - `inputs` must be non-empty
/// - `inputs.len()` must be a power of two
pub fn compact_trace_from_inputs(inputs: &[[u64; 25]]) -> CompactTrace {
	assert!(!inputs.is_empty(), "precondition: inputs must be non-empty");
	assert!(inputs.len().is_power_of_two(), "precondition: inputs.len() must be a power of two");
	let _trace_guard = tracing::info_span!(
		"Keccak Compact Trace",
		operation = "keccak_compact_trace",
		perfetto_category = "operation",
		n_instances = inputs.len()
	)
	.entered();

	let mut current = inputs.to_vec();
	let mut round_inputs = Vec::with_capacity(24);

	for round in 0..24 {
		round_inputs.push(current.clone());
		current = current
			.iter()
			.map(|state| {
				let mut s = *state;
				theta_rho_pi_words(&mut s);
				chi_iota_words(&mut s, round);
				s
			})
			.collect();
	}

	CompactTrace {
		round_inputs,
		final_output: current,
	}
}

/// Materialize the full 24-round Keccak trace as lane multilinear tables.
///
/// # Preconditions
///
/// - `inputs` must be non-empty
/// - `inputs.len()` must be a power of two
pub fn trace_from_inputs<P: PackedField>(inputs: &[[u64; 25]]) -> FullTrace<P> {
	let _trace_guard = tracing::info_span!(
		"Keccak Trace Tables",
		operation = "keccak_trace_tables",
		perfetto_category = "operation",
		n_instances = inputs.len()
	)
	.entered();
	let word_trace = trace_words_from_inputs(inputs);
	let final_output = state_batch_to_lane_tables(
		&word_trace
			.last()
			.expect("trace_words_from_inputs must produce 24 rounds")
			.output,
	);
	let rounds = word_trace
		.into_iter()
		.map(|round_trace| RoundTrace {
			input: state_batch_to_lane_tables(&round_trace.input),
			pre_chi: state_batch_to_lane_tables(&round_trace.pre_chi),
		})
		.collect();

	FullTrace {
		rounds,
		final_output,
	}
}

/// Apply the linear `theta`, `rho`, and `pi` substeps to a Keccak state in place.
pub fn theta_rho_pi_words(state: &mut [u64; 25]) {
	theta_words(state);
	rho_pi_words(state);
}

/// Apply the nonlinear `chi` and affine `iota` substeps to a Keccak state in place.
///
/// # Preconditions
///
/// - `round < 24`
pub fn chi_iota_words(state: &mut [u64; 25], round: usize) {
	assert!(round < 24, "precondition: round index must be < 24");
	chi_words(state);
	iota_words(state, round);
}

fn theta_words(state: &mut [u64; 25]) {
	let c = array::from_fn::<_, 5, _>(|x| {
		state[idx(x, 0)] ^ state[idx(x, 1)] ^ state[idx(x, 2)] ^ state[idx(x, 3)] ^ state[idx(x, 4)]
	});
	let d = array::from_fn::<_, 5, _>(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));

	for y in 0..5 {
		for x in 0..5 {
			state[idx(x, y)] ^= d[x];
		}
	}
}

fn rho_pi_words(state: &mut [u64; 25]) {
	let mut temp = *state;

	for y in 0..5 {
		for x in 0..5 {
			temp[idx(y, (2 * x + 3 * y) % 5)] = state[idx(x, y)].rotate_left(R[idx(x, y)]);
		}
	}

	*state = temp;
}

fn chi_words(state: &mut [u64; 25]) {
	for y in 0..5 {
		let a0 = state[idx(0, y)];
		let a1 = state[idx(1, y)];
		let a2 = state[idx(2, y)];
		let a3 = state[idx(3, y)];
		let a4 = state[idx(4, y)];

		state[idx(0, y)] = a0 ^ ((!a1) & a2);
		state[idx(1, y)] = a1 ^ ((!a2) & a3);
		state[idx(2, y)] = a2 ^ ((!a3) & a4);
		state[idx(3, y)] = a3 ^ ((!a4) & a0);
		state[idx(4, y)] = a4 ^ ((!a0) & a1);
	}
}

fn iota_words(state: &mut [u64; 25], round: usize) {
	state[0] ^= RC[round];
}

#[cfg(test)]
mod tests {
	use binius_field::{
		Field,
		arch::{OptimalB128, OptimalPackedB128},
	};
	use binius_math::{
		multilinear::evaluate::evaluate,
		test_utils::{index_to_hypercube_point, random_scalars},
	};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;

	type F = OptimalB128;
	type P = OptimalPackedB128;

	#[test]
	fn test_state_batch_to_lane_tables_round_trip() {
		let state = std::array::from_fn(|i| (i as u64).wrapping_mul(0x1020_4081_0204_0811));
		let lane_tables = state_batch_to_lane_tables::<P>(&[state]);

		for lane in 0..25 {
			for bit in 0..64 {
				let point = index_to_hypercube_point::<F>(6, bit);
				let expected = if (state[lane] >> bit) & 1 == 1 {
					F::ONE
				} else {
					F::ZERO
				};

				assert_eq!(evaluate(&lane_tables[lane], &point), expected);
			}
		}
	}

	#[test]
	fn test_trace_from_inputs_round_chaining() {
		let mut rng = StdRng::seed_from_u64(0);
		let inputs = vec![
			std::array::from_fn(|_| rng.random::<u64>()),
			std::array::from_fn(|_| rng.random::<u64>()),
		];

		let word_trace = trace_words_from_inputs(&inputs);
		assert_eq!(word_trace.len(), 24);

		for round in 0..23 {
			assert_eq!(word_trace[round].output, word_trace[round + 1].input);
		}
	}

	#[test]
	fn test_compact_trace_matches_word_trace() {
		let mut rng = StdRng::seed_from_u64(2);
		let inputs = vec![
			std::array::from_fn(|_| rng.random::<u64>()),
			std::array::from_fn(|_| rng.random::<u64>()),
		];

		let compact = compact_trace_from_inputs(&inputs);
		let word_trace = trace_words_from_inputs(&inputs);

		assert_eq!(compact.round_inputs.len(), 24);
		for round in 0..24 {
			assert_eq!(compact.round_inputs[round], word_trace[round].input);
		}
		assert_eq!(compact.final_output, word_trace[23].output);
	}

	#[test]
	fn test_trace_from_inputs_tables_have_expected_dimension() {
		let mut rng = StdRng::seed_from_u64(1);
		let inputs = vec![
			std::array::from_fn(|_| rng.random::<u64>()),
			std::array::from_fn(|_| rng.random::<u64>()),
			std::array::from_fn(|_| rng.random::<u64>()),
			std::array::from_fn(|_| rng.random::<u64>()),
		];

		let trace = trace_from_inputs::<P>(&inputs);
		assert_eq!(trace.rounds.len(), 24);
		assert!(trace.rounds.iter().all(|round| {
			round.input.iter().all(|lane| lane.log_len() == 8)
				&& round.pre_chi.iter().all(|lane| lane.log_len() == 8)
		}));
		assert!(trace.final_output.iter().all(|lane| lane.log_len() == 8));

		for round in 0..23 {
			assert_eq!(trace.round_output(round), &trace.rounds[round + 1].input);
		}
		assert_eq!(trace.round_output(23), &trace.final_output);

		let point = random_scalars::<F>(&mut rng, 8);
		let _ = evaluate(&trace.rounds[0].input[0], &point);
	}
}
