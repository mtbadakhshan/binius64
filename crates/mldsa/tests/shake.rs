// Copyright 2026 The Binius Developers

//! Cross-validation of `shake::shake256` against the `sha3` crate.
//!
//! Covers single-block / multi-block absorbs, single-block / multi-block
//! squeezes, the SHAKE256 padding boundary case (`len_bytes ==
//! RATE − 1`), and the worst-case combination R7 will eventually need
//! (832-byte input, 32-byte squeeze).

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::shake::{
	SHAKE256_RATE_BYTES, SHAKE256_RATE_LANES, Shake256Sponge, shake256,
};
use sha3::{
	Shake256,
	digest::{ExtendableOutput, Update, XofReader},
};

/// Packs `bytes` into 8-bytes-per-wire little-endian lanes, zero-padding
/// the trailing partial lane.
fn pack_le_lanes(bytes: &[u8]) -> Vec<u64> {
	let mut out = Vec::with_capacity(bytes.len().div_ceil(8));
	for chunk in bytes.chunks(8) {
		let mut w = [0u8; 8];
		w[..chunk.len()].copy_from_slice(chunk);
		out.push(u64::from_le_bytes(w));
	}
	out
}

/// Native SHAKE256 → little-endian 64-bit lanes.
fn shake256_native_lanes(input: &[u8], out_lanes: usize) -> Vec<u64> {
	let mut hasher = Shake256::default();
	hasher.update(input);
	let mut reader = hasher.finalize_xof();
	let mut out_bytes = vec![0u8; out_lanes * 8];
	reader.read(&mut out_bytes);
	out_bytes
		.chunks_exact(8)
		.map(|c| {
			let mut w = [0u8; 8];
			w.copy_from_slice(c);
			u64::from_le_bytes(w)
		})
		.collect()
}

/// Build a circuit that runs `shake256(input, len_bytes, out_lanes)` and
/// asserts each output lane matches the witness-supplied native value.
fn check_shake256(input: &[u8], out_lanes: usize) {
	let expected_lanes = shake256_native_lanes(input, out_lanes);
	let input_lanes = pack_le_lanes(input);

	let builder = CircuitBuilder::new();
	let input_wires: Vec<Wire> = (0..input_lanes.len())
		.map(|_| builder.add_witness())
		.collect();
	let expected_wires: Vec<Wire> = (0..out_lanes).map(|_| builder.add_witness()).collect();

	let computed = shake256(&builder, &input_wires, input.len(), out_lanes);
	for (i, (lhs, rhs)) in computed.iter().zip(&expected_wires).enumerate() {
		builder.assert_eq(format!("shake256[{i}] match"), *lhs, *rhs);
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in input_wires.iter().zip(&input_lanes) {
		filler[*w] = Word(v);
	}
	for (w, &v) in expected_wires.iter().zip(&expected_lanes) {
		filler[*w] = Word(v);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("shake256 circuit must accept honest witness");
}

// ─── Phase 0 single-block coverage (preserved) ──────────────────────────

#[test]
fn shake256_empty_input() {
	check_shake256(&[], 4);
}

#[test]
fn shake256_short_input_one_lane_out() {
	check_shake256(b"abc", 1);
}

#[test]
fn shake256_short_input_four_lanes_out() {
	// 4 lanes = 32 bytes, the size of `c̃` in Dilithium2 (the actual R7
	// output size).
	check_shake256(b"abc", 4);
}

#[test]
fn shake256_word_aligned_input() {
	check_shake256(b"binius64-mldsa!!", 4);
}

#[test]
fn shake256_one_byte_before_block_boundary() {
	// 135 bytes triggers the corner case where the 0x1f domain separator
	// lands in the same byte as the 0x80 padding terminator. This was a
	// boundary case for the Phase 0 single-block path; same byte logic
	// applies in the multi-block absorb's *last* block.
	let input: Vec<u8> = (0..135u8).collect();
	check_shake256(&input, 4);
}

#[test]
fn shake256_max_lanes_in_first_squeeze_block() {
	check_shake256(b"max-lanes-out", SHAKE256_RATE_LANES);
}

// ─── Multi-block absorb ─────────────────────────────────────────────────

#[test]
fn shake256_exactly_one_rate_block_absorb() {
	// `len_bytes == RATE` triggers the "padding-only block" branch of
	// `absorb`: one full input block is absorbed, then a separate
	// padding block (0x1f at byte 0, 0x80 at byte RATE-1, all zero
	// elsewhere) is absorbed.
	let input: Vec<u8> = (0..SHAKE256_RATE_BYTES).map(|i| (i % 251) as u8).collect();
	check_shake256(&input, 4);
}

#[test]
fn shake256_one_byte_over_rate_absorb() {
	let input: Vec<u8> = (0..SHAKE256_RATE_BYTES + 1).map(|i| (i % 251) as u8).collect();
	check_shake256(&input, 4);
}

#[test]
fn shake256_two_full_blocks_plus_partial() {
	// 300 bytes = 2 full rate blocks (272 B) + 28-byte partial block.
	let input: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
	check_shake256(&input, 4);
}

#[test]
fn shake256_r7_worst_case_input() {
	// R7 input size for Dilithium2: μ (64 B) + PackW1(w₁') (768 B) =
	// 832 B. Six full rate blocks (816 B) + 16-byte partial.
	let input: Vec<u8> = (0u32..832).map(|i| (i.wrapping_mul(91) % 251) as u8).collect();
	check_shake256(&input, 4);
}

// ─── Cross-block squeeze ────────────────────────────────────────────────

#[test]
fn shake256_squeeze_one_more_lane_than_rate() {
	// Forces exactly one extra permutation during squeeze.
	check_shake256(b"abc", SHAKE256_RATE_LANES + 1);
}

#[test]
fn shake256_squeeze_three_blocks_worth() {
	// 50 lanes = 17 + 17 + 16 → two extra permutations during squeeze.
	check_shake256(b"abc", 50);
}

// ─── Combined extreme ───────────────────────────────────────────────────

#[test]
fn shake256_long_input_long_output() {
	let input: Vec<u8> = (0u32..1000).map(|i| (i.wrapping_mul(31) % 251) as u8).collect();
	check_shake256(&input, 100);
}

// ─── Streaming squeeze API directly ─────────────────────────────────────

/// Build a circuit that absorbs `input` once and squeezes the byte
/// stream in `chunks` chunks (each chunk size is in 64-bit lanes), then
/// asserts the concatenation matches the native single-shot reference.
/// Used to verify that the [`Shake256Sponge`] cursor composes correctly
/// across squeeze calls — the exact pattern Phase 1 R3 (Fisher-Yates
/// rejection) will rely on.
fn check_streaming_squeeze(input: &[u8], chunks: &[usize]) {
	let total_out_lanes: usize = chunks.iter().sum();
	let expected_lanes = shake256_native_lanes(input, total_out_lanes);
	let input_lanes = pack_le_lanes(input);

	let builder = CircuitBuilder::new();
	let input_wires: Vec<Wire> = (0..input_lanes.len())
		.map(|_| builder.add_witness())
		.collect();
	let expected_wires: Vec<Wire> = (0..total_out_lanes).map(|_| builder.add_witness()).collect();

	let mut sponge = Shake256Sponge::absorb(&builder, &input_wires, input.len());
	let mut computed: Vec<Wire> = Vec::with_capacity(total_out_lanes);
	for &n in chunks {
		computed.extend(sponge.squeeze(&builder, n));
	}

	for (i, (lhs, rhs)) in computed.iter().zip(&expected_wires).enumerate() {
		builder.assert_eq(format!("squeeze[{i}]"), *lhs, *rhs);
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in input_wires.iter().zip(&input_lanes) {
		filler[*w] = Word(v);
	}
	for (w, &v) in expected_wires.iter().zip(&expected_lanes) {
		filler[*w] = Word(v);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("streaming squeeze chunks must match one long squeeze");
}

#[test]
fn streaming_squeeze_two_chunks_within_one_block() {
	// 7 + 5 = 12 < RATE_LANES, no internal permutation needed.
	check_streaming_squeeze(b"streaming", &[7, 5]);
}

#[test]
fn streaming_squeeze_chunks_straddle_block_boundary() {
	// 7 + 23 = 30 = (17 - 7) + 17 + (rest). The second chunk straddles
	// the rate-block boundary and forces exactly one mid-stream
	// permutation. This is the case the Phase 0 standalone `squeeze`
	// API got wrong; the `Shake256Sponge` cursor fixes it.
	check_streaming_squeeze(b"streaming", &[7, 23]);
}

#[test]
fn streaming_squeeze_one_lane_at_a_time() {
	// 20 successive 1-lane reads — exercises the cursor through a
	// boundary three times (after lane 17, 34, ...). Mirrors R3's
	// expected access pattern most closely.
	check_streaming_squeeze(b"fisher-yates", &[1; 20]);
}
