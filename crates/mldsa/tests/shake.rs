// Copyright 2026 The Binius Developers

//! Cross-validation of `shake::shake256_fixed` against the `sha3` crate.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
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

/// Native SHAKE256, returned as `out_lanes` little-endian 64-bit lanes.
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

fn check_shake256_fixed(input: &[u8], out_lanes: usize) {
	let expected_lanes = shake256_native_lanes(input, out_lanes);
	let input_lanes = pack_le_lanes(input);

	let builder = CircuitBuilder::new();
	let input_wires: Vec<Wire> = (0..input_lanes.len())
		.map(|_| builder.add_witness())
		.collect();
	let expected_wires: Vec<Wire> = (0..out_lanes).map(|_| builder.add_witness()).collect();

	let computed = binius_mldsa::shake::shake256_fixed(&builder, &input_wires, input.len(), out_lanes);
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
		.expect("shake256_fixed circuit must accept honest witness");
}

#[test]
fn shake256_empty_input() {
	check_shake256_fixed(&[], 4);
}

#[test]
fn shake256_short_input_one_lane_out() {
	check_shake256_fixed(b"abc", 1);
}

#[test]
fn shake256_short_input_four_lanes_out() {
	// 4 lanes = 32 bytes, the size of `c̃` in Dilithium2 (the actual R7
	// output size).
	check_shake256_fixed(b"abc", 4);
}

#[test]
fn shake256_word_aligned_input() {
	let input: &[u8; 16] = b"binius64-mldsa!!";
	check_shake256_fixed(input, 4);
}

#[test]
fn shake256_one_byte_before_block_boundary() {
	// 135 bytes triggers the corner case where the 0x1f domain separator
	// lands in the same byte as the 0x80 padding terminator. Phase 0
	// allows len_bytes < SHAKE256_RATE_BYTES (= 136), so 135 is the tightest
	// we can exercise here.
	let input: Vec<u8> = (0..135u8).collect();
	check_shake256_fixed(&input, 4);
}

#[test]
fn shake256_max_lanes_out() {
	// Largest single-block squeeze: SHAKE256_RATE_LANES = 17.
	check_shake256_fixed(b"max-lanes-out", binius_mldsa::shake::SHAKE256_RATE_LANES);
}

#[test]
#[should_panic(expected = "Phase 0 only supports single-block absorbs")]
fn shake256_rejects_full_rate_block_input() {
	// Calling shake256_fixed with len_bytes == SHAKE256_RATE_BYTES would
	// require a second padding block, which Phase 0 does not implement.
	// The wrapper must panic with a clear message.
	let builder = CircuitBuilder::new();
	let input_wires: Vec<Wire> = (0..17).map(|_| builder.add_witness()).collect();
	let _ = binius_mldsa::shake::shake256_fixed(
		&builder,
		&input_wires,
		binius_mldsa::shake::SHAKE256_RATE_BYTES,
		1,
	);
}

#[test]
#[should_panic(expected = "out_lanes")]
fn shake256_rejects_zero_out_lanes() {
	let builder = CircuitBuilder::new();
	let input_wires: Vec<Wire> = vec![builder.add_witness()];
	let _ = binius_mldsa::shake::shake256_fixed(&builder, &input_wires, 1, 0);
}
