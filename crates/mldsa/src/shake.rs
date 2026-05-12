// Copyright 2026 The Binius Developers

//! SHAKE256 wrapper over `binius-circuits::keccak::permutation::Permutation`.
//!
//! ML-DSA needs SHAKE256 in two places that survive the verifier-side
//! precomputation (R2 / R4 are hoisted, so SHAKE128 isn't needed at all):
//!
//! - **R3 — `c = SampleInBall(c̃)`**: SHAKE256(`c̃`) seed for a
//!   Fisher-Yates shuffle that yields a sparse `±1` polynomial.
//! - **R7 — final hash**: `c̃' = SHAKE256(μ ‖ PackW1(w₁'))`, the binding
//!   equality `c̃' == c̃`.
//!
//! Both invocations have a fixed input length and a fixed (small) output
//! length, so this Phase 0 wrapper exposes a single
//! [`shake256_fixed`] entry point. A variable-length API will land in
//! Phase 1 alongside R3 / R7 if the streaming squeeze pattern is needed.

use binius_circuits::keccak::permutation::{Permutation, State};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

/// SHAKE256 rate in 64-bit lanes: `(1600 − 2·256) / 64 = 17`.
pub const SHAKE256_RATE_LANES: usize = 17;
/// SHAKE256 rate in bytes: `17 · 8 = 136`.
pub const SHAKE256_RATE_BYTES: usize = 136;
/// SHAKE256 domain-separation byte (10*1 padding head).
pub const SHAKE256_DSEP: u8 = 0x1f;

/// Compute SHAKE256(input) and squeeze exactly `out_lanes` 64-bit lanes
/// (i.e. `out_lanes · 8` bytes).
///
/// `input` is interpreted as a little-endian byte stream in lane-packed
/// form: `input[i]` holds bytes `8·i .. 8·(i+1)` of the message in
/// little-endian order. Trailing bytes inside the last input lane that
/// are not part of the message must be zero.
///
/// `len_bytes` is the actual message length in bytes; it must satisfy
/// `len_bytes ≤ input.len() · 8`.
///
/// `out_lanes` must satisfy `1 ≤ out_lanes ≤ SHAKE256_RATE_LANES`.
/// Cross-block squeezes (i.e. outputs longer than the rate) are not
/// supported in Phase 0; they will land in Phase 1 if R3 / R7 turn out
/// to need them. The Dilithium2 R7 squeeze is exactly 32 bytes = 4
/// lanes, well under the rate, so this restriction is non-blocking.
///
/// # Panics
///
/// Panics in any of the following cases:
/// - `len_bytes > input.len() · 8`
/// - `len_bytes` would push the padded input past one rate block
///   (`> SHAKE256_RATE_BYTES − 1`); cross-block absorbs are also a
///   Phase 1 follow-up.
/// - `out_lanes == 0` or `out_lanes > SHAKE256_RATE_LANES`.
pub fn shake256_fixed(
	b: &CircuitBuilder,
	input: &[Wire],
	len_bytes: usize,
	out_lanes: usize,
) -> Vec<Wire> {
	assert!(
		len_bytes <= input.len() * 8,
		"shake256_fixed: len_bytes={len_bytes} exceeds input.len()*8={}",
		input.len() * 8,
	);
	assert!(
		len_bytes < SHAKE256_RATE_BYTES,
		"shake256_fixed: Phase 0 only supports single-block absorbs (got len_bytes={len_bytes})",
	);
	assert!(
		(1..=SHAKE256_RATE_LANES).contains(&out_lanes),
		"shake256_fixed: out_lanes={out_lanes} must be in 1..={SHAKE256_RATE_LANES}",
	);

	// Build a single padded rate block.
	//
	// SHAKE256 padding (little-endian byte view):
	//   block[len_bytes]                        = SHAKE256_DSEP (0x1f)
	//   block[SHAKE256_RATE_BYTES - 1]         |= 0x80
	//   all other bytes                         = 0
	//
	// The DSEP byte and the 0x80 high-bit can land in the same byte when
	// `len_bytes == SHAKE256_RATE_BYTES - 1`; in that case the resulting
	// lane is `0x9f` rather than two separate XORs. Our `len_bytes <
	// SHAKE256_RATE_BYTES` precondition keeps the corner case in scope.
	let zero = b.add_constant(Word::ZERO);
	let mut state_lanes: [Wire; 25] = [zero; 25];
	for (lane_idx, lane) in state_lanes.iter_mut().enumerate().take(SHAKE256_RATE_LANES) {
		let dsep_byte_in_this_lane = lane_idx == len_bytes / 8;
		let final_byte_in_this_lane = lane_idx == SHAKE256_RATE_LANES - 1;

		// Start from the input lane (or zero-padding) ...
		let mut acc = if lane_idx < input.len() {
			input[lane_idx]
		} else {
			zero
		};

		// ... XOR in the DSEP byte at the right position ...
		if dsep_byte_in_this_lane {
			let shift = (len_bytes % 8) * 8;
			let dsep_lane = b.add_constant_64((SHAKE256_DSEP as u64) << shift);
			acc = b.bxor(acc, dsep_lane);
		}

		// ... and XOR in 0x80 in the high byte of the final rate lane.
		if final_byte_in_this_lane {
			let final_lane = b.add_constant_64(0x80u64 << 56);
			acc = b.bxor(acc, final_lane);
		}

		*lane = acc;
	}

	// Run one Keccak-f[1600] permutation.
	let initial_state = State { words: state_lanes };
	let perm = Permutation::new(b, initial_state);

	// Squeeze `out_lanes` lanes from the front of the output state.
	let words = perm.output_state.words;
	(0..out_lanes).map(|i| words[i]).collect()
}

// (The integration test in `tests/shake.rs` carries its own `sha3`-crate
// reference oracle; no `shake256_native` helper is exposed from this
// module.)
