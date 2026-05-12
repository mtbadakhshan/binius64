// Copyright 2026 The Binius Developers

//! SHAKE256 wrapper over `binius-circuits::keccak::permutation::Permutation`.
//!
//! ML-DSA needs SHAKE256 in two places that survive the verifier-side
//! precomputation (R2 / R4 are hoisted, so SHAKE128 isn't needed at all):
//!
//! - **R3 — `c = SampleInBall(c̃)`**: SHAKE256(`c̃`) seed for a
//!   Fisher-Yates shuffle that yields a sparse `±1` polynomial.
//!   Single-block absorb (32 bytes), variable-length squeeze.
//! - **R7 — final hash**: `c̃' = SHAKE256(μ ‖ PackW1(w₁'))`, the binding
//!   equality `c̃' == c̃`. Multi-block absorb (832 bytes for Mode 2),
//!   single-block squeeze (32 bytes).
//!
//! Both message length and output length are circuit-construction-time
//! constants (the signature has a fixed shape), so this module unrolls
//! the entire sponge as a constant number of Keccak-f[1600] permutations.
//!
//! Two entry points:
//!
//! - [`shake256`] — one-shot `(input, out_lanes)` → `Vec<Wire>`. Use this
//!   for fixed-output applications like R7's final hash.
//! - [`Shake256Sponge`] — explicit `absorb` + multiple [`Shake256Sponge::squeeze`]
//!   calls that share the same underlying sponge state. Required by R3
//!   (Fisher-Yates rejection sampling) where many short reads come out
//!   of the same absorbed seed.

use binius_circuits::keccak::permutation::Permutation;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

/// SHAKE256 rate in 64-bit lanes: `(1600 − 2·256) / 64 = 17`.
pub const SHAKE256_RATE_LANES: usize = 17;
/// SHAKE256 rate in bytes: `17 · 8 = 136`.
pub const SHAKE256_RATE_BYTES: usize = 136;
/// SHAKE256 domain-separation byte (10*1 padding head).
pub const SHAKE256_DSEP: u8 = 0x1f;

/// Number of 64-bit lanes in the Keccak-f[1600] state (`5 · 5`).
pub const KECCAK_STATE_LANES: usize = 25;

// ─── One-shot entry point ───────────────────────────────────────────────

/// Compute `SHAKE256(input)` and squeeze exactly `out_lanes` 64-bit
/// little-endian lanes (`out_lanes · 8` bytes).
///
/// `input` is interpreted as a little-endian byte stream in lane-packed
/// form: `input[i]` holds bytes `8·i .. 8·(i+1)` of the message in
/// little-endian order. Trailing bytes inside the last input lane that
/// are not part of the message **must** be zero (the wrapper does not
/// mask the partial lane against that contract — this matches the
/// natural witness shape produced by [`crate::sigdecode::signature_to_lanes`]
/// and similar).
///
/// `len_bytes` is the actual message length in bytes; it must satisfy
/// `len_bytes ≤ input.len() · 8`. Both `len_bytes` and `out_lanes` are
/// circuit-construction-time constants — the resulting circuit unrolls
/// `ceil(len_bytes / RATE) + 1 + ceil(out_lanes / RATE_LANES) − 1`
/// Keccak-f[1600] permutations.
///
/// # Panics
///
/// Panics if `len_bytes > input.len() · 8` or `out_lanes == 0`.
pub fn shake256(
	b: &CircuitBuilder,
	input: &[Wire],
	len_bytes: usize,
	out_lanes: usize,
) -> Vec<Wire> {
	let mut sponge = Shake256Sponge::absorb(b, input, len_bytes);
	sponge.squeeze(b, out_lanes)
}

// ─── Streaming sponge ───────────────────────────────────────────────────

/// In-circuit SHAKE256 sponge in its post-absorb state. Carries the
/// 25-lane Keccak state plus the offset (in 64-bit lanes) into the
/// current rate block, so multiple [`Self::squeeze`] calls compose into
/// the same byte stream a single long squeeze would produce.
///
/// All operations are circuit-construction-time bounded: the offset
/// advances at compile time and any required Keccak-f[1600]
/// permutations are emitted as the squeeze sees them.
#[derive(Clone)]
pub struct Shake256Sponge {
	state: [Wire; KECCAK_STATE_LANES],
	/// Number of rate-lanes already consumed from the current state.
	/// Always satisfies `0 ≤ pos ≤ SHAKE256_RATE_LANES`. When `pos ==
	/// SHAKE256_RATE_LANES`, the next squeeze first permutes and resets
	/// to 0.
	pos: usize,
}

impl Shake256Sponge {
	/// Absorb `len_bytes` of `input` into a fresh SHAKE256 sponge.
	///
	/// Internally absorbs `n_full = len_bytes / RATE` full rate blocks
	/// without padding, then absorbs one final rate block carrying the
	/// remaining `len_bytes % RATE` input bytes plus the SHAKE256
	/// padding (`0x1f` at byte `len_bytes mod RATE`, `0x80` at byte
	/// `RATE − 1`, possibly XOR'd into the same byte when
	/// `len_bytes % RATE == RATE − 1`). Always emits exactly
	/// `n_full + 1` permutations.
	pub fn absorb(b: &CircuitBuilder, input: &[Wire], len_bytes: usize) -> Self {
		assert!(
			len_bytes <= input.len() * 8,
			"absorb: len_bytes={len_bytes} exceeds input.len()*8={}",
			input.len() * 8,
		);

		let zero = b.add_constant(Word::ZERO);
		let mut state: [Wire; KECCAK_STATE_LANES] = [zero; KECCAK_STATE_LANES];

		let n_full_blocks = len_bytes / SHAKE256_RATE_BYTES;
		let last_block_len = len_bytes % SHAKE256_RATE_BYTES;

		// Absorb each full rate block: XOR the 17 input lanes into the
		// first 17 state lanes, then permute.
		for blk in 0..n_full_blocks {
			let global_lane_offset = blk * SHAKE256_RATE_LANES;
			for lane in 0..SHAKE256_RATE_LANES {
				state[lane] = b.bxor(state[lane], input[global_lane_offset + lane]);
			}
			Permutation::keccak_f1600(b, &mut state);
		}

		// Build the padded last block in a 17-lane scratch array, then
		// XOR it into the state and permute.
		let mut last_block: [Wire; SHAKE256_RATE_LANES] = [zero; SHAKE256_RATE_LANES];
		let global_lane_offset = n_full_blocks * SHAKE256_RATE_LANES;

		let n_full_input_lanes_in_last = last_block_len / 8;
		last_block[..n_full_input_lanes_in_last].copy_from_slice(
			&input[global_lane_offset..global_lane_offset + n_full_input_lanes_in_last],
		);

		let partial_lane_idx = n_full_input_lanes_in_last;
		let partial_byte_idx = last_block_len % 8;

		// DSEP byte (0x1f) goes at byte position `last_block_len` within
		// the rate block. Two cases by `partial_byte_idx`:
		//   - 0: the DSEP byte is byte 0 of a fresh (currently-zero)
		//        lane, so we just write the constant.
		//   - >0: the DSEP byte sits in the high portion of a lane that
		//         already carries `partial_byte_idx` low input bytes;
		//         mask out the (caller-supplied) high bytes and OR the
		//         DSEP in.
		if partial_byte_idx == 0 {
			last_block[partial_lane_idx] = b.add_constant_64(SHAKE256_DSEP as u64);
		} else {
			let partial_input_lane = input[global_lane_offset + partial_lane_idx];
			// Keep the low `partial_byte_idx · 8` bits of the input lane.
			let mask = b.add_constant_64((1u64 << (partial_byte_idx * 8)) - 1);
			let masked_input = b.band(partial_input_lane, mask);
			let dsep_lane =
				b.add_constant_64((SHAKE256_DSEP as u64) << (partial_byte_idx * 8));
			last_block[partial_lane_idx] = b.bxor(masked_input, dsep_lane);
		}

		// 0x80 padding terminator goes at the last byte of the rate
		// block — the high byte of lane 16. When `last_block_len ==
		// RATE_BYTES − 1` it XORs into the same byte that carries the
		// DSEP, giving the expected `0x9f` (= `0x1f ^ 0x80`).
		let final_lane = SHAKE256_RATE_LANES - 1;
		let pad_high = b.add_constant_64(0x80u64 << 56);
		last_block[final_lane] = b.bxor(last_block[final_lane], pad_high);

		for lane in 0..SHAKE256_RATE_LANES {
			state[lane] = b.bxor(state[lane], last_block[lane]);
		}
		Permutation::keccak_f1600(b, &mut state);

		Self { state, pos: 0 }
	}

	/// Squeeze the next `n_lanes` 64-bit lanes from the sponge,
	/// permuting the state as needed when an internal rate block is
	/// exhausted.
	///
	/// Multiple calls on the same sponge return the byte stream that a
	/// single `squeeze(total)` call would produce — i.e. they share the
	/// same `(state, pos)` cursor. R3's Fisher-Yates rejection loop
	/// will thread one sponge through many short `squeeze` calls.
	///
	/// # Panics
	///
	/// Panics if `n_lanes == 0`.
	pub fn squeeze(&mut self, b: &CircuitBuilder, n_lanes: usize) -> Vec<Wire> {
		assert!(n_lanes > 0, "squeeze: n_lanes must be positive");

		let mut out = Vec::with_capacity(n_lanes);
		let mut remaining = n_lanes;
		while remaining > 0 {
			if self.pos == SHAKE256_RATE_LANES {
				Permutation::keccak_f1600(b, &mut self.state);
				self.pos = 0;
			}
			let available = SHAKE256_RATE_LANES - self.pos;
			let take = remaining.min(available);
			for lane in 0..take {
				out.push(self.state[self.pos + lane]);
			}
			self.pos += take;
			remaining -= take;
		}
		out
	}
}
