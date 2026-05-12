// Copyright 2026 The Binius Developers

//! Native `Z_q` reference implementation used as the proptest oracle in
//! `tests/zq.rs`. Not used inside circuits.

use crate::params::Q;

/// `(a + b) mod Q` over native `u32`s.
#[inline]
pub fn add(a: u32, b: u32) -> u32 {
	debug_assert!(a < Q && b < Q);
	let s = a + b;
	if s >= Q { s - Q } else { s }
}

/// `(a − b) mod Q` over native `u32`s. Result is canonical `0 ≤ r < Q`.
#[inline]
pub fn sub(a: u32, b: u32) -> u32 {
	debug_assert!(a < Q && b < Q);
	let s = a + Q - b; // both < Q, so the addition fits in u32 (max 2Q < 2²⁴).
	if s >= Q { s - Q } else { s }
}

/// `(a · b) mod Q` over native `u32`s, computed in `u64` to avoid overflow.
#[inline]
pub fn mul(a: u32, b: u32) -> u32 {
	debug_assert!(a < Q && b < Q);
	((a as u64 * b as u64) % Q as u64) as u32
}
