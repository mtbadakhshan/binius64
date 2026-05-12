// Copyright 2026 The Binius Developers

//! `Z_q` (Q = 8 380 417, 23-bit prime) field-arithmetic gadgets for ML-DSA.
//!
//! All public values fit in a single 64-bit `Wire`: `0 ≤ x < Q < 2²³`, so
//! `(a, b) ∈ Z_q × Z_q` admits `a + b < 2²⁴` (single-limb add) and
//! `a · b < 2⁴⁶` (single-limb multiply via [`CircuitBuilder::imul`]'s low
//! word). This avoids the bignum machinery used by `binius-circuits` for
//! the secp256k1 / generic primes.
//!
//! ## Gadgets
//!
//! - [`add`] — `(a + b) mod Q`. ~3 AND constraints (icmp + select +
//!   conditional sub).
//! - [`sub`] — `(a + Q − b) mod Q`. Same cost as [`add`].
//! - [`mul`] — `(a · b) mod Q`, with the quotient/remainder hinted and
//!   then constrained.
//! - [`from_u64_witness`] — allocate a witness wire and constrain
//!   `0 ≤ value < Q`.
//!
//! All four come with proptest unit tests in `tests/zq.rs` validating
//! against the native `u64` reference implementation in [`reference`].

mod reference;

pub use reference::{add as add_native, mul as mul_native, sub as sub_native};

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

use crate::params::Q;

// ─── In-circuit gadgets ─────────────────────────────────────────────────

/// In-circuit `(a + b) mod Q`. Both inputs must already be in canonical
/// form (`0 ≤ a, b < Q`); use [`from_u64_witness`] to enforce that on
/// fresh witness wires.
pub fn add(b: &CircuitBuilder, a: Wire, b_w: Wire) -> Wire {
	let q = b.add_constant_64(Q as u64);
	// a + b: two 23-bit values give a 24-bit sum; the carry-out wire from
	// `iadd` is unused (always zero given the operand bound).
	let (sum, _carry) = b.iadd(a, b_w);
	// Conditional subtract: if Q ≤ sum then sum -= Q.
	conditional_sub_q(b, sum, q)
}

/// In-circuit `(a − b) mod Q` computed as `(a + Q − b) mod Q`.
pub fn sub(b: &CircuitBuilder, a: Wire, b_w: Wire) -> Wire {
	let q = b.add_constant_64(Q as u64);
	let zero = b.add_constant(Word::ZERO);
	// (Q - b): both are < 2²³, no borrow-out (`a + Q - b` stays positive
	// because the caller's contract bounds `a, b < Q`).
	let (q_minus_b, _bout) = b.isub_bin_bout(q, b_w, zero);
	let (sum, _carry) = b.iadd(a, q_minus_b);
	conditional_sub_q(b, sum, q)
}

/// In-circuit `(a · b) mod Q` using a hinted (quotient, remainder) witness
/// constrained by `a · b == quotient · Q + remainder` and
/// `0 ≤ remainder < Q`.
///
/// The quotient is bounded by `(Q − 1)² / Q < 2²³`, so a single 64-bit
/// limb is sufficient on both sides of the constraint.
pub fn mul(b: &CircuitBuilder, a: Wire, b_w: Wire) -> Wire {
	let q = b.add_constant_64(Q as u64);
	let zero = b.add_constant(Word::ZERO);

	// product = a * b (low 64 bits; high 64 bits must be zero given
	// operand bounds, which we constrain below).
	let (prod_hi, prod_lo) = b.imul(a, b_w);
	b.assert_zero("zq.mul: product fits in 64 bits", prod_hi);

	// Hint (quotient, remainder) with prod = quotient * Q + remainder.
	let dividend_limbs = [prod_lo, zero];
	let divisor_limbs = [q, zero];
	let (quotient_limbs, remainder_limbs) =
		b.biguint_divide_hint(&dividend_limbs, &divisor_limbs);
	let quotient = quotient_limbs[0];
	let remainder = remainder_limbs[0];
	// Both higher limbs must be zero given operand bounds.
	b.assert_zero("zq.mul: quotient fits in 64 bits", quotient_limbs[1]);
	b.assert_zero("zq.mul: remainder fits in 64 bits", remainder_limbs[1]);

	// Constraint: quotient * Q + remainder == product.
	let (qq_hi, qq_lo) = b.imul(quotient, q);
	b.assert_zero("zq.mul: quotient*Q fits in 64 bits", qq_hi);
	let (recovered, carry) = b.iadd(qq_lo, remainder);
	// `iadd` emits a per-bit carry word; the MSB is the actual 65-th bit
	// overflow, which must be zero given operand bounds.
	b.assert_false("zq.mul: quotient*Q + remainder fits in 64 bits", carry);
	b.assert_eq("zq.mul: quotient*Q + remainder == product", recovered, prod_lo);

	// Range-check the remainder: 0 ≤ remainder < Q.
	let lt = b.icmp_ult(remainder, q);
	b.assert_true("zq.mul: remainder < Q", lt);

	remainder
}

/// Allocate a fresh witness wire in `Z_q` and constrain it canonical
/// (`0 ≤ value < Q`). Use this on every wire that holds a `Z_q` value
/// supplied as witness from outside the circuit.
pub fn from_u64_witness(b: &CircuitBuilder) -> Wire {
	let w = b.add_witness();
	let q = b.add_constant_64(Q as u64);
	let lt = b.icmp_ult(w, q);
	b.assert_true("zq.from_u64_witness: value < Q", lt);
	w
}

// ─── Internal helpers ───────────────────────────────────────────────────

/// `(value, q) ↦ value − Q · ⟦Q ≤ value⟧` — a single conditional subtract
/// used by [`add`] and [`sub`].
fn conditional_sub_q(b: &CircuitBuilder, value: Wire, q: Wire) -> Wire {
	let zero = b.add_constant(Word::ZERO);
	let geq = b.icmp_ule(q, value); // MSB-bool: Q ≤ value
	let (value_minus_q, _bout) = b.isub_bin_bout(value, q, zero);
	b.select(geq, value_minus_q, value)
}
