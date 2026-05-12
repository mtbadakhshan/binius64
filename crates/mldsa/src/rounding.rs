// Copyright 2026 The Binius Developers

//! `Decompose` and `UseHint` (FIPS 204 §7.4 / §7.5) for Dilithium2.
//!
//! These are the integer / rounding primitives at the heart of the R6
//! sub-relation of the verifier:
//!
//! - [`decompose`] splits an `r ∈ Z_q` into `(r1, r0)` such that
//!   `r ≡ r1 · 2γ₂ + r0 (mod Q)` with `r1 ∈ [0, 43]` and the centered
//!   `r0_signed = r0_p − γ₂ ∈ [−γ₂, γ₂]`. The wrapper returns the
//!   non-negative shifted form `r0_p ∈ [0, 2γ₂]` so the downstream
//!   gadgets stay in unsigned arithmetic.
//! - [`use_hint`] applies a single hint bit (`h ∈ {0, 1}`) to
//!   reconstruct the high bits `w₁'` of `r` according to FIPS 204:
//!   `if h == 0 then r1 else if r0 > 0 then r1+1 mod 44 else r1−1 mod 44`.
//!
//! ## Boundary uniqueness — soundness argument
//!
//! `decompose` is *not* unique: at the tie points `r = (2k+1)γ₂` for
//! `k ∈ [0, 42]`, both `(k, +γ₂)` and `(k+1, −γ₂)` satisfy the algebraic
//! relation. The C reference picks the first; our in-circuit constraints
//! accept either. Soundness still holds because the two choices produce
//! *different* `w₁' = use_hint(r, h)` outputs, and the R7 final-hash
//! check at the end of the verifier circuit detects any deviation from
//! the signer's canonical w₁'. See the corresponding section of
//! `docs/aggregate-mldsa-design.md`.
//!
//! Completeness: the [`DecomposeMode2Hint`] handler emits the C-canonical
//! form, so an honest prover never witnesses the non-canonical
//! representation in the first place.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, hints::Hint};

use crate::{params::MODE2, zq};

/// `2γ₂ = (Q − 1) / 44` for Dilithium2.
const TWO_GAMMA2: u32 = 2 * MODE2.gamma2;
/// `(Q − 1) / 2γ₂ = 44` — the high-bit alphabet size.
const ALPHA: u32 = 44;
/// Largest valid `r1` value (`ALPHA − 1 = 43`).
const R1_MAX: u32 = ALPHA - 1;

// ─── In-circuit gadgets ─────────────────────────────────────────────────

/// `Decompose(r)` for Dilithium2.
///
/// Input: `r ∈ [0, Q − 1]` as a single `Wire`. The caller is responsible
/// for the canonical-form contract (use [`crate::zq::from_u64_witness`]
/// on fresh witness wires).
///
/// Output: `(r1, r0_p)` where:
///
/// - `r1 ∈ [0, 43]` (the high bits, 6-bit alphabet).
/// - `r0_p ∈ [0, 2γ₂]` is the *shifted* low residue: the mathematical
///   centered low residue is `r0_signed = r0_p − γ₂ ∈ [−γ₂, γ₂]`. Working
///   in the shifted form keeps every wire in unsigned arithmetic, which
///   composes cleanly with the rest of the `binius-frontend` API.
///
/// Constraints (≈ 7 cells per call):
///   1. Witness `(r1, r0_p)` via a `Hint` that runs `decompose_native`.
///   2. Range check `r1 < 44`.
///   3. Range check `r0_p ≤ 2γ₂` (i.e. `r0_p < 2γ₂ + 1`).
///   4. Algebraic relation `(r + γ₂) mod Q == r1 · 2γ₂ + r0_p` (the LHS
///      is computed via [`zq::add`]; the RHS is plain integer arithmetic
///      since `r1 · 2γ₂ + r0_p ≤ 44 · 2γ₂ < 2²³ < Q`).
pub fn decompose(b: &CircuitBuilder, r: Wire) -> (Wire, Wire) {
	let gamma2_const = b.add_constant_64(MODE2.gamma2 as u64);
	let two_gamma2_const = b.add_constant_64(TWO_GAMMA2 as u64);

	// `r' = (r + γ₂) mod Q`. After this rewrite the relation becomes
	// `r' = r1 · 2γ₂ + r0_p` in plain (non-mod-Q) integer arithmetic
	// because `r1 · 2γ₂ + r0_p ∈ [0, 44 · 2γ₂] = [0, Q − 1]`.
	let r_prime = zq::add(b, r, gamma2_const);

	// Hint provides the canonical `(r1, r0_p)` derived from `r`. A
	// non-canonical malicious prover can witness a different valid
	// decomposition, but downstream `use_hint` will then produce a
	// different `w1'` and R7's hash check will reject — see module
	// docs for the soundness sketch.
	let outputs = b.call_hint(DecomposeMode2Hint, &[], &[r]);
	let r1 = outputs[0];
	let r0_p = outputs[1];

	// Range checks.
	let r1_bound = b.add_constant_64(ALPHA as u64);
	let r1_ok = b.icmp_ult(r1, r1_bound);
	b.assert_true("decompose: r1 < 44", r1_ok);

	let r0_p_bound = b.add_constant_64(TWO_GAMMA2 as u64 + 1);
	let r0_p_ok = b.icmp_ult(r0_p, r0_p_bound);
	b.assert_true("decompose: r0_p <= 2*gamma2", r0_p_ok);

	// Relation: `r' = r1 · 2γ₂ + r0_p`.
	let (r1_two_g_hi, r1_two_g_lo) = b.imul(r1, two_gamma2_const);
	b.assert_zero("decompose: r1*2*gamma2 fits in 64 bits", r1_two_g_hi);
	let (sum, carry) = b.iadd(r1_two_g_lo, r0_p);
	b.assert_false("decompose: r1*2*gamma2 + r0_p has no overflow", carry);
	b.assert_eq("decompose: r' == r1 * 2*gamma2 + r0_p", sum, r_prime);

	(r1, r0_p)
}

/// `UseHint(r, h)` for Dilithium2.
///
/// Returns `w₁' ∈ [0, 43]` per FIPS 204:
///   - `h == 0` → `r1`
///   - `h == 1` and `r0 > 0` → `r1 + 1 mod 44` (so `r1 == 43` wraps to 0)
///   - `h == 1` and `r0 ≤ 0` → `r1 − 1 mod 44` (so `r1 ==  0` wraps to 43)
///
/// `hint` must be a 0/1 wire — enforced by an `assert_true` on
/// `icmp_ult(hint, 2)`.
pub fn use_hint(b: &CircuitBuilder, r: Wire, hint: Wire) -> Wire {
	// Validate hint ∈ {0, 1}.
	let two = b.add_constant_64(2);
	let hint_ok = b.icmp_ult(hint, two);
	b.assert_true("use_hint: hint < 2", hint_ok);

	let (r1, r0_p) = decompose(b, r);
	let zero = b.add_constant(Word::ZERO);
	let one = b.add_constant_64(1);
	let gamma2_const = b.add_constant_64(MODE2.gamma2 as u64);
	let r1_max_const = b.add_constant_64(R1_MAX as u64); // 43

	// `r0_signed > 0` ⇔ `r0_p > γ₂`.
	let r0_pos = b.icmp_ult(gamma2_const, r0_p);
	// `hint == 1` ⇔ `0 < hint` (range-checked above to be ≤ 1).
	let hint_set = b.icmp_ult(zero, hint);

	// `r1 + 1 mod 44`: if `r1 < 43` then `r1 + 1` else `0`.
	let (r1_plus_one, _carry) = b.iadd(r1, one);
	let r1_lt_43 = b.icmp_ult(r1, r1_max_const);
	let r1_plus_one_wrap = b.select(r1_lt_43, r1_plus_one, zero);

	// `r1 − 1 mod 44`: if `r1 > 0` then `r1 − 1` else `43`.
	let (r1_minus_one, _bout) = b.isub_bin_bout(r1, one, zero);
	let r1_gt_zero = b.icmp_ult(zero, r1);
	let r1_minus_one_wrap = b.select(r1_gt_zero, r1_minus_one, r1_max_const);

	let case_when_hint = b.select(r0_pos, r1_plus_one_wrap, r1_minus_one_wrap);
	b.select(hint_set, case_when_hint, r1)
}

// ─── Native (out-of-circuit) reference ──────────────────────────────────

/// Native `decompose` for Dilithium2 — exact port of
/// `dilithium/ref/rounding.c::decompose` for `GAMMA2 == (Q − 1) / 88`.
///
/// Returns `(a1, a0_signed)` with `a1 ∈ [0, 43]` and `a0_signed ∈
/// [−γ₂, γ₂]` such that `r ≡ a1 · 2γ₂ + a0_signed (mod Q)`.
pub fn decompose_native(r: u32) -> (u32, i32) {
	debug_assert!(r < crate::params::Q, "decompose_native: r out of range");
	let r_signed = r as i32;
	let gamma2 = MODE2.gamma2 as i32;
	let q = crate::params::Q as i32;

	let mut a1 = (r_signed + 127) >> 7;
	a1 = (a1 * 11275 + (1 << 23)) >> 24;
	a1 ^= ((43 - a1) >> 31) & a1;

	let mut a0 = r_signed - a1 * 2 * gamma2;
	a0 -= (((q - 1) / 2 - a0) >> 31) & q;
	(a1 as u32, a0)
}

/// Native `use_hint` for Dilithium2 — exact port of
/// `dilithium/ref/rounding.c::use_hint` for `GAMMA2 == (Q − 1) / 88`.
pub fn use_hint_native(r: u32, hint: u32) -> u32 {
	debug_assert!(hint < 2, "use_hint_native: hint must be 0 or 1");
	let (a1, a0) = decompose_native(r);
	if hint == 0 {
		return a1;
	}
	if a0 > 0 {
		if a1 == R1_MAX { 0 } else { a1 + 1 }
	} else if a1 == 0 {
		R1_MAX
	} else {
		a1 - 1
	}
}

// ─── Hint handler (provides canonical form to the prover) ───────────────

/// Hint that produces the canonical `(r1, r0_p)` decomposition of `r`
/// per [`decompose_native`], emitted to the in-circuit witness so an
/// honest prover always satisfies [`decompose`]'s constraints.
pub struct DecomposeMode2Hint;

impl Hint for DecomposeMode2Hint {
	const NAME: &'static str = "binius.mldsa.decompose.mode2";

	fn shape(&self, _: &[usize]) -> (usize, usize) {
		(1, 2)
	}

	fn execute(&self, _: &[usize], inputs: &[Word], outputs: &mut [Word]) {
		let r = inputs[0].as_u64() as u32;
		let (r1, r0_signed) = decompose_native(r);
		// `r0_signed + γ₂` is in `[0, 2γ₂]`, fits cleanly in `u64`.
		let r0_p = (r0_signed + MODE2.gamma2 as i32) as u32;
		outputs[0] = Word::from_u64(r1 as u64);
		outputs[1] = Word::from_u64(r0_p as u64);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::params::Q;

	/// Verify the algebraic relation + canonical-form bounds across all
	/// `r ∈ [0, Q − 1]`. Slow (~Q iterations), so gated behind
	/// `--ignored` to keep the default test run fast.
	#[test]
	#[ignore = "exhaustive: ~8M iterations"]
	fn decompose_native_exhaustive_relation_holds() {
		let two_gamma2 = TWO_GAMMA2 as i32;
		let gamma2 = MODE2.gamma2 as i32;
		let q = Q as i32;
		for r in 0..Q {
			let (a1, a0) = decompose_native(r);
			assert!(a1 < ALPHA, "a1={a1} out of range for r={r}");
			assert!(a0 >= -gamma2 && a0 <= gamma2, "a0={a0} out of range for r={r}");
			let recomposed = a1 as i32 * two_gamma2 + a0;
			let recomposed_mod = ((recomposed % q) + q) % q;
			assert_eq!(recomposed_mod, r as i32, "decomposition mismatch for r={r}");
		}
	}

	#[test]
	fn decompose_native_boundary_values() {
		// Boundary cases that exercise the wrap logic in the C reference.
		let cases = [
			(0u32, 0u32, 0i32),
			(MODE2.gamma2, 0, MODE2.gamma2 as i32), // r = γ₂ → (0, γ₂) per C
			(MODE2.gamma2 - 1, 0, MODE2.gamma2 as i32 - 1),
			(MODE2.gamma2 + 1, 1, -(MODE2.gamma2 as i32 - 1)),
			(2 * MODE2.gamma2, 1, 0),
			(Q - MODE2.gamma2 - 1, R1_MAX, MODE2.gamma2 as i32), // r = 87γ₂ → (43, γ₂)
			(Q - MODE2.gamma2, 0, -(MODE2.gamma2 as i32)),       // wrap to a1 = 0
			(Q - 1, 0, -1),
		];
		for (r, expected_a1, expected_a0) in cases {
			let (a1, a0) = decompose_native(r);
			assert_eq!(a1, expected_a1, "a1 wrong for r={r}");
			assert_eq!(a0, expected_a0, "a0 wrong for r={r}");
		}
	}

	#[test]
	fn use_hint_native_boundary_values() {
		// Trivial hint == 0 path: must equal a1.
		assert_eq!(use_hint_native(0, 0), 0);
		assert_eq!(use_hint_native(MODE2.gamma2, 0), 0);
		assert_eq!(use_hint_native(Q - 1, 0), 0);

		// hint == 1 with a0 > 0: r1 + 1 mod 44.
		// At r = γ₂ the canonical decomposition is (0, +γ₂), so
		// use_hint(γ₂, 1) = 0 + 1 = 1.
		assert_eq!(use_hint_native(MODE2.gamma2, 1), 1);
		// At r = 87γ₂ the canonical is (43, +γ₂); a0 > 0 ⇒ wrap to 0.
		assert_eq!(use_hint_native(Q - MODE2.gamma2 - 1, 1), 0);

		// hint == 1 with a0 ≤ 0: r1 − 1 mod 44.
		// At r = γ₂ + 1 the canonical is (1, −(γ₂−1)); a0 < 0 ⇒ 1 − 1 = 0.
		assert_eq!(use_hint_native(MODE2.gamma2 + 1, 1), 0);
		// At r = Q − 1 the canonical is (0, −1); a0 < 0 ⇒ wrap to 43.
		assert_eq!(use_hint_native(Q - 1, 1), R1_MAX);
		// a0 == 0 (e.g. r = 2γ₂) goes to the `else` branch: r1 − 1.
		assert_eq!(use_hint_native(2 * MODE2.gamma2, 1), 0);
	}
}
