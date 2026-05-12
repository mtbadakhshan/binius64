// Copyright 2026 The Binius Developers

//! ML-DSA parameter constants.
//!
//! Phase 0 only defines the Dilithium2 (ML-DSA-44) parameter set from
//! [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). Modes 3 and 5 are
//! intentionally not exposed; the [`Mode`] enum is shaped so they can be
//! added without breaking call sites.

/// ML-DSA prime modulus `Q = 2²³ − 2¹³ + 1 = 8 380 417`.
///
/// Same value across Dilithium2 / 3 / 5. Fits in 23 bits, so any
/// `(a, b) ∈ Z_q × Z_q` product fits in 46 bits and stays inside a single
/// 64-bit `Wire`.
pub const Q: u32 = 8_380_417;

/// `Q⁻¹ mod 2³²` — the Montgomery constant used by the reference C
/// implementation (`dilithium/ref/reduce.c::montgomery_reduce`). Carried
/// here so that future Montgomery-based reductions (Phase 1+) match the
/// reference exactly.
pub const Q_INV: u32 = 58_728_449;

/// Polynomial degree. Same across all parameter sets.
pub const N: usize = 256;

/// Number of low-order bits dropped from `t` to form `t₁`. Same across all
/// parameter sets.
pub const D: u32 = 13;

/// Per-mode parameter bundle. Phase 0 only constructs the Dilithium2 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeParams {
	/// Number of rows in the public matrix `A` (and the dimension of `t₁`,
	/// `w`, hint vector `h`).
	pub k: usize,
	/// Number of columns in `A` (and the dimension of the response vector
	/// `z`).
	pub l: usize,
	/// Hamming weight of the challenge polynomial `c` produced by
	/// `SampleInBall`.
	pub tau: usize,
	/// Slack term for the `‖z‖ < γ₁ − β` range check.
	pub beta: u32,
	/// Maximum number of nonzero hint coefficients allowed in `h`.
	pub omega: usize,
	/// Bound on each coefficient of the response vector `z`.
	pub gamma1: u32,
	/// Hint quantum used by `Decompose` / `UseHint`.
	pub gamma2: u32,
	/// Total signature length in bytes.
	pub sig_bytes: usize,
	/// Total public-key length in bytes.
	pub pk_bytes: usize,
}

/// Forward-compatible mode selector. Only `Mode2` is implemented in Phase 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
	/// ML-DSA-44 (Dilithium2). `K = L = 4`.
	Mode2,
	// Mode3 (ML-DSA-65) and Mode5 (ML-DSA-87) intentionally absent — see
	// the Phase 5 entry in `docs/aggregate-mldsa-design.md`.
}

impl Mode {
	/// Returns the per-mode constants for this parameter set.
	pub const fn params(self) -> ModeParams {
		match self {
			Mode::Mode2 => MODE2,
		}
	}
}

/// Dilithium2 parameter bundle.
pub const MODE2: ModeParams = ModeParams {
	k: 4,
	l: 4,
	tau: 39,
	beta: 78,
	omega: 80,
	gamma1: 1 << 17,
	gamma2: (Q - 1) / 88,
	sig_bytes: 2420,
	pk_bytes: 1312,
};

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn dilithium2_constants_match_fips_204() {
		// Cross-check against FIPS 204 §4 (Table 1) and the reference
		// implementation header `dilithium/ref/params.h` for MODE = 2.
		assert_eq!(Q, 8_380_417);
		assert_eq!(N, 256);
		assert_eq!(D, 13);
		assert_eq!(MODE2.k, 4);
		assert_eq!(MODE2.l, 4);
		assert_eq!(MODE2.tau, 39);
		assert_eq!(MODE2.beta, 78);
		assert_eq!(MODE2.omega, 80);
		assert_eq!(MODE2.gamma1, 131_072); // 2^17
		assert_eq!(MODE2.gamma2, 95_232); // (Q-1)/88
		assert_eq!(MODE2.sig_bytes, 2_420);
		assert_eq!(MODE2.pk_bytes, 1_312);
	}

	#[test]
	fn q_minv_consistency() {
		// Q_INV must satisfy Q · Q_INV ≡ 1 (mod 2³²) — see
		// `dilithium/ref/reduce.c::montgomery_reduce` for usage.
		let prod = (Q as u64).wrapping_mul(Q_INV as u64) as u32;
		assert_eq!(prod, 1u32);
	}
}
