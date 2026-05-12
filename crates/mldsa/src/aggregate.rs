// Copyright 2026 The Binius Developers

//! N-aggregate ML-DSA verifier circuit.
//!
//! ## Status: Phase 0 stub
//!
//! Like [`crate::verifier`], this is an `unimplemented!()` skeleton whose
//! type shape is fixed for downstream tests. The implementation rolls out
//! across Phase 4–5 of the roadmap in
//! `docs/aggregate-mldsa-design.md`.
//!
//! ## Aggregation strategies
//!
//! The design doc enumerates three approaches lifted from the
//! `mldsa-verification-relation.canvas.tsx` Aggregation tab:
//!
//! 1. **Flat composition** — instantiate `N` copies of
//!    [`crate::verifier::MlDsaVerifier`] inside a single Binius64 circuit
//!    and produce one proof. Circuit size is `N · C`. Practical for small
//!    `N` (≤ 16). This is the **Phase 4-MVP** target.
//! 2. **Recursive SNARK** — each step verifies one signature plus the
//!    proof from the previous step. Circuit size `C + C_verifier`,
//!    constant proof size, streaming-friendly.
//! 3. **Folding (Nova / Protogalaxy)** — fold `N` instances of the
//!    verifier relation into a single instance with one final SNARK at
//!    the end. Per-step cost is dominated by a commitment, much cheaper
//!    than full SNARK verification. **Phase 5+** target for production.
//!
//! ## Cross-field bridge sharing
//!
//! Each of the `N` verifications independently bridges three values
//! (`z_i`, `c_i`, `wApprox_i`) between the Binius64 and Akita-lattice
//! tracks. Phase 4 shares the bridge transcript across all `N` instances
//! to amortise the parity-bridge / sumcheck overhead — see the bridge
//! design discussion in `docs/aggregate-mldsa-design.md`.

use binius_frontend::CircuitBuilder;

use crate::{params::Mode, verifier::MlDsaVerifier};

/// In-circuit verifier for `N` independent ML-DSA signatures, producing
/// a single succinct proof. Phase 0 stub.
#[derive(Debug)]
pub struct AggregateMlDsaVerifier {
	/// One sub-verifier per aggregated signature. `len() == N`.
	pub per_signature: Vec<MlDsaVerifier>,
}

impl AggregateMlDsaVerifier {
	/// Construct an N-aggregate verifier.
	///
	/// # Panics
	///
	/// Phase 0: always panics. Phase 4 (flat composition) will instantiate
	/// `n_signatures` copies of [`MlDsaVerifier`] under disjoint sub-circuit
	/// namespaces and share the cross-field bridge.
	pub fn new(_b: &CircuitBuilder, mode: Mode, n_signatures: usize) -> Self {
		assert!(matches!(mode, Mode::Mode2), "Phase 0 only supports Mode2");
		assert!(n_signatures > 0, "n_signatures must be positive");
		unimplemented!(
			"binius-mldsa Phase 4 (flat composition): see \
			 `docs/aggregate-mldsa-design.md`"
		);
	}
}
