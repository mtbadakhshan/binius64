// Copyright 2026 The Binius Developers

//! End-to-end smoke tests for the (future) ML-DSA single-signature and
//! N-aggregate verifiers.
//!
//! Phase 0 ships only stubs (`MlDsaVerifier::new` and
//! `AggregateMlDsaVerifier::new` panic with `unimplemented!()`), so every
//! test here is `#[ignore]`. Each test documents the exact end-to-end shape
//! Phase 1+ should land:
//!
//! - `mldsa_verifier_accepts_honest_dilithium2_signature` — Phase 1
//!   target (single-signature, full pipeline including R5 placeholder).
//! - `mldsa_verifier_rejects_tampered_signature` — soundness sibling for
//!   the above.
//! - `aggregate_mldsa_verifier_accepts_n_honest_signatures` — Phase 4
//!   target (flat composition over `N = 4` Dilithium2 signatures).
//!
//! The ignore reason on each test points the reader at the design doc
//! `docs/aggregate-mldsa-design.md` so the corresponding phase has a
//! concrete next step instead of stale `unimplemented!()` stack traces.

use binius_frontend::CircuitBuilder;
use binius_mldsa::{
	aggregate::AggregateMlDsaVerifier,
	params::Mode,
	verifier::MlDsaVerifier,
};

#[test]
#[ignore = "Phase 1: implement R1/R3/R6/R7; see docs/aggregate-mldsa-design.md"]
fn mldsa_verifier_accepts_honest_dilithium2_signature() {
	// Phase 1 wiring sketch (pseudo-code):
	//   1. Hoisted (verifier-side, native sha3):
	//        tr = SHAKE256(pk)
	//        μ  = SHAKE256(tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ msg)
	//        A  = ExpandA(ρ)
	//   2. In-circuit:
	//        let v = MlDsaVerifier::new(&builder, Mode::Mode2);
	//        - allocate witness wires for σ = (c̃, z, h)
	//        - allocate public-input wires for (μ, A, t₁·2^D, wApprox)
	//        - emit R1 (norm) + R3 (SampleInBall) + R6 (UseHint) +
	//          R7 (final SHAKE256) constraint subcircuits.
	//   3. Build circuit, populate witness with a known-good signature
	//      (e.g. via the dilithium reference at /Users/.../Projects/dilithium),
	//      and run binius-prover + binius-verifier to confirm acceptance.
	let builder = CircuitBuilder::new();
	let _ = MlDsaVerifier::new(&builder, Mode::Mode2);
}

#[test]
#[ignore = "Phase 1: implement R1/R3/R6/R7 + tamper test; see docs/aggregate-mldsa-design.md"]
fn mldsa_verifier_rejects_tampered_signature() {
	// Same construction as the honest test, but the signature witness
	// bytes are corrupted (single-byte flip in `c̃`, `z`, or `h`). The
	// expected outcome is either:
	//   (a) populate_wire_witness fails (R6 / R7 detects the
	//       inconsistency at witness-derivation time), or
	//   (b) verify_constraints rejects the resulting witness.
	// Honest acceptance would be a soundness break.
	let builder = CircuitBuilder::new();
	let _ = MlDsaVerifier::new(&builder, Mode::Mode2);
}

#[test]
#[ignore = "Phase 4 (flat composition) — see docs/aggregate-mldsa-design.md §6"]
fn aggregate_mldsa_verifier_accepts_n_honest_signatures() {
	// Phase 4 wiring sketch (pseudo-code, Mode2, N = 4):
	//   1. For each i in 0..N: hoist (tr_i, μ_i, A_i) on the verifier side.
	//   2. In-circuit:
	//        let agg = AggregateMlDsaVerifier::new(&builder, Mode::Mode2, 4);
	//        - this allocates N disjoint sub-namespaces, each containing
	//          a MlDsaVerifier instance.
	//        - the cross-field bridge transcript is shared across all N
	//          instances (single parity bridge + sumcheck batch over the
	//          aggregate witness).
	//   3. Build, populate, prove, verify.
	let builder = CircuitBuilder::new();
	let _ = AggregateMlDsaVerifier::new(&builder, Mode::Mode2, 4);
}
