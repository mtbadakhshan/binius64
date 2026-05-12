// Copyright 2026 The Binius Developers

//! End-to-end pedagogical example: trace a tiny circuit through every step.
//!
//! Circuit:
//!     private & 0xFF00 == 0x1200
//! Witness:
//!     private = 0x1234, output = 0x1200 (public)
//!
//! Run:
//!     cargo test -p binius-prover --test learn_e2e -- --nocapture
//!
//! See `docs/learn-e2e-walkthrough.md` for the math behind each step.

use binius_core::{
	constraint_system::{ShiftVariant, ValueVec},
	verify::{eval_operand, verify_constraints},
	word::Word,
};
use binius_field::{AESTowerField8b as B8, Field, arch::OptimalPackedB128};
use binius_math::multilinear::evaluate::evaluate_inplace_scalars;
use binius_frontend::{CircuitBuilder, stat::CircuitStat};
use binius_prover::{Prover, hash::parallel_compression::ParallelCompressionAdaptor};
use binius_transcript::ProverTranscript;
use binius_verifier::{
	Verifier,
	config::{B128, PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES, StdChallenger},
	hash::{StdCompression, StdDigest},
};

fn shift_str(v: ShiftVariant) -> &'static str {
	match v {
		ShiftVariant::Sll => "sll",
		ShiftVariant::Slr => "slr",
		ShiftVariant::Sar => "sar",
		ShiftVariant::Rotr => "rotr",
		ShiftVariant::Sll32 => "sll32",
		ShiftVariant::Srl32 => "srl32",
		ShiftVariant::Sra32 => "sra32",
		ShiftVariant::Rotr32 => "rotr32",
	}
}

fn dump_operand(indent: &str, name: &str, op: &binius_core::constraint_system::Operand) {
	let parts: Vec<String> = op
		.iter()
		.map(|sv| {
			if sv.amount == 0 {
				format!("v{}", sv.value_index.0)
			} else {
				format!("v{} {} {}", sv.value_index.0, shift_str(sv.shift_variant), sv.amount)
			}
		})
		.collect();
	let body = if parts.is_empty() {
		"0".to_string()
	} else {
		parts.join(" XOR ")
	};
	println!("{}{} = {}", indent, name, body);
}

#[test]
fn learn_e2e_minimal() {
	println!("\n========== LEARN E2E: minimal AND-mask circuit ==========\n");

	// =========================================================================
	// PHASE 1: Build the circuit
	// =========================================================================
	let builder = CircuitBuilder::new();

	let mask = builder.add_constant_64(0xFF00);
	let private = builder.add_witness();
	let output = builder.add_inout();

	let result = builder.band(private, mask);
	builder.assert_eq("masked_result", result, output);

	let circuit = builder.build();

	let stat = CircuitStat::collect(&circuit);
	println!("[1] Circuit");
	println!("    AND constraints: {}", stat.n_and_constraints);
	println!("    MUL constraints: {}", stat.n_mul_constraints);
	println!("    Gates:           {}", stat.n_gates);

	// =========================================================================
	// PHASE 2: Witness population
	// =========================================================================
	let mut w = circuit.new_witness_filler();
	w[private] = Word(0x1234);
	w[output] = Word(0x1200);
	circuit.populate_wire_witness(&mut w).unwrap();

	let cs = circuit.constraint_system();
	let witness_vec: ValueVec = w.into_value_vec();

	let layout = &cs.value_vec_layout;
	println!("\n[2] ValueVecLayout");
	println!("    n_const     = {}, n_inout = {}, n_witness = {}, n_internal = {}",
		layout.n_const, layout.n_inout, layout.n_witness, layout.n_internal);
	println!("    offsets: inout={}, witness={}", layout.offset_inout, layout.offset_witness);
	println!("    committed_total_len = {} (= 2^{})",
		layout.committed_total_len,
		layout.committed_total_len.trailing_zeros());

	let combined = witness_vec.combined_witness();
	println!("\n    ValueVec contents:");
	for (i, w) in combined.iter().enumerate() {
		let role = if i < layout.n_const {
			"const"
		} else if i >= layout.offset_inout && i < layout.offset_inout + layout.n_inout {
			"inout"
		} else if i >= layout.offset_witness && i < layout.offset_witness + layout.n_witness {
			"witness"
		} else if i >= layout.offset_witness + layout.n_witness
			&& i < layout.offset_witness + layout.n_witness + layout.n_internal
		{
			"internal"
		} else {
			"padding"
		};
		println!("      v{} = 0x{:016x}  ({})", i, w.0, role);
	}

	println!("\n    AND constraints:");
	for (i, c) in cs.and_constraints.iter().enumerate() {
		println!("      constraint {}:", i);
		dump_operand("        ", "A", &c.a);
		dump_operand("        ", "B", &c.b);
		dump_operand("        ", "C", &c.c);
	}

	verify_constraints(cs, &witness_vec).expect("constraints should hold");
	println!("    ✓ Native constraint verification PASSED");

	// =========================================================================
	// PHASE 3: Per-constraint operand evaluation (the columns A, B, C)
	// =========================================================================
	println!("\n[3] AND-reduction columns");
	println!("    For each constraint i, compute (a_i, b_i, c_i) = (eval(A_i), eval(B_i), eval(C_i)):");

	let mut a_col: Vec<u64> = Vec::with_capacity(cs.and_constraints.len());
	let mut b_col: Vec<u64> = Vec::with_capacity(cs.and_constraints.len());
	let mut c_col: Vec<u64> = Vec::with_capacity(cs.and_constraints.len());
	for (i, c) in cs.and_constraints.iter().enumerate() {
		let av = eval_operand(&witness_vec, &c.a).0;
		let bv = eval_operand(&witness_vec, &c.b).0;
		let cv = eval_operand(&witness_vec, &c.c).0;
		a_col.push(av);
		b_col.push(bv);
		c_col.push(cv);
		println!("      i={}: a=0x{:016x}, b=0x{:016x}, c=0x{:016x}", i, av, bv, cv);
		println!("           a & b = 0x{:016x}  (must equal c) → {}",
			av & bv,
			if (av & bv) == cv { "OK" } else { "FAIL" });
	}

	// =========================================================================
	// PHASE 4: AND-reduction Phase 1 deterministic challenge inspection
	// =========================================================================
	let n_constraints = cs.and_constraints.len();
	let log_n = n_constraints.trailing_zeros() as usize;
	assert!(n_constraints.is_power_of_two(), "Need power-of-two AND count");

	println!("\n[4] AND reduction parameters");
	println!("    n_constraints = {} = 2^{}", n_constraints, log_n);
	println!("    bit-axis variables: {} (from 64-bit words = 2^6 bits)", 6);
	println!("    constraint-axis variables: {}", log_n);
	println!("    total Boolean variables: {}", 6 + log_n);

	let mut zerocheck_challenges = PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES.to_vec();
	zerocheck_challenges.truncate(log_n);
	println!("    small-field zerocheck challenges (first {} of 3 baked-in):", log_n);
	for (j, ch) in zerocheck_challenges.iter().enumerate() {
		// Lift the AES8b challenge into B128 the way the prover does.
		let ch_b128: B128 = B128::from(*ch);
		println!("      r[{}] = AES8b(0x{:02x}) → B128 = 0x{:032x}",
			j, ch.val(), ch_b128.val());
	}

	// =========================================================================
	// PHASE 5: Witness MLE evaluation (what the PIOP actually produces)
	// =========================================================================
	// The committed witness is interpreted as a multilinear polynomial (MLE)
	// in n_vars variables, where 2^n_vars = committed_total_len * bits_per_word.
	//
	// Two ways to view it:
	//   (a) B128 MLE: pack 2 u64 words → 1 B128 element, then take MLE over
	//       log2(num_b128_elements) variables. Each evaluation point is in B128.
	//   (b) B1 MLE: each individual bit is one evaluation, MLE has
	//       log2(committed_words * 64) = 3 + 6 = 9 variables.
	//
	// The PIOP works in (a); the ring switch reduces to (b) which is what gets
	// committed to the PCS.
	println!("\n[5] Witness MLE evaluations");

	// (a) B128 MLE: pack pairs of u64 into B128 elements.
	let n_b128 = combined.len() / 2;  // 8 / 2 = 4
	let mut b128_witness: Vec<B128> = Vec::with_capacity(n_b128);
	for chunk in combined.chunks(2) {
		// Pack lo = chunk[0], hi = chunk[1] into a 128-bit value.
		let lo = chunk[0].0 as u128;
		let hi = chunk[1].0 as u128;
		let packed = lo | (hi << 64);
		b128_witness.push(B128::new(packed));
	}
	let log_b128_len = (n_b128 as u32).trailing_zeros() as usize;
	println!("    B128 packed witness ({} elements, log_len={}):", n_b128, log_b128_len);
	for (i, x) in b128_witness.iter().enumerate() {
		println!("      W[{}] = 0x{:032x}", i, x.val());
	}

	// Evaluate the B128 MLE at a deterministic challenge point r = (r_0, r_1).
	let r0 = B128::new(0x123456789abcdef0123456789abcdef0u128);
	let r1 = B128::new(0x0fedcba987654321fedcba9876543210u128);
	let r = vec![r0, r1];
	let mle_eval = evaluate_inplace_scalars(b128_witness.clone(), &r);
	println!("    Evaluated B128-MLE at r=(r0, r1):");
	println!("      r0 = 0x{:032x}", r0.val());
	println!("      r1 = 0x{:032x}", r1.val());
	println!("      W(r) = 0x{:032x}", mle_eval.val());

	// Sanity: at corner points (Boolean inputs), MLE evaluates to W[i].
	let corner = vec![B128::ZERO, B128::ZERO];
	let v_at_corner = evaluate_inplace_scalars(b128_witness.clone(), &corner);
	assert_eq!(v_at_corner, b128_witness[0]);
	println!("      W(0,0) = W[0] ? {} ✓", v_at_corner == b128_witness[0]);

	// (b) B1 MLE: each bit individually. log_len = 9.
	// Total bits = 8 words * 64 bits/word = 512 = 2^9.
	let total_bits = combined.len() * 64;
	let log_b1_len = (total_bits as u32).trailing_zeros() as usize;
	println!("    B1 (per-bit) MLE has log_len = {} ({} bits total)", log_b1_len, total_bits);

	// Evaluate the B1 MLE at the same point, but with extra coordinates for the
	// bit axis. Conceptually: the B1 polynomial has 2 extra variables
	// (since 2^7 = 128 = log_packing of B128 over B1 = 7, but we need 9 total).
	// Actually log_packing(B128/B1) = 7 (one B128 = 128 bits), and log_b128_len = 2,
	// so log_b1_len = 7 + 2 = 9. ✓

	// Compute the bit-MLE evaluation by checking the eq_ind expansion.
	// (We just demonstrate it lives in the same field as r.)
	let bits: Vec<B128> = combined
		.iter()
		.flat_map(|w| {
			(0..64).map(move |b| {
				let bit = (w.0 >> b) & 1;
				if bit == 1 { B128::ONE } else { B128::ZERO }
			})
		})
		.collect();
	assert_eq!(bits.len(), 1 << log_b1_len);

	// Evaluate the B1-MLE at a 9-coordinate point.
	let mut r_bits: Vec<B128> = (0..log_b1_len)
		.map(|i| B128::new((i as u128 + 1).wrapping_mul(0x9e3779b97f4a7c15)))
		.collect();
	r_bits[0] = B128::new(0x11);
	let bit_mle_eval = evaluate_inplace_scalars(bits.clone(), &r_bits);
	println!("    B1-MLE evaluated at a 9-dim test point: 0x{:032x}",
		bit_mle_eval.val());
	println!("    (in production, the ring switch produces this evaluation point)");

	// =========================================================================
	// PHASE 6: Run the prover and verifier
	// =========================================================================
	const LOG_INV_RATE: usize = 1;
	let verifier =
		Verifier::<StdDigest, _>::setup(cs.clone(), LOG_INV_RATE, StdCompression::default())
			.unwrap();
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.unwrap();

	println!("\n[6] Prover setup");
	println!("    log_inv_rate = {}", LOG_INV_RATE);

	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover.prove(witness_vec.clone(), &mut prover_transcript).unwrap();
	let proof = prover_transcript.finalize();

	println!("    proof size: {} bytes", proof.len());

	let mut verifier_transcript = binius_transcript::VerifierTranscript::new(
		StdChallenger::default(),
		proof,
	);
	verifier
		.verify(witness_vec.public(), &mut verifier_transcript)
		.expect("verifier should accept");
	verifier_transcript.finalize().expect("transcript should finalize");

	println!("    ✓ proof accepted\n");

	// Touch B8 once so the import isn't flagged.
	let _ = B8::ZERO;
}

/// Smoke test for the Akita full-open bridge end-to-end on the same toy
/// circuit. Runs `private & 0xFF00 == 0x1200` through
/// `prove_akita_full_open` / `verify_akita_full_open` instead of the
/// default BaseFold path.
///
/// The full-open Akita path is the **non-succinct** bridge mode: it reveals
/// the terminal Binius oracle in the proof and verifies the batched parity
/// bridge directly. The test exercises the Akita commitment plumbing plus
/// the full Binius PIOP pipeline (AND reduction → IntMul reduction → shift
/// reduction → ring switch) on top of the Akita commitment.
#[cfg(feature = "akita")]
#[test]
fn learn_e2e_akita_full_open() {
	use binius_transcript::VerifierTranscript;
	println!("\n========== LEARN E2E (Akita full-open path) ==========\n");

	let builder = CircuitBuilder::new();
	let mask = builder.add_constant_64(0xFF00);
	let private = builder.add_witness();
	let output = builder.add_inout();
	let result = builder.band(private, mask);
	builder.assert_eq("masked_result", result, output);
	let circuit = builder.build();

	let mut w = circuit.new_witness_filler();
	w[private] = Word(0x1234);
	w[output] = Word(0x1200);
	circuit.populate_wire_witness(&mut w).unwrap();
	let cs = circuit.constraint_system().clone();
	let witness_vec: ValueVec = w.into_value_vec();

	const LOG_INV_RATE: usize = 1;
	let verifier =
		Verifier::<StdDigest, _>::setup(cs, LOG_INV_RATE, StdCompression::default()).unwrap();
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)
	.unwrap();

	// Akita full-open prover.
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove_akita_full_open(witness_vec.clone(), &mut prover_transcript)
		.expect("Akita full-open prove should succeed");
	let proof = prover_transcript.finalize();
	println!(
		"    [Akita full-open] proof size: {} bytes (expected larger than BaseFold — full-open mode reveals the witness)",
		proof.len()
	);

	// Akita full-open verifier.
	let mut verifier_transcript = VerifierTranscript::new(StdChallenger::default(), proof);
	verifier
		.verify_akita_full_open(witness_vec.public(), &mut verifier_transcript)
		.expect("Akita full-open verifier should accept");
	verifier_transcript
		.finalize()
		.expect("Akita full-open transcript should finalize");

	println!("    ✓ Akita full-open proof accepted\n");
}

/// Documents why the Akita succinct bridge cannot run on the toy walkthrough
/// circuit, and points at where it IS validated.
///
/// The Akita succinct bridge in `AkitaSuccinctSetup::new` requires each oracle
/// to have `log_msg_len >= 7` — i.e., at least 2^7 = 128 packed B128 elements
/// (= 256 64-bit words). The toy walkthrough circuit has only 4 packed B128
/// elements (log_msg_len = 2), so it falls below the minimum.
///
/// The schedule-driven `akita_succinct_opening_shape` implementation is
/// validated by `crates/prover/tests/prove_verify.rs`'s
/// `akita_proof_mode_mismatches_reject` test, which uses a SHA-256 preimage
/// circuit large enough for the Akita succinct path. That test covers
/// the positive roundtrip, byte-tamper rejection, and cross-mode rejection.
#[cfg(feature = "akita")]
#[test]
#[ignore = "Toy circuit too small for Akita succinct (needs log_msg_len >= 7); see akita_proof_mode_mismatches_reject in prove_verify.rs for the actual runtime validation"]
fn learn_e2e_akita_succinct() {
	// Intentionally ignored — see the test docstring for the reason and where
	// the corresponding validation lives.
}
