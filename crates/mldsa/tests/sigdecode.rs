// Copyright 2026 The Binius Developers

//! Tests for [`binius_mldsa::sigdecode`] — the top-level signature
//! decoder that pulls `c̃` and the `L = 4` `z` polynomials out of a
//! packed Dilithium2 signature.

use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::{CircuitBuilder, Wire};
use binius_mldsa::{
	params::{MODE2, N},
	polyz::assert_norm_centered,
	sigdecode::{
		SIG_C_TILDE_BYTES, SIG_PACKED_BYTES, SIG_PACKED_LANES, pack_signature_native,
		signature_to_lanes, unpack_c_tilde, unpack_z,
	},
};
use rand::{Rng, SeedableRng, rngs::StdRng};

const L: usize = MODE2.l;
const TWO_GAMMA1: u32 = 2 * MODE2.gamma1;

/// Builds a circuit that allocates `SIG_PACKED_LANES` witness wires for
/// the byte-packed signature, runs `unpack_c_tilde` + `unpack_z`, and
/// asserts each extracted wire matches a corresponding "expected"
/// witness. Used as the round-trip check between the native packer and
/// the in-circuit unpacker.
fn check_roundtrip(c_tilde: &[u8; SIG_C_TILDE_BYTES], z: &[[u32; N]; L]) {
	let packed = pack_signature_native(c_tilde, z);
	let lanes = signature_to_lanes(&packed);

	let builder = CircuitBuilder::new();
	let sig_wires: [Wire; SIG_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());

	let extracted_c_tilde = unpack_c_tilde(&sig_wires);
	let extracted_z = unpack_z(&builder, &sig_wires);

	let expected_c_tilde: [Wire; 4] = std::array::from_fn(|_| builder.add_witness());
	for i in 0..4 {
		builder.assert_eq(
			format!("sigdecode c~[{i}]"),
			extracted_c_tilde[i],
			expected_c_tilde[i],
		);
	}

	let expected_z: [[Wire; N]; L] = std::array::from_fn(|_| {
		std::array::from_fn(|_| builder.add_witness())
	});
	for p in 0..L {
		for j in 0..N {
			builder.assert_eq(
				format!("sigdecode z[{p}][{j}]"),
				extracted_z[p][j],
				expected_z[p][j],
			);
		}
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in sig_wires.iter().zip(&lanes) {
		filler[*w] = Word(v);
	}
	let c_tilde_lanes = signature_to_lanes_chunk_4(c_tilde);
	for (w, &v) in expected_c_tilde.iter().zip(&c_tilde_lanes) {
		filler[*w] = Word(v);
	}
	for p in 0..L {
		for j in 0..N {
			filler[expected_z[p][j]] = Word(z[p][j] as u64);
		}
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("sigdecode round-trip must accept honest witness");
}

/// Tiny helper: pack a 32-byte `c̃` into 4 LE 64-bit lanes.
fn signature_to_lanes_chunk_4(c_tilde: &[u8; 32]) -> [u64; 4] {
	std::array::from_fn(|i| {
		let mut w = [0u8; 8];
		w.copy_from_slice(&c_tilde[8 * i..8 * (i + 1)]);
		u64::from_le_bytes(w)
	})
}

// ─── Layout sanity checks (constants are correct) ───────────────────────

#[test]
fn signature_layout_constants_match_fips_204() {
	// CRYPTO_BYTES for Dilithium2 in FIPS 204 / dilithium ref `params.h`.
	assert_eq!(SIG_PACKED_BYTES, MODE2.sig_bytes);
	assert_eq!(SIG_PACKED_BYTES, 2_420);
	assert_eq!(SIG_PACKED_LANES, 303);
}

// ─── Round-trip extraction ──────────────────────────────────────────────

#[test]
fn sigdecode_zeros() {
	let c_tilde = [0u8; SIG_C_TILDE_BYTES];
	let z = [[0u32; N]; L];
	check_roundtrip(&c_tilde, &z);
}

#[test]
fn sigdecode_random_seeded() {
	let mut rng = StdRng::seed_from_u64(0xdeadbeef);
	let c_tilde: [u8; SIG_C_TILDE_BYTES] = std::array::from_fn(|_| rng.random());
	let z: [[u32; N]; L] =
		std::array::from_fn(|_| std::array::from_fn(|_| rng.random_range(0..TWO_GAMMA1)));
	check_roundtrip(&c_tilde, &z);
}

#[test]
fn sigdecode_isolates_each_z_polynomial() {
	// Set polynomial p to all-`p+1` (a small distinct constant per
	// polynomial), zero c~, others zero. Confirms the L wrapper does
	// not cross-contaminate polynomials.
	for p_target in 0..L {
		let c_tilde = [0u8; SIG_C_TILDE_BYTES];
		let z: [[u32; N]; L] = std::array::from_fn(|p| {
			if p == p_target {
				[(p_target as u32 + 1) * 1000; N]
			} else {
				[0u32; N]
			}
		});
		check_roundtrip(&c_tilde, &z);
	}
}

#[test]
fn sigdecode_isolates_c_tilde_from_z() {
	// Non-trivial c̃, all-zero z. c̃ extraction must not be perturbed
	// by neighbouring lanes and z must come out as zero.
	let c_tilde: [u8; SIG_C_TILDE_BYTES] = std::array::from_fn(|i| (i as u8).wrapping_mul(17));
	let z = [[0u32; N]; L];
	check_roundtrip(&c_tilde, &z);
}

// ─── Integration with the polyz norm check ──────────────────────────────

#[test]
fn sigdecode_then_norm_check_accepts_in_bound_signature() {
	let mut rng = StdRng::seed_from_u64(0x1234);
	let c_tilde: [u8; SIG_C_TILDE_BYTES] = std::array::from_fn(|_| rng.random());
	// All centered coefficients strictly inside (β, 2γ₁ − β).
	let z: [[u32; N]; L] = std::array::from_fn(|_| {
		std::array::from_fn(|_| rng.random_range(MODE2.beta + 1..2 * MODE2.gamma1 - MODE2.beta))
	});
	let packed = pack_signature_native(&c_tilde, &z);
	let lanes = signature_to_lanes(&packed);

	let builder = CircuitBuilder::new();
	let sig_wires: [Wire; SIG_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let extracted_z = unpack_z(&builder, &sig_wires);
	for poly in &extracted_z {
		assert_norm_centered(&builder, poly);
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in sig_wires.iter().zip(&lanes) {
		filler[*w] = Word(v);
	}
	circuit.populate_wire_witness(&mut filler).unwrap();
	verify_constraints(circuit.constraint_system(), &filler.into_value_vec())
		.expect("in-bound signature must pass full sigdecode + norm check");
}

#[test]
fn sigdecode_then_norm_check_rejects_out_of_bound_signature() {
	let mut rng = StdRng::seed_from_u64(0x5678);
	let c_tilde: [u8; SIG_C_TILDE_BYTES] = std::array::from_fn(|_| rng.random());
	// Same as the accept test, but flip exactly one coefficient (in the
	// last polynomial, last position) to an out-of-bound centered value.
	let mut z: [[u32; N]; L] = std::array::from_fn(|_| {
		std::array::from_fn(|_| rng.random_range(MODE2.beta + 1..2 * MODE2.gamma1 - MODE2.beta))
	});
	z[L - 1][N - 1] = MODE2.beta; // exactly the bound — must reject
	let packed = pack_signature_native(&c_tilde, &z);
	let lanes = signature_to_lanes(&packed);

	let builder = CircuitBuilder::new();
	let sig_wires: [Wire; SIG_PACKED_LANES] =
		std::array::from_fn(|_| builder.add_witness());
	let extracted_z = unpack_z(&builder, &sig_wires);
	for poly in &extracted_z {
		assert_norm_centered(&builder, poly);
	}

	let circuit = builder.build();
	let mut filler = circuit.new_witness_filler();
	for (w, &v) in sig_wires.iter().zip(&lanes) {
		filler[*w] = Word(v);
	}
	let populated = circuit.populate_wire_witness(&mut filler);
	if populated.is_ok() {
		assert!(
			verify_constraints(circuit.constraint_system(), &filler.into_value_vec()).is_err(),
			"out-of-bound signature must be rejected by sigdecode + norm check",
		);
	}
}
