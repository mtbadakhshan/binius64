// Copyright 2026 The Binius Developers

use std::{array, iter};

use binius_field::{BinaryField, Field, PackedField};
use binius_math::{
	BinarySubspace, FieldBuffer, multilinear::eq::eq_ind_partial_eval_scalars,
	univariate::lagrange_evals_scalars,
};

use crate::{BIT_INDEX_SIZE, LOG_BIT_INDEX_VARS, trace::RC};

/// Compute the 64-entry rotation predicate vector for a fixed `alpha` and offset `k`.
///
/// Entry `c` equals `rot_k(alpha, c)`, the multilinear extension of the indicator
/// `1[<alpha> = <c> + k mod 64]`.
pub fn rot_k_eq_vector<F: Field>(alpha_bits: &[F; 6], k: u32) -> [F; 64] {
	let eq_vector = eq_ind_partial_eval_scalars(alpha_bits);
	let shift = (k as usize) % 64;

	array::from_fn(|c| eq_vector[(c + shift) % 64])
}

/// Compute the 64-point Lagrange basis vector for the fixed bit-index challenge `z_bit`.
pub fn bit_lagrange_weights<F: BinaryField>(z_bit: F) -> [F; BIT_INDEX_SIZE] {
	let subspace = BinarySubspace::<F>::with_dim(LOG_BIT_INDEX_VARS);
	lagrange_evals_scalars(&subspace, z_bit)
		.try_into()
		.expect("bit-index subspace must have 64 elements")
}

/// Compute the 64-point Lagrange basis vector for the rotated view at `z_bit`.
///
/// This matches the same orientation as [`rotate_lane_table`]: the returned weight at index `bit`
/// is the coefficient applied to the unrotated input bit at that index.
pub fn rotated_bit_lagrange_weights<F: BinaryField>(
	z_bit: F,
	rotation: u32,
) -> [F; BIT_INDEX_SIZE] {
	let weights = bit_lagrange_weights(z_bit);
	rotate_bit_lagrange_weights(&weights, rotation)
}

/// Rotate precomputed bit-index Lagrange weights using the same orientation as
/// [`rotate_lane_table`].
pub fn rotate_bit_lagrange_weights<F: Field>(
	weights: &[F; BIT_INDEX_SIZE],
	rotation: u32,
) -> [F; BIT_INDEX_SIZE] {
	let shift = (rotation as usize) % BIT_INDEX_SIZE;
	array::from_fn(|bit| weights[(bit + shift) % BIT_INDEX_SIZE])
}

/// Rotate a lane table in place by `k` bits within each 64-entry instance block.
///
/// # Preconditions
///
/// - `lane.log_len() >= 6`
pub fn permute_lane_table_inplace<P: PackedField>(lane: &mut FieldBuffer<P>, k: u32) {
	assert!(lane.log_len() >= 6, "precondition: lane table must have at least 6 variables");
	*lane = rotate_lane_table(lane, k);
}

/// Return a rotated copy of a lane table.
///
/// # Preconditions
///
/// - `lane.log_len() >= 6`
pub fn rotate_lane_table<P: PackedField>(lane: &FieldBuffer<P>, k: u32) -> FieldBuffer<P> {
	assert!(lane.log_len() >= 6, "precondition: lane table must have at least 6 variables");

	let shift = (k as usize) % 64;
	let scalars = lane.iter_scalars().collect::<Vec<_>>();
	let rotated = scalars
		.chunks_exact(64)
		.flat_map(|chunk| (0..64).map(move |bit| chunk[(bit + 64 - shift) % 64]))
		.collect::<Vec<_>>();

	FieldBuffer::from_values(&rotated)
}

/// Build the multilinear table for a Keccak round constant.
///
/// The table has 6 low bit-index variables and `log_h` high batch variables.
/// The value is constant across the batch dimension.
pub fn round_constant_table<P: PackedField>(round: usize, log_h: usize) -> FieldBuffer<P> {
	assert!(round < 24, "precondition: round must be < 24");
	let rc = RC[round];
	let instance_count = 1usize << log_h;
	let scalars = (0..instance_count)
		.flat_map(|_| (0..64).map(move |bit| scalar_rc_bit::<P>(rc, bit)))
		.collect::<Vec<_>>();

	FieldBuffer::from_values(&scalars)
}

/// Evaluate a round constant table at a scalar point without building the full table.
///
/// # Preconditions
///
/// - `point.len() >= 6`
/// - `round < 24`
pub fn round_constant_eval<F: Field>(round: usize, point: &[F]) -> F {
	assert!(round < 24, "precondition: round must be < 24");
	assert!(point.len() >= 6, "precondition: point must have at least 6 coordinates");

	let eq_vector = eq_ind_partial_eval_scalars(&point[..6]);
	let rc = RC[round];

	iter::zip(0..64, eq_vector).fold(
		F::ZERO,
		|acc, (bit, eq)| {
			if (rc >> bit) & 1 == 1 { acc + eq } else { acc }
		},
	)
}

/// Evaluate the 64-bit round-constant word at the univariate bit challenge `z_bit`.
pub fn round_constant_univariate_eval<F: BinaryField>(round: usize, z_bit: F) -> F {
	let bit_weights = bit_lagrange_weights(z_bit);
	round_constant_from_bit_weights(round, &bit_weights)
}

/// Evaluate the 64-bit round-constant word against precomputed bit-index weights.
pub fn round_constant_from_bit_weights<F: Field>(
	round: usize,
	bit_weights: &[F; BIT_INDEX_SIZE],
) -> F {
	assert!(round < 24, "precondition: round must be < 24");
	iter::zip(0..BIT_INDEX_SIZE, bit_weights).fold(F::ZERO, |acc, (bit, weight)| {
		if (RC[round] >> bit) & 1 == 1 {
			acc + *weight
		} else {
			acc
		}
	})
}

fn scalar_rc_bit<P: PackedField>(round_constant: u64, bit: usize) -> P::Scalar {
	if (round_constant >> bit) & 1 == 1 {
		P::Scalar::ONE
	} else {
		P::Scalar::ZERO
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{
		BinaryField, Field, Random,
		arch::{OptimalB128, OptimalPackedB128},
	};
	use binius_math::{
		BinarySubspace,
		multilinear::{eq::eq_ind, evaluate::evaluate},
		test_utils::index_to_hypercube_point,
		univariate::lagrange_evals_scalars,
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::trace::state_batch_to_lane_tables;

	type F = OptimalB128;
	type P = OptimalPackedB128;

	fn bit_domain_element<F: BinaryField>(bit_index: usize) -> F {
		assert!(bit_index < BIT_INDEX_SIZE, "bit index out of range");
		BinarySubspace::<F>::with_dim(LOG_BIT_INDEX_VARS)
			.iter()
			.nth(bit_index)
			.expect("bit domain must contain 64 elements")
	}

	#[test]
	fn test_rot_k_eq_vector_matches_bruteforce() {
		let mut rng = StdRng::seed_from_u64(2);
		let alpha = std::array::from_fn(|_| F::random(&mut rng));

		for k in 0..64 {
			let actual = rot_k_eq_vector(&alpha, k);
			let expected = array::from_fn(|c| {
				let sigma_k_c = index_to_hypercube_point::<F>(6, (c + k as usize) % 64);
				eq_ind(&alpha, &sigma_k_c)
			});
			assert_eq!(actual, expected, "rotation predicate mismatch at k={k}");
		}
	}

	#[test]
	fn test_rotate_lane_table_matches_rotate_left_on_boolean_points() {
		let lane_word = 0xDEAD_BEEF_0123_4567u64;
		let lane_table = state_batch_to_lane_tables::<P>(&[[lane_word; 25]])[0].clone();

		for k in 0..64 {
			let rotated = rotate_lane_table(&lane_table, k);
			let expected_word = lane_word.rotate_left(k);

			for bit in 0..64 {
				let point = index_to_hypercube_point::<F>(6, bit);
				let expected = if (expected_word >> bit) & 1 == 1 {
					F::ONE
				} else {
					F::ZERO
				};

				assert_eq!(
					evaluate(&rotated, &point),
					expected,
					"rotated lane mismatch at k={k}, bit={bit}"
				);
			}
		}
	}

	#[test]
	fn test_round_constant_eval_matches_table_evaluation() {
		let mut rng = StdRng::seed_from_u64(3);

		for round in [0usize, 7, 23] {
			let table = round_constant_table::<P>(round, 0);
			let point: [F; 6] = std::array::from_fn(|_| F::random(&mut rng));
			assert_eq!(evaluate(&table, &point), round_constant_eval(round, &point));
		}
	}

	#[test]
	fn test_bit_lagrange_weights_matches_direct_helper() {
		let mut rng = StdRng::seed_from_u64(16);
		let subspace = BinarySubspace::<F>::with_dim(LOG_BIT_INDEX_VARS);
		let z_bit = F::random(&mut rng);
		let actual = bit_lagrange_weights(z_bit);
		let expected: [F; BIT_INDEX_SIZE] = lagrange_evals_scalars(&subspace, z_bit)
			.try_into()
			.expect("bit-index subspace must have 64 elements");

		assert_eq!(actual, expected);
	}

	#[test]
	fn test_rotated_bit_lagrange_weights_match_rotated_lane_evaluation() {
		let lane_word = 0xDEAD_BEEF_0123_4567u64;
		let lane_table = state_batch_to_lane_tables::<P>(&[[lane_word; 25]])[0].clone();

		for rotation in [0u32, 1, 7, 13, 63] {
			let rotated_table = rotate_lane_table(&lane_table, rotation);
			for bit_index in [0usize, 1, 17, 63] {
				let z_bit = bit_domain_element::<F>(bit_index);
				let rotated_weights = rotated_bit_lagrange_weights(z_bit, rotation);
				let expected = iter::zip(0..BIT_INDEX_SIZE, rotated_weights).fold(
					F::ZERO,
					|acc, (bit, weight)| {
						let bit_value = if (lane_word >> bit) & 1 == 1 {
							F::ONE
						} else {
							F::ZERO
						};
						acc + weight * bit_value
					},
				);
				let point = index_to_hypercube_point::<F>(LOG_BIT_INDEX_VARS, bit_index);
				let actual = evaluate(&rotated_table, &point);
				assert_eq!(
					actual, expected,
					"rotated bit weights mismatch at rotation={rotation}, bit_index={bit_index}"
				);
			}
		}
	}

	#[test]
	fn test_round_constant_univariate_eval_selects_boolean_domain_point() {
		for round in [0usize, 7, 23] {
			for bit_index in [0usize, 1, 17, 63] {
				let z_bit = bit_domain_element::<F>(bit_index);
				let expected = if (RC[round] >> bit_index) & 1 == 1 {
					F::ONE
				} else {
					F::ZERO
				};
				assert_eq!(round_constant_univariate_eval(round, z_bit), expected);
			}
		}
	}
}
