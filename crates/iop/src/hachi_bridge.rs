// Copyright 2026 The Binius Developers

//! Experimental bridge boundary for a Hachi-backed PCS.
//!
//! Binius64's IOP oracle relations are stated over the binary tower field
//! [`BinaryField128bGhash`]. The local Hachi implementation works over its
//! `fp128` prime field preset. This module deliberately exposes only the
//! canonical integer lift and the reason it is not yet a sound PCS replacement.

use binius_field::{BinaryField128bGhash, Field};
use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::Challenger};
use hachi_pcs::protocol::commitment::presets::fp128;
use hachi_pcs::protocol::hachi_poly_ops::{DensePoly, OneHotPoly};
use hachi_pcs::{CanonicalField, FieldCore, FromSmallInt};

use crate::{channel::Error, hachi_wire};

/// Binius64's current scalar field for IOP oracle relations.
pub type BiniusScalar = BinaryField128bGhash;

/// Hachi's default 128-bit prime field preset.
pub type HachiScalar = fp128::Field;

/// Number of Boolean coordinates in one Binius scalar.
pub const BINIUS_SCALAR_BITS: usize = 128;

/// Evaluations of the 128 bit-slice multilinears for one Binius oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitSliceOracle {
	/// `bit_polys[j][i]` is bit `j` of oracle element `i`, embedded in Hachi's field.
	pub bit_polys: Vec<Vec<HachiScalar>>,
}

impl BitSliceOracle {
	/// Build bit-slice polynomial evaluation tables from Binius oracle values.
	pub fn from_binius_oracle(oracle: &[BiniusScalar]) -> Self {
		let mut bit_polys = vec![vec![HachiScalar::from_u64(0); oracle.len()]; BINIUS_SCALAR_BITS];
		for (i, &value) in oracle.iter().enumerate() {
			for (bit, poly) in bit_polys.iter_mut().enumerate() {
				poly[i] = HachiScalar::from_u64(bit_at(value, bit));
			}
		}
		Self { bit_polys }
	}

	/// Number of oracle elements.
	pub fn len(&self) -> usize {
		self.bit_polys.first().map_or(0, Vec::len)
	}

	/// Returns true when there are no oracle elements.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Convert bit-slice evaluation tables into Hachi dense polynomials.
	pub fn to_dense_polys<const D: usize>(
		&self,
	) -> Result<Vec<DensePoly<HachiScalar, D>>, hachi_pcs::HachiError> {
		let num_vars = self.len().trailing_zeros() as usize;
		self.bit_polys
			.iter()
			.map(|evals| DensePoly::<HachiScalar, D>::from_field_evals(num_vars, evals))
			.collect()
	}

	/// Flatten to one bit-table MLE with index `(oracle_index, bit_index)`.
	pub fn to_bit_table_evals(&self) -> Vec<HachiScalar> {
		let len = self.len();
		let mut evals = Vec::with_capacity(len * BINIUS_SCALAR_BITS);
		for i in 0..len {
			for bit in 0..BINIUS_SCALAR_BITS {
				evals.push(self.bit_polys[bit][i]);
			}
		}
		evals
	}

	/// Convert the flattened bit table into one Hachi dense polynomial.
	pub fn to_bit_table_dense_poly<const D: usize>(
		&self,
	) -> Result<DensePoly<HachiScalar, D>, hachi_pcs::HachiError> {
		let num_vars = self.len().trailing_zeros() as usize + 7;
		DensePoly::<HachiScalar, D>::from_field_evals(num_vars, &self.to_bit_table_evals())
	}

	/// Convert bit table to a 1-of-2 Hachi one-hot polynomial.
	///
	/// The extra least-significant variable selects `(1 - bit, bit)`, so opening
	/// this polynomial at `point || 1` recovers the bit-table MLE at `point`.
	pub fn to_onehot_bit_table_poly<const D: usize>(
		&self,
	) -> Result<OneHotPoly<HachiScalar, D, u8>, hachi_pcs::HachiError> {
		let indices = self
			.to_bit_table_evals()
			.into_iter()
			.map(|bit| {
				if bit == HachiScalar::from_u64(0) {
					Some(0u8)
				} else {
					Some(1u8)
				}
			})
			.collect();
		OneHotPoly::<HachiScalar, D, u8>::new(2, indices)
	}
}

/// Degree-2 product-sumcheck proof over Hachi's field.
///
/// This proves claims of the form `sum_x sum_j A_j(x) * B_j(x) = claim`.
/// The final equality must be discharged by opening all multilinears at the
/// verifier challenges and checking `claim_final = sum_j A_j(r) * B_j(r)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductSumcheckProof {
	/// Each round stores `q(0), q(1), q(2)` for the quadratic round polynomial.
	pub round_evals: Vec<[HachiScalar; 3]>,
}

impl ProductSumcheckProof {
	/// Verify sumcheck round consistency and return the final claim.
	pub fn verify_rounds(
		&self,
		initial_claim: HachiScalar,
		challenges: &[HachiScalar],
	) -> Result<HachiScalar, BatchedParityBridgeError> {
		if self.round_evals.len() != challenges.len() {
			return Err(BatchedParityBridgeError::InvalidSumcheck);
		}

		let mut claim = initial_claim;
		for (&round, &challenge) in self.round_evals.iter().zip(challenges) {
			if round[0] + round[1] != claim {
				return Err(BatchedParityBridgeError::InvalidSumcheck);
			}
			claim = evaluate_quadratic_from_0_1_2(round, challenge);
		}
		Ok(claim)
	}
}

/// Prove a product-sumcheck for multilinears with equal power-of-two lengths.
pub fn prove_product_sumcheck(
	lefts: &[Vec<HachiScalar>],
	rights: &[Vec<HachiScalar>],
	challenges: &[HachiScalar],
) -> Result<
	(HachiScalar, ProductSumcheckProof, Vec<HachiScalar>, Vec<HachiScalar>),
	BatchedParityBridgeError,
> {
	validate_product_inputs(lefts, rights)?;

	let len = lefts[0].len();
	let log_len = len.trailing_zeros() as usize;
	if challenges.len() != log_len {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}

	let mut lefts = lefts.to_vec();
	let mut rights = rights.to_vec();
	let initial_claim = product_sum(&lefts, &rights);
	let mut round_evals = Vec::with_capacity(log_len);

	for &challenge in challenges {
		let round = product_round_evals(&lefts, &rights);
		round_evals.push(round);
		for poly in &mut lefts {
			fold_evals(poly, challenge);
		}
		for poly in &mut rights {
			fold_evals(poly, challenge);
		}
	}

	let final_lefts = lefts.into_iter().map(|poly| poly[0]).collect();
	let final_rights = rights.into_iter().map(|poly| poly[0]).collect();
	Ok((initial_claim, ProductSumcheckProof { round_evals }, final_lefts, final_rights))
}

fn validate_product_inputs(
	lefts: &[Vec<HachiScalar>],
	rights: &[Vec<HachiScalar>],
) -> Result<(), BatchedParityBridgeError> {
	if lefts.len() != rights.len() || lefts.is_empty() {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}
	let len = lefts[0].len();
	if !len.is_power_of_two()
		|| lefts.iter().any(|poly| poly.len() != len)
		|| rights.iter().any(|poly| poly.len() != len)
	{
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}
	Ok(())
}

/// Construct the selected-bit masks batched by `alpha`.
pub fn batched_selected_sum_masks(
	transparent: &[BiniusScalar],
	alpha: HachiScalar,
) -> Vec<Vec<HachiScalar>> {
	let alpha_powers = powers(alpha, BINIUS_SCALAR_BITS);
	let mut masks = vec![vec![HachiScalar::from_u64(0); transparent.len()]; BINIUS_SCALAR_BITS];
	for (i, &coefficient) in transparent.iter().enumerate() {
		for (input_bit, mask_poly) in masks.iter_mut().enumerate() {
			let basis = BiniusScalar::new(1u128 << input_bit);
			let product = coefficient * basis;
			let mut mask_value = HachiScalar::from_u64(0);
			for output_bit in 0..BINIUS_SCALAR_BITS {
				if bit_at(product, output_bit) == 1 {
					mask_value += alpha_powers[output_bit];
				}
			}
			mask_poly[i] = mask_value;
		}
	}
	masks
}

/// Construct one selected-bit mask over the flattened `(oracle_index, bit_index)` table.
pub fn batched_selected_sum_table_mask(
	transparent: &[BiniusScalar],
	alpha: HachiScalar,
) -> Vec<HachiScalar> {
	let alpha_powers = powers(alpha, BINIUS_SCALAR_BITS);
	let mut mask = Vec::with_capacity(transparent.len() * BINIUS_SCALAR_BITS);
	for &coefficient in transparent {
		for input_bit in 0..BINIUS_SCALAR_BITS {
			mask.push(selected_sum_mask_value(coefficient, input_bit, &alpha_powers));
		}
	}
	mask
}

/// Evaluate the flattened selected-bit mask without materializing its full table.
pub fn evaluate_batched_selected_sum_table_mask(
	transparent: &[BiniusScalar],
	alpha: HachiScalar,
	point: &[HachiScalar],
) -> Result<HachiScalar, BatchedParityBridgeError> {
	if point.len() < 7 {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}

	let log_transparent_len = point.len() - 7;
	let expected_len = 1usize
		.checked_shl(log_transparent_len as u32)
		.ok_or(BatchedParityBridgeError::InvalidSumcheck)?;
	if transparent.len() != expected_len {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}

	let alpha_powers = powers(alpha, BINIUS_SCALAR_BITS);
	let bit_eq_evals = multilinear_eq_evals(&point[..7]);
	let transparent_eq_evals = multilinear_eq_evals(&point[7..]);
	let mut eval = HachiScalar::from_u64(0);
	for (&coefficient, &transparent_eq) in transparent.iter().zip(&transparent_eq_evals) {
		let mut coefficient_eval = HachiScalar::from_u64(0);
		for (input_bit, &bit_eq) in bit_eq_evals.iter().enumerate() {
			coefficient_eval +=
				bit_eq * selected_sum_mask_value(coefficient, input_bit, &alpha_powers);
		}
		eval += transparent_eq * coefficient_eval;
	}
	Ok(eval)
}

/// Compute `sum_k alpha^k values[k]`.
pub fn batched_u64_sum(values: &[u64; BINIUS_SCALAR_BITS], alpha: HachiScalar) -> HachiScalar {
	let mut alpha_power = HachiScalar::from_u64(1);
	let mut sum = HachiScalar::from_u64(0);
	for &value in values {
		sum += alpha_power * HachiScalar::from_u64(value);
		alpha_power *= alpha;
	}
	sum
}

/// Build the Booleanity product-sumcheck input for bit-slice polynomials.
pub fn booleanity_sumcheck_inputs(
	bit_slices: &BitSliceOracle,
) -> (Vec<Vec<HachiScalar>>, Vec<Vec<HachiScalar>>) {
	let lefts = bit_slices.bit_polys.clone();
	let rights = bit_slices
		.bit_polys
		.iter()
		.map(|poly| {
			poly.iter()
				.map(|&bit| bit - HachiScalar::from_u64(1))
				.collect()
		})
		.collect();
	(lefts, rights)
}

/// Build Booleanity product inputs for one flattened bit-table polynomial.
pub fn booleanity_table_sumcheck_inputs(
	bit_table: &[HachiScalar],
) -> (Vec<Vec<HachiScalar>>, Vec<Vec<HachiScalar>>) {
	(
		vec![bit_table.to_vec()],
		vec![
			bit_table
				.iter()
				.map(|&bit| bit - HachiScalar::from_u64(1))
				.collect(),
		],
	)
}

/// Prove a product sumcheck with Fiat-Shamir challenges from the Binius transcript.
pub fn prove_product_sumcheck_transcript<Challenger_>(
	lefts: &[Vec<HachiScalar>],
	rights: &[Vec<HachiScalar>],
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<
	(HachiScalar, ProductSumcheckProof, Vec<HachiScalar>, Vec<HachiScalar>, Vec<HachiScalar>),
	BatchedParityBridgeError,
>
where
	Challenger_: Challenger,
{
	validate_product_inputs(lefts, rights)?;
	let mut lefts = lefts.to_vec();
	let mut rights = rights.to_vec();
	let initial_claim = product_sum(&lefts, &rights);
	hachi_wire::write_hachi(transcript, &initial_claim);

	let log_len = lefts[0].len().trailing_zeros() as usize;
	let mut round_evals = Vec::with_capacity(log_len);
	let mut challenges = Vec::with_capacity(log_len);
	for _ in 0..log_len {
		let round = product_round_evals(&lefts, &rights);
		for value in &round {
			hachi_wire::write_hachi(transcript, value);
		}
		let challenge = hachi_wire::sample_hachi_scalar(transcript);
		challenges.push(challenge);
		for poly in &mut lefts {
			fold_evals(poly, challenge);
		}
		for poly in &mut rights {
			fold_evals(poly, challenge);
		}
		round_evals.push(round);
	}

	Ok((
		initial_claim,
		ProductSumcheckProof { round_evals },
		challenges,
		lefts.into_iter().map(|poly| poly[0]).collect(),
		rights.into_iter().map(|poly| poly[0]).collect(),
	))
}

/// Verify a product sumcheck from a Binius transcript and return challenges plus final claim.
pub fn verify_product_sumcheck_transcript<Challenger_>(
	expected_initial_claim: HachiScalar,
	num_rounds: usize,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(ProductSumcheckProof, Vec<HachiScalar>, HachiScalar), Error>
where
	Challenger_: Challenger,
{
	let initial_claim = hachi_wire::read_hachi::<HachiScalar, _>(transcript, &())?;
	if initial_claim != expected_initial_claim {
		return Err(Error::ProofEmpty);
	}

	let mut claim = initial_claim;
	let mut round_evals = Vec::with_capacity(num_rounds);
	let mut challenges = Vec::with_capacity(num_rounds);
	for _ in 0..num_rounds {
		let round = [
			hachi_wire::read_hachi::<HachiScalar, _>(transcript, &())?,
			hachi_wire::read_hachi::<HachiScalar, _>(transcript, &())?,
			hachi_wire::read_hachi::<HachiScalar, _>(transcript, &())?,
		];
		if round[0] + round[1] != claim {
			return Err(Error::ProofEmpty);
		}
		let challenge = hachi_wire::verify_sample_hachi_scalar(transcript);
		claim = evaluate_quadratic_from_0_1_2(round, challenge);
		round_evals.push(round);
		challenges.push(challenge);
	}
	Ok((ProductSumcheckProof { round_evals }, challenges, claim))
}

/// Canonical `u128` lift from the Binius binary field to Hachi's prime field.
///
/// This is useful for diagnostics and for constructing Hachi test polynomials,
/// but it is not a field homomorphism and must not be used as a verifier-accepted
/// replacement for BaseFold openings.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalU128Bridge;

impl CanonicalU128Bridge {
	/// Lift one Binius scalar into Hachi's prime field using its raw canonical bits.
	pub fn lift(value: BiniusScalar) -> HachiScalar {
		HachiScalar::from_canonical_u128_reduced(value.val())
	}

	/// Lift a slice of Binius scalars into Hachi's prime field.
	pub fn lift_slice(values: &[BiniusScalar]) -> Vec<HachiScalar> {
		values.iter().copied().map(Self::lift).collect()
	}

	/// Returns the first algebraic obstruction that prevents using this lift as a
	/// strict PCS bridge.
	pub fn strict_pcs_obstruction() -> Option<BridgeObstruction> {
		let one = BiniusScalar::new(1);
		if Self::lift(one + one) != Self::lift(one) + Self::lift(one) {
			return Some(BridgeObstruction::NotAdditive);
		}

		let generator = BiniusScalar::MULTIPLICATIVE_GENERATOR;
		if Self::lift(generator * generator) != Self::lift(generator) * Self::lift(generator) {
			return Some(BridgeObstruction::NotMultiplicative);
		}

		None
	}
}

/// Batched parity proof for one terminal Binius linear-opening claim.
///
/// For a Binius claim `y = sum_i t_i * w_i`, each output bit is a parity of
/// selected witness bits. This proof carries the integer openings `S_k` of
/// those selected-bit sums. Since the verifier range-checks each `S_k`, it can
/// check `S_k mod 2 == y_k` directly and does not need quotient witnesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedParityBridgeProof {
	/// Integer selected-bit sums, one per output bit.
	pub opened_sums: [u64; BINIUS_SCALAR_BITS],
}

impl BatchedParityBridgeProof {
	/// Verify the 128 parity equations using public integer bounds.
	///
	/// Soundness relies on `opened_sums[k]` being range checked against public bounds. Once
	/// bounded, equality modulo 2 is an exact integer parity check, so no quotient payload is
	/// required.
	pub fn verify(
		&self,
		transparent: &[BiniusScalar],
		claim: BiniusScalar,
	) -> Result<(), BatchedParityBridgeError> {
		let bounds = parity_sum_bounds(transparent)?;
		for (bit, (&sum, &bound)) in self.opened_sums.iter().zip(&bounds).enumerate() {
			if sum > bound {
				return Err(BatchedParityBridgeError::SumOutOfRange { bit, sum, bound });
			}

			if (sum & 1) != bit_at(claim, bit) {
				return Err(BatchedParityBridgeError::BatchedParityCheckFailed);
			}
		}

		Ok(())
	}
}

/// Errors returned by the batched parity bridge prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BatchedParityBridgeError {
	/// The committed oracle and transparent coefficient vectors differ in length.
	#[error("length mismatch: oracle has {oracle_len} elements, transparent has {transparent_len}")]
	LengthMismatch {
		/// Number of oracle values.
		oracle_len: usize,
		/// Number of transparent coefficients.
		transparent_len: usize,
	},
	/// A public parity-sum bound overflowed `u64`.
	#[error("parity-sum bound overflowed for bit {bit}")]
	BoundOverflow {
		/// Output bit whose bound overflowed.
		bit: usize,
	},
	/// An opened selected-bit sum exceeded its public bound.
	#[error("opened sum for bit {bit} is {sum}, above bound {bound}")]
	SumOutOfRange {
		/// Output bit.
		bit: usize,
		/// Opened selected-bit sum.
		sum: u64,
		/// Public upper bound.
		bound: u64,
	},
	/// An opened selected-bit sum had the wrong parity for the claimed Binius bit.
	#[error("batched parity check failed")]
	BatchedParityCheckFailed,
	/// Product-sumcheck proof is malformed or inconsistent.
	#[error("invalid product-sumcheck proof")]
	InvalidSumcheck,
}

/// Prove the terminal Binius linear claim using the batched parity bridge.
///
/// This prototype computes `opened_sums` directly from witness values. In the
/// full protocol, those same sums are Hachi opening claims against committed
/// bit-slice witness polynomials.
pub fn prove_terminal_linear_claim(
	oracle: &[BiniusScalar],
	transparent: &[BiniusScalar],
) -> Result<(BiniusScalar, BatchedParityBridgeProof), BatchedParityBridgeError> {
	if oracle.len() != transparent.len() {
		return Err(BatchedParityBridgeError::LengthMismatch {
			oracle_len: oracle.len(),
			transparent_len: transparent.len(),
		});
	}

	let claim = terminal_linear_claim(oracle, transparent);
	let opened_sums = parity_sums(oracle, transparent)?;
	for bit in 0..BINIUS_SCALAR_BITS {
		let claim_bit = bit_at(claim, bit);
		debug_assert_eq!(opened_sums[bit] & 1, claim_bit);
	}

	Ok((claim, BatchedParityBridgeProof { opened_sums }))
}

/// Compute the native Binius terminal linear-opening claim.
pub fn terminal_linear_claim(
	oracle: &[BiniusScalar],
	transparent: &[BiniusScalar],
) -> BiniusScalar {
	oracle
		.iter()
		.zip(transparent)
		.fold(BiniusScalar::new(0), |acc, (&w_i, &t_i)| acc + t_i * w_i)
}

/// Public upper bounds for each parity sum, derived only from transparent coefficients.
pub fn parity_sum_bounds(
	transparent: &[BiniusScalar],
) -> Result<[u64; BINIUS_SCALAR_BITS], BatchedParityBridgeError> {
	let mut bounds = [0u64; BINIUS_SCALAR_BITS];
	for &coefficient in transparent {
		for input_bit in 0..BINIUS_SCALAR_BITS {
			let basis = BiniusScalar::new(1u128 << input_bit);
			add_output_bits(&mut bounds, coefficient * basis)?;
		}
	}
	Ok(bounds)
}

fn parity_sums(
	oracle: &[BiniusScalar],
	transparent: &[BiniusScalar],
) -> Result<[u64; BINIUS_SCALAR_BITS], BatchedParityBridgeError> {
	let mut sums = [0u64; BINIUS_SCALAR_BITS];
	for (&w_i, &t_i) in oracle.iter().zip(transparent) {
		let mut witness_bits = w_i.val();
		while witness_bits != 0 {
			let input_bit = witness_bits.trailing_zeros() as usize;
			let basis = BiniusScalar::new(1u128 << input_bit);
			add_output_bits(&mut sums, t_i * basis)?;
			witness_bits &= witness_bits - 1;
		}
	}
	Ok(sums)
}

fn add_output_bits(
	accumulator: &mut [u64; BINIUS_SCALAR_BITS],
	value: BiniusScalar,
) -> Result<(), BatchedParityBridgeError> {
	let mut output_bits = value.val();
	while output_bits != 0 {
		let output_bit = output_bits.trailing_zeros() as usize;
		accumulator[output_bit] = accumulator[output_bit]
			.checked_add(1)
			.ok_or(BatchedParityBridgeError::BoundOverflow { bit: output_bit })?;
		output_bits &= output_bits - 1;
	}
	Ok(())
}

fn bit_at(value: BiniusScalar, bit: usize) -> u64 {
	((value.val() >> bit) & 1) as u64
}

fn selected_sum_mask_value(
	coefficient: BiniusScalar,
	input_bit: usize,
	alpha_powers: &[HachiScalar],
) -> HachiScalar {
	let basis = BiniusScalar::new(1u128 << input_bit);
	let mut output_bits = (coefficient * basis).val();
	let mut mask_value = HachiScalar::from_u64(0);
	while output_bits != 0 {
		let output_bit = output_bits.trailing_zeros() as usize;
		mask_value += alpha_powers[output_bit];
		output_bits &= output_bits - 1;
	}
	mask_value
}

fn powers(base: HachiScalar, len: usize) -> Vec<HachiScalar> {
	let mut powers = Vec::with_capacity(len);
	let mut current = HachiScalar::from_u64(1);
	for _ in 0..len {
		powers.push(current);
		current *= base;
	}
	powers
}

fn multilinear_eq_evals(point: &[HachiScalar]) -> Vec<HachiScalar> {
	let mut evals = vec![HachiScalar::from_u64(1)];
	for &coordinate in point {
		let len = evals.len();
		let one_minus_coordinate = HachiScalar::from_u64(1) - coordinate;
		for index in 0..len {
			let value = evals[index];
			evals[index] = value * one_minus_coordinate;
			evals.push(value * coordinate);
		}
	}
	evals
}

fn product_sum(lefts: &[Vec<HachiScalar>], rights: &[Vec<HachiScalar>]) -> HachiScalar {
	lefts
		.iter()
		.zip(rights)
		.flat_map(|(left, right)| left.iter().zip(right))
		.fold(HachiScalar::from_u64(0), |acc, (&left, &right)| acc + left * right)
}

fn product_round_evals(
	lefts: &[Vec<HachiScalar>],
	rights: &[Vec<HachiScalar>],
) -> [HachiScalar; 3] {
	let two = HachiScalar::from_u64(2);
	let mut evals = [HachiScalar::from_u64(0); 3];
	for (left, right) in lefts.iter().zip(rights) {
		for (left_pair, right_pair) in left.chunks_exact(2).zip(right.chunks_exact(2)) {
			let left0 = left_pair[0];
			let left1 = left_pair[1];
			let right0 = right_pair[0];
			let right1 = right_pair[1];
			evals[0] += left0 * right0;
			evals[1] += left1 * right1;
			let left2 = left0 + two * (left1 - left0);
			let right2 = right0 + two * (right1 - right0);
			evals[2] += left2 * right2;
		}
	}
	evals
}

fn fold_evals(evals: &mut Vec<HachiScalar>, challenge: HachiScalar) {
	let half = evals.len() / 2;
	for i in 0..half {
		evals[i] = evals[2 * i] + challenge * (evals[2 * i + 1] - evals[2 * i]);
	}
	evals.truncate(half);
}

fn evaluate_quadratic_from_0_1_2(evals: [HachiScalar; 3], x: HachiScalar) -> HachiScalar {
	let two = HachiScalar::from_u64(2);
	let inv_two = two
		.inv()
		.expect("2 is invertible in Hachi's odd prime field");
	let c0 = evals[0];
	let c2 = (evals[2] - two * evals[1] + evals[0]) * inv_two;
	let c1 = evals[1] - c0 - c2;
	c0 + c1 * x + c2 * x * x
}

/// Why the current Hachi adapter cannot yet be wired as a strict PCS backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeObstruction {
	/// Binary-field addition is XOR, while Hachi `fp128` addition is prime-field addition.
	NotAdditive,
	/// Binary-field multiplication and Hachi `fp128` multiplication are different operations.
	NotMultiplicative,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn canonical_lift_is_not_additive() {
		let one = BiniusScalar::new(1);

		assert_eq!(one + one, BiniusScalar::new(0));
		assert_ne!(
			CanonicalU128Bridge::lift(one + one),
			CanonicalU128Bridge::lift(one) + CanonicalU128Bridge::lift(one)
		);
	}

	#[test]
	fn strict_pcs_bridge_reports_obstruction() {
		assert_eq!(
			CanonicalU128Bridge::strict_pcs_obstruction(),
			Some(BridgeObstruction::NotAdditive)
		);
	}

	#[test]
	fn lifted_linear_claims_are_not_binary_field_claims() {
		let a = [BiniusScalar::new(1), BiniusScalar::new(1)];
		let b = [BiniusScalar::new(1), BiniusScalar::new(1)];

		let binary_claim = a[0] * b[0] + a[1] * b[1];
		let lifted_claim = CanonicalU128Bridge::lift(a[0]) * CanonicalU128Bridge::lift(b[0])
			+ CanonicalU128Bridge::lift(a[1]) * CanonicalU128Bridge::lift(b[1]);

		assert_eq!(binary_claim, BiniusScalar::new(0));
		assert_ne!(CanonicalU128Bridge::lift(binary_claim), lifted_claim);
	}

	#[test]
	fn batched_parity_bridge_verifies_terminal_claim() {
		let oracle = [
			BiniusScalar::new(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210),
			BiniusScalar::new(0xffff_0000_5555_aaaa_1234_5678_9abc_def0),
			BiniusScalar::new(0x0000_0000_0000_0001_8000_0000_0000_0000),
		];
		let transparent = [
			BiniusScalar::new(0x1111_2222_3333_4444_5555_6666_7777_8888),
			BiniusScalar::new(0xdead_beef_cafe_babe_0102_0304_0506_0708),
			BiniusScalar::new(0x494e_f997_94d5_244f_9152_df59_d87a_9186),
		];

		let (claim, proof) = prove_terminal_linear_claim(&oracle, &transparent).unwrap();
		assert_eq!(claim, terminal_linear_claim(&oracle, &transparent));
		proof.verify(&transparent, claim).unwrap();
	}

	#[test]
	fn batched_parity_bridge_rejects_tampered_sum() {
		let oracle = [BiniusScalar::new(1), BiniusScalar::new(2)];
		let transparent = [BiniusScalar::new(3), BiniusScalar::new(5)];
		let (claim, mut proof) = prove_terminal_linear_claim(&oracle, &transparent).unwrap();

		proof.opened_sums[0] += 1;

		assert_eq!(
			proof.verify(&transparent, claim),
			Err(BatchedParityBridgeError::BatchedParityCheckFailed)
		);
	}

	#[test]
	fn batched_parity_bridge_rejects_out_of_range_sum() {
		let oracle = [BiniusScalar::new(1)];
		let transparent = [BiniusScalar::new(0)];
		let (claim, mut proof) = prove_terminal_linear_claim(&oracle, &transparent).unwrap();

		proof.opened_sums[0] = 1;

		assert_eq!(
			proof.verify(&transparent, claim),
			Err(BatchedParityBridgeError::SumOutOfRange {
				bit: 0,
				sum: 1,
				bound: 0
			})
		);
	}

	#[test]
	fn terminal_claim_length_mismatch_is_rejected() {
		assert_eq!(
			prove_terminal_linear_claim(&[BiniusScalar::new(1)], &[]),
			Err(BatchedParityBridgeError::LengthMismatch {
				oracle_len: 1,
				transparent_len: 0
			})
		);
	}

	#[test]
	fn selected_sum_product_sumcheck_matches_batched_sums() {
		let oracle = [
			BiniusScalar::new(0x0123_4567_89ab_cdef),
			BiniusScalar::new(0xfedc_ba98_7654_3210),
			BiniusScalar::new(0x1111_2222_3333_4444),
			BiniusScalar::new(0x9999_aaaa_bbbb_cccc),
		];
		let transparent = [
			BiniusScalar::new(0x1234),
			BiniusScalar::new(0x5678),
			BiniusScalar::new(0x9abc),
			BiniusScalar::new(0xdef0),
		];
		let (claim, parity_proof) = prove_terminal_linear_claim(&oracle, &transparent).unwrap();
		let alpha = HachiScalar::from_u64(17);
		let bit_slices = BitSliceOracle::from_binius_oracle(&oracle);
		let masks = batched_selected_sum_masks(&transparent, alpha);
		let expected_batched_sum = batched_u64_sum(&parity_proof.opened_sums, alpha);

		let challenges = [HachiScalar::from_u64(3), HachiScalar::from_u64(5)];
		let (sumcheck_claim, proof, final_lefts, final_rights) =
			prove_product_sumcheck(&bit_slices.bit_polys, &masks, &challenges).unwrap();

		assert_eq!(sumcheck_claim, expected_batched_sum);
		let final_claim = proof.verify_rounds(sumcheck_claim, &challenges).unwrap();
		let final_opening_claim = final_lefts
			.iter()
			.zip(&final_rights)
			.fold(HachiScalar::from_u64(0), |acc, (&left, &right)| acc + left * right);
		assert_eq!(final_claim, final_opening_claim);
		parity_proof.verify(&transparent, claim).unwrap();
	}

	#[test]
	fn booleanity_product_sumcheck_accepts_bit_slices() {
		let oracle = [
			BiniusScalar::new(0),
			BiniusScalar::new(1),
			BiniusScalar::new(u128::MAX),
			BiniusScalar::new(0xfeed_face),
		];
		let bit_slices = BitSliceOracle::from_binius_oracle(&oracle);
		let (lefts, rights) = booleanity_sumcheck_inputs(&bit_slices);
		let challenges = [HachiScalar::from_u64(19), HachiScalar::from_u64(23)];
		let (claim, proof, final_lefts, final_rights) =
			prove_product_sumcheck(&lefts, &rights, &challenges).unwrap();

		assert_eq!(claim, HachiScalar::from_u64(0));
		let final_claim = proof.verify_rounds(claim, &challenges).unwrap();
		let final_opening_claim = final_lefts
			.iter()
			.zip(&final_rights)
			.fold(HachiScalar::from_u64(0), |acc, (&left, &right)| acc + left * right);
		assert_eq!(final_claim, final_opening_claim);
	}

	#[test]
	fn booleanity_product_sumcheck_rejects_non_boolean_slice() {
		let oracle = [BiniusScalar::new(0), BiniusScalar::new(1)];
		let mut bit_slices = BitSliceOracle::from_binius_oracle(&oracle);
		bit_slices.bit_polys[0][0] = HachiScalar::from_u64(2);
		let (lefts, rights) = booleanity_sumcheck_inputs(&bit_slices);
		let challenges = [HachiScalar::from_u64(29)];
		let (claim, proof, final_lefts, final_rights) =
			prove_product_sumcheck(&lefts, &rights, &challenges).unwrap();

		assert_ne!(claim, HachiScalar::from_u64(0));
		let final_claim = proof.verify_rounds(claim, &challenges).unwrap();
		let final_opening_claim = final_lefts
			.iter()
			.zip(&final_rights)
			.fold(HachiScalar::from_u64(0), |acc, (&left, &right)| acc + left * right);
		assert_eq!(final_claim, final_opening_claim);
	}

	#[test]
	fn hachi_batched_opening_round_trips_bit_slices() {
		use hachi_pcs::algebra::poly::multilinear_eval;
		use hachi_pcs::protocol::commitment::presets::fp128;
		use hachi_pcs::protocol::commitment_scheme::HachiCommitmentScheme;
		use hachi_pcs::protocol::transcript::Blake2bTranscript;
		use hachi_pcs::{BasisMode, CommitmentScheme, Transcript};

		type Cfg = fp128::D128Full;
		const D: usize = 128;
		type Scheme = HachiCommitmentScheme<D, Cfg>;

		let oracle = (0..128)
			.map(|i| BiniusScalar::new((i as u128) * 0x0101_0101_0101_0101))
			.collect::<Vec<_>>();
		let bit_slices = BitSliceOracle::from_binius_oracle(&oracle);
		let polys = bit_slices.to_dense_polys::<D>().unwrap();
		let point = vec![
			HachiScalar::from_u64(7),
			HachiScalar::from_u64(11),
			HachiScalar::from_u64(13),
			HachiScalar::from_u64(17),
			HachiScalar::from_u64(19),
			HachiScalar::from_u64(23),
			HachiScalar::from_u64(29),
		];
		let openings = bit_slices
			.bit_polys
			.iter()
			.map(|evals| multilinear_eval(evals, &point).unwrap())
			.collect::<Vec<_>>();

		let setup = <Scheme as CommitmentScheme<HachiScalar, D>>::setup_prover(14, 128, 1);
		let verifier_setup = <Scheme as CommitmentScheme<HachiScalar, D>>::setup_verifier(&setup);
		let mut commitments = Vec::with_capacity(polys.len());
		let mut hints = Vec::with_capacity(polys.len());
		for poly in &polys {
			let (commitment, hint) = <Scheme as CommitmentScheme<HachiScalar, D>>::commit(
				std::slice::from_ref(poly),
				&setup,
			)
			.unwrap();
			commitments.push(commitment);
			hints.push(hint);
		}

		let poly_refs = polys.iter().map(|poly| [poly]).collect::<Vec<_>>();
		let poly_groups = poly_refs.iter().map(|group| &group[..]).collect::<Vec<_>>();
		let opening_values = openings
			.iter()
			.map(|opening| [*opening])
			.collect::<Vec<_>>();
		let opening_groups = opening_values
			.iter()
			.map(|group| &group[..])
			.collect::<Vec<_>>();
		let mut prover_transcript = Blake2bTranscript::<HachiScalar>::new(b"bit_slices");
		let proof = <Scheme as CommitmentScheme<HachiScalar, D>>::batched_prove(
			&setup,
			&[&poly_groups[..]],
			&[&point[..]],
			vec![hints],
			&mut prover_transcript,
			&[&commitments[..]],
			BasisMode::Lagrange,
		)
		.unwrap();

		let mut verifier_transcript = Blake2bTranscript::<HachiScalar>::new(b"bit_slices");
		<Scheme as CommitmentScheme<HachiScalar, D>>::batched_verify(
			&proof,
			&verifier_setup,
			&mut verifier_transcript,
			&[&point[..]],
			&[&opening_groups[..]],
			&[&commitments[..]],
			BasisMode::Lagrange,
		)
		.unwrap();
	}

	#[test]
	fn bit_table_product_sumchecks_reduce_to_single_opening() {
		let oracle = (0..8)
			.map(|i| BiniusScalar::new((i as u128) * 0x101))
			.collect::<Vec<_>>();
		let transparent = (0..8)
			.map(|i| BiniusScalar::new((3 * i as u128) + 1))
			.collect::<Vec<_>>();
		let bit_slices = BitSliceOracle::from_binius_oracle(&oracle);
		let bit_table = bit_slices.to_bit_table_evals();
		let (_claim, parity) = prove_terminal_linear_claim(&oracle, &transparent).unwrap();
		let alpha = HachiScalar::from_u64(31);
		let selected_mask = batched_selected_sum_table_mask(&transparent, alpha);
		let selected_claim = batched_u64_sum(&parity.opened_sums, alpha);
		let challenges = (0..10)
			.map(|i| HachiScalar::from_u64(37 + i as u64))
			.collect::<Vec<_>>();
		let (claim, proof, left, right) =
			prove_product_sumcheck(&[bit_table.clone()], &[selected_mask], &challenges).unwrap();
		assert_eq!(claim, selected_claim);
		assert_eq!(proof.verify_rounds(claim, &challenges).unwrap(), left[0] * right[0]);

		let (bool_lefts, bool_rights) = booleanity_table_sumcheck_inputs(&bit_table);
		let (bool_claim, bool_proof, bool_left, bool_right) =
			prove_product_sumcheck(&bool_lefts, &bool_rights, &challenges).unwrap();
		assert_eq!(bool_claim, HachiScalar::from_u64(0));
		assert_eq!(
			bool_proof.verify_rounds(bool_claim, &challenges).unwrap(),
			bool_left[0] * bool_right[0]
		);
	}

	#[test]
	fn selected_table_mask_lazy_eval_matches_materialized() {
		use hachi_pcs::algebra::poly::multilinear_eval;

		let transparent = (0..8)
			.map(|i| {
				BiniusScalar::new(((i as u128) + 1) * 0x0101_0203_0508_0d15_2237_5990_e979_62db)
			})
			.collect::<Vec<_>>();
		let alpha = HachiScalar::from_u64(43);
		let point = (0..10)
			.map(|i| HachiScalar::from_u64(47 + i as u64))
			.collect::<Vec<_>>();

		let selected_mask = batched_selected_sum_table_mask(&transparent, alpha);
		let expected = multilinear_eval(&selected_mask, &point).unwrap();
		let actual = evaluate_batched_selected_sum_table_mask(&transparent, alpha, &point).unwrap();

		assert_eq!(actual, expected);
	}
}
