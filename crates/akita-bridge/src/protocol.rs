// Copyright 2026 The Binius Developers

//! Experimental bridge boundary for a Akita-backed PCS.
//!
//! Binius64's IOP oracle relations are stated over the binary tower field
//! [`BinaryField128bGhash`]. The local Akita implementation works over its
//! `fp128` prime field preset. This module deliberately exposes only the
//! canonical integer lift and the reason it is not yet a sound PCS replacement.

use binius_field::{BinaryField128bGhash, Field};
use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::Challenger};

use akita_config::proof_optimized::fp128;
use akita_field::{AkitaError, CanonicalField};
use akita_prover::{DensePoly, OneHotPoly};

use binius_iop::channel::Error;

use crate::wire;

/// Binius64's current scalar field for IOP oracle relations.
pub type BiniusScalar = BinaryField128bGhash;

/// Akita's default 128-bit prime field preset.
pub type AkitaFieldScalar = fp128::Field;

/// Number of Boolean coordinates in one Binius scalar.
pub const BINIUS_SCALAR_BITS: usize = 128;

/// Verifier-owned structured transparent relation for the Akita succinct bridge.
///
/// Implementations must derive every value from public verifier state. The prover must not choose
/// the results of these methods, because they replace full transparent-table scans in the bridge
/// soundness checks.
pub trait StructuredTransparentRelation {
	/// Log2 of the number of Binius coefficients in the relation.
	fn log_len(&self) -> usize;

	/// Evaluates the Binius multilinear extension of the transparent relation.
	fn eval_binius(&self, point: &[BiniusScalar])
	-> Result<BiniusScalar, BatchedParityBridgeError>;

	/// Public upper bounds for each selected-bit parity sum.
	fn parity_sum_bounds(&self) -> Result<[u64; BINIUS_SCALAR_BITS], BatchedParityBridgeError>;

	/// Evaluates the Akita-field multilinear extension of the batched selected-bit mask.
	fn eval_selected_mask(
		&self,
		alpha: AkitaFieldScalar,
		point: &[AkitaFieldScalar],
	) -> Result<AkitaFieldScalar, BatchedParityBridgeError>;
}

/// Structured relation for a constant transparent table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstantTransparentRelation {
	log_len: usize,
	coefficient: BiniusScalar,
}

impl ConstantTransparentRelation {
	/// Creates a relation with `2^log_len` copies of `coefficient`.
	pub fn new(log_len: usize, coefficient: BiniusScalar) -> Self {
		Self {
			log_len,
			coefficient,
		}
	}
}

impl StructuredTransparentRelation for ConstantTransparentRelation {
	fn log_len(&self) -> usize {
		self.log_len
	}

	fn eval_binius(
		&self,
		point: &[BiniusScalar],
	) -> Result<BiniusScalar, BatchedParityBridgeError> {
		if point.len() != self.log_len {
			return Err(BatchedParityBridgeError::InvalidSumcheck);
		}
		Ok(self.coefficient)
	}

	fn parity_sum_bounds(&self) -> Result<[u64; BINIUS_SCALAR_BITS], BatchedParityBridgeError> {
		if self.log_len >= u64::BITS as usize {
			return Err(BatchedParityBridgeError::InvalidSumcheck);
		}
		let count = 1u64 << self.log_len;
		let mut bounds = [0u64; BINIUS_SCALAR_BITS];
		for input_bit in 0..BINIUS_SCALAR_BITS {
			let basis = BiniusScalar::new(1u128 << input_bit);
			add_output_bits_scaled(&mut bounds, self.coefficient * basis, count)?;
		}
		Ok(bounds)
	}

	fn eval_selected_mask(
		&self,
		alpha: AkitaFieldScalar,
		point: &[AkitaFieldScalar],
	) -> Result<AkitaFieldScalar, BatchedParityBridgeError> {
		let expected_point_len = self
			.log_len
			.checked_add(7)
			.ok_or(BatchedParityBridgeError::InvalidSumcheck)?;
		if point.len() != expected_point_len {
			return Err(BatchedParityBridgeError::InvalidSumcheck);
		}

		let alpha_powers = powers(alpha, BINIUS_SCALAR_BITS);
		let bit_eq_evals = multilinear_eq_evals(&point[..7]);
		let mut eval = AkitaFieldScalar::from_u64(0);
		for (input_bit, &bit_eq) in bit_eq_evals.iter().enumerate() {
			eval += bit_eq * selected_sum_mask_value(self.coefficient, input_bit, &alpha_powers);
		}
		Ok(eval)
	}
}

/// Evaluations of the 128 bit-slice multilinears for one Binius oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitSliceOracle {
	/// `bit_polys[j][i]` is bit `j` of oracle element `i`, embedded in Akita's field.
	pub bit_polys: Vec<Vec<AkitaFieldScalar>>,
}

impl BitSliceOracle {
	/// Build bit-slice polynomial evaluation tables from Binius oracle values.
	pub fn from_binius_oracle(oracle: &[BiniusScalar]) -> Self {
		let mut bit_polys = vec![vec![AkitaFieldScalar::from_u64(0); oracle.len()]; BINIUS_SCALAR_BITS];
		for (i, &value) in oracle.iter().enumerate() {
			for (bit, poly) in bit_polys.iter_mut().enumerate() {
				poly[i] = AkitaFieldScalar::from_u64(bit_at(value, bit));
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

	/// Convert bit-slice evaluation tables into Akita dense polynomials.
	pub fn to_dense_polys<const D: usize>(
		&self,
	) -> Result<Vec<DensePoly<AkitaFieldScalar, D>>, AkitaError> {
		let num_vars = self.len().trailing_zeros() as usize;
		self.bit_polys
			.iter()
			.map(|evals| DensePoly::<AkitaFieldScalar, D>::from_field_evals(num_vars, evals))
			.collect()
	}

	/// Flatten to one bit-table MLE with index `(oracle_index, bit_index)`.
	pub fn to_bit_table_evals(&self) -> Vec<AkitaFieldScalar> {
		let len = self.len();
		let mut evals = Vec::with_capacity(len * BINIUS_SCALAR_BITS);
		for i in 0..len {
			for bit in 0..BINIUS_SCALAR_BITS {
				evals.push(self.bit_polys[bit][i]);
			}
		}
		evals
	}

	/// Convert the flattened bit table into one Akita dense polynomial.
	pub fn to_bit_table_dense_poly<const D: usize>(
		&self,
	) -> Result<DensePoly<AkitaFieldScalar, D>, AkitaError> {
		let num_vars = self.len().trailing_zeros() as usize + 7;
		DensePoly::<AkitaFieldScalar, D>::from_field_evals(num_vars, &self.to_bit_table_evals())
	}

	/// Convert bit table to a 1-of-2 Akita one-hot polynomial.
	///
	/// The extra least-significant variable selects `(1 - bit, bit)`, so opening
	/// this polynomial at `point || 1` recovers the bit-table MLE at `point`.
	pub fn to_onehot_bit_table_poly<const D: usize>(
		&self,
	) -> Result<OneHotPoly<AkitaFieldScalar, D, u8>, AkitaError> {
		let indices = self
			.to_bit_table_evals()
			.into_iter()
			.map(|bit| {
				if bit == AkitaFieldScalar::from_u64(0) {
					Some(0u8)
				} else {
					Some(1u8)
				}
			})
			.collect();
		OneHotPoly::<AkitaFieldScalar, D, u8>::new(2, indices)
	}
}

/// Degree-2 product-sumcheck proof over Akita's field.
///
/// This proves claims of the form `sum_x sum_j A_j(x) * B_j(x) = claim`.
/// The final equality must be discharged by opening all multilinears at the
/// verifier challenges and checking `claim_final = sum_j A_j(r) * B_j(r)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductSumcheckProof {
	/// Each round stores `q(0), q(1), q(2)` for the quadratic round polynomial.
	pub round_evals: Vec<[AkitaFieldScalar; 3]>,
}

impl ProductSumcheckProof {
	/// Verify sumcheck round consistency and return the final claim.
	pub fn verify_rounds(
		&self,
		initial_claim: AkitaFieldScalar,
		challenges: &[AkitaFieldScalar],
	) -> Result<AkitaFieldScalar, BatchedParityBridgeError> {
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

/// Degree-3 sumcheck proof for weighted Booleanity.
///
/// This proves claims of the form `sum_x eq(rho, x) * B(x) * (B(x) - 1) = claim`.
/// The final equality must be discharged by opening `B` at the verifier challenges and
/// checking `claim_final = eq(rho, r) * B(r) * (B(r) - 1)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedBooleanitySumcheckProof {
	/// Each round stores `q(0), q(1), q(2), q(3)` for the cubic round polynomial.
	pub round_evals: Vec<[AkitaFieldScalar; 4]>,
}

impl WeightedBooleanitySumcheckProof {
	/// Verify sumcheck round consistency and return the final claim.
	pub fn verify_rounds(
		&self,
		initial_claim: AkitaFieldScalar,
		challenges: &[AkitaFieldScalar],
	) -> Result<AkitaFieldScalar, BatchedParityBridgeError> {
		if self.round_evals.len() != challenges.len() {
			return Err(BatchedParityBridgeError::InvalidSumcheck);
		}

		let mut claim = initial_claim;
		for (&round, &challenge) in self.round_evals.iter().zip(challenges) {
			if round[0] + round[1] != claim {
				return Err(BatchedParityBridgeError::InvalidSumcheck);
			}
			claim = evaluate_cubic_from_0_1_2_3(round, challenge);
		}
		Ok(claim)
	}
}

/// Prove a product-sumcheck for multilinears with equal power-of-two lengths.
pub fn prove_product_sumcheck(
	lefts: &[Vec<AkitaFieldScalar>],
	rights: &[Vec<AkitaFieldScalar>],
	challenges: &[AkitaFieldScalar],
) -> Result<
	(AkitaFieldScalar, ProductSumcheckProof, Vec<AkitaFieldScalar>, Vec<AkitaFieldScalar>),
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
	lefts: &[Vec<AkitaFieldScalar>],
	rights: &[Vec<AkitaFieldScalar>],
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
	alpha: AkitaFieldScalar,
) -> Vec<Vec<AkitaFieldScalar>> {
	let alpha_powers = powers(alpha, BINIUS_SCALAR_BITS);
	let mut masks = vec![vec![AkitaFieldScalar::from_u64(0); transparent.len()]; BINIUS_SCALAR_BITS];
	for (i, &coefficient) in transparent.iter().enumerate() {
		for (input_bit, mask_poly) in masks.iter_mut().enumerate() {
			let basis = BiniusScalar::new(1u128 << input_bit);
			let product = coefficient * basis;
			let mut mask_value = AkitaFieldScalar::from_u64(0);
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
	alpha: AkitaFieldScalar,
) -> Vec<AkitaFieldScalar> {
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
	alpha: AkitaFieldScalar,
	point: &[AkitaFieldScalar],
) -> Result<AkitaFieldScalar, BatchedParityBridgeError> {
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
	let mut eval = AkitaFieldScalar::from_u64(0);
	for (&coefficient, &transparent_eq) in transparent.iter().zip(&transparent_eq_evals) {
		let mut coefficient_eval = AkitaFieldScalar::from_u64(0);
		for (input_bit, &bit_eq) in bit_eq_evals.iter().enumerate() {
			coefficient_eval +=
				bit_eq * selected_sum_mask_value(coefficient, input_bit, &alpha_powers);
		}
		eval += transparent_eq * coefficient_eval;
	}
	Ok(eval)
}

/// Compute `sum_k alpha^k values[k]`.
pub fn batched_u64_sum(values: &[u64; BINIUS_SCALAR_BITS], alpha: AkitaFieldScalar) -> AkitaFieldScalar {
	let mut alpha_power = AkitaFieldScalar::from_u64(1);
	let mut sum = AkitaFieldScalar::from_u64(0);
	for &value in values {
		sum += alpha_power * AkitaFieldScalar::from_u64(value);
		alpha_power *= alpha;
	}
	sum
}

/// Build the Booleanity product-sumcheck input for bit-slice polynomials.
pub fn booleanity_sumcheck_inputs(
	bit_slices: &BitSliceOracle,
) -> (Vec<Vec<AkitaFieldScalar>>, Vec<Vec<AkitaFieldScalar>>) {
	let lefts = bit_slices.bit_polys.clone();
	let rights = bit_slices
		.bit_polys
		.iter()
		.map(|poly| {
			poly.iter()
				.map(|&bit| bit - AkitaFieldScalar::from_u64(1))
				.collect()
		})
		.collect();
	(lefts, rights)
}

/// Build Booleanity product inputs for one flattened bit-table polynomial.
pub fn booleanity_table_sumcheck_inputs(
	bit_table: &[AkitaFieldScalar],
) -> (Vec<Vec<AkitaFieldScalar>>, Vec<Vec<AkitaFieldScalar>>) {
	(
		vec![bit_table.to_vec()],
		vec![
			bit_table
				.iter()
				.map(|&bit| bit - AkitaFieldScalar::from_u64(1))
				.collect(),
		],
	)
}

/// Prove randomly weighted Booleanity for one bit-table polynomial.
pub fn prove_weighted_booleanity_sumcheck(
	bit_table: &[AkitaFieldScalar],
	weight_point: &[AkitaFieldScalar],
	challenges: &[AkitaFieldScalar],
) -> Result<(AkitaFieldScalar, WeightedBooleanitySumcheckProof, AkitaFieldScalar), BatchedParityBridgeError> {
	validate_weighted_booleanity_inputs(bit_table, weight_point)?;
	if challenges.len() != weight_point.len() {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}

	let mut bits = bit_table.to_vec();
	let mut weights = multilinear_eq_evals(weight_point);
	let initial_claim = weighted_booleanity_sum(&bits, &weights);
	let mut round_evals = Vec::with_capacity(challenges.len());

	for &challenge in challenges {
		let round = weighted_booleanity_round_evals(&bits, &weights);
		round_evals.push(round);
		fold_evals(&mut bits, challenge);
		fold_evals(&mut weights, challenge);
	}

	Ok((initial_claim, WeightedBooleanitySumcheckProof { round_evals }, bits[0]))
}

/// Prove a product sumcheck with Fiat-Shamir challenges from the Binius transcript.
#[allow(clippy::type_complexity)]
pub fn prove_product_sumcheck_transcript<Challenger_>(
	lefts: &[Vec<AkitaFieldScalar>],
	rights: &[Vec<AkitaFieldScalar>],
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<
	(AkitaFieldScalar, ProductSumcheckProof, Vec<AkitaFieldScalar>, Vec<AkitaFieldScalar>, Vec<AkitaFieldScalar>),
	BatchedParityBridgeError,
>
where
	Challenger_: Challenger,
{
	validate_product_inputs(lefts, rights)?;
	let mut lefts = lefts.to_vec();
	let mut rights = rights.to_vec();
	let initial_claim = product_sum(&lefts, &rights);
	wire::write_akita(transcript, &initial_claim);

	let log_len = lefts[0].len().trailing_zeros() as usize;
	let mut round_evals = Vec::with_capacity(log_len);
	let mut challenges = Vec::with_capacity(log_len);
	for _ in 0..log_len {
		let round = product_round_evals(&lefts, &rights);
		for value in &round {
			wire::write_akita(transcript, value);
		}
		let challenge = wire::sample_akita_scalar(transcript);
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
	expected_initial_claim: AkitaFieldScalar,
	num_rounds: usize,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(ProductSumcheckProof, Vec<AkitaFieldScalar>, AkitaFieldScalar), Error>
where
	Challenger_: Challenger,
{
	let initial_claim = wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?;
	if initial_claim != expected_initial_claim {
		return Err(Error::ProofEmpty);
	}

	let mut claim = initial_claim;
	let mut round_evals = Vec::with_capacity(num_rounds);
	let mut challenges = Vec::with_capacity(num_rounds);
	for _ in 0..num_rounds {
		let round = [
			wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?,
			wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?,
			wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?,
		];
		if round[0] + round[1] != claim {
			return Err(Error::ProofEmpty);
		}
		let challenge = wire::verify_sample_akita_scalar(transcript);
		claim = evaluate_quadratic_from_0_1_2(round, challenge);
		round_evals.push(round);
		challenges.push(challenge);
	}
	Ok((ProductSumcheckProof { round_evals }, challenges, claim))
}

/// Prove weighted Booleanity with Fiat-Shamir challenges from the Binius transcript.
pub fn prove_weighted_booleanity_sumcheck_transcript<Challenger_>(
	bit_table: &[AkitaFieldScalar],
	weight_point: &[AkitaFieldScalar],
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<
	(AkitaFieldScalar, WeightedBooleanitySumcheckProof, Vec<AkitaFieldScalar>, AkitaFieldScalar),
	BatchedParityBridgeError,
>
where
	Challenger_: Challenger,
{
	validate_weighted_booleanity_inputs(bit_table, weight_point)?;
	let mut bits = bit_table.to_vec();
	let mut weights = multilinear_eq_evals(weight_point);
	let initial_claim = weighted_booleanity_sum(&bits, &weights);
	wire::write_akita(transcript, &initial_claim);

	let log_len = bit_table.len().trailing_zeros() as usize;
	let mut round_evals = Vec::with_capacity(log_len);
	let mut challenges = Vec::with_capacity(log_len);
	for _ in 0..log_len {
		let round = weighted_booleanity_round_evals(&bits, &weights);
		for value in &round {
			wire::write_akita(transcript, value);
		}
		let challenge = wire::sample_akita_scalar(transcript);
		challenges.push(challenge);
		fold_evals(&mut bits, challenge);
		fold_evals(&mut weights, challenge);
		round_evals.push(round);
	}

	Ok((initial_claim, WeightedBooleanitySumcheckProof { round_evals }, challenges, bits[0]))
}

/// Verify weighted Booleanity from a Binius transcript and return challenges plus final claim.
pub fn verify_weighted_booleanity_sumcheck_transcript<Challenger_>(
	expected_initial_claim: AkitaFieldScalar,
	num_rounds: usize,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(WeightedBooleanitySumcheckProof, Vec<AkitaFieldScalar>, AkitaFieldScalar), Error>
where
	Challenger_: Challenger,
{
	let initial_claim = wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?;
	if initial_claim != expected_initial_claim {
		return Err(Error::ProofEmpty);
	}

	let mut claim = initial_claim;
	let mut round_evals = Vec::with_capacity(num_rounds);
	let mut challenges = Vec::with_capacity(num_rounds);
	for _ in 0..num_rounds {
		let round = [
			wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?,
			wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?,
			wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?,
			wire::read_akita::<AkitaFieldScalar, _>(transcript, &())?,
		];
		if round[0] + round[1] != claim {
			return Err(Error::ProofEmpty);
		}
		let challenge = wire::verify_sample_akita_scalar(transcript);
		claim = evaluate_cubic_from_0_1_2_3(round, challenge);
		round_evals.push(round);
		challenges.push(challenge);
	}
	Ok((WeightedBooleanitySumcheckProof { round_evals }, challenges, claim))
}

// ============================================================================
// Claim reduction sumcheck (used by the `akita-claim-reduced` bridge variant)
// ============================================================================
//
// Reduces two opening claims on the same committed polynomial `B`:
//
//     B(selected_point) = e_selected
//     B(bool_point)     = e_bool
//
// into a single claim `B(r_final) = e_final` for a freshly sampled point
// `r_final`, so the PCS only needs to open `B` at one point.
//
// Construction: sample a verifier random `alpha`, define
//
//     T(x) = eq(selected_point, x) + alpha * eq(bool_point, x)
//
// and run the standard degree-2 product sumcheck on the identity
//
//     sum_{x ∈ {0,1}^n} B(x) * T(x) = e_selected + alpha * e_bool
//
// The sumcheck reduces this to a final claim `B(r_final) * T(r_final) = c`
// at the sumcheck challenges `r_final`. The verifier computes `T(r_final)`
// independently from the two public opening points and `alpha`, so the
// residual claim collapses to `B(r_final) = c / T(r_final)` — a single-point
// opening that the PCS discharges.
//
// Soundness (Schwartz-Zippel + sumcheck soundness):
//   - Probability the verifier accepts a wrong reduction: ≤ 1/|F| from the
//     `alpha` linear combination, plus ≤ 3·log(N)/|F| from the n-round
//     degree-2 sumcheck. For |F| = fp128 ≈ 2^128 this is ~negligible.

/// Prove the claim-reduction sumcheck with Fiat-Shamir challenges from the
/// Binius transcript.
///
/// Reuses [`prove_product_sumcheck_transcript`] internally — the claim
/// reduction is exactly a degree-2 product sumcheck on
/// `B(x) * (eq(r0, x) + alpha · eq(r1, x))`.
///
/// # Returns
///
/// `(alpha, sumcheck_proof, challenges, b_final)` where:
/// - `alpha` is the linear-combination scalar sampled from the transcript.
/// - `sumcheck_proof` is the underlying product sumcheck proof.
/// - `challenges` is the new opening point `r_final ∈ F^n`.
/// - `b_final` is the prover's claim for `B(r_final)`.
pub fn prove_claim_reduction_sumcheck_transcript<Challenger_>(
	bit_table: &[AkitaFieldScalar],
	selected_point: &[AkitaFieldScalar],
	bool_point: &[AkitaFieldScalar],
	e_selected: AkitaFieldScalar,
	e_bool: AkitaFieldScalar,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<(AkitaFieldScalar, ProductSumcheckProof, Vec<AkitaFieldScalar>, AkitaFieldScalar), BatchedParityBridgeError>
where
	Challenger_: Challenger,
{
	if selected_point.len() != bool_point.len() {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}
	let log_len = bit_table.len().trailing_zeros() as usize;
	if !bit_table.len().is_power_of_two() || selected_point.len() != log_len {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}

	// 1. Sample alpha after both opening claims are fixed in the transcript.
	//    Per the bridge's outer protocol, e_selected and e_bool have already
	//    been observed by the transcript as part of the preceding sumchecks'
	//    final claims, so `alpha` is bound to them via Fiat-Shamir.
	let alpha = wire::sample_akita_scalar(transcript);

	// 2. Build the combined transparent T(x) = eq(r0, x) + alpha · eq(r1, x).
	let eq_selected = multilinear_eq_evals(selected_point);
	let eq_bool = multilinear_eq_evals(bool_point);
	let combined_transparent: Vec<AkitaFieldScalar> = eq_selected
		.iter()
		.zip(eq_bool.iter())
		.map(|(es, eb)| *es + alpha * *eb)
		.collect();

	// 3. Run the underlying product sumcheck. It internally writes the
	//    initial claim to the transcript; the verifier independently computes
	//    `e_selected + alpha · e_bool` and checks it matches via
	//    `verify_product_sumcheck_transcript`.
	let (initial_claim, proof, challenges, b_finals, _t_finals) =
		prove_product_sumcheck_transcript(
			&[bit_table.to_vec()],
			&[combined_transparent],
			transcript,
		)?;

	// Prover-side sanity check: the initial claim the sumcheck computed from
	// `sum_x B(x) · T(x)` must equal the verifier's expected `e_selected + alpha · e_bool`.
	// If this ever fails, either e_selected/e_bool are inconsistent with the
	// bit_table values, or alpha was sampled out of order with the transcript.
	debug_assert_eq!(
		initial_claim,
		e_selected + alpha * e_bool,
		"claim reduction sumcheck: prover-side initial-claim mismatch",
	);

	Ok((alpha, proof, challenges, b_finals[0]))
}

/// Verify the claim-reduction sumcheck from a Binius transcript.
///
/// Mirror of [`prove_claim_reduction_sumcheck_transcript`]. The caller is
/// responsible for checking that the final bit-table evaluation `b_final` is
/// consistent with `T(r_final) = eq(selected_point, r_final) + alpha ·
/// eq(bool_point, r_final)` and the returned `claim_final`. Concretely:
///
/// ```text
/// b_final * T(r_final) == claim_final
/// ```
///
/// where `T(r_final)` is computed from the two public opening points and
/// `alpha` returned here. The PCS then opens the committed polynomial at
/// `r_final` (the `challenges` vector) and the opened value is compared
/// against `b_final`.
///
/// # Returns
///
/// `(alpha, sumcheck_proof, challenges, claim_final)`.
pub fn verify_claim_reduction_sumcheck_transcript<Challenger_>(
	selected_point: &[AkitaFieldScalar],
	bool_point: &[AkitaFieldScalar],
	e_selected: AkitaFieldScalar,
	e_bool: AkitaFieldScalar,
	num_rounds: usize,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(AkitaFieldScalar, ProductSumcheckProof, Vec<AkitaFieldScalar>, AkitaFieldScalar), Error>
where
	Challenger_: Challenger,
{
	if selected_point.len() != bool_point.len() || selected_point.len() != num_rounds {
		return Err(Error::ProofEmpty);
	}
	let alpha = wire::verify_sample_akita_scalar(transcript);
	let expected_initial_claim = e_selected + alpha * e_bool;
	let (proof, challenges, claim_final) =
		verify_product_sumcheck_transcript(expected_initial_claim, num_rounds, transcript)?;
	Ok((alpha, proof, challenges, claim_final))
}

/// Helper: evaluate the combined transparent `T(r) = eq(selected, r) + alpha · eq(bool, r)`
/// at the sumcheck-final point. The verifier uses this to bridge
/// `claim_final = b_final · T(r)` from the sumcheck back to a single-point
/// opening claim on the committed polynomial.
pub fn evaluate_claim_reduction_transparent(
	selected_point: &[AkitaFieldScalar],
	bool_point: &[AkitaFieldScalar],
	alpha: AkitaFieldScalar,
	r_final: &[AkitaFieldScalar],
) -> Result<AkitaFieldScalar, BatchedParityBridgeError> {
	let es = evaluate_akita_eq(selected_point, r_final)
		.ok_or(BatchedParityBridgeError::InvalidSumcheck)?;
	let eb = evaluate_akita_eq(bool_point, r_final)
		.ok_or(BatchedParityBridgeError::InvalidSumcheck)?;
	Ok(es + alpha * eb)
}

/// Canonical `u128` lift from the Binius binary field to Akita's prime field.
///
/// This is useful for diagnostics and for constructing Akita test polynomials,
/// but it is not a field homomorphism and must not be used as a verifier-accepted
/// replacement for BaseFold openings.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalU128Bridge;

impl CanonicalU128Bridge {
	/// Lift one Binius scalar into Akita's prime field using its raw canonical bits.
	pub fn lift(value: BiniusScalar) -> AkitaFieldScalar {
		AkitaFieldScalar::from_canonical_u128_reduced(value.val())
	}

	/// Lift a slice of Binius scalars into Akita's prime field.
	pub fn lift_slice(values: &[BiniusScalar]) -> Vec<AkitaFieldScalar> {
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
		self.verify_with_bounds(&bounds, claim)
	}

	/// Verify the 128 parity equations against verifier-derived public bounds.
	pub fn verify_with_bounds(
		&self,
		bounds: &[u64; BINIUS_SCALAR_BITS],
		claim: BiniusScalar,
	) -> Result<(), BatchedParityBridgeError> {
		for (bit, (&sum, &bound)) in self.opened_sums.iter().zip(bounds).enumerate() {
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
/// full protocol, those same sums are Akita opening claims against committed
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
			add_output_bits_scaled(&mut bounds, coefficient * basis, 1)?;
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
	add_output_bits_scaled(accumulator, value, 1)
}

fn add_output_bits_scaled(
	accumulator: &mut [u64; BINIUS_SCALAR_BITS],
	value: BiniusScalar,
	count: u64,
) -> Result<(), BatchedParityBridgeError> {
	let mut output_bits = value.val();
	while output_bits != 0 {
		let output_bit = output_bits.trailing_zeros() as usize;
		accumulator[output_bit] = accumulator[output_bit]
			.checked_add(count)
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
	alpha_powers: &[AkitaFieldScalar],
) -> AkitaFieldScalar {
	let basis = BiniusScalar::new(1u128 << input_bit);
	let mut output_bits = (coefficient * basis).val();
	let mut mask_value = AkitaFieldScalar::from_u64(0);
	while output_bits != 0 {
		let output_bit = output_bits.trailing_zeros() as usize;
		mask_value += alpha_powers[output_bit];
		output_bits &= output_bits - 1;
	}
	mask_value
}

fn powers(base: AkitaFieldScalar, len: usize) -> Vec<AkitaFieldScalar> {
	let mut powers = Vec::with_capacity(len);
	let mut current = AkitaFieldScalar::from_u64(1);
	for _ in 0..len {
		powers.push(current);
		current *= base;
	}
	powers
}

fn multilinear_eq_evals(point: &[AkitaFieldScalar]) -> Vec<AkitaFieldScalar> {
	let mut evals = vec![AkitaFieldScalar::from_u64(1)];
	for &coordinate in point {
		let len = evals.len();
		let one_minus_coordinate = AkitaFieldScalar::from_u64(1) - coordinate;
		for index in 0..len {
			let value = evals[index];
			evals[index] = value * one_minus_coordinate;
			evals.push(value * coordinate);
		}
	}
	evals
}

/// Evaluate the multilinear equality polynomial `eq(left, right)`.
pub fn evaluate_akita_eq(left: &[AkitaFieldScalar], right: &[AkitaFieldScalar]) -> Option<AkitaFieldScalar> {
	if left.len() != right.len() {
		return None;
	}
	let one = AkitaFieldScalar::from_u64(1);
	Some(
		left.iter()
			.zip(right)
			.fold(one, |acc, (&left, &right)| acc * ((one - left) * (one - right) + left * right)),
	)
}

fn product_sum(lefts: &[Vec<AkitaFieldScalar>], rights: &[Vec<AkitaFieldScalar>]) -> AkitaFieldScalar {
	lefts
		.iter()
		.zip(rights)
		.flat_map(|(left, right)| left.iter().zip(right))
		.fold(AkitaFieldScalar::from_u64(0), |acc, (&left, &right)| acc + left * right)
}

fn validate_weighted_booleanity_inputs(
	bit_table: &[AkitaFieldScalar],
	weight_point: &[AkitaFieldScalar],
) -> Result<(), BatchedParityBridgeError> {
	if bit_table.is_empty() || !bit_table.len().is_power_of_two() {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}
	if bit_table.len().trailing_zeros() as usize != weight_point.len() {
		return Err(BatchedParityBridgeError::InvalidSumcheck);
	}
	Ok(())
}

fn weighted_booleanity_sum(bits: &[AkitaFieldScalar], weights: &[AkitaFieldScalar]) -> AkitaFieldScalar {
	debug_assert_eq!(bits.len(), weights.len());
	let one = AkitaFieldScalar::from_u64(1);
	bits.iter()
		.zip(weights)
		.fold(AkitaFieldScalar::from_u64(0), |acc, (&bit, &weight)| acc + weight * bit * (bit - one))
}

fn weighted_booleanity_round_evals(
	bits: &[AkitaFieldScalar],
	weights: &[AkitaFieldScalar],
) -> [AkitaFieldScalar; 4] {
	debug_assert_eq!(bits.len(), weights.len());
	let one = AkitaFieldScalar::from_u64(1);
	let mut evals = [AkitaFieldScalar::from_u64(0); 4];
	for (bit_pair, weight_pair) in bits.chunks_exact(2).zip(weights.chunks_exact(2)) {
		let bit0 = bit_pair[0];
		let bit_delta = bit_pair[1] - bit0;
		let weight0 = weight_pair[0];
		let weight_delta = weight_pair[1] - weight0;
		for (t, eval) in evals.iter_mut().enumerate() {
			let t = AkitaFieldScalar::from_u64(t as u64);
			let bit_t = bit0 + t * bit_delta;
			let weight_t = weight0 + t * weight_delta;
			*eval += weight_t * bit_t * (bit_t - one);
		}
	}
	evals
}

fn product_round_evals(
	lefts: &[Vec<AkitaFieldScalar>],
	rights: &[Vec<AkitaFieldScalar>],
) -> [AkitaFieldScalar; 3] {
	let two = AkitaFieldScalar::from_u64(2);
	let mut evals = [AkitaFieldScalar::from_u64(0); 3];
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

fn fold_evals(evals: &mut Vec<AkitaFieldScalar>, challenge: AkitaFieldScalar) {
	let half = evals.len() / 2;
	for i in 0..half {
		evals[i] = evals[2 * i] + challenge * (evals[2 * i + 1] - evals[2 * i]);
	}
	evals.truncate(half);
}

fn evaluate_quadratic_from_0_1_2(evals: [AkitaFieldScalar; 3], x: AkitaFieldScalar) -> AkitaFieldScalar {
	let two = AkitaFieldScalar::from_u64(2);
	let inv_two = two
		.inverse()
		.expect("2 is invertible in Akita's odd prime field");
	let c0 = evals[0];
	let c2 = (evals[2] - two * evals[1] + evals[0]) * inv_two;
	let c1 = evals[1] - c0 - c2;
	c0 + c1 * x + c2 * x * x
}

fn evaluate_cubic_from_0_1_2_3(evals: [AkitaFieldScalar; 4], x: AkitaFieldScalar) -> AkitaFieldScalar {
	let one = AkitaFieldScalar::from_u64(1);
	let two = AkitaFieldScalar::from_u64(2);
	let three = AkitaFieldScalar::from_u64(3);
	let six = AkitaFieldScalar::from_u64(6);
	let inv_two = two
		.inverse()
		.expect("2 is invertible in Akita's odd prime field");
	let inv_six = six
		.inverse()
		.expect("6 is invertible in Akita's odd prime field");

	let x_minus_one = x - one;
	let x_minus_two = x - two;
	let x_minus_three = x - three;
	let l0 = AkitaFieldScalar::from_u64(0) - x_minus_one * x_minus_two * x_minus_three * inv_six;
	let l1 = x * x_minus_two * x_minus_three * inv_two;
	let l2 = AkitaFieldScalar::from_u64(0) - x * x_minus_one * x_minus_three * inv_two;
	let l3 = x * x_minus_one * x_minus_two * inv_six;
	evals[0] * l0 + evals[1] * l1 + evals[2] * l2 + evals[3] * l3
}

/// Why the current Akita adapter cannot yet be wired as a strict PCS backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeObstruction {
	/// Binary-field addition is XOR, while Akita `fp128` addition is prime-field addition.
	NotAdditive,
	/// Binary-field multiplication and Akita `fp128` multiplication are different operations.
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
		let alpha = AkitaFieldScalar::from_u64(17);
		let bit_slices = BitSliceOracle::from_binius_oracle(&oracle);
		let masks = batched_selected_sum_masks(&transparent, alpha);
		let expected_batched_sum = batched_u64_sum(&parity_proof.opened_sums, alpha);

		let challenges = [AkitaFieldScalar::from_u64(3), AkitaFieldScalar::from_u64(5)];
		let (sumcheck_claim, proof, final_lefts, final_rights) =
			prove_product_sumcheck(&bit_slices.bit_polys, &masks, &challenges).unwrap();

		assert_eq!(sumcheck_claim, expected_batched_sum);
		let final_claim = proof.verify_rounds(sumcheck_claim, &challenges).unwrap();
		let final_opening_claim = final_lefts
			.iter()
			.zip(&final_rights)
			.fold(AkitaFieldScalar::from_u64(0), |acc, (&left, &right)| acc + left * right);
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
		let challenges = [AkitaFieldScalar::from_u64(19), AkitaFieldScalar::from_u64(23)];
		let (claim, proof, final_lefts, final_rights) =
			prove_product_sumcheck(&lefts, &rights, &challenges).unwrap();

		assert_eq!(claim, AkitaFieldScalar::from_u64(0));
		let final_claim = proof.verify_rounds(claim, &challenges).unwrap();
		let final_opening_claim = final_lefts
			.iter()
			.zip(&final_rights)
			.fold(AkitaFieldScalar::from_u64(0), |acc, (&left, &right)| acc + left * right);
		assert_eq!(final_claim, final_opening_claim);
	}

	#[test]
	fn booleanity_product_sumcheck_rejects_non_boolean_slice() {
		let oracle = [BiniusScalar::new(0), BiniusScalar::new(1)];
		let mut bit_slices = BitSliceOracle::from_binius_oracle(&oracle);
		bit_slices.bit_polys[0][0] = AkitaFieldScalar::from_u64(2);
		let (lefts, rights) = booleanity_sumcheck_inputs(&bit_slices);
		let challenges = [AkitaFieldScalar::from_u64(29)];
		let (claim, proof, final_lefts, final_rights) =
			prove_product_sumcheck(&lefts, &rights, &challenges).unwrap();

		assert_ne!(claim, AkitaFieldScalar::from_u64(0));
		let final_claim = proof.verify_rounds(claim, &challenges).unwrap();
		let final_opening_claim = final_lefts
			.iter()
			.zip(&final_rights)
			.fold(AkitaFieldScalar::from_u64(0), |acc, (&left, &right)| acc + left * right);
		assert_eq!(final_claim, final_opening_claim);
	}

	// The Akita PCS round-trip on the bit-slice oracle is covered end-to-end
	// by `akita_proof_mode_mismatches_reject` in
	// `crates/prover/tests/prove_verify.rs` (positive roundtrip on a real
	// SHA-256 preimage circuit). A unit-scoped equivalent of that test used
	// to live here, but it depended on the old monolithic `CommitmentScheme`
	// trait that was decomposed upstream into `CommitmentProver` and
	// `CommitmentVerifier`. Removed in the 2026-05 bridge cleanup.

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
		let alpha = AkitaFieldScalar::from_u64(31);
		let selected_mask = batched_selected_sum_table_mask(&transparent, alpha);
		let selected_claim = batched_u64_sum(&parity.opened_sums, alpha);
		let challenges = (0..10)
			.map(|i| AkitaFieldScalar::from_u64(37 + i as u64))
			.collect::<Vec<_>>();
		let (claim, proof, left, right) =
			prove_product_sumcheck(std::slice::from_ref(&bit_table), &[selected_mask], &challenges)
				.unwrap();
		assert_eq!(claim, selected_claim);
		assert_eq!(proof.verify_rounds(claim, &challenges).unwrap(), left[0] * right[0]);

		let (bool_lefts, bool_rights) = booleanity_table_sumcheck_inputs(&bit_table);
		let (bool_claim, bool_proof, bool_left, bool_right) =
			prove_product_sumcheck(&bool_lefts, &bool_rights, &challenges).unwrap();
		assert_eq!(bool_claim, AkitaFieldScalar::from_u64(0));
		assert_eq!(
			bool_proof.verify_rounds(bool_claim, &challenges).unwrap(),
			bool_left[0] * bool_right[0]
		);

		let weight_point = (0..10)
			.map(|i| AkitaFieldScalar::from_u64(101 + i as u64))
			.collect::<Vec<_>>();
		let (weighted_claim, weighted_proof, bool_opening) =
			prove_weighted_booleanity_sumcheck(&bit_table, &weight_point, &challenges).unwrap();
		assert_eq!(weighted_claim, AkitaFieldScalar::from_u64(0));
		let weighted_final = weighted_proof
			.verify_rounds(weighted_claim, &challenges)
			.unwrap();
		let final_weight = evaluate_akita_eq(&weight_point, &challenges).unwrap();
		assert_eq!(
			weighted_final,
			final_weight * bool_opening * (bool_opening - AkitaFieldScalar::from_u64(1))
		);
	}

	#[test]
	fn weighted_booleanity_rejects_cancelling_non_boolean_table() {
		let inv_five = AkitaFieldScalar::from_u64(5)
			.inverse()
			.expect("5 is invertible in Akita's field");
		let bit_table = vec![
			AkitaFieldScalar::from_u64(2) * inv_five,
			AkitaFieldScalar::from_u64(0) - inv_five,
		];

		let (lefts, rights) = booleanity_table_sumcheck_inputs(&bit_table);
		let (unweighted_claim, _, _, _) =
			prove_product_sumcheck(&lefts, &rights, &[AkitaFieldScalar::from_u64(7)]).unwrap();
		assert_eq!(unweighted_claim, AkitaFieldScalar::from_u64(0));

		let weight_point = [AkitaFieldScalar::from_u64(3)];
		let (weighted_claim, weighted_proof, bool_opening) = prove_weighted_booleanity_sumcheck(
			&bit_table,
			&weight_point,
			&[AkitaFieldScalar::from_u64(7)],
		)
		.unwrap();
		assert_ne!(weighted_claim, AkitaFieldScalar::from_u64(0));
		assert_eq!(
			weighted_proof.verify_rounds(weighted_claim, &[AkitaFieldScalar::from_u64(7)]),
			Ok(evaluate_akita_eq(&weight_point, &[AkitaFieldScalar::from_u64(7)]).unwrap()
				* bool_opening
				* (bool_opening - AkitaFieldScalar::from_u64(1)))
		);
	}

	#[test]
	fn selected_table_mask_lazy_eval_matches_materialized() {
		use akita_algebra::poly::multilinear_eval;

		let transparent = (0..8)
			.map(|i| {
				BiniusScalar::new(((i as u128) + 1) * 0x0101_0203_0508_0d15_2237_5990_e979_62db)
			})
			.collect::<Vec<_>>();
		let alpha = AkitaFieldScalar::from_u64(43);
		let point = (0..10)
			.map(|i| AkitaFieldScalar::from_u64(47 + i as u64))
			.collect::<Vec<_>>();

		let selected_mask = batched_selected_sum_table_mask(&transparent, alpha);
		let expected = multilinear_eval(&selected_mask, &point).unwrap();
		let actual = evaluate_batched_selected_sum_table_mask(&transparent, alpha, &point).unwrap();

		assert_eq!(actual, expected);
	}

	#[test]
	fn constant_structured_relation_matches_materialized_checks() {
		use binius_math::{FieldBuffer, multilinear::evaluate::evaluate_inplace};
		use akita_algebra::poly::multilinear_eval;

		let log_len = 4;
		let coefficient = BiniusScalar::new(0x0101_0203_0508_0d15_2237_5990_e979_62db);
		let relation = ConstantTransparentRelation::new(log_len, coefficient);
		let transparent = vec![coefficient; 1 << log_len];

		let binius_point = (0..log_len)
			.map(|i| BiniusScalar::new(3 + i as u128))
			.collect::<Vec<_>>();
		let materialized_eval =
			evaluate_inplace(FieldBuffer::<BiniusScalar>::from_values(&transparent), &binius_point);
		assert_eq!(relation.eval_binius(&binius_point), Ok(materialized_eval));

		assert_eq!(relation.parity_sum_bounds(), parity_sum_bounds(&transparent));

		let alpha = AkitaFieldScalar::from_u64(43);
		let akita_point = (0..log_len + 7)
			.map(|i| AkitaFieldScalar::from_u64(47 + i as u64))
			.collect::<Vec<_>>();
		let selected_mask = batched_selected_sum_table_mask(&transparent, alpha);
		let materialized_mask_eval = multilinear_eval(&selected_mask, &akita_point).unwrap();
		assert_eq!(relation.eval_selected_mask(alpha, &akita_point), Ok(materialized_mask_eval));
	}

	#[test]
	fn constant_structured_relation_rejects_wrong_point_lengths() {
		let relation = ConstantTransparentRelation::new(3, BiniusScalar::new(7));

		assert_eq!(
			relation.eval_binius(&[BiniusScalar::new(1), BiniusScalar::new(2)]),
			Err(BatchedParityBridgeError::InvalidSumcheck)
		);
		assert_eq!(
			relation.eval_selected_mask(AkitaFieldScalar::from_u64(5), &[AkitaFieldScalar::from_u64(1)]),
			Err(BatchedParityBridgeError::InvalidSumcheck)
		);
	}
}
