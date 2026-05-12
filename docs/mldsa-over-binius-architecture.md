# ML-DSA Over Binius + Hachi: Architecture Understanding

Status: design analysis, fourth iteration. Fact-checked against source code. Arithmetic verified.

## 1. What We Are Building

A complete **ML-DSA (FIPS 204) signature verification proof** where **Hachi is the PCS backend**, replacing Binius64's hash-based BaseFold with a lattice-based PCS for post-quantum security and compact proof sizes.

The end goal is **signature aggregation**: batch N ML-DSA signatures into one succinct proof.

## 2. The Lifting: Binary Field → Hachi's Field (Fact-Checked)

### 2.1 The Core Problem: Field Incompatibility

Binius64's PIOP works in **GF(2^128)** (GHASH irreducible, characteristic 2). Hachi works over **fp128** (a 128-bit prime field, odd characteristic). These are fundamentally different algebraic structures.

The codebase **explicitly documents** this incompatibility in `crates/iop/src/hachi_bridge.rs`:

```rust
pub enum BridgeObstruction {
    /// Binary-field addition is XOR, while Hachi fp128 addition is prime-field addition.
    NotAdditive,
    /// Binary-field multiplication and Hachi fp128 multiplication are different operations.
    NotMultiplicative,
}
```

A unit test confirms: lifting `1 + 1 = 0` in GF(2^128) does NOT map to `lift(1) + lift(1) = lift(0)` in fp128. The canonical u128 embedding is **not a ring homomorphism**. You cannot just "embed" binary field arithmetic into Hachi's prime field.

**Previous claim that was wrong**: "Bitwise AND in GF(2) is just integer multiplication of {0,1} values in Z_{q'}." This is true for individual bits, but the Binius64 PIOP doesn't operate bit-by-bit — it works with packed B128 elements where addition is XOR and multiplication is carry-less polynomial multiplication. The PIOP evaluation claims are in GF(2^128), not over individual bits. You can't just lift them.

### 2.2 The Batched Parity Bridge: How It Actually Works

The existing code solves this through a **batched parity bridge** (`BatchedParityBridgeProof`):

1. **Bit-slice decomposition**: Each GF(2^128) witness element is split into 128 individual bits (`BitSliceOracle`). Each bit is a {0,1} value that embeds trivially into Hachi's field.

2. **Parity reduction**: The terminal PIOP claim `y = Σ_i t_i · w_i` in GF(2^128) is decomposed bit-by-bit. Each output bit `y_k` is a **parity** (integer sum mod 2) of selected witness bits. The bridge provides the integer sum `S_k` and the verifier checks `S_k mod 2 == y_k`.

3. **Range-checked openings**: Soundness relies on public bounds for each `S_k`. Once bounded, the mod-2 check is exact. No quotient witnesses needed for this step.

4. **Hachi opens bit-slice polynomials**: The 128 bit-slice multilinears (one per bit position) are committed as Hachi dense or one-hot polynomials. There's a Booleanity sumcheck verifying each committed value is actually {0,1}.

5. **Product-sumcheck in Hachi's field**: A degree-2 sumcheck over Hachi's field verifies that the opened sums are consistent with the committed bit-slice polynomials and the transparent coefficients.

**Important caveat**: The bridge module says "This module deliberately exposes only the canonical integer lift and the reason **it is not yet a sound PCS replacement**." This is active work.

### 2.3 The Actual Pipeline

```
Witness: flat array of u64 words
    ↓
AND reduction: GF(2^128) sumcheck (unchanged)
    ↓
Shift reduction: GF(2^128) sumcheck (unchanged)
    ↓
Ring switch: B128 MLE claim → B1 MLE claim (unchanged)
    ↓
BATCHED PARITY BRIDGE: decomposes B128 terminal claim into
  128 bit-parity claims, each verifiable over integers
    ↓
Hachi PCS: commits bit-slice polynomials as {0,1} tables in Z_{q'},
  opens them via lattice-based proofs
```

### 2.4 What the Bridge Does and Does Not Solve

**It solves**: replacing BaseFold with Hachi for binary witness commitment.

**It does NOT solve**: making shared ML-DSA witness values (z, c, wApprox) trivially available to both the binary PIOP and the lattice constraints.

The binary PIOP sees the witness as packed B128 elements (64-bit words). The lattice constraints see the witness as Z_q coefficient tables. Even though both are committed through Hachi, the **representations are different**. The z coefficients need to be:
- Packed into 64-bit words and processed through AND/shift constraints for the norm check
- Available as individual Z_q integers for the lattice polynomial identity

This is a witness-layout design problem, not a fundamental impossibility. But it means "shared values are just different columns of the same table" (my earlier claim) was an oversimplification. The bit-slice decomposition adds 128× expansion, and reconstructing integer values from bit-sliced tables for the lattice layer needs explicit protocol machinery.

## 3. What Already Exists (Verified)

### 3.1 Quang's Bit-Heavy Circuit (branch: `origin/quang/keccak-prove`)

11 Rust files in `crates/circuits/src/mldsa/`, covering sigDecode, z norm, hint decode, SampleInBall (dense+sparse), UseHint, w1Encode, final challenge hash, and end-to-end relations for all three variants. Prover integration tests in `crates/prover/tests/mldsa_prove.rs`.

Performance (ML-DSA-44, optimization pass 9, **using BaseFold PCS**):

```
gates: 205,627 / AND: 166,351 / MUL: 0
proof size: 272,224 bytes / prove: ~148 ms / verify: ~11 ms
```

**Fact-check note**: These numbers are with BaseFold. With Hachi PCS, proof size should decrease significantly (lattice-based, no Merkle trees), but prover time may change (different commitment cost).

### 3.2 Hachi Bridge Infrastructure (on current `hachi` branch)

Already implemented:
- `crates/iop/src/hachi_bridge.rs`: `BitSliceOracle`, `BatchedParityBridgeProof`, `ProductSumcheckProof`, `WeightedBooleanitySumcheckProof`, `StructuredTransparentRelation`
- `crates/iop/src/hachi_wire.rs`: serialization of Hachi proof objects in Binius transcript
- `crates/iop/src/hachi_succinct_channel.rs` and `hachi_full_open_channel.rs`: Hachi-backed IOP channel implementations
- `crates/iop-prover/src/hachi_succinct_channel.rs` and `hachi_full_open_channel.rs`: prover-side counterparts
- Feature-gated behind `#[cfg(feature = "hachi")]`

**NOT yet implemented**: full end-to-end proof with Hachi replacing BaseFold (the bridge is "not yet a sound PCS replacement" per the source).

### 3.3 What Does NOT Exist

1. **Sound Hachi PCS replacement for Binius64** — bridge is experimental/in-progress
2. **ML-DSA lattice relation** — no Hachi-side ring arithmetic for `wApprox = A·z − c·(t1·2^d)`
3. **Witness layout connecting binary and lattice views** — no design for how z/c/wApprox are simultaneously available as packed binary words and Z_q integers
4. **Aggregation pipeline** — repeated-circuit batching exists, but no N-signature aggregation
5. **ML-DSA code on the hachi branch** — the mldsa circuit is on `quang/keccak-prove`, which has NOT been merged into `hachi`

## 4. Open Problems: Comprehensive List

### 4.1 The Field Translation (Active Research)

The batched parity bridge decomposes GF(2^128) claims into bit-parity claims. This works but has costs:
- **128× witness expansion**: each B128 element becomes 128 bit-slice values in Hachi
- **Booleanity overhead**: need to prove all committed bit-slice values are in {0,1}
- **Soundness**: the module explicitly says it's "not yet a sound PCS replacement"
- **Performance**: the product-sumcheck and weighted-booleanity-sumcheck in Hachi's field add prover work

### 4.2 ML-DSA Lattice Relation: Concrete Arithmetic (Previous Version Was Wrong)

**Previous claim was wrong**: I said the quotient witness count is k·l = 16 pairs for ML-DSA-44. This is incorrect because the row-level identity can be **batched**: the sum `Σ_s A[i][s](X) · z[s](X)` is one polynomial expression per row, not one per multiplication. The correct count is **k = 4 quotient pairs (v_i, w_i)** for ML-DSA-44 (one per row), not k·l = 16.

The lifted coefficient-domain identity per row i:

```
wApprox[i](X) − Σ_s A[i][s](X)·z[s](X) + c(X)·t1_shifted[i](X)
  + q·v_i(X) + (X^256+1)·w_i(X) = 0    over Z[X]
```

This is **one identity per row** with k=4 quotient pairs total for ML-DSA-44 (vs Falcon's 1 pair). Manageable, but the coefficient magnitudes are the real problem.

### 4.3 No-Wrap Bounds: q' = 2^32 Is NOT Sufficient (Concrete Computation)

The critical arithmetic for the coefficient-domain approach. A coefficient of `Σ_s A[i][s](X) · z[s](X)` is the convolution sum:

```
(A[i][s] · z[s])_j = Σ_{k=0}^{255} A[i][s][k] · z[s][(j-k) mod 256 with sign]
```

Worst-case magnitude per term: max |A_coeff| · max |z_coeff| = (q-1) · (γ1-1).

For ML-DSA-44: (8,380,416) · (131,071) = 1.098 × 10^12 ≈ 2^40 per term.

With n=256 terms in the sum and l=4 polynomials:

```
max |coefficient| ≤ l · n · (q-1) · (γ1-1)
                  = 4 · 256 · 8,380,416 · 131,071
                  ≈ 1.12 × 10^18 ≈ 2^60
```

For the full identity: `|wApprox_coeff| + |sum_coeff| + |c·t1_coeff| + q·|v_coeff| + |w_coeff|`.

The quotient magnitudes: v ≈ 2^60 / q ≈ 2^37, w ≈ 2^60.

No-wrap requires: total < q'. With terms summing to ~2^61, **q' must exceed 2^61**.

| Parameter set | l·n·(q-1)·(γ1-1) | Approx bits | q' needed |
|---------------|-------------------|-------------|-----------|
| ML-DSA-44 | 4·256·8.38M·131K | ~2^60 | >2^61 |
| ML-DSA-65 | 5·256·8.38M·524K | ~2^62 | >2^63 |
| ML-DSA-87 | 7·256·8.38M·524K | ~2^63 | >2^64 |

**Conclusion: the Falcon-style coefficient-domain lift with q' ≈ 2^32 completely fails for ML-DSA.** Even with Hachi's fp128, the intermediate values fit (128 > 64 bits), but the Hachi MSIS modulus used for commitment security is ~32 bits per the Falcon design. The identity must be checked modulo this q' for soundness, and it wraps.

This is not a minor parameter issue — it's a **fundamental structural mismatch** between the Falcon approach and ML-DSA's larger parameters.

### 4.4 The NTT-Domain Alternative (Detailed Analysis)

The NTT-domain approach avoids ring multiplication entirely. In NTT domain, the relation is coefficient-wise (no convolution, no negacyclic modulus):

```
For each NTT index j ∈ [0,255], for each row i ∈ [0,k-1]:
  wApprox_ntt[i][j] ≡ Σ_s Ahat[i][s][j] · z_ntt[s][j]
                       − c_ntt[j] · t1_ntt_shifted[i][j]    (mod q)
```

Each individual product: Ahat[i][s][j] · z_ntt[s][j] ≤ (q-1)² ≈ 2^46.
Sum of l=4 products plus the c·t1 term: ≤ (l+1) · (q-1)² ≈ 5 · 2^46 ≈ 2^48.

With quotient v_ij = floor(sum / q): v_ij ≤ 2^48 / q ≈ 2^25.
No-wrap: sum + q · v ≈ 2 · 2^48 ≈ 2^49. **Still exceeds 2^32.**

But now there's NO negacyclic quotient w (no X^n+1 reduction). Each NTT coefficient is independent.

| Domain | Quotient count per sig | Max coefficient | q' needed |
|--------|----------------------|-----------------|-----------|
| Coefficient | k pairs (v_i, w_i) | ~2^60 (ML-DSA-44) | >2^61 |
| NTT | k·n scalars (v_{i,j}) | ~2^49 (ML-DSA-44) | >2^50 |

**NTT domain halves the bit-width** by eliminating the n-term convolution sum. But 50 bits still exceeds 32. This is a hard constraint.

### 4.5 Three Candidate Approaches to the Modulus Problem

**Approach A: Larger q' (brute force).** Use q' ≈ 2^64 or larger. This requires re-sizing Hachi's lattice parameters for MSIS security at this larger modulus. The Falcon design specifically chose q' ≈ 2^32 because larger q' requires larger lattice dimension (more expensive commitment). Doubling log(q') roughly doubles proof size contributions from the MSIS commitment.

**Approach B: Native Z_q sumcheck (avoid the lift entirely).** Instead of lifting to Z[X] and checking modulo q', verify the NTT-domain relation directly in Z_q using a Hachi-field sumcheck:
- Batch all k·n = 1024 (ML-DSA-44) coefficient equations using a random challenge α in Hachi's field
- Each equation is a Z_q identity checked via: prover provides the result mod q, verifier checks consistency
- The integer arithmetic stays within Z_q (23 bits), so q' = 2^32 suffices for checking each equation
- But the *batching* challenge α lives in fp128 (Hachi's field), and the Schwartz-Zippel error bound depends on the batching field size

This avoids the no-wrap problem because individual Z_q multiplications never exceed q² ≈ 2^46, and quotient witnesses are only ~23 bits each. The total per equation is at most ~2^47, checkable modulo q' = 2^64 or even 2^32 with per-equation quotients.

**Approach C: Modulus-switching composition.** Use the lattice-jolt modulus-switching framework to check the ML-DSA relation at a larger field, then switch down to the Hachi commitment modulus. The `cross-field fold` in lattice-jolt reportedly reduces witness size by ~51% in one worked example. This is the most principled approach but also the most complex.

**Assessment**: Approach B seems most promising for ML-DSA specifically, because it keeps the Z_q arithmetic native and uses the Hachi field only for batching. But it needs concrete protocol design.

### 4.6 NTT Consistency Proof

If z is committed in coefficient domain (needed for the binary-layer norm check) and the lattice relation operates in NTT domain, we need to prove NTT(z) = z_ntt.

NTT is a **linear transformation**: z_ntt = M_ntt · z where M_ntt is the 256×256 NTT matrix over Z_q. This is a structured linear relation (like Hashcaster's Lincheck or Binius64's shift reduction).

Cost estimate:
- l=4 polynomials, each 256 coefficients: 1024 NTT input values
- The NTT matrix is sparse (butterfly structure): each of the 8 butterfly layers has n/2 = 128 butterfly operations, each involving one twiddle-factor multiplication
- Total twiddle multiplications: 8 · 128 = 1024 per polynomial, 4096 for all l=4
- A sumcheck-based NTT proof would batch these into ~log(n) = 8 sumcheck rounds

Alternatively, commit z_ntt separately and prove consistency via a single random-point evaluation: `z_ntt(α) = M_ntt · z(α)` for random α. This is one structured matrix-vector product evaluation, comparable in cost to one lincheck.

Similarly, wApprox would need either an NTT⁻¹ proof or separate commitment in coefficient domain.

**Total NTT proof overhead**: ~2 lincheck-style sumchecks (one for z → z_ntt, one for wApprox_ntt → wApprox). Each is ~8 rounds with n/2 products per round. This is non-trivial but tractable.

### 4.7 The Dual-Representation Problem (Refined)

Previous versions overstated this. The actual question is narrower:

**z** needs to be:
- Decoded from sigma bytes and norm-checked (binary layer): requires packed 64-bit words
- Available as Z_q coefficients for the lattice relation: requires multi-bit integer values

These are the SAME underlying 256 integers per polynomial (l·256 = 1024 total for ML-DSA-44). The binary layer processes them as packed bits in 64-bit words; the lattice layer needs them as individual Z_q integers.

With bit-slicing, each z coefficient (18 bits for ML-DSA-44) becomes 18 separate bit columns. Reconstructing the integer value: z_coeff = Σ_{b=0}^{17} 2^b · bit_b. This is a weighted sum of 18 bit-slice polynomials — a RAF-style reconstruction sumcheck.

Cost per coefficient: 18 bit-slice openings + 1 reconstruction check. For 1024 coefficients: 18×1024 = 18,432 bit-slice values. This is the expansion cost, but it's committed efficiently as 18 boolean-valued Hachi polynomials (not 18,432 separate commitments).

**wApprox** is more nuanced. It flows from the lattice layer TO the binary layer:
- The lattice layer computes wApprox (or proves it was computed correctly)
- The binary layer applies UseHint to each coefficient

If wApprox is committed as integer coefficients (Z_q values), the binary layer needs to import these. This could work if the binary PIOP can reference Hachi-committed integer values as wire inputs. The current Binius64 circuit takes wApprox as direct wire inputs — the question is whether Hachi-committed values can play this role.

### 4.8 Zero Knowledge (Clarified)

Binius64's PIOP is NOT zero-knowledge. But:
- The sumcheck messages in Binius64's AND/shift reduction are functions of the witness evaluated at random challenges
- These messages are sent as part of the proof transcript
- A computationally unbounded verifier could extract witness information from them

For hidden-signature ML-DSA, this is a problem. The signature (z, h, c_tilde) must remain hidden.

**Two paths forward**:
1. Use Iron Spartan (the ZK variant in this repo, over GF(2^128)) for the bit-heavy constraints. This requires re-implementing the ML-DSA circuit in Iron Spartan's constraint format (multiplication over GF(2^128), not AND/MUL on 64-bit words). The existing ML-DSA circuit would NOT carry over directly.

2. Use Hachi's hiding properties to mask the witness, and add ZK masking to the PIOP (e.g., random blinding polynomials in the sumcheck). The `lattice-jolt` ZK section at `sections/6_zero_knowledge.tex` flags this as having "open ZK problems across modulus switching, residual quadratic audit, and parameter promotion."

**This is a hard unsolved problem for ML-DSA. Falcon v1 sidesteps it because the Falcon relation is proved entirely in Hachi (which provides hiding), with no binary-layer PIOP.**

### 4.9 SampleInBall c Export (Binary → Lattice)

SampleInBall outputs sparse challenge c with τ nonzero ternary coefficients. The binary PIOP proves this via a Fisher-Yates rejection trace. The lattice layer needs c (or NTT(c)) as input.

With the sparse SampleInBall output (positions + signs), c has exactly τ=39 (ML-DSA-44) nonzero entries. In NTT domain, c becomes fully dense (256 entries). Computing NTT(c) inside the proof requires an NTT consistency proof (see 4.6).

Alternatively, c could be committed as a sparse representation (τ position-sign pairs) and the lattice layer computes `c · t1_shifted` via sparse convolution (τ·n multiplications), avoiding the NTT. This is O(τ·n) = O(10K) multiplications — cheaper than a full NTT proof in most encodings.

### 4.10 Hachi q' vs fp128 Confusion (Clarified)

Hachi's fp128 is a 128-bit prime field. But the **MSIS commitment modulus** (denoted q' in the Falcon design) is a smaller parameter (~32 bits) that determines the lattice commitment security. These are different:
- fp128 is used for sumcheck challenges and evaluation points
- q' ≈ 2^32 is the modulus of the polynomial ring in the Ajtai commitment
- The polynomial identity P(X) = 0 must hold modulo q', NOT modulo fp128

The Falcon design's analysis shows q' = 2^32 is sufficient for Falcon (coefficients ≤ ~2^31). For ML-DSA, coefficients reach ~2^50-2^60, far above 2^32. **The identity wraps modulo q' and is unsound.**

Using fp128 as q' would require complete Hachi parameter redesign. Using q' ≈ 2^64 is possible but increases the lattice dimension needed for MSIS security.

### 4.11 Repeated-Circuit Batching Under Hachi PCS

The existing repeated-circuit-batching infrastructure assumes BaseFold. The `hachi_succinct_channel` and `hachi_full_open_channel` are different channel implementations. Whether the batching framework ports cleanly needs verification.

### 4.12 Proof Size Under Hachi vs BaseFold

Current proof size with BaseFold: 272 KB per ML-DSA-44 signature. For aggregation, the target is much smaller per signature. The Falcon design targets "tens of KB" for 1000 signatures. ML-DSA's additional binary layer and larger lattice relation will add to this.

### 4.13 Overlooked: The wApprox Direction Problem

wApprox flows from the lattice layer TO the binary layer. In the current circuit, wApprox enters as a direct wire input (mock bridge). In the real system, the lattice layer *computes* wApprox, and UseHint in the binary layer *consumes* it.

This is unusual: most shared values flow in one direction or are computed jointly. wApprox is computed by the lattice relation and then imported into the binary PIOP. If both layers share one Hachi commitment, this means the lattice constraints define wApprox values, and the binary PIOP must read from the same committed table. This requires the two constraint sets to be orchestrated so that the binary PIOP's wire inputs are derived from the same committed witness that the lattice constraints check.

### 4.14 Overlooked: Cost of Binary Layer With Hachi vs BaseFold

The current ML-DSA circuit has ~166K AND constraints producing a 272 KB proof with BaseFold. The Binius64 PIOP at this scale takes ~200ms for AND+shift reduction. With Hachi:
- The PIOP (AND reduction, shift reduction) stays the same — it's independent of the PCS
- The ring switch stays the same
- The batched parity bridge ADDS overhead (128 bit-slice polynomials, Booleanity sumcheck, product-sumcheck)
- The Hachi commitment replaces BaseFold (different cost profile)

The binary layer may actually be MORE expensive under Hachi than under BaseFold for a single proof, because the bit-slice decomposition adds work. The efficiency gain comes from aggregation, where N proofs share one Hachi recursive suffix.

### 4.15 Witness Commitment: Merkle (BaseFold) vs Hachi

This subsection explicitly separates the **current state of the `hachi` branch** from **what the production design requires**. There is real ambiguity here that has caused confusion in earlier discussions.

#### 4.15.1 Shared invariant (true today and in the target design)

The `send_oracle` trait method in `IOPProverChannel` is the commitment abstraction. All channels receive the **same input**: the packed `ValueVec` as a multilinear polynomial. From `prove.rs`:

```rust
let witness_packed = pack_witness::<P>(self.log_witness_elems, &witness)?;
// ...
let trace_oracle = channel.send_oracle(witness_packed.to_ref());
```

`witness_packed: FieldBuffer<P>` is the `ValueVec` (public + precommitted + private 64-bit words) repacked into B128 elements and padded to a power-of-two length. The same buffer is committed regardless of backend — there is no separate "Hachi witness." `BitSliceOracle::from_binius_oracle(&oracle_values)` in `hachi_succinct_channel.rs` decomposes the *exact same B128 oracle values* into bit columns at commitment time. **Hachi commits to the same `ValueVec` that BaseFold commits to**, just with a different commitment scheme.

What differs between backends:

| Backend | What `send_oracle` does to `witness_packed` | Transcript output |
|---------|---------------------------------------------|-------------------|
| BaseFold | RS-encode (NTT) → Merkle tree | 32-byte Merkle root |
| Hachi succinct | Iterate scalars → bit-slice (each B128 → 128 bits) → one-hot polynomial → Hachi IPA commit | Lattice IPA commitment (curve points) |
| Hachi full-open | Write all scalars verbatim (no commitment, testing only) | All witness values |

#### 4.15.2 As-is: how the `hachi` branch is structured TODAY

The `Prover` struct on `hachi` exposes three proving entry points:

```rust
// 1. BaseFold (Merkle) — the default Binius64 path
pub fn prove(...)                  // PROOF_MODE_BASEFOLD
// 2. Hachi full-open — testing, non-succinct (writes raw witness)
pub fn prove_hachi_full_open(...)  // PROOF_MODE_HACHI_FULL_OPEN
// 3. Hachi succinct — production Hachi path
pub fn prove_hachi_succinct(...)   // PROOF_MODE_HACHI_SUCCINCT
```

**The Merkle tree commitment IS still built and used today**, in two distinct senses:

1. **`prove()` (the default path) still does Merkle commitment.** This is the path most existing tests, benchmarks, and the ML-DSA circuit on `quang/keccak-prove` exercise. ML-DSA has not been migrated to either Hachi path on the `hachi` branch.

2. **Even when calling `prove_hachi_succinct()` or `prove_hachi_full_open()`, the `Prover` struct still constructs a `basefold_compiler`**:
   ```rust
   pub struct Prover<...> {
       iop_prover: IOPProver,
       basefold_compiler: BaseFoldProverCompiler<...>,    // always present
       #[cfg(feature = "hachi")]
       hachi_succinct_setup: Option<Arc<HachiSuccinctSetup>>,
   }
   ```
   `Prover::setup` always builds the NTT domain context and `BinaryMerkleTreeProver`, regardless of which proving path is later invoked. The Hachi paths reuse `self.basefold_compiler.oracle_specs()` to get oracle specifications — those specs are currently produced as a side effect of constructing the BaseFold compiler.

   So on the `hachi` branch today, even a "pure Hachi" run pays the setup cost of NTT tables and the Merkle prover, even though the Merkle tree itself is never built at prove time when you call `prove_hachi_succinct`.

3. **No ML-DSA + Hachi path exists end-to-end.** The ML-DSA circuit lives on `quang/keccak-prove` (not yet merged into `hachi`). The `hachi` branch tests cover Hachi commitment for generic constraint systems, not ML-DSA specifically.

#### 4.15.3 To-be: what the production Hachi-backed ML-DSA design requires

For ML-DSA verification proofs targeting Hachi as the actual on-chain PCS backend:

1. **Drop the Merkle commitment at prove time.** Production ML-DSA proofs should call `prove_hachi_succinct` (or its eventual replacement). The Merkle tree must not be built or written to the transcript.

2. **Decouple the `Prover` from `basefold_compiler`.** A Hachi-only prover should not require the NTT domain context or `BinaryMerkleTreeProver` to exist in memory. The oracle specs must be derivable independently of the BaseFold compiler. This is a refactor, not a fundamental redesign — the oracle specs are metadata about the witness layout, not BaseFold-specific.

3. **Merge ML-DSA circuit into the `hachi` branch and exercise the Hachi succinct path.** Today, `quang/keccak-prove` contains the ML-DSA circuit (committing via BaseFold), and `hachi` contains the Hachi channel infrastructure (without ML-DSA). These have not been combined.

4. **Resolve the soundness gap.** `hachi_bridge.rs` self-documents: "This module deliberately exposes only the canonical integer lift and the reason it is not yet a sound PCS replacement." A production Hachi PCS replacement requires resolving this — the batched parity bridge needs to become provably sound, not just experimental.

#### 4.15.4 Cost comparison

**BaseFold commitment cost (current default, from `crates/iop-prover/src/fri/commit.rs`):**

1. **Reed-Solomon encode** (`rs_code.encode_batch` via NTT): Expands the witness polynomial from `2^log_dim` to `2^(log_dim + log_inv_rate)` evaluations. For ML-DSA-44 with ~166K AND constraints, the witness is ~16K B128 elements (2^14). With `log_inv_rate = 1`, the codeword doubles to ~32K elements. The NTT is O(n log n) over B128 — fast but non-trivial.

2. **Merkle tree construction** (`merkle_prover.commit_iterated`): Hashes the RS codeword into a binary Merkle tree. ~32K leaves of 16 bytes, ~32K parallel hash calls — typically 1-2ms.

3. **Total commitment as fraction of prove time**: For ~148ms total ML-DSA-44 prove time, commitment is roughly 5-10%. Dominant costs are AND reduction (~40%), shift reduction (~25%), ring switch + MLE reduction (~20%).

**Hachi succinct commitment cost (target):**

- No Merkle tree or NTT encoding at commit time
- Bit-slice decomposition: each B128 element → 128 bit columns (`BitSliceOracle::from_binius_oracle`)
- One-hot polynomial encoding for the Hachi commitment scheme
- Lattice-based IPA commit over the one-hot polynomials
- Per-oracle commit cost is **higher** than BaseFold (lattice operations vs hashing), amortized only in aggregation

For a single ML-DSA proof, the Hachi commitment is likely more expensive than BaseFold's. The benefit is in proof size (no Merkle paths) and aggregation (N proofs share one recursive Hachi suffix).

#### 4.15.5 Key takeaway

The PIOP internals (AND reduction, IntMul reduction, shift reduction, ring switch) are **already backend-agnostic** in `prove.rs` — `IOPProver::prove` takes a generic `Channel: IOPProverChannel<P>` and the same code path runs for all backends. The work needed to make ML-DSA production-ready under Hachi is concentrated in:

- (a) the soundness of the parity bridge,
- (b) the structural decoupling of `Prover` from `basefold_compiler`, and
- (c) merging the ML-DSA circuit onto the `hachi` branch and integrating it with `prove_hachi_succinct`.

The PCS abstraction is in good shape; the missing pieces are integration and soundness, not pipeline architecture.

## 5. Revised Confidence Assessment

### High Confidence

- Quang's bit-heavy circuit is correct and well-optimized
- Hoisting policy is correct (public-only hashing outside the proof)
- Hachi replaces BaseFold as PCS (confirmed by code: `hachi_bridge.rs`, `hachi_succinct_channel.rs`)
- The batched parity bridge is the field-translation mechanism (confirmed in code)
- **q' = 2^32 is insufficient for the Falcon-style coefficient-domain lift of ML-DSA** (arithmetic verified above)

### Medium Confidence

- NTT-domain approach reduces the bit-width problem but doesn't eliminate it (needs q' > 2^50)
- Native Z_q sumcheck (Approach B in 4.5) could avoid the no-wrap problem entirely
- Aggregation under Hachi will give compact proof sizes for the lattice layer
- The batched parity bridge will eventually be sound (actively worked on)

### Low Confidence / Active Research

- Which of the three approaches (larger q', native Z_q sumcheck, modulus-switching) is correct for ML-DSA's lattice relation
- NTT consistency proof cost and feasibility
- Zero-knowledge properties (Binius64 PIOP is non-ZK; Iron Spartan is ZK but different constraint system)
- Whether the full ML-DSA system (binary + lattice + bridge) is practically efficient enough for aggregation
- The exact Hachi parameter impact of moving q' above 2^32

## 6. Component-Level Cost Breakdown (ML-DSA-44)

(Unchanged — these numbers are from the existing circuit with BaseFold and remain accurate for the binary-layer constraint count.)

| Component | Gates | % | AND | % |
|-----------|------:|---:|----:|---:|
| Canonical h match | 92,929 | 43% | 91,621 | 52% |
| UseHint | 47,104 | 22% | 33,792 | 19% |
| SampleInBall sparse core | 32,236 | 15% | 28,446 | 16% |
| Final SHAKE256 (7 Keccak-f) | 19,440 | 9% | 5,048 | 3% |
| z unpack + norm | 8,960 | 4% | 5,632 | 3% |
| SampleInBall SHAKE256 (1 Keccak-f) | 2,778 | 1% | 722 | 0.4% |
| w1Encode | 2,176 | 1% | 1,088 | 0.6% |

## 7. Relationship to Falcon Work

Falcon v1 is sequenced first because it avoids the binary-field layer entirely (pure lattice in Hachi, SHAKE outside the SNARK). ML-DSA v2 inherits Hachi infrastructure but adds:
- The Binius64 PIOP for bit-heavy constraints
- The batched parity bridge for field translation
- A much larger lattice relation (matrix-vector product vs single ring multiplication)

The key risk: **the design patterns that work for Falcon's minimal lattice relation may not scale to ML-DSA's k×l matrix structure.** This is the architectural question that needs resolution before committing to an implementation approach.

## 8. The Keccak Budget

Hidden-signature mode, public hashing hoisted:

| Call | Keccak-f (ML-DSA-44) | (ML-DSA-87) |
|------|---------------------|-------------|
| SampleInBall(c_tilde) | 1 | 1 |
| H(mu \|\| w1_bytes, λ/4) | 7 | 9 |
| **Total** | **8** | **10** |

Hoisted: tr=H(pk), mu=H(tr||M'), ExpandA(rho) — ~91 to ~301 Keccak-f calls.

## 9. Dilithium Reference Implementation

Located at `/Users/taghi.badakhshan/Projects/dilithium/`. Provides the verification algorithm as C source. `SampleInBall` is `poly_challenge` in `ref/poly.c`. The key data structures are `poly` (256 int32 coefficients) and `polyveck`/`polyvecl` (vectors of polynomials).
