# Hachi PCS Integration Report

## Baseline: Binius64 Keccak With BaseFold/FRI

Command:

```bash
HASH_MAX_BYTES=256 cargo bench --bench keccak -- --warm-up-time 0.1 --measurement-time 0.5 --sample-size 10
```

Result on macOS arm64 with `mt_arm64_neon_aes`:

- Witness generation: 40.971 us median estimate
- Proof generation: 44.228 ms median estimate
- Proof verification: 482.92 us median estimate
- Proof size: 80,000 bytes (78.12 KiB)
- Peak proof-generation memory: 69.15 MiB

## Local Hachi Smoke

Smoke test:

```bash
cargo test --test single_poly_e2e single_dense_nv10 -- --nocapture
```

Profile command:

```bash
HACHI_NUM_VARS=14 HACHI_MODE=full HACHI_PROFILE_TRACE=0 HACHI_PROFILE_ANSI=0 HACHI_PROFILE_LOG=info cargo run --release --example profile
```

Result for local Hachi `fp128::D32Full` dense profile:

- Setup: 3.72 ms
- Commit: 4.47 ms
- Prove: 119.735 ms
- Verify: 4.93 ms
- Proof size: 59,536 bytes

Hachi's `Fp128` serializer ignores the compression flag, and the terminal witness is already bit-packed, so the compressed proof size for this measured profile is also 59,536 bytes.

## Strict Integration Status

The optional `hachi` feature in `binius-iop` adds a narrow adapter surface in `crates/iop/src/hachi_bridge.rs`. It exposes the only currently obvious bridge, a canonical `u128` lift from `BinaryField128bGhash` into Hachi's `fp128` prime field.

That bridge is not a sound PCS replacement because it is not field-homomorphic:

- Binary-field addition is XOR, so `1 + 1 = 0`.
- Hachi `fp128` addition is prime-field addition, so `1 + 1 = 2`.
- Binius oracle linear relations are checked over `B128`; lifting the vectors and checking over `fp128` changes the claimed relation.

The feature-gated bridge tests make this obstruction executable:

```bash
cargo test -p binius-iop --features hachi hachi_bridge -- --nocapture
```

Under the strict target, the Hachi prover/verifier channel is intentionally not wired until a real binary-field-compatible Hachi backend or a separately proven arithmetization bridge exists.

## Batched Parity Bridge And Modulus-Switching Plan

The bridge targets the terminal Binius PCS relation:

```text
y = sum_i t_i * w_i in B128
```

Here `w_i` are committed oracle values and `t_i` are transparent verifier-derived coefficients. Since multiplication by a fixed `B128` coefficient is a linear map over `GF(2)`, each output bit of `y` is the parity of a public linear combination of the 128 bit-slices of the `w_i`.

Hachi's paper uses ring switching to move statements already living over `R_q`/`F_q^k` into finite-field sumchecks by evaluating lifted polynomial-ring identities at a random extension-field point. This is not a direct homomorphic embedding from characteristic two into Hachi's odd-prime field. The sound analogue for Binius is a bounded integer modulus switch: turn every binary parity statement into an exact bounded integer statement, then check that statement modulo Hachi's prime. If all integer bounds are below the checking modulus, equality modulo the prime implies equality over the integers, which implies the original binary-field parity claim.

The sound bridge protocol is:

1. Commit with Hachi to 128 Boolean bit-slice MLEs for the Binius oracle values.
2. Prove Booleanity for the bit-slice commitments: each committed value is in `{0, 1}` over Hachi's prime field.
3. For each output bit `k`, derive a public transparent mask selecting exactly the committed witness bits whose XOR is `y_k`.
4. Open the Hachi bit-slice commitments against those masks to obtain integer sums `S_k`.
5. Prove bounded parity with quotient witnesses `Q_k`:

```text
S_k - y_k = 2 Q_k
0 <= S_k <= public_bound_k
0 <= Q_k <= floor(public_bound_k / 2)
```

6. Batch the 128 parity equations with a random Hachi-field challenge `alpha` sampled after the opened sums and quotients are fixed:

```text
sum_k alpha^k * (S_k - y_k - 2 Q_k) = 0 in fp128
```

7. If any `public_bound_k` is too large for one prime modulus, use CRT-style modulus switching for the integer equality. Check the same bounded equation modulo primes `p_j`, with product `P = prod_j p_j` greater than the maximum possible absolute residual. The CRT checks then imply the exact integer equation.

The range bounds are part of the soundness argument. Without them, a prover could choose arbitrary field elements as quotients because `2` is invertible in an odd prime field. With the bounds and `public_bound_k < p` (or below the CRT product), the field equality implies the intended integer equality, hence the intended parity relation.

For efficiency, the implementation should not produce 128 independent Hachi proofs. It should build one random linear combination of the 128 selected-bit masks and open a single batched linear claim:

```text
S_alpha = sum_k alpha^k S_k
y_alpha = sum_k alpha^k y_k
Q_alpha = sum_k alpha^k Q_k
S_alpha - y_alpha - 2 Q_alpha = 0
```

The prover still commits to quotient/range data, but the terminal PCS opening is batched into one Hachi opening relation. The verifier derives all masks from public `t_i`, samples `alpha` after commitments/openings are fixed, and checks the batched equation plus Booleanity and range/smallness proofs.

The current code is a verifier/prover prototype for this bridge algebra. It computes selected-bit sums directly from witness values, then verifies the same bounded batched parity relation that a full Hachi-backed implementation must verify after receiving Hachi openings.

## Implemented Full-Opening Bridge

The first end-to-end implementation is the `hachi-full-open` example proof path. It is sound because it reveals the terminal Binius oracle and verifies the native `B128` inner-product relation directly, while also carrying and checking the batched bounded parity bridge over Hachi's prime field.

Command:

```bash
cargo run -p binius-examples --features hachi --example keccak -- --max-len-bytes 256 --message-len 256 --compression hachi-full-open
```

Result:

- Prove: 63.58 ms
- Verify: 12.83 ms
- PCS-opening phase: 6.81 ms prover, 12.42 ms verifier
- Proof size: 48,896 bytes (47 KiB)

Implementation points:

- `crates/iop-prover/src/hachi_full_open_channel.rs`
- `crates/iop/src/hachi_full_open_channel.rs`
- `Prover::prove_hachi_full_open`
- `Verifier::verify_hachi_full_open`
- `binius-examples --features hachi --compression hachi-full-open`

This is intentionally the conservative bridge target. The remaining optimization is to replace the full oracle reveal with Hachi batched openings plus Boolean/range proofs for the bit-slice and quotient commitments.

## Succinct Hachi Bridge Execution Plan

The final succinct bridge replaces the full oracle reveal with committed bit-slice polynomials and two sumcheck layers.

1. **Bit-slice commitments**
   - Convert the terminal Binius oracle `w_i in B128` into 128 Hachi-field MLEs `B_j(i) in {0,1}`.
   - Commit all `B_j` with Hachi as one grouped batch.
   - The commitment is the IOP oracle commitment that feeds Fiat-Shamir.

2. **Batched selected-sum opening**
   - The prover sends integer `S_k` and `Q_k` before the batching challenge.
   - The verifier samples `alpha` and forms one selected-sum claim:

   ```text
   S_alpha = sum_k alpha^k S_k
   ```

   - A degree-2 product sumcheck proves

   ```text
   S_alpha = sum_i sum_j B_j(i) * M_{j,alpha}(i)
   ```

   where `M_{j,alpha}` is derived from the transparent `B128` coefficients and the public multiplication-by-basis linear maps.
   - The final sumcheck claim is discharged by one Hachi batched opening of all `B_j` at the sumcheck point.

3. **Booleanity proof**
   - A second degree-2 sumcheck proves

   ```text
   sum_i sum_j B_j(i) * (B_j(i) - 1) = 0
   ```

   - Its final claim is discharged by another Hachi batched opening of all `B_j` at the Booleanity sumcheck point.

4. **Quotient/range proof**
   - The verifier checks public integer bounds:

   ```text
   0 <= S_k <= public_bound_k
   0 <= Q_k <= floor(public_bound_k / 2)
   ```

   - Then it checks the batched bounded parity equation:

   ```text
   sum_k alpha^k * (S_k - y_k - 2 Q_k) = 0
   ```

   - If a bound exceeds one Hachi prime, the same relation is checked modulo enough CRT primes so their product exceeds the maximum residual.

5. **E2E channel**
   - `hachi-full-open` remains the sound reference path.
   - `hachi-succinct` should use the same Binius transcript order but replace the terminal full opening with:
     bit-slice Hachi commitment, selected-sum sumcheck, Booleanity sumcheck, quotient/range checks, and Hachi batched openings.

## Implemented Succinct Hachi Bridge

The `hachi-succinct` path implements the five-step bridge above. It does not reveal the terminal Binius witness oracle. Instead it:

- commits to one Hachi `fp128::D64OneHot` bit-table polynomial `B(i, j)`,
- proves the selected-bit sum with a Fiat-Shamir product sumcheck,
- proves bit-slice Booleanity with a second Fiat-Shamir product sumcheck,
- checks the bounded quotient parity equation,
- discharges both sumcheck final claims with one Hachi batched opening proof over two points.

The optimized implementation treats the bit index as seven additional multilinear variables, committing to one bit-table polynomial `B(i, j)` rather than 128 independent bit-slice commitment groups. The Boolean table is encoded as a 1-of-2 one-hot polynomial with one extra selector variable. This follows the same claim-batch reduction idea used in Jolt: reduce many related claims by random linear combination before handing them to the PCS.

Command:

```bash
cargo run -p binius-examples --features hachi --example keccak -- --max-len-bytes 256 --message-len 256 --compression hachi-succinct
```

Result:

- Prove: 391.00 ms
- Verify: 102.75 ms
- PCS-opening phase: 323.54 ms prover, 86.88 ms verifier
- Proof size: 85,638 bytes (83 KiB)

Implementation points:

- `../lz-hachi/src/protocol/external_bridge.rs` on branch `binius-succinct-bridge`
- `crates/iop/src/hachi_succinct_channel.rs`
- `crates/iop-prover/src/hachi_succinct_channel.rs`
- `Prover::prove_hachi_succinct`
- `Verifier::verify_hachi_succinct`
- `binius-examples --features hachi --compression hachi-succinct`

This is a complete sound e2e bridge and is now in the expected 80-100 KiB proof-size range. The main remaining performance work is verifier-time optimization: precompute/reuse Hachi setup, add a generated schedule table for this bridge shape, and avoid verifier-side transparent-mask materialization.

## Succinct Hachi Optimization Backlog

Current trace for the 256-byte Keccak `hachi-succinct` path:

- Proof size: 85,638 bytes.
- Verify time: 102.75 ms.
- Hachi batched verify: approximately 12.3 ms.
- `HachiProverSetup::new`: approximately 15.6 ms.

Track these as implementation targets for future agents:

- [x] **Precompute/reuse Hachi verifier/prover setup**
  - Status: implemented.
  - Implementation: `Verifier::setup` now builds `HachiSuccinctSetup` once and `Verifier::verify_hachi_succinct` passes it into the verifier channel. `Prover::setup` reuses the same setup handle for the Hachi prover channel.
  - Expected impact: removes `HachiProverSetup::new` from per-proof verification and proof generation. The setup cost still appears during public-parameter setup, where it belongs.

- [x] **Generated schedule table for `num_vars=18`, `num_claims=2` bridge shapes**
  - Status: implemented in the local Hachi path dependency.
  - Implementation: `../lz-hachi` now emits exact-runtime `fp128::D64OneHot` generated schedule rows for both bridge keys:
    - opening: `max_num_vars=18`, `layout_num_claims=2`, `batch_num_claims=2`, `batch_num_commitment_groups=2`, `batch_num_points=2`,
    - commitment/root split: `max_num_vars=18`, `layout_num_claims=2`, `batch_num_claims=2`, `batch_num_commitment_groups=1`, `batch_num_points=1`.
  - Expected impact: the trace now reports the bridge root split as read from the pre-computed table instead of computed from scratch.

- [x] **Derive proof shape from public params**
  - Status: implemented.
  - Implementation: the prover no longer writes `HachiBatchedProofShape` into the Binius transcript. The verifier derives the Hachi proof shape from `log_msg_len`, the fixed two-point/two-claim bridge opening, and Hachi's public schedule.
  - Expected impact: small proof-size reduction and less transcript shape metadata.

- [x] **Compress `S_k` and remove `Q_k`**
  - Status: implemented.
  - Implementation: `S_k` values are bit-packed against verifier-derived public bounds. The verifier unpacks canonical little-endian bitstreams, rejects values above bound or non-zero padding, and checks `S_k mod 2 == y_k` directly.
  - Expected impact: reduces the bridge transcript payload without changing the bounded-parity soundness argument.

- [x] **RLC/compact quotient data**
  - Status: implemented by eliminating quotient payload.
  - Implementation: since the verifier already receives every bounded integer `S_k`, it no longer needs any `Q_k` values or an RLC of quotients. The quotient is conceptually derived from `(S_k - y_k) / 2` after the verifier checks exact integer parity.
  - Expected impact: removes all quotient bytes and parsing work for the 128 parity lanes.

- [x] **Lazy selected-mask evaluation**
  - Status: implemented for the selected-bit mask final check.
  - Implementation: verifier evaluates the selected-bit mask directly at the product-sumcheck point instead of materializing the flattened `(oracle_index, bit_index)` mask table.
  - Remaining work: verifier still reconstructs the transparent coefficient vector over the Boolean hypercube before the bridge check. A deeper optimization would fuse the transparent closure itself into lazy evaluation.

- [x] **Protocol-specific Hachi schedule tuning**
  - Status: first pass implemented.
  - Implementation: the exact bridge opening and commitment/root-split schedules are now pinned in Hachi's generated table for the D64 one-hot path.
  - Remaining work: continue tuning to close the remaining gap between the Hachi batched verifier core and the end-to-end verifier trace.

Latest local result after the second optimization pass:

- Proof size: 83,439 bytes.
- Verify time: 60.43 ms.
- Hachi batched verify: approximately 2.18 ms.
