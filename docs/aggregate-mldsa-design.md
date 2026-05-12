# Succinct N-Aggregate ML-DSA Verification — Design and Roadmap

This document is the canonical design + multi-phase roadmap for the
`binius-mldsa` crate. The goal is a single succinct proof that
**N independent ML-DSA-44 (Dilithium2 / FIPS 204) signatures all verify**.

It mirrors the architecture sketched in the four reference canvases that
live (locally) under
`~/.cursor/projects/Users-taghi-badakhshan-Projects-dilithium/canvases/`:
`mldsa-layer-architecture`, `mldsa-verification-relation`,
`dilithium-sign-flow`, `cross-pcs-evaluation-bridge`,
`matrix-expand-from-rho`. They are the source of truth for the layered
design; this document specialises them into a phased Binius64
implementation plan.

---

## 1. Problem statement

For a fixed parameter set (Phase 0–4 only target Dilithium2 / ML-DSA-44),
build an in-circuit relation
\[
R_{\text{agg}}\big((pk_i, m_i, \text{ctx}_i, \sigma_i)_{i=1}^{N}\big) = 1
\quad\Longleftrightarrow\quad
\bigwedge_{i=1}^{N}\,\text{ML-DSA.Verify}(pk_i, m_i, \text{ctx}_i, \sigma_i)
\]
producible as a single Binius64 (+ Akita-lattice) succinct proof. All
inputs are public.

Concrete success criteria:

- The single-signature verifier (`MlDsaVerifier`) compiles to a Binius64
  constraint system that accepts all KAT vectors from
  `dilithium/ref/nistkat` and rejects single-byte-tampered variants.
- The N-aggregate verifier (`AggregateMlDsaVerifier`) accepts a vector
  of `N ∈ {1, 4, 16, 64}` honest signatures and rejects if any one is
  tampered.
- Verifier wall-clock per signature scales as `O(1)` (independent of `N`)
  once Phase 5 folding lands; through Phase 4 the cost is `O(N)` from
  the flat composition.

---

## 2. Reference architecture (two-track)

The verification relation splits into seven sub-relations (R1–R7). R2
(`tr, μ`) and R4 (`A = ExpandA(ρ)`) are pure hashes of public inputs and
are hoisted to the verifier (no proof cost). The remaining five live in
two tracks:

```mermaid
flowchart TB
    subgraph publicInputs [Layer 1 - Public statement]
        Sig["sigma = (c~, z, h)"]
        Pk["pk = (rho, t1)"]
        Msg["m, ctx"]
    end

    subgraph hoisted [Verifier precomputation - hoisted, no proof cost]
        Tr["R2: tr = SHAKE256(pk)"]
        Mu["R2: mu = SHAKE256(tr || pre || m)"]
        ExpandA["R4: A = ExpandA(rho)"]
        T1Shift["t1 * 2^D from pkDecode"]
    end

    subgraph binius [Layer 2 - Binius64 track]
        SigDecode["R1: sigDecode + ||z|| < gamma1 - beta"]
        SampleInBall["R3: c = SampleInBall(c~)"]
        UseHint["R6: w1' = UseHint(Decompose(w), h) + w1Encode"]
        FinalHash["R7: c~' = SHAKE256(mu || w1') and c~' == c~"]
    end

    subgraph akita [Layer 3 - Akita lattice track]
        RingArith["R5: w = A.z - c.t1.2^D in Z_q[X]/(X^256 + 1)"]
    end

    subgraph pcs [Layer 4 - PCS]
        AkitaPcs["Akita lattice PCS over fp128"]
    end

    Pk --> Tr --> Mu
    Msg --> Mu
    Pk --> ExpandA
    Pk --> T1Shift
    Sig --> SigDecode
    SigDecode --> SampleInBall
    Mu --> FinalHash

    SigDecode -- "z bridge" --> RingArith
    SampleInBall -- "c bridge" --> RingArith
    ExpandA --> RingArith
    T1Shift --> RingArith
    RingArith -- "wApprox bridge" --> UseHint
    UseHint --> FinalHash

    binius --> AkitaPcs
    akita --> AkitaPcs
```

The three horizontal **cross-field bridges** are:

- `z` (`L = 4` polynomials, each 256 coefficients in `Z_q`): Binius64 → Akita
- `c` (sparse polynomial, `τ = 39` non-zero `±1` coefficients): Binius64 → Akita
- `wApprox` (`K = 4` polynomials, each 256 coefficients in `Z_q`): Akita → Binius64

---

## 3. Sub-relation decomposition

| Sub-relation | Where | Proof system | Phase to land |
|---|---|---|---|
| R1 — sigDecode + `‖z‖ < γ₁ − β` (`L · 256 = 1024` range checks) | Binius64 | `verifier::range::z_norm_check` | Phase 1 |
| R2 — `tr = H(pk)`, `μ = H(tr ‖ pre ‖ m)` | hoisted | verifier-side `sha3` | (none) |
| R3 — `c = SampleInBall(c̃)` (Fisher–Yates over SHAKE256) | Binius64 | `verifier::sample_in_ball` | Phase 1 |
| R4 — `A = ExpandA(ρ)` (`K·L = 16` SHAKE128 streams) | hoisted | verifier-side `sha3` | (none) |
| R5 — `w = A·z − c·t₁·2^D` (`K·L + K = 20` ring multiplications) | Akita lattice | `lattice::ring_arith` | Phase 2 |
| R6 — `Decompose` + `UseHint` + `w1Encode` (`K · 256 = 1024` operations) | Binius64 | `verifier::hint::use_hint` | Phase 1 |
| R7 — `c̃' = SHAKE256(μ ‖ PackW1(w₁'))` and `c̃' == c̃` | Binius64 | `verifier::final_hash` | Phase 1 |

Per the canvas's cost analysis tab, R7's single SHAKE256 evaluation
dominates the in-circuit cost at 30–60 % of total constraints; replacing
SHAKE256 with an algebraic hash (Poseidon / Rescue) is a future
optimisation (Phase 6+), not in scope here.

---

## 4. Cross-field bridge

The bridge between Binius64 (binary tower over `BinaryField128bGhash`,
addition = XOR) and Akita (prime field `fp128`, addition = mod-p) is
the same algebraic problem as the Akita PCS bridge already solved in
`crates/akita-bridge/`: the lift is not a field homomorphism, so we
bit-decompose, commit the bit table over Akita, and reconnect via a
parity bridge + sumchecks.

### 4.1 Option A — public-output bridge (Phase 2 MVP)

Each of `z`, `c`, `wApprox` is exposed as a **public output** of both
the Binius64 sub-proof and the Akita sub-proof. The outer transcript
runs an equality check after the two sub-proofs verify
independently. Pros: trivial composition, no new soundness machinery.
Cons: (a) leaks the signature-derived intermediate values into the
transcript (acceptable here since all ML-DSA inputs are public), (b)
proof size grows linearly in the bridge data (`L · 256 + τ + K · 256
≈ 2.3 K coefficients in Z_q ≈ 7 KiB raw per signature`).

### 4.2 Option B — cross-field commitment (Phase 3)

Both sides commit to the bridge data — Binius64 commits the bit-slice
table, Akita commits the field-element form — and prove they commit to
the same values via a parity bridge + selected-bit sumcheck + Booleanity
sumcheck, exactly as in `crates/akita-bridge/src/protocol.rs`. The
machinery is already there for the witness oracle; Phase 3 generalises
it to arbitrary "shared" wires.

Once Phase 3 lands, the bridge becomes succinct: cost grows only
logarithmically in the bridge data size.

---

## 5. Aggregation

Three strategies are available per the canvas's Aggregation tab:

| Strategy | Per-step cost | Proof size | Streaming | When |
|---|---|---|---|---|
| Flat composition | `N · C` | `O(1)` | no | small `N` (≤ 16); Phase 4 MVP |
| Recursive SNARK (IVC) | `C + C_verifier` | `O(1)` | yes | medium `N`; later Phase 5 |
| Folding (Nova / Protogalaxy) | `C + C_fold` (≈ 1 MSM) | `O(1)` | yes | large `N`; production target, Phase 5 |

**Bridge sharing under aggregation**: the bridge transcript can be
shared across all `N` per-signature instances — the parity bridge and
both sumchecks can batch over the aggregate (concatenated) witness
oracle. This drops the bridge cost from `O(N · log B)` to `O(log(N·B))`
where `B` is the per-signature bridge size. Phase 4 implements this
sharing.

---

## 6. Phase plan

### Phase 0 — scaffolding (this PR)

- [x] New `binius-mldsa` crate at [`crates/mldsa/`](../crates/mldsa/).
- [x] Dilithium2 constants in [`crates/mldsa/src/params.rs`](../crates/mldsa/src/params.rs).
- [x] `Z_q` (Q = 8 380 417, 23-bit) field gadgets in
  [`crates/mldsa/src/zq.rs`](../crates/mldsa/src/zq.rs):
  `add`, `sub`, `mul`, `from_u64_witness` — proptest-validated against
  the native reference in [`crates/mldsa/tests/zq.rs`](../crates/mldsa/tests/zq.rs).
- [x] SHAKE256 single-block wrapper in
  [`crates/mldsa/src/shake.rs`](../crates/mldsa/src/shake.rs), cross-validated
  against the `sha3` crate in
  [`crates/mldsa/tests/shake.rs`](../crates/mldsa/tests/shake.rs).
- [x] `MlDsaVerifier` and `AggregateMlDsaVerifier` `unimplemented!()`
  stubs whose tests are `#[ignore]`'d with phase pointers (see
  [`crates/mldsa/tests/verifier_smoke.rs`](../crates/mldsa/tests/verifier_smoke.rs)).
- [x] This design doc.

### Phase 1 — single-signature verifier, single-track

Goal: a working `MlDsaVerifier` that takes (`pk, sig, μ, c, A, t₁·2^D,
wApprox`) as public inputs (R5 hoisted to the verifier — it natively
runs `w = A·z − c·t₁·2^D` and feeds the result in) and proves R1 + R3
+ R6 + R7 in Binius64.

- R1: `sigDecode` (bit-packed `z` / `h` decoding) + `‖z‖ < γ₁ − β`
  (1024 range checks).
  - [x] `polyz_unpack_centered` (576-byte → 256-coefficient unpacker)
    and `assert_norm_centered` (`β < centered < 2γ₁ − β` per coefficient)
    in [`crates/mldsa/src/polyz.rs`](../crates/mldsa/src/polyz.rs); 14
    tests in [`crates/mldsa/tests/polyz.rs`](../crates/mldsa/tests/polyz.rs).
  - [ ] `unpack_z` wrapper for the `L = 4` polynomials inside the full
    signature byte stream (composes 4 × `polyz_unpack_centered`).
  - [ ] `unpack_c_tilde` (trivial: 32 bytes → 4 × 64-bit lanes).
  - [ ] `unpack_h` (variable-length hint encoding with rejection
    conditions; non-trivial since the C parser has data-dependent
    control flow — needs a multiplexer-based design).
- [ ] R3: `SampleInBall(c̃)` — extends `shake::shake256_fixed` to a
  multi-block streaming API; emits a sparse polynomial with `τ = 39`
  `±1` non-zero coefficients via Fisher-Yates.
- [ ] R6: `Decompose` + `UseHint` + `w1Encode` over the 1024
  `wApprox` coefficients, using `zq` gadgets.
- [ ] R7: `c̃' = SHAKE256(μ ‖ w₁')` + binding equality `c̃' == c̃`.
- [ ] Wire up KAT verification: pull KATs from
  `dilithium/ref/nistkat`, run them through the `binius-prover` /
  `binius-verifier` end-to-end, flip on
  `mldsa_verifier_accepts_honest_dilithium2_signature` and
  `mldsa_verifier_rejects_tampered_signature`.
- [ ] Bench prover / verifier per signature in
  `crates/mldsa/benches/single_signature.rs`.

Out-of-scope for Phase 1: the actual lattice computation; Akita;
aggregation.

### Phase 2 — bring R5 into the proof via Akita lattice + Option-A bridge

Goal: replace the "hoisted `wApprox`" hack with a real R5 sub-proof.

- [ ] Implement `lattice::ring_arith` that proves
  `w = A·z − c·t₁·2^D` in `Z_q[X]/(X²⁵⁶ + 1)` using the Akita PCS for
  the bit-table commitments to `z`, `c`, `wApprox`. This requires
  upstream `akita-prover` to expose lattice-ring arithmetic
  (currently it only does PCS); coordinate with the Akita
  maintainers.
- [ ] Wire up Option-A bridge (`z`, `c`, `wApprox` exposed as outer
  public outputs; outer transcript checks equality between the
  Binius64 and Akita sub-proofs).
- [ ] End-to-end smoke test: same KATs, both sub-proofs accept, and
  the bridge equality holds.

### Phase 3 — replace Option-A bridge with Option-B succinct bridge

Goal: drop the linear-in-bridge-data cost.

- [ ] Reuse the parity bridge / selected-bit sumcheck / Booleanity
  sumcheck primitives from
  [`crates/akita-bridge/src/protocol.rs`](../crates/akita-bridge/src/protocol.rs)
  to commit the bridge data once and prove cross-field equality.
- [ ] Replace the public-output equality check from Phase 2 with the
  succinct bridge proof.
- [ ] Bench: target ≤ 5 % overhead vs Phase 2 in-circuit, and a proof
  size that grows logarithmically (not linearly) in `L · K · N`.

### Phase 4 — N-aggregate via flat composition

Goal: working `AggregateMlDsaVerifier` for `N ∈ {1, 4, 16, 64}` of
Dilithium2 signatures, with shared bridge.

- [ ] Generalise `MlDsaVerifier::new` to take a `subcircuit` namespace
  so `N` instances live cleanly under `agg/sig0`, `agg/sig1`, … in the
  constraint graph.
- [ ] Share the cross-field bridge transcript across all `N`
  instances (single batched parity bridge + sumcheck over the
  aggregate witness oracle).
- [ ] Wire up `aggregate_mldsa_verifier_accepts_n_honest_signatures`
  for `N = 4`.
- [ ] Bench `(prove, verify, proof_size)` matrix against
  `N ∈ {1, 2, 4, 8, 16, 32, 64}` in
  `crates/mldsa/benches/aggregate.rs`.

### Phase 5 — folding-based aggregation (production target)

Goal: drop the per-step cost from `O(C)` to roughly one MSM.

- [ ] Pick a folding scheme compatible with Binius64's commitment
  layer (Nova-style with FRI, or Protogalaxy if a polynomial-commitment
  matching scheme exists; this is itself a research question).
- [ ] Implement an in-circuit verifier for the folding step.
- [ ] Stream-aggregate over arbitrary `N` with constant per-step cost.

### Phase 6+ — out-of-scope optimisations

- [ ] Modes 3 / 5 (ML-DSA-65 / -87) parameterisation. The current
  `Mode` enum is forward-compatible but nothing else in the crate
  currently keys off `Mode::Mode3` / `Mode5`.
- [ ] Replace SHAKE256 with an algebraic hash (Poseidon / Rescue) in a
  Dilithium variant tailored for proofs — would roughly halve circuit
  size per the canvas cost analysis.

---

## 7. Open research questions

The following items are genuinely undecided and are flagged so future
phases don't over-commit:

1. **Mod-Q reduction in `Z_q`**: Phase 0 uses a hinted `(quotient,
   remainder)` pattern. Barrett reduction with a precomputed inverse
   would also work and might be cheaper at scale; revisit during
   Phase 1 once R5 / R6 reveal the multiplication count.
2. **NTT representation in R5**: do we keep `z`, `c`, `wApprox` in
   coefficient form throughout, or do an in-circuit NTT once at the
   start of R5? The reference C implementation does an NTT-domain
   multiply; the right answer in-circuit depends on the cost of NTT
   butterflies vs naive polynomial multiplication via convolution.
3. **Folding scheme for Phase 5**: Nova-on-FRI (e.g. HyperNova) vs
   Protogalaxy vs nothing-yet. Tied to what the binius-iop / akita
   stack ergonomically supports for an in-circuit verifier.
4. **In-circuit verifier of the cross-field bridge for Phase 5**: if
   we recurse, the cross-field bridge proof itself needs to be
   in-circuit-verifiable, which is a non-trivial extension of the
   current akita-bridge.

---

## 8. References

- **Canvases (local, Cursor)**:
  - `~/.cursor/projects/Users-taghi-badakhshan-Projects-dilithium/canvases/mldsa-layer-architecture.canvas.tsx`
  - `~/.cursor/projects/Users-taghi-badakhshan-Projects-dilithium/canvases/mldsa-verification-relation.canvas.tsx`
  - `~/.cursor/projects/Users-taghi-badakhshan-Projects-dilithium/canvases/dilithium-sign-flow.canvas.tsx`
  - `~/.cursor/projects/Users-taghi-badakhshan-Projects-dilithium/canvases/cross-pcs-evaluation-bridge.canvas.tsx`
  - `~/.cursor/projects/Users-taghi-badakhshan-Projects-dilithium/canvases/matrix-expand-from-rho.canvas.tsx`
- **Specifications**:
  - [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
  - Reference C implementation:
    `/Users/taghi.badakhshan/Projects/dilithium/ref/`
- **Adjacent in this repository**:
  - [`docs/akita-bridge-design-and-benchmarks.md`](akita-bridge-design-and-benchmarks.md)
    — the lattice-PCS bridge that R5 will eventually ride.
  - [`crates/akita-bridge/src/protocol.rs`](../crates/akita-bridge/src/protocol.rs)
    — the parity-bridge / sumcheck primitives that Phase 3 reuses.
  - [`docs/latex-write-up/akita-bridge.tex`](latex-write-up/akita-bridge.tex)
    — formal protocol spec of the lattice-PCS bridge.
