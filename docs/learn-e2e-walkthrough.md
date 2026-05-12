# Binius64 End-to-End Walkthrough: A Tiny Example, Step by Step

This document follows one tiny circuit through every layer of the Binius64
prove/verify pipeline. The goal is pedagogical: connect the mathematics to the
actual data structures that flow through the code, with concrete numbers
captured by running the test in
`crates/prover/tests/learn_e2e.rs`.

Run it yourself:

```bash
cargo test -p binius-prover --test learn_e2e learn_e2e_minimal -- --nocapture
```

> **Branch note**: This walkthrough lives on `taghi/learn-e2e`. The optional
> `hachi-pcs` dependency is commented out so the workspace builds without the
> external `lz-hachi` repo. The pipeline below uses **BaseFold** as the PCS,
> which is fully implemented. The first six steps are identical for the Hachi
> backend — only steps 7 and 8 (PCS opening) differ. See
> `docs/mldsa-over-binius-architecture.md` for how Hachi replaces BaseFold.

## The Example

Prove that someone knows a private 64-bit value `private` such that
`private & 0xFF00 == 0x1200`. We use `private = 0x1234`, which gives
`0x1234 & 0xFF00 = 0x1200` ✓.

```rust
let mask    = builder.add_constant_64(0xFF00);   // public constant
let private = builder.add_witness();              // secret
let output  = builder.add_inout();                // public output

let result = builder.band(private, mask);         // result = private & mask
builder.assert_eq("masked_result", result, output);
```

That looks like one AND. The actual constraint system has two ANDs: one for
the `band` gate and one for the `assert_eq`.

## Step 0: Field arithmetic primer

Two binary extension fields appear throughout this walkthrough.

| Field | Size | Used for | Defined in |
|---|---|---|---|
| **B1** = GF(2) | 1 bit | the witness, viewed bit by bit | `binius_field::BinaryField1b` |
| **B128** = GF(2^128) (GHASH) | 128 bits | sumcheck challenges, MLE values | `binius_field::BinaryField128bGhash` |

GF(2^128) is the quotient `GF(2)[X] / p(X)` for the GHASH irreducible
`p(X) = X^128 + X^7 + X^2 + X + 1`. Elements are 128-bit vectors:

- **Addition** is bitwise XOR. So `1 + 1 = 0`.
- **Multiplication** is polynomial multiplication mod `p(X)`. The CPU does
  this with one carry-less mul (`pclmulqdq` / `pmull`) and a reduction.

A side field, **B8** = `AESTowerField8b`, also appears. It is GF(2^8) with the
AES-tower irreducible. The protocol uses three deterministic B8 challenges
that are baked into the proof system and lifted into B128 when needed.

**Important**: lifting B8 → B128 is **not** the natural u8 → u128 zero-extend
because B8 and B128 use different irreducibles. In the example output:

```
r[0] = AES8b(0x02) → B128 = 0x0dcb364640a222fe6b8330483c2e9849
```

The number `0x02` in B8 maps to a structured 128-bit value through an
isomorphism, not through bit-padding.

---

## Step 1: Build the circuit

Output:

```
[1] Circuit
    AND constraints: 2
    MUL constraints: 0
    Gates:           2
```

Two AND constraints, no multiplications. The `band` gate produces one AND
constraint; the `assert_eq` produces a second.

## Step 2: Constraint system layout

The `ValueVec` is the array of all 64-bit words known to the proof system —
constants, inputs/outputs, witness, and intermediate values. It must have
length a power of two. Padding fills any gaps.

Output for our circuit:

```
[2] ValueVecLayout
    n_const=2, n_inout=1, n_witness=1, n_internal=1
    offsets: inout=2, witness=4
    committed_total_len = 8 (= 2^3)

    ValueVec contents:
      v0 = 0x000000000000ff00  (const)
      v1 = 0xffffffffffffffff  (const)
      v2 = 0x0000000000001200  (inout)
      v3 = 0x0000000000000000  (padding)
      v4 = 0x0000000000001234  (witness)
      v5 = 0x0000000000001200  (internal)
      v6 = 0x0000000000000000  (padding)
      v7 = 0x0000000000000000  (padding)
```

Two interesting observations:

1. **An extra constant `v1 = 0xFFFF...FFFF` appeared.** It's there to encode
   `assert_eq` (see next step).
2. **`v3` is padding** because the public segment (constants + inout) must
   itself be a power-of-two size. With 2 constants + 1 inout = 3, we round up
   to 4, with `v3` as filler.

The two AND constraints:

```
constraint 0:
    A = v4
    B = v0
    C = v5
constraint 1:
    A = v5 XOR v2
    B = v1
    C = 0
```

Reading them:

- **Constraint 0** says `v4 & v0 = v5`, i.e. `private & mask = result`.
- **Constraint 1** says `(v5 XOR v2) & v1 = 0`. Since `v1` is all-ones, this
  is `v5 XOR v2 = 0`, i.e. `v5 = v2`. That is the `assert_eq` between
  `result` and `output`.

The trick: equality is enforced as `(a XOR b) & ALL_ONES = 0`. XOR is zero
iff the values are equal; the all-ones AND is a no-op that lets us reuse the
AND-only constraint shape.

## Step 3: AND-reduction column vectors

The 2 AND constraints become three vectors `a[]`, `b[]`, `c[]`, each of
length 2 (one entry per constraint):

```
[3] AND-reduction columns
      i=0: a=0x...1234, b=0x...ff00, c=0x...1200    a & b = 0x...1200 ✓
      i=1: a=0x...0000, b=0x...ffff, c=0x...0000    a & b = 0x...0000 ✓
```

For constraint 1, `a = v5 XOR v2 = 0x1200 XOR 0x1200 = 0`, `b = 0xFFFF...`, so
`a & b = 0`. Correct.

These vectors are the operand evaluations. The prover must convince the
verifier that for **every** `i` in the constraint axis,

$$a_i \;\&\; b_i \;=\; c_i \quad \text{(64-bit bitwise AND)}.$$

Equivalently, every individual bit must satisfy the relation. Writing
$a_i^{(j)}$ for bit `j` of constraint `i`'s `a`-operand:

$$\forall i \in [0, N), \forall j \in [0, 64): \; a_i^{(j)} \cdot b_i^{(j)} = c_i^{(j)} \quad (\text{in } GF(2))$$

In our run, `N = 2`, so there are `2 × 64 = 128` individual bit equations.
Both columns have only two nonzero bits (bit 9 and bit 12 of constraint 0),
so most equations are trivially `0 · 0 = 0`.

## Step 4: Encoding the AND relation as a multilinear polynomial identity

We bundle the bit equations into one polynomial identity. Define three
multilinear extensions:

$$A(Z, X), \; B(Z, X), \; C(Z, X)$$

where
- **Z** indexes the 64 bit positions inside one word (so 6 Boolean variables).
- **X** indexes the constraint number (so 1 Boolean variable for our example;
  generally, $\log_2 N$ variables).

By construction, on Boolean inputs:

$$A(j, i) = a_i^{(j)} \in \{0, 1\}, \quad B(j, i) = b_i^{(j)}, \quad C(j, i) = c_i^{(j)}.$$

That is, $A$ is the unique multilinear polynomial that *interpolates* the bit
table — its values at the 128 corners $(j, i) \in \{0,1\}^7$ are exactly the
128 individual bits of the `a[]` column from Step 3, and similarly for $B$
and $C$.

The AND constraint becomes the polynomial identity

$$A(Z, X) \cdot B(Z, X) - C(Z, X) \;=\; 0 \quad \forall (Z, X) \in \{0,1\}^7$$

over GF(2^128).

### Why two fields appear: GF(2) and GF(2^128)

This is a common point of confusion. Two different fields show up, and they
play different roles:

- **GF(2)** $= \{0, 1\}$: the field where the original *bit equations* live.
  Each $a_i^{(j)}$ is a single bit, and the AND relation
  $a_i^{(j)} \cdot b_i^{(j)} = c_i^{(j)}$ is multiplication in GF(2)
  (which is just bitwise AND on single bits).

- **GF(2^128)**: the field where the *polynomials* $A, B, C$ are evaluated
  during the proof. Coefficients live in GF(2^128), and the prover/verifier
  exchange random challenge points drawn from this large field.

The two are compatible because GF(2) is a **subfield** of GF(2^128): the
elements 0 and 1 of GF(2) are literally the additive and multiplicative
identities of GF(2^128). So a "bit value" is automatically also a GF(2^128)
value — no conversion needed.

Concretely, the polynomial $A(Z, X)$ is a function

$$A : \mathbb{F}_{2^{128}}^7 \to \mathbb{F}_{2^{128}}$$

that accepts any 7-tuple of GF(2^128) elements and returns a GF(2^128)
element. But it has a special property: when restricted to the Boolean cube
$\{0,1\}^7$ (a tiny corner of its full domain), it returns the original bit
values.

| Where we evaluate $A$ | Input type | Output |
|---|---|---|
| Boolean cube $\{0,1\}^7$ (the 128 corner points) | bits | bits ($\in \{0, 1\}$) |
| A random point $r \in \mathbb{F}_{2^{128}}^7$ | general 128-bit element | general 128-bit element |

The same is true for $B$ and $C$. The polynomial identity above only needs
to hold *on the Boolean cube* — that's all the original bit equations
require. Outside the cube, the values of $A \cdot B - C$ can be arbitrary.

### Why we need the larger field GF(2^128)

The verifier cannot afford to check the identity at all 128 cube corners
directly — that's what we're trying to avoid in the first place. Instead, it
samples a *random challenge* $r$ and asks the prover to evaluate
$A(r) \cdot B(r) - C(r)$. Soundness comes from **Schwartz-Zippel**: if a
nonzero polynomial of degree $d$ is evaluated at a uniformly random point in
$\mathbb{F}^n$, the probability it accidentally evaluates to zero is at most
$d / |\mathbb{F}|$.

- Over **GF(2)**: $|\mathbb{F}| = 2$, so a cheating prover wins with
  probability $\geq 1/2$. Useless for cryptography.
- Over **GF(2^128)**: $|\mathbb{F}| = 2^{128} \approx 3.4 \times 10^{38}$,
  so a cheater wins with probability $\leq d \cdot 2^{-128}$. Negligible.

The lift to GF(2^128) is purely for soundness — it gives the verifier
"enough room" to issue an unpredictable challenge. The witness data itself
is unchanged: the bits stay bits, but the polynomial that represents them
now lives in a much larger ambient field.

### The zerocheck protocol

The prover's job: convince the verifier the identity above holds, **without
revealing $A, B, C$ themselves**. The standard tool is the **zerocheck**.

The verifier picks a random point $r \in \mathbb{F}_{2^{128}}^7$ and asks
the prover to prove

$$\sum_{(Z, X) \in \{0,1\}^7} (A B - C)(Z, X) \cdot \mathrm{eq}((Z,X); r) \;=\; 0$$

where $\mathrm{eq}((Z,X); r)$ is the multilinear equality polynomial that
evaluates to 1 at the corner equal to $r$ (and interpolates between corners
elsewhere). The sum equals 0 **iff** $A \cdot B - C$ vanishes on every
Boolean cube point — which is exactly the AND relation we want.

#### Why this works (the careful version)

A common pitfall: one might think the verifier can just evaluate $A \cdot B - C$ at a random $r$ and check if it's zero. **This does not work**, because
"$A \cdot B - C$ vanishes on the Boolean cube" is *strictly weaker* than
"$A \cdot B - C$ is the zero polynomial." A nonzero polynomial can vanish on
the cube — for example, $x(1-x)$ vanishes at $x \in \{0,1\}$ but is not
identically zero. So evaluating $A \cdot B - C$ at a random $r$ would fail
on honest provers (false negatives) and pass cheating provers (false
positives).

The eq-weighted sum is the right reformulation:

$$\sum_{x \in \{0,1\}^n} f(x) \cdot \mathrm{eq}(x; r) \;=\; \tilde{f}(r)$$

where $\tilde{f}$ is the *multilinear extension* of $f$ restricted to the
cube — i.e., the unique multilinear polynomial that interpolates $f|_{\{0,
1\}^n}$. This sum equals 0 iff $\tilde{f}$ is the zero polynomial iff $f$
vanishes on every cube point. So the sum being zero is equivalent to the
AND relation holding everywhere.

#### Soundness via the sumcheck protocol

The verifier doesn't actually compute the sum directly — that would require
$2^7$ evaluations, defeating the purpose. Instead, it runs the **sumcheck
protocol** on the eq-weighted sum, which reduces

$$\sum_{x \in \{0,1\}^7} g(x) \;=\; 0 \quad \text{where } g = (A B - C) \cdot \mathrm{eq}(\cdot; r)$$

to a single point evaluation $g(r_1, \ldots, r_7)$ at random challenges
$r_i \in \mathbb{F}_{2^{128}}$, in $\log_2(2^7) = 7$ rounds.

The soundness analysis comes from sumcheck, not from Schwartz-Zippel on
$A \cdot B - C$ directly. In each round, the prover sends a univariate
polynomial whose degree equals the **per-variable degree** of $g$:

| Factor | Per-variable degree |
|---|---|
| $A$ (multilinear) | 1 |
| $B$ (multilinear) | 1 |
| $A \cdot B$ | 2 |
| $C$ (multilinear) | 1 |
| $A \cdot B - C$ | 2 |
| $\mathrm{eq}(\cdot; r)$ (multilinear) | 1 |
| $g = (A B - C) \cdot \mathrm{eq}$ | **3** |

Per-round soundness error: $\leq 3 / 2^{128}$. Over 7 rounds:

$$\Pr[\text{cheater succeeds}] \;\leq\; 7 \cdot \frac{3}{2^{128}} \;=\; \frac{21}{2^{128}}$$

Negligible.

#### A note on degrees

You may wonder where the **total** degree of $A \cdot B - C$ enters: it
doesn't directly govern soundness in the zerocheck protocol, but it's still
a useful quantity to keep in mind.

- Each multilinear polynomial in 7 variables has total degree $\leq 7$
  (degree 1 per variable, 7 variables).
- The product of two multilinear polynomials is no longer multilinear: each
  variable can appear with degree up to 2, giving total degree
  $\leq 7 + 7 = 14$.
- So $A \cdot B - C$ has total degree at most $14$.

This is why $A \cdot B$ is sometimes called a **degree-2** polynomial
identity: it's degree 2 in the multilinear basis (i.e., it's the product of
2 multilinear factors), even though its total degree as an algebraic
polynomial is up to $14$. The zerocheck soundness analysis uses the
per-variable degree (2 for $A \cdot B$, 3 once $\mathrm{eq}$ is included),
not the total degree.

This is the foundational efficiency gain of the IOP approach: turning
$N \cdot 64 = 128$ bit equations (in our toy circuit) into a small-round
interactive argument with $\approx 21 / 2^{128}$ soundness error.

In its **un-optimized form**, this would be a 7-round vanilla sumcheck
(one round per Boolean variable). Binius further compresses it: the
**univariate-skip trick** (described below) collapses the 6 bit-axis
rounds into a single non-sumcheck round, leaving only $1 + \log_2 N$
rounds total ($1 + 1 = 2$ for our toy circuit, $1 + 18 = 19$ for
ML-DSA-44).

Output:

```
[4] AND reduction parameters
    n_constraints = 2 = 2^1
    bit-axis variables: 6
    constraint-axis variables: 1
    total Boolean variables: 7
    small-field zerocheck challenges (first 1 of 3 baked-in):
      r[0] = AES8b(0x02) → B128 = 0x0dcb364640a222fe6b8330483c2e9849
```

### Two distinct kinds of challenges in the zerocheck

Before going further, it's worth being explicit that the zerocheck protocol
has **two** kinds of random challenges that play very different roles:

| Challenge | Purpose | Field | When sampled |
|---|---|---|---|
| **Eq-indicator anchor point** $r$ | Defines the weighted sum $\sum_x f(x) \cdot \mathrm{eq}(x; r)$ | First $k$ components in **B8** (deterministic), rest in **B128** (Fiat-Shamir) | Once, before sumcheck starts |
| **Per-round sumcheck folding challenges** $z_i$ | Fold the multilinear into a smaller table per round | **B128 always** | Once per round, sampled from Fiat-Shamir |

The "small-field zerocheck challenges" printed in the output above are the
**first kind** — components of the eq-indicator anchor point $r$, decided
upfront. They are *not* the per-round folding challenges (which are
always sampled fresh from B128 inside the sumcheck protocol).

### Anatomy of the eq-indicator anchor point

The anchor point $r$ has $\log_2 N$ components — one per constraint-axis
variable. It's split into two parts:

- **Small-field part** (first $k = \min(\log_2 N, 3)$ components):
  the **deterministic** B8 values `[0x02, 0x04, 0x10]` (truncated to $k$
  entries). Both prover and verifier know these constants ahead of time;
  they are *not* sampled from the transcript. Why exactly 3 max?
  Because $\dim_{\mathbb{F}_2}(B_8) = 8$, and the tensor expansion of $k$
  B8 elements gives $2^k$ products — so $k = 3$ gives exactly 8 products,
  matching the dimension of B8 over $\mathbb{F}_2$.
- **Big-field part** (remaining $\log_2 N - k$ components): sampled from
  the Fiat-Shamir transcript as fresh B128 elements.

For our toy circuit, $\log_2 N = 1$, so $k = \min(1, 3) = 1$. We use just
**one** small-field challenge: $r_0 = $ `AES8b(0x02)`. There are zero
big-field challenges.

### Why the small-field part is split out (two independent reasons)

The small-field design earns its complexity from **two separate** wins:

1. **Speed in Phase 1's inner loop.** The Phase 1 univariate-skip
   computation runs on the entire witness, with the eq-indicator weighting
   each cube vertex. By keeping the eq-indicator's first $k$ components
   in B8, the inner-loop arithmetic uses **packed B8 operations** (16-lane
   SIMD, ~16× faster than B128 per multiplication). This dominates the
   AND-reduction cost.

2. **Soundness without randomness.** Normally a zerocheck challenge must
   be unpredictable to the prover. But the small-field components are
   hardcoded — *no randomness involved*. This is sound because the
   deterministic values `[0x02, 0x04, 0x10]` are chosen so their tensor
   product expansion forms an $\mathbb{F}_2$-basis of $B_8$
   (see Step 4's discussion of why those exact constants). The
   basis-spanning property substitutes for the Schwartz-Zippel argument
   that randomness would normally provide.

These two wins are independent: the **basis property** (point 2) gives
soundness, the **B8-ness** (point 1) gives speed. The protocol gets both.

### Where the upcast B8 → B128 happens

You might wonder: if the small-field challenges are B8, but Phase 2's
sumcheck is in B128, isn't the speed advantage thrown away when we
convert? No — because the upcast happens *after* Phase 1's expensive
inner loop has completed. Concretely:

```
Phase 1 inner loop (B8, hot path)  ──→  O(N) packed-B8 SIMD ops
                                           │
                                           ▼
Upcast 3 scalar B8 challenges to B128  ──→  O(1) trivial casts
                                           │
                                           ▼
Phase 2 sumcheck (B128, log N rounds)  ──→  Standard B128 mlecheck
```

The upcast is plumbing — three constant casts at the Phase 1→Phase 2
boundary. The B8 work over $O(N)$ field elements has already been
extracted by the time the upcast runs.

### The univariate-skip trick (Phase 1 in detail)

The 6 bit-axis variables are not handled with 6 sumcheck rounds. They are
collapsed into **one round** by sending a univariate polynomial $R_0(Z)$
of degree at most 126:

$$R_0(Z) \;=\; \sum_{X \in \{0,1\}^{\log N}} (A(Z,X) B(Z,X) - C(Z,X)) \cdot \mathrm{eq}(X; r_X).$$

#### The two domains $D_0 \subset D$

$R_0(Z)$ is evaluated on an $\mathbb{F}_2$-linear subspace of $B_8$ (the
AES-tower 8-bit field), lifted into B128 when sent. Two nested subspaces
are involved:

| Subspace | Dimension | Size | Role |
|---|---|---|---|
| $D_0 = \mathrm{span}_{\mathbb{F}_2}\{1, \beta, \beta^2, \ldots, \beta^5\}$ | 6 | 64 | the **input domain**: its 64 elements are identified with the 64 bit positions of one 64-bit word |
| $D = \mathrm{span}_{\mathbb{F}_2}\{1, \beta, \beta^2, \ldots, \beta^6\}$ | 7 | 128 | the **output (extrapolation) domain**: large enough to uniquely determine the degree-126 polynomial $R_0$ |

where $\beta$ is the canonical generator of $B_8$ over $\mathbb{F}_2$.
$D_0$ is exactly the lower half of $D$ (the 7th basis element $\beta^6$ is
toggled to switch halves).

The bit-position-to-element identification is:
$\text{bit } j \in \{0, ..., 63\} \;\leftrightarrow\; u_j = \sum_{i=0}^{5} j_i \cdot \beta^i \in D_0$,
where $j_5 j_4 \ldots j_0$ is the binary expansion of $j$. So
$A(u_j, X)$ is exactly bit $j$ of the operand $A$ at constraint $X$.

#### Why $D_0$ is "free"

Because the AND constraint says
$A(u_j, X) \cdot B(u_j, X) = C(u_j, X)$ for every bit position $j$ and
every constraint $X$, the polynomial expression
$A(Z, X) B(Z, X) - C(Z, X)$ is **identically zero on
$D_0 \times \{0,1\}^{\log N}$**. Summing over $X$ with eq weights, $R_0(Z)$
**vanishes on all 64 elements of $D_0$**.

The prover therefore only sends the **64 evaluations on the upper half
$D \setminus D_0$**. The verifier supplies the 64 zeros on $D_0$ for
free. Together they have all 128 evaluations on $D$, which uniquely
determine $R_0$ (degree 126 ≤ 127 = $|D|-1$).

#### Why the extra dimension (going from $D_0$ to $D$)

$A(Z,X)$ and $B(Z,X)$, viewed as univariates in $Z$ via the bijection
between $\{0,1\}^6$ and $D_0$, have degree at most $|D_0| - 1 = 63$ each.
This bound comes purely from interpolation: any function on 64 distinct
points has a unique interpolating univariate of degree at most 63.

Their product $A \cdot B$ has degree at most $63 + 63 = 126$ in $Z$. To
recover a degree-126 univariate uniquely, we need **127 evaluation
points**. The next power of two is 128, so we work over $|D| = 128$, the
smallest binary subspace large enough.

#### What the prover and verifier exchange

1. **Prover sends** 64 elements of $B_{128}$: the values
   $\{R_0(z) : z \in D \setminus D_0\}$.
2. **Verifier samples** $z_{\text{challenge}} \in B_{128}$.
3. **Both compute** $R_0(z_{\text{challenge}})$ by Lagrange interpolation
   over $D$ (using 64 sent values + 64 known zeros = 128 total).
4. The interpolated value becomes the **claim for Phase 2**.

In code, this happens inside `OblongZerocheckProver::new`
(`crates/prover/src/and_reduction/prover.rs`). The construction reads:

```rust
let prover_message_domain = BinarySubspace::<B8>::with_dim(LOG_WORD_SIZE_BITS + 1);
//                                                          = 6 + 1 = 7  →  |D| = 128
```

and the input subspace $D_0$ comes from
`BinarySubspace::<B8>::with_dim(LOG_WORD_SIZE_BITS)` (= 6, $|D_0| = 64$).

The 64 byte-indexed lookups into `ntt_lookup`
(`crates/prover/src/and_reduction/ntt_lookup.rs`) implement the **additive
NTT** (Lin-Chung-Han) that produces $R_0$ on $D \setminus D_0$ in one
parallel pass over the witness, exploiting $\mathbb{F}_2$-linearity to
split per-input-byte and amortize via 256-entry tables.

### Phase 2 in detail

After Phase 1, the bit axis is fixed at $z_{\text{challenge}}$. We are left
with a standard multilinear sumcheck on the constraint axis:

$$R_0(z_{\text{challenge}}) = \sum_{X \in \{0,1\}^{\log N}} (A(z, X) B(z, X) - C(z, X)) \cdot \mathrm{eq}(X; r_X)$$

Here $r_X$ is the **eq-indicator anchor point** discussed earlier — the
fixed vector with $k$ small-field components (B8, deterministic) and
$\log_2 N - k$ big-field components (B128, Fiat-Shamir). For our toy
circuit, $r_X = (\texttt{0x02 lifted to B128})$, a single component.

Each round (for `log_n = 1` rounds total in our example), the prover
sends a degree-2 round message; the verifier **samples a fresh
folding challenge $z_i$ in B128** (this is a different challenge from
$r_X$ — it's the per-round folding randomness, sampled new each round
from the channel); both sides fold their data on $z_i$.

After `log_n` rounds the verifier has three evaluation claims:

```
a_eval = A(z_challenge, eval_point)
b_eval = B(z_challenge, eval_point)
c_eval = C(z_challenge, eval_point)
```

It checks $a_{\text{eval}} \cdot b_{\text{eval}} = c_{\text{eval}}$.
In code: `AndCheckOutput { a_eval, b_eval, c_eval, z_challenge, eval_point }`
in `prove.rs`.

## Step 5: From operand MLEs to one witness MLE — the shift reduction

The operand polynomials $A, B, C$ are not stored directly. Each operand is
a **public XOR-sum of shifted witness words**. For example, our constraint 1
has `A = v5 XOR v2` — that's an XOR of two unshifted witness elements.

The shift reduction (`crates/prover/src/protocols/shift/`) translates
the three operand-MLE evaluations into **one** evaluation of the **witness
MLE** at a single point.

Conceptually: given $a_{\text{eval}} = A(z, r_X)$ where
$A(z, X) = \sum_{(\text{vidx}, \text{shift})} \text{coef}_{\text{vidx}}(z, r_X) \cdot W(\text{vidx})$,
the shift reduction proves a sumcheck of the form

$$a_{\text{eval}} \;=\; \sum_y \text{coef}(z, r_X, y) \cdot W(y)$$

and similarly for B and C, batched together with random $\lambda$ scalars.

The reduction has two phases:

- **Phase 1 (12 rounds)**: collapse the 64 bit positions × 64 shift amounts
  into 12 axes. For each of the 8 shift variants, build an `(g, h)` pair
  where `g` is the witness-side polynomial and `h` encodes the shift pattern.
- **Phase 2 (L rounds, where $2^L$ = number of witness words)**: walk the
  witness once via Method of Four Russians and run a bivariate sumcheck.

Output: a single claim `witness_eval = WitnessMLE(r_j, r_y)` at a point of
dimension $6 + L$.

For our circuit, $L = \log_2 8 = 3$, so the final point has 9 coordinates
when measured in bits (or $L + \log_2(B_{128} / B_1) = 3 + 7 = 10$
coordinates if we describe it as a B1-MLE evaluation point — see the ring
switch below).

In code: `prove_shift_reduction` is called from `prove.rs:235`. It returns a
`SumcheckOutput { challenges, eval }`.

## Step 6: Ring switching — B128 view ↔ B1 view

The test prints both views:

```
[5] Witness MLE evaluations
    B128 packed witness (4 elements, log_len=2):
      W[0] = 0xffffffffffffffff000000000000ff00
      W[1] = 0x00000000000000000000000000001200
      W[2] = 0x00000000000012000000000000001234
      W[3] = 0x00000000000000000000000000000000
```

Each B128 element packs two consecutive u64 words:
- `W[0]` packs `(v0, v1) = (0xFF00, 0xFFFF...FFFF)` → low 64 bits | high 64 bits.
- `W[1]` packs `(v2, v3) = (0x1200, 0)`.
- `W[2]` packs `(v4, v5) = (0x1234, 0x1200)`.
- `W[3]` packs `(v6, v7) = (0, 0)`.

So `W` is a multilinear polynomial in `log_len = 2` variables (since there
are 4 packed elements). Evaluated at our test point:

```
r0 = 0x123456789abcdef0123456789abcdef0
r1 = 0x0fedcba987654321fedcba9876543210
W(r0, r1) = 0x427a66fb7f83de0ecd2b64c2cad31a30
```

The same witness, viewed bit-by-bit, is a polynomial in 9 variables (since
$8 \cdot 64 = 512 = 2^9$ bits). Evaluated at a 9-coordinate test point:

```
B1-MLE evaluated at a 9-dim test point: 0xc7b4ea3a58d75e58cac6d030a10a8108
```

These two MLEs are different objects, but they are **algebraically related**.
The relationship is the **ring switching identity** ([DP24]):

For any point $r = (r_{\text{low}}, r_{\text{high}})$ where $r_{\text{low}}$
has 7 coordinates (= $\log_2 |B_{128} / B_1|$) and $r_{\text{high}}$ has the
remaining coordinates,

$$\text{B128MLE}(r_{\text{high}}) \;\overset{?}{=}\; \langle \text{tensor expansion of } \text{B1MLE} \text{ at } r_{\text{high}}, \; r_{\text{low}} \text{-basis} \rangle$$

In code (`crates/prover/src/ring_switch.rs:335`):

1. Compute $\hat{s}_v = \text{fold\_1b\_rows\_for\_b128}(\text{packed\_witness}, \text{eq}(r_{\text{high}}, \cdot))$
   — a tensor-algebra element with 128 B128 coordinates.
2. Send $\hat{s}_v$ to the verifier (128 B128 elements, embedded in the
   transcript).
3. Verifier samples 7 row-batching challenges $r''$.
4. The new sumcheck claim becomes
   $\text{sumcheck\_claim} = \langle \text{transpose}(\hat{s}_v), \text{eq}(r'') \rangle$.

After this the proof contains exactly one claim:

$$\sum_{x \in \{0,1\}^{L+6}} \text{WitnessB1MLE}(x) \cdot \text{rs\_eq\_ind}(x) \;=\; \text{sumcheck\_claim}$$

where `rs_eq_ind` is a public (transparent) multilinear that bakes in the
evaluation point and the row-batching challenges. This is the **B1-level
claim** that gets opened by the PCS.

## Step 7: PCS opening — BaseFold (and what Hachi would do)

The prover holds the B1 witness as a committed oracle. The verifier holds
one inner-product claim:

```rust
// crates/iop/src/channel.rs
pub struct OracleLinearRelation<'a, Oracle, Elem> {
    pub oracle: Oracle,           // commitment to WitnessB1MLE
    pub transparent: ...,          // closure evaluating rs_eq_ind at any point
    pub claim: Elem,              // the inner product value
}
```

### BaseFold (current default)

BaseFold runs FRI over GF(2^128) on the B1-multilinear:
1. Commit witness as a Merkle tree over its Reed-Solomon encoding.
2. Run BaseFold rounds (folding sumcheck + FRI folding interleaved).
3. Final low-degree check by opening Merkle paths.

Total proof size for our tiny example: **28,607 bytes**. Most of it is
Merkle path data and FRI commitment hashes — fixed-overhead-heavy at this
small scale.

### Hachi (the lattice alternative): the actual problem

Steps 1–6 of the pipeline are identical for the Hachi backend. Only the
**PCS-opening step** changes. To swap BaseFold for Hachi we need to take the
final claim

$$\sum_{x \in \{0,1\}^{L+6}} \text{WitnessB1MLE}(x) \cdot \text{rs\_eq\_ind}(x) \;=\; \text{sumcheck\_claim}$$

— which is stated **in GF(2^128)** — and turn it into a claim that
**Hachi's lattice PCS** can open. Hachi works over a **prime field
`fp128`**, not a binary field. This is the hard problem.

#### What goes wrong with the "obvious" approach

The naive idea is: the witness MLE evaluates to a B128 value, lift it to
fp128 by treating its 128-bit representation as a u128 integer, then ask
Hachi to verify the inner product in fp128.

This **does not work**. The codebase has a unit test that proves it
(`crates/iop/src/hachi_bridge.rs`):

```rust
#[test]
fn canonical_lift_is_not_additive() {
    let one = BiniusScalar::new(1);
    assert_eq!(one + one, BiniusScalar::new(0));   // GF(2^128): 1+1 = 0
    assert_ne!(
        CanonicalU128Bridge::lift(one + one),
        CanonicalU128Bridge::lift(one) + CanonicalU128Bridge::lift(one)
    );
    // The lift sends 0 to 0, but lift(1)+lift(1) = 2 in fp128, not 0.
}
```

Two structural failures:

```rust
pub enum BridgeObstruction {
    NotAdditive,        // GF(2^128) addition is XOR; fp128 addition is integer +.
    NotMultiplicative,  // GF(2^128) multiplication is carry-less mul mod p(X);
                        // fp128 multiplication is integer · mod a prime.
}
```

Because the lift is not a ring homomorphism, you cannot just translate the
B128 inner-product claim into an fp128 inner-product claim. Algebraic
identities don't survive.

#### The batched parity bridge: how the code dodges the problem

The trick is to **never claim the lift is a homomorphism**. Instead, the
prover gives Hachi enough "raw integer information" that Hachi can verify
the claim via integer arithmetic alone, without ever needing the GF(2^128)
algebra.

Recall what the final B128 claim looks like:

$$y = \sum_{i \in \{0,1\}^{L+6}} t_i \cdot w_i \quad \text{(in } GF(2^{128}))$$

where $t_i = \text{rs\_eq\_ind}(i) \in B_{128}$ are public (transparent
values) and $w_i \in \{0, 1\}$ are the witness bits. The verifier wants to
believe a specific value of $y$.

**Key observation**: even though the inner product is over GF(2^128),
**each witness $w_i$ is just a bit**. So $t_i \cdot w_i$ is either $0$ or
$t_i$. Picking the bit of position $k$ from each $t_i \cdot w_i$ and XORing
them across $i$ gives bit $k$ of $y$.

Because GF(2^128) multiplication by a fixed $t_i$ is **GF(2)-linear**, bit
$k$ of $t_i \cdot w_i$ is just **some specific bit** of $t_i$ multiplied by
$w_i$ (where the specific bit depends on $k$ and $t_i$ but not on $w_i$).

So bit $k$ of the claim $y$ equals

$$y_k = \bigoplus_i \text{(some specific bit of } t_i\text{)} \cdot w_i \pmod 2.$$

That XOR is the same as the **integer sum mod 2** of the same set of
$\{0,1\}$-valued $w_i$'s (filtered by which ones are selected by the public
mask).

Now we have a claim that **doesn't need GF(2^128) arithmetic**:

> For each output bit $k$ ($k = 0..127$), the integer sum $S_k$ of the
> selected witness bits, taken mod 2, equals bit $k$ of $y$.

Hachi verifies this purely in integer/fp128 arithmetic.

#### What the bridge proof actually contains

The proof object (in `hachi_bridge.rs`):

```rust
pub struct BatchedParityBridgeProof {
    pub opened_sums: [u64; 128],   // one S_k per output bit
}
```

**Verifier checks** (`verify_with_bounds`):

```rust
for k in 0..128 {
    if opened_sums[k] > bound_k { return Err(SumOutOfRange) }   // (1)
    if (opened_sums[k] & 1) != bit_k(claim) { return Err(...) } // (2)
}
```

(1) The **range bound** comes only from the public transparent values: it's
the maximum number of bits that could be selected. If the prover lies and
provides a huge fake $S_k$, this bound rejects it.

(2) The **parity check** is the integer fact that GF(2) sum = integer sum
mod 2.

But wait — these two checks alone don't tell us $S_k$ is the **actual sum
of the actual witness bits**. The prover could provide any $S_k$ that
satisfies the bound and parity. We still need to bind $S_k$ to the
committed witness.

That's where Hachi steps in. The witness is committed as **128 bit-slice
polynomials** (one per bit position of the packed B128 elements). Hachi
proves:

(3) **Booleanity**: each committed value is in $\{0, 1\}$. This uses a
weighted-Booleanity sumcheck $\sum_x \text{eq}(\rho, x) \cdot B(x)(B(x)-1) = 0$,
which is a degree-3 cubic sumcheck over fp128.

(4) **Inner-product consistency**: the claimed $S_k$ equals the actual
inner product of the public mask with the committed bit-slice polynomial.
This is a degree-2 product sumcheck batched across all 128 bits with a
random fp128 coefficient $\alpha$:

$$\sum_x \left(\sum_k \alpha^k \cdot \text{mask}_k(x)\right) \cdot \text{bit\_table}(x) = \sum_k \alpha^k \cdot S_k.$$

(5) **PCS opening**: Hachi opens the committed bit-slice polynomial at the
final sumcheck challenge point using the Ajtai-style lattice commitment.
This is where the actual lattice cryptography happens.

#### The two Hachi proof modes in this codebase

The repo currently exposes two Hachi paths, both going through the bridge:

| Mode | What it sends | Soundness | Succinctness |
|---|---|---|---|
| `prove_hachi_full_open` | full witness + full transparent + parity sums + Booleanity sumcheck + inner-product sumcheck | sound | NOT succinct (sends entire witness in plaintext) |
| `prove_hachi_succinct` | parity sums + Booleanity sumcheck + inner-product sumcheck + Hachi opening proof | sound | succinct |

The full-open mode is a **debugging stepping stone**. It tests the
batched-parity bridge logic without depending on the lattice commitment.
The succinct mode replaces the "send full witness" with a real Hachi
opening proof, which is the production target.

In code:

```rust
// crates/prover/src/prove.rs:404
pub fn prove_hachi_full_open<Challenger_>(...)  // gated on feature = "hachi"
pub fn prove_hachi_succinct<Challenger_>(...)   // gated on feature = "hachi"
```

#### Why the test in this branch uses BaseFold

Three reasons:

1. **The `lz-hachi` repo isn't on disk.** `crates/iop/Cargo.toml` and
   `crates/iop-prover/Cargo.toml` reference `path = "../../../lz-hachi"`
   for the `hachi-pcs` crate, but `/Users/taghi.badakhshan/Projects/lz-hachi`
   doesn't exist. On this `taghi/learn-e2e` branch I commented those
   dependencies out so the workspace builds.

2. **The hachi feature is opt-in.** Even when `lz-hachi` is available,
   `prove_hachi_full_open`/`prove_hachi_succinct` are behind
   `#[cfg(feature = "hachi")]`. Calling `Prover::prove(...)` always uses
   BaseFold.

3. **The bridge is documented as not-yet-sound.** The module header
   for `hachi_bridge.rs` explicitly states:

   > This module deliberately exposes only the canonical integer lift and
   > the reason it is not yet a sound PCS replacement.

   The structures are in place, the protocol is implemented, but the
   security analysis isn't finalized. This is current research.

#### Soundness gaps (research-level open questions)

Even with the batched parity bridge in place, several issues remain:

- **128× witness expansion**: each B128 element becomes 128 bit-slice
  values. For ML-DSA this means committing ~10M values for a single signature.
  The Booleanity sumcheck must run over all of them.

- **No-wrap analysis at q' ≈ 2^32**: Hachi's MSIS commitment modulus is
  about 32 bits. The integer sums $S_k$ are bounded by the number of
  selected bits, which is bounded by the witness size — fine for this
  layer. But when the same machinery is used for ML-DSA's lattice relation
  (Z_q with q = 8,380,417), intermediate values go to 2^50+ bits and the
  Falcon-style modulus lift fails. See
  `docs/mldsa-over-binius-architecture.md` §4.3.

- **Zero-knowledge**: this PIOP is not ZK. The Booleanity and product
  sumchecks both reveal information about the witness through their round
  messages. Hachi's commitment can be hiding, but the surrounding sumcheck
  messages are not.

- **Performance penalty**: the bridge adds a Booleanity sumcheck (degree 3,
  log_n rounds), a product sumcheck (degree 2, log_n rounds), and the
  Hachi opening on top of the BaseFold equivalent. At small scale
  (1 MiB Keccak: 59 µs/perm with BaseFold), this is likely a slowdown.
  The Hachi advantage shows up only with aggregation, where N bridges share
  one Hachi recursive opening suffix.

#### What the unified Hachi pipeline looks like

If `lz-hachi` were present and the feature enabled, the `prove_hachi_succinct`
path would produce a proof structured as:

```
Bytes 0..32:  proof-mode tag                       (PROOF_MODE_HACHI_SUCCINCT)
Bytes ...:    Hachi witness commitment             (lattice Ajtai)
              IntMul reduction transcript          (steps 4-5 unchanged)
              BitAnd reduction transcript          (step 4 unchanged)
              Shift reduction transcript           (step 5 unchanged)
              Ring-switch s_hat_v                  (step 6 unchanged)
              Public-input batching coefficient
              Batched parity bridge:
                BatchedParityBridgeProof.opened_sums  // 128 × u64
                Booleanity sumcheck transcript        // degree 3, log_n rounds
                Product sumcheck transcript           // degree 2, log_n rounds
                Hachi opening proof                   // lattice opening
              Final consistency checks
```

The verifier reads each section, runs the matching verifier procedure, and
asserts every check passes. The "is the witness consistent with the
commitment" question is answered by the Hachi lattice opening, not by
Merkle paths.

#### Comparison table: BaseFold vs Hachi

| Property | BaseFold | Hachi-succinct |
|---|---|---|
| Commitment | Merkle tree over Reed-Solomon encoding | Ajtai lattice commitment |
| Field for opening | GF(2^128) | fp128 (prime) |
| Bridge needed? | No (native B1 → B128) | Yes (batched parity bridge) |
| Per-element witness expansion | 1× (RS rate inflation) | 128× (bit slicing) |
| Post-quantum | Yes (hash-based) | Yes (lattice-based) |
| Aggregation | N proofs of size ~272 KB → no shared structure | N proofs share one recursive Hachi suffix → much smaller aggregate |
| Single-proof size | Logarithmic in witness, hash-heavy | Larger constant, smaller log term |
| Bridge soundness | trivial | open research |
| Status in this repo | production | experimental, on `hachi` branch |

The takeaway: BaseFold wins for one-shot proofs. Hachi wins for
**aggregation**, which is the real target for ML-DSA and Falcon signature
batching.

## Step 8: Verifier finalization

The verifier reads the proof, runs each phase's verifier in lockstep, and
ends with one Merkle/lattice opening. If any check fails it errors;
otherwise it accepts.

In code: `verifier.verify(public_words, transcript)?` then
`transcript.finalize()?`. The finalize step ensures all transcript bytes
were consumed (catches malformed proofs that pad the end).

## Pipeline summary table

| # | Step | Input claim | Output claim | Field | Code |
|---|---|---|---|---|---|
| 1 | Build circuit | high-level Rust | constraint system | — | `binius_frontend::CircuitBuilder` |
| 2 | Witness | Wire values | `ValueVec` | u64 | `WitnessFiller` |
| 3 | Operand eval | `ValueVec` | per-constraint `(a_i, b_i, c_i)` | u64 | `eval_operand` |
| 4 | AND reduction Phase 1 | $A B - C = 0$ on hypercube | $R_0(z_{\text{challenge}})$ | B128 | `OblongZerocheckProver` |
| 4' | AND reduction Phase 2 | $R_0(z) = \sum_X \dots$ | $a_{\text{eval}}, b_{\text{eval}}, c_{\text{eval}}$ | B128 | `QuadraticMleCheckProver` |
| 5 | Shift reduction | operand evals | one `witness_eval` | B128 | `prove_shift_reduction` |
| 6 | Ring switch | B128 MLE eval | B1 MLE inner-product claim | B128 | `ring_switch::prove` |
| 7 | PCS open | B1 inner-product claim | proof bytes | B128 (FRI) or fp128 (Hachi) | `prove_oracle_relations` |

For our example:

- 2 AND constraints, 0 MUL constraints
- 8 committed words (= 4 B128 elements = 512 bits)
- B128-MLE has 2 variables; B1-MLE has 9 variables
- Ring-switch suffix has 9 − 7 = 2 coordinates (high), bit axis has 7
  coordinates (low)
- AND-reduction Phase 1: 1 univariate-skip round
- AND-reduction Phase 2: 1 multilinear sumcheck round
- Shift reduction: 12 + 3 = 15 sumcheck rounds
- Ring switch: 7 row-batching challenges
- BaseFold: ~9 folding rounds (depends on rate parameter)
- Total proof size: 28,607 bytes

## Verifying consistency of the example

The test asserts:

- All AND constraints are satisfied at the operand level.
- Native `verify_constraints` passes.
- The MLE evaluation at corner $(0, 0)$ equals $W[0]$ (sanity check on the
  evaluation routine).
- The full prove → verify cycle succeeds.

## What this example does NOT demonstrate

To keep the example tractable we skipped:

- **The actual NTT lookup tables** used in Phase 1. They are 128 KiB of
  precomputed bytes; the relevant code is in
  `crates/prover/src/and_reduction/ntt_lookup.rs`.
- **The exact byte-table fold** in Phase 2 of the AND reduction. See
  `fold_lookup.rs`.
- **All 8 shift variants** in the shift reduction. Our circuit only uses
  unshifted operands, but the protocol always pays for all 8 (transparent
  multilinears `build_h_parts` in `monster.rs`).
- **BaseFold internals**: Reed-Solomon encoding, FRI folding, Merkle path
  generation. See `crates/iop/src/basefold.rs`.
- **Hachi's lattice arithmetic**: Ajtai commitment, gadget decomposition,
  recursive proof. The optional dependency on `lz-hachi` is not on disk in
  this branch.

## Further reading

- `docs/mldsa-over-binius-architecture.md` — how this pipeline applies to
  ML-DSA aggregation.
- `lattice-sig-aggregation/hashcaster-vs-binius64.md` — measured benchmarks
  and detailed protocol comparison.
- [DP24] — the ring-switching paper this code follows.
- The Binius blueprint at https://www.binius.xyz/blueprint.

## How to extend this walkthrough

To explore further, modify `crates/prover/tests/learn_e2e.rs`:

- Increase the witness size (more witnesses, more constants) and observe
  how `committed_total_len` grows.
- Add a MUL constraint by using `builder.imul(a, b)` and watch a third
  protocol layer activate (`prove_intmul_reduction`).
- Print Phase 1's $R_0(Z)$ values by adding tracing to the
  `OblongZerocheckProver::new` constructor.
- Try larger inputs to see how proof size scales (it grows mostly
  logarithmically because BaseFold has fixed per-round overhead).
