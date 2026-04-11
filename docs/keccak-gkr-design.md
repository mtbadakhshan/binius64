# Binary-Field KeccakCheck: Design Notes

**Status:** Early design / exploration
**Context:** Adapting the [KeccakCheck](https://eprint.iacr.org/2025/1764) protocol to Binius's binary tower field setting.

## Motivation

The current Keccak circuit in `binius_circuits` uses the generic `CircuitBuilder` constraint system.
Each keccak-f permutation compiles to ~1300 AND constraints plus linear constraints.
While this is already efficient (binary fields make bitwise ops cheap), we can do better with a bespoke sumcheck/GKR-based protocol that:

1. **Eliminates commitments to intermediate round states.**
   Currently every intermediate wire becomes a committed witness column (BaseFold).
   With GKR, only the input and output state need commitments; the 24 intermediate round states are "virtual."
2. **Makes rotations free.**
   Currently `rotl` costs 1 AND constraint per rotation (~30 per round, ~720 across 24 rounds).
   In the MLE representation, rotation is a permutation of bit indices absorbed into the sumcheck coefficients.
3. **Enables efficient batching.**
   Multiple keccak-f instances share the same MLE structure with log(h) extra variables, amortizing the sumcheck overhead.

## Background

### Keccak-f State as MLEs

Represent h instances of keccak-f simultaneously.
Let n = 6 + log(h).
Each of the 25 lanes is an n-variate multilinear polynomial:

$$A_{ij}(x_1, \ldots, x_n) \quad \text{where } (x_1,\ldots,x_6) \text{ index the 64 bits, } (x_7,\ldots,x_n) \text{ index the instance.}$$

On Boolean inputs: $A_{ij}(b) = A[\langle b_7 \ldots b_n \rangle][i][j][\langle b_1 \ldots b_6 \rangle]$, i.e. the $\langle b_1\ldots b_6\rangle$-th bit of lane $(i,j)$ in instance $\langle b_7\ldots b_n\rangle$.

### Bitwise Operations over $\mathbb{F}_2$

Over characteristic 2, the arithmetic is simpler than over prime fields:

| Operation | Formula | Degree |
|-----------|---------|--------|
| XOR       | $a + b$ | 1 |
| AND       | $a \cdot b$ | 2 |
| NOT       | $1 + a$ | 1 |

No need for the $\hat{a} = 1 - 2a$ trick from prime-field KeccakCheck.

### Rotations as Polynomial Predicates

#### The problem with rotation

Cyclic rotation of a 64-bit lane by $k$ positions means: bit $z$ of the rotated word equals bit $(z - k) \bmod 64$ of the original.
On the Boolean hypercube, this is a permutation $\sigma_k$ on $\{0,1\}^6$ defined by $\langle \sigma_k(b_1,\ldots,b_6) \rangle = (\langle b_1 \ldots b_6 \rangle + k) \bmod 64$.

This permutation involves modular arithmetic with carries, so it scrambles individual bit coordinates in a complex way.
It is **not** a polynomial map on the MLE variables.
There is no simple function $f: \mathbb{F}^6 \to \mathbb{F}^6$ such that $\operatorname{Rot}[Q, k](\alpha) = Q(f(\alpha_{1..6}), \alpha_{7..n})$.

#### The rotation predicate

Define the 12-variate multilinear polynomial:

$$\operatorname{rot}_k(a, c) = \widetilde{\mathbf{1}[\langle a \rangle \equiv \langle c \rangle + k \pmod{64}]}$$

for $a, c \in \mathbb{F}^6$.
On Boolean inputs, this is a permutation matrix: for each $c \in \{0,1\}^6$, exactly one $a$ makes it 1.

#### The rotation operator

For an n-variate lane polynomial $Q$, define the **rotated polynomial** $\operatorname{Rot}[Q, k]$ by its values on the Boolean hypercube:

$$\operatorname{Rot}[Q, k](b_1,\ldots,b_n) = Q(\sigma_{-k}(b_{1..6}),\; b_{7..n}).$$

This is the function "read bit $(z-k) \bmod 64$ of the original lane, in the same instance."
$\operatorname{Rot}[Q, k]$ has a unique multilinear extension to $\mathbb{F}^n$.

#### Key identity

For all $x \in \mathbb{F}^n$:

$$\operatorname{Rot}[Q, k](x) = \sum_{b \in \{0,1\}^n} Q(b) \cdot \operatorname{rot}_k(x_{1..6},\, b_{1..6}) \cdot \operatorname{eq}(x_{7..n},\, b_{7..n}).$$

In words: evaluating the rotated polynomial at a field point $\alpha$ is an **inner product** of $Q$'s evaluation table with a **transparent** coefficient vector that depends only on the fixed constant $k$ and the evaluation point $\alpha$.

**Proof.**
Both sides are multilinear in $x$.
It suffices to check agreement on Boolean inputs $x = (a, m)$ with $a \in \{0,1\}^6$, $m \in \{0,1\}^{n-6}$:

$$\text{RHS} = \sum_{b \in \{0,1\}^n} Q(b) \cdot \mathbf{1}[\langle a \rangle \equiv \langle b_{1..6} \rangle + k \pmod{64}] \cdot \mathbf{1}[m = b_{7..n}].$$

The $\operatorname{eq}$ factor picks out $b_{7..n} = m$.
The $\operatorname{rot}_k$ factor picks out the unique $b_{1..6}$ with $\langle b_{1..6} \rangle = (\langle a \rangle - k) \bmod 64$, i.e. $b_{1..6} = \sigma_{-k}(a)$.
So $\text{RHS} = Q(\sigma_{-k}(a), m) = \operatorname{Rot}[Q, k](a, m) = \text{LHS}$. $\square$

#### Consequences for sumcheck

**Prover side.**
During sumcheck, the prover needs to evaluate $\operatorname{Rot}[Q, k](k)$ as $k$ ranges over the hypercube (and then gets partially bound to field elements).
The simplest approach: permute $Q$'s evaluation table by the rotation at the start (cost: one pass over 64h entries), then fold through sumcheck rounds like any other multilinear.
No new witness data is created.

**Verifier side (committed $Q$).**
After sumcheck, the terminal check produces a claimed value $v = \operatorname{Rot}[Q, k](\alpha)$.
By the key identity, this is equivalent to claiming $v = \langle Q, T_{\alpha,k} \rangle$ where $T_{\alpha,k}(b) = \operatorname{rot}_k(\alpha_{1..6}, b_{1..6}) \cdot \operatorname{eq}(\alpha_{7..n}, b_{7..n})$ is a transparent polynomial.
This is exactly an `OracleLinearRelation` in Binius's IOP framework (`crates/iop/src/channel.rs`).
BaseFold verifies the inner product against the committed $Q$.

**Verifier side (virtual $Q$).**
If $Q$ is a virtual (non-committed) polynomial (e.g. an intermediate round state $A^{(t)}$ for $t > 0$), the same identity defines a **virtual linear relation** on $Q$.
This is the virtual analogue of `OracleLinearRelation`: same terminal point, same transparent kernel, but no PCS.
It should be tracked explicitly in the virtual-claim layer rather than being coerced into a plain point opening $Q(\alpha)$.

#### Efficient computation of the rotation predicate

The 64-entry vector $\{\operatorname{rot}_k(\alpha_{1..6}, b)\}_{b \in \{0,1\}^6}$ for fixed $\alpha$ and $k$ is obtained by cyclically shifting the standard eq-evaluation vector $\{\operatorname{eq}(\alpha_{1..6}, b)\}_{b \in \{0,1\}^6}$ by $k$ positions.

This works because $\operatorname{rot}_k(\alpha, b) = \operatorname{eq}(\alpha, \sigma_k(b))$, and $\sigma_k$ cyclically shifts the integer index.
Cost: $O(64)$ to compute the eq-vector, then $O(64)$ to rotate it.

#### Why rotation is "free"

In the current constraint system (`CircuitBuilder`), `rotl` costs 1 AND constraint because it must mask and reassemble word halves.
In the MLE/sumcheck approach:

- The prover pays $O(64h)$ to permute the evaluation table (a one-time cost, negligible compared to the $O(2^n)$ sumcheck work).
- The verifier pays nothing during sumcheck (the rotation predicate is absorbed into the transparent coefficients).
- The terminal check is either an `OracleLinearRelation` (for committed lanes) or a virtual linear relation (for virtual lanes).

No AND constraints, no new witness columns, no additional commitments.

## Protocol Structure

### Per-Round Reduction

Each keccak-f round applies five steps: $\theta \to \rho \to \pi \to \chi \to \iota$.
The protocol works **backwards** from the output, reducing transparent linear claims step by step.
At the protocol boundary these are usually random-point evaluation claims.
Inside the round chain, it is more convenient to allow an arbitrary transparent kernel on each carried lane.

**Why rounds still need to be chained:**
Across 24 rounds, repeatedly composing the degree-2 chi step would yield degree $2^{24}$, so some per-round decomposition is still necessary.
Within a single round, however, the picture is much better than in prime-field KeccakCheck.
Over $\mathbb{F}_2$, theta, rho, pi, and iota are all linear.
Only chi is nonlinear.
So the paper's step-by-step decomposition should be viewed as an upper bound for Binius, not the likely final shape.

Note: the round structure is identical across all 24 rounds.
Only the iota round constant RC[t] changes.

### Step-by-Step Polynomial Identities (over $\mathbb{F}_2$)

**Iota.** $\iota_{00}(x) = \chi_{00}(x) + \text{RC}(x)$, and $\iota_{ij} = \chi_{ij}$ for $(i,j) \neq (0,0)$.
This step is linear in $\chi$.
In a binary-field design it should usually be folded directly into the chi sumcheck as an extra transparent term.

**Chi.** The only nonlinear step:

$$\chi_{ij}(x) = \pi_{ij}(x) + (1 + \pi_{(i+1)j}(x)) \cdot \pi_{(i+2)j}(x)$$
$$= \pi_{ij}(x) + \pi_{(i+2)j}(x) + \pi_{(i+1)j}(x) \cdot \pi_{(i+2)j}(x).$$

Degree 2 in $\pi$.
This is the main reason a round cannot be checked by purely linear reductions.

**Pi.** Pure index permutation $\pi_{ij} = \rho_{j,(2i+3j) \bmod 5}$.
Free (relabeling).

**Rho.** $\rho_{ij}(x) = \text{rot}(\theta_{ij}, r[i,j])(x)$.
This step is linear.
If treated separately, it needs one sumcheck with the rotation predicate as a coefficient.
In practice it should probably be fused with theta and pi.

**Theta.** Over $\mathbb{F}_2$, theta is linear in the input state:

$$\theta_{ij}(x) = A_{ij}(x) + \sum_{j'} A_{i-1,j'}(x) + \sum_{j'} \text{rot}(A_{i+1,j'}, 1)(x).$$

So if theta is handled as its own reduction, it needs only one sumcheck, not the three-step prime-field decomposition from KeccakCheck.
The integrand still contains `eq` and `rot` predicates, but the dependence on the witness remains linear.

**Binary-field simplification.**
A natural conservative decomposition is:

1. One degree-2 sumcheck for `iota + chi`.
2. One linear sumcheck for `theta + rho + pi`.

An even more aggressive design may inline the whole round map into a single degree-2 sumcheck.
That may be worth exploring later, but the 2-sumcheck plan seems like the cleanest first target.

### Round Chaining

After reducing through all steps of round $t$, we have 25 transparent linear relation claims on $A_{ij}^{(t)}$.
But $A_{ij}^{(t)}$ is round $t$'s input = round $(t-1)$'s output = $\iota_{ij}^{(t-1)}$.
So we start the next round's reduction from those 25 carried kernels.

After all 24 rounds, we have transparent linear relation claims on the **input** state, which the verifier checks directly against the committed input polynomials via `OracleLinearRelation`.

### Sumcheck Count

For Binius, the prime-field KeccakCheck schedule should be treated as a loose upper bound, not the expected design.

A conservative characteristic-2 plan is about 2 sumchecks per round:

1. `iota + chi`
2. `theta + rho + pi`

That gives about 48 sumcheck instances across 24 rounds.
If the whole round map is inlined, the count may drop to about 24 total.
Each sumcheck has $n = 6 + \log(h)$ rounds and degree at most 2 in the witness values.

### Explicit fused round sketches

#### Notation summary

Throughout this section:

- $A^{(t)}_{x,y}$ is an n-variate multilinear polynomial representing lane $(x,y)$ at the **input** to round $t$.
  On Boolean inputs $b \in \{0,1\}^n$, the value $A^{(t)}_{x,y}(b)$ is the $\langle b_1 \ldots b_6\rangle$-th **bit** of lane $(x,y)$ in instance $\langle b_7 \ldots b_n \rangle$.
- $O^{(t)}_{i,j}$ is the **output** of round $t$, i.e. the input to round $t+1$.
- $\operatorname{Rot}[Q, k]$ is the **rotated polynomial**: a new n-variate multilinear whose Boolean evaluations are a cyclic rotation of $Q$'s evaluations by $k$ positions within each 64-bit lane.
  On Boolean inputs: $\operatorname{Rot}[Q, k](b_1,\ldots,b_n) = Q(b_1',\ldots,b_6', b_7,\ldots,b_n)$ where $\langle b_1' \ldots b_6'\rangle = (\langle b_1 \ldots b_6\rangle - k) \bmod 64$.
  At non-Boolean points (inside sumcheck), $\operatorname{Rot}[Q,k]$ is the unique multilinear extension of that function.
  **This is not a new witness.** It is the same data as $Q$, viewed with a permuted bit-index.
- $\operatorname{eq}(\alpha, k) = \prod_{i=1}^{n}(\alpha_i k_i + (1-\alpha_i)(1-k_i))$ is the standard equality polynomial.
  When a sumcheck proves $\sum_k f(k) = s$, multiplying the integrand by $\operatorname{eq}(\alpha, k)$ turns it into a proof that $f(\alpha) = s$, i.e. an evaluation claim at the random point $\alpha$.
  In Binius this multiplication is handled by the `MleToSumCheckDecorator` adapter, which folds the equality factor in round-by-round without increasing the transmitted degree.
- $r[x,y]$ is the fixed Keccak rho rotation offset for lane $(x,y)$, from `permutation.rs:37-43`.
- $\mathrm{RC}_t$ is the round constant for round $t$, expanded as a 6-variate polynomial (its 64-bit binary representation), constant across instances.
  On Boolean inputs: $\mathrm{RC}_t(b_1,\ldots,b_6, b_7,\ldots,b_n) = \text{bit } \langle b_1\ldots b_6\rangle \text{ of } \texttt{RC[t]}$.
- Indices $x, y, i, j, s$ range over $\{0,1,2,3,4\}$ with arithmetic mod 5.

#### Deriving the pre-chi state

The Keccak round map is $\iota \circ \chi \circ \pi \circ \rho \circ \theta$.
Working backwards from the output, we need to express the **pre-chi state** (the input to chi) in terms of the round's input lanes.

**Step 1: theta.**
Theta XORs each lane with its column parity and a rotated neighbor parity:

$$\theta_{x,y} = A^{(t)}_{x,y} + \sum_s A^{(t)}_{x-1,s} + \operatorname{Rot}\!\Big[\sum_s A^{(t)}_{x+1,s},\; 1\Big].$$

(All additions are XOR, i.e. addition in $\mathbb{F}_2$.)

**Step 2: rho.**
Rho rotates each lane by a fixed offset:

$$\rho_{x,y} = \operatorname{Rot}[\theta_{x,y},\; r[x,y]].$$

Because $\operatorname{Rot}$ is linear (it permutes evaluations), we can push it through the sum from theta:

$$\rho_{x,y} = \operatorname{Rot}[A^{(t)}_{x,y},\; r[x,y]] + \sum_s \operatorname{Rot}[A^{(t)}_{x-1,s},\; r[x,y]] + \sum_s \operatorname{Rot}[A^{(t)}_{x+1,s},\; r[x,y]+1].$$

The $+1$ in the last term comes from composing the rho rotation $r[x,y]$ with theta's rotation by 1.

**Step 3: pi.**
Pi is a fixed index permutation: lane $(x,y)$ moves to position $(y, (2x+3y) \bmod 5)$.
Define $\phi(x,y) = (y, (2x+3y) \bmod 5)$.
Then the pre-chi lane at index $\phi(x,y)$ is $\rho_{x,y}$.

**Combined: the pre-chi state.**
Define $P^{(t)}_{\phi(x,y)} = \rho_{x,y}$, i.e.:

$$P^{(t)}_{\phi(x,y)} = \operatorname{Rot}[A^{(t)}_{x,y},\; r[x,y]] + \sum_s \operatorname{Rot}[A^{(t)}_{x-1,s},\; r[x,y]] + \sum_s \operatorname{Rot}[A^{(t)}_{x+1,s},\; r[x,y]+1].$$

This is **entirely linear** in the 25 input lanes $A^{(t)}$.
Each term is just "take lane $(x',y')$, cyclically rotate its bits by some fixed amount."

#### Chi and iota (the nonlinear part)

Chi applies lane-by-lane with the formula (over $\mathbb{F}_2$):

$$\chi_{i,j} = P^{(t)}_{i,j} + (1 + P^{(t)}_{i+1,j}) \cdot P^{(t)}_{i+2,j} = P^{(t)}_{i,j} + P^{(t)}_{i+2,j} + P^{(t)}_{i+1,j} \cdot P^{(t)}_{i+2,j}.$$

Iota XORs the round constant into lane $(0,0)$:

$$O^{(t)}_{i,j} = \begin{cases}\chi_{0,0} + \mathrm{RC}_t & \text{if } (i,j) = (0,0),\\ \chi_{i,j} & \text{otherwise.}\end{cases}$$

#### Two sumchecks per round

The protocol works backwards from a lane-wise carried claim on the output state.
At the protocol boundary this is usually a random-point evaluation claim.
More generally, for round $t$ let the carried claim be

$$C^{(t)}_{\mathrm{out}} = \sum_{i,j} \langle O^{(t)}_{i,j}, W^{(t)}_{i,j} \rangle,$$

where each $W^{(t)}_{i,j}$ is a transparent multilinear polynomial.
The usual boundary case is $W^{(t)}_{i,j}(k) = \beta_{i,j}\operatorname{eq}(\alpha_t, k)$.
We want to reduce this to a new carried claim on the **input** lanes $A^{(t)}$.

**Sumcheck 1 (degree 2): reduces output claim to pre-chi claim.**

Substituting chi and iota into the carried claim gives

$$C^{(t)}_{\mathrm{out}} = \sum_{k \in \{0,1\}^n} \sum_{i,j} W^{(t)}_{i,j}(k)\Big(P^{(t)}_{i,j}(k) + P^{(t)}_{i+2,j}(k) + P^{(t)}_{i+1,j}(k)\cdot P^{(t)}_{i+2,j}(k) + \delta_{i0}\delta_{j0}\,\mathrm{RC}_t(k)\Big).$$

Here $\delta_{i0}\delta_{j0}$ is just the Kronecker delta: it equals 1 when $i=j=0$ and 0 otherwise.
It selects the single lane where iota adds the round constant.

This is a sumcheck claim $\sum_k g(k) = C^{(t)}_{\mathrm{out}}$ where the integrand $g$ has degree 2 in the witness values (from the $P \cdot P$ product in chi).
The transparent kernels $W^{(t)}_{i,j}$ do not change that witness degree, so the prover still sends 2 field elements per sumcheck variable.

After $n$ rounds of this sumcheck, the verifier holds a random challenge point $\rho_t$.
The prover **caches** the 25 values $P^{(t)}_{i,j}(\rho_t)$ as virtual point openings.
The verifier checks the final sumcheck equation using those claimed values (which will be verified by the next sumcheck).

**Sumcheck 2 (degree 1): reduces pre-chi claim to input-lane claim.**

The verifier now samples fresh random lane weights $\gamma_{i,j}$ and forms a new claim:

$$C^{(t)}_{\mathrm{lin}} = \sum_{i,j} \gamma_{i,j}\, P^{(t)}_{i,j}(\rho_t).$$

Expanding $P^{(t)}$ into the input lanes via the linear map derived above:

$$C^{(t)}_{\mathrm{lin}} = \sum_{k \in \{0,1\}^n} \operatorname{eq}(\rho_t, k) \sum_{x,y}\gamma_{\phi(x,y)}\Big(\operatorname{Rot}[A^{(t)}_{x,y}, r[x,y]](k) + \sum_s \operatorname{Rot}[A^{(t)}_{x-1,s}, r[x,y]](k) + \sum_s \operatorname{Rot}[A^{(t)}_{x+1,s}, r[x,y]+1](k)\Big).$$

This is degree 1 in the witness values (every term is just a rotated view of an input lane, no products).
The prover sends 1 field element per sumcheck variable.

After this sumcheck completes at a new challenge point $\alpha_{t-1}$, write

$$T_{\alpha,\delta}(b) = \operatorname{rot}_{\delta}(\alpha_{1..6}, b_{1..6}) \cdot \operatorname{eq}(\alpha_{7..n}, b_{7..n}).$$

The plain openings $A^{(t)}_{u,v}(\alpha_{t-1})$ are **not** enough to close this terminal check, because $\operatorname{Rot}[Q, \delta](\alpha)$ is not $Q$ at a transformed point.
Instead, group the terminal expression by source lane.
For each $(u,v)$, define the transparent kernel

$$K^{(t)}_{u,v;\alpha_{t-1},\gamma}(b) = \gamma_{\phi(u,v)}\,T_{\alpha_{t-1},\,r[u,v]}(b) + \sum_y \gamma_{\phi(u+1,y)}\,T_{\alpha_{t-1},\,r[u+1,y]}(b) + \sum_y \gamma_{\phi(u-1,y)}\,T_{\alpha_{t-1},\,r[u-1,y]+1}(b),$$

with all indices mod 5.
Then the reduced scalar can be written as

$$C^{(t-1)}_{\mathrm{out}} = \sum_{u,v} \langle A^{(t)}_{u,v}, K^{(t)}_{u,v;\alpha_{t-1},\gamma} \rangle.$$

Because $A^{(t)}_{u,v} = O^{(t-1)}_{u,v}$, these 25 kernels become the carried claims for the next round:

$$W^{(t-1)}_{u,v} = K^{(t)}_{u,v;\alpha_{t-1},\gamma}.$$

At the final step $t = 0$, the same relations are checked directly against the committed input lanes via `OracleLinearRelation`.

**What "rotated openings" means operationally.**

In sumcheck 2, the integrand involves expressions like $\operatorname{Rot}[A^{(t)}_{x,y}, r[x,y]](k)$.

An important subtlety: cyclic rotation of bit indices is **not** a polynomial map on the MLE coordinates.
Adding $k$ modulo 64 involves carries that scramble individual bits, so there is no way to express $\operatorname{Rot}[Q, k](\alpha)$ as $Q(\text{some simple function of } \alpha)$.
Instead, the relationship is through an inner product with a transparent "rotation predicate" polynomial:

$$\operatorname{Rot}[Q, k](\alpha) = \sum_{b \in \{0,1\}^n} Q(b) \cdot \operatorname{rot}_k(\alpha_{1..6}, b_{1..6}) \cdot \operatorname{eq}(\alpha_{7..n}, b_{7..n}).$$

Here $\operatorname{rot}_k(a, c)$ is the multilinear extension of $\mathbf{1}[\langle a \rangle \equiv \langle c \rangle + k \pmod{64}]$, as defined in the Background section.
The right-hand side depends on $Q$'s evaluation table (witness data) and on a transparent coefficient vector determined by $k$ and $\alpha$ (no witness dependence).

This means:

- **Prover during sumcheck:** permute $Q$'s evaluation table by the rotation at the start, then fold through sumcheck rounds like any other multilinear. On the Boolean hypercube, rotation is just a permutation of entries, so this is trivial.
- **Verifier after sumcheck:** the terminal check produces a claimed value $v = \operatorname{Rot}[Q, k](\alpha)$. To verify:
  - If $Q$ is **committed** (e.g. the input lanes $A^{(0)}$), this claim is an `OracleLinearRelation`: the inner product of committed $Q$ with the transparent rotation predicate evaluated at $\alpha$. Binius's existing BaseFold machinery handles this.
  - If $Q$ is **virtual** (e.g. intermediate round lanes $A^{(t)}$ for $t > 0$), this is a virtual linear relation on $Q$ at the same terminal point $\alpha$, not a plain point opening $Q(\alpha)$.

For the linear round map, many rotated views of the same source lane share the same terminal point.
So they can be combined by summing their transparent kernels before recording the carried claim for that lane.

The 64-entry rotation predicate vector $\{\operatorname{rot}_k(\alpha_{1..6}, b)\}_{b \in \{0,1\}^6}$ is computed by cyclically shifting the standard eq-evaluation vector $\{\operatorname{eq}(\alpha_{1..6}, b)\}_{b \in \{0,1\}^6}$ by $k$ positions, costing $O(64)$ work.

#### One sumcheck per round

Instead of caching $P^{(t)}$ as virtual point openings and running a second sumcheck, substitute the explicit linear map directly into the chi formula.
The integrand becomes:

$$g^{(t)}_{\mathrm{round}}(k) = \operatorname{eq}(\alpha_t, k)\sum_{i,j}\beta_{i,j}\Big(P^{(t)}_{i,j}(k) + P^{(t)}_{i+2,j}(k) + P^{(t)}_{i+1,j}(k)\cdot P^{(t)}_{i+2,j}(k) + \delta_{i0}\delta_{j0}\,\mathrm{RC}_t(k)\Big),$$

where each $P^{(t)}_{i,j}(k)$ is replaced by the full linear combination of rotated input lanes.

The composite is still degree 2 in the input lanes $A^{(t)}$:
the $P \cdot P$ product in chi is degree 2 because each $P$ is degree 1 in the input lanes.
Theta, rho, and pi contribute only linear terms.

After this single sumcheck completes at challenge point $\alpha_{t-1}$, the verifier still needs transparent linear relations on the input lanes, not plain point openings.
Operationally, the terminal check can be organized by first exposing the 25 pre-chi lane values $P^{(t)}_{i,j}(\alpha_{t-1})$, with each such value represented as a virtual linear relation on the input lanes $A^{(t)}$, and then applying the chi+iota formula locally.
The resulting 25 carried kernels on $A^{(t)} = O^{(t-1)}$ are then passed to round $t-1$ exactly as in the two-sumcheck plan.

**Tradeoff.**
This saves one sumcheck per round (24 total instead of 48) and eliminates the 25 intermediate pre-chi point openings.
The cost is a more complex prover kernel: each sumcheck round must compute the full theta+rho+pi linear map on the fly while evaluating the chi quadratic.
It also requires the virtual-claim layer to support lane-wise transparent linear relations on input lanes, not just plain point openings.

### Cost sketch

The current `binius-keccak-check` implementation no longer matches the older explicit-table two-sumcheck prototype.
`crates/keccak-check/src/protocol.rs` now proves each Keccak round with one fused degree-2 MLE-check over `CompactTrace`, and `crates/keccak-check/src/fused_round.rs` folds the `64` bit positions once at a fixed `bit_challenge` before running sumcheck only over the high batch variables.
So the live protocol has one sumcheck per Keccak round, not two.

In Binius's MLE-check verifier, each degree-2 round sends exactly `2` field elements.
The current fused Keccak prover therefore sends only the truncated quadratic round polynomial for each of the $\ell = \log(h)$ high variables.

To turn that into proof bytes, fix the following accounting model:

- count only prover-sent field elements inside the standalone Keccak sub-protocol,
- count transparent kernels (`eq`, rotated bit-weight vectors, and the fused linear recipe) as `0` proof bytes because the verifier recomputes them from challenges and constants,
- do not count Fiat-Shamir challenges, since they are derived from the transcript rather than transmitted by the prover,
- do not count BaseFold / PCS opening-proof bytes,
- do not count the explicit `CompactTrace`, because in the current standalone checker it is verifier-side input rather than proof data.

If the sumcheck field is $\mathrm{GF}(2^{128})$, each transmitted field element costs `16` bytes.
Under that model, the current fused implementation has the exact transcript cost:

| Quantity | Field elements | Bytes |
|---|---:|---:|
| Per Keccak round | $2\ell$ | $32\ell$ |
| Per `KeccakF1600` | $48\ell$ | $768\ell$ |

If the same fused reduction is lifted into the committed-boundary protocol from this note, then the transcript still contributes only $48\ell$ field elements, and the `25` output-lane claims plus `25` input-lane claims contribute another `50` field elements.
That gives $48\ell + 50$ field elements, or $768\ell + 800$ bytes, before any PCS bytes are added.

Concrete example: proving $h = 2^{17}$ Keccak instances.
Then $\ell = 17$, so the exact standalone fused transcript is:

- `816` field elements,
- `13,056` bytes,
- `12.75 KiB`,
- `13,056 / 2^17 = 0.099609375` bytes amortized per proved instance.

Adding the `50` committed boundary scalars would raise that to:

- `866` field elements,
- `13,856` bytes,
- `13.53125 KiB`,
- `13,856 / 2^17 = 0.105712890625` bytes amortized per proved instance.

This still excludes any PCS bytes.

Relative to the previous standalone two-sumcheck prototype, this changes the leading transcript term from $3 \log(h)$ field elements per Keccak round to $2 \log(h)$.
At $h = 2^{17}$, that is the difference between `19,584` bytes and `13,056` bytes for the standalone sub-protocol transcript.

#### Detailed prover constant

The transcript formulas above hide the arithmetic constant that actually dominates proving time.
For the current fused implementation, that constant now has two different regimes:

1. the first MLE-check round of each Keccak round runs directly on native `u64` words,
2. the remaining $\ell - 1$ MLE-check rounds run on folded $25 \times 64$ field blocks.

To keep this section comparable with the older derivation, count only the `GF(2^{128})` arithmetic performed inside the custom Keccak kernels.
Do not separately count `Gruen32` bookkeeping, transcript plumbing, SIMD packing, or the native `u64` rotates, XORs, and ANDs in the first specialized round.

For Keccak round `t`, let:

- $\ell = \log(h)$,
- $r_t = \operatorname{wt}(\mathrm{RC}_t)$,
- $C_t^{(1)}$ be the total number of set-bit iterations executed by `chi_iota_word_eval()` across the `h / 2` points of the first MLE-check round,
- $C_t^{(\infty)}$ be the total number of set-bit iterations executed by `chi_infinity_word_eval()` across the same `h / 2` points,
- $C_t = C_t^{(1)} + C_t^{(\infty)}$.

The first specialized MLE-check round then costs exactly:

- $C_t + h + 2$ multiplications,
- $C_t + h + 2$ additions,
- `1` inversion.

The remaining $\ell - 1$ rounds are deterministic.
Reading off `fused_chi_linear_eval()` and `fused_chi_linear_infinity_eval()` in `crates/keccak-check/src/fused_round.rs`, each scanned half-cube point in those rounds contributes:

- `3226` multiplications and $22425 + r_t$ additions for the $y_1$ path,
- `3225` multiplications and `19225` additions for the $y_\infty$ path,
- `2` more multiplications for the equality weight.

Summing that over the remaining half-cubes, then adding the accumulator reductions, the generic field-block folds, the `25` terminal dot products, and the degree-2 interpolation steps gives the exact remaining-round cost:

- $8053(h / 2 - 1) + 1600 + 2\ell - 2$ multiplications,
- $(44850 + r_t)(h / 2 - 1) + h + 2\ell + 1596$ additions,
- $\ell - 1$ inversions.

So one Keccak round in the current fused implementation costs exactly:

- $C_t + h + 8053(h / 2 - 1) + 1600 + 2\ell$ multiplications,
- $C_t + (44850 + r_t)(h / 2 - 1) + 2h + 2\ell + 1598$ additions,
- $\ell$ inversions.

The only trace-dependent term is $C_t$, which comes from the first word-specialized round.
For random-looking traces, the natural approximation is:

- $\mathbb{E}[C_t^{(1)}] \approx 25 \cdot 32 \cdot (h / 2) = 400h$,
- $\mathbb{E}[C_t^{(\infty)}] \approx 25 \cdot 16 \cdot (h / 2) = 200h$,
- so $\mathbb{E}[C_t] \approx 600h$.

Using that heuristic together with the exact identity $\sum_{t=0}^{23} r_t = 86$, the expected current fused cost at $h = 2^{17}$ is:

- `14,556,702,264` multiplications per `KeccakF1600`,
- `74,957,821,434` additions per `KeccakF1600`,
- `408` inversions per `KeccakF1600`.

Amortized over the batch, that is about:

- `111,059` multiplications per proved Keccak instance,
- `571,883` additions per proved Keccak instance.

This should be read as an expected-cost model for the current fused prover, not as a worst-case upper bound.
The transcript size above is exact.
The arithmetic count is exact up to the trace-dependent popcount term $C_t$, and the displayed concrete numbers plug in the random-looking-trace heuristic for that one term.

#### Native execution vs proving

It is useful to compare the proving cost against the cost of running `KeccakF1600` directly on a CPU.
For long messages, the cleanest back-of-the-envelope conversion is:

- `cycles per permutation ≈ (cycles per byte) * 136`

for `SHA3-256` or `SHAKE256`, since the rate is `136` bytes and each full absorbed rate block triggers one `KeccakF1600` permutation.

Representative native software costs are:

| ISA / implementation | Long-message metric | Approx cycles per `KeccakF1600` |
|---|---:|---:|
| x86-64 Skylake-X, fastest XKCP path | `SHAKE256 = 5.49 c/B` | `747` |
| x86-64 Skylake, fastest XKCP path | `SHAKE256 = 7.70 c/B` | `1047` |
| x86-64 Haswell, fastest XKCP path | `SHAKE256 = 8.75 c/B` | `1190` |
| x86-64 Sandy Bridge, fastest XKCP path | `SHAKE256 = 10.87 c/B` | `1478` |
| x86-64 Tiger Lake AVX512 path | `SHAKE256 = 5.72 c/B` | `778` |
| ARMv8 scalar Cortex-A53 | `SHA3-256 = 12.4 c/B` | `1686` |
| ARMv8 scalar Cortex-A57 | `SHA3-256 = 11.8 c/B` | `1605` |
| ARMv8 scalar Cortex-A76 / Pi 5 | `SHA3-256 = 7.56 c/B` | `1028` |

So native execution is in the rough range of `0.75k` to `1.7k` cycles per permutation on common 64-bit software paths.
With dedicated SHA-3 instructions the cost can be lower still.
For example, an Apple M1 benchmark of a 2-way ARMv8.2-SHA3 path reports `156 ns` for `F1600x2`, i.e. about `78 ns` per permutation, which is on the order of a few hundred cycles on a 3 GHz-class core.

By contrast, the current fused standalone prover at $h = 2^{17}$ is expected to spend, per proved Keccak instance:

- about `111,059` `GF(2^128)` multiplications,
- about `571,883` `GF(2^128)` additions.

Even under the unrealistically optimistic lower bound that every field operation costs only one cycle, this already implies about `6.8e5` cycles per proved Keccak instance.
Against the `0.75k` to `1.7k` native range above, that is still roughly $4 \cdot 10^2$ to $9 \cdot 10^2$ times more expensive.
If `GF(2^128)` multiplication costs several cycles, which is the more realistic software model, the gap widens again.

This is still a large overhead, but it is materially better than the earlier explicit-table two-sumcheck prototype.
The current fused path wins in three different ways:

- it reduces the transcript from $3 \log(h)$ to $2 \log(h)$ field elements per Keccak round,
- it halves the inversion count from $2 \log(h)$ to $\log(h)$ per Keccak round,
- it keeps the largest MLE-check round in native `u64` arithmetic, which is where most of the multiplication saving comes from.

So the current one-sumcheck implementation is no longer only a transcript optimization.
It already improves the dominant prover constant in practice, even though the overall cost is still linear in `h` and still much larger than native Keccak execution.

The main protocol-level tradeoff is:

- **Two-sumcheck plan:** one extra vector of `25` pre-chi point openings per round, plus one extra sumcheck transcript
- **One-sumcheck plan:** no pre-chi point-opening layer, one fewer sumcheck per round, and a more specialized prover with richer carried kernels on the input lanes

The main prover-work tradeoff is:

- **Two-sumcheck plan:** one quadratic pass over the pre-chi lanes, then one linear pass relating them back to the input lanes
- **One-sumcheck plan:** one quadratic pass whose first and largest MLE-check round stays at the word level before converting to field blocks

Asymptotically both are still linear in the current hypercube size each round.
Concretely, the current fused one-sumcheck path wins on both transcript size and prover constant because it avoids materializing the pre-chi layer and exploits native `u64` structure in the dominant first fold.

## Expected Wins

### Commitment Savings

| | Current (CircuitBuilder) | GKR approach |
|---|---|---|
| Committed polynomials | ~600+ (all intermediate wires) | ~50 (25 input + 25 output lanes) |
| BaseFold work | Proportional to committed polys | ~12x reduction |

This is likely the dominant improvement.
BaseFold commitment is expensive, so reducing the number of committed polynomials directly reduces prover time.

### AND Constraint Savings

| Source | Current cost | GKR cost |
|--------|-------------|----------|
| Chi (fax) | 25 AND/round × 24 = 600 | 0 (absorbed into degree-2 sumcheck) |
| Rotations (rotl) | ~30 AND/round × 24 ≈ 720 | 0 (absorbed as polynomial predicate) |
| Total AND constraints | ~1320 | 0 |

All nonlinearity is handled by the sumcheck protocol itself, not by explicit AND constraints.

### Batching

For $h$ instances, the sumcheck overhead grows as $O(\log h)$ per round (one extra variable per doubling of batch size), while the MLE evaluation cost grows linearly as $O(h)$.
The fixed overhead per sumcheck is small in binary fields (no in-circuit Fiat-Shamir needed, since sumcheck is native to Binius).

## Design Alternatives: GKR vs Flattened Trace

There are two main approaches, differing in what gets committed.

### Option A: Pure GKR (virtual intermediate states)

Only commit to the 25 input and 25 output lane polynomials.
Intermediate round states are "virtual": the sumcheck protocol reduces claims through all 24 rounds sequentially, never materializing or committing to intermediate data.

- **Commitments:** ~50 polynomials (25 input + 25 output)
- **Sumchecks:** ~24-48 sequential instances (roughly 1-2 per round)
- **Pro:** Minimal commitment work
- **Con:** Long sequential sumcheck chain; prover must maintain all intermediate MLE evaluations in memory

### Option B: Flattened trace (committed round states)

Commit to all 24 round states as a single polynomial per lane.
Encode the round index in 5 extra variables (pad 24 → 32), giving each lane polynomial `6 + 5 + log(h) = 11 + log(h)` variables.
The round transition becomes a constraint between "row t" and "row t+1" in this flattened polynomial, verified by sumcheck.

- **Commitments:** 25 polynomials (one per lane, each encoding all 32 rounds × h instances)
- **Sumchecks:** Fewer, larger instances, potentially ~1-2 global checks if all rounds are verified in parallel
- **Pro:** Simpler protocol, all rounds verified simultaneously, more parallelism
- **Con:** 24× more data to commit per lane (but still only 25 committed polynomials total)

### Comparison

| | Option A (GKR) | Option B (Flattened) |
|---|---|---|
| Committed data | 50 × 64h bits | 25 × 64 × 32h bits |
| Committed polynomials | 50 | 25 |
| Sumcheck instances | ~24-48 | ~1-2 |
| Sequential depth | ~24-48 sumchecks | ~1-2 sumchecks |
| Integration complexity | New sub-protocol | Closer to existing Binius model |

Option B is closer to how Binius already works (one big committed witness, constraints verified via sumcheck sub-protocols).
The 24× data increase may be acceptable since BaseFold cost scales with the *number* of committed polynomials, not just their size, and we go from 600+ to 25.
It also benefits the most from the characteristic-2 simplification that almost the entire round is linear.

### Hybrid: commit every R rounds

A middle ground: commit every R rounds (e.g., R=4 or R=6), reducing to 4-6 sumcheck chains of depth R instead of one chain of depth 24.
This trades off commitment size vs sequential sumcheck depth.

## How Binius64 Currently Draws the Committed/Virtual Line

Understanding the existing infrastructure is key to choosing the right integration approach.

### ValueVec layout (constraint_system.rs)

The witness is a single flat vector (`ValueVec`) with this layout:

```
[constants | inout | pad | witness + internal | pad ] = committed_total_len
[                                                     | scratch            ]
```

- **Committed region** (`0..committed_total_len`): Everything in this region is packed into a single MLE and committed via BaseFold (`combined_witness()`, line 862).
  This includes constants, public I/O, and all witness/internal wires that appear in any constraint.
- **Scratch region** (`committed_total_len..`): Wires allocated above this boundary are NOT committed.
  Used for intermediate values that don't appear in constraints.

### What counts as "transparent" (not committed)

The IOP layer (`crates/iop/src/channel.rs`, line 43) has `OracleLinearRelation`:
a committed oracle polynomial paired with a transparent MLE (a verifier-computable closure).
The transparent side never gets a BaseFold commitment.

Current transparent polynomials include:
- **Wiring polynomials** in Spartan (`crates/spartan-verifier/src/wiring.rs`): encode constraint structure, computable from the constraint system definition.
- **Shift predicates** in the shift reduction protocol: `ShiftedValueIndex` (line 134) references a committed word with a symbolic shift.
  The shift is resolved in the shift reduction protocol without a separate commitment.
- **Ring-switch batching** polynomials.

### Gate fusion as "virtual elimination"

Gate fusion (`crates/frontend/src/compiler/gate_fusion/`) inlines linear intermediates into AND constraints, effectively making them virtual.
For example, `a XOR b` feeding into `(a XOR b) AND c` can be fused into a single AND constraint on the shifted/combined operand, eliminating the XOR wire from the committed region entirely.

The `force_commit` mechanism (used in Keccak's theta step, `permutation.rs` lines 122-129) overrides fusion to force certain wires to be committed, preventing fusion from inlining them in a way that hurts shift reduction.

### Existing sub-protocol architecture

The prover pipeline (`crates/prover/src/prove.rs`) composes independent sub-protocols:

1. Commit witness trace (one BaseFold oracle)
2. **IntMul** reduction (mul constraints → sumcheck)
3. **BitAnd** reduction (and constraints → sumcheck)
4. **Shift** reduction (links shifted references to the committed trace)
5. **Ring-switch** + batched pubcheck (transparent relations)
6. **BaseFold** opening proof

A Keccak GKR/flattened protocol would fit as a new sub-protocol in this pipeline, producing `OracleLinearRelation` claims against the committed trace.

## Round Constants

All 24 keccak-f rounds have identical structure; the only thing that varies is the iota round constant RC[t].
In the current circuit (`permutation.rs:171-174`), iota is:

```rust
let rc_wire = b.add_constant(Word(RC[round]));
state[0] = b.bxor(state[0], rc_wire);
```

The 24 constants are defined in `permutation.rs:8-33`:

```
RC[0]  = 0x0000_0000_0000_0001    RC[12] = 0x0000_0000_8000_808B
RC[1]  = 0x0000_0000_0000_8082    RC[13] = 0x8000_0000_0000_008B
RC[2]  = 0x8000_0000_0000_808A    RC[14] = 0x8000_0000_0000_8089
...                                ...
RC[11] = 0x0000_0000_8000_000A    RC[23] = 0x8000_0000_8000_8008
```

These are sparse in bits (most have only a few bits set among the 64).
In the MLE approach, each RC[t] is expanded as a 6-variate polynomial (its 64-bit representation), constant across instances.

For Option B (flattened trace), the round constant becomes a function of the round-index variables too: an (11+log h)-variate polynomial that selects the right RC based on the 5 round-index variables.
This is a transparent polynomial (verifier-computable from the constants), not witness data.

## Jolt's VirtualPolynomial Pattern

Jolt (`../jolt`) has an explicit `VirtualPolynomial` concept that is worth studying for integration design.
(Jolt's book credits the [Binius paper](https://eprint.iacr.org/2023/1784) for introducing the concept.)

### What it is

`VirtualPolynomial` is an **enum of symbolic names** for non-committed witness MLEs (`jolt-core/src/zkvm/witness.rs:232`).
It is NOT a polynomial data structure. It is a **key** in the opening accumulator.

```rust
pub enum PolynomialId {
    Committed(CommittedPolynomial),
    Virtual(VirtualPolynomial),
}
```

### How it works in the sumcheck DAG

Jolt's proving pipeline is a DAG of sumcheck instances.
Each sumcheck instance implements two hooks:

- **`input_claim`**: reads claimed point openings or transparent linear relations on virtual polynomials from earlier sumchecks (in-edges in the DAG).
- **`cache_openings`**: after the sumcheck completes, writes new virtual claims to the accumulator (out-edges).

The prover's accumulator should store virtual claims keyed by `(VirtualPolynomial, SumcheckId)`.
For Keccak, the important cases are ordinary point openings `(point, claim)` and transparent linear relations `(point, transparent, claim)`.
Committed claims are eventually batched and verified via PCS (Dory).
Virtual claims are carried from one sumcheck instance to the next without a PCS, exactly as in Jolt's virtual-polynomial layer.

### Algebraic composition via `ClaimExpr`

Claims on virtual polynomials are combined using `ClaimExpr<F>` (`sumcheck_claim.rs:138`):

```rust
pub enum ClaimExpr<F> {
    Constant(F),
    Var(PolynomialId),
    Add(Box<ClaimExpr<F>>, Box<ClaimExpr<F>>),
    Mul(Box<ClaimExpr<F>>, Box<ClaimExpr<F>>),
    Sub(Box<ClaimExpr<F>>, Box<ClaimExpr<F>>),
}
```

This lets the verifier evaluate complex expressions over cached openings without materializing intermediate polynomials.

### Relevance to this design

For a binary-field KeccakCheck in Binius, the useful thing to import is the protocol abstraction, not the exact enum design.
We could adopt a similar pattern:

- Each intermediate round state is a `VirtualPolynomial` (named, not committed).
- The Keccak protocol is a sequence of sumcheck instances, each consuming virtual claims from the previous step and producing new ones.
- Only the input/output state polynomials are `Committed`.
- The opening accumulator tracks the chain of claims through 24 rounds.

This would require extending Binius's prover pipeline with:
1. A `VirtualPolynomial` or equivalent naming/keying mechanism.
2. An accumulator that stores virtual point openings and virtual transparent linear relations.
3. Sumcheck instances that can read/write both kinds of virtual claims.

Binius currently lacks this explicit abstraction.
The closest analogs are `OracleLinearRelation` (for transparent polynomials) and `ShiftedValueIndex` (for symbolic shifts), but neither provides the general virtual-claim DAG that Jolt uses.

For Keccak specifically, this points to a clear staging strategy:

1. Introduce a minimal Jolt-style virtual-claim DAG in Binius.
2. Implement the clean `2 sumchecks / round` design on top of that DAG.
3. Collapse to `1 sumcheck / round` only after carried transparent kernels for shifted and rotated lane views are first-class protocol objects.

The reason to stage it this way is that the `2 / round` boundary is exactly the pre-chi state.
That makes it the cleanest place to cache pre-chi point openings and exercise the new abstraction.
The `1 / round` design is likely the better steady-state protocol, but it is an optimization on top of the same machinery.

## From `Keccak256` to a Keccak Sponge Protocol

The current `Keccak256` code is already structured as a sponge.
It pads the input, absorbs one 136-byte block at a time into the first 17 state words, runs `keccak_f1600`, and then exposes the first 32 bytes of the final rate portion as output.

This suggests the right bespoke protocol target is not "Keccak-256 digest correctness."
It is "correct execution of a Keccak sponge state machine."

### The key shift in abstraction

Instead of proving:

- `digest = Keccak256(message)`

we should prove:

- `output = KeccakSponge(rate = 136, suffix, absorb_blocks, output_len)`

where:

- `suffix = 0x01` gives current Keccak-style hashing behavior.
- `suffix = 0x1F` gives SHAKE256 behavior.
- `output_len = 32` recovers `Keccak256`.
- arbitrary `output_len` gives XOF squeezing.

The important point is that `Keccak256` and `SHAKE256` use the same permutation and the same rate.
The main differences are the framing byte and the squeeze schedule.

### Scope of the first protocol

The first protocol should not try to reason about raw message bytes.
It should take already-framed absorb blocks as input.

In other words, the proof target should be something like:

- `prove_sponge_136(absorb_blocks, output_len, output_bytes)`

where `absorb_blocks` is a sequence of already padded 136-byte blocks.

This deliberately keeps the following out of scope for the first version:

- raw-byte padding logic,
- suffix injection,
- `ExpandA`,
- rejection sampling,
- bit-slicing tricks,
- lattice arithmetic,
- any signature-level logic.

Those are outer wrappers around the sponge and can be handled later.

### Sponge state machine

Let:

- `a` be the number of absorb blocks,
- `s = ceil(output_len / 136)` be the number of output blocks needed,
- `T = a + s - 1` be the number of permutation steps.

Define states `S_0, S_1, ..., S_T`, where each `S_t` is a 1600-bit state arranged as 25 lanes of 64 bits.
Set `S_0` to the all-zero state.

For each step `t`, define an addend `A_t`:

- if `t < a`, then `A_t` is absorb block `t` embedded into the first 17 lanes,
- if `t >= a`, then `A_t = 0`.

Then define the transition:

- `X_t = S_t XOR A_t`,
- `S_{t+1} = KeccakF1600(X_t)`.

This single recurrence handles both absorb and squeeze.

- During absorb steps, `A_t` contains a real message block.
- During extra squeeze steps, `A_t = 0`, so we simply permute the previous state again.

The output blocks are then:

- `Y_u = RatePrefix(S_{a+u})` for `u = 0, ..., s - 1`,

and the final result is:

- `output = truncate(output_len, Y_0 || Y_1 || ... || Y_{s-1})`.

For `Keccak256`, we have `s = 1`, so this is just the first 32 bytes of `Y_0`.
For `SHAKE256`, `s` is arbitrary.

### Where the bespoke GKR protocol fits

The nonlinear part of the sponge protocol is only the permutation step:

- `S_{t+1} = KeccakF1600(X_t)`.

Everything else is linear or transparent:

- absorbing a block is XOR into the first 17 lanes,
- squeezing is projection of the first 17 lanes,
- extra squeeze rounds are just permutation calls with zero absorb addend,
- truncation is byte selection.

So the sponge protocol should wrap the bespoke Keccak-f protocol, not replace it.

Concretely:

1. Use the bespoke Keccak-f protocol to prove each transition `X_t -> S_{t+1}`.
2. Use transparent linear checks for `S_t -> X_t`.
3. Use transparent projection checks for `S_{a+u} -> Y_u`.
4. Leave framing and byte-level parsing outside the first protocol.

This is the cleanest path from the current `Keccak256` implementation to a SHAKE-capable proof system.

### Two ways to organize the sponge proof

#### Option A: virtual state chain

Use a Jolt-style virtual-claim DAG.

Natural virtual objects are:

- `SpongeState(t)`,
- `AbsorbedState(t)`,
- `OutputBlock(u)`.

The proof graph is:

1. `SpongeState(t)` plus `AbsorbAddend(t)` gives `AbsorbedState(t)` via a linear check.
2. `AbsorbedState(t)` is consumed by the bespoke Keccak-f proof.
3. The bespoke Keccak-f proof outputs `SpongeState(t+1)`.
4. Selected `SpongeState(a+u)` nodes produce `OutputBlock(u)` by transparent projection.

This reuses the Keccak-f protocol almost unchanged.
It also matches the Jolt-style idea that intermediate states are named and opened, but not committed.

#### Option B: flattened sponge trace

Flatten the entire sponge trace over the permutation-step index.

Each lane becomes a polynomial over:

- 6 bit-index variables,
- `log(T)` step-index variables,
- `log(h)` batch-index variables.

Then the absorb and squeeze schedule is encoded as a transparent selector over the step index.
This allows more parallelism and fewer explicit sumcheck edges, but it is a heavier first implementation.

For now, the virtual-state-chain design looks like the better first prototype.

### Why this is enough for the intended applications

If we ignore `ExpandA` entirely, then the relevant in-proof use cases are exactly the ones where SHAKE256 is used as a sponge/XOF:

- Falcon-style `HashToPoint`,
- ML-DSA's `H = SHAKE256` calls such as `tr`, `mu`, `c_tilde`, and `SampleInBall`.

All of these sit above the same primitive:

- absorb some bytes,
- squeeze some bytes,
- parse those bytes outside the sponge proof.

So the immediate high-leverage target is:

- prove Keccak sponge state transitions,
- not the downstream parsing logic.

### Suggested migration path

1. Conceptually refactor `Keccak256` into a 136-byte sponge API with fixed-length output as a wrapper.
2. Define a first proof target that accepts already framed absorb blocks and claimed output bytes.
3. Implement the virtual-state-chain version using a Jolt-style opening accumulator idea.
4. Reuse the bespoke Keccak-f proof as the nonlinear core of each sponge transition.
5. Add a thin `SHAKE256` wrapper on top once the sponge protocol exists.

## Precise SHAKE256 Accounting for Signature Verification

This section gives the cost model for the in-proof SHAKE256 work under the current scope assumptions.

- `ExpandA` is always out of proof.
- We count only SHAKE256 work that remains in verification.
- We do not count rejection-sampling logic, lattice arithmetic, or byte-to-object parsing outside the sponge itself.

### Counting unit

For throughput estimation, the right unit is the number of `KeccakF1600` calls, not just the number of SHAKE256 invocations.

For a SHAKE256 call that absorbs `N` bytes and squeezes `L > 0` bytes, with rate 136, the exact number of permutation calls is:

- `floor(N / 136) + ceil(L / 136)`.

This is the quantity that should be multiplied by 24 if we want the total number of Keccak rounds.

### ML-DSA: exact SHAKE256 sub-tasks

Ignoring `ExpandA`, `ML-DSA.Verify_internal` performs exactly three or four SHAKE256 computations:

1. `tr = H(pk, 64)`, unless `tr` is cached per verifying key.
2. `mu = H(tr || M', 64)`.
3. `c = SampleInBall(c_tilde)`.
4. `c_tilde' = H(mu || w1Encode(w1'), lambda / 4)`.

The key lines are:

- `tr <- H(pk, 64)` at `FIPS_204_ML_DSA.pdf:1408`.
- `mu <- H(BytesToBits(tr)||M', 64)` at `FIPS_204_ML_DSA.pdf:1409`.
- `c <- SampleInBall(c_tilde)` at `FIPS_204_ML_DSA.pdf:1411`.
- `c_tilde' <- H(mu || w1Encode(w1'), lambda / 4)` at `FIPS_204_ML_DSA.pdf:1417-1418`.

Assume byte-aligned messages and let:

- `m = |M|` in bytes,
- `c = |ctx|` in bytes.

Then `M'` contributes `2 + c + m` bytes, so the input to `mu` has length `66 + c + m`.

#### `tr = H(pk, 64)`

Using FIPS 204 Table 2 public-key sizes:

| Parameter set | `|pk|` | SHAKE256 invocations | `KeccakF1600` calls |
| --- | ---: | ---: | ---: |
| `ML-DSA-44` | `1312` | `1` | `10` |
| `ML-DSA-65` | `1952` | `1` | `15` |
| `ML-DSA-87` | `2592` | `1` | `20` |

These are cacheable per verifying key.

#### `mu = H(tr || M', 64)`

This always uses:

- `1` SHAKE256 invocation,
- `floor((66 + c + m) / 136) + 1` permutation calls.

For the default empty context (`c = 0`):

| Message bytes `m` | `KeccakF1600` calls for `mu` |
| ---: | ---: |
| `32` | `1` |
| `256` | `3` |
| `1024` | `9` |

#### `SampleInBall(c_tilde)`

This is one incremental SHAKE256 context.
It absorbs `lambda / 4` bytes and then squeezes:

- `8` bytes for the sign bits,
- plus a variable number of one-byte draws for the Fisher-Yates position selection.

The expected number of position bytes is:

| Parameter set | `tau` | Expected position bytes | Expected total output bytes |
| --- | ---: | ---: | ---: |
| `ML-DSA-44` | `39` | `42.221969` | `50.221969` |
| `ML-DSA-65` | `49` | `54.271230` | `62.271230` |
| `ML-DSA-87` | `60` | `68.215242` | `76.215242` |

All of these fit well within one 136-byte rate block.
So for throughput accounting, `SampleInBall` costs:

- `1` SHAKE256 invocation,
- effectively `1` `KeccakF1600` call.

#### `c_tilde' = H(mu || w1Encode(w1'), lambda / 4)`

`w1Encode` has size:

- `768` bytes for `ML-DSA-44`,
- `768` bytes for `ML-DSA-65`,
- `1024` bytes for `ML-DSA-87`.

Thus the SHAKE256 cost is:

| Parameter set | Input bytes | Output bytes | SHAKE256 invocations | `KeccakF1600` calls |
| --- | ---: | ---: | ---: | ---: |
| `ML-DSA-44` | `64 + 768 = 832` | `32` | `1` | `7` |
| `ML-DSA-65` | `64 + 768 = 832` | `48` | `1` | `7` |
| `ML-DSA-87` | `64 + 1024 = 1088` | `64` | `1` | `9` |

### ML-DSA totals

With `tr` cached per key:

| Parameter set | SHAKE256 invocations | `KeccakF1600` calls |
| --- | ---: | ---: |
| `ML-DSA-44` | `3` | `floor((66 + c + m) / 136) + 8 + 1` |
| `ML-DSA-65` | `3` | `floor((66 + c + m) / 136) + 8 + 1` |
| `ML-DSA-87` | `3` | `floor((66 + c + m) / 136) + 10 + 1` |

Equivalently:

| Parameter set | SHAKE256 invocations | `KeccakF1600` calls |
| --- | ---: | ---: |
| `ML-DSA-44` | `3` | `floor((66 + c + m) / 136) + 9` |
| `ML-DSA-65` | `3` | `floor((66 + c + m) / 136) + 9` |
| `ML-DSA-87` | `3` | `floor((66 + c + m) / 136) + 11` |

Without caching `tr`:

| Parameter set | SHAKE256 invocations | `KeccakF1600` calls |
| --- | ---: | ---: |
| `ML-DSA-44` | `4` | `floor((66 + c + m) / 136) + 19` |
| `ML-DSA-65` | `4` | `floor((66 + c + m) / 136) + 24` |
| `ML-DSA-87` | `4` | `floor((66 + c + m) / 136) + 31` |

For empty context and common message lengths:

| Parameter set | `m = 32` | `m = 256` | `m = 1024` |
| --- | ---: | ---: | ---: |
| `ML-DSA-44`, cached `tr` | `9` | `11` | `17` |
| `ML-DSA-65`, cached `tr` | `9` | `11` | `17` |
| `ML-DSA-87`, cached `tr` | `11` | `13` | `19` |
| `ML-DSA-44`, uncached `tr` | `19` | `21` | `27` |
| `ML-DSA-65`, uncached `tr` | `24` | `26` | `32` |
| `ML-DSA-87`, uncached `tr` | `31` | `33` | `39` |

### FN-DSA / Falcon: exact SHAKE256 sub-tasks

In the deployed `c-fn-dsa` verification path, the relevant SHAKE256 work is:

1. hash the verifying key to 64 bytes, unless cached,
2. run `hash_to_point(...)`.

The verification code hashes the verifying key here:

- `vrfy.c:44-57`.

The deployed `hash_to_point` input framing is documented here:

- `util.c:20-23`.

In raw-message mode, the absorbed string is:

- `nonce || hashed_vrfy_key || 0x00 || len(ctx) || ctx || message`.

The nonce length is fixed at 40 bytes, and `hashed_vrfy_key` is fixed at 64 bytes.
Thus the absorbed input length for the deployed mode is:

- `106 + c + m`.

#### Key hash

Using Falcon public-key sizes from the Falcon spec:

| Parameter set | `|pk|` | SHAKE256 invocations | `KeccakF1600` calls |
| --- | ---: | ---: | ---: |
| `Falcon-512` | `897` | `1` | `7` |
| `Falcon-1024` | `1793` | `1` | `14` |

This is cacheable per verifying key.

#### `hash_to_point`

Falcon squeezes 16-bit values and accepts each draw with probability:

- `61445 / 65536`.

It needs `n` accepted values, where `n = 512` or `1024`.

Therefore the exact expected number of 16-bit draws is:

| Parameter set | Expected 16-bit draws | Expected squeezed bytes |
| --- | ---: | ---: |
| `Falcon-512` | `546.088893` | `1092.177785` |
| `Falcon-1024` | `1092.177785` | `2184.355570` |

Converting this into expected 136-byte squeeze blocks gives:

| Parameter set | Expected squeeze blocks | Expected `KeccakF1600` calls from squeeze |
| --- | ---: | ---: |
| `Falcon-512` | `8.592536` | `8.592536` |
| `Falcon-1024` | `16.660246` | `16.660246` |

So the expected `hash_to_point` cost in deployed FN-DSA mode is:

- `1` SHAKE256 invocation,
- `floor((106 + c + m) / 136) + 8.592536` for `Falcon-512`,
- `floor((106 + c + m) / 136) + 16.660246` for `Falcon-1024`.

For legacy original Falcon mode, replace `106 + c + m` with `40 + m`.

### FN-DSA / Falcon totals

With `hashed_vrfy_key` cached:

| Parameter set | SHAKE256 invocations | Expected `KeccakF1600` calls |
| --- | ---: | ---: |
| `Falcon-512` | `1` | `floor((106 + c + m) / 136) + 8.592536` |
| `Falcon-1024` | `1` | `floor((106 + c + m) / 136) + 16.660246` |

Without caching `hashed_vrfy_key`:

| Parameter set | SHAKE256 invocations | Expected `KeccakF1600` calls |
| --- | ---: | ---: |
| `Falcon-512` | `2` | `floor((106 + c + m) / 136) + 15.592536` |
| `Falcon-1024` | `2` | `floor((106 + c + m) / 136) + 30.660246` |

For empty context and common message lengths:

| Parameter set | `m = 32` | `m = 256` | `m = 1024` |
| --- | ---: | ---: | ---: |
| `Falcon-512`, cached key hash | `9.592536` | `10.592536` | `16.592536` |
| `Falcon-1024`, cached key hash | `17.660246` | `18.660246` | `24.660246` |
| `Falcon-512`, uncached key hash | `16.592536` | `17.592536` | `23.592536` |
| `Falcon-1024`, uncached key hash | `31.660246` | `32.660246` | `38.660246` |

### SLH-DSA / SPHINCS+: exact SHAKE256 sub-tasks

Unlike ML-DSA and Falcon, `SLH-DSA-SHAKE-*` uses SHAKE256 for essentially the verifier's entire symmetric workload.

FIPS 205 defines both SHAKE and SHA2 parameter sets.
This subsection counts only the six `SLH-DSA-SHAKE-*` sets.

The verifier-side structure is:

1. `digest <- H_msg(R, PK.seed, PK.root, M')`.
2. `PK_FORS <- fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)`.
3. `ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)`.

The key lines are:

- `slh_verify_internal` at `FIPS_205_SLH_DSA.pdf:1742-1776`.
- `fors_pkFromSig` at `FIPS_205_SLH_DSA.pdf:1554-1582`.
- `ht_verify` at `FIPS_205_SLH_DSA.pdf:1389-1411`.
- `xmss_pkFromSig` at `FIPS_205_SLH_DSA.pdf:1277-1300`.
- `wots_pkFromSig` at `FIPS_205_SLH_DSA.pdf:1127-1145`.
- SHAKE instantiations at `FIPS_205_SLH_DSA.pdf:2089-2098`.
- parameter sets at `FIPS_205_SLH_DSA.pdf:2030-2049`.

Let:

- `n, h, d, h', a, k, m` be the FIPS 205 parameters,
- `len = 2n + 3`,
- `|M'|` be the byte length passed to `slh_verify_internal`.

Then the verifier work expands as follows:

- `H_msg` contributes `1` SHAKE256 invocation, absorbing `3n + |M'|` bytes and squeezing `m` bytes.
- `fors_pkFromSig` contributes `k` calls to `F`, `k * a` calls to `H`, and `1` call to `T_k`.
- `ht_verify` contributes `d` calls to `xmss_pkFromSig`.
- each `xmss_pkFromSig` contributes `1` `wots_pkFromSig` plus `h'` calls to `H`.
- each `wots_pkFromSig` contributes a data-dependent number of chain-`F` calls plus `1` call to `T_len`.

For the SHAKE parameter sets, the address is the full 32-byte `ADRS`, not the compressed 22-byte SHA2 address.
So the absorbed lengths are:

- `F`: `32 + 2n` bytes,
- `H`: `32 + 3n` bytes,
- `T_k`: `32 + (k + 1)n` bytes,
- `T_len`: `32 + (len + 1)n` bytes.

Let `ΣW` be the total number of verifier-side WOTS chain `F` evaluations across the whole hypertree.
Then the exact internal SHAKE256 invocation count is:

- `2 + k * (a + 1) + h + d + ΣW`.

The exact internal `KeccakF1600` count is:

- `floor((3n + |M'|) / 136) + 1 + k + k * a + perm(T_k) + h + d * perm(T_len) + ΣW`,

where:

- `perm(T_k) = floor((32 + (k + 1)n) / 136) + 1`,
- `perm(T_len) = floor((32 + (len + 1)n) / 136) + 1`.

For all six approved SHAKE parameter sets:

- every `F` call costs exactly `1` permutation,
- every `H` call costs exactly `1` permutation,
- only `H_msg`, `T_k`, and `T_len` can cost more than one permutation.

#### Exact WOTS chain term

This is the dominant verifier-side cost.

For one `wots_pkFromSig`, let the signed `n`-byte message have hex digits `x_0, ..., x_{2n-1}`.
Define:

- `C = sum_t (15 - x_t)`,
- `W = C + 45 - s_16(C)`,

where `s_16(C)` is the sum of the three hex digits of `C`.

Then `W` is exactly the number of verifier-side `F` evaluations in that one WOTS verification.

Per WOTS verification, the bounds and exact uniform-message expectations are:

| `n` | Parameter sets | Best `W` | Expected `W` | Worst `W` |
| --- | --- | ---: | ---: | ---: |
| `16` | `SLH-DSA-SHAKE-128s`, `SLH-DSA-SHAKE-128f` | `45` | `267.122905` | `510` |
| `24` | `SLH-DSA-SHAKE-192s`, `SLH-DSA-SHAKE-192f` | `45` | `390.461503` | `750` |
| `32` | `SLH-DSA-SHAKE-256s`, `SLH-DSA-SHAKE-256f` | `45` | `505.922620` | `990` |

The expectation above is exact for the model where the WOTS message is uniform over `n` bytes.
It was computed by dynamic programming over the checksum distribution of `(1 + x + ... + x^15)^(2n)`.

#### Parameter-set constants

| Parameter set | `n` | `h` | `d` | `h'` | `a` | `k` | `len` | `m` | `perm(T_k)` | `perm(T_len)` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `SLH-DSA-SHAKE-128s` | `16` | `63` | `7` | `9` | `12` | `14` | `35` | `30` | `3` | `5` |
| `SLH-DSA-SHAKE-128f` | `16` | `66` | `22` | `3` | `6` | `33` | `35` | `34` | `5` | `5` |
| `SLH-DSA-SHAKE-192s` | `24` | `63` | `7` | `9` | `14` | `17` | `51` | `39` | `4` | `10` |
| `SLH-DSA-SHAKE-192f` | `24` | `66` | `22` | `3` | `8` | `33` | `51` | `42` | `7` | `10` |
| `SLH-DSA-SHAKE-256s` | `32` | `64` | `8` | `8` | `14` | `22` | `67` | `47` | `6` | `17` |
| `SLH-DSA-SHAKE-256f` | `32` | `68` | `17` | `4` | `9` | `35` | `67` | `49` | `9` | `17` |

### SLH-DSA totals

The hypertree-wide WOTS chain term `ΣW` has the following ranges:

| Parameter set | Best `ΣW` | Expected `ΣW` | Worst `ΣW` |
| --- | ---: | ---: | ---: |
| `SLH-DSA-SHAKE-128s` | `315` | `1869.860333` | `3570` |
| `SLH-DSA-SHAKE-128f` | `990` | `5876.703903` | `11220` |
| `SLH-DSA-SHAKE-192s` | `315` | `2733.230524` | `5250` |
| `SLH-DSA-SHAKE-192f` | `990` | `8590.153076` | `16500` |
| `SLH-DSA-SHAKE-256s` | `360` | `4047.380956` | `7920` |
| `SLH-DSA-SHAKE-256f` | `765` | `8600.684532` | `16830` |

So the total internal SHAKE256 invocation counts are:

| Parameter set | Best | Expected | Worst |
| --- | ---: | ---: | ---: |
| `SLH-DSA-SHAKE-128s` | `569` | `2123.860333` | `3824` |
| `SLH-DSA-SHAKE-128f` | `1311` | `6197.703903` | `11541` |
| `SLH-DSA-SHAKE-192s` | `642` | `3060.230524` | `5577` |
| `SLH-DSA-SHAKE-192f` | `1377` | `8977.153076` | `16887` |
| `SLH-DSA-SHAKE-256s` | `764` | `4451.380956` | `8324` |
| `SLH-DSA-SHAKE-256f` | `1202` | `9037.684532` | `17267` |

The total internal `KeccakF1600` counts are:

| Parameter set | Best | Expected | Worst |
| --- | --- | --- | --- |
| `SLH-DSA-SHAKE-128s` | `floor((48 + |M'|) / 136) + 599` | `floor((48 + |M'|) / 136) + 2153.860333` | `floor((48 + |M'|) / 136) + 3854` |
| `SLH-DSA-SHAKE-128f` | `floor((48 + |M'|) / 136) + 1403` | `floor((48 + |M'|) / 136) + 6289.703903` | `floor((48 + |M'|) / 136) + 11633` |
| `SLH-DSA-SHAKE-192s` | `floor((72 + |M'|) / 136) + 708` | `floor((72 + |M'|) / 136) + 3126.230524` | `floor((72 + |M'|) / 136) + 5643` |
| `SLH-DSA-SHAKE-192f` | `floor((72 + |M'|) / 136) + 1581` | `floor((72 + |M'|) / 136) + 9181.153076` | `floor((72 + |M'|) / 136) + 17091` |
| `SLH-DSA-SHAKE-256s` | `floor((96 + |M'|) / 136) + 897` | `floor((96 + |M'|) / 136) + 4584.380956` | `floor((96 + |M'|) / 136) + 8457` |
| `SLH-DSA-SHAKE-256f` | `floor((96 + |M'|) / 136) + 1482` | `floor((96 + |M'|) / 136) + 9317.684532` | `floor((96 + |M'|) / 136) + 17547` |

For pure `slh_verify`, `|M'| = 2 + c + m_msg`, where `c = |ctx|` and `m_msg = |M|`.

For empty context and common message lengths, the expected pure-verification counts are:

| Parameter set | `m_msg = 32` | `m_msg = 256` | `m_msg = 1024` |
| --- | ---: | ---: | ---: |
| `SLH-DSA-SHAKE-128s` | `2153.860333` | `2155.860333` | `2160.860333` |
| `SLH-DSA-SHAKE-128f` | `6289.703903` | `6291.703903` | `6296.703903` |
| `SLH-DSA-SHAKE-192s` | `3126.230524` | `3128.230524` | `3134.230524` |
| `SLH-DSA-SHAKE-192f` | `9181.153076` | `9183.153076` | `9189.153076` |
| `SLH-DSA-SHAKE-256s` | `4584.380956` | `4586.380956` | `4592.380956` |
| `SLH-DSA-SHAKE-256f` | `9317.684532` | `9319.684532` | `9325.684532` |

For `hash_slh_verify`, the internal verifier sees:

- `|M'| = 2 + c + |OID| + |PH(M)|`.
- for the standard OIDs above, `|OID| = 11`, so `|M'| = 13 + c + |PH(M)|`.

If `PH = SHAKE256`, this adds one extra external SHAKE256 call with cost:

- `floor(m_msg / 136) + 1`.

### Why SLH-DSA changes the protocol-design picture

SLH-DSA-SHAKE has a very different shape from ML-DSA and Falcon.
The dominant cost is not one or two long sponge computations.
It is thousands of short, address-separated SHAKE256 calls inside WOTS verification.

On expectation, the WOTS chain term accounts for about:

- `86.9%` of the internal non-`H_msg` `KeccakF1600` count for `SLH-DSA-SHAKE-128s`,
- `93.4%` for `SLH-DSA-SHAKE-128f`,
- `87.5%` for `SLH-DSA-SHAKE-192s`,
- `93.6%` for `SLH-DSA-SHAKE-192f`,
- `88.3%` for `SLH-DSA-SHAKE-256s`,
- `92.3%` for `SLH-DSA-SHAKE-256f`.

This suggests an important design distinction:

- ML-DSA and Falcon mostly want an efficient proof for a small number of longer sponge/XOF traces.
- SLH-DSA-SHAKE wants an efficient proof for a very large batch of short SHAKE256 calls with structured prefixes `PK.seed || ADRS || ...`.

The `f` parameter sets are especially strong stress tests.
They cost roughly `2x` to `3x` more than the corresponding `s` sets because the hypertree depth `d` is much larger.

### Practical takeaways for aggregation throughput

For aggregation throughput, the main conclusions are:

1. Invocation counts alone are misleading.
   One long `hash_to_point` invocation for Falcon is comparable to many short SHAKE256 calls in ML-DSA, while SLH-DSA-SHAKE is dominated by thousands of very short SHAKE256 calls.
2. Caching per-key prefix material matters a lot.
   In ML-DSA, caching `tr` saves `10`, `15`, or `20` permutation calls.
   In FN-DSA, caching `hashed_vrfy_key` saves `7` or `14` permutation calls.
   In SLH-DSA-SHAKE, there is much less comparable cacheable verifier-side prefix material, and the dominant WOTS chain cost is inherently per signature.
3. Once `ExpandA` is excluded, ML-DSA, deployed FN-DSA, and `SLH-DSA-SHAKE` are all fundamentally Keccak-based workloads, but they stress very different parts of the cost surface.
4. If the target application mix includes SLH-DSA, optimizing only long sponge traces is not enough.
   We also need a strategy for batched short SHAKE256 calls with address-based domain separation.
5. For throughput models, `KeccakF1600` calls should be treated as the primary accounting unit.

## Open Design Questions

### Integration path

The existing sub-protocol composition (`prove.rs`) suggests a clean integration:
the Keccak protocol runs as a new step (between commit and BaseFold), producing transparent linear relation claims on committed input/output polynomials that feed into the final BaseFold opening.

For Option B (flattened), the round-transition constraints could potentially be expressed as a new constraint type alongside `AndConstraint` and `MulConstraint`, with a dedicated reduction protocol.

Introducing a Jolt-style virtual polynomial abstraction would make Option A (pure GKR) much cleaner to implement and could benefit other future sub-protocols beyond Keccak.

The most plausible implementation order is:

1. Add a minimal accumulator for virtual claims, supporting both point openings and transparent linear relations, conceptually similar to Jolt's `input_claim` / `cache_openings` pattern.
2. Implement `KeccakChiIotaSumcheck`, which consumes carried output kernels and caches 25 pre-chi point openings.
3. Implement `KeccakLinearRoundSumcheck`, which consumes those 25 pre-chi point openings and emits the 25 carried transparent kernels on the next-round input lanes.
4. Reuse Binius's existing equality-weighted MLE-check path (`MleCheckProver` plus `MleToSumCheckDecorator`) where the carried claim is a point evaluation, and extend the same interface to general transparent kernels for the round-to-round handoff.
5. Only after that, consider replacing the pair with a single `KeccakRoundSumcheck` that inlines the linear map into chi.

This is the main recommendation of this note:
the `2 / round` design is the right first implementation target, while the `1 / round` design is the right optimization target.

### Current project decision

The exploratory oblong-first-round and packed-suffix variants did not deliver useful speedups.
In practice they regressed proving time enough that this line of work is not worth continuing in its current form.
For now, the recommended path is to use `binius64` unchanged for Keccak workloads.
We should revisit a bespoke Keccak protocol only if we have a design that is demonstrably better on the target benchmarks.

### Crossover point

For a single keccak-f, the bespoke protocol has fixed overhead.
The current direct circuit costs ~1320 AND constraints + linear constraints.
Need to determine: at what batch size does the bespoke protocol become cheaper?

The prime-field KeccakCheck crosses over at ~16 instances vs Gnark.
In binary fields, the crossover might be lower (simpler sumcheck polynomials, no in-circuit hashing) or higher (AND constraints are already cheap in Binius).

### Reuse of existing infrastructure

How much of `binius-core`'s sumcheck implementation can be reused?
The prover needs to:
- Evaluate MLEs at arbitrary points
- Compute sumcheck round polynomials for specific polynomial identities (chi, rho, theta)
- Handle the reduction chain across rounds

Most of the low-level machinery already exists:

- `crates/ip-prover/src/sumcheck/common.rs` already has the round-by-round prover interface needed for bespoke compositions.
- `crates/ip-prover/src/sumcheck/mle_to_sumcheck.rs` already provides the equality-weighted MLE-check adapter we want for evaluation claims at random points.
- `crates/iop/src/channel.rs` and `crates/iop-prover/src/basefold.rs` already support transparent linear relations against committed polynomials.

The missing piece is the protocol layer that sits above these and chains virtual point openings and virtual linear relations from one sumcheck instance into the next.

### Working over $\mathbb{F}_2$ vs tower extensions

The polynomial identities are naturally over $\mathbb{F}_2$.
But Binius's sumcheck operates over tower extensions ($T_i$) for soundness.
Need to work out:
- What extension field degree is needed for soundness?
- Does the choice affect the degree analysis above?

## References

- [KeccakCheck (eprint 2025/1764)](https://eprint.iacr.org/2025/1764) — original prime-field protocol
- [GKR (Goldwasser-Kalai-Rothblum 2008)](https://doi.org/10.1145/1374376.1374396) — delegating computation via layered sumcheck
- [Thaler, Proofs Arguments and Zero-Knowledge](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf) — standard reference for sumcheck and GKR
- Current implementation: `crates/circuits/src/keccak/` (direct circuit approach)
