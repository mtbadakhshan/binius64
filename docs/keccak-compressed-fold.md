# Compressed Fold Optimization — Experiment Results

**Status:** Implemented, benchmarked, **reverted** — no measurable improvement on Apple Silicon.

## Background

### The Memory Blowup Problem

The Keccak GKR prover (`FusedRoundProver`) stores instance data in three phases:

1. **u64 words** (first sumcheck round): 25 lanes × 8 bytes = **200 bytes per instance**
2. **GF(2^128) block tables** (subsequent rounds): 25 lanes × 64 bits × 16 bytes = **25,600 bytes per instance**
3. Each `fold()` halves the instance count but the first fold expands the representation 128×

At batch 2^14 (16384 instances), the block-table working set after the first fold is:
8192 instances × 25,600 bytes = **200 MB**, far exceeding L2 cache (~4 MB on Apple Silicon).

### The Idea

After `m` folds, each element depends on `2^m` original bits and takes one of `2^(2^m)` possible
values. Instead of storing a full 128-bit field element, store a compact **index** into a
precomputed lookup table:

| Folds done | Bits per index | Table entries | Bytes per instance | vs block tables |
|---:|---:|---:|---:|---:|
| 1 | 2 | 4 | 400 B | 64× smaller |
| 2 | 4 | 16 | 800 B | 32× smaller |
| 3 | 8 (u8) | 256 | 1,600 B | 16× smaller |

At `m=3`: 1,600 bytes per instance instead of 25,600 — a 16× memory reduction.

### The Math

After fold 1 with challenge `r₁`, each folded element is `lo + r₁ × (hi − lo)` where lo, hi ∈ {0,1}.
The four possible values are `{0, 1, r₁, 1+r₁}`, indexed by `(lo_bit | hi_bit << 1)`.

After fold 2 with challenge `r₂`, each element depends on 4 original bits. The 16 possible values
are `old[lo_idx] + r₂ × (old[hi_idx] − old[lo_idx])` for all pairs `(lo_idx, hi_idx)` of
4-entry table indices.

After fold 3 with challenge `r₃`, each element depends on 8 original bits. The 256 possible values
fit in a `Vec<F>` of 256 entries, and each per-instance element is a single `u8` index.

### Implementation

The `FusedRoundProver` state machine was extended:

```
words → compressed(m=1) → compressed(m=2) → compressed(m=3) → full blocks → ...
```

The `CompressedBlocks<F>` struct stores:
- `indices: Vec<[[u8; 64]; 25]>` — per-instance, per-lane, per-bit index
- `table: Vec<F>` — the lookup table (4, 16, or 256 entries)
- `folds_done: usize`

During `execute()`, a new evaluation function resolves indices through the table before
computing the chi+linear polynomial — identical math to the block-table path but with an
extra indirection layer.

## Benchmark Results

Tested on Apple M-series (AArch64), `RUSTFLAGS="-C target-cpu=native"`, release build.

| Batch | Before (blocks) | After (compressed) | Change |
|---:|---:|---:|---:|
| 2^8 (256) | 46.7 ms | 53.9 ms | 1.15× slower |
| 2^10 (1024) | 82.8 ms | 92.7 ms | 1.12× slower |
| 2^14 (16384) | 649 ms | 638 ms | ~same (noise) |

**The optimization had no positive effect.** Small batches got slower; large batches were unchanged.

## Why It Didn't Work

### 1. Indirection overhead

The compressed path replaces `input_hi[lane][rotated_indices[b]]` (direct array access) with
`table[input_hi_idx[lane][rotated_indices[b]] as usize]` (two-level indirection). The extra
pointer chase adds latency per element.

### 2. Apple Silicon's prefetcher handles large sequential scans well

The block-table representation is accessed sequentially within each instance (64 elements per
lane, 25 lanes). Apple Silicon's hardware prefetcher recognizes this stride pattern and
prefetches cache lines ahead of the access. The 200 MB working set at 2^14 causes L2 misses,
but the prefetcher hides most of the latency by streaming data from L3/DRAM.

The compressed representation is 16× smaller, so more of it fits in cache — but the indirection
through the table defeats the prefetcher's ability to predict the access pattern.

### 3. The sumcheck halves data each round anyway

The sumcheck naturally halves the instance count at each fold. After 4 rounds, the working set
is 1/16 of the original — reaching the same cache-friendly size that the compressed
representation provides from the start. The compressed fold front-loads the benefit, but the
total memory traffic difference across all rounds is small.

### 4. The 128× blowup is unavoidable in the computation

Even with compressed storage, the `execute()` function must produce full GF(2^128) field
values (to compute chi's degree-2 polynomial). The table lookup reconstitutes each value to
128 bits before any arithmetic. So the ALU sees the same 128-bit operands regardless of
storage format — the savings are purely in memory bandwidth, which the prefetcher already
handles.

## Conclusion

The compressed fold is mathematically correct and reduces memory footprint by 16×, but on
modern hardware with aggressive prefetching, the indirection overhead cancels the cache benefit.
The optimization might help on architectures with weaker prefetchers or smaller caches, but on
Apple Silicon it is not worthwhile.

The fundamental bottleneck of the Keccak GKR prover remains the **24 sequential sumcheck
passes**, not the per-pass memory access pattern. Each pass takes ~24ms regardless of whether
the data is in cache or not, because the computation (field multiplies for chi evaluation) is
the dominant cost, not memory latency.
