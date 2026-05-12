// Copyright 2026 The Binius Developers

//! Verifier-side bridge from Binius's IOP layer to the Akita lattice PCS.
//!
//! Three opening variants are supported, each in its own submodule:
//!
//! - [`full_open`] — sends the committed polynomial in clear (largest proof,
//!   simplest verifier; used mainly for testing).
//! - [`succinct`] — succinct multi-point Akita opening.
//! - [`claim_reduced`] — succinct single-point Akita opening via a
//!   claim-reduction sumcheck. Smaller and faster than [`succinct`] in
//!   exchange for one extra degree-2 sumcheck.
//!
//! Shared building blocks live in [`protocol`] (parity bridge, product
//! sumcheck, booleanity, claim-reduction primitives, bit-table extraction)
//! and [`wire`] (length-prefixed I/O of Akita proof objects on the Binius
//! transcript).
//!
//! Prover-side implementations live in `binius-akita-bridge-prover`.

#![warn(rustdoc::missing_crate_level_docs)]

pub mod claim_reduced;
pub mod full_open;
pub mod protocol;
pub mod succinct;
pub mod wire;
