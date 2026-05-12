// Copyright 2026 The Binius Developers

//! Prover-side bridge from Binius's IOP layer to the Akita lattice PCS.
//!
//! Mirrors the three verifier-side opening variants from
//! `binius-akita-bridge` and provides the prover channels that produce the
//! corresponding proofs.

#![warn(rustdoc::missing_crate_level_docs)]

pub mod claim_reduced;
pub mod full_open;
pub mod succinct;
