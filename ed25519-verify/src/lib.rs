#![no_std]

//! Stateless Ed25519 verification utilities for Solana programs.
//!
//! This crate contains the reusable verifier used by
//! `solana-ed25519-program`. Programs can also depend on it directly to verify
//! Ed25519 signatures without invoking the standalone verifier program.
//!
//! By default the verifier performs ZIP-215 verification with canonical `S`.
//! The variant can be selected via [`VerificationCriteria`] and
//! [`Ed25519Verifier::with_criteria`].

#[cfg(feature = "instruction")]
extern crate alloc;

mod config;
#[cfg(feature = "instruction")]
pub mod program;
mod scalar;
mod verifier;

pub use config::VerificationCriteria;
#[cfg(feature = "instruction")]
pub use program::ed25519_verify_instruction;
pub use verifier::Ed25519Verifier;

pub const PUBKEY_SERIALIZED_SIZE: usize = 32;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
