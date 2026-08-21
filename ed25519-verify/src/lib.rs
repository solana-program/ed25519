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
pub mod instruction;

#[cfg(feature = "instruction")]
pub use instruction::{id, verify, ID};

#[cfg(feature = "verify")]
mod config;
#[cfg(feature = "verify")]
pub mod constants;
#[cfg(feature = "verify")]
mod error;
#[cfg(feature = "verify")]
mod points;
#[cfg(feature = "verify")]
mod scalar;
#[cfg(feature = "verify")]
mod verifier;

#[cfg(feature = "verify")]
pub use config::VerificationCriteria;
#[cfg(feature = "verify")]
pub use error::Ed25519VerifyError;
#[cfg(feature = "verify")]
pub use verifier::Ed25519Verifier;
