#![no_std]

//! Stateless Ed25519 verification utilities for Solana programs.
//!
//! This crate contains the reusable verifier and instruction-data helpers used
//! by `solana-ed25519-program`. It is intended for programs that want to verify
//! Ed25519 signatures directly without invoking the standalone verifier
//! program.
//!
//! Instruction data mirrors the native ed25519 precompile format:
//!
//! ```text
//! [num_signatures: u8]
//! [padding: u8]
//! [Ed25519SignatureOffsets x num_signatures]   (14 bytes each, little-endian)
//! [public key || signature || message ...]     (payload, order flexible)
//! ```
//!
//! The verifier accepts only current-instruction references
//! (`CURRENT_INSTRUCTION_INDEX`, `u16::MAX`) and performs ZIP-215 verification
//! with canonical `S`.

#[cfg(feature = "instruction")]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod instruction;
mod instruction_data;
mod scalar;
#[cfg(feature = "dev-context-only-utils")]
pub mod test_utils;
mod verifier;

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub use instruction::sign_message;
#[cfg(feature = "instruction")]
pub use instruction::{new_ed25519_instruction_with_signature, offsets_to_ed25519_instruction};
pub use instruction::{
    Ed25519SignatureOffsets, CURRENT_INSTRUCTION_INDEX, DATA_START, PUBKEY_SERIALIZED_SIZE,
    SIGNATURE_OFFSETS_SERIALIZED_SIZE, SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
};
pub use verifier::Ed25519Verifier;
