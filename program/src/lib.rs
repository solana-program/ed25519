#![no_std]

//! Pinocchio SBF wrapper for [`solana_ed25519_verify`].

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
extern crate std;

use {
    pinocchio::{
        entrypoint::InstructionContext, error::ProgramError, lazy_program_entrypoint, ProgramResult,
    },
    solana_ed25519_verify::{Ed25519Verifier, PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
};

const PUBKEY_OFFSET: usize = 0;
const SIGNATURE_OFFSET: usize = PUBKEY_OFFSET + PUBKEY_SERIALIZED_SIZE;
const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SERIALIZED_SIZE;

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::no_allocator!();
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::nostd_panic_handler!();

lazy_program_entrypoint!(process_instruction);

/// Program entry point.
///
/// Expects no accounts and instruction data encoded as
/// `public_key || signature || message`. The signature is verified under the
/// [ZIP-215] criteria ([`Ed25519Verifier::new`]).
///
/// Programs needing a different verification variant should depend on
/// `solana-ed25519-verify` directly and build an [`Ed25519Verifier`] from the
/// desired `VerificationCriteria`.
///
/// [ZIP-215]: solana_ed25519_verify::VerificationCriteria::zip215
pub fn process_instruction(context: InstructionContext) -> ProgramResult {
    if context.remaining() > 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let instruction_data = context.instruction_data()?;
    if instruction_data.len() < MESSAGE_OFFSET {
        return Err(ProgramError::InvalidInstructionData);
    }

    let public_key = instruction_data[PUBKEY_OFFSET..SIGNATURE_OFFSET]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let signature = instruction_data[SIGNATURE_OFFSET..MESSAGE_OFFSET]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let message = &instruction_data[MESSAGE_OFFSET..];

    Ed25519Verifier::new().verify_signature(signature, public_key, message)
}
