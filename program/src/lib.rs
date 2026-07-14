#![no_std]

//! Pinocchio SBF wrapper for [`solana_ed25519_verify`].

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
extern crate std;

use {
    pinocchio::{
        entrypoint::InstructionContext, error::ProgramError, lazy_program_entrypoint, ProgramResult,
    },
    solana_ed25519_verify::{
        Ed25519Verifier, VerificationCriteria, VerificationVariant, PUBKEY_SERIALIZED_SIZE,
        SIGNATURE_SERIALIZED_SIZE,
    },
};

const VARIANT_OFFSET: usize = 0;
const PUBKEY_OFFSET: usize = 1;
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
/// `variant || public_key || signature || message`, where `variant` is the
/// [`VerificationVariant`] selector byte.
pub fn process_instruction(context: InstructionContext) -> ProgramResult {
    if context.remaining() > 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let instruction_data = context.instruction_data()?;
    if instruction_data.len() < MESSAGE_OFFSET {
        return Err(ProgramError::InvalidInstructionData);
    }

    let variant = VerificationVariant::from_byte(instruction_data[VARIANT_OFFSET])
        .ok_or(ProgramError::InvalidInstructionData)?;

    // Select the verifier instance for the requested preset. The default preset
    // is available directly via `new()`; other presets are built explicitly from
    // their `VerificationCriteria`.
    let verifier = match variant {
        VerificationVariant::Zip215 => Ed25519Verifier::new(),
        VerificationVariant::DalekVerifyStrict => {
            Ed25519Verifier::with_criteria(VerificationCriteria::dalek_verify_strict())
        }
    };

    let public_key = instruction_data[PUBKEY_OFFSET..SIGNATURE_OFFSET]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let signature = instruction_data[SIGNATURE_OFFSET..MESSAGE_OFFSET]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let message = &instruction_data[MESSAGE_OFFSET..];

    verifier.verify_signature(signature, public_key, message)
}
