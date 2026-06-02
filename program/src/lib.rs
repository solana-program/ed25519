//! Solana program that re-verifies Ed25519 signatures on-chain.
//!
//! The native [`ed25519` precompile] validates signatures at the transaction
//! level. This program performs the same strict signature check from SBF so
//! other programs can CPI into it and trust the explicit pass/fail result.
//!
//! # Instruction format
//!
//! The instruction data mirrors the layout consumed by the native ed25519
//! precompile:
//!
//! ```text
//! [num_signatures: u8]
//! [padding: u8]
//! [Ed25519SignatureOffsets x num_signatures]   (14 bytes each, little-endian)
//! [public key || signature || message ...]     (payload, order flexible)
//! ```
//!
//! All data references inside `Ed25519SignatureOffsets` must use the native
//! "current instruction" sentinel (`u16::MAX`); cross-instruction references
//! are rejected.
//!
//! [`ed25519` precompile]: https://docs.solanalabs.com/runtime/programs#ed25519-program

use {
    instruction_data::{get_signature_fields, iter_signature_offsets, SignatureFields},
    solana_account_info::AccountInfo,
    solana_curve25519::{
        edwards::{multiply_edwards, multiscalar_multiply_edwards, PodEdwardsPoint},
        scalar::PodScalar,
    },
    solana_program_entrypoint::ProgramResult,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

mod instruction;
mod instruction_data;
mod scalar;

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub use instruction::sign_message;
#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
pub use instruction::{
    new_ed25519_instruction_with_signature, offsets_to_ed25519_instruction,
    try_new_ed25519_instruction_with_signature, try_offsets_to_ed25519_instruction,
};
pub use instruction::{
    Ed25519SignatureOffsets, CURRENT_INSTRUCTION_INDEX, DATA_START, PUBKEY_SERIALIZED_SIZE,
    SIGNATURE_OFFSETS_SERIALIZED_SIZE, SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
};

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

#[cfg(target_os = "solana")]
#[no_mangle]
pub extern "C" fn abort() -> ! {
    loop {}
}

const ED25519_BASEPOINT_COMPRESSED: PodEdwardsPoint = PodEdwardsPoint([
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]);
const EDWARDS_IDENTITY_COMPRESSED: PodEdwardsPoint = PodEdwardsPoint([
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const EIGHT_SCALAR: PodScalar = PodScalar([
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

/// Returns `true` when every offset field references the current instruction.
fn references_current_instruction(offsets: &Ed25519SignatureOffsets) -> bool {
    offsets.signature_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.public_key_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index == CURRENT_INSTRUCTION_INDEX
}

/// Parses `instruction_data` and verifies every ed25519 signature it describes.
fn verify_ed25519_instruction(instruction_data: &[u8]) -> ProgramResult {
    for offsets in iter_signature_offsets(instruction_data)? {
        verify_signature(instruction_data, &offsets?)?;
    }

    Ok(())
}

/// Program entry point.
///
/// Expects no accounts and instruction data in the ed25519 precompile format.
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if !accounts.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_ed25519_instruction(instruction_data)
}

/// Validates a single signature entry described by `offsets`.
fn verify_signature(instruction_data: &[u8], offsets: &Ed25519SignatureOffsets) -> ProgramResult {
    if !references_current_instruction(offsets) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let fields = get_signature_fields(instruction_data, offsets)?;
    verify_signature_fields(&fields)
}

/// Performs strict Ed25519 verification for one entry.
///
/// This matches `ed25519_dalek::VerifyingKey::verify_strict`:
/// canonical `S`, non-small-order `R`, non-small-order public key `A`, and
/// `S*B - H(R || A || M)*A == R`.
fn verify_signature_fields(fields: &SignatureFields) -> ProgramResult {
    let r_bytes: &[u8; 32] = fields.signature[..32]
        .try_into()
        .map_err(|_| ProgramError::InvalidArgument)?;
    let s_bytes: &[u8; 32] = fields.signature[32..]
        .try_into()
        .map_err(|_| ProgramError::InvalidArgument)?;
    if !scalar::is_canonical_scalar(s_bytes) {
        return Err(ProgramError::InvalidArgument);
    }

    let r_point = PodEdwardsPoint(*r_bytes);
    reject_small_order(&r_point)?;

    let public_key_point = PodEdwardsPoint(*fields.public_key);
    reject_small_order(&public_key_point)?;

    let challenge = compute_challenge(r_bytes, fields.public_key, fields.message);
    let minus_challenge = scalar::negate(&challenge);
    let expected_r = multiscalar_multiply_edwards(
        &[PodScalar(*s_bytes), PodScalar(minus_challenge)],
        &[ED25519_BASEPOINT_COMPRESSED, public_key_point],
    )
    .ok_or(ProgramError::InvalidArgument)?;

    if expected_r.0 != r_point.0 {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

fn reject_small_order(point: &PodEdwardsPoint) -> ProgramResult {
    let cofactored = multiply_edwards(&EIGHT_SCALAR, point).ok_or(ProgramError::InvalidArgument)?;
    if cofactored == EDWARDS_IDENTITY_COMPRESSED {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

fn compute_challenge(signature_r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]).to_bytes();
    scalar::reduce_wide(&digest)
}
