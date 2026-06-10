use {
    crate::{
        instruction::CURRENT_INSTRUCTION_INDEX,
        instruction_data::{get_signature_fields, iter_signature_offsets, SignatureFields},
        scalar, Ed25519SignatureOffsets,
    },
    solana_account_info::AccountInfo,
    solana_curve25519::{
        edwards::{
            multiply_edwards, multiscalar_multiply_edwards, subtract_edwards, PodEdwardsPoint,
        },
        scalar::PodScalar,
    },
    solana_program_entrypoint::ProgramResult,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

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

/// Parses `instruction_data` and verifies every ed25519 signature it
/// describes, returning an error on the first failure.
pub(crate) fn verify_ed25519_instruction(instruction_data: &[u8]) -> ProgramResult {
    for offsets in iter_signature_offsets(instruction_data)? {
        verify_signature(instruction_data, &offsets?)?;
    }

    Ok(())
}

/// Program entry point.
///
/// Expects no accounts and instruction data in the ed25519 precompile
/// format. Returns [`ProgramError::InvalidArgument`] if any accounts are
/// provided, or propagates errors from signature verification.
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

/// Returns `true` when every offset field references the current instruction.
fn references_current_instruction(offsets: &Ed25519SignatureOffsets) -> bool {
    offsets.signature_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.public_key_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index == CURRENT_INSTRUCTION_INDEX
}

/// Validates a single signature entry described by `offsets`.
fn verify_signature(instruction_data: &[u8], offsets: &Ed25519SignatureOffsets) -> ProgramResult {
    if !references_current_instruction(offsets) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let fields = get_signature_fields(instruction_data, offsets)?;
    verify_signature_fields(&fields)
}

/// Performs ZIP-215 Ed25519 verification for one entry.
///
/// Uses the cofactored equation `[8](S*B - H(R || A || M)*A) == [8]R`.
/// The combined multiply-add minus `R` is performed first, then multiplied by
/// 8 and compared with the identity, matching the ed25519-zebra batch
/// verification shape.
/// Canonical `S` is still required.
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
    let public_key_point = PodEdwardsPoint(*fields.public_key);

    let challenge = compute_challenge(r_bytes, fields.public_key, fields.message);
    let minus_challenge = scalar::negate(&challenge);
    let lhs = multiscalar_multiply_edwards(
        &[PodScalar(*s_bytes), PodScalar(minus_challenge)],
        &[ED25519_BASEPOINT_COMPRESSED, public_key_point],
    )
    .ok_or(ProgramError::InvalidArgument)?;
    let difference = subtract_edwards(&lhs, &r_point).ok_or(ProgramError::InvalidArgument)?;
    let difference_cofactored =
        multiply_edwards(&EIGHT_SCALAR, &difference).ok_or(ProgramError::InvalidArgument)?;

    if difference_cofactored != EDWARDS_IDENTITY_COMPRESSED {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

fn compute_challenge(signature_r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]).to_bytes();
    scalar::reduce_wide(&digest)
}
