//! Parsing helpers for the ed25519 instruction data wire format.
//!
//! The on-wire layout matches the native ed25519 precompile:
//!
//! ```text
//! Byte 0             : num_signatures (u8)
//! Byte 1             : padding, ignored
//! Bytes 2 ...        : num_signatures x Ed25519SignatureOffsets (14 bytes each, LE)
//! Remaining bytes    : raw payload (public keys, signatures, messages)
//! ```
//!
//! The native precompile treats instruction index `u16::MAX` as "current
//! instruction". This SBF program receives only its own instruction data, so
//! all index fields must use that sentinel.

use {
    crate::{
        Ed25519SignatureOffsets, PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
        SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
    },
    solana_program_error::ProgramError,
};

/// Borrowed views into the raw signature fields for one entry.
pub(crate) struct SignatureFields<'a> {
    /// 64-byte ed25519 signature (`R || S`).
    pub(crate) signature: &'a [u8; SIGNATURE_SERIALIZED_SIZE],
    /// 32-byte compressed Edwards public key.
    pub(crate) public_key: &'a [u8; PUBKEY_SERIALIZED_SIZE],
    /// Raw message bytes that were signed.
    pub(crate) message: &'a [u8],
}

/// Parses a 14-byte `Ed25519SignatureOffsets` record from `input`.
fn unpack_signature_offsets(input: &[u8]) -> Result<Ed25519SignatureOffsets, ProgramError> {
    if input.len() != SIGNATURE_OFFSETS_SERIALIZED_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(Ed25519SignatureOffsets {
        signature_offset: decode_u16(input, 0)?,
        signature_instruction_index: decode_u16(input, 2)?,
        public_key_offset: decode_u16(input, 4)?,
        public_key_instruction_index: decode_u16(input, 6)?,
        message_data_offset: decode_u16(input, 8)?,
        message_data_size: decode_u16(input, 10)?,
        message_instruction_index: decode_u16(input, 12)?,
    })
}

fn decode_u16(input: &[u8], index: usize) -> Result<u16, ProgramError> {
    let bytes: [u8; 2] = input
        .get(index..index + 2)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Returns `input[offset .. offset + length]`, checking bounds on both ends.
fn get_instruction_data_slice(
    input: &[u8],
    offset: u16,
    length: usize,
) -> Result<&[u8], ProgramError> {
    let offset = usize::from(offset);
    let end = offset
        .checked_add(length)
        .ok_or(ProgramError::InvalidInstructionData)?;
    input
        .get(offset..end)
        .ok_or(ProgramError::InvalidInstructionData)
}

fn get_instruction_data_array<const N: usize>(
    input: &[u8],
    offset: u16,
) -> Result<&[u8; N], ProgramError> {
    get_instruction_data_slice(input, offset, N)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)
}

/// Extracts all signature fields for one entry from raw instruction data.
pub(crate) fn get_signature_fields<'a>(
    instruction_data: &'a [u8],
    offsets: &'a Ed25519SignatureOffsets,
) -> Result<SignatureFields<'a>, ProgramError> {
    Ok(SignatureFields {
        signature: get_instruction_data_array(instruction_data, offsets.signature_offset)?,
        public_key: get_instruction_data_array(instruction_data, offsets.public_key_offset)?,
        message: get_instruction_data_slice(
            instruction_data,
            offsets.message_data_offset,
            usize::from(offsets.message_data_size),
        )?,
    })
}

/// Parses the leading `num_signatures` byte and returns an iterator that yields
/// one `Ed25519SignatureOffsets` per entry.
///
/// `num_signatures == 0` is valid only when the buffer is exactly the 2-byte
/// header. The padding byte is intentionally ignored for nonzero counts,
/// matching the native precompile.
pub(crate) fn iter_signature_offsets(
    input: &[u8],
) -> Result<impl Iterator<Item = Result<Ed25519SignatureOffsets, ProgramError>> + '_, ProgramError>
{
    if input.len() < SIGNATURE_OFFSETS_START {
        return Err(ProgramError::InvalidInstructionData);
    }

    let num_signatures = input[0];
    if num_signatures == 0 {
        if input.len() == SIGNATURE_OFFSETS_START {
            return Ok(input[SIGNATURE_OFFSETS_START..SIGNATURE_OFFSETS_START]
                .chunks_exact(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
                .map(unpack_signature_offsets));
        }

        return Err(ProgramError::InvalidInstructionData);
    }

    let all_offsets_size = SIGNATURE_OFFSETS_SERIALIZED_SIZE
        .checked_mul(usize::from(num_signatures))
        .ok_or(ProgramError::InvalidInstructionData)?;
    let all_offsets_end = SIGNATURE_OFFSETS_START
        .checked_add(all_offsets_size)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let all_offsets = input
        .get(SIGNATURE_OFFSETS_START..all_offsets_end)
        .ok_or(ProgramError::InvalidInstructionData)?;

    Ok(all_offsets
        .chunks_exact(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .map(unpack_signature_offsets))
}
