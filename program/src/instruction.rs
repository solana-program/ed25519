//! Ed25519 instruction layout and construction helpers.
// This was adapted from `solana-sdk/ed25519_program`.

#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use solana_instruction::Instruction;
#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use solana_program_error::ProgramError;

pub const PUBKEY_SERIALIZED_SIZE: usize = 32;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
/// The second header byte is padding; the native precompile ignores it.
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;
pub const CURRENT_INSTRUCTION_INDEX: u16 = u16::MAX;

/// Offsets of signature data within an ed25519 instruction.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ed25519SignatureOffsets {
    /// Offset to 64-byte ed25519 signature.
    pub signature_offset: u16,
    /// Instruction index that contains the signature, or `u16::MAX` for this instruction.
    pub signature_instruction_index: u16,
    /// Offset to 32-byte public key.
    pub public_key_offset: u16,
    /// Instruction index that contains the public key, or `u16::MAX` for this instruction.
    pub public_key_instruction_index: u16,
    /// Offset to start of message data.
    pub message_data_offset: u16,
    /// Size of message data in bytes.
    pub message_data_size: u16,
    /// Instruction index that contains the message, or `u16::MAX` for this instruction.
    pub message_instruction_index: u16,
}

/// Signs a message from the given private key bytes.
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn sign_message(
    priv_key_bytes: &[u8; PUBKEY_SERIALIZED_SIZE],
    message: &[u8],
) -> [u8; SIGNATURE_SERIALIZED_SIZE] {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(priv_key_bytes);
    signing_key.sign(message).to_bytes()
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
/// Encode just the signature offsets in a single ed25519 instruction.
///
/// This preserves the upstream SDK helper API by returning [`Instruction`]
/// directly. For fallible construction with explicit overflow errors, use
/// [`try_offsets_to_ed25519_instruction`].
///
/// # Panics
///
/// Panics if `offsets.len()` cannot fit in the native program's one-byte
/// signature count field.
pub fn offsets_to_ed25519_instruction(offsets: &[Ed25519SignatureOffsets]) -> Instruction {
    try_offsets_to_ed25519_instruction(offsets).expect("invalid ed25519 instruction offsets")
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
/// Encode just the signature offsets in a single ed25519 instruction with
/// checked inputs.
///
/// Returns an error if `offsets.len()` cannot fit in the native program's
/// one-byte signature count field.
pub fn try_offsets_to_ed25519_instruction(
    offsets: &[Ed25519SignatureOffsets],
) -> Result<Instruction, ProgramError> {
    let num_signatures =
        u8::try_from(offsets.len()).map_err(|_| ProgramError::InvalidInstructionData)?;
    let offsets_len = SIGNATURE_OFFSETS_SERIALIZED_SIZE
        .checked_mul(offsets.len())
        .ok_or(ProgramError::InvalidInstructionData)?;
    let instruction_data_len = SIGNATURE_OFFSETS_START
        .checked_add(offsets_len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let mut instruction_data = vec![0; instruction_data_len];
    instruction_data[0] = num_signatures;

    for (index, offsets) in offsets.iter().enumerate() {
        let start = SIGNATURE_OFFSETS_START + index * SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        let end = start + SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        serialize_signature_offsets(&mut instruction_data[start..end], offsets)?;
    }

    Ok(Instruction {
        program_id: solana_sdk_ids::ed25519_program::id(),
        accounts: vec![],
        data: instruction_data,
    })
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
/// Builds a single-signature ed25519 instruction.
///
/// This preserves the upstream SDK helper API by returning [`Instruction`]
/// directly. For fallible construction with explicit overflow errors, use
/// [`try_new_ed25519_instruction_with_signature`].
///
/// # Panics
///
/// Panics if the message length or any offset cannot be represented in the
/// 16-bit wire fields.
pub fn new_ed25519_instruction_with_signature(
    message: &[u8],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    pubkey: &[u8; PUBKEY_SERIALIZED_SIZE],
) -> Instruction {
    try_new_ed25519_instruction_with_signature(message, signature, pubkey)
        .expect("invalid ed25519 instruction inputs")
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
/// Builds a single-signature ed25519 instruction with checked inputs.
///
/// Returns an error if the message length or any offset cannot be represented
/// in the 16-bit wire fields.
pub fn try_new_ed25519_instruction_with_signature(
    message: &[u8],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    pubkey: &[u8; PUBKEY_SERIALIZED_SIZE],
) -> Result<Instruction, ProgramError> {
    let public_key_offset = DATA_START;
    let signature_offset = public_key_offset
        .checked_add(pubkey.len())
        .ok_or(ProgramError::InvalidInstructionData)?;
    let message_data_offset = signature_offset
        .checked_add(signature.len())
        .ok_or(ProgramError::InvalidInstructionData)?;
    let message_data_end = message_data_offset
        .checked_add(message.len())
        .ok_or(ProgramError::InvalidInstructionData)?;

    let public_key_offset =
        u16::try_from(public_key_offset).map_err(|_| ProgramError::InvalidInstructionData)?;
    let signature_offset =
        u16::try_from(signature_offset).map_err(|_| ProgramError::InvalidInstructionData)?;
    let message_data_offset =
        u16::try_from(message_data_offset).map_err(|_| ProgramError::InvalidInstructionData)?;
    let message_data_size =
        u16::try_from(message.len()).map_err(|_| ProgramError::InvalidInstructionData)?;

    let mut instruction_data = vec![0; message_data_end];
    instruction_data[0] = 1;

    let offsets = Ed25519SignatureOffsets {
        signature_offset,
        signature_instruction_index: CURRENT_INSTRUCTION_INDEX,
        public_key_offset,
        public_key_instruction_index: CURRENT_INSTRUCTION_INDEX,
        message_data_offset,
        message_data_size,
        message_instruction_index: CURRENT_INSTRUCTION_INDEX,
    };
    serialize_signature_offsets(
        &mut instruction_data[SIGNATURE_OFFSETS_START..DATA_START],
        &offsets,
    )?;

    let public_key_start = usize::from(public_key_offset);
    let public_key_end = public_key_start + pubkey.len();
    instruction_data[public_key_start..public_key_end].copy_from_slice(pubkey);

    let signature_start = usize::from(signature_offset);
    let signature_end = signature_start + signature.len();
    instruction_data[signature_start..signature_end].copy_from_slice(signature);

    let message_data_start = usize::from(message_data_offset);
    instruction_data[message_data_start..message_data_end].copy_from_slice(message);

    Ok(Instruction {
        program_id: solana_sdk_ids::ed25519_program::id(),
        accounts: vec![],
        data: instruction_data,
    })
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
fn serialize_signature_offsets(
    output: &mut [u8],
    offsets: &Ed25519SignatureOffsets,
) -> Result<(), ProgramError> {
    if output.len() != SIGNATURE_OFFSETS_SERIALIZED_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }

    output[0..2].copy_from_slice(&offsets.signature_offset.to_le_bytes());
    output[2..4].copy_from_slice(&offsets.signature_instruction_index.to_le_bytes());
    output[4..6].copy_from_slice(&offsets.public_key_offset.to_le_bytes());
    output[6..8].copy_from_slice(&offsets.public_key_instruction_index.to_le_bytes());
    output[8..10].copy_from_slice(&offsets.message_data_offset.to_le_bytes());
    output[10..12].copy_from_slice(&offsets.message_data_size.to_le_bytes());
    output[12..14].copy_from_slice(&offsets.message_instruction_index.to_le_bytes());

    Ok(())
}

#[cfg(all(
    test,
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
mod tests {
    use super::*;

    fn read_first_offsets(input: &[u8]) -> Ed25519SignatureOffsets {
        Ed25519SignatureOffsets {
            signature_offset: u16::from_le_bytes(input[2..4].try_into().unwrap()),
            signature_instruction_index: u16::from_le_bytes(input[4..6].try_into().unwrap()),
            public_key_offset: u16::from_le_bytes(input[6..8].try_into().unwrap()),
            public_key_instruction_index: u16::from_le_bytes(input[8..10].try_into().unwrap()),
            message_data_offset: u16::from_le_bytes(input[10..12].try_into().unwrap()),
            message_data_size: u16::from_le_bytes(input[12..14].try_into().unwrap()),
            message_instruction_index: u16::from_le_bytes(input[14..16].try_into().unwrap()),
        }
    }

    #[test]
    fn test_instruction_builder_keeps_legacy_return_type() {
        let signature = [1; SIGNATURE_SERIALIZED_SIZE];
        let pubkey = [2; PUBKEY_SERIALIZED_SIZE];

        let instruction = new_ed25519_instruction_with_signature(b"message", &signature, &pubkey);
        let offsets = read_first_offsets(&instruction.data);

        assert_eq!(instruction.accounts.len(), 0);
        assert_eq!(instruction.data[0], 1);
        assert_eq!(instruction.data[1], 0);
        assert_eq!(
            offsets.signature_instruction_index,
            CURRENT_INSTRUCTION_INDEX
        );
        assert_eq!(
            offsets.public_key_instruction_index,
            CURRENT_INSTRUCTION_INDEX
        );
        assert_eq!(offsets.message_instruction_index, CURRENT_INSTRUCTION_INDEX);
    }

    #[test]
    fn test_instruction_builder_rejects_oversized_messages() {
        let signature = [1; SIGNATURE_SERIALIZED_SIZE];
        let pubkey = [2; PUBKEY_SERIALIZED_SIZE];
        let max_message = vec![3; u16::MAX as usize];
        let oversized_message = vec![3; u16::MAX as usize + 1];

        assert!(
            try_new_ed25519_instruction_with_signature(&max_message, &signature, &pubkey).is_ok()
        );
        assert!(try_new_ed25519_instruction_with_signature(
            &oversized_message,
            &signature,
            &pubkey
        )
        .is_err());
    }

    #[test]
    fn test_offsets_builder_rejects_too_many_signatures() {
        let offsets = vec![Ed25519SignatureOffsets::default(); u8::MAX as usize + 1];

        assert!(try_offsets_to_ed25519_instruction(&offsets).is_err());
    }
}
