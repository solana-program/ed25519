extern crate alloc;

use {
    crate::{VerificationVariant, PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
    alloc::{vec, vec::Vec},
    solana_instruction::Instruction,
    solana_pubkey::Pubkey,
};

/// Constructs an on-chain instruction to invoke `solana-ed25519-program`.
///
/// The instruction data is `variant || public_key || signature || message`,
/// where `variant` is the single selector byte from [`VerificationVariant`] that
/// chooses which verification preset the program applies.
pub fn ed25519_verify_instruction(
    program_id: &Pubkey,
    variant: VerificationVariant,
    public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    message: &[u8],
) -> Instruction {
    let mut data =
        Vec::with_capacity(1 + PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE + message.len());
    data.push(variant.to_byte());
    data.extend_from_slice(public_key);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction::new_with_bytes(*program_id, &data, vec![])
}
