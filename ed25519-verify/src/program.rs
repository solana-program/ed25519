extern crate alloc;

use {
    crate::{PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
    alloc::{vec, vec::Vec},
    solana_instruction::Instruction,
    solana_pubkey::Pubkey,
};

/// Constructs an on-chain instruction to invoke `solana-ed25519-program`.
///
/// The instruction data is `public_key || signature || message`. The program
/// verifies the signature under the [ZIP-215] criteria.
///
/// [ZIP-215]: crate::VerificationCriteria::zip215
pub fn ed25519_verify_instruction(
    program_id: &Pubkey,
    public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    message: &[u8],
) -> Instruction {
    let mut data =
        Vec::with_capacity(PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE + message.len());
    data.extend_from_slice(public_key);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction::new_with_bytes(*program_id, &data, vec![])
}
