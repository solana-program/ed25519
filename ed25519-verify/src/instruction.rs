extern crate alloc;

use {
    alloc::{vec, vec::Vec},
    solana_address::{declare_id, Address},
    solana_instruction::Instruction,
};

declare_id!("ed2DNnfPh19L66ahBPivbPkf5H1nW82zWTYGMjuQk9L");

/// Constructs an on-chain instruction to invoke `solana-ed25519-program`.
///
/// The instruction data is `public_key || signature || message`. The program
/// verifies the signature under the [ZIP-215] criteria.
///
/// [ZIP-215]: crate::VerificationCriteria::zip215
pub fn verify(
    program_id: &Address,
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Instruction {
    // 32 (public key) + 64 (signature) = 96 bytes ahead of the message.
    let mut data = Vec::with_capacity(96 + message.len());
    data.extend_from_slice(public_key);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction::new_with_bytes(*program_id, &data, vec![])
}
