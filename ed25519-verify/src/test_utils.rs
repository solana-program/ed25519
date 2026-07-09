//! Test-only ed25519 instruction builders.
//!
//! Shared by this crate's own integration tests and by `solana-ed25519-program`'s,
//! so the wire-format builders live in one place instead of being duplicated
//! per crate. Gated behind `dev-context-only-utils` so none of this ships in
//! on-chain builds.

use {
    crate::{
        instruction::serialize_signature_offsets, instruction_data::unpack_signature_offsets,
        new_ed25519_instruction_with_signature, verifier::EDWARDS_IDENTITY_COMPRESSED_BYTES,
        SignatureOffsets, DATA_START, PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
        SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
    },
    alloc::{vec, vec::Vec},
    ed25519_dalek::{Signer, SigningKey},
    solana_pubkey::Pubkey,
};

pub const EDWARDS_IDENTITY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] =
    EDWARDS_IDENTITY_COMPRESSED_BYTES;
pub const SMALL_ORDER_PUBLIC_KEY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Holds all cryptographic material for a single signed message.
struct SignedPayload<'a> {
    signature: [u8; SIGNATURE_SERIALIZED_SIZE],
    pubkey: [u8; PUBKEY_SERIALIZED_SIZE],
    message: &'a [u8],
}

/// Signs `message` with `signing_key`.
fn signed_payload<'a>(signing_key: &SigningKey, message: &'a [u8]) -> SignedPayload<'a> {
    SignedPayload {
        signature: signing_key.sign(message).to_bytes(),
        pubkey: signing_key.verifying_key().to_bytes(),
        message,
    }
}

/// Builds a valid ed25519 instruction buffer containing one entry per message,
/// all signed by a fixed test key.
pub fn signed_instruction(messages: &[&[u8]]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let payloads = messages
        .iter()
        .map(|message| signed_payload(&signing_key, message))
        .collect::<Vec<_>>();
    let offsets_len = payloads.len() * SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    let mut instruction = vec![0; SIGNATURE_OFFSETS_START + offsets_len];
    instruction[0] = payloads.len() as u8;

    for (index, payload) in payloads.iter().enumerate() {
        let public_key_offset = instruction.len();
        instruction.extend_from_slice(&payload.pubkey);

        let signature_offset = instruction.len();
        instruction.extend_from_slice(&payload.signature);

        let message_data_offset = instruction.len();
        instruction.extend_from_slice(payload.message);

        let offsets = SignatureOffsets {
            signature_offset: u16::try_from(signature_offset).unwrap(),
            public_key_offset: u16::try_from(public_key_offset).unwrap(),
            message_data_offset: u16::try_from(message_data_offset).unwrap(),
            message_data_size: u16::try_from(payload.message.len()).unwrap(),
        };
        write_offsets(
            &mut instruction[SIGNATURE_OFFSETS_START + index * SIGNATURE_OFFSETS_SERIALIZED_SIZE
                ..SIGNATURE_OFFSETS_START + (index + 1) * SIGNATURE_OFFSETS_SERIALIZED_SIZE],
            &offsets,
        );
    }

    instruction
}

/// Builds a single-entry instruction from caller-provided signature material.
pub fn instruction_with_signature(
    message: &[u8],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    pubkey: &[u8; PUBKEY_SERIALIZED_SIZE],
) -> Vec<u8> {
    new_ed25519_instruction_with_signature(Pubkey::default(), message, signature, pubkey)
        .expect("valid test inputs")
        .data
}

/// Parses and returns the first `SignatureOffsets` entry from `instruction`.
pub fn first_offsets(instruction: &[u8]) -> SignatureOffsets {
    unpack_signature_offsets(&instruction[SIGNATURE_OFFSETS_START..DATA_START])
        .expect("well-formed test instruction")
}

/// Serializes `offsets` into the 8-byte little-endian wire format in `output`.
pub fn write_offsets(output: &mut [u8], offsets: &SignatureOffsets) {
    serialize_signature_offsets(output, offsets).expect("output is exactly 8 bytes");
}
