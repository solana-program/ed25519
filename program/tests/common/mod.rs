use {
    ed25519_dalek::{Signer, SigningKey},
    solana_ed25519_program::{
        Ed25519SignatureOffsets, CURRENT_INSTRUCTION_INDEX, DATA_START, PUBKEY_SERIALIZED_SIZE,
        SIGNATURE_OFFSETS_SERIALIZED_SIZE, SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
    },
};

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
pub(crate) fn signed_instruction(messages: &[&[u8]]) -> Vec<u8> {
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

        let offsets = Ed25519SignatureOffsets {
            signature_offset: u16::try_from(signature_offset).unwrap(),
            signature_instruction_index: CURRENT_INSTRUCTION_INDEX,
            public_key_offset: u16::try_from(public_key_offset).unwrap(),
            public_key_instruction_index: CURRENT_INSTRUCTION_INDEX,
            message_data_offset: u16::try_from(message_data_offset).unwrap(),
            message_data_size: u16::try_from(payload.message.len()).unwrap(),
            message_instruction_index: CURRENT_INSTRUCTION_INDEX,
        };
        write_offsets(
            &mut instruction[SIGNATURE_OFFSETS_START + index * SIGNATURE_OFFSETS_SERIALIZED_SIZE
                ..SIGNATURE_OFFSETS_START + (index + 1) * SIGNATURE_OFFSETS_SERIALIZED_SIZE],
            &offsets,
        );
    }

    instruction
}

/// Parses and returns the first `Ed25519SignatureOffsets` entry from `instruction`.
pub(crate) fn first_offsets(instruction: &[u8]) -> Ed25519SignatureOffsets {
    read_offsets(&instruction[SIGNATURE_OFFSETS_START..DATA_START])
}

/// Deserializes the 14-byte little-endian wire format.
fn read_offsets(input: &[u8]) -> Ed25519SignatureOffsets {
    Ed25519SignatureOffsets {
        signature_offset: u16::from_le_bytes(input[0..2].try_into().unwrap()),
        signature_instruction_index: u16::from_le_bytes(input[2..4].try_into().unwrap()),
        public_key_offset: u16::from_le_bytes(input[4..6].try_into().unwrap()),
        public_key_instruction_index: u16::from_le_bytes(input[6..8].try_into().unwrap()),
        message_data_offset: u16::from_le_bytes(input[8..10].try_into().unwrap()),
        message_data_size: u16::from_le_bytes(input[10..12].try_into().unwrap()),
        message_instruction_index: u16::from_le_bytes(input[12..14].try_into().unwrap()),
    }
}

/// Serializes `offsets` into the 14-byte little-endian wire format in `output`.
pub(crate) fn write_offsets(output: &mut [u8], offsets: &Ed25519SignatureOffsets) {
    output[0..2].copy_from_slice(&offsets.signature_offset.to_le_bytes());
    output[2..4].copy_from_slice(&offsets.signature_instruction_index.to_le_bytes());
    output[4..6].copy_from_slice(&offsets.public_key_offset.to_le_bytes());
    output[6..8].copy_from_slice(&offsets.public_key_instruction_index.to_le_bytes());
    output[8..10].copy_from_slice(&offsets.message_data_offset.to_le_bytes());
    output[10..12].copy_from_slice(&offsets.message_data_size.to_le_bytes());
    output[12..14].copy_from_slice(&offsets.message_instruction_index.to_le_bytes());
}
