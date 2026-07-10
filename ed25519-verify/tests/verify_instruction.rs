use {
    ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey},
    solana_ed25519_verify::{
        ed25519_verify_instruction, Ed25519Verifier, PUBKEY_SERIALIZED_SIZE,
        SIGNATURE_SERIALIZED_SIZE,
    },
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

const EDWARDS_IDENTITY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const SMALL_ORDER_PUBLIC_KEY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

fn signed_payload(
    message: &[u8],
) -> (
    [u8; SIGNATURE_SERIALIZED_SIZE],
    [u8; PUBKEY_SERIALIZED_SIZE],
) {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    (
        signing_key.sign(message).to_bytes(),
        signing_key.verifying_key().to_bytes(),
    )
}

fn verify_signature(
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
    message: &[u8],
) -> Result<(), ProgramError> {
    Ed25519Verifier::new().verify_signature(signature, public_key, message)
}

#[test]
fn verifies_matching_signature() {
    let message = b"hello ed25519";
    let (signature, public_key) = signed_payload(message);

    assert_eq!(verify_signature(&signature, &public_key, message), Ok(()));
}

#[test]
fn constructs_program_instruction_with_direct_layout() {
    let program_id = Pubkey::new_unique();
    let message = b"hello ed25519";
    let (signature, public_key) = signed_payload(message);

    let instruction = ed25519_verify_instruction(&program_id, &public_key, &signature, message);

    assert_eq!(instruction.program_id, program_id);
    assert!(instruction.accounts.is_empty());
    assert_eq!(&instruction.data[..PUBKEY_SERIALIZED_SIZE], &public_key);
    assert_eq!(
        &instruction.data
            [PUBKEY_SERIALIZED_SIZE..PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE],
        &signature
    );
    assert_eq!(
        &instruction.data[PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE..],
        message
    );
}

#[test]
fn accepts_zip215_small_order_public_key_vector_rejected_by_strict_verification() {
    let message = b"zip215 low-order public key vector";
    let mut signature = [0; SIGNATURE_SERIALIZED_SIZE];
    signature[..EDWARDS_IDENTITY_COMPRESSED.len()].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    let dalek_key = VerifyingKey::from_bytes(&SMALL_ORDER_PUBLIC_KEY_COMPRESSED)
        .expect("small-order key decompresses");
    let dalek_signature = Signature::from_bytes(&signature);
    assert!(dalek_key.verify_strict(message, &dalek_signature).is_err());

    assert_eq!(
        verify_signature(&signature, &SMALL_ORDER_PUBLIC_KEY_COMPRESSED, message),
        Ok(())
    );
}

#[test]
fn rejects_wrong_public_key() {
    let message = b"hello ed25519";
    let (signature, mut public_key) = signed_payload(message);
    public_key[0] ^= 1;

    assert_eq!(
        verify_signature(&signature, &public_key, message),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_corrupted_signature() {
    let message = b"hello ed25519";
    let (mut signature, public_key) = signed_payload(message);
    signature[0] ^= 1;

    assert_eq!(
        verify_signature(&signature, &public_key, message),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_tampered_message() {
    let message = b"hello ed25519";
    let (signature, public_key) = signed_payload(message);

    assert_eq!(
        verify_signature(&signature, &public_key, b"hello ed25518"),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_non_canonical_s_scalar() {
    let message = b"hello ed25519";
    let (mut signature, public_key) = signed_payload(message);
    signature[32..64].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ]);

    assert_eq!(
        verify_signature(&signature, &public_key, message),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_low_order_r() {
    let message = b"hello ed25519";
    let (mut signature, public_key) = signed_payload(message);
    signature[..32].copy_from_slice(&[
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);

    assert_eq!(
        verify_signature(&signature, &public_key, message),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_low_order_public_key() {
    let message = b"hello ed25519";
    let (signature, _) = signed_payload(message);

    assert_eq!(
        verify_signature(&signature, &SMALL_ORDER_PUBLIC_KEY_COMPRESSED, message),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_invalid_public_key() {
    let message = b"hello ed25519";
    let (signature, _) = signed_payload(message);

    assert_eq!(
        verify_signature(&signature, &[0xff; PUBKEY_SERIALIZED_SIZE], message),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn accepts_valid_zip215_pure_torsion_signature() {
    let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
    signature[..32].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    for i in 0..20 {
        let message = vec![i as u8; 10];

        assert_eq!(
            verify_signature(&signature, &SMALL_ORDER_PUBLIC_KEY_COMPRESSED, &message),
            Ok(()),
            "message index {i} is failing"
        );
    }
}
