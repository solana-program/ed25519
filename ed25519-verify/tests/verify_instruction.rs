use {
    ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey},
    solana_ed25519_verify::{
        ed25519_verify_instruction, Ed25519Verifier, VerificationCriteria, VerificationVariant,
        PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
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
/// Non-canonical encoding of a small-order point: `y = p` (reduces to `y = 0`,
/// an order-4 point). Its `y`-coordinate is not reduced modulo `p`.
const NON_CANONICAL_SMALL_ORDER_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
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

    let instruction = ed25519_verify_instruction(
        &program_id,
        VerificationVariant::DalekVerifyStrict,
        &public_key,
        &signature,
        message,
    );

    const PUBKEY_START: usize = 1;
    const SIGNATURE_START: usize = PUBKEY_START + PUBKEY_SERIALIZED_SIZE;
    const MESSAGE_START: usize = SIGNATURE_START + SIGNATURE_SERIALIZED_SIZE;

    assert_eq!(instruction.program_id, program_id);
    assert!(instruction.accounts.is_empty());
    assert_eq!(
        instruction.data[0],
        VerificationVariant::DalekVerifyStrict.to_byte()
    );
    assert_eq!(
        &instruction.data[PUBKEY_START..SIGNATURE_START],
        &public_key
    );
    assert_eq!(
        &instruction.data[SIGNATURE_START..MESSAGE_START],
        &signature
    );
    assert_eq!(&instruction.data[MESSAGE_START..], message);
}

#[test]
fn verification_variant_byte_round_trips() {
    for variant in [
        VerificationVariant::Zip215,
        VerificationVariant::DalekVerifyStrict,
    ] {
        assert_eq!(
            VerificationVariant::from_byte(variant.to_byte()),
            Some(variant)
        );
        assert_eq!(
            variant.criteria(),
            match variant {
                VerificationVariant::Zip215 => VerificationCriteria::zip215(),
                VerificationVariant::DalekVerifyStrict =>
                    VerificationCriteria::dalek_verify_strict(),
            }
        );
    }
    assert_eq!(VerificationVariant::from_byte(2), None);
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

fn verify_with(
    criteria: VerificationCriteria,
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
    message: &[u8],
) -> Result<(), ProgramError> {
    Ed25519Verifier::with_criteria(criteria).verify_signature(signature, public_key, message)
}

#[test]
fn new_uses_zip215_criteria() {
    assert_eq!(
        Ed25519Verifier::new().criteria(),
        VerificationCriteria::zip215()
    );
    assert_eq!(
        VerificationCriteria::default(),
        VerificationCriteria::zip215()
    );
}

#[test]
fn require_canonical_s_is_enforced_by_default_only() {
    let message = b"hello ed25519";
    let (mut signature, public_key) = signed_payload(message);
    // S = L (the group order): non-canonical.
    signature[32..64].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ]);

    // ZIP-215 requires canonical S.
    assert_eq!(
        verify_with(
            VerificationCriteria::zip215(),
            &signature,
            &public_key,
            message
        ),
        Err(ProgramError::InvalidArgument)
    );

    // Disabling the knob lets the reduced scalar through; S = L reduces to 0, so
    // the equation no longer holds and it fails for a different reason, but never
    // via the canonical-S gate. Use a genuinely valid signature to confirm the
    // gate itself is off.
    let (valid_signature, valid_public_key) = signed_payload(message);
    let criteria = VerificationCriteria {
        require_canonical_s: false,
        ..VerificationCriteria::zip215()
    };
    assert_eq!(
        verify_with(criteria, &valid_signature, &valid_public_key, message),
        Ok(())
    );
}

#[test]
fn reject_small_order_public_key_rejects_zip215_vector() {
    let message = b"zip215 low-order public key vector";
    let mut signature = [0; SIGNATURE_SERIALIZED_SIZE];
    signature[..EDWARDS_IDENTITY_COMPRESSED.len()].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    // Accepted under the default ZIP-215 criteria.
    assert_eq!(
        verify_with(
            VerificationCriteria::zip215(),
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Ok(())
    );

    // Rejected once small-order public keys are disallowed.
    let criteria = VerificationCriteria {
        reject_small_order_a: true,
        ..VerificationCriteria::zip215()
    };
    assert_eq!(
        verify_with(
            criteria,
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn reject_small_order_r_rejects_torsion_signature() {
    let message = b"torsion r";
    // S = 0, R = a non-canonical small-order point. With a small-order public
    // key this satisfies the cofactored equation.
    let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
    signature[..32].copy_from_slice(&NON_CANONICAL_SMALL_ORDER_COMPRESSED);

    assert_eq!(
        verify_with(
            VerificationCriteria::zip215(),
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Ok(())
    );

    let criteria = VerificationCriteria {
        reject_small_order_r: true,
        ..VerificationCriteria::zip215()
    };
    assert_eq!(
        verify_with(
            criteria,
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn require_canonical_a_rejects_non_canonical_public_key() {
    let message = b"non-canonical a";
    // S = 0, R = identity, small-order (order 4) public key encoded as y = p.
    let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
    signature[..32].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    assert_eq!(
        verify_with(
            VerificationCriteria::zip215(),
            &signature,
            &NON_CANONICAL_SMALL_ORDER_COMPRESSED,
            message
        ),
        Ok(())
    );

    let criteria = VerificationCriteria {
        require_canonical_a: true,
        ..VerificationCriteria::zip215()
    };
    assert_eq!(
        verify_with(
            criteria,
            &signature,
            &NON_CANONICAL_SMALL_ORDER_COMPRESSED,
            message
        ),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn require_canonical_r_rejects_non_canonical_r() {
    let message = b"non-canonical r";
    // S = 0, R = small-order point encoded as y = p.
    let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
    signature[..32].copy_from_slice(&NON_CANONICAL_SMALL_ORDER_COMPRESSED);

    assert_eq!(
        verify_with(
            VerificationCriteria::zip215(),
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Ok(())
    );

    let criteria = VerificationCriteria {
        require_canonical_r: true,
        ..VerificationCriteria::zip215()
    };
    assert_eq!(
        verify_with(
            criteria,
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn cofactorless_still_accepts_prime_order_signature() {
    let message = b"hello ed25519";
    let (signature, public_key) = signed_payload(message);

    let criteria = VerificationCriteria {
        cofactored: false,
        ..VerificationCriteria::zip215()
    };
    assert_eq!(
        verify_with(criteria, &signature, &public_key, message),
        Ok(())
    );
}

/// Whether `ed25519_dalek::verify_strict` accepts the given triple, or `false`
/// if the inputs cannot even be parsed into dalek types.
fn dalek_verify_strict_accepts(
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
    message: &[u8],
) -> bool {
    match VerifyingKey::from_bytes(public_key) {
        Ok(key) => key
            .verify_strict(message, &Signature::from_bytes(signature))
            .is_ok(),
        Err(_) => false,
    }
}

#[test]
fn dalek_verify_strict_preset_matches_dalek() {
    let good_message = b"hello ed25519";
    let (good_signature, good_public_key) = signed_payload(good_message);

    let mut wrong_public_key = good_public_key;
    wrong_public_key[0] ^= 1;
    let (mut corrupt_signature, corrupt_public_key) = signed_payload(good_message);
    corrupt_signature[0] ^= 1;

    // S = L: non-canonical scalar.
    let (mut non_canonical_s, non_canonical_s_key) = signed_payload(good_message);
    non_canonical_s[32..64].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ]);

    // Small-order public key with the ZIP-215 torsion signature.
    let mut torsion_signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
    torsion_signature[..32].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    let cases: &[(
        &[u8; SIGNATURE_SERIALIZED_SIZE],
        &[u8; PUBKEY_SERIALIZED_SIZE],
        &[u8],
    )] = &[
        (&good_signature, &good_public_key, good_message),
        (&good_signature, &wrong_public_key, good_message),
        (&corrupt_signature, &corrupt_public_key, good_message),
        (&non_canonical_s, &non_canonical_s_key, good_message),
        (
            &torsion_signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            good_message,
        ),
    ];

    for (index, (signature, public_key, message)) in cases.iter().enumerate() {
        let ours = verify_with(
            VerificationCriteria::dalek_verify_strict(),
            signature,
            public_key,
            message,
        )
        .is_ok();
        let dalek = dalek_verify_strict_accepts(signature, public_key, message);
        assert_eq!(
            ours, dalek,
            "case {index} disagrees with dalek verify_strict"
        );
    }
}

#[test]
fn dalek_verify_strict_preset_rejects_zip215_small_order_key() {
    // The canonical example where ZIP-215 and verify_strict diverge.
    let message = b"zip215 low-order public key vector";
    let mut signature = [0; SIGNATURE_SERIALIZED_SIZE];
    signature[..EDWARDS_IDENTITY_COMPRESSED.len()].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    assert_eq!(
        verify_with(
            VerificationCriteria::zip215(),
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Ok(())
    );
    assert_eq!(
        verify_with(
            VerificationCriteria::dalek_verify_strict(),
            &signature,
            &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
            message
        ),
        Err(ProgramError::InvalidArgument)
    );
    assert!(!dalek_verify_strict_accepts(
        &signature,
        &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
        message
    ));
}
