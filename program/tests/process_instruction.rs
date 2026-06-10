use {
    common::{
        first_offsets, instruction_with_signature, signed_instruction, write_offsets,
        EDWARDS_IDENTITY_COMPRESSED, SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
    },
    ed25519_dalek::{Signature, VerifyingKey},
    solana_ed25519_program::{
        process_instruction, CURRENT_INSTRUCTION_INDEX, DATA_START, SIGNATURE_SERIALIZED_SIZE,
    },
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
};

mod common;

#[test]
fn verifies_matching_signature() {
    let program_id = Pubkey::default();
    let instruction = signed_instruction(&[b"hello ed25519"]);

    assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
}

#[test]
fn verifies_multiple_signatures() {
    let program_id = Pubkey::default();
    let instruction = signed_instruction(&[b"hello ed25519", b"second message"]);

    assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
}

#[test]
fn accepts_zip215_small_order_public_key_vector_rejected_by_strict_verification() {
    let program_id = Pubkey::default();
    let message = b"zip215 low-order public key vector";
    let mut signature = [0; SIGNATURE_SERIALIZED_SIZE];
    signature[..EDWARDS_IDENTITY_COMPRESSED.len()].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    let dalek_key = VerifyingKey::from_bytes(&SMALL_ORDER_PUBLIC_KEY_COMPRESSED)
        .expect("small-order key decompresses");
    let dalek_signature = Signature::from_bytes(&signature);
    assert!(dalek_key.verify_strict(message, &dalek_signature).is_err());

    let instruction =
        instruction_with_signature(message, &signature, &SMALL_ORDER_PUBLIC_KEY_COMPRESSED);
    assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
}

#[test]
fn rejects_wrong_public_key() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let offsets = first_offsets(&instruction);
    instruction[usize::from(offsets.public_key_offset)] ^= 1;

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_corrupted_signature() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let offsets = first_offsets(&instruction);
    instruction[usize::from(offsets.signature_offset)] ^= 1;

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_tampered_message() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let offsets = first_offsets(&instruction);
    instruction[usize::from(offsets.message_data_offset)] ^= 1;

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_short_instruction() {
    let program_id = Pubkey::default();

    assert_eq!(
        process_instruction(&program_id, &[], &[]),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(&program_id, &[], &[1]),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(&program_id, &[], &[1, 0]),
        Err(ProgramError::InvalidInstructionData)
    );
}

#[test]
fn accepts_zero_signatures_only_when_data_has_just_header() {
    let program_id = Pubkey::default();

    assert_eq!(process_instruction(&program_id, &[], &[0, 0]), Ok(()));
    assert_eq!(
        process_instruction(&program_id, &[], &[0]),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(&program_id, &[], &[0, 0, 0]),
        Err(ProgramError::InvalidInstructionData)
    );
}

#[test]
fn rejects_offsets_to_other_instructions() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let mut offsets = first_offsets(&instruction);
    offsets.signature_instruction_index = 0;
    write_offsets(&mut instruction[2..DATA_START], &offsets);

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidInstructionData)
    );

    offsets.signature_instruction_index = CURRENT_INSTRUCTION_INDEX;
    offsets.public_key_instruction_index = 0;
    write_offsets(&mut instruction[2..DATA_START], &offsets);
    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidInstructionData)
    );

    offsets.public_key_instruction_index = CURRENT_INSTRUCTION_INDEX;
    offsets.message_instruction_index = 0;
    write_offsets(&mut instruction[2..DATA_START], &offsets);
    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidInstructionData)
    );
}

#[test]
fn rejects_out_of_bounds_offsets() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let mut offsets = first_offsets(&instruction);
    offsets.message_data_size = u16::MAX;
    write_offsets(&mut instruction[2..DATA_START], &offsets);

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidInstructionData)
    );
}

#[test]
fn rejects_non_canonical_s_scalar() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let offsets = first_offsets(&instruction);
    let s_offset = usize::from(offsets.signature_offset) + 32;
    instruction[s_offset..s_offset + 32].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ]);

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_low_order_r() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let offsets = first_offsets(&instruction);
    let r_offset = usize::from(offsets.signature_offset);
    instruction[r_offset..r_offset + 32].copy_from_slice(&[
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_low_order_public_key() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let offsets = first_offsets(&instruction);
    let public_key_offset = usize::from(offsets.public_key_offset);
    instruction[public_key_offset..public_key_offset + 32]
        .copy_from_slice(&SMALL_ORDER_PUBLIC_KEY_COMPRESSED);

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_invalid_public_key() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let offsets = first_offsets(&instruction);
    let public_key_offset = usize::from(offsets.public_key_offset);
    instruction[public_key_offset..public_key_offset + 32].copy_from_slice(&[0xff; 32]);

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_accounts() {
    let program_id = Pubkey::default();
    let instruction = signed_instruction(&[b"hello ed25519"]);
    let key = Pubkey::new_unique();
    let mut lamports = 0;
    let mut data = [];
    let account = solana_account_info::AccountInfo::new(
        &key,
        false,
        false,
        &mut lamports,
        &mut data,
        &program_id,
        false,
    );

    assert_eq!(
        process_instruction(&program_id, &[account], &instruction),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn ignores_padding_byte() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    instruction[1] = 0xff;

    assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
}

#[test]
fn signature_offset_points_to_exactly_64_bytes() {
    let program_id = Pubkey::default();
    let mut instruction = signed_instruction(&[b"hello ed25519"]);
    let mut offsets = first_offsets(&instruction);
    offsets.signature_offset = u16::try_from(instruction.len() - SIGNATURE_SERIALIZED_SIZE + 1)
        .expect("test instruction length fits u16");
    write_offsets(&mut instruction[2..DATA_START], &offsets);

    assert_eq!(
        process_instruction(&program_id, &[], &instruction),
        Err(ProgramError::InvalidInstructionData)
    );
}

#[test]
fn accepts_valid_zip215_pure_torsion_signature() {
    let program_id = Pubkey::default();

    // R = Identity Point
    let signature_r = EDWARDS_IDENTITY_COMPRESSED;
    // S = Zero Scalar
    let signature_s = [0u8; 32];

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&signature_r);
    signature[32..].copy_from_slice(&signature_s);

    // A = A non-identity pure torsion point.
    let pubkey = SMALL_ORDER_PUBLIC_KEY_COMPRESSED;

    // Under ZIP-215: [8](S*B) = [8]R + [8](c*A)
    // Since S=0 and R=O, this becomes O = O + c*[8]A.
    // Because A is an 8-torsion point, [8]A = O.
    // The equation is O = O + O, which is always true.
    // This signature must be accepted for any message.

    // The buggy verification failed for some challenge values, so try a couple
    // messages in a loop to cover multiple challenges.
    for i in 0..20 {
        let message = vec![i as u8; 10];
        let instruction = instruction_with_signature(&message, &signature, &pubkey);

        assert_eq!(
            process_instruction(&program_id, &[], &instruction),
            Ok(()),
            "message index {i} is failing"
        );
    }
}
