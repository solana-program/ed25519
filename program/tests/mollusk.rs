use {
    ed25519_dalek::{Signer, SigningKey},
    mollusk_svm::{result::ProgramResult, Mollusk},
    pinocchio::error::ProgramError,
    solana_account::Account,
    solana_address::Address,
    solana_ed25519_verify::{
        constants::{PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
        verify,
    },
    solana_instruction::{AccountMeta, Instruction},
    std::{env, path::PathBuf},
};

const PROGRAM_SO_STEM: &str = "solana_ed25519_program";
const SINGLE_MESSAGE: &[u8] = b"deterministic ed25519 verify benchmark";
const PUBLIC_KEY_OFFSET: usize = 0;
const MESSAGE_OFFSET: usize = PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE;

const EDWARDS_IDENTITY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const SMALL_ORDER_PUBLIC_KEY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

fn sbf_program_path() -> Option<String> {
    if let Some(out_dir) = env::var_os("SBF_OUT_DIR") {
        let path = PathBuf::from(out_dir).join(PROGRAM_SO_STEM);
        let so_path = path.with_extension("so");
        assert!(
            so_path.exists(),
            "SBF artifact not found at {}; run make build-sbf-program first",
            so_path.display()
        );
        return Some(path.to_string_lossy().into_owned());
    }

    eprintln!("skipping Mollusk SBF tests: set SBF_OUT_DIR to target/deploy");
    None
}

fn make_mollusk() -> Option<(Mollusk, Address)> {
    let program_path = sbf_program_path()?;
    let program_id = Address::new_unique();
    let mut mollusk = Mollusk::default();
    mollusk.add_program(&program_id, &program_path);
    Some((mollusk, program_id))
}

fn instruction(program_id: Address, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

fn signed_instruction(program_id: Address, message: &[u8]) -> Instruction {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signature = signing_key.sign(message).to_bytes();
    let public_key = signing_key.verifying_key().to_bytes();

    verify(&program_id, &public_key, &signature, message)
}

#[test]
fn verifies_single_signature_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = signed_instruction(program_id, SINGLE_MESSAGE);
    let result = mollusk.process_instruction(&ix, &[]);

    assert!(
        result.program_result.is_ok(),
        "verify failed: {:?}",
        result.program_result
    );
    println!(
        "ed25519 verify: 1 signature, {} message bytes, {} CUs",
        SINGLE_MESSAGE.len(),
        result.compute_units_consumed
    );
}

#[test]
fn accepts_zip215_small_order_public_key_vector_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let message = b"zip215 low-order public key vector";
    let mut signature = [0; SIGNATURE_SERIALIZED_SIZE];
    signature[..EDWARDS_IDENTITY_COMPRESSED.len()].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);
    let ix = verify(
        &program_id,
        &SMALL_ORDER_PUBLIC_KEY_COMPRESSED,
        &signature,
        message,
    );
    let result = mollusk.process_instruction(&ix, &[]);

    assert!(
        result.program_result.is_ok(),
        "verify failed: {:?}",
        result.program_result
    );
}

#[test]
fn rejects_tampered_message_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut ix = signed_instruction(program_id, SINGLE_MESSAGE);
    ix.data[MESSAGE_OFFSET] ^= 1;

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
fn rejects_tampered_public_key_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut ix = signed_instruction(program_id, SINGLE_MESSAGE);
    ix.data[PUBLIC_KEY_OFFSET] ^= 1;

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
fn rejects_accounts_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let account = Address::new_unique();
    let mut ix = signed_instruction(program_id, SINGLE_MESSAGE);
    ix.accounts = vec![AccountMeta::new_readonly(account, false)];
    let accounts = [(account, Account::default())];

    let result = mollusk.process_instruction(&ix, &accounts);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidArgument),
    );
}

#[test]
fn rejects_short_instruction_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = instruction(program_id, vec![0; MESSAGE_OFFSET - 1]);

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
fn verifies_signature_corpus_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };

    let mut cases = 0u64;
    let mut total_cus = 0u64;
    let mut min_cus = u64::MAX;
    let mut max_cus = 0u64;

    for seed in [7u8, 42, 99, 201] {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = signing_key.verifying_key().to_bytes();

        for message_len in [0usize, 1, 38, 47, 48, 49, 128, 1024] {
            let message = if message_len == SINGLE_MESSAGE.len() {
                SINGLE_MESSAGE.to_vec()
            } else {
                (0..message_len)
                    .map(|index| (index as u8).wrapping_mul(31).wrapping_add(17))
                    .collect::<Vec<u8>>()
            };
            let signature = signing_key.sign(&message).to_bytes();
            let ix = verify(&program_id, &public_key, &signature, &message);

            let result = mollusk.process_instruction(&ix, &[]);
            assert_eq!(
                result.program_result,
                ProgramResult::Success,
                "corpus verification failed: seed={seed}, message_len={message_len}",
            );

            let cus = result.compute_units_consumed;
            println!("ed25519 corpus: seed={seed}, message_bytes={message_len}, CUs={cus}");

            cases += 1;
            total_cus += cus;
            min_cus = min_cus.min(cus);
            max_cus = max_cus.max(cus);
        }
    }

    println!(
        "ed25519 corpus summary: cases={cases}, total_CUs={total_cus}, \
         min_CUs={min_cus}, max_CUs={max_cus}"
    );
}

#[test]
fn accepts_zip215_torsion_encodings_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    // Eight canonical torsion encodings, followed by six non-canonical aliases.
    let encodings = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];

    for (case, encoded) in encodings.iter().enumerate() {
        let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
        for (i, byte) in signature[..32].iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[2 * i..2 * i + 2], 16).unwrap();
        }
        // A = identity and S = 0 leave -R as the verification difference.
        let ix = verify(
            &program_id,
            &EDWARDS_IDENTITY_COMPRESSED,
            &signature,
            b"zip215 torsion fallback",
        );
        let result = mollusk.process_instruction(&ix, &[]);
        assert!(
            result.program_result.is_ok(),
            "torsion case={case} failed: {:?}",
            result.program_result
        );
        println!(
            "ed25519 torsion: case={case}, CUs={}",
            result.compute_units_consumed
        );
    }
}

#[test]
fn rejects_invalid_msm_inputs_on_sbf() {
    use {mollusk_svm::result::ProgramResult, pinocchio::error::ProgramError};

    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };

    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
    signature[..32].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);

    // With A = R = identity, reducing S = L to zero would wrongly accept.
    let mut noncanonical_s = signature;
    noncanonical_s[32..].copy_from_slice(&ORDER);

    // Compressed y = 2 does not decompress to an Edwards point.
    let mut invalid_public_key = [0u8; PUBKEY_SERIALIZED_SIZE];
    invalid_public_key[0] = 2;

    for (case, public_key, signature) in [
        ("S equals L", EDWARDS_IDENTITY_COMPRESSED, noncanonical_s),
        ("invalid A", invalid_public_key, signature),
    ] {
        let ix = verify(&program_id, &public_key, &signature, b"invalid MSM inputs");
        let result = mollusk.process_instruction(&ix, &[]);

        assert_eq!(
            result.program_result,
            ProgramResult::Failure(ProgramError::InvalidInstructionData),
            "{case}"
        );
    }
}
