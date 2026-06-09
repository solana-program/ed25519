use {
    common::{
        first_offsets, instruction_with_signature, signed_instruction, EDWARDS_IDENTITY_COMPRESSED,
    },
    mollusk_svm::Mollusk,
    solana_ed25519_program::SIGNATURE_SERIALIZED_SIZE,
    solana_instruction::Instruction,
    solana_program_runtime::{
        invoke_context::InvokeContext,
        solana_sbpf::{
            declare_builtin_function,
            error::ProgramResult as SbpfProgramResult,
            memory_region::{AccessType, MemoryMapping},
        },
    },
    solana_pubkey::Pubkey,
    std::{env, error::Error, io, mem::size_of, path::PathBuf, slice},
};

mod common;

const PROGRAM_SO_STEM: &str = "solana_ed25519_program";
const SINGLE_MESSAGE: &[u8] = b"deterministic ed25519 verify benchmark";
const SECOND_MESSAGE: &[u8] = b"second deterministic ed25519 verify benchmark";

#[repr(C)]
#[derive(Clone, Copy)]
struct VmSlice {
    ptr: u64,
    len: u64,
}

declare_builtin_function!(
    /// Local SHA-512 syscall shim for runtimes that have not published `sol_sha512` yet.
    ///
    /// Remove this shim and the manual registration below once `sol_sha512` is
    /// live on mainnet and available in the local Agave/Mollusk runtime.
    SyscallSha512,
    fn rust(
        _invoke_context: &mut InvokeContext,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn Error>> {
        let vals =
            translate_slice::<VmSlice>(memory_mapping, vals_addr, vals_len, AccessType::Load)?
                .to_vec();
        let mut hasher = solana_sha512_hasher::Hasher::default();
        for val in &vals {
            let bytes = translate_slice::<u8>(memory_mapping, val.ptr, val.len, AccessType::Load)?;
            hasher.hash(bytes);
        }

        let output = translate_slice_mut::<u8>(memory_mapping, result_addr, 64)?;
        output.copy_from_slice(hasher.result().as_ref());
        Ok(0)
    }
);

fn translate_slice<T>(
    memory_mapping: &mut MemoryMapping,
    vm_addr: u64,
    len: u64,
    access_type: AccessType,
) -> Result<&[T], Box<dyn Error>> {
    let byte_len = mapped_byte_len::<T>(len)?;
    let host_addr = map(memory_mapping, access_type, vm_addr, byte_len)?;
    let len = usize::try_from(len).map_err(|_| length_error())?;
    Ok(unsafe { slice::from_raw_parts(host_addr as *const T, len) })
}

fn translate_slice_mut<T>(
    memory_mapping: &mut MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&mut [T], Box<dyn Error>> {
    let byte_len = mapped_byte_len::<T>(len)?;
    let host_addr = map(memory_mapping, AccessType::Store, vm_addr, byte_len)?;
    let len = usize::try_from(len).map_err(|_| length_error())?;
    Ok(unsafe { slice::from_raw_parts_mut(host_addr as *mut T, len) })
}

fn mapped_byte_len<T>(len: u64) -> Result<u64, Box<dyn Error>> {
    len.checked_mul(size_of::<T>() as u64)
        .ok_or_else(|| length_error().into())
}

fn map(
    memory_mapping: &mut MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
) -> Result<u64, Box<dyn Error>> {
    match memory_mapping.map_with_access_violation_handler(access_type, vm_addr, len) {
        SbpfProgramResult::Ok(host_addr) => Ok(host_addr),
        SbpfProgramResult::Err(err) => Err(err.into()),
    }
}

fn length_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid VM slice length")
}

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

fn make_mollusk() -> Option<(Mollusk, Pubkey)> {
    let program_path = sbf_program_path()?;
    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::default();
    mollusk
        .program_cache
        .program_runtime_environment
        .register_function("sol_sha512", SyscallSha512::vm)
        .expect("register sol_sha512 test syscall");
    mollusk.add_program(&program_id, &program_path);
    Some((mollusk, program_id))
}

fn instruction(program_id: Pubkey, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

#[test]
fn verifies_single_signature_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = instruction(program_id, signed_instruction(&[SINGLE_MESSAGE]));
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
fn verifies_multiple_signatures_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = instruction(
        program_id,
        signed_instruction(&[SINGLE_MESSAGE, SECOND_MESSAGE]),
    );
    let result = mollusk.process_instruction(&ix, &[]);

    assert!(
        result.program_result.is_ok(),
        "verify failed: {:?}",
        result.program_result
    );
    println!(
        "ed25519 verify: 2 signatures, {} total message bytes, {} CUs",
        SINGLE_MESSAGE.len() + SECOND_MESSAGE.len(),
        result.compute_units_consumed
    );
}

#[test]
fn accepts_zip215_identity_vector_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let message = b"zip215 low-order identity vector";
    let mut signature = [0; SIGNATURE_SERIALIZED_SIZE];
    signature[..EDWARDS_IDENTITY_COMPRESSED.len()].copy_from_slice(&EDWARDS_IDENTITY_COMPRESSED);
    let ix = instruction(
        program_id,
        instruction_with_signature(message, &signature, &EDWARDS_IDENTITY_COMPRESSED),
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
    let mut data = signed_instruction(&[SINGLE_MESSAGE]);
    let offsets = first_offsets(&data);
    data[usize::from(offsets.message_data_offset)] ^= 1;

    let result = mollusk.process_instruction(&instruction(program_id, data), &[]);
    assert!(
        result.program_result.is_err(),
        "expected failure on tampered message, got: {:?}",
        result.program_result
    );
}

#[test]
fn rejects_tampered_public_key_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut data = signed_instruction(&[SINGLE_MESSAGE]);
    let offsets = first_offsets(&data);
    data[usize::from(offsets.public_key_offset)] ^= 1;

    let result = mollusk.process_instruction(&instruction(program_id, data), &[]);
    assert!(
        result.program_result.is_err(),
        "expected failure on tampered public key, got: {:?}",
        result.program_result
    );
}
