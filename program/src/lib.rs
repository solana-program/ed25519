//! Instructions and on-chain verification for the [`ed25519` native program][np].
//!
//! [np]: https://solana.com/docs/core/programs/precompiles#verify-ed25519-signatures
//!
//! This crate contains the on-chain processor that re-verifies Ed25519
//! signatures inside a Solana program, and re-exports the shared Ed25519
//! instruction types and client-side builders from the upstream SDK crate.
//!
//! _This crate exposes low-level cryptographic building blocks. Read this
//! documentation carefully and validate instruction layout assumptions in any
//! program that depends on signature verification for safety._
//!
//! The native ed25519 precompile validates signatures at the transaction level.
//! The shared API re-exported by this crate mirrors that native instruction
//! format so clients can build compatible instructions, while this crate's
//! processor lets other programs CPI into a verifier and trust the explicit
//! pass/fail result.
//!
//! # Current crate structure
//!
//! This crate intentionally separates the shared client-facing wire definitions
//! from the on-chain verifier implementation:
//!
//! - The re-exported SDK surface provides types like
//!   [`Ed25519SignatureOffsets`], layout constants, and instruction builders.
//! - The `processor` module contains the on-chain verification logic.
//! - The `instruction_data` module contains parser helpers for the 14-byte
//!   offset records and instruction payload slices.
//! - The `scalar` module contains scalar arithmetic helpers used for canonical
//!   `S` checks and challenge reduction.
//!
//! The crate root remains thin and contains only documentation, re-exports, and
//! the Solana entry point.
//!
//! # Instruction data layout
//!
//! The instruction data mirrors the layout consumed by the native ed25519
//! precompile:
//!
//! ```text
//! [num_signatures: u8]
//! [padding: u8]
//! [Ed25519SignatureOffsets x num_signatures]   (14 bytes each, little-endian)
//! [public key || signature || message ...]     (payload, order flexible)
//! ```
//!
//! The payload bytes can be arranged however the client wants, as long as each
//! [`Ed25519SignatureOffsets`] record points at the correct byte ranges.
//!
//! All data references inside [`Ed25519SignatureOffsets`] must use the native
//! "current instruction" sentinel (`u16::MAX`) when processed by this crate;
//! cross-instruction references are rejected.
//!
//! # ZIP-215 verification behavior
//!
//! This crate verifies signatures with the cofactored ZIP-215 equation
//! `[8](S*B - H(R || A || M)*A) == [8]R`. Verification fails if any of the
//! following are true:
//!
//! - The signature scalar `S` is non-canonical.
//! - The signature point `R` cannot be decompressed.
//! - The compressed public key cannot be decompressed.
//! - The cofactored signature equation does not hold.
//! - The instruction data is empty, truncated, or contains out-of-bounds
//!   offsets.
//! - Any offset record references an instruction index other than `u16::MAX`.
//!
//! Small-order `R` and public-key points are not rejected solely because they
//! are small order; their torsion components are removed by the cofactor
//! multiplication.
//!
//! # Additional security considerations
//!
//! Most programs should be conservative about what instruction shapes they
//! accept. Desirable checks often include:
//!
//! - The number of signatures is exactly what the program expects.
//! - Every instruction index field is exactly where the program expects the
//!   signature material to live.
//! - The signed messages are domain-separated and cannot be replayed across
//!   unrelated instructions or protocols.
//! - The verifier program ID is the expected one, so a malicious program cannot
//!   fake a successful verification path.

mod instruction;
mod instruction_data;
mod processor;
mod scalar;

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub use instruction::sign_message;
#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
pub use instruction::{
    new_ed25519_instruction_with_signature, offsets_to_ed25519_instruction,
    try_new_ed25519_instruction_with_signature, try_offsets_to_ed25519_instruction,
};
pub use instruction::{
    Ed25519SignatureOffsets, CURRENT_INSTRUCTION_INDEX, DATA_START, PUBKEY_SERIALIZED_SIZE,
    SIGNATURE_OFFSETS_SERIALIZED_SIZE, SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
};
pub use processor::process_instruction;

#[cfg(target_os = "solana")]
use solana_program_error::ProgramError;

/// Program entry point for the version 2 instruction-data pointer interface.
///
/// # Safety
///
/// The Solana runtime must pass `input` as the serialized accounts buffer and
/// `instruction_data_addr` as the pointer to instruction data with its length
/// stored in the preceding 8 bytes.
#[cfg(all(target_os = "solana", not(feature = "no-entrypoint")))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entrypoint(input: *mut u8, instruction_data_addr: *const u8) -> u64 {
    let result = unsafe {
        let num_accounts = *(input as *const u64);
        if num_accounts != 0 {
            Err(ProgramError::InvalidArgument)
        } else {
            let Some(instruction_data_len_addr) =
                (instruction_data_addr as usize).checked_sub(core::mem::size_of::<u64>())
            else {
                return ProgramError::InvalidInstructionData.into();
            };
            let instruction_data_len = *(instruction_data_len_addr as *const u64);
            let instruction_data =
                core::slice::from_raw_parts(instruction_data_addr, instruction_data_len as usize);
            processor::verify_ed25519_instruction(instruction_data)
        }
    };

    match result {
        Ok(()) => solana_program_entrypoint::SUCCESS,
        Err(error) => error.into(),
    }
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::custom_heap_default!();
#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::custom_panic_default!();

#[cfg(all(target_os = "solana", not(feature = "no-entrypoint")))]
#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    let message = "abort";
    let file = file!();
    unsafe {
        solana_program_entrypoint::__log(message.as_ptr(), message.len() as u64);
        solana_program_entrypoint::__panic(
            file.as_ptr(),
            file.len() as u64,
            line!() as u64,
            column!() as u64,
        )
    }
}
