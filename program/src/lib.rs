#![no_std]

//! Pinocchio SBF wrapper for [`solana_ed25519_verify`].
//!
//! The reusable verifier, instruction layout, and instruction constructors live
//! in `solana-ed25519-verify`. This crate keeps only the standalone program
//! entrypoint.

#[cfg(all(
    not(feature = "no-entrypoint"),
    any(target_os = "solana", target_arch = "bpf")
))]
use pinocchio::{lazy_program_entrypoint, no_allocator, nostd_panic_handler};

mod processor;

pub use processor::process_instruction;

#[cfg(all(
    not(feature = "no-entrypoint"),
    any(target_os = "solana", target_arch = "bpf")
))]
lazy_program_entrypoint!(process_instruction);
#[cfg(all(
    not(feature = "no-entrypoint"),
    any(target_os = "solana", target_arch = "bpf")
))]
no_allocator!();
#[cfg(all(
    not(feature = "no-entrypoint"),
    any(target_os = "solana", target_arch = "bpf")
))]
nostd_panic_handler!();
