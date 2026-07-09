use {
    pinocchio::{entrypoint::InstructionContext, error::ProgramError, ProgramResult},
    solana_ed25519_verify::Ed25519Verifier,
};

/// Program entry point.
///
/// Expects no accounts and instruction data in the ed25519 precompile format.
pub fn process_instruction(context: InstructionContext) -> ProgramResult {
    if context.remaining() > 0 {
        return Err(ProgramError::InvalidArgument);
    }

    Ed25519Verifier::new().verify_instruction(context.instruction_data()?)
}
