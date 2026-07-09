use {
    crate::{
        instruction_data::{get_signature_fields, iter_signature_offsets},
        scalar, PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
    },
    solana_curve25519::{
        edwards::{
            multiply_edwards, multiscalar_multiply_edwards, subtract_edwards, PodEdwardsPoint,
        },
        scalar::PodScalar,
    },
    solana_program_error::ProgramError,
};

const ED25519_BASEPOINT_COMPRESSED: PodEdwardsPoint = PodEdwardsPoint([
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]);
const EDWARDS_IDENTITY_COMPRESSED: PodEdwardsPoint = PodEdwardsPoint([
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const EIGHT_SCALAR: PodScalar = PodScalar([
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

/// Stateless, zero-allocation Ed25519 verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Initializes a new verifier.
    pub const fn new() -> Self {
        Self
    }

    /// Parses `instruction_data` and verifies every ed25519 signature it
    /// describes, returning an error on the first failure.
    pub fn verify_instruction(&self, instruction_data: &[u8]) -> Result<(), ProgramError> {
        for offsets in iter_signature_offsets(instruction_data)? {
            let offsets = offsets?;
            let fields = get_signature_fields(instruction_data, &offsets)?;
            self.verify_signature(fields.signature, fields.public_key, fields.message)?;
        }

        Ok(())
    }

    /// Performs ZIP-215 Ed25519 verification for one signature.
    ///
    /// Uses the cofactored equation `[8](S*B - H(R || A || M)*A) == [8]R`.
    /// The combined multiply-add minus `R` is performed first, then multiplied
    /// by 8 and compared with the identity, matching the ed25519-zebra batch
    /// verification shape. Canonical `S` is still required.
    pub fn verify_signature(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
        message: &[u8],
    ) -> Result<(), ProgramError> {
        let r_bytes: &[u8; 32] = signature[..32]
            .try_into()
            .map_err(|_| ProgramError::InvalidArgument)?;
        let s_bytes: &[u8; 32] = signature[32..]
            .try_into()
            .map_err(|_| ProgramError::InvalidArgument)?;
        if !scalar::is_canonical_scalar(s_bytes) {
            return Err(ProgramError::InvalidArgument);
        }

        let r_point = PodEdwardsPoint(*r_bytes);
        let public_key_point = PodEdwardsPoint(*public_key);

        let challenge = compute_challenge(r_bytes, public_key, message);
        let minus_challenge = scalar::negate(&challenge);
        let lhs = multiscalar_multiply_edwards(
            &[PodScalar(*s_bytes), PodScalar(minus_challenge)],
            &[ED25519_BASEPOINT_COMPRESSED, public_key_point],
        )
        .ok_or(ProgramError::InvalidArgument)?;
        let difference = subtract_edwards(&lhs, &r_point).ok_or(ProgramError::InvalidArgument)?;
        let difference_cofactored =
            multiply_edwards(&EIGHT_SCALAR, &difference).ok_or(ProgramError::InvalidArgument)?;

        if difference_cofactored != EDWARDS_IDENTITY_COMPRESSED {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }
}

fn compute_challenge(signature_r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]).to_bytes();
    scalar::reduce_wide(&digest)
}
