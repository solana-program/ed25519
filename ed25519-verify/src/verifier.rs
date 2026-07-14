use {
    crate::{
        field, scalar, VerificationCriteria, PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
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
/// Identity point of the Edwards curve, in compressed form.
pub(crate) const EDWARDS_IDENTITY_COMPRESSED_BYTES: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const EDWARDS_IDENTITY_COMPRESSED: PodEdwardsPoint =
    PodEdwardsPoint(EDWARDS_IDENTITY_COMPRESSED_BYTES);
const EIGHT_SCALAR: PodScalar = PodScalar([
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

/// Stateless, zero-allocation Ed25519 verifier.
///
/// The verification variant is selected by [`VerificationCriteria`]. A verifier
/// created with [`Ed25519Verifier::new`] uses the [`VerificationCriteria::zip215`]
/// preset, matching this crate's historical behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Verifier {
    criteria: VerificationCriteria,
}

impl Ed25519Verifier {
    /// Initializes a verifier using the default [ZIP-215] criteria.
    ///
    /// [ZIP-215]: VerificationCriteria::zip215
    pub const fn new() -> Self {
        Self {
            criteria: VerificationCriteria::zip215(),
        }
    }

    /// Initializes a verifier with explicit [`VerificationCriteria`].
    pub const fn with_criteria(criteria: VerificationCriteria) -> Self {
        Self { criteria }
    }

    /// Returns the criteria this verifier enforces.
    pub const fn criteria(&self) -> VerificationCriteria {
        self.criteria
    }

    /// Verifies one Ed25519 signature according to the configured criteria.
    ///
    /// The core relation is `S*B - H(R || A || M)*A == R`. Depending on
    /// [`VerificationCriteria::cofactored`], the check is performed either
    /// cofactored — `[8](S*B - H*A - R) == identity`, matching the
    /// ed25519-zebra batch verification shape — or cofactorless —
    /// `S*B - H*A - R == identity`. The canonical-`S`, canonical-encoding, and
    /// small-order rejections are applied first per the configured knobs.
    pub fn verify_signature(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
        message: &[u8],
    ) -> Result<(), ProgramError> {
        let (r_bytes, s_bytes) = signature.split_at(32);
        let r_bytes: &[u8; 32] = r_bytes.try_into().unwrap();
        let s_bytes: &[u8; 32] = s_bytes.try_into().unwrap();

        if self.criteria.require_canonical_s && !scalar::is_canonical_scalar(s_bytes) {
            return Err(ProgramError::InvalidArgument);
        }
        if self.criteria.require_canonical_a && !field::is_canonical_point_encoding(public_key) {
            return Err(ProgramError::InvalidArgument);
        }
        if self.criteria.require_canonical_r && !field::is_canonical_point_encoding(r_bytes) {
            return Err(ProgramError::InvalidArgument);
        }

        let r_point = PodEdwardsPoint(*r_bytes);
        let public_key_point = PodEdwardsPoint(*public_key);

        if self.criteria.reject_small_order_a && is_small_order(&public_key_point) {
            return Err(ProgramError::InvalidArgument);
        }
        if self.criteria.reject_small_order_r && is_small_order(&r_point) {
            return Err(ProgramError::InvalidArgument);
        }

        let challenge = compute_challenge(r_bytes, public_key, message);
        let minus_challenge = scalar::negate(&challenge);
        let lhs = multiscalar_multiply_edwards(
            &[PodScalar(*s_bytes), PodScalar(minus_challenge)],
            &[ED25519_BASEPOINT_COMPRESSED, public_key_point],
        )
        .ok_or(ProgramError::InvalidArgument)?;
        let difference = subtract_edwards(&lhs, &r_point).ok_or(ProgramError::InvalidArgument)?;

        let residue = if self.criteria.cofactored {
            multiply_edwards(&EIGHT_SCALAR, &difference).ok_or(ProgramError::InvalidArgument)?
        } else {
            difference
        };

        if residue != EDWARDS_IDENTITY_COMPRESSED {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }
}

/// Returns `true` if `point` decompresses to a small-order (torsion) point.
///
/// A point has order dividing the cofactor 8 exactly when `[8]P` is the
/// identity. This decompresses `point` (accepting non-canonical encodings, which
/// reduce modulo `p`); an encoding that does not decompress is not treated as
/// small order and is rejected later by the verification equation.
fn is_small_order(point: &PodEdwardsPoint) -> bool {
    matches!(
        multiply_edwards(&EIGHT_SCALAR, point),
        Some(product) if product == EDWARDS_IDENTITY_COMPRESSED
    )
}

fn compute_challenge(signature_r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]).to_bytes();
    scalar::reduce_wide(&digest)
}
