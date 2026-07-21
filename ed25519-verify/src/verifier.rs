use {
    crate::{scalar, VerificationCriteria, PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
    solana_curve25519::{
        edwards::{add_edwards, multiscalar_multiply_edwards, subtract_edwards, PodEdwardsPoint},
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
        if self.criteria.require_canonical_a && !scalar::is_canonical_point_encoding(public_key) {
            return Err(ProgramError::InvalidArgument);
        }
        if self.criteria.require_canonical_r && !scalar::is_canonical_point_encoding(r_bytes) {
            return Err(ProgramError::InvalidArgument);
        }

        let r_point = PodEdwardsPoint(*r_bytes);
        let public_key_point = PodEdwardsPoint(*public_key);

        if self.criteria.reject_small_order_a && is_small_order(&public_key_point)? {
            return Err(ProgramError::InvalidArgument);
        }
        if self.criteria.reject_small_order_r && is_small_order(&r_point)? {
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
            multiply_by_8(&difference).ok_or(ProgramError::InvalidArgument)?
        } else {
            difference
        };

        if residue != EDWARDS_IDENTITY_COMPRESSED {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }
}

/// Returns `Ok(true)` if `point` decompresses to a small-order (torsion) point.
///
/// A point has order dividing the cofactor 8 exactly when `[8]P` is the
/// identity. This decompresses `point` (accepting non-canonical encodings, which
/// reduce modulo `p`). An encoding that does not decompress returns
/// `Err(InvalidArgument)` so the caller can reject it immediately, rather than
/// treating it as non-small-order and paying for the subsequent verification
/// syscalls only to fail there.
fn is_small_order(point: &PodEdwardsPoint) -> Result<bool, ProgramError> {
    let product = multiply_by_8(point).ok_or(ProgramError::InvalidArgument)?;
    Ok(product == EDWARDS_IDENTITY_COMPRESSED)
}

/// Multiplies `point` by the cofactor 8 via three point doublings.
///
/// Cheaper than a scalar multiplication by 8: three `sol_curve_group_op`
/// additions (473 CU each, 1,419 total) versus one multiplication (2,177 CU).
/// Returns `None` if `point` is not a valid curve encoding.
fn multiply_by_8(point: &PodEdwardsPoint) -> Option<PodEdwardsPoint> {
    let double = add_edwards(point, point)?;
    let quadruple = add_edwards(&double, &double)?;
    add_edwards(&quadruple, &quadruple)
}

fn compute_challenge(signature_r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]).to_bytes();
    scalar::reduce_wide(&digest)
}
