use {
    crate::{
        constants::{
            ED25519_BASEPOINT_NEGATED_COMPRESSED, EDWARDS_IDENTITY_COMPRESSED,
            PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
        },
        error::Ed25519VerifyError,
        points::{compute_challenge, is_small_order, multiply_by_8},
        scalar, VerificationCriteria,
    },
    solana_curve25519::{
        edwards::{multiscalar_multiply_edwards, subtract_edwards, PodEdwardsPoint},
        scalar::PodScalar,
    },
};

/// Stateless, zero-allocation Ed25519 verifier.
///
/// The verification behavior is selected by [`VerificationCriteria`]. A verifier
/// created with [`Ed25519Verifier::new`] uses the [`VerificationCriteria::zip215`]
/// preset, matching this crate's historical behavior.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519Verifier {
    criteria: VerificationCriteria,
}

impl Default for Ed25519Verifier {
    fn default() -> Self {
        Self::new()
    }
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
    /// `S*B - H*A - R == identity`. The canonical-encoding and
    /// small-order rejections are applied first per the configured knobs.
    pub fn verify_signature(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
        message: &[u8],
    ) -> Result<(), Ed25519VerifyError> {
        let (r_bytes, s_bytes) = signature.split_at(32);
        let r_bytes: &[u8; 32] = r_bytes.try_into().unwrap();
        let s_bytes: &[u8; 32] = s_bytes.try_into().unwrap();

        // `require_canonical_s` is deliberately not checked because
        // `multiscalar_multiply_edwards` converts `PodScalar` through
        // `Scalar::from_canonical_bytes` and returns `None` on a non-canonical
        // scalar, which maps to `InvalidEncoding` below. Re-checking it
        // in-program duplicates work the curve backend already performs, and
        // would not let us distinguish it from a malformed public key anyway
        // (see `Ed25519VerifyError::InvalidEncoding`).

        if self.criteria.require_canonical_a && !scalar::is_canonical_point_encoding(public_key) {
            return Err(Ed25519VerifyError::NonCanonicalPublicKey);
        }
        if self.criteria.require_canonical_r && !scalar::is_canonical_point_encoding(r_bytes) {
            return Err(Ed25519VerifyError::NonCanonicalR);
        }

        let r_point = PodEdwardsPoint(*r_bytes);
        let public_key_point = PodEdwardsPoint(*public_key);

        if self.criteria.reject_small_order_a && is_small_order(&public_key_point)? {
            return Err(Ed25519VerifyError::SmallOrderPublicKey);
        }
        if self.criteria.reject_small_order_r && is_small_order(&r_point)? {
            return Err(Ed25519VerifyError::SmallOrderR);
        }

        let challenge = compute_challenge(r_bytes, public_key, message);

        // S*(-B) + H*A = -(S*B - H*A), so this yields the negation of the value
        // the verification equation compares against R.
        let neg_lhs = multiscalar_multiply_edwards(
            &[PodScalar(*s_bytes), PodScalar(challenge)],
            &[ED25519_BASEPOINT_NEGATED_COMPRESSED, public_key_point],
        )
        .ok_or(Ed25519VerifyError::InvalidEncoding)?;

        // Flip the sign bit back to recover the encoding of `S*B - H*A`, then
        // compare against `R` as supplied. `neg_lhs` is canonical, so the flip
        // yields the canonical encoding of `lhs` (except when `lhs` has x = 0,
        // where it yields negative zero — which can only miss, never falsely
        // match). A match therefore implies `R == lhs` as points, so `lhs - R`
        // is the identity and both the cofactorless and the cofactored equation
        // hold. Deciding here skips the `subtract_edwards` syscall on the path
        // every honestly generated signature follows.
        let mut lhs_bytes = neg_lhs.0;
        lhs_bytes[31] ^= 0x80;
        if lhs_bytes == *r_bytes {
            return Ok(());
        }

        let lhs = PodEdwardsPoint(lhs_bytes);
        // `lhs` is always a valid point by construction (see above), so a
        // `None` here can only mean `r_point` — built directly from the
        // caller-supplied `r_bytes` — failed to decode.
        let difference =
            subtract_edwards(&lhs, &r_point).ok_or(Ed25519VerifyError::InvalidEncoding)?;

        // An exact-identity difference satisfies both the cofactorless and the
        // cofactored equation, so accept it without the cofactor multiplication.
        // This is the common case for honestly generated (prime-order) signatures,
        // so it saves the `multiply_by_8` syscalls on the hot path.
        if difference == EDWARDS_IDENTITY_COMPRESSED {
            return Ok(());
        }
        // Cofactorless verification requires an exact identity, which is now ruled
        // out. Cofactored verification additionally accepts a difference that
        // clears to identity once multiplied by the cofactor 8 (the mixed-order
        // points that ZIP-215 tolerates).
        if !self.criteria.cofactored {
            return Err(Ed25519VerifyError::SignatureMismatch);
        }
        // `difference` is a point returned by `subtract_edwards` above, so it
        // is always a valid encoding; `multiply_by_8` failing here is not
        // expected to be reachable in practice. `InvalidEncoding` is used
        // defensively in case it is.
        if multiply_by_8(&difference).ok_or(Ed25519VerifyError::InvalidEncoding)?
            != EDWARDS_IDENTITY_COMPRESSED
        {
            return Err(Ed25519VerifyError::SignatureMismatch);
        }

        Ok(())
    }
}
