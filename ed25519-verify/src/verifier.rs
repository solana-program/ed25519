use {
    crate::{
        constants::{
            ED25519_BASEPOINT_NEGATED_COMPRESSED, EDWARDS_IDENTITY_COMPRESSED,
            PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
        },
        error::Ed25519VerifyError,
        points::{
            compute_challenge_into, is_small_order_canonical, is_small_order_encoding,
            multiscalar_multiply_edwards_2,
        },
        scalar, VerificationCriteria,
    },
    solana_curve25519::{
        edwards::{subtract_edwards, validate_edwards, PodEdwardsPoint},
        scalar::PodScalar,
    },
};

/// Stateless, zero-allocation Ed25519 verifier.
///
/// Behavior is selected by [`VerificationCriteria`]; [`Ed25519Verifier::new`]
/// uses the [ZIP-215] preset.
///
/// [ZIP-215]: VerificationCriteria::zip215
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

    /// Verifies one Ed25519 signature against the configured criteria.
    ///
    /// Checks `S*B - H(R || A || M)*A - R == identity`, multiplied by the
    /// cofactor 8 when [`VerificationCriteria::cofactored`] is set.
    /// Canonical-encoding and small-order rejections run first.
    /// Point decompression is deferred to the verification operations, so
    /// malformed points may cost as much to reject as other invalid signatures.
    #[inline(always)]
    pub fn verify_signature(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
        message: &[u8],
    ) -> Result<(), Ed25519VerifyError> {
        self.verify_inner::<false>(signature, public_key, message, None)
    }

    #[inline(always)]
    fn verify_inner<const PREPARED: bool>(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
        message: &[u8],
        prepared_points: Option<&[PodEdwardsPoint; 2]>,
    ) -> Result<(), Ed25519VerifyError> {
        // PREPARED is only set by PreparedPublicKey, whose constructors prove
        // that A decodes and meets this verifier's public-key criteria.
        let (r_bytes, s_bytes) = signature.split_at(32);
        let r_bytes: &[u8; 32] = r_bytes.try_into().unwrap();
        let s_bytes: &[u8; 32] = s_bytes.try_into().unwrap();

        // `S < L` is enforced by the multiscalar-mul syscall, not here; see
        // `VerificationCriteria` for why there is no knob.

        // Every torsion encoding and non-canonical y has its masked final
        // byte in 0..=5 or 0x7a..=0x7f. Other encodings need no byte checks;
        // their curve validity is still enforced by the operations below.
        let check_a = public_key[31].wrapping_add(6) & 0x7f <= 11;
        let check_r = r_bytes[31].wrapping_add(6) & 0x7f <= 11;

        if !PREPARED
            && self.criteria.require_canonical_a
            && check_a
            && !scalar::is_canonical_point_encoding(public_key)
        {
            return Err(Ed25519VerifyError::NonCanonicalPublicKey);
        }
        if self.criteria.require_canonical_r
            && check_r
            && !scalar::is_canonical_point_encoding(r_bytes)
        {
            return Err(Ed25519VerifyError::NonCanonicalR);
        }

        if !PREPARED
            && self.criteria.reject_small_order_a
            && check_a
            && is_small_order_encoding(public_key)
        {
            return Err(Ed25519VerifyError::SmallOrderPublicKey);
        }
        if self.criteria.reject_small_order_r && check_r && is_small_order_encoding(r_bytes) {
            // Preserve the error precedence of validating A before checking R.
            // Other A encodings are validated by the MSM below.
            if !PREPARED
                && self.criteria.reject_small_order_a
                && !validate_edwards(&PodEdwardsPoint(*public_key))
            {
                return Err(Ed25519VerifyError::InvalidEncoding);
            }
            return Err(Ed25519VerifyError::SmallOrderR);
        }

        let mut scalars = [PodScalar(*s_bytes), PodScalar([0u8; 32])];
        compute_challenge_into(r_bytes, public_key, message, &mut scalars[1].0);

        // `S*(-B) + H*A` is `-(S*B - H*A)`, the negation of the value the
        // verification equation compares against `R`.
        let points;
        let points = match prepared_points {
            Some(points) => points,
            None => {
                points = [
                    ED25519_BASEPOINT_NEGATED_COMPRESSED,
                    PodEdwardsPoint(*public_key),
                ];
                &points
            }
        };
        let neg_lhs = multiscalar_multiply_edwards_2(&scalars, points)
            .ok_or(Ed25519VerifyError::InvalidEncoding)?;

        // Flipping the sign bit recovers the left-hand side's encoding.
        // `neg_lhs` is canonical, so the flip is too — except at `x = 0`, where
        // it yields negative zero, which can only miss, never falsely match. A
        // byte match also proves R is a valid point and implies `R == lhs`,
        // satisfying both equations without a separate curve operation.
        let mut lhs_bytes = neg_lhs.0;
        lhs_bytes[31] ^= 0x80;
        if lhs_bytes == *r_bytes {
            return Ok(());
        }

        if !self.criteria.cofactored
            && self.criteria.require_canonical_r
            && self.criteria.reject_small_order_r
        {
            // Non-small-order points have unique canonical encodings. The
            // byte mismatch rules out equality; only R's validity is unknown.
            return if validate_edwards(&PodEdwardsPoint(*r_bytes)) {
                Err(Ed25519VerifyError::SignatureMismatch)
            } else {
                Err(Ed25519VerifyError::InvalidEncoding)
            };
        }

        let lhs = PodEdwardsPoint(lhs_bytes);
        let r_point = PodEdwardsPoint(*r_bytes);
        // `lhs` is valid by construction, so a `None` here means `r_point`,
        // built from caller-supplied bytes, failed to decode.
        let difference =
            subtract_edwards(&lhs, &r_point).ok_or(Ed25519VerifyError::InvalidEncoding)?;

        // Exact identity satisfies both equations, so accept before performing
        // the torsion lookup.
        if difference == EDWARDS_IDENTITY_COMPRESSED {
            return Ok(());
        }
        // Cofactorless requires exact identity, now ruled out; cofactored also
        // accepts a difference that clears to identity under multiplication by
        // 8 — the mixed-order points ZIP-215 tolerates.
        if !self.criteria.cofactored {
            return Err(Ed25519VerifyError::SignatureMismatch);
        }
        // Subtraction produces a valid, canonical encoding.
        // Its cofactor multiple is identity exactly when it is a torsion point.
        if !is_small_order_canonical(&difference) {
            return Err(Ed25519VerifyError::SignatureMismatch);
        }

        Ok(())
    }
}

/// An owned public key validated for a fixed set of verification criteria.
///
/// Construct through [`Ed25519Verifier::verify_and_prepare`] to reuse validation
/// from a successful signature, or [`Ed25519Verifier::prepare_public_key`] to
/// validate the key separately. Subsequent signatures reuse the encoded points
/// passed to the curve syscall and skip the public-key policy checks. Each
/// signature still requires hashing, scalar reduction, and a curve syscall.
/// Preparation adds overhead, so use this when verifying several signatures
/// with the same key. The standalone program continues to verify one signature
/// at a time through [`Ed25519Verifier::verify_signature`].
///
/// The original public-key bytes are preserved for hashing, including any
/// non-canonical encoding permitted by the criteria. The key and criteria
/// cannot be changed after preparation.
///
/// ```
/// use solana_ed25519_verify::{Ed25519Verifier, Ed25519VerifyError, VerificationCriteria};
/// # fn example(public_key: &[u8; 32], first_signature: &[u8; 64], first_message: &[u8],
/// # next_signature: &[u8; 64], next_message: &[u8]) -> Result<(), Ed25519VerifyError> {
/// let verifier = Ed25519Verifier::with_criteria(VerificationCriteria::dalek_verify_strict());
/// let prepared = verifier.verify_and_prepare(first_signature, public_key, first_message)?;
/// prepared.verify_signature(next_signature, next_message)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
// Word alignment reduces the cost of returning the cache on SBF.
#[repr(align(8))]
pub struct PreparedPublicKey {
    verifier: Ed25519Verifier,
    points: [PodEdwardsPoint; 2],
}

impl Ed25519Verifier {
    /// Validates a public key once for repeated verification with these criteria.
    ///
    /// Rejects a non-canonical or small-order key when the corresponding
    /// criterion is enabled, and always rejects an invalid curve encoding.
    /// This performs a separate point-validation syscall on SBF. When a first
    /// signature is available, [`Self::verify_and_prepare`] avoids that syscall
    /// by obtaining the same guarantees from successful signature verification.
    #[inline(always)]
    pub fn prepare_public_key(
        &self,
        public_key: &[u8; 32],
    ) -> Result<PreparedPublicKey, Ed25519VerifyError> {
        let check_a = public_key[31].wrapping_add(6) & 0x7f <= 11;
        if self.criteria.require_canonical_a
            && check_a
            && !scalar::is_canonical_point_encoding(public_key)
        {
            return Err(Ed25519VerifyError::NonCanonicalPublicKey);
        }
        if self.criteria.reject_small_order_a && check_a && is_small_order_encoding(public_key) {
            return Err(Ed25519VerifyError::SmallOrderPublicKey);
        }
        if !validate_edwards(&PodEdwardsPoint(*public_key)) {
            return Err(Ed25519VerifyError::InvalidEncoding);
        }
        Ok(PreparedPublicKey {
            verifier: *self,
            points: [
                ED25519_BASEPOINT_NEGATED_COMPRESSED,
                PodEdwardsPoint(*public_key),
            ],
        })
    }

    /// Verifies a signature and prepares its public key for further signatures.
    ///
    /// Returns the same errors as [`Self::verify_signature`]. A successful
    /// result certifies this signature and binds the returned key to these
    /// criteria without a separate point-validation syscall.
    #[inline(always)]
    pub fn verify_and_prepare(
        &self,
        signature: &[u8; 64],
        public_key: &[u8; 32],
        message: &[u8],
    ) -> Result<PreparedPublicKey, Ed25519VerifyError> {
        self.verify_signature(signature, public_key, message)?;
        Ok(PreparedPublicKey {
            verifier: *self,
            points: [
                ED25519_BASEPOINT_NEGATED_COMPRESSED,
                PodEdwardsPoint(*public_key),
            ],
        })
    }
}

impl PreparedPublicKey {
    /// Returns the original compressed public-key encoding used for hashing.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.points[1].0
    }

    /// Returns the criteria used both during preparation and verification.
    pub const fn criteria(&self) -> VerificationCriteria {
        self.verifier.criteria()
    }

    /// Verifies another signature with the prepared key and its fixed criteria.
    ///
    /// For a successfully prepared key, this returns the same result as
    /// [`Ed25519Verifier::verify_signature`] with the original key and criteria.
    #[inline(always)]
    pub fn verify_signature(
        &self,
        signature: &[u8; 64],
        message: &[u8],
    ) -> Result<(), Ed25519VerifyError> {
        self.verifier
            .verify_inner::<true>(signature, self.as_bytes(), message, Some(&self.points))
    }
}
