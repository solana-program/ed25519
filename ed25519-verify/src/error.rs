/// Errors that can occur during Ed25519 signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519VerifyError {
    /// The public key `A` is not a canonical compressed Edwards point
    /// encoding (its `y`-coordinate is `>= p`).
    ///
    /// Only returned when [`require_canonical_a`] is enabled.
    ///
    /// [`require_canonical_a`]: crate::VerificationCriteria::require_canonical_a
    NonCanonicalPublicKey,
    /// The signature component `R` is not a canonical compressed Edwards
    /// point encoding (its `y`-coordinate is `>= p`).
    ///
    /// Only returned when [`require_canonical_r`] is enabled.
    ///
    /// [`require_canonical_r`]: crate::VerificationCriteria::require_canonical_r
    NonCanonicalR,
    /// The public key `A` lies in the small-order (torsion) subgroup.
    ///
    /// Only returned when [`reject_small_order_a`] is enabled.
    ///
    /// [`reject_small_order_a`]: crate::VerificationCriteria::reject_small_order_a
    SmallOrderPublicKey,
    /// The signature component `R` lies in the small-order (torsion)
    /// subgroup.
    ///
    /// Only returned when [`reject_small_order_r`] is enabled.
    ///
    /// [`reject_small_order_r`]: crate::VerificationCriteria::reject_small_order_r
    SmallOrderR,
    /// The public key or signature's `R` does not decode to a valid Edwards
    /// curve point, or the signature's `S` scalar is not canonical (`S >= L`).
    ///
    /// Individual verification lets the curve syscall check `A` and `S`
    /// together. Batch verification checks the original `S` before aggregation.
    /// Both report the same error for invalid scalar or point encodings.
    InvalidEncoding,
    /// The public key, signature, and message all decoded successfully, but
    /// the signature does not satisfy the verification equation.
    SignatureMismatch,
}
