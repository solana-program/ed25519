//! Configurable Ed25519 verification criteria.
//!
//! Ed25519 "signature validity" is not a single definition: implementations
//! differ on cofactored vs. cofactorless verification, whether non-canonical
//! point encodings are accepted, and whether small-order points are rejected.
//! These divergences are catalogued in Henry de Valence's
//! ["It's 255:19AM. Do you know what your validation criteria are?"][blog].
//!
//! [`VerificationCriteria`] exposes those divergences as independent knobs so a
//! caller can select the exact variant they need. Two named presets ship today —
//! [`zip215`] (the [ZIP-215] criteria specified by [SIMD-0376]) and
//! [`dalek_verify_strict`] — and the knobs are designed so that other well-known
//! profiles (e.g. libsodium, RFC 8032 / FIPS 186-5) can be added as presets in
//! follow-ups without changing the verifier.
//!
//! [blog]: https://hdevalence.ca/blog/2020-10-04-its-25519am/
//! [ZIP-215]: https://zips.z.cash/zip-0215
//! [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
//! [`zip215`]: VerificationCriteria::zip215
//! [`dalek_verify_strict`]: VerificationCriteria::dalek_verify_strict

/// Independent Ed25519 validation knobs.
///
/// Each field toggles one decision point from the "255:19AM" taxonomy. Fields
/// are public so callers can compose arbitrary combinations, typically by
/// starting from a preset and overriding a single knob:
///
/// ```
/// use solana_ed25519_verify::VerificationCriteria;
///
/// let custom = VerificationCriteria {
///     reject_small_order_a: true,
///     ..VerificationCriteria::zip215()
/// };
/// ```
///
/// Canonical `S` (`S < L`) has no corresponding field. Every profile worth
/// targeting requires it — accepting `S >= L` reintroduces signature
/// malleability — and the multiscalar-mul syscall enforces it regardless,
/// converting scalars through `Scalar::from_canonical_bytes` and rejecting
/// out-of-range values before any group operation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationCriteria {
    /// Use the cofactored verification equation
    /// `[8](S·B − H·A − R) == identity`.
    ///
    /// When `false`, the difference must be the identity.
    /// When `true`, any torsion difference is accepted, using a lookup of
    /// its canonical compressed encoding.
    pub cofactored: bool,
    /// Reject public keys whose compressed `y`-coordinate is `>= p` (a
    /// non-canonical encoding of a reduced point).
    pub require_canonical_a: bool,
    /// Reject signature `R` values whose compressed `y`-coordinate is `>= p`.
    pub require_canonical_r: bool,
    /// Reject public keys that lie in the small-order (torsion) subgroup.
    ///
    /// Checks the compressed encoding, including non-canonical aliases.
    /// Point validity is enforced by the curve operations during verification.
    pub reject_small_order_a: bool,
    /// Reject signature `R` values that lie in the small-order subgroup.
    ///
    /// Checks the compressed encoding, including non-canonical aliases.
    /// Point validity is enforced by the verification equation or, on a byte
    /// mismatch, a curve operation.
    pub reject_small_order_r: bool,
}

impl VerificationCriteria {
    /// [ZIP-215] verification, as specified for Solana by [SIMD-0376].
    ///
    /// Cofactored equation; non-canonical point encodings and small-order
    /// points are accepted (cofactor multiplication makes them
    /// indistinguishable from the identity contribution). This is backward
    /// compatible with `ed25519_dalek::verify_strict`: every signature
    /// dalek accepts is accepted here.
    ///
    /// [ZIP-215]: https://zips.z.cash/zip-0215
    /// [SIMD-0376]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0376-verify-strict.md
    pub const fn zip215() -> Self {
        Self {
            cofactored: true,
            require_canonical_a: false,
            require_canonical_r: false,
            reject_small_order_a: false,
            reject_small_order_r: false,
        }
    }

    /// The criteria enforced by `ed25519_dalek::VerifyingKey::verify_strict`.
    ///
    /// Cofactorless, with canonical `R` and small-order rejection for both `A`
    /// and `R`. Note that a non-canonically encoded `A` is *not* rejected:
    /// dalek's `VerifyingKey::from_bytes` decompresses `A` (reducing `y` modulo
    /// `p`) without a canonicity check, and `verify_strict` only re-encodes and
    /// compares `R`. The match is exact in both directions, cross-checked in
    /// the test suite.
    pub const fn dalek_verify_strict() -> Self {
        Self {
            cofactored: false,
            require_canonical_a: false,
            require_canonical_r: true,
            reject_small_order_a: true,
            reject_small_order_r: true,
        }
    }
}
