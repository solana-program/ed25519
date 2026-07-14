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
//! [`zip215`] (this crate's historical default) and [`dalek_verify_strict`] — and
//! the knobs are designed so that other well-known profiles (e.g. libsodium,
//! RFC 8032 / FIPS 186-5) can be added as presets in follow-ups without changing
//! the verifier.
//!
//! [blog]: https://hdevalence.ca/blog/2020-10-04-its-25519am/
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
/// let strict_s = VerificationCriteria {
///     reject_small_order_a: true,
///     ..VerificationCriteria::zip215()
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationCriteria {
    /// Use the cofactored verification equation `[8](S·B − H·A) == [8]R`.
    ///
    /// When `false`, the cofactorless equation `S·B − H·A == R` is used, which
    /// rejects mixed-order points that the cofactored equation tolerates. The
    /// cofactored form costs one extra `sol_curve_group_op` syscall.
    pub cofactored: bool,
    /// Reject public keys whose compressed `y`-coordinate is `>= p` (a
    /// non-canonical encoding of a reduced point).
    pub require_canonical_a: bool,
    /// Reject signature `R` values whose compressed `y`-coordinate is `>= p`.
    pub require_canonical_r: bool,
    /// Reject public keys that lie in the small-order (torsion) subgroup.
    ///
    /// Costs one `sol_curve_group_op` syscall when enabled.
    pub reject_small_order_a: bool,
    /// Reject signature `R` values that lie in the small-order subgroup.
    ///
    /// Costs one `sol_curve_group_op` syscall when enabled.
    pub reject_small_order_r: bool,
    /// Reject signatures whose scalar `S` is not in canonical `[0, L)` form.
    pub require_canonical_s: bool,
}

impl VerificationCriteria {
    /// [ZIP-215] verification: the historical default of this crate.
    ///
    /// Cofactored equation with a canonical `S` requirement; non-canonical point
    /// encodings and small-order points are accepted (cofactor multiplication
    /// makes them indistinguishable from the identity contribution). This is
    /// backward compatible with `ed25519_dalek::verify_strict`: every signature
    /// dalek accepts is accepted here.
    ///
    /// [ZIP-215]: https://zips.z.cash/zip-0215
    pub const fn zip215() -> Self {
        Self {
            cofactored: true,
            require_canonical_a: false,
            require_canonical_r: false,
            reject_small_order_a: false,
            reject_small_order_r: false,
            require_canonical_s: true,
        }
    }

    /// The criteria enforced by `ed25519_dalek::VerifyingKey::verify_strict`.
    ///
    /// Cofactorless verification with canonical `S`, canonical `R`, and
    /// small-order rejection for both `A` and `R`. Mirrors ed25519-dalek 2.x
    /// exactly, including the detail that a non-canonically encoded public key
    /// `A` is *not* rejected — dalek's `VerifyingKey::from_bytes` decompresses
    /// `A` (reducing `y` modulo `p`) without a canonicity check, and
    /// `verify_strict` only re-encodes and compares `R`. Every signature this
    /// preset accepts is accepted by dalek's `verify_strict`, and vice versa.
    pub const fn dalek_verify_strict() -> Self {
        Self {
            cofactored: false,
            require_canonical_a: false,
            require_canonical_r: true,
            reject_small_order_a: true,
            reject_small_order_r: true,
            require_canonical_s: true,
        }
    }
}

impl Default for VerificationCriteria {
    fn default() -> Self {
        Self::zip215()
    }
}

/// A named verification preset selectable on-chain via the program's leading
/// instruction-data byte.
///
/// This is a discrete, forward-compatible selector over the shipped presets, as
/// opposed to [`VerificationCriteria`], which exposes every individual knob. The
/// client constructor ([`ed25519_verify_instruction`]) writes [`to_byte`] and
/// the program decodes it with [`from_byte`].
///
/// [`ed25519_verify_instruction`]: crate::ed25519_verify_instruction
/// [`to_byte`]: VerificationVariant::to_byte
/// [`from_byte`]: VerificationVariant::from_byte
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerificationVariant {
    /// [`VerificationCriteria::zip215`] — the default.
    Zip215 = 0,
    /// [`VerificationCriteria::dalek_verify_strict`].
    DalekVerifyStrict = 1,
}

impl VerificationVariant {
    /// Decodes the instruction-data selector byte, or `None` if unrecognized.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Zip215),
            1 => Some(Self::DalekVerifyStrict),
            _ => None,
        }
    }

    /// Returns the selector byte for this variant.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns the [`VerificationCriteria`] this variant selects.
    pub const fn criteria(self) -> VerificationCriteria {
        match self {
            Self::Zip215 => VerificationCriteria::zip215(),
            Self::DalekVerifyStrict => VerificationCriteria::dalek_verify_strict(),
        }
    }
}
