//! Cryptographic constants for the Ed25519 curve and signatures.

use solana_curve25519::edwards::PodEdwardsPoint;

/// The byte length of a serialized Ed25519 public key (compressed Edwards
/// point).
pub const PUBKEY_SERIALIZED_SIZE: usize = 32;

/// The byte length of a serialized Ed25519 signature (`R || S`).
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;

/// Group order of the ed25519 base point in little-endian form:
/// `2^252 + 27742317777372353535851937790883648493`.
pub(crate) const BASEPOINT_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Reinterprets a 32-byte little-endian integer as four little-endian 64-bit
/// limbs.
///
/// Evaluated at compile time so that limb constants are derived from their byte
/// counterparts rather than transcribed by hand a second time.
pub(crate) const fn to_le_limbs(bytes: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    let mut limb_index = 0;

    while limb_index < 4 {
        let mut limb = 0u64;
        let mut byte_index = 0;
        while byte_index < 8 {
            limb |= (bytes[limb_index * 8 + byte_index] as u64) << (byte_index * 8);
            byte_index += 1;
        }
        limbs[limb_index] = limb;
        limb_index += 1;
    }

    limbs
}

/// [`BASEPOINT_ORDER`] as little-endian 64-bit limbs.
///
/// Used by the limb-wise reduction in [`crate::scalar`], where a 64-bit borrow
/// chain replaces a byte-wise one.
pub(crate) const BASEPOINT_ORDER_LIMBS: [u64; 4] = to_le_limbs(BASEPOINT_ORDER);

/// Field modulus `p = 2^255 - 19` in little-endian form.
pub(crate) const FIELD_MODULUS: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The Ed25519 base point `B`, negated and compressed.
///
/// Used by [`crate::verifier`] to compute `S*(-B) + H*A`, the negation of the
/// verification equation's left-hand side, in a single
/// `multiscalar_multiply_edwards` call.
pub(crate) const ED25519_BASEPOINT_NEGATED_COMPRESSED: PodEdwardsPoint = PodEdwardsPoint([
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6,
]);

/// Identity point of the Edwards curve, in compressed form.
pub(crate) const EDWARDS_IDENTITY_COMPRESSED_BYTES: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// [`EDWARDS_IDENTITY_COMPRESSED_BYTES`], wrapped as a curve point for direct
/// use in `solana-curve25519` calls.
pub(crate) const EDWARDS_IDENTITY_COMPRESSED: PodEdwardsPoint =
    PodEdwardsPoint(EDWARDS_IDENTITY_COMPRESSED_BYTES);

#[cfg(test)]
mod tests {
    use {
        super::*,
        curve25519_dalek::{scalar::Scalar, traits::Identity},
    };

    // These constants are hand-transcribed byte literals with no compiler check
    // that they encode what the doc comments claim. Cross-checking them against
    // `curve25519-dalek` (an independent implementation, not just a second copy
    // of the same literal) catches a transcription error immediately instead of
    // relying on review.

    #[test]
    fn negated_basepoint_constant_matches_curve25519_dalek() {
        let mut expected = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        // Negating a compressed Edwards point flips only the sign bit of `x`,
        // stored in the top bit of the last byte; the `y`-coordinate bytes are
        // unchanged.
        expected[31] ^= 0x80;

        assert_eq!(ED25519_BASEPOINT_NEGATED_COMPRESSED.0, expected);
    }

    #[test]
    fn identity_constant_matches_curve25519_dalek() {
        let expected = curve25519_dalek::edwards::EdwardsPoint::identity()
            .compress()
            .to_bytes();

        assert_eq!(EDWARDS_IDENTITY_COMPRESSED_BYTES, expected);
    }

    #[test]
    fn basepoint_order_matches_curve25519_dalek() {
        // dalek does not export `L` directly, but `from_canonical_bytes` accepts
        // exactly the values below it. `L - 1` being accepted and `L` itself
        // being rejected pins the constant to dalek's group order.
        let mut order_minus_one = BASEPOINT_ORDER;
        order_minus_one[0] -= 1;

        assert!(Scalar::from_canonical_bytes(order_minus_one)
            .into_option()
            .is_some());
        assert!(Scalar::from_canonical_bytes(BASEPOINT_ORDER)
            .into_option()
            .is_none());
    }

    #[test]
    fn basepoint_order_limbs_round_trip_to_bytes() {
        // Rebuilds the byte constant from the limbs using `to_le_bytes` rather
        // than the shift loop in `to_le_limbs`, so the two directions are not
        // the same code checked against itself.
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(BASEPOINT_ORDER_LIMBS) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }

        assert_eq!(bytes, BASEPOINT_ORDER);
    }
}
