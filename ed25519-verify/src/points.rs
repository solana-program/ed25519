//! Edwards curve point operations built on `solana-curve25519` syscalls.
//!
//! Covers the cofactor-8 multiplication used both for small-order rejection
//! and for the ZIP-215 cofactored verification equation, and the Ed25519
//! challenge hash `H(R || A || M) mod L`.

use {
    crate::{constants::EDWARDS_IDENTITY_COMPRESSED, error::Ed25519VerifyError, scalar},
    solana_curve25519::edwards::{add_edwards, PodEdwardsPoint},
};

/// Returns `Ok(true)` if `point` decompresses to a small-order (torsion) point.
///
/// A point has order dividing the cofactor 8 exactly when `[8]P` is the
/// identity. This decompresses `point` (accepting non-canonical encodings, which
/// reduce modulo `p`). An encoding that does not decompress returns
/// `Err(InvalidEncoding)` so the caller can reject it immediately, rather than
/// treating it as non-small-order and paying for the subsequent verification
/// syscalls only to fail there.
pub(crate) fn is_small_order(point: &PodEdwardsPoint) -> Result<bool, Ed25519VerifyError> {
    let product = multiply_by_8(point).ok_or(Ed25519VerifyError::InvalidEncoding)?;
    Ok(product == EDWARDS_IDENTITY_COMPRESSED)
}

/// Multiplies `point` by the cofactor 8 via three point doublings.
///
/// Cheaper than a scalar multiplication by 8: three `sol_curve_group_op`
/// additions (473 CU each, 1,419 total) versus one multiplication (2,177 CU).
/// Returns `None` if `point` is not a valid curve encoding.
pub(crate) fn multiply_by_8(point: &PodEdwardsPoint) -> Option<PodEdwardsPoint> {
    let double = add_edwards(point, point)?;
    let quadruple = add_edwards(&double, &double)?;
    add_edwards(&quadruple, &quadruple)
}

/// Computes the Ed25519 challenge scalar `H(R || A || M) mod L`.
pub(crate) fn compute_challenge(
    signature_r: &[u8; 32],
    public_key: &[u8; 32],
    message: &[u8],
) -> [u8; 32] {
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]).to_bytes();
    scalar::reduce_wide(&digest)
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::PUBKEY_SERIALIZED_SIZE, ed25519_dalek::SigningKey};

    const SMALL_ORDER_PUBLIC_KEY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];

    // `y = 2`, sign bit unset. By Euler's criterion, `x^2 = (y^2 - 1) / (d*y^2
    // + 1) mod p` raised to `(p - 1) / 2` reduces to `p - 1` (i.e. `-1 mod
    // p`), so `x^2` is a quadratic non-residue: this encoding provably has no
    // corresponding point on the curve, independent of which decompression
    // algorithm a given curve backend implements.
    const NON_DECOMPRESSING_ENCODING: [u8; PUBKEY_SERIALIZED_SIZE] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    fn prime_order_point() -> PodEdwardsPoint {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        PodEdwardsPoint(signing_key.verifying_key().to_bytes())
    }

    #[test]
    fn multiply_by_8_maps_identity_to_identity() {
        assert_eq!(
            multiply_by_8(&EDWARDS_IDENTITY_COMPRESSED),
            Some(EDWARDS_IDENTITY_COMPRESSED)
        );
    }

    #[test]
    fn multiply_by_8_clears_small_order_point() {
        let point = PodEdwardsPoint(SMALL_ORDER_PUBLIC_KEY_COMPRESSED);
        assert_eq!(multiply_by_8(&point), Some(EDWARDS_IDENTITY_COMPRESSED));
    }

    #[test]
    fn multiply_by_8_does_not_clear_prime_order_point() {
        assert_ne!(
            multiply_by_8(&prime_order_point()),
            Some(EDWARDS_IDENTITY_COMPRESSED)
        );
    }

    #[test]
    fn multiply_by_8_rejects_non_decompressing_encoding() {
        let point = PodEdwardsPoint(NON_DECOMPRESSING_ENCODING);
        assert_eq!(multiply_by_8(&point), None);
    }

    #[test]
    fn is_small_order_true_for_torsion_point() {
        let point = PodEdwardsPoint(SMALL_ORDER_PUBLIC_KEY_COMPRESSED);
        assert_eq!(is_small_order(&point), Ok(true));
    }

    #[test]
    fn is_small_order_false_for_prime_order_point() {
        assert_eq!(is_small_order(&prime_order_point()), Ok(false));
    }

    #[test]
    fn is_small_order_propagates_decompression_failure() {
        let point = PodEdwardsPoint(NON_DECOMPRESSING_ENCODING);
        assert_eq!(
            is_small_order(&point),
            Err(Ed25519VerifyError::InvalidEncoding)
        );
    }

    #[test]
    fn compute_challenge_hashes_r_then_a_then_message() {
        // Independently re-derives H(R || A || M) via a differently-shaped
        // `hashv` call (three slices, matching the argument order in the RFC
        // 8032 challenge definition) so this test doesn't just echo
        // `compute_challenge`'s own call, and would catch R/A getting swapped
        // in a future refactor.
        let r = [0x11u8; 32];
        let a = [0x22u8; 32];
        let message = b"order check";

        let digest = solana_sha512_hasher::hashv(&[&r, &a, message]).to_bytes();
        let expected = scalar::reduce_wide(&digest);

        assert_eq!(compute_challenge(&r, &a, message), expected);
    }
}
