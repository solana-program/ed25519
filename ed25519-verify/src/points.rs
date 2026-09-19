//! Edwards curve point operations built on `solana-curve25519` syscalls.
//!
//! Covers small-order checks, the ZIP-215 torsion lookup, and the Ed25519
//! challenge hash `H(R || A || M) mod L`.

use {
    crate::{constants::EDWARDS_IDENTITY_COMPRESSED, scalar},
    solana_curve25519::{edwards::PodEdwardsPoint, scalar::PodScalar},
};

#[cfg(test)]
use {crate::error::Ed25519VerifyError, solana_curve25519::edwards::add_edwards};

/// Tests whether an encoding represents a torsion point, including aliases.
///
/// This does not validate other encodings. Before accepting a signature, a
/// `false` result still requires a curve operation or a match to a known-valid
/// point encoding.
#[inline(always)]
pub(crate) fn is_small_order_encoding(bytes: &[u8; 32]) -> bool {
    const Y0: [u64; 4] = crate::constants::to_le_limbs(ORDER_EIGHT_Y0);
    const Y1: [u64; 4] = crate::constants::to_le_limbs(ORDER_EIGHT_Y1);

    let low = || u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let middle_low = || u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let middle_high = || u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let high = || u64::from_le_bytes(bytes[24..].try_into().unwrap()) & 0x7fff_ffff_ffff_ffff;

    match bytes[31] & 0x7f {
        // y = 0 or 1, with either sign bit (including negative zero).
        0x00 => low() & !1 == 0 && middle_low() == 0 && middle_high() == 0 && high() == 0,
        // The two remaining y-coordinates of the order-eight points.
        0x05 => {
            low() == Y0[0] && middle_low() == Y0[1] && middle_high() == Y0[2] && high() == Y0[3]
        }
        0x7a => {
            low() == Y1[0] && middle_low() == Y1[1] && middle_high() == Y1[2] && high() == Y1[3]
        }
        // y = p - 1, p, or p + 1. The last two alias y = 0 and 1.
        0x7f => {
            low().wrapping_add(20) <= 2
                && middle_low() == u64::MAX
                && middle_high() == u64::MAX
                && high() == 0x7fff_ffff_ffff_ffff
        }
        _ => false,
    }
}

/// Multiplies `point` by the cofactor 8 via three point doublings.
///
/// Cheaper than a scalar multiplication by 8: three `sol_curve_group_op`
/// additions (473 CU each, 1,419 total) versus one multiplication (2,177 CU).
/// Returns `None` if `point` is not a valid curve encoding.
#[cfg(test)]
pub(crate) fn multiply_by_8(point: &PodEdwardsPoint) -> Option<PodEdwardsPoint> {
    let double = add_edwards(point, point)?;
    let quadruple = add_edwards(&double, &double)?;
    add_edwards(&quadruple, &quadruple)
}

/// Computes the Ed25519 challenge scalar `H(R || A || M) mod L`.
pub(crate) fn compute_challenge_into(
    signature_r: &[u8; 32],
    public_key: &[u8; 32],
    message: &[u8],
    challenge: &mut [u8; 32],
) {
    // Borrow the digest to avoid a 64-byte copy before reduction on SBF.
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]);
    scalar::reduce_wide_into(digest.as_bytes(), challenge);
}

#[cfg(test)]
pub(crate) fn compute_challenge(
    signature_r: &[u8; 32],
    public_key: &[u8; 32],
    message: &[u8],
) -> [u8; 32] {
    let mut challenge = [0u8; 32];
    compute_challenge_into(signature_r, public_key, message, &mut challenge);
    challenge
}

// The two y-coordinates of order-eight points, with the sign bit cleared.
const ORDER_EIGHT_Y0: [u8; 32] = [
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
];
const ORDER_EIGHT_Y1: [u8; 32] = [
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
];

/// Tests torsion membership for a valid, canonical curve encoding.
///
/// Use only with canonical encodings returned by successful curve operations.
#[inline(never)]
pub(crate) fn is_small_order_canonical(point: &PodEdwardsPoint) -> bool {
    const ORDER_TWO_Y: [u8; 32] = {
        let mut y = [0xff; 32];
        y[0] = 0xec;
        y[31] = 0x7f;
        y
    };

    let mut y = point.0;
    y[31] &= 0x7f;
    y == [0u8; 32]
        || y == EDWARDS_IDENTITY_COMPRESSED.0
        || y == ORDER_TWO_Y
        || y == ORDER_EIGHT_Y0
        || y == ORDER_EIGHT_Y1
}

/// Computes an Edwards MSM with exactly two scalar-point pairs.
#[inline(always)]
pub(crate) fn multiscalar_multiply_edwards_2(
    scalars: &[PodScalar; 2],
    points: &[PodEdwardsPoint; 2],
) -> Option<PodEdwardsPoint> {
    #[cfg(not(target_os = "solana"))]
    {
        solana_curve25519::edwards::multiscalar_multiply_edwards(scalars, points)
    }

    #[cfg(target_os = "solana")]
    {
        use {
            core::mem::MaybeUninit, solana_define_syscall::definitions::sol_curve_multiscalar_mul,
        };

        // Edwards25519 selector in Solana's curve syscall ABI.
        const CURVE25519_EDWARDS: u64 = 0;

        let mut output = MaybeUninit::<PodEdwardsPoint>::uninit();

        // SAFETY: Both input arrays contain exactly two contiguous POD
        // encodings. The output has space for one encoded point and does
        // not overlap either input. The syscall validates the encodings.
        let status = unsafe {
            sol_curve_multiscalar_mul(
                CURVE25519_EDWARDS,
                scalars.as_ptr().cast::<u8>(),
                points.as_ptr().cast::<u8>(),
                2,
                output.as_mut_ptr().cast::<u8>(),
            )
        };

        if status != 0 {
            return None;
        }

        // SAFETY: A successful syscall writes the complete output point.
        Some(unsafe { output.assume_init() })
    }
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

    #[test]
    fn canonical_torsion_lookup_matches_dalek() {
        use curve25519_dalek::{
            constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
            scalar::Scalar,
        };

        for i in 0..16u64 {
            let prime = ED25519_BASEPOINT_POINT * Scalar::from(i);
            for torsion in &EIGHT_TORSION {
                let point = prime + torsion;
                let encoded = PodEdwardsPoint(point.compress().to_bytes());
                assert_eq!(
                    is_small_order_canonical(&encoded),
                    point.is_small_order(),
                    "prime scalar={i}"
                );
            }
        }
    }

    #[test]
    fn cofactorless_rejects_nonidentity_torsion_differences() {
        let verifier = crate::Ed25519Verifier::with_criteria(crate::VerificationCriteria {
            cofactored: false,
            ..crate::VerificationCriteria::zip215()
        });
        let public_key = EDWARDS_IDENTITY_COMPRESSED.0;

        for torsion in &curve25519_dalek::constants::EIGHT_TORSION {
            let r = torsion.compress().to_bytes();
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r);
            let expected = if r == public_key {
                Ok(())
            } else {
                Err(Ed25519VerifyError::SignatureMismatch)
            };
            assert_eq!(
                verifier.verify_signature(&signature, &public_key, b"cofactorless torsion"),
                expected
            );
        }
    }

    #[test]
    fn encoded_torsion_lookup_matches_dalek() {
        use curve25519_dalek::{
            constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
            edwards::CompressedEdwardsY,
            scalar::Scalar,
        };

        let check = |encoding: [u8; 32]| {
            let expected = CompressedEdwardsY(encoding)
                .decompress()
                .is_some_and(|point| point.is_small_order());
            assert_eq!(
                is_small_order_encoding(&encoding),
                expected,
                "encoding={encoding:02x?}"
            );
        };

        for i in 0..16u64 {
            let prime = ED25519_BASEPOINT_POINT * Scalar::from(i);
            for torsion in EIGHT_TORSION {
                check((prime + torsion).compress().to_bytes());
            }
        }

        let mut torsion_encodings = [[0u8; 32]; 14];
        for (encoding, point) in torsion_encodings[..8].iter_mut().zip(EIGHT_TORSION) {
            *encoding = point.compress().to_bytes();
        }
        let mut aliases = 8;
        for sign in [0u8, 0x80] {
            for y in 0..19u8 {
                let mut reduced = [0u8; 32];
                reduced[0] = y;
                reduced[31] = sign;
                check(reduced);

                let mut alias = [0xffu8; 32];
                alias[0] = 0xed + y;
                alias[31] = 0x7f | sign;
                check(alias);
                if y < 2 {
                    torsion_encodings[aliases] = alias;
                    aliases += 1;
                }
            }
        }
        let mut negative_identity = EDWARDS_IDENTITY_COMPRESSED.0;
        negative_identity[31] = 0x80;
        torsion_encodings[12] = negative_identity;
        let mut negative_order_two = [0xffu8; 32];
        negative_order_two[0] = 0xec;
        torsion_encodings[13] = negative_order_two;

        // Check all 14 encodings and every one-bit neighbor. This catches
        // accidentally omitting a byte or ignoring an extra bit in a lookup.
        for encoding in torsion_encodings {
            assert!(is_small_order_encoding(&encoding));
            for bit in 0..256 {
                let mut neighbor = encoding;
                neighbor[bit / 8] ^= 1 << (bit % 8);
                check(neighbor);
            }
        }
    }
}
