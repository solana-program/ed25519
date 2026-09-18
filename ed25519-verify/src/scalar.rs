//! Small scalar- and field-element helpers needed to assemble Ed25519
//! verification around syscalls.

use crate::constants::{BASEPOINT_ORDER_LIMBS, FIELD_MODULUS};

/// Returns `true` if `encoding` is a canonical compressed Edwards point.
///
/// A compressed point stores the `y`-coordinate in the low 255 bits and the
/// sign of `x` in the top bit. An encoding is canonical when the masked
/// `y`-coordinate is a reduced field element (`y < p`). Non-canonical encodings
/// (`y >= p`) still decompress — they reduce modulo `p` first — but represent a
/// point with an alternative, non-reduced serialization.
pub(crate) fn is_canonical_point_encoding(encoding: &[u8; 32]) -> bool {
    let mut y = *encoding;
    y[31] &= 0x7f;
    cmp_le(&y, &FIELD_MODULUS).is_lt()
}

// Share the carry/fold schedule between full and bounded decoders. Expanding
// in place lets the SBF compiler eliminate known-zero limbs without copying
// a temporary array into a helper.
macro_rules! reduce_limbs {
    ($limbs:ident, $reduced:ident) => {{
        #[inline(always)]
        fn fold($limbs: &mut [i64; 24], index: usize) {
            // The radix-2^21 expansion of -c.
            const COEFFICIENTS: [i64; 6] = [666643, 470296, 654183, -997805, 136657, -683901];

            let high = $limbs[index];
            $limbs[index] = 0;
            for (j, &coefficient) in COEFFICIENTS.iter().enumerate() {
                $limbs[index - 12 + j] += high * coefficient;
            }
        }

        // Fold the highest six limbs before propagating their carries.
        fold(&mut $limbs, 23);
        fold(&mut $limbs, 22);
        fold(&mut $limbs, 21);
        fold(&mut $limbs, 20);
        fold(&mut $limbs, 19);
        fold(&mut $limbs, 18);

        // Normalize limbs 7..16 before the next folds. Limb 6 can wait for the
        // full carry pass below; every folding intermediate stays below 2^49
        // in magnitude without carrying it here.
        for i in 7..17 {
            let carry = $limbs[i] >> 21;
            $limbs[i] &= 0x1f_ffff;
            $limbs[i + 1] += carry;
        }

        fold(&mut $limbs, 17);
        fold(&mut $limbs, 16);
        fold(&mut $limbs, 15);
        fold(&mut $limbs, 14);
        fold(&mut $limbs, 13);
        fold(&mut $limbs, 12);

        for i in 0..12 {
            let carry = $limbs[i] >> 21;
            $limbs[i] &= 0x1f_ffff;
            $limbs[i + 1] += carry;
        }

        // Here limbs[12] is in [-1, 28], and the lower twelve limbs encode
        // a value below 2^252. Folding once more gives -28*c <= r < L.
        // Since 28*c < L, a negative remainder needs exactly one addition of L.
        fold(&mut $limbs, 12);
        for i in 0..5 {
            let carry = $limbs[i] >> 21;
            $limbs[i] &= 0x1f_ffff;
            $limbs[i + 1] += carry;
        }

        let carry = $limbs[5] >> 21;
        $limbs[5] &= 0x1f_ffff;

        // The upper six limbs are still normalized. Pack their 126 bits and add
        // the carry once instead of propagating through five more radix-2^21
        // limbs. The carry is in [-10, 1], so upper is in [-10, 2^126] and fits
        // in i128. Signed shifts below preserve a negative remainder's sign.
        let upper = (i128::from($limbs[6])
            | (i128::from($limbs[7]) << 21)
            | (i128::from($limbs[8]) << 42)
            | (i128::from($limbs[9]) << 63)
            | (i128::from($limbs[10]) << 84)
            | (i128::from($limbs[11]) << 105))
            + i128::from(carry);

        // Pack r modulo 2^256. The top word retains the sign of r.
        let remainder = [
            ($limbs[0] as u64)
                | (($limbs[1] as u64) << 21)
                | (($limbs[2] as u64) << 42)
                | (($limbs[3] as u64) << 63),
            (($limbs[3] as u64) >> 1)
                | (($limbs[4] as u64) << 20)
                | (($limbs[5] as u64) << 41)
                | ((upper as u64) << 62),
            (upper >> 2) as u64,
            (upper >> 66) as u64,
        ];

        // Keep the uncommon correction out of the normal path. Passing words by
        // value avoids materializing a temporary array for the SBF call.
        #[cold]
        fn add_order_and_store(r0: u64, r1: u64, r2: u64, r3: u64, $reduced: &mut [u8; 32]) {
            let mut carry = 0u64;
            for ((chunk, limb), order) in $reduced
                .chunks_exact_mut(8)
                .zip([r0, r1, r2, r3])
                .zip(BASEPOINT_ORDER_LIMBS)
            {
                // Every order limb is below u64::MAX, so order + carry fits.
                let (limb, overflow) = limb.overflowing_add(order + carry);
                chunk.copy_from_slice(&limb.to_le_bytes());
                carry = u64::from(overflow);
            }
        }
        if (remainder[3] as i64) < 0 {
            add_order_and_store(
                remainder[0],
                remainder[1],
                remainder[2],
                remainder[3],
                $reduced,
            );
            return;
        }

        for (chunk, limb) in $reduced.chunks_exact_mut(8).zip(remainder) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
    }};
}

/// Reduces a 64-byte little-endian integer modulo the Ed25519 group order.
///
/// Uses radix `2^21` limbs and the relation `2^252 = -c (mod L)`, where
/// `L = 2^252 + c`. After folding, `-L < r < L`; adding `L` when `r` is
/// negative produces a canonical scalar.
/// This variable-time helper only handles public verification challenges.
pub(crate) fn reduce_wide_into(wide: &[u8; 64], reduced: &mut [u8; 32]) {
    // Initialize every limb at once so the SBF compiler can unroll decoding
    // without zeroing a temporary array. Keep the wider top limb here too.
    let mut limbs: [i64; 24] = core::array::from_fn(|i| {
        if i == 23 {
            // The top limb contains the remaining 29 bits.
            i64::from(u32::from_le_bytes(wide[60..64].try_into().unwrap()) >> 3)
        } else {
            let bit = i * 21;
            let byte = bit / 8;
            let word = u32::from_le_bytes(wide[byte..byte + 4].try_into().unwrap());
            i64::from((word >> (bit % 8)) & 0x1f_ffff)
        }
    });

    reduce_limbs!(limbs, reduced);
}

// A separate expansion keeps batch call sites from changing the SBF compiler
// inlining decision for the ordinary signature verifier.
pub(crate) fn reduce_batch_challenge_into(wide: &[u8; 64], reduced: &mut [u8; 32]) {
    // Initialize every limb at once so the SBF compiler can unroll decoding
    // without zeroing a temporary array. Keep the wider top limb here too.
    let mut limbs: [i64; 24] = core::array::from_fn(|i| {
        if i == 23 {
            // The top limb contains the remaining 29 bits.
            i64::from(u32::from_le_bytes(wide[60..64].try_into().unwrap()) >> 3)
        } else {
            let bit = i * 21;
            let byte = bit / 8;
            let word = u32::from_le_bytes(wide[byte..byte + 4].try_into().unwrap());
            i64::from((word >> (bit % 8)) & 0x1f_ffff)
        }
    });

    reduce_limbs!(limbs, reduced);
}

/// Reduces a batch product or sum whose bits 399..512 are zero.
///
/// Each 256-by-128-bit product is below `2^384`. Summing at most 32 of
/// them stays below `2^389`, so the batch verifier meets this bound.
/// Omitting five zero limbs avoids unnecessary decoding and folding on SBF.
pub(crate) fn reduce_batch_wide_into(wide: &[u8; 64], reduced: &mut [u8; 32]) {
    let mut limbs: [i64; 24] = [
        i64::from((u32::from_le_bytes(wide[0..4].try_into().unwrap())) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[2..6].try_into().unwrap()) >> 5) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[5..9].try_into().unwrap()) >> 2) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[7..11].try_into().unwrap()) >> 7) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[10..14].try_into().unwrap()) >> 4) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[13..17].try_into().unwrap()) >> 1) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[15..19].try_into().unwrap()) >> 6) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[18..22].try_into().unwrap()) >> 3) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[21..25].try_into().unwrap())) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[23..27].try_into().unwrap()) >> 5) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[26..30].try_into().unwrap()) >> 2) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[28..32].try_into().unwrap()) >> 7) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[31..35].try_into().unwrap()) >> 4) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[34..38].try_into().unwrap()) >> 1) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[36..40].try_into().unwrap()) >> 6) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[39..43].try_into().unwrap()) >> 3) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[42..46].try_into().unwrap())) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[44..48].try_into().unwrap()) >> 5) & 0x1f_ffff),
        i64::from((u32::from_le_bytes(wide[47..51].try_into().unwrap()) >> 2) & 0x1f_ffff),
        0,
        0,
        0,
        0,
        0,
    ];

    reduce_limbs!(limbs, reduced);
}

#[cfg(test)]
pub(crate) fn reduce_wide(wide: &[u8; 64]) -> [u8; 32] {
    let mut reduced = [0u8; 32];
    reduce_wide_into(wide, &mut reduced);
    reduced
}

pub(crate) fn cmp_le(left: &[u8; 32], right: &[u8; 32]) -> core::cmp::Ordering {
    for index in (0..4).rev() {
        let left_limb = u64::from_le_bytes(left[index * 8..index * 8 + 8].try_into().unwrap());
        let right_limb = u64::from_le_bytes(right[index * 8..index * 8 + 8].try_into().unwrap());
        match left_limb.cmp(&right_limb) {
            core::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    core::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::BASEPOINT_ORDER};

    fn wide_from_low_32(low: &[u8; 32]) -> [u8; 64] {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(low);
        wide
    }

    #[test]
    fn reduces_group_order_to_zero() {
        assert_eq!(reduce_wide(&wide_from_low_32(&BASEPOINT_ORDER)), [0; 32]);
    }

    #[test]
    fn reduces_order_boundaries() {
        // L - 1 is already reduced and must pass through unchanged.
        let mut order_minus_one = BASEPOINT_ORDER;
        order_minus_one[0] -= 1;
        assert_eq!(
            reduce_wide(&wide_from_low_32(&order_minus_one)),
            order_minus_one
        );

        // L + 1 must come back as 1.
        let mut order_plus_one = BASEPOINT_ORDER;
        order_plus_one[0] += 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(reduce_wide(&wide_from_low_32(&order_plus_one)), one);
    }

    // `reduce_wide` is hand-rolled modular arithmetic with a conditional final
    // correction, so it is cross-checked against curve25519-dalek's own wide
    // reduction rather than against a second copy of the same reasoning.
    #[test]
    fn matches_curve25519_dalek_wide_reduction() {
        let mut wide = [0u8; 64];

        for round in 0..32u32 {
            for (index, byte) in wide.iter_mut().enumerate() {
                *byte = (index as u32).wrapping_mul(31).wrapping_add(round * 7) as u8;
            }

            let expected =
                curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&wide).to_bytes();
            assert_eq!(reduce_wide(&wide), expected, "round {round}");
        }

        // Saturated input exercises the widest possible quotient.
        let saturated = [0xff; 64];
        let expected =
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&saturated).to_bytes();
        assert_eq!(reduce_wide(&saturated), expected);
    }

    #[test]
    fn matches_dalek_on_wide_reduction_boundaries_and_random_inputs() {
        fn check(wide: &[u8; 64]) {
            let expected =
                curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(wide).to_bytes();
            assert_eq!(reduce_wide(wide), expected, "wide input: {wide:02x?}");
            let mut batch = [0; 32];
            reduce_batch_challenge_into(wide, &mut batch);
            assert_eq!(batch, expected, "batch challenge: {wide:02x?}");
            let mut bounded = *wide;
            bounded[49] &= 0x7f;
            bounded[50..].fill(0);
            reduce_batch_wide_into(&bounded, &mut batch);
            assert_eq!(
                batch,
                curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&bounded).to_bytes()
            );
        }

        fn check_neighbors(wide: [u8; 64]) {
            check(&wide);

            let mut below = wide;
            for byte in &mut below {
                let (value, borrow) = byte.overflowing_sub(1);
                *byte = value;
                if !borrow {
                    break;
                }
            }
            check(&below);

            let mut above = wide;
            for byte in &mut above {
                let (value, carry) = byte.overflowing_add(1);
                *byte = value;
                if !carry {
                    break;
                }
            }
            check(&above);
        }

        check(&[0; 64]);
        check(&[0xff; 64]);

        // Powers of two and their neighbors across every bit position.
        for bit in 0..512usize {
            let mut wide = [0u8; 64];
            wide[bit / 8] = 1u8 << (bit % 8);
            check_neighbors(wide);
        }

        // L * 2^shift and its neighbors, through the highest fitting shift.
        let mut shifted_order = wide_from_low_32(&BASEPOINT_ORDER);
        for shift in 0..=259 {
            check_neighbors(shifted_order);

            // Exercise both carry directions at packed-word boundaries near
            // multiples of L, where random inputs rarely reach negative r.
            if [0, 64, 126, 127, 128, 252, 259].contains(&shift) {
                for bit in [0, 63, 64, 125, 126, 127, 128, 189, 190, 191, 192, 251, 252] {
                    for subtract in [false, true] {
                        let mut boundary = shifted_order;
                        let mut carry = 1u8 << (bit % 8);
                        for byte in &mut boundary[bit / 8..] {
                            let (value, next) = if subtract {
                                byte.overflowing_sub(carry)
                            } else {
                                byte.overflowing_add(carry)
                            };
                            *byte = value;
                            carry = u8::from(next);
                            if carry == 0 {
                                break;
                            }
                        }
                        check_neighbors(boundary);
                    }
                }
            }

            let mut carry = 0u8;
            for byte in &mut shifted_order {
                let next_carry = *byte >> 7;
                *byte = (*byte << 1) | carry;
                carry = next_carry;
            }
        }

        // Deterministic test inputs; this PRNG is not used by the verifier.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..4096 {
            let mut wide = [0u8; 64];
            for chunk in wide.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            check(&wide);
        }
    }

    #[test]
    fn accepts_reduced_encodings() {
        // y = 0
        assert!(is_canonical_point_encoding(&[0; 32]));

        // y = p - 1 (the small-order point (0, -1)), with and without sign bit.
        let mut y = FIELD_MODULUS;
        y[0] -= 1;
        assert!(is_canonical_point_encoding(&y));
        y[31] |= 0x80;
        assert!(is_canonical_point_encoding(&y));
    }

    #[test]
    fn rejects_unreduced_encodings() {
        // y = p
        assert!(!is_canonical_point_encoding(&FIELD_MODULUS));

        // y = p, sign bit set (the sign bit must be ignored, so still rejected).
        let mut y = FIELD_MODULUS;
        y[31] |= 0x80;
        assert!(!is_canonical_point_encoding(&y));

        // y = 2^255 - 1 (largest value the 255 bits can hold, > p).
        let mut y = [0xff; 32];
        y[31] = 0x7f;
        assert!(!is_canonical_point_encoding(&y));
    }
}
