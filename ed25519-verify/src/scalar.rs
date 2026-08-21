//! Small scalar- and field-element helpers needed to assemble Ed25519
//! verification around syscalls.

use crate::constants::{BASEPOINT_ORDER, FIELD_MODULUS};

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

/// Reduces a 64-byte little-endian integer modulo the ed25519 base point order.
pub(crate) fn reduce_wide(wide: &[u8; 64]) -> [u8; 32] {
    let mut remainder = [0u8; 32];

    for bit_index in (0..512).rev() {
        shl1(&mut remainder);
        if (wide[bit_index / 8] >> (bit_index % 8)) & 1 == 1 {
            remainder[0] |= 1;
        }
        if !cmp_le(&remainder, &BASEPOINT_ORDER).is_lt() {
            sub_assign(&mut remainder, &BASEPOINT_ORDER);
        }
    }

    remainder
}

fn shl1(value: &mut [u8; 32]) {
    let mut carry = 0u8;
    for byte in value {
        let next_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
}

fn sub_assign(left: &mut [u8; 32], right: &[u8; 32]) {
    let mut borrow = 0u16;
    for (left_byte, right_byte) in left.iter_mut().zip(right) {
        let minuend = u16::from(*left_byte);
        let subtrahend = u16::from(*right_byte) + borrow;
        if minuend >= subtrahend {
            *left_byte = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            *left_byte = (minuend + 256 - subtrahend) as u8;
            borrow = 1;
        }
    }
}

pub(crate) fn cmp_le(left: &[u8; 32], right: &[u8; 32]) -> core::cmp::Ordering {
    for (left_byte, right_byte) in left.iter().zip(right).rev() {
        match left_byte.cmp(right_byte) {
            core::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    core::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduces_group_order_to_zero() {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&BASEPOINT_ORDER);
        assert_eq!(reduce_wide(&wide), [0; 32]);
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
