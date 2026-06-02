//! Small scalar helpers needed to assemble Ed25519 verification around syscalls.

/// Group order of the ed25519 basepoint in little-endian form:
/// `2^252 + 27742317777372353535851937790883648493`.
pub(crate) const BASEPOINT_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Returns `true` if `scalar` is in canonical `[0, L)` form.
pub(crate) fn is_canonical_scalar(scalar: &[u8; 32]) -> bool {
    cmp_le(scalar, &BASEPOINT_ORDER).is_lt()
}

/// Reduces a 64-byte little-endian integer modulo the ed25519 basepoint order.
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

/// Returns `-scalar mod L`, preserving zero.
pub(crate) fn negate(scalar: &[u8; 32]) -> [u8; 32] {
    if scalar.iter().all(|byte| *byte == 0) {
        return [0; 32];
    }

    let mut result = BASEPOINT_ORDER;
    sub_assign(&mut result, scalar);
    result
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

fn cmp_le(left: &[u8; 32], right: &[u8; 32]) -> core::cmp::Ordering {
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
    fn rejects_group_order_as_non_canonical() {
        assert!(!is_canonical_scalar(&BASEPOINT_ORDER));

        let mut scalar = BASEPOINT_ORDER;
        scalar[0] -= 1;
        assert!(is_canonical_scalar(&scalar));
    }

    #[test]
    fn reduces_group_order_to_zero() {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&BASEPOINT_ORDER);
        assert_eq!(reduce_wide(&wide), [0; 32]);
    }

    #[test]
    fn negates_zero_to_zero() {
        assert_eq!(negate(&[0; 32]), [0; 32]);
    }
}
