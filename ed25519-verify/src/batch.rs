//! Cofactored batch verification using a transcript-bound weighted equation.
//!
//! For each signature, `D_i = S_i B - h_i A_i - R_i`. After checking each
//! encoding and scalar, verify `[8] sum(z_i D_i) = 0` with 128-bit weights.
//! Multiplying by the cofactor places every residual in the prime-order subgroup;
//! omitting it would allow torsion residuals to cancel with substantial probability.
//! The full challenge hashes and all original S encodings are committed before
//! deriving weights, so an attacker cannot choose S to cancel known weights.

use {
    crate::{
        constants::{
            BASEPOINT_ORDER, ED25519_BASEPOINT_NEGATED_COMPRESSED, EDWARDS_IDENTITY_COMPRESSED,
        },
        points::{is_small_order_canonical, is_small_order_encoding},
        scalar, Ed25519Verifier, Ed25519VerifyError,
    },
    solana_curve25519::{
        edwards::{multiscalar_multiply_edwards, PodEdwardsPoint},
        scalar::PodScalar,
    },
};

const CAPACITY: usize = 32;
const DOMAIN: &[u8] = b"solana-ed25519-verify:batch:v1";
const EXPAND_DOMAIN: &[u8] = b"solana-ed25519-verify:batch:expand:v1";

/// A borrowed signature, public key, and message for batch verification.
#[derive(Debug, Clone, Copy)]
pub struct BatchItem<'a> {
    /// The original Ed25519 signature encoding, `R || S`.
    pub signature: &'a [u8; 64],
    /// The original compressed public-key encoding, `A`.
    pub public_key: &'a [u8; 32],
    /// The signed message.
    pub message: &'a [u8],
}

impl Ed25519Verifier {
    /// Verifies a batch using the configured criteria without allocating.
    ///
    /// Cofactored profiles aggregate signatures in chunks of at most 32, using
    /// deterministic 128-bit weights derived from a domain-separated SHA-512
    /// transcript of the entire chunk. As with randomized batch verification,
    /// an invalid batch has a negligible chance of acceptance under the hash
    /// random-oracle assumption; this is not an exact per-signature check.
    /// Canonical `S`, point validity, and the selected encoding and small-order
    /// checks are still enforced for every input.
    ///
    /// Small chunks and all cofactorless profiles (including
    /// [`VerificationCriteria::dalek_verify_strict`](crate::VerificationCriteria::dalek_verify_strict))
    /// use individual verification. Cofactorless equations cannot safely use
    /// this aggregate check because of their different torsion rules.
    /// An empty batch succeeds. Errors do not identify a failing index, and
    /// their precedence may differ from a loop over `verify_signature`.
    ///
    /// ```
    /// # fn example(signature: &[u8; 64], public_key: &[u8; 32], message: &[u8])
    /// # -> Result<(), solana_ed25519_verify::Ed25519VerifyError> {
    /// use solana_ed25519_verify::{BatchItem, Ed25519Verifier};
    /// let items = [BatchItem { signature, public_key, message }; 3];
    /// Ed25519Verifier::new().verify_batch(&items)?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn verify_batch(&self, items: &[BatchItem<'_>]) -> Result<(), Ed25519VerifyError> {
        if !self.criteria().cofactored {
            for item in items {
                self.verify_signature(item.signature, item.public_key, item.message)?;
            }
            return Ok(());
        }
        for chunk in items.chunks(CAPACITY) {
            let same_key = chunk[1..]
                .iter()
                .all(|item| item.public_key == chunk[0].public_key);
            // Below these measured SBF v3 break-even points, hashing the
            // transcript and assembling a larger MSM costs more than it saves.
            if chunk.len() < if same_key { 3 } else { 11 } {
                for item in chunk {
                    self.verify_signature(item.signature, item.public_key, item.message)?;
                }
            } else {
                match (
                    self.criteria() == crate::VerificationCriteria::zip215(),
                    same_key,
                ) {
                    (true, true) => self.verify_chunk::<true, true>(chunk)?,
                    (true, false) => self.verify_chunk::<true, false>(chunk)?,
                    (false, true) => self.verify_chunk::<false, true>(chunk)?,
                    (false, false) => self.verify_chunk::<false, false>(chunk)?,
                }
            }
        }
        Ok(())
    }

    #[inline(never)]
    fn verify_chunk<const ZIP215: bool, const SAME_KEY: bool>(
        &self,
        items: &[BatchItem<'_>],
    ) -> Result<(), Ed25519VerifyError> {
        // Keep the transcript, points, and scalars in separate stack frames
        // below SBF's 4 KiB per-frame limit. Only the used prefixes are hashed
        // or passed to the curve syscall.
        let mut hashes = [[0u8; 96]; CAPACITY];
        let seed = hash_batch::<ZIP215>(items, self.criteria(), &mut hashes)?;
        verify_hashed::<SAME_KEY>(items, &hashes, &seed)
    }
}

#[inline(always)]
fn mul128_into(x: &[u8; 32], y: &[u8; 16], output: &mut [u8; 64]) {
    let x: [u32; 8] =
        core::array::from_fn(|i| u32::from_le_bytes(x[i * 4..i * 4 + 4].try_into().unwrap()));
    let y: [u32; 4] =
        core::array::from_fn(|i| u32::from_le_bytes(y[i * 4..i * 4 + 4].try_into().unwrap()));
    let mut product = [0u32; 12];
    #[inline(always)]
    fn row<const I: usize>(x: u32, y: &[u32; 4], product: &mut [u32; 12]) {
        let mut carry = 0u64;
        for j in 0..4 {
            // At most (2^32 - 1)^2 + 2(2^32 - 1) = 2^64 - 1.
            let value = u64::from(x) * u64::from(y[j]) + u64::from(product[I + j]) + carry;
            product[I + j] = value as u32;
            carry = value >> 32;
        }
        product[I + 4] = carry as u32;
    }
    row::<0>(x[0], &y, &mut product);
    row::<1>(x[1], &y, &mut product);
    row::<2>(x[2], &y, &mut product);
    row::<3>(x[3], &y, &mut product);
    row::<4>(x[4], &y, &mut product);
    row::<5>(x[5], &y, &mut product);
    row::<6>(x[6], &y, &mut product);
    row::<7>(x[7], &y, &mut product);
    for (bytes, limb) in output[..48].chunks_exact_mut(4).zip(product) {
        bytes.copy_from_slice(&limb.to_le_bytes());
    }
    output[48..].fill(0);
}

fn add_wide(accumulator: &mut [u64; 7], value: &[u8; 64]) {
    // Every summand is below 2^384; at most 32 summands fit below 2^389.
    let mut carry = false;
    for (limb, bytes) in accumulator[..6].iter_mut().zip(value[..48].chunks_exact(8)) {
        let word = u64::from_le_bytes(bytes.try_into().unwrap());
        let (sum, overflow) = limb.overflowing_add(word);
        let (sum, overflow_carry) = sum.overflowing_add(u64::from(carry));
        *limb = sum;
        carry = overflow || overflow_carry;
    }
    accumulator[6] += u64::from(carry);
}

#[inline(never)]
fn hash_batch<const ZIP215: bool>(
    items: &[BatchItem<'_>],
    criteria: crate::VerificationCriteria,
    hashes: &mut [[u8; 96]; CAPACITY],
) -> Result<[u8; 64], Ed25519VerifyError> {
    let criteria = if ZIP215 {
        crate::VerificationCriteria::zip215()
    } else {
        criteria
    };
    for (item, hash) in items.iter().zip(hashes.iter_mut()) {
        let r: &[u8; 32] = item.signature[..32].try_into().unwrap();
        let s: &[u8; 32] = item.signature[32..].try_into().unwrap();
        let check_a = item.public_key[31].wrapping_add(6) & 0x7f <= 11;
        let check_r = r[31].wrapping_add(6) & 0x7f <= 11;
        if criteria.require_canonical_a
            && check_a
            && !scalar::is_canonical_point_encoding(item.public_key)
        {
            return Err(Ed25519VerifyError::NonCanonicalPublicKey);
        }
        if criteria.require_canonical_r && check_r && !scalar::is_canonical_point_encoding(r) {
            return Err(Ed25519VerifyError::NonCanonicalR);
        }
        if criteria.reject_small_order_a && check_a && is_small_order_encoding(item.public_key) {
            return Err(Ed25519VerifyError::SmallOrderPublicKey);
        }
        if criteria.reject_small_order_r && check_r && is_small_order_encoding(r) {
            return Err(Ed25519VerifyError::SmallOrderR);
        }
        // Check the original S before reducing weighted products: otherwise
        // adding L to an input S would disappear in the aggregate equation.
        if s[31] >= 0x10 && !scalar::cmp_le(s, &BASEPOINT_ORDER).is_lt() {
            return Err(Ed25519VerifyError::InvalidEncoding);
        }
        hash[..64].copy_from_slice(
            solana_sha512_hasher::hashv(&[r, item.public_key, item.message]).as_bytes(),
        );
        hash[64..].copy_from_slice(s);
    }
    // Fixed-size records make the transcript unambiguous. Each full digest
    // binds the original R, A, and message; S must be bound separately.
    let length = (items.len() as u64).to_le_bytes();
    Ok(
        *solana_sha512_hasher::hashv(&[DOMAIN, &length, hashes[..items.len()].as_flattened()])
            .as_bytes(),
    )
}

#[inline(never)]
fn verify_hashed<const SAME_KEY: bool>(
    items: &[BatchItem<'_>],
    hashes: &[[u8; 96]; CAPACITY],
    seed: &[u8; 64],
) -> Result<(), Ed25519VerifyError> {
    // from_fn allows the SBF compiler to use a bulk zeroing operation here.
    let mut points: [PodEdwardsPoint; CAPACITY * 2 + 1] =
        core::array::from_fn(|_| PodEdwardsPoint([0; 32]));
    verify_with_points::<SAME_KEY>(items, hashes, seed, &mut points)
}

#[inline(never)]
fn verify_with_points<const SAME_KEY: bool>(
    items: &[BatchItem<'_>],
    hashes: &[[u8; 96]; CAPACITY],
    seed: &[u8; 64],
    points: &mut [PodEdwardsPoint; CAPACITY * 2 + 1],
) -> Result<(), Ed25519VerifyError> {
    let mut block = *seed;
    let mut scalars: [PodScalar; CAPACITY * 2 + 1] = core::array::from_fn(|_| PodScalar([0; 32]));

    points[0] = ED25519_BASEPOINT_NEGATED_COMPRESSED;
    let mut base = [0u64; 7];
    let mut key_coefficient = [0u64; 7];
    if SAME_KEY {
        // Merge A terms only when all original public-key bytes are identical.
        points[1 + items.len()] = PodEdwardsPoint(*items[0].public_key);
    }
    for (i, item) in items.iter().enumerate() {
        let r_index = if SAME_KEY { 1 + i } else { 1 + i * 2 };
        let a_index = if SAME_KEY { 1 + items.len() } else { 2 + i * 2 };
        points[r_index] = PodEdwardsPoint(item.signature[..32].try_into().unwrap());
        if !SAME_KEY {
            points[a_index] = PodEdwardsPoint(*item.public_key);
        }
        let mut challenge = [0; 32];
        scalar::reduce_batch_challenge_into(hashes[i][..64].try_into().unwrap(), &mut challenge);
        let s: &[u8; 32] = item.signature[32..].try_into().unwrap();
        if i == 0 {
            // Fixing the first weight to one saves two products. If that is
            // the only invalid signature, its nonzero residual cannot vanish.
            scalars[1].0[0] = 1;
            if SAME_KEY {
                for (limb, bytes) in key_coefficient.iter_mut().zip(challenge.chunks_exact(8)) {
                    *limb = u64::from_le_bytes(bytes.try_into().unwrap());
                }
            } else {
                scalars[2].0 = challenge;
            }
            for (limb, bytes) in base.iter_mut().zip(s.chunks_exact(8)) {
                *limb = u64::from_le_bytes(bytes.try_into().unwrap());
            }
        } else {
            // Four little-endian 128-bit weights per hash block. Zero weights
            // are allowed, with the same negligible probability as any value.
            let index = i - 1;
            if index != 0 && index % 4 == 0 {
                block = *solana_sha512_hasher::hashv(&[
                    EXPAND_DOMAIN,
                    seed,
                    &((index / 4) as u64).to_le_bytes(),
                ])
                .as_bytes();
            }
            let weight: &[u8; 16] = block[index % 4 * 16..index % 4 * 16 + 16]
                .try_into()
                .unwrap();
            scalars[r_index].0[..16].copy_from_slice(weight);
            let mut wide = [0u8; 64];
            mul128_into(&challenge, weight, &mut wide);
            if SAME_KEY {
                add_wide(&mut key_coefficient, &wide);
            } else {
                scalar::reduce_batch_wide_into(&wide, &mut scalars[a_index].0);
            }
            mul128_into(s, weight, &mut wide);
            add_wide(&mut base, &wide);
        }
    }
    let mut wide = [0u8; 64];
    for (bytes, limb) in wide.chunks_exact_mut(8).zip(base) {
        bytes.copy_from_slice(&limb.to_le_bytes());
    }
    scalar::reduce_batch_wide_into(&wide, &mut scalars[0].0);
    if SAME_KEY {
        for (bytes, limb) in wide.chunks_exact_mut(8).zip(key_coefficient) {
            bytes.copy_from_slice(&limb.to_le_bytes());
        }
        scalar::reduce_batch_wide_into(&wide, &mut scalars[1 + items.len()].0);
    }
    let count = if SAME_KEY {
        2 + items.len()
    } else {
        1 + items.len() * 2
    };
    // The syscall validates every A and R, including points with a zero
    // coefficient. Its canonical output is torsion exactly when [8]D = 0.
    let result = multiscalar_multiply_edwards(&scalars[..count], &points[..count])
        .ok_or(Ed25519VerifyError::InvalidEncoding)?;
    if result == EDWARDS_IDENTITY_COMPRESSED || is_small_order_canonical(&result) {
        Ok(())
    } else {
        Err(Ed25519VerifyError::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::VerificationCriteria,
        curve25519_dalek::scalar::Scalar,
        ed25519_dalek::{Signer, SigningKey},
    };

    #[test]
    fn batch_products_and_accumulators_match_dalek() {
        let mut accumulator = [0u64; 7];
        let mut expected_sum = Scalar::ZERO;
        for i in 0..1024u64 {
            let mut input = solana_sha512_hasher::hashv(&[&i.to_le_bytes()]).to_bytes();
            if i == 0 {
                input.fill(0xff);
            } // Maximum product and carry.
            if i == 1 {
                input.fill(0);
            }
            let x: &[u8; 32] = input[..32].try_into().unwrap();
            let y: &[u8; 16] = input[32..48].try_into().unwrap();
            let mut y_scalar = [0; 32];
            y_scalar[..16].copy_from_slice(y);
            let expected =
                Scalar::from_bytes_mod_order(*x) * Scalar::from_bytes_mod_order(y_scalar);
            let mut wide = [0xa5; 64];
            mul128_into(x, y, &mut wide);
            assert_eq!(&wide[48..], &[0; 16]);
            assert_eq!(Scalar::from_bytes_mod_order_wide(&wide), expected);
            add_wide(&mut accumulator, &wide);
            expected_sum += expected;
            wide.fill(0);
            for (bytes, limb) in wide.chunks_exact_mut(8).zip(accumulator) {
                bytes.copy_from_slice(&limb.to_le_bytes());
            }
            let mut reduced = [0; 32];
            scalar::reduce_batch_wide_into(&wide, &mut reduced);
            assert_eq!(reduced, expected_sum.to_bytes(), "sum at {i}");
        }
    }

    #[test]
    fn weights_bind_s_and_prevent_adaptive_cancellation() {
        fn items<'a>(
            keys: &'a [[u8; 32]; 11],
            signatures: &'a [[u8; 64]; 11],
        ) -> [BatchItem<'a>; 11] {
            core::array::from_fn(|i| BatchItem {
                public_key: &keys[i],
                signature: &signatures[i],
                message: b"cancellation regression",
            })
        }
        for same_key in [false, true] {
            let signing_keys: [_; 11] = core::array::from_fn(|i| {
                SigningKey::from_bytes(&[if same_key { 7 } else { 7 + i as u8 }; 32])
            });
            let keys = signing_keys
                .each_ref()
                .map(|key| key.verifying_key().to_bytes());
            let mut signatures = signing_keys
                .each_ref()
                .map(|key| key.sign(b"cancellation regression").to_bytes());
            let verifier = Ed25519Verifier::new();
            let verify = |signatures: &_| verifier.verify_batch(&items(&keys, signatures));
            let seed = |signatures: &_| {
                hash_batch::<true>(
                    &items(&keys, signatures),
                    VerificationCriteria::zip215(),
                    &mut [[0; 96]; CAPACITY],
                )
                .unwrap()
            };
            assert_eq!(verify(&signatures), Ok(()));
            let original_seed = seed(&signatures);
            let mut weight = [0; 32];
            weight[..16].copy_from_slice(&original_seed[..16]);
            let weight = Scalar::from_bytes_mod_order(weight);
            let s0 = Scalar::from_bytes_mod_order(signatures[0][32..].try_into().unwrap());
            let s1 = Scalar::from_bytes_mod_order(signatures[1][32..].try_into().unwrap());
            // These invalid signatures cancel under the original weights;
            // including every S in the transcript must change those weights.
            signatures[0][32..].copy_from_slice(&(s0 + weight).to_bytes());
            signatures[1][32..].copy_from_slice(&(s1 - Scalar::ONE).to_bytes());
            assert_ne!(original_seed, seed(&signatures));
            assert!(verify(&signatures).is_err());
            // Also reject cancellation under naive equal-weight aggregation.
            signatures[0][32..].copy_from_slice(&(s0 + Scalar::ONE).to_bytes());
            assert!(verify(&signatures).is_err());
        }
    }
}
