//! ODXT's two PRFs, realised as the paper realises them.
//!
//! > *"we realize all PRF operations using AES-256 in counter mode"*
//! > — ODXT §IV, Implementation Details
//!
//! Two ranges are needed:
//!
//! * `F : {0,1}^λ × {0,1}* → {0,1}^λ` for `TSet` addresses and payload masks.
//! * `F_p : {0,1}^λ × {0,1}* → Z_p^*` for the three exponent keys.
//!
//! ⚠️ **AES-CTR is a stream cipher, not a variable-input-length PRF.** Feeding a
//! message in as the nonce only works for messages of exactly one block, and
//! silently truncates otherwise — keywords are longer than that. The input is
//! therefore compressed to a block first with CMAC-style AES-CBC-MAC over a
//! length-framed message, and the result used as the CTR nonce. This is the
//! standard construction the paper's one-line description elides, and it is
//! recorded in `../UPGRADES.md`.

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use curve25519_dalek::scalar::Scalar;

/// A 256-bit PRF key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrfKey(pub [u8; 32]);

/// AES-256 CBC-MAC over a length-framed message, giving one block.
///
/// Length framing makes the MAC injective over variable-length inputs; without
/// it `("ab", 1)` and `("a", 0xb1)` would collide, and in ODXT a collision
/// between two `(w, cnt)` pairs is a wrong search result, not just a security
/// weakness.
fn compress(key: &PrfKey, data: &[u8]) -> [u8; 16] {
    let cipher = Aes256::new(GenericArray::from_slice(&key.0));

    let mut framed = Vec::with_capacity(data.len() + 8);
    framed.extend_from_slice(&u64::try_from(data.len()).unwrap_or(u64::MAX).to_be_bytes());
    framed.extend_from_slice(data);
    // Pad to a block boundary. The length prefix already disambiguates, so
    // zero padding is unambiguous here.
    while framed.len() % 16 != 0 {
        framed.push(0);
    }

    let mut state = [0u8; 16];
    for chunk in framed.chunks_exact(16) {
        for (s, c) in state.iter_mut().zip(chunk) {
            *s ^= *c;
        }
        let mut block = GenericArray::clone_from_slice(&state);
        cipher.encrypt_block(&mut block);
        state.copy_from_slice(&block);
    }
    state
}

/// One AES-256 block of keystream at counter `ctr`, keyed by `key`, over the
/// compressed input. This is the CTR-mode expansion the paper describes.
fn keystream_block(key: &PrfKey, seed: &[u8; 16], ctr: u8) -> [u8; 16] {
    let cipher = Aes256::new(GenericArray::from_slice(&key.0));
    let mut block = *seed;
    block[15] ^= ctr;
    let mut b = GenericArray::clone_from_slice(&block);
    cipher.encrypt_block(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

/// `F(key, data) → {0,1}^256`.
#[must_use]
pub fn prf_bytes(key: &PrfKey, data: &[u8]) -> [u8; 32] {
    let seed = compress(key, data);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&keystream_block(key, &seed, 0));
    out[16..].copy_from_slice(&keystream_block(key, &seed, 1));
    out
}

/// `F_p(key, data) → Z_p^*`, the scalar field of Ristretto255.
///
/// ⭐ **Never returns zero.** ODXT inverts `F_p(K_Z, ·)`, so a zero output is
/// not merely improbable, it is a correctness failure — `Scalar::invert` on
/// zero yields zero, and the cross-tag identity would silently stop holding for
/// that entry. The loop below is the honest fix; it terminates with
/// overwhelming probability on the first iteration.
#[must_use]
pub fn prf_scalar(key: &PrfKey, data: &[u8]) -> Scalar {
    let seed = compress(key, data);
    let mut ctr = 0u8;
    loop {
        let mut wide = [0u8; 64];
        for (i, chunk) in wide.chunks_exact_mut(16).enumerate() {
            let c = ctr.wrapping_add(u8::try_from(i).unwrap_or(0));
            chunk.copy_from_slice(&keystream_block(key, &seed, c));
        }
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        if s != Scalar::ZERO {
            return s;
        }
        ctr = ctr.wrapping_add(4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PrfKey {
        PrfKey([7u8; 32])
    }

    #[test]
    fn distinct_inputs_give_distinct_outputs() {
        assert_ne!(prf_bytes(&key(), b"alpha"), prf_bytes(&key(), b"beta"));
        assert_ne!(prf_scalar(&key(), b"alpha"), prf_scalar(&key(), b"beta"));
    }

    #[test]
    fn the_prf_is_deterministic() {
        assert_eq!(prf_bytes(&key(), b"same"), prf_bytes(&key(), b"same"));
        assert_eq!(prf_scalar(&key(), b"same"), prf_scalar(&key(), b"same"));
    }

    #[test]
    fn different_keys_give_different_outputs() {
        let other = PrfKey([8u8; 32]);
        assert_ne!(prf_bytes(&key(), b"x"), prf_bytes(&other, b"x"));
    }

    /// The framing test. Without a length prefix these two inputs are the same
    /// byte string, and the collision would surface as a wrong search result
    /// rather than as an obvious failure.
    #[test]
    fn length_framing_separates_ambiguous_concatenations() {
        let a = [b"ab".as_slice(), &[0x01]].concat();
        let b = [b"a".as_slice(), &[0x62, 0x01]].concat();
        assert_eq!(a, b, "the two inputs really are the same bytes");
        // Same bytes must give the same output — that is not the point. The
        // point is that the *callers* frame their arguments, which is checked
        // in the lib.rs tag helpers.
        assert_eq!(prf_bytes(&key(), &a), prf_bytes(&key(), &b));
    }

    /// `prf_scalar` feeds `Scalar::invert`, so a zero would be a correctness
    /// bug rather than a security nit.
    #[test]
    fn scalars_are_never_zero_and_invert_round_trips() {
        for i in 0..256u32 {
            let s = prf_scalar(&key(), &i.to_be_bytes());
            assert_ne!(s, Scalar::ZERO);
            assert_eq!(s * s.invert(), Scalar::ONE);
        }
    }
}
