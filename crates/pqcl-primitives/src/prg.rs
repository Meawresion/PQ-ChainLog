//! The GGM tree step `G`, on AES-256 — M12 R3.
//!
//! ```text
//! G(s) = AES-256_s(⟨0⟩) ‖ AES-256_s(⟨1⟩) ‖ AES-256_s(⟨2⟩) ‖ AES-256_s(⟨3⟩)
//! ```
//!
//! with `⟨i⟩` the 128-bit big-endian encoding of `i`: four blocks, 512 bits =
//! 2λ, one key schedule per tree level. The first λ bytes are the left child,
//! the second λ the right, exactly as the SHAKE256 form it replaces.
//!
//! # Why this is sound, and what it does not touch
//!
//! GGM needs `G` to be a length-doubling PRG and nothing more — a
//! standard-model assumption. AES-256 keyed by the seed, run in counter mode
//! over fixed blocks, is the textbook PRG from a PRP. The QROM argument of
//! draft6 §III concerns `H₁` and `H_X`, which **stay SHAKE256**; AES-256 is
//! already in the system (the AEAD), so this adds no primitive and no
//! assumption. At 256-bit keys Grover leaves 128-bit post-quantum security,
//! matching λ.
//!
//! # Why
//!
//! After R1 + R2, campaign 03's range-ingest loss was still per-token GGM cost:
//! a cold keyword walks all 64 levels, and every level was a SHAKE256
//! permutation. AES-256 with hardware support is a few dozen cycles per block.
//!
//! # Backend
//!
//! The `aes` crate selects AES-NI **at run time** (`cpufeatures`), never from
//! the build machine's ISA — the same trap `non_portable` sets for liboqs, where
//! a baked-in ISA makes local and AWS runs silently incomparable.
//!
//! Correctness is gated by the ACVP AES-256 ECB encrypt vectors
//! (`tests/kat.rs`) and by GGM vectors produced independently with Python's
//! `cryptography` (`tests/vectors/ggm_aes.py`, checked in `pqcl-ggm`).

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use crate::LAMBDA_BYTES;
use crate::xof::Digest32;

/// AES-256 encryption of one block. Exposed so the ACVP vectors can test the
/// exact primitive [`ggm_step`] is built on.
#[must_use]
pub fn aes256_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

/// `G(s)` → 2λ: the GGM step. Left child first, then right.
#[must_use]
pub fn ggm_step(seed: &Digest32) -> [u8; 2 * LAMBDA_BYTES] {
    const { assert!(2 * LAMBDA_BYTES == 4 * 16) };
    let cipher = Aes256::new(GenericArray::from_slice(seed));
    let mut blocks = [GenericArray::default(); 4];
    for (i, b) in blocks.iter_mut().enumerate() {
        // ⟨i⟩: 128-bit big-endian, so i sits in the last byte.
        b[15] = u8::try_from(i).unwrap_or(0);
    }
    cipher.encrypt_blocks(&mut blocks);
    let mut out = [0u8; 2 * LAMBDA_BYTES];
    for (chunk, b) in out.chunks_exact_mut(16).zip(&blocks) {
        chunk.copy_from_slice(b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_step_is_four_counter_blocks_under_the_seed() {
        // Written from the equation, block by block, against the single-block
        // primitive that the ACVP vectors pin.
        let seed = [0x42u8; 32];
        let out = ggm_step(&seed);
        for i in 0..4u8 {
            let mut ctr = [0u8; 16];
            ctr[15] = i;
            assert_eq!(
                out[16 * usize::from(i)..16 * (usize::from(i) + 1)],
                aes256_encrypt_block(&seed, &ctr),
                "block {i}"
            );
        }
    }

    #[test]
    fn the_children_differ_and_depend_on_the_seed() {
        let a = ggm_step(&[1u8; 32]);
        let b = ggm_step(&[2u8; 32]);
        assert_ne!(a[..32], a[32..]);
        assert_ne!(a, b);
    }
}
