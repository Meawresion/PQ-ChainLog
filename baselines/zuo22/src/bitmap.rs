//! The bitmap index, and `P` — the simple symmetric encryption with
//! homomorphic addition.
//!
//! Zuo et al., TDSC 2022, §2 and §2.1.
//!
//! > *"For a database with `y` files, we set a bit string `bs` of length `y`.
//! > If there exists file `f_i`, we set the `i`th bit of `bs` to 1."*
//!
//! And `P = (Setup, Enc, Dec, Add)` with `n = 2^y`:
//!
//! ```text
//! Enc(sk, m, n) = sk + m mod n
//! Dec(sk, c, n) = c − sk  mod n
//! Add(c₀, c₁, n) = c₀ + c₁ mod n
//! ```
//!
//! ⭐ **Deletion is addition.** The paper: deleting `f₂` from a 5-file index is
//! *"either subtracting the string 00100 from the index or adding
//! −(00100)₂ = (11100)₂ … modulo 2⁵"*. So there is one update path, and the
//! scheme never needs to know whether an update was an insertion or a deletion
//! — which is exactly where its backward privacy comes from.
//!
//! # Representation
//!
//! The authors used Java `BigInteger` at bit lengths of 10³–10⁴. Arithmetic
//! modulo `2^y` on a `y`-bit value is plain wrapping addition over a
//! fixed-width buffer, so this uses a byte array of `⌈y/8⌉` bytes with the
//! unused high bits masked. That is what `BigInteger.mod(2^y)` computes, minus
//! the allocation per operation.

/// A `y`-bit value in `Z_{2^y}`, little-endian by byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitString {
    bits: usize,
    bytes: Vec<u8>,
}

impl BitString {
    /// Zero, with room for `bits` files.
    ///
    /// # Panics
    ///
    /// If `bits` is zero — a database that can hold no files is a configuration
    /// error, and every later operation would silently be a no-op.
    #[must_use]
    pub fn zero(bits: usize) -> Self {
        assert!(bits > 0, "a bitmap index needs at least one bit");
        Self {
            bits,
            bytes: vec![0u8; bits.div_ceil(8)],
        }
    }

    /// `2^i` — the delta that inserts file `i`.
    ///
    /// # Panics
    ///
    /// If `i >= bits`. The paper fixes `y` as *"the maximum number of files
    /// this scheme can support"*; exceeding it silently would wrap a file
    /// identifier onto another file's bit, which is data corruption rather than
    /// an overflow.
    #[must_use]
    pub fn insert_delta(bits: usize, i: usize) -> Self {
        assert!(i < bits, "file index {i} exceeds the bitmap width {bits}");
        let mut v = Self::zero(bits);
        v.bytes[i / 8] |= 1u8 << (i % 8);
        v
    }

    /// `−2^i mod 2^y` — the delta that deletes file `i`.
    #[must_use]
    pub fn delete_delta(bits: usize, i: usize) -> Self {
        Self::insert_delta(bits, i).negate()
    }

    /// Two's complement modulo `2^y`.
    #[must_use]
    pub fn negate(&self) -> Self {
        let mut out = self.clone();
        for b in &mut out.bytes {
            *b = !*b;
        }
        out.add_assign(&Self::one(self.bits));
        out.mask();
        out
    }

    fn one(bits: usize) -> Self {
        let mut v = Self::zero(bits);
        v.bytes[0] = 1;
        v
    }

    /// `Add(self, other, n)`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.add_assign(other);
        out.mask();
        out
    }

    /// `Dec`: `self − other mod n`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    fn add_assign(&mut self, other: &Self) {
        assert_eq!(self.bits, other.bits, "bitmap widths differ");
        let mut carry = 0u16;
        for (a, b) in self.bytes.iter_mut().zip(other.bytes.iter()) {
            let s = u16::from(*a) + u16::from(*b) + carry;
            *a = u8::try_from(s & 0xff).unwrap_or(0);
            carry = s >> 8;
        }
        // The final carry is discarded: that *is* the reduction mod 2^y.
        self.mask();
    }

    /// Clear bits above `y`, so the value stays a canonical element of
    /// `Z_{2^y}` even when `y` is not a multiple of 8.
    fn mask(&mut self) {
        let rem = self.bits % 8;
        if let (true, Some(last)) = (rem != 0, self.bytes.last_mut()) {
            *last &= (1u8 << rem) - 1;
        }
    }

    /// Is file `i` present?
    #[must_use]
    pub fn get(&self, i: usize) -> bool {
        i < self.bits && (self.bytes[i / 8] >> (i % 8)) & 1 == 1
    }

    /// The set bits — the file identifiers this index currently holds.
    #[must_use]
    pub fn files(&self) -> Vec<usize> {
        (0..self.bits).filter(|&i| self.get(i)).collect()
    }

    /// Width in bits, the paper's `y`.
    #[must_use]
    pub const fn bits(&self) -> usize {
        self.bits
    }

    /// Raw little-endian bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Adopt raw bytes, e.g. an XOF output, as a value in `Z_{2^y}`.
    #[must_use]
    pub fn from_bytes(bits: usize, src: &[u8]) -> Self {
        let mut v = Self::zero(bits);
        let n = src.len().min(v.bytes.len());
        v.bytes[..n].copy_from_slice(&src[..n]);
        v.mask();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_papers_own_example() {
        // §2, Fig. 1: y = 5, the index holds f2, then f1 is added, then f2 is
        // deleted by adding (11100)_2 = 28.
        let bits = 5;
        let mut idx = BitString::insert_delta(bits, 2);
        assert_eq!(idx.files(), vec![2]);

        idx = idx.add(&BitString::insert_delta(bits, 1));
        assert_eq!(idx.files(), vec![1, 2]);

        let del = BitString::delete_delta(bits, 2);
        assert_eq!(del.as_bytes()[0], 0b1_1100, "−4 mod 32 should be 28");

        idx = idx.add(&del);
        assert_eq!(idx.files(), vec![1]);
    }

    #[test]
    fn addition_is_modulo_two_to_the_y() {
        let bits = 5;
        let a = BitString::from_bytes(bits, &[31]);
        let b = BitString::from_bytes(bits, &[1]);
        assert_eq!(a.add(&b), BitString::zero(bits), "31 + 1 = 0 mod 32");
    }

    /// The homomorphic property the whole scheme rests on: the server adds
    /// ciphertexts it cannot read, and the client subtracts the summed keys.
    #[test]
    fn homomorphic_addition_round_trips() {
        let bits = 64;
        let m0 = BitString::insert_delta(bits, 3);
        let m1 = BitString::insert_delta(bits, 40);
        let sk0 = BitString::from_bytes(bits, &[0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15]);
        let sk1 = BitString::from_bytes(bits, &[0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8, 0x34]);

        let c0 = m0.add(&sk0);
        let c1 = m1.add(&sk1);

        let summed_c = c0.add(&c1);
        let summed_sk = sk0.add(&sk1);

        assert_eq!(summed_c.sub(&summed_sk), m0.add(&m1));
        assert_eq!(summed_c.sub(&summed_sk).files(), vec![3, 40]);
    }

    /// Widths that are not a byte multiple must stay canonical, or two equal
    /// values could compare unequal.
    #[test]
    fn non_byte_aligned_widths_stay_canonical() {
        let bits = 11;
        let a = BitString::insert_delta(bits, 10);
        let b = a.negate().negate();
        assert_eq!(a, b);
        assert_eq!(a.add(&a.negate()), BitString::zero(bits));
    }

    #[test]
    #[should_panic(expected = "exceeds the bitmap width")]
    fn a_file_index_past_the_width_is_rejected() {
        let _ = BitString::insert_delta(8, 8);
    }
}
