//! RLP — Ethereum's Recursive Length Prefix encoding.
//!
//! Only what a receipt-trie proof needs: decoding nodes and receipts, and
//! encoding trie keys and node payloads.
//!
//! ⚠️ **Decoding is strict about canonical form.** RLP has exactly one valid
//! encoding per value, and a permissive decoder is a real vulnerability here:
//! two distinct byte strings that decode alike would let an attacker present a
//! proof node whose hash differs from the one committed while still parsing to
//! the expected structure. The three rules enforced below are the ones the
//! yellow paper requires and that lenient implementations skip:
//!
//! 1. A single byte `< 0x80` must be encoded as itself, never with a prefix.
//! 2. A length that fits in the short form must not use the long form.
//! 3. A long-form length must have no leading zero bytes.
//!
//! Each is checked, and each has a test that a non-canonical encoding is
//! rejected rather than silently accepted.

use crate::ProofError;

/// A decoded RLP item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rlp<'a> {
    /// A byte string.
    Bytes(&'a [u8]),
    /// A list of items.
    List(Vec<Rlp<'a>>),
}

impl<'a> Rlp<'a> {
    /// The byte string, or an error if this is a list.
    pub fn bytes(&self) -> Result<&'a [u8], ProofError> {
        match self {
            Self::Bytes(b) => Ok(b),
            Self::List(_) => Err(ProofError::Rlp("expected a byte string, found a list")),
        }
    }

    /// The list items, or an error if this is a byte string.
    pub fn list(&self) -> Result<&[Self], ProofError> {
        match self {
            Self::List(items) => Ok(items),
            Self::Bytes(_) => Err(ProofError::Rlp("expected a list, found a byte string")),
        }
    }

    /// A big-endian unsigned integer.
    ///
    /// RLP integers are minimally encoded, so a leading zero byte is
    /// non-canonical and is rejected.
    pub fn u64(&self) -> Result<u64, ProofError> {
        let b = self.bytes()?;
        if b.len() > 8 {
            return Err(ProofError::Rlp("integer wider than 64 bits"));
        }
        if b.first() == Some(&0) {
            return Err(ProofError::Rlp("integer has a leading zero byte"));
        }
        Ok(b.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x)))
    }
}

/// Decode exactly one item, requiring it to consume all of `input`.
///
/// Trailing bytes are an error rather than an oversight: a proof node with junk
/// appended hashes differently, so accepting it would mean verifying a
/// different object than the one committed.
pub fn decode(input: &[u8]) -> Result<Rlp<'_>, ProofError> {
    let (item, rest) = decode_item(input)?;
    if !rest.is_empty() {
        return Err(ProofError::Rlp("trailing bytes after the RLP item"));
    }
    Ok(item)
}

/// Decode one item, returning it and whatever follows.
pub fn decode_item(input: &[u8]) -> Result<(Rlp<'_>, &[u8]), ProofError> {
    let &prefix = input
        .first()
        .ok_or(ProofError::Rlp("unexpected end of input"))?;

    match prefix {
        // A single byte below 0x80 encodes itself.
        0x00..=0x7f => Ok((Rlp::Bytes(&input[..1]), &input[1..])),

        // Short string, 0..=55 bytes.
        0x80..=0xb7 => {
            let len = usize::from(prefix - 0x80);
            let body = slice(input, 1, len)?;
            // Canonical form: a one-byte string below 0x80 must not be
            // prefixed. `0x81 0x7f` and `0x7f` would otherwise both decode to
            // the same value while hashing differently.
            if len == 1 && body[0] < 0x80 {
                return Err(ProofError::Rlp(
                    "non-canonical: single byte below 0x80 wrapped in a prefix",
                ));
            }
            Ok((Rlp::Bytes(body), &input[1 + len..]))
        }

        // Long string, more than 55 bytes.
        0xb8..=0xbf => {
            let len_of_len = usize::from(prefix - 0xb7);
            let len = long_len(input, len_of_len)?;
            if len <= 55 {
                return Err(ProofError::Rlp(
                    "non-canonical: short string encoded in long form",
                ));
            }
            let start = 1 + len_of_len;
            let body = slice(input, start, len)?;
            Ok((Rlp::Bytes(body), &input[start + len..]))
        }

        // Short list, payload 0..=55 bytes.
        0xc0..=0xf7 => {
            let len = usize::from(prefix - 0xc0);
            let body = slice(input, 1, len)?;
            Ok((Rlp::List(decode_list(body)?), &input[1 + len..]))
        }

        // Long list.
        0xf8..=0xff => {
            let len_of_len = usize::from(prefix - 0xf7);
            let len = long_len(input, len_of_len)?;
            if len <= 55 {
                return Err(ProofError::Rlp(
                    "non-canonical: short list encoded in long form",
                ));
            }
            let start = 1 + len_of_len;
            let body = slice(input, start, len)?;
            Ok((Rlp::List(decode_list(body)?), &input[start + len..]))
        }
    }
}

fn decode_list(mut body: &[u8]) -> Result<Vec<Rlp<'_>>, ProofError> {
    let mut items = Vec::new();
    while !body.is_empty() {
        let (item, rest) = decode_item(body)?;
        items.push(item);
        body = rest;
    }
    Ok(items)
}

fn long_len(input: &[u8], len_of_len: usize) -> Result<usize, ProofError> {
    if len_of_len == 0 || len_of_len > 8 {
        return Err(ProofError::Rlp("invalid long-form length width"));
    }
    let bytes = slice(input, 1, len_of_len)?;
    if bytes[0] == 0 {
        return Err(ProofError::Rlp(
            "non-canonical: long-form length has a leading zero",
        ));
    }
    let mut len = 0usize;
    for &b in bytes {
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(usize::from(b)))
            .ok_or(ProofError::Rlp("length overflows usize"))?;
    }
    Ok(len)
}

fn slice(input: &[u8], start: usize, len: usize) -> Result<&[u8], ProofError> {
    input
        .get(start..start + len)
        .ok_or(ProofError::Rlp("item runs past the end of the input"))
}

// --------------------------------------------------------------- encoding

/// Encode a byte string.
#[must_use]
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 9);
    if data.len() == 1 && data[0] < 0x80 {
        out.push(data[0]);
    } else if data.len() <= 55 {
        out.push(0x80 + u8::try_from(data.len()).unwrap_or(0));
        out.extend_from_slice(data);
    } else {
        let len = data.len().to_be_bytes();
        let sig = len.iter().position(|&b| b != 0).unwrap_or(7);
        let len_bytes = &len[sig..];
        out.push(0xb7 + u8::try_from(len_bytes.len()).unwrap_or(0));
        out.extend_from_slice(len_bytes);
        out.extend_from_slice(data);
    }
    out
}

/// Encode a list whose items are already encoded.
#[must_use]
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = Vec::with_capacity(payload.len() + 9);
    if payload.len() <= 55 {
        out.push(0xc0 + u8::try_from(payload.len()).unwrap_or(0));
    } else {
        let len = payload.len().to_be_bytes();
        let sig = len.iter().position(|&b| b != 0).unwrap_or(7);
        let len_bytes = &len[sig..];
        out.push(0xf7 + u8::try_from(len_bytes.len()).unwrap_or(0));
        out.extend_from_slice(len_bytes);
    }
    out.extend_from_slice(&payload);
    out
}

/// Encode an unsigned integer, minimally.
///
/// ⭐ Zero encodes as the **empty string** `0x80`, not as `0x00`. That is the
/// receipt trie's key for transaction index 0, so getting it wrong makes every
/// single-transaction block unverifiable.
#[must_use]
pub fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let be = value.to_be_bytes();
    let sig = be.iter().position(|&b| b != 0).unwrap_or(7);
    encode_bytes(&be[sig..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_bytes_encode_as_themselves() {
        assert_eq!(encode_bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(encode_bytes(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn zero_encodes_as_the_empty_string() {
        // The receipt-trie key for transaction index 0. A `0x00` here breaks
        // every single-transaction block.
        assert_eq!(encode_u64(0), vec![0x80]);
        assert_eq!(encode_u64(1), vec![0x01]);
        assert_eq!(encode_u64(127), vec![0x7f]);
        assert_eq!(encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(encode_u64(1024), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn round_trips_through_decode() {
        for v in [0u64, 1, 127, 128, 255, 256, 65535, u64::MAX] {
            let enc = encode_u64(v);
            let dec = decode(&enc).expect("decodes");
            if v == 0 {
                assert_eq!(dec.bytes().expect("bytes"), &[] as &[u8]);
            } else {
                assert_eq!(dec.u64().expect("u64"), v);
            }
        }
    }

    #[test]
    fn long_strings_round_trip() {
        let data = vec![0xabu8; 1000];
        let enc = encode_bytes(&data);
        assert_eq!(
            decode(&enc).expect("decodes").bytes().expect("bytes"),
            &data[..]
        );
    }

    #[test]
    fn lists_round_trip() {
        let enc = encode_list(&[encode_bytes(b"hello"), encode_u64(42)]);
        let dec = decode(&enc).expect("decodes");
        let items = dec.list().expect("list");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].bytes().expect("bytes"), b"hello");
        assert_eq!(items[1].u64().expect("u64"), 42);
    }

    // --- the canonical-form rules, each with its own rejection test --------
    //
    // These are the ones a permissive decoder skips. Without them two byte
    // strings could decode alike while hashing differently, which is exactly
    // the substitution a proof is supposed to prevent.

    #[test]
    fn a_prefixed_single_low_byte_is_rejected() {
        assert!(
            decode(&[0x81, 0x7f]).is_err(),
            "0x81 0x7f must not decode; 0x7f is the canonical form"
        );
    }

    #[test]
    fn a_short_string_in_long_form_is_rejected() {
        // 0xb8 0x05 "hello" says "long form, one length byte, length 5" — but 5
        // fits the short form, so this is a second encoding of the same value.
        let mut bad = vec![0xb8, 0x05];
        bad.extend_from_slice(b"hello");
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn a_leading_zero_in_a_long_length_is_rejected() {
        let mut bad = vec![0xb9, 0x00, 0x38];
        bad.extend_from_slice(&[0u8; 56]);
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn an_integer_with_a_leading_zero_is_rejected() {
        let item = decode(&[0x82, 0x00, 0x01]).expect("decodes as bytes");
        assert!(item.u64().is_err(), "0x0001 is not a canonical integer");
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut enc = encode_bytes(b"hello");
        enc.push(0xff);
        assert!(decode(&enc).is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(
            decode(&[0x83, 0x01, 0x02]).is_err(),
            "claims 3 bytes, supplies 2"
        );
        assert!(decode(&[]).is_err());
    }
}
