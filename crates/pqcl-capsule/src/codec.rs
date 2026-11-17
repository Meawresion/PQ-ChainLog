//! Canonical deterministic serialization.
//!
//! Every structure that is hashed, signed or anchored is encoded here, and the
//! encoding is **injective**: distinct field tuples never produce the same
//! bytes. That is the same requirement draft6 eq. (3) imposes on commitments,
//! for the same reason — an ambiguous encoding lets a committer open one digest
//! to two different records.
//!
//! # Requirements this must meet
//!
//! * **Deterministic.** Encoding the same value twice gives identical bytes,
//!   with no map iteration order or padding entering the result.
//! * **Round-trippable.** `decode(encode(x)) == x`, so a disclosure bundle can
//!   be parsed by whoever receives it.
//! * **Cross-language stable.** An auditor may reimplement this in another
//!   language. That is why the format is a version byte, then length-prefixed
//!   fields in a fixed order, and nothing else — no varints, no self-describing
//!   tags, no floating point.
//!
//! The build plan (M4) names round-trip and cross-language
//! stability explicitly. `the_wire_format_is_pinned` fixes concrete bytes so a
//! reimplementation has something to check against, and so an accidental change
//! here fails CI rather than silently invalidating every anchored root.

/// Format version. Bump only with a migration plan: anchored roots commit to
/// these bytes, so a change is not backwards compatible by definition.
pub const CODEC_VERSION: u8 = 1;

/// Decoding failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The version byte is not one this build understands.
    UnsupportedVersion(u8),
    /// Input ended mid-field.
    Truncated,
    /// A length prefix exceeds the remaining input — malformed or hostile.
    LengthOverflow,
    /// Bytes remained after the last expected field.
    TrailingBytes(usize),
    /// A field held a value outside its domain.
    InvalidField(&'static str),
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported codec version {v}"),
            Self::Truncated => f.write_str("input ended mid-field"),
            Self::LengthOverflow => f.write_str("length prefix exceeds the remaining input"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after the last field"),
            Self::InvalidField(w) => write!(f, "field {w} held an out-of-domain value"),
        }
    }
}

impl core::error::Error for CodecError {}

/// Where an encoding's bytes go. The field logic is written once, in
/// [`Encoder`], and every sink receives exactly the same bytes: a buffer
/// ([`Writer`]), a byte count ([`Counter`]), or a hash absorbing them directly
/// (§1r.2: hashing a record without first assembling it).
pub trait Sink {
    /// Take the next bytes of the encoding.
    fn put(&mut self, bytes: &[u8]);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Counts an encoding's bytes without keeping them.
#[derive(Debug, Default)]
pub struct Counter(pub usize);

impl Sink for Counter {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

impl Sink for pqcl_primitives::xof::DomainStream {
    fn put(&mut self, bytes: &[u8]) {
        self.absorb(bytes);
    }
}

/// Builds a canonical encoding into any [`Sink`]: version byte, then
/// length-prefixed fields.
#[derive(Debug, Default)]
pub struct Encoder<S: Sink> {
    sink: S,
}

/// The buffer-building encoder every `encode()` uses.
pub type Writer = Encoder<Vec<u8>>;

impl<S: Sink> Encoder<S> {
    /// Start an encoding into `sink`, emitting the version byte.
    #[must_use]
    pub fn into_sink(mut sink: S) -> Self {
        sink.put(&[CODEC_VERSION]);
        Self { sink }
    }

    /// Append a length-prefixed field. The length is an 8-byte little-endian
    /// `u64`, matching draft6 eq. (3) so the codec and the commitment framing
    /// agree rather than being two nearly-identical schemes.
    pub fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.sink.put(&(bytes.len() as u64).to_le_bytes());
        self.sink.put(bytes);
        self
    }

    /// Append a `u64` as a fixed-width little-endian field.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.field(&v.to_le_bytes())
    }

    /// Append a single byte as a field, e.g. an enum discriminant.
    pub fn byte(&mut self, v: u8) -> &mut Self {
        self.field(&[v])
    }

    /// Append an optional field: one byte presence flag, then the value.
    ///
    /// The flag is separate rather than encoded as a zero length, because an
    /// absent field and a present empty one are different facts. A witness
    /// co-signature is absent on most records and empty on none; collapsing the
    /// two would let a record claim a co-signature it does not have.
    pub fn optional(&mut self, v: Option<&[u8]>) -> &mut Self {
        match v {
            None => self.byte(0),
            Some(b) => {
                self.byte(1);
                self.field(b)
            }
        }
    }

    /// The sink, holding everything written.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.sink
    }
}

impl Encoder<Vec<u8>> {
    /// Start a buffered encoding, emitting the version byte.
    #[must_use]
    pub fn new() -> Self {
        Self::into_sink(Vec::new())
    }

    /// Finish, yielding the canonical bytes.
    #[must_use]
    pub fn finish(&self) -> Vec<u8> {
        self.sink.clone()
    }
}

/// Reads a canonical encoding.
#[derive(Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Start reading, checking the version byte.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] on empty input;
    /// [`CodecError::UnsupportedVersion`] otherwise.
    pub fn new(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let (&v, rest) = bytes.split_first().ok_or(CodecError::Truncated)?;
        if v != CODEC_VERSION {
            return Err(CodecError::UnsupportedVersion(v));
        }
        Ok(Self { rest })
    }

    /// Read the next length-prefixed field.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] or [`CodecError::LengthOverflow`].
    pub fn field(&mut self) -> Result<&'a [u8], CodecError> {
        if self.rest.len() < 8 {
            return Err(CodecError::Truncated);
        }
        let (len_bytes, rest) = self.rest.split_at(8);
        let mut l = [0u8; 8];
        l.copy_from_slice(len_bytes);
        let len = usize::try_from(u64::from_le_bytes(l)).map_err(|_| CodecError::LengthOverflow)?;
        if rest.len() < len {
            return Err(CodecError::LengthOverflow);
        }
        let (val, rest) = rest.split_at(len);
        self.rest = rest;
        Ok(val)
    }

    /// Read a fixed-width `u64` field.
    ///
    /// # Errors
    ///
    /// As [`Reader::field`], plus [`CodecError::InvalidField`] on a wrong width.
    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let f = self.field()?;
        let a: [u8; 8] = f.try_into().map_err(|_| CodecError::InvalidField("u64"))?;
        Ok(u64::from_le_bytes(a))
    }

    /// Read a single-byte field.
    ///
    /// # Errors
    ///
    /// As [`Reader::field`], plus [`CodecError::InvalidField`] on a wrong width.
    pub fn byte(&mut self) -> Result<u8, CodecError> {
        let f = self.field()?;
        match f {
            [b] => Ok(*b),
            _ => Err(CodecError::InvalidField("byte")),
        }
    }

    /// Read an optional field.
    ///
    /// # Errors
    ///
    /// As [`Reader::field`], plus [`CodecError::InvalidField`] on a flag that
    /// is neither 0 nor 1 — which would otherwise be a second encoding of the
    /// same value and break injectivity.
    pub fn optional(&mut self) -> Result<Option<&'a [u8]>, CodecError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.field()?)),
            _ => Err(CodecError::InvalidField("optional flag")),
        }
    }

    /// Assert the input is fully consumed.
    ///
    /// # Errors
    ///
    /// [`CodecError::TrailingBytes`] if anything remains. Enforced because
    /// trailing bytes would let two encodings decode to the same value, and a
    /// signature over one would then transfer to the other.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes(self.rest.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_field_kind() {
        let mut w = Writer::new();
        w.field(b"hello")
            .u64(42)
            .byte(7)
            .optional(None)
            .optional(Some(b"sig"));
        let bytes = w.finish();

        let mut r = Reader::new(&bytes).expect("version");
        assert_eq!(r.field().expect("f"), b"hello");
        assert_eq!(r.u64().expect("u"), 42);
        assert_eq!(r.byte().expect("b"), 7);
        assert_eq!(r.optional().expect("o"), None);
        assert_eq!(r.optional().expect("o"), Some(&b"sig"[..]));
        r.finish().expect("consumed");
    }

    #[test]
    fn encoding_is_deterministic() {
        let build = || {
            let mut w = Writer::new();
            w.field(b"a").u64(1).optional(Some(b"z"));
            w.finish()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn the_encoding_is_injective_across_field_boundaries() {
        // The property that matters: ("ab","c") and ("a","bc") must not
        // collide, or a signature over one record would cover another.
        let mut a = Writer::new();
        a.field(b"ab").field(b"c");
        let mut b = Writer::new();
        b.field(b"a").field(b"bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn an_absent_field_differs_from_an_empty_one() {
        let mut a = Writer::new();
        a.optional(None);
        let mut b = Writer::new();
        b.optional(Some(b""));
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut w = Writer::new();
        w.field(b"x");
        let mut bytes = w.finish();
        bytes.push(0xff);
        let mut r = Reader::new(&bytes).expect("version");
        assert_eq!(r.field().expect("f"), b"x");
        assert_eq!(r.finish(), Err(CodecError::TrailingBytes(1)));
    }

    #[test]
    fn a_hostile_length_prefix_is_rejected_not_panicked() {
        // A length claiming more than the input holds must be an error, not an
        // allocation or a slice panic.
        let mut bytes = vec![CODEC_VERSION];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        let mut r = Reader::new(&bytes).expect("version");
        assert!(matches!(
            r.field(),
            Err(CodecError::LengthOverflow | CodecError::Truncated)
        ));
    }

    #[test]
    fn a_wrong_version_is_rejected() {
        assert_eq!(
            Reader::new(&[99u8, 0, 0]).err(),
            Some(CodecError::UnsupportedVersion(99))
        );
        assert_eq!(Reader::new(&[]).err(), Some(CodecError::Truncated));
    }

    #[test]
    fn an_invalid_optional_flag_is_rejected() {
        // Flag 2 would be a second encoding of a present-or-absent value.
        let mut w = Writer::new();
        w.byte(2);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes).expect("version");
        assert_eq!(r.optional(), Err(CodecError::InvalidField("optional flag")));
    }

    #[test]
    fn the_wire_format_is_pinned() {
        // Concrete bytes, so an auditor reimplementing this in another language
        // has something to check against — and so an accidental change here
        // fails CI instead of silently invalidating every anchored root.
        let mut w = Writer::new();
        w.field(b"ab").u64(1);
        assert_eq!(
            w.finish(),
            vec![
                1, // version
                2, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', // len = 2, then "ab"
                8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // len = 8, then 1u64
            ]
        );
    }
}
