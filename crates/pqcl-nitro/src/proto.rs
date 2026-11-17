//! The vsock wire protocol between the parent instance and the enclave.
//!
//! # What crosses the boundary, and what never does
//!
//! Every message here is a *request for a derived output* — a pseudonym, a
//! signature, a public key. ⛔ **No message returns a key**, and none may be
//! added. `K_mst` and `K_case` exist only inside the enclave; a
//! `Response::CaseKey` variant would defeat the entire boundary in one line and
//! is exactly the obvious-looking convenience to refuse.
//!
//! That is the same rule `AgentModule` states for the trait, restated here
//! because the wire format is a second place it could be broken independently.
//!
//! # Encoding
//!
//! `pqcl_capsule::codec`, the project's canonical length-framed encoding, rather
//! than serde or CBOR. Two reasons: a wire format needs unambiguous framing of
//! variable-length fields and that is precisely what the codec provides; and
//! reusing it means the encoding a reviewer has already checked is the encoding
//! on this path too.
//!
//! ⚠️ **Every decode is strict.** Trailing bytes, an unknown tag, or a short
//! field is an error rather than something tolerated. A permissive parser on a
//! security boundary is how a confused-deputy bug starts.

use pqcl_capsule::codec::{CodecError, Reader, Writer};
use pqcl_capsule::{ActorRef, Capsule, SealedDisclosure};
use pqcl_primitives::xof::Digest32;
use pqcl_sm::append::{AppendRequest, Appended, SealRequest};

use crate::appendwire::{
    append_request_bytes, appended_bytes, read_actor_ref, read_append_request, read_appended,
    read_seal_request, seal_request_bytes, write_actor_ref,
};

/// Request tags. Stable on the wire — ⛔ **never renumber**, and only append.
mod tag {
    pub(super) const ATTEST: u8 = 0x01;
    pub(super) const CAPSULE_PSEUDONYM: u8 = 0x02;
    pub(super) const SIGN_DEFR: u8 = 0x03;
    pub(super) const DEFR_PUBLIC_KEY: u8 = 0x04;
    // The `KeyCustody` half. `AgentModule: KeyCustody`, so the boundary owes
    // the whole surface — and it is what keeps M5a's "the identical suite
    // passes on both backends" property true once the enclave is a third.
    pub(super) const GENERATE_AES: u8 = 0x05;
    pub(super) const TRY_EXPORT: u8 = 0x06;
    pub(super) const AES_GCM_ENCRYPT: u8 = 0x07;
    pub(super) const AES_GCM_DECRYPT: u8 = 0x08;
    pub(super) const RANDOM: u8 = 0x09;
    // ⭐ M13 A18: the custody plane crosses the boundary. Before these four,
    // the module signed `σ_DEFR` and derived pseudonyms — so the boundary
    // covered the evidence plane and nothing on the custody plane, which is
    // the plane this work's title claims.
    pub(super) const CUSTODY_APPEND: u8 = 0x0a;
    // 0x0b was `COUNTERSIGN`, retired by §1br F2: `σ_witness` is sealed inside
    // `C_rec`, so it is made with the release, never added to a finished
    // record. Tags are append-only; 0x0b is never reused.
    pub(super) const ACTOR_PUBLIC_KEY: u8 = 0x0c;
    pub(super) const ENROLLED_ROLES: u8 = 0x0d;
    pub(super) const SEAL_CAPSULE: u8 = 0x0e;
    pub(super) const SEAL_DISCLOSURE: u8 = 0x0f;
}

/// Response tags. As above: stable, append-only.
mod rtag {
    pub(super) const ATTESTATION: u8 = 0x81;
    pub(super) const DIGEST: u8 = 0x82;
    pub(super) const BYTES: u8 = 0x83;
    pub(super) const ERROR: u8 = 0x84;
    pub(super) const HANDLE: u8 = 0x85;
    pub(super) const PROVISIONED: u8 = 0x86;
    pub(super) const APPENDED: u8 = 0x87;
    // 0x88 was `RECORD`, the counter-signed record; retired with 0x0b.
    pub(super) const ROLES: u8 = 0x89;
    pub(super) const CAPSULE: u8 = 0x8a;
    pub(super) const SEALED_DISCLOSURE: u8 = 0x8b;
}

/// Provisioning tag. ⛔ **Its own namespace, and never a [`Request`].** The
/// serving loop decodes only `Request`, so it cannot receive a provisioning
/// message at all — enforced by the type, not by a runtime branch someone
/// could later relax.
mod ptag {
    pub(super) const PROVISION: u8 = 0x40;
}

/// What the parent asks the enclave to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Ask the Nitro Security Module for an attestation document.
    ///
    /// The `nonce` is the caller's freshness challenge: it is embedded in the
    /// document, so a replayed document from an earlier boot does not satisfy a
    /// new request. ⚠️ A verifier that ignores the nonce gets no freshness at
    /// all, which is the usual way attestation is made decorative.
    Attest {
        /// Caller-chosen freshness challenge.
        nonce: Vec<u8>,
    },
    /// `eid = F(K_case, ⟪"eid", nonce⟫)`.
    CapsulePseudonym {
        /// `cid_c`, the case commitment.
        case_commitment: Digest32,
        /// The capsule nonce.
        nonce: Vec<u8>,
    },
    /// Sign the sealed capsule tuple as the Digital Evidence First Responder.
    SignDefr {
        /// The exact bytes to sign.
        message: Vec<u8>,
    },
    /// The DEFR verification key.
    DefrPublicKey,
    /// Generate a non-extractable AES-256 key inside the boundary.
    GenerateAes {
        /// A name for the object, not a security parameter.
        label: String,
    },
    /// Attempt to read a key out. ⭐ Must be refused for a key the boundary
    /// generated — that refusal is the only way to tell a module that protects
    /// keys from one nobody ever asked.
    TryExport {
        /// The key handle.
        handle: u64,
    },
    /// Encrypt under a key that never leaves.
    AesGcmEncrypt {
        /// The key handle.
        handle: u64,
        /// The 12-byte GCM nonce.
        nonce: [u8; 12],
        /// Additional authenticated data.
        aad: Vec<u8>,
        /// The plaintext.
        plaintext: Vec<u8>,
    },
    /// Decrypt under a key that never leaves.
    AesGcmDecrypt {
        /// The key handle.
        handle: u64,
        /// The 12-byte GCM nonce.
        nonce: [u8; 12],
        /// Additional authenticated data.
        aad: Vec<u8>,
        /// The ciphertext with its tag appended.
        ciphertext: Vec<u8>,
    },
    /// Random bytes from the boundary's generator.
    Random {
        /// How many.
        len: u64,
    },
    /// ⭐ **Build, seal, sign and index one custody record inside the
    /// boundary** (M13 A18) — one round trip per record.
    ///
    /// Boxed because an [`AppendRequest`] carries a predecessor record with a
    /// 3309-byte ML-DSA signature, and an unboxed variant would make every
    /// other request that large.
    CustodyAppend(Box<AppendRequest>),
    /// An enrolled actor's **verification** key, which an auditor needs to
    /// check `σ_actor`.
    ///
    /// ⛔ There is deliberately no request for a *signing* key, and none may be
    /// added — see this module's opening note.
    ActorPublicKey {
        /// Whose, by `(role, id)`.
        actor: ActorRef,
    },
    /// Which actors this module can sign as. Tag 0x0d, which named roles
    /// only until `(role, id)` enrolment.
    Enrolled,
    /// ⭐ Seal one capsule with the enclave's own first responder, so `σ_DEFR`
    /// and the `COLLECT` that opens the chain cannot come from two keys.
    SealCapsule(Box<SealRequest>),
    /// ⭐ One capsule's disclosure keys, **sealed to the court** (M13 A18).
    ///
    /// The lab's half of a court disclosure. Under Nitro `K_link` and `K_coc`
    /// are here, so without this request no bundle can be built for a record
    /// the enclave made. The answer is ciphertext under `court_ek`, never the
    /// keys; see [`pqcl_capsule::SealedDisclosure`] for what that does and
    /// does not stop.
    SealDisclosure {
        /// `cid_c`, the case commitment.
        case_commitment: Digest32,
        /// The capsule.
        eid: Digest32,
        /// The court's ML-KEM-768 encapsulation key.
        court_ek: Vec<u8>,
    },
}

/// What comes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// A CBOR/COSE attestation document, verbatim from the NSM.
    ///
    /// Passed through unparsed on purpose: the party that must be convinced by
    /// it is **AWS KMS**, which does its own verification when it enforces the
    /// key policy. Re-implementing COSE verification here would add a second,
    /// weaker verifier for a property something else already enforces.
    Attestation(Vec<u8>),
    /// A 32-byte derived value.
    Digest(Digest32),
    /// A variable-length value: a signature, a public key.
    Bytes(Vec<u8>),
    /// A key handle. Carries no key material and no means of obtaining any.
    Handle(u64),
    /// The enclave refused or failed, with a reason safe to show the parent.
    ///
    /// ⚠️ Deliberately a *string*, not a structured error carrying internals.
    /// The parent is outside the boundary; an error that leaked which key or
    /// which offset failed would be a side channel.
    Error(String),
    /// The enclave obtained `K_mst` from KMS and is about to serve. Carries
    /// nothing — in particular not the key, nor anything derived from it.
    Provisioned,
    /// A signed, sealed, indexed custody record with its openings (M13 A18).
    Appended(Box<Appended>),
    /// The enrolled actors, by `(role, id)`. Tag 0x89, which carried role
    /// bytes only until `(role, id)` enrolment.
    Actors(Vec<ActorRef>),
    /// A sealed capsule.
    Capsule(Box<Capsule>),
    /// One capsule's disclosure keys, sealed to the court.
    SealedDisclosure(Box<SealedDisclosure>),
}

/// The one message the enclave accepts **before** it holds `K_mst`: what
/// `kmstool_enclave_cli decrypt` needs, sent by the parent at boot.
///
/// ⛔ **Why not the image.** The first design read these from the enclave's
/// environment, "set by `nitro/Dockerfile`". An enclave's environment *is* its
/// image, so that meant baking live IAM credentials into the EIF — where they
/// expire within hours, and where every refresh would move PCR0 and orphan the
/// key policy conditioned on it. Nothing set them, so the enclave would have
/// failed at `PQCL_KMS_REGION is unset` on its first AWS boot. Provisioning over
/// vsock keeps PCR0 a function of the code alone.
///
/// ⭐ **Sending credentials across is sound.** They are the parent role's own,
/// and they are not what authorises the decrypt: the key policy's PCR0
/// condition is, checked by KMS against the NSM-signed attestation that
/// `kmstool` attaches. A parent that lies here gains nothing it did not have.
///
/// ⚠️ They are still secrets, so [`Debug`](core::fmt::Debug) redacts them and
/// this type deliberately does not derive it.
#[derive(Clone, PartialEq, Eq)]
pub struct Provision {
    /// KMS region, e.g. `us-east-1`.
    pub region: String,
    /// The parent's `vsock-proxy` port forwarding to the KMS endpoint.
    pub proxy_port: u32,
    /// `K_mst` wrapped under the KMS key, base64 — ciphertext, useless without
    /// a KMS decision.
    pub ciphertext_b64: String,
    /// Parent role credential: access key id.
    pub access_key_id: String,
    /// Parent role credential: secret access key.
    pub secret_access_key: String,
    /// Parent role credential: session token.
    pub session_token: String,
}

impl core::fmt::Debug for Provision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Provision")
            .field("region", &self.region)
            .field("proxy_port", &self.proxy_port)
            .field(
                "ciphertext_b64",
                &format_args!("<{} chars>", self.ciphertext_b64.len()),
            )
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .finish()
    }
}

impl Provision {
    /// Encode for the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.byte(ptag::PROVISION)
            .field(self.region.as_bytes())
            .u64(u64::from(self.proxy_port))
            .field(self.ciphertext_b64.as_bytes())
            .field(self.access_key_id.as_bytes())
            .field(self.secret_access_key.as_bytes())
            .field(self.session_token.as_bytes());
        w.finish()
    }

    /// Decode from the wire.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on any other tag — including every [`Request`] tag — a
    /// short or non-UTF-8 field, a port over `u32`, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        fn text(r: &mut Reader<'_>, what: &'static str) -> Result<String, CodecError> {
            String::from_utf8(r.field()?.to_vec()).map_err(|_| CodecError::InvalidField(what))
        }
        let mut r = Reader::new(bytes)?;
        if r.byte()? != ptag::PROVISION {
            return Err(CodecError::InvalidField("not a provisioning message"));
        }
        let out = Self {
            region: text(&mut r, "region is not UTF-8")?,
            proxy_port: u32::try_from(r.u64()?)
                .map_err(|_| CodecError::InvalidField("proxy port exceeds u32"))?,
            ciphertext_b64: text(&mut r, "ciphertext is not UTF-8")?,
            access_key_id: text(&mut r, "access key id is not UTF-8")?,
            secret_access_key: text(&mut r, "secret access key is not UTF-8")?,
            session_token: text(&mut r, "session token is not UTF-8")?,
        };
        r.finish()?;
        Ok(out)
    }
}

impl Request {
    /// Encode for the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::Attest { nonce } => {
                w.byte(tag::ATTEST).field(nonce);
            }
            Self::CapsulePseudonym {
                case_commitment,
                nonce,
            } => {
                w.byte(tag::CAPSULE_PSEUDONYM)
                    .field(case_commitment)
                    .field(nonce);
            }
            Self::SignDefr { message } => {
                w.byte(tag::SIGN_DEFR).field(message);
            }
            Self::DefrPublicKey => {
                w.byte(tag::DEFR_PUBLIC_KEY);
            }
            Self::GenerateAes { label } => {
                w.byte(tag::GENERATE_AES).field(label.as_bytes());
            }
            Self::TryExport { handle } => {
                w.byte(tag::TRY_EXPORT).u64(*handle);
            }
            Self::AesGcmEncrypt {
                handle,
                nonce,
                aad,
                plaintext,
            } => {
                w.byte(tag::AES_GCM_ENCRYPT)
                    .u64(*handle)
                    .field(nonce)
                    .field(aad)
                    .field(plaintext);
            }
            Self::AesGcmDecrypt {
                handle,
                nonce,
                aad,
                ciphertext,
            } => {
                w.byte(tag::AES_GCM_DECRYPT)
                    .u64(*handle)
                    .field(nonce)
                    .field(aad)
                    .field(ciphertext);
            }
            Self::Random { len } => {
                w.byte(tag::RANDOM).u64(*len);
            }
            Self::CustodyAppend(q) => {
                w.byte(tag::CUSTODY_APPEND).field(&append_request_bytes(q));
            }
            Self::ActorPublicKey { actor } => {
                w.byte(tag::ACTOR_PUBLIC_KEY);
                write_actor_ref(&mut w, actor);
            }
            Self::Enrolled => {
                w.byte(tag::ENROLLED_ROLES);
            }
            Self::SealCapsule(q) => {
                w.byte(tag::SEAL_CAPSULE).field(&seal_request_bytes(q));
            }
            Self::SealDisclosure {
                case_commitment,
                eid,
                court_ek,
            } => {
                w.byte(tag::SEAL_DISCLOSURE)
                    .field(case_commitment)
                    .field(eid)
                    .field(court_ek);
            }
        }
        w.finish()
    }

    /// Decode from the wire.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on an unknown tag, a short field, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let out = match r.byte()? {
            tag::ATTEST => Self::Attest {
                nonce: r.field()?.to_vec(),
            },
            tag::CAPSULE_PSEUDONYM => {
                let cc: Digest32 = r
                    .field()?
                    .try_into()
                    .map_err(|_| CodecError::InvalidField("case commitment must be 32 bytes"))?;
                Self::CapsulePseudonym {
                    case_commitment: cc,
                    nonce: r.field()?.to_vec(),
                }
            }
            tag::SIGN_DEFR => Self::SignDefr {
                message: r.field()?.to_vec(),
            },
            tag::DEFR_PUBLIC_KEY => Self::DefrPublicKey,
            tag::GENERATE_AES => Self::GenerateAes {
                label: String::from_utf8(r.field()?.to_vec())
                    .map_err(|_| CodecError::InvalidField("label is not UTF-8"))?,
            },
            tag::TRY_EXPORT => Self::TryExport { handle: r.u64()? },
            tag::AES_GCM_ENCRYPT => Self::AesGcmEncrypt {
                handle: r.u64()?,
                nonce: nonce12(r.field()?)?,
                aad: r.field()?.to_vec(),
                plaintext: r.field()?.to_vec(),
            },
            tag::AES_GCM_DECRYPT => Self::AesGcmDecrypt {
                handle: r.u64()?,
                nonce: nonce12(r.field()?)?,
                aad: r.field()?.to_vec(),
                ciphertext: r.field()?.to_vec(),
            },
            tag::RANDOM => Self::Random { len: r.u64()? },
            tag::CUSTODY_APPEND => Self::CustodyAppend(Box::new(read_append_request(r.field()?)?)),
            tag::ACTOR_PUBLIC_KEY => Self::ActorPublicKey {
                actor: read_actor_ref(&mut r)?,
            },
            tag::ENROLLED_ROLES => Self::Enrolled,
            tag::SEAL_CAPSULE => Self::SealCapsule(Box::new(read_seal_request(r.field()?)?)),
            tag::SEAL_DISCLOSURE => {
                let digest = |f: &[u8]| -> Result<Digest32, CodecError> {
                    f.try_into()
                        .map_err(|_| CodecError::InvalidField("a digest must be 32 bytes"))
                };
                Self::SealDisclosure {
                    case_commitment: digest(r.field()?)?,
                    eid: digest(r.field()?)?,
                    court_ek: r.field()?.to_vec(),
                }
            }
            _ => return Err(CodecError::InvalidField("unknown request tag")),
        };
        r.finish()?;
        Ok(out)
    }
}

impl Response {
    /// Encode for the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::Attestation(d) => {
                w.byte(rtag::ATTESTATION).field(d);
            }
            Self::Digest(d) => {
                w.byte(rtag::DIGEST).field(d);
            }
            Self::Bytes(b) => {
                w.byte(rtag::BYTES).field(b);
            }
            Self::Handle(h) => {
                w.byte(rtag::HANDLE).u64(*h);
            }
            Self::Error(m) => {
                w.byte(rtag::ERROR).field(m.as_bytes());
            }
            Self::Appended(a) => {
                w.byte(rtag::APPENDED).field(&appended_bytes(a));
            }
            Self::Actors(actors) => {
                w.byte(rtag::ROLES).u64(actors.len() as u64);
                for a in actors {
                    write_actor_ref(&mut w, a);
                }
            }
            Self::Capsule(c) => {
                w.byte(rtag::CAPSULE).field(&c.encode());
            }
            Self::SealedDisclosure(s) => {
                w.byte(rtag::SEALED_DISCLOSURE).field(&s.encode());
            }
            Self::Provisioned => {
                w.byte(rtag::PROVISIONED);
            }
        }
        w.finish()
    }

    /// Decode from the wire.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on an unknown tag, a short field, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let out = match r.byte()? {
            rtag::ATTESTATION => Self::Attestation(r.field()?.to_vec()),
            rtag::DIGEST => {
                let d: Digest32 = r
                    .field()?
                    .try_into()
                    .map_err(|_| CodecError::InvalidField("digest must be 32 bytes"))?;
                Self::Digest(d)
            }
            rtag::BYTES => Self::Bytes(r.field()?.to_vec()),
            rtag::HANDLE => Self::Handle(r.u64()?),
            rtag::ERROR => Self::Error(
                String::from_utf8(r.field()?.to_vec())
                    .map_err(|_| CodecError::InvalidField("error message is not UTF-8"))?,
            ),
            rtag::APPENDED => Self::Appended(Box::new(read_appended(r.field()?)?)),
            rtag::ROLES => {
                // Each role validated on the way in (`read_actor`), so a caller
                // never has to wonder whether one it reads back is real.
                let n = usize::try_from(r.u64()?).map_err(|_| CodecError::LengthOverflow)?;
                let mut actors = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    actors.push(read_actor_ref(&mut r)?);
                }
                Self::Actors(actors)
            }
            rtag::CAPSULE => Self::Capsule(Box::new(Capsule::decode(r.field()?)?)),
            rtag::SEALED_DISCLOSURE => {
                Self::SealedDisclosure(Box::new(SealedDisclosure::decode(r.field()?)?))
            }
            rtag::PROVISIONED => Self::Provisioned,
            _ => return Err(CodecError::InvalidField("unknown response tag")),
        };
        r.finish()?;
        Ok(out)
    }
}

/// A GCM nonce is exactly 12 bytes; anything else is malformed rather than
/// something to pad or truncate.
fn nonce12(bytes: &[u8]) -> Result<[u8; 12], CodecError> {
    bytes
        .try_into()
        .map_err(|_| CodecError::InvalidField("a GCM nonce must be 12 bytes"))
}

/// Length-prefix a message for a stream transport.
///
/// vsock is a stream, so messages need their own framing; without it two
/// requests sent back to back are indistinguishable from one long request.
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

/// The largest message accepted off the wire.
///
/// ⚠️ **A bound, not a guess.** The parent is untrusted; without a cap it could
/// announce a 4 GiB message and make the enclave allocate it. The largest
/// legitimate message is a `SignDefr` over a capsule tuple, which is far below
/// this.
pub const MAX_FRAME: usize = 1 << 20;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use pqcl_capsule::{CustodyRecord, Event, Role};
    use pqcl_pipeline::RecordParams;
    use pqcl_sm::append::AppendStep;

    use super::*;
    use crate::appendwire::append_request_bytes;

    /// A plausible custody record. Hand-built from public fields rather than
    /// signed for real, because what is under test is the **codec**: a record
    /// produced by the module would exercise the same encoder over the same
    /// field shapes, at the cost of a case setup inside a unit test.
    fn record() -> CustodyRecord {
        CustodyRecord {
            rid: [0x11; 32],
            eid_e: [0x22; 32],
            h_prev: [0x33; 32],
            body: vec![0x44; 96],
            order_ref: Some([0x55; 32]),
        }
    }

    /// A plausible sealed capsule, again from public fields: the codec is what
    /// is under test, and a real `Agent::seal` would exercise the same encoder.
    fn capsule() -> pqcl_capsule::Capsule {
        pqcl_capsule::Capsule {
            eid: [0xa2; 32],
            cid_c: [0xa1; 32],
            epoch: 3,
            artefact_type: b"disk-image".to_vec(),
            d_ev: [0xc1; 32],
            cm_ev: [0xc2; 32],
            ptr: b"s3://bucket/key".to_vec(),
            provenance: pqcl_capsule::Provenance::Attested,
            gap_seconds: 0,
            sig_defr: vec![0x88; 3309],
        }
    }

    /// What pairs a receipt with its release.
    fn pairing() -> pqcl_sm::Pairing {
        pqcl_sm::Pairing {
            handoff: pqcl_pipeline::handoff::Handoff {
                eid_e: [0xd1; 32],
                from: [0xd2; 32],
                to: [0xd3; 32],
                cond: [0xd4; 32],
                r_cap: [0xd5; 32],
            },
            receiving: pqcl_pipeline::handoff::Receiving {
                actor: pqcl_capsule::ActorOpening {
                    id: b"custodian-1".to_vec(),
                    role: Role::Custodian,
                    r_a: [0xd6; 32],
                },
            },
        }
    }

    fn append_request() -> AppendRequest {
        AppendRequest {
            cid_c: [0xa1; 32],
            capsule: [0xa2; 32].into(),
            actor: pqcl_capsule::ActorRef::new(Role::Custodian, b"evidence-store-1"),
            doc: 42,
            params: RecordParams::at(7, 1_700_000_000)
                .with_params(pqcl_capsule::Params::of(b"dd", b"8.45", b"if=/dev/sda"))
                .with_note(b"bagged".to_vec())
                .in_epoch(3),
            step: AppendStep::Append {
                event: Event::Transfer,
                previous: Box::new(record()),
            },
        }
    }

    fn appended() -> Appended {
        Appended {
            signed: pqcl_pipeline::Signed {
                record: record(),
                body: pqcl_capsule::RecordBody {
                    event: Event::Transfer,
                    ts: 1_700_000_000,
                    actor_c: [0xb1; 32],
                    params_c: [0xb2; 32],
                    link: [0xb3; 32],
                    note: b"bagged".to_vec(),
                },
                actor: pqcl_capsule::ActorOpening {
                    id: b"officer-7".to_vec(),
                    role: Role::Custodian,
                    r_a: [0xb4; 32],
                },
                params: Some(pqcl_capsule::ParamsOpening {
                    params: pqcl_capsule::Params::justified(b"handover"),
                    r_p: [0xb5; 32],
                }),
            },
            tokens: (0..3)
                .map(|i| pqcl_dsse::core::UpdateToken {
                    addr: [i; 32],
                    val: pqcl_primitives::aead::SealedRecord::from_bytes(vec![i; 25]),
                })
                .collect(),
            // A release's answer; the `None` form is covered by the second
            // `Response::Appended` fixture below.
            pairing: Some(Box::new(pairing())),
        }
    }

    /// ⭐ **Every variant, and a test proves it is every variant.**
    ///
    /// Five of the nine original requests were missing here, so
    /// `requests_round_trip` and `a_truncated_message_is_refused` were running
    /// correctly against a fixture that did not describe the protocol — rule
    /// 13's third shape, a check against the wrong input. See
    /// [`the_request_fixture_covers_every_tag_the_decoder_accepts`].
    fn requests() -> Vec<Request> {
        vec![
            Request::Attest {
                nonce: vec![1, 2, 3],
            },
            Request::Attest { nonce: Vec::new() },
            Request::CapsulePseudonym {
                case_commitment: [7u8; 32],
                nonce: vec![9; 16],
            },
            Request::SignDefr {
                message: vec![0xab; 500],
            },
            Request::DefrPublicKey,
            Request::GenerateAes {
                label: "k-case".to_owned(),
            },
            Request::TryExport { handle: 9 },
            Request::AesGcmEncrypt {
                handle: 3,
                nonce: [0x5a; 12],
                aad: b"aad".to_vec(),
                plaintext: vec![0x1c; 64],
            },
            Request::AesGcmDecrypt {
                handle: 3,
                nonce: [0x5a; 12],
                aad: Vec::new(),
                ciphertext: vec![0x2d; 80],
            },
            Request::Random { len: 32 },
            Request::CustodyAppend(Box::new(append_request())),
            Request::CustodyAppend(Box::new(AppendRequest {
                step: AppendStep::Collect,
                params: RecordParams::at(0, 1_700_000_001),
                ..append_request()
            })),
            Request::CustodyAppend(Box::new(AppendRequest {
                actor: pqcl_capsule::ActorRef::new(Role::Custodian, b"lab-custodian-1"),
                step: AppendStep::Dispose {
                    previous: Box::new(record()),
                    order_id: None,
                },
                ..append_request()
            })),
            Request::CustodyAppend(Box::new(AppendRequest {
                step: AppendStep::Release {
                    capsule: Box::new(capsule()),
                    chain: vec![record(), record()],
                    cond: [0xcd; 32],
                    witness: pqcl_capsule::ActorRef::new(Role::Custodian, b"lab-custodian-1"),
                },
                ..append_request()
            })),
            Request::CustodyAppend(Box::new(AppendRequest {
                step: AppendStep::Receipt {
                    capsule: Box::new(capsule()),
                    chain: vec![record()],
                    recomputed: [0xc1; 32],
                    pairing: Box::new(pairing()),
                },
                ..append_request()
            })),
            Request::ActorPublicKey {
                actor: pqcl_capsule::ActorRef::new(Role::Des, b"specialist-1"),
            },
            Request::Enrolled,
            Request::SealCapsule(Box::new(SealRequest {
                cid_c: [0xa1; 32],
                cm_ev: [0xc2; 32],
                nonce: [0xe1; 32],
                epoch: 3,
                artefact_type: b"disk-image".to_vec(),
                d_ev: [0xc1; 32],
                ptr: b"s3://bucket/key".to_vec(),
            })),
            Request::SealDisclosure {
                case_commitment: [0xa1; 32],
                eid: [0xe2; 32],
                court_ek: vec![0x5e; 1184],
            },
        ]
    }

    fn responses() -> Vec<Response> {
        vec![
            Response::Attestation(vec![0xcb; 300]),
            Response::Digest([3u8; 32]),
            Response::Bytes(vec![0xff; 3309]),
            Response::Handle(17),
            Response::Error("refused".to_owned()),
            Response::Provisioned,
            Response::Appended(Box::new(appended())),
            // ⭐ Both shapes of the optional pair, because `optional` encodes
            // them differently and a fixture with only one would leave the
            // other's decode untested.
            Response::Appended(Box::new(Appended {
                pairing: None,
                ..appended()
            })),
            Response::Actors(vec![
                ActorRef::new(Role::Defr, b"first-responder-1"),
                ActorRef::new(Role::Custodian, b"lab-custodian-1"),
            ]),
            Response::Capsule(Box::new(capsule())),
            Response::SealedDisclosure(Box::new(pqcl_capsule::SealedDisclosure {
                cid_c: [0xa1; 32],
                eid: [0xe2; 32],
                kem_ct: vec![0x6b; 1088],
                sealed: pqcl_primitives::aead::SealedRecord::from_bytes(vec![0x5d; 124]),
            })),
        ]
    }

    /// The tag a message carries, read the way the decoder reads it rather
    /// than by indexing into the bytes past the version prefix.
    fn tag_of(encoded: &[u8]) -> u8 {
        Reader::new(encoded)
            .expect("a framed message")
            .byte()
            .expect("a tag byte")
    }

    /// One bare tag byte, framed — enough to tell "unknown tag" from "known
    /// tag, missing fields".
    fn one_tag(t: u8) -> Vec<u8> {
        let mut w = Writer::new();
        w.byte(t);
        w.finish()
    }

    fn provision() -> Provision {
        Provision {
            region: "us-east-1".to_owned(),
            proxy_port: 8000,
            ciphertext_b64: "AQIDBA==".to_owned(),
            access_key_id: "AKIA-FIXTURE".to_owned(),
            secret_access_key: "secret-fixture-value".to_owned(),
            session_token: "token-fixture-value".to_owned(),
        }
    }

    #[test]
    fn provision_round_trips() {
        let p = provision();
        assert_eq!(Provision::decode(&p.encode()).expect("decodes"), p);
    }

    /// ⭐ The namespace separation, from both sides: the serving loop decodes
    /// only `Request`, so a provisioning message must not decode as one, and
    /// no request may be mistaken for provisioning.
    #[test]
    fn provisioning_and_requests_never_cross() {
        assert!(Request::decode(&provision().encode()).is_err());
        for r in requests() {
            assert!(
                Provision::decode(&r.encode()).is_err(),
                "{r:?} decoded as provisioning"
            );
        }
    }

    #[test]
    fn provision_debug_redacts_every_credential() {
        let shown = format!("{:?}", provision());
        for secret in [
            "AKIA-FIXTURE",
            "secret-fixture-value",
            "token-fixture-value",
            "AQIDBA==",
        ] {
            assert!(!shown.contains(secret), "Debug leaked {secret}: {shown}");
        }
        assert!(
            shown.contains("us-east-1"),
            "non-secret fields stay visible: {shown}"
        );
    }

    #[test]
    fn a_truncated_provision_is_refused() {
        let e = provision().encode();
        for cut in 1..e.len() {
            assert!(
                Provision::decode(&e[..cut]).is_err(),
                "truncated at {cut} decoded"
            );
        }
    }

    #[test]
    fn a_proxy_port_over_u32_is_refused() {
        let mut w = Writer::new();
        w.byte(ptag::PROVISION)
            .field(b"us-east-1")
            .u64(u64::from(u32::MAX) + 1)
            .field(b"ct")
            .field(b"a")
            .field(b"s")
            .field(b"t");
        assert!(Provision::decode(&w.finish()).is_err());
    }

    #[test]
    fn requests_round_trip() {
        for r in requests() {
            assert_eq!(Request::decode(&r.encode()).expect("decodes"), r);
        }
    }

    #[test]
    fn responses_round_trip() {
        for r in responses() {
            assert_eq!(Response::decode(&r.encode()).expect("decodes"), r);
        }
    }

    /// ⭐ **Rule 14: derive the universe, do not transcribe it.**
    ///
    /// The set of request variants is taken from the **decoder itself** — a tag
    /// it does not reject as unknown is a variant that exists — and compared
    /// against the tags the fixture actually produces. So a new variant cannot
    /// be added without either appearing in `requests()` or failing here, and
    /// no hand-kept list can go stale instead.
    ///
    /// A list of tag constants would not do: adding a constant and forgetting
    /// to list it would leave the test passing over a universe that had
    /// changed, which is the exact failure this project has hit seven times.
    #[test]
    fn the_request_fixture_covers_every_tag_the_decoder_accepts() {
        let accepted: BTreeSet<u8> = (0u8..=0xff)
            .filter(|t| {
                !matches!(
                    Request::decode(&one_tag(*t)),
                    Err(CodecError::InvalidField("unknown request tag"))
                )
            })
            .collect();
        let covered: BTreeSet<u8> = requests().iter().map(|r| tag_of(&r.encode())).collect();
        assert_eq!(
            covered, accepted,
            "the request fixture and the decoder disagree about which variants exist"
        );
    }

    /// ⭐ **And the same, one level down**, for the append steps.
    ///
    /// The tag-level test above cannot see these: every step travels inside one
    /// `CustodyAppend` tag, so a new step could be added and never appear in a
    /// fixture while every tag stayed covered. That is rule 13's second shape —
    /// a check running correctly against nothing — so the step universe gets
    /// its own derived check, again taken from the decoder rather than from a
    /// list.
    #[test]
    fn the_fixture_covers_every_append_step_the_decoder_accepts() {
        /// One bare step discriminant inside an otherwise well-formed request,
        /// enough to tell "unknown step" from "known step, missing fields".
        fn with_step(d: u8) -> Vec<u8> {
            let mut step = Writer::new();
            step.byte(d);
            let mut inner = Writer::new();
            inner.field(&[0xa1; 32]).field(&[0xa2; 32]);
            write_actor_ref(&mut inner, &append_request().actor);
            inner
                .u64(1)
                .field(&record_params_probe())
                .field(&step.finish());
            let mut outer = Writer::new();
            outer.byte(tag::CUSTODY_APPEND).field(&inner.finish());
            outer.finish()
        }

        let accepted: BTreeSet<u8> = (0u8..=0xff)
            .filter(|d| {
                !matches!(
                    Request::decode(&with_step(*d)),
                    Err(CodecError::InvalidField("unknown append-step discriminant"))
                )
            })
            .collect();

        let covered: BTreeSet<u8> = requests()
            .iter()
            .filter_map(|r| match r {
                Request::CustodyAppend(q) => {
                    // Read the step's own discriminant back out of the wire
                    // form, so this measures the encoding and not the enum.
                    let encoded = append_request_bytes(q);
                    let mut rd = Reader::new(&encoded).expect("framed");
                    rd.field().expect("cid_c");
                    rd.field().expect("eid");
                    rd.byte().expect("role");
                    rd.field().expect("actor id");
                    rd.u64().expect("doc");
                    rd.field().expect("params");
                    let step = rd.field().expect("step");
                    Some(tag_of(step))
                }
                _ => None,
            })
            .collect();

        assert_eq!(
            covered, accepted,
            "the append-step fixture and the decoder disagree about which steps exist"
        );
    }

    /// As above, for responses.
    #[test]
    fn the_response_fixture_covers_every_tag_the_decoder_accepts() {
        let accepted: BTreeSet<u8> = (0u8..=0xff)
            .filter(|t| {
                !matches!(
                    Response::decode(&one_tag(*t)),
                    Err(CodecError::InvalidField("unknown response tag"))
                )
            })
            .collect();
        let covered: BTreeSet<u8> = responses().iter().map(|r| tag_of(&r.encode())).collect();
        assert_eq!(
            covered, accepted,
            "the response fixture and the decoder disagree about which variants exist"
        );
    }

    /// ⭐ Truncation, over **every** request rather than one of them.
    ///
    /// The append messages are the ones that matter here: they are the only
    /// deeply nested structures on this wire, and a nested decoder that read
    /// past its own frame would show up as a prefix that decodes.
    #[test]
    fn every_truncation_of_every_request_is_refused() {
        for r in requests() {
            let e = r.encode();
            for cut in 1..e.len() {
                assert!(
                    Request::decode(&e[..cut]).is_err(),
                    "{r:?} truncated at {cut} of {} decoded",
                    e.len()
                );
            }
        }
    }

    /// An out-of-domain role must be refused by the **parser**, not forwarded
    /// to the module to fail as a lookup miss.
    #[test]
    fn a_role_outside_the_four_is_refused() {
        for bad in [0u8, 5, 0xff] {
            let mut w = Writer::new();
            w.byte(tag::ACTOR_PUBLIC_KEY).byte(bad);
            assert!(
                Request::decode(&w.finish()).is_err(),
                "role byte {bad} decoded"
            );
        }
    }

    /// Likewise an event outside the seven.
    #[test]
    fn an_event_outside_the_seven_is_refused() {
        let inner = append_request_bytes(&append_request());
        // The step frame is the last field; rebuild it with a bad event byte.
        let mut step = Writer::new();
        step.byte(0x01).byte(0x7f).field(&record().encode());
        let mut w = Writer::new();
        w.field(&[0xa1; 32]).field(&[0xa2; 32]);
        write_actor_ref(&mut w, &append_request().actor);
        w.u64(42)
            .field(&record_params_probe())
            .field(&step.finish());
        let bad = w.finish();
        assert_ne!(inner, bad, "the probe must differ from the good encoding");
        let mut outer = Writer::new();
        outer.byte(tag::CUSTODY_APPEND).field(&bad);
        assert!(Request::decode(&outer.finish()).is_err());
    }

    /// The `RecordParams` frame of [`append_request`], extracted so the probe
    /// above can reuse it verbatim instead of restating its layout.
    fn record_params_probe() -> Vec<u8> {
        let encoded = append_request_bytes(&append_request());
        let mut r = Reader::new(&encoded).expect("framed");
        r.field().expect("cid_c");
        r.field().expect("eid");
        r.byte().expect("role");
        r.field().expect("actor id");
        r.u64().expect("doc");
        r.field().expect("params").to_vec()
    }

    #[test]
    fn an_unknown_tag_is_refused() {
        assert!(Request::decode(&[0xee]).is_err());
        assert!(Response::decode(&[0xee]).is_err());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut e = Request::DefrPublicKey.encode();
        e.push(0x00);
        assert!(
            Request::decode(&e).is_err(),
            "a request with junk appended must not decode"
        );
    }

    #[test]
    fn a_truncated_message_is_refused() {
        let e = Request::SignDefr {
            message: vec![1; 40],
        }
        .encode();
        for cut in 1..e.len() {
            assert!(
                Request::decode(&e[..cut]).is_err(),
                "a message truncated at {cut} must not decode"
            );
        }
    }

    #[test]
    fn a_wrong_sized_digest_is_refused() {
        // A 31-byte case commitment must not be accepted as a 32-byte one.
        let mut w = Writer::new();
        w.byte(0x02).field(&[0u8; 31]).field(b"nonce");
        assert!(Request::decode(&w.finish()).is_err());
    }

    #[test]
    fn framing_carries_the_length() {
        let payload = vec![0xaa; 300];
        let f = frame(&payload);
        assert_eq!(&f[..4], &300u32.to_be_bytes());
        assert_eq!(&f[4..], &payload[..]);
    }

    /// ⛔ The boundary's defining property, asserted against the wire format
    /// rather than only against the trait. If a future variant returned key
    /// material, this is the test that should have caught it.
    #[test]
    fn no_response_variant_carries_a_key() {
        /// ⭐ Exhaustive with no wildcard. Adding a variant breaks this match,
        /// which forces whoever adds it to decide whether it carries key
        /// material — the `Handle` arm was added exactly that way. A `Handle`
        /// *names* a key; it is not one, and carries no means of obtaining one.
        const fn carries_key_material(r: &Response) -> bool {
            match r {
                // `Provisioned` is a bare acknowledgement: it reports that
                // KMS released the key, and carries nothing of it.
                //
                // ⭐ `Appended` is the one that needed thought (M13 A18). It
                // carries `r_a` and `r_p` — λ-bit secrets — but they are
                // **commitment blinds, not keys**: they open a commitment to
                // data the parent itself supplied, the parent must keep them
                // for a court to open `actor_c` and `params_c`, and on the
                // host path the parent drew them. Nothing about the key
                // hierarchy is recoverable from them. It also carries Π_core
                // tokens, which are what the server receives anyway.
                //
                // `Actors` carries enrolled names and roles, no key.
                Response::Attestation(_)
                | Response::Digest(_)
                | Response::Bytes(_)
                | Response::Handle(_)
                | Response::Error(_)
                | Response::Provisioned
                | Response::Appended(_)
                | Response::Actors(_)
                // A sealed capsule: commitments and a signature, the object the
                // AIS stores in the clear anyway.
                | Response::Capsule(_)
                // ⭐ Disclosure keys, but **sealed to the court's ML-KEM key**
                // (M13 A18): the parent relays ciphertext it cannot open. The
                // court key arrives in the request, so this holds against a
                // parent that leaks, not one that names its own key — see
                // `SealedDisclosure`. Keys in the clear here would be `true`.
                | Response::SealedDisclosure(_) => false,
            }
        }

        for r in responses() {
            assert!(
                !carries_key_material(&r),
                "a response variant carries key material: {r:?}"
            );
        }
    }
}
