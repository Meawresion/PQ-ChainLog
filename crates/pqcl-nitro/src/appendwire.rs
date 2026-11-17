//! Wire encoding for the custody-append messages (M13 A18).
//!
//! # Why the codec is here and not in `pqcl-capsule`
//!
//! `Params`, `ActorOpening`, `ParamsOpening`, `RecordParams` and `Signed` have
//! no encoding of their own, because nothing outside a process has ever needed
//! them: the openings stay with the client and the record is what travels.
//! A18 puts a boundary in the middle of record *building*, so for the first
//! time they cross one.
//!
//! Keeping the encoding in this crate rather than adding it to `pqcl-capsule`
//! means the types that are stored keep exactly the codecs that storage needs,
//! and the vsock protocol owns the ones only it needs. If a second transport
//! ever wants them, that is the moment to move them down — not before.
//!
//! # Every decode is strict
//!
//! Same rule as [`crate::proto`]: a short field, an unknown discriminant or a
//! trailing byte is an error. The parent is outside the boundary, so this is
//! the parser an attacker reaches first.

use pqcl_capsule::codec::{CodecError, Reader, Writer};
use pqcl_capsule::{
    Act, ActorOpening, ActorRef, Capsule, CustodyRecord, Event, Params, ParamsOpening, RecordBody,
    Role,
};
use pqcl_dsse::core::UpdateToken;
use pqcl_pipeline::handoff::{Handoff, Receiving};
use pqcl_pipeline::{RecordParams, Signed};
use pqcl_primitives::aead::SealedRecord;
use pqcl_primitives::xof::Digest32;
use pqcl_sm::append::{AppendRequest, AppendStep, Appended, Pairing, SealRequest};

/// Act discriminants. ⛔ Stable on the wire: never renumber, only append.
mod act {
    pub(super) const PARAMS: u8 = 0x00;
    pub(super) const DESCRIPTOR: u8 = 0x01;
}

/// Step discriminants, as above.
mod step {
    pub(super) const COLLECT: u8 = 0x00;
    pub(super) const APPEND: u8 = 0x01;
    pub(super) const DISPOSE: u8 = 0x02;
    pub(super) const RELEASE: u8 = 0x03;
    pub(super) const RECEIPT: u8 = 0x04;
}

/// Read a field that must be exactly 32 bytes.
fn digest(r: &mut Reader<'_>, what: &'static str) -> Result<Digest32, CodecError> {
    r.field()?
        .try_into()
        .map_err(|_| CodecError::InvalidField(what))
}

/// Read a role byte, refusing one outside the four roles.
///
/// ⚠️ **A permissive parser on a security boundary is how a confused-deputy bug
/// starts**, and a role is a field here that decides *authority*: an unknown
/// byte that fell through would reach the module's actor lookup, which would
/// refuse it — but by then the refusal is a lookup miss rather than a rejected
/// message, and the two read very differently in a log.
fn role(r: &mut Reader<'_>) -> Result<Role, CodecError> {
    Role::from_byte(r.byte()?).ok_or(CodecError::InvalidField("role is not one of the four"))
}

/// An actor on the wire: `role ‖ ⟪id⟫` (`(role, id)` enrolment, §1br.4).
pub fn write_actor_ref(w: &mut Writer, a: &ActorRef) {
    w.byte(a.role.byte()).field(&a.id);
}

/// Read one, refusing a role outside the four.
///
/// # Errors
///
/// [`CodecError`] on a short field or an unknown role.
pub fn read_actor_ref(r: &mut Reader<'_>) -> Result<ActorRef, CodecError> {
    let role = role(r)?;
    Ok(ActorRef {
        role,
        id: r.field()?.to_vec(),
    })
}

/// Read an event byte, refusing one outside the seven events.
fn event(r: &mut Reader<'_>) -> Result<Event, CodecError> {
    Event::from_byte(r.byte()?).ok_or(CodecError::InvalidField("event is not one of the seven"))
}

/// `Params`, as its own frame.
///
/// A nested structure travels as one framed field holding its own complete
/// encoding, so each level's `finish()` still refuses trailing bytes.
fn params_bytes(p: &Params) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&p.tool).field(&p.ver).field(&p.args).field(&p.just);
    w.finish()
}

fn read_params(bytes: &[u8]) -> Result<Params, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = Params {
        tool: r.field()?.to_vec(),
        ver: r.field()?.to_vec(),
        args: r.field()?.to_vec(),
        just: r.field()?.to_vec(),
    };
    r.finish()?;
    Ok(out)
}

/// `Act`, as its own frame.
fn act_bytes(a: &Act) -> Vec<u8> {
    let mut w = Writer::new();
    match a {
        Act::Params(p) => {
            w.byte(act::PARAMS).field(&params_bytes(p));
        }
        Act::Descriptor(d) => {
            w.byte(act::DESCRIPTOR).field(d);
        }
    }
    w.finish()
}

fn read_act(bytes: &[u8]) -> Result<Act, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = match r.byte()? {
        act::PARAMS => Act::Params(read_params(r.field()?)?),
        act::DESCRIPTOR => Act::Descriptor(digest(&mut r, "descriptor must be 32 bytes")?),
        _ => return Err(CodecError::InvalidField("unknown act discriminant")),
    };
    r.finish()?;
    Ok(out)
}

/// `RecordParams`, as its own frame.
fn record_params_bytes(p: &RecordParams) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&p.note)
        .u64(p.j)
        .field(&act_bytes(&p.act))
        .u64(p.ts)
        .u64(p.epoch);
    w.finish()
}

fn read_record_params(bytes: &[u8]) -> Result<RecordParams, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = RecordParams {
        note: r.field()?.to_vec(),
        j: r.u64()?,
        act: read_act(r.field()?)?,
        ts: r.u64()?,
        epoch: r.u64()?,
    };
    r.finish()?;
    Ok(out)
}

/// `Handoff` — the descriptor's five inputs — as its own frame.
///
/// Five fixed-width digests, so the framing is pure redundancy here; it is used
/// anyway, because a hand-rolled fixed-offset reader beside a framed one is how
/// an off-by-32 survives review.
fn handoff_bytes(h: &Handoff) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&h.eid_e)
        .field(&h.from)
        .field(&h.to)
        .field(&h.cond)
        .field(&h.r_cap);
    w.finish()
}

fn read_handoff(bytes: &[u8]) -> Result<Handoff, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = Handoff {
        eid_e: digest(&mut r, "eid_e must be 32 bytes")?,
        from: digest(&mut r, "from must be 32 bytes")?,
        to: digest(&mut r, "to must be 32 bytes")?,
        cond: digest(&mut r, "cond must be 32 bytes")?,
        r_cap: digest(&mut r, "r_cap must be 32 bytes")?,
    };
    r.finish()?;
    Ok(out)
}

/// `ActorOpening`, as its own frame.
fn actor_bytes(a: &ActorOpening) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&a.id).byte(a.role.byte()).field(&a.r_a);
    w.finish()
}

fn read_actor(bytes: &[u8]) -> Result<ActorOpening, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = ActorOpening {
        id: r.field()?.to_vec(),
        role: role(&mut r)?,
        r_a: digest(&mut r, "r_a must be 32 bytes")?,
    };
    r.finish()?;
    Ok(out)
}

/// `ParamsOpening`, as its own frame.
fn params_opening_bytes(o: &ParamsOpening) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&params_bytes(&o.params)).field(&o.r_p);
    w.finish()
}

fn read_params_opening(bytes: &[u8]) -> Result<ParamsOpening, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = ParamsOpening {
        params: read_params(r.field()?)?,
        r_p: digest(&mut r, "r_p must be 32 bytes")?,
    };
    r.finish()?;
    Ok(out)
}

/// `Signed`, as its own frame.
fn signed_bytes(s: &Signed) -> Vec<u8> {
    // Bound, not chained: `optional` borrows, and a temporary `Vec` built
    // inside the call expression would not outlive it.
    let opening = s.params.as_ref().map(params_opening_bytes);
    let mut w = Writer::new();
    w.field(&s.record.encode())
        .field(&s.body.encode())
        .field(&actor_bytes(&s.actor))
        .optional(opening.as_deref());
    w.finish()
}

fn read_signed(bytes: &[u8]) -> Result<Signed, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = Signed {
        record: CustodyRecord::decode(r.field()?)?,
        body: RecordBody::decode(r.field()?)?,
        actor: read_actor(r.field()?)?,
        params: r.optional()?.map(read_params_opening).transpose()?,
    };
    r.finish()?;
    Ok(out)
}

/// `AppendStep`, as its own frame.
fn step_bytes(s: &AppendStep) -> Vec<u8> {
    let mut w = Writer::new();
    match s {
        AppendStep::Collect => {
            w.byte(step::COLLECT);
        }
        AppendStep::Append { event, previous } => {
            w.byte(step::APPEND)
                .byte(event.byte())
                .field(&previous.encode());
        }
        AppendStep::Dispose { previous, order_id } => {
            w.byte(step::DISPOSE)
                .field(&previous.encode())
                .optional(order_id.as_ref().map(<[u8; 32]>::as_slice));
        }
        AppendStep::Release {
            capsule,
            chain,
            cond,
            witness,
        } => {
            w.byte(step::RELEASE)
                .field(&capsule.encode())
                .field(&chain_bytes(chain))
                .field(cond);
            write_actor_ref(&mut w, witness);
        }
        AppendStep::Receipt {
            capsule,
            chain,
            recomputed,
            pairing,
        } => {
            w.byte(step::RECEIPT)
                .field(&capsule.encode())
                .field(&chain_bytes(chain))
                .field(recomputed)
                .field(&pair_bytes(pairing));
        }
    }
    w.finish()
}

/// A whole chain, as its own frame: the count, then each record.
///
/// A transfer carries the chain so the module can open it with
/// `K_rec^{eid}` — so the parent needs no body key to make one, and the
/// descriptor and the counter-signature are both computed inside.
fn chain_bytes(chain: &[CustodyRecord]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(chain.len() as u64);
    for r in chain {
        w.field(&r.encode());
    }
    w.finish()
}

fn read_chain(bytes: &[u8]) -> Result<Vec<CustodyRecord>, CodecError> {
    let mut r = Reader::new(bytes)?;
    let n = usize::try_from(r.u64()?)
        .map_err(|_| CodecError::InvalidField("chain length exceeds usize"))?;
    let mut out = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        out.push(CustodyRecord::decode(r.field()?)?);
    }
    r.finish()?;
    Ok(out)
}

fn read_step(bytes: &[u8]) -> Result<AppendStep, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = match r.byte()? {
        step::COLLECT => AppendStep::Collect,
        step::APPEND => AppendStep::Append {
            event: event(&mut r)?,
            previous: Box::new(CustodyRecord::decode(r.field()?)?),
        },
        step::DISPOSE => AppendStep::Dispose {
            previous: Box::new(CustodyRecord::decode(r.field()?)?),
            order_id: r
                .optional()?
                .map(|b| {
                    <Digest32>::try_from(b)
                        .map_err(|_| CodecError::InvalidField("order id must be 32 bytes"))
                })
                .transpose()?,
        },
        step::RELEASE => AppendStep::Release {
            capsule: Box::new(Capsule::decode(r.field()?)?),
            chain: read_chain(r.field()?)?,
            cond: digest(&mut r, "cond must be 32 bytes")?,
            witness: read_actor_ref(&mut r)?,
        },
        step::RECEIPT => AppendStep::Receipt {
            capsule: Box::new(Capsule::decode(r.field()?)?),
            chain: read_chain(r.field()?)?,
            recomputed: digest(&mut r, "the recomputed digest must be 32 bytes")?,
            pairing: Box::new(read_pair(r.field()?)?),
        },
        _ => return Err(CodecError::InvalidField("unknown append-step discriminant")),
    };
    r.finish()?;
    Ok(out)
}

/// A [`SealRequest`] as the body of a request frame.
#[must_use]
pub fn seal_request_bytes(q: &SealRequest) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&q.cid_c)
        .field(&q.cm_ev)
        .field(&q.nonce)
        .u64(q.epoch)
        .field(&q.artefact_type)
        .field(&q.d_ev)
        .field(&q.ptr);
    w.finish()
}

/// Decode one.
///
/// # Errors
///
/// [`CodecError`] on a short or wrong-sized field, or trailing bytes.
pub fn read_seal_request(bytes: &[u8]) -> Result<SealRequest, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = SealRequest {
        cid_c: digest(&mut r, "cid_c must be 32 bytes")?,
        cm_ev: digest(&mut r, "cm_ev must be 32 bytes")?,
        nonce: digest(&mut r, "the nonce must be 32 bytes")?,
        epoch: r.u64()?,
        artefact_type: r.field()?.to_vec(),
        d_ev: digest(&mut r, "d_ev must be 32 bytes")?,
        ptr: r.field()?.to_vec(),
    };
    r.finish()?;
    Ok(out)
}

/// An [`AppendRequest`] as the body of a request frame.
#[must_use]
pub fn append_request_bytes(q: &AppendRequest) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&q.cid_c).field(&q.capsule.eid);
    write_actor_ref(&mut w, &q.actor);
    w.u64(q.doc)
        .field(&record_params_bytes(&q.params))
        .field(&step_bytes(&q.step));
    w.finish()
}

/// Decode one.
///
/// # Errors
///
/// [`CodecError`] on a short field, an out-of-domain role, event, act or step
/// discriminant, or trailing bytes.
pub fn read_append_request(bytes: &[u8]) -> Result<AppendRequest, CodecError> {
    let mut r = Reader::new(bytes)?;
    let out = AppendRequest {
        cid_c: digest(&mut r, "cid_c must be 32 bytes")?,
        capsule: digest(&mut r, "eid must be 32 bytes")?.into(),
        actor: read_actor_ref(&mut r)?,
        doc: r.u64()?,
        params: read_record_params(r.field()?)?,
        step: read_step(r.field()?)?,
    };
    r.finish()?;
    Ok(out)
}

/// An [`Appended`] as the body of a response frame.
#[must_use]
pub fn appended_bytes(a: &Appended) -> Vec<u8> {
    // Bound before the writer borrows it, as in `signed_bytes`.
    let pair = a.pairing.as_deref().map(pair_bytes);
    let mut w = Writer::new();
    w.field(&signed_bytes(&a.signed)).u64(a.tokens.len() as u64);
    for t in &a.tokens {
        w.field(&t.addr).field(t.val.as_bytes());
    }
    w.optional(pair.as_deref());
    w.finish()
}

/// Decode one.
///
/// # Errors
///
/// [`CodecError`] on a short field, a token count that does not match the
/// fields that follow, or trailing bytes.
pub fn read_appended(bytes: &[u8]) -> Result<Appended, CodecError> {
    let mut r = Reader::new(bytes)?;
    let signed = read_signed(r.field()?)?;
    let n = usize::try_from(r.u64()?)
        .map_err(|_| CodecError::InvalidField("token count exceeds usize"))?;
    let mut tokens = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        tokens.push(UpdateToken {
            addr: digest(&mut r, "token address must be 32 bytes")?,
            val: SealedRecord::from_bytes(r.field()?.to_vec()),
        });
    }
    let pairing = r
        .optional()?
        .map(|b| read_pair(b).map(Box::new))
        .transpose()?;
    r.finish()?;
    Ok(Appended {
        signed,
        tokens,
        pairing,
    })
}

/// A [`Pairing`]: the descriptor and the receiving commitment, as one frame
/// holding two nested ones.
fn pair_bytes(p: &Pairing) -> Vec<u8> {
    let mut w = Writer::new();
    w.field(&handoff_bytes(&p.handoff))
        .field(&actor_bytes(&p.receiving.actor));
    w.finish()
}

fn read_pair(bytes: &[u8]) -> Result<Pairing, CodecError> {
    let mut r = Reader::new(bytes)?;
    let handoff = read_handoff(r.field()?)?;
    let actor = read_actor(r.field()?)?;
    r.finish()?;
    Ok(Pairing {
        handoff,
        receiving: Receiving { actor },
    })
}
