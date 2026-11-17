//! Phase 6 Step 1 — the bilateral handoff (draft7 `eq:handoff`, design §3a).
//!
//! A transfer is **two linked custody records over one descriptor**
//!
//! ```text
//! D = H(0x26 ‖ ⟪eid_e, from, to, cond, R_cap⟫)
//! ```
//!
//! * the **release** is signed by the releasing custodian (`actor_c = from`);
//! * the **receipt** is signed by the receiving custodian (`actor_c = to`),
//!   chains to the release through `h_prev`, and is only issued after the
//!   receiver has **re-verified `d_ev`** against the stored ciphertext.
//!
//! Between the two the artefact is in transit, and a release with no receipt
//! is what a policy-window alarm looks for ([`in_transit`]).
//!
//! # Where `D` lives in the record
//!
//! The record tuple (draft7 Phase 5 Step 1) has no field named for the
//! descriptor, and the paper says only that both halves are "over" it. Both
//! halves carry `D` in **`params_c`**, the field that commits an event's
//! parameters: for a `TRANSFER` the parameters *are* the handoff. That keeps
//! the record format, its encoding and every `0x02` leaf unchanged, and it puts
//! `D` under each custodian's own `σ_actor`.
//!
//! ⚠️ **The honest limit** (design §3a). This proves both custodians asserted
//! the handoff and that the ciphertext still matches its anchored digest. It
//! cannot prove the physical object that arrived is the one that left.

use pqcl_capsule::{Act, ActorOpening, Capsule, CustodyRecord, Event, RecordBody};
use pqcl_primitives::aead::{AeadError, CustodyKey};
use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

use crate::{Agent, CaseKeys, RecordParams, Signed, tier1_root};

/// The descriptor both halves of a transfer sign over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handoff {
    /// The capsule's pseudonym in the epoch of the transfer.
    pub eid_e: Digest32,
    /// Commitment to the releasing custodian, same form as `actor_c`.
    pub from: Digest32,
    /// Commitment to the receiving custodian.
    pub to: Digest32,
    /// Commitment to the declared condition (packaging, seal id, …).
    pub cond: Digest32,
    /// The capsule's Tier-1 root at the instant of release.
    pub r_cap: Digest32,
}

impl Handoff {
    /// `D = H(0x26 ‖ ⟪eid_e, from, to, cond, R_cap⟫)`. Framed, so `(from, to)`
    /// is bound as a pair (the row-12b defect).
    #[must_use]
    pub fn descriptor(&self) -> Digest32 {
        hash_domain(
            Domain::HandoffDescriptor,
            &[&self.eid_e, &self.from, &self.to, &self.cond, &self.r_cap],
        )
    }
}

/// Why a receipt was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    /// The record handed over is not a `TRANSFER` release of this descriptor.
    NotARelease,
    /// The release names a different releasing custodian than the descriptor.
    WrongSender,
    /// The receiver recomputed `d_ev` over the stored ciphertext and it does
    /// not match the capsule's anchored `d_ev`.
    IntegrityMismatch {
        /// The capsule's `d_ev`.
        anchored: Digest32,
        /// What the receiver recomputed.
        recomputed: Digest32,
    },
    /// The capsule is already in transit: a second release before the first
    /// is received would leave two parties claiming it.
    InTransit,
    /// Signing failed.
    Sign(String),
}

impl core::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotARelease => f.write_str("the record is not a release of this handoff"),
            Self::WrongSender => f.write_str("the release is signed for a different sender"),
            Self::IntegrityMismatch { .. } => {
                f.write_str("the stored ciphertext no longer matches the anchored d_ev")
            }
            Self::InTransit => f.write_str("the capsule is already in transit"),
            Self::Sign(m) => write!(f, "signing failed: {m}"),
        }
    }
}

impl core::error::Error for HandoffError {}

/// The Tier-1 root of a chain as it stands, `R_cap`.
#[must_use]
pub fn running_root(chain: &[CustodyRecord]) -> Digest32 {
    tier1_root(chain)
}

/// The terms of one release.
///
/// A struct rather than four trailing parameters: `ts` and `epoch` are both
/// `u64` and `to` and `cond` are both digests, so a positional call site is one
/// transposition away from a release into the wrong segment at the wrong time —
/// which would verify cleanly and be wrong. The same reasoning as
/// [`crate::IngestParams`].
#[derive(Debug, Clone, Copy)]
pub struct Terms {
    /// The receiving custodian's `actor_c`.
    pub to: Digest32,
    /// The condition commitment: the seal, the bag number, the packaging.
    pub cond: Digest32,
    /// Trusted timestamp.
    pub ts: u64,
    /// The **current** epoch, which decides the segment the release joins
    /// (M13 A20).
    pub epoch: u64,
}

/// `to`, and the opening the receiver keeps.
///
/// The receiver publishes the commitment before the release is signed, because
/// `D` binds it; it then signs its receipt under the same opening (M13 A2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receiving {
    /// The opening of `to`.
    pub actor: ActorOpening,
}

impl Receiving {
    /// The receiver's own commitment, as `Terms::to`.
    #[must_use]
    pub fn to(&self) -> Digest32 {
        self.actor.commit()
    }
}

/// The releasing half. `sender` signs a `TRANSFER` record whose `params_c` is
/// `D` and whose `actor_c` is `from`, extending `chain`.
///
/// `witness`, when given, counter-signs the same message **before the body is
/// sealed** (§1br F2): `σ_witness` lives inside `C_rec`, so it cannot be added
/// to a finished record without re-sealing it, and re-sealing under the
/// record's derived nonce would reuse that nonce.
///
/// # Errors
///
/// A signing failure, or an empty `chain` (a capsule with no opening record
/// cannot be released).
///
/// A transfer that straddles an epoch boundary has its two halves in
/// different segments, linked only inside `C_rec` — which is correct, and is
/// why [`in_transit`] needs the body key (M13 A20).
pub fn release(
    sender: &Agent,
    keys: &CaseKeys,
    capsule: &Capsule,
    chain: &OpenChain<'_>,
    terms: &Terms,
    witness: Option<&Agent>,
) -> Result<(Signed, Handoff), HandoffError> {
    let previous = chain.records.last().ok_or(HandoffError::NotARelease)?;
    if !in_transit(chain).is_empty() {
        return Err(HandoffError::InTransit);
    }
    // ⭐ **Commit, then bind, then sign** (M13 A2). `D` binds `from`, and
    // `from` is the releasing custodian's commitment **for this record**, so
    // the order is forced: draw `r_a`, commit, build `D` over it, and sign the
    // record under the same opening. Before A2 `from` was copied from the
    // previous record's `actor_c`, which reused one `r_a` down the chain and
    // let the server group an actor's records by equality.
    let actor = sender
        .commit_actor()
        .map_err(|e| HandoffError::Sign(e.to_string()))?;
    let handoff = Handoff {
        eid_e: previous.eid_e,
        from: actor.commit(),
        to: terms.to,
        cond: terms.cond,
        r_cap: running_root(chain.records),
    };
    let signed = sender
        .append_record_as(
            keys,
            capsule,
            Event::Transfer,
            previous,
            &RecordParams::at(chain.len() as u64, terms.ts)
                .with_act(Act::Descriptor(handoff.descriptor()))
                .in_epoch(terms.epoch),
            crate::Signing { actor, witness },
        )
        .map_err(|e| HandoffError::Sign(e.to_string()))?;
    Ok((signed, handoff))
}

/// A chain with its bodies opened — what a **key holder** works with.
///
/// ⭐ **M13 A1 moved handoff pairing across the trust boundary.** Pairing a
/// release to its receipt tests `event`, `actor_c` and `params_c`, and all
/// three now live inside `C_rec`. So the AIS can no longer do it, and neither
/// can a keyless auditor: these functions belong to the case's own key holder
/// (its auditor daemon, or the investigator's Secure Module). Opening the
/// chain once, here, is what keeps that explicit instead of scattering
/// decryption through the pairing logic.
///
/// ⚠️ Design §3a's unmatched-release alarm is therefore **raised by a key
/// holder, not by the server** — reported in the design record.
pub struct OpenChain<'a> {
    /// The records, as stored.
    pub records: &'a [CustodyRecord],
    /// Their opened bodies, index for index with `records`.
    pub bodies: Vec<RecordBody>,
}

impl<'a> OpenChain<'a> {
    /// Open every record in a capsule's chain under its body key.
    ///
    /// # Errors
    ///
    /// [`AeadError::Authentication`] if any record fails to open — a wrong
    /// key, or a tampered ciphertext.
    pub fn open(records: &'a [CustodyRecord], key: &CustodyKey) -> Result<Self, AeadError> {
        let bodies = records
            .iter()
            .map(|r| r.open_body(key))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { records, bodies })
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ⛔ **There is no `actor_of_sender` any more, and there cannot be** (M13 A2).
// It used to answer "who holds this evidence" by walking back to the last
// `TRANSFER` or `COLLECT` and taking its `actor_c`, and the release then reused
// that commitment as its own. Both halves of that are now wrong: `actor_c`
// carries a fresh `r_a` per record, so *no* two records of one actor are equal
// by commitment, and the releasing custodian commits afresh for the transfer it
// is signing.
//
// Identity therefore comes from the **openings**, which the client holds and
// the server never sees — `ActorOpening { id, role, r_a }`. That is the point of
// blinding: an honest-but-curious server with every body decrypted still cannot
// group a case's records by who touched them, which is the activity profile the
// per-epoch pseudonyms exist to deny it. Anything that needs the holder (the
// custody graph, a policy window) takes the openings.

/// A release and its opened body, which travel together.
///
/// The two are a pair by construction — since M13 A1 the release's event,
/// descriptor and actor are inside its ciphertext, so a caller that has the
/// record without the body cannot check anything about it.
#[derive(Debug, Clone, Copy)]
pub struct Release<'a> {
    /// The release record, as stored.
    pub record: &'a CustodyRecord,
    /// Its opened body.
    pub body: &'a RecordBody,
}

/// What the receiving side contributes: its own integrity re-check, and where
/// its record sits in the chain.
#[derive(Debug, Clone)]
pub struct Receipt {
    /// `d_ev` as the receiver recomputed it over the stored ciphertext. This is
    /// the re-verification that makes a handoff a check and not a formality.
    pub recomputed: Digest32,
    /// The receipt's index in the capsule's chain.
    pub j: u64,
    /// Its timestamp.
    pub ts: u64,
    /// The epoch the receipt is written in (M13 A20). Named rather than
    /// positional for the obvious reason: it sits beside `ts` and `j`, and all
    /// three are `u64`.
    pub epoch: u64,
    /// The receiver's published commitment and its opening (M13 A2).
    pub receiving: Receiving,
}

/// The receiving half. `receiver` first checks the release really is this
/// handoff's, then **re-verifies `d_ev`**: `recomputed` is the digest it
/// computed itself over the stored ciphertext. Only then does it sign a
/// `TRANSFER` record chained to the release.
///
/// # Errors
///
/// [`HandoffError`]: a record that is not this release, the wrong sender, a
/// ciphertext that no longer matches, or a signing failure.
pub fn receive(
    receiver: &Agent,
    keys: &CaseKeys,
    capsule: &Capsule,
    release: &Release<'_>,
    handoff: &Handoff,
    receipt: &Receipt,
) -> Result<Signed, HandoffError> {
    receive_after(
        receiver,
        keys,
        capsule,
        release,
        handoff,
        receipt,
        release.record,
    )
}

/// [`receive`], with the receipt chained to `previous` rather than to the
/// release itself: a record was written while the artefact was in transit,
/// an `ACCESS` by the courier, say (M13 A15). The receipt still pairs with its
/// release by the descriptor both carry, which is what [`in_transit`] reads.
///
/// # Errors
///
/// As [`receive`].
pub fn receive_after(
    receiver: &Agent,
    keys: &CaseKeys,
    capsule: &Capsule,
    release: &Release<'_>,
    handoff: &Handoff,
    receipt: &Receipt,
    previous: &CustodyRecord,
) -> Result<Signed, HandoffError> {
    let release_body = release.body;
    let &Receipt {
        recomputed,
        j,
        ts,
        epoch,
        ..
    } = receipt;
    // The three tests below read the release's **body**, which is encrypted
    // from A1 on, so `receive` is a key holder's operation. The receiver is
    // one by definition — it is about to sign a record of its own.
    if release_body.event != Event::Transfer || release_body.params_c != handoff.descriptor() {
        return Err(HandoffError::NotARelease);
    }
    if release_body.actor_c != handoff.from {
        return Err(HandoffError::WrongSender);
    }
    if recomputed != capsule.d_ev {
        return Err(HandoffError::IntegrityMismatch {
            anchored: capsule.d_ev,
            recomputed,
        });
    }
    // The receipt is signed under the commitment the receiver published as
    // `to`, which the descriptor binds. A receiver that cannot reproduce it is
    // not the party this transfer was addressed to.
    if receipt.receiving.to() != handoff.to {
        return Err(HandoffError::WrongSender);
    }
    receiver
        .append_record_as(
            keys,
            capsule,
            Event::Transfer,
            previous,
            &RecordParams::at(j, ts)
                .with_act(Act::Descriptor(handoff.descriptor()))
                .in_epoch(epoch),
            crate::Signing {
                actor: receipt.receiving.actor.clone(),
                witness: None,
            },
        )
        .map_err(|e| HandoffError::Sign(e.to_string()))
}

/// Indices of releases with no receipt: a `TRANSFER` that no **later**
/// `TRANSFER` over the same descriptor answers.
///
/// ⭐ **Paired by descriptor, not by adjacency** (M13 A15, `audit/06` W37).
/// It used to require the receipt to be the very next record, so a release
/// followed by an `ACCESS` before its receipt was reported in transit
/// **forever**, a permanent false alarm. `D` binds `eid_e`, `from`, `to`,
/// `cond` and the running root at the release, so it names one transfer; the
/// first `TRANSFER` carrying it is the release and the next is the receipt.
///
/// ⚠️ **Needs the body key, since M13 A1.** The predicate tests `event` and
/// `params_c`, both of which moved inside `C_rec`. The previous doc comment
/// here claimed this was "computable from the records alone, with no
/// decryption" — true of v1, false of v2, and the correction is the point of
/// [`OpenChain`].
///
/// ⚠️ It reads no cleartext link at all. A transfer can straddle an epoch
/// boundary, and then the receipt's cleartext `h_prev` is its own segment's
/// genesis rather than the release's link (A20); chain integrity is
/// `Bundle::open`'s job, and this is only the completeness alarm.
#[must_use]
pub fn in_transit(chain: &OpenChain<'_>) -> Vec<usize> {
    let mut open: Vec<usize> = Vec::new();
    for (i, body) in chain.bodies.iter().enumerate() {
        if body.event != Event::Transfer {
            continue;
        }
        match open
            .iter()
            .position(|&r| chain.bodies[r].params_c == body.params_c)
        {
            Some(at) => {
                open.remove(at);
            }
            None => open.push(i),
        }
    }
    open
}

/// The policy-window alarm (design §3a, M13 A15): releases still unanswered
/// more than `window` seconds after their own timestamp, as of `now`.
///
/// A release inside its window is in transit, which is normal; one past it is
/// what the case's key-holding auditor raises.
#[must_use]
pub fn in_transit_since(chain: &OpenChain<'_>, now: u64, window: u64) -> Vec<usize> {
    in_transit(chain)
        .into_iter()
        .filter(|&i| chain.bodies[i].ts.saturating_add(window) < now)
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::IngestParams;
    use pqcl_capsule::{Params, Role};
    use pqcl_primitives::xof::{PrfKey, digest256};
    use pqcl_primitives::{SoftwareMlDsa, sig};

    fn setup() -> (CaseKeys, Agent, Agent, Capsule, CustodyRecord) {
        let keys = CaseKeys::derive(
            &PrfKey::new(digest256(b"k_mst handoff")),
            b"case",
            &digest256(b"r"),
        );
        // M13 A2: the DEFR collects; a transfer is signed by custodians, so
        // the releasing side is one.
        let defr = Agent::new(
            SoftwareMlDsa::generate().unwrap(),
            b"first-responder-1",
            Role::Defr,
        );
        let store = Agent::new(
            SoftwareMlDsa::generate().unwrap(),
            b"evidence-store-1",
            Role::Custodian,
        );
        let capsule = defr
            .seal(
                &keys,
                digest256(b"cm"),
                &IngestParams {
                    artefact_type: b"disk-image",
                    d_ev: digest256(b"d_ev"),
                    ptr: b"store://1",
                    epoch: 1,
                    nonce: &digest256(b"nonce"),
                },
            )
            .unwrap();
        let first = defr
            .collect_record(
                &keys,
                &capsule,
                &RecordParams::at(0, 10)
                    .with_params(Params::justified(b"acq"))
                    .in_epoch(1),
            )
            .unwrap()
            .record;
        (keys, defr, store, capsule, first)
    }

    /// The receiving custodian, with the commitment it publishes as `to`.
    fn receiver() -> (Agent, Receiving) {
        let lab = Agent::new(
            SoftwareMlDsa::generate().unwrap(),
            b"lab-1",
            Role::Custodian,
        );
        let receiving = Receiving {
            actor: lab.commit_actor().unwrap(),
        };
        (lab, receiving)
    }

    #[test]
    fn a_completed_handoff_is_two_linked_records_signed_by_each_side() {
        let (keys, _defr, store, capsule, first) = setup();
        let (lab, receiving) = receiver();
        // The body key for this capsule. Handoff pairing is a key holder's
        // operation from M13 A1 on, so the test holds the key the way a real
        // custodian does.
        let body_key = keys.record_body_key(&capsule.eid);
        let mut chain = vec![first];

        let open = OpenChain::open(&chain, &body_key).unwrap();
        let (out, h) = release(
            &store,
            &keys,
            &capsule,
            &open,
            &Terms {
                to: receiving.to(),
                cond: digest256(b"sealed bag 7"),
                ts: 20,
                epoch: 1,
            },
            None,
        )
        .unwrap();
        let out = out.record;
        let out_body = out.open_body(&body_key).unwrap();
        assert_eq!(
            out_body.actor_c, h.from,
            "the release's actor_c is the `from` its descriptor binds"
        );
        chain.push(out.clone());

        let open = OpenChain::open(&chain, &body_key).unwrap();
        assert_eq!(in_transit(&open), vec![1], "a release alone is in transit");

        let inn = receive(
            &lab,
            &keys,
            &capsule,
            &Release {
                record: &out,
                body: &out_body,
            },
            &h,
            &Receipt {
                recomputed: capsule.d_ev,
                j: 2,
                ts: 30,
                epoch: 1,
                receiving: receiving.clone(),
            },
        )
        .unwrap();
        let inn = inn.record;
        let inn_body = inn.open_body(&body_key).unwrap();
        assert_eq!(
            inn.h_prev,
            out.chain_link(),
            "the receipt chains to the release"
        );
        assert_eq!(
            inn_body.params_c, out_body.params_c,
            "both halves are over one descriptor"
        );
        assert_eq!(
            inn_body.actor_c,
            receiving.to(),
            "the receipt is signed under the commitment the descriptor binds"
        );
        // §1br F2: the signatures are inside `C_rec`, so a key holder opens
        // the record before it can verify one.
        for (r, pk) in [(&out, store.public_key()), (&inn, lab.public_key())] {
            let o = r.open(&body_key).unwrap();
            sig::verify(
                &crate::record_signed_bytes(r, &o.body),
                &o.sigs.actor,
                pk,
                &[],
            )
            .unwrap();
        }
        chain.push(inn);
        let open = OpenChain::open(&chain, &body_key).unwrap();
        assert!(in_transit(&open).is_empty());
    }

    #[test]
    fn a_transfer_across_an_epoch_boundary_pairs_through_the_ciphertext() {
        // ⭐ **M13 A20's effect on bilateral transfer.** A release in one epoch
        // and its receipt in the next land in different segments, so the
        // receipt's cleartext `h_prev` is its own segment's genesis and *not*
        // the release's link. The pair is still a pair — the real link is in
        // the body — and `in_transit` must say so.
        //
        // This is the case that would have produced a false unmatched-release
        // alarm if the pairing had stayed on the cleartext.
        let (keys, _defr, store, capsule, first) = setup();
        let (lab, receiving) = receiver();
        let body_key = keys.record_body_key(&capsule.eid);
        let mut chain = vec![first];

        let open = OpenChain::open(&chain, &body_key).unwrap();
        let (out, h) = release(
            &store,
            &keys,
            &capsule,
            &open,
            &Terms {
                to: receiving.to(),
                cond: digest256(b"sealed bag 7"),
                ts: 20,
                epoch: 1,
            },
            None,
        )
        .unwrap();
        let out = out.record;
        let out_body = out.open_body(&body_key).unwrap();
        chain.push(out.clone());

        // The epoch rolls over between the two halves.
        let inn = receive(
            &lab,
            &keys,
            &capsule,
            &Release {
                record: &out,
                body: &out_body,
            },
            &h,
            &Receipt {
                recomputed: capsule.d_ev,
                j: 2,
                ts: 30,
                epoch: 2,
                receiving: receiving.clone(),
            },
        )
        .unwrap();
        let inn = inn.record;
        let inn_body = inn.open_body(&body_key).unwrap();

        assert_ne!(inn.eid_e, out.eid_e, "the receipt is in a new segment");
        assert_eq!(
            inn.h_prev,
            CustodyRecord::segment_genesis_link(&inn.eid_e),
            "the receipt's cleartext link is not its own segment's genesis"
        );
        assert_eq!(
            inn_body.link,
            out.chain_link(),
            "the real link to the release is not in the body"
        );

        chain.push(inn);
        let open = OpenChain::open(&chain, &body_key).unwrap();
        assert!(
            in_transit(&open).is_empty(),
            "an epoch-crossing transfer was reported unmatched"
        );
    }

    #[test]
    fn a_receipt_is_refused_when_the_ciphertext_changed() {
        let (keys, _defr, store, capsule, first) = setup();
        let (lab, receiving) = receiver();
        let body_key = keys.record_body_key(&capsule.eid);
        let chain = [first];
        let open = OpenChain::open(&chain, &body_key).unwrap();
        let (out, h) = release(
            &store,
            &keys,
            &capsule,
            &open,
            &Terms {
                to: receiving.to(),
                cond: digest256(b"c"),
                ts: 20,
                epoch: 1,
            },
            None,
        )
        .unwrap();
        let out = out.record;
        let out_body = out.open_body(&body_key).unwrap();
        let err = receive(
            &lab,
            &keys,
            &capsule,
            &Release {
                record: &out,
                body: &out_body,
            },
            &h,
            &Receipt {
                recomputed: digest256(b"other"),
                j: 2,
                ts: 30,
                epoch: 1,
                receiving: receiving.clone(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandoffError::IntegrityMismatch { .. }));
    }

    #[test]
    fn the_descriptor_binds_from_and_to_as_a_pair() {
        let h = Handoff {
            eid_e: digest256(b"e"),
            from: digest256(b"a"),
            to: digest256(b"b"),
            cond: digest256(b"c"),
            r_cap: digest256(b"r"),
        };
        let swapped = Handoff {
            from: h.to,
            to: h.from,
            ..h
        };
        assert_ne!(h.descriptor(), swapped.descriptor());
    }

    #[test]
    fn a_receipt_for_another_descriptor_is_refused() {
        let (keys, _defr, store, capsule, first) = setup();
        let (lab, receiving) = receiver();
        let body_key = keys.record_body_key(&capsule.eid);
        let chain = [first];
        let open = OpenChain::open(&chain, &body_key).unwrap();
        let (out, h) = release(
            &store,
            &keys,
            &capsule,
            &open,
            &Terms {
                to: receiving.to(),
                cond: digest256(b"c"),
                ts: 20,
                epoch: 1,
            },
            None,
        )
        .unwrap();
        let out = out.record;
        let out_body = out.open_body(&body_key).unwrap();
        let other = Handoff {
            to: digest256(b"someone else"),
            ..h
        };
        assert_eq!(
            receive(
                &lab,
                &keys,
                &capsule,
                &Release {
                    record: &out,
                    body: &out_body,
                },
                &other,
                &Receipt {
                    recomputed: capsule.d_ev,
                    j: 2,
                    ts: 30,
                    epoch: 1,
                    receiving: receiving.clone(),
                },
            )
            .unwrap_err(),
            HandoffError::NotARelease
        );
    }

    // ------------------------------------------- policy window, terminal state (M13 A15)

    /// Release `first`'s capsule from `store` to `receiving`, at `ts = 20`.
    fn released(
        keys: &CaseKeys,
        store: &Agent,
        capsule: &Capsule,
        first: &CustodyRecord,
        receiving: &Receiving,
    ) -> (CustodyRecord, Handoff) {
        let chain = [first.clone()];
        let open = OpenChain::open(&chain, &keys.record_body_key(&capsule.eid)).unwrap();
        let (out, h) = release(
            store,
            keys,
            capsule,
            &open,
            &Terms {
                to: receiving.to(),
                cond: digest256(b"sealed bag 9"),
                ts: 20,
                epoch: 1,
            },
            None,
        )
        .unwrap();
        (out.record, h)
    }

    /// ⭐ **Acceptance A15 (a): a release answered after an intervening record
    /// is not in transit.** Pairing used to be by adjacency, so an `ACCESS`
    /// between release and receipt left the release reported in transit
    /// forever (`audit/06` W37).
    #[test]
    fn a_release_answered_after_an_intervening_record_is_not_in_transit() {
        let (keys, _defr, store, capsule, first) = setup();
        let (lab, receiving) = receiver();
        let body_key = keys.record_body_key(&capsule.eid);
        let (out, h) = released(&keys, &store, &capsule, &first, &receiving);
        let out_body = out.open_body(&body_key).unwrap();

        // A specialist reads the artefact while it is in transit.
        let des = Agent::new(SoftwareMlDsa::generate().unwrap(), b"des-1", Role::Des);
        let access = des
            .append_record(
                &keys,
                &capsule,
                Event::Access,
                &out,
                &RecordParams::at(2, 25)
                    .with_params(Params::justified(b"imaging check"))
                    .in_epoch(1),
            )
            .unwrap()
            .record;
        let mut chain = vec![first, out.clone(), access.clone()];
        let open = OpenChain::open(&chain, &body_key).unwrap();
        assert_eq!(
            in_transit(&open),
            vec![1],
            "still in transit before the receipt"
        );

        let inn = receive_after(
            &lab,
            &keys,
            &capsule,
            &Release {
                record: &out,
                body: &out_body,
            },
            &h,
            &Receipt {
                recomputed: capsule.d_ev,
                j: 3,
                ts: 30,
                epoch: 1,
                receiving,
            },
            &access,
        )
        .unwrap()
        .record;
        assert_eq!(
            inn.h_prev,
            access.chain_link(),
            "the receipt follows the ACCESS"
        );
        chain.push(inn);
        let open = OpenChain::open(&chain, &body_key).unwrap();
        assert!(
            in_transit(&open).is_empty(),
            "a receipt after an intervening record was not paired"
        );
    }

    /// ⭐ **Acceptance A15 (b): an expired window raises the alarm**, and an
    /// unexpired one does not.
    #[test]
    fn a_release_past_its_window_raises_the_alarm() {
        let (keys, _defr, store, capsule, first) = setup();
        let (_lab, receiving) = receiver();
        let (out, _) = released(&keys, &store, &capsule, &first, &receiving);
        let chain = [first, out];
        let open = OpenChain::open(&chain, &keys.record_body_key(&capsule.eid)).unwrap();
        // Released at ts = 20 with a 50 s window.
        assert!(
            in_transit_since(&open, 70, 50).is_empty(),
            "alarmed inside the window"
        );
        assert_eq!(
            in_transit_since(&open, 71, 50),
            vec![1],
            "no alarm past the window"
        );
    }

    /// ⭐ **Acceptance A15 (c): nothing is appended after a `DISPOSE`**, by any
    /// path: an ordinary append, and a release.
    #[test]
    fn nothing_is_appended_after_a_dispose() {
        let (keys, _defr, store, capsule, first) = setup();
        let disposed = store
            .dispose_record(
                &keys,
                &capsule,
                &first,
                None,
                &RecordParams::at(1, 20)
                    .with_params(Params::justified(b"retention expired"))
                    .in_epoch(1),
            )
            .unwrap()
            .record;
        let again = store.append_record(
            &keys,
            &capsule,
            Event::Seal,
            &disposed,
            &RecordParams::at(2, 30)
                .with_params(Params::justified(b"reseal"))
                .in_epoch(1),
        );
        assert!(
            matches!(again, Err(crate::SignError::AfterTerminal)),
            "appended after a DISPOSE"
        );

        let (_lab, receiving) = receiver();
        let chain = [first, disposed];
        let open = OpenChain::open(&chain, &keys.record_body_key(&capsule.eid)).unwrap();
        let moved = release(
            &store,
            &keys,
            &capsule,
            &open,
            &Terms {
                to: receiving.to(),
                cond: digest256(b"bag"),
                ts: 40,
                epoch: 1,
            },
            None,
        );
        assert!(moved.is_err(), "a disposed capsule was released");
    }
}
