//! Building a case's custody records the way the library does (M13 A14).
//!
//! ⭐ **Every harness used to build a `TRANSFER` as one ordinary record.** The
//! stream emits a transfer as **two** events — a release and a receipt, the
//! second flagged `receipt` — and the harnesses signed both with
//! `append_record`, which produces two records that happen to be adjacent. A
//! real bilateral transfer is more than that: the two halves are over one
//! descriptor `D = H(0x26 ‖ ⟪eid_e, from, to, cond, R_cap⟫)`, the receiver
//! commits to `to` before the release is signed, the receipt re-verifies the
//! capsule's `d_ev`, and the sender counter-signs. None of that was exercised
//! by the records any experiment measured, so draft8's §3a was a claim about
//! code the measurements did not run.
//!
//! [`CaseBuilder`] routes each event to the right step — `Release` and
//! `Receipt` for the two halves of a transfer — and keeps the per-capsule state
//! that needs: the open chain and the pending pairing. One implementation,
//! shared, because four copies of this bookkeeping would be four chances to
//! disagree about what a transfer is.
//!
//! ⭐ **Since M13 A18 it builds through a `CustodyAppender`**, so the same
//! harness builds a case in process or inside the Nitro enclave, and the result
//! record names which.
//!
//! ⚠️ **The receipt's `d_ev` is the capsule's own, not a re-read artefact.** The
//! streams are synthetic (plan decision D10): there is no file behind a stream
//! event to re-hash, so the harness passes the anchored digest and the check
//! becomes an identity. Exp. 1's ingest path therefore does **not** include an
//! artefact re-read, and that is stated in every record this builds.

use std::collections::HashMap;

use pqcl_capsule::{Capsule, CustodyRecord, Event, Params};
use pqcl_pipeline::{CaseKeys, RecordParams};
use pqcl_primitives::xof::{Digest32, Domain, hash_domain};
use pqcl_sm::{
    AppendRequest, AppendStep, Appended, Backend, CustodyAppender, Pairing, SealRequest,
};

use crate::cast::role_for;
use crate::custody_stream::CustodyEvent;

type Res<T> = Result<T, Box<dyn core::error::Error>>;

/// One capsule's chain as the client holds it.
struct Open {
    capsule: Capsule,
    records: Vec<CustodyRecord>,
    /// A release awaiting its receipt: what the appender handed back, carried
    /// to the receipt because the appender keeps no state across a transfer.
    pending: Option<Box<Pairing>>,
}

/// Builds one case's custody records from a stream, through an appender and
/// nothing else.
///
/// ⭐ **Since M13 A18 the builder signs nothing itself.** Every capsule and every
/// record comes from the [`CustodyAppender`] it was handed — the harness's own
/// cast in process, or the Nitro enclave over vsock — and [`Self::backend`]
/// names which, so the result record can say. The bookkeeping (open chains,
/// the transfer that is mid-flight) stays here, because it is the client's and
/// no appender needs it.
pub struct CaseBuilder<'a> {
    appender: &'a dyn CustodyAppender,
    cid_c: Digest32,
    open: HashMap<u32, Open>,
}

impl<'a> CaseBuilder<'a> {
    /// A builder over an appender, for the case `keys` name.
    #[must_use]
    pub fn new(appender: &'a dyn CustodyAppender, keys: &CaseKeys) -> Self {
        Self {
            appender,
            cid_c: keys.cid_c,
            open: HashMap::new(),
        }
    }

    /// Which Secure Module built this case — what `emit_custody` records.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.appender.backend()
    }

    /// Seal a capsule through the appender, so the first responder who signs it
    /// is the one whose `COLLECT` opens its chain.
    ///
    /// `nonce` and `cm_ev` are the caller's: the nonce picks the pseudonym and
    /// `cm_ev` comes from streaming the artefact, which only the caller has.
    ///
    /// # Errors
    ///
    /// Whatever the appender refuses.
    pub fn seal(
        &self,
        nonce: Digest32,
        cm_ev: Digest32,
        d_ev: Digest32,
        artefact_type: &[u8],
        ptr: &[u8],
        epoch: u64,
    ) -> Res<Capsule> {
        Ok(self.appender.seal(&SealRequest {
            cid_c: self.cid_c,
            cm_ev,
            nonce,
            epoch,
            artefact_type: artefact_type.to_vec(),
            d_ev,
            ptr: ptr.to_vec(),
        })?)
    }

    /// Hand the builder a capsule the harness has sealed.
    ///
    /// Sealing stays with the harness, because `d_ev`, `cm_ev` and the pointer
    /// differ per experiment; everything after it is the same for all of them.
    pub fn insert_capsule(&mut self, id: u32, capsule: Capsule) {
        self.open.insert(
            id,
            Open {
                capsule,
                records: Vec::new(),
                pending: None,
            },
        );
    }

    /// The capsule for a stream index, once inserted.
    #[must_use]
    pub fn capsule(&self, id: u32) -> Option<&Capsule> {
        self.open.get(&id).map(|o| &o.capsule)
    }

    /// The chain so far.
    #[must_use]
    pub fn chain(&self, id: u32) -> Option<&[CustodyRecord]> {
        self.open.get(&id).map(|o| o.records.as_slice())
    }

    /// The chain of a capsule the builder holds, found by its `eid`.
    #[must_use]
    pub fn chain_of(&self, capsule: &Capsule) -> Option<&[CustodyRecord]> {
        self.open
            .values()
            .find(|o| o.capsule.eid == capsule.eid)
            .map(|o| o.records.as_slice())
    }

    /// Build the record for one stream event, through the step the event
    /// calls for: `Release` and `Receipt` for the two halves of a transfer,
    /// `Dispose` for a disposal, `Collect` for the opening.
    ///
    /// Returns the record with its 29 custody-plane tokens: every appender
    /// indexes what it builds, because draft8 Phase 6 Step 4 indexes every
    /// record and the enclave does it in the same round trip.
    ///
    /// `order_id` is the court order a `DISPOSE` executes, or `None` for a
    /// retention-driven one; it is ignored for every other event.
    ///
    /// # Errors
    ///
    /// An unknown capsule, a receipt with no release before it, or whatever
    /// the appender refuses.
    pub fn feed(
        &mut self,
        e: &CustodyEvent,
        ts: u64,
        epoch: u64,
        order_id: Option<&Digest32>,
    ) -> Res<Appended> {
        let j = u64::from(e.seq);
        let act = Params::of(
            b"custody-stream",
            b"1",
            &[&[e.event.byte()][..], &ts.to_le_bytes()].concat(),
        );
        let params = RecordParams::at(j, ts).with_params(act).in_epoch(epoch);
        let o = self.open.get(&e.capsule).ok_or("record before COLLECT")?;
        let last = || -> Res<Box<CustodyRecord>> {
            Ok(Box::new(
                o.records.last().ok_or("record before COLLECT")?.clone(),
            ))
        };

        let step = match (e.event, e.receipt) {
            (Event::Collect, _) => AppendStep::Collect,
            (Event::Transfer, false) => AppendStep::Release {
                capsule: Box::new(o.capsule.clone()),
                chain: o.records.clone(),
                cond: hash_domain(
                    Domain::HandoffDescriptor,
                    &[b"cond", &e.capsule.to_le_bytes(), &ts.to_le_bytes()],
                ),
                // The receiving custodian witnesses the release as it accepts
                // it, before writing its own receipt: `σ_witness` is inside the
                // release's `C_rec` and the receipt's link is over that record's
                // leaf (M13 A14, §1br F2). The evidence store releases and the
                // lab's custodian receives, so the transfer is between two
                // enrolled actors and not one key twice (§1br.4).
                witness: pqcl_sm::lab_custodian(),
            },
            (Event::Transfer, true) => AppendStep::Receipt {
                capsule: Box::new(o.capsule.clone()),
                chain: o.records.clone(),
                // Synthetic stream: no artefact to re-read, so the anchored
                // digest is what the receiver can check. See the module docs.
                recomputed: o.capsule.d_ev,
                pairing: o
                    .pending
                    .clone()
                    .ok_or("a receipt with no release before it")?,
            },
            // `None` is a retention-driven disposal, which no order covers —
            // the distinction `redaction::account` classifies on keylessly, so
            // a placeholder id here would make that classifier look exact when
            // it is not.
            (Event::Dispose, _) => AppendStep::Dispose {
                previous: last()?,
                order_id: order_id.copied(),
            },
            (event, _) => AppendStep::Append {
                event,
                previous: last()?,
            },
        };

        // The receipt is the lab custodian's; every other record is signed by
        // the cast member for its role.
        let actor = if e.event == Event::Transfer && e.receipt {
            pqcl_sm::lab_custodian()
        } else {
            pqcl_sm::cast_member(role_for(e.event))
        };
        let appended = self.appender.append(&AppendRequest {
            cid_c: self.cid_c,
            capsule: o.capsule.eid.into(),
            actor,
            // The stream's capsule index, which the custody plane's postings
            // name — the same `doc` the harnesses used before A18.
            doc: u64::from(e.capsule),
            params,
            step,
        })?;

        let o = self.open.get_mut(&e.capsule).ok_or("capsule lost")?;
        o.records.push(appended.signed.record.clone());
        match (e.event, e.receipt) {
            (Event::Transfer, false) => {
                o.pending = Some(
                    appended
                        .pairing
                        .clone()
                        .ok_or("a release came back without its pairing")?,
                );
            }
            (Event::Transfer, true) => o.pending = None,
            _ => {}
        }
        Ok(appended)
    }
}

/// A **one-party** transfer: one record, no descriptor, no receipt, no
/// counter-signature.
///
/// ⚠️ **This is a baseline, not a transfer.** It exists for the one experiment
/// whose subject is the difference — `custody.rs`'s `bilateral_transfer`, which
/// measures what the bilateral form costs over it. It is named here, in the
/// shared module, so that no harness writes `append_record(Event::Transfer, …)`
/// by accident: A14's grep test asserts `Event::Transfer` appears in no harness
/// at all, and this function is why it can.
///
/// ⭐ **Through the same appender as the bilateral form** (M13 A18). The
/// comparison is the cost of a second record, a descriptor, a counter-signature
/// and a re-check; if the bilateral arm went through the enclave and this one
/// stayed in process, the vsock round trips would be charged to ours alone and
/// the gap would be wider for a reason that has nothing to do with the protocol.
///
/// # Errors
///
/// Whatever the appender refuses.
pub fn unilateral_transfer(
    appender: &dyn CustodyAppender,
    keys: &CaseKeys,
    capsule: &Capsule,
    previous: &CustodyRecord,
    rp: &RecordParams,
) -> Res<Appended> {
    Ok(appender.append(&AppendRequest {
        cid_c: keys.cid_c,
        capsule: capsule.eid.into(),
        actor: pqcl_sm::cast_member(role_for(Event::Transfer)),
        doc: 0,
        params: rp.clone(),
        step: AppendStep::Append {
            event: Event::Transfer,
            previous: Box::new(previous.clone()),
        },
    })?)
}

/// What every record built this way should say about its provenance, for the
/// result record.
pub const BUILT_BY: &str = "every capsule and record through a CustodyAppender, whose backend \
     the record names in secure_module (M13 A18); each record built by pqcl_sm::sign_step over \
     pqcl-pipeline's Agent, with the role table enforced and fresh r_a/r_p per record (M13 A2), \
     and indexed under its 29 custody keywords in the same call; every TRANSFER pair through \
     handoff::release and handoff::receive, counter-signed (M13 A14); the receipt's d_ev is the \
     anchored digest, since a synthetic stream has no artefact to re-read (D10)";
