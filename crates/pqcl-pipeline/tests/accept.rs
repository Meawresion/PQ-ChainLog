//! ⭐ **`eq:accept`, one conjunct at a time**.
//!
//! A real case: a DEFR collects, a DES analyses, the evidence store releases to
//! the lab custodian, who witnesses the release and signs the receipt, across
//! two epochs that a committee of three approves (M = 2) and an SLH-DSA
//! co-signer endorses. The honest bundle is accepted, and every conjunct is
//! then broken on its own and watched refusing, including the two the main
//! agent named: a role that may not sign its event, and a roster key that is
//! not the signer's.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use pqcl_capsule::redaction::{Mode, Order, Scope, Target};
use pqcl_capsule::{
    ActorOpening, Bundle, Capsule, CustodyRecord, Event, Params, ParamsOpening, RecordBody,
    RecordSignatures, Role,
};
use pqcl_pipeline::accept::{
    AcceptError, AcceptInputs, ActOpening, AnchoredEpoch, CourtPackage, Predicate, RecordOpening,
    RedactionEvidence, Roster, RosterEntry, SealedPackage, accept,
};
use pqcl_pipeline::checkpoint::{
    ApprovalSet, ChainView, Committed, Proposal, Registration, approve, checkpoint,
};
use pqcl_pipeline::handoff::{self, Handoff, OpenChain, Receipt, Receiving, Release, Terms};
use pqcl_pipeline::redaction::ClaimedOrder;
use pqcl_pipeline::{
    Agent, Ais, CaseKeys, IngestParams, PlaintextOpening, RecordParams, Signed, chunked,
    record_signed_bytes,
};
use pqcl_primitives::xof::{Digest32, PrfKey, digest256};
use pqcl_primitives::{CoSigner, KeyPair, Signer, SoftwareMlDsa};

const NOW: u64 = 1_700_000_000;

/// Which single thing a variant of the case gets wrong, or adds.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Variant {
    /// Nothing.
    #[default]
    Honest,
    /// The ANALYZE is built outside any `Agent`, by a custodian identity,
    /// which the role table forbids and `Agent` would refuse.
    ForgeRole,
    /// The release is witnessed by a custodian who is not the receiver.
    ImpostorWitness,
    /// Stop after the release: no receipt.
    NoReceipt,
    /// The release is signed but never appended; the lab appends a receipt
    /// over its descriptor by hand.
    LoneReceipt,
    /// After the honest pair, the lab appends a second receipt over the same
    /// descriptor by hand.
    SecondReceipt,
    /// Close the chain with a court-ordered DISPOSE.
    Order,
}

/// How to build a variant of the case.
#[derive(Clone, Copy, Default)]
struct Opts {
    /// Applied to the roster **before** `reg` commits to it, so the case is
    /// coherent and only the property under test is wrong.
    edit_roster: Option<fn(&mut Roster)>,
    /// What else differs.
    variant: Variant,
}

/// One built case, everything a court is handed.
#[derive(Clone)]
struct Fx {
    bundle: Bundle,
    reg: Registration,
    epochs: Vec<AnchoredEpoch>,
    package: CourtPackage,
    opening: PlaintextOpening,
    artefact: Vec<u8>,
    order: Option<OrderFx>,
}

#[derive(Clone)]
struct OrderFx {
    claimed: Vec<ClaimedOrder>,
    leaves: HashMap<Digest32, u64>,
    registry: HashMap<Digest32, Digest32>,
    court_pk: Vec<u8>,
}

fn agent(id: &[u8], role: Role) -> Agent {
    Agent::new(SoftwareMlDsa::generate().expect("keygen"), id, role)
}

fn entry(a: &Agent) -> RosterEntry {
    RosterEntry {
        actor: a.actor_ref(),
        pk: a.public_key().to_vec(),
    }
}

fn params_of(s: &Signed) -> ActOpening {
    ActOpening::Params(
        s.params
            .clone()
            .expect("a tool-run record has a params opening"),
    )
}

/// Record `j` of `capsule`'s chain, built outside the library's append path
/// and signed by `sign`: what an insider holding a real key can produce, and
/// what `accept` must judge without relying on the append path's refusals.
fn hand_record(
    keys: &CaseKeys,
    capsule: &Capsule,
    previous: &CustodyRecord,
    j: u64,
    epoch: u64,
    body: &RecordBody,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> CustodyRecord {
    let rid = CustodyRecord::derive_rid(&CustodyRecord::rid_key(&keys.coc_key(), &capsule.eid), j);
    let eid_e = keys.epoch_pseudonym(&capsule.eid, epoch);
    // The first record of an epoch opens a new segment (A20).
    let h_prev = if previous.eid_e == eid_e {
        body.link
    } else {
        CustodyRecord::segment_genesis_link(&eid_e)
    };
    let mut record = CustodyRecord {
        rid,
        eid_e,
        h_prev,
        body: Vec::new(),
        order_ref: None,
    };
    let sigs = RecordSignatures {
        actor: sign(&record_signed_bytes(&record, body)),
        witness: None,
    };
    record.body = CustodyRecord::seal_body(&keys.record_body_key(&capsule.eid), &rid, body, &sigs)
        .expect("seal");
    record
}

/// An ANALYZE signed under a custodian's identity, built by hand because the
/// library refuses to: the insider forgery the role conjunct exists for.
fn forged_analyze(
    keys: &CaseKeys,
    capsule: &Capsule,
    previous: &CustodyRecord,
    as_whom: &Agent,
) -> (CustodyRecord, ActorOpening, ParamsOpening) {
    let actor = as_whom.commit_actor().expect("blind");
    let params = ParamsOpening {
        params: Params::of(b"fls", b"4.12", b"-r"),
        r_p: digest256(b"r_p forged"),
    };
    let body = RecordBody {
        event: Event::Analyze,
        ts: NOW + 1,
        actor_c: actor.commit(),
        params_c: params.commit(),
        link: previous.chain_link(),
        note: Vec::new(),
    };
    let forger = SoftwareMlDsa::generate().expect("keygen");
    let record = hand_record(keys, capsule, previous, 1, 0, &body, |m| {
        forger.sign(m).expect("sign")
    });
    (record, actor, params)
}

/// A receipt over `h`, signed with the receiving custodian's own key but built
/// by hand, so nothing checks that a release over `h` came first.
fn hand_receipt(
    keys: &CaseKeys,
    capsule: &Capsule,
    previous: &CustodyRecord,
    j: u64,
    h: &Handoff,
    as_whom: &Agent,
) -> CustodyRecord {
    let body = RecordBody {
        event: Event::Transfer,
        ts: NOW + 20 + j,
        actor_c: h.to,
        params_c: h.descriptor(),
        link: previous.chain_link(),
        note: Vec::new(),
    };
    hand_record(keys, capsule, previous, j, 1, &body, |m| {
        as_whom.sign_defr(m).expect("sign")
    })
}

#[allow(clippy::too_many_lines)]
fn build(o: Opts) -> Fx {
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst (accept)")),
        b"case-accept",
        &digest256(b"r_case"),
    );
    let defr = agent(b"first-responder-1", Role::Defr);
    let des = agent(b"specialist-1", Role::Des);
    let store = agent(b"evidence-store-1", Role::Custodian);
    let lab = agent(b"lab-custodian-1", Role::Custodian);
    let impostor = agent(b"lab-custodian-2", Role::Custodian);
    let court = SoftwareMlDsa::generate().expect("keygen");

    let artefact = b"a real disk image would be here; ".repeat(40);
    let r_ev = digest256(b"r_ev");
    let cm = chunked::commit_bytes(&artefact, &r_ev);
    let capsule = defr
        .seal(
            &keys,
            *cm.root(),
            &IngestParams {
                artefact_type: b"disk-image",
                d_ev: digest256(&artefact),
                ptr: b"s3://case/obj",
                epoch: 0,
                nonce: &digest256(b"nonce"),
            },
        )
        .expect("seal");
    let opening = PlaintextOpening { r_ev, chunks: cm };
    let eid = capsule.eid;
    let body_key = keys.record_body_key(&eid);

    let mut ais = Ais::new();
    let mut chain: Vec<CustodyRecord> = Vec::new();
    let mut openings: Vec<RecordOpening> = Vec::new();

    // Epoch 0: COLLECT and ANALYZE.
    let collect = defr
        .collect_record(
            &keys,
            &capsule,
            &RecordParams::at(0, NOW).with_params(Params::justified(b"on scene")),
        )
        .expect("collect");
    ais.accept(capsule.clone(), collect.record.clone());
    openings.push(RecordOpening {
        actor: collect.actor.clone(),
        act: params_of(&collect),
    });
    chain.push(collect.record.clone());

    let (analyze, a_actor, a_params) = if o.variant == Variant::ForgeRole {
        forged_analyze(&keys, &capsule, &collect.record, &store)
    } else {
        let s = des
            .append_record(
                &keys,
                &capsule,
                Event::Analyze,
                &collect.record,
                &RecordParams::at(1, NOW + 1).with_params(Params::of(b"fls", b"4.12", b"-r")),
            )
            .expect("analyze");
        let p = s.params.clone().expect("params");
        (s.record, s.actor, p)
    };
    ais.append(analyze.clone());
    openings.push(RecordOpening {
        actor: a_actor,
        act: ActOpening::Params(a_params),
    });
    chain.push(analyze);
    ais.close_epoch();

    // Epoch 1: the transfer.
    let receiving = Receiving {
        actor: lab.commit_actor().expect("blind"),
    };
    let witness = if o.variant == Variant::ImpostorWitness {
        &impostor
    } else {
        &lab
    };
    let (rel, h) = handoff::release(
        &store,
        &keys,
        &capsule,
        &OpenChain::open(&chain, &body_key).expect("open"),
        &Terms {
            to: receiving.to(),
            cond: digest256(b"sealed bag 7"),
            ts: NOW + 10,
            epoch: 1,
        },
        Some(witness),
    )
    .expect("release");
    if o.variant == Variant::LoneReceipt {
        let r = hand_receipt(&keys, &capsule, &chain[1], 2, &h, &lab);
        ais.append(r.clone());
        openings.push(RecordOpening {
            actor: receiving.actor.clone(),
            act: ActOpening::Descriptor(h),
        });
        chain.push(r);
    } else {
        ais.append(rel.record.clone());
        openings.push(RecordOpening {
            actor: rel.actor.clone(),
            act: ActOpening::Descriptor(h),
        });
        chain.push(rel.record.clone());
    }

    if !matches!(o.variant, Variant::NoReceipt | Variant::LoneReceipt) {
        let rec = handoff::receive(
            &lab,
            &keys,
            &capsule,
            &Release {
                record: &rel.record,
                body: &rel.body,
            },
            &h,
            &Receipt {
                recomputed: capsule.d_ev,
                j: 3,
                ts: NOW + 11,
                epoch: 1,
                receiving: receiving.clone(),
            },
        )
        .expect("receipt");
        ais.append(rec.record.clone());
        openings.push(RecordOpening {
            actor: rec.actor.clone(),
            act: ActOpening::Descriptor(h),
        });
        chain.push(rec.record);
    }
    if o.variant == Variant::SecondReceipt {
        let r = hand_receipt(&keys, &capsule, &chain[3], 4, &h, &lab);
        ais.append(r.clone());
        openings.push(RecordOpening {
            actor: receiving.actor.clone(),
            act: ActOpening::Descriptor(h),
        });
        chain.push(r);
    }

    let mut order_fx = None;
    if o.variant == Variant::Order {
        let target = Target::new(&[eid]);
        let order = Order::issue(
            &court,
            digest256(b"oid"),
            target.root(),
            Scope::Payload,
            Mode::Erased,
            NOW,
            NOW + 9_999,
        )
        .expect("order");
        ais.record_order(&order);
        // The lab custodian holds the capsule after the receipt and disposes.
        let d = lab
            .dispose_record(
                &keys,
                &capsule,
                chain.last().expect("a chain"),
                Some(&order.oid),
                &RecordParams::at(chain.len() as u64, NOW + 12)
                    .with_params(Params::justified(b"court order"))
                    .in_epoch(1),
            )
            .expect("dispose");
        ais.append(d.record.clone());
        openings.push(RecordOpening {
            actor: d.actor.clone(),
            act: params_of(&d),
        });
        chain.push(d.record);
        order_fx = Some(OrderFx {
            claimed: vec![ClaimedOrder {
                order: order.clone(),
                covers: vec![(eid, target.prove(&eid).expect("covered"))],
            }],
            leaves: HashMap::new(),
            registry: HashMap::from([(order.oid, order.leaf().digest)]),
            court_pk: court.public_key().to_vec(),
        });
    }
    ais.close_epoch();

    // Registration, with the roster the court will be handed.
    let mut roster = Roster {
        entries: vec![entry(&defr), entry(&des), entry(&store), entry(&lab)],
    };
    if let Some(f) = o.edit_roster {
        f(&mut roster);
    }
    let committee: Vec<SoftwareMlDsa> =
        (0..3).map(|_| SoftwareMlDsa::generate().unwrap()).collect();
    let cosigner = CoSigner::generate().expect("cosigner");
    let ca = SoftwareMlDsa::generate().unwrap();
    let reg = Registration {
        cid: keys.cid_c,
        pk_sig: ca.public_key().to_vec(),
        pk_kem: KeyPair::generate().unwrap().encapsulation_key().to_vec(),
        pk_slh: cosigner.public_key().to_vec(),
        custodians: committee.iter().map(|c| c.public_key().to_vec()).collect(),
        m: 2,
        delta: 600,
        roster: roster.digest(),
    };

    // Every closed epoch, validated by each custodian and approved.
    let mut views: Vec<ChainView> = (0..3)
        .map(|_| ChainView::new(reg.cid, reg.digest()))
        .collect();
    let mut prev = reg.digest();
    let mut epochs = Vec::new();
    for c in ais.closed_epochs() {
        let d_e = checkpoint(&reg.cid, c.epoch, &c.root, c.count, &prev);
        let p = Proposal {
            cid: reg.cid,
            e: c.epoch,
            root: c.root,
            n_e: c.count,
            d_prev: prev,
            d_e,
            over: Committed::Epoch(c.leaf_digests()),
        };
        let approvals = views
            .iter_mut()
            .zip(&committee)
            .enumerate()
            .map(|(j, (v, k))| {
                approve(k, u32::try_from(j).unwrap(), &v.validate(&p).unwrap()).unwrap()
            })
            .collect();
        let set = ApprovalSet::new(approvals, &cosigner, &d_e).expect("co-sign");
        if let Some(f) = order_fx.as_mut() {
            for leaf in c.leaf_digests() {
                f.leaves.insert(*leaf, c.epoch);
            }
        }
        epochs.push(AnchoredEpoch {
            e: c.epoch,
            root: c.root,
            n_e: c.count,
            d_e,
            a_e: set.digest(),
            approvals: set,
        });
        prev = d_e;
    }

    Fx {
        bundle: ais.disclose(0, &keys).expect("bundle"),
        reg,
        epochs,
        package: CourtPackage { roster, openings },
        opening,
        artefact,
        order: order_fx,
    }
}

/// The honest case, built once: SLH-DSA co-signing is the slow part.
fn honest() -> Fx {
    static FX: OnceLock<Fx> = OnceLock::new();
    FX.get_or_init(|| build(Opts::default())).clone()
}

fn run(fx: &Fx) -> Result<pqcl_pipeline::accept::AcceptReport, AcceptError> {
    accept(&AcceptInputs {
        bundle: &fx.bundle,
        reg: &fx.reg,
        epochs: &fx.epochs,
        package: &fx.package,
        plaintext: None,
        redaction: None,
    })
}

// ------------------------------------------------------------ the honest case

#[test]
fn an_honest_bundle_is_accepted_and_the_report_names_what_ran() {
    let fx = honest();
    let r = run(&fx).expect("accepted");
    assert_eq!(
        r.ran,
        vec![
            Predicate::CheckpointChain,
            Predicate::Approvals,
            Predicate::Structure,
            Predicate::Open,
            Predicate::Roster,
            Predicate::Openings,
            Predicate::TransferPairs,
            Predicate::Roles,
            Predicate::ActorSignatures,
            Predicate::WitnessSignatures,
        ]
    );
    let skipped: Vec<_> = r.skipped.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        skipped,
        vec![Predicate::PlaintextOpening, Predicate::Redaction]
    );
    assert_eq!(r.records, 4);
    assert_eq!(r.witnesses, 1, "the release's witness was checked");

    // With the artefact and r_ev, cm_ev is opened too.
    let with = accept(&AcceptInputs {
        bundle: &fx.bundle,
        reg: &fx.reg,
        epochs: &fx.epochs,
        package: &fx.package,
        plaintext: Some((&fx.opening, &fx.artefact)),
        redaction: None,
    })
    .expect("accepted with the plaintext");
    assert!(with.ran.contains(&Predicate::PlaintextOpening));
}

#[test]
fn another_artefact_does_not_open_cm_ev() {
    let fx = honest();
    let mut other = fx.artefact.clone();
    other[0] ^= 1;
    let err = accept(&AcceptInputs {
        bundle: &fx.bundle,
        reg: &fx.reg,
        epochs: &fx.epochs,
        package: &fx.package,
        plaintext: Some((&fx.opening, &other)),
        redaction: None,
    })
    .unwrap_err();
    assert_eq!(err, AcceptError::PlaintextOpening);
}

// ------------------------------------------------------------ the anchor side

#[test]
fn a_checkpoint_that_does_not_chain_is_refused() {
    let mut fx = honest();
    fx.epochs[1].n_e += 1;
    assert_eq!(run(&fx).unwrap_err(), AcceptError::CheckpointChain);
}

#[test]
fn an_approval_set_that_is_not_the_anchored_one_is_refused() {
    let mut fx = honest();
    fx.epochs[0].a_e = digest256(b"another A_e");
    assert!(matches!(
        run(&fx).unwrap_err(),
        AcceptError::Approvals { e: 0, .. }
    ));
}

#[test]
fn an_epoch_withheld_from_the_court_is_refused_by_the_structure() {
    // The checkpoints still chain (a prefix does), but the bundle's second
    // segment has no root to verify against.
    let mut fx = honest();
    fx.epochs.truncate(1);
    assert!(matches!(run(&fx).unwrap_err(), AcceptError::Structure(_)));
}

// --------------------------------------------------------------- the roster

#[test]
fn a_roster_that_is_not_the_registered_one_is_refused() {
    let mut fx = honest();
    fx.package.roster.entries.pop();
    assert_eq!(run(&fx).unwrap_err(), AcceptError::RosterMismatch);
}

#[test]
fn a_roster_naming_one_actor_twice_is_refused() {
    let mut fx = honest();
    let dup = fx.package.roster.entries[0].clone();
    fx.package.roster.entries.push(dup);
    assert_eq!(run(&fx).unwrap_err(), AcceptError::RosterDuplicate);
}

#[test]
fn the_registration_commits_to_the_roster() {
    let fx = honest();
    let mut other = fx.reg.clone();
    other.roster = digest256(b"another roster");
    assert_ne!(fx.reg.digest(), other.digest(), "reg does not bind ρ_c");
}

// -------------------------------------------------------------- the openings

#[test]
fn one_opening_per_record_is_required() {
    let mut fx = honest();
    fx.package.openings.pop();
    assert_eq!(
        run(&fx).unwrap_err(),
        AcceptError::OpeningCount {
            records: 4,
            openings: 3
        }
    );
}

#[test]
fn an_actor_opening_with_another_blind_is_refused() {
    let mut fx = honest();
    fx.package.openings[1].actor.r_a = digest256(b"not r_a");
    assert_eq!(run(&fx).unwrap_err(), AcceptError::ActorOpening { j: 1 });
}

#[test]
fn a_params_opening_with_another_blind_is_refused() {
    let mut fx = honest();
    let ActOpening::Params(p) = &mut fx.package.openings[1].act else {
        panic!("ANALYZE opens params");
    };
    p.r_p = digest256(b"not r_p");
    assert_eq!(run(&fx).unwrap_err(), AcceptError::ActOpening { j: 1 });
}

#[test]
fn a_transfer_opened_as_a_tool_run_is_refused() {
    let mut fx = honest();
    fx.package.openings[2].act = fx.package.openings[1].act.clone();
    assert_eq!(run(&fx).unwrap_err(), AcceptError::ActOpening { j: 2 });
}

// --------------------------------------------- the two the design review named

#[test]
fn a_role_that_may_not_sign_its_event_is_refused() {
    // ⭐ The swapped-role case: an ANALYZE whose opening names the evidence
    // store, a custodian. It opens, and its signer is enrolled; the role table
    // is what refuses it.
    let fx = build(Opts {
        variant: Variant::ForgeRole,
        ..Opts::default()
    });
    assert_eq!(run(&fx).unwrap_err(), AcceptError::WrongRole { j: 1 });
}

#[test]
fn a_signature_under_a_key_that_is_not_the_signers_is_refused() {
    // ⭐ The wrong-key case: the registered roster lists the DEFR's key for
    // the DES. Everything else holds, so σ_actor is what refuses.
    let fx = build(Opts {
        edit_roster: Some(|r: &mut Roster| {
            let defr_pk = r.entries[0].pk.clone();
            r.entries[1].pk = defr_pk;
        }),
        ..Opts::default()
    });
    assert_eq!(run(&fx).unwrap_err(), AcceptError::ActorSignature { j: 1 });
}

#[test]
fn a_signer_missing_from_the_roster_is_refused() {
    let fx = build(Opts {
        edit_roster: Some(|r: &mut Roster| {
            r.entries.pop();
        }),
        ..Opts::default()
    });
    assert_eq!(run(&fx).unwrap_err(), AcceptError::NotEnrolled { j: 3 });
}

#[test]
fn a_release_witnessed_by_someone_other_than_its_receiver_is_refused() {
    let fx = build(Opts {
        variant: Variant::ImpostorWitness,
        ..Opts::default()
    });
    assert_eq!(
        run(&fx).unwrap_err(),
        AcceptError::WitnessSignature { j: 2 }
    );
}

#[test]
fn a_witnessed_release_with_no_disclosed_receipt_is_refused() {
    let fx = build(Opts {
        variant: Variant::NoReceipt,
        ..Opts::default()
    });
    assert_eq!(run(&fx).unwrap_err(), AcceptError::WitnessUnpaired { j: 2 });
}

// ---------------------------------------------------- transfer pairing (§1bu.1)

#[test]
fn a_receipt_with_no_earlier_release_is_refused() {
    // The lab's own key signs a receipt over a descriptor whose release never
    // reached the chain. The append path would refuse it; the court's check
    // must not depend on that.
    let fx = build(Opts {
        variant: Variant::LoneReceipt,
        ..Opts::default()
    });
    assert_eq!(run(&fx).unwrap_err(), AcceptError::ReceiptUnpaired { j: 2 });
}

#[test]
fn a_descriptor_used_by_a_second_receipt_is_refused() {
    let fx = build(Opts {
        variant: Variant::SecondReceipt,
        ..Opts::default()
    });
    assert_eq!(
        run(&fx).unwrap_err(),
        AcceptError::DescriptorReused { j: 4 }
    );
}

// --------------------------------------------------------------- redaction

#[test]
fn a_court_ordered_dispose_needs_its_order_and_the_order_must_be_genuine() {
    let fx = build(Opts {
        variant: Variant::Order,
        ..Opts::default()
    });
    assert_eq!(run(&fx).unwrap_err(), AcceptError::RedactionEvidenceMissing);

    let o = fx.order.as_ref().expect("an order");
    let erased = Path::new("/nonexistent/pqcl-accept-payload");
    let with = |registry: &HashMap<Digest32, Digest32>| {
        accept(&AcceptInputs {
            bundle: &fx.bundle,
            reg: &fx.reg,
            epochs: &fx.epochs,
            package: &fx.package,
            plaintext: None,
            redaction: Some(RedactionEvidence {
                claimed: &o.claimed,
                anchored_leaves: &o.leaves,
                registry,
                court_pk: &o.court_pk,
                payload: erased,
            }),
        })
    };
    let r = with(&o.registry).expect("a genuine order, executed");
    assert!(r.ran.contains(&Predicate::Redaction));

    // The chain recorded nothing under that oid: the DISPOSE cites no genuine
    // order, which `account` alone would not report.
    assert_eq!(
        with(&HashMap::new()).unwrap_err(),
        AcceptError::OrderNotGenuine { j: 4 }
    );
}

// ---------------------------------------------------------- the package

#[test]
fn the_package_reaches_only_its_court_and_only_for_its_capsule() {
    let fx = honest();
    let court = KeyPair::generate().unwrap();
    let cid = fx.reg.cid;
    let eid = fx.bundle.capsule.eid;
    let sealed =
        SealedPackage::seal(&fx.package, cid, eid, court.encapsulation_key()).expect("seal");
    assert_eq!(sealed.open(&court).expect("open"), fx.package);

    let other = KeyPair::generate().unwrap();
    assert!(sealed.open(&other).is_err(), "another key opened it");

    let mut moved = sealed.clone();
    moved.eid = digest256(b"another capsule");
    assert!(moved.open(&court).is_err(), "not bound to its capsule");

    assert_eq!(
        CourtPackage::decode(&fx.package.encode()).expect("decode"),
        fx.package
    );
}
