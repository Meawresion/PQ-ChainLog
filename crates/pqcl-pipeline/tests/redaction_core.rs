//! SAC Phase 5 as built: redaction over
//! `Π_core` alone, and `eq:validredact` as one check a court runs.
//!
//! Every negative case is the real verifier refusing a real object, built the
//! way the attack builds it: an insider's self-signed order, a field changed
//! after signing, one capsule's order replayed on another, another capsule's
//! `DISPOSE`, and each anchor withheld in turn.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeSet, HashMap};

use pqcl_capsule::redaction::{Mode, Order, OrderError, Scope, Target};
use pqcl_capsule::{Bundle, Capsule, Params, Role};
use pqcl_dsse::core::{Client, Edb, HonestEdb, Op};
use pqcl_dsse::range::RangeTree;
use pqcl_pipeline::redaction::{
    Openings, PayloadStore, Redactee, RedactionCheck, RedactionClaim, RedactionError, execute_core,
    index_keywords, verify_redaction,
};
use pqcl_pipeline::{Agent, Ais, CaseKeys, IngestParams, LeafRef, RecordParams};
use pqcl_primitives::kem;
use pqcl_primitives::xof::{Digest32, PrfKey, digest256};
use pqcl_primitives::{Signer, SoftwareMlDsa};

const NOW: u64 = 1_700_000_100;

// ------------------------------------------------------------ execute_core

struct Index {
    client: Client,
    edb: HonestEdb,
    keywords: Vec<Vec<Vec<u8>>>,
}

fn eid(i: u64) -> Digest32 {
    digest256(&i.to_le_bytes())
}

/// Six documents under `common`, every other one also under `even`, each with
/// its range prefixes.
fn index() -> Index {
    let tree = RangeTree::new("hour", 8);
    let mut client = Client::new(PrfKey::new([0x33u8; 32]));
    let mut edb = HonestEdb::new();
    let mut keywords = Vec::new();
    for d in 0..6u64 {
        let mut plain = vec![b"common".to_vec()];
        if d % 2 == 0 {
            plain.push(b"even".to_vec());
        }
        let kws = index_keywords(&plain, &[(&tree, 100 + d)]);
        for w in &kws {
            edb.insert(&client.update(Op::Add, w, d).unwrap());
        }
        keywords.push(kws);
    }
    Index {
        client,
        edb,
        keywords,
    }
}

fn search(ix: &Index, w: &[u8]) -> BTreeSet<u64> {
    let t = ix.client.search_token(w).unwrap();
    ix.client.finish(w, &t, &ix.edb.search(&t)).unwrap()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("pqcl-redcore-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Run one order over document 2 at `scope`; `record` decides whether the
/// chain recorded it.
fn redact(
    name: &str,
    scope: Scope,
    record: bool,
) -> (
    Index,
    PayloadStore,
    Result<pqcl_pipeline::redaction::Outcome, RedactionError>,
) {
    let mut ix = index();
    let payloads = PayloadStore::open(&scratch(name)).unwrap();
    for d in 0..6 {
        payloads.put(&eid(d), b"ciphertext").unwrap();
    }
    let mut openings = Openings::new();
    openings.insert(eid(2), [7u8; 32]);
    let court = SoftwareMlDsa::generate().unwrap();
    let court_kem = kem::KeyPair::generate().unwrap();
    let target = Target::new(&[eid(2)]);
    let o = Order::issue(
        &court,
        digest256(b"oid"),
        target.root(),
        scope,
        Mode::Erased,
        NOW - 10,
        NOW + 1000,
    )
    .unwrap();
    let mut registry = HashMap::new();
    if record {
        registry.insert(o.oid, o.leaf().digest);
    }
    let r = [Redactee {
        eid: eid(2),
        doc: 2,
        membership: target.prove(&eid(2)).unwrap(),
        keywords: ix.keywords[2].clone(),
    }];
    let out = execute_core(
        &o,
        court.public_key(),
        NOW,
        &registry,
        &r,
        &payloads,
        &mut openings,
        court_kem.encapsulation_key(),
        &mut ix.client,
        &mut ix.edb,
    );
    (ix, payloads, out)
}

#[test]
fn an_unrecorded_order_deletes_nothing() {
    let (ix, payloads, out) = redact("unrecorded", Scope::Full, false);
    assert!(matches!(
        out,
        Err(RedactionError::Order(OrderError::NotRecorded))
    ));
    assert!(payloads.exists(&eid(2)), "the payload went before the gate");
    assert!(search(&ix, b"even").contains(&2));
}

#[test]
fn payload_erases_the_payload_and_leaves_the_index() {
    let (ix, payloads, out) = redact("payload", Scope::Payload, true);
    let out = out.unwrap();
    assert_eq!((out.payloads_erased, out.pairs_tombstoned), (1, 0));
    assert_eq!(
        out.openings_destroyed, 1,
        "ERASED destroys r_ev at every scope"
    );
    assert!(!payloads.exists(&eid(2)));
    assert!(search(&ix, b"even").contains(&2), "a match stays learnable");
}

#[test]
fn payload_and_index_leaves_no_keyword_or_range_prefix_returning_it() {
    for (name, scope) in [("pi", Scope::PayloadIndex), ("full", Scope::Full)] {
        let (ix, payloads, out) = redact(name, scope, true);
        let out = out.unwrap();
        assert!(!out.compacted, "Π_core has nothing to compact");
        assert_eq!(out.pairs_tombstoned, ix.keywords[2].len());
        assert!(!payloads.exists(&eid(2)));
        for w in &ix.keywords[2] {
            assert!(!search(&ix, w).contains(&2), "{scope:?} left {w:?}");
        }
        assert_eq!(search(&ix, b"even"), BTreeSet::from([0, 4]));
        assert_eq!(search(&ix, b"common").len(), 5);
    }
}

// ------------------------------------------------------- verify_redaction

struct Case {
    keys: CaseKeys,
    court: SoftwareMlDsa,
    order: Order,
    target: Target,
    order_at: LeafRef,
    ais: Ais,
    capsules: [Capsule; 2],
}

fn seal(defr: &Agent, keys: &CaseKeys, n: &[u8]) -> Capsule {
    defr.seal(
        keys,
        digest256(&[b"cm".as_slice(), n].concat()),
        &IngestParams {
            artefact_type: b"disk-image",
            d_ev: digest256(&[b"d_ev".as_slice(), n].concat()),
            ptr: b"s3://case/obj",
            epoch: 0,
            nonce: &digest256(n),
        },
    )
    .unwrap()
}

/// Epoch 0 seals capsules A and B. Epoch 1 holds an order over A, A's
/// `DISPOSE` citing it, and B's `DISPOSE` citing it too, which the order does
/// not cover.
fn case() -> Case {
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst (validredact)")),
        b"case-validredact",
        &digest256(b"r_case"),
    );
    let defr = Agent::new(
        SoftwareMlDsa::generate().unwrap(),
        b"first-responder-1",
        Role::Defr,
    );
    let lab = Agent::new(
        SoftwareMlDsa::generate().unwrap(),
        b"lab-custodian-1",
        Role::Custodian,
    );
    let court = SoftwareMlDsa::generate().unwrap();
    let mut ais = Ais::new();
    let capsules = [seal(&defr, &keys, b"A"), seal(&defr, &keys, b"B")];
    let mut collects = Vec::new();
    for c in &capsules {
        let r = defr
            .collect_record(
                &keys,
                c,
                &RecordParams::at(0, NOW).with_params(Params::justified(b"on scene")),
            )
            .unwrap();
        ais.accept(c.clone(), r.record.clone());
        collects.push(r.record);
    }
    ais.close_epoch();

    let target = Target::new(&[capsules[0].eid]);
    let order = Order::issue(
        &court,
        digest256(b"oid A"),
        target.root(),
        Scope::PayloadIndex,
        Mode::Erased,
        NOW,
        NOW + 9_999,
    )
    .unwrap();
    let order_at = ais.record_order(&order);
    for (c, prev) in capsules.iter().zip(&collects) {
        let d = lab
            .dispose_record(
                &keys,
                c,
                prev,
                Some(&order.oid),
                &RecordParams::at(1, NOW + 5)
                    .with_params(Params::justified(b"court order"))
                    .in_epoch(1),
            )
            .unwrap();
        ais.append(d.record);
    }
    ais.close_epoch();
    Case {
        keys,
        court,
        order,
        target,
        order_at,
        ais,
        capsules,
    }
}

fn bundle(c: &Case, i: usize) -> Bundle {
    c.ais.disclose(i, &c.keys).unwrap()
}

/// The claim for capsule `i` with every part honest, then `edit` applied.
fn check(c: &Case, edit: impl FnOnce(&mut Parts)) -> Result<(), RedactionCheck> {
    let a = bundle(c, 0);
    let mut p = Parts {
        order: c.order.clone(),
        membership: c.target.prove(&c.capsules[0].eid).unwrap(),
        order_proof: c.ais.prove(&c.order_at).unwrap(),
        capsule: a.capsule.clone(),
        seal: a.seal.clone(),
        disposal: a.segments.last().unwrap().clone(),
        roots: c.ais.epoch_roots(),
        court_pk: c.court.public_key().to_vec(),
    };
    edit(&mut p);
    let claim = RedactionClaim {
        order: &p.order,
        membership: &p.membership,
        order_proof: &p.order_proof,
        capsule: &p.capsule,
        seal: &p.seal,
        disposal: &p.disposal,
    };
    let k_eid = c.keys.capsule_link_key(&c.capsules[0].eid);
    verify_redaction(&claim, &p.court_pk, &k_eid, &p.roots)
}

struct Parts {
    order: Order,
    membership: pqcl_forest::InclusionProof,
    order_proof: pqcl_forest::MmrProof,
    capsule: Capsule,
    seal: pqcl_capsule::disclosure::SealProof,
    disposal: pqcl_capsule::Segment,
    roots: Vec<(u64, Digest32)>,
    court_pk: Vec<u8>,
}

#[test]
fn an_honest_redaction_is_accepted() {
    assert_eq!(check(&case(), |_| {}), Ok(()));
}

#[test]
fn an_order_the_court_did_not_sign_is_refused() {
    let c = case();
    let insider = SoftwareMlDsa::generate().unwrap();
    let o = &c.order;
    let forged = Order::issue(&insider, o.oid, o.tgt, o.scope, o.mode, o.ts, o.exp).unwrap();
    assert_eq!(check(&c, |p| p.order = forged), Err(RedactionCheck::Order));
}

#[test]
fn an_order_edited_after_signing_is_refused() {
    let c = case();
    assert_eq!(
        check(&c, |p| p.order.scope = Scope::Full),
        Err(RedactionCheck::Order)
    );
}

#[test]
fn an_order_replayed_on_another_capsule_is_refused() {
    // B's own disclosure, A's order: B is not in A's target.
    let c = case();
    let b = bundle(&c, 1);
    let other = Target::new(&[c.capsules[0].eid, digest256(b"x")]);
    let r = check(&c, |p| {
        p.capsule = b.capsule.clone();
        p.seal = b.seal.clone();
        p.disposal = b.segments.last().unwrap().clone();
        p.membership = other.prove(&c.capsules[0].eid).unwrap();
    });
    assert_eq!(r, Err(RedactionCheck::NotTargeted));
}

#[test]
fn another_capsules_dispose_is_refused() {
    let c = case();
    let b = bundle(&c, 1);
    assert_eq!(
        check(&c, |p| p.disposal = b.segments.last().unwrap().clone()),
        Err(RedactionCheck::DisposalNotAnchored)
    );
}

#[test]
fn a_segment_with_no_dispose_is_refused() {
    let c = case();
    assert_eq!(
        check(&c, |p| p.disposal = bundle(&c, 0).segments[0].clone()),
        Err(RedactionCheck::NoDisposal)
    );
}

#[test]
fn each_anchor_withheld_is_refused() {
    let c = case();
    assert_eq!(
        check(&c, |p| p.roots.retain(|(e, _)| *e != 0)),
        Err(RedactionCheck::SealNotAnchored)
    );
    assert_eq!(
        check(&c, |p| p.roots.retain(|(e, _)| *e != 1)),
        Err(RedactionCheck::OrderNotAnchored)
    );
    // A proof for another leaf of the redaction epoch is not L_red's.
    let wrong = c
        .ais
        .prove(&LeafRef {
            epoch: 1,
            index: c.order_at.index + 1,
        })
        .unwrap();
    assert_eq!(
        check(&c, |p| p.order_proof = wrong),
        Err(RedactionCheck::OrderNotAnchored)
    );
}

#[test]
fn a_redaction_epoch_before_the_sealing_epoch_is_refused() {
    let c = case();
    assert_eq!(
        check(&c, |p| p.seal.epoch = 2),
        Err(RedactionCheck::OrderPrecedesSeal)
    );
}
