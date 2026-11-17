//! Phase 11 end to end (the design record items (a)–(g)).
//!
//! Every property is checked against real signatures, a real index and real
//! files. The two negative tests §1u.3 requires, and the one (f) implies, are
//! demonstrated failing rather than asserted absent:
//!
//! * an order-less deletion alerts, the same deletion under a recorded order
//!   does not ([`an_unordered_deletion_alerts_and_an_ordered_one_does_not`]);
//! * tombstoning without the range prefixes leaves a searchable ghost
//!   ([`omitting_range_prefixes_leaves_a_searchable_ghost`]).
//!
//! (The `mode`/`exp` flip is in `contracts/test/Redaction.t.sol` and in
//! `pqcl-capsule`'s unit tests.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use pqcl_capsule::Event;
use pqcl_capsule::redaction::{Mode, Order, OrderError, Scope, Target};
use pqcl_dsse::core::{Client, DocId, Op};
use pqcl_dsse::range::RangeTree;
use pqcl_dsse::xt::{HonestServer, XTag, XtClient};
use pqcl_pipeline::redaction::{
    AnchoredPayload, ClaimedOrder, DisposalClaim, Openings, PayloadStore, Redactee, RedactionError,
    Unaccounted, account, execute, index_keywords,
};
use pqcl_primitives::kem;
use pqcl_primitives::xof::{Digest32, PrfKey, digest256};
use pqcl_primitives::{Signer, SoftwareMlDsa};

const NOW: u64 = 1_700_000_100;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pqcl-redaction-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// The index identifier of document `d`: `id = (e, j)` (draft8 D3). The
/// fixture closes its first epoch after document 5.
fn did(d: u64) -> DocId {
    pqcl_dsse::xt::doc_id(u64::from(d > 5), d)
}

fn eid(i: u64) -> Digest32 {
    digest256(&i.to_le_bytes())
}

struct World {
    court: SoftwareMlDsa,
    court_kem: kem::KeyPair,
    index: XtClient,
    server: HonestServer,
    payloads: PayloadStore,
    openings: Openings,
    tree: RangeTree,
    /// doc → its full keyword set.
    keywords: Vec<Vec<Vec<u8>>>,
    /// oid → the `0x05` digest the chain recorded for it.
    registry: HashMap<Digest32, Digest32>,
}

const DOCS: u64 = 12;
const VICTIM: u64 = 3;

fn world(name: &str) -> World {
    let tree = RangeTree::new("size", 8);
    let mut index = XtClient::new(
        Client::new(PrfKey::new([0x21u8; 32])),
        PrfKey::new([0x91u8; 32]),
        4,
    );
    let mut server = HonestServer::new();
    let payloads = PayloadStore::open(&scratch(name)).unwrap();
    let mut openings = Openings::new();
    let mut keywords = Vec::new();
    for id in 0..DOCS {
        let mut plain = vec![b"common".to_vec()];
        if id % 3 == 0 {
            plain.push(b"secret".to_vec());
        }
        let kws = index_keywords(&plain, &[(&tree, 40 + id)]);
        for w in &kws {
            index.update(&mut server, Op::Add, w, did(id)).unwrap();
        }
        payloads.put(&eid(id), b"ciphertext").unwrap();
        openings.insert(eid(id), [u8::try_from(id).unwrap(); 32]);
        keywords.push(kws);
        if id == 5 {
            index.close_epoch(&mut server);
        }
    }
    index.close_epoch(&mut server);
    World {
        court: SoftwareMlDsa::generate().unwrap(),
        court_kem: kem::KeyPair::generate().unwrap(),
        index,
        server,
        payloads,
        openings,
        tree,
        keywords,
        registry: HashMap::new(),
    }
}

fn order(w: &World, scope: Scope, mode: Mode, docs: &[u64]) -> (Order, Vec<Redactee>) {
    let members: Vec<_> = docs.iter().map(|d| eid(*d)).collect();
    let target = Target::new(&members);
    let o = Order::issue(
        &w.court,
        digest256(format!("order {docs:?} {scope:?}").as_bytes()),
        target.root(),
        scope,
        mode,
        NOW - 50,
        NOW + 1000,
    )
    .unwrap();
    let r = docs
        .iter()
        .map(|d| Redactee {
            eid: eid(*d),
            doc: did(*d),
            membership: target.prove(&eid(*d)).unwrap(),
            keywords: w.keywords[usize::try_from(*d).unwrap()].clone(),
        })
        .collect();
    (o, r)
}

fn run(
    w: &mut World,
    o: &Order,
    r: &[Redactee],
) -> Result<pqcl_pipeline::redaction::Outcome, RedactionError> {
    let pk = w.court.public_key().to_vec();
    let ek = w.court_kem.encapsulation_key().to_vec();
    execute(
        o,
        &pk,
        NOW,
        &w.registry,
        r,
        &w.payloads,
        &mut w.openings,
        &ek,
        &mut w.index,
        &mut w.server,
        || PrfKey::new([0xa7u8; 32]),
    )
}

fn server_tags(s: &HonestServer) -> HashSet<XTag> {
    s.xset
        .all_epochs()
        .into_iter()
        .flat_map(|(_, t)| t)
        .collect()
}

/// Redacted pairs an adversary holding the current key state and every
/// retained `XSet` can still confirm.
fn residual(w: &World, retained: &HashSet<XTag>, doc: DocId) -> usize {
    let now = server_tags(&w.server);
    w.keywords[usize::try_from(doc).unwrap()]
        .iter()
        .filter(|kw| {
            w.index
                .derivable_xtags(kw, did(doc))
                .iter()
                .any(|t| retained.contains(t) || now.contains(t))
        })
        .count()
}

fn found(w: &World, kw: &[u8]) -> bool {
    w.index
        .candidates(&w.server, kw)
        .unwrap()
        .contains(&did(VICTIM))
}

fn range_hit(w: &World, lo: u64, hi: u64) -> bool {
    w.tree.cover_keywords(lo, hi).iter().any(|k| {
        w.index
            .candidates(&w.server, k)
            .unwrap()
            .contains(&did(VICTIM))
    })
}

// ------------------------------------------------------------- (c) the gate

#[test]
fn nothing_is_touched_until_the_order_is_genuine_recorded_and_targeting() {
    let mut w = world("gate");
    let (o, r) = order(&w, Scope::Full, Mode::Erased, &[VICTIM]);
    let live = w.index.live_pairs();

    // Not recorded on chain.
    assert!(matches!(
        run(&mut w, &o, &r),
        Err(RedactionError::Order(OrderError::NotRecorded))
    ));
    w.registry.insert(o.oid, o.leaf().digest);

    // Signed by someone other than the court.
    let rogue = SoftwareMlDsa::generate().unwrap();
    let mut forged = o.clone();
    forged.sig_co = rogue.sign(&forged.message()).unwrap();
    assert!(matches!(
        run(&mut w, &forged, &r),
        Err(RedactionError::Order(OrderError::BadSignature))
    ));

    // A capsule the order does not cover.
    let (_, other) = order(&w, Scope::Full, Mode::Erased, &[VICTIM + 1]);
    assert!(matches!(
        run(&mut w, &o, &other),
        Err(RedactionError::Order(OrderError::NotTargeted))
    ));

    // Expired.
    let mut stale = Order::issue(&w.court, o.oid, o.tgt, o.scope, o.mode, 1, NOW - 1).unwrap();
    stale.oid = o.oid;
    assert!(matches!(
        run(&mut w, &stale, &r),
        Err(RedactionError::Order(OrderError::Expired { .. }))
    ));

    assert!(
        w.payloads.exists(&eid(VICTIM)),
        "a refused order deleted the payload"
    );
    assert_eq!(
        w.index.live_pairs(),
        live,
        "a refused order touched the index"
    );
    assert!(w.openings.holds(&eid(VICTIM)));
}

// ---------------------------------------------------------- scopes, (e), (f)

#[test]
fn each_scope_does_exactly_what_phase_11_says() {
    for scope in [Scope::Payload, Scope::PayloadIndex, Scope::Full] {
        let mut w = world(&format!("scope-{}", scope.byte()));
        let retained = server_tags(&w.server);
        let all = w.keywords[usize::try_from(VICTIM).unwrap()].len();
        let (o, r) = order(&w, scope, Mode::Erased, &[VICTIM]);
        w.registry.insert(o.oid, o.leaf().digest);
        let out = run(&mut w, &o, &r).unwrap();

        assert!(
            !w.payloads.exists(&eid(VICTIM)),
            "{scope:?}: payload survived"
        );
        assert_eq!(out.payloads_erased, 1);
        let res = residual(&w, &retained, VICTIM);
        match scope {
            Scope::Payload => {
                assert!(
                    found(&w, b"secret") && range_hit(&w, 0, 255),
                    "PAYLOAD: a match must stay learnable"
                );
                assert_eq!(out.pairs_tombstoned, 0);
                assert_eq!(res, all);
            }
            Scope::PayloadIndex => {
                assert!(
                    !found(&w, b"secret") && !found(&w, b"common"),
                    "PAYLOAD+INDEX: a trapdoor returns it"
                );
                assert!(
                    !range_hit(&w, 0, 255) && !range_hit(&w, 43, 43),
                    "PAYLOAD+INDEX: a range returns it"
                );
                assert!(!out.compacted);
                assert_eq!(res, all, "cross-tags live until compaction");
            }
            Scope::Full => {
                assert!(out.compacted);
                assert!(!found(&w, b"secret") && !range_hit(&w, 0, 255));
                assert_eq!(res, 0, "FULL: a redacted pair is still confirmable");
                assert!(found_other(&w), "FULL destroyed an unredacted match");
            }
        }
    }
}

fn found_other(w: &World) -> bool {
    w.index
        .candidates(&w.server, b"secret")
        .unwrap()
        .contains(&did(6))
}

#[test]
fn omitting_range_prefixes_leaves_a_searchable_ghost() {
    // ⭐ (f), demonstrated: tombstone the plain keywords only.
    let mut w = world("ghost");
    let (o, mut r) = order(&w, Scope::PayloadIndex, Mode::Erased, &[VICTIM]);
    r[0].keywords = vec![b"common".to_vec(), b"secret".to_vec()];
    w.registry.insert(o.oid, o.leaf().digest);
    run(&mut w, &o, &r).unwrap();
    assert!(!found(&w, b"secret"));
    assert!(
        range_hit(&w, 0, 255),
        "without prefixes the range query must still hit (the ghost)"
    );

    // With index_keywords, it does not (each_scope_does_exactly_what_phase_11_says).
}

#[test]
fn a_sweep_is_one_order_over_many_capsules() {
    let mut w = world("sweep");
    let retained = server_tags(&w.server);
    let docs = [0u64, 3, 6, 9];
    let (o, r) = order(&w, Scope::Full, Mode::Erased, &docs);
    w.registry.insert(o.oid, o.leaf().digest);
    let out = run(&mut w, &o, &r).unwrap();
    assert_eq!(out.payloads_erased, 4);
    for d in docs {
        assert_eq!(residual(&w, &retained, d), 0);
        assert!(!w.payloads.exists(&eid(d)));
    }
    assert!(
        w.payloads.exists(&eid(1)),
        "an untargeted payload was deleted"
    );
}

// ------------------------------------------------------------------ r_ev, mode

#[test]
fn sealed_escrows_to_the_court_and_erased_destroys() {
    let mut w = world("mode");
    let (o, r) = order(&w, Scope::Full, Mode::Sealed, &[VICTIM]);
    w.registry.insert(o.oid, o.leaf().digest);
    let out = run(&mut w, &o, &r).unwrap();
    assert!(!w.openings.holds(&eid(VICTIM)), "the lab kept r_ev");
    assert_eq!(out.escrows.len(), 1);
    assert_eq!(out.escrows[0].open(&w.court_kem).unwrap(), [3u8; 32]);
    let stranger = kem::KeyPair::generate().unwrap();
    assert!(
        out.escrows[0].open(&stranger).is_err(),
        "anyone but the court opened the escrow"
    );

    let (o2, r2) = order(&w, Scope::Payload, Mode::Erased, &[4]);
    w.registry.insert(o2.oid, o2.leaf().digest);
    let out = run(&mut w, &o2, &r2).unwrap();
    assert!(out.escrows.is_empty());
    assert_eq!(out.openings_destroyed, 1);
    assert!(!w.openings.holds(&eid(4)));
}

// ------------------------------------------------------------- (g) accounting

struct Ledger {
    anchored: Vec<AnchoredPayload>,
    claimed: Vec<ClaimedOrder>,
    /// `0x05` leaf digest → the epoch whose anchored root holds it.
    leaves: HashMap<Digest32, u64>,
    disposals: Vec<(Digest32, DisposalClaim)>,
}

/// What the auditor reads off a stored `DISPOSE`, with no key.
///
/// ⭐ Since M13 A1 this is a [`DisposalClaim`] and not a fabricated
/// `CustodyRecord`. The old fixture invented a record with zeroed `actor_c`,
/// `params_c` and an empty signature purely to reach one field — which is both
/// a private record-building path (M13 A2 forbids them) and a thing no real
/// chain contains. Accounting only ever read `eid_e` and `order_ref`, so the
/// narrowed input type made the fake record unnecessary rather than merely
/// easier to build.
fn dispose(e: Digest32, oid: Option<Digest32>) -> (Digest32, DisposalClaim) {
    (
        e,
        DisposalClaim {
            eid_e: e,
            order_ref: oid,
        },
    )
}

/// The epoch each document's seal was anchored in: `world` closes epoch 0
/// after document 5.
fn epoch_of(d: u64) -> u64 {
    u64::from(d > 5)
}

/// The epoch orders are anchored in unless a test says otherwise: the last
/// one, after every capsule.
const ORDER_EPOCH: u64 = 1;

fn ledger(w: &World) -> Ledger {
    Ledger {
        anchored: (0..DOCS)
            .map(|d| AnchoredPayload {
                eid: eid(d),
                path: w.payloads.path(&eid(d)),
                epoch: epoch_of(d),
            })
            .collect(),
        claimed: Vec::new(),
        leaves: HashMap::new(),
        disposals: Vec::new(),
    }
}

fn audit(w: &World, l: &Ledger) -> Vec<Unaccounted> {
    account(
        &l.anchored,
        &l.claimed,
        &l.leaves,
        &w.registry,
        &l.disposals,
        w.court.public_key(),
    )
}

#[test]
fn an_unordered_deletion_alerts_and_an_ordered_one_does_not() {
    // ⭐ §1u.3's second negative test.
    let mut w = world("account");
    let mut l = ledger(&w);
    assert!(audit(&w, &l).is_empty(), "a clean store raised a finding");

    // The unauthorised deletion: same bytes gone, no order.
    std::fs::remove_file(w.payloads.path(&eid(VICTIM))).unwrap();
    assert_eq!(
        audit(&w, &l),
        vec![Unaccounted::PayloadDeleted { eid: eid(VICTIM) }]
    );

    // The lawful one: order recorded, executed, DISPOSE, 0x05 anchored.
    let (o, r) = order(&w, Scope::Payload, Mode::Erased, &[VICTIM]);
    w.registry.insert(o.oid, o.leaf().digest);
    run(&mut w, &o, &r).unwrap();
    l.claimed.push(ClaimedOrder {
        order: o.clone(),
        covers: vec![(eid(VICTIM), r[0].membership.clone())],
    });
    l.leaves.insert(o.leaf().digest, ORDER_EPOCH);
    l.disposals.push(dispose(eid(VICTIM), Some(o.oid)));
    assert!(
        audit(&w, &l).is_empty(),
        "a lawful deletion raised an alarm"
    );
}

#[test]
fn a_compromised_ais_cannot_explain_a_deletion_away() {
    let mut w = world("compromised");
    let mut l = ledger(&w);
    std::fs::remove_file(w.payloads.path(&eid(VICTIM))).unwrap();
    let want = vec![Unaccounted::PayloadDeleted { eid: eid(VICTIM) }];

    // It forges an order under its own key, anchors its leaf, writes a DISPOSE.
    let rogue = SoftwareMlDsa::generate().unwrap();
    let t = Target::new(&[eid(VICTIM)]);
    let fake = Order::issue(
        &rogue,
        digest256(b"fake"),
        t.root(),
        Scope::Payload,
        Mode::Erased,
        NOW,
        NOW + 9,
    )
    .unwrap();
    // It controls its anchoring account, so it records the fake on chain too:
    // only σ_CO stops it.
    w.registry.insert(fake.oid, fake.leaf().digest);
    l.claimed.push(ClaimedOrder {
        order: fake.clone(),
        covers: vec![(eid(VICTIM), t.prove(&eid(VICTIM)).unwrap())],
    });
    l.leaves.insert(fake.leaf().digest, ORDER_EPOCH);
    l.disposals.push(dispose(eid(VICTIM), Some(fake.oid)));
    assert_eq!(audit(&w, &l), want, "a forged σ_CO was accepted");

    // A genuine order it never anchored.
    let real = Order::issue(
        &w.court,
        digest256(b"real"),
        t.root(),
        Scope::Payload,
        Mode::Erased,
        NOW,
        NOW + 9,
    )
    .unwrap();
    w.registry.insert(real.oid, real.leaf().digest);
    l.claimed.push(ClaimedOrder {
        order: real.clone(),
        covers: vec![(eid(VICTIM), t.prove(&eid(VICTIM)).unwrap())],
    });
    l.disposals.push(dispose(eid(VICTIM), Some(real.oid)));
    assert_eq!(audit(&w, &l), want, "an unanchored order was accepted");

    // Anchored, but no DISPOSE references it.
    l.leaves.insert(real.leaf().digest, ORDER_EPOCH);
    l.disposals.retain(|(_, d)| d.order_ref != Some(real.oid));
    assert_eq!(
        audit(&w, &l),
        want,
        "an order without a DISPOSE was accepted"
    );

    // A genuine anchored order for a *different* capsule, stretched to this one.
    let other = Target::new(&[eid(1)]);
    let o2 = Order::issue(
        &w.court,
        digest256(b"o2"),
        other.root(),
        Scope::Payload,
        Mode::Erased,
        NOW,
        NOW + 9,
    )
    .unwrap();
    w.registry.insert(o2.oid, o2.leaf().digest);
    l.leaves.insert(o2.leaf().digest, ORDER_EPOCH);
    l.claimed.push(ClaimedOrder {
        order: o2.clone(),
        covers: vec![(eid(VICTIM), other.prove(&eid(1)).unwrap())],
    });
    l.disposals.push(dispose(eid(VICTIM), Some(o2.oid)));
    assert!(audit(&w, &l).contains(&Unaccounted::PayloadDeleted { eid: eid(VICTIM) }));
}

/// ⭐ **Acceptance A7 (a): an order is the digest the chain recorded, not the
/// id.** Before A7 the registry answered only whether *an* order was recorded
/// under an id, so a second, genuinely court-signed order carrying a recorded
/// id — a superseded draft, or the same instrument re-issued with a wider
/// target — was executed and accepted by the audit although the chain holds a
/// different order under that id (`eq:vred`'s `ℓ^ord = order^chain_oid`,
/// `audit/06` D6). `σ_CO` covers `oid`, so the two orders are both genuine:
/// only the recorded digest tells them apart.
#[test]
fn an_order_presented_under_anothers_recorded_id_is_refused() {
    let mut w = world("digest-differs");
    let mut l = ledger(&w);
    let (recorded, _) = order(&w, Scope::Payload, Mode::Erased, &[1]);
    let (_, r) = order(&w, Scope::Payload, Mode::Erased, &[VICTIM]);
    let o = Order::issue(
        &w.court,
        recorded.oid,
        Target::new(&[eid(VICTIM)]).root(),
        Scope::Payload,
        Mode::Erased,
        NOW - 50,
        NOW + 1000,
    )
    .unwrap();
    assert_ne!(o.leaf().digest, recorded.leaf().digest);
    w.registry.insert(recorded.oid, recorded.leaf().digest);
    assert!(matches!(
        run(&mut w, &o, &r),
        Err(RedactionError::Order(OrderError::RecordedDigestDiffers))
    ));
    assert!(
        w.payloads.path(&eid(VICTIM)).is_file(),
        "refused, yet deleted"
    );

    // And at audit: the payload goes, the claimed order is anchored and signed
    // and has a DISPOSE, but the chain recorded something else under its id.
    std::fs::remove_file(w.payloads.path(&eid(VICTIM))).unwrap();
    l.claimed.push(ClaimedOrder {
        order: o.clone(),
        covers: vec![(eid(VICTIM), r[0].membership.clone())],
    });
    l.leaves.insert(o.leaf().digest, ORDER_EPOCH);
    l.disposals.push(dispose(eid(VICTIM), Some(o.oid)));
    let want = vec![Unaccounted::PayloadDeleted { eid: eid(VICTIM) }];
    assert_eq!(
        audit(&w, &l),
        want,
        "a mismatched recorded digest was accepted"
    );

    // The control: with the chain holding this order's leaf it is accounted.
    w.registry.insert(o.oid, o.leaf().digest);
    assert!(
        audit(&w, &l).is_empty(),
        "the lawful order is not accounted"
    );
}

/// ⭐ **Acceptance A7 (b): `e′ ≥ e`.** An order whose `0x05` leaf was anchored
/// in an epoch before the capsule's own cannot have been about it, whatever its
/// target root says: the capsule was not yet anchored when the order was.
#[test]
fn an_order_anchored_before_the_capsule_does_not_account_for_it() {
    const LATE: u64 = 8;
    assert_eq!(
        epoch_of(LATE),
        1,
        "the fixture's late capsule is in epoch 1"
    );
    let mut w = world("before");
    let mut l = ledger(&w);
    let (o, r) = order(&w, Scope::Payload, Mode::Erased, &[LATE]);
    w.registry.insert(o.oid, o.leaf().digest);
    run(&mut w, &o, &r).unwrap();
    l.claimed.push(ClaimedOrder {
        order: o.clone(),
        covers: vec![(eid(LATE), r[0].membership.clone())],
    });
    l.disposals.push(dispose(eid(LATE), Some(o.oid)));

    l.leaves.insert(o.leaf().digest, 0);
    assert_eq!(
        audit(&w, &l),
        vec![Unaccounted::PayloadDeleted { eid: eid(LATE) }],
        "an order anchored before its capsule was accepted"
    );
    l.leaves.insert(o.leaf().digest, 1);
    assert!(
        audit(&w, &l).is_empty(),
        "the same order at e' = e is not accounted"
    );
}

#[test]
fn a_redacted_payload_that_is_still_present_is_a_finding() {
    let mut w = world("present");
    let mut l = ledger(&w);
    let t = Target::new(&[eid(VICTIM)]);
    let o = Order::issue(
        &w.court,
        digest256(b"o"),
        t.root(),
        Scope::Payload,
        Mode::Erased,
        NOW,
        NOW + 9,
    )
    .unwrap();
    l.claimed.push(ClaimedOrder {
        order: o.clone(),
        covers: vec![(eid(VICTIM), t.prove(&eid(VICTIM)).unwrap())],
    });
    l.leaves.insert(o.leaf().digest, ORDER_EPOCH);
    w.registry.insert(o.oid, o.leaf().digest);
    l.disposals.push(dispose(eid(VICTIM), Some(o.oid)));
    assert_eq!(
        audit(&w, &l),
        vec![Unaccounted::RedactedPayloadPresent { eid: eid(VICTIM) }]
    );
}

// ------------------------------------ the audit across epochs (§1v.4, A20)

#[test]
fn a_chain_spanning_two_epochs_is_two_segments_audited_once_each() {
    use pqcl_capsule::DisclosureError;
    use pqcl_capsule::{Params, Role};
    use pqcl_pipeline::{Agent, Ais, CaseKeys, IngestParams, RecordParams};

    // ⭐ **Rewritten for M13 A20, and the old shape is the finding.** Until
    // A20 a capsule touched in two epochs was anchored twice over *prefixes of
    // one chain* under *one pseudonym*, and `Bundle::verify_across_memo`
    // checked that structure. So the two anchors shared `eid_e`, which handed
    // the AIS the cross-epoch link the pseudonym existed to deny it
    // (`audit/07` D1). Now each epoch is its own segment with its own
    // pseudonym and its own Tier-1 root, and the links between them are inside
    // `C_rec`.
    let defr = Agent::new(
        SoftwareMlDsa::generate().unwrap(),
        b"first-responder-1",
        Role::Defr,
    );
    let des = Agent::new(
        SoftwareMlDsa::generate().unwrap(),
        b"specialist-1",
        Role::Des,
    );
    let inv = Agent::new(
        SoftwareMlDsa::generate().unwrap(),
        b"investigator-1",
        Role::Investigator,
    );
    let cust = Agent::new(
        SoftwareMlDsa::generate().unwrap(),
        b"evidence-store-1",
        Role::Custodian,
    );
    let keys = CaseKeys::derive(&PrfKey::new([7u8; 32]), b"case", &[1u8; 32]);
    let nonce = [9u8; 32];
    let ip = IngestParams {
        artefact_type: b"disk-image",
        d_ev: [2u8; 32],
        ptr: b"s3://x",
        epoch: 0,
        nonce: &nonce,
    };
    let capsule = defr.seal(&keys, [3u8; 32], &ip).unwrap();
    let rp = |j: u64, ts: u64, e: u64| {
        RecordParams::at(j, ts)
            .with_params(Params::justified(b"test"))
            .in_epoch(e)
    };

    let mut ais = Ais::new();
    let first = defr
        .collect_record(&keys, &capsule, &rp(0, 1, 0))
        .unwrap()
        .record;
    ais.accept(capsule.clone(), first.clone());
    let second = inv
        .append_record(&keys, &capsule, Event::Access, &first, &rp(1, 2, 0))
        .unwrap()
        .record;
    ais.append(second.clone());
    let root_0 = ais.close_epoch();

    // Epoch 1. The pseudonym changes, so these two records are a new segment
    // and the server cannot tell they continue the previous one.
    let third = des
        .append_record(&keys, &capsule, Event::Analyze, &second, &rp(2, 3, 1))
        .unwrap()
        .record;
    ais.append(third.clone());
    let fourth = cust
        .dispose_record(&keys, &capsule, &third, Some(&[6u8; 32]), &rp(3, 9, 1))
        .unwrap()
        .record;
    ais.append(fourth.clone());
    let root_1 = ais.close_epoch();

    assert_ne!(first.eid_e, third.eid_e, "both epochs share one pseudonym");
    let bundle = ais.disclose(0, &keys).expect("bundle");
    assert_eq!(bundle.segments.len(), 2, "the capsule is not two segments");
    assert_eq!(bundle.record_count(), 4);

    let roots = vec![(0, root_0), (1, root_1)];
    assert_eq!(bundle.verify(&roots), Ok(()));
    let bodies = bundle.open().expect("open");
    assert_eq!(bodies.len(), 4);
    assert_eq!(bodies[3].body.event, Event::Dispose);

    // Each epoch's root is checked against its own segment, so swapping them
    // is caught.
    assert_eq!(
        bundle.verify(&[(0, root_1), (1, root_0)]),
        Err(DisclosureError::NotAnchored),
        "the epoch roots are interchangeable"
    );
    // An epoch with no root is a refusal, not a pass.
    assert_eq!(
        bundle.verify(&[(0, root_0)]),
        Err(DisclosureError::UnanchoredEpoch { epoch: 1 })
    );
    // And dropping the second segment is caught by the positions `rid`
    // commits to, keylessly undetectable though it is.
    let mut short = bundle.clone();
    short.segments.pop();
    assert_eq!(short.verify(&roots), Ok(()));
    assert_eq!(short.open().map(|b| b.len()), Ok(2));
    let mut tail = bundle.clone();
    tail.segments.remove(0);
    assert_eq!(tail.verify(&roots), Ok(()));
    assert_eq!(tail.open(), Err(DisclosureError::WrongPosition { j: 0 }));
}
