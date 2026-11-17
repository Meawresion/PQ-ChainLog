//! **M4's headline acceptance criterion, and M13 A20's.**
//!
//! The build plan (M4): *"the court-disclosure bundle for one
//! capsule verifies standalone and **contains no information about any other
//! capsule** (assert on the bundle's byte content, not on intent)."*
//!
//! The parenthesis is the whole instruction. It is easy to write a test that
//! checks the bundle "was built from one capsule" — that tests the builder, not
//! the artefact. What matters is that the bytes a court actually receives carry
//! nothing about the rest of the case, so these tests **search the serialized
//! bundle** for every other capsule's identifiers and digests.
//!
//! M13 A20 adds the per-epoch half: a capsule's history is a list of segments,
//! each anchored in its own epoch, and the links between them live inside
//! `C_rec`. So these tests also pin **where the boundary between the keyless
//! and the keyed check now runs** — see
//! `a_segment_set_moved_onto_another_capsule_is_caught_only_by_a_key_holder`,
//! which is a property of the design and not a gap in it.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
// Reporting-only ratio in one assertion message; never a measurement.
#![allow(clippy::cast_precision_loss)]

use pqcl_capsule::disclosure::SealProof;
use pqcl_capsule::record::{
    Capsule, CustodyRecord, Event, Provenance, RecordBody, RecordSignatures,
};
use pqcl_capsule::{Bundle, DisclosureError, DisclosureKeys, Segment};
use pqcl_forest::{CustodyTree, Leaf, Mmr};
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, hash_domain};

/// How many epochs every fixture capsule is touched in.
const EPOCHS: u64 = 3;
/// Records per segment.
const PER_EPOCH: usize = 2;

/// An epoch number as an index. A fixture constant, so it fits; spelled out
/// rather than cast, because `as` here is a lint and a lie at the same time.
fn ix(epoch: u64) -> usize {
    usize::try_from(epoch).expect("the fixture's epoch numbers are small")
}

/// One capsule with a segmented custody history.
#[derive(Clone)]
struct Sealed {
    capsule: Capsule,
    /// One entry per epoch: the pseudonym and that epoch's records.
    segments: Vec<(u64, Digest32, Vec<CustodyRecord>)>,
    keys: DisclosureKeys,
}

/// Every field derived from a distinct label, so no two values can collide by
/// accident.
///
/// An earlier fixture used `[n; 32]` fill patterns, and capsule 0's second
/// `rid` came out equal to capsule 1's `eid` — which made the leakage test
/// fail on a coincidence rather than a leak. A fixture whose values collide
/// cannot distinguish "the bundle leaks" from "two fields happened to match".
fn distinct(n: u8, what: &str) -> Digest32 {
    pqcl_primitives::xof::digest256(format!("fixture:{n}:{what}").as_bytes())
}

fn k_coc() -> PrfKey {
    PrfKey::new([0x7eu8; 32])
}

fn k_link() -> PrfKey {
    PrfKey::new([0x11u8; 32])
}

/// A capsule touched in `EPOCHS` epochs, `PER_EPOCH` records each, with real
/// pseudonyms, real sealed bodies and real links — including the cross-segment
/// links, which only exist inside the ciphertext.
fn seal(n: u8) -> Sealed {
    seal_with(n, |j| {
        if j == 0 {
            Event::Collect
        } else {
            Event::Access
        }
    })
}

/// [`seal`] with the event at each position chosen by `event_at`.
fn seal_with(n: u8, event_at: impl Fn(u64) -> Event) -> Sealed {
    let capsule = Capsule {
        eid: distinct(n, "eid"),
        cid_c: [0xcc; 32], // shared: every capsule is in the same case
        epoch: 0,
        artefact_type: format!("type-{n}").into_bytes(),
        d_ev: distinct(n, "d_ev"),
        cm_ev: distinct(n, "cm_ev"),
        ptr: format!("s3://case/obj-{n}").into_bytes(),
        provenance: Provenance::Attested,
        gap_seconds: 0,
        sig_defr: distinct(n, "sig_defr").to_vec(),
    };
    let k_eid = CustodyRecord::capsule_link_key(&k_link(), &capsule.eid);
    let k_rid = CustodyRecord::rid_key(&k_coc(), &capsule.eid);
    let k_rec = CustodyRecord::body_key(&k_coc(), &capsule.eid);

    let mut segments = Vec::new();
    // The capsule's own base case. It is never in clear again after A20.
    let mut link = CustodyRecord::genesis_link(&capsule.eid);
    let mut j: u64 = 0;

    for e in 0..EPOCHS {
        let eid_e = CustodyRecord::epoch_pseudonym(&k_eid, e);
        let mut records = Vec::new();
        for i in 0..PER_EPOCH {
            let rid = CustodyRecord::derive_rid(&k_rid, j);
            let body = RecordBody {
                event: event_at(j),
                ts: 1_700_000_000 + j,
                actor_c: distinct(n, "actor_c"),
                params_c: distinct(n, "params_c"),
                // The true link, always. At a segment start this is its only
                // copy anywhere.
                link,
                note: Vec::new(),
            };
            let r = CustodyRecord {
                rid,
                eid_e,
                // ⭐ A20: in clear, a segment's first record links to its own
                // pseudonym and not to its real predecessor.
                h_prev: if i == 0 {
                    CustodyRecord::segment_genesis_link(&eid_e)
                } else {
                    link
                },
                body: CustodyRecord::seal_body(
                    &k_rec,
                    &rid,
                    &body,
                    &RecordSignatures {
                        actor: distinct(n, &format!("sig-{j}")).to_vec(),
                        witness: None,
                    },
                )
                .expect("seal"),
                order_ref: None,
            };
            link = r.chain_link();
            records.push(r);
            j += 1;
        }
        segments.push((e, eid_e, records));
    }

    let keys = DisclosureKeys {
        k_eid: *k_eid.as_bytes(),
        k_rec: CustodyRecord::body_key_bytes(&k_coc(), &capsule.eid),
        k_rid: *k_rid.as_bytes(),
    };
    Sealed {
        capsule,
        segments,
        keys,
    }
}

fn tier1_root(records: &[CustodyRecord]) -> Digest32 {
    let mut t = CustodyTree::new();
    for r in records {
        t.append(&r.encode());
    }
    t.root().expect("non-empty")
}

fn custody_leaf(eid_e: &Digest32, records: &[CustodyRecord]) -> Leaf {
    Leaf::new(
        Domain::CustodyRoot,
        &[
            eid_e,
            &tier1_root(records),
            &(records.len() as u64).to_le_bytes(),
        ],
    )
}

/// A case with `n` capsules, anchored into **one MMR per epoch**. Capsule `i`'s
/// segment for epoch `e` is leaf `i` of epoch `e`'s MMR.
fn case(n: u8) -> (Vec<Sealed>, Vec<Mmr>) {
    case_of((0..n).map(|i| seal(i + 1)).collect())
}

/// [`case`] over capsules already sealed.
fn case_of(sealed: Vec<Sealed>) -> (Vec<Sealed>, Vec<Mmr>) {
    let mut mmrs = Vec::new();
    for e in 0..EPOCHS {
        let mut mmr = Mmr::new();
        // Epoch 0 holds each capsule's `0x01` seal leaf first — capsules are
        // sealed before their chains open, which is how `Ais::accept` does it.
        if e == 0 {
            for s in &sealed {
                mmr.append(&s.capsule.seal_leaf());
            }
        }
        for s in &sealed {
            let (_, eid_e, records) = &s.segments[ix(e)];
            mmr.append(&custody_leaf(eid_e, records));
        }
        mmrs.push(mmr);
    }
    (sealed, mmrs)
}

/// Where capsule `i`'s `0x02` leaf sits in epoch `e`'s MMR: after the seal
/// leaves in epoch 0, first in every later epoch.
fn segment_at(e: u64, i: usize, capsules: usize) -> u64 {
    let base = if e == 0 { capsules } else { 0 };
    (base + i) as u64
}

fn roots(mmrs: &[Mmr]) -> Vec<(u64, Digest32)> {
    mmrs.iter()
        .enumerate()
        .map(|(e, m)| (e as u64, m.root().expect("non-empty")))
        .collect()
}

fn bundle_for(sealed: &[Sealed], mmrs: &[Mmr], i: usize) -> Bundle {
    let s = &sealed[i];
    let segments = s
        .segments
        .iter()
        .map(|(e, eid_e, records)| {
            Segment::new(
                *eid_e,
                *e,
                records.clone(),
                mmrs[ix(*e)]
                    .prove(segment_at(*e, i, sealed.len()))
                    .expect("in range"),
            )
        })
        .collect();
    let seal = SealProof {
        epoch: 0,
        proof: mmrs[0]
            .prove(i as u64)
            .expect("the seal leaf is in epoch 0"),
    };
    Bundle::new(s.capsule.clone(), segments, seal, s.keys.clone())
}

// ------------------------------------------------------------ verification

#[test]
fn a_bundle_verifies_against_the_anchored_epoch_roots() {
    let (sealed, mmrs) = case(6);
    let r = roots(&mmrs);
    for i in 0..sealed.len() {
        let b = bundle_for(&sealed, &mmrs, i);
        b.verify(&r)
            .unwrap_or_else(|e| panic!("bundle {i} failed to verify: {e}"));
        let bodies = b
            .open()
            .unwrap_or_else(|e| panic!("bundle {i} failed to open: {e}"));
        assert_eq!(bodies.len(), ix(EPOCHS) * PER_EPOCH);
        assert_eq!(bodies[0].body.event, Event::Collect);
    }
}

/// ⭐ **Acceptance A15 (c), the court's side: nothing follows a `DISPOSE`.**
/// A record appended after the terminal disposition is refused when the
/// bundle is opened, and the same chain with the `DISPOSE` last opens.
#[test]
fn a_record_after_the_dispose_is_refused() {
    let after = |j| match j {
        0 => Event::Collect,
        2 => Event::Dispose,
        _ => Event::Access,
    };
    let (sealed, mmrs) = case_of(vec![seal_with(1, after)]);
    let b = bundle_for(&sealed, &mmrs, 0);
    b.verify(&roots(&mmrs)).expect("hash-level checks pass");
    assert_eq!(b.open(), Err(DisclosureError::AfterTerminal { j: 3 }));

    let last = ix(EPOCHS) * PER_EPOCH - 1;
    let closed = move |j| match j {
        0 => Event::Collect,
        j if j == last as u64 => Event::Dispose,
        _ => Event::Access,
    };
    let (sealed, mmrs) = case_of(vec![seal_with(1, closed)]);
    bundle_for(&sealed, &mmrs, 0)
        .open()
        .expect("a chain that ends in its DISPOSE opens");
}

#[test]
fn a_bundle_verifies_from_its_serialized_bytes_alone() {
    // What a court actually receives is a file. It must verify from that plus
    // the public anchors, with no access to the lab that produced it.
    let (sealed, mmrs) = case(5);
    let bytes = bundle_for(&sealed, &mmrs, 2).encode();

    let parsed = Bundle::decode(&bytes).expect("decode");
    parsed
        .verify(&roots(&mmrs))
        .expect("verify from bytes alone");
    parsed.open().expect("open from bytes alone");
    assert_eq!(parsed.encode(), bytes, "round-trip is not byte-stable");
}

#[test]
fn a_bundle_does_not_verify_against_another_epochs_roots() {
    let (sealed, mmrs) = case(4);
    let b = bundle_for(&sealed, &mmrs, 1);
    // Same shape, different MMR contents, under the same epoch numbers.
    let mut different = Vec::new();
    for e in 0..EPOCHS {
        let mut m = Mmr::new();
        let other = seal(99);
        let (_, eid_e, records) = &other.segments[ix(e)];
        m.append(&custody_leaf(eid_e, records));
        different.push((e, m.root().expect("non-empty")));
    }
    assert_eq!(b.verify(&different), Err(DisclosureError::NotAnchored));
}

#[test]
fn an_epoch_with_no_anchored_root_is_a_refusal_not_a_pass() {
    // A court that cannot check a segment must reject the bundle. Silently
    // skipping the segment would make a bundle verifiable by claiming an epoch
    // nobody anchored.
    let (sealed, mmrs) = case(3);
    let mut r = roots(&mmrs);
    r.pop();
    assert_eq!(
        bundle_for(&sealed, &mmrs, 0).verify(&r),
        Err(DisclosureError::UnanchoredEpoch { epoch: EPOCHS - 1 })
    );
}

// -------------------------------------------------------- tamper detection

#[test]
fn a_removed_custody_event_is_detected() {
    // The attack a custody log exists to stop: quietly dropping an ACCESS.
    let (sealed, mmrs) = case(4);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.segments[0].records.remove(1);
    b.segments[0].count = b.segments[0].records.len() as u64;
    assert!(matches!(
        b.verify(&roots(&mmrs)),
        Err(DisclosureError::BrokenChain { .. } | DisclosureError::NotAnchored)
    ));
}

#[test]
fn an_added_custody_event_is_detected() {
    let (sealed, mmrs) = case(4);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    let mut extra = b.segments[0].records[0].clone();
    // Perturb the ciphertext: `ts` is inside `C_rec` from M13 A1 on, and the
    // leaf covers the ciphertext, so this is the same attack on the same
    // commitment.
    extra.body[0] ^= 0xff;
    b.segments[0].records.push(extra);
    b.segments[0].count = b.segments[0].records.len() as u64;
    assert!(b.verify(&roots(&mmrs)).is_err());
}

#[test]
fn a_modified_custody_event_is_detected() {
    let (sealed, mmrs) = case(4);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    // Rewrite who did it. `actor_c` now sits inside `C_rec`, so the edit is a
    // ciphertext edit — which is what the Tier-1 leaf and `σ_actor` cover.
    b.segments[0].records[1].body[0] ^= 1;
    assert!(b.verify(&roots(&mmrs)).is_err());
}

#[test]
fn a_reordered_chain_is_detected() {
    // Custody is a sequence. Swapping two events changes what happened.
    let (sealed, mmrs) = case(4);
    let mut b = bundle_for(&sealed, &mmrs, 2);
    b.segments[1].records.swap(0, 1);
    assert!(matches!(
        b.verify(&roots(&mmrs)),
        Err(DisclosureError::BrokenChain { .. })
    ));
}

#[test]
fn a_chain_linked_under_the_pre_m12_form_is_rejected() {
    // Links written as H(0x24 ‖ ⟪CR⟫), the form before M12, must not verify
    // under eq:hprev's H(0x24 ‖ ⟪L⟫): the audit's leaf reuse must not have
    // turned the link check into something that accepts either.
    let (sealed, _) = case(3);
    let mut s = sealed[1].clone();
    let (_, eid_e, records) = &mut s.segments[0];
    let mut prev = CustodyRecord::segment_genesis_link(eid_e);
    for r in records.iter_mut() {
        r.h_prev = prev;
        prev = hash_domain(Domain::ChainLink, &[&r.encode()]);
    }
    let (e, eid_e, records) = s.segments[0].clone();
    let mut mmr = Mmr::new();
    mmr.append(&s.capsule.seal_leaf());
    mmr.append(&custody_leaf(&eid_e, &records));
    let b = Bundle::new(
        s.capsule.clone(),
        vec![Segment::new(
            eid_e,
            e,
            records,
            mmr.prove(1).expect("proof"),
        )],
        SealProof {
            epoch: e,
            proof: mmr.prove(0).expect("proof"),
        },
        s.keys.clone(),
    );
    assert_eq!(
        b.verify(&[(e, mmr.root().expect("root"))]),
        Err(DisclosureError::BrokenChain { index: 1 })
    );
}

#[test]
fn a_link_broken_at_write_time_still_fails() {
    // §1m.1's negative case, kept through M12 and A20: a record whose h_prev
    // was wrong when it was written, anchored as written, is still rejected.
    // The anchor proves the bytes were committed, not that they were well
    // linked.
    let (sealed, _) = case(3);
    let mut s = sealed[0].clone();
    s.segments[0].2[1].h_prev = [0xee; 32];
    let (e, eid_e, records) = s.segments[0].clone();
    let mut mmr = Mmr::new();
    mmr.append(&s.capsule.seal_leaf());
    mmr.append(&custody_leaf(&eid_e, &records));
    let b = Bundle::new(
        s.capsule.clone(),
        vec![Segment::new(
            eid_e,
            e,
            records,
            mmr.prove(1).expect("proof"),
        )],
        SealProof {
            epoch: e,
            proof: mmr.prove(0).expect("proof"),
        },
        s.keys.clone(),
    );
    assert_eq!(
        b.verify(&[(e, mmr.root().expect("root"))]),
        Err(DisclosureError::BrokenChain { index: 1 })
    );
}

#[test]
fn a_record_spliced_in_from_another_capsule_is_detected() {
    let (sealed, mmrs) = case(4);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.segments[0].records[1] = sealed[1].segments[0].2[1].clone();
    assert!(matches!(
        b.verify(&roots(&mmrs)),
        Err(DisclosureError::ForeignRecord { index: 1 } | DisclosureError::BrokenChain { .. })
    ));
}

#[test]
fn an_empty_chain_is_rejected() {
    let (sealed, mmrs) = case(4);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.segments[0].records.clear();
    b.segments[0].count = 0;
    assert_eq!(b.verify(&roots(&mmrs)), Err(DisclosureError::EmptyChain));
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.segments.clear();
    assert_eq!(b.verify(&roots(&mmrs)), Err(DisclosureError::EmptyChain));
}

// --------------------------------------------- ⭐ A20: the segment boundary

#[test]
fn a_segments_first_cleartext_link_says_nothing_about_the_previous_segment() {
    // ⭐ **This is row A20.** Before it, the first record of each epoch carried
    // the real `h_prev` in clear, so the AIS joined a capsule's segments by
    // hashing the previous segment's last record. Now the cleartext link is a
    // function of the segment's own pseudonym — a value the AIS already holds —
    // and the real link exists only inside `C_rec`.
    let (sealed, _) = case(2);
    let s = &sealed[0];
    for w in s.segments.windows(2) {
        let (_, _, previous) = &w[0];
        let (_, eid_e, next) = &w[1];
        let real = previous.last().expect("non-empty").chain_link();
        assert_eq!(
            next[0].h_prev,
            CustodyRecord::segment_genesis_link(eid_e),
            "a segment's first cleartext link is not its own genesis"
        );
        assert_ne!(
            next[0].h_prev, real,
            "the real cross-segment link is still in clear"
        );
        // And it is not reachable by hashing the predecessor under any of the
        // record tags either.
        for tag in [
            Domain::ChainLink,
            Domain::CustodyRecord,
            Domain::CustodyRoot,
            Domain::DeviceChainLink,
        ] {
            assert_ne!(
                next[0].h_prev,
                hash_domain(tag, &[&previous.last().expect("non-empty").encode()]),
                "the cross-segment link is recomputable under {tag:?}"
            );
        }
    }
}

#[test]
fn dropping_a_middle_segment_is_refused() {
    // Acceptance A20 (b). Two independent mechanisms catch it, and the test
    // asserts the first one that fires: the cross-segment link, and — even if
    // that had been forged — the positions `rid` commits to.
    let (sealed, mmrs) = case(3);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.segments.remove(1);
    // Keyless verification cannot see it: each remaining segment is internally
    // sound and anchored. That is the point of the segment split.
    b.verify(&roots(&mmrs))
        .expect("each surviving segment is still anchored");
    // The key holder can.
    assert_eq!(b.open(), Err(DisclosureError::WrongPosition { j: 2 }));
}

#[test]
fn reordering_segments_is_refused() {
    let (sealed, mmrs) = case(3);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.segments.swap(0, 2);
    assert_eq!(b.verify(&roots(&mmrs)), Err(DisclosureError::SegmentOrder));
}

#[test]
fn relabelling_a_segment_into_another_epoch_is_refused() {
    // The pseudonym and the epoch have to agree, or a segment could be moved
    // to an epoch whose anchor happens to be convenient.
    let (sealed, mmrs) = case(3);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.segments[1].epoch = 7;
    assert_eq!(b.open(), Err(DisclosureError::WrongPseudonym { epoch: 7 }));
}

#[test]
fn a_cross_segment_link_rewritten_in_the_ciphertext_is_refused() {
    // The link is under the AEAD with `rid` as associated data, so there is no
    // way to rewrite it that still opens.
    let (sealed, mmrs) = case(2);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    // Flip a byte of the second segment's first record's ciphertext body.
    let n = b.segments[1].records[0].body.len();
    b.segments[1].records[0].body[n - 1] ^= 1;
    assert_eq!(b.open(), Err(DisclosureError::Sealed { j: 2 }));
}

#[test]
fn a_segment_set_moved_onto_another_capsule_is_caught_twice() {
    // ⭐ **The history of this test is the point.** Before A20 the capsule
    // binding was keyless: the first record's cleartext `h_prev` was
    // `H(0x24 ‖ ⟪eid⟫)`, which anyone could recompute — and which is exactly
    // the value that let the AIS tie a capsule to its first segment. A20 moved
    // it into `C_rec`, which closed that leak and left the binding **keyed**:
    // this test then asserted that only a key holder could see a capsule swap.
    //
    // A3 gives the binding back to the keyless verifier by a different route:
    // the bundle carries the capsule's own `0x01` seal leaf, recomputed from
    // the disclosed capsule, so a swapped capsule produces a leaf that is not
    // the anchored one. ⚠️ This supersedes the design record (a),
    // which told the reviewers the binding was court-side only.
    //
    // Both checks now fire, on different evidence: the seal proof keylessly,
    // and the body's link for a key holder.
    let (sealed, mmrs) = case(4);
    let mut b = bundle_for(&sealed, &mmrs, 0);
    b.capsule = sealed[3].capsule.clone();

    assert_eq!(
        b.verify(&roots(&mmrs)),
        Err(DisclosureError::CapsuleNotAnchored),
        "the seal leaf no longer binds the capsule keylessly"
    );
    assert_eq!(
        b.open(),
        Err(DisclosureError::BrokenSegmentLink { segment: 0 })
    );
}

#[test]
fn a_capsule_with_its_commitments_swapped_is_rejected() {
    // ⭐ **A3's headline acceptance**: the audit probe that swapped `d_ev` and
    // `cm_ev` and was not rejected, moved into the suite. The seal leaf covers
    // both, so exchanging them changes the leaf and the anchored proof fails —
    // keylessly, which matters because this is a check an auditor makes without
    // ever holding a case key.
    let (sealed, mmrs) = case(3);
    let mut b = bundle_for(&sealed, &mmrs, 1);
    std::mem::swap(&mut b.capsule.d_ev, &mut b.capsule.cm_ev);
    assert_eq!(
        b.verify(&roots(&mmrs)),
        Err(DisclosureError::CapsuleNotAnchored)
    );

    // Every other field the leaf commits, one at a time, so the test cannot
    // pass because one of them happens to be covered.
    for (what, edit) in [
        (
            "artefact_type",
            (|c: &mut Capsule| c.artefact_type = b"memory-dump".to_vec()) as fn(&mut Capsule),
        ),
        ("gap_seconds", |c: &mut Capsule| c.gap_seconds += 1),
        ("provenance", |c: &mut Capsule| {
            c.provenance = Provenance::Declared;
        }),
        ("sig_defr", |c: &mut Capsule| c.sig_defr[0] ^= 1),
        ("epoch", |c: &mut Capsule| c.epoch += 1),
        ("eid", |c: &mut Capsule| c.eid[0] ^= 1),
        ("cid_c", |c: &mut Capsule| c.cid_c[0] ^= 1),
    ] {
        let mut b = bundle_for(&sealed, &mmrs, 1);
        edit(&mut b.capsule);
        assert_eq!(
            b.verify(&roots(&mmrs)),
            Err(DisclosureError::CapsuleNotAnchored),
            "an edited {what} was accepted"
        );
    }
}

#[test]
fn the_storage_pointer_is_bound_through_the_signature_not_the_leaf() {
    // ⚠️ **`ptr` is the one capsule field the `0x01` leaf does not commit**, and
    // that is deliberate: a stored object can be migrated between buckets
    // without the evidence changing, and a leaf that committed its locator
    // would make every migration invalidate an anchor.
    //
    // It is still bound, one step further out: `σ_DEFR` covers the whole
    // encoded capsule including `ptr`, and the leaf covers `σ_DEFR`. So an
    // edited pointer fails the **signature** check, and re-signing to repair
    // that changes the leaf. This test pins which check catches it, because
    // "some check catches it" is how a gap hides.
    let (sealed, mmrs) = case(3);
    let mut b = bundle_for(&sealed, &mmrs, 1);
    let before = b.capsule.seal_leaf().digest;
    b.capsule.ptr = b"file:///elsewhere".to_vec();
    assert_eq!(
        b.capsule.seal_leaf().digest,
        before,
        "the leaf now commits ptr; if that is intended, this test and the          migration argument in it are both out of date"
    );
    b.verify(&roots(&mmrs))
        .expect("the seal proof does not see ptr");
    // What does see it:
    assert_ne!(
        b.capsule.encode(),
        sealed[1].capsule.encode(),
        "σ_DEFR covers the encoded capsule, so an edited ptr changes its          message"
    );
}

#[test]
fn a_bundle_whose_sealing_epoch_is_unanchored_is_refused() {
    // The capsule's epoch need not be any segment's, so its root must be
    // supplied separately — and a court that cannot check the seal refuses the
    // bundle rather than ignoring it.
    let (sealed, mmrs) = case(3);
    let b = bundle_for(&sealed, &mmrs, 0);
    let later: Vec<_> = roots(&mmrs).into_iter().filter(|(e, _)| *e != 0).collect();
    assert_eq!(
        b.verify(&later),
        Err(DisclosureError::UnanchoredEpoch { epoch: 0 })
    );
}

#[test]
fn the_disclosed_link_key_derives_no_other_capsules_pseudonyms() {
    // Acceptance A20 (c). `k_eid = F(K_link, eid)`, so the key a court receives
    // enumerates one capsule's epochs and nothing else.
    let (sealed, mmrs) = case(6);
    let b = bundle_for(&sealed, &mmrs, 0);

    // It reproduces its own capsule's pseudonyms, which is how a court goes
    // looking for a segment the lab left out...
    for (e, eid_e, _) in &sealed[0].segments {
        assert_eq!(
            b.expected_pseudonym(*e),
            *eid_e,
            "the disclosed key does not reproduce the capsule's own pseudonym for epoch {e}"
        );
    }
    // ...and it reproduces nothing else, in any epoch, including epochs past
    // the ones disclosed.
    for e in 0..EPOCHS + 4 {
        let mine = b.expected_pseudonym(e);
        for (i, other) in sealed.iter().enumerate().skip(1) {
            for (oe, eid_e, _) in &other.segments {
                assert_ne!(
                    mine, *eid_e,
                    "the disclosed k_eid derives capsule {i}'s pseudonym for epoch {oe}"
                );
            }
        }
    }
}

// ------------------------------------------- ⭐ the selective-disclosure test

#[test]
fn the_bundle_bytes_contain_nothing_about_any_other_capsule() {
    // ⭐ M4's stated acceptance criterion, asserted on byte content.
    //
    // A bundle for capsule 0 must not contain any other capsule's identifiers,
    // digests, pointers, signatures, custody records, epoch pseudonyms **or
    // keys**. The Tier-2 proof necessarily carries sibling digests — but a
    // sibling is a *hash of* another capsule's custody root, which reveals
    // nothing about its contents, and specifically is not that root itself.
    let (sealed, mmrs) = case(8);
    let bytes = bundle_for(&sealed, &mmrs, 0).encode();

    for (i, other) in sealed.iter().enumerate().skip(1) {
        let mut forbidden: Vec<(String, Vec<u8>)> = vec![
            ("eid".into(), other.capsule.eid.to_vec()),
            ("d_ev".into(), other.capsule.d_ev.to_vec()),
            ("cm_ev".into(), other.capsule.cm_ev.to_vec()),
            ("ptr".into(), other.capsule.ptr.clone()),
            ("artefact_type".into(), other.capsule.artefact_type.clone()),
            ("sig_defr".into(), other.capsule.sig_defr.clone()),
            ("capsule encoding".into(), other.capsule.encode()),
            ("k_eid".into(), other.keys.k_eid.to_vec()),
            ("k_rec".into(), other.keys.k_rec.to_vec()),
            ("k_rid".into(), other.keys.k_rid.to_vec()),
        ];
        for (e, eid_e, records) in &other.segments {
            forbidden.push((format!("eid_e for epoch {e}"), eid_e.to_vec()));
            forbidden.push((
                format!("tier-1 root for epoch {e}"),
                tier1_root(records).to_vec(),
            ));
            for (j, r) in records.iter().enumerate() {
                forbidden.push((format!("record {e}/{j}"), r.encode()));
                forbidden.push((format!("record {e}/{j} rid"), r.rid.to_vec()));
            }
        }

        for (what, needle) in forbidden {
            assert!(
                !contains(&bytes, &needle),
                "the disclosure bundle for capsule 0 leaks capsule {i}'s {what}"
            );
        }
    }
}

#[test]
fn the_bundle_does_not_reveal_how_many_other_capsules_exist() {
    // A weaker but real leak: if the proof size grew with case size in a way
    // that pinned the count, the bundle would disclose activity volume even
    // without disclosing contents. It is logarithmic, so a case of 8 and a case
    // of 15 produce the same proof shape.
    let (a, ma) = case(8);
    let (b, mb) = case(15);
    let pa = bundle_for(&a, &ma, 0).segments[0].anchor_proof.clone();
    let pb = bundle_for(&b, &mb, 0).segments[0].anchor_proof.clone();
    assert_eq!(
        pa.path.len(),
        pb.path.len(),
        "proof path length differs between an 8-capsule and a 15-capsule case"
    );
}

#[test]
fn bundle_size_is_dominated_by_the_disclosed_chain_not_the_case() {
    // The practical form of selective disclosure: what a court receives scales
    // with the one capsule's history, not with the size of the investigation.
    let (small, ms) = case(4);
    let (large, ml) = case(64);
    let bs = bundle_for(&small, &ms, 0).encode().len();
    let bl = bundle_for(&large, &ml, 0).encode().len();
    let growth = bl as f64 / bs as f64;
    assert!(
        growth < 1.5,
        "bundle grew {growth:.2}x when the case grew 16x: disclosure is not \
         selective"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
