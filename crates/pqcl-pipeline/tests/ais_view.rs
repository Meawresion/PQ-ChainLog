//! ⭐ **M13 A20's headline acceptance: the AIS-view test.**
//!
//! The build plan row A20 (a): *"from everything the AIS stores,
//! compute every keyless link it can (leaf hashes, `h_prev`, `rid`, genesis
//! links); assert no link joins two segments of one capsule."*
//!
//! This is `audit/07` finding D1 made executable. The claim is per-epoch
//! unlinkability: an honest-but-curious server holding the whole custody store
//! cannot tell that two segments belong to one capsule, or that a segment
//! belongs to a particular capsule.
//!
//! # How it is tested, and why not by inspection
//!
//! The server's advantage, if it has one, is a value it can compute two ways.
//! So the test builds, for each stored object, the set of 32-byte values that
//! object yields: its own digests, every record's `rid`, `h_prev`, Tier-1 leaf
//! and chain link, the segment's Tier-1 root and `0x02` leaf — and then the
//! closure of all of those under **every registered domain tag**, one
//! application deep. A collision anywhere in that closure is a link.
//!
//! The tag closure is the part that matters. The leak A20 fixes was exactly of
//! that shape: `h_prev` of a segment's first record was `H(0x24 ‖ ⟪eid⟫)`, one
//! tag application away from a value the server holds in clear. Enumerating
//! the tags finds that class rather than the one instance of it.
//!
//! # ⭐ The checker is shown failing
//!
//! A checker that reports "no link" is worth nothing until it has been watched
//! report one. So each test runs its checker twice:
//! once over the real store, where it must find nothing, and once over a
//! **pre-A20 reconstruction** of the same store — the cleartext links put back
//! the way they were before this row — where it must find the link on every
//! segment boundary. The guard against a false pass is a demonstrated true
//! positive, not a claim about the fixture.
//!
//! # ⭐ Not only digests: every cleartext byte field
//!
//! The closure above compares 32-byte values, and the first version of this
//! file stopped there. Design review found the link it could not
//! see: `C_rec` began with its 12-byte AEAD nonce, which was the record's
//! position `j` **counted across the whole chain**. A segment starting at
//! `j = n` continued the one that ended at `j = n − 1`, by arithmetic rather
//! than by hashing, and it also told the server each capsule's history length
//! at every segment. So a second checker reads every cleartext byte field of a
//! stored record as integers and as byte prefixes, and is watched finding that
//! join on every boundary of a reconstruction of the pre-fix layout.
//!
//! # What this test deliberately does **not** claim (A20 clause 6)
//!
//! Linkage the design concedes, and which this fixture therefore avoids
//! asserting about:
//!
//! * **A redaction order names its target.** `tgt` is on chain and the
//!   `DISPOSE` it causes is in a segment, so an order ties that capsule to that
//!   segment. That is inherent to publishing the order.
//! * **Timing and volume.** Segments in one epoch are in one MMR, and a server
//!   sees when records arrive and how many. Correlating a 3-record segment that
//!   stops in epoch 4 with a 3-record segment that starts in epoch 5 is outside
//!   the claim.
//! * **The capsule store.** `eid` is in clear in the capsule, because the AIS
//!   serves the sealed object. What must not exist is a path from `eid` to any
//!   segment, and that is what is asserted below.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{HashMap, HashSet};

use pqcl_capsule::{Capsule, CustodyRecord, Event, Params, Role};
use pqcl_forest::{CustodyTree, Leaf};
use pqcl_pipeline::{Agent, Ais, CaseKeys, IngestParams, RecordParams};
use pqcl_primitives::SoftwareMlDsa;
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, digest256, hash_domain};

const CAPSULES: usize = 3;
const EPOCHS: u64 = 4;

/// An epoch number as a count. A fixture constant, so it fits; spelled out
/// rather than cast, because `as` here is a lint and a lie at the same time.
fn ix(epoch: u64) -> usize {
    usize::try_from(epoch).expect("the fixture's epoch numbers are small")
}

/// One segment as the test sees it: the server's view, plus the owner the lab
/// knows and the server does not.
#[derive(Clone)]
struct Seg {
    who: usize,
    epoch: u64,
    eid_e: Digest32,
    records: Vec<CustodyRecord>,
}

/// A case where every capsule is touched in every epoch — the shape the claim
/// is about.
fn case() -> (Ais, CaseKeys, Vec<Capsule>) {
    // One agent per role (M13 A2): a DEFR opens the chain, an investigator
    // reads it. One agent doing both would now be refused, which is the point.
    let defr = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"first-responder-1",
        Role::Defr,
    );
    let inv = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"investigator-1",
        Role::Investigator,
    );
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst")),
        b"case-7",
        &digest256(b"r"),
    );
    let mut ais = Ais::new();

    let mut capsules = Vec::new();
    let mut tails: Vec<(Capsule, CustodyRecord, u64)> = Vec::new();

    for c in 0..CAPSULES {
        let nonce = digest256(&(c as u64).to_le_bytes());
        let capsule = defr
            .seal(
                &keys,
                digest256(b"cm"),
                &IngestParams {
                    artefact_type: b"disk-image",
                    d_ev: digest256(&nonce),
                    ptr: format!("s3://case-7/obj-{c}").as_bytes(),
                    epoch: 0,
                    nonce: &nonce,
                },
            )
            .expect("seal");
        let first = defr
            .collect_record(
                &keys,
                &capsule,
                &RecordParams::at(0, 1_000).with_params(Params::justified(b"on-scene")),
            )
            .expect("collect")
            .record;
        capsules.push(capsule.clone());
        ais.accept(capsule.clone(), first.clone());
        tails.push((capsule, first, 1));
    }

    // Two records per capsule per epoch, so no capsule is distinguishable by
    // its record count. Epoch 0 already holds the opening `COLLECT`.
    for e in 0..EPOCHS {
        if e > 0 {
            open_count_holds(&ais, tails.len());
            ais.close_epoch();
        }
        for (capsule, previous, j) in &mut tails {
            for k in 0..2u64 {
                if e == 0 && k == 1 {
                    continue;
                }
                let r = inv
                    .append_record(
                        &keys,
                        &*capsule,
                        Event::Access,
                        previous,
                        &RecordParams::at(*j, 2_000 + *j)
                            .with_params(Params::justified(b"review"))
                            .in_epoch(e),
                    )
                    .expect("append")
                    .record;
                ais.append(r.clone());
                *previous = r;
                *j += 1;
            }
        }
    }
    open_count_holds(&ais, tails.len());
    ais.close_epoch();
    (ais, keys, capsules)
}

/// `open_segments` is a kept count since campaign 08 (§1by), not a scan: check
/// it against the scan it replaced, and against the capsules touched — every
/// capsule appends in every epoch here, so each owns one open segment.
fn open_count_holds(ais: &Ais, touched: usize) {
    let scanned = ais
        .stored_segments()
        .filter(|(_, epoch, _)| *epoch == ais.epoch())
        .count();
    assert_eq!(
        ais.open_segments(),
        scanned,
        "kept count drifted from the store"
    );
    assert_eq!(
        ais.open_segments(),
        touched,
        "one open segment per touched capsule"
    );
}

/// The server's custody store, with each segment's owner filled in from the
/// lab's keys. The owner exists only so the test knows which collisions would
/// be findings; nothing in [`segment_values`] uses it.
fn store(ais: &Ais, keys: &CaseKeys, capsules: &[Capsule]) -> Vec<Seg> {
    let mut owner: HashMap<Digest32, usize> = HashMap::new();
    for (i, c) in capsules.iter().enumerate() {
        let k_eid = keys.capsule_link_key(&c.eid);
        for e in 0..EPOCHS {
            owner.insert(CustodyRecord::epoch_pseudonym(&k_eid, e), i);
        }
    }
    let mut segs: Vec<Seg> = ais
        .stored_segments()
        .map(|(eid_e, epoch, records)| Seg {
            who: *owner
                .get(eid_e)
                .expect("the lab can place every segment it created"),
            epoch,
            eid_e: *eid_e,
            records: records.to_vec(),
        })
        .collect();
    segs.sort_by_key(|s| (s.who, s.epoch));
    segs
}

/// The same store as it would have looked **before A20**: the cleartext
/// `h_prev` of each segment's first record put back to the real link — the
/// capsule genesis for the first segment, the previous segment's last chain
/// link for every later one.
///
/// Nothing else changes. That one field is the whole of finding D1.
fn pre_a20(segs: &[Seg]) -> Vec<Seg> {
    let mut out = segs.to_vec();
    for i in 0..out.len() {
        let previous_tail = out
            .iter()
            .filter(|s| s.who == out[i].who && s.epoch < out[i].epoch)
            .max_by_key(|s| s.epoch)
            .and_then(|s| s.records.last())
            .map(CustodyRecord::chain_link);
        if let (Some(link), Some(first)) = (previous_tail, out[i].records.first_mut()) {
            first.h_prev = link;
        }
    }
    out
}

/// Every 32-byte value the server can compute from one stored object, closed
/// one tag application deep.
fn closure(raw: &[Digest32]) -> Vec<Digest32> {
    let mut out = raw.to_vec();
    for v in raw {
        for tag in Domain::ALL {
            out.push(hash_domain(tag, &[v]));
            // And framed with a count, the other shape the forest uses.
            out.push(hash_domain(tag, &[v, &1u64.to_le_bytes()]));
        }
    }
    out
}

fn segment_values(s: &Seg) -> Vec<Digest32> {
    let mut raw = vec![s.eid_e];
    let mut tree = CustodyTree::new();
    for r in &s.records {
        raw.push(r.rid);
        raw.push(r.h_prev);
        raw.push(r.tier1_leaf());
        raw.push(r.chain_link());
        raw.push(digest256(&r.encode()));
        raw.push(digest256(&r.body));
        if let Some(o) = r.order_ref {
            raw.push(o);
        }
        tree.append(&r.encode());
    }
    let root = tree.root().expect("non-empty");
    raw.push(root);
    raw.push(
        Leaf::new(
            Domain::CustodyRoot,
            &[&s.eid_e, &root, &(s.records.len() as u64).to_le_bytes()],
        )
        .digest,
    );
    closure(&raw)
}

fn capsule_values(c: &Capsule) -> Vec<Digest32> {
    let raw = vec![
        c.eid,
        c.d_ev,
        c.cm_ev,
        digest256(&c.encode()),
        digest256(&c.sig_defr),
        c.seal_leaf().digest,
        CustodyRecord::genesis_link(&c.eid),
    ];
    closure(&raw)
}

/// Pairs of segments **of one capsule** that share a keyless value: the links
/// the claim says do not exist.
fn joined_segments(segs: &[Seg]) -> Vec<(usize, u64, u64)> {
    let mut found = Vec::new();
    for (i, a) in segs.iter().enumerate() {
        let set: HashSet<Digest32> = segment_values(a).into_iter().collect();
        for b in segs.iter().skip(i + 1) {
            if a.who != b.who {
                continue;
            }
            if segment_values(b).iter().any(|v| set.contains(v)) {
                found.push((a.who, a.epoch, b.epoch));
            }
        }
    }
    found
}

/// Segments that share a keyless value with a stored capsule: the placements
/// the claim says the server cannot make.
fn placed_segments(capsules: &[Capsule], segs: &[Seg]) -> Vec<(usize, u64)> {
    let mut found = Vec::new();
    for (i, c) in capsules.iter().enumerate() {
        let set: HashSet<Digest32> = capsule_values(c).into_iter().collect();
        for s in segs {
            if segment_values(s).iter().any(|v| set.contains(v)) {
                found.push((i, s.epoch));
            }
        }
    }
    found
}

/// Every cleartext byte field of a stored record, as the server holds it.
///
/// Listed from the type, not from memory: [`CustodyRecord`]'s clear fields are
/// `rid`, `eid_e`, `h_prev`, `body` and `order_ref` (the signatures moved
/// inside `body` with §1br F2). A field added later and left out of this list
/// is the shape of defect F1 was, so the destructuring below fails to compile
/// when the struct gains one.
fn clear_fields(r: &CustodyRecord) -> Vec<Vec<u8>> {
    let CustodyRecord {
        rid,
        eid_e,
        h_prev,
        body,
        order_ref,
    } = r;
    let mut out = vec![rid.to_vec(), eid_e.to_vec(), h_prev.to_vec(), body.clone()];
    out.push(order_ref.map(|o| o.to_vec()).unwrap_or_default());
    out
}

/// A field read as a little-endian counter, a big-endian counter, and its
/// leading 12 bytes verbatim (the width of a GCM nonce).
type View = (u64, u64, [u8; 12]);

/// The small integers and byte prefixes a field yields: its leading 8 bytes as
/// a little- and a big-endian counter, and its leading 12 bytes verbatim.
fn field_views(f: &[u8]) -> Option<View> {
    let head: [u8; 12] = f.get(..12)?.try_into().ok()?;
    let le = u64::from_le_bytes(head[..8].try_into().ok()?);
    let be = u64::from_be_bytes(head[..8].try_into().ok()?);
    Some((le, be, head))
}

/// Pairs of segments **of one capsule** that a cleartext counter joins: some
/// field of a record in the later segment equals the same field of a record in
/// the earlier one **plus one**, read either way round, or shares its 12-byte
/// prefix.
fn counter_joined_segments(segs: &[Seg]) -> Vec<(usize, u64, u64)> {
    let views = |s: &Seg| -> Vec<(usize, View)> {
        s.records
            .iter()
            .flat_map(|r| {
                clear_fields(r)
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, f)| field_views(&f).map(|v| (i, v)))
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let mut found = Vec::new();
    for (i, a) in segs.iter().enumerate() {
        let va = views(a);
        for b in segs.iter().skip(i + 1) {
            if a.who != b.who {
                continue;
            }
            let vb = views(b);
            let joined = va.iter().any(|(fa, (le_a, be_a, head_a))| {
                vb.iter().any(|(fb, (le_b, be_b, head_b))| {
                    fa == fb
                        && (le_a.checked_add(1) == Some(*le_b)
                            || be_a.checked_add(1) == Some(*be_b)
                            || head_a == head_b)
                })
            });
            if joined {
                found.push((a.who, a.epoch, b.epoch));
            }
        }
    }
    found
}

/// The same store with each record's `C_rec` laid out as it was **before §1br
/// F1**: `nonce ‖ ciphertext ‖ tag`, with `nonce = ⟪j⟫₈ ‖ 0⁴`. The lab finds
/// each record's `j` by recomputing `rid`, which only it can.
fn pre_f1(segs: &[Seg], keys: &CaseKeys, capsules: &[Capsule]) -> Vec<Seg> {
    let mut out = segs.to_vec();
    for s in &mut out {
        let k_rid = CustodyRecord::rid_key(&keys.coc_key(), &capsules[s.who].eid);
        for r in &mut s.records {
            let j = (0..64u64)
                .find(|j| CustodyRecord::derive_rid(&k_rid, *j) == r.rid)
                .expect("the lab can place every record");
            let mut body = j.to_le_bytes().to_vec();
            body.extend_from_slice(&[0u8; 4]);
            body.extend_from_slice(&r.body);
            r.body = body;
        }
    }
    out
}

// ------------------------------------------------------------- the claims

#[test]
fn no_cleartext_counter_joins_two_segments_of_one_capsule() {
    // §1br F1. Every clear byte field, not only the 32-byte digests.
    let (ais, keys, capsules) = case();
    let segs = store(&ais, &keys, &capsules);
    let joined = counter_joined_segments(&segs);
    assert!(
        joined.is_empty(),
        "a cleartext counter links segments of one capsule: {joined:?}"
    );
}

#[test]
fn the_counter_checker_finds_the_pre_f1_nonce_on_every_boundary() {
    // ⭐ The true positive: put the position nonce back at the head of `C_rec`
    // and the checker must report every boundary, adjacent epochs only.
    let (ais, keys, capsules) = case();
    let before = pre_f1(&store(&ais, &keys, &capsules), &keys, &capsules);
    let joined = counter_joined_segments(&before);
    assert_eq!(
        joined.len(),
        CAPSULES * (ix(EPOCHS) - 1),
        "the checker did not find every pre-F1 boundary: {joined:?}"
    );
    for (who, a, b) in &joined {
        assert_eq!(
            *b,
            a + 1,
            "capsule {who}: the join is not between adjacent epochs"
        );
    }
}

#[test]
fn no_keyless_value_joins_two_segments_of_one_capsule() {
    let (ais, keys, capsules) = case();
    let segs = store(&ais, &keys, &capsules);
    assert_eq!(
        segs.len(),
        CAPSULES * ix(EPOCHS),
        "the fixture did not produce one segment per capsule per epoch"
    );

    let joined = joined_segments(&segs);
    assert!(
        joined.is_empty(),
        "the AIS can link segments of one capsule: {joined:?}"
    );
}

#[test]
fn the_same_checker_finds_the_pre_a20_link_on_every_boundary() {
    // ⭐ The true positive. Put the cleartext cross-segment link back and the
    // checker above must report every boundary — three capsules × three
    // boundaries each.
    let (ais, keys, capsules) = case();
    let before = pre_a20(&store(&ais, &keys, &capsules));

    let joined = joined_segments(&before);
    assert_eq!(
        joined.len(),
        CAPSULES * (ix(EPOCHS) - 1),
        "the checker did not find every pre-A20 boundary: {joined:?}"
    );
    for (who, a, b) in &joined {
        assert_eq!(
            *b,
            a + 1,
            "capsule {who}: the link found is not between adjacent epochs"
        );
    }
}

#[test]
fn no_keyless_value_joins_a_segment_to_its_capsule() {
    // The second half of D1: the capsule store holds `eid` in clear, so if any
    // segment value were reachable from it the per-epoch pseudonyms would be
    // decoration. Before A20 the first record's `h_prev` was exactly that
    // value, `H(0x24 ‖ ⟪eid⟫)`.
    let (ais, keys, capsules) = case();
    let segs = store(&ais, &keys, &capsules);
    let placed = placed_segments(&capsules, &segs);
    assert!(
        placed.is_empty(),
        "the AIS can place a segment against a stored capsule: {placed:?}"
    );
}

#[test]
fn the_same_checker_finds_the_pre_a20_genesis_link() {
    // The true positive for the other half. Before A20 the opening record's
    // cleartext `h_prev` was `H(0x24 ‖ ⟪eid⟫)`, which any holder of the capsule
    // recomputes, so epoch 0's segment was placeable.
    let (ais, keys, capsules) = case();
    let mut before = store(&ais, &keys, &capsules);
    for s in &mut before {
        if s.epoch == 0 {
            let eid = capsules[s.who].eid;
            s.records[0].h_prev = CustodyRecord::genesis_link(&eid);
        }
    }

    let placed = placed_segments(&capsules, &before);
    assert_eq!(
        placed.len(),
        CAPSULES,
        "the checker did not place every capsule's first segment: {placed:?}"
    );
    assert!(
        placed.iter().all(|(_, e)| *e == 0),
        "the placement found is not the genesis one: {placed:?}"
    );
}

#[test]
fn the_lab_can_still_place_every_segment() {
    // The mirror image, and the reason the claims above are properties and not
    // vacuous passes: with `k_eid` a capsule's segments are all findable. A
    // store that linked nothing *to anyone* would satisfy the claim and be
    // useless.
    let (ais, keys, capsules) = case();
    for (i, c) in capsules.iter().enumerate() {
        let k_eid = keys.capsule_link_key(&c.eid);
        for e in 0..EPOCHS {
            let eid_e = CustodyRecord::epoch_pseudonym(&k_eid, e);
            assert!(
                ais.segment(&eid_e).is_some(),
                "capsule {i}'s epoch-{e} segment is not findable from its own link key"
            );
        }
        let bundle = ais.disclose(i, &keys).expect("bundle");
        assert_eq!(bundle.segments.len(), ix(EPOCHS));
        bundle
            .verify(&ais.epoch_roots())
            .expect("every segment is anchored in its own epoch");
        bundle.open().expect("the cross-segment links hold");
    }
}
