//! ⭐ **M13 A21 acceptance (c): two cases of different size, anchored in epochs
//! of the same size, are indistinguishable by what they publish.**
//!
//! `audit/07` D2: the claim that a flat MMR cannot disclose one capsule without
//! leaking case size was contradicted by **our own anchor**, whose cumulative
//! `leafCount` was public. A21 takes the count off chain; A20 made the count
//! per epoch, so there is no running total left to publish.
//!
//! What this test asserts, and what it deliberately does not:
//!
//! * ✅ a disclosure bundle's length depends on the **disclosed capsule's own**
//!   history, not on the case around it;
//! * ✅ the per-epoch data an epoch publishes — `(R_e, d_e, A_e)` — is the same
//!   shape in both cases, and `d_e` does not widen with `n_e`;
//! * ⚠️ **not** that the two cases are wholly indistinguishable on chain. The
//!   bigger case closes more epochs, so it emits more `RootCommitted` events.
//!   With epochs closed on a period `Δ` that is independent of case size; with
//!   epochs closed on a fixed size it bounds the record count to within `Δ`.
//!   The design record has the wording, and the last test here
//!   pins the residue rather than hiding it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
// One reported ratio in an assertion message, over byte lengths of a few
// kilobytes. Never a measurement.
#![allow(clippy::cast_precision_loss)]

use pqcl_capsule::{Event, Params, Role};
use pqcl_pipeline::checkpoint::{ChainView, Committed, Proposal};
use pqcl_pipeline::{Agent, Ais, CaseKeys, IngestParams, RecordParams, checkpoint};
use pqcl_primitives::SoftwareMlDsa;
use pqcl_primitives::xof::{Digest32, PrfKey, digest256};

/// Records per capsule per epoch — the epoch size that does not grow with the
/// case.
const PER_EPOCH: u64 = 2;

struct Case {
    /// Each closed epoch's `(R_e, n_e, d_e)`.
    epochs: Vec<(Digest32, u64, Digest32)>,
    /// The disclosure bundle for capsule 0, as bytes.
    bundle: Vec<u8>,
    /// Records in the whole case.
    records: usize,
}

/// A case of `capsules` capsules over `epochs` epochs, every capsule touched
/// `PER_EPOCH` times per epoch.
fn case(name: &[u8], capsules: usize, epochs: u64) -> Case {
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
    let keys = CaseKeys::derive(&PrfKey::new(digest256(b"K_mst")), name, &digest256(b"r"));
    let mut ais = Ais::new();
    let mut tails = Vec::new();
    let mut records = 0usize;

    for c in 0..capsules {
        let nonce = digest256(&(c as u64).to_le_bytes());
        let capsule = defr
            .seal(
                &keys,
                digest256(b"cm"),
                &IngestParams {
                    artefact_type: b"disk-image",
                    d_ev: digest256(&nonce),
                    ptr: b"s3://case/obj",
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
        ais.accept(capsule.clone(), first.clone());
        records += 1;
        tails.push((capsule, first, 1u64));
    }

    let mut closed = Vec::new();
    let mut d_prev = digest256(b"reg");
    // ⭐ A custodian approving every epoch this AIS really closes (M13 A5):
    // recomputing `R_e` and `n_e` from the leaves the AIS holds, so an honest
    // AIS is shown to be approved, not merely assumed to be.
    let mut view = ChainView::new(keys.cid_c, d_prev);
    for e in 0..epochs {
        for (capsule, previous, j) in &mut tails {
            // Epoch 0 already holds each capsule's opening COLLECT.
            let extra = if e == 0 { PER_EPOCH - 1 } else { PER_EPOCH };
            for _ in 0..extra {
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
                records += 1;
            }
        }
        let root = ais.close_epoch();
        let last = ais.closed_epochs().last().expect("the epoch closed");
        let n_e = last.count;
        let d_e = checkpoint::checkpoint(&keys.cid_c, e, &root, n_e, &d_prev);
        view.validate(&Proposal {
            cid: keys.cid_c,
            e,
            root,
            n_e,
            d_prev,
            d_e,
            over: Committed::Epoch(last.leaf_digests()),
        })
        .unwrap_or_else(|err| panic!("a custodian refused the AIS's honest epoch {e}: {err}"));
        d_prev = d_e;
        closed.push((root, n_e, d_e));
    }

    let bundle = ais.disclose(0, &keys).expect("bundle").encode();
    Case {
        epochs: closed,
        bundle,
        records,
    }
}

#[test]
fn a_disclosure_does_not_grow_with_the_case_around_it() {
    // Same per-capsule history, 4 capsules against 40. The bundle a court
    // receives must be the same size: Tier 1 is per capsule, and the Tier-2
    // paths grow only logarithmically in the epoch's own width.
    let small = case(b"case-small", 4, 3);
    let large = case(b"case-large", 40, 3);
    assert_eq!(large.records, small.records * 10);

    let growth = large.bundle.len() as f64 / small.bundle.len() as f64;
    assert!(
        growth < 1.10,
        "the bundle grew {growth:.3}x when the case grew 10x: {} B vs {} B",
        small.bundle.len(),
        large.bundle.len()
    );
}

#[test]
fn what_each_epoch_publishes_is_the_same_shape_in_both_cases() {
    // `(R_e, d_e)` are digests, so what an epoch publishes is fixed-width
    // whatever it held. `n_e` is inside `d_e`, which is why `d_e` cannot widen.
    let small = case(b"case-small", 4, 3);
    let large = case(b"case-large", 40, 3);
    assert_eq!(small.epochs.len(), large.epochs.len());
    for ((rs, ns, ds), (rl, nl, dl)) in small.epochs.iter().zip(&large.epochs) {
        assert_eq!(rs.len(), rl.len());
        assert_eq!(ds.len(), dl.len());
        // The counts differ — that is the quantity A21 takes off chain.
        assert_ne!(ns, nl, "the fixture's two cases hold the same leaf count");
    }
}

#[test]
fn the_number_of_epochs_is_what_remains_visible() {
    // ⚠️ The residue, pinned so nobody reads the claim as more than it is. Two
    // cases with the same activity *per epoch* and different durations publish
    // a different number of epochs, and that is visible on chain. The claim is
    // about the record count inside an epoch, not about the epoch count.
    let short = case(b"case-short", 4, 2);
    let long = case(b"case-long", 4, 5);
    assert_eq!(short.epochs.len(), 2);
    assert_eq!(long.epochs.len(), 5);
    assert!(
        long.bundle.len() > short.bundle.len(),
        "a capsule with more history must disclose more; it is its own history, \
         not the case's"
    );
}

/// ⭐ **Acceptance A5, against a real AIS.** An AIS that withholds one leaf
/// of an epoch from the custodians — so the root it anchors covers a record
/// they never saw — is refused, because the custodian bags what it was
/// handed and the AIS's `R_e` is not that.
#[test]
fn a_custodian_refuses_an_epoch_whose_leaves_were_not_all_shown() {
    let defr = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"first-responder-1",
        Role::Defr,
    );
    let keys = CaseKeys::derive(&PrfKey::new(digest256(b"K_mst")), b"A5", &digest256(b"r"));
    let mut ais = Ais::new();
    for c in 0..3u64 {
        let nonce = digest256(&c.to_le_bytes());
        let capsule = defr
            .seal(
                &keys,
                digest256(b"cm"),
                &IngestParams {
                    artefact_type: b"disk-image",
                    d_ev: digest256(&nonce),
                    ptr: b"s3://case/obj",
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
        ais.accept(capsule, first);
    }
    let root = ais.close_epoch();
    let last = ais.closed_epochs().last().expect("closed");
    let reg = digest256(b"reg");
    let d_e = checkpoint::checkpoint(&keys.cid_c, 0, &root, last.count, &reg);
    let shown = &last.leaf_digests()[..last.leaf_digests().len() - 1];
    let mut view = ChainView::new(keys.cid_c, reg);
    assert!(
        view.validate(&Proposal {
            cid: keys.cid_c,
            e: 0,
            root,
            n_e: last.count,
            d_prev: reg,
            d_e,
            over: Committed::Epoch(shown),
        })
        .is_err(),
        "an epoch with a leaf withheld from the custodian was approved"
    );
    // And the whole epoch, shown in full, is approved by the same custodian.
    assert!(
        view.validate(&Proposal {
            cid: keys.cid_c,
            e: 0,
            root,
            n_e: last.count,
            d_prev: reg,
            d_e,
            over: Committed::Epoch(last.leaf_digests()),
        })
        .is_ok()
    );
}
