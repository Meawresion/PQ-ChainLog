//! §1q.5: the honest `XSet` is stored hashed (as ODXT's is), but draft6's
//! `0x03` leaf commits to the **sorted** set. Every read that exposes order
//! must therefore produce it: `all_epochs` ascending, `epoch` equal as a set.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use pqcl_dsse::xt::{HonestXSet, XSetStore, XTag};
use pqcl_primitives::xof;

fn tags(seed: u8, n: u32) -> Vec<XTag> {
    (0..n)
        .map(|i| xof::digest256(&[&[seed][..], &i.to_le_bytes()].concat()))
        .collect()
}

#[test]
fn every_epoch_reads_back_sorted_and_complete() {
    let mut x = HonestXSet::new();
    let per_epoch: Vec<Vec<XTag>> = (0..4u8).map(|e| tags(e, 500 + u32::from(e) * 37)).collect();
    for (e, t) in per_epoch.iter().enumerate() {
        // Two batches per epoch, in the scrambled order a shuffled upload has.
        let (a, b) = t.split_at(t.len() / 2);
        x.add_xtags(e as u64, b);
        x.add_xtags(e as u64, a);
    }
    let all = x.all_epochs();
    assert_eq!(all.len(), per_epoch.len());
    for ((e, got), want) in all.iter().zip(&per_epoch) {
        assert!(
            got.windows(2).all(|w| w[0] < w[1]),
            "epoch {e} is not strictly ascending"
        );
        let want: BTreeSet<XTag> = want.iter().copied().collect();
        assert_eq!(
            got.iter().copied().collect::<BTreeSet<_>>(),
            want,
            "epoch {e} lost or gained tags"
        );
        assert_eq!(x.epoch(*e).expect("epoch present"), want);
    }
    assert_eq!(
        x.xtag_count(),
        per_epoch.iter().map(Vec::len).sum::<usize>()
    );
}
