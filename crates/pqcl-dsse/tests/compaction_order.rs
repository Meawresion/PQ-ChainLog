//! M12 R2: the live set's representation changed, and compaction must not.
//!
//! `XtClient::live` was a `BTreeSet<(Vec<u8>, DocId)>`, which allocated on
//! every token. It is now interned keywords in a `HashSet`. Compaction feeds
//! the live set through a keyed shuffle whose output depends on input order,
//! and a `HashSet` iterates in a per-process random order, so the rewrite has
//! to reproduce the old order exactly or the upload order silently changes.
//!
//! Two checks, because either alone can pass while the property fails:
//!
//! * **As a set**, the compacted batch equals an independent model: a
//!   `BTreeSet` of live pairs kept by this test, tagged with `H_X` directly.
//! * **In order**, the batch's digest equals the pin produced by the pre-R2
//!   code (`082ce26`) on this exact script.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use pqcl_dsse::core::{Client, DocId, Edb, Op, SearchResponse, SearchToken, UpdateToken};
use pqcl_dsse::xt::{Epoch, Ratchet, Transcript, XSetStore, XTag, XtClient};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::{self, PrfKey};

/// Records every `add_xtags` batch in arrival order.
#[derive(Default)]
struct Recorder {
    batches: Vec<(Epoch, Vec<XTag>)>,
}

impl Edb for Recorder {
    fn insert(&mut self, _token: &UpdateToken) {}
    fn search(&self, _token: &SearchToken) -> SearchResponse {
        SearchResponse(Vec::new())
    }
    fn len(&self) -> usize {
        0
    }
}

impl XSetStore for Recorder {
    fn add_xtags(&mut self, epoch: Epoch, tags: &[XTag]) {
        self.batches.push((epoch, tags.to_vec()));
    }
    fn probe(&self, _transcript: &Transcript) -> Vec<bool> {
        Vec::new()
    }
    fn xtag_count(&self) -> usize {
        self.batches.iter().map(|(_, b)| b.len()).sum()
    }
    fn seal_epoch(&mut self, _epoch: Epoch) {}
    fn reset(&mut self) {
        self.batches.clear();
    }
}

/// Keywords whose byte order differs from their first-seen order, so an
/// implementation that iterated in insertion order would be caught.
fn keyword(i: u64) -> Vec<u8> {
    format!(
        "{}kw{}",
        "z".repeat(usize::try_from(i % 5).unwrap()),
        997 - i
    )
    .into_bytes()
}

#[test]
fn compaction_output_is_unchanged_by_interning() {
    let mut client = XtClient::new(
        Client::new(PrfKey::new([0x31; LAMBDA_BYTES])),
        PrfKey::new([0x32; LAMBDA_BYTES]),
        16,
    );
    let mut store = Recorder::default();
    let mut model: BTreeSet<(Vec<u8>, DocId)> = BTreeSet::new();

    for i in 0..600u64 {
        let w = keyword(i % 150);
        let id: DocId = pqcl_dsse::xt::doc_id(client.epoch(), (i * 7) % 211);
        let op = if i % 9 == 4 { Op::Del } else { Op::Add };
        client.update(&mut store, op, &w, id).unwrap();
        match op {
            Op::Add => {
                model.insert((w, id));
            }
            Op::Del => {
                model.remove(&(w, id));
            }
        }
        if i % 97 == 96 {
            client.close_epoch(&mut store);
        }
    }
    for i in [3u64, 40, 41, 149] {
        let w = keyword(i);
        let id = model.iter().find(|(k, _)| *k == w).map_or(5, |(_, d)| *d);
        client.tombstone(&w, id);
        assert!(client.is_tombstoned(&w, id));
        model.remove(&(w, id));
    }
    assert!(!client.is_tombstoned(b"never-seen", 1));
    assert_eq!(client.live_pairs(), model.len());

    let seed = [0x5e; LAMBDA_BYTES];
    client.compact(&mut store, PrfKey::new(seed));
    let (epoch, batch) = store
        .batches
        .last()
        .expect("compaction uploads a batch")
        .clone();
    // Compaction rebuilds into the epoch that was open, so numbering never
    // repeats (D3): six closes happened above.
    assert_eq!(epoch, 6);

    // As a set: the independent model, tagged directly with H_X (eq:xtagdef,
    // insert-only: no op byte since D3).
    let fresh = Ratchet::new(PrfKey::new(seed));
    let want: BTreeSet<XTag> = model
        .iter()
        .map(|(w, id)| xof::cross_tag(fresh.current(), &[w, &id.to_le_bytes()]))
        .collect();
    let got: BTreeSet<XTag> = batch.iter().copied().collect();
    assert_eq!(got, want, "compaction carried a different live set");
    assert_eq!(batch.len(), want.len(), "compaction uploaded a duplicate");

    // In order: the pre-R2 shuffle output.
    let flat: Vec<u8> = batch.iter().flatten().copied().collect();
    assert_eq!(
        hex(&xof::digest256(&flat)),
        PRE_R2_ORDER_DIGEST,
        "compaction upload order changed"
    );
}

/// `digest256` of the compacted batch, concatenated in upload order.
///
/// ⚠️ Re-pinned at the draft8 D3 change: the tag
/// lost its `op` byte and identifiers now carry their epoch, so every tag
/// changed. The set check above is the independent one (it re-derives every
/// tag from the model); this pin guards the upload ORDER against drift from
/// here on. The previous value, from the pre-R2 implementation at `082ce26`,
/// described the old tag format.
const PRE_R2_ORDER_DIGEST: &str =
    "0d7688f81ae9e283ddc7521d5eeed30ab235dcf9f5bc288e390874e141eee9f0";

fn hex(d: &[u8]) -> String {
    use std::fmt::Write;
    d.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
