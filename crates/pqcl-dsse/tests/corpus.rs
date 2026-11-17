//! **M2's acceptance criterion**, on the real corpus.
//!
//! The build plan (M2): *"on a real corpus (Enron),
//! `Π_core.Search(w)` equals the oracle for every keyword, across an
//! interleaved add/delete workload."*
//!
//! `tests/pi_core.rs` already proves the protocol correct on a generated
//! workload. This adds what a generated workload cannot: a **real keyword
//! distribution**. Enron's is heavily skewed — a handful of keywords appear in
//! most documents, and a long tail appears once. That shape is what stresses
//! the counter space, produces the ragged GGM covers, and is exactly the
//! distribution the s-term selection of M3 depends on. A uniform fixture would
//! pass while hiding all of it.
//!
//! # Requires the corpus
//!
//! ```text
//! sh datasets/fetch-enron.sh
//! PQCL_ENRON=$PWD/datasets/enron/maildir \
//!   cargo test --release -p pqcl-dsse --test corpus -- --ignored --nocapture
//! ```
//!
//! `#[ignore]`d because it needs a 1.7 GB download that `cargo test` must not
//! require, and **it fails loudly rather than skipping** when `PQCL_ENRON` is
//! unset — so "M2 accepted" can never be claimed on the strength of a test that
//! quietly did nothing. Use `--release`: this is a lot of SHAKE256.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
// Reporting-only arithmetic: counts into f64 for a MiB figure, and a u64 count
// compared against a usize. Neither feeds a measurement — the throughput and
// size numbers that reach the paper come from `pqcl-bench` through the results
// pipeline, never from a test's eprintln.
#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pqcl_dsse::Oracle;
use pqcl_dsse::core::{Client, Edb, HonestEdb, Op};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

/// How many messages to index. The whole corpus is ~517k; a tier of this size
/// exercises the real distribution in minutes rather than hours, and
/// The build plan's tiering rule says the big run happens once,
/// on AWS, not on every developer check.
const MESSAGES: usize = 20_000;

fn corpus_root() -> PathBuf {
    let raw = std::env::var("PQCL_ENRON").unwrap_or_else(|_| {
        panic!(
            "\n\nPQCL_ENRON is not set, so the M2 corpus acceptance cannot run.\n\n\
             Fetch the corpus:\n    sh datasets/fetch-enron.sh\n\n\
             Then:\n    PQCL_ENRON=$PWD/datasets/enron/maildir \\\n      \
             cargo test --release -p pqcl-dsse --test corpus -- --ignored --nocapture\n\n\
             This fails rather than skips on purpose: M2 must not be recorded as \
             accepted on the strength of a test that did nothing.\n"
        )
    });
    let path = PathBuf::from(raw);
    assert!(
        path.is_dir(),
        "PQCL_ENRON points at {}, which is not a directory",
        path.display()
    );
    path
}

/// Collect message files, breadth-limited so one huge mailbox cannot dominate.
fn collect(root: &Path, limit: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if out.len() >= limit {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if out.len() < limit {
                out.push(p);
            }
        }
    }
    out.sort();
    out.truncate(limit);
    out
}

/// Lowercase alphabetic tokens of 3..=20 characters, deduplicated per document.
///
/// Deliberately plain. A clever tokenizer would be a second thing that could be
/// wrong, and the oracle comparison only means something if both sides see
/// exactly the same keyword set — which they do, because both are fed from
/// here.
fn keywords(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| (3..=20).contains(&t.len()))
        .map(str::to_ascii_lowercase)
        .collect()
}

#[test]
#[ignore = "needs the Enron corpus; set PQCL_ENRON — see the module docs"]
fn pi_core_matches_the_oracle_on_enron() {
    let root = corpus_root();
    let files = collect(&root, MESSAGES);
    assert!(
        files.len() > MESSAGES / 2,
        "found only {} files under {} — is this the maildir?",
        files.len(),
        root.display()
    );

    let mut client = Client::new(PrfKey::new([0x5eu8; LAMBDA_BYTES]));
    let mut edb = HonestEdb::new();
    let mut oracle = Oracle::new();

    // Phase 1 — index.
    let mut indexed = 0u64;
    for (doc_id, path) in files.iter().enumerate() {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue; // a handful of messages are not valid UTF-8
        };
        let id = doc_id as u64;
        for w in keywords(&text) {
            let w = w.as_bytes();
            oracle.update(Op::Add, w, id);
            edb.insert(&client.update(Op::Add, w, id).expect("update"));
        }
        indexed += 1;
    }

    // Phase 2 — interleave deletions, which is what makes this a DSSE test
    // rather than a static-index one. Delete every 7th document entirely.
    let mut deleted = 0u64;
    for (doc_id, path) in files.iter().enumerate() {
        if !doc_id.is_multiple_of(7) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let id = doc_id as u64;
        for w in keywords(&text) {
            let w = w.as_bytes();
            oracle.update(Op::Del, w, id);
            edb.insert(&client.update(Op::Del, w, id).expect("update"));
        }
        deleted += 1;
    }

    eprintln!(
        "Enron tier: {indexed} documents indexed, {deleted} deleted, \
         {} keywords, {} updates, {} live pairs, {} EDB records, {:.1} MiB index",
        oracle.keyword_count(),
        oracle.update_count(),
        oracle.live_pairs(),
        edb.len(),
        edb.stored_bytes() as f64 / (1024.0 * 1024.0),
    );

    // Phase 3 — the acceptance check itself: every keyword, no sampling.
    let mut checked = 0u64;
    for w in oracle.keywords() {
        let expected = oracle.search(w);
        let token = client.search_token(w).expect("keyword was updated");
        let got = client
            .finish(w, &token, &edb.search(&token))
            .expect("honest server must verify");
        assert_eq!(
            got,
            expected,
            "Π_core disagrees with the oracle for {:?}",
            String::from_utf8_lossy(w)
        );
        checked += 1;
    }

    assert_eq!(
        usize::try_from(checked).expect("fits"),
        oracle.keyword_count()
    );
    assert_eq!(
        edb.len(),
        oracle.update_count(),
        "every update must occupy exactly one address: a collision would mean \
         two records shared a slot and one was silently lost"
    );
    eprintln!("M2 acceptance: {checked} keywords checked against the oracle, all match");
}
