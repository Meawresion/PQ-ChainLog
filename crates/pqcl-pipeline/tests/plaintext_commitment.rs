//! `cm_ev` is a **hiding** commitment (draft8 `eq:capsule`; design §14.3 and
//! §12.4).
//!
//! Without its opening `r_ev`, anyone holding the capsule and a guessed copy of
//! the artefact could confirm the guess forever, and redaction's FULL mode,
//! which destroys `r_ev` so that `cm_ev` becomes unopenable, would erase
//! nothing. So: the same bytes ingested twice must commit differently, the
//! opening must verify, and a wrong opening or wrong bytes must not.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use pqcl_capsule::Role;
use pqcl_pipeline::{Agent, CaseKeys, IngestParams, chunked};
use pqcl_primitives::SoftwareMlDsa;
use pqcl_primitives::xof::{Domain, PrfKey, digest256};

fn case_keys() -> CaseKeys {
    CaseKeys::derive(
        &PrfKey::new(digest256(b"k_mst")),
        b"CASE-CM",
        &digest256(b"r_case"),
    )
}

/// A small artefact on disk, spanning a chunk boundary, unique to this test.
fn artefact(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("pqcl-cm-{name}-{}", std::process::id()));
    let mut bytes = vec![0u8; chunked::CHUNK_BYTES + 100];
    bytes[7] = 1;
    std::fs::write(&p, bytes).expect("temp artefact");
    p
}

fn ingest(
    agent: &Agent,
    path: &Path,
    nonce: &[u8],
) -> (pqcl_capsule::Capsule, pqcl_pipeline::PlaintextOpening) {
    let nonce = digest256(nonce);
    agent
        .ingest(
            &case_keys(),
            path,
            &IngestParams {
                artefact_type: b"disk-image",
                d_ev: digest256(b"stored"),
                ptr: b"p",
                epoch: 1,
                nonce: &nonce,
            },
        )
        .expect("ingest")
}

#[test]
fn the_same_artefact_ingested_twice_commits_differently() {
    let path = artefact("twice");
    let agent = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"first-responder-1",
        Role::Defr,
    );
    let (a, _) = ingest(&agent, &path, b"n1");
    let (b, _) = ingest(&agent, &path, b"n2");
    std::fs::remove_file(&path).ok();
    assert_ne!(
        a.cm_ev, b.cm_ev,
        "cm_ev must hide the artefact: equal bytes, unequal commitments"
    );
}

#[test]
fn cm_ev_is_not_the_unblinded_root_of_the_plaintext() {
    let path = artefact("unblinded");
    let agent = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"first-responder-1",
        Role::Defr,
    );
    let (c, _) = ingest(&agent, &path, b"n");
    let guess = chunked::digest_file(&path, Domain::PlaintextCommit)
        .expect("read")
        .root()
        .to_owned();
    std::fs::remove_file(&path).ok();
    assert_ne!(
        c.cm_ev, guess,
        "a guessed copy alone must not confirm the artefact"
    );
}

#[test]
fn the_opening_verifies_and_only_for_the_right_bytes() {
    let path = artefact("open");
    let agent = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"first-responder-1",
        Role::Defr,
    );
    let (c, opening) = ingest(&agent, &path, b"n");
    let bytes = std::fs::read(&path).expect("read");
    std::fs::remove_file(&path).ok();

    assert!(
        opening.opens(&c.cm_ev, &bytes),
        "the opening must verify the artefact it was made for"
    );

    let mut wrong = bytes.clone();
    wrong[chunked::CHUNK_BYTES + 3] ^= 1;
    assert!(
        !opening.opens(&c.cm_ev, &wrong),
        "one changed byte must not open"
    );

    let other = pqcl_pipeline::PlaintextOpening {
        r_ev: digest256(b"another r_ev"),
        ..opening.clone()
    };
    assert!(
        !other.opens(&c.cm_ev, &bytes),
        "a different r_ev must not open"
    );
}

/// Design §14.3: equal chunks in two capsules must not be linkable by their
/// leaves, so `r_ev` enters every chunk leaf, not only the root.
#[test]
fn equal_chunks_in_two_capsules_have_unlinkable_leaves() {
    let path = artefact("leaves");
    let agent = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"first-responder-1",
        Role::Defr,
    );
    let (_, a) = ingest(&agent, &path, b"n1");
    let (_, b) = ingest(&agent, &path, b"n2");
    std::fs::remove_file(&path).ok();
    assert_eq!(a.chunks.chunk_count(), 2);
    assert!(
        a.chunks
            .chunks()
            .iter()
            .all(|l| !b.chunks.chunks().contains(l))
    );
}
