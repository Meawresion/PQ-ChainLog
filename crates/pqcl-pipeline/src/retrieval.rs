//! Phase 9 Step 4 (draft8, P6): retrieval accountability.
//!
//! After recovery the client commits to exactly what it disclosed,
//!
//! ```text
//! R_res = H(0x35 ‖ ⟪N, H(0x34 ‖ ⟪td⟫), sorted(R), r_res⟫)      eq:rres
//! 0x04 ‖ H(⟪wid, H(0x34 ‖ ⟪td⟫), R_res, ts⟫)                   eq:leaves
//! ```
//!
//! and the `0x04` leaf, emitted **after** the search, anchors it. An auditor
//! later shown `(R, r_res)` confirms that exactly those records left under that
//! warrant; the server learns nothing from the commitment (`r_res` is fresh and
//! kept by the investigator). `wid` is the nullifier `N`, the only warrant
//! identifier the AIS sees.

use pqcl_dsse::core::DocId;
use pqcl_forest::Leaf;
use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

/// `H(0x34 ‖ ⟪td⟫)`: the trapdoor as the AIS received it.
#[must_use]
pub fn trapdoor_digest(td: &[u8]) -> Digest32 {
    hash_domain(Domain::TrapdoorDigest, &[td])
}

/// `sorted(R)` as one field: fixed-width identifiers in ascending order, so
/// the encoding of a set is unique.
fn sorted_ids(results: &[DocId]) -> Vec<u8> {
    let mut ids = results.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids.iter().flat_map(|i| i.to_le_bytes()).collect()
}

/// `R_res`.
#[must_use]
pub fn commit_results(
    n: &Digest32,
    td_digest: &Digest32,
    results: &[DocId],
    r_res: &Digest32,
) -> Digest32 {
    hash_domain(
        Domain::ResultSet,
        &[n, td_digest, &sorted_ids(results), r_res],
    )
}

/// The `0x04` leaf: `wid`, the trapdoor digest, `R_res`, `ts`.
#[must_use]
pub fn audit_leaf(
    wid: &Digest32,
    td_digest: &Digest32,
    r_res_commitment: &Digest32,
    ts: u64,
) -> Leaf {
    Leaf::new(
        Domain::AuditEvent,
        &[wid, td_digest, r_res_commitment, &ts.to_le_bytes()],
    )
}

/// The auditor's opening: does `(results, r_res)` open the anchored `R_res`
/// for this nullifier and trapdoor?
#[must_use]
pub fn opens(
    commitment: &Digest32,
    n: &Digest32,
    td_digest: &Digest32,
    results: &[DocId],
    r_res: &Digest32,
) -> bool {
    commit_results(n, td_digest, results, r_res) == *commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcl_primitives::xof::digest256;

    fn setup() -> (Digest32, Digest32, Vec<DocId>, Digest32, Digest32) {
        let n = digest256(b"N");
        let td = trapdoor_digest(b"the constrained key and the probe list the AIS received");
        let r = vec![42, 7, 19];
        let r_res = digest256(b"fresh r_res");
        let c = commit_results(&n, &td, &r, &r_res);
        (n, td, r, r_res, c)
    }

    #[test]
    fn the_disclosed_set_opens_the_commitment_in_any_order() {
        let (n, td, mut r, r_res, c) = setup();
        assert!(opens(&c, &n, &td, &r, &r_res));
        r.reverse();
        assert!(opens(&c, &n, &td, &r, &r_res), "a set, not a sequence");
    }

    #[test]
    fn a_substituted_id_nullifier_trapdoor_or_opening_fails() {
        let (n, td, r, r_res, c) = setup();
        assert!(
            !opens(&c, &n, &td, &[42, 7, 20], &r_res),
            "a substituted id"
        );
        assert!(!opens(&c, &n, &td, &[42, 7], &r_res), "an omitted id");
        assert!(!opens(&c, &n, &td, &[42, 7, 19, 1], &r_res), "an added id");
        assert!(
            !opens(&c, &digest256(b"another N"), &td, &r, &r_res),
            "another warrant's nullifier"
        );
        assert!(
            !opens(&c, &n, &trapdoor_digest(b"another trapdoor"), &r, &r_res),
            "another trapdoor"
        );
        assert!(
            !opens(&c, &n, &td, &r, &digest256(b"guessed r_res")),
            "a wrong opening"
        );
    }

    #[test]
    fn the_leaf_binds_the_result_commitment() {
        let (n, td, _, _, c) = setup();
        let a = audit_leaf(&n, &td, &c, 1_000);
        let b = audit_leaf(&n, &td, &digest256(b"another R_res"), 1_000);
        assert_ne!(a.digest, b.digest);
    }
}
