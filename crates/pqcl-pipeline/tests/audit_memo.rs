//! The memoised full-case audit accepts and rejects exactly what the
//! per-capsule audit does — on tampered cases,
//! with the memo already warmed by a full audit of the intact case, which is
//! where a cache would give a stale answer if it could.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use pqcl_capsule::{Bundle, Event, Params, Role};
use pqcl_forest::tier2::NodeMemo;
use pqcl_pipeline::{Agent, Ais, CaseKeys, IngestParams, RecordParams};
use pqcl_primitives::SoftwareMlDsa;
use pqcl_primitives::xof::{Digest32, PrfKey, digest256};

/// One agent per role (M13 A2). `Agent` commits its own role into every
/// `actor_c` and refuses an event its role may not sign, so a fixture needs the
/// cast the events call for — which is also what a real case has.
fn cast() -> (Agent, Agent, Agent, Agent) {
    let agent = |id: &[u8], role| Agent::new(SoftwareMlDsa::generate().expect("keygen"), id, role);
    (
        agent(b"first-responder-1", Role::Defr),
        agent(b"specialist-1", Role::Des),
        agent(b"investigator-1", Role::Investigator),
        agent(b"evidence-store-1", Role::Custodian),
    )
}

fn case() -> (Vec<Bundle>, Vec<(u64, Digest32)>) {
    let (defr, _des, inv, _cust) = cast();
    let keys = CaseKeys::derive(&PrfKey::new(digest256(b"K")), b"case", &digest256(b"r"));
    let mut ais = Ais::new();
    for c in 0..23u64 {
        let nonce = digest256(&c.to_le_bytes());
        let ip = IngestParams {
            artefact_type: b"x",
            d_ev: digest256(&nonce),
            ptr: b"p",
            epoch: 0,
            nonce: &nonce,
        };
        let cap = defr.seal(&keys, digest256(b"cm"), &ip).expect("seal");
        let rp = |j: u64, ts: u64| {
            RecordParams::at(j, ts).with_params(Params::justified(&c.to_le_bytes()))
        };
        let mut prev = defr
            .collect_record(&keys, &cap, &rp(0, 0))
            .expect("sign")
            .record;
        ais.accept(cap.clone(), prev.clone());
        for k in 1..=(c % 4) {
            let r = inv
                .append_record(&keys, &cap, Event::Access, &prev, &rp(k, k))
                .expect("sign")
                .record;
            ais.append(r.clone());
            prev = r;
        }
    }
    ais.close_epoch();
    let roots = ais.epoch_roots();
    (
        (0..ais.len())
            .filter_map(|k| ais.disclose(k, &keys))
            .collect(),
        roots,
    )
}

/// Every way to break a bundle this test knows, applied to capsule `k`.
fn tampered(b: &Bundle) -> Vec<(&'static str, Bundle)> {
    let mut out = Vec::new();
    let mut x = b.clone();
    // Flip a ciphertext byte. `ts` used to be editable in the clear; since
    // M13 A1 it is inside `C_rec`, and the leaf and signature cover the
    // ciphertext — so this is the same attack against the same commitments,
    // expressed against the shape the record now has.
    x.segments[0].records[0].body[0] ^= 1;
    out.push(("record edited", x));
    if b.segments[0].records.len() > 1 {
        let mut x = b.clone();
        x.segments[0].records.remove(1);
        out.push(("record removed", x));
    }
    if !b.segments[0].anchor_proof.path.is_empty() {
        let mut x = b.clone();
        x.segments[0].anchor_proof.path[0].sibling[0] ^= 1;
        out.push(("path sibling", x));
        let mut x = b.clone();
        let last = x.segments[0].anchor_proof.path.len() - 1;
        x.segments[0].anchor_proof.path[last].sibling_is_right ^= true;
        out.push(("path direction near the peak", x));
    }
    if !b.segments[0].anchor_proof.peaks_left.is_empty() {
        let mut x = b.clone();
        x.segments[0].anchor_proof.peaks_left[0][5] ^= 1;
        out.push(("left peak", x));
    }
    if !b.segments[0].anchor_proof.peaks_right.is_empty() {
        let mut x = b.clone();
        x.segments[0].anchor_proof.peaks_right.pop();
        out.push(("right peak dropped", x));
    }
    let mut x = b.clone();
    x.segments[0].anchor_proof.index = x.segments[0].anchor_proof.count;
    out.push(("index out of range", x));
    let mut x = b.clone();
    x.segments[0].eid_e[0] ^= 1;
    out.push(("pseudonym", x));
    out
}

#[test]
fn the_memoised_audit_decides_exactly_as_the_per_capsule_audit() {
    let (bundles, roots) = case();
    let mut memo = NodeMemo::default();
    // Warm the memo with a full audit of the intact case.
    for b in &bundles {
        assert_eq!(b.verify(&roots), Ok(()));
        assert_eq!(b.verify_memo(&roots, &mut memo), Ok(()));
    }
    assert!(
        memo.hits > 0,
        "a case this size must share nodes near the peaks"
    );

    let mut compared = 0;
    for b in &bundles {
        for (what, t) in tampered(b) {
            let plain = t.verify(&roots);
            let memoised = t.verify_memo(&roots, &mut memo);
            assert_eq!(plain, memoised, "{what}: the memo changed the decision");
            assert!(plain.is_err(), "{what}: a tampered bundle verified");
            compared += 1;
        }
        // And the wrong root rejects both ways.
        let mut other = roots.clone();
        other[0].1[0] ^= 1;
        assert_eq!(b.verify(&other), b.verify_memo(&other, &mut memo));
        assert!(b.verify(&other).is_err());
    }
    assert!(compared > 100, "only {compared} tampered bundles compared");
}
