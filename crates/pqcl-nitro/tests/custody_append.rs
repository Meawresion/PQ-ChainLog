//! M13 A18's acceptance, over a real socket: the custody append inside the
//! boundary.
//!
//! # Why a loopback socket and not a direct call
//!
//! vsock has no loopback on the development box, so the real transport cannot
//! run here. Everything above it can, and does: a TCP pair carries the framing
//! of [`pqcl_nitro::session`], the codec of [`pqcl_nitro::proto`] and
//! [`pqcl_nitro::appendwire`], the dispatch of [`pqcl_nitro::dispatch`], and
//! the module itself. What is untested locally is the socket type and the NSM,
//! which is why A18's clauses (a) and (d) need an enclave instance.
//!
//! The attester is [`pqcl_nitro::dispatch::no_nsm`], which imitates nothing:
//! `/dev/nsm` exists only inside an enclave, so that error *is* the correct
//! answer here, byte-for-byte what the real attester returns off-enclave.
//!
//! # ⚠️ What "verify byte-for-byte like host-built ones" can and cannot mean
//!
//! A18's clause (c) asks for it, and taken literally it is unachievable: a
//! record carries fresh `r_a` and `r_p`, so two runs over identical inputs
//! differ in `actor_c`, `params_c`, and therefore in every signature. Written
//! here as the strongest form that is true:
//!
//! * `rid`, `eid_e` and `h_prev` are **byte-identical**, because they do not
//!   depend on a blind;
//! * all 29 `Π_core` tokens are **byte-identical** to a host-built index at the
//!   same counters, which is the part clause (c) is really about — the index
//!   the server receives must not depend on which side built it;
//! * the sealed body opens under `K_rec^{eid}` to the same event, timestamp,
//!   link and note;
//! * `σ_actor` verifies under the enrolled actor's key, and `actor_c` opens
//!   under the returned opening.
//!
//! That the blinds differ is the design (M13 A2), so a test demanding equality
//! there would be demanding a defect.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use pqcl_capsule::{ActorOpening, ActorRef, Capsule, CustodyRecord, Event, Params, Role};
use pqcl_dsse::core::{Client as CoreClient, Op};
use pqcl_nitro::appendwire::append_request_bytes;
use pqcl_nitro::proto::{Request, Response};
use pqcl_nitro::session::exchange;
use pqcl_nitro::{dispatch, frame};
use pqcl_pipeline::handoff::OpenChain;
use pqcl_pipeline::{
    Agent, CUSTODY_KEYWORDS_PER_RECORD, CaseKeys, IngestParams, RecordParams, Signed,
    custody_keywords, record_signed_bytes,
};
use pqcl_primitives::sig::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, SoftwareMlDsa};
use pqcl_primitives::xof::{Digest32, PrfKey, digest256};
use pqcl_sm::append::{AppendRequest, AppendStep, Appended, SealRequest};
use pqcl_sm::{AgentModule, CustodyAppender, HostAgentModule};

/// The case every test here runs in. Fixed bytes, so a failure is reproducible.
fn case() -> (PrfKey, CaseKeys) {
    let k_mst = PrfKey::new(digest256(b"A18 test master key"));
    let keys = CaseKeys::derive(&k_mst, b"case-A18", &digest256(b"r_case"));
    (k_mst, keys)
}

const EID: Digest32 = [0x4e; 32];

/// A module with the full cast enrolled, and the agents again on the side so a
/// host-built comparison can use the *same* signing keys.
///
/// ⚠️ **Two `Agent`s cannot share one key** — [`SoftwareMlDsa`] is not `Clone`,
/// deliberately — so the host-side comparison uses its own keypair per role and
/// the tests compare the fields that do not depend on which key signed. Where a
/// signature must be checked, it is checked against the module's own
/// `actor_public_key`.
fn module(k_mst: PrfKey) -> HostAgentModule {
    // The enclave's own cast: `pqcl_sm::CAST`, by `(role, id)`, two custodians.
    let agents: Vec<Agent> = pqcl_sm::CAST
        .iter()
        .map(|(role, id)| Agent::new(SoftwareMlDsa::generate().expect("keygen"), id, *role))
        .collect();
    let mut agents = agents.into_iter();
    let defr = agents.next().expect("CAST opens with its first responder");
    HostAgentModule::new(k_mst, defr)
        .with_actors(agents.collect())
        .expect("the CAST enrols")
}

/// A real loopback socket pair — not an in-memory buffer — so framing is
/// exercised across an actual stream with its own buffering.
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    (client, server)
}

/// Run `requests` against a module across a socket, in order, on one session.
fn over_the_boundary(module: HostAgentModule, requests: &[Request]) -> Vec<Response> {
    let (mut client, mut server) = pair();
    let enclave = thread::spawn(move || {
        dispatch::serve_over(&module, &mut server, &dispatch::no_nsm);
    });

    let mut out = Vec::with_capacity(requests.len());
    for q in requests {
        out.push(exchange(&mut client, &q.encode()).expect("an answer"));
    }
    drop(client);
    enclave.join().expect("the serving thread");
    out
}

/// The one request every test starts from: open a capsule's chain.
fn collect_at(j: u64, ts: u64, epoch: u64) -> AppendRequest {
    let (_, keys) = case();
    AppendRequest {
        cid_c: keys.cid_c,
        capsule: EID.into(),
        actor: pqcl_sm::cast_member(Role::Defr),
        doc: 1,
        params: RecordParams::at(j, ts).in_epoch(epoch),
        step: AppendStep::Collect,
    }
}

fn appended(r: Response) -> Appended {
    match r {
        Response::Appended(a) => *a,
        other => panic!("expected an append, got {other:?}"),
    }
}

fn error(r: Response) -> String {
    match r {
        Response::Error(m) => m,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// A18 (c): the record and the index do not depend on which side built them.
// ---------------------------------------------------------------------------

#[test]
fn an_enclave_built_record_agrees_with_a_host_built_one_everywhere_a_blind_does_not_reach() {
    let (k_mst, keys) = case();
    let out = over_the_boundary(
        module(k_mst),
        &[Request::CustodyAppend(Box::new(collect_at(
            0,
            1_700_000_000,
            2,
        )))],
    );
    let a = appended(out.into_iter().next().expect("one answer"));

    // The host path, same inputs, its own DEFR key.
    let host_defr = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"defr-1",
        Role::Defr,
    );
    let host: Signed = host_defr
        .collect_record(&keys, EID, &RecordParams::at(0, 1_700_000_000).in_epoch(2))
        .expect("the host builds the same record");

    assert_eq!(
        a.signed.record.rid, host.record.rid,
        "rid is keyed, not blinded"
    );
    assert_eq!(
        a.signed.record.eid_e, host.record.eid_e,
        "the segment pseudonym"
    );
    assert_eq!(
        a.signed.record.h_prev, host.record.h_prev,
        "the segment's genesis link"
    );
    assert_eq!(a.signed.body.event, Event::Collect);
    assert_eq!(a.signed.body.ts, host.body.ts);
    assert_eq!(a.signed.body.link, host.body.link, "the true chain link");

    // ⭐ And the sealed body really is sealed under the case's own key: a court
    // holding `K_rec^{eid}` opens it to exactly what the module reported.
    let opened = a
        .signed
        .record
        .open_body(&keys.record_body_key(&EID))
        .expect("the body opens under K_rec^{eid}");
    assert_eq!(opened, a.signed.body, "the reported body is the sealed one");

    // The blinds differ, and must: that is M13 A2.
    assert_ne!(
        a.signed.actor.r_a, host.actor.r_a,
        "a fresh blind per record is the point"
    );
}

#[test]
fn the_twentynine_tokens_are_byte_identical_to_a_host_built_index() {
    let (k_mst, keys) = case();
    let out = over_the_boundary(
        module(k_mst),
        &[Request::CustodyAppend(Box::new(collect_at(
            0,
            1_700_000_000,
            2,
        )))],
    );
    let a = appended(out.into_iter().next().expect("one answer"));

    assert_eq!(a.tokens.len(), CUSTODY_KEYWORDS_PER_RECORD);

    // ⭐ The strong half of clause (c). `Π_core`'s tokens are deterministic in
    // (K_S, keyword, counter, op, id), and `K_S^COC` comes from `K_case` — so a
    // host-side client over the *enclave's own* keywords must reproduce them
    // exactly. If the module had derived `K_S^COC` differently, or indexed a
    // different keyword set, or advanced counters differently, this is where it
    // shows.
    let keywords = custody_keywords(&a.signed.record.eid_e, &a.signed.body, &a.signed.actor)
        .expect("the timestamp is inside the window");
    let mut host_index = CoreClient::new(keys.custody_index_key());
    let host_tokens: Vec<_> = keywords
        .iter()
        .map(|w| host_index.update(Op::Add, w, 1).expect("a token"))
        .collect();

    assert_eq!(
        a.tokens, host_tokens,
        "the index the server receives must not depend on which side built it"
    );
}

#[test]
fn sigma_actor_verifies_under_the_key_the_module_will_name_in_the_audit_package() {
    let (k_mst, keys) = case();
    let out = over_the_boundary(
        module(k_mst),
        &[
            Request::CustodyAppend(Box::new(collect_at(0, 1_700_000_000, 2))),
            Request::ActorPublicKey {
                actor: pqcl_sm::cast_member(Role::Defr),
            },
        ],
    );
    let mut out = out.into_iter();
    let a = appended(out.next().expect("the append"));
    let pk = match out.next().expect("the key") {
        Response::Bytes(b) => b,
        other => panic!("expected a key, got {other:?}"),
    };

    assert_eq!(pk.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
    // §1br F2: `σ_actor` is sealed inside `C_rec`; the case's key holder opens it.
    let o = a
        .signed
        .record
        .open(&keys.record_body_key(&EID))
        .expect("the record opens");
    pqcl_primitives::sig::verify(
        &record_signed_bytes(&a.signed.record, &o.body),
        &o.sigs.actor,
        &pk,
        b"",
    )
    .expect("σ_actor verifies under the enrolled DEFR's key");

    // And the opening really opens the commitment the record carries.
    let opening = ActorOpening {
        id: a.signed.actor.id.clone(),
        role: a.signed.actor.role,
        r_a: a.signed.actor.r_a,
    };
    assert_eq!(opening.commit(), a.signed.body.actor_c);
}

#[test]
fn the_defr_that_signs_a_capsule_is_the_one_that_opens_its_chain() {
    // ⭐ Structural since A18: the module has no DEFR key beside its cast, so
    // `sign_defr` and the `COLLECT`'s `σ_actor` cannot come from two keys.
    // This asserts the consequence a court would rely on.
    let (k_mst, _) = case();
    let m = module(k_mst);
    let from_the_capsule_path = m.defr_public_key().expect("the DEFR key");
    let from_the_cast = m
        .actor_public_key(&pqcl_sm::cast_member(Role::Defr))
        .expect("the DEFR actor");
    assert_eq!(from_the_capsule_path, from_the_cast);
}

// ---------------------------------------------------------------------------
// A18 (b) and the refusals the boundary adds.
// ---------------------------------------------------------------------------

#[test]
fn no_door_in_the_protocol_hands_out_a_signing_key() {
    // ⚠️ **Why this is a shape test and not a byte search.** The honest form
    // would be to search every response for the actor's secret-key bytes — but
    // a test cannot learn them: `SoftwareMlDsa` exposes no accessor and the
    // module stores no copy, which *is* the property. So what is checked is
    // every door in turn: the actor-key door returns a verification key of
    // exactly the public length, never the 4032-byte secret one; and
    // `TryExport` refuses. The compile-time half — that no response *variant*
    // can carry key material — is `proto`'s exhaustive match, which a derived
    // coverage test keeps honest.
    let (k_mst, _) = case();
    let out = over_the_boundary(
        module(k_mst),
        &[
            Request::ActorPublicKey {
                actor: pqcl_sm::cast_member(Role::Defr),
            },
            Request::ActorPublicKey {
                actor: pqcl_sm::cast_member(Role::Custodian),
            },
            Request::ActorPublicKey {
                actor: pqcl_sm::cast_member(Role::Des),
            },
            Request::ActorPublicKey {
                actor: pqcl_sm::cast_member(Role::Investigator),
            },
            Request::DefrPublicKey,
            Request::GenerateAes {
                label: "k".to_owned(),
            },
        ],
    );

    for r in &out[..5] {
        match r {
            Response::Bytes(b) => {
                assert_eq!(b.len(), ML_DSA_65_PUBLIC_KEY_BYTES, "a verification key");
                assert_ne!(b.len(), ML_DSA_65_SECRET_KEY_BYTES, "never a signing key");
            }
            other => panic!("expected a key, got {other:?}"),
        }
    }

    let handle = match &out[5] {
        Response::Handle(h) => *h,
        other => panic!("expected a handle, got {other:?}"),
    };
    let (k_mst, _) = case();
    let refused = over_the_boundary(
        module(k_mst),
        &[
            Request::TryExport { handle },
            // A handle nobody was given, for good measure.
            Request::TryExport { handle: 0xdead },
        ],
    );
    for r in refused {
        let _ = error(r);
    }
}

#[test]
fn a_role_that_may_not_sign_the_event_is_refused_across_the_boundary() {
    let (k_mst, keys) = case();
    // The DES may sign ANALYZE and nothing else; EXPORT is the custodian's.
    let previous = CustodyRecord {
        rid: [1; 32],
        eid_e: keys.epoch_pseudonym(&EID, 2),
        h_prev: [2; 32],
        body: vec![3; 96],
        order_ref: None,
    };
    let out = over_the_boundary(
        module(k_mst),
        &[Request::CustodyAppend(Box::new(AppendRequest {
            actor: pqcl_sm::cast_member(Role::Des),
            step: AppendStep::Append {
                event: Event::Export,
                previous: Box::new(previous),
            },
            params: RecordParams::at(1, 1_700_000_100)
                .with_params(Params::justified(b"hand over"))
                .in_epoch(2),
            ..collect_at(1, 1_700_000_100, 2)
        }))],
    );
    let m = error(out.into_iter().next().expect("one answer"));
    assert!(
        m.contains("may not sign"),
        "the refusal should name the table: {m}"
    );
}

#[test]
fn a_role_with_no_enrolled_actor_is_refused() {
    let (k_mst, keys) = case();
    let defr = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"defr-1",
        Role::Defr,
    );
    // Only a DEFR enrolled; an ANALYZE needs the DES.
    let m = HostAgentModule::new(k_mst, defr);
    let err = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: EID.into(),
            actor: pqcl_sm::cast_member(Role::Des),
            doc: 1,
            params: RecordParams::at(1, 1_700_000_000),
            step: AppendStep::Append {
                event: Event::Analyze,
                previous: Box::new(CustodyRecord {
                    rid: [1; 32],
                    eid_e: keys.epoch_pseudonym(&EID, 0),
                    h_prev: [2; 32],
                    body: vec![3; 96],
                    order_ref: None,
                }),
            },
        })
        .expect_err("no DES is enrolled");
    assert!(err.to_string().contains("no actor is enrolled"), "{err}");
}

#[test]
fn enrolment_is_by_role_and_id() {
    let (k_mst, _) = case();
    let agent = |id: &[u8], role| Agent::new(SoftwareMlDsa::generate().expect("keygen"), id, role);
    // `HostAgentModule` has no `Debug` — it holds keys — so each error is
    // taken out by hand rather than through `expect_err`.

    // Two custodians under different ids: enrolled, and each addressable.
    let Ok(m) =
        HostAgentModule::new(k_mst.clone(), agent(b"defr-1", Role::Defr)).with_actors(vec![
            agent(b"store", Role::Custodian),
            agent(b"lab", Role::Custodian),
        ])
    else {
        panic!("two custodians with distinct ids were refused");
    };
    let store = m
        .actor_public_key(&ActorRef::new(Role::Custodian, b"store"))
        .expect("store");
    let lab = m
        .actor_public_key(&ActorRef::new(Role::Custodian, b"lab"))
        .expect("lab");
    assert_ne!(store, lab, "two custodians, one key");
    assert_eq!(m.enrolled().len(), 3);
    assert!(
        m.actor_public_key(&ActorRef::new(Role::Custodian, b"nobody"))
            .is_err(),
        "an id never enrolled was answered"
    );

    // The same `(role, id)` twice: refused.
    let Err(err) =
        HostAgentModule::new(k_mst.clone(), agent(b"defr-1", Role::Defr)).with_actors(vec![
            agent(b"store", Role::Custodian),
            agent(b"store", Role::Custodian),
        ])
    else {
        panic!("one (role, id) was enrolled twice");
    };
    assert!(err.to_string().contains("enrolled once"), "{err}");

    // A second first responder: refused, because `σ_DEFR` and the `COLLECT`
    // that opens a chain must be one key.
    let Err(err) = HostAgentModule::new(k_mst, agent(b"defr-1", Role::Defr))
        .with_actors(vec![agent(b"defr-2", Role::Defr)])
    else {
        panic!("a second DEFR was enrolled");
    };
    assert!(err.to_string().contains("second first responder"), "{err}");
}

/// ⭐ **A receipt must be signed by the custodian the release named** (§1br.4).
/// The receiving opening is the lab custodian's; asking the evidence store to
/// sign the receipt under it is refused, where with one key per role it could
/// not even be expressed.
#[test]
fn a_receipt_signed_by_another_custodian_is_refused() {
    let (k_mst, keys) = case();
    let m = module(k_mst);
    let capsule = sealed_capsule(&keys);
    let collect = open_chain_for(&m, &keys, &capsule);
    let release = release_over(&m, &keys, &capsule, vec![collect.signed.record.clone()]);
    let err = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::evidence_store(),
            doc: 1,
            params: RecordParams::at(2, 1_700_000_200).in_epoch(2),
            step: AppendStep::Receipt {
                capsule: Box::new(capsule.clone()),
                chain: vec![collect.signed.record, release.signed.record],
                recomputed: capsule.d_ev,
                pairing: release.pairing.expect("a pairing"),
            },
        })
        .expect_err("the evidence store signed the lab's receipt");
    assert!(err.to_string().contains("another actor"), "{err}");
}

/// ⭐ The property the boundary buys that the host path cannot: `j` fixes
/// `rid`, whose prefix is the record body's AES-GCM nonce under a per-capsule
/// key (§1br F1), so two records at one
/// position are the same key and the same nonce over different plaintext.
///
/// The host path is shown accepting exactly that, so the test records what is
/// **gained** rather than only asserting a refusal.
#[test]
fn a_position_already_signed_is_refused_by_the_module_and_not_by_the_host_path() {
    let (k_mst, keys) = case();
    let m = module(k_mst);

    let first = m
        .custody_append(&collect_at(0, 1_700_000_000, 2))
        .expect("the opening record");
    let again = m
        .custody_append(&collect_at(0, 1_700_000_001, 2))
        .expect_err("position 0 was already signed");
    assert!(again.to_string().contains("already signed"), "{again}");

    // The host path has no such guard, and the consequence is visible: two
    // bodies, one key, one nonce.
    let host_defr = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"defr-1",
        Role::Defr,
    );
    let a = host_defr
        .collect_record(&keys, EID, &RecordParams::at(0, 1_700_000_000))
        .expect("first");
    let b = host_defr
        .collect_record(&keys, EID, &RecordParams::at(0, 1_700_000_001))
        .expect("the host path signs a second record at position 0");
    assert_eq!(a.record.rid, b.record.rid, "same position, same rid");
    assert_ne!(
        a.record.body, b.record.body,
        "two different plaintexts under one key and one nonce"
    );

    // And a later position is accepted, so the guard is a guard and not a wall.
    let (_, keys2) = case();
    m.custody_append(&AppendRequest {
        cid_c: keys2.cid_c,
        capsule: EID.into(),
        actor: pqcl_sm::cast_member(Role::Custodian),
        doc: 1,
        params: RecordParams::at(1, 1_700_000_200)
            .with_params(Params::justified(b"sealed"))
            .in_epoch(2),
        step: AppendStep::Append {
            event: Event::Seal,
            previous: Box::new(first.signed.record),
        },
    })
    .expect("position 1 follows position 0");
}

#[test]
fn a_malformed_request_is_answered_and_the_session_continues() {
    let (k_mst, _) = case();
    let m = module(k_mst);
    let (mut client, mut server) = pair();
    let enclave = thread::spawn(move || {
        dispatch::serve_over(&m, &mut server, &dispatch::no_nsm);
    });

    // Junk, then a real request on the same session.
    client
        .write_all(&frame(&[0xee, 0x01, 0x02]))
        .expect("write");
    client.flush().expect("flush");
    let mut len = [0u8; 4];
    client.read_exact(&mut len).expect("a reply length");
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    client.read_exact(&mut buf).expect("a reply");
    let m = error(Response::decode(&buf).expect("a response"));
    assert!(m.contains("malformed request"), "{m}");

    let good = exchange(&mut client, &Request::Enrolled.encode()).expect("still serving");
    match good {
        Response::Actors(a) => assert_eq!(a.len(), pqcl_sm::CAST.len(), "the whole cast"),
        other => panic!("expected roles, got {other:?}"),
    }
    drop(client);
    enclave.join().expect("the serving thread");
}

#[test]
fn an_attestation_request_off_enclave_says_so_rather_than_pretending() {
    let (k_mst, _) = case();
    let out = over_the_boundary(
        module(k_mst),
        &[Request::Attest {
            nonce: vec![1, 2, 3],
        }],
    );
    let m = error(out.into_iter().next().expect("one answer"));
    assert!(m.contains("not running inside a Nitro"), "{m}");
}

#[test]
fn the_wire_form_of_an_append_round_trips_through_the_whole_stack() {
    // The codec is unit-tested in `proto`; this checks the same bytes survive a
    // real socket, where short reads and buffering are in play.
    let q = collect_at(3, 1_700_000_000, 7);
    let bytes = append_request_bytes(&q);
    let back = pqcl_nitro::appendwire::read_append_request(&bytes).expect("decodes");
    assert_eq!(back, q);

    let (k_mst, _) = case();
    let out = over_the_boundary(module(k_mst), &[Request::CustodyAppend(Box::new(q))]);
    let a = appended(out.into_iter().next().expect("one answer"));
    // `j` was 3, but a Collect is position 0 whatever the caller said.
    let (_, keys) = case();
    assert_eq!(
        a.signed.record.rid,
        CustodyRecord::derive_rid(&keys.record_id_key(&EID), 0),
        "the opening record is position zero by definition"
    );
}

// ---------------------------------------------------------------------------
// A14 inside the boundary: both halves of a bilateral transfer.
// ---------------------------------------------------------------------------

/// A capsule the module can open a chain against. Sealed by a real `Agent`, so
/// the commitments are genuine — the transfer re-checks `d_ev` against this.
fn sealed_capsule(keys: &CaseKeys) -> Capsule {
    let defr = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"defr-1",
        Role::Defr,
    );
    defr.seal(
        keys,
        digest256(b"cm_ev"),
        &IngestParams {
            nonce: &digest256(b"nonce-1"),
            epoch: 2,
            artefact_type: b"disk-image",
            d_ev: digest256(b"d_ev"),
            ptr: b"s3://bucket/key",
        },
    )
    .expect("a sealed capsule")
}

fn open_chain_for(m: &HostAgentModule, keys: &CaseKeys, capsule: &Capsule) -> Appended {
    m.custody_append(&AppendRequest {
        cid_c: keys.cid_c,
        capsule: capsule.eid.into(),
        actor: pqcl_sm::cast_member(Role::Defr),
        doc: 1,
        params: RecordParams::at(0, 1_700_000_000).in_epoch(2),
        step: AppendStep::Collect,
    })
    .expect("the chain opens")
}

/// The releasing half, over a chain the caller supplies.
fn release_over(
    m: &HostAgentModule,
    keys: &CaseKeys,
    capsule: &Capsule,
    chain: Vec<CustodyRecord>,
) -> Appended {
    m.custody_append(&AppendRequest {
        cid_c: keys.cid_c,
        capsule: capsule.eid.into(),
        actor: pqcl_sm::cast_member(Role::Defr),
        doc: 1,
        params: RecordParams::at(1, 1_700_000_100).in_epoch(2),
        step: AppendStep::Release {
            capsule: Box::new(capsule.clone()),
            chain,
            cond: digest256(b"cond"),
            witness: pqcl_sm::lab_custodian(),
        },
    })
    .expect("the releasing half")
}

/// Both halves of a bilateral transfer, released and received by the module,
/// with the parent holding no body key and never seeing the receiver's blind.
///
/// This is A14's protocol run end to end behind the boundary: the module
/// commits the receiver, builds `D` over it, signs the release, counter-signs it
/// as the witness, remembers the pending handoff, and then pairs the receipt
/// against it — none of the descriptor's inputs and neither blind leaving.
#[test]
fn a_bilateral_transfer_completes_with_both_halves_built_inside_the_boundary() {
    let (k_mst, keys) = case();
    let m = module(k_mst);
    let capsule = sealed_capsule(&keys);
    let eid = capsule.eid;

    let collect = open_chain_for(&m, &keys, &capsule);
    let release = release_over(&m, &keys, &capsule, vec![collect.signed.record.clone()]);
    // ⭐ The descriptor comes back out rather than being remembered inside, so
    // the module is stateless across a transfer — a release written before an
    // enclave restart can still be received after it. Safe because
    // `handoff::receive` verifies the release against whatever handoff it is
    // handed, over a record the parent cannot forge.
    let pending = release
        .pairing
        .clone()
        .expect("a release answers with its pairing");

    // The release leaves the boundary already witnessed, because the receipt's
    // link covers the Tier-1 leaf that signature sits inside, and since §1br
    // F2 the signature is inside `C_rec`, sealed with the release.
    let o = release
        .signed
        .record
        .open(&keys.record_body_key(&eid))
        .expect("the release opens");
    pqcl_primitives::sig::verify(
        &record_signed_bytes(&release.signed.record, &o.body),
        o.sigs
            .witness
            .as_deref()
            .expect("the release must be counter-signed before it is chained"),
        &m.actor_public_key(&pqcl_sm::lab_custodian())
            .expect("the witnessing custodian"),
        b"",
    )
    .expect("σ_witness verifies under the witnessing custodian's key");
    assert_eq!(release.signed.body.event, Event::Transfer);

    let receipt = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: eid.into(),
            actor: pqcl_sm::lab_custodian(),
            doc: 1,
            params: RecordParams::at(2, 1_700_000_200).in_epoch(2),
            step: AppendStep::Receipt {
                capsule: Box::new(capsule.clone()),
                chain: vec![collect.signed.record.clone(), release.signed.record.clone()],
                // The parent re-hashes the stored object; the module checks the
                // result against the anchored `d_ev`.
                recomputed: capsule.d_ev,
                pairing: pending,
            },
        })
        .expect("the receiving half");

    // The two halves carry the same descriptor, which is what pairs them.
    assert_eq!(
        release.signed.body.params_c, receipt.signed.body.params_c,
        "a release and its receipt are one transfer because they share D"
    );
    // And `in_transit` sees a completed transfer, not an unmatched release.
    let chain = [
        collect.signed.record,
        release.signed.record,
        receipt.signed.record,
    ];
    let opened = OpenChain::open(&chain, &keys.record_body_key(&eid)).expect("the chain opens");
    assert!(
        pqcl_pipeline::handoff::in_transit(&opened).is_empty(),
        "the transfer completed, so nothing is in transit"
    );
}

/// ⭐ A receipt over a record that is not a release of **this** handoff is
/// refused — which is what makes handing the descriptor back out safe.
///
/// The module keeps no pending state, so the only thing standing between a
/// parent and a mispaired transfer is `handoff::receive`'s own check that the
/// release's `params_c` equals the descriptor. This drives exactly that: a
/// well-formed handoff that the release was not signed over.
#[test]
fn a_receipt_whose_handoff_is_not_the_one_the_release_was_signed_over_is_refused() {
    let (k_mst, keys) = case();
    let m = module(k_mst);
    let capsule = sealed_capsule(&keys);
    let collect = open_chain_for(&m, &keys, &capsule);
    let release = release_over(&m, &keys, &capsule, vec![collect.signed.record.clone()]);
    let pending = release.pairing.clone().expect("the pairing");

    // One field changed: the conditions. `D` moves, so the release no longer
    // matches it.
    let mut substituted = pending.clone();
    substituted.handoff.cond = digest256(b"different conditions");

    let err = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::cast_member(Role::Custodian),
            doc: 1,
            params: RecordParams::at(2, 1_700_000_200).in_epoch(2),
            step: AppendStep::Receipt {
                capsule: Box::new(capsule.clone()),
                chain: vec![collect.signed.record, release.signed.record],
                recomputed: capsule.d_ev,
                pairing: substituted,
            },
        })
        .expect_err("the release was not signed over this descriptor");
    let text = err.to_string();
    assert!(
        text.contains("not a release") || text.contains("NotARelease"),
        "the refusal should name the pairing check: {text}"
    );
}

/// The receipt's integrity check is real: a recomputed digest that no longer
/// matches the anchor is refused, which is what makes a handoff a check rather
/// than a formality.
#[test]
fn a_receipt_whose_recomputed_digest_does_not_match_the_anchor_is_refused() {
    let (k_mst, keys) = case();
    let m = module(k_mst);
    let capsule = sealed_capsule(&keys);

    let collect = open_chain_for(&m, &keys, &capsule);
    let release = release_over(&m, &keys, &capsule, vec![collect.signed.record.clone()]);
    let pending = release.pairing.clone().expect("the pairing");

    let err = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::cast_member(Role::Custodian),
            doc: 1,
            params: RecordParams::at(2, 1_700_000_200).in_epoch(2),
            step: AppendStep::Receipt {
                capsule: Box::new(capsule.clone()),
                chain: vec![collect.signed.record, release.signed.record],
                recomputed: digest256(b"a different artefact"),
                pairing: pending,
            },
        })
        .expect_err("the ciphertext no longer matches the anchor");
    let text = err.to_string();
    assert!(
        text.contains("no longer matches")
            || text.contains("mismatch")
            || text.contains("ntegrity"),
        "the refusal should name the integrity check: {text}"
    );
}

/// The trait both backends implement, exercised through `dyn` so a harness
/// provably cannot tell which it holds (A18 clause (d)).
#[test]
fn a_harness_holding_the_trait_cannot_tell_which_backend_it_has() {
    let (k_mst, keys) = case();
    let m = module(k_mst);
    let appender: &dyn CustodyAppender = &m;

    assert_eq!(
        appender.backend(),
        pqcl_sm::Backend::HostSoftware,
        "locally it is the unpublishable one, and it says so"
    );
    assert!(
        !appender.backend().is_publishable(),
        "a host-software number must never reach the paper"
    );
    let a = appender
        .append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: EID.into(),
            actor: pqcl_sm::cast_member(Role::Defr),
            doc: 1,
            params: RecordParams::at(0, 1_700_000_000),
            step: AppendStep::Collect,
        })
        .expect("the chain opens through the trait");
    assert_eq!(a.tokens.len(), CUSTODY_KEYWORDS_PER_RECORD);
    assert_eq!(
        appender
            .verification_key(&pqcl_sm::cast_member(Role::Defr))
            .expect("the DEFR key")
            .len(),
        ML_DSA_65_PUBLIC_KEY_BYTES
    );
}

/// ⭐ A capsule sealed through the boundary and the `COLLECT` that opens its
/// chain are signed by **one** key — the case can no longer name two first
/// responders.
///
/// Before sealing moved into the appender, a harness appending through the
/// enclave sealed capsules with a DEFR key of its own. Both signatures verified
/// and named different responders. This seals and opens over a real socket and
/// checks both against the single key the module reports.
#[test]
fn a_capsule_sealed_across_the_boundary_names_the_responder_that_opens_its_chain() {
    let (k_mst, keys) = case();
    let seal = SealRequest {
        cid_c: keys.cid_c,
        cm_ev: digest256(b"cm_ev"),
        nonce: digest256(b"nonce-seal"),
        epoch: 2,
        artefact_type: b"disk-image".to_vec(),
        d_ev: digest256(b"d_ev"),
        ptr: b"s3://bucket/key".to_vec(),
    };
    let out = over_the_boundary(
        module(k_mst),
        &[
            Request::SealCapsule(Box::new(seal.clone())),
            Request::DefrPublicKey,
        ],
    );
    let mut out = out.into_iter();
    let capsule = match out.next().expect("the seal") {
        Response::Capsule(c) => *c,
        other => panic!("expected a capsule, got {other:?}"),
    };
    let defr_pk = match out.next().expect("the key") {
        Response::Bytes(b) => b,
        other => panic!("expected a key, got {other:?}"),
    };

    // The pseudonym is the one the case keys derive, so the module used the
    // case it was named and not some other.
    assert_eq!(
        capsule.eid,
        pqcl_primitives::xof::prf(
            &keys.k_case,
            pqcl_primitives::xof::Label::Eid,
            &[&seal.nonce]
        ),
        "eid = F(K_case, eid || nonce), derived inside the boundary"
    );
    assert_eq!(capsule.cid_c, keys.cid_c);

    pqcl_primitives::sig::verify(
        &pqcl_pipeline::capsule_signed_bytes(&capsule),
        &capsule.sig_defr,
        &defr_pk,
        b"",
    )
    .expect("σ_DEFR verifies under the module's DEFR key");

    // And the record that opens the chain, from a module built over the same
    // master key — the same key again, because the first responder is one
    // enrolled actor and not a second field.
    let (k_mst, _) = case();
    let m = module(k_mst);
    let opened = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::cast_member(Role::Defr),
            doc: 1,
            params: RecordParams::at(0, 1_700_000_000).in_epoch(2),
            step: AppendStep::Collect,
        })
        .expect("the chain opens");
    let collect_pk = m
        .actor_public_key(&pqcl_sm::cast_member(Role::Defr))
        .expect("the DEFR");
    assert_eq!(
        collect_pk,
        m.defr_public_key().expect("the DEFR key"),
        "one key signs the capsule and opens its chain"
    );
    let o = opened
        .signed
        .record
        .open(&keys.record_body_key(&capsule.eid))
        .expect("the COLLECT opens");
    pqcl_primitives::sig::verify(
        &record_signed_bytes(&opened.signed.record, &o.body),
        &o.sigs.actor,
        &collect_pk,
        b"",
    )
    .expect("the COLLECT verifies under the same key");
}

/// ⭐ **The position guard cannot be walked around through a release.**
///
/// `handoff::release` signs at the chain's length; the guard reads the
/// request's `j`. This is the attack that mismatch allowed. The chain holds
/// positions 0 and 1, so the guard's maximum is 1. A parent pads the chain with
/// a repeat of a genuine record (it decrypts, so `OpenChain` accepts it) and
/// claims position 2. The release would be signed at 3, the guard would record
/// 2, and a later append at 3 would pass the guard and reuse that nonce under
/// the capsule's key. The release must be refused.
#[test]
fn a_release_whose_position_disagrees_with_its_chain_is_refused() {
    let (k_mst, keys) = case();
    let m = module(k_mst);
    let capsule = sealed_capsule(&keys);
    let collect = open_chain_for(&m, &keys, &capsule);
    let seal = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::cast_member(Role::Custodian),
            doc: 1,
            params: RecordParams::at(1, 1_700_000_050)
                .with_params(Params::justified(b"bagged"))
                .in_epoch(2),
            step: AppendStep::Append {
                event: Event::Seal,
                previous: Box::new(collect.signed.record.clone()),
            },
        })
        .expect("position 1");

    // Claim 2 — above the guard's maximum of 1, so the guard passes it — over a
    // padded chain of three, where the release would actually be signed at 3.
    let err = m
        .custody_append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::cast_member(Role::Custodian),
            doc: 1,
            params: RecordParams::at(2, 1_700_000_100).in_epoch(2),
            step: AppendStep::Release {
                capsule: Box::new(capsule.clone()),
                chain: vec![
                    collect.signed.record,
                    seal.signed.record.clone(),
                    seal.signed.record,
                ],
                cond: digest256(b"cond"),
                witness: pqcl_sm::lab_custodian(),
            },
        })
        .expect_err("a release claiming a position its chain does not have");
    assert!(err.to_string().contains("is at position 3"), "{err}");
}
