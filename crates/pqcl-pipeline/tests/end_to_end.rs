//! M8's acceptance, executed.
//!
//! The build plan:
//!
//! > *Accept:* ingest real disk images / memory dumps / PCAPs; run real
//! > forensic tooling; query across both planes; produce a court-disclosure
//! > bundle; auditor verifies it from public data alone.
//!
//! ⛔ **These tests do not skip.** A missing artefact or a missing container is
//! a loud failure naming the command that fixes it, never a silent pass — the
//! same rule `pqcl-sm`'s PKCS#11 suite follows, and for the same reason: an
//! acceptance test that quietly does nothing reports green forever.
//!
//! Each artefact type gets its own test so a partially-fetched corpus fails
//! precisely, rather than one monolith failing on whichever file is missing.

// A test asserts by failing loudly, so the lints that forbid panicking in
// library code are off here — the same allowance every other test file in this
// workspace carries.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pqcl_capsule::{Bundle, Event, Params, Role};
use pqcl_dsse::{Client, Edb, HonestEdb, Op};
use pqcl_pipeline::forensics::Forensics;
use pqcl_pipeline::{
    Agent, Ais, CaseKeys, IngestParams, RecordParams, ToolRun, capsule_signed_bytes, chunked,
    record_signed_bytes,
};
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, digest256};
use pqcl_primitives::{SoftwareMlDsa, sig};

// --------------------------------------------------------------- fixtures

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/pqcl-pipeline.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> has two ancestors")
        .to_path_buf()
}

fn artefact_dir() -> PathBuf {
    repo_root().join("datasets/artefacts")
}

fn require_artefact(name: &str) -> PathBuf {
    let p = artefact_dir().join(name);
    assert!(
        p.exists(),
        "missing real artefact {name}.\n\
         Run:  sh datasets/fetch-artefacts.sh\n\
         These tests do not skip: §8 requires real artefacts, and a generated \
         one would have nothing for a forensic tool to find."
    );
    p
}

fn forensics() -> Forensics {
    let runner = repo_root().join("forensics/run.sh");
    Forensics::new(&runner, &artefact_dir()).unwrap_or_else(|e| {
        panic!(
            "the pinned forensic container is unavailable: {e}\n\
             Run:  forensics/run.sh --build\n\
             These tests do not skip: ground rule #1 forbids standing in for a \
             tool that did not run."
        )
    })
}

fn case_keys() -> CaseKeys {
    CaseKeys::derive(
        &PrfKey::new(digest256(b"k_mst for the M8 acceptance run")),
        b"CASE-2026-0912",
        &digest256(b"r_case"),
    )
}

/// One artefact, ingested and carried through the whole loop.
struct Run {
    ais: Ais,
    /// The case keys. Held because a disclosure bundle cannot be assembled
    /// without them from M13 A20 on — the AIS does not know which segments
    /// belong to one capsule.
    keys: CaseKeys,
    /// The specialist's key, since M13 A2 split the roles: the DEFR signs the
    /// opening record and the DES signs each tool run.
    des_pk: Vec<u8>,
    epoch_root: Digest32,
    agent_pk: Vec<u8>,
    capsule_index: usize,
    tool_runs: Vec<ToolRun>,
}

/// Ingest one real artefact, run real tools over it, anchor, and return the
/// state an auditor would be handed.
fn pipeline(artefact: &str, artefact_type: &[u8], tools: &[(&str, Vec<String>)]) -> Run {
    let path = require_artefact(artefact);
    let f = forensics();
    let keys = case_keys();
    // One agent per role (M13 A2): the DEFR collects, the DES runs the tools.
    let defr = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"first-responder-1",
        Role::Defr,
    );
    let des = Agent::new(
        SoftwareMlDsa::generate().expect("keygen"),
        b"specialist-1",
        Role::Des,
    );

    // `d_ev` binds the stored object. Sealing is the storage layer's job, so
    // this run digests the same bytes under the ciphertext domain — the split
    // that matters for the test is that the two commitments are distinct and
    // both anchored.
    let d_ev = chunked::digest_file(&path, Domain::EvidenceDigest)
        .expect("the artefact is readable")
        .root()
        .to_owned();

    let ptr = format!("file://{artefact}");
    let nonce = digest256(artefact.as_bytes());
    let (capsule, plaintext) = defr
        .ingest(
            &keys,
            &path,
            &IngestParams {
                artefact_type,
                d_ev,
                ptr: ptr.as_bytes(),
                epoch: 9,
                nonce: &nonce,
            },
        )
        .expect("ingest");

    assert!(
        plaintext.chunks.chunk_count() >= 1,
        "a real artefact must produce at least one chunk"
    );
    assert_ne!(
        capsule.d_ev, capsule.cm_ev,
        "the ciphertext digest and the plaintext commitment must be distinct commitments"
    );

    let first = defr
        .collect_record(
            &keys,
            &capsule,
            &RecordParams::at(0, 1_757_000_000).with_params(Params::justified(b"acquisition")),
        )
        .expect("collect record")
        .record;

    let mut ais = Ais::new();
    ais.accept(capsule.clone(), first.clone());

    // Real tool runs, each producing one custody record whose `params_c`
    // commits to the version the binary actually reported.
    let mut previous = first;
    let mut tool_runs = Vec::new();
    for (i, (tool, args)) in tools.iter().enumerate() {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = f
            .run(tool, &argv)
            .unwrap_or_else(|e| panic!("{tool} failed on {artefact}: {e}"));

        assert!(
            !run.stdout.is_empty(),
            "{tool} produced no output on {artefact}; the custody record would \
             document work that did nothing"
        );

        let record = des
            .append_record(
                &keys,
                &capsule,
                Event::Analyze,
                &previous,
                // `j = i + 1`: the opening COLLECT is position 0. The act is
                // the tool run itself; the agent blinds it (M13 A2).
                &RecordParams::at(i as u64 + 1, 1_757_000_100 + i as u64)
                    .with_params(run.params(b"court-ordered examination")),
            )
            .expect("analyze record")
            .record;

        ais.append(record.clone());
        previous = record;
        tool_runs.push(run);
    }

    let epoch_root = ais.close_epoch();

    Run {
        ais,
        keys,
        epoch_root,
        agent_pk: defr.public_key().to_vec(),
        des_pk: des.public_key().to_vec(),
        capsule_index: 0,
        tool_runs,
    }
}

/// Everything an auditor is allowed: the bundle, the anchored epoch root, and
/// the agent's public key. No case key, no index key, no server state.
fn audit(run: &Run) -> Bundle {
    // ⚠️ **Assembling the bundle needs a key, since M13 A20** — the capsule's
    // segments are filed under per-epoch pseudonyms only the lab can derive.
    // Checking it still needs none, which is the half that matters: everything
    // below runs on the bundle and the anchored root alone.
    let bundle = run
        .ais
        .disclose(run.capsule_index, &run.keys)
        .expect("the epoch is closed, so a bundle exists");

    bundle
        .verify(&[(0, run.epoch_root)])
        .expect("the bundle must verify against the anchored root alone");

    // Signatures are checked separately from the structure: `Bundle::verify`
    // establishes linkage and inclusion, not authorship.
    sig::verify(
        &capsule_signed_bytes(&bundle.capsule),
        &bundle.capsule.sig_defr,
        &run.agent_pk,
        &[],
    )
    .expect("sigma_DEFR must verify under the agent's key");

    // The opening record is the DEFR's; every tool run is the DES's. A single
    // key would have verified both before A2, which is exactly the "presence,
    // not responsibility" the role table removes.
    //
    // §1br F2: `σ_actor` is inside `C_rec`, so the court opens the bundle
    // before it can check who signed.
    let opened = bundle.open().expect("the court opens it");
    for (i, (r, o)) in bundle.records().zip(&opened).enumerate() {
        let pk = if i == 0 { &run.agent_pk } else { &run.des_pk };
        sig::verify(&record_signed_bytes(r, &o.body), &o.sigs.actor, pk, &[])
            .expect("sigma_actor must verify under its signer's key");
    }

    bundle
}

// ------------------------------------------------- the three artefact types

/// A real `EnCase` disk image: a Canon `PowerShot` card with a FAT12 filesystem.
/// `mmls` reads its partition table and `fls` lists its real files.
#[test]
fn the_full_pipeline_over_a_real_disk_image() {
    let image = "nps-2009-canon2-gen6.E01";
    let run = pipeline(
        image,
        b"disk-image",
        &[
            ("ewfinfo", vec![image.to_owned()]),
            ("mmls", vec![image.to_owned()]),
            // The FAT12 filesystem starts at sector 51; `mmls` above is what
            // says so. Without the offset TSK reads the container and reports
            // "possible encryption detected".
            (
                "fls",
                vec![
                    "-o".to_owned(),
                    "51".to_owned(),
                    "-r".to_owned(),
                    image.to_owned(),
                ],
            ),
        ],
    );

    let listing = String::from_utf8_lossy(&run.tool_runs[2].stdout);
    assert!(
        listing.contains("DCIM") && listing.contains(".JPG"),
        "fls did not find the camera's real files; the run is not what it claims"
    );

    let bundle = audit(&run);
    assert_eq!(bundle.record_count(), 4, "collect + three tool runs");
    // The event lives in `C_rec` from M13 A1 on, so reading it is a key
    // holder's operation — which a court holding the disclosure bundle is.
    // `open` is that operation for the whole bundle: it decrypts every body
    // and checks the cross-segment links and the committed positions as it
    // goes (M13 A20).
    let bodies = bundle.open().expect("the court opens it");
    assert_eq!(bodies[0].body.event, Event::Collect);
}

/// A real packet capture. `tshark` dissects it.
#[test]
fn the_full_pipeline_over_a_real_pcap() {
    let pcap = "multifile_25_21.pcap";
    let run = pipeline(
        pcap,
        b"pcap",
        &[(
            "tshark",
            vec![
                "-r".to_owned(),
                pcap.to_owned(),
                "-q".to_owned(),
                "-z".to_owned(),
                "io,phs".to_owned(),
            ],
        )],
    );

    let phs = String::from_utf8_lossy(&run.tool_runs[0].stdout);
    assert!(
        phs.contains("eth") || phs.contains("ip"),
        "tshark produced no protocol hierarchy; the capture was not dissected"
    );

    let bundle = audit(&run);
    assert_eq!(bundle.record_count(), 2, "collect + one tool run");
}

/// A real Windows RAM capture from the M57-Patents scenario. Volatility 3
/// enumerates its real processes.
#[test]
fn the_full_pipeline_over_a_real_memory_dump() {
    let dump = "charlie-2009-12-03.mddramimage";
    let run = pipeline(
        dump,
        b"memdump",
        &[(
            "vol",
            vec!["-f".to_owned(), dump.to_owned(), "windows.info".to_owned()],
        )],
    );

    let info = String::from_utf8_lossy(&run.tool_runs[0].stdout);
    assert!(
        info.contains("Kernel") || info.contains("NtMajorVersion"),
        "volatility did not identify a kernel; the dump was not analysed"
    );

    audit(&run);
}

// ------------------------------------------------------- the other criteria

/// ⭐ **Query across both planes, joined on the client.**
///
/// Design §6c′ is emphatic that the join is never server-side: a server that
/// can join the planes can answer "which artefacts did this investigator
/// touch", which is precisely the question the two-plane split exists to make
/// unanswerable. So the two indices are separately keyed, queried separately,
/// and intersected here.
#[test]
fn a_cross_plane_query_is_joined_on_the_client() {
    let keys = case_keys();

    // Two DSSE instances, two keys. Deriving both from `K_case` under distinct
    // labels is what makes a trapdoor for one plane useless against the other.
    let mut evidence = Client::new(PrfKey::new(digest256(b"K_S evidence")));
    let mut custody = Client::new(PrfKey::new(digest256(b"K_S custody")));
    let mut evidence_edb = HonestEdb::new();
    let mut custody_edb = HonestEdb::new();

    // Capsule 1 is a disk image an analyst ANALYZEd; capsule 2 is a pcap nobody
    // analysed; capsule 3 is a disk image nobody analysed.
    for (id, ty) in [(1u64, "disk-image"), (2, "pcap"), (3, "disk-image")] {
        evidence_edb.insert(&evidence.update(Op::Add, ty.as_bytes(), id).expect("update"));
    }
    custody_edb.insert(&custody.update(Op::Add, b"ANALYZE", 1).expect("update"));
    custody_edb.insert(&custody.update(Op::Add, b"COLLECT", 2).expect("update"));

    let hits = |c: &Client, edb: &HonestEdb, w: &[u8]| -> BTreeSet<u64> {
        c.search_token(w).map_or_else(BTreeSet::new, |t| {
            c.finish(w, &t, &edb.search(&t)).expect("honest server")
        })
    };

    let disk_images = hits(&evidence, &evidence_edb, b"disk-image");
    let analysed = hits(&custody, &custody_edb, b"ANALYZE");

    assert_eq!(disk_images, BTreeSet::from([1, 3]));
    assert_eq!(analysed, BTreeSet::from([1]));

    // The join. Neither server saw this intersection, and neither could have
    // computed it: each holds one plane's index and no key for the other.
    let joined: BTreeSet<u64> = disk_images.intersection(&analysed).copied().collect();
    assert_eq!(
        joined,
        BTreeSet::from([1]),
        "only capsule 1 is both a disk image and analysed"
    );

    // A custody trapdoor must be meaningless against the evidence index. This
    // is the keyspace-disjointness property, checked rather than assumed.
    //
    // The assertion is on what the *client* can recover, not on whether the
    // server returned bytes: the server will happily answer any token, so
    // "the response was empty" would be a weaker claim than the one that
    // matters. Either the addresses miss, or the AEAD fails to open — both are
    // "recovers nothing", and neither may yield a document identifier.
    let custody_token = custody.search_token(b"ANALYZE").expect("token");
    let cross = custody.finish(
        b"ANALYZE",
        &custody_token,
        &evidence_edb.search(&custody_token),
    );
    let recovered_nothing = match &cross {
        // Addresses missed, or nothing decrypted to a live identifier.
        Ok(ids) => ids.is_empty(),
        // The AEAD refused to open, which is the same conclusion reached
        // earlier: the trapdoor is meaningless here.
        Err(_) => true,
    };
    assert!(
        recovered_nothing,
        "a custody trapdoor recovered {cross:?} from the evidence plane"
    );

    let _ = keys;
}

/// ⭐ **A disclosure bundle reveals one capsule and nothing else.**
///
/// The point of Tier 1: a court gets one capsule's complete history without
/// learning how many other capsules the case holds or how active they were.
/// Asserting this over the bundle's *bytes* rather than its fields is what
/// makes it a real check — a field-level assertion would miss a leak in the
/// encoding.
#[test]
fn a_bundle_carries_nothing_about_other_capsules() {
    let image = "nps-2009-canon2-gen6.E01";
    let f = forensics();
    let keys = case_keys();
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
    let path = require_artefact(image);

    let d_ev = chunked::digest_file(&path, Domain::EvidenceDigest)
        .expect("readable")
        .root()
        .to_owned();

    let mut ais = Ais::new();
    let mut capsules = Vec::new();

    // Three capsules in one case, with different chain lengths so a leak of
    // "activity shape" would be visible.
    for (n, extra) in [(0usize, 0usize), (1, 2), (2, 5)] {
        let ptr = format!("file://obj-{n}");
        let nonce = digest256(format!("nonce-{n}").as_bytes());
        let (capsule, _) = defr
            .ingest(
                &keys,
                &path,
                &IngestParams {
                    artefact_type: b"disk-image",
                    d_ev,
                    ptr: ptr.as_bytes(),
                    epoch: 9,
                    nonce: &nonce,
                },
            )
            .expect("ingest");

        let first = defr
            .collect_record(
                &keys,
                &capsule,
                &RecordParams::at(0, 1_757_000_000).with_params(Params::justified(b"on-scene")),
            )
            .expect("collect")
            .record;
        ais.accept(capsule.clone(), first.clone());

        let mut previous = first;
        for j in 0..extra {
            let r = inv
                .append_record(
                    &keys,
                    &capsule,
                    Event::Access,
                    &previous,
                    // `j + 1`: the opening COLLECT is position 0.
                    &RecordParams::at(j as u64 + 1, 1_757_000_500 + j as u64)
                        .with_params(Params::justified(b"review")),
                )
                .expect("access")
                .record;
            ais.append(r.clone());
            previous = r;
        }
        capsules.push(capsule);
    }

    let epoch_root = ais.close_epoch();
    let bundle = ais.disclose(1, &keys).expect("bundle");
    bundle
        .verify(&[(0, epoch_root)])
        .expect("verifies standalone");

    let bytes = bundle.encode();
    for (n, other) in capsules.iter().enumerate() {
        if n == 1 {
            continue;
        }
        assert!(
            !contains(&bytes, &other.eid),
            "the bundle leaks capsule {n}'s eid"
        );
        assert!(
            !contains(&bytes, other.ptr.as_slice()),
            "the bundle leaks capsule {n}'s storage pointer"
        );
    }

    // A real tool run is not needed for this property, but the container must
    // still be the one under test — otherwise this test would pass in an
    // environment where nothing else can.
    assert!(f.version_of("sleuthkit").is_some());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
