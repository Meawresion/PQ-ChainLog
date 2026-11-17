//! The custody graph, **built in this process** (design §13.1).
//!
//! The server holds custody records as opaque, per-capsule chains. It cannot
//! draw this graph, and must not be able to: a server that can traverse "who
//! passed what to whom" is a server that holds it. The client already holds the
//! whole custody plane (it is small, which is why `Π_CD` is its default), so it
//! materialises the graph from records it verified and openings it holds.
//!
//! Custodians appear as their commitment `actor_c` unless this client holds the
//! opening; an opened commitment is labelled with what it opens to and marked
//! as opened. Nothing is named that the client cannot open.

use core::fmt::Write as _;
use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;

use pqcl_capsule::{CustodyRecord, Event, RecordBody};
use pqcl_pipeline::handoff::Handoff;
use pqcl_primitives::xof::Digest32;
use serde_json::{Value, json};

/// What the client knows about a commitment it can open.
#[derive(Debug, Clone)]
pub struct Opening {
    /// `actor_id` inside `actor_c`.
    pub actor_id: String,
    /// The role byte's name.
    pub role: String,
}

/// One capsule's chain, as the client holds it after verification.
#[derive(Debug)]
pub struct ChainView<'a> {
    /// What the client calls the capsule (it opened the artefact).
    pub label: &'a str,
    /// The records, in chain order.
    pub chain: &'a [CustodyRecord],
    /// Their opened bodies, index for index with `chain`.
    ///
    /// ⭐ **The dashboard is a key holder, which is why it can have these.**
    /// Since M13 A1 the event, actor and parameter commitments live inside
    /// `C_rec`; the custody graph is drawn by the investigator's own loopback
    /// client (design §13.1), which holds the case keys, so it opens each body
    /// before rendering. A server that could draw this graph would be a server
    /// that holds the plane — which is the thing the two-plane split exists to
    /// prevent.
    pub bodies: &'a [RecordBody],
}

fn short(d: &Digest32) -> String {
    hex_bytes(&d[..4])
}

/// The event's name as the paper writes it.
#[must_use]
pub const fn event_name(e: Event) -> &'static str {
    match e {
        Event::Collect => "COLLECT",
        Event::Transfer => "TRANSFER",
        Event::Access => "ACCESS",
        Event::Analyze => "ANALYZE",
        Event::Export => "EXPORT",
        Event::Seal => "SEAL",
        Event::Dispose => "DISPOSE",
    }
}

/// Build the graph as JSON for the page to render: nodes (capsules and
/// custodians), edges (events), and per-capsule the path of holders.
#[must_use]
pub fn build<S: BuildHasher, T: BuildHasher>(
    capsules: &[ChainView<'_>],
    openings: &HashMap<Digest32, Opening, S>,
    handoffs: &HashMap<Digest32, Handoff, T>,
) -> Value {
    let mut custodians: BTreeMap<String, Value> = BTreeMap::new();
    let mut node_of =
        |c: &Digest32| -> String {
            let id = format!("actor:{}", short(c));
            custodians.entry(id.clone()).or_insert_with(|| match openings.get(c) {
            Some(o) => json!({"id": id, "kind": "custodian", "label": o.actor_id, "role": o.role,
                              "opened": true, "commitment": hex(c)}),
            None => json!({"id": id, "kind": "custodian", "label": format!("actor_c {}…", short(c)),
                           "opened": false, "commitment": hex(c)}),
        });
            id
        };

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut paths = Vec::new();

    for (ci, view) in capsules.iter().enumerate() {
        let cap_id = format!("capsule:{ci}");
        let mut holders: Vec<String> = Vec::new();
        let mut status = "open";
        let mut i = 0;
        while i < view.chain.len() {
            let r = &view.chain[i];
            let body = &view.bodies[i];
            match body.event {
                Event::Collect => {
                    let a = node_of(&body.actor_c);
                    edges.push(
                        json!({"from": a, "to": cap_id, "event": "COLLECT", "ts": body.ts,
                                      "state": "complete", "record": i}),
                    );
                    holders.push(a);
                }
                Event::Transfer => {
                    let from = node_of(&body.actor_c);
                    // Pairing tests the *body* throughout: the descriptor,
                    // the event and — since M13 A20 — the chain link itself
                    // are all inside `C_rec`. Reading the cleartext `h_prev`
                    // here would break every transfer that straddles an epoch
                    // boundary, where the receipt's cleartext link is its own
                    // segment's genesis rather than the release's.
                    let receipt = view.bodies.get(i + 1).filter(|nbody| {
                        nbody.event == Event::Transfer
                            && nbody.params_c == body.params_c
                            && nbody.link == r.chain_link()
                    });
                    let declared_to = handoffs.get(&body.params_c).map(|h| h.to);
                    if let Some(nbody) = receipt {
                        let to = node_of(&nbody.actor_c);
                        edges.push(
                            json!({"from": from, "to": to, "event": "TRANSFER", "capsule": cap_id,
                                          "ts": nbody.ts, "state": "complete", "record": i,
                                          "descriptor": hex(&body.params_c)}),
                        );
                        holders.push(to);
                        i += 2;
                        continue;
                    }
                    // A release with no receipt: in transit.
                    let to = declared_to.map_or_else(
                        || format!("unknown:{}", short(&body.params_c)),
                        |t| node_of(&t),
                    );
                    edges.push(
                        json!({"from": from, "to": to, "event": "TRANSFER", "capsule": cap_id,
                                      "ts": body.ts, "state": "pending", "record": i,
                                      "descriptor": hex(&body.params_c)}),
                    );
                    status = "in transit";
                }
                Event::Dispose => {
                    let a = node_of(&body.actor_c);
                    edges.push(
                        json!({"from": a, "to": cap_id, "event": "DISPOSE", "ts": body.ts,
                                      "state": "terminal", "record": i,
                                      "order": r.order_ref.as_ref().map(hex)}),
                    );
                    status = "closed";
                }
                e => {
                    let a = node_of(&body.actor_c);
                    edges.push(
                        json!({"from": a, "to": cap_id, "event": event_name(e), "ts": body.ts,
                                      "state": "activity", "record": i}),
                    );
                }
            }
            i += 1;
        }
        nodes.push(
            json!({"id": cap_id, "kind": "capsule", "label": view.label, "status": status,
                          "records": view.chain.len()}),
        );
        paths.push(json!({"capsule": cap_id, "holders": holders, "status": status}));
    }
    nodes.extend(custodians.into_values());
    json!({"nodes": nodes, "edges": edges, "paths": paths})
}

/// Lower-case hex.
#[must_use]
pub fn hex(d: &Digest32) -> String {
    hex_bytes(d)
}

/// Lower-case hex of any byte string.
#[must_use]
pub fn hex_bytes(d: &[u8]) -> String {
    d.iter()
        .fold(String::with_capacity(2 * d.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
