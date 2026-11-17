//! One case's custody event stream, shared by every custody-plane experiment.
//!
//! Exp. 6's head-to-head (M10 H2) and Exp. 7's court disclosure (H7) must run
//! **the same custody events** through ours and through each baseline, so the
//! stream is defined once, here, and seeded.
//!
//! # The lifecycle
//!
//! Every capsule follows ISO/IEC 27037's order and our seven event types:
//! `COLLECT`, `SEAL`, then a run of handling actions drawn from `ACCESS`,
//! `ANALYZE`, `EXPORT` and `TRANSFER`, and — for a fraction of capsules —
//! `DISPOSE`. A `TRANSFER` is **bilateral** (design §3a): two linked records,
//! the sender's and the receiver's, so it contributes two events.
//!
//! Capsules arrive over the case's life: at most [`StreamParams::active`] are
//! open at once, and a finished capsule admits the next. Within that window the
//! next event comes from a seeded choice of open capsule, so events interleave
//! across capsules while each capsule's own order is preserved.
//!
//! ⚠️ **This is a workload, and its mix is a parameter.** It changes a
//! baseline's average cost per transition (LEChain's `Store` writes storage,
//! its `Access` does not), so every record carries the parameters and the
//! realised event counts, and nobody reads a per-transition average without
//! the mix that produced it.

use pqcl_capsule::Event;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// One custody event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyEvent {
    /// Capsule index, in order of collection.
    pub capsule: u32,
    /// Position within that capsule's chain.
    pub seq: u32,
    /// The event type.
    pub event: Event,
    /// Actor index in `0..actors`. For a bilateral `TRANSFER`, the sender
    /// record carries the sender and the receipt record the receiver.
    pub actor: u32,
    /// For the second record of a bilateral `TRANSFER`: `true`.
    pub receipt: bool,
}

/// The stream's shape. Every field is recorded beside any result.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct StreamParams {
    /// Capsules in the case.
    pub capsules: u32,
    /// Handling actions per capsule, drawn uniformly from `min..=max`.
    pub actions_min: u32,
    /// See `actions_min`.
    pub actions_max: u32,
    /// Percent of handling actions that are a (bilateral) `TRANSFER`.
    pub transfer_pct: u32,
    /// Percent of capsules that end in `DISPOSE`.
    pub dispose_pct: u32,
    /// Distinct actors.
    pub actors: u32,
    /// Capsules open at once.
    pub active: u32,
    /// Seed.
    pub seed: u64,
}

impl Default for StreamParams {
    fn default() -> Self {
        Self {
            capsules: 200,
            actions_min: 2,
            actions_max: 8,
            transfer_pct: 25,
            dispose_pct: 10,
            actors: 32,
            active: 32,
            seed: 0x0C05_70D7,
        }
    }
}

fn lifecycle(p: &StreamParams, capsule: u32, rng: &mut StdRng) -> Vec<CustodyEvent> {
    let actors = p.actors.max(2);
    let mut out = Vec::new();
    let mut push = |event, actor, receipt| {
        let seq = u32::try_from(out.len()).unwrap_or(u32::MAX);
        out.push(CustodyEvent {
            capsule,
            seq,
            event,
            actor,
            receipt,
        });
    };
    let mut holder = rng.gen_range(0..actors);
    push(Event::Collect, holder, false);
    push(Event::Seal, holder, false);
    for _ in 0..rng.gen_range(p.actions_min..=p.actions_max.max(p.actions_min)) {
        if rng.gen_range(0..100) < p.transfer_pct {
            let to = (holder + rng.gen_range(1..actors)) % actors;
            push(Event::Transfer, holder, false);
            push(Event::Transfer, to, true);
            holder = to;
        } else {
            let event = [Event::Access, Event::Analyze, Event::Export][rng.gen_range(0..3)];
            push(event, rng.gen_range(0..actors), false);
        }
    }
    if rng.gen_range(0..100) < p.dispose_pct {
        push(Event::Dispose, holder, false);
    }
    out
}

/// The stream, deterministically from `p`.
#[must_use]
pub fn custody_stream(p: &StreamParams) -> Vec<CustodyEvent> {
    let mut rng = StdRng::seed_from_u64(p.seed);
    let mut chains: Vec<std::collections::VecDeque<CustodyEvent>> = (0..p.capsules)
        .map(|c| lifecycle(p, c, &mut rng).into())
        .collect();
    let mut open: Vec<usize> = Vec::new();
    let mut next = 0usize;
    let mut out = Vec::new();
    loop {
        while open.len() < p.active.max(1) as usize && next < chains.len() {
            open.push(next);
            next += 1;
        }
        if open.is_empty() {
            return out;
        }
        let slot = rng.gen_range(0..open.len());
        let c = open[slot];
        if let Some(e) = chains[c].pop_front() {
            out.push(e);
        }
        if chains[c].is_empty() {
            open.swap_remove(slot);
        }
    }
}

/// Realised count per event type, for the record.
#[must_use]
pub fn event_counts(stream: &[CustodyEvent]) -> serde_json::Value {
    let mut m = std::collections::BTreeMap::<String, usize>::new();
    for e in stream {
        *m.entry(format!("{:?}", e.event)).or_default() += 1;
    }
    serde_json::json!(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_chain_is_in_iso_order_and_complete() {
        let p = StreamParams::default();
        let s = custody_stream(&p);
        let mut last: Vec<Option<u32>> = vec![None; p.capsules as usize];
        for e in &s {
            let prev = last[e.capsule as usize];
            assert_eq!(
                prev.map_or(0, |x| x + 1),
                e.seq,
                "capsule {} out of order",
                e.capsule
            );
            if e.seq == 0 {
                assert_eq!(e.event, Event::Collect);
            }
            if e.seq == 1 {
                assert_eq!(e.event, Event::Seal);
            }
            last[e.capsule as usize] = Some(e.seq);
        }
        assert!(last.iter().all(Option::is_some), "a capsule never appeared");
    }

    #[test]
    fn a_transfer_is_two_linked_records() {
        let s = custody_stream(&StreamParams::default());
        let mut by_capsule: std::collections::BTreeMap<u32, Vec<CustodyEvent>> =
            std::collections::BTreeMap::default();
        for e in s {
            by_capsule.entry(e.capsule).or_default().push(e);
        }
        let mut transfers = 0;
        for chain in by_capsule.values() {
            for w in chain.windows(2) {
                if w[1].receipt {
                    assert_eq!(w[0].event, Event::Transfer);
                    assert!(!w[0].receipt);
                    assert_ne!(w[0].actor, w[1].actor, "a handoff to oneself");
                    transfers += 1;
                }
            }
        }
        assert!(transfers > 0);
    }

    #[test]
    fn the_stream_is_deterministic_and_interleaved() {
        let p = StreamParams::default();
        let a = custody_stream(&p);
        assert_eq!(a, custody_stream(&p));
        // Interleaved: the first 50 events touch more than one capsule.
        let distinct: std::collections::BTreeSet<u32> =
            a.iter().take(50).map(|e| e.capsule).collect();
        assert!(distinct.len() > 5);
        let other = custody_stream(&StreamParams { seed: 1, ..p });
        assert_ne!(a, other);
    }
}
