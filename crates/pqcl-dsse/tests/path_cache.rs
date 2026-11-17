//! M10 P1: the derivation-path cache must not change a single byte.
//!
//! `Client::with_path_cache(key, 0)` is the uncached derivation — a fresh
//! 64-call GGM walk per token, exactly what campaign 02 measured. Every cached
//! configuration, including one small enough to evict constantly, must emit
//! **byte-identical** update tokens for the same interleaved multi-keyword
//! stream. `pqcl-ggm`'s `PathEval` tests cover ≥ 10⁵ consecutive counters and
//! every `2^j` boundary; this covers the integration: keyword interleaving,
//! eviction and re-creation, and `K^M_w` reuse.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use pqcl_dsse::core::{Client, Op, UpdateToken};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

fn key() -> PrfKey {
    PrfKey::new([0x5a; LAMBDA_BYTES])
}

/// An interleaved stream over 7 keywords at uneven rates. `kw0` alone passes
/// every `2^j` boundary up to 2^13, and the others interleave between its
/// steps, so each cached path is resumed after other keywords used the cache.
fn stream() -> Vec<(Op, Vec<u8>, u64)> {
    let mut out = Vec::new();
    for i in 0u64..12_000 {
        out.push((Op::Add, b"kw0".to_vec(), i));
        if i % 2 == 0 {
            out.push((Op::Add, format!("kw{}", 1 + i % 3).into_bytes(), i));
        }
        if i % 5 == 0 {
            let op = if i % 10 == 0 { Op::Del } else { Op::Add };
            out.push((op, format!("kw{}", 4 + i % 3).into_bytes(), i / 5));
        }
    }
    out
}

fn tokens(capacity: usize) -> (Vec<UpdateToken>, Client) {
    let mut client = Client::with_path_cache(key(), capacity);
    let toks = stream()
        .into_iter()
        .map(|(op, w, id)| client.update(op, &w, id).expect("update"))
        .collect();
    (toks, client)
}

#[test]
fn cached_tokens_are_byte_identical_to_the_uncached_derivation() {
    let (reference, _) = tokens(0);
    assert!(reference.len() > 17_000, "the stream should be long");
    // 3 < 7 keywords: constant eviction and path re-creation. 64: all fit.
    for capacity in [1, 3, 64] {
        let (cached, client) = tokens(capacity);
        assert_eq!(cached.len(), reference.len());
        for (i, (a, b)) in cached.iter().zip(&reference).enumerate() {
            assert_eq!(
                a.addr, b.addr,
                "capacity {capacity}: addr differs at update {i}"
            );
            assert_eq!(
                a.val, b.val,
                "capacity {capacity}: val differs at update {i}"
            );
        }
        let s = client.path_cache_stats();
        assert_eq!(
            s.hits + s.misses,
            u64::try_from(reference.len()).expect("fits")
        );
        assert!(
            s.cached <= capacity,
            "capacity {capacity} exceeded: {}",
            s.cached
        );
    }
}

#[test]
fn the_cache_actually_hits_when_it_fits() {
    let (_, client) = tokens(64);
    let s = client.path_cache_stats();
    // 7 keywords, each a miss exactly once.
    assert_eq!(s.misses, 7, "{s:?}");
    assert_eq!(s.cached, 7);
}

#[test]
fn searches_still_verify_over_a_cached_history() {
    use pqcl_dsse::core::{Edb, HonestEdb};
    let mut client = Client::with_path_cache(key(), 2);
    let mut server = HonestEdb::new();
    for (op, w, id) in stream().into_iter().take(3_000) {
        let t = client.update(op, &w, id).expect("update");
        server.insert(&t);
    }
    let token = client.search_token(b"kw0").expect("kw0 was written");
    let response = server.search(&token);
    let result = client.finish(b"kw0", &token, &response).expect("verifies");
    assert!(!result.is_empty());
}
