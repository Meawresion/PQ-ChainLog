//! `Π_core` — single-keyword DSSE, forward private and Type-II backward private.
//!
//! `PQ-DSSE-Formal.md` §5.1. Symmetric primitives only: a GGM range-constrained
//! PRF, a keyed PRF, a hash and an AEAD. No novelty is claimed for the
//! construction — it is Diana's token compression plus BMO's `B′` in-band
//! tombstones — but it is the foundation everything else stands on.
//!
//! # The two trees, and why collapsing them destroys the scheme
//!
//! Each keyword has **two** independent keys:
//!
//! ```text
//! K^A_w = F(K_S, "addr" ‖ w)   GGM root over the counter space; released
//!                              CONSTRAINED to [0, c_w) at search time
//! K^M_w = F(K_S, "mask" ‖ w)   payload key seed; NEVER released
//! ```
//!
//! `PQ-DSSE-Formal.md` calls merging them *"the natural-looking optimisation
//! that silently destroys the scheme"*. Two properties depend on the split:
//!
//! * **Forward privacy.** The server receives a key constrained to `[0, c_w)`,
//!   so it can derive every address written so far and none that will be. It
//!   cannot recognise a future update to `w` as belonging to `w`.
//! * **Verifiability against a malicious server** (design §11.1). The client
//!   derives every `addr_i` itself and binds it as AEAD associated data, while
//!   the server never sees `K^M_w`. That single fact makes omission, forgery,
//!   substitution and replay all detectable, with no additional machinery. We
//!   had been under-claiming this.
//!
//! # Deletions are in-band
//!
//! A delete is an ordinary record whose payload happens to say `Del`. It is
//! byte-indistinguishable from an add, which is what makes the scheme Type-II
//! rather than Type-III backward private: the server learns *when* updates
//! happened, never *which* were deletions.

use std::collections::{BTreeSet, HashMap};

/// Hash maps on `ahash`, keyed and randomised per process (§1q.5). `SipHash`'s
/// per-lookup cost showed in the range-ingest remainder; an unkeyed hasher
/// would let adversarial evidence choose colliding keywords.
pub(crate) type FastMap<K, V> = HashMap<K, V, ahash::RandomState>;
/// A set over the same hasher.
pub(crate) type FastSet<T> = std::collections::HashSet<T, ahash::RandomState>;

use pqcl_ggm::{ConstrainedKey, MasterKey, PathEval};
use pqcl_primitives::aead::{AeadError, RecordKey, SealedRecord};
use pqcl_primitives::xof::{self, Digest32, Label, PrfKey};

/// A document identifier.
pub type DocId = u64;

/// Add or delete. Encoded in the payload, never visible to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Insert `id` into `DB(w)`.
    Add,
    /// Remove `id` from `DB(w)`.
    Del,
}

impl Op {
    const fn byte(self) -> u8 {
        match self {
            Self::Add => 0x01,
            Self::Del => 0x02,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Add),
            0x02 => Some(Self::Del),
            _ => None,
        }
    }
}

/// One `(addr, val)` pair, the entire content of an update as the server sees
/// it. Both fields are pseudorandom to anyone without `K_S`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateToken {
    /// `addr = H₁(CPRF.Eval(K^A_w, c))`.
    pub addr: Digest32,
    /// `val = AEAD.Enc(F(K^M_w, c); nonce = 0; AD = addr; op ‖ id)`.
    pub val: SealedRecord,
}

/// What the client sends to search: a constrained key and the counter.
///
/// Note what is *absent*: the keyword. The server learns only that some
/// keyword with `count` updates was searched.
#[derive(Debug, Clone)]
pub struct SearchToken {
    /// `K^A_w` constrained to `[0, count)`.
    pub constrained: ConstrainedKey,
    /// Number of updates for this keyword.
    pub count: u64,
}

impl SearchToken {
    /// Bytes on the wire, ignoring framing — a language-independent axis, so it
    /// compares against every baseline including the Python ones
    ///
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.constrained.wire_bytes() + core::mem::size_of::<u64>()
    }
}

/// The server's reply: one slot per counter position, in index order.
///
/// `None` means the server claims to hold nothing at that address. It is a
/// distinct case from a decryption failure and the client rejects both — an
/// honest server always has every address, because the client wrote them.
#[derive(Debug, Clone, Default)]
pub struct SearchResponse(pub Vec<Option<SealedRecord>>);

/// Why a search was rejected.
///
/// Every variant is a **detected server deviation**, not a recoverable
/// condition. `PQ-ChainLog-DESIGN.md` §11.1 enumerates the four attacks; each
/// lands here. A caller that treats any of these as "no results" throws away
/// the verifiability property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    /// The server returned a different number of slots than were requested.
    WrongLength {
        /// Slots requested.
        expected: u64,
        /// Slots returned.
        got: usize,
    },
    /// The server returned nothing at a position the client had written.
    /// **Omission.**
    Missing {
        /// Counter position.
        index: u64,
    },
    /// A payload failed to authenticate. Covers **forgery**, **substitution**
    /// and **replay** — all three fail the same check, because the payload is
    /// bound to its address and encrypted under a key the server never sees.
    Unauthentic {
        /// Counter position.
        index: u64,
        /// The underlying AEAD failure.
        cause: AeadError,
    },
    /// A payload authenticated but did not decode. Only reachable if the client
    /// and server disagree about the payload format, since the AEAD already
    /// proves the bytes are ours.
    Malformed {
        /// Counter position.
        index: u64,
    },
}

impl core::fmt::Display for SearchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { expected, got } => write!(
                f,
                "server returned {got} slots for a token covering {expected}"
            ),
            Self::Missing { index } => write!(
                f,
                "server omitted the record at counter {index}, which the client wrote"
            ),
            Self::Unauthentic { index, cause } => write!(
                f,
                "record at counter {index} failed to authenticate ({cause}): \
                 forged, substituted, or replayed"
            ),
            Self::Malformed { index } => {
                write!(
                    f,
                    "record at counter {index} authenticated but did not decode"
                )
            }
        }
    }
}

impl core::error::Error for SearchError {}

/// Default bound on keywords whose derivation path is cached. See
/// [`Client::with_path_cache`].
pub const DEFAULT_PATH_CACHE: usize = 4096;

/// A cached keyword's derivation state. Pure acceleration: dropping it changes
/// nothing but the cost of the next update for that keyword.
struct KeywordPath {
    /// The GGM path to the last counter used, over `K^A_w`.
    path: PathEval,
    /// `K^M_w`, so `record_key` does not re-derive it per update.
    mask_seed: PrfKey,
    /// LRU clock value at last use.
    last_used: u64,
}

/// Cache hits and misses, for reporting the hit rate the bound costs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathCacheStats {
    /// Updates whose keyword's path was cached.
    pub hits: u64,
    /// Updates that had to start a fresh path (first use, or evicted).
    pub misses: u64,
    /// Keywords currently cached.
    pub cached: usize,
}

/// The client. Holds `K_S` and the per-keyword update counters.
///
/// In deployment `K_S` lives in the Secure Module and this struct calls into
/// it; at M5 that becomes a backend swap rather than a redesign.
pub struct Client {
    key: PrfKey,
    /// `W: w ↦ c_w`. Exact counters are needed for chain positions; the
    /// Count–Min Sketch of `sec:cms` replaces this only for *ranking* s-terms
    /// at M3, never for position. A `HashMap` since M12 R2: it is looked up,
    /// counted and inserted into, never iterated, so the ordered tree's
    /// byte-string comparisons bought nothing.
    counters: FastMap<Vec<u8>, u64>,
    /// ⭐ M10 P1: per-keyword derivation paths, so an update costs ~2 PRG calls
    /// instead of a 64-call GGM walk. **Never authoritative** — the counter
    /// above is — so eviction is always safe.
    paths: FastMap<Vec<u8>, KeywordPath>,
    path_capacity: usize,
    path_clock: u64,
    path_stats: PathCacheStats,
}

impl Client {
    /// Create a client over a master key, caching up to
    /// [`DEFAULT_PATH_CACHE`] keywords' derivation paths.
    #[must_use]
    pub fn new(key: PrfKey) -> Self {
        Self::with_path_cache(key, DEFAULT_PATH_CACHE)
    }

    /// Create a client caching up to `capacity` keywords' derivation paths.
    ///
    /// ⭐ **M10 P1.** Campaign 02's profile put 92% of an update's crypto cost
    /// in the root-to-leaf GGM walk (`TREE_DEPTH = 64` PRG calls per token).
    /// Counters only increase, so the path to `c + 1` reuses the path to `c`
    /// above the highest flipped bit ([`PathEval`]), and `K^A_w` / `K^M_w` are
    /// kept rather than re-derived. **Tokens are byte-identical** to the
    /// uncached derivation; `capacity = 0` *is* the uncached derivation, kept
    /// as the reference the tests compare against.
    ///
    /// Memory: ~2.2 KB per cached keyword (a 65-node path plus `K^M_w`), so the
    /// default bound is ~9 MB. Least-recently-used keywords are evicted beyond
    /// it; [`path_cache_stats`](Self::path_cache_stats) reports the hit rate
    /// that bound costs.
    #[must_use]
    pub fn with_path_cache(key: PrfKey, capacity: usize) -> Self {
        Self {
            key,
            counters: FastMap::default(),
            paths: FastMap::default(),
            path_capacity: capacity,
            path_clock: 0,
            path_stats: PathCacheStats::default(),
        }
    }

    /// Hit/miss counts of the derivation-path cache.
    #[must_use]
    pub fn path_cache_stats(&self) -> PathCacheStats {
        PathCacheStats {
            cached: self.paths.len(),
            ..self.path_stats
        }
    }

    /// Bytes the path cache holds now: each entry's struct, its key's heap
    /// bytes and `Vec` header. Excludes the hash table's own slack, so it is a
    /// floor. M12 R2 reports it beside the capacity it chose (§1l.3 rule).
    #[must_use]
    pub fn path_cache_bytes(&self) -> usize {
        self.paths
            .keys()
            .map(|k| {
                k.len() + core::mem::size_of::<Vec<u8>>() + core::mem::size_of::<KeywordPath>()
            })
            .sum()
    }

    /// GGM `G` calls made by the paths **currently cached**. An evicted
    /// path's calls leave with it, so this is the total only when nothing was
    /// evicted, which is how M12's per-token breakdown uses it.
    #[must_use]
    pub fn cached_path_prg_calls(&self) -> u64 {
        self.paths.values().map(|e| e.path.prg_calls()).sum()
    }

    /// The cached path state for `w`, created (evicting the least recently
    /// used entry if full) on a miss. `None` only when caching is disabled.
    fn cached_path(&mut self, w: &[u8]) -> Option<&mut KeywordPath> {
        if self.path_capacity == 0 {
            return None;
        }
        self.path_clock += 1;
        let clock = self.path_clock;
        if self.paths.contains_key(w) {
            self.path_stats.hits += 1;
        } else {
            self.path_stats.misses += 1;
            if self.paths.len() >= self.path_capacity {
                let oldest = self
                    .paths
                    .iter()
                    .min_by_key(|(_, e)| e.last_used)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    self.paths.remove(&k);
                }
            }
            let entry = KeywordPath {
                path: self.addr_root(w).path_eval(),
                mask_seed: self.mask_seed(w),
                last_used: clock,
            };
            self.paths.insert(w.to_vec(), entry);
        }
        let entry = self.paths.get_mut(w)?;
        entry.last_used = clock;
        Some(entry)
    }

    /// `K^A_w` — the GGM root over the counter space.
    fn addr_root(&self, w: &[u8]) -> MasterKey {
        MasterKey::new(xof::prf(&self.key, Label::Addr, &[w]))
    }

    /// `K^M_w` — the payload key seed. Never leaves the client.
    fn mask_seed(&self, w: &[u8]) -> PrfKey {
        PrfKey::new(xof::prf(&self.key, Label::Mask, &[w]))
    }

    /// The one-time record key at counter `c`: `F(K^M_w, c)`.
    fn record_key(&self, w: &[u8], c: u64) -> RecordKey {
        record_key_from(&self.mask_seed(w), c)
    }

    /// Current update count for `w`.
    #[must_use]
    pub fn counter(&self, w: &[u8]) -> u64 {
        self.counters.get(w).copied().unwrap_or(0)
    }

    /// Number of distinct keywords written. Client-state size, which the paper
    /// reports.
    #[must_use]
    pub fn keyword_count(&self) -> usize {
        self.counters.len()
    }

    /// Produce the update token for `(op, w, id)` and advance the counter.
    ///
    /// # Errors
    ///
    /// [`AeadError`] only if the payload exceeds the AEAD limit, which a
    /// 9-byte `op ‖ id` cannot.
    pub fn update(&mut self, op: Op, w: &[u8], id: DocId) -> Result<UpdateToken, AeadError> {
        let c = self.counter(w);

        // Same derivation either way; the cached path only avoids redoing the
        // part of the GGM walk that did not change (M10 P1).
        let (tag, record_key) = match self.cached_path(w) {
            Some(entry) => (entry.path.eval(c), record_key_from(&entry.mask_seed, c)),
            None => (self.addr_root(w).eval(c), self.record_key(w, c)),
        };
        let addr = xof::addr_hash(&tag);

        let mut payload = Vec::with_capacity(1 + core::mem::size_of::<DocId>());
        payload.push(op.byte());
        payload.extend_from_slice(&id.to_le_bytes());

        // AD = addr binds the payload to its position. This is what makes
        // substitution detectable.
        let val = record_key.seal(&addr, &payload)?;

        // Allocate the key only for a keyword's first update (M10 H1): an
        // unconditional `insert(w.to_vec(), …)` paid a heap allocation per token.
        match self.counters.get_mut(w) {
            Some(n) => *n = c + 1,
            None => {
                self.counters.insert(w.to_vec(), c + 1);
            }
        }
        Ok(UpdateToken { addr, val })
    }

    /// Produce a search token, or `None` if `w` has never been updated.
    ///
    /// Returning `None` rather than an empty token matters: sending a token for
    /// `c = 0` would tell the server a search happened for a keyword with no
    /// history, which is information an honest client never needs to reveal.
    #[must_use]
    pub fn search_token(&self, w: &[u8]) -> Option<SearchToken> {
        let c = self.counter(w);
        let constrained = self.addr_root(w).constrain_prefix(c).ok()?;
        Some(SearchToken {
            constrained,
            count: c,
        })
    }

    /// The addresses a token covers, in counter order.
    ///
    /// The client derives these **itself**, which is half of why the scheme is
    /// verifiable: it never has to trust the server's claim about which record
    /// sits where.
    #[must_use]
    pub fn addresses(&self, w: &[u8], count: u64) -> Vec<Digest32> {
        let root = self.addr_root(w);
        (0..count).map(|c| xof::addr_hash(&root.eval(c))).collect()
    }

    /// Decrypt a server response into the current result set.
    ///
    /// # Errors
    ///
    /// Any [`SearchError`]. Each one is a detected server deviation and must be
    /// treated as an abort, never as an empty result.
    pub fn finish(
        &self,
        w: &[u8],
        token: &SearchToken,
        response: &SearchResponse,
    ) -> Result<BTreeSet<DocId>, SearchError> {
        if response.0.len() != usize::try_from(token.count).unwrap_or(usize::MAX) {
            return Err(SearchError::WrongLength {
                expected: token.count,
                got: response.0.len(),
            });
        }

        // ⭐ Expand the token's own constrained key rather than re-deriving each
        // address from the root.
        //
        // `MasterKey::eval(c)` walks the full `TREE_DEPTH` — 64 PRG steps — for
        // **every** address, so a search over `c_w` postings cost `64·c_w` PRG
        // calls. `ConstrainedKey::expand` walks each covering subtree once, which
        // is about **two** calls per leaf, and `pqcl-ggm` already documented that
        // as the server's path. The client was not using it.
        //
        // Measured: this was ~50 µs per posting and dominated every search
        // number in Exp. 1, Exp. 2 and Exp. 7 — the whole `k·t_PRF` term. The
        // output is identical by construction; the existing `Π_core` and oracle
        // tests are what check that claim.
        let addrs: Vec<Digest32> = token
            .constrained
            .expand()
            .into_iter()
            .map(|(_, leaf)| xof::addr_hash(&leaf))
            .collect();

        // Hoisted: `record_key` re-derived `mask_seed(w)` — a PRF over the
        // keyword — on every iteration of the loop below.
        let mask = self.mask_seed(w);
        let mut result = BTreeSet::new();

        for (i, slot) in response.0.iter().enumerate() {
            let index = i as u64;
            debug_assert!(index < token.count);
            let sealed = slot.as_ref().ok_or(SearchError::Missing { index })?;

            let plain = RecordKey::new(xof::prf(&mask, Label::Mask, &[&index.to_le_bytes()]))
                .open(&addrs[i], sealed)
                .map_err(|cause| SearchError::Unauthentic { index, cause })?;

            if plain.len() != 1 + core::mem::size_of::<DocId>() {
                return Err(SearchError::Malformed { index });
            }
            let op = Op::from_byte(plain[0]).ok_or(SearchError::Malformed { index })?;
            let mut id_bytes = [0u8; core::mem::size_of::<DocId>()];
            id_bytes.copy_from_slice(&plain[1..]);
            let id = DocId::from_le_bytes(id_bytes);

            // Replayed in-band: a later Del cancels an earlier Add, which is
            // why deletions cost no cleanup round.
            match op {
                Op::Add => {
                    result.insert(id);
                }
                Op::Del => {
                    result.remove(&id);
                }
            }
        }

        Ok(result)
    }
}

/// `F(K^M_w, c)` — the one-time record key, from an already-derived `K^M_w`.
fn record_key_from(mask_seed: &PrfKey, c: u64) -> RecordKey {
    RecordKey::new(xof::prf(mask_seed, Label::Mask, &[&c.to_le_bytes()]))
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Client {{ keywords: {}, key: <redacted> }}",
            self.counters.len()
        )
    }
}

/// What the server stores and does.
///
/// A trait from the start, so a malicious variant can be substituted in tests
/// without the client knowing. M3's transcript-equality test — the highest-value
/// test in the project — needs the same seam.
pub trait Edb {
    /// Store an update. `EDB[addr] ← val`, write-once in an honest server.
    fn insert(&mut self, token: &UpdateToken);

    /// Answer a search token, in counter order.
    fn search(&self, token: &SearchToken) -> SearchResponse;

    /// Number of stored records. An index-size figure, comparable across every
    /// baseline regardless of language.
    fn len(&self) -> usize;

    /// Whether the index is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The honest server: a map from address to record, and nothing else.
///
/// It cannot decrypt anything it holds. Its entire view is a set of
/// pseudorandom addresses and ciphertexts.
#[derive(Debug, Default)]
pub struct HonestEdb {
    /// Hashed, as the baselines' servers are (ODXT's `TSet`, Zuo'22's `EDB`):
    /// nothing reads this map in order, and an ordered tree cost ~0.33 µs per
    /// token that no baseline paid (§1q.5 profile).
    map: FastMap<Digest32, SealedRecord>,
}

impl HonestEdb {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read an address directly. Used by tests that model a malicious server.
    #[must_use]
    pub fn get(&self, addr: &Digest32) -> Option<&SealedRecord> {
        self.map.get(addr)
    }

    /// Total stored ciphertext bytes — the index-size figure the paper reports.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.map
            .values()
            .map(|v| v.len() + core::mem::size_of::<Digest32>())
            .sum()
    }
}

impl Edb for HonestEdb {
    fn insert(&mut self, token: &UpdateToken) {
        self.map.insert(token.addr, token.val.clone());
    }

    fn search(&self, token: &SearchToken) -> SearchResponse {
        // The server derives addresses from the constrained key. It cannot go
        // past `count` — that is forward privacy, enforced by the key rather
        // than by the server's good behaviour.
        //
        // ⛔ M10 P2: **expand each covering subtree once**, as `pqcl-ggm`'s own
        // header says the server does. This called `constrained.eval(c)` per
        // counter instead — a walk from the covering node down to every leaf,
        // ~12 PRG calls per posting for a 4 096-posting keyword — and the
        // profile put 80% of a Π_RANGE search there (8.4 µs of 10.5 µs per
        // posting, local). The client was moved to `expand` long ago; the
        // server never was. Same leaves, so the same response: a counter the
        // key does not cover still yields an empty slot, as `eval`'s error did.
        let expanded = token.constrained.expand();
        let mut leaves = expanded.iter().peekable();
        let mut out = Vec::with_capacity(usize::try_from(token.count).unwrap_or(0));
        for c in 0..token.count {
            while leaves.next_if(|(i, _)| *i < c).is_some() {}
            let slot = leaves
                .next_if(|(i, _)| *i == c)
                .map(|(_, leaf)| xof::addr_hash(leaf))
                .and_then(|addr| self.map.get(&addr).cloned());
            out.push(slot);
        }
        SearchResponse(out)
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}
