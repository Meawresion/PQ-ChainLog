//! `Π_XT` and `Π_BOOL` — group-free conjunctive and Boolean search.
//!
//! # The insight the paper rests on
//!
//! OXT's discrete-log group buys exactly one thing: a single-round oblivious
//! evaluation. Give up that round and it disappears — and because the client
//! then holds the candidate set, the server can be handed a **shuffled** probe
//! list and asked only for an unordered bit vector. That is where the leakage
//! advantage comes from, and `Π_BOOL` and `Π_RANGE` are corollaries of the same
//! fact: once the client holds the bit matrix, what it computes over the matrix
//! is invisible to the server.
//!
//! # Two rounds (draft8 Phase 9, D3)
//!
//! ```text
//! Round 1   w₁ ← argmin volume        s-term
//!           Cand ← Π_core.Search(w₁)  live, exact; each id = (e, j)
//!           Cand* ← { id ∈ Cand : e(id) closed }   the rest is PENDING
//!
//! Round 2   for id ∈ Cand*, i ∈ [2,n]:
//!               p ← H_X(K_X^(e(id)), wᵢ ‖ id)        eq:probe
//!           shuffle P (unlabelled), send
//!           server tests each p against ∪ closed XSet_e, one bit back
//!
//!           match(id, wᵢ) = b
//!           R = { id ∈ Cand* : ψ(match(id,w₂), …, match(id,wₙ)) }
//! ```
//!
//! `|P| = |Cand*| · (n−1)` (`eq:probecount`). There is no factor `E` and no
//! delete probe: the identifier carries its epoch, so the client knows which
//! key holds a candidate's tags, and deletion is record-granular, so a deleted
//! record has already left `Cand` in round one.
//!
//! # The coverage rule
//!
//! A candidate of the still-open epoch has no tags the server answers for (the
//! open epoch is never probed: forward privacy). Evaluating ψ over it would read
//! every bit as absent, so `w₁ ∧ ¬w₂` would return a record that has `w₂`
//! (`tests/coverage.rs`). Such candidates are set aside as **pending**
//! ([`XtClient::pending`]) and never evaluated, so a result is exactly the set
//! provable against a committed root.
//!
//! # Why `ψ` is free
//!
//! `Π_XT` hard-codes `ψ = ∀i. match(id, wᵢ)`. Nothing forces that. The client
//! already holds the whole bit matrix, so it can evaluate **any** Boolean
//! formula — including negation — over the same transcript. The server cannot
//! tell the difference, because `ψ` is applied after the transcript ends.
//!
//! [`Transcript`] exists to make that testable rather than asserted: it records
//! exactly what the server saw, and `tests/transcript.rs` checks that a
//! conjunction and a formula with a disjunction and a negation produce
//! identical server views over the same term multiset. That test *is*
//! Thm. `thm:bool`.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::{FastMap, FastSet};

use pqcl_primitives::xof::{self, Digest32, Label, PrfKey};

use crate::core::{Client, DocId, Edb, Op, SearchError};
use pqcl_primitives::aead::AeadError;

/// An interned keyword, private to one [`XtClient`].
type KeywordIx = u32;

/// Epoch index.
pub type Epoch = u64;

/// A cross-tag. Pseudorandom to anyone without the epoch key.
pub type XTag = Digest32;

/// Low bits of a [`DocId`] that hold the record's sequence number `j`; the
/// bits above hold its epoch `e` (draft8 Phase 4 Step 1, `id = (e, j)`).
///
/// ⭐ Packed into the same 8 bytes `id` always had, so the `(addr, val)`
/// payload `op ‖ id` keeps its width, and an
/// identifier of epoch 0 is numerically the old `j`.
pub const SEQ_BITS: u32 = 48;
const SEQ_MASK: u64 = (1u64 << SEQ_BITS) - 1;

/// `id = (e, j)`.
#[must_use]
pub const fn doc_id(e: Epoch, j: u64) -> DocId {
    (e << SEQ_BITS) | (j & SEQ_MASK)
}

/// The epoch an identifier was ingested in.
#[must_use]
pub const fn epoch_of(id: DocId) -> Epoch {
    id >> SEQ_BITS
}

/// The sequence number `j` of an identifier.
#[must_use]
pub const fn seq_of(id: DocId) -> u64 {
    id & SEQ_MASK
}

/// Why an update was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XtUpdateError {
    /// The `Π_core` token could not be sealed.
    Aead(AeadError),
    /// An insertion whose identifier names an epoch other than the open one.
    /// Its tags would land under the wrong key, and the client would later
    /// probe the epoch the identifier names: a silent false negative.
    WrongEpoch {
        /// The identifier.
        id: DocId,
        /// The open epoch.
        open: Epoch,
    },
}

impl core::fmt::Display for XtUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Aead(e) => write!(f, "{e}"),
            Self::WrongEpoch { id, open } => write!(
                f,
                "insertion of id {id:#x} names epoch {}, but epoch {open} is open",
                epoch_of(*id)
            ),
        }
    }
}

impl core::error::Error for XtUpdateError {}

impl From<AeadError> for XtUpdateError {
    fn from(e: AeadError) -> Self {
        Self::Aead(e)
    }
}

/// The client's cross-tag key ratchet, draft6 eq. (`eq:ratchet`).
///
/// `K_X^(0)` is an **independent draw**, not a derivation from `K_mst`. That is
/// a correctness constraint on erasure, not a preference: compaction completes
/// a court-ordered deletion by destroying superseded `{K_X^(e)}`, and the
/// server must be assumed to have kept every historical `XSet_e`. If the keys
/// were re-derivable from a surviving master, deleting our copy would achieve
/// nothing and the erasure would be cosmetic.
///
/// The client retains the **set** of keys, not just the newest, because
/// round-two probes range over all closed epochs.
pub struct Ratchet {
    /// Keys for closed epochs `0 .. past.len()`, in order. A destroyed key is
    /// zeroed in place so epoch numbering stays stable after an erasure.
    past: Vec<PrfKey>,
    /// The open epoch's key, epoch index `past.len()`.
    ///
    /// Held separately so "the ratchet always has a current key" is a property
    /// of the type rather than an assertion. The alternative — one vector and
    /// an `expect` on `last()` — is a panic on the ingest path guarded only by
    /// an invariant nobody re-checks.
    current: PrfKey,
    /// Epochs below this have had their keys destroyed by an erasure.
    destroyed_below: Epoch,
    /// The epoch index of `past[0]`. Zero until a compaction, which starts a
    /// fresh ratchet **at the epoch it compacts into**, so epoch numbers never
    /// repeat and an identifier's `e` is never ambiguous.
    base: Epoch,
}

impl Ratchet {
    /// Start from a fresh independent draw.
    #[must_use]
    pub fn new(seed: PrfKey) -> Self {
        Self::new_at(seed, 0)
    }

    /// Start from a fresh independent draw whose first epoch is `base`.
    #[must_use]
    pub fn new_at(seed: PrfKey, base: Epoch) -> Self {
        Self {
            past: Vec::new(),
            current: seed,
            destroyed_below: base,
            base,
        }
    }

    /// Advance: `K_X^(e+1) = F(K_X^(e), "rat")`.
    pub fn advance(&mut self) {
        let next = PrfKey::new(xof::prf(&self.current, Label::Ratchet, &[]));
        let closed = core::mem::replace(&mut self.current, next);
        self.past.push(closed);
    }

    /// The open epoch's key. Infallible.
    #[must_use]
    pub const fn current(&self) -> &PrfKey {
        &self.current
    }

    /// The key for epoch `e`, or `None` if destroyed or not yet reached.
    #[must_use]
    pub fn key(&self, e: Epoch) -> Option<&PrfKey> {
        if e < self.destroyed_below || e < self.base {
            return None;
        }
        let i = usize::try_from(e - self.base).ok()?;
        if i == self.past.len() {
            Some(&self.current)
        } else {
            self.past.get(i)
        }
    }

    /// Index of the open epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.base + self.past.len() as Epoch
    }

    /// Closed epochs — the `E` that multiplies the probe count.
    #[must_use]
    pub fn closed(&self) -> Epoch {
        self.epoch()
    }

    /// Destroy the keys for epochs `< before`, completing an erasure.
    ///
    /// Preimage resistance of `F` makes this final: no retained key can
    /// regenerate a destroyed prefix, and `K_X^(0)` was an independent draw so
    /// no master can either. **M3b's acceptance must test this against an
    /// adversary holding `K_mst`**, not against a client that has merely
    /// dropped its copy — the latter passes while the property fails.
    pub fn destroy_before(&mut self, before: Epoch) {
        self.destroyed_below = self.destroyed_below.max(before);
        let n = usize::try_from(before.saturating_sub(self.base))
            .unwrap_or(usize::MAX)
            .min(self.past.len());
        for k in self.past.iter_mut().take(n) {
            *k = PrfKey::new([0u8; 32]);
        }
    }

    /// Lowest epoch whose key still exists.
    #[must_use]
    pub const fn oldest_live_epoch(&self) -> Epoch {
        self.destroyed_below
    }
}

impl core::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ratchet {{ epoch: {}, keys: <redacted> }}", self.epoch())
    }
}

/// Exactly what the server observes during round two.
///
/// The point of naming this type is Thm. `thm:bool`: for a fixed term multiset,
/// this value must not depend on the formula the client intends to evaluate.
/// A test compares two of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    /// Probes as sent, already shuffled, and **unlabelled**: the server learns
    /// no epoch from a probe and tests it against every closed epoch's set.
    pub probes: Vec<XTag>,
}

impl Transcript {
    /// Number of probes — `|Cand*|·(n−1)` (`eq:probecount`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    /// Whether nothing was probed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    /// Bytes up. Down is exactly `len()` bits.
    #[must_use]
    pub fn wire_bytes_up(&self) -> usize {
        self.probes.len() * core::mem::size_of::<XTag>()
    }

    /// The order-independent view: what the server sees, ignoring the shuffle.
    ///
    /// Two transcripts that agree here are indistinguishable to a server that
    /// cannot invert the shuffle — which is the sense in which Thm. `thm:bool`
    /// claims they are identically distributed.
    #[must_use]
    pub fn multiset(&self) -> BTreeMap<XTag, usize> {
        let mut m = BTreeMap::new();
        for p in &self.probes {
            *m.entry(*p).or_insert(0) += 1;
        }
        m
    }
}

/// A Boolean formula over the x-terms, evaluated client-side.
///
/// Indices refer to positions in the x-term list, i.e. `w₂ … wₙ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Formula {
    /// `match(id, wᵢ)` for x-term `i`.
    Term(usize),
    /// Negation. Free — the client already holds the bit.
    Not(Box<Formula>),
    /// Conjunction.
    And(Vec<Formula>),
    /// Disjunction.
    Or(Vec<Formula>),
}

impl Formula {
    /// The plain conjunction `Π_XT` evaluates: every x-term must match.
    #[must_use]
    pub fn conjunction(x_terms: usize) -> Self {
        Self::And((0..x_terms).map(Self::Term).collect())
    }

    fn eval(&self, matches: &[bool]) -> bool {
        match self {
            Self::Term(i) => matches.get(*i).copied().unwrap_or(false),
            Self::Not(f) => !f.eval(matches),
            Self::And(v) => v.iter().all(|f| f.eval(matches)),
            Self::Or(v) => v.iter().any(|f| f.eval(matches)),
        }
    }
}

/// The `Π_XT` client: `Π_core` plus the cross-tag ratchet and buffer.
pub struct XtClient {
    /// The underlying single-keyword scheme.
    pub core: Client,
    ratchet: Ratchet,
    /// Cross-tags for the open epoch, awaiting a shuffled batch upload.
    buffer: Vec<XTag>,
    /// Batch size `β`. Cross-tags are uploaded shuffled and decoupled from the
    /// `(addr, val)` stream, which is what breaks the xtag↔update linkage.
    beta: usize,
    /// Counter feeding the shuffle PRF, so two shuffles never coincide.
    shuffle_ctr: u64,
    /// Live `(keyword, document)` pairs, keyword interned (see `keywords`).
    ///
    /// Compaction must recompute cross-tags for exactly the live set, so the
    /// client has to be able to enumerate it. `PQ-DSSE-Formal.md` §7.4 places
    /// this mirror at the **aggregation tier, not the edge** — an edge agent
    /// has no business holding the case's live-pair set.
    ///
    /// ⭐ M12 R2: this was a `BTreeSet<(Vec<u8>, DocId)>`, which paid a heap
    /// allocation and an ordered byte-string insert on **every** token. A
    /// keyword is now copied once, when first seen. Compaction sorts into the
    /// old `(keyword bytes, id)` order before shuffling, so its output is
    /// byte-identical (`compaction_output_is_unchanged_by_interning`).
    live: FastSet<(KeywordIx, DocId)>,
    /// Pairs a redaction order has tombstoned. Excluded from the live set at
    /// the next compaction, which is when erasure actually completes.
    tombstoned: FastSet<(KeywordIx, DocId)>,
    /// Keyword interning: bytes → index, and index → bytes.
    keyword_ix: FastMap<Vec<u8>, KeywordIx>,
    keyword_bytes: Vec<Vec<u8>>,
    /// Frequency sketch for s-term selection. Sublinear, unlike the exact
    /// counters `Pi_core` needs for chain positions.
    cms: crate::cms::CountMinSketch,
    /// The epoch the last compaction rebuilt every live pair into. A record of
    /// an epoch at or below it has its tags there now, under that key.
    compacted_at: Option<Epoch>,
}

impl XtClient {
    /// Build over a `Π_core` client, an independent cross-tag seed, and `β`.
    #[must_use]
    pub fn new(core: Client, x_seed: PrfKey, beta: usize) -> Self {
        let cms_key = PrfKey::new(xof::prf(&x_seed, Label::Index, &[b"cms"]));
        Self {
            core,
            ratchet: Ratchet::new(x_seed),
            buffer: Vec::new(),
            beta: beta.max(1),
            shuffle_ctr: 0,
            live: FastSet::default(),
            tombstoned: FastSet::default(),
            keyword_ix: FastMap::default(),
            keyword_bytes: Vec::new(),
            cms: crate::cms::CountMinSketch::new(cms_key),
            compacted_at: None,
        }
    }

    /// The open epoch: an insertion's identifier must name it.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.ratchet.epoch()
    }

    /// The epoch whose key holds `id`'s cross-tags: its ingest epoch, or the
    /// compacted epoch if it predates the last compaction (§1ao.1.4).
    #[must_use]
    pub fn key_epoch(&self, id: DocId) -> Epoch {
        let e = epoch_of(id);
        match self.compacted_at {
            Some(c) if e <= c => c,
            _ => e,
        }
    }

    /// Whether `id` can be evaluated: its tags sit in a **closed** epoch whose
    /// key still exists.
    #[must_use]
    pub fn is_covered(&self, id: DocId) -> bool {
        let e = self.key_epoch(id);
        e < self.ratchet.epoch() && self.ratchet.key(e).is_some()
    }

    /// The coverage rule (Phase 9 Step 1): candidates that cannot be evaluated
    /// yet, reported with their count and never passed to ψ.
    #[must_use]
    pub fn pending(&self, candidates: &[DocId]) -> Vec<DocId> {
        candidates
            .iter()
            .copied()
            .filter(|&id| !self.is_covered(id))
            .collect()
    }

    /// Closed epochs, `E`.
    #[must_use]
    pub fn closed_epochs(&self) -> Epoch {
        self.ratchet.closed()
    }

    /// The interned index of `w`; copies the bytes only the first time.
    fn intern(&mut self, w: &[u8]) -> KeywordIx {
        if let Some(&ix) = self.keyword_ix.get(w) {
            return ix;
        }
        let ix = KeywordIx::try_from(self.keyword_bytes.len())
            .unwrap_or_else(|_| unreachable!("more than 2^32 distinct keywords in one client"));
        self.keyword_bytes.push(w.to_vec());
        self.keyword_ix.insert(w.to_vec(), ix);
        ix
    }

    /// `xtag = H_X(K_X^(e), w ‖ id)` (`eq:xtagdef`). Insertions only: there is
    /// no `op` and no delete tag, because deletion is record-granular and acts
    /// in round one.
    fn xtag(key: &PrfKey, w: &[u8], id: DocId) -> XTag {
        xof::cross_tag(key, &[w, &id.to_le_bytes()])
    }

    /// Apply an update: the `Π_core` token, plus a buffered cross-tag for an
    /// insertion.
    ///
    /// Returns the batch to upload, if `β` was reached. The batch is shuffled
    /// and carries no ordering relationship to the `(addr, val)` stream.
    ///
    /// # Errors
    ///
    /// [`XtUpdateError::WrongEpoch`] for an insertion whose `id` does not name
    /// the open epoch, or the AEAD failure from `Π_core`.
    pub fn update<S: Edb + XSetStore>(
        &mut self,
        store: &mut S,
        op: Op,
        w: &[u8],
        id: DocId,
    ) -> Result<(), XtUpdateError> {
        if op == Op::Add && epoch_of(id) != self.ratchet.epoch() {
            return Err(XtUpdateError::WrongEpoch {
                id,
                open: self.ratchet.epoch(),
            });
        }
        let token = self.core.update(op, w, id)?;
        store.insert(&token);

        if op == Op::Add {
            self.buffer.push(Self::xtag(self.ratchet.current(), w, id));
        }

        self.cms.add(w);

        let pair = (self.intern(w), id);
        match op {
            Op::Add => {
                self.live.insert(pair);
            }
            Op::Del => {
                self.live.remove(&pair);
            }
        }

        if self.buffer.len() >= self.beta {
            self.flush(store);
        }
        Ok(())
    }

    /// Upload the buffered cross-tags, shuffled, into the open epoch.
    pub fn flush<S: XSetStore>(&mut self, store: &mut S) {
        if self.buffer.is_empty() {
            return;
        }
        let mut batch = core::mem::take(&mut self.buffer);
        self.shuffle(&mut batch);
        store.add_xtags(self.ratchet.epoch(), &batch);
    }

    /// Close the open epoch: flush and advance the ratchet.
    pub fn close_epoch<S: XSetStore>(&mut self, store: &mut S) {
        self.flush(store);
        store.seal_epoch(self.ratchet.epoch());
        self.ratchet.advance();
    }

    /// Access the ratchet, e.g. to destroy superseded keys at compaction.
    pub fn ratchet_mut(&mut self) -> &mut Ratchet {
        &mut self.ratchet
    }

    /// Fisher–Yates driven by SHAKE256 under the current cross-tag key.
    ///
    /// Keyed rather than from a system RNG so the permutation is unpredictable
    /// to the server but reproducible for the client that needs to de-shuffle.
    /// The counter guarantees two shuffles never share a permutation.
    fn shuffle<T>(&mut self, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }
        self.shuffle_ctr += 1;
        let stream = xof::shake256(
            &[
                self.ratchet.current().as_bytes().as_slice(),
                &self.shuffle_ctr.to_le_bytes(),
            ]
            .concat(),
            items.len() * 8,
        );
        for i in (1..items.len()).rev() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&stream[i * 8..(i + 1) * 8]);
            let j = usize::try_from(u64::from_le_bytes(b) % (i as u64 + 1)).unwrap_or(0);
            items.swap(i, j);
        }
    }

    /// Choose the s-term for a conjunctive query, returning its index.
    ///
    /// `w1 <- argmin_w vol(w)` via the frequency sketch. The anchor bounds
    /// everything after it -- probes are `2*|Cand|*(n-1)*E` -- so this choice
    /// is the difference between probing tens of documents and millions.
    ///
    /// WARNING: pass **positive literals only**. `Cand = DB(w1)` bounds the
    /// result, so a negated anchor would exclude the very documents the query
    /// is meant to find. Design 6a states the same restriction and notes it is
    /// OXT's too, hence not a regression.
    #[must_use]
    pub fn select_s_term(&self, keywords: &[&[u8]]) -> Option<usize> {
        self.cms.select_s_term(keywords)
    }

    /// The sketch's estimate for `w`. Never an underestimate.
    #[must_use]
    pub fn estimated_volume(&self, w: &[u8]) -> u32 {
        self.cms.estimate(w)
    }

    /// Round 1: the candidate set, `DB(w₁)`.
    ///
    /// # Errors
    ///
    /// Any [`SearchError`] — each is a detected server deviation.
    pub fn candidates<S: Edb>(&self, store: &S, s_term: &[u8]) -> Result<Vec<DocId>, SearchError> {
        let Some(token) = self.core.search_token(s_term) else {
            return Ok(Vec::new());
        };
        let response = store.search(&token);
        Ok(self
            .core
            .finish(s_term, &token, &response)?
            .into_iter()
            .collect())
    }

    /// Build round two's probe list.
    ///
    /// **Independent of the formula by construction** — it takes only the
    /// candidates and the x-terms. That is what makes Thm. `thm:bool` true
    /// rather than merely claimed: there is no parameter here through which a
    /// formula could influence the server's view.
    #[must_use]
    ///
    /// One probe per **covered** candidate and x-term, under the key of the
    /// epoch that holds the candidate's tags (`eq:probe`). A pending candidate
    /// is not probed: the open epoch is never probed (forward privacy).
    pub fn probe(&mut self, candidates: &[DocId], x_terms: &[&[u8]]) -> (Transcript, ProbeMap) {
        let mut probes = Vec::new();
        let mut map = Vec::new();

        for (ti, w) in x_terms.iter().enumerate() {
            for &id in candidates {
                if !self.is_covered(id) {
                    continue;
                }
                let Some(key) = self.ratchet.key(self.key_epoch(id)) else {
                    continue;
                };
                probes.push(Self::xtag(key, w, id));
                map.push((id, ti));
            }
        }

        // Shuffle probes and their meaning together, so the client can
        // de-shuffle while the server sees an unordered list.
        let mut paired: Vec<_> = probes.into_iter().zip(map).collect();
        self.shuffle(&mut paired);
        let (probes, map): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

        (Transcript { probes }, ProbeMap(map))
    }

    /// Evaluate any Boolean formula over the returned bits, for the covered
    /// candidates only: a pending one is never evaluated ([`Self::pending`]).
    ///
    /// The server's reply is a bit per probe, in probe order. Everything below
    /// happens after the transcript ends and is therefore invisible to it.
    #[must_use]
    pub fn evaluate(
        &self,
        candidates: &[DocId],
        x_terms: usize,
        map: &ProbeMap,
        bits: &[bool],
        formula: &Formula,
    ) -> BTreeSet<DocId> {
        // (id, term) → the one bit the server answered.
        let mut seen: BTreeMap<(DocId, usize), bool> = BTreeMap::new();
        for (slot, bit) in map.0.iter().zip(bits) {
            seen.insert(*slot, *bit);
        }

        candidates
            .iter()
            .filter(|&&id| self.is_covered(id))
            .filter(|&&id| {
                let matches: Vec<bool> = (0..x_terms)
                    .map(|t| seen.get(&(id, t)).copied().unwrap_or(false))
                    .collect();
                formula.eval(&matches)
            })
            .copied()
            .collect()
    }
}

/// What each probe meant, in probe order. Client-side only — the server never
/// receives this, which is precisely why the intersection pattern is hidden.
#[derive(Debug, Clone)]
pub struct ProbeMap(Vec<(DocId, usize)>);

impl ProbeMap {
    /// Number of probes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Server-side cross-tag storage, per epoch.
pub trait XSetStore {
    /// Add cross-tags to an epoch's set.
    fn add_xtags(&mut self, epoch: Epoch, tags: &[XTag]);

    /// Answer a probe list with one bit each, in probe order: whether the tag
    /// is in **any closed** epoch's set (the probes are unlabelled).
    fn probe(&self, transcript: &Transcript) -> Vec<bool>;

    /// Total cross-tags stored — an index-size figure.
    fn xtag_count(&self) -> usize;

    /// The epoch is closed: no more tags will arrive for it, and from now on
    /// probes are answered against it.
    ///
    /// A compressing store (`BloomXSet`) also sizes the epoch's filter here,
    /// from the epoch's actual load — the M10 P3 fix, since a filter sized in
    /// advance overfills whenever loads are uneven.
    fn seal_epoch(&mut self, epoch: Epoch);

    /// Discard every epoch's cross-tags.
    ///
    /// Called by compaction. On a real server this is the moment the old
    /// `XSet_e` become unreachable; the client destroying its epoch keys is
    /// what makes them uninterpretable even to a server that kept a copy.
    fn reset(&mut self);
}

/// The honest server's `XSet_e`, one sorted set per epoch.
///
/// Sorted because draft6's `0x03` Tier-2 leaf commits to `MerkleRoot(sorted
/// XSet_e)`, which is what lets a malicious server be made to prove both
/// membership and non-membership of a probe (design §11.1). That verified mode
/// is M8's experiment; the ordering it needs starts here.
#[derive(Debug, Default)]
pub struct HonestXSet {
    /// Hashed per epoch, as ODXT's `XSet` is; the sorted order the `0x03`
    /// leaf needs is produced where it is read ([`Self::epoch`],
    /// [`Self::all_epochs`]), not paid on every insert (§1q.5 profile).
    epochs: BTreeMap<Epoch, FastSet<XTag>>,
    /// Epochs sealed (closed): the only ones a probe is answered against.
    closed: BTreeSet<Epoch>,
}

impl HonestXSet {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The sorted cross-tags of one epoch, as the `0x03` leaf commits to them.
    /// Built on demand: the store itself is hashed.
    #[must_use]
    pub fn epoch(&self, e: Epoch) -> Option<BTreeSet<XTag>> {
        self.epochs.get(&e).map(|s| s.iter().copied().collect())
    }

    /// The sealed (closed) epochs: the ones a probe is answered against.
    #[must_use]
    pub fn closed_epochs(&self) -> Vec<Epoch> {
        self.closed.iter().copied().collect()
    }

    /// Every epoch and its tags.
    ///
    /// Exists so an alternative [`XSetStore`] — the Bloom filter of
    /// `crate::bloom` — can be loaded with **exactly** the tags the oracle
    /// holds. Rebuilding it from a second pass over the corpus would leave the
    /// two stores potentially disagreeing about their contents, which is the one
    /// thing an oracle comparison must rule out.
    #[must_use]
    pub fn all_epochs(&self) -> Vec<(Epoch, Vec<XTag>)> {
        self.epochs
            .iter()
            .map(|(e, tags)| {
                let mut v: Vec<XTag> = tags.iter().copied().collect();
                v.sort_unstable();
                (*e, v)
            })
            .collect()
    }
}

impl XSetStore for HonestXSet {
    fn add_xtags(&mut self, epoch: Epoch, tags: &[XTag]) {
        let set = self.epochs.entry(epoch).or_default();
        for t in tags {
            set.insert(*t);
        }
    }

    fn probe(&self, transcript: &Transcript) -> Vec<bool> {
        transcript
            .probes
            .iter()
            .map(|tag| {
                self.closed
                    .iter()
                    .any(|e| self.epochs.get(e).is_some_and(|s| s.contains(tag)))
            })
            .collect()
    }

    fn xtag_count(&self) -> usize {
        self.epochs.values().map(FastSet::len).sum()
    }

    fn seal_epoch(&mut self, epoch: Epoch) {
        self.closed.insert(epoch);
    }

    fn reset(&mut self) {
        self.epochs.clear();
        self.closed.clear();
    }
}

/// The honest server: an `EDB` and a per-epoch `XSet`, together.
///
/// One type because a real server is one process, and because the transcript
/// tests need to hand a single object to both rounds.
#[derive(Debug, Default)]
pub struct HonestServer {
    /// The `Π_core` index.
    pub edb: crate::core::HonestEdb,
    /// The cross-tag sets.
    pub xset: HonestXSet,
}

impl HonestServer {
    /// An empty server.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Edb for HonestServer {
    fn insert(&mut self, token: &crate::core::UpdateToken) {
        self.edb.insert(token);
    }
    fn search(&self, token: &crate::core::SearchToken) -> crate::core::SearchResponse {
        self.edb.search(token)
    }
    fn len(&self) -> usize {
        self.edb.len()
    }
}

impl XSetStore for HonestServer {
    fn add_xtags(&mut self, epoch: Epoch, tags: &[XTag]) {
        self.xset.add_xtags(epoch, tags);
    }
    fn probe(&self, transcript: &Transcript) -> Vec<bool> {
        self.xset.probe(transcript)
    }
    fn xtag_count(&self) -> usize {
        self.xset.xtag_count()
    }
    fn seal_epoch(&mut self, epoch: Epoch) {
        self.xset.seal_epoch(epoch);
    }
    fn reset(&mut self) {
        self.xset.reset();
    }
}

// ---------------------------------------------------------------- redaction

impl XtClient {
    /// Live `(keyword, document)` pairs — what compaction must rebuild.
    #[must_use]
    pub fn live_pairs(&self) -> usize {
        self.live.len()
    }

    /// Mark a `(keyword, document)` pair for erasure.
    ///
    /// **This does not erase anything yet.** Tombstoning removes the pair from
    /// the live set so the next compaction will not carry it forward; erasure
    /// *completes* at compaction, when the superseded epoch keys are destroyed.
    ///
    /// Design §12.3a: tombstoning the index alone is **not sufficient**. It
    /// stops an honest client probing the pair, but cross-tags from prior
    /// epochs persist in the server's sets, and an adversary who retained them
    /// and later obtains the epoch keys can still confirm the association.
    pub fn tombstone(&mut self, w: &[u8], id: DocId) {
        let pair = (self.intern(w), id);
        self.live.remove(&pair);
        self.tombstoned.insert(pair);
    }

    /// Whether a pair has been tombstoned.
    #[must_use]
    pub fn is_tombstoned(&self, w: &[u8], id: DocId) -> bool {
        self.keyword_ix
            .get(w)
            .is_some_and(|&ix| self.tombstoned.contains(&(ix, id)))
    }

    /// Compaction: re-key the cross-tag ratchet and rebuild `XSet` from the
    /// live set alone, destroying every superseded epoch key.
    ///
    /// `PQ-DSSE-Formal.md` §7.4. Costs `O(Σ_id |W_id|)` and resets `E` to 0,
    /// which is the whole reason to do it — the probe count is linear in `E`.
    ///
    /// # ⚠️ Tombstone before compaction, always
    ///
    /// Compaction rebuilds cross-tags for the **live** pairs. Compacting first
    /// carries a to-be-redacted pair into the new `XSet`, and then the
    /// redaction appears to succeed while doing nothing: the tombstone lands
    /// after the pair has already been re-keyed forward. `tests/redaction.rs`
    /// demonstrates that failure rather than merely warning about it.
    ///
    /// `seed` is the fresh **independent draw** for `K_X^(0)`. It must not be
    /// derived from any surviving key — that is the property that makes the
    /// erasure real rather than cosmetic.
    pub fn compact<S: XSetStore>(&mut self, store: &mut S, seed: PrfKey) {
        self.buffer.clear();

        let mut tags: Vec<XTag> = Vec::with_capacity(self.live.len());
        // The fresh ratchet starts AT the open epoch, which becomes the
        // compacted epoch: epoch numbers never repeat, so an identifier's `e`
        // stays unambiguous, and every record at or below it now maps here.
        let into = self.ratchet.epoch();
        let fresh = Ratchet::new_at(seed, into);
        // The pre-R2 `BTreeSet<(Vec<u8>, DocId)>` order, reproduced: the keyed
        // shuffle below is deterministic in its input order, and a `HashSet`
        // iterates in a per-process random one.
        let mut pairs: Vec<(&[u8], DocId)> = self
            .live
            .iter()
            .map(|&(ix, id)| (self.keyword_bytes[ix as usize].as_slice(), id))
            .collect();
        pairs.sort_unstable();
        for (w, id) in &pairs {
            // A live pair is one that was inserted and not deleted, so the
            // rebuilt set carries no tombstone history at all. That is also
            // why compaction shrinks XSet rather than just re-keying it.
            tags.push(Self::xtag(fresh.current(), w, *id));
        }

        store.reset();
        self.ratchet = fresh;
        self.shuffle(&mut tags);
        store.add_xtags(into, &tags);
        // Close it immediately: probes only ever touch closed epochs, so a
        // compaction that left everything in the open epoch would answer
        // nothing until the next epoch boundary.
        store.seal_epoch(into);
        self.ratchet.advance();
        self.compacted_at = Some(into);
        self.tombstoned.clear();
    }

    /// Every cross-tag an adversary *holding the client's master key* could
    /// derive for `(w, id)` across the epochs whose keys still exist.
    ///
    /// Exists for the M3b acceptance test. `PQ-ChainLog-DESIGN.md` §12.6
    /// requires re-deriving every tag the client **could** produce for a
    /// redacted pair and asserting none survives — a test that only checked
    /// the client's own current view would pass while the property failed.
    #[must_use]
    pub fn derivable_xtags(&self, w: &[u8], id: DocId) -> Vec<XTag> {
        let mut out = Vec::new();
        for e in self.ratchet.oldest_live_epoch()..=self.ratchet.epoch() {
            if let Some(k) = self.ratchet.key(e) {
                out.push(Self::xtag(k, w, id));
            }
        }
        out
    }
}
