//! GlassDB's ledger storage: a two-level pattern-oriented split tree.
//!
//! Cong Yue, Tien Tuan Anh Dinh, Zhongle Xie, Meihui Zhang, Gang Chen, Beng Chin
//! Ooi, Xiaokui Xiao, *"GlassDB: An Efficient Verifiable Ledger Database
//! System Through Transparency"*, PVLDB 16(6), 2023 (SAC `b32`).
//!
//! # Provenance of this code
//!
//! Transcribed from §3.2.1 (APIs, `VerifyBlock`), §3.3.1 and Fig. 3 (the
//! two-level POS-tree) of `ref-papers/p1359-ooi.pdf`, read directly
//! as the baseline reading rule in `baselines/UPGRADES.md` requires, with the extended version
//! (`doc/GlassDB_extended_version.pdf` in `nusdbsystem/LedgerDatabase`) for
//! batching (§3.3.3: a fixed batch size per block) and the batch size it
//! reports as space-efficient (§5.3.3: more than 1,000 keys). The authors'
//! public repository holds their four baselines but **not** GlassDB's own
//! POS-tree, so the chunker follows the POS-tree's origin, ForkBase
//! (`nusdbsystem/forkbase`, `include/node/rolling_hash.h`): a buzhash over a
//! 256-byte window, boundary when the low 12 bits are all ones, a 32 KiB cap.
//!
//! # The structure, as specified (Fig. 3)
//!
//! * **Lower level**: a POS-tree over the database state, sorted by key. A
//!   leaf entry is `(key, value, H_prev)`, where `H_prev` is the hash of the
//!   node holding the key's previous version (`H_Φ` for the first). Index
//!   entries are `(first key of child, H(child))`.
//! * **Data block** `BLK_B`: block number, timestamp, and the lower root's hash.
//! * **Upper level**: a POS-tree keyed by block number, each entry `(B, H(BLK_B))`.
//!   The hash of its root is the ledger **digest**.
//! * Nodes are split by **content-defined chunking**, so the tree's shape
//!   depends only on its content, never on the order of updates
//!   ("structurally invariant"). An update creates new nodes copy-on-write;
//!   every node ever created stays addressable by its hash.
//!
//! # What the court and the auditor do
//!
//! * **History of one key** ([`Ledger::prove`]): the current-value proof at
//!   the last block (upper path, `BLK`, lower path), then each previous
//!   version by following `H_prev` to the node that holds it.
//! * **`VerifyBlock`** ([`Ledger::verify_block`]): for one block, the block's
//!   proof against the digest, then every key the block's transactions wrote
//!   checked included, with its value, in that block's lower tree.
//!
//! # Deviations, all recorded in `../UPGRADES.md`
//!
//! SHAKE256 for BLAKE2b; the buzhash table drawn from SHAKE256 rather than
//! ForkBase's constant table; one shard (the paper partitions keys over nodes,
//! and an auditor checks each shard's blocks the same way).

#![allow(clippy::doc_markdown)] // system names (GlassDB, ForkBase, BLAKE2b) are prose here

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use tiny_keccak::{Hasher, Shake, Xof};

/// A 32-byte digest.
pub type Digest = [u8; 32];

/// One write of a transaction: `(key, value)`.
pub type Write = (Vec<u8>, Arc<[u8]>);

/// `H_Φ`, the "empty hash" of Fig. 3: the previous-version pointer of a key's
/// first version.
pub const EMPTY: Digest = [0u8; 32];

/// ForkBase's `kDefaultChunkWindow`.
pub const WINDOW: usize = 256;
/// ForkBase's `kDefaultChunkPattern`: twelve low bits, so ~4 KiB nodes.
pub const PATTERN: u32 = (1 << 12) - 1;
/// ForkBase's `kDefaultMaxChunkSize`.
pub const MAX_NODE_BYTES: usize = 1 << 15;
/// Writes per persist batch. The extended version (§5.3.3) reports GlassDB
/// most space-efficient above 1,000 keys per batch.
pub const BATCH: usize = 1000;

const KIND_LEAF: u8 = 0;
const KIND_INDEX: u8 = 1;
const KIND_BLOCK: u8 = 2;

fn hash(bytes: &[u8]) -> Digest {
    let mut h = Shake::v256();
    h.update(bytes);
    let mut out = [0u8; 32];
    h.squeeze(&mut out);
    out
}

fn table() -> &'static [u32; 256] {
    static T: OnceLock<[u32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut h = Shake::v256();
        h.update(b"GlassDB POS-tree buzhash table");
        let mut raw = [0u8; 1024];
        h.squeeze(&mut raw);
        let mut t = [0u32; 256];
        for (i, c) in raw.chunks_exact(4).enumerate() {
            t[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }
        t
    })
}

/// ForkBase's `RollingHasher::HashByte`, one node at a time.
struct Roller {
    ring: [u8; WINDOW],
    pos: usize,
    filled: usize,
    h: u32,
    hashed: usize,
    crossed: bool,
}

impl Roller {
    fn new() -> Self {
        Self {
            ring: [0; WINDOW],
            pos: 0,
            filled: 0,
            h: 0,
            hashed: 0,
            crossed: false,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        let t = table();
        for &b in bytes {
            self.hashed += 1;
            self.h = self.h.rotate_left(1);
            if self.filled == WINDOW {
                let out = self.ring[self.pos];
                #[allow(clippy::cast_possible_truncation)] // WINDOW % 32 < 32
                {
                    self.h ^= t[out as usize].rotate_left((WINDOW % 32) as u32);
                }
            } else {
                self.filled += 1;
            }
            self.h ^= t[b as usize];
            self.ring[self.pos] = b;
            self.pos = (self.pos + 1) % WINDOW;
            self.crossed = self.hashed >= WINDOW
                && (self.crossed || (self.h & PATTERN) == PATTERN || self.hashed == MAX_NODE_BYTES);
            if self.crossed {
                // The node ends after this entry; ForkBase stops hashing here.
                return;
            }
        }
    }
}

fn put_key(out: &mut Vec<u8>, key: &[u8]) {
    #[allow(clippy::cast_possible_truncation)] // keys are a few bytes
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(key);
}

/// A lower or upper **leaf** entry: `(key, value, H_prev)`.
fn leaf_entry(key: &[u8], value: &[u8], prev: &Digest) -> Vec<u8> {
    let mut e = Vec::with_capacity(2 + key.len() + 4 + value.len() + 32);
    put_key(&mut e, key);
    #[allow(clippy::cast_possible_truncation)] // values are records, far below 4 GiB
    e.extend_from_slice(&(value.len() as u32).to_be_bytes());
    e.extend_from_slice(value);
    e.extend_from_slice(prev);
    e
}

/// An **index** entry: `(first key of the child, H(child))`.
fn index_entry(key: &[u8], child: &Digest) -> Vec<u8> {
    let mut e = Vec::with_capacity(2 + key.len() + 32);
    put_key(&mut e, key);
    e.extend_from_slice(child);
    e
}

/// A cursor over a node's bytes.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn u32(&mut self) -> Option<usize> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    fn digest(&mut self) -> Option<Digest> {
        self.take(32).and_then(|b| b.try_into().ok())
    }
}

/// One step down from `node` towards `key`.
enum Step<'a> {
    /// An index node: descend to this child.
    Child(Digest),
    /// A leaf holding `key`: its value and `H_prev`.
    Found(&'a [u8], Digest),
}

/// Parse `node` and take one step towards `key`. `None` if the node is
/// malformed or `key` is not under it.
fn step<'a>(node: &'a [u8], key: &[u8]) -> Option<Step<'a>> {
    let (&kind, rest) = node.split_first()?;
    let mut r = Rd(rest);
    match kind {
        KIND_INDEX => {
            // The last child whose first key is <= key.
            let mut pick = None;
            while !r.0.is_empty() {
                let k = {
                    let n = r.u16()?;
                    r.take(n)?
                };
                let h = r.digest()?;
                if k <= key {
                    pick = Some(h);
                } else {
                    break;
                }
            }
            pick.map(Step::Child)
        }
        KIND_LEAF => {
            while !r.0.is_empty() {
                let k = {
                    let n = r.u16()?;
                    r.take(n)?
                };
                let v = {
                    let n = r.u32()?;
                    r.take(n)?
                };
                let p = r.digest()?;
                if k == key {
                    return Some(Step::Found(v, p));
                }
            }
            None
        }
        _ => None,
    }
}

/// Where a node sits within its level, and its hash.
#[derive(Debug, Clone)]
struct Node {
    start: usize,
    len: usize,
    hash: Digest,
}

/// One level: its entries in key order and the nodes they are chunked into.
#[derive(Debug, Default)]
struct Level {
    keys: Vec<Vec<u8>>,
    entries: Vec<Vec<u8>>,
    nodes: Vec<Node>,
}

/// Replace `removed` entries at `at` (old positions) with `entries`.
struct Splice {
    at: usize,
    removed: usize,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Every node ever created, by hash. Copy-on-write means old versions stay.
pub type Store = HashMap<Digest, Arc<[u8]>>;

/// A POS-tree: `levels[0]` holds the data entries, each level above indexes
/// the nodes of the one below, and the top level is one node.
#[derive(Debug, Default)]
struct PosTree {
    levels: Vec<Level>,
}

impl PosTree {
    fn root(&self) -> Option<Digest> {
        self.levels
            .last()
            .and_then(|l| l.nodes.first())
            .map(|n| n.hash)
    }

    /// Hash of the leaf node now holding `key`, if any.
    fn node_of(&self, key: &[u8]) -> Option<Digest> {
        let l = self.levels.first()?;
        let i = l.keys.binary_search_by(|k| k.as_slice().cmp(key)).ok()?;
        let n = l.nodes.partition_point(|n| n.start <= i);
        l.nodes.get(n.checked_sub(1)?).map(|n| n.hash)
    }

    /// Chunk `level`'s entries from `pos`: one node, ending after the entry at
    /// which the rolling hash crosses a boundary, or at the last entry.
    fn chunk(level: &Level, pos: usize, kind: u8, store: &mut Store) -> Node {
        let mut roller = Roller::new();
        let mut bytes = vec![kind];
        let mut end = level.entries.len();
        for (i, e) in level.entries.iter().enumerate().skip(pos) {
            bytes.extend_from_slice(e);
            roller.feed(e);
            if roller.crossed {
                end = i + 1;
                break;
            }
        }
        let h = hash(&bytes);
        store.entry(h).or_insert_with(|| bytes.into());
        Node {
            start: pos,
            len: end - pos,
            hash: h,
        }
    }

    /// Apply `splices` to level `k` and re-chunk only what they touched,
    /// resuming the old nodes at the first old boundary the new chunking
    /// meets. Returns the splices this makes in level `k + 1`.
    #[allow(clippy::too_many_lines)]
    fn apply_level(&mut self, k: usize, splices: Vec<Splice>, store: &mut Store) -> Vec<Splice> {
        let kind = if k == 0 { KIND_LEAF } else { KIND_INDEX };
        let level = &mut self.levels[k];
        let old = std::mem::take(&mut level.nodes);
        let meta: Vec<(usize, usize, usize)> = splices
            .iter()
            .map(|s| (s.at, s.removed, s.entries.len()))
            .collect();
        for s in splices.into_iter().rev() {
            let (ks, es): (Vec<_>, Vec<_>) = s.entries.into_iter().unzip();
            level.keys.splice(s.at..s.at + s.removed, ks);
            level.entries.splice(s.at..s.at + s.removed, es);
        }
        let n_new = level.entries.len();
        let mut parent = Vec::new();
        if old.is_empty() {
            let mut produced = Vec::new();
            let mut pos = 0;
            while pos < n_new {
                let node = Self::chunk(level, pos, kind, store);
                pos = node.start + node.len;
                produced.push(node);
            }
            parent.push(Splice {
                at: 0,
                removed: 0,
                entries: produced.iter().map(|n| Self::up(level, n)).collect(),
            });
            level.nodes = produced;
            return parent;
        }
        // Which old nodes a splice touches. An insertion at the very end
        // touches the last node, whose end was the data's end, not a boundary.
        let mut dirty = vec![false; old.len()];
        for &(at, removed, _) in &meta {
            let first = old
                .partition_point(|n| n.start + n.len <= at)
                .min(old.len() - 1);
            let last = if removed == 0 {
                first
            } else {
                old.partition_point(|n| n.start < at + removed)
                    .saturating_sub(1)
            };
            for d in &mut dirty[first..=last.max(first)] {
                *d = true;
            }
        }
        // New start of every clean node: shifted by every splice before it.
        let mut new_start = vec![0usize; old.len()];
        let (mut si, mut shift) = (0usize, 0isize);
        for (j, n) in old.iter().enumerate() {
            while si < meta.len() && meta[si].0 < n.start {
                #[allow(clippy::cast_possible_wrap)]
                {
                    shift += meta[si].2 as isize - meta[si].1 as isize;
                }
                si += 1;
            }
            #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
            {
                new_start[j] = (n.start as isize + shift) as usize;
            }
        }
        let mut nodes = Vec::with_capacity(old.len() + 8);
        let mut j = 0;
        while j < old.len() {
            if !dirty[j] {
                nodes.push(Node {
                    start: new_start[j],
                    ..old[j].clone()
                });
                j += 1;
                continue;
            }
            // A dirty node's start is the end of a clean predecessor (or 0),
            // so it is a real boundary and chunking can restart there.
            let first = j;
            let mut pos = if j == 0 {
                0
            } else {
                nodes.last().map_or(0, |n: &Node| n.start + n.len)
            };
            let mut produced = Vec::new();
            loop {
                let node = Self::chunk(level, pos, kind, store);
                pos = node.start + node.len;
                produced.push(node);
                if pos >= n_new {
                    j = old.len();
                    break;
                }
                while j < old.len() && (dirty[j] || new_start[j] < pos) {
                    j += 1;
                }
                if j < old.len() && new_start[j] == pos {
                    break; // resynchronised with the old chunking
                }
            }
            parent.push(Splice {
                at: first,
                removed: j - first,
                entries: produced.iter().map(|n| Self::up(level, n)).collect(),
            });
            nodes.extend(produced);
        }
        level.nodes = nodes;
        parent
    }

    /// The index entry level `k + 1` keeps for `node`.
    fn up(level: &Level, node: &Node) -> (Vec<u8>, Vec<u8>) {
        let key = level.keys[node.start].clone();
        let e = index_entry(&key, &node.hash);
        (key, e)
    }

    /// Apply `splices` to the data level and propagate to the root.
    fn apply(&mut self, splices: Vec<Splice>, store: &mut Store) {
        if self.levels.is_empty() {
            self.levels.push(Level::default());
        }
        let mut sp = splices;
        let mut k = 0;
        loop {
            if sp.is_empty() {
                return;
            }
            let up = self.apply_level(k, sp, store);
            if self.levels[k].nodes.len() <= 1 {
                self.levels.truncate(k + 1);
                return;
            }
            if k + 1 == self.levels.len() {
                // A new top level indexes every node of this one.
                self.levels.push(Level::default());
                let l = &self.levels[k];
                sp = vec![Splice {
                    at: 0,
                    removed: 0,
                    entries: l.nodes.iter().map(|n| Self::up(l, n)).collect(),
                }];
            } else {
                sp = up;
            }
            k += 1;
        }
    }

    /// Insert or replace sorted, distinct `(key, entry)` pairs in the data level.
    fn upsert(&mut self, mut writes: Vec<(Vec<u8>, Vec<u8>)>, store: &mut Store) {
        writes.sort_by(|a, b| a.0.cmp(&b.0));
        let keys = self.levels.first().map(|l| &l.keys);
        let splices = writes
            .into_iter()
            .map(|(key, e)| {
                let found = keys.map(|ks| ks.binary_search(&key));
                let (at, removed) = match found {
                    Some(Ok(i)) => (i, 1),
                    Some(Err(i)) => (i, 0),
                    None => (0, 0),
                };
                Splice {
                    at,
                    removed,
                    entries: vec![(key, e)],
                }
            })
            .collect::<Vec<_>>();
        // Distinct keys arrive sorted, so the splices are sorted and disjoint,
        // except insertions at one gap, which merge.
        let mut merged: Vec<Splice> = Vec::with_capacity(splices.len());
        for s in splices {
            match merged.last_mut() {
                Some(m) if m.removed == 0 && s.removed == 0 && m.at == s.at => {
                    m.entries.extend(s.entries);
                }
                _ => merged.push(s),
            }
        }
        self.apply(merged, store);
    }
}

/// One persisted block, as the auditor's `VerifyBlock` receives it.
#[derive(Debug, Clone)]
pub struct Block {
    /// `H(BLK_B)`.
    pub hash: Digest,
    /// The lower root this block snapshots.
    pub lower_root: Digest,
    /// The block's signed transactions' writes: `(key, value)`.
    pub writes: Vec<Write>,
}

/// A GlassDB shard's ledger.
#[derive(Debug, Default)]
pub struct Ledger {
    lower: PosTree,
    upper: PosTree,
    store: Store,
    blocks: Vec<Block>,
}

/// An upper-level key: the block number, big-endian so byte order is number order.
fn block_key(b: u64) -> Vec<u8> {
    b.to_be_bytes().to_vec()
}

/// A history disclosure: the block it is proven at and the nodes, each once.
#[derive(Debug, Clone)]
pub struct Proof {
    /// The block whose snapshot the current values are proven in.
    pub block: u64,
    /// Every node the proof needs, de-duplicated.
    pub nodes: Vec<Arc<[u8]>>,
}

impl Proof {
    /// Bytes on the wire: the block number, then each node with a length.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        8 + self.nodes.iter().map(|n| 4 + n.len()).sum::<usize>()
    }
}

/// What a verified [`Proof`] establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// For each current-value key, its value.
    pub current: Vec<Vec<u8>>,
    /// For each history key, every version, newest first.
    pub history: Vec<Vec<Vec<u8>>>,
}

impl Ledger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The ledger digest `H(UR)`.
    #[must_use]
    pub fn digest(&self) -> Option<Digest> {
        self.upper.root()
    }

    /// The persisted blocks.
    #[must_use]
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Nodes stored, all versions.
    #[must_use]
    pub fn stored_nodes(&self) -> usize {
        self.store.len()
    }

    /// Persist one batch of writes in commit order. The `j`-th write to a key
    /// within the batch lands in the batch's `j`-th block, so each block holds
    /// one version per key and every version is in some block's snapshot
    /// (§3.3.2: a version's block is the current block plus its sequence).
    pub fn persist(&mut self, writes: &[Write]) {
        for batch in writes.chunks(BATCH) {
            let mut seen: HashMap<&[u8], usize> = HashMap::new();
            let mut per_block: Vec<Vec<Write>> = Vec::new();
            for (k, v) in batch {
                let j = seen.entry(k.as_slice()).or_insert(0);
                if per_block.len() <= *j {
                    per_block.push(Vec::new());
                }
                per_block[*j].push((k.clone(), v.clone()));
                *j += 1;
            }
            for b in per_block {
                self.commit_block(b);
            }
        }
    }

    fn commit_block(&mut self, writes: Vec<Write>) {
        let entries = writes
            .iter()
            .map(|(k, v)| {
                let prev = self.lower.node_of(k).unwrap_or(EMPTY);
                (k.clone(), leaf_entry(k, v, &prev))
            })
            .collect();
        self.lower.upsert(entries, &mut self.store);
        let Some(lower_root) = self.lower.root() else {
            return;
        };
        let no = self.blocks.len() as u64;
        let mut blk = vec![KIND_BLOCK];
        blk.extend_from_slice(&no.to_be_bytes());
        blk.extend_from_slice(&(1_700_000_000 + no).to_be_bytes()); // t_B
        blk.extend_from_slice(&lower_root);
        #[allow(clippy::cast_possible_truncation)]
        blk.extend_from_slice(&(writes.len() as u32).to_be_bytes());
        let h = hash(&blk);
        self.store.insert(h, blk.into());
        let key = block_key(no);
        let e = leaf_entry(&key, &h, &EMPTY);
        self.upper.upsert(vec![(key, e)], &mut self.store);
        self.blocks.push(Block {
            hash: h,
            lower_root,
            writes,
        });
    }

    fn node(&self, h: &Digest) -> Option<&Arc<[u8]>> {
        self.store.get(h)
    }

    /// The nodes on the way from `root` to `key`, and what was found there.
    fn path(&self, root: &Digest, key: &[u8], out: &mut Vec<Digest>) -> Option<(Vec<u8>, Digest)> {
        let mut at = *root;
        loop {
            out.push(at);
            match step(self.node(&at)?, key)? {
                Step::Child(c) => at = c,
                Step::Found(v, p) => return Some((v.to_vec(), p)),
            }
        }
    }

    /// The court's disclosure: the current value of each of `current`, and
    /// the full version history of each of `history`, at the last block.
    #[must_use]
    pub fn prove(&self, current: &[&[u8]], history: &[&[u8]]) -> Option<Proof> {
        let last = self.blocks.len().checked_sub(1)? as u64;
        let mut want = Vec::new();
        let (blk, _) = self.path(&self.digest()?, &block_key(last), &mut want)?;
        let blk: Digest = blk.try_into().ok()?;
        want.push(blk);
        let lower = self.blocks.last()?.lower_root;
        for k in current {
            self.path(&lower, k, &mut want)?;
        }
        for k in history {
            let (_, mut prev) = self.path(&lower, k, &mut want)?;
            while prev != EMPTY {
                want.push(prev);
                match step(self.node(&prev)?, k)? {
                    Step::Found(_, p) => prev = p,
                    Step::Child(_) => return None,
                }
            }
        }
        let mut seen = HashSet::new();
        let nodes = want
            .into_iter()
            .filter(|h| seen.insert(*h))
            .map(|h| self.node(&h).cloned())
            .collect::<Option<Vec<_>>>()?;
        Some(Proof { block: last, nodes })
    }

    /// The court's check of a [`Proof`] against the anchored `digest`: every
    /// node hashed once, then each key walked down from the digest.
    #[must_use]
    pub fn verify(
        digest: &Digest,
        proof: &Proof,
        current: &[&[u8]],
        history: &[&[u8]],
    ) -> Option<Verified> {
        let map: HashMap<Digest, &[u8]> = proof.nodes.iter().map(|n| (hash(n), &n[..])).collect();
        let walk = |root: &Digest, key: &[u8]| -> Option<(&[u8], Digest)> {
            let mut at = *root;
            loop {
                match step(map.get(&at)?, key)? {
                    Step::Child(c) => at = c,
                    Step::Found(v, p) => return Some((v, p)),
                }
            }
        };
        let (blk_h, _) = walk(digest, &block_key(proof.block))?;
        let blk_h: Digest = blk_h.try_into().ok()?;
        let lower = parse_block(map.get(&blk_h)?, proof.block)?;
        let current = current
            .iter()
            .map(|k| walk(&lower, k).map(|(v, _)| v.to_vec()))
            .collect::<Option<Vec<_>>>()?;
        let mut hist = Vec::with_capacity(history.len());
        for k in history {
            let (v, mut prev) = walk(&lower, k)?;
            let mut versions = vec![v.to_vec()];
            while prev != EMPTY {
                match step(map.get(&prev)?, k)? {
                    Step::Found(v, p) => {
                        versions.push(v.to_vec());
                        prev = p;
                    }
                    Step::Child(_) => return None,
                }
            }
            hist.push(versions);
        }
        Some(Verified {
            current,
            history: hist,
        })
    }

    /// `VerifyBlock(digest, b)`: block `b`'s proof against `digest`, then
    /// every write of its transactions included, with its value, in its lower
    /// tree. Nodes already hashed for this auditor are in `memo` and are not
    /// hashed again: every node is immutable and named by its hash.
    #[must_use]
    pub fn verify_block(&self, b: usize, digest: &Digest, memo: &mut HashSet<Digest>) -> bool {
        let Some(block) = self.blocks.get(b) else {
            return false;
        };
        let mut checked = |h: &Digest| -> Option<&[u8]> {
            let n = self.node(h)?;
            if !memo.contains(h) {
                if hash(n) != *h {
                    return None;
                }
                memo.insert(*h);
            }
            Some(&n[..])
        };
        let mut walk = |root: &Digest, key: &[u8]| -> Option<(Vec<u8>, Digest)> {
            let mut at = *root;
            loop {
                match step(checked(&at)?, key)? {
                    Step::Child(c) => at = c,
                    Step::Found(v, p) => return Some((v.to_vec(), p)),
                }
            }
        };
        let Some((blk_h, _)) = walk(digest, &block_key(b as u64)) else {
            return false;
        };
        if blk_h != block.hash {
            return false;
        }
        let Some(blk) = self.node(&block.hash) else {
            return false;
        };
        if hash(blk) != block.hash || parse_block(blk, b as u64) != Some(block.lower_root) {
            return false;
        }
        block
            .writes
            .iter()
            .all(|(k, v)| walk(&block.lower_root, k).is_some_and(|(got, _)| got == **v))
    }
}

/// A data block's lower root, if `bytes` is block `no`.
fn parse_block(bytes: &[u8], no: u64) -> Option<Digest> {
    let (&kind, rest) = bytes.split_first()?;
    let mut r = Rd(rest);
    let n = u64::from_be_bytes(r.take(8)?.try_into().ok()?);
    let _ts = r.take(8)?;
    let root = r.digest()?;
    (kind == KIND_BLOCK && n == no).then_some(root)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::range_plus_one,
        clippy::many_single_char_names
    )]
    use super::*;

    fn val(i: usize, v: usize, len: usize) -> Arc<[u8]> {
        let mut x = format!("value {i} version {v} ").into_bytes();
        x.resize(len, u8::try_from(i % 251).unwrap_or(0));
        x.into()
    }

    fn key(i: usize) -> Vec<u8> {
        (i as u64).to_be_bytes().to_vec()
    }

    /// A tree built in one go over `entries`.
    fn fresh(entries: &[(Vec<u8>, Vec<u8>)]) -> Option<Digest> {
        let mut t = PosTree::default();
        let mut s = Store::new();
        t.upsert(entries.to_vec(), &mut s);
        t.root()
    }

    #[test]
    fn structurally_invariant_under_any_update_order() {
        // The POS-tree's defining property (§3.3.1): the same content gives the
        // same tree, whatever order it arrived in. Incremental re-chunking is
        // checked against a from-scratch build after every batch.
        let mut t = PosTree::default();
        let mut s = Store::new();
        let mut state = std::collections::BTreeMap::<Vec<u8>, Vec<u8>>::default();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = |m: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % m as u64) as usize
        };
        for round in 0..60 {
            let mut batch = std::collections::BTreeMap::new();
            for _ in 0..(1 + rnd(120)) {
                let k = key(rnd(4000));
                let e = leaf_entry(&k, &val(round, rnd(9), 40 + rnd(400)), &EMPTY);
                batch.insert(k, e);
            }
            for (k, e) in &batch {
                state.insert(k.clone(), e.clone());
            }
            t.upsert(batch.into_iter().collect(), &mut s);
            let all: Vec<_> = state.iter().map(|(k, e)| (k.clone(), e.clone())).collect();
            assert_eq!(t.root(), fresh(&all), "round {round}");
        }
        assert!(t.levels.len() >= 3, "the test must exercise index levels");
    }

    fn ledger(keys: usize, writes: usize) -> (Ledger, Vec<Write>) {
        // Mostly appends at the end, as a stable capsule id is assigned at
        // intake, plus updates to a sliding window of open keys.
        let mut w = Vec::new();
        let mut version = vec![0usize; keys];
        for i in 0..writes {
            let k = (i * 7 + i / 13) % keys;
            version[k] += 1;
            w.push((key(k), val(k, version[k], 300 + (k % 5) * 200)));
        }
        let mut l = Ledger::new();
        l.persist(&w);
        (l, w)
    }

    #[test]
    fn history_of_every_key_verifies_and_is_complete() {
        let (l, w) = ledger(300, 4000);
        let d = l.digest().expect("non-empty");
        for k in [0usize, 1, 150, 299] {
            let kk = key(k);
            let p = l.prove(&[], &[&kk]).expect("provable");
            let v = Ledger::verify(&d, &p, &[], &[&kk]).expect("verifies");
            let mut want: Vec<Vec<u8>> = w
                .iter()
                .filter(|(x, _)| *x == kk)
                .map(|(_, v)| v.to_vec())
                .collect();
            want.reverse();
            assert_eq!(v.history[0], want, "key {k}");
        }
    }

    #[test]
    fn a_changed_node_or_wrong_digest_fails() {
        let (l, _) = ledger(200, 2500);
        let d = l.digest().expect("non-empty");
        let k = key(42);
        let p = l.prove(&[&key(7)], &[&k]).expect("provable");
        assert!(Ledger::verify(&d, &p, &[&key(7)], &[&k]).is_some());
        for i in 0..p.nodes.len() {
            let mut q = p.clone();
            let mut n = q.nodes[i].to_vec();
            let at = n.len() / 2;
            n[at] ^= 1;
            q.nodes[i] = n.into();
            assert!(
                Ledger::verify(&d, &q, &[&key(7)], &[&k]).is_none(),
                "node {i}"
            );
        }
        let mut bad = d;
        bad[0] ^= 1;
        assert!(Ledger::verify(&bad, &p, &[&key(7)], &[&k]).is_none());
    }

    #[test]
    fn every_block_verifies_and_a_wrong_write_does_not() {
        let (mut l, _) = ledger(150, 3000);
        let d = l.digest().expect("non-empty");
        assert!(l.blocks().len() > 3);
        let mut memo = HashSet::new();
        for b in 0..l.blocks().len() {
            assert!(l.verify_block(b, &d, &mut memo), "block {b}");
        }
        // A transaction value the ledger does not hold.
        l.blocks[2].writes[0].1 = val(9999, 1, 10);
        assert!(!l.verify_block(2, &d, &mut HashSet::new()));
    }

    #[test]
    fn one_version_per_key_per_block() {
        let (l, w) = ledger(50, 1200);
        let total: usize = l.blocks().iter().map(|b| b.writes.len()).sum();
        assert_eq!(total, w.len());
        for b in l.blocks() {
            let mut ks: Vec<_> = b.writes.iter().map(|(k, _)| k).collect();
            ks.sort();
            let n = ks.len();
            ks.dedup();
            assert_eq!(ks.len(), n);
        }
    }

    #[test]
    fn chunking_follows_forkbase() {
        // No boundary inside the first window; the cap forces one.
        let mut r = Roller::new();
        r.feed(&[0u8; WINDOW - 1]);
        assert!(!r.crossed);
        let mut r = Roller::new();
        let big = vec![7u8; MAX_NODE_BYTES];
        r.feed(&big);
        assert!(r.crossed && r.hashed <= MAX_NODE_BYTES);
    }
}
