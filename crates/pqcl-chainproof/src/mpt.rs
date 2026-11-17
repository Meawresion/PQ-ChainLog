//! The Merkle-Patricia trie, enough of it to build and verify receipt proofs.
//!
//! # Which half matters
//!
//! [`verify`] is the security-critical half — it is what runs inside the Secure
//! Module, and it must accept a value only when the proof genuinely chains to
//! the committed root. [`Trie`] is the generating half, used by whoever holds
//! the block's receipts (the AIS, or a test) to produce a proof in the first
//! place.
//!
//! They are kept in one module deliberately: the tests build a trie, take a
//! proof from it, and verify it, so a disagreement between the two shows up
//! immediately rather than at integration time.
//!
//! # The encoding rules that bite
//!
//! * **Nibbles, not bytes.** Keys are traversed a nibble at a time, so a
//!   2-byte key is a 4-step path.
//! * **Hex-prefix encoding.** A node's path fragment carries a prefix nibble
//!   saying whether it is a leaf or an extension and whether the nibble count
//!   is odd, because nibbles do not divide evenly into bytes.
//! * ⚠️ **Nodes shorter than 32 bytes are inlined, not hashed.** A child is
//!   referenced by its hash only when its RLP is 32 bytes or longer; below that
//!   the RLP itself is embedded. Receipt tries are small, so this case is
//!   common rather than exotic — a verifier that always expects a hash fails on
//!   most real blocks.

use crate::rlp::{self, Rlp};
use crate::{ProofError, keccak256};

/// Split a byte string into nibbles, high half first.
fn nibbles(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() * 2);
    for &b in key {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

/// Hex-prefix encoding: pack nibbles into bytes with a type/parity prefix.
///
/// The prefix nibble is `2*is_leaf + is_odd`, and when the count is even a zero
/// padding nibble follows it.
fn hex_prefix(path: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag = u8::from(is_leaf) * 2;
    let odd = path.len() % 2 == 1;

    let mut nib = Vec::with_capacity(path.len() + 2);
    if odd {
        nib.push(flag + 1);
    } else {
        nib.push(flag);
        nib.push(0);
    }
    nib.extend_from_slice(path);

    nib.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

/// Undo [`hex_prefix`], returning the nibble path and whether it is a leaf.
fn parse_hex_prefix(encoded: &[u8]) -> Result<(Vec<u8>, bool), ProofError> {
    let first = *encoded
        .first()
        .ok_or(ProofError::Trie("empty hex-prefix path"))?;
    let flag = first >> 4;
    let is_leaf = flag & 2 != 0;
    let odd = flag & 1 != 0;

    let mut path = nibbles(encoded);
    // Drop the prefix nibble, plus the padding nibble when the count is even.
    path.drain(..if odd { 1 } else { 2 });

    if flag > 3 {
        return Err(ProofError::Trie("invalid hex-prefix flag"));
    }
    Ok((path, is_leaf))
}

/// How a node refers to a child.
enum Child<'a> {
    /// A 32-byte hash: look the child up among the proof nodes.
    Hash(&'a [u8]),
    /// The child's RLP, embedded because it is shorter than 32 bytes.
    Inline(Rlp<'a>),
    /// No child.
    Empty,
}

fn child_of<'a>(item: &Rlp<'a>) -> Result<Child<'a>, ProofError> {
    match item {
        Rlp::Bytes([]) => Ok(Child::Empty),
        Rlp::Bytes(b) if b.len() == 32 => Ok(Child::Hash(b)),
        Rlp::Bytes(_) => Err(ProofError::Trie(
            "a child reference must be empty or exactly 32 bytes",
        )),
        // An inlined node is a list, never a hash.
        list @ Rlp::List(_) => Ok(Child::Inline(list.clone())),
    }
}

/// Verify that `key` maps to some value under `root`, and return that value.
///
/// `proof` is the set of nodes on the path from the root, in any order — they
/// are looked up by hash, so ordering carries no trust.
///
/// # Errors
///
/// [`ProofError`] if the proof does not chain to `root`, if a node is
/// malformed, or if the key is absent. **Absence is an error, not `None`**: the
/// caller is asking to be shown a receipt, and "there isn't one" must not be
/// mistakable for "here it is".
pub fn verify<'p>(
    root: &[u8; 32],
    key: &[u8],
    proof: &'p [Vec<u8>],
) -> Result<Vec<u8>, ProofError> {
    // Index the proof by node hash. A node nothing references is simply never
    // consulted, which is why the order the caller supplies carries no trust.
    let by_hash: Vec<([u8; 32], &'p [u8])> =
        proof.iter().map(|n| (keccak256(n), n.as_slice())).collect();
    let lookup = |h: &[u8]| -> Option<&'p [u8]> {
        by_hash
            .iter()
            .find(|(hash, _)| hash.as_slice() == h)
            .map(|(_, node)| *node)
    };

    let path = nibbles(key);
    let mut at = 0usize;

    // Everything below borrows from `proof`, including inlined children, which
    // are sub-slices of their parent's buffer. That is why no cloning is
    // needed: one lifetime covers the whole walk.
    let mut current = rlp::decode(lookup(root).ok_or(ProofError::RootNotInProof)?)?;

    // Bounded so a cyclic or adversarial proof cannot spin forever. A receipt
    // trie over one block's transactions is far shallower than this.
    for _ in 0..64 {
        let items = current.list()?;

        let next: Rlp<'p> = match items.len() {
            // Leaf or extension.
            2 => {
                let (frag, is_leaf) = parse_hex_prefix(items[0].bytes()?)?;
                if !path.get(at..).unwrap_or(&[]).starts_with(&frag) {
                    return Err(ProofError::KeyNotFound);
                }
                at += frag.len();

                if is_leaf {
                    // A leaf answers only for the exact key. Returning its
                    // value for a prefix would be the classic wrong-key
                    // acceptance.
                    if at != path.len() {
                        return Err(ProofError::KeyNotFound);
                    }
                    return Ok(items[1].bytes()?.to_vec());
                }

                descend(&items[1], &lookup)?
            }

            // Branch: 16 children plus a value slot.
            17 => {
                if at == path.len() {
                    return Ok(items[16].bytes()?.to_vec());
                }
                let nib = usize::from(path[at]);
                at += 1;
                descend(&items[nib], &lookup)?
            }

            0 => return Err(ProofError::Trie("empty trie node")),
            _ => return Err(ProofError::Trie("a trie node must have 2 or 17 items")),
        };

        current = next;
    }

    Err(ProofError::Trie("proof exceeded the maximum trie depth"))
}

/// Resolve a child reference into the node it names.
fn descend<'p>(
    item: &Rlp<'p>,
    lookup: &impl Fn(&[u8]) -> Option<&'p [u8]>,
) -> Result<Rlp<'p>, ProofError> {
    match child_of(item)? {
        Child::Hash(h) => rlp::decode(lookup(h).ok_or(ProofError::MissingNode)?),
        Child::Inline(node) => Ok(node),
        Child::Empty => Err(ProofError::KeyNotFound),
    }
}

// ------------------------------------------------------------- generation

/// A trie built in memory, for producing proofs.
///
/// Deliberately simple: receipt tries hold one entry per transaction in a
/// block, so they are small and shallow, and a straightforward recursive
/// construction is easier to check by eye than a fast one.
#[derive(Debug, Default)]
pub struct Trie {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug)]
enum Node {
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>, Box<Node>),
    Branch(Box<[Option<Node>; 16]>, Option<Vec<u8>>),
}

impl Trie {
    /// An empty trie.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a key/value pair.
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.entries.retain(|(k, _)| k != &key);
        self.entries.push((key, value));
    }

    fn build(&self) -> Option<Node> {
        let mut items: Vec<(Vec<u8>, Vec<u8>)> = self
            .entries
            .iter()
            .map(|(k, v)| (nibbles(k), v.clone()))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        build_node(&items)
    }

    /// The trie root hash. An empty trie hashes the RLP of the empty string,
    /// which is the well-known `0x56e8…` constant Ethereum uses.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        // ⚠️ The root is hashed regardless of length. The under-32-byte
        // inlining rule governs how a *parent* refers to a child; the root has
        // no parent, so it is always presented as a hash.
        self.build().map_or_else(
            || keccak256(&rlp::encode_bytes(&[])),
            |n| keccak256(&encode_node(&n)),
        )
    }

    /// Every node on the path to `key`, as the proof the verifier consumes.
    #[must_use]
    pub fn proof(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let Some(root) = self.build() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        collect(&root, &nibbles(key), 0, true, &mut out);
        out
    }
}

fn build_node(items: &[(Vec<u8>, Vec<u8>)]) -> Option<Node> {
    match items.len() {
        0 => None,
        1 => Some(Node::Leaf(items[0].0.clone(), items[0].1.clone())),
        _ => {
            // Factor out any path all keys share.
            let common = items[0]
                .0
                .iter()
                .enumerate()
                .take_while(|&(i, nib)| items.iter().all(|(k, _)| k.get(i) == Some(nib)))
                .count();

            if common > 0 {
                let stripped: Vec<(Vec<u8>, Vec<u8>)> = items
                    .iter()
                    .map(|(k, v)| (k[common..].to_vec(), v.clone()))
                    .collect();
                let child = build_node(&stripped)?;
                return Some(Node::Extension(
                    items[0].0[..common].to_vec(),
                    Box::new(child),
                ));
            }

            let mut buckets: [Vec<(Vec<u8>, Vec<u8>)>; 16] = core::array::from_fn(|_| Vec::new());
            let mut here = None;
            for (k, v) in items {
                if k.is_empty() {
                    here = Some(v.clone());
                } else {
                    buckets[usize::from(k[0])].push((k[1..].to_vec(), v.clone()));
                }
            }
            let children: [Option<Node>; 16] = core::array::from_fn(|i| build_node(&buckets[i]));
            Some(Node::Branch(Box::new(children), here))
        }
    }
}

fn encode_node(node: &Node) -> Vec<u8> {
    match node {
        Node::Leaf(path, value) => rlp::encode_list(&[
            rlp::encode_bytes(&hex_prefix(path, true)),
            rlp::encode_bytes(value),
        ]),
        Node::Extension(path, child) => rlp::encode_list(&[
            rlp::encode_bytes(&hex_prefix(path, false)),
            reference(child),
        ]),
        Node::Branch(children, value) => {
            let mut items: Vec<Vec<u8>> = children
                .iter()
                .map(|c| c.as_ref().map_or_else(|| rlp::encode_bytes(&[]), reference))
                .collect();
            items.push(match value {
                Some(v) => rlp::encode_bytes(v),
                None => rlp::encode_bytes(&[]),
            });
            rlp::encode_list(&items)
        }
    }
}

/// How a parent refers to a child: the child's RLP if under 32 bytes, its hash
/// otherwise. This is the inlining rule, and it is the one most easily got
/// wrong — see the module docs.
fn reference(node: &Node) -> Vec<u8> {
    let enc = encode_node(node);
    if enc.len() < 32 {
        enc
    } else {
        rlp::encode_bytes(&keccak256(&enc))
    }
}

fn collect(node: &Node, path: &[u8], at: usize, is_root: bool, out: &mut Vec<Vec<u8>>) {
    let enc = encode_node(node);

    // ⭐ **The root is always included, however short it is.** Everywhere else
    // a node under 32 bytes is inlined into its parent and never looked up by
    // hash, so shipping it would be dead weight. The root has no parent: the
    // verifier starts by resolving `receiptsRoot` as a hash, so a small root
    // that was skipped here makes every single-entry trie unverifiable — which
    // is precisely a block with one transaction, the common case on our chain.
    if is_root || enc.len() >= 32 {
        out.push(enc);
    }

    match node {
        Node::Leaf(_, _) => {}
        Node::Extension(frag, child) => {
            if path.get(at..).is_some_and(|r| r.starts_with(frag)) {
                collect(child, path, at + frag.len(), false, out);
            }
        }
        Node::Branch(children, _) => {
            if let Some(child) = path
                .get(at)
                .and_then(|&nib| children[usize::from(nib)].as_ref())
            {
                collect(child, path, at + 1, false, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn hex_prefix_matches_the_yellow_paper() {
        // Even-length extension: prefix 0, then a padding nibble.
        assert_eq!(hex_prefix(&[1, 2, 3, 4], false), vec![0x00, 0x12, 0x34]);
        // Odd-length extension: prefix 1, no padding.
        assert_eq!(hex_prefix(&[1, 2, 3], false), vec![0x11, 0x23]);
        // Even-length leaf: prefix 2, then padding.
        assert_eq!(hex_prefix(&[1, 2, 3, 4], true), vec![0x20, 0x12, 0x34]);
        // Odd-length leaf: prefix 3.
        assert_eq!(hex_prefix(&[1, 2, 3], true), vec![0x31, 0x23]);
    }

    #[test]
    fn hex_prefix_round_trips() {
        for path in [vec![], vec![1], vec![1, 2], vec![0xf, 0, 0xa, 3, 7]] {
            for is_leaf in [true, false] {
                let enc = hex_prefix(&path, is_leaf);
                let (back, leaf) = parse_hex_prefix(&enc).expect("parses");
                assert_eq!(back, path);
                assert_eq!(leaf, is_leaf);
            }
        }
    }

    #[test]
    fn an_empty_trie_has_the_known_root() {
        // keccak256(rlp("")) — the constant every Ethereum client uses for an
        // empty trie.
        let expect = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
        let got = hex(&Trie::new().root());
        assert_eq!(got, expect);
    }

    fn round_trip(pairs: &[(Vec<u8>, Vec<u8>)]) {
        let mut t = Trie::new();
        for (k, v) in pairs {
            t.insert(k.clone(), v.clone());
        }
        let root = t.root();
        for (k, v) in pairs {
            let proof = t.proof(k);
            let got =
                verify(&root, k, &proof).unwrap_or_else(|e| panic!("proof for {k:?} failed: {e}"));
            assert_eq!(&got, v, "wrong value for {k:?}");
        }
    }

    #[test]
    fn a_single_entry_verifies() {
        round_trip(&[(rlp::encode_u64(0), b"receipt-zero".to_vec())]);
    }

    #[test]
    fn a_receipt_trie_shaped_set_verifies() {
        // Keys are rlp(index) exactly as a receipt trie uses.
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..12u64)
            .map(|i| (rlp::encode_u64(i), format!("receipt-{i}").into_bytes()))
            .collect();
        round_trip(&pairs);
    }

    #[test]
    fn large_values_that_force_hashed_children_verify() {
        // Values long enough that nodes exceed 32 bytes and must be referenced
        // by hash rather than inlined — the other side of the inlining rule.
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..8u64)
            .map(|i| (rlp::encode_u64(i), vec![u8::try_from(i).unwrap_or(0); 200]))
            .collect();
        round_trip(&pairs);
    }

    #[test]
    fn a_deep_shared_prefix_verifies() {
        // Keys sharing a long prefix, forcing extension nodes.
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..6u64)
            .map(|i| {
                let mut k = vec![0xaa, 0xbb, 0xcc, 0xdd];
                k.push(u8::try_from(i).unwrap_or(0));
                (k, format!("v{i}").into_bytes())
            })
            .collect();
        round_trip(&pairs);
    }

    /// ⭐ **The soundness property, stated as what it actually is.**
    ///
    /// The guarantee an inclusion proof gives is *not* "a proof works only for
    /// the key it was generated for" — that is a property about proof
    /// generation, and it is false. It is **"`verify` never returns a value
    /// other than the true one for that key under that root."** An attacker's
    /// goal is a forged value, not an extra answer.
    ///
    /// This checks the real thing: over a trie exercising both inlined and
    /// hashed children, every key/proof pair either returns the true value or
    /// errors. Nothing in between.
    #[test]
    fn verify_never_returns_a_value_that_is_not_the_true_one() {
        for value_len in [2usize, 200] {
            let mut t = Trie::new();
            let mut truth = Vec::new();
            for i in 0..12u64 {
                let k = rlp::encode_u64(i);
                let v = vec![u8::try_from(i).unwrap_or(0); value_len];
                t.insert(k.clone(), v.clone());
                truth.push((k, v));
            }
            let root = t.root();

            // Every proof, against every key.
            for (proof_key, _) in &truth {
                let proof = t.proof(proof_key);
                for (query_key, true_value) in &truth {
                    if let Ok(got) = verify(&root, query_key, &proof) {
                        assert_eq!(
                            &got, true_value,
                            "forged a value for {query_key:?} from a proof of {proof_key:?}"
                        );
                    }
                }
            }
        }
    }

    /// The companion fact, recorded so the test above is not misread as
    /// permissive: when a trie is small enough that nodes inline into their
    /// parents, the proof **does** commit to entries other than the one it was
    /// generated for, and it can answer for them. That is correct, not a hole —
    /// what comes back is the true value, and it chains to the real root.
    ///
    /// Worth pinning because the first version of the test above assumed the
    /// opposite and failed against correct code.
    #[test]
    fn a_small_tries_proof_answers_truthfully_for_other_keys() {
        let mut t = Trie::new();
        for i in 0..8u64 {
            t.insert(rlp::encode_u64(i), format!("r{i}").into_bytes());
        }
        let root = t.root();
        let proof = t.proof(&rlp::encode_u64(3));

        // Small enough that the whole trie travels in a couple of nodes.
        assert!(
            proof.len() <= 2,
            "fixture is larger than intended: {} nodes",
            proof.len()
        );

        let got = verify(&root, &rlp::encode_u64(5), &proof)
            .expect("the inlined nodes commit to index 5 as well");
        assert_eq!(
            got,
            b"r5".to_vec(),
            "and the value returned is the true one"
        );
    }

    /// With values large enough to force hashed children, a proof really is
    /// path-specific: the nodes for another key are simply absent.
    #[test]
    fn a_proof_with_hashed_children_cannot_answer_for_another_key() {
        let mut t = Trie::new();
        for i in 0..12u64 {
            t.insert(rlp::encode_u64(i), vec![u8::try_from(i).unwrap_or(0); 200]);
        }
        let root = t.root();
        let proof = t.proof(&rlp::encode_u64(3));

        match verify(&root, &rlp::encode_u64(5), &proof) {
            Ok(v) => panic!(
                "a proof for index 3 answered for index 5 with {} bytes",
                v.len()
            ),
            Err(ProofError::KeyNotFound | ProofError::MissingNode) => {}
            Err(e) => panic!("refused for the wrong reason: {e}"),
        }
    }

    #[test]
    fn a_proof_against_the_wrong_root_is_refused() {
        let mut t = Trie::new();
        for i in 0..4u64 {
            t.insert(rlp::encode_u64(i), format!("r{i}").into_bytes());
        }
        let proof = t.proof(&rlp::encode_u64(1));
        let wrong = [0xffu8; 32];
        assert!(matches!(
            verify(&wrong, &rlp::encode_u64(1), &proof),
            Err(ProofError::RootNotInProof)
        ));
    }

    #[test]
    fn a_tampered_proof_node_is_refused() {
        let mut t = Trie::new();
        for i in 0..8u64 {
            t.insert(rlp::encode_u64(i), vec![u8::try_from(i).unwrap_or(0); 100]);
        }
        let root = t.root();
        let mut proof = t.proof(&rlp::encode_u64(2));
        // Flip a byte in the last node — the one holding the value.
        let last = proof.len() - 1;
        let n = proof[last].len();
        proof[last][n - 1] ^= 0x01;

        assert!(
            verify(&root, &rlp::encode_u64(2), &proof).is_err(),
            "a tampered node must break the hash chain"
        );
    }

    #[test]
    fn a_truncated_proof_is_refused() {
        let mut t = Trie::new();
        for i in 0..16u64 {
            t.insert(rlp::encode_u64(i), vec![u8::try_from(i).unwrap_or(0); 100]);
        }
        let root = t.root();
        let mut proof = t.proof(&rlp::encode_u64(7));
        assert!(proof.len() > 1, "the fixture needs a multi-node proof");
        proof.pop();
        assert!(matches!(
            verify(&root, &rlp::encode_u64(7), &proof),
            Err(ProofError::MissingNode)
        ));
    }
}
