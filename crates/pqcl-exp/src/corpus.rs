//! Loading the Enron corpus, once, for every experiment that needs it.
//!
//! ⭐ **One loader, shared by every scheme under comparison.** A comparison is
//! only meaningful if both sides index exactly the same keyword/document pairs,
//! and the cheapest way to guarantee that is for there to be one function that
//! produces them. Two tokenizers that agree today are two things that can drift.
//!
//! The tokenizer is deliberately plain — lowercase alphabetic runs of 3..=20
//! characters, deduplicated per document. A cleverer one would be a second
//! thing that could be wrong, and it would not make the comparison fairer.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A document: an identifier, and its distinct keywords.
#[derive(Debug, Clone)]
pub struct Document {
    /// Dense index, used as the `DocId` by both schemes.
    pub id: u64,
    /// Distinct keywords, sorted.
    pub keywords: Vec<String>,
}

/// Why a corpus could not be loaded.
#[derive(Debug)]
pub enum CorpusError {
    /// `PQCL_ENRON` is unset.
    NotConfigured,
    /// It is set but does not name a directory.
    NotADirectory(PathBuf),
    /// Far fewer files than asked for — almost always the archive root rather
    /// than `maildir`.
    TooFewFiles {
        /// What was found.
        found: usize,
        /// What was requested.
        wanted: usize,
        /// Where we looked.
        root: PathBuf,
    },
}

impl core::fmt::Display for CorpusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotConfigured => f.write_str(
                "PQCL_ENRON is not set, so this experiment has no corpus.\n\n  \
                 Fetch it:  sh datasets/fetch-enron.sh\n  \
                 Then:      PQCL_ENRON=datasets/enron/maildir cargo run --release -p pqcl-exp --bin <exp>",
            ),
            Self::NotADirectory(p) => {
                write!(f, "PQCL_ENRON points at {}, which is not a directory", p.display())
            }
            Self::TooFewFiles { found, wanted, root } => write!(
                f,
                "found only {found} files under {} but wanted {wanted} — is this the maildir \
                 rather than the archive root?",
                root.display()
            ),
        }
    }
}

impl core::error::Error for CorpusError {}

/// Where the corpus lives.
///
/// ⛔ **Returns an error rather than an empty corpus.** An experiment that
/// quietly measured zero documents would emit a record with real provenance and
/// meaningless numbers behind it — a *publishable* record that says nothing,
/// which is the single outcome the results pipeline exists to prevent. Failing
/// here costs a restart; failing silently costs a retracted table.
///
/// # Errors
///
/// [`CorpusError::NotConfigured`] or [`CorpusError::NotADirectory`].
pub fn root() -> Result<PathBuf, CorpusError> {
    let raw = std::env::var("PQCL_ENRON").map_err(|_| CorpusError::NotConfigured)?;
    let path = PathBuf::from(raw);
    if path.is_dir() {
        Ok(path)
    } else {
        Err(CorpusError::NotADirectory(path))
    }
}

/// Choose `limit` message files: **every** file listed, sorted, then evenly
/// spaced through the sorted list, so every mailbox is sampled and no one
/// mailbox dominates.
///
/// ⛔ **Fixed in M10 H3: the selection depended on the host.** The previous
/// version stopped walking once it had `limit` files *in `read_dir` order* and
/// only sorted afterwards, so the sort fixed the order of a set the filesystem
/// had already chosen. On ext4 that order comes from a per-filesystem hash seed:
/// the same tier on WSL and on the campaign instance held different documents
/// — 2 613 686 pairs against 3 447 285 at 20 000 documents. Listing everything
/// first makes the choice a function of the corpus alone; [`fingerprint`] lets
/// a record prove which documents it indexed.
fn collect(root: &Path, limit: usize) -> Vec<PathBuf> {
    let mut all = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                all.push(p);
            }
        }
    }
    all.sort();
    if all.len() <= limit {
        return all;
    }
    (0..limit)
        .map(|i| all[i * all.len() / limit].clone())
        .collect()
}

/// A digest of exactly which documents, with which keywords, an experiment
/// indexed — for `RunSpec::dataset_checksums`. Content-based, so it does not
/// depend on where the corpus is mounted.
#[must_use]
pub fn fingerprint(docs: &[Document]) -> String {
    let mut buf = Vec::new();
    for d in docs {
        buf.extend_from_slice(&d.id.to_le_bytes());
        for k in &d.keywords {
            buf.extend_from_slice(k.as_bytes());
            buf.push(0);
        }
        buf.push(0xff);
    }
    pqcl_primitives::xof::digest256(&buf)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Lowercase alphabetic tokens of 3..=20 characters, deduplicated.
fn keywords(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| (3..=20).contains(&t.len()))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Load at most `limit` documents.
///
/// # Errors
///
/// [`CorpusError`] if the corpus is unconfigured, absent, or implausibly small.
pub fn load(limit: usize) -> Result<Vec<Document>, CorpusError> {
    let root = root()?;
    let files = collect(&root, limit);
    if files.len() <= limit / 2 {
        return Err(CorpusError::TooFewFiles {
            found: files.len(),
            wanted: limit,
            root,
        });
    }

    Ok(files
        .iter()
        .enumerate()
        .filter_map(|(i, path)| {
            let text = std::fs::read_to_string(path).ok()?;
            let kws = keywords(&text);
            if kws.is_empty() {
                return None;
            }
            Some(Document {
                id: i as u64,
                keywords: kws.into_iter().collect(),
            })
        })
        .collect())
}

/// **Nested** tiers: one seeded permutation
/// of every file, and tier `limit` is its first `limit` files, read in sorted
/// order. Each tier is a uniform sample of the corpus, and a smaller tier is a
/// subset of every larger one, so a query drawn from the smallest tier keeps
/// its source document at every tier.
///
/// [`load`]'s tiers are independent strided samples, so a harness that
/// re-draws its queries per tier measures a different query set at each size.
/// A new function rather than a change to [`load`], whose tiers Exp. 1's
/// records were measured on.
///
/// # Errors
///
/// As [`load`].
pub fn load_nested(limit: usize, seed: u64) -> Result<Vec<Document>, CorpusError> {
    use rand::SeedableRng as _;
    use rand::seq::SliceRandom as _;
    let root = root()?;
    let mut all = collect(&root, usize::MAX);
    if all.len() <= limit / 2 {
        return Err(CorpusError::TooFewFiles {
            found: all.len(),
            wanted: limit,
            root,
        });
    }
    all.shuffle(&mut rand::rngs::StdRng::seed_from_u64(seed));
    all.truncate(limit);
    all.sort();
    Ok(all
        .iter()
        .enumerate()
        .filter_map(|(i, path)| {
            let text = std::fs::read_to_string(path).ok()?;
            let kws = keywords(&text);
            if kws.is_empty() {
                return None;
            }
            Some(Document {
                id: i as u64,
                keywords: kws.into_iter().collect(),
            })
        })
        .collect())
}

/// Total `(keyword, document)` pairs — the `n` the paper's tiers are stated in.
#[must_use]
pub fn pair_count(docs: &[Document]) -> usize {
    docs.iter().map(|d| d.keywords.len()).sum()
}

/// Keywords ordered by descending document frequency.
///
/// ⭐ Query selection has to be **stated and reproducible**, not incidental.
/// Conjunctive search cost depends almost entirely on the s-term's volume, so
/// picking query terms by hand — or by whatever the corpus happens to yield
/// first — would let the experimenter choose the result. Ranking by frequency
/// and sampling at fixed positions makes the choice a property of the corpus.
#[must_use]
pub fn by_frequency(docs: &[Document]) -> Vec<(String, usize)> {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for d in docs {
        for k in &d.keywords {
            *counts.entry(k.as_str()).or_insert(0) += 1;
        }
    }
    let mut v: Vec<(String, usize)> = counts.into_iter().map(|(k, c)| (k.to_owned(), c)).collect();
    // Descending frequency, then alphabetical: ties must not depend on hash
    // iteration order, or the query set changes between runs.
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tokenizer_keeps_only_plausible_words() {
        let k = keywords("Hello, WORLD! a bb ccc 12345 supercalifragilisticexpialidocious x-ray");
        assert!(k.contains("hello"));
        assert!(k.contains("world"));
        assert!(k.contains("ccc"));
        // Too short.
        assert!(!k.contains("a"));
        assert!(!k.contains("bb"));
        // Digits are separators, so nothing survives from "12345".
        assert!(!k.contains("12345"));
        // Too long (34 characters).
        assert!(!k.contains("supercalifragilisticexpialidocious"));
        // Hyphen is a separator, so "x" is dropped as too short and "ray" stays.
        assert!(k.contains("ray"));
    }

    /// The selection is every file, sorted, evenly spaced — a function of the
    /// corpus, not of directory iteration order.
    #[test]
    fn the_selection_spans_the_sorted_corpus() {
        let root = std::env::temp_dir().join(format!("pqcl-corpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (dir, name) in [
            ("b", "3"),
            ("a", "1"),
            ("b", "4"),
            ("a", "2"),
            ("c", "5"),
            ("c", "6"),
        ] {
            std::fs::create_dir_all(root.join(dir)).expect("mkdir");
            std::fs::write(root.join(dir).join(name), "x").expect("write");
        }
        let names = |v: Vec<PathBuf>| -> Vec<String> {
            v.iter()
                .map(|p| {
                    p.strip_prefix(&root)
                        .expect("under root")
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect()
        };
        assert_eq!(names(collect(&root, 3)), ["a/1", "b/3", "c/5"]);
        assert_eq!(
            names(collect(&root, 6)),
            ["a/1", "a/2", "b/3", "b/4", "c/5", "c/6"]
        );
        assert_eq!(collect(&root, 3), collect(&root, 3));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_fingerprint_changes_with_any_document() {
        let d = |id, k: &str| Document {
            id,
            keywords: vec![k.to_owned()],
        };
        let a = fingerprint(&[d(0, "alpha"), d(1, "beta")]);
        assert_eq!(a, fingerprint(&[d(0, "alpha"), d(1, "beta")]));
        assert_ne!(a, fingerprint(&[d(0, "alpha"), d(1, "gamma")]));
        assert_ne!(a, fingerprint(&[d(0, "alpha")]));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn keywords_are_deduplicated_within_a_document() {
        let k = keywords("test test TEST Test");
        assert_eq!(k.len(), 1);
        assert!(k.contains("test"));
    }

    #[test]
    fn frequency_ranking_is_deterministic_including_ties() {
        let docs = vec![
            Document {
                id: 0,
                keywords: vec!["alpha".into(), "beta".into()],
            },
            Document {
                id: 1,
                keywords: vec!["alpha".into(), "gamma".into()],
            },
        ];
        let ranked = by_frequency(&docs);
        assert_eq!(ranked[0], ("alpha".to_owned(), 2));
        // beta and gamma both appear once, so the tie breaks alphabetically
        // rather than by map iteration order.
        assert_eq!(ranked[1].0, "beta");
        assert_eq!(ranked[2].0, "gamma");
    }

    #[test]
    fn pair_count_sums_keywords_not_documents() {
        let docs = vec![
            Document {
                id: 0,
                keywords: vec!["a".into(), "b".into(), "c".into()],
            },
            Document {
                id: 1,
                keywords: vec!["d".into()],
            },
        ];
        assert_eq!(pair_count(&docs), 4);
    }
}
