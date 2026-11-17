//! Evidence-plane documents, derived from **real tool output** over real
//! artefacts — never written by hand.
//!
//! Phase 3 Step 1 canonicalises each event and extracts field-qualified
//! keywords. Here an "event" is one line a forensic tool reported:
//!
//! * one file-system entry `fls -m` listed in the disk image (path, size,
//!   timestamps — The Sleuth Kit's body format);
//! * one IP conversation `tshark -z conv,ip` reported in the capture.
//!
//! Numeric fields become range attributes (`Π_RANGE`): a file's size in bytes
//! and its modification time in hours since the Unix epoch; a conversation's
//! duration in seconds.

use pqcl_dsse::core::DocId;
use pqcl_dsse::range::{Attribute, RangeTree};

/// One indexed document.
#[derive(Debug, Clone)]
pub struct Document {
    /// The DSSE document identifier.
    pub id: DocId,
    /// Which capsule (artefact) it came from.
    pub capsule: usize,
    /// What the tool reported, for the client's display only.
    pub label: String,
    /// Field-qualified keywords, e.g. `ext:jpg`.
    pub keywords: Vec<String>,
    /// Numeric attributes: (attribute, value).
    pub numbers: Vec<(Attribute, u64)>,
}

impl Document {
    /// Every keyword the index carries for this document: the plain ones and
    /// every range prefix of every numeric attribute (`eq:anc`).
    #[must_use]
    pub fn index_keywords(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self
            .keywords
            .iter()
            .map(|k| k.as_bytes().to_vec())
            .collect();
        for (attr, v) in &self.numbers {
            out.extend(RangeTree::profile(*attr).index_keywords(*v));
        }
        out
    }
}

/// The value `Π_RANGE`'s `ts` attribute indexes for a Unix timestamp.
///
/// ⚠️ **This used to be `unix_seconds / 3600`**, named `hours`, which kept the
/// value inside the depth-24 domain by reinterpreting a *minute*-granular
/// attribute as hours. Keywords are `ts:level:prefix` either way, so a
/// minute-granular range query produced structurally valid keywords that
/// matched nothing — a disagreement about units that no type could catch.
/// `Attribute::of_unix` is now the one conversion (M13 A2).
///
/// `None` past the attribute's window, for the reason `of_unix` documents: a
/// document indexed under an unreachable keyword would answer the wrong query.
#[must_use]
pub fn ts_value(unix_seconds: u64) -> Option<u64> {
    Attribute::Timestamp.of_unix(unix_seconds)
}

/// Documents from `fls -m / -r -p` body output (`md5|name|inode|mode|uid|gid|
/// size|atime|mtime|ctime|crtime`).
#[must_use]
pub fn from_fls_body(text: &str, capsule: usize, next_id: &mut DocId) -> Vec<Document> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() < 11 || f[1].contains("(Volume Label Entry)") {
            continue;
        }
        let deleted = f[1].contains("(deleted)");
        let name = f[1].replace(" (deleted)", "");
        let is_dir = f[3].starts_with('d');
        let size: u64 = f[6].parse().unwrap_or(0);
        let mtime: u64 = f[8].parse().unwrap_or(0);

        let mut keywords = vec!["src:disk-image".to_owned()];
        keywords.push(format!("kind:{}", if is_dir { "dir" } else { "file" }));
        if deleted {
            keywords.push("state:deleted".to_owned());
        }
        if let Some((dir, base)) = name.rsplit_once('/') {
            keywords.push(format!("dir:{}", if dir.is_empty() { "/" } else { dir }));
            if !is_dir && let Some((_, ext)) = base.rsplit_once('.') {
                keywords.push(format!("ext:{}", ext.to_ascii_lowercase()));
            }
        }
        let mut numbers = vec![(Attribute::Bytes, size)];
        // A document whose mtime is past the attribute's window (year ~3882)
        // is indexed without a time, rather than under a keyword that answers
        // the wrong range — the artefact's other keywords still find it.
        if mtime > 0
            && let Some(v) = ts_value(mtime)
        {
            numbers.push((Attribute::Timestamp, v));
        }
        out.push(Document {
            id: *next_id,
            capsule,
            label: format!("{name}{}", if deleted { " (deleted)" } else { "" }),
            keywords,
            numbers,
        });
        *next_id += 1;
    }
    out
}

/// Documents from `tshark -q -z conv,ip`: one per IPv4 conversation.
#[must_use]
pub fn from_tshark_conv(text: &str, capsule: usize, next_id: &mut DocId) -> Vec<Document> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 5 || t[1] != "<->" || !looks_like_ipv4(t[0]) || !looks_like_ipv4(t[2]) {
            continue;
        }
        // The last two columns are the relative start and the duration (s).
        let duration = t[t.len() - 1].parse::<f64>().unwrap_or(0.0);
        let mut keywords = vec!["src:pcap".to_owned(), "proto:ipv4".to_owned()];
        for ip in [t[0], t[2]] {
            keywords.push(format!("ip:{ip}"));
            if let Some((net, _)) = ip.rsplit_once('.') {
                keywords.push(format!("net:{net}.0/24"));
            }
        }
        keywords.sort();
        keywords.dedup();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let secs = duration.round().max(0.0) as u64;
        out.push(Document {
            id: *next_id,
            capsule,
            label: format!("{} <-> {}, {duration:.1} s", t[0], t[2]),
            keywords,
            numbers: vec![(Attribute::Duration, secs)],
        });
        *next_id += 1;
    }
    out
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_line_becomes_a_file_document() {
        let mut id = 7;
        let d = from_fls_body(
            "0|/DCIM/100CANON/IMG_0044.JPG|1029|r/rrwxrwxrwx|0|0|105195|1230076800|1230150104|0|1230150104\n\
             0|/CANON_DC    (Volume Label Entry)|3|r/rrwxrwxrwx|0|0|0|0|1230041544|0|0\n",
            0,
            &mut id,
        );
        assert_eq!(d.len(), 1, "the volume label is not a file");
        assert_eq!(d[0].id, 7);
        assert!(d[0].keywords.contains(&"ext:jpg".to_owned()));
        assert!(d[0].keywords.contains(&"dir:/DCIM/100CANON".to_owned()));
        assert_eq!(d[0].numbers[0], (Attribute::Bytes, 105_195));
        assert_eq!(id, 8);
    }

    #[test]
    fn a_conversation_line_becomes_a_document() {
        let mut id = 0;
        let d = from_tshark_conv(
            "192.168.123.101      <-> 74.125.128.125           119 22 kB          91 13 kB         210 35 kB         5.489363000       253.9287\n\
             Filter:<No Filter>\n",
            1,
            &mut id,
        );
        assert_eq!(d.len(), 1);
        assert!(d[0].keywords.contains(&"ip:74.125.128.125".to_owned()));
        assert!(d[0].keywords.contains(&"net:192.168.123.0/24".to_owned()));
        assert_eq!(d[0].numbers[0], (Attribute::Duration, 254));
    }
}
