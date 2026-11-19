//! A real `ls` and a real `cat` of the demo's data folders, for the Storage
//! page (`/storage.html`): what is on disk now, read when you click.
//!
//! ⛔ **Read only, four fixed roots, nothing outside them.** A request names a
//! root by id and a path relative to it; the path may hold only plain names
//! (no `..`, no absolute paths), and the resolved file must still sit under
//! the root after symlinks are followed. **Key files are never shown**: the
//! demo chain's folder holds the validator's private key. The page is served
//! on loopback only, like the rest of the dashboard ([`crate::web`]).

use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde_json::{Value, json};

/// Most bytes `cat` returns as text.
const TEXT_MAX: u64 = 64 * 1024;
/// Most bytes `cat` shows as a hex dump of a binary file.
const HEX_MAX: u64 = 512;

/// One folder the page may read.
#[derive(Debug, Clone)]
pub struct Root {
    /// The id the page names it by.
    pub id: &'static str,
    /// Where it is.
    pub dir: PathBuf,
    /// The path as typed in a terminal from `implementation/`.
    pub shown: String,
}

/// The four folders: the AIS payload store, the synthetic bursts before
/// sealing, the original artefacts, and the demo chain's data.
#[must_use]
pub fn roots(repo: &Path, store: &Path) -> Vec<Root> {
    let rel = |p: &Path| {
        p.strip_prefix(repo)
            .map_or_else(|_| p.display().to_string(), |r| r.display().to_string())
    };
    let synthetic = store.with_file_name("demo-synthetic");
    let artefacts = repo.join("datasets/artefacts");
    let chain = repo.join("besu/demo/data");
    vec![
        Root {
            id: "store",
            shown: rel(store),
            dir: store.to_path_buf(),
        },
        Root {
            id: "synthetic",
            shown: rel(&synthetic),
            dir: synthetic,
        },
        Root {
            id: "artefacts",
            shown: rel(&artefacts),
            dir: artefacts,
        },
        Root {
            id: "chain",
            shown: rel(&chain),
            dir: chain,
        },
    ]
}

/// The roots, and whether each exists yet.
#[must_use]
pub fn list_roots(roots: &[Root]) -> Value {
    json!(
        roots
            .iter()
            .map(|r| json!({"id": r.id, "shown": r.shown, "exists": r.dir.is_dir()}))
            .collect::<Vec<_>>()
    )
}

/// A private key, by name: never read.
fn is_secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let ext = Path::new(&n)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    n == "key" || ext == "key" || ext == "priv" || n.contains("private")
}

/// The root and the joined path, refusing anything but plain names.
fn locate<'a>(roots: &'a [Root], id: &str, rel: &str) -> Result<(&'a Root, PathBuf), String> {
    let root = roots
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| format!("no folder {id}"))?;
    let rel_path = Path::new(rel);
    if !rel_path
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err("only plain names inside the folder are allowed".into());
    }
    Ok((root, root.dir.join(rel_path)))
}

/// The path resolved, and still under its root after symlinks.
fn confined(root: &Root, path: &Path) -> Result<PathBuf, String> {
    let base = fs::canonicalize(&root.dir).map_err(|e| format!("{}: {e}", root.shown))?;
    let real = fs::canonicalize(path).map_err(|e| e.to_string())?;
    if real.starts_with(&base) {
        Ok(real)
    } else {
        Err("that path leaves the folder".into())
    }
}

fn shown(root: &Root, rel: &str) -> String {
    if rel.is_empty() {
        root.shown.clone()
    } else {
        format!("{}/{rel}", root.shown)
    }
}

/// `ls -la`: the entries of one directory, folders first.
///
/// # Errors
///
/// An unknown root, a path that is not plain names or leaves the root, or a
/// directory that cannot be read.
pub fn ls(roots: &[Root], id: &str, rel: &str) -> Result<Value, String> {
    let (root, path) = locate(roots, id, rel)?;
    if !path.exists() {
        return Ok(
            json!({"root": id, "path": rel, "shown": shown(root, rel), "exists": false, "entries": []}),
        );
    }
    let real = confined(root, &path)?;
    let mut rows: Vec<(bool, String, Value)> = Vec::new();
    for entry in fs::read_dir(&real).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let md = entry.metadata().map_err(|e| e.to_string())?;
        let modified = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let v = json!({"name": name, "dir": md.is_dir(), "size": md.len(), "modified": modified,
                       "secret": is_secret(&name)});
        rows.push((md.is_dir(), name, v));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    Ok(
        json!({"root": id, "path": rel, "shown": shown(root, rel), "exists": true,
              "entries": rows.into_iter().map(|r| r.2).collect::<Vec<_>>()}),
    )
}

/// `cat` of a text file (its first 64 KiB), or `xxd | head` of a binary one
/// (its first 512 bytes).
///
/// # Errors
///
/// An unknown root, a bad path, a key file, a directory, or a read failure.
pub fn cat(roots: &[Root], id: &str, rel: &str) -> Result<Value, String> {
    let (root, path) = locate(roots, id, rel)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or("name a file")?;
    if is_secret(&name) {
        return Err(format!("{name} is a private key: never shown"));
    }
    let real = confined(root, &path)?;
    let md = fs::metadata(&real).map_err(|e| e.to_string())?;
    if md.is_dir() {
        return Err("that is a folder".into());
    }
    let size = md.len();
    let mut buf = Vec::new();
    File::open(&real)
        .and_then(|f| f.take(TEXT_MAX).read_to_end(&mut buf))
        .map_err(|e| e.to_string())?;
    // Text: no NUL byte and valid UTF-8, allowing a character cut at the end.
    let text = if buf.contains(&0) {
        None
    } else {
        match std::str::from_utf8(&buf) {
            Ok(s) => Some(s.to_owned()),
            Err(e) if e.error_len().is_none() => {
                Some(String::from_utf8_lossy(&buf[..e.valid_up_to()]).into_owned())
            }
            Err(_) => None,
        }
    };
    let shown_path = shown(root, rel);
    if let Some(t) = text {
        let n = t.len() as u64;
        return Ok(
            json!({"kind": "text", "shown": shown_path, "size": size, "bytes": n,
                         "truncated": n < size, "text": t}),
        );
    }
    let head = &buf[..buf
        .len()
        .min(usize::try_from(HEX_MAX).unwrap_or(usize::MAX))];
    Ok(
        json!({"kind": "binary", "shown": shown_path, "size": size, "bytes": head.len(),
              "truncated": (head.len() as u64) < size, "hex": xxd(head)}),
    )
}

/// The same layout `xxd` prints: offset, 16 bytes in pairs, and the bytes as
/// ASCII with `.` for anything unprintable.
fn xxd(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    for (i, row) in bytes.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}: ", i * 16);
        for (j, b) in row.iter().enumerate() {
            let _ = write!(out, "{b:02x}");
            if j % 2 == 1 {
                out.push(' ');
            }
        }
        for j in row.len()..16 {
            out.push_str("  ");
            if j % 2 == 1 {
                out.push(' ');
            }
        }
        out.push(' ');
        out.extend(row.iter().map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        }));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, Vec<Root>) {
        let base = std::env::temp_dir().join(format!("pqcl-files-test-{}", std::process::id()));
        let store = base.join("target/demo-store");
        fs::create_dir_all(&store).unwrap();
        fs::create_dir_all(base.join("target/demo-synthetic")).unwrap();
        fs::write(store.join("ab12"), [0u8, 1, 2, 0xff, b'A']).unwrap();
        fs::write(
            base.join("target/demo-synthetic/b.log"),
            "line one\nline two\n",
        )
        .unwrap();
        fs::write(store.join("key"), "secret").unwrap();
        let roots = roots(&base, &store);
        (base, roots)
    }

    #[test]
    fn ls_and_cat_read_what_is_there_and_nothing_else() {
        let (base, r) = fixture();
        let l = ls(&r, "store", "").unwrap();
        let names: Vec<&str> = l["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["ab12", "key"]);
        assert_eq!(l["shown"], "target/demo-store");
        let t = cat(&r, "synthetic", "b.log").unwrap();
        assert_eq!(t["kind"], "text");
        assert_eq!(t["text"], "line one\nline two\n");
        let b = cat(&r, "store", "ab12").unwrap();
        assert_eq!(b["kind"], "binary");
        assert!(
            b["hex"]
                .as_str()
                .unwrap()
                .starts_with("00000000: 0001 02ff 41")
        );
        // Never a key, never outside the root, never an unknown root.
        assert!(cat(&r, "store", "key").is_err());
        assert!(cat(&r, "store", "../demo-synthetic/b.log").is_err());
        assert!(ls(&r, "store", "/etc").is_err());
        assert!(ls(&r, "nowhere", "").is_err());
        // A folder that does not exist yet is reported, not an error.
        assert_eq!(ls(&r, "chain", "").unwrap()["exists"], false);
        fs::remove_dir_all(base).unwrap();
    }
}
