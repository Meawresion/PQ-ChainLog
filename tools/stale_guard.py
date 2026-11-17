#!/usr/bin/env python3
"""Is a record stale? Only if what its harness *executed* has changed since.

The design record, stated as acceptance:

* **must flag** any change to the bytes or the work in a record's timed region
  (e.g. the `0x01` seal, the custody-record encoding);
* **must not flag** additions the timed region never reaches (a new leaf
  constructor, a new test, a new binary).

A crate-closure rule fails the second: every harness lives in `pqcl-exp`, so
one new function anywhere would mark everything stale. This guard instead uses
**runtime reachability**: `tools/stale_coverage.sh` builds each harness with
LLVM coverage *at the record's SHA*, runs it at smoke scale, and exports which
functions ran. Then, over `git diff <record-sha> HEAD`:

| hunk | verdict |
|---|---|
| overlaps a function the harness executed | **STALE** (its work or bytes changed) |
| edits or deletes item-level code (const, struct, enum, static) in a file the harness executed | **STALE**, conservatively |
| inserts inside a struct/enum body in an executed file | **STALE** (layout), conservatively |
| touches only unexecuted functions, `#[cfg(test)]` code, comments or `use` lines | fresh |
| inserts a new top-level item or a new `impl` member | fresh (old code cannot call it) |
| `Cargo.lock` changes an existing package's version/source/checksum | **STALE** |
| `rust-toolchain.toml`, `.cargo/config*`, or a `[profile` section changes | **STALE** |

⚠️ Scope and direction of error: coverage spans the whole smoke process, a
superset of the timed region, so this may over-flag and never under-flags
executed code. It does not see non-Rust inputs (a harness reading a Foundry
artefact); those are named in the verdict for a human to judge. A `const`
changed in a file where *no* function ran would be missed; such a file has
never been observed.

Usage:
    python3 tools/stale_guard.py <cov-dir> <record-sha> [<head> | --worktree]

`--worktree` diffs against the working tree rather than a commit: the check to
run before committing work a campaign will measure.
    python3 tools/stale_guard.py --selftest
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BENIGN_LINE = re.compile(r"^\s*(//.*|#!\[.*\]|(pub(\(crate\))?\s+)?(use|mod)\s.*|)\s*$")
BLOCK_HEAD_FRESH = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?(unsafe\s+)?(impl|mod|trait)\b")
TOOLCHAIN_FILES = ("rust-toolchain.toml", ".cargo/config", ".cargo/config.toml")


@dataclass
class Coverage:
    """Per file (relative to the repository root): executed and unexecuted spans."""

    executed: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    unexecuted: dict[str, list[tuple[int, int]]] = field(default_factory=dict)


def load_coverage(doc: dict, root: str) -> Coverage:
    cov = Coverage()
    prefix = root.rstrip("/") + "/"
    for data in doc.get("data", []):
        for fn in data.get("functions", []):
            files = fn["filenames"]
            regions = [r for r in fn["regions"] if len(r) >= 8 and r[7] == 0]
            if not regions:
                continue
            fid = regions[0][5]
            path = files[fid] if fid < len(files) else files[0]
            if not path.startswith(prefix):
                continue
            rel = path[len(prefix):]
            own = [r for r in regions if r[5] == fid]
            span = (min(r[0] for r in own), max(r[2] for r in own))
            (cov.executed if fn["count"] > 0 else cov.unexecuted).setdefault(rel, []).append(span)
    return cov


@dataclass
class Hunk:
    path: str
    old_start: int
    old_len: int
    removed: list[str]
    added: list[str]


def parse_diff(text: str, prefix: str = "") -> list[Hunk]:
    hunks: list[Hunk] = []
    path = None
    cur: Hunk | None = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            cur = None
            b = line.split(" b/", 1)[1]
            path = b[len(prefix):] if b.startswith(prefix) else None
        elif line.startswith(("--- ", "+++ ")):
            continue
        elif (m := HUNK.match(line)) and path is not None:
            cur = Hunk(path, int(m[1]), int(m[2]) if m[2] is not None else 1, [], [])
            hunks.append(cur)
        elif cur is not None and line.startswith("-"):
            cur.removed.append(line[1:])
        elif cur is not None and line.startswith("+"):
            cur.added.append(line[1:])
    return hunks


def test_spans(src: str) -> list[tuple[int, int]]:
    """Line spans of `#[cfg(test)]` items, by brace matching."""
    lines = src.splitlines()
    spans = []
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("#[cfg(test)]"):
            start = i + 1
            depth, opened, j = 0, False, i + 1
            while j < len(lines):
                depth += code(lines[j]).count("{") - code(lines[j]).count("}")
                opened |= "{" in code(lines[j])
                if opened and depth <= 0:
                    break
                j += 1
            spans.append((start, j + 1))
            i = j
        i += 1
    return spans


def code(line: str) -> str:
    """A line with its `//` comment and string literals removed, roughly."""
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    return line.split("//", 1)[0]


def enclosing_head(src: str, lineno: int) -> str | None:
    """The line that opened the innermost block containing line `lineno`
    (1-based, the insertion point), or None at top level."""
    stack: list[str] = []
    for text in src.splitlines()[:lineno]:
        for ch in code(text):
            if ch == "{":
                stack.append(text)
            elif ch == "}" and stack:
                stack.pop()
    return stack[-1] if stack else None


def inside(spans: list[tuple[int, int]], a: int, b: int) -> bool:
    return any(s <= b and a <= e for s, e in spans)


def classify(h: Hunk, cov: Coverage, old_src: str | None) -> str | None:
    """A reason the hunk makes the record stale, or None."""
    if h.path in TOOLCHAIN_FILES or h.path.startswith(".cargo/config"):
        return f"{h.path}: toolchain/config changed"
    if h.path == "Cargo.lock" or h.path.endswith("/Cargo.lock"):
        return None  # judged by `lock_changes`, per package
    if h.path.endswith("Cargo.toml"):
        return None  # profiles judged by `profile_changes`
    if not h.path.endswith(".rs"):
        return None
    executed = cov.executed.get(h.path)
    if not executed:
        return None  # nothing in this file ran
    if all(BENIGN_LINE.match(x) for x in h.removed + h.added):
        return None
    src = old_src or ""
    tests = test_spans(src)
    if h.old_len > 0:
        a, b = h.old_start, h.old_start + h.old_len - 1
        if inside(tests, a, b):
            return None
        if inside(executed, a, b):
            return f"{h.path}:{a}-{b}: an executed function changed"
        if inside(cov.unexecuted.get(h.path, []), a, b):
            return None
        return f"{h.path}:{a}-{b}: item-level code changed in an executed file"
    # Pure insertion after old line `a`.
    a = h.old_start
    if inside(tests, a, a):
        return None
    if any(s <= a < e for s, e in executed):
        return f"{h.path}:{a}: code inserted into an executed function"
    if any(s <= a < e for s, e in cov.unexecuted.get(h.path, [])):
        return None
    head = enclosing_head(src, a)
    if head is None or BLOCK_HEAD_FRESH.match(head):
        return None  # a new item old code cannot reach
    return f"{h.path}:{a}: inserted into `{head.strip()[:60]}` (layout) in an executed file"


def lock_packages(text: str) -> dict[str, tuple[str, str, str]]:
    out = {}
    for block in text.split("[[package]]")[1:]:
        kv = dict(re.findall(r'^(name|version|source|checksum) = "([^"]*)"', block, re.M))
        if "name" in kv:
            out[f"{kv['name']}@{kv.get('version', '')}"] = (
                kv.get("version", ""), kv.get("source", ""), kv.get("checksum", ""))
    return out


def lock_changes(old: str, new: str) -> list[str]:
    """Existing packages whose version, source or checksum changed. An added
    package (a new dependency of a crate) is not by itself a change to work
    an old harness did; a removed or bumped one is."""
    o, n = lock_packages(old), lock_packages(new)
    by_name_old = {k.split("@")[0]: v for k, v in o.items()}
    by_name_new = {k.split("@")[0]: v for k, v in n.items()}
    out = []
    for name, v in by_name_old.items():
        if name in by_name_new and by_name_new[name] != v:
            out.append(f"Cargo.lock: {name} {v[0]} -> {by_name_new[name][0]}")
        elif name not in by_name_new:
            out.append(f"Cargo.lock: {name} removed")
    return out


def profile_sections(text: str) -> str:
    keep, out = False, []
    for line in text.splitlines():
        if line.startswith("["):
            keep = line.startswith("[profile")
        if keep:
            out.append(line)
    return "\n".join(out)


def git(repo: Path, *args: str) -> str:
    """Run git, UTF-8. ⛔ A failure raises: a guard that silently diffed
    nothing would report every record fresh (rule 18)."""
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                       encoding="utf-8", errors="replace", check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def git_show(repo: Path, ref_path: str) -> str:
    """`git show <ref>:<path>`, or "" when the path does not exist at that ref
    (a file added since): the one miss that is not an error."""
    r = subprocess.run(["git", "-C", str(repo), "show", ref_path], capture_output=True,
                       encoding="utf-8", errors="replace", check=False)
    if r.returncode == 0:
        return r.stdout
    if "does not exist" in r.stderr or "exists on disk, but not in" in r.stderr:
        return ""
    raise RuntimeError(f"git show {ref_path} failed: {r.stderr.strip()}")


def verdict(cov_dir: Path, sha: str, head: str = "HEAD") -> dict:
    repo = Path(__file__).resolve().parents[1]
    root = (cov_dir / "root.txt").read_text().strip()
    worktree = head == "--worktree"
    refs = [sha] if worktree else [sha, head]
    diff = git(repo, "diff", "-U0", "--no-color", *refs, "--", ".")
    hunks = parse_diff(diff)

    def now(path: str) -> str:
        if worktree:
            f = repo / path
            return f.read_text(encoding="utf-8") if f.is_file() else ""
        return git_show(repo, f"{head}:{path}")

    shared = lock_changes(git_show(repo, f"{sha}:Cargo.lock"),
                          now("Cargo.lock"))
    if profile_sections(git_show(repo, f"{sha}:Cargo.toml")) != \
            profile_sections(now("Cargo.toml")):
        shared.append("Cargo.toml: a [profile] section changed")
    old_src_cache: dict[str, str] = {}
    out = {"record_sha": sha,
           "head": "working tree" if worktree else git(repo, "rev-parse", head).strip(),
           "method": "LLVM coverage of the smoke run at the record's SHA (tools/stale_coverage.sh)",
           "harnesses": {}}
    for f in sorted(cov_dir.glob("*.json")):
        cov = load_coverage(json.loads(f.read_text()), root)
        reasons = list(shared)
        for h in hunks:
            if h.path not in old_src_cache:
                old_src_cache[h.path] = git_show(repo, f"{sha}:{h.path}")
            r = classify(h, cov, old_src_cache[h.path])
            if r:
                reasons.append(r)
        out["harnesses"][f.stem] = {
            "stale": bool(reasons),
            "reasons": reasons,
            "executed_files": len(cov.executed),
            "executed_functions": sum(len(v) for v in cov.executed.values()),
        }
    return out


# ------------------------------------------------------------------ self-test

SELF_SRC = """use a::b;

pub const TAG: u8 = 0x01;

pub struct Rec {
    pub a: u8,
}

impl Rec {
    pub fn seal(&self) -> u8 {
        self.a ^ TAG
    }

    pub fn unused(&self) -> u8 {
        0
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}
"""
# seal: lines 10-12 executed; unused: 14-16 not executed.
SELF_COV = Coverage(executed={"crates/x/src/lib.rs": [(10, 12)]},
                    unexecuted={"crates/x/src/lib.rs": [(14, 16)]})


def _h(old_start, old_len, removed=(), added=(), path="crates/x/src/lib.rs"):
    return Hunk(path, old_start, old_len, list(removed), list(added))


def selftest() -> int:
    must_flag = {
        "an executed function's body changed (the 0x01 seal)":
            _h(11, 1, ["        self.a ^ TAG"], ["        self.a ^ TAG ^ 1"]),
        "code inserted into an executed function":
            _h(10, 0, [], ["        let _extra = work();"]),
        "a const an executed function reads changed":
            _h(3, 1, ["pub const TAG: u8 = 0x01;"], ["pub const TAG: u8 = 0x02;"]),
        "a field added to a struct in an executed file (encoding/layout)":
            _h(6, 0, [], ["    pub b: u8,"]),
    }
    must_not = {
        "a new top-level function (a new leaf constructor)":
            _h(7, 0, [], ["", "pub fn new_leaf() -> u8 { 5 }"]),
        "a new impl member old code cannot call":
            _h(12, 0, [], ["", "    pub fn dispose(&self) -> u8 { 7 }"]),
        "an unexecuted function changed":
            _h(15, 1, ["        0"], ["        1"]),
        "a test changed": _h(22, 1, ["    fn t() {}"], ["    fn t() { assert!(true) }"]),
        "a comment changed": _h(9, 0, [], ["/// docs"]),
        "a new file in an unexecuted crate":
            _h(0, 0, [], ["pub fn anything() {}"], path="crates/y/src/new.rs"),
        "a use line": _h(1, 1, ["use a::b;"], ["use a::{b, c};"]),
    }
    bad = 0
    for name, h in must_flag.items():
        if classify(h, SELF_COV, SELF_SRC) is None:
            print(f"FAIL must flag: {name}")
            bad += 1
    for name, h in must_not.items():
        r = classify(h, SELF_COV, SELF_SRC)
        if r is not None:
            print(f"FAIL must not flag: {name}: {r}")
            bad += 1
    # Cargo.lock: a bump flags, an added path dependency does not.
    old_lock = '[[package]]\nname = "sha3"\nversion = "0.10.8"\nsource = "registry"\nchecksum = "aa"\n' \
               '[[package]]\nname = "pqcl-interop"\nversion = "0.1.0"\ndependencies = [\n "x",\n]\n'
    added_dep = old_lock.replace('dependencies = [\n "x",\n]', 'dependencies = [\n "x",\n "pqcl-capsule",\n]')
    bumped = old_lock.replace('"0.10.8"', '"0.10.9"').replace('"aa"', '"bb"')
    if lock_changes(old_lock, added_dep):
        print("FAIL must not flag: an added path dependency in Cargo.lock")
        bad += 1
    if not lock_changes(old_lock, bumped):
        print("FAIL must flag: a registry crate bumped in Cargo.lock")
        bad += 1
    # A diff round trip through the parser.
    d = ("diff --git a/crates/x/src/lib.rs b/crates/x/src/lib.rs\n"
         "--- a/crates/x/src/lib.rs\n+++ b/crates/x/src/lib.rs\n"
         "@@ -11 +11 @@\n-        self.a ^ TAG\n+        self.a ^ TAG ^ 1\n"
         "@@ -7,0 +8,2 @@\n+\n+pub fn new_leaf() -> u8 { 5 }\n")
    hs = parse_diff(d)
    got = [classify(h, SELF_COV, SELF_SRC) is not None for h in hs]
    if got != [True, False]:
        print(f"FAIL diff parse/classify round trip: {got}")
        bad += 1
    total = len(must_flag) + len(must_not) + 3
    print(f"stale_guard selftest: {total - bad}/{total} ok")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--selftest"]:
        return selftest()
    if len(argv) < 3:
        print(__doc__)
        return 2
    v = verdict(Path(argv[1]), argv[2], argv[3] if len(argv) > 3 else "HEAD")
    print(json.dumps(v, indent=2))
    return 1 if any(h["stale"] for h in v["harnesses"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
