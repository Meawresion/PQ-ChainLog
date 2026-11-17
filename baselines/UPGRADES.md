# Baseline deviations and modernizations

Ground rule #6: **state every baseline upgrade.** Silent
modernization is how baselines become strawmen — and a strawman baseline is worse than a missing
one, because the comparison still looks legitimate.

Every entry here is either (a) a change forced by porting to our environment, or (b) something the
paper left ambiguous plus the resolution chosen. Anything that would flatter PQ-ChainLog is called
out as such.

Reading rule: each scheme was implemented from **the paper
itself**, read out of `ref-papers/`. Not from the build plan, not from
`LIT-REVIEW.md`, not from `draft6.tex`.

---

## ODXT — Patranabis & Mukhopadhyay, NDSS 2021

Source: `ref-papers/ODXT_NDSS2021.pdf`, Figures 7 (`Setup`), 8 (`Update`), 9 (`Search`);
implementation details from §IV.

Code: `baselines/odxt/`.

### What the paper's own prototype used

| | Theirs | Ours | Why |
|---|---|---|---|
| Language | Python 3.8 | Rust | Plan §5's fairness rule: wall-clock compares **only** inside the Rust workspace. A Python-vs-Rust latency table is meaningless and a reviewer will say so. Index size, communication volume, round count and leakage are language-independent and compare freely |
| Symmetric primitives | PyCryptodome | `aes` 0.8 (RustCrypto) | Same primitive, AES-256. Library change only |
| Group | SageMath over Curve25519 | `curve25519-dalek` 4.1, **Ristretto255** | See "Ristretto, not raw Curve25519" below — this one is not cosmetic |
| TSet storage | Riak (distributed NoSQL KV) | in-process `HashMap` | Riak over their 10 MBps WAN measures a network and a database, not the scheme. Our own schemes are measured against in-process storage, so this is what makes the comparison like-for-like. ⚠️ It **removes** a cost from ODXT, so the change favours *them*, not us |
| XSet storage | Bloom filter | exact `HashSet` for correctness; Bloom measured separately for storage | A Bloom filter admits false positives, which in ODXT means reporting a document as containing an x-term it does not. Checking correctness against the exact set means a genuine protocol bug cannot hide behind an expected false-positive rate |
| Dataset | 60.92 GB Wikimedia, 16 M docs, 43 M keywords, 10⁸ updates, 30% deletions | Enron (as for our schemes), same update mix | Both schemes must see the same corpus or the comparison says nothing. The 30% deletion rate is kept |

### Ristretto, not raw Curve25519

The paper says "all group operations in ODXT over the elliptic curve Curve25519". Curve25519 has
cofactor 8, so its point group is **not** of prime order.

ODXT needs prime order. The scheme's central identity is

```
xtoken_{i,j}^{α_j} = g^{F_p(K_X,w_i)·F_p(K_Z,w₁‖j)·F_p(K_Y,id‖op)·F_p(K_Z,w₁‖j)^{-1}} = xtag_{i,j}
```

which requires `F_p(K_Z, ·)` to be **invertible**, i.e. the exponents to live in a field. In a
group with a cofactor, small-subgroup components are not cancelled by that inverse and the identity
can fail. Ristretto255 is the standard prime-order quotient of Curve25519 and is what the authors'
SageMath code would have had to be doing in effect. Recorded because "Curve25519" and "prime-order
group" are not the same statement, and the difference is load-bearing.

### The PRF construction the paper compresses to one line

> *"we realize all PRF operations using AES-256 in counter mode"*

AES-CTR is a stream cipher, not a variable-input-length PRF — keywords are longer than one block,
and feeding a message in as the counter nonce silently truncates. `baselines/odxt/src/prf.rs`
therefore compresses the input with AES-256 CBC-MAC over a **length-framed** message and uses the
result as the CTR nonce. This is the standard construction the one-liner implies; it is recorded
because it is a choice we made and not something the paper states.

Two details inside it that are correctness-bearing, not stylistic:

- **Length framing.** The paper writes PRF inputs as `w ‖ cnt ‖ 0`. Plain concatenation of a
  variable-length keyword with a counter is ambiguous: `("ab", 1)` and `("a", 0xb1)` are the same
  byte string. In ODXT a collision between two `(w, cnt)` pairs is a **wrong search result**, not
  merely a security weakness. Every PRF input is length-framed.
- **`F_p` never returns zero.** ODXT inverts `F_p(K_Z, ·)`, and `Scalar::invert` on zero yields
  zero rather than erroring, so a zero output would silently break the cross-tag identity for that
  entry. `prf_scalar` rejects and re-derives.

### ⭐ A semantic limit of ODXT that constrains Exp. 2's workload

**Finding, not a defect in the transcription.** ODXT detects a deletion only when it appears in the
**s-term's** update list. Deleting a single `(id, w)` pair while the document's other pairs stay
live therefore returns the document anyway:

- `Del(42, alpha)` makes `UpdateCnt[alpha] = 2` against `UpdateCnt[beta] = 1`, so Figure 9 picks
  **beta** as the s-term.
- Beta's list holds only the `add`, so `op_j` is never `del` and Figure 9 step 2(d)'s removal rule
  never fires.
- The cross-tag test asks whether `xtag(alpha, 42, add) ∈ XSet` — true, because 42 *was* added to
  alpha. The deletion appended a separate `op = del` cross-tag; it did not retract the original.

This is consistent with the paper, which assumes document-level deletion: §III-C footnote 3, *"when
an existing file is to be updated, it is deleted and re-inserted (in modified form) under a fresh
file identifier."* Under that model every deletion appears under every keyword of the document,
including the s-term, and ODXT is correct — verified in
`tests/against_oracle.rs::a_deleted_document_stops_matching`.

⛔ **The consequence for the paper.** Our schemes support per-pair deletion; ODXT does not. A
comparison workload containing per-pair deletions would make ODXT return wrong answers — a
strawman **in our favour**. Exp. 2 must therefore delete at document granularity, and the paper
should say so rather than leave a reader to assume the workloads were identical in every respect.
The behaviour is pinned by `tests/against_oracle.rs::deleting_only_one_pair_is_outside_odxts_model`,
which asserts what ODXT actually does so a later "fix" cannot quietly diverge from the paper.

### ⚠️ Ambiguity: its Bloom `XSet`'s false-positive rate (M10 H4)

§VII (p. 14) says the XSet "is realized using a Bloom filter" and gives **no rate**. The storage
experiment (`crates/pqcl-exp/src/bin/size.rs`) therefore sizes it at the rate the answer-loss bound
derives for ODXT's own structure — `max_epsilon(δ, n−1, E = 1)`, since it has no epochs — while
ours is sized at its `E`. That choice charges our epochs to us rather than to ODXT. Rows at Doris's
`10⁻⁶` (its OXT/HXT convention, `setup_exp.py:98`) are recorded beside them. The rate is not
invented; the resolution is stated here so a reader can re-size either side.

### Added: an observation hook for the leakage experiment (M10 H6) — not a protocol change

`search_server_observed` returns, beside the unchanged `ServerResponse`, what the server sees for
each s-term candidate `j`: its `TSet` address and every xtag it computed with the XSet outcome.
It shares one loop with `search_server`, so the instrumented path cannot drift from the measured
one, and `tests/against_oracle.rs::the_observed_server_answers_identically_and_sees_every_lookup`
pins identical responses, one view per candidate, recorded hits equal to the returned `cnt_j`,
and that xtags repeat across queries. Exp. 5's association count is read off this, never inferred
from the paper's leakage function.

### Exp. 9, court-ordered redaction — two read-only accessors, and what is **not** added

Exp. 9 measures ODXT in two rows: **`del`** (one `Op::Del` update per pair of the redacted document)
and **rebuild** (`Setup` over the live pairs under a freshly drawn `sk`, the old one discarded).
The rebuild is ODXT's own route to erasure against an adversary who later holds the current key
state; the client re-derives the live pairs from its plaintext corpus, as `Setup` does.

- **Added, read-only:** `xtag_of(sk, w, id, op)` — the cross-tag `update` inserts, derived from `sk`
  alone — and `Edb::xset_contains` / `Edb::xset_snapshot`. They model the Exp. 9 **adversary**
  (current key state plus every `XSet` the server ever retained) and count its confirmable redacted
  pairs. Neither is called by `update` or `search`; the protocol is unchanged.
- ⛔ **Not added: compaction.** ODXT's paper has none, so adding ours to it would measure our
  mechanism under its name. Its honest equivalent is the full rebuild, measured as its own row.
- The order gate (`σ_CO` verification, the on-chain record, the target proof) is timed inside
  **our** erase column and has no ODXT counterpart: ODXT has no notion of an order. That cost is
  ours alone, which is pessimistic for us, and stated rather than removed.

### Not changed

- The protocol. Update, search-token generation, the server's oblivious cross-tag computation and
  the client's final output rule are transcribed from Figures 8 and 9 without alteration.
- **Figure 9 step 5(e)'s permutation of each cross-token row.** Correctness cannot see it — the
  server only counts XSet hits — so an implementation that dropped it would pass every functional
  test while leaking strictly more than the paper proves. Since one axis of the comparison *is*
  leakage, dropping it would have flattered our scheme. Kept, and tested directly.
- The s-term rule, including that a never-updated term has count 0 and therefore wins, making the
  conjunction empty.
- Client state is `UpdateCnt` and nothing else, so ODXT's `O(|W| log N)` client storage claim is
  measured rather than assumed.

### Two typographical errors in the paper's Figure 9

Recorded so nobody "corrects" the code towards them:

1. Step 5(e) says *"randomly permute the tuple-entries of `xTagList_j`"*, but no `xTagList` exists
   at the client — it is `xtokenList_j`.
2. The client's final output block initialises `IdList`, populates `sIdList`, and outputs
   `IdList`. The intent is unambiguous; the names are not consistent.

---

## Zuo et al., TDSC 2022 — *Forward and Backward Private DSSE for Range Queries* (FBDSSE-RQ)

Source: `ref-papers/Forward_and_Backward_Private_DSSE_for_Range_Queries.pdf`, Algorithm 1 (binary
tree), Algorithm 2 (the scheme), §2.1 (`P`, the homomorphic-addition encryption), §7
(implementation).

Code: `baselines/zuo22/`. Exp. 7's baseline.

### What the paper's own prototype used

| | Theirs | Ours | Why |
|---|---|---|---|
| Language | Java, macOS 10.13.2, i7 @ 2.8 GHz | Rust | Plan §5's fairness rule — wall-clock compares only inside the Rust workspace |
| Bitmap arithmetic | `java.math.BigInteger` at bit lengths 10³–10⁴ | fixed-width byte buffer, wrapping add | Arithmetic mod `2^y` on a `y`-bit value **is** wrapping addition over a fixed buffer; this is what `BigInteger.mod(2^y)` computes, without an allocation per operation. Same results, and the exhaustive tests check that |
| `H₁, H₂, H₃`, `F` | unspecified ("hash functions", random oracles in the proof) | SHAKE256, domain-separated | The paper never names them. SHAKE256 is our system XOF and the only one with the arbitrary output length `H₃` needs — `sk_i` must be a full `y`-bit one-time key, and `y` is 10³–10⁴ bits. The four uses are domain-separated by a leading tag byte; realising distinct oracles from one XOF without that would make them the same function |
| Parameters | `d ∈ {128, 256}`, `y ∈ {10³, 10⁴}` | same, plus small `d` for exhaustive tests | Kept so the numbers are comparable |

### The binary tree is not materialised

Algorithm 1 describes pointer plumbing — `parent`, `left`, `right`, `leftmost`, `rightmost`. Every
operation it supports (`TPath`, `TGetCover`, sibling detection) is determined by the node's
leaf-value interval, so `tree.rs` computes them arithmetically instead of allocating `2^{ℓ+1} − 1`
node objects. This is an implementation choice with no protocol effect; allocating the tree would
only add memory to the baseline's measured cost. Both of the paper's own worked examples —
`PT = {w1, w01, w03, w07}` for `v = 1`, and `BRC = {w23, w4}` for `q = [2,4]` — are pinned as tests,
and cover exactness is checked exhaustively over every range for several `d`.

### Node naming

The paper names a node `w_ab` after its leftmost and rightmost leaf values. Kept, but encoded as a
fixed 16-byte pair rather than a formatted string: `w_{1,23}` and `w_{12,3}` render identically once
punctuation is dropped, and a keyword collision there silently merges two subtrees. Injectivity is
tested.

### ⭐ Two properties that constrain how Exp. 7 may be measured

**1. Search is destructive and compacting.** Algorithm 2's server removes every entry it walked and
writes back `EDB[UT_c] ← (Sum_e, ⊥)` — the paper states this is *"in order to save the server
storage"*. A second search over the same node therefore does dramatically less work than the first.
⛔ Any reported search latency must say whether it is a cold or a warm search, and the same
convention must apply to our scheme. Reporting their warm number against our cold one, or the
reverse, would be a fabricated comparison. Pinned by
`tests/against_oracle.rs::search_compacts_the_server_index` and
`::a_repeated_search_returns_the_same_answer`.

**2. A missing cover node aborts the whole query.** Algorithm 2's `Search` lines 5–7 `return ⊥` if
*any* node of the best range cover has no history — not a partial answer. So a range whose matching
files all sit in one half still returns nothing when the other half's cover node was never updated.

Faithful, and left as-is. The resolution is to build the workload the way the authors built theirs:
§7, *"We update one time for each value."* With every value touched, every cover node is reachable
and the `⊥` path never fires. ⛔ If Exp. 7 instead used a sparse workload, Zuo'22 would return `⊥`
on many queries and appear **fast** for the wrong reason — a strawman that flatters *them* while
making the comparison meaningless. Pinned by
`tests/against_oracle.rs::an_untouched_cover_node_aborts_the_whole_query`.

Worth noting what is *not* missing: updating a value walks `TPath`, which touches every ancestor up
to the root, so a single updated leaf makes all of its ancestors reachable. Only a subtree
containing no updated leaf is absent.

### Exp. 1 ingest (M10 H1) — the same stream as ours, and how its oracle check reads `⊥`

Exp. 1's head-to-head feeds Zuo'22 the **numeric attributes of our own event stream**: one tree per
attribute at **our** depths (24/20/32/32, domain `2^depth`), bitmap width `y` = the stream's event
count, one `Update` per value (`crates/pqcl-exp/src/baseline_ingest.rs`). Ingest cost does not
depend on density: each value walks its `depth + 1` nodes either way, which is also why the node
count equals our prefix-keyword count exactly and `figspec.py` checks the two against each other.

The stream is **sparse** (2 000 events over `2^24`–`2^32`), so property 2 above fires on most
ranges. The oracle check therefore accepts a `⊥` **only** when the oracle confirms a cover node with
no value beneath it, and requires ≥ 2 answered ranges per attribute (a point query on a present
value always answers). An unjustified `⊥` fails the run, as does a wrong answer — both pinned by
tests. This sparsity does not touch Exp. 7, which keeps "touch every value once".

### Added: `Edb::stored_bytes` — instrumentation, not a protocol change

`tab:exp-range` reports Zuo'22's index size at the largest `y`, **measured**. `stored_bytes` sums
what the server's `EDB` holds, in the label + value convention the size harness uses for every
other scheme: `UT` (32 B) as the label, then the value `(e, C_ST)`, the `y`-bit bitmap ciphertext
plus the 32 B masked token (absent at a chain's head). It reads the map; it changes nothing the
server stores or does. Before this, the only size figure was the skip reason's estimate
(~14·y² bytes), which §1o.4 ruled out as a table entry.

### Not changed

- The protocol. Update, the server's backward chain walk, the compaction write-back, and the
  client's key-sum decryption are transcribed from Algorithm 2 without alteration.
- Deletion as addition of `−2^i mod 2^y`. The scheme never distinguishes an insertion from a
  deletion, which is precisely where its Type-R backward privacy comes from; giving the update path
  an `op` flag would have destroyed the property being measured.
- One-time keys. `P` is perfectly secure *only* while each `sk` is used once; `sk_i = H₃(K'_w, i)`
  is derived per counter value and never reused.

---

## Reused, not reimplemented — `CDSecLab/Doris` (OXT, HXT, ConjFilter, Doris)

Source: `ref-papers/DORIS_CCS2024.pdf` (§Implementation Settings) and the authors' own repository,
vendored as a submodule at `baselines/doris/upstream`, pinned to
`61907c60910e159830009051c32fef077274c6e1`.

Code: `baselines/doris/` — `Dockerfile`, `run.sh`, `metrics.py`.

⛔ **Python, so no wall-clock number from here may ever reach the paper.** Plan §5. We take only
index size, communication volume, round count and leakage. `metrics.py` does not merely drop the
timing column — it never calls `time()`, so there is nothing for a later reader to "restore".

### ⭐ The one deviation from the standing modernization rule, and why

✅ **Reviewed and accepted 2026-09-15.** Logged here because the register exists so that no deviation
is silent — and *declining* to deviate is itself a decision a reviewer should be able to audit.

Plan §7 says to modernize a dated baseline stack so the comparison is like-for-like. **This
container deliberately does the opposite** and reproduces the authors' environment exactly: Ubuntu
20.04, Python 3.8.10, PBC 0.5.14, `pypbc`, and their four pinned pip packages.

Modernizing exists to stop a baseline being *slow* for reasons unrelated to its design. We take no
timing from this code at all, so modernizing buys nothing and costs fidelity — every version bump
is a chance to change behaviour in a reused implementation nobody here wrote. Reproducing their
stack is the lower-risk choice **because** the metrics are language-independent.

The same reasoning disposes of the usual "never build under `/mnt`, 9p wrecks I/O measurements"
rule: there is no timing here to wreck.

### The `pypbc` problem, resolved

`pypbc` is unmaintained — no PyPI release, no tags, no CI — and PBC 0.5.14 is not packaged.

- **PBC** is built from source, with its tarball checksum verified against an actual download
  (654 515 bytes, `7725274041…4c23d2`, 2026-09-13) rather than carried as a constant nobody has
  checked. Without it a truncated tarball surfaces as a linker error deep in the `pypbc` build.
- **`pypbc`** is pinned to commit `c518d6ff074f538080c5794924f83ee441ed44ea`, resolved from the
  remote rather than left as "whatever the default branch was when you built this".

📌 **Ubuntu 20.04 is past standard support but `focal` is still on `archive.ubuntu.com`** — checked
2026-09-13: `dists/focal/Release` returns 200, `old-releases.ubuntu.com` returns 404. An earlier
draft of the Dockerfile rewrote sources to `old-releases` on the assumption that EOL implies the
move. It does not, and that rewrite is what broke the first build. Recorded so nobody re-adds it.

### ⭐ Upstream's `TSet` setup fails probabilistically — a finding, not a flaky box

`Utils/TSet.py` sizes a `B × S` grid with `B = S = ceil(sqrt(n·k))`, and `_free_b` raises
`Exception("insufficient space")` when the bucket a pair hashes into is already full. Bucket
assignment depends on `kt`, which `setup` draws **freshly at random on every call**, so whether a
run survives is a coin flip weighted by how close the maximum bucket load sits to `S`.

Measured at the authors' own `k = 2`, 12 trials per tier on Enron:

| tier | pairs | `B = S` | failures |
|---|---|---|---|
| 0 | 100 | 15 | **1 / 12** |
| 1 | 1 000 | 45 | 0 / 12 |
| 2 | 10 000 | 142 | 0 / 12 |

At `k = 4` and `k = 6`, 0/12 everywhere. This is why the first full run died at tier 1 with
`insufficient space` — not misconfiguration on our side.

**Resolution: retry with a fresh `TSet`, keeping `k = 2` unchanged.** Preferred over raising `k`
because `k` is an upstream parameter that shapes the structure, whereas `kt` is *already* random
per run — re-drawing it changes nothing about the scheme. `metrics.py` reports `setup_attempts`
per row, so the fragility is visible in the data rather than smoothed away. A non-capacity
exception is re-raised rather than retried into silence.

### What their storage number counts, and what it does not

`cal_size` sums `len(pair)` over **occupied** slots only. The allocated `TSet` is `B × S ≈ n·k`
slots, so the reported `tset_size` is *payload*, not allocation. ⚠️ When our index size is compared
to theirs the paper must say which convention is in force, or the comparison silently favours
whichever side counts less.

### Their size formulas, used verbatim

Copied from `setup_exp.py`, because the schemes count differently and recomputing them our own way
would measure something the authors never reported:

| Scheme | `tset_size` | `xset_size` |
|---|---|---|
| OXT | `cal_size(edb.tset)` | `len(edb.xset) // 8` — Bloom **bit** array, bits→bytes |
| HXT | `cal_size(edb.tset)` | `len(edb.xset) * 32` |
| ConjFilter | `cal_size(edb.EMM)` | `len(edb.X) * 32` |
| Doris | `cal_size(edb.tset)` | `len(edb.ct) * 32` |

Sanity check reproduced: HXT's SHVE-encrypted Bloom filter costs far more than OXT's plain one
(98 330 B vs 6 658 B at tier 0), which is exactly what §Setup Evaluation claims.

### What the run produced, and the sanity checks it passed

**36 rows**, zero errors: four schemes × two corpora × tiers 100–10⁵ in `doris-structural.json`,
plus the 10⁶ cap on Enron in `doris-structural-tier4.json`. Both are provenance-stamped with the
upstream commit.

⛔ **The table below is SUPERSEDED — it predates the §1.7 canonicalisation.** Every OXT and HXT
figure in it sums *minimal-length* field-element encodings, a Python artifact that understates
their index; the tell is that the totals are not round (66 586 524 where the canonical run gives a
clean multiple of 63 B/entry). Regenerating via `run.sh publish`; do not quote these. Same defect,
same reason, as the implementation report.

Enron, total index bytes:

| Scheme | 10² | 10³ | 10⁴ | 10⁵ | 10⁶ |
|---|---|---|---|---|---|
| OXT | 6 659 | 66 587 | 665 866 | 6 658 674 | 66 586 524 |
| HXT | 98 330 | 983 182 | 9 831 585 | 98 315 821 | 983 157 683 |
| ConjFilter | 49 420 | 631 608 | 5 937 904 | 78 430 688 | 772 854 464 |
| Doris | 52 740 | 687 272 | 6 398 544 | 87 409 248 | 859 997 696 |

Three independent checks that the reuse behaves as the papers describe, rather than merely running:

1. **`TSet` cost per pair is constant to four orders of magnitude** — 62.99 B for OXT and HXT,
   107.00 B for ConjFilter, 41.00 B for Doris, unchanged from 10² to 10⁶. These are fixed-width
   records, so the exact round numbers are expected rather than suspicious. A drift here would mean
   the harness was measuring something that varies with tier, which is the failure mode worth ruling
   out before quoting any of it.
2. **HXT's XSet is ~256× OXT's**, which is the SHVE encryption of the Bloom filter that Doris §Setup
   Evaluation gives as HXT's cost for hiding KPRP.
3. **ConjFilter and Doris scale with document size, OXT and HXT do not.** At equal pair count the
   Enwiki XSets are far larger than the Enron ones (tier 3: 493 MB vs 68 MB for ConjFilter) while
   OXT's and HXT's are identical across corpora. That is exactly the `O(N)` vs `O(n)` split of
   Table 1, where `N` counts pairwise intersections and therefore depends on how many labels each
   document carries.

### Provenance, and a trap that silently destroyed it

`metrics.py` originally resolved the upstream commit itself with `git rev-parse HEAD`. Inside the
container that **silently returns nothing usable**: a submodule's `.git` is a *file* pointing at
`../../.git/modules/…`, which is outside the mount, so the lookup fails and the field was written
as `"unknown"`. A metric that cannot be traced to the code that produced it is not a usable metric,
and the failure was invisible — no error, just a placeholder string.

Now the host resolves it (`git -C upstream rev-parse HEAD`) and passes it in, and `metrics.py`
**refuses to write results at all** if it is missing rather than emitting `"unknown"` again.

### ⛔ NAMED CARVE-OUT — the one AWS-only exception, and where it stops

*Condition 1 of the the design record standing rule, ruled 2026-09-15.*

⛔ **This is a named exception to ground rule #3, not a softening of it.** Rule #3 — *paper numbers
come from AWS only* — stands unchanged everywhere else in this project.

| | |
|---|---|
| **Scope** | The reused `CDSecLab/Doris` container, **structural quantities only** |
| **Not covered** | ⛔ Everything else. In particular **our own Rust structural metrics are not covered** and run on AWS like every other number |
| **Never covered** | ⛔ Any latency, throughput or gas figure, from any source, under any label |

**Why it was granted.** Re-running was priced at *"costs minutes"*, which is true of our Rust metrics
and false here: it means rebuilding a 446 MB Ubuntu 20.04 image that compiles PBC 0.5.14 from source,
on a paid instance, at the end of the campaign. The deciding argument is consistency — the
justification for **not** modernizing this stack (the section above) is that its metrics are language-
and host-independent. That premise cannot be accepted to skip the modernization and rejected to force
the rebuild.

**It is enforced, not remembered.** `tools/mkfigs.py` accepts the marker `reused-baseline-structural`
**only** when the record also names an upstream and commit, carries determinism evidence, and every
row key is in a closed structural whitelist. `dirty_tree` is **not** waived. Sixteen self-tests cover
the ways the exception could widen, and `cargo xtask ci` runs them — because a test suite nobody runs
is a convention, which is what condition 3 exists to rule out.

⚠️ **Do not add a metric name to that whitelist to make a record pass.** Adding one is a decision to
be argued in the design record, not a convenience.

### ✅ Condition 4 — failed, diagnosed, fixed by canonical field-element width

*Measured 2026-09-15, the first time condition 4 was run. Raised as the design record,
ruled **A**, resolved at `ba2efb8`. The failure and its diagnosis are kept below because the fix only
makes sense against them.*

**The fix.** `metrics.py` wraps `pbcUtil.Zr2Bytes` to pad every field element to
`⌈log₂ r / 8⌉ = 20` bytes, with the width **derived from upstream's own curve parameters** rather
than hardcoded — a changed curve must not leave a stale constant behind.

⭐ **Applied at the serialisation point, not by modelling an entry's composition.** An entry is
`h.L(8) ‖ β(1) ‖ struct.pack("H", len(y))(2) ‖ y ‖ e`, and `y` is the only variable-width part. The
alternative — summing canonical widths per component — needs a model of that layout which we could
get wrong silently and in our own favour. Padding the one variable component makes the total exact by
construction and removes the class of error rather than checking for it.

**Result, with every prediction from the diagnosis holding:**

| | |
|---|---|
| `tset_bytes` | now **exactly round** — 63 000 at n = 1000, i.e. 63 B/entry, at every tier |
| ConjFilter, Doris | **`canon+0`** — not pairing-based, never call `Zr2Bytes`, were already reproducible |
| OXT, HXT | corrected by **3–11 bytes per 1000**, against a predicted 7.6 ± 2.75 |
| Net effect | affected indices move **up ~1.3 × 10⁻⁴**, i.e. against us |

**The tripwire, and why it is not decoration.** A canonical figure we derived wrongly would be *our*
error moving a published number in *our* favour. So `check_canonicalisation` asserts the correction is
non-negative, **exactly zero** for any scheme that serialised no field element, and within
`mean + 6σ + 16` of the binomial. A correction wrong by a factor — bad model, changed curve, a second
source of variation — halts the run and says not to publish.

⚠️ **`zr_short_encodings` and `canonical_bytes_added` are excluded from the determinism comparison,
and that is not a loophole.** They *are* the absorbed variation: they vary precisely so that
`tset_bytes` no longer does. `zr_elements` is **not** excluded and must agree exactly.

---

#### The original failure, kept for the record

Two container runs of the same commit over the same corpus disagree by a few bytes:
`tset_bytes` at tier 1 spans **62 987 … 62 995** across runs — a range of 8 in ~62 990, or
`1.3 × 10⁻⁴`.

**Cause, isolated rather than assumed.** A five-trial probe run both in-process and across three
containers:

- the **entry count is exactly deterministic** — 1000, every run, always;
- `tset_bytes` is **constant within a process** even with a fresh `PARAMS()` per trial;
- it varies **across processes** only.

`Utils/cfg.py` pins the pairing curve, so a Zr element is a fixed 160-bit value — but
`Utils/pbcUtils.py:30` serialises with `long_to_bytes`, which is **minimal-length**. An element below
`2^152` encodes one byte shorter, and `2^152/r ≈ 1/132`, giving ~7.6 short encodings per 1000 entries
with a binomial spread of ±2.7. The observed range matches that prediction.

⭐ **The consequence that matters is not the nondeterminism.** Summing minimal-length encodings
**understates** their index, and it measures `Crypto.Util.number` rather than the scheme — any C or
Rust implementation writes a canonical fixed-width element. We are currently reporting a baseline's
index as *smaller than it is*, for a reason unrelated to its design. Same shape as the ODXT
deletion-granularity finding: a strawman pointing in our favour.

⛔ **Do not "fix" this by loosening the comparison to a tolerance.** A tolerance is a number a later
agent can widen, which is exactly the hole condition 3 was written to close. ✅ It was not: §1.7 ruled
canonical width, which is the fix recorded above.

📌 **Confirmed at scale afterwards.** The correction tracks `n/132` across four orders of magnitude —
**+6/+8** at 10³, **+87/+73** at 10⁴, **+785/+764** at 10⁵, against predicted means of 7.6, 76 and
758. A diagnosis that predicts the right number at 10⁵ having been fitted at 10³ is the reason this
is recorded as a cause rather than a correlation.

### ⚠️ Regenerating the big tiers needs an environment that stays up

*Recorded 2026-09-15 after three killed attempts, so the next person does not spend the same hour.*

Measured cost of `run.sh publish` on Enron, both determinism runs included:

| Tiers | Wall clock |
|---|---|
| 10²–10⁴ | **58 s** ✅ fits comfortably in one agent tool call |
| 10²–10⁵ | over 10 min ⛔ |
| 10²–10⁶ | ~40 min+ ⛔ — OXT alone at 10⁶ is a million Python pairing operations, twice |

⛔ **Detaching does not help, and this cost three attempts to establish.** `nohup … &` dies with the
process group; `setsid nohup … &` escapes the group but the distro itself goes away between agent
invocations. Worse, the `docker run` **outlives its wrapper** — a container sat "healthy" for forty
minutes after the job controlling it had died, with nothing capturing its output and no subsequent
step able to run. A running container is not evidence of a progressing job; a **growing log file**
is.

⭐ **So run the 10⁵ and 10⁶ tiers on a box where a job can run for an hour** — in practice the AWS
instance, during the campaign. Note this is a *practical* constraint, not the carve-out talking: the
carve-out permits these numbers off AWS, and they would be equally valid produced anywhere. It is
simply the machine we have that stays up.

### ✅ Read-versus-assumed audit — every paper-derived claim checked against the PDF

*Done 2026-09-15, prompted by the HXT round-count error: that claim was **asserted** rather than read
from Table 1, and it ran in a baseline's favour. The lesson generalises, so every claim in this file
sourced to the Doris paper was re-checked against `ref-papers/DORIS_CCS2024.pdf` directly.*

| Claim | Verdict |
|---|---|
| Table 1's four rows — storage order, rounds, KPRP/IP hidden | ✅ **Verified verbatim**, p. 3. `O(n)/1/✗/✗`, `O(n)/2/✓/✗`, `O(N)/1/✗/✓`, `O(N)/1/✓/✓`. Matches `metrics.py::PROTOCOL` exactly, HXT's 2 rounds included |
| Bloom false-positive rate `10⁻⁶` | ✅ **Verified**, p. 12 and p. 13 |
| §Implementation Settings, §Setup Evaluation exist and say what we cite | ✅ **Verified**, both p. 12 |
| HXT's SHVE-encrypted XSet dominates the storage comparison | ✅ **Verified**, p. 12: *"The difference between the compared four schemes is dominated by the data structure of XSet"* |
| ⚠️ TSet expansion `k = 2` attributed to §Implementation Settings | ❌ **Wrong — corrected.** The paper never states it; it is upstream's code only. See *Smaller notes* |

⚠️ **Re-run 2026-09-24, and it turned up a sixth thing the first pass did not look for: `O(N)`
does not mean what a reader will assume.** The first audit verified the four rows' *values* against
Table 1 and stopped there. It did not read the caption, which defines the symbols — and `n` and `N`
are not the same kind of quantity:

```
n    = Σ_{ℓ∈L} |MM[ℓ]|                    total label/value pairs
N    = Σ_{ℓi,ℓj∈L} |MM[ℓi] ∩ MM[ℓj]|      summed over label PAIRS
n_ℓ1 = |MM[ℓ1]|                           the s-term's postings
```

So ConjFilter's and Doris's `O(N)` is a sum over *pairs* of labels of their intersection sizes,
which on a correlated corpus is far larger than `n`. It is not "N records", and it is emphatically
not a synonym for our `pairs` column — which sits in the same emitted row, inviting exactly that
misreading. The storage trade OXT/HXT `O(n)` versus ConjFilter/Doris `O(N)` is *worse* for the
latter two than four letters suggest.

📌 The shape of this miss is worth naming too: verifying the cells of a table while skipping its
caption. A symbol is only as checked as its definition.

📌 **One error found in five claims, and it is the same shape as the HXT one** — a fact true of the
*artefact* being attributed to the *text*. Neither changes a measurement: `k = 2` is what upstream
runs either way. What it changes is what we could defend if a reviewer asked where the parameter came
from.

⭐ **Worth generalising beyond this file.** "Upstream's code says X" and "the paper says X" are
different citations with different strength, and the cheap habit is to name which one at the point of
writing rather than to audit for it later.

### 📌 How the AWS ruling reached the carve-out above — the history, so it is not re-argued

The build plan puts every published number on AWS, so *performance* figures are
comparable. The metrics here are byte counts, so the first run was local and a **general** exemption
was requested on the grounds that they are host-independent.

**Refused first, then narrowed and granted.** The refusal was right: *"this particular metric is
host-independent"* is a case that can later be made about almost any metric, and a general carve-out
only ever widens. What moved the answer was consistency, not cost — the section above declines to
modernize this stack **because** its metrics are language- and host-independent, and that premise
cannot be accepted to skip the modernization and then rejected to force a rebuild.

The result is the **named, bounded** carve-out at the top of this file, enforced in `mkfigs.py`
rather than remembered. Everything outside its scope — including all of our own Rust structural
metrics — is regenerated on AWS with no bypass flag.

⚠️ **The numbers in this file and in the implementation report are SUPERSEDED**, for a
different reason than where they ran: they are sums of minimal-length encodings. §1.7 is now
**resolved** — `Zr2Bytes` is canonicalised to `⌈log₂ r / 8⌉ = 20 B`, so a tier's `tset_bytes` is an
exact multiple of 63 B per entry — and the regeneration is running. Until it lands, quote neither.

### Smaller notes

- **Tiers.** Their driver hardcodes `cnt = 4`, stopping at 10⁵. Plan §7 caps us at their 10⁶ tier,
  which is index 4, so all five are run. Parameters are otherwise untouched, but ⚠️ **the two have
  different provenance and an earlier version of this line conflated them** (corrected by the
  read-versus-assumed audit, 2026-09-15):
  - Bloom false-positive rate **10⁻⁶** — in *both*. `setup_exp.py:98` and the paper, p. 12:
    *"we deploy OXT and HXT using Bloom filter with a fixed false positive rate 10⁻⁶"*, restated on
    p. 13.
  - TSet expansion **`k = 2`** — **upstream's code only** (`setup_exp.py:99, 123, 146, 174`). The
    paper does not state it anywhere. Faithful to the artefact, not attributable to the text.
- **PyCrypto → pycryptodome.** The paper says PyCrypto; `requirements.txt` pins
  `pycryptodome==3.19.0`. Upstream had already made that substitution — we keep their pin and did
  not introduce it.
- **`stack setup Failure` from Doris is expected.** It is the XOR filter's peeling step failing,
  which is normal for that structure; `Utils/XorFilter.py::update` retries up to five times with
  fresh seeds. Not an error, and not something we changed.
- **Round counts are paper-derived, not measured.** `metrics.py` labels them as such rather than
  implying it observed them. ⚠️ **They are not all one round: HXT is two** (their Table 1, and the
  body explains why — hiding KPRP costs an extra round of interaction). An earlier version of this
  note said "all four are single-round", which was stale and wrong **in HXT's favour**; `metrics.py`
  has had `HXT: 2` since the harness was written, so the code was never affected. Corrected
  2026-09-15.
- **`pympler` is a red herring.** It appears in `requirements.txt` and in one unit test
  (`Utils/test/BF_test.py`), but the experiment path never uses it. Worth stating because a
  `pympler.asizeof` number would be Python object overhead — language-*dependent*, and therefore
  not comparable to our Rust byte counts. Their real measurements are honest byte counts.

## LEChain — Li et al., FGCS 115 (2021) — deployed from its published contract (M10 H2)

Exp. 6's custody-commit baseline. **Reused, not reimplemented**: the contract its paper cites as
its source code (footnote 5, `github.com/SopmmmodII/LEChain`), deployed unmodified on our Besu
network next to `Anchor.sol`, driven by `crates/pqcl-exp/src/bin/exp6chain.rs`. Read from
`ref-papers/LEChain.pdf` §7.1–§7.3 and Tables 3–4.

### Source, and why it is not vendored

The repository has **no licence**, so its source is not committed here. `baselines/lechain/fetch.sh`
clones it into a gitignored `upstream/`, pinned at commit `159b5a7` ("Add files via upload", the
head, 2020-08-18; the only other commit is GitHub's empty initial one) **and** by the file's
SHA-256 `a9767874…d36d4fa`. A mismatch refuses rather than warns. The upstream blob is CRLF; the
hash is of the bytes as served.

### Compilation — what the paper does not say, resolved

The pragma admits `>=0.4.22 <0.7.0`; §7.1 says only "written on Remix". Resolved as **solc 0.6.12**
(the newest the pragma admits), **optimizer off** and the compiler's default EVM target
(**Istanbul**) — Remix's 2020 defaults (`baselines/lechain/foundry.toml`). It compiles with
warnings only (unused parameters). The bytecode is 11 603 B, inside EIP-170. **The source is not
modified**: no port was needed, so the "say so and stop" branch did not fire.

⚠️ Gas is measured on **our** chain (Cancun rules, post-Berlin cold-access pricing), not quoted from
2020. That is the point: B-CoC's Table 1 gas is pre-Berlin and is never set beside ours.

### Network — modernised, and the same for both sides

LEChain ran geth Clique PoA with 10 s blocks on four VMware miners (§7.1). Ours is the four-validator
Besu QBFT network every chain measurement here uses (`besu/`), 2 s blocks. Both contracts run on
it, in one process, through one client, so the block period changes **both** sides' commit
latency by the same mechanism. The block gas limit is the network's (plan §9: not a dial).

### Roles and payloads — from the paper

- Role accounts per Table 4: 10 police investigators, 100 crime-scene analysts, one police
  department; its four miners serve as the blockchain nodes `orRejectUpload` requires. Set once via
  `setChars`, as its constructor's initializer.
- Payload sizes per §7.3's communication analysis: `R_ω` 132 B, `{c_sa}` 120 B, `ρ` 20 B,
  identities 7 B. Filled with hash output, since group elements and signatures are not zero-heavy
  and calldata gas depends on it.
- Every transition carries the `(msgh, v, r, s)` its contract `ecrecover`-checks against
  `msg.sender`, signed by that sender (`evm::Key::sign_digest`, KAT-checked).
- Gas limit = `eth_estimateGas` × 1.25 per call type: what web3.py, LEChain's client, does. ⚠️ A
  fixed generous cap was the first draft and was changed **before** anything was measured, because
  Besu stops packing a block when the next limit no longer fits, so an inflated limit would have
  lowered LEChain's throughput for a reason that is not its design.

### ⚠️ The event mapping — a modelling choice, and its direction

Our stream uses seven event types; LEChain's contract has seven state transitions, not the same
seven. The mapping:

| Ours | LEChain | Note |
|---|---|---|
| `COLLECT` | `orUpload` | its collection is `Request` **then** `Upload`; only `Upload` is sent — **conservative for us** (one transaction fewer per capsule) |
| `SEAL` | `orStore` | the police department stores the evidence |
| `ACCESS`, `ANALYZE`, `EXPORT` | `orAccess` | its only handling transition |
| `TRANSFER` (both bilateral records) | `orAccess` | **it has no handoff transition**; `Access` is its cheapest state-changing call — conservative for us |
| `DISPOSE` | `orRejectUpload` | its only deleting transition (it deletes the collection request) |

`Vote` and `Complete` (court trial) have no custody-event counterpart and are not exercised.

⚠️ **Redaction orders are ours alone (§1v.4).** Since 2026-09-28 every epoch of ours that disposes
anything also pays one `orderRedaction` transaction (a sweep over its disposals), recorded before
that epoch's anchor and amortised into our gas per entry. LEChain's `orRejectUpload` needs no order.
Pessimistic for us, and chosen that way: one order per disposing epoch, where practice is likely
one sweep at case closure.

### Measurement — theirs, plus the throughput they can reach

- **Sequential** — §7.3's own method: send one upload, `waitForTransactionReceipt`, repeat, 40
  times. Reproduced over the first 40 events of the stream.
- **Pipelined** — the rest of the stream, at most 64 in flight per sender: the throughput the
  contract reaches on this network. Not something §7.3 measured; stated as ours.
- Commit time for both sides = the first observation of the including block by a watcher thread
  polling every 20 ms, so resolution is ±20 ms against a 2 s block.
- Its client-side preparation (the `msgh` signature and the transaction signature) is timed
  separately and excluded from commit latency, as our own client-side record signing is.

---

## PQ-ABL — Fugkeaw et al., IEEE TCC 14(2) 2026 — integrity layer reimplemented (SAC Exp. 2, §1cd)

SAC Exp. 2's per-epoch comparator (SAC `b23`). `baselines/pqabl`, driven by `custody.rs`'s
`pq_abl`. Read from `ref-papers/Optimized_Post-Quantum_Attribute-Based_Logging_*.pdf`: Phase 4
(p. 7), Phase 5 (pp. 7–8), eq. (1) (p. 14). There is no public code.

- **What is built.** Only the integrity half: `h_n = H(CT_n)` per stored ciphertext object,
  `R_e = MerkleRoot(h_1…h_N)` over one independent tree per epoch, standalone membership by an
  `O(log N)` path (Phase 5 Step 3), and full-epoch verification (recompute every `h_n`, rebuild,
  compare; eq. (1)). The lattice CP-ABE that encrypts each log is upstream of what Exp. 2 times,
  which starts from stored ciphertexts.
- **Hash: SHAKE256 for SHA3-256**, through the same `tiny-keccak` our system uses, as in every
  Exp. 2 arm. The table compares structures, not hash functions. Same Keccak permutation and
  output size; SHAKE256's rate is 136 B against SHA3-256's 136 B, so the cost per byte is the same.
- **Leaf and node prefix bytes (`0x00`/`0x01`)**, and an unpaired node is **promoted, never
  duplicated** (CVE-2012-2459). The paper writes `MerkleRoot` without fixing either. Both cost
  one byte per hash and neither changes the work.
- **Epochs are ours, and since §1ci.5 they are 10⁴ records each.** The paper's epoch is a time
  interval `Δ` (30 s in its evaluation, p. 13); its epoch-size study runs 1,000 to 50,000 logs
  (p. 15, Fig. 7). The case's records are cut into sealing epochs of 10⁴ records, closed by count
  in stream order, then one redaction epoch, and PQ-ABL gets exactly those, so its per-epoch
  trees cover the same records as our per-epoch MMRs. A capsule's seal object goes into the epoch
  of its `COLLECT`, just before it; the redaction epoch holds the order and the `DISPOSE`s.
  - ⚠️ **Rule 20, corrected before re-measuring (c10c).** Until c09a every record but the
    `DISPOSE`s sat in **one** epoch, so PQ-ABL built one tree over about 10⁶ objects: paths of about
    20 hashes where its own largest epoch gives about 16. That lengthened its proof and verify time,
    a baseline configured to look worse, and it also gave ours its best layout (one `0x02` path per
    capsule). 10⁴ is inside PQ-ABL's range, near its geometric middle, and a point on Exp. 1's axis.
  - The parallel audit now shards across epochs first, and inside an epoch only when there are
    fewer epochs than threads: the most parallelism the structure allows.
- **The court's proof is one path per object** (the capsule and each record), since the paper
  gives no batched form. Its leaf-pair proof set `P_e` gives `O(1)` checks only *after* the epoch
  has been validated (p. 7), which a court disclosure has not done.
- **Parallel audit.** The paper does not parallelise. We shard the leaf hashing and every tree
  level of ≥4,096 nodes across cores, splitting at even offsets so the tree is the one-core tree.
  That is the most parallelism its structure allows, so the baseline is not measured slower than
  it can run.
- **Rows it is expected to win or tie.** Its structure is a flat Merkle tree per epoch, close to
  our own flat-MMR arm. That is the point of including it.

## PQ-ABL in Exp. 4 — deletion as rebuild and re-commit, our extension (SAC Exp. 4, §1ci.2)

PQ-ABL defines no deletion. Its structure allows exactly one: remove the ciphertexts, rebuild each
epoch that held them, and commit that epoch again. That is what this arm does, and the paper will
say the deletion is **our extension** of PQ-ABL, as Exp. 3 does for re-validation.
`crates/pqcl-exp/src/bin/redaction.rs` (`Pqabl`), `contracts/src/PqablAnchor.sol` (3 Foundry
tests), `baselines/pqabl` (`archive`, `extract`, `proof_set`).
- **What is deleted:** the capsule's evidence object (the same 4 KiB ciphertext ours and B-DEMS
  store) and its custody-record ciphertexts, from every epoch that holds them. One deletion of
  `k` capsules rebuilds each affected epoch **once**, as our one order covers all `k`.
- **The rebuild follows Phase 4 (p. 7):** the tree over the kept leaf digests (Step 2); the proof
  set `P_e` (Step 2); `Archive_e = tar.gz(CT_1…CT_N)` re-packed (Step 3); `CID_epoch` and
  `CID_Proof` (Step 3); `Commit(R_e, CID_epoch, CID_Proof, t_e)` (Step 4).
  - **Favours PQ-ABL:** a SHA-256 content hash stands in for the IPFS CID, so no upload or pinning
    is timed; the kept leaf digests are reused, not recomputed; the epochs are rebuilt across
    cores, each tree's levels shard across cores, and each archive's gzip runs in members
    across cores (a valid gzip file any `gunzip` reads whole); the gzip level is the default
    and the paper names none.
  - ⚠️ **Corrected before c10b (rule 20).** The gzip members were a fixed 8 MiB, so a 10⁴-record
    epoch (about 40 MB) used at most 5 of the instance's cores, and a 1,000-record smoke epoch
    one. A member is now the stream split evenly across the cores, between pigz's 128 KiB block
    and 8 MiB. The tree root was also built on one core; it now shards like Exp. 2's audit.
  - `P_e` keeps the unpaired last leaf. The paper's `⌊N/2⌋` pairs would drop it, and its auditor
    rebuilds the tree from `P_e`, which needs it.
- **The re-commit appends; an anchor is never overwritten.** `PqablAnchor.commit` pushes a new
  `(R_e, CID_epoch, CID_Proof, t_e)` for the epoch, and `getAnchorData` (Phase 5 Step 1) returns
  the latest. The old root stays on chain.
- **Authority: the logger.** PQ-ABL has no court and no order, so the logger re-commits, measured
  as built. No court signature was added.
- **The court's check, from PQ-ABL's own artefacts.** For each epoch that held the capsule: a
  second commitment exists; the original `P_e` (fetched by its `CID_Proof`; digests only, so it
  is kept) rebuilds the original root and holds the capsule's digests; the latest archive (by its
  `CID_epoch`) matches its address, unpacks, and its re-hashed objects rebuild the latest root
  (Phase 5 Steps 2–3); those objects are a subset of the original's and none is the capsule's.
  This costs a full-epoch re-validation per epoch, which is the mechanism behind its F(b) number.
  - Re-hashing and both tree rebuilds run on every core (corrected before c10b; they ran on
    one), as Exp. 2's audit of the same structure does. Unpacking stays on one core: a gzip
    stream has no index of its members, and `gunzip` and pigz both decompress serially.
  - **Also timed, beside it: the same verdict from digests alone** (`verify_digests_only_ns`),
    with the latest `P_e` (by its `CID_Proof`) in place of the archive. That answers what ours
    and B-DEMS answer, that the deletion is recorded, without re-validating the stored archive.
    It would accept T2's `Modified` row, whose archive is altered; T2 uses the full check. The
    paper can report either with this mechanism; the two differ by the archive's share.
- **T2, stated before measuring (rule 20).** Valid: accept. NoRecord (rebuilt and stored, never
  committed; the archive the chain names is gone): reject. **Insider (the logger alone): accept,
  by design**, as for B-DEMS. Modified (the stored archive altered after an honest re-commit):
  reject, its content address no longer matches. Replay (each rebuilt epoch committed with another
  epoch's honest state): reject, its objects are not the epoch's.
- **Invalidated proofs.** Every other log in a rebuilt epoch gets a new root, so its earlier path
  no longer verifies against the latest anchor. The record counts them per deletion
  (`invalidated_records`); ours invalidates none, since a redaction anchors a new epoch.
- **Epochs:** Exp. 4's case uses the same 10⁴-record sealing epochs as Exp. 2. ⚠️ **Rule 20:** T1's
  gas grows with the number of distinct epochs the `k` capsules touch, which the stream decides.
  `k`'s capsules come from the same seeded shuffle all three arms draw from, not chosen to land
  in many epochs.
- **The labelled one-epoch series (§1ci.6).** The same case sizes with every record in one sealing
  epoch, ours (`FULL`) and PQ-ABL only, F(a) at every size and T1 on the largest. PQ-ABL's deletion
  cost (rebuild, re-pack, re-commit) grows with its epoch, ours does not. Past 50,000 logs an epoch
  is beyond PQ-ABL's evaluated range (p. 15); each case carries `beyond_pqabl_evaluated_range`.
- **Not modelled:** Phase 3 Step 4's per-log asynchronous anchoring of `⟨h_n, CID_n⟩`. Exp. 4's
  case setup does not issue it; if it did, those digests would stay on chain after a deletion.

## GlassDB — Yue et al., PVLDB 16(6) 2023 — reimplemented in Rust (SAC Exp. 2, §1cd)

SAC Exp. 2's verifiable-ledger comparator (SAC `b32`). `baselines/glassdb`, driven by
`custody.rs`'s `glassdb`. Read from `ref-papers/p1359-ooi.pdf`: §3.2.1 (APIs and `VerifyBlock`),
§3.3.1 and Fig. 3 (two-level POS-tree). Also read from the extended version in the authors'
repository (`nusdbsystem/LedgerDatabase`, `doc/GlassDB_extended_version.pdf`): §3.3.3 (fixed batch
size per block) and §5.3.3 (batch size).

### Why a reimplementation, and what it follows

The authors' code is C++, and a C++ wall clock does not go in a Rust table (plan §5). Their public
repository holds the four systems GlassDB was compared against (QLDB\*, LedgerDB\*, SQL Ledger\*,
Trillian) but **not GlassDB's own POS-tree**. The POS-tree comes from ForkBase (Wang et al., PVLDB
2018), and its chunker follows ForkBase's released code (`nusdbsystem/forkbase`,
`include/node/rolling_hash.h`):
- a buzhash over a **256-byte window**;
- a boundary when the low **12 bits** are all ones (`kDefaultChunkPattern`), so nodes average about
  4 KiB;
- a **32 KiB** cap;
- a node ends after the entry in which the boundary is crossed.

Leaf and index nodes use the same rolling hash, as in ForkBase.

### The structure, as the paper specifies it

- **Lower level.** A POS-tree over the state, sorted by key. A leaf entry is
  `(key, value, H_prev)`; `H_prev` is the hash of the node that held the key's previous version,
  and `H_Φ` (zero) for the first version. Index entries are `(first key of child, H(child))`.
  Values sit **in the leaves**, as in Fig. 3.
- **Data block** `BLK_B` = block number, timestamp, lower root hash, and the number of writes.
- **Upper level.** A POS-tree keyed by block number, entries `(B, H(BLK_B))`. The ledger digest is
  `H(upper root)`.
- **Copy-on-write**, and every node ever created stays addressable by its hash. The tree is
  **structurally invariant**: it depends on content, not update order. The crate's tests check
  this: after each of 60 random batches, the incrementally updated tree is compared with a
  from-scratch build.

### Choices the paper leaves open, and their direction

- **Hash: SHAKE256 for BLAKE2b**, through our `tiny-keccak`, as in every arm. The buzhash table
  (ForkBase's is a fixed constant table) is drawn from SHAKE256. Chunk boundaries then fall at
  different bytes but with the same distribution.
- **Batch size: 1,000 writes per persist batch.** This is the extended version's §5.3.3 statement:
  GlassDB is most space-efficient above 1,000 keys per batch. It was taken from their evaluation,
  not chosen against our workload.
- **One version per key per block.** Within a batch, the `j`-th write to a key goes to the batch's
  `j`-th block. This follows §3.3.2 (a version's block is the current block plus its sequence in
  the data map). Every version is then in some block's snapshot, so the history is complete.
- **Keys.** A **stable capsule intake number** (big-endian, so key order is intake order), then a
  kind byte: `0` for the capsule object, `1` for its custody record. The order has a key of its
  own. GlassDB has no per-epoch pseudonym, so a capsule's records are versions of one key.
  - ⚠️ **This favours GlassDB.** The stream's open capsules are the most recent intakes, so most
    writes land in the last few leaves and touch few index nodes. Hashed or random keys would
    spread writes over the whole tree.
- **One shard.** The paper partitions keys over nodes, and each shard keeps its own ledger. One
  case on one shard is the case's whole ledger, and an auditor checks each shard's blocks the same
  way.

### What the court and the auditor do

- **Court.** The capsule's current value and the record key's **full history**:
  - the current-value proof at the last block: the upper path, `BLK`, and the lower path;
  - each earlier version reached through its `H_prev` pointer, which is GlassDB's own history
    chain (Fig. 3).

  Nodes are **de-duplicated**, and each is hashed once. The work order said "one inclusion proof
  per version". The pointer chain proves the same history in fewer nodes, so it is the
  **cheaper, more faithful** form; this deviation favours the baseline.
  - A redacted capsule's disclosure adds the order's current value under the same node set, plus
    target membership.
- **Auditor.** `VerifyBlock` over every block (§3.2.1): the block's proof against the digest, then
  every key its transactions wrote checked included, with its value, in that block's lower tree.
  - One auditor does not re-hash a node it has already verified: nodes are immutable and named by
    hash, and ours keeps its Tier-2 memo the same way.
  - In parallel, blocks are sharded across cores, each shard with its own memo.
  - Re-executing transactions (the extended version's §3.3.4) is the stronger check. It is not
    what `VerifyBlock` specifies, and it would only add cost.
- **Disclosed bytes** = 8 (block number) + each node with a 4-byte length.
  - A leaf node carries its **neighbours'** entries: other capsules' sealed records and intake
    numbers. That is the structure's cost and its exposure, and the record says so.

## SAC Exp. 3 — the tamper arms re-attributed to PQ-ABL and LRFM, no re-run (§1cd.3)

SAC's Exp. 3 names its two existing arms after 2023+ systems. The code (`tamper.rs`) is unchanged.
- **Full re-hash → PQ-ABL's epoch validation** (TCC 2026). The arm recomputes the digest of every
  stored ciphertext object, at the read budget it shares with our sweep, and judges each object by
  its root. That is PQ-ABL's leaf recomputation, `h*_n = H(CT_n)`.
  - It **leaves out PQ-ABL's tree rebuild** over those leaves, and it re-validates retained
    objects on a cycle, where PQ-ABL validates an epoch once at its close.
  - Leaving out the rebuild only makes the baseline faster: a few hundred node hashes against
    hundreds of MB of objects.
  - The cycle is the extension the paper states as ours.
- **Verify-on-access → LRFM** (Chew et al., TIFS 2024). Each recipient checks `V₁` over
  `h(E‖E_I‖R₁)`, the whole evidence (eq. (11), p. 5). The arm hashes the whole object before
  trusting a byte of it, which is the same work.

---

## B-DEMS — Park & Jeong, IP&M 63 (2026) art. 104654 — ported to our Besu (SAC Exp. 1 and Exp. 4, §1cf, §1ci)

SAC's comparator in Exp. 4 and second arm in Exp. 1 (SAC `b35`). `contracts/src/BDems.sol` (21
Foundry tests in `contracts/test/BDems.t.sol`), driven by `crates/pqcl-exp/src/bin/redaction.rs`
(Exp. 4) and `exp6chain.rs` (Exp. 1). Read from `ref-papers/1-s2.0-S0306457326000464-main.pdf`:
§3.1–§3.2 and Algorithm 1 (`TxA`, `TxB`, `TxA.Completed`, pp. 5–7), Fig. 2, §3.3 and Algorithm 2
(`TxC`, `TxD`, pp. 7–9), Fig. 3, §3.4.1 and Algorithm 3 (p. 10), Fig. 4 (`TxE`, `TxF`, p. 11),
§3.4.2 (admissibility), §4.2–§4.3 (setup, security evaluation). There is no public code.

### The whole workflow, since §1ci (2026-10-15)

Exp. 4 needed destruction only; Exp. 1 measures every custody step, so the contract now carries
each transaction with the signature checks the paper gives it.
- **`TxA` = `(H, M, P, A)`** (Alg. 1 Step 1): `H = SHA-256(E)` is the identifier, `M` is stored as
  its hash, `P` is the Provider's address, `A` is `msg.sender`. ECDSA signatures by the
  participants, with the threshold reached off chain by Shamir's scheme (§3.2.1): the Sender and
  the Provider for a voluntary submission, the Sender and the Court for a compulsory seizure. The
  contract checks exactly that threshold (2) by `ecrecover`, over a domain-tagged digest.
- **`TxB`** (Alg. 1 Step 2): the access policy, under the Court's signature, checked by
  `ecrecover` against the enrolled Courts.
- **`TxA.Completed`** (§3.2.3): the registering Sender records `H(E′)`. The contract does not
  require `TxB` first; the paper gives no such rule, and Exp. 4's setup omits `TxB`.
- **`TxC` = `(EvidenceID, Purpose, ReceiverAddr, pending)`** (Alg. 2 Step 1), by a whitelisted
  Receiver. `TxD` carries `keccak256(TxC)`, the Sender's signature and, for a voluntary
  submission, the Provider's (Alg. 2 Step 3); the contract checks the reference, that `TxC` is
  pending, that the item has the Court's `TxB`, and the signatures (§3.3.2), then emits
  `KeyDecryptionApproved`.
- **Ours to fix, stated:** the digests' framing (`abi.encode` of a tag and the fields), and
  `TxD` submitted by the registering Sender. The paper's Fabric chaincode is not public.
- **Exp. 4's setup now issues the full `TxA` and `TxA.Completed`** from 16 registrars, with one
  Provider signing (voluntary). `TxB` is left out of that setup only: destruction never reads it,
  and from one Court account it would take a 10⁵-item registration about an hour. Nothing Exp. 4
  times changes.

### Exp. 1: the custody stream as B-DEMS transactions (§1ci.1)

The same stream, network and client as LEChain (`exp6chain`, `bdems_runs`), each event mapped to
the transactions B-DEMS's workflow issues for that step:

| event | B-DEMS transactions | direction against one transaction per event |
|---|---|---|
| `COLLECT` | `TxA` (2 signatures) and `TxB` (Court) | against B-DEMS: two transactions |
| `SEAL` | `TxA.Completed` with `H(E′)` | neutral |
| `TRANSFER` release | `TxC` by the receiving agency | neutral |
| `TRANSFER` receipt | `TxD` by the registering Sender | neutral |
| `ACCESS`, `ANALYZE`, `EXPORT` | `TxC` + `TxD` the first time an agency needs the item; **none** after, since its decryption key was already released (§3.3.2) | first access against B-DEMS (two), later ones **for** it (zero) |
| `DISPOSE` | `TxE`, then the confirmation once `TxE` is included | against B-DEMS: two transactions |

- ⚠️ **Rule 20, stated before measuring.** B-DEMS records no transaction for an agency's repeat
  access, where LEChain commits one per event. Those events cost it nothing, which favours it.
  The record counts them (`events_without_transaction`), and gas per record divides the total gas
  by **every** event of the stream, so they enter the average at zero.
- **Roles.** 32 agencies, one per stream actor, all on the whitelist (Senders and Receivers); one
  Court; 100 Providers, who sign but never send. The registering Sender is the agency of the
  `COLLECT`'s actor. Collection method: voluntary for an even capsule index, compulsory for an
  odd one (the paper gives no mix).
- **Ordering.** A step from one account that builds on another account's step (`TxB` on `TxA`,
  `TxC` on `TxA`, `TxD` on `TxC` and `TxB`, the confirmation on `TxE`) is submitted once that step
  is included (`chain::submit_when_ready`). Nonces order one account's transactions, and nothing
  orders two accounts'. Otherwise a block may carry the second first, and it reverts. This wait is
  B-DEMS's workflow: a Court reviews a `TxA` that exists. Everything else is pipelined through the
  same 64-transaction window per account as LEChain.
  - ⭐ **Each transaction is signed when it is ready, taking its account's next nonce then.** The
    first local smoke signed every call up front in stream order. A waiting `TxD` then blocked
    every later, independent call of the same agency, and B-DEMS measured 30 records/s against
    LEChain's 287 on the same anvil node. That was our harness, not B-DEMS; a real client signs
    what is ready. **Direction:** this favours B-DEMS. Signing the envelope (not the participants'
    signatures, made earlier) is inside the measured span; LEChain's envelopes were signed before
    it, which favours LEChain by about 0.1 ms per transaction.
- **One Court account** carries every `TxB`, as LEChain's one police department carries every
  `orStore`. Under the shared per-account window that bounds both baselines the same way.
- **Warm-up, not measured:** one voluntary and one compulsory item through every step, each
  included before the next is estimated, so every call shape has its gas limit before the stream
  is prepared.

- **Platform: Hyperledger Fabric 2.5.8 → Solidity on our four-validator Besu QBFT network**, the
  substitution LEChain runs under (above). The paper reports Fabric's TPS and latency; we measure
  gas and latency on our chain, beside our anchor, through the same client (`pqcl_exp::chain`,
  moved out of `exp6chain` unchanged). **Direction:** Fabric needs no per-sender nonce. On Besu
  B-DEMS's Sender submits from one account, so its `k` `TxE`s enter blocks in nonce order. We
  submit all `k` at once rather than through `exp6chain`'s 64-transaction window, which helps
  B-DEMS. For the same reason Exp. 4's network raises Besu's per-sender pool window
  (`--tx-pool-max-future-by-sender`) from its default 200 to 4,096 (`besu/redaction.sh`). At the
  default, T1's `k = 1,000` batch was refused ("nonce is too distant", c09b's second attempt).
  That refusal comes from nonces, which Fabric does not have.
- **What Exp. 4 times: the destruction path.** That is `TxE` (`requestDestruction`), the
  off-chain destruction, the confirmation hash and status "destroyed" (`confirmDestruction`), and
  the court's query (`destructionOf`).
  - Never built, in either experiment: `TxF`, the pause switch and the per-jurisdiction whitelist.
  - Registration runs in setup from 16 whitelisted accounts, so a 10⁶-record case registers in
    minutes. Destruction uses one Sender.
- **Authority is the Sender's role, as the paper has it.** The Sender is on the AccessControl
  whitelist (§3.3.1, §4.3); there is no court-signed destruction order. `requestDestruction`
  refuses a non-Sender, an unregistered `EID` and a second `TxE` for one item.
  `confirmDestruction` accepts only the `TxE`'s own Sender.
- **`TxE = (EvidenceID, SenderAddr, Reason, Timestamp)`** (Fig. 4), one per evidence item, as
  Algorithm 3 runs per `EID`.
  - The paper does not batch.
  - `SenderAddr` is `msg.sender`.
  - `Reason` is the string `"court-ordered destruction"` (25 B, one storage slot). A longer reason
    would cost B-DEMS more gas, so this choice favours it.
  - `EID = SHA-256(E)` (Alg. 1, §3.2.1).
- **⚠️ Ambiguity: the destruction confirmation hash.** The paper says only that it is "generated
  from the deletion process and recorded in the blockchain" (§3.4.1, Alg. 3 lines 8–9), and that
  the court checks it "matches the recorded value". We fix it as
  `SHA-256(keccak256(TxE) ‖ H(E′))`, written by the `TxE`'s Sender in a second transaction once the
  copy is destroyed. That transaction also sets status "destroyed" (Alg. 3 lines 18–19).
  - **Direction:** one extra transaction per item over a reading that folds the hash into `TxE`.
    That reading is impossible, since the hash comes *after* the deletion that `TxE` precedes.
  - Flagged in the design record before measuring.
- **Secure deletion as §3.4.1 names it ("cryptographic deletion, overwriting with encrypted random
  data").** One pass of random bytes, `fsync`, unlink. Ours unlinks `C_ev` (and its key material
  by mode). On 4 KiB artefacts both cost microseconds against two block intervals.
- **The court's check (Alg. 3 Step 3, §3.4.2).** The court reads `destructionOf(EID)` from the
  chain. It accepts when a `TxE` exists, the status is "destroyed", and
  `SHA-256(keccak256(TxE as presented) ‖ H(E′))` equals the recorded confirmation.
  - The presented `TxE` is what the party claiming lawful destruction hands the court, as an order
    is for ours. So both verifiers check a presented claim against the chain.
- **T2 rows, B-DEMS's mechanism, stated before measuring (rule 20).**
  - **Insider** (row 3) is **accepted by design.** B-DEMS carries no court signature, so a Sender
    destroying on its own `TxE` is the same transaction sequence as a court-ordered destruction.
    That is its trust model, not a flaw we found.
  - **Modified** (row 4) is a `TxE` presented with another `Reason`. The confirmation hash no
    longer matches, so it is refused.
  - **Replay** (row 5) is one item's `TxE` presented for another. The other has no `TxE`, so it is
    refused.
  - **NoRecord** (row 2) has no `TxE`, so it is refused.

## SDSSE-CQ and SDSSE-CQ-S (M14, `baselines/sdsse_cq`)

Zuo et al., PoPETs 2025(1), Algs. 1–3, and Aura (Sun et al., NDSS 2021, Alg. 1 and §V), both read
directly. Exps. 1, 2, 3 and 5's conjunctive arm. Validated against a plaintext oracle in
`tests/against_oracle.rs`, and on Enron before every timed cell of `exp1` and `exp2`.

- **The group: Ristretto255, as our ODXT port.** The authors use PBC's `G_T` for exponentiations only
  ("we do not use the functions related to pairing", their footnote 12).
- **Preprocessing kept.** They amortise group costs with PBC's preprocessing. `g^x` here uses the
  fixed-base table. `xtoken^y` has a different base each time, so it stays variable-base, in theirs too.
- **Inner scheme kept: FB-DSSE's one-way chain** (their §5.1), the one `baselines/zuo22` uses, keyed
  per `(w, i)` as Aura requires. Hash: SHAKE256, the system XOF.
- **PRFs: ODXT's AES-256 `F` and `F_p`** (`baseline_odxt::prf`). SDSSE-CQ evaluates against ODXT, so one
  PRF keeps that comparison about the schemes.
- **Ambiguity: deletion as printed cannot revoke** (Alg. 1). It would re-encrypt with a fresh counter, so
  its tag never equals the insertion's. Their §5.1 derives the tag from the real `(w, ind)`, which this
  follows. Their Table 3 (0.03 ms per deletion) cannot include lines 7–8's group work, so a deletion does
  lines 1–5 and sets Bloom bits, nothing more.
- **Ambiguity: Aura's line 11 cannot remove an entry cached by an earlier search.** It removes only tags
  among the new ciphertexts, and a cached entry deleted since never comes back among them. Aura's §V has
  the server check tags against `D`, which this does (tested: `add_delete_search_across_key_refreshes`).
- **Bloom filter: `h = 5`, `p = 10⁻⁴`** (SDSSE-CQ §5.1), `b` from Aura's formula; `bloom_size_reproduces_auras_table_ii`
  checks it against Aura's Table II. **Direction: favours the arm.** The authors use one `d` for all
  keywords; each keyword here has a filter sized for its own true deletion count, floor 10. A real client
  cannot know that in advance.
- **GGM leaves are derived on demand and memoised** rather than expanding the tree. **Favours the arm.**
- **Early exit favours the arm too:** a candidate's x-term loop stops at the first miss (Alg. 1 line 25
  has no break), so width 6 costs less than printed.
- **A dummy deletion before each search with an empty filter,** from Aura §IV, or `sk_R` would be the root.
- **Reported, per §1cu.2:**
  - first and repeat searches apart, since the second reads Aura's cache;
  - results a Bloom false positive lost (`oracle_shortfall_bloom_false_positives`);
  - updates per term with each query, since cost follows the x-terms' volume (their Fig. 3).
- **What is stored is `h` ciphertexts per entry,** as Aura §V says. Their Table 4's 172 B per addition does
  not reach `h` copies; we count what is stored.

## DSSE_SKQ (M14, `baselines/dsse_skq`)

Wang et al., IEEE TDSC 20(4), 2023, Algs. 1–2 and §4.2, read directly. Exps. 1 and 4's keyword-and-range arm.

- **One dimension.** The Hilbert curve of one dimension is the identity, so `PreCode` is the value's binary
  prefixes and `PreCover` the best prefix cover, the same reduction as Zuo et al.'s and our `Π_RANGE`.
- **Typo.** Alg. 2 lines 18, 21 and 22 touch `KDB` for prefix entries, which Alg. 1 line 18 stores in `SDB`.
  Read as `SDB`.
- **Several numeric attributes** (Exp. 1's stream has four): one prefix family each, under its own label, at
  the same depths as ours. So the entry counts match and `figspec`'s guard still applies.
- **The DPRF is our GGM (`pqcl-ggm`, depth 64) with the same incremental evaluator ours uses.** They implement
  a GGM PRF in Java (§7). Hash: SHAKE256, not their HMAC-SHA256.
- **`Enc` and `Add` are `baselines/zuo22`'s `BitString`,** arithmetic in `Z_{2^l}`, the same scheme `P`.
- **Server walk: steps twice, then expands** if the chain is still going. Cheaper in both the cold and warm
  case than either alone. **Favours the arm.**
- **A workload the paper never has:** one document with several values of one attribute, which Exp. 4's cells
  with `D > N` contain. The bitmap adds in `Z_{2^l}`, so `2^i` added twice carries into the next document:
  - within a label, a client keeping a set skips a label already holding the document (`update_point_once`);
  - across cover prefixes, line 23's `SumP` is replaced by one sum per prefix, ORed at the client (`multi_valued`).
  - Those cells carry `several_values_per_document: true`. **The same work,** less one addition; `|BPC|` bitmaps
    down instead of one. Every other cell runs the printed line.
  - ⚠️ `baselines/zuo22` has the same carry, and `exp7` never checked its answers. Its timings hold, since a
    carry costs nothing. Its `D > N` answers can be wrong (`a_document_with_two_values_reads_as_its_neighbour`). It leaves the paper with this campaign, so this is
    recorded rather than fixed.
- **§4.2's Boolean forms are the client's bitmap logic,** so every row of `tab:exp-range` is defined. They run
  on the same term multiset as ours and must return the same hits, or `exp7` refuses.
- **Batch updates (§4.2) are not used,** as Zuo's was not: one update per event, as Exp. 1's arms all are.

## The Doris follow-up (M14, `baselines/doris_fu`)

Nguyen et al., ProvSec (LNCS 2026), Algs. 1–4 and §§4–5, read directly. There is no released code. Exp. 3's
structural counts only: no wall-clock figure comes from it.

- **⛔ No use of the Doris carve-out (§1cs.5 item 6).** It is our reimplementation and runs through the pipeline.
- **The real filter is built,** twice under different keys and seeds, and the counts must agree.
- **Ambiguity: Alg. 3 lines 13–16** read as printed pair `w` with every other keyword's every id. The prose
  ("pairing each keyword with a counter in every document") and Doris's own loop say the outer loop's `id`.
- **Ambiguity: §4's `H`** is printed as `[t(s+1)b/m, (t+1)(s+1)b/m)`, which leaves the array for `s > 0`. At `m = 3` it
  is the XOR filter. At `m = 200` we use the Binary Fuse Filter it cites: a start segment, then `κ` consecutive ones.
- **`TSet` is counted by Doris's convention:** `L` (8), `β` (1) and `e` (32), 41 B per pair, since the
  follow-up builds on "the generic construction of Doris". Filter slots are 32 B, Doris's `len(ct) * 32`.
- **Checked against Doris's record for the same pairs:** `TSet` exact, and `XSet` within 0.1% below `10⁷` tags. They
  differ slightly because Doris's `prf(kx, w + w_tmp + str(i))` has no framing, so a few distinct triples collide
  (14 of 2.1M at Enron tier 3).
- **CMS's `α` and `β` are not given.** We use `α = 5`, `β = 2719` (`ε = 0.1%`, `δ < 1%`). This is client state, not in the
  index, so no count depends on it.

## M15 trial arms

Built for a local go/no-go first (`m15trial`, deleted at the c15 port). All four were accepted for
c15 by the user on 2026-11-09 and now run in `exp2`, `exp7` and `exp345` (see "The c15 port" below). Each is
checked against the plaintext oracle on its experiment's own workload before any timing is kept.

### VCFB (`baselines/vcfb`), Ge et al., IEEE TBD 11(3) 2025 (`b40`)

Alg. 1 (`Update`, `TokenGen`, `Search`) and eqs. (3)–(8), read directly. Exps. 2 and 5.

- **Search path only (§1da).** Not built: the bilinear accumulator (`Acc(VAL_w)`, `Acc(XSet)`, Update
  lines 15–25), the proofs of Search lines 28–33, and `Verify` (Algs. 2, 4). **Favours the arm**: their
  Search builds `proof1`/`proof2` before replying. Their Fig. 6(a) also times updates without
  verification, and our `Π_XT` is timed outside verified mode.
- **The group: Ristretto255 with a fixed-base table** for `g^x`, as our SDSSE-CQ port. They used GmSSL's
  elliptic curve (§VIII-A). `xtoken^{vα}` has a new base every time, so it stays variable-base.
- **PRFs: ODXT's AES-256 `F` and `F_p`** (`baseline_odxt::prf`), as for SDSSE-CQ. They used HMAC; `H` is
  SHAKE256 for their SHA-256. `λ = 256` as theirs.
- **Reading: `α′ = vα ⊕ F_p(K_e, w‖c‖2)` (Update line 5) is unmasked by `K_{w1,j} = F(K_e, w₁‖j‖2)`
  (TokenGen line 5).** One 32-byte PRF output serves as both, XORed with `vα`'s canonical encoding. Any
  other reading leaves the server unable to recover `vα`.
- **Reading: Search lines 4 and 7.** Line 4 replaces `st` by `st_{m−1}` before line 7 decodes bucket `m`,
  whose tags are under `st_m`. Bucket `m` is decoded with `st_m`, then the walk steps back.
- **Reading: the walk stops at the first bucket an earlier search decoded.** Line 5 removes `β` from each
  bucket, so the printed loop "for `m = SrchCt` to 1" cannot step past a decoded bucket on a later
  search. Every bucket below it was decoded by that earlier search, so the answer is the printed one.
  **Favours the arm** by `O(#searches)` hashes.
- **Reading: `UpTag`.** The algorithm sets it to 0 in TokenGen and opens a new bucket when an update
  finds it 0. §V-B's prose says once that TokenGen sets it to 1. The algorithm is followed.
- **Reading: Search line 37 indexes `R` by its own position.** The mask is keyed by the candidate's
  counter, so the server returns each entry with its `j`.
- **Early exit, as for SDSSE-CQ:** a candidate stops at its first failing x-term, and the `del` element
  is not computed when `add ∉ XSet`. Line 17's loop has no break. **Favours the arm.** Exp. 5's observer
  computes every lookup.
- **Their assumption** "update operations involving the same file identifier are never repeated" (§V-A)
  holds in every workload here: deletions are document-granular and no id is re-added.
- **First and repeat searches are reported apart**, as for SDSSE-CQ (§1cu.2). The first search after
  bulk ingest decodes every `xtag′` uploaded since the last search, `O(pairs)` XORs and inserts. A timed
  first search is rolled back (`Server::undo`, `Client::set_up_tag`) outside the timed region.

### Doris follow-up search (`baselines/doris_fu`, module `search`), Nguyen et al., ProvSec 2025 (`b39`)

Algs. 3–4 and §5 (XBPE), read directly; Doris's released `SSPE_XF.py` and `Doris_XF.py` consulted
where the follow-up builds on "the generic construction of Doris". Exps. 2 and 5. The counting
functions of the crate (Exp. 3) are unchanged; `Filter::hashes` was added, read-only.

- **⛔ Static.** Built once over the **live** documents of the tier (the post-deletion state the
  dynamic arms hold). It has no update or delete.
- **`XBPE.KeyGen`'s locations are over `y′ = F(sk, x)`.** §5 writes `S = {h_i(x)}` while `Enc` places
  `y′ = F(sk, y)` in the filter. Doris's code takes positions over `prf(msk.sk, x)`, which is the only
  reading under which `Dec` can succeed. The fingerprint `hf` is the identity at `k = λ = 256` bits,
  as in the counting crate.
- **`S` is XORed as a list.** If two x-terms shared a slot, set semantics would cancel it and break
  correctness. Doris's code iterates the list.
- **`SE` for `sk² = SE.Enc(K, 0^λ)`: AES-256-CTR under a random IV.** It is PCPA-secure, as §5
  requires. Doris's code uses a PRF check instead (`prf(K, 0)`); the cost is the same order, one or
  two AES blocks.
- **`SE.Enc(K_e, id)` is Doris's `AES_enc`**: AES-256-CBC, random IV, one block, so 32 bytes.
- **`TSet`: one SHAKE256 call per entry** gives a 16-byte label and the mask of `β‖e`, walked until
  `β = 0`. This keeps the per-entry retrieval cost of Cash et al.'s `TSet` without its bucket layout.
- **Counter alignment.** Alg. 3 counts `c` from 0, Alg. 4 from 1; both index the same `TSet` position.
- **The client streams `xtoken[c]` until the server says stop** (Alg. 4 line 13). In process that is
  exactly one token per candidate, with the RNG for each fresh `K` inside the timed region, as ODXT's.
- **PRF `F`: ODXT's AES-256**, as every other comparator port.

### MDRSSE (`baselines/mdrsse`), Kasra Kermanshahi et al., Inf. Sci. 652 (2024) 119773

Algs. 1–3 and §§2.1, 4, 5, read directly. Exp. 4's pure-range rows and the `N` axis only.

- **One dimension.** The KD-tree of one axis is a sorted split at the median until at most `γ` points
  remain; its leaves are consecutive value buckets. Data live only at leaves (§2.1), so the median
  point goes right. A value split across two leaves is covered by both.
- **`γ = 500`, the authors' default (§5.1), fixed before measuring.** A `γ` sweep would be a labelled
  extra, not run.
- **Padding on**, as in all their experiments (§5 footnote 5): each leaf holds `γ` ciphertexts, the
  extra ones encryptions of zeros. A dummy plaintext carries a flag byte 0, so it cannot read as the
  record (value 0, document 0).
- **Reading: the client filters each returned leaf to the range.** Alg. 3 adds every record of a
  returned leaf to `RS`; a range answer needs the filter and the oracle checks it. The server's work is
  unchanged.
- **`Π` is AES-256-GCM**, nonce the record's index in its leaf (each `K_i` encrypts at most `γ` records,
  once). They used Java's AES. `F` is ODXT's AES-256 PRF.
- **"Find nodes covering `[a,b]`"** is read as the leaves whose value interval meets the range, which is
  the minimum leaf set. The client keeps each leaf's interval in `kdt′`.
- **⛔ Static** (§4.3 only sketches updates), so it cannot enter Exp. 1. It returns whole buckets (up to
  `2γ` records outside the range, before the client's filter) and their identity.

### The c15 port

The arms moved from the deleted `m15trial` into the harnesses the paper reads: VCFB and the Doris
follow-up into `exp2` and `exp345` (Exp. 5), MDRSSE and SDSSE's three-keyword row into `exp7`. Each
arm is built **once per tier** (once per depth or `N` in `exp7`) and checked against the plaintext
oracle before it is timed or counted. What changed on the way:

- **ODXT is no longer re-run in `exp2`** (`PQCL_EXP2_ODXT=1` brings it back). Its macros were retired
  (§1cy.3). Its agreement check used to stand in for an oracle check of ours, so ours is now checked
  against the plaintext oracle directly, every query, before it is timed.
- **The Doris follow-up's Exp. 2 stop size is 5·10⁴ documents** (`exp2.rs`, `DORIS_FU_MAX_DOCS`),
  decided before c15 from the smoke's ≈ 10 kB stored per pair and the 256 GiB c15r host. Before each
  tier the harness counts the tags exactly (`Σ k(k−1)`) and models the build's peak at 85 B per tag
  (the smoke measured ≈ 80); a tier above the stop size, over 85 % of `MemTotal`, or over the filter's
  32-bit index is **skipped with its reason in the record**, never run into the OOM killer.
- **Exp. 2 runs in two passes** (§1db.8 fix A): the Doris follow-up alone, after the other arms'
  record exists, one record per tier (`m15-doris-fu-search`), so its memory can never cost the other
  arms' work; `mkfigs` merges it and refuses another commit, instance type or query set, and any
  oracle mismatch. Each tier records its measured peak RSS.
- **The filter refuses a shape past its 32-bit indices** before allocating (§1db.8 fix B); it never maps
  a slot to 0.
- **The Doris follow-up's tags are computed on every core** (`search::xset_parallel`). The build is not
  timed, and the output is the sequential vector, tested.
- **MDRSSE runs on Exp. 4's full axes** (depths 8–14; `N` to 65 536 on c15a), §1db.6 (c).
- **SDSSE's three-keyword row emits `hits` beside `want`** (§1db.6 (a)); only `hits > want` refuses.
- **VCFB's first and repeat searches are separate values** (`first_search_ns`, `repeat_search_ns`),
  §1db.6 (b).

### SDSSE-CQ and -S on Exp. 4's `w₁ ∧ w₂ ∧ w₃` row

No new scheme code. The arms of `baselines/sdsse_cq` run on `exp7`'s Boolean fixture (`N = 4 096`:
`w1` on every document, `w2` on the even ones, `w3` on multiples of three), over the same three terms
as ours. No deletions there, so each keyword's Bloom filter takes Aura's floor `d = 10`.

## Documented, not implemented

Trinity and BiMM are not reimplemented. BiMM has no public code. Trinity's repository holds micro-benchmarks only, and its algorithms as printed cannot return identifiers. They appear in the functionality
comparison on paper-reported properties only, never in a measured table.
