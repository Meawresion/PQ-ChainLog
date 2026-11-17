# Porting ETHDILITHIUM from ML-DSA-44 to ML-DSA-65

**Condition 3 of the design record.** Upstream stays pinned and
unmodified; this file is the record of what was changed, why, and what evidence
says it is right.

| | |
|---|---|
| Upstream | `ZKNoxHQ/ETHDILITHIUM` |
| Pinned commit | `c8b6a60d563fbdc76dbe468f960b0ca882a585f8` (2026-09-09) |
| Location | `lib/ETHDILITHIUM` — a submodule, **never edited** |
| Derived work | `src/mldsa65/` — four files, banner on each |
| Regenerate | `python3 tools/port65.py` (mechanical; every edit is an explicit anchor pair) |

## Why the port exists

The upstream verifier is **ML-DSA-44** (level II). PQ-ChainLog signs at
**ML-DSA-65** (level III). Measuring the level-II verifier would not answer the
question Exp. 6 exists to ask: §9.1's optimization trigger is a *threshold* test
and verifier gas is dominated by terms scaling with `k·l`, so a level-II number
can land on the wrong side of the threshold and **invert the decision** rather
than merely mislabel it.

## What changed

**62 edits across four files.** Grouped by why they were needed.

### 1. Parameter constants (`MLDSA65_utils.sol`)

FIPS 204 Table 1. `q = 8380417`, `n = 256` and `d = 13` are identical at every
level and were not touched.

| | Level II | Level III |
|---|---|---|
| `k`, `l` | 4, 4 | **6, 5** |
| `TAU` | 39 | **49** |
| `OMEGA` | 80 | **55** |
| `GAMMA_1` | 2¹⁷ | **2¹⁹** |
| `GAMMA_1_MINUS_BETA` | 130994 | **524092** (`γ₁ − τη`, η = 4) |
| `ROW_COUNT`, `COL_COUNT` | 4, 4 | **6, 5** |

### 2. Signature layout (`MLDSA65.sol`)

`c_tilde ‖ z ‖ h`, sizes derived from λ = 192, `l = 5`, `ω = 55`, `k = 6`:

| | Level II | Level III |
|---|---|---|
| `c_tilde` | 32 | **48** (λ/4) |
| `z` | 2304 | **3200** (`l·256·20/8`) |
| `h` | 84 | **61** (`ω + k`) |
| total | 2420 | **3309** |

### 3. ⚠️ The changes a name-grep does not find

These are the ones that matter, and none of them mention `k`, `l`, `TAU`,
`OMEGA` or `GAMMA_1`. All four would have produced a verifier that **compiles,
deploys, and computes the wrong thing**.

| Where | What | Why it hides |
|---|---|---|
| `MLDSA65_hint.sol` | `GAMMA_2`: `(q−1)/88` → **`(q−1)/32`** | Spelled `GAMMA_2`, in a file naming none of the usual parameters |
| `MLDSA65_hint.sol` | `2·GAMMA_2` and `GAMMA_2` **inlined as literals inside `assembly`** | Yul cannot read a Solidity constant, so fixing the named constant alone leaves `decompose()` at level II |
| `MLDSA65_hint.sol` | `w1` packing: **6 bits → 4 bits** per coefficient, rotation `mod 44` → `mod 16`, row stride 192 → 128 B | An *algorithmic* change, not a constant. `w1 ∈ [0,43]` at level II and `[0,15]` at level III. Total output stays 768 B, which makes the change invisible to a size check |
| `MLDSA65_core.sol`, `MLDSA65.sol` | loop bounds hardcoded `4`, which are `k` in three places and `l` in two | `A·z` is `k`-dimensional while `z` is `l`-dimensional; using one for the other reads plausibly |

Plus one that is a **security** change rather than a correctness one:

> `MLDSA65.sol` squeezed 32 bytes of the challenge hash and compared with a
> `bytes32` cast. At level III `c_tilde` is 48 bytes, so that checked two thirds
> of it — and it would still have **passed every valid signature**, which is
> what makes it dangerous rather than obvious. Now squeezes 48 and compares
> under `keccak256`.

### 4. What needed nothing

- **The NTT.** Same ring at every level (`n = 256`, `q = 8380417`), so
  `ZKNOX_NTT_dilithium.sol` is used unmodified.
- **`SampleInBall`.** Takes `tau` and `c_tilde` as arguments, so it is already
  parameter-generic. This was expected to be the hard part and was not.
- **`ETA`.** A keygen/signing parameter; verification never sees `s1`/`s2`.
- **SHAKE**, `SSTORE2`, `IVerifier`.

## Evidence

| Check | Result |
|---|---|
| ⭐ **ACVP ML-DSA-65, ported verifier** (`test_PortedVerifierMatchesAcvp65`) | **15/15** — 3 expect-valid, 12 expect-invalid |
| ⭐ **ACVP ML-DSA-44, _unported_ upstream** (`test_UnportedNistVerifierMatchesAcvp`) | **15/15** — the bisection control, condition 2 |
| A level-II signature is rejected by the level-III verifier | pass |
| Config C cannot verify FIPS-204 at all | pass — rejected all 3 valid vectors |

The control matters as much as the gate. Upstream's own KAT is a single vector
from their generator with **no negative cases**; the control is NIST's, with
twelve. Because it passes on the *unmodified* submodule, any future ACVP-65
failure is attributable to the port rather than to upstream.

⚠️ **No gas number may be reported from this verifier unless the ACVP-65 gate is
green.** That is condition 1 and it is binding, not advisory.

## Re-deriving after an upstream bump

`tools/port65.py` fails loudly on any anchor it cannot find, so a bump that
touches ported lines stops the regeneration instead of silently dropping an
edit. Re-run it, re-run both suites, and update the evidence table above.
