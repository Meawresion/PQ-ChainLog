//! A Bloom-filter `XSet`, and the space it buys.
//!
//! [`HonestXSet`](crate::xt::HonestXSet) stores every cross-tag exactly: 32
//! bytes each, and membership is certain. That is the correctness oracle and it
//! is not going anywhere. This is the deployable alternative — a bit array with
//! `k` positions per tag, trading a bounded false-positive rate for roughly an
//! order of magnitude less server storage.
//!
//! # ⛔ What a false positive costs — corrected 2026-09-16
//!
//! This module used to claim that *"a false positive never produces a wrong
//! answer … the cost is retrieval overhead, not incorrectness."* **That is
//! false, and `tests/bloom_vs_oracle.rs` is how it was caught.**
//!
//! The reasoning behind the old claim only covered half the probe list. Round
//! two decides membership with `add && !del` ([`crate::xt::XtClient::evaluate`]),
//! because deletions are in-band in the cross-tag set — the probe list carries
//! an `Add` tag *and* a `Del` tag per (candidate, x-term, epoch), which is
//! exactly the factor 2 in `2·|Cand|·(n−1)·E`. So:
//!
//! | false positive on | effect | detectable by the client? |
//! |---|---|---|
//! | `Add` tag | admits a document that does not match | ✅ it fails to decrypt |
//! | `Del` tag | **drops a document that does match** | ❌ nothing is fetched |
//!
//! The `Del` direction is silent loss. `Π_core`'s AEAD catches a document that
//! should not be in the answer; nothing catches one that should be and is not.
//!
//! Measured on the `bloom_vs_oracle` fixture (40 true matches):
//!
//! ```text
//! ε        dropped   spurious
//! 10⁻¹      16/40      12
//! 10⁻²       2/40       2
//! 10⁻³       0/40       0
//! 10⁻⁴       0/40       0
//! ```
//!
//! ⚠️ **Result cardinality hides this almost completely.** At `ε = 10⁻¹` the
//! answer went from 40 documents to 36 — a 10% shortfall that looks like mild
//! degradation — while 40% of the true answer had in fact been replaced by
//! wrong documents. Any evaluation that reports `|result|` rather than a
//! set difference against an oracle will miss it.
//!
//! ⚠️ It is not free for leakage either. A filter that answers "yes" more often
//! makes the returned bit vector less informative about which documents truly
//! matched, so `ε` interacts with the aggregate leakage Experiment 3 measures.
//!
//! # ⛔ `ε` is a derived bound, not a constant — ruled §1.8, 2026-09-16
//!
//! The first version of this note concluded that `10⁻³` "sits inside the safe
//! region, which is fortunate rather than designed". **That was wrong, and
//! wrong in the dangerous direction.** The fixture it was read off has `E = 2`
//! and `n−1 = 2`; `tab:params` specifies **`E ≤ 24`**, and the two regimes do
//! not compare.
//!
//! A document survives round two only if **every** `Del` probe covering it comes
//! back correctly negative — one per x-term per closed epoch. So the loss is not
//! `ε`, it is compounded `(n−1)E` times:
//!
//! ```text
//! retained = (1 − ε)^((n−1)E)
//! loss     = 1 − (1 − ε)^((n−1)E)
//! ε ≤ 1 − (1 − δ)^(1/((n−1)E))   ≈  δ / ((n−1)E)     for a target loss δ
//! ```
//!
//! [`predicted_loss`] and [`max_epsilon`] are those two, and the same formula
//! extrapolated to the paper's own operating point says plainly what `10⁻³`
//! costs there:
//!
//! ```text
//!                       ε = 10⁻³   10⁻⁴    10⁻⁵
//! n−1 = 2, E = 24         4.69 %   0.48 %  0.05 %
//! n−1 = 4, E = 24         9.16 %   0.96 %  0.10 %
//! ```
//!
//! ⛔ **So `10⁻³` must not be written down as a default** — not here, not in
//! `tab:params`, not as a `const`. At `n−1 = 4`, `E = 24`, `δ = 10⁻³` the bound
//! gives `ε ≤ 1.04 × 10⁻⁵`. Experiment 5 exists to **validate the exponent**,
//! not to pick a number: the formula is corpus-independent, which makes it a
//! design rule rather than a recommendation for Enron.
//!
//! ⭐ **A second reason compaction exists.** The bound tightens linearly in `E`,
//! so resetting `E` is not only a storage optimisation — it is what keeps `ε`
//! attainable at all.
//!
//! 📌 **This is a cost of being dynamic, and it is ours to state.** A Bloom
//! filter has one-sided error per tag; the client's `add ∧ ¬del` rule **negates
//! one of the two tests**, which makes the error two-sided at the answer level.
//! The static symmetric-only schemes that filter an `XSet` — HXT's Bloom,
//! Doris's XOR filter — carry no deletion tags and do not pay this.
//!
//! # Parameters
//!
//! The design record: sweep `ε ∈ {10⁻¹…10⁻⁴}` **jointly with `E`**.
//! ⛔ No default; see the bound above. At `ε = 10⁻³` the sizing gives `k = 10`
//! and ≈14.4 bits per tag against 256 exact — about **17.8×** — which is the
//! space figure, and it is only half of what choosing `ε` has to weigh. The
//! standard sizing is used:
//!
//! ```text
//! m = -n ln ε / (ln 2)²        bits
//! k = -log₂ ε                  hash positions
//! ```
//!
//! ⛔ **Validate against [`HonestXSet`], never instead of it.** A Bloom filter
//! that returned `true` unconditionally would pass every positive test and be
//! useless; only the *negative* direction carries information, and only the
//! oracle can say which negatives were correct.

use std::collections::{BTreeMap, BTreeSet};

use pqcl_primitives::xof;

use crate::xt::{Epoch, Transcript, XSetStore, XTag};

/// One epoch's filter.
#[derive(Debug, Clone)]
struct Filter {
    bits: Vec<u64>,
    /// Bit count `m`. Kept explicit: `bits.len() * 64` rounds up and would make
    /// the reported storage larger than the sizing formula asked for.
    m: usize,
    k: u32,
    /// Tags inserted. Not derivable from the filter, and needed to report the
    /// bits-per-tag ratio the experiment exists to measure.
    inserted: usize,
    /// Tags the filter was sized for.
    sized_for: usize,
}

impl Filter {
    fn new(expected: usize, epsilon: f64) -> Self {
        let (m, k) = sizing(expected, epsilon);
        Self {
            bits: vec![0u64; m.div_ceil(64)],
            m,
            k,
            inserted: 0,
            sized_for: expected,
        }
    }

    /// The `k` bit positions for a tag.
    ///
    /// Derived by hashing the tag with a counter rather than by the Kirsch–
    /// Mitzenmacher double-hashing trick. Double hashing is sound and cheaper,
    /// but it makes the positions a *linear* function of two hashes, and this
    /// filter holds cross-tags whose unlinkability is the point — so the
    /// conservative construction is the right default, and `k` is small.
    fn positions(&self, tag: &XTag) -> impl Iterator<Item = usize> + '_ {
        let tag = *tag;
        let m = self.m as u64;
        (0..self.k).map(move |i| {
            // SHAKE256 over `tag ‖ i`: one squeeze per position, 8 bytes each.
            let mut input = tag.as_ref().to_vec();
            input.extend_from_slice(&i.to_le_bytes());
            let h = xof::shake256(&input, 8);
            let v = u64::from_le_bytes(h[..8].try_into().unwrap_or([0u8; 8]));
            #[expect(
                clippy::cast_possible_truncation,
                reason = "reduced modulo m, which is a usize"
            )]
            let p = (v % m) as usize;
            p
        })
    }

    fn insert(&mut self, tag: &XTag) {
        let positions: Vec<usize> = self.positions(tag).collect();
        for p in positions {
            self.bits[p / 64] |= 1u64 << (p % 64);
        }
        self.inserted += 1;
    }

    fn contains(&self, tag: &XTag) -> bool {
        self.positions(tag)
            .all(|p| self.bits[p / 64] & (1u64 << (p % 64)) != 0)
    }
}

/// Standard Bloom sizing: `m = -n ln ε / (ln 2)²`, `k = -log₂ ε`.
///
/// # Panics
///
/// If `epsilon` is not in `(0, 1)`. A filter sized from a nonsensical rate
/// would silently be the wrong size, and every storage figure taken from it
/// would be wrong in a way nothing downstream could detect.
#[must_use]
pub fn sizing(expected: usize, epsilon: f64) -> (usize, u32) {
    assert!(
        epsilon > 0.0 && epsilon < 1.0,
        "false-positive rate {epsilon} is not in (0, 1)"
    );
    #[expect(
        clippy::cast_precision_loss,
        reason = "a tag count large enough to lose f64 precision is 2^53 cross-tags, \
                  which is far beyond any corpus this system indexes; the sizing \
                  formula is inherently floating-point"
    )]
    let n = expected.max(1) as f64;
    let ln2 = core::f64::consts::LN_2;
    let m = (-n * epsilon.ln() / (ln2 * ln2)).ceil();
    let k = (-epsilon.log2()).round().max(1.0);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "m and k are positive and bounded by the expected tag count, \
                  which is a usize the caller already holds"
    )]
    let out = (m as usize, k as u32);
    out
}

/// How many `Del` probes must all come back correctly negative for one document
/// to survive round two: one per x-term per closed epoch.
///
/// Kept as a named function because it is the exponent in both formulas below,
/// and because Experiment 5 **fits** it from measurements rather than assuming
/// it — four points at a single `E` cannot tell `(n−1)E` from a neighbouring
/// form, and if the fit disagrees, the model is wrong and that matters before it
/// becomes a design rule.
#[must_use]
pub fn del_probes_per_document(x_terms: usize, epochs: u64) -> u32 {
    let e = u32::try_from(epochs).unwrap_or(u32::MAX);
    u32::try_from(x_terms).unwrap_or(u32::MAX).saturating_mul(e)
}

/// Fraction of true matches a Bloom `XSet` silently drops.
///
/// `1 − (1−ε)^((n−1)E)`. ⚠️ This is **answer loss**, not the filter's
/// false-positive rate: a single unlucky `Del` probe removes a document, so the
/// per-tag rate `ε` compounds over every x-term and every closed epoch.
///
/// # Panics
///
/// If `epsilon` is not in `[0, 1)`.
#[must_use]
pub fn predicted_loss(epsilon: f64, x_terms: usize, epochs: u64) -> f64 {
    assert!(
        (0.0..1.0).contains(&epsilon),
        "false-positive rate {epsilon} is not in [0, 1)"
    );
    1.0 - (1.0 - epsilon)
        .powi(i32::try_from(del_probes_per_document(x_terms, epochs)).unwrap_or(i32::MAX))
}

/// The largest `ε` that keeps answer loss at or below `target_loss`.
///
/// `ε ≤ 1 − (1−δ)^(1/((n−1)E))`, which is about `δ/((n−1)E)` for small `δ`.
///
/// ⭐ **Corpus-independent**, which is what makes it a design rule. Experiment 5
/// validates it; it does not produce it. At `n−1 = 4`, `E = 24`, `δ = 10⁻³` this
/// is `1.04 × 10⁻⁵` — three orders tighter than the `10⁻³` that was nearly
/// locked in as a default.
///
/// # Panics
///
/// If `target_loss` is not in `(0, 1)`, or if no `Del` probe is made at all —
/// with nothing to go wrong there is no bound to return, and silently answering
/// "any `ε`" would be a licence rather than an answer.
#[must_use]
pub fn max_epsilon(target_loss: f64, x_terms: usize, epochs: u64) -> f64 {
    assert!(
        target_loss > 0.0 && target_loss < 1.0,
        "target loss {target_loss} is not in (0, 1)"
    );
    let probes = del_probes_per_document(x_terms, epochs);
    assert!(
        probes > 0,
        "no Del probes are made with {x_terms} x-terms over {epochs} epochs, so \
         there is no loss to bound"
    );
    1.0 - (1.0 - target_loss).powf(1.0 / f64::from(probes))
}

/// Exact storage of one cross-tag, in bits, for an unsealed epoch.
const EXACT_TAG_BITS: usize = 256;

/// A Bloom-filter `XSet`: one filter per **sealed** epoch, sized from that
/// epoch's actual load.
///
/// ⛔ **M10 P3.** The first version sized every epoch's filter from one
/// `expected_per_epoch` fixed at construction — in practice the *average*
/// load. Epoch loads are not equal (the last epoch of a build also carries the
/// deletions), and an overfilled Bloom filter's false-positive rate rises
/// steeply: campaign 02 observed **33×** the configured ε at `ε = 10⁻⁴`,
/// `E = 16`, while its loss model — fed the *observed* rate — tracked the
/// observed loss exactly. The model was right and the filter was wrong.
///
/// A filter cannot be resized after the fact, but it does not have to be sized
/// in advance either: the **open epoch is never probed** (forward privacy), so
/// its tags are held exactly until [`seal_epoch`](XSetStore::seal_epoch) and
/// then compressed into a filter sized for exactly that many tags.
/// `XtClient::close_epoch` seals the closing epoch.
#[derive(Debug)]
pub struct BloomXSet {
    sealed: BTreeMap<Epoch, Filter>,
    /// Exact tags of epochs not yet sealed — in deployment, only the open one.
    pending: BTreeMap<Epoch, BTreeSet<XTag>>,
    epsilon: f64,
    /// Tags that arrived for an already-sealed epoch. Inserted, so nothing is
    /// lost, but they overfill that filter; non-zero means a caller sealed too
    /// early, and [`observed_load`](Self::observed_load) shows by how much.
    late: usize,
}

impl BloomXSet {
    /// A store at false-positive rate `epsilon`, sizing each epoch's filter
    /// from its own load when the epoch is sealed.
    ///
    /// # Panics
    ///
    /// If `epsilon` is not in `(0, 1)`, via [`sizing`].
    #[must_use]
    pub fn new(epsilon: f64) -> Self {
        let _ = sizing(1, epsilon); // validate eagerly
        Self {
            sealed: BTreeMap::new(),
            pending: BTreeMap::new(),
            epsilon,
            late: 0,
        }
    }

    /// Compress every pending epoch into its filter. For callers that load a
    /// finished history at once (Experiment 5 rebuilds the honest store's
    /// epochs into this one) rather than closing epochs as they go.
    pub fn seal_all(&mut self) {
        let epochs: Vec<Epoch> = self.pending.keys().copied().collect();
        for e in epochs {
            self.seal_epoch(e);
        }
    }

    /// Total bits allocated — the server-storage figure. Sealed epochs count
    /// their filter; an unsealed epoch counts its exact tags at 256 bits each.
    #[must_use]
    pub fn total_bits(&self) -> usize {
        self.sealed.values().map(|f| f.m).sum::<usize>()
            + self.pending.values().map(BTreeSet::len).sum::<usize>() * EXACT_TAG_BITS
    }

    /// Bits per inserted tag, scaled by 1000 to stay in integer arithmetic.
    ///
    /// Against 256 bits for an exact 32-byte tag, this is the space saving the
    /// design claims.
    #[must_use]
    pub fn bits_per_tag_milli(&self) -> usize {
        let inserted = self.xtag_count();
        if inserted == 0 {
            return 0;
        }
        self.total_bits() * 1000 / inserted
    }

    /// Per sealed epoch: `(epoch, tags inserted, tags it was sized for)`. Equal
    /// unless tags arrived after sealing; a ratio above 1.0 means that epoch's
    /// true false-positive rate exceeds `ε`.
    #[must_use]
    pub fn observed_load(&self) -> Vec<(Epoch, usize, usize)> {
        self.sealed
            .iter()
            .map(|(e, f)| (*e, f.inserted, f.sized_for))
            .collect()
    }

    /// Tags that arrived for an already-sealed epoch. Zero in correct use.
    #[must_use]
    pub const fn late_tags(&self) -> usize {
        self.late
    }

    /// The configured false-positive rate.
    #[must_use]
    pub const fn epsilon(&self) -> f64 {
        self.epsilon
    }

    /// Membership in one epoch's filter. A diagnostic for per-epoch
    /// false-positive accounting only: a real probe is unlabelled and answered
    /// against the union of the sealed epochs ([`XSetStore::probe`]).
    #[must_use]
    pub fn contains_in(&self, epoch: Epoch, tag: &XTag) -> bool {
        match self.sealed.get(&epoch) {
            Some(f) => f.contains(tag),
            None => self.pending.get(&epoch).is_some_and(|p| p.contains(tag)),
        }
    }
}

impl XSetStore for BloomXSet {
    fn add_xtags(&mut self, epoch: Epoch, tags: &[XTag]) {
        if let Some(filter) = self.sealed.get_mut(&epoch) {
            for t in tags {
                filter.insert(t);
            }
            self.late += tags.len();
        } else {
            self.pending
                .entry(epoch)
                .or_default()
                .extend(tags.iter().copied());
        }
    }

    fn seal_epoch(&mut self, epoch: Epoch) {
        let Some(tags) = self.pending.remove(&epoch) else {
            return;
        };
        let mut filter = Filter::new(tags.len(), self.epsilon);
        for t in &tags {
            filter.insert(t);
        }
        self.sealed.insert(epoch, filter);
    }

    /// Each unlabelled probe is tested against every **sealed** epoch's
    /// filter; an unsealed (open) epoch is never answered against. With `E`
    /// sealed filters at rate `ε` each, a non-member reads as present with
    /// probability at most `E·ε`, which is why `ε ≤ δ/((n_max−1)E)` still
    /// holds after D3 (draft8 §VII, Bloom paragraph).
    fn probe(&self, transcript: &Transcript) -> Vec<bool> {
        transcript
            .probes
            .iter()
            .map(|tag| self.sealed.values().any(|f| f.contains(tag)))
            .collect()
    }

    fn xtag_count(&self) -> usize {
        self.sealed.values().map(|f| f.inserted).sum::<usize>()
            + self.pending.values().map(BTreeSet::len).sum::<usize>()
    }

    fn reset(&mut self) {
        self.sealed.clear();
        self.pending.clear();
        self.late = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(n: u64) -> XTag {
        xof::cross_tag(
            &pqcl_primitives::xof::PrfKey::new([9u8; pqcl_primitives::LAMBDA_BYTES]),
            &[&n.to_le_bytes()],
        )
    }

    /// Relative error, for comparing against the closed form.
    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol * b.abs().max(f64::MIN_POSITIVE)
    }

    #[test]
    fn the_loss_model_reproduces_the_measured_fixture() {
        // `tests/bloom_vs_oracle.rs` has n−1 = 2, E = 2, 40 true matches, and
        // measured 16 dropped at ε=10⁻¹ and 2 at 10⁻².
        let at = |eps: f64| predicted_loss(eps, 2, 2) * 40.0;
        assert!(
            (13.0..=17.0).contains(&at(1e-1)),
            "predicted {} dropped at ε=10⁻¹ against 16 observed",
            at(1e-1)
        );
        assert!(
            (1.0..=3.0).contains(&at(1e-2)),
            "predicted {} dropped at ε=10⁻² against 2 observed",
            at(1e-2)
        );
        assert!(at(1e-3) < 1.0 && at(1e-4) < 1.0, "both measured zero");
    }

    #[test]
    fn the_paper_operating_point_is_where_ten_to_the_minus_three_fails() {
        // ⛔ The reason `10⁻³` must not be a default. tab:params allows E ≤ 24.
        let loss = predicted_loss(1e-3, 4, 24);
        assert!(
            close(loss, 0.0916, 0.02),
            "expected ≈9.16% loss at n−1=4, E=24, ε=10⁻³; got {:.4}%",
            loss * 100.0
        );

        // And it is fine at the fixture's parameters, which is exactly the trap:
        // a value read off E=2 and carried to E=24.
        assert!(predicted_loss(1e-3, 2, 2) < 0.005);
    }

    #[test]
    fn max_epsilon_matches_the_ruling_and_round_trips() {
        // §1.8: n−1 = 4, E = 24, δ = 10⁻³ gives ε ≤ 1.04 × 10⁻⁵.
        let eps = max_epsilon(1e-3, 4, 24);
        assert!(
            close(eps, 1.042e-5, 0.01),
            "expected ε ≤ 1.04e-5, got {eps:e}"
        );

        // Inverse of `predicted_loss`, which is the property that makes either
        // one safe to quote.
        for (delta, n, e) in [(1e-3, 4, 24), (1e-2, 2, 8), (1e-4, 1, 1)] {
            let eps = max_epsilon(delta, n, e);
            assert!(
                close(predicted_loss(eps, n, e), delta, 1e-9),
                "round trip failed at δ={delta}, n−1={n}, E={e}"
            );
        }
    }

    #[test]
    fn the_bound_tightens_linearly_in_epochs() {
        // ⭐ Why compaction has a second purpose: halving E roughly doubles the
        // ε a deployment can afford.
        let a = max_epsilon(1e-3, 4, 24);
        let b = max_epsilon(1e-3, 4, 12);
        assert!(
            close(b / a, 2.0, 0.01),
            "halving E should roughly double the affordable ε; ratio was {}",
            b / a
        );
    }

    #[test]
    fn sizing_matches_the_published_space_figure() {
        // ε = 10⁻³ gives k = 10 and ≈14.4 bits/tag. ⛔ This is the *space*
        // figure only — it is not a recommendation; see `max_epsilon`.
        let (m, k) = sizing(1_000, 1e-3);
        assert_eq!(k, 10);
        // Integer milli-bits per tag: the workspace denies precision-losing
        // casts, and the assertion is just as sharp without floats.
        let milli = m * 1000 / 1_000;
        assert!(
            (14_000..15_000).contains(&milli),
            "expected ~14.4 bits/tag at ε=10⁻³, got {}.{} ",
            milli / 1000,
            milli % 1000
        );
    }

    #[test]
    fn every_inserted_tag_is_found() {
        // The direction a Bloom filter must never get wrong: no false negatives.
        let mut f = Filter::new(1_000, 1e-3);
        for i in 0..1_000u64 {
            f.insert(&tag(i));
        }
        for i in 0..1_000u64 {
            assert!(f.contains(&tag(i)), "false negative at {i}");
        }
    }

    /// The 99% two-sided binomial interval for `trials` Bernoulli(`p`) draws,
    /// normal approximation (`z = 2.576`). Adequate here: every use below has
    /// an expected count of at least 100.
    fn binomial_99(trials: usize, p: f64) -> (f64, f64) {
        #[expect(clippy::cast_precision_loss, reason = "test trial counts are small")]
        let n = trials as f64;
        let mean = n * p;
        let half = 2.576 * (n * p * (1.0 - p)).sqrt();
        (mean - half, mean + half)
    }

    /// False positives among `trials` non-member probes of one epoch.
    fn epoch_false_positives(s: &BloomXSet, epoch: Epoch, start: u64, trials: usize) -> usize {
        (start..start + trials as u64)
            .filter(|i| s.contains_in(epoch, &tag(*i)))
            .count()
    }

    #[test]
    fn the_false_positive_rate_is_near_the_configured_one() {
        // ⭐ The test that makes the filter worth having. A filter returning
        // `true` unconditionally passes `every_inserted_tag_is_found`; only this
        // one can tell it apart from a real filter.
        //
        // ⛔ M10 P3: this used to accept anything under 50 000 ppm for a
        // 10 000 ppm target — a 5x band loose enough that an overfilled filter
        // passed. It is now the 99% binomial interval, which is also the
        // acceptance criterion for the whole (ε, E) sweep.
        let n = 2_000usize;
        let mut f = Filter::new(n, 1e-2);
        for i in 0..n as u64 {
            f.insert(&tag(i));
        }

        let trials = 20_000usize;
        let start = n as u64;
        let fps = (start..start + trials as u64)
            .filter(|i| f.contains(&tag(*i)))
            .count();
        let (lo, hi) = binomial_99(trials, 1e-2);
        #[expect(clippy::cast_precision_loss, reason = "a count of at most 20 000")]
        let got = fps as f64;
        assert!(
            (lo..=hi).contains(&got),
            "{fps} false positives in {trials} probes; 99% interval at ε = 1% is [{lo:.0}, {hi:.0}]"
        );
    }

    /// ⭐ The M10 P3 regression. Loads differ 10x between epochs — as they do
    /// in practice, where the last epoch of a build also carries deletions —
    /// and every sealed epoch must still sit at ε. Sized from one shared
    /// "expected" load, the heavy epoch here was overfilled 2.7x and its rate
    /// several times ε; that is what campaign 02 measured as 33x at E = 16.
    #[test]
    fn every_epoch_sits_at_epsilon_even_when_loads_are_uneven() {
        let eps = 1e-3;
        let mut s = BloomXSet::new(eps);
        let loads = [(0u64, 500u64), (1, 500), (2, 5_000)];
        let mut next = 0u64;
        for &(epoch, n) in &loads {
            let tags: Vec<XTag> = (next..next + n).map(tag).collect();
            s.add_xtags(epoch, &tags);
            s.seal_epoch(epoch);
            next += n;
        }
        assert_eq!(s.late_tags(), 0);
        for (e, inserted, sized_for) in s.observed_load() {
            assert_eq!(inserted, sized_for, "epoch {e} was not sized from its load");
        }

        let trials = 100_000usize;
        let (lo, hi) = binomial_99(trials, eps);
        for &(epoch, _) in &loads {
            let fps = epoch_false_positives(&s, epoch, 1_000_000 + epoch * 10_000_000, trials);
            #[expect(clippy::cast_precision_loss, reason = "a count of at most 100 000")]
            let got = fps as f64;
            assert!(
                (lo..=hi).contains(&got),
                "epoch {epoch}: {fps} false positives in {trials}; 99% interval at \
                 ε = {eps} is [{lo:.0}, {hi:.0}]"
            );
        }
    }

    #[test]
    fn an_open_epoch_is_never_answered_against_until_sealed() {
        let mut s = BloomXSet::new(1e-1);
        s.add_xtags(7, &[tag(1), tag(2)]);
        let probes = vec![tag(1), tag(3)];
        assert_eq!(
            s.probe(&Transcript {
                probes: probes.clone()
            }),
            vec![false, false]
        );
        assert!(s.contains_in(7, &tag(1)), "held exactly while open");
        s.seal_epoch(7);
        assert!(s.probe(&Transcript { probes })[0], "answered once sealed");
        assert_eq!(s.xtag_count(), 2);
    }

    #[test]
    fn a_smaller_epsilon_costs_more_bits() {
        let (loose, _) = sizing(1_000, 1e-1);
        let (tight, _) = sizing(1_000, 1e-4);
        assert!(
            tight > loose * 3,
            "tightening ε by three orders should cost several times the space"
        );
    }

    #[test]
    fn bits_per_tag_beats_an_exact_tag_by_about_the_claimed_factor() {
        let mut s = BloomXSet::new(1e-3);
        let tags: Vec<XTag> = (0..1_000u64).map(tag).collect();
        s.add_xtags(0, &tags);
        s.seal_epoch(0);

        // 256 bits for an exact 32-byte tag against ~14.4 here.
        let ratio = 256_000 / s.bits_per_tag_milli();
        assert!(
            (15..=20).contains(&ratio),
            "expected ≈17.8x space saving, got {ratio}x"
        );
    }
}
