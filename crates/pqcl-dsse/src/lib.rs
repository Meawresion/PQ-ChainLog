//! Dynamic searchable symmetric encryption for PQ-ChainLog.
//!
//! | Module | What |
//! |---|---|
//! | [`core`] | `Π_core` — single-keyword DSSE, forward private, Type-II backward private |
//! | [`xt`] | `Π_XT` / `Π_BOOL` — group-free conjunctive and Boolean search |
//! | [`range`] | `Π_RANGE` — range queries by reduction to `Π_BOOL` |
//! | [`cms`] | Count-Min Sketch and the s-term selection rule |
//! | [`oracle`] | the plaintext inverted index every scheme is checked against |
//!
//! `Π_CD` — client-side intersection, the fallback when every conjunct is
//! selective — is a two-line composition of `Π_core` searches and is provided
//! by [`cd_search`].
//!
//! # What is claimed, and what is not
//!
//! No novelty is claimed for `Π_core`: it is Diana's GGM token compression plus
//! the `B′` transform's in-band tombstones, omitting `B′`'s cleanup round.
//! The project rules is explicit about this, and about the fact that MITRA —
//! whose mechanism this resembles — cannot be cited.
//!
//! What *is* ours to claim is that `Π_core` turns out to be **verifiable search
//! against a malicious server for free** (design §11.1), because the client
//! derives every address itself and never releases `K^M_w`. That was true of
//! the construction all along; we had simply been assuming an
//! honest-but-curious server and under-claiming.

pub mod bloom;
pub mod cms;
pub mod core;
pub mod oracle;
pub mod range;
pub mod verified;
pub mod xt;

pub use bloom::BloomXSet;
pub use cms::CountMinSketch;
pub use core::{
    Client, DocId, Edb, HonestEdb, Op, SearchError, SearchResponse, SearchToken, UpdateToken,
};
pub use oracle::Oracle;
pub use xt::{
    Epoch, Formula, HonestServer, HonestXSet, Ratchet, Transcript, XSetStore, XTag, XtClient,
};

use std::collections::BTreeSet;

/// `Π_CD` — conjunctive search by client-side intersection.
///
/// `n` independent `Π_core` searches, intersected locally. The server learns
/// each keyword's search pattern separately and nothing about the conjunction,
/// so its leakage is *incomparable* to `Π_XT`'s rather than worse — that
/// incomparability is a theorem in the paper, not a hedge.
///
/// **Not the default.** `PQ-DSSE-Formal.md` §6 works the example: at a 10⁸
/// corpus with a common conjunct this transfers hundreds of megabytes to answer
/// a three-document query. It is the right choice in exactly two situations —
/// when every conjunct is selective, and on the custody plane, which holds
/// 10²–10⁴ records rather than 10⁷–10⁹.
///
/// # Errors
///
/// Any [`SearchError`] from an underlying `Π_core` search.
pub fn cd_search<S: Edb>(
    client: &Client,
    store: &S,
    keywords: &[&[u8]],
) -> Result<BTreeSet<DocId>, SearchError> {
    let mut result: Option<BTreeSet<DocId>> = None;
    for w in keywords {
        let set = match client.search_token(w) {
            None => BTreeSet::new(),
            Some(token) => client.finish(w, &token, &store.search(&token))?,
        };
        result = Some(match result {
            None => set,
            Some(acc) => acc.intersection(&set).copied().collect(),
        });
    }
    Ok(result.unwrap_or_default())
}
