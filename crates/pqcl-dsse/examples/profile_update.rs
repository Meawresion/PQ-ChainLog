//! Per-component cost of one `Π_XT` update — M10 P1's profile.
//!
//! `perf` is not available in the development WSL (installing it needs sudo),
//! so this times each step of `Client::update` / `XtClient::update` in
//! isolation, with the **same public primitives in the same order**, and
//! then the real `XtClient::update` end to end as a cross-check: the parts
//! must add up to roughly the whole, or the breakdown is missing something.
//!
//! ⛔ Local figures, for the fix decision only. Run in release:
//!
//! ```text
//! cargo run --release -p pqcl-dsse --example profile_update
//! ```

// A profiling example, not library code: timings are converted to f64 for
// display (precision loss is irrelevant at µs), a failed seal should abort the
// run loudly, and the one-letter names mirror the components they time.
#![allow(
    clippy::cast_precision_loss,
    clippy::expect_used,
    clippy::many_single_char_names
)]

use std::hint::black_box;
use std::time::Instant;

use pqcl_dsse::core::Client;
use pqcl_dsse::core::Op;
use pqcl_dsse::xt::{HonestServer, XtClient};
use pqcl_ggm::MasterKey;
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::aead::RecordKey;
use pqcl_primitives::xof::{self, Label, PrfKey};

const N: u64 = 20_000;

fn per_op(label: &str, total_ns: u128, n: u64) -> f64 {
    let us = total_ns as f64 / n as f64 / 1_000.0;
    println!("  {label:<44} {us:>9.3} µs");
    us
}

fn main() {
    let key = PrfKey::new([0x11; LAMBDA_BYTES]);
    let w: &[u8] = b"keyword";
    println!("per-update components, mean over {N} updates:");

    // K^A_w = F(K_S, "addr" ‖ w)
    let t = Instant::now();
    for _ in 0..N {
        black_box(xof::prf(&key, Label::Addr, &[black_box(w)]));
    }
    let a = per_op("addr_root: PRF(K_S, Addr, w)", t.elapsed().as_nanos(), N);

    // GGM root-to-leaf walk, TREE_DEPTH PRG calls
    let root = MasterKey::new(xof::prf(&key, Label::Addr, &[w]));
    let t = Instant::now();
    for c in 0..N {
        black_box(root.eval(black_box(c)));
    }
    let b = per_op("GGM eval(c): 64 × PRG", t.elapsed().as_nanos(), N);

    // one PRG call, to size the walk
    let seed = [7u8; LAMBDA_BYTES];
    let t = Instant::now();
    for _ in 0..N {
        black_box(pqcl_primitives::prg::ggm_step(black_box(&seed)));
    }
    let p = per_op("  (one PRG call)", t.elapsed().as_nanos(), N);

    let tag = root.eval(1);
    let t = Instant::now();
    for _ in 0..N {
        black_box(xof::addr_hash(black_box(&tag)));
    }
    let c = per_op("addr_hash(tag)", t.elapsed().as_nanos(), N);

    // record_key: mask_seed(w) then F(K^M_w, c)
    let t = Instant::now();
    for i in 0..N {
        let ms = PrfKey::new(xof::prf(&key, Label::Mask, &[w]));
        black_box(xof::prf(&ms, Label::Mask, &[&i.to_le_bytes()]));
    }
    let d = per_op("record_key: mask_seed + PRF", t.elapsed().as_nanos(), N);

    let addr = xof::addr_hash(&tag);
    let t = Instant::now();
    for i in 0..N {
        let rk = RecordKey::new([u8::try_from(i % 251).unwrap_or(0); LAMBDA_BYTES]);
        black_box(rk.seal(&addr, &[1u8; 9]).expect("seal"));
    }
    let e = per_op("AEAD seal (key schedule + 9 B)", t.elapsed().as_nanos(), N);

    let xkey = PrfKey::new([0x12; LAMBDA_BYTES]);
    let t = Instant::now();
    for i in 0..N {
        black_box(xof::cross_tag(&xkey, &[&[1u8], w, &i.to_le_bytes()]));
    }
    let f = per_op("cross_tag", t.elapsed().as_nanos(), N);

    let sum = a + b + c + d + e + f;
    println!("  {:<44} {sum:>9.3} µs", "sum of the crypto components");
    println!(
        "  GGM walk share of that sum: {:.0}%   (64 PRG calls = {:.3} µs)",
        100.0 * b / sum,
        64.0 * p
    );

    // the real thing, end to end, one keyword and many
    for (name, kws) in [
        ("one keyword", 1usize),
        ("2 000 keywords round-robin", 2_000),
    ] {
        let words: Vec<Vec<u8>> = (0..kws).map(|k| format!("kw{k:05}").into_bytes()).collect();
        let mut client = XtClient::new(Client::new(key.clone()), xkey.clone(), 256);
        let mut server = HonestServer::new();
        let t = Instant::now();
        for i in 0..N {
            let w = &words[usize::try_from(i).unwrap_or(0) % kws];
            client.update(&mut server, Op::Add, w, i).expect("update");
        }
        client.flush(&mut server);
        per_op(
            &format!("XtClient::update end to end ({name})"),
            t.elapsed().as_nanos(),
            N,
        );
    }
}
