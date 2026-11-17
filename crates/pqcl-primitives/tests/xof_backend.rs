//! SHAKE256 backend comparison — our backend (`tiny-keccak` since M12 R1) against
//! an independent Keccak (`sha3`, the previous backend).
//!
//! # Why measure this at all
//!
//! SHAKE256 is the hottest primitive in the system. Every domain-separated
//! hash, every PRF derivation, every Merkle node and every GGM step goes
//! through it, several times per ingested event. `PQ-ChainLog-DESIGN.md` §8's
//! per-event cost is `t_AEAD(|m|) + k·t_PRF + t_sign/B + t_MMR_append`, and the
//! `k·t_PRF` term is this function.
//!
//! Accepting the default without looking would mean the Exp. 1 headline rests
//! on an unexamined choice. So: measure, then choose.
//!
//! # Why `#[ignore]`, like the SLH-DSA bake-off
//!
//! This is a **backend-selection experiment**, not a correctness gate. SHAKE256
//! correctness is gated unconditionally by the ACVP vectors in `tests/kat.rs`.
//! Re-running a throughput comparison on every CI would measure whatever else
//! the machine happened to be doing.
//!
//! ```text
//! cargo test --release -p pqcl-primitives --test xof_backend -- --ignored --nocapture
//! ```
//!
//! **Use `--release`.** A debug measurement of a hash function is noise.
//!
//! # These numbers must never reach the paper
//!
//! The build plan: published figures come from an AWS run through
//! the results pipeline, which refuses non-AWS records and dirty trees. What
//! this test produces is a *relative* comparison used to pick a library — the
//! kind of local number §0.3 explicitly permits for deciding "is this worth
//! running on AWS", and for nothing else.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use pqcl_primitives::xof;

/// Sizes chosen to bracket real use: a PRF derivation absorbs tens of bytes, a
/// Merkle node 64, and a chunked evidence digest 1 MiB.
const SIZES: &[usize] = &[32, 64, 1024, 64 * 1024, 1024 * 1024];

fn throughput_mib_s(bytes: usize, iters: usize, elapsed: std::time::Duration) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let total = (bytes * iters) as f64;
    total / (1024.0 * 1024.0) / elapsed.as_secs_f64()
}

/// Enough iterations that a fast case still runs long enough to time.
fn iters_for(size: usize) -> usize {
    (8 * 1024 * 1024 / size.max(1)).max(64)
}

#[test]
#[ignore = "backend-selection experiment; see the module docs"]
fn compare_shake256_backends() {
    println!(
        "\n{:>10}  {:>14}  {:>14}  {:>8}",
        "input", "ours (MiB/s)", "sha3", "ratio"
    );
    println!("{}", "-".repeat(52));

    for &size in SIZES {
        let input = vec![0xa5u8; size];
        let iters = iters_for(size);

        // --- our backend, through the hot-path API
        //
        // `digest256` and not `shake256`: the latter heap-allocates its output
        // buffer, so timing it against tiny-keccak writing into a stack array
        // would measure our allocator rather than either Keccak. `digest256`
        // squeezes into a fixed `[u8; 32]`, which is what every PRF derivation,
        // Merkle node and commitment in the system actually calls.
        let start = Instant::now();
        let mut sink = 0u8;
        for _ in 0..iters {
            sink ^= xof::digest256(&input)[0];
        }
        let ours = throughput_mib_s(size, iters, start.elapsed());

        // --- an independent implementation, doing exactly the same work
        //
        // Absorbs the same `0x00` role byte that `digest256` applies, so this
        // is like-for-like and the XOR check below is meaningful rather than
        // decorative.
        let start = Instant::now();
        for _ in 0..iters {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake256::default();
            h.update(&[0x00]);
            h.update(&input);
            let mut out = [0u8; 32];
            h.finalize_xof().read(&mut out);
            sink ^= out[0];
        }
        let theirs = throughput_mib_s(size, iters, start.elapsed());

        assert_eq!(
            sink, 0,
            "the two backends disagreed while being timed, so the numbers above \
             compare different functions"
        );

        println!(
            "{size:>10}  {ours:>14.0}  {theirs:>14.0}  {:>7.2}x",
            ours / theirs
        );
    }

    println!(
        "\nRecord the outcome in the build plan. A ratio near 1.0 means \n\
         the default is fine and the choice is settled by maintenance and \n\
         dependency weight rather than speed.\n"
    );
}

/// The two backends must agree byte-for-byte, or the comparison above is
/// measuring two different functions. Unlike the timing, this is cheap and
/// unconditional.
#[test]
fn shake256_backends_agree() {
    for &size in &[0usize, 1, 32, 135, 136, 137, 1024] {
        let input = vec![0x5au8; size];

        let ours = xof::shake256(&input, 64);

        let mut theirs = [0u8; 64];
        {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake256::default();
            h.update(&input);
            h.finalize_xof().read(&mut theirs);
        }

        assert_eq!(
            ours,
            theirs.to_vec(),
            "SHAKE256 backends disagree at input length {size}"
        );
    }
    // 135/136/137 straddle the SHAKE256 rate (136 bytes), which is where
    // padding bugs live.
}
