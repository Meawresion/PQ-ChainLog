//! M12 R3: our GGM-over-AES against vectors from an implementation that is not
//! ours — `tests/vectors/ggm_aes.py`, Python `cryptography`, written from the
//! equation. Every `G` output and every 64-level leaf must match byte for byte.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pqcl_ggm::MasterKey;
use pqcl_primitives::prg::ggm_step;

const VECTORS: &str = include_str!("vectors/ggm_aes.txt");

fn bytes32(hex: &str) -> [u8; 32] {
    let v = unhex(hex);
    v.try_into().expect("32 bytes")
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn ggm_over_aes_matches_an_independent_implementation() {
    let (mut steps, mut evals) = (0, 0);
    for line in VECTORS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.as_slice() {
            ["step", seed, out] => {
                assert_eq!(ggm_step(&bytes32(seed)).to_vec(), unhex(out), "G({seed})");
                steps += 1;
            }
            ["eval", root, index, leaf] => {
                let x: u64 = index.parse().expect("index");
                let got = MasterKey::new(bytes32(root)).eval(x);
                assert_eq!(got, bytes32(leaf), "leaf {x} under root {root}");
                // The incremental evaluator must agree with the fresh walk.
                let mut path = MasterKey::new(bytes32(root)).path_eval();
                assert_eq!(path.eval(x), got);
                evals += 1;
            }
            _ => panic!("unparseable vector line: {line}"),
        }
    }
    // Fail loudly on an empty or truncated file: a test over nothing passes.
    assert_eq!(
        (steps, evals),
        (8, 20),
        "vector file does not have the expected cases"
    );
}
