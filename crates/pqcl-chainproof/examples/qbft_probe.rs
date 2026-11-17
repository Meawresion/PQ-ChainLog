//! Diagnostic: work out how our QBFT chain computes a block hash.
//!
//! Mainnet's rule is `keccak256(rlp(header))`. BFT consensus families are known
//! to differ, because a header carries commit seals that are only known *after*
//! the block is agreed — so hashing them would make the hash unstable. This
//! probe tries the candidate transformations against a real header and reports
//! which one reproduces the hash Besu itself reports.
//!
//! Written as a probe rather than a guess: getting this wrong would make the
//! Secure Module reject every genuine authorisation, and the failure would look
//! like a proof bug rather than a consensus-family difference.
//!
//! ```sh
//! cargo run -p pqcl-chainproof --example qbft_probe -- <header-hex> <blockhash-hex>
//! ```
//!
//! ⚠️ **A diagnostic, not library code.** It panics freely on malformed input
//! because the operator is standing right there reading the output, and a
//! `Result` chain would bury the one line that matters. The workspace lints
//! that forbid this in shipped code are relaxed below for that reason, and only
//! within this file.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::format_collect,
    reason = "an operator-facing diagnostic; see the module docs"
)]

use pqcl_chainproof::{keccak256, rlp};

fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Re-encode a header, replacing field 12 (`extraData`) with `extra`.
fn with_extra(header: &[u8], extra: &[u8]) -> Vec<u8> {
    let decoded = rlp::decode(header).expect("header decodes");
    let fields = decoded.list().expect("header is a list");
    let items: Vec<Vec<u8>> = fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            if i == 12 {
                rlp::encode_bytes(extra)
            } else {
                match f {
                    rlp::Rlp::Bytes(b) => rlp::encode_bytes(b),
                    rlp::Rlp::List(_) => panic!("header field {i} is unexpectedly a list"),
                }
            }
        })
        .collect();
    rlp::encode_list(&items)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() == 3,
        "usage: qbft_probe <header-hex> <blockhash-hex>"
    );
    let header = unhex(&args[1]);
    let want = unhex(&args[2]);

    println!("want                     : {}", hex(&want));
    println!("header bytes             : {}", header.len());

    // Candidate 0: mainnet's rule, unchanged.
    println!("keccak(header)           : {}", hex(&keccak256(&header)));

    // Inspect extraData: QBFT encodes it as
    // RLP([vanity, validators, vote, roundNumber, commitSeals]).
    let decoded = rlp::decode(&header).expect("header decodes");
    let fields = decoded.list().expect("list");
    println!("header field count       : {}", fields.len());

    let extra = match &fields[12] {
        rlp::Rlp::Bytes(b) => *b,
        rlp::Rlp::List(_) => panic!("extraData is a list?"),
    };
    println!("extraData bytes          : {}", extra.len());

    let Ok(ed) = rlp::decode(extra) else {
        println!("extraData is not RLP; this is not a BFT header");
        return;
    };
    let Ok(parts) = ed.list() else {
        println!("extraData is not a list");
        return;
    };
    println!("extraData item count     : {}", parts.len());

    let enc = |item: &rlp::Rlp<'_>| -> Vec<u8> {
        match item {
            rlp::Rlp::Bytes(b) => rlp::encode_bytes(b),
            rlp::Rlp::List(items) => {
                let inner: Vec<Vec<u8>> = items
                    .iter()
                    .map(|i| match i {
                        rlp::Rlp::Bytes(b) => rlp::encode_bytes(b),
                        rlp::Rlp::List(_) => panic!("nested list too deep"),
                    })
                    .collect();
                rlp::encode_list(&inner)
            }
        }
    };

    if parts.len() == 5 {
        // Candidate 1: commit seals emptied.
        let no_seals = rlp::encode_list(&[
            enc(&parts[0]),
            enc(&parts[1]),
            enc(&parts[2]),
            enc(&parts[3]),
            rlp::encode_list(&[]),
        ]);
        println!(
            "keccak(no seals)         : {}",
            hex(&keccak256(&with_extra(&header, &no_seals)))
        );

        // Candidate 2: commit seals emptied *and* round number zeroed, so a
        // block agreed in a later round hashes the same as in the first.
        let no_seals_no_round = rlp::encode_list(&[
            enc(&parts[0]),
            enc(&parts[1]),
            enc(&parts[2]),
            rlp::encode_bytes(&[]),
            rlp::encode_list(&[]),
        ]);
        println!(
            "keccak(no seals, round 0): {}",
            hex(&keccak256(&with_extra(&header, &no_seals_no_round)))
        );

        // Candidate 3: both dropped entirely rather than emptied.
        let dropped = rlp::encode_list(&[enc(&parts[0]), enc(&parts[1]), enc(&parts[2])]);
        println!(
            "keccak(3-item extra)     : {}",
            hex(&keccak256(&with_extra(&header, &dropped)))
        );
    }
}
