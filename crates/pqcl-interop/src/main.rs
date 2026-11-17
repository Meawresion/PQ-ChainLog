//! Emit an ML-DSA-65 signature produced by *our* signer, for the Solidity
//! verifier to check.
//!
//! # Why this exists
//!
//! The build plan (M7) requires an interop gate in both directions
//! before any on-chain benchmarking:
//!
//! > a signature produced by our Rust/liboqs signer must verify in the deployed
//! > Solidity verifier, and their Python signer's vectors must verify in our
//! > Rust code. Both directions. If the two disagree on encoding, endianness or
//! > domain separation, the gas number is measuring the wrong thing.
//!
//! The second direction is already discharged, and more strongly than the plan
//! asks: `pqcl-primitives/tests/kat.rs` checks our verifier against the NIST
//! ACVP `sigVer` vectors exactly, and `contracts/test/MLDSA65Gate.t.sol` checks
//! the Solidity verifier against those *same* vectors. Both implementations are
//! therefore pinned to NIST rather than to each other, which is the stronger
//! arrangement — two implementations can agree with each other and both be
//! wrong.
//!
//! What that leaves unproven is this direction: a key and signature **we**
//! generated, rather than ones NIST handed us, being accepted on-chain. That is
//! what this binary produces.
//!
//! # A deliberate second purpose
//!
//! The message is 32 bytes with an empty context, which is exactly the workload
//! upstream ETHDILITHIUM's published benchmark uses. Verification cost in the
//! NIST variant is linear in message length — about 1.9 k gas per byte at level
//! III, measured in `contracts/test/GasProfile.t.sol` — so a fixture at this
//! size is what makes our figure comparable to theirs instead of merely
//! different from it.
//!
//! # Reproducibility
//!
//! Regenerating this fixture yields a *different* file. liboqs exposes no
//! seeded key generation, and its ML-DSA signing is hedged, so neither the key
//! nor the signature is reproducible from a seed. The fixture is therefore
//! committed as an artefact rather than rebuilt on demand, and the gate test
//! consumes the committed bytes. A regenerated fixture is equally valid; it
//! just is not byte-identical, and nothing should assert that it would be.

use pqcl_primitives::{Signer, SoftwareMlDsa};

/// Upstream's benchmark signs 32 bytes. Matching it is the point — see the
/// module docs.
const MESSAGE_BYTES: usize = 32;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let key = SoftwareMlDsa::generate()?;

    // A fixed, obviously-not-secret pattern. The content is irrelevant to the
    // gate — only its length is — and a recognisable one makes the fixture
    // readable when someone opens it.
    let message: Vec<u8> = (0..MESSAGE_BYTES)
        .map(|i| u8::try_from(i).unwrap_or(0))
        .collect();

    let signature = key.sign(&message)?;

    // Verify locally before emitting. If our own verifier rejects our own
    // signature, the fixture is worthless and the Solidity failure would be
    // misread as a porting defect in the contract.
    pqcl_primitives::sig::verify(&message, &signature, key.public_key(), &[])?;

    let doc = serde_json::json!({
        "note": "ML-DSA-65 signature produced by PQ-ChainLog's liboqs signer. \
                 Public key is the raw 1952-byte FIPS-204 encoding; the Solidity \
                 verifier needs it expanded, which contracts/tools/ does.",
        "parameterSet": "ML-DSA-65",
        "backend": pqcl_primitives::sig::backend_version()?,
        "signatureInterface": "external",
        "preHash": "pure",
        "context": "0x",
        "message": format!("0x{}", hex(&message)),
        "pk": format!("0x{}", hex(key.public_key())),
        "signature": format!("0x{}", hex(&signature)),
    });

    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
