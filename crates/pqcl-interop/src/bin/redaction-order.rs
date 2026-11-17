//! Emit one court redaction order signed by *our* signer, for `Anchor.sol`.
//!
//! The Solidity suite needs a genuine `σ_CO` over a real `eq:order` tuple to
//! show two things the Rust tests cannot: that `orderRedaction` accepts the
//! order exactly as `pqcl_capsule::redaction::Order::message` encodes it, and
//! that flipping any signed field (`mode`, `exp`, …) makes it revert
//! A key that never signed an order would
//! prove neither.
//!
//! ```text
//! cargo run -q -p pqcl-interop --bin redaction-order \
//!   | python3 contracts/tools/redaction_order_fixture.py
//! ```
//!
//! Like the interop fixture, regenerating yields a different, equally valid
//! file: liboqs keygen is unseeded and its signing is hedged.

use pqcl_capsule::redaction::{Mode, Order, Scope, Target};
use pqcl_primitives::xof::digest256;
use pqcl_primitives::{Signer, SoftwareMlDsa};

/// Issue time of the fixture order; the Solidity test warps past it.
const TS: u64 = 1_700_000_000;
/// Valid for thirty days.
const TTL: u64 = 30 * 24 * 3600;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let court = SoftwareMlDsa::generate()?;
    // A three-capsule sweep, so the target is a Merkle root, not a pseudonym.
    let members: Vec<_> = (0u8..3)
        .map(|i| digest256(&[b"fixture capsule ".as_slice(), &[i]].concat()))
        .collect();
    let tgt = Target::new(&members).root();
    let order = Order::issue(
        &court,
        digest256(b"fixture order"),
        tgt,
        Scope::Full,
        Mode::Erased,
        TS,
        TS + TTL,
    )?;
    // Verify locally first: a fixture our own verifier rejects would make a
    // Solidity failure look like a contract defect.
    order.verify(court.public_key(), TS + 1)?;

    let doc = serde_json::json!({
        "note": "Court redaction order (draft7 eq:order) signed by PQ-ChainLog's liboqs ML-DSA-65 signer.",
        "parameterSet": "ML-DSA-65",
        "backend": pqcl_primitives::sig::backend_version()?,
        "signatureInterface": "external",
        "preHash": "pure",
        "context": "0x",
        "orderId": format!("0x{}", hex(&order.oid)),
        "target": format!("0x{}", hex(&order.tgt)),
        "scope": order.scope.byte(),
        "mode": order.mode.byte(),
        "ts": order.ts,
        "exp": order.exp,
        "message": format!("0x{}", hex(&order.message())),
        "pk": format!("0x{}", hex(court.public_key())),
        "signature": format!("0x{}", hex(&order.sig_co)),
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
