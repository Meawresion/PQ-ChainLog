//! What B-DEMS's participants sign (`contracts/src/BDems.sol`), computed the
//! way its `tx*Digest` functions compute it, so the contract's `ecrecover`
//! checks pass for an honest signer and fail for anyone else.
//!
//! Shared by SAC Exp. 1 (`exp6chain`, the whole workflow) and Exp. 4
//! (`redaction`, registration as setup). Behind the `chain` feature, as
//! [`crate::evm`] is.

use crate::evm::{Abi, EvmError, Key, Word, abi_encode, keccak256};

/// `keccak256(abi.encode(keccak256(tag), words…))`: `BDems.txaDigest` with
/// tag `"B-DEMS TxA"`, and likewise for `TxB`, `TxC` and `TxD`.
#[must_use]
pub fn digest(tag: &str, words: &[Word]) -> Word {
    let mut args = vec![Abi::Word(keccak256(tag.as_bytes()))];
    args.extend(words.iter().map(|w| Abi::Word(*w)));
    keccak256(&abi_encode(&args))
}

/// One signature as `BDems._signer` reads it: `r ‖ s ‖ v`.
///
/// # Errors
///
/// Signing fails.
pub fn sig(key: &Key, digest: &Word) -> Result<Vec<u8>, EvmError> {
    let (v, r, s) = key.sign_digest(digest)?;
    Ok([r.as_slice(), s.as_slice(), &[v]].concat())
}
