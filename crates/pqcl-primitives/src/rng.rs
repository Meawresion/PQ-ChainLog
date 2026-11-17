//! Randomness, from the operating system.
//!
//! One place, for the same reason every other primitive is in one place: *"which
//! RNG produced this key?"* must have a single answer. A crate that reaches for
//! its own `OsRng` makes that question a per-file investigation.
//!
//! # Why the OS and not a userspace DRBG
//!
//! Every secret this draws is long-lived — a case master key, a custody key —
//! and drawn rarely. There is no throughput argument for a userspace generator,
//! and a seeded DRBG adds a seeding question and a fork-safety question in
//! exchange for speed we do not need. `getrandom` is a thin wrapper over
//! `getrandom(2)` on Linux and `BCryptGenRandom` on Windows, both of which are
//! fork-safe and require no initialisation.
//!
//! # ⚠️ Failure is an error, never a fallback
//!
//! If the OS cannot supply entropy, these return `Err`. They do **not** fall
//! back to a timestamp, a counter, or a weaker source. A key drawn from a
//! degraded source is indistinguishable from a good one by inspection, which is
//! precisely why the failure must be loud.

use core::fmt;

use crate::LAMBDA_BYTES;

/// The OS entropy source was unavailable.
#[derive(Debug, Clone)]
pub struct RngError(String);

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OS entropy unavailable: {}", self.0)
    }
}

impl core::error::Error for RngError {}

/// Fill `buf` with cryptographically secure random bytes.
///
/// # Errors
///
/// [`RngError`] if the OS entropy source is unavailable. Never falls back.
pub fn fill(buf: &mut [u8]) -> Result<(), RngError> {
    getrandom::fill(buf).map_err(|e| RngError(e.to_string()))
}

/// Draw a fresh λ-bit secret.
///
/// # Errors
///
/// [`RngError`] if the OS entropy source is unavailable.
pub fn secret() -> Result<[u8; LAMBDA_BYTES], RngError> {
    let mut out = [0u8; LAMBDA_BYTES];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        let (a, b) = (secret().expect("entropy"), secret().expect("entropy"));
        assert_ne!(a, b, "two λ-bit draws collided; the RNG is broken");
    }

    #[test]
    fn a_draw_is_not_all_zero() {
        // The failure this catches is a wrapper that silently returns without
        // writing — the buffer keeps its initial value and looks like a key.
        assert_ne!(secret().expect("entropy"), [0u8; LAMBDA_BYTES]);
    }

    #[test]
    fn fill_writes_the_whole_buffer() {
        // A short write would leave a tail of zeros that still looks random at
        // the head, which is the shape a spot-check misses.
        let mut buf = [0u8; 256];
        fill(&mut buf).expect("entropy");
        assert!(
            buf[192..].iter().any(|&b| b != 0),
            "the tail of the buffer was never written"
        );
    }
}
