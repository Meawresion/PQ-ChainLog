//! What the CPU actually offers, detected at runtime.
//!
//! # Why this is not a footnote
//!
//! `RustCrypto`'s `aes` and `polyval` pick their backend at runtime via
//! `cpufeatures`. On a machine without AES-NI they fall back to a portable
//! bitsliced implementation that is roughly an order of magnitude slower — and
//! **produces identical output**. A throughput number measured on that path
//! looks entirely normal and is wrong by 10×.
//!
//! liboqs makes the same kind of choice for its AVX2 code paths, which is why
//! The build plan forbids the `oqs` `non_portable` feature: that
//! feature disables runtime detection and bakes in the build machine's ISA,
//! so a binary built on a laptop and run on an AWS instance would silently use
//! the laptop's instruction set.
//!
//! Two consequences, both implemented:
//!
//! * `aead` asserts the hardware path is present, so a software-fallback
//!   measurement fails loudly instead of being published.
//! * Every results record carries [`CpuFeatures`], so a number can be traced to
//!   the instruction set that produced it.

/// Runtime CPU capabilities relevant to our measured paths.
///
/// `clippy::struct_excessive_bools` is allowed deliberately: this is a record
/// of independent hardware capability flags, not a set of behaviour switches.
/// Collapsing them into an enum or bitflags would make the results JSON harder
/// to read for the reviewer it exists to serve.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuFeatures {
    /// AES-NI. Drives `aes-gcm`'s block cipher.
    pub aes: bool,
    /// Carry-less multiply. Drives GHASH, the other half of AES-GCM.
    pub pclmulqdq: bool,
    /// AVX2. liboqs uses it for ML-KEM and ML-DSA.
    pub avx2: bool,
    /// AVX-512F, if present.
    pub avx512f: bool,
    /// SHA extensions. Not used by SHAKE256 (Keccak has no such instruction on
    /// x86), recorded because it distinguishes CPU generations.
    pub sha: bool,
}

impl CpuFeatures {
    /// Detect at runtime.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                aes: std::arch::is_x86_feature_detected!("aes"),
                pclmulqdq: std::arch::is_x86_feature_detected!("pclmulqdq"),
                avx2: std::arch::is_x86_feature_detected!("avx2"),
                avx512f: std::arch::is_x86_feature_detected!("avx512f"),
                sha: std::arch::is_x86_feature_detected!("sha"),
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self {
                aes: std::arch::is_aarch64_feature_detected!("aes"),
                pclmulqdq: std::arch::is_aarch64_feature_detected!("pmull"),
                avx2: false,
                avx512f: false,
                sha: std::arch::is_aarch64_feature_detected!("sha3"),
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self::default()
        }
    }

    /// Whether AES-GCM will take its hardware path.
    ///
    /// Both halves are needed: AES-NI for the block cipher and carry-less
    /// multiply for GHASH. Having one without the other still means a slow,
    /// correct, and misleading measurement.
    #[must_use]
    pub const fn aes_gcm_is_accelerated(self) -> bool {
        self.aes && self.pclmulqdq
    }

    /// Compact form for a results record, e.g. `"aes+pclmulqdq+avx2"`.
    #[must_use]
    pub fn summary(self) -> String {
        let mut v = Vec::new();
        for (on, name) in [
            (self.aes, "aes"),
            (self.pclmulqdq, "pclmulqdq"),
            (self.avx2, "avx2"),
            (self.avx512f, "avx512f"),
            (self.sha, "sha"),
        ] {
            if on {
                v.push(name);
            }
        }
        if v.is_empty() {
            "none".to_owned()
        } else {
            v.join("+")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_runs_and_reports() {
        let f = CpuFeatures::detect();
        eprintln!("CPU features: {}", f.summary());
        // On any x86_64 host new enough to run this project, AES-NI is present.
        // If this fails, the machine cannot produce a trustworthy AES-GCM
        // number and that needs to be known before anything is measured.
        #[cfg(target_arch = "x86_64")]
        assert!(
            f.aes_gcm_is_accelerated(),
            "no AES-NI/PCLMULQDQ on this host: AES-GCM would fall back to a \
             portable implementation that is ~10x slower and produces identical \
             output, so any throughput measured here would be wrong but \
             plausible-looking. Features seen: {}",
            f.summary()
        );
    }

    #[test]
    fn summary_is_stable_and_readable() {
        let f = CpuFeatures {
            aes: true,
            pclmulqdq: true,
            avx2: true,
            avx512f: false,
            sha: false,
        };
        assert_eq!(f.summary(), "aes+pclmulqdq+avx2");
        assert_eq!(CpuFeatures::default().summary(), "none");
    }
}
