//! Reading `kmstool_enclave_cli`'s answer.
//!
//! # Why this is a module and not four lines in the enclave binary
//!
//! It used to be four lines in the enclave binary, and they were **wrong**: the
//! code stripped a prefix of `"KEY PLAINTEXT: "`, which the tool has never
//! printed. The real format is
//!
//! ```text
//! fprintf(stdout, "PLAINTEXT: %s\n", (const char *)ciphertext_decrypted_b64.buffer);
//! ```
//!
//! — `aws/aws-nitro-enclaves-sdk-c`, `bin/kmstool-enclave-cli/main.c:514`
//! (tag `v0.4.5`). The enclave would have started, asked KMS for `K_mst`,
//! received it, failed to find a line it recognised, and refused to serve with
//! the message *"`kmstool_enclave_cli` produced no key line"* — on the campaign
//! instance, after paying for an enclave-enabled host, and pointing at the wrong
//! component.
//!
//! The bug survived review because nothing could execute it: the binary is
//! `#![cfg(all(feature = "enclave", target_os = "linux"))]`, so the parsing was
//! unreachable from `cargo test` on any developer machine. Moving it here makes
//! it ordinary library code that ordinary CI compiles and tests, which is the
//! only reason the format is now pinned by an assertion rather than by a
//! comment.
//!
//! ⛔ **Do not move this back into the binary.** The subprocess call has to live
//! there — it needs a real enclave — but parsing a string does not, and the
//! parsing is the part that was wrong.

/// The prefix `kmstool_enclave_cli` puts before base64 plaintext.
///
/// ⚠️ Load-bearing and externally owned: it comes from AWS's source, not from
/// us, so it can only be changed by re-reading `main.c` at the tag
/// `nitro/build-eif.sh` pins. `genkey` also prints a `CIPHERTEXT: ` line, which
/// is why matching is anchored at the start of a line rather than done with a
/// substring search.
pub const PLAINTEXT_PREFIX: &str = "PLAINTEXT: ";

/// Pull the base64 plaintext out of the tool's stdout.
///
/// # Errors
///
/// If no line carries the prefix, or if more than one does. The second case
/// cannot arise from `decrypt`, which prints exactly one line — so if it ever
/// happens the output is not what we think it is, and guessing which line holds
/// the case master key is not a reasonable thing to do.
pub fn parse_plaintext_line(stdout: &str) -> Result<&str, String> {
    let mut found = stdout
        .lines()
        .filter_map(|l| l.strip_prefix(PLAINTEXT_PREFIX));

    let first = found.next().ok_or_else(|| {
        format!(
            "kmstool_enclave_cli printed no `{PLAINTEXT_PREFIX}` line; got: {}",
            stdout.trim()
        )
    })?;

    if found.next().is_some() {
        return Err(format!(
            "kmstool_enclave_cli printed more than one `{PLAINTEXT_PREFIX}` line; \
             refusing to guess which one is K_mst"
        ));
    }
    Ok(first.trim())
}

/// Prefix of an enclave refusal that **KMS decided**. The parent classifies on
/// it: only this prefix is a refusal; any other enclave error is not.
pub const KMS_REFUSED_PREFIX: &str = "KMS REFUSED: ";

/// Prefix of an enclave failure that is **not** a KMS decision — the tool died,
/// TLS failed, the proxy was unreachable.
pub const KMSTOOL_FAILED_PREFIX: &str = "KMSTOOL FAILED: ";

/// What `kmstool_enclave_cli` prints when KMS answered, but not with 200.
///
/// ⚠️ Externally owned, like [`PLAINTEXT_PREFIX`], and observed rather than
/// assumed: campaign 02's mutated image logged exactly this line after a signed
/// `TrentService.Decrypt` carrying its attestation. kmstool does not log the
/// response body, so this cannot tell `AccessDenied` from, say, an expired token —
/// which is why M5b's acceptance test releases A with the same credentials,
/// key and ciphertext immediately before B.
pub const KMS_NON_200_MARKER: &str = "Got non-200 answer from KMS";

/// Classify a failed `kmstool decrypt` run into the message the enclave reports.
///
/// ⛔ **A refusal needs positive evidence that KMS was reached and said no:** a
/// normal exit *and* the non-200 marker. Campaign 02's first M5b run had
/// neither — no CA bundle in the image, so TLS failed and kmstool aborted on an
/// assertion (a signal, so no exit code) — and the old code reported that as
/// "KMS refused". For the mutated image that is a false pass: a crash would
/// have satisfied a test whose whole point is that KMS refuses.
///
/// ⛔ **The stderr it forwards is redacted** (campaign 08). kmstool logs its
/// `SigV4` signing at `INFO`, including the session token header and the
/// `Authorization` value, and this string goes to the parent and into every
/// acceptance log. The credentials are the parent's own, so nothing crosses
/// the boundary that was not already outside it; but they were being written
/// to disk by a message whose contract is "a reason safe to show the parent".
#[must_use]
pub fn classify_failure(exit_code: Option<i32>, stderr: &str) -> String {
    let detail = format!(
        "kmstool exit {exit_code:?}\nstderr: {}",
        redact_sigv4(stderr.trim())
    );
    if exit_code.is_some() && stderr.contains(KMS_NON_200_MARKER) {
        format!(
            "{KMS_REFUSED_PREFIX}KMS answered the attested Decrypt with an error status. \
             If the enclave image changed, PCR0 moved and the key policy no longer \
             matches — the mechanism working, not a bug.\n{detail}"
        )
    } else {
        format!(
            "{KMSTOOL_FAILED_PREFIX}kmstool did not get a KMS answer — this is NOT a \
             refusal (TLS, proxy, crash, or configuration).\n{detail}"
        )
    }
}

/// kmstool's stderr with every credential-bearing value removed: the session
/// token header and the `SigV4` `Authorization` line's credential and signature.
/// Plain string tests, no pattern library, because this runs inside the TCB.
#[must_use]
pub fn redact_sigv4(stderr: &str) -> String {
    stderr
        .lines()
        .map(|l| {
            if let Some(at) = l.find("x-amz-security-token:") {
                format!("{}x-amz-security-token:<redacted>", &l[..at])
            } else if l.contains("Credential=") || l.contains("Signature=") {
                "<SigV4 authorization value redacted>".to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Minimal standard-alphabet base64 decoder.
///
/// Written out rather than pulled in: this is inside the trusted computing base,
/// the input is one short line from a tool we already trust to hold the key, and
/// a dependency here would be a dependency on the path that releases `K_mst`.
///
/// # Errors
///
/// On any character outside the standard alphabet, padding and ASCII whitespace
/// excepted.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();

    for c in s.bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = TABLE
            .iter()
            .position(|&t| t == c)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or_else(|| format!("invalid base64 character {:?}", c as char))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or(0));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly what `main.c:514` emits for a 32-byte key, with the trailing
    /// newline `fprintf` adds.
    const REAL_DECRYPT_OUTPUT: &str = "PLAINTEXT: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n";

    /// Campaign 02, mutated image: kmstool reached KMS and was answered 400.
    /// Credential lines omitted; these are the lines that carry the signal.
    const OBSERVED_KMS_REFUSAL: &str = "Connected.\nPOST\n/\n\n\
        Got non-200 answer from KMS: 400\nCould not read response from KMS\n\
        Could not decrypt ciphertext\nCould not decrypt\n";

    /// Campaign 02, first run: no CA bundle, TLS never came up, then an abort.
    const OBSERVED_TLS_ABORT: &str = "[ERROR] [tls-handler] - ctx: configuration error: \
        Error initializing trust store\n[ERROR] [tls-handler] - Failed to set ca_path: \
        (null) and ca_file (null)\n\nFatal error condition occurred in \
        ../source/kms.c:2660: client != ((void *)0)\n";

    #[test]
    fn a_kms_non_200_with_a_normal_exit_is_a_refusal() {
        let m = classify_failure(Some(255), OBSERVED_KMS_REFUSAL);
        assert!(m.starts_with(KMS_REFUSED_PREFIX), "{m}");
    }

    /// The refusal forwards no credential: campaign 08's acceptance log carried
    /// the session token and the `SigV4` signature, verbatim from kmstool.
    #[test]
    fn a_refusal_forwards_no_credential() {
        let stderr = "x-amz-date:20261012T123537Z\n\
                      x-amz-security-token:IQoJb3JpZ2luSECRETTOKEN\n\
                      [INFO] [AuthSigning] - contents\n\
                      AWS4-HMAC-SHA256 Credential=ASIAEXAMPLEKEYID/20261012/us-east-1/kms/aws4_request, \
                      SignedHeaders=host, Signature=254d9687d4c9e895\n\
                      Got non-200 answer from KMS: 400\n\
                      Could not decrypt";
        let m = classify_failure(Some(255), stderr);
        assert!(m.starts_with(KMS_REFUSED_PREFIX), "still classified: {m}");
        for secret in [
            "IQoJb3JpZ2luSECRETTOKEN",
            "ASIAEXAMPLEKEYID",
            "254d9687d4c9e895",
        ] {
            assert!(!m.contains(secret), "forwarded {secret}: {m}");
        }
        assert!(
            m.contains("Got non-200 answer from KMS: 400"),
            "dropped the reason: {m}"
        );
    }

    /// ⭐ The false pass this exists to prevent: the TLS abort was reported as
    /// "KMS refused", which a mutated image would have counted as success.
    #[test]
    fn a_tls_abort_is_a_tool_failure_not_a_refusal() {
        let m = classify_failure(None, OBSERVED_TLS_ABORT);
        assert!(m.starts_with(KMSTOOL_FAILED_PREFIX), "{m}");
        assert!(!m.starts_with(KMS_REFUSED_PREFIX));
    }

    #[test]
    fn the_marker_without_a_normal_exit_is_not_a_refusal() {
        // Killed after KMS answered is still not a clean KMS decision.
        assert!(classify_failure(None, OBSERVED_KMS_REFUSAL).starts_with(KMSTOOL_FAILED_PREFIX));
    }

    #[test]
    fn a_normal_exit_without_the_marker_is_not_a_refusal() {
        assert!(
            classify_failure(Some(1), "could not connect to proxy\n")
                .starts_with(KMSTOOL_FAILED_PREFIX)
        );
    }

    #[test]
    fn the_real_decrypt_output_parses() {
        let b64 = parse_plaintext_line(REAL_DECRYPT_OUTPUT).expect("the documented format");
        let raw = base64_decode(b64).expect("valid base64");
        assert_eq!(raw.len(), 32, "a 32-byte key must decode to 32 bytes");
        assert_eq!(raw, (0u8..32).collect::<Vec<u8>>());
    }

    #[test]
    fn the_prefix_we_used_to_strip_is_not_the_one_the_tool_prints() {
        // ⭐ The regression test for the actual bug. `"KEY PLAINTEXT: "` was
        // stripped for as long as this code existed; against real output it
        // matches nothing, so the enclave refused to start.
        assert!(
            !REAL_DECRYPT_OUTPUT.starts_with("KEY PLAINTEXT: "),
            "if this ever passes, AWS changed the format and the fixture is stale"
        );
        assert!(REAL_DECRYPT_OUTPUT.starts_with(PLAINTEXT_PREFIX));
    }

    #[test]
    fn a_ciphertext_line_is_not_mistaken_for_a_plaintext_line() {
        // `genkey` prints both. We only ever call `decrypt`, but a substring
        // match would happily return the wrong one if that changed.
        let out = "CIPHERTEXT: AAAA\nPLAINTEXT: AQID\n";
        assert_eq!(parse_plaintext_line(out).expect("parses"), "AQID");
    }

    #[test]
    fn unrelated_chatter_on_stdout_is_skipped() {
        let out = "[INFO] connecting to KMS via vsock proxy\nPLAINTEXT: AQID\n";
        assert_eq!(parse_plaintext_line(out).expect("parses"), "AQID");
    }

    #[test]
    fn a_missing_key_line_is_an_error_and_says_what_it_saw() {
        let err = parse_plaintext_line("Could not decrypt ciphertext\n").expect_err("no key line");
        assert!(
            err.contains("Could not decrypt"),
            "error hid the tool's output: {err}"
        );
    }

    #[test]
    fn two_key_lines_are_refused_rather_than_guessed() {
        let err = parse_plaintext_line("PLAINTEXT: AQID\nPLAINTEXT: BAUG\n")
            .expect_err("ambiguous output");
        assert!(err.contains("more than one"), "{err}");
    }

    #[test]
    fn base64_matches_the_rfc4648_vectors() {
        // RFC 4648 §10. Covers all three padding cases, which is where a
        // hand-written decoder gets the bit accounting wrong.
        for (encoded, plain) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            let got = base64_decode(encoded).expect("valid");
            assert_eq!(got, plain.as_bytes(), "decoding {encoded:?}");
        }
    }

    #[test]
    fn base64_rejects_a_character_outside_the_alphabet() {
        // Silent acceptance would turn a corrupted line into a wrong key, and a
        // wrong K_mst produces pseudonyms that match nothing already anchored.
        assert!(base64_decode("AQID!").is_err());
        assert!(
            base64_decode("AQ_D").is_err(),
            "URL-safe base64 is not what the tool emits"
        );
    }
}
