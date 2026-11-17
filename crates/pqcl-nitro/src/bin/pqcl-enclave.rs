//! The enclave application — the process that runs *inside* the Nitro Enclave.
//!
//! This is what `nitro/Dockerfile` packages and `nitro-cli build-enclave` turns
//! into an EIF. Its measurement is PCR0, and PCR0 is what the KMS key policy
//! conditions on, so **changing this binary changes which key material AWS will
//! release to it**. That is the whole mechanism.
//!
//! ⛔ Keep it small and keep it boring. Every line here is inside the trusted
//! computing base, and every change moves PCR0.

#![cfg(all(feature = "enclave", target_os = "linux"))]

use pqcl_capsule::Role;
use pqcl_nitro::{Provision, enclave, kms};
use pqcl_pipeline::Agent;
use pqcl_primitives::sig::SoftwareMlDsa;
use pqcl_primitives::xof::PrfKey;
use pqcl_sm::HostAgentModule;

/// Obtain `K_mst` by asking KMS to decrypt a wrapped blob, conditioned on this
/// enclave's attestation.
///
/// # Why a subprocess rather than a Rust KMS client
///
/// ⭐ **`kmstool_enclave_cli` is AWS's supported path, and using it is the
/// correct engineering choice rather than a shortcut.** The `kms:Decrypt` call
/// an enclave makes is not an ordinary one: it carries a `Recipient` parameter
/// holding the attestation document, KMS verifies that document against the key
/// policy, and it returns `CiphertextForRecipient` — an RFC 5652 CMS
/// `EnvelopedData` encrypted under the ephemeral public key the attestation
/// carried. Unwrapping it means parsing CMS and doing RSAES-OAEP.
///
/// ⛔ Hand-rolling that inside the trusted computing base would put a bespoke
/// CMS parser and an RSA implementation on the path that releases the case
/// master key. AWS ships a maintained tool that does exactly this; writing our
/// own would be more code, more attack surface, and no more trustworthy.
///
/// The enclave also has **no network**. `kmstool_enclave_cli` reaches KMS
/// through the parent's `vsock-proxy`, which is why the parent runs one and why
/// `nitro/README.md` sets it up before the enclave starts.
///
/// # Where the inputs come from
///
/// ⛔ **From the parent at boot, over vsock — never from the image.** An
/// earlier version read them from the environment "set by `nitro/Dockerfile`",
/// which nothing set, and which would have meant baking expiring IAM
/// credentials into the EIF and moving PCR0 on every refresh. See
/// [`pqcl_nitro::Provision`].
///
/// Credentials are the parent role's own. They are *not* what authorises the
/// decrypt — the key policy's PCR0 condition is. A stolen credential without
/// the right measurements still gets nothing, which is the property M5b's
/// acceptance test checks.
///
/// ⚠️ **Never runnable off an enclave.** Without `/dev/nsm` the tool cannot
/// attest, so this fails loudly everywhere else. Its first real execution is on
/// the campaign instance.
fn unwrap_k_mst(p: &Provision) -> Result<PrfKey, String> {
    use std::process::Command;

    let proxy_port = p.proxy_port.to_string();
    let (region, ciphertext) = (p.region.as_str(), p.ciphertext_b64.as_str());
    let (akid, skid, token) = (
        p.access_key_id.as_str(),
        p.secret_access_key.as_str(),
        p.session_token.as_str(),
    );

    let out = Command::new("/app/kmstool_enclave_cli")
        // ⚠️ `libnsm.so` is an Amazon Linux 2 library living under /opt, not in
        // the system path — see `nitro/Dockerfile`. Scoping it to this child
        // rather than exporting it image-wide is deliberate: our own binary
        // links Debian's OpenSSL and liboqs, and an AL2 library reaching *it*
        // would be a load-order accident on the path that signs evidence.
        .env("LD_LIBRARY_PATH", "/opt/kmstool/lib")
        .args([
            "decrypt",
            "--region",
            region,
            "--proxy-port",
            &proxy_port,
            "--aws-access-key-id",
            akid,
            "--aws-secret-access-key",
            skid,
            "--aws-session-token",
            token,
            "--ciphertext",
            ciphertext,
        ])
        .output()
        .map_err(|e| format!("could not run kmstool_enclave_cli: {e}"))?;

    if !out.status.success() {
        // ⛔ Classified, not assumed. Only a normal exit with KMS's non-200
        // marker is reported as a refusal; anything else — the TLS abort
        // campaign 02 hit first — is reported as a tool failure, so the
        // mutate-the-image test cannot pass on a crash. See kms::classify_failure.
        return Err(kms::classify_failure(
            out.status.code(),
            &String::from_utf8_lossy(&out.stderr),
        ));
    }

    // The tool prints `PLAINTEXT: <base64>` — see `kms::PLAINTEXT_PREFIX`, which
    // pins the format against AWS's source and is tested in ordinary CI. This
    // file cannot be: it is `cfg`-gated to an enclave build, so anything parsed
    // here is unreachable from `cargo test` and was wrong for exactly that long.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let b64 = kms::parse_plaintext_line(&stdout)?;

    let raw = kms::base64_decode(b64)?;
    let bytes: [u8; pqcl_primitives::LAMBDA_BYTES] = raw.as_slice().try_into().map_err(|_| {
        format!(
            "KMS returned {} bytes but K_mst is {} — the wrapped blob is the wrong key",
            raw.len(),
            pqcl_primitives::LAMBDA_BYTES
        )
    })?;
    Ok(PrfKey::new(bytes))
}

fn main() -> Result<(), Box<dyn core::error::Error>> {
    // ⭐ Fail closed. An enclave that cannot obtain its key must refuse to
    // serve, not fall back to generating one — a locally generated key would
    // produce signatures that verify against nothing and pseudonyms that do not
    // match the ones already anchored. The refusal has already been reported
    // to the parent by `await_provisioning`; exiting is the fail-closed half.
    let k_mst = enclave::await_provisioning(unwrap_k_mst)?
        .map_err(|e| -> Box<dyn core::error::Error> { e.into() })?;

    // The cast this enclave signs for. ⚠️ **Generated at boot, which means a
    // restart changes every actor's verification key** — the same durability
    // gap as `K_mst` had before KMS, and the same answer will be needed. A18's
    // row concedes the other half of this: all four keys live in one enclave
    // on one host, which is declared rather than hidden.
    //
    // ⭐ Enrolled from `pqcl_sm::CAST` by `(role, id)`, the table every harness
    // names actors from, so a harness appending through this enclave asks for
    // actors it holds. It has two custodians, so a bilateral transfer is
    // between two keys (§1br.4).
    let mut defr = None;
    let mut rest = Vec::new();
    for (role, id) in pqcl_sm::CAST {
        let agent = Agent::new(SoftwareMlDsa::generate()?, id, role);
        if role == Role::Defr {
            defr = Some(agent);
        } else {
            rest.push(agent);
        }
    }
    let defr = defr.ok_or("CAST enrols no first responder")?;
    let module = HostAgentModule::new(k_mst, defr).with_actors(rest)?;

    enclave::serve(&module)?;
    Ok(())
}
