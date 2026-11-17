//! The enclave side: a vsock server wrapping the *same* module the host runs.
//!
//! ⛔ **Linux and the `enclave` feature only.** vsock does not exist elsewhere,
//! and a paper build path has no reason to pull it in.

use pqcl_primitives::xof::PrfKey;
use pqcl_sm::host::HostAgentModule;
use vsock::{VsockAddr, VsockListener};

use crate::VSOCK_PORT;
use crate::dispatch::serve_over;
use crate::proto::Provision;
// Framing, the provisioning handshake and the request handler all live
// elsewhere, transport-generic and tested over a real loopback socket; this
// module only binds vsock.
use crate::session::answer_provision;

/// Ask the Nitro Security Module for an attestation document.
///
/// Returns a `COSE_Sign1` document signed by the Nitro hypervisor, carrying this
/// enclave's PCR measurements, the caller's `nonce`, and — when supplied — a
/// public key KMS will encrypt its response to.
///
/// ⛔ **This document is not verified here, and must not be.** The party it has
/// to convince is KMS, which checks it while enforcing the key policy. A second
/// COSE/CBOR verifier in this file would be a weaker checker for a property
/// something else already enforces, and if the two ever disagreed ours would be
/// the wrong one. Ruled in the implementation report.
///
/// ⚠️ **Only runnable inside an enclave.** `/dev/nsm` exists nowhere else, so
/// `nsm_init` returns a negative descriptor on any other machine and this
/// reports that plainly rather than pretending. The first real execution is on
/// the campaign instance.
fn attest(nonce: &[u8], public_key: Option<&[u8]>) -> Result<Vec<u8>, String> {
    use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use serde_bytes::ByteBuf;

    let fd = nsm_init();
    if fd < 0 {
        return Err(
            "could not open /dev/nsm: this process is not running inside a Nitro \
             Enclave. See nitro/README.md."
                .to_owned(),
        );
    }

    let request = NsmRequest::Attestation {
        // Left empty: everything we would put here is already covered by the
        // capsule's own signature, and user_data is attacker-influenced input
        // that the hypervisor copies verbatim.
        user_data: None,
        nonce: Some(ByteBuf::from(nonce.to_vec())),
        public_key: public_key.map(|k| ByteBuf::from(k.to_vec())),
    };

    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        NsmResponse::Attestation { document } => Ok(document),
        NsmResponse::Error(e) => Err(format!("NSM refused the attestation request: {e:?}")),
        other => Err(format!(
            "NSM answered an attestation request with {other:?}, which is not an \
             attestation document"
        )),
    }
}

/// Wait for the parent's one [`Provision`] message, obtain `K_mst` with it,
/// and report the outcome back before returning it.
///
/// ⭐ **The refusal is reported, not just logged.** When the image has changed,
/// PCR0 no longer matches the key policy and KMS refuses. M5b's acceptance test
/// *is* that refusal, so the parent must be able to observe it: the reply is
/// `Response::Error` carrying KMS's reason, and only then does the enclave exit.
///
/// A malformed message is answered and waited past — it is not a key-release
/// attempt. A KMS refusal is final: an enclave whose measurements do not match
/// will never match, so it fails closed rather than inviting retries.
///
/// # Errors
///
/// The outer error is transport (bind/accept); the inner is `unwrap`'s refusal.
pub fn await_provisioning(
    unwrap: impl Fn(&Provision) -> Result<PrfKey, String>,
) -> std::io::Result<Result<PrfKey, String>> {
    let listener = VsockListener::bind(&VsockAddr::new(vsock::VMADDR_CID_ANY, VSOCK_PORT))?;
    eprintln!("pqcl enclave awaiting provisioning on vsock port {VSOCK_PORT}");

    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        // `None`: this connection carried no provisioning attempt (and was
        // answered if it said anything). Keep waiting for one that does.
        if let Some(outcome) = answer_provision(&mut stream, &unwrap) {
            return Ok(outcome);
        }
    }

    Err(std::io::Error::other(
        "provisioning listener closed before any provisioning",
    ))
}

/// Serve requests on `VSOCK_PORT` until the listener fails.
///
/// ⚠️ **The module is built by the caller, not here** (M13 A18). It now carries
/// the enrolled cast as well as `K_mst`, and the cast is a deployment question
/// — which actors this enclave signs for — that the serving loop has no
/// business deciding. `K_mst` itself arrives from a KMS unwrap gated on this
/// enclave's PCR measurements (see `nitro/README.md`), which is what makes the
/// enclave's key the *same* key across restarts, and why KMS is in the
/// recovery TCB.
///
/// # Errors
///
/// Any listener or accept failure.
pub fn serve(module: &HostAgentModule) -> std::io::Result<()> {
    let listener = VsockListener::bind(&VsockAddr::new(vsock::VMADDR_CID_ANY, VSOCK_PORT))?;

    eprintln!("pqcl enclave listening on vsock port {VSOCK_PORT}");

    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                // One bad connection must not take the enclave down: it serves
                // an ingest path that runs for hours.
                eprintln!("accept failed: {e}");
                continue;
            }
        };

        // ⭐ The real NSM here, and only here. Every other caller of
        // `serve_over` passes `dispatch::no_nsm`, which is what this closure
        // itself returns off-enclave.
        serve_over(module, &mut stream, &|nonce: &[u8]| attest(nonce, None));
    }

    Ok(())
}
