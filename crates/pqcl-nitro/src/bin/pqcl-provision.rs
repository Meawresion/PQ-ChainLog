//! Parent-side: send a booted enclave its one provisioning message.
//!
//! ```text
//! pqcl-provision --cid <cid> --ciphertext-file <path>
//! ```
//!
//! Reads `PQCL_KMS_REGION` (required), `PQCL_KMS_PROXY_PORT` (default `8000`),
//! and the parent role's credentials from the standard `AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` — `nitro/m5b-acceptance.sh`
//! exports them from the instance metadata service (IMDS, version 2).
//!
//! # Exit codes — the acceptance script branches on these
//!
//! | code | meaning |
//! |---|---|
//! | 0 | provisioned: KMS released `K_mst` and the enclave is serving |
//! | 3 | **refused**: the enclave answered with a refusal, normally KMS declining because PCR0 does not match the key policy |
//! | 1 | anything else: usage, a missing input, or no usable answer |
//!
//! ⚠️ 3 is not "failure" in general. Against a mutated image it is the pass
//! condition, and conflating it with 1 would let a broken run read as a pass.

#![cfg(all(feature = "enclave", target_os = "linux"))]

use std::process::ExitCode;

use pqcl_nitro::Provision;
use pqcl_nitro::host::{ProvisionError, provision};

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is unset"))
}

fn inputs() -> Result<(u32, Provision), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| -> Result<String, String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .ok_or_else(|| format!("missing {name} <value>"))
    };

    let cid: u32 = flag("--cid")?
        .parse()
        .map_err(|e| format!("--cid is not a u32: {e}"))?;
    let ciphertext_path = flag("--ciphertext-file")?;
    let ciphertext_b64 = std::fs::read_to_string(&ciphertext_path)
        .map_err(|e| format!("reading {ciphertext_path}: {e}"))?
        .trim()
        .to_owned();
    if ciphertext_b64.is_empty() {
        return Err(format!("{ciphertext_path} is empty; wrap K_mst first"));
    }
    let proxy_port: u32 = std::env::var("PQCL_KMS_PROXY_PORT")
        .unwrap_or_else(|_| "8000".to_owned())
        .parse()
        .map_err(|e| format!("PQCL_KMS_PROXY_PORT is not a u32: {e}"))?;

    Ok((
        cid,
        Provision {
            region: env("PQCL_KMS_REGION")?,
            proxy_port,
            ciphertext_b64,
            access_key_id: env("AWS_ACCESS_KEY_ID")?,
            secret_access_key: env("AWS_SECRET_ACCESS_KEY")?,
            session_token: env("AWS_SESSION_TOKEN")?,
        },
    ))
}

fn main() -> ExitCode {
    let (cid, p) = match inputs() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("pqcl-provision: {e}");
            return ExitCode::from(1);
        }
    };
    match provision(cid, &p) {
        Ok(()) => {
            println!("PROVISIONED cid={cid}");
            ExitCode::SUCCESS
        }
        Err(ProvisionError::Refused(reason)) => {
            println!("REFUSED cid={cid}: {reason}");
            ExitCode::from(3)
        }
        Err(ProvisionError::EnclaveError(reason)) => {
            println!("ENCLAVE-ERROR cid={cid} (not a refusal): {reason}");
            ExitCode::from(4)
        }
        Err(ProvisionError::Transport(reason)) => {
            eprintln!("pqcl-provision: no usable answer from cid {cid}: {reason}");
            ExitCode::from(1)
        }
    }
}
