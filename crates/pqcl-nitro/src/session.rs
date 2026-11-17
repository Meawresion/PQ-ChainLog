//! One exchange over a byte stream: framing, the provisioning handshake, and
//! how the parent classifies its outcome — **independent of the transport.**
//!
//! ⭐ **Why this is split out of `enclave`/`host`.** Those modules are
//! vsock-only and `enclave`-feature-only, and vsock has no loopback on the
//! development box (WSL2's kernel refuses CID 1). Left there, the provisioning
//! handshake — the path M5b's acceptance test runs through — would have had its
//! first execution on a billing instance, and CI's default test run could not
//! reach it at all. Here it is generic over `Read + Write`, always compiled, and
//! tested over a real loopback socket. The vsock modules only bind and connect.

use std::io::{Read, Write};

use crate::proto::{MAX_FRAME, Provision, Response};

/// Read one length-prefixed frame, refusing any announced length over
/// [`MAX_FRAME`].
///
/// ⚠️ The cap is load-bearing in both directions: the parent is outside the
/// boundary, and without it could announce a 4 GiB message and make a
/// fixed-memory enclave allocate it.
///
/// # Errors
///
/// Any read failure, or an oversized announcement.
pub fn read_frame<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME}-byte limit"),
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write one length-prefixed frame.
///
/// # Errors
///
/// Any write failure.
pub fn write_frame<W: Write>(stream: &mut W, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&crate::frame(payload))?;
    stream.flush()
}

/// Write one framed payload and read one framed [`Response`].
///
/// # Errors
///
/// A transport failure or a malformed response, as text.
pub fn exchange<S: Read + Write>(stream: &mut S, payload: &[u8]) -> Result<Response, String> {
    write_frame(stream, payload).map_err(|e| format!("enclave write: {e}"))?;
    let buf = read_frame(stream).map_err(|e| format!("enclave read: {e}"))?;
    Response::decode(&buf).map_err(|e| format!("malformed response: {e}"))
}

/// Why provisioning did not succeed. The two cases are kept apart because
/// M5b's acceptance test **expects** one of them: after the image is mutated,
/// `Refused` is the pass condition and `Transport` is a broken run.
#[derive(Debug)]
pub enum ProvisionError {
    /// The enclave answered that **KMS** refused — its reason carries
    /// [`crate::kms::KMS_REFUSED_PREFIX`], which the enclave sets only with
    /// positive evidence that KMS was reached and said no.
    Refused(String),
    /// The enclave answered with an error that is **not** a KMS refusal: kmstool
    /// failed, TLS failed, a malformed message. Never a pass for the mutated
    /// image — that is the false pass campaign 02 exposed.
    EnclaveError(String),
    /// No usable answer: the peer was unreachable, or the reply was malformed
    /// or unexpected.
    Transport(String),
}

/// Parent side: send `p` and classify the answer.
///
/// # Errors
///
/// [`ProvisionError::Refused`] if the enclave answered with a refusal,
/// [`ProvisionError::Transport`] for anything else.
pub fn provision_over<S: Read + Write>(
    stream: &mut S,
    p: &Provision,
) -> Result<(), ProvisionError> {
    match exchange(stream, &p.encode()).map_err(ProvisionError::Transport)? {
        Response::Provisioned => Ok(()),
        Response::Error(reason) if reason.starts_with(crate::kms::KMS_REFUSED_PREFIX) => {
            Err(ProvisionError::Refused(reason))
        }
        Response::Error(reason) => Err(ProvisionError::EnclaveError(reason)),
        other => Err(ProvisionError::Transport(format!(
            "enclave answered provisioning with {other:?}"
        ))),
    }
}

/// Enclave side: answer one connection's provisioning attempt.
///
/// Returns `None` when the connection carried no provisioning attempt — it
/// closed, overran the frame cap, or sent something that is not a
/// [`Provision`] (which is answered with an error). `unwrap` is **not called**
/// in any of those cases. Otherwise returns `unwrap`'s outcome, after reporting
/// it to the parent: `Provisioned`, or the refusal's reason.
pub fn answer_provision<S, K>(
    stream: &mut S,
    unwrap: impl Fn(&Provision) -> Result<K, String>,
) -> Option<Result<K, String>>
where
    S: Read + Write,
{
    let payload = read_frame(stream).ok()?;
    let provision = match Provision::decode(&payload) {
        Ok(p) => p,
        Err(e) => {
            let reply = Response::Error(format!("expected a provisioning message: {e}"));
            let _ = write_frame(stream, &reply.encode());
            return None;
        }
    };
    let outcome = unwrap(&provision);
    let reply = match &outcome {
        Ok(_) => Response::Provisioned,
        Err(reason) => Response::Error(reason.clone()),
    };
    // Best effort: the outcome stands whether or not the parent heard it.
    let _ = write_frame(stream, &reply.encode());
    Some(outcome)
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use super::*;
    use crate::proto::Request;

    fn provision() -> Provision {
        Provision {
            region: "us-east-1".to_owned(),
            proxy_port: 8000,
            ciphertext_b64: "AQIDBA==".to_owned(),
            access_key_id: "AKIA-FIXTURE".to_owned(),
            secret_access_key: "secret-fixture-value".to_owned(),
            session_token: "token-fixture-value".to_owned(),
        }
    }

    /// A real loopback socket pair — not an in-memory buffer — so framing is
    /// exercised across an actual stream with its own buffering.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    #[test]
    fn a_release_is_reported_as_provisioned() {
        let (mut client, mut server) = pair();
        let enclave = thread::spawn(move || {
            answer_provision(&mut server, |p| {
                assert_eq!(
                    p,
                    &provision(),
                    "the enclave must receive exactly what was sent"
                );
                Ok::<u8, String>(42)
            })
        });
        assert!(provision_over(&mut client, &provision()).is_ok());
        assert_eq!(enclave.join().expect("enclave thread"), Some(Ok(42)));
    }

    /// ⭐ The M5b pass condition, end to end: a KMS refusal inside the enclave
    /// must reach the parent as `Refused` carrying the reason — never as
    /// `Transport`, which the acceptance script reads as a broken run.
    #[test]
    fn a_kms_refusal_reaches_the_parent_as_refused() {
        let (mut client, mut server) = pair();
        let enclave = thread::spawn(move || {
            answer_provision(&mut server, |_| {
                Err::<u8, String>(crate::kms::classify_failure(
                    Some(255),
                    "Got non-200 answer from KMS: 400\nCould not decrypt\n",
                ))
            })
        });
        match provision_over(&mut client, &provision()) {
            Err(ProvisionError::Refused(reason)) => assert!(reason.contains("400"), "{reason}"),
            other => panic!("expected Refused, got {other:?}"),
        }
        assert!(matches!(
            enclave.join().expect("enclave thread"),
            Some(Err(_))
        ));
    }

    /// ⭐ The campaign 02 false pass, end to end: a kmstool crash must reach
    /// the parent as `EnclaveError`, never as `Refused`.
    #[test]
    fn a_kmstool_crash_reaches_the_parent_as_an_enclave_error_not_a_refusal() {
        let (mut client, mut server) = pair();
        let enclave = thread::spawn(move || {
            answer_provision(&mut server, |_| {
                Err::<u8, String>(crate::kms::classify_failure(
                    None,
                    "Error initializing trust store\nFatal error condition occurred\n",
                ))
            })
        });
        match provision_over(&mut client, &provision()) {
            Err(ProvisionError::EnclaveError(reason)) => {
                assert!(reason.contains("NOT a refusal"), "{reason}");
            }
            other => panic!("expected EnclaveError, got {other:?}"),
        }
        let _ = enclave.join();
    }

    #[test]
    fn a_non_provisioning_message_is_answered_and_never_unwrapped() {
        let (mut client, mut server) = pair();
        let called = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&called);
        let enclave = thread::spawn(move || {
            answer_provision(&mut server, move |_| {
                flag.store(true, Ordering::SeqCst);
                Ok::<u8, String>(0)
            })
        });
        let reply = exchange(&mut client, &Request::DefrPublicKey.encode()).expect("an answer");
        assert!(
            matches!(reply, Response::Error(ref m) if m.contains("provisioning")),
            "{reply:?}"
        );
        assert_eq!(enclave.join().expect("enclave thread"), None);
        assert!(
            !called.load(Ordering::SeqCst),
            "unwrap ran on a non-provisioning message"
        );
    }

    #[test]
    fn an_oversized_announcement_is_refused_before_allocation() {
        let (mut client, mut server) = pair();
        let called = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&called);
        let enclave = thread::spawn(move || {
            answer_provision(&mut server, move |_| {
                flag.store(true, Ordering::SeqCst);
                Ok::<u8, String>(0)
            })
        });
        let too_big = u32::try_from(MAX_FRAME + 1)
            .expect("fits u32")
            .to_be_bytes();
        client.write_all(&too_big).expect("write header");
        assert_eq!(enclave.join().expect("enclave thread"), None);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn a_peer_that_hangs_up_is_transport_not_refused() {
        let (mut client, server) = pair();
        drop(server);
        assert!(matches!(
            provision_over(&mut client, &provision()),
            Err(ProvisionError::Transport(_))
        ));
    }
}
