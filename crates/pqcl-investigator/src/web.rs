//! The dashboard's HTTP surface: a rendering surface on loopback, nothing more.
//!
//! ⛔ **Bound to `127.0.0.1` and nowhere else, with no option to change it.**
//! This is not a web app the AIS serves (plan M8b, design §13.1): the browser
//! draws, and every decryption, traversal and verification happens in this
//! process, which holds the case keys. An address flag would be the first step
//! towards a hosted custody dashboard, which is exactly the thing that would
//! make the confidentiality claim decorative. Reaching it from another machine
//! is an SSH tunnel to this loopback port, which keeps that true.
//!
//! **One worker owns the case**. The demo state
//! is created inside a single worker thread and never leaves it; the HTTP side
//! sends it commands over a channel and reads a JSON snapshot it publishes. So
//! a slow action (an SLH-DSA co-signature, a forensic tool run) never freezes
//! the page: the page keeps polling the snapshot, which says what is running.
//! The worker runs the warm-up first, before any command.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};

use crate::demo::{Config, Demo, WARM_UP};

const INDEX: &str = include_str!("../assets/index.html");

/// How often the worker refreshes the snapshot when idle, so the block height
/// and the badges stay current without a click.
const REFRESH: Duration = Duration::from_secs(2);

enum Cmd {
    /// The walkthrough's next step.
    Step(String),
    /// A corner action, with its JSON body.
    Act(String, Value),
}

struct Job {
    cmd: Cmd,
    reply: mpsc::Sender<Value>,
}

struct Shared {
    /// The last state the worker published.
    snapshot: Mutex<Value>,
    /// What the worker is doing now, if anything.
    busy: Mutex<Option<String>>,
    /// Why the warm-up stopped, if it failed.
    warm_error: Mutex<Option<String>>,
    jobs: Mutex<mpsc::Sender<Job>>,
}

/// Serve the dashboard on `127.0.0.1:port` until the process exits. With
/// `warm_up`, the worker first runs [`WARM_UP`] and labels it "pre-run".
///
/// # Errors
///
/// The port cannot be bound, or the worker thread cannot start.
pub fn serve(cfg: Config, port: u16, warm_up: bool) -> std::io::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
    let bound = listener.local_addr()?;
    if !bound.ip().is_loopback() {
        return Err(std::io::Error::other(
            "the dashboard must bind loopback only",
        ));
    }
    let (tx, rx) = mpsc::channel::<Job>();
    let shared = Arc::new(Shared {
        snapshot: Mutex::new(json!({})),
        busy: Mutex::new(Some("starting".to_owned())),
        warm_error: Mutex::new(None),
        jobs: Mutex::new(tx),
    });
    // The Performance page's sampler: kernel counters every 50 ms, the
    // evidence store's directory on disk, and the chain node's container.
    crate::perf::start_sampler(cfg.store.clone(), "pqcl-demo-besu")?;
    // The Chain page's explorer: reads the node like any auditor would, and
    // decodes with the ABI of the artefact the demo deploys.
    crate::explorer::start(
        &cfg.rpc,
        cfg.repo.join("contracts/out/Anchor.sol/Anchor.json"),
    )?;
    let for_worker = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("demo-worker".to_owned())
        .spawn(move || worker(cfg, warm_up, &rx, &for_worker))?;
    eprintln!("dashboard: http://{bound}/  (loopback only)");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let sh = Arc::clone(&shared);
                let spawned =
                    std::thread::Builder::new()
                        .name("http".to_owned())
                        .spawn(move || {
                            if let Err(e) = handle(s, &sh) {
                                eprintln!("request failed: {e}");
                            }
                        });
                if let Err(e) = spawned {
                    eprintln!("could not start a request thread: {e}");
                }
            }
            Err(e) => eprintln!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// The only thread that touches the case.
fn worker(cfg: Config, warm_up: bool, rx: &mpsc::Receiver<Job>, shared: &Shared) {
    let mut demo = Demo::new(cfg);
    if warm_up {
        demo.set_warming(true);
        for step in WARM_UP {
            *lock(&shared.busy) = Some(format!("warm-up: {step}"));
            if let Err(e) = demo.run(step) {
                eprintln!("warm-up step {step} failed: {e}");
                *lock(&shared.warm_error) = Some(format!("warm-up step {step} failed: {e}"));
                break;
            }
            publish(&demo, shared);
        }
        demo.set_warming(false);
    }
    *lock(&shared.busy) = None;
    publish(&demo, shared);
    loop {
        match rx.recv_timeout(REFRESH) {
            Ok(job) => {
                let label = match &job.cmd {
                    Cmd::Step(s) => format!("step: {s}"),
                    Cmd::Act(a, _) => format!("action: {a}"),
                };
                *lock(&shared.busy) = Some(label);
                let out = match job.cmd {
                    Cmd::Step(s) => demo.run(&s),
                    Cmd::Act(a, b) => demo.act(&a, &b),
                };
                let reply = match out {
                    Ok(v) => json!({"ok": true, "result": v}),
                    Err(e) => json!({"ok": false, "error": e}),
                };
                *lock(&shared.busy) = None;
                publish(&demo, shared);
                // The requester may have gone away; the result is in the log.
                let _ = job.reply.send(reply);
            }
            Err(RecvTimeoutError::Timeout) => publish(&demo, shared),
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn publish(demo: &Demo, shared: &Shared) {
    let state = demo.state();
    *lock(&shared.snapshot) = state;
}

/// Hand a command to the worker and wait for its answer.
fn submit(shared: &Shared, cmd: Cmd) -> Value {
    let (reply, answer) = mpsc::channel();
    let sent = lock(&shared.jobs).send(Job { cmd, reply });
    if sent.is_err() {
        return json!({"ok": false, "error": "the demo worker has stopped"});
    }
    answer
        .recv()
        .unwrap_or_else(|_| json!({"ok": false, "error": "the demo worker stopped mid-action"}))
}

fn handle(mut stream: TcpStream, shared: &Shared) -> std::io::Result<()> {
    // Refuse anything that did not come from this machine, belt and braces.
    if !stream.peer_addr()?.ip().is_loopback() {
        return respond(&mut stream, 403, "text/plain", b"loopback only");
    }
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length.min(1 << 16)];
    reader.read_exact(&mut body)?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    match (method, path) {
        ("GET", "/") => respond(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            INDEX.as_bytes(),
        ),
        ("GET", "/api/state") => {
            let mut state = lock(&shared.snapshot).clone();
            state["busy"] = json!(*lock(&shared.busy));
            state["warm_error"] = json!(*lock(&shared.warm_error));
            respond(
                &mut stream,
                200,
                "application/json",
                state.to_string().as_bytes(),
            )
        }
        ("GET", "/api/perf") => {
            let since = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("since="))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let v = crate::perf::snapshot(since);
            respond(
                &mut stream,
                200,
                "application/json",
                v.to_string().as_bytes(),
            )
        }
        ("GET", "/api/chain") => {
            let v = crate::explorer::snapshot();
            respond(
                &mut stream,
                200,
                "application/json",
                v.to_string().as_bytes(),
            )
        }
        ("GET", "/api/profile") => {
            let v = crate::perf::profile();
            respond(
                &mut stream,
                200,
                "application/json",
                v.to_string().as_bytes(),
            )
        }
        ("POST", "/api/profile/reset") => {
            crate::perf::reset_profile();
            reply(&mut stream, &json!({"ok": true}))
        }
        ("POST", p) if p.starts_with("/api/step/") => {
            let step = p["/api/step/".len()..].to_owned();
            let v = submit(shared, Cmd::Step(step));
            reply(&mut stream, &v)
        }
        ("POST", p) if p.starts_with("/api/act/") => {
            let action = p["/api/act/".len()..].to_owned();
            let args: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let v = submit(shared, Cmd::Act(action, args));
            reply(&mut stream, &v)
        }
        _ => respond(&mut stream, 404, "text/plain", b"not found"),
    }
}

fn reply(stream: &mut TcpStream, v: &Value) -> std::io::Result<()> {
    let code = if v["ok"] == true { 200 } else { 409 };
    respond(stream, code, "application/json", v.to_string().as_bytes())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicked action must not take the dashboard down with it.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn respond(stream: &mut TcpStream, code: u16, kind: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Conflict",
    };
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}
