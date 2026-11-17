//! Live telemetry for the dashboard's Performance page (the design record
//! §1dc.7).
//!
//! Three sources, all real, none estimated:
//!
//! * **the kernel's own counters** under `/proc` (this process, each of its
//!   threads, each CPU, memory, I/O, network interfaces) and the Besu
//!   container's cgroup files, read by one sampler thread every
//!   [`SAMPLE_EVERY`];
//! * **byte counters at the client ↔ AIS seam**: every update token, cross-tag,
//!   record, capsule and ciphertext the client hands the server, and every
//!   answer it gets back, counted where it crosses (`LoggedStore`,
//!   `append_record`, `seal_artefact`), plus the chain's JSON-RPC traffic;
//! * **a span profiler**: the worker names what it is doing and *for which
//!   side* (investigator's client, evidence store, chain, forensic tool). The
//!   per-side clock answers "how much of this action was the client's work and
//!   how much the store's", which a process CPU counter cannot, because both
//!   sides run on the one worker thread (the AIS is not a separate server in
//!   the demo, [`crate::demo`]).
//!
//! ⛔ Laptop numbers, one validator, a host-software Secure Module. Nothing
//! here reaches a document.

// Telemetry arithmetic: nanosecond and kilobyte counters become percentages
// and rates for a chart. The precision lost converting u64 to f64 is far below
// what a chart can draw.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How often the sampler reads the kernel's counters.
pub const SAMPLE_EVERY: Duration = Duration::from_millis(50);

/// Samples kept: one minute at [`SAMPLE_EVERY`].
const KEEP: usize = 1200;

/// Completed spans kept for the timeline.
const RECENT: usize = 800;

/// Who a span of the worker's time is spent for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The investigator's client: sealing, signing, tokens, decryption, checks.
    Client = 0,
    /// The evidence store (the AIS): storing, index lookups, probe answers.
    Store = 1,
    /// Waiting on the chain's JSON-RPC (transactions, calls, inclusion).
    Chain = 2,
    /// A forensic tool run in its pinned container.
    Tool = 3,
}

const SIDES: usize = 4;
const IDLE: usize = SIDES;
const SIDE_NAMES: [&str; SIDES] = ["client", "store", "chain", "tool"];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn start() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

fn now_ns() -> u64 {
    u64::try_from(start().elapsed().as_nanos()).unwrap_or(u64::MAX)
}

// ------------------------------------------------------------ per-side clock

static SIDE_NS: [AtomicU64; SIDES] = [const { AtomicU64::new(0) }; SIDES];
static CUR_SIDE: AtomicUsize = AtomicUsize::new(IDLE);
static CUR_SINCE: AtomicU64 = AtomicU64::new(0);

/// Charge the time since the last switch to the side that was running, and
/// make `to` the running side. Returns the side that was running.
fn switch(to: usize) -> usize {
    let t = now_ns();
    let prev = CUR_SIDE.swap(to, Relaxed);
    let since = CUR_SINCE.swap(t, Relaxed);
    if prev < SIDES {
        SIDE_NS[prev].fetch_add(t.saturating_sub(since), Relaxed);
    }
    prev
}

/// Cumulative nanoseconds per side, including the running stretch.
fn side_totals() -> [u64; SIDES] {
    let mut out = [0u64; SIDES];
    for (o, a) in out.iter_mut().zip(&SIDE_NS) {
        *o = a.load(Relaxed);
    }
    let cur = CUR_SIDE.load(Relaxed);
    if cur < SIDES {
        out[cur] += now_ns().saturating_sub(CUR_SINCE.load(Relaxed));
    }
    out
}

/// Charges the worker's time to one side until dropped, without a profiler
/// entry. For hot paths (one per index update), where a named span would cost
/// more than the work it names.
#[derive(Debug)]
#[must_use = "the side is charged only while the guard lives"]
pub struct OnSide(usize);

/// Charge time to `side` until the guard drops.
pub fn on(side: Side) -> OnSide {
    OnSide(switch(side as usize))
}

impl Drop for OnSide {
    fn drop(&mut self) {
        switch(self.0);
    }
}

// ------------------------------------------------------------ the seam

/// Which way bytes cross the client ↔ store seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Client → evidence store.
    Up,
    /// Evidence store → client.
    Down,
}

static UP_BYTES: AtomicU64 = AtomicU64::new(0);
static DOWN_BYTES: AtomicU64 = AtomicU64::new(0);
static MESSAGES: AtomicU64 = AtomicU64::new(0);
static RPC_CALLS: AtomicU64 = AtomicU64::new(0);
static RPC_UP: AtomicU64 = AtomicU64::new(0);
static RPC_DOWN: AtomicU64 = AtomicU64::new(0);
static TXS: AtomicU64 = AtomicU64::new(0);
static GAS: AtomicU64 = AtomicU64::new(0);
static TX_BYTES: AtomicU64 = AtomicU64::new(0);

/// Per message kind: (kind, bytes up, bytes down, messages).
static KINDS: Mutex<Vec<(&'static str, u64, u64, u64)>> = Mutex::new(Vec::new());

/// Count one message of `bytes` crossing the seam.
pub fn seam(dir: Dir, kind: &'static str, bytes: usize) {
    let b = bytes as u64;
    match dir {
        Dir::Up => UP_BYTES.fetch_add(b, Relaxed),
        Dir::Down => DOWN_BYTES.fetch_add(b, Relaxed),
    };
    MESSAGES.fetch_add(1, Relaxed);
    let mut k = lock(&KINDS);
    let i = k.iter().position(|e| e.0 == kind).unwrap_or_else(|| {
        k.push((kind, 0, 0, 0));
        k.len() - 1
    });
    match dir {
        Dir::Up => k[i].1 += b,
        Dir::Down => k[i].2 += b,
    }
    k[i].3 += 1;
}

/// Count one JSON-RPC exchange with the node.
pub fn rpc(up: usize, down: usize) {
    RPC_CALLS.fetch_add(1, Relaxed);
    RPC_UP.fetch_add(up as u64, Relaxed);
    RPC_DOWN.fetch_add(down as u64, Relaxed);
}

/// Count one mined transaction.
pub fn tx(gas: u64, bytes: usize) {
    TXS.fetch_add(1, Relaxed);
    GAS.fetch_add(gas, Relaxed);
    TX_BYTES.fetch_add(bytes as u64, Relaxed);
}

// ------------------------------------------------------------ span profiler

#[derive(Debug, Default, Clone, Copy)]
struct Node {
    calls: u64,
    total_ns: u64,
    max_ns: u64,
    side: usize,
}

static TREE: Mutex<Option<HashMap<Vec<&'static str>, Node>>> = Mutex::new(None);
/// A finished span: its path, its side, and when it started and ended (ns).
type SpanEvent = (Vec<&'static str>, usize, u64, u64);

static SPANS: Mutex<VecDeque<SpanEvent>> = Mutex::new(VecDeque::new());

thread_local! {
    static STACK: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

/// One named stretch of the worker's time, charged to a side. Nested spans
/// form the call tree the Performance page draws.
#[derive(Debug)]
#[must_use = "the span measures only while it lives"]
pub struct Span {
    start: u64,
    side: usize,
    prev: usize,
}

/// Open a span named `name`, charged to `side`, until the guard drops.
pub fn span(side: Side, name: &'static str) -> Span {
    STACK.with(|s| s.borrow_mut().push(name));
    let prev = switch(side as usize);
    Span {
        start: now_ns(),
        side: side as usize,
        prev,
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let end = now_ns();
        let took = end.saturating_sub(self.start);
        let path = STACK.with(|s| {
            let mut s = s.borrow_mut();
            let p = s.clone();
            s.pop();
            p
        });
        {
            let mut t = lock(&TREE);
            let n = t
                .get_or_insert_with(HashMap::new)
                .entry(path.clone())
                .or_default();
            n.calls += 1;
            n.total_ns += took;
            n.max_ns = n.max_ns.max(took);
            n.side = self.side;
        }
        {
            let mut r = lock(&SPANS);
            r.push_back((path, self.side, self.start, end));
            while r.len() > RECENT {
                r.pop_front();
            }
        }
        switch(self.prev);
    }
}

/// Forget the call tree and the timeline (the counters keep running).
pub fn reset_profile() {
    *lock(&TREE) = None;
    lock(&SPANS).clear();
}

// ------------------------------------------------------------ the sampler

/// What one tick saw. Rates are per second over the tick.
#[derive(Debug, Clone, Default)]
struct Sample {
    seq: u64,
    /// Milliseconds since the process started.
    t_ms: u64,
    /// This process, percent of one core.
    cpu: f64,
    /// Each CPU's busy percent.
    cpus: Vec<f64>,
    rss_kb: u64,
    hwm_kb: u64,
    sys_used_kb: u64,
    sys_total_kb: u64,
    threads: u64,
    /// `rchar`/`wchar` rates: every read/write syscall, sockets included.
    io_r: f64,
    io_w: f64,
    /// Bytes that reached the block layer.
    disk_r: f64,
    disk_w: f64,
    /// Client → store and store → client, bytes per second.
    seam_up: f64,
    seam_down: f64,
    rpc_up: f64,
    rpc_down: f64,
    /// Loopback interface, bytes per second.
    lo_rx: f64,
    lo_tx: f64,
    /// Each side's share of the tick, 0–1.
    sides: [f64; SIDES],
    besu_cpu: Option<f64>,
    besu_mem_kb: Option<u64>,
    besu_rx: Option<f64>,
    besu_tx: Option<f64>,
}

impl Sample {
    fn json(&self) -> Value {
        let r1 = |x: f64| (x * 10.0).round() / 10.0;
        json!({
            "seq": self.seq, "t": self.t_ms, "cpu": r1(self.cpu),
            "cpus": self.cpus.iter().map(|c| r1(*c)).collect::<Vec<_>>(),
            "rss": self.rss_kb, "hwm": self.hwm_kb, "sys_used": self.sys_used_kb,
            "sys_total": self.sys_total_kb, "threads": self.threads,
            "io_r": self.io_r.round(), "io_w": self.io_w.round(),
            "disk_r": self.disk_r.round(), "disk_w": self.disk_w.round(),
            "up": self.seam_up.round(), "down": self.seam_down.round(),
            "rpc_up": self.rpc_up.round(), "rpc_down": self.rpc_down.round(),
            "lo_rx": self.lo_rx.round(), "lo_tx": self.lo_tx.round(),
            "sides": self.sides.iter().map(|s| (s * 1000.0).round() / 1000.0).collect::<Vec<_>>(),
            "besu_cpu": self.besu_cpu.map(r1), "besu_mem": self.besu_mem_kb,
            "besu_rx": self.besu_rx.map(f64::round), "besu_tx": self.besu_tx.map(f64::round),
        })
    }
}

/// One thread as the last tick saw it.
#[derive(Debug, Clone)]
struct ThreadRow {
    tid: u64,
    name: String,
    state: char,
    cpu: f64,
    total_s: f64,
}

#[derive(Debug, Default)]
struct Telemetry {
    samples: VecDeque<Sample>,
    threads: Vec<ThreadRow>,
    store_bytes: u64,
    store_files: u64,
    besu: Option<String>,
    started_unix: u64,
}

static TELEMETRY: Mutex<Option<Telemetry>> = Mutex::new(None);

/// Start the sampler thread. `store` is the evidence store's payload
/// directory, measured on disk; `container` is the chain node's container.
///
/// # Errors
///
/// The thread cannot be spawned.
pub fn start_sampler(store: PathBuf, container: &str) -> std::io::Result<()> {
    let _ = start();
    *lock(&TELEMETRY) = Some(Telemetry {
        started_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        ..Telemetry::default()
    });
    let container = container.to_owned();
    std::thread::Builder::new()
        .name("perf-sampler".to_owned())
        .spawn(move || sampler(&store, &container))?;
    Ok(())
}

/// CPU counters move in kernel ticks (10 ms at the usual `CLK_TCK` of 100),
/// so over one 50 ms tick a rate can only be a multiple of 20%. CPU rates are
/// therefore taken over a trailing window: [`CPU_WINDOW`] readings back for the
/// process and each core, [`THREAD_WINDOW`] for each thread.
const CPU_WINDOW: usize = 5;
const THREAD_WINDOW: usize = 20;

/// One reading of the tick counters.
struct Reading {
    at: Instant,
    proc: u64,
    cpus: Vec<(u64, u64)>,
    threads: HashMap<u64, u64>,
}

/// Previous readings, to turn counters into rates.
#[derive(Default)]
struct Prev {
    at: Option<Instant>,
    hist: VecDeque<Reading>,
    io: [u64; 4],
    seam: [u64; 4],
    lo: (u64, u64),
    sides: [u64; SIDES],
    besu_usec: Option<u64>,
    besu_net: Option<(u64, u64)>,
}

fn sampler(store: &Path, container: &str) {
    let tck = clock_ticks();
    let mut prev = Prev::default();
    let mut besu: Option<Besu> = None;
    let mut seq = 0u64;
    let mut tick = 0u64;
    loop {
        let t0 = Instant::now();
        if besu.is_none() && tick.is_multiple_of(100) {
            besu = Besu::find(container);
            if let Some(t) = lock(&TELEMETRY).as_mut() {
                t.besu = besu.as_ref().map(|b| b.id.chars().take(12).collect());
            }
        }
        seq += 1;
        let (sample, threads) = read_sample(seq, tck, &mut prev, besu.as_ref());
        if besu.is_some() && sample.besu_mem_kb.is_none() {
            besu = None; // the container went away; look for it again
        }
        let disk = if tick.is_multiple_of(10) {
            Some(dir_size(store))
        } else {
            None
        };
        if let Some(t) = lock(&TELEMETRY).as_mut() {
            t.samples.push_back(sample);
            while t.samples.len() > KEEP {
                t.samples.pop_front();
            }
            t.threads = threads;
            if let Some((b, f)) = disk {
                t.store_bytes = b;
                t.store_files = f;
            }
        }
        tick += 1;
        if let Some(left) = SAMPLE_EVERY.checked_sub(t0.elapsed()) {
            std::thread::sleep(left); // xtask-allow: sleep — the sampler's real cadence between kernel reads
        }
    }
}

#[allow(clippy::too_many_lines)]
fn read_sample(
    seq: u64,
    tck: f64,
    prev: &mut Prev,
    besu: Option<&Besu>,
) -> (Sample, Vec<ThreadRow>) {
    let now = Instant::now();
    let dt = prev.at.map_or(0.0, |a| now.duration_since(a).as_secs_f64());
    let rate = |cur: u64, old: u64| {
        if dt > 0.0 {
            cur.saturating_sub(old) as f64 / dt
        } else {
            0.0
        }
    };
    let mut s = Sample {
        seq,
        t_ms: u64::try_from(start().elapsed().as_millis()).unwrap_or(u64::MAX),
        ..Sample::default()
    };

    // The tick counters' windows: a quarter second back for the process and
    // the cores, a second back for the threads.
    let short = prev.hist.get(prev.hist.len().saturating_sub(CPU_WINDOW));
    let long = prev.hist.front();
    let per_s = |cur: u64, old: u64, then: Instant| {
        let d = now.duration_since(then).as_secs_f64();
        if d > 0.0 {
            cur.saturating_sub(old) as f64 / d
        } else {
            0.0
        }
    };

    // This process.
    let mut proc_ticks = 0;
    if let Some(st) = read("/proc/self/stat").and_then(|t| stat_fields(&t)) {
        proc_ticks = field(&st, 11) + field(&st, 12); // utime + stime
        s.cpu = short.map_or(0.0, |r| per_s(proc_ticks, r.proc, r.at) / tck * 100.0);
        s.threads = field(&st, 17);
    }
    if let Some(status) = read("/proc/self/status") {
        s.rss_kb = kb(&status, "VmRSS:");
        s.hwm_kb = kb(&status, "VmHWM:");
    }
    if let Some(mi) = read("/proc/meminfo") {
        s.sys_total_kb = kb(&mi, "MemTotal:");
        s.sys_used_kb = s.sys_total_kb.saturating_sub(kb(&mi, "MemAvailable:"));
    }

    // Each CPU.
    let mut cpu_rows = Vec::new();
    if let Some(ps) = read("/proc/stat") {
        let rows: Vec<(u64, u64)> = ps
            .lines()
            .filter(|l| l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit))
            .map(|l| {
                let v: Vec<u64> = l
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|x| x.parse().ok())
                    .collect();
                let total: u64 = v.iter().sum();
                let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
                (total, total.saturating_sub(idle))
            })
            .collect();
        let old = short.map_or(&[][..], |r| r.cpus.as_slice());
        s.cpus = rows
            .iter()
            .enumerate()
            .map(|(i, (tot, busy))| {
                old.get(i).map_or(0.0, |(pt, pb)| {
                    let d = tot.saturating_sub(*pt);
                    if d == 0 {
                        0.0
                    } else {
                        busy.saturating_sub(*pb) as f64 / d as f64 * 100.0
                    }
                })
            })
            .collect();
        cpu_rows = rows;
    }

    // I/O: rchar, wchar, read_bytes, write_bytes.
    if let Some(io) = read("/proc/self/io") {
        let cur = [
            kv(&io, "rchar:"),
            kv(&io, "wchar:"),
            kv(&io, "read_bytes:"),
            kv(&io, "write_bytes:"),
        ];
        s.io_r = rate(cur[0], prev.io[0]);
        s.io_w = rate(cur[1], prev.io[1]);
        s.disk_r = rate(cur[2], prev.io[2]);
        s.disk_w = rate(cur[3], prev.io[3]);
        prev.io = cur;
    }

    // The seam and the chain RPC.
    let seam = [
        UP_BYTES.load(Relaxed),
        DOWN_BYTES.load(Relaxed),
        RPC_UP.load(Relaxed),
        RPC_DOWN.load(Relaxed),
    ];
    s.seam_up = rate(seam[0], prev.seam[0]);
    s.seam_down = rate(seam[1], prev.seam[1]);
    s.rpc_up = rate(seam[2], prev.seam[2]);
    s.rpc_down = rate(seam[3], prev.seam[3]);
    prev.seam = seam;

    // Loopback.
    if let Some(nd) = read("/proc/net/dev")
        && let Some((rx, tx)) = iface(&nd, "lo")
    {
        s.lo_rx = rate(rx, prev.lo.0);
        s.lo_tx = rate(tx, prev.lo.1);
        prev.lo = (rx, tx);
    }

    // The worker's time by side.
    let sides = side_totals();
    if dt > 0.0 {
        for ((out, cur), old) in s.sides.iter_mut().zip(sides).zip(prev.sides) {
            *out = (cur.saturating_sub(old) as f64 / 1e9 / dt).min(1.0);
        }
    }
    prev.sides = sides;

    // Threads.
    let mut threads = Vec::new();
    let mut seen = HashMap::new();
    if let Ok(dir) = std::fs::read_dir("/proc/self/task") {
        for e in dir.flatten() {
            let Some(tid) = e.file_name().to_str().and_then(|t| t.parse::<u64>().ok()) else {
                continue;
            };
            let Some(text) = read(&format!("/proc/self/task/{tid}/stat")) else {
                continue;
            };
            let name = text
                .find('(')
                .zip(text.rfind(')'))
                .map(|(a, b)| text[a + 1..b].to_owned())
                .unwrap_or_default();
            let Some(st) = stat_fields(&text) else {
                continue;
            };
            let ticks = field(&st, 11) + field(&st, 12);
            let cpu = long
                .and_then(|r| r.threads.get(&tid).map(|old| (r.at, *old)))
                .map_or(0.0, |(then, old)| per_s(ticks, old, then) / tck * 100.0);
            seen.insert(tid, ticks);
            threads.push(ThreadRow {
                tid,
                name,
                state: st.first().and_then(|x| x.chars().next()).unwrap_or('?'),
                cpu,
                total_s: ticks as f64 / tck,
            });
        }
    }
    prev.hist.push_back(Reading {
        at: now,
        proc: proc_ticks,
        cpus: cpu_rows,
        threads: seen,
    });
    while prev.hist.len() > THREAD_WINDOW {
        prev.hist.pop_front();
    }
    threads.sort_by(|a, b| {
        b.cpu
            .total_cmp(&a.cpu)
            .then(b.total_s.total_cmp(&a.total_s))
    });

    // The chain node's container.
    if let Some(b) = besu {
        if let Some(usec) = read(&b.cg("cpu.stat")).map(|t| kv(&t, "usage_usec")) {
            s.besu_cpu = prev.besu_usec.map(|old| rate(usec, old) / 1e6 * 100.0);
            prev.besu_usec = Some(usec);
        }
        s.besu_mem_kb = read(&b.cg("memory.current"))
            .and_then(|t| t.trim().parse::<u64>().ok())
            .map(|v| v / 1024);
        if let Some((rx, tx)) =
            read(&format!("/proc/{}/net/dev", b.pid)).and_then(|t| iface(&t, "eth0"))
        {
            if let Some((orx, otx)) = prev.besu_net {
                s.besu_rx = Some(rate(rx, orx));
                s.besu_tx = Some(rate(tx, otx));
            }
            prev.besu_net = Some((rx, tx));
        }
    } else {
        prev.besu_usec = None;
        prev.besu_net = None;
    }

    prev.at = Some(now);
    (s, threads)
}

/// The chain node's container, found once by name.
struct Besu {
    id: String,
    pid: u64,
    cgroup: PathBuf,
}

impl Besu {
    fn find(name: &str) -> Option<Self> {
        let out = std::process::Command::new("docker")
            .args(["inspect", "-f", "{{.Id}} {{.State.Pid}}", name])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut it = text.split_whitespace();
        let id = it.next()?.to_owned();
        let pid = it.next()?.parse().ok()?;
        let cgroup = [
            format!("/sys/fs/cgroup/system.slice/docker-{id}.scope"),
            format!("/sys/fs/cgroup/docker/{id}"),
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.join("memory.current").exists())?;
        Some(Self { id, pid, cgroup })
    }

    fn cg(&self, file: &str) -> String {
        self.cgroup.join(file).to_string_lossy().into_owned()
    }
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// The fields of a `stat` line after the `(comm)`, so field 0 is the state.
fn stat_fields(text: &str) -> Option<Vec<String>> {
    let rest = &text[text.rfind(')')? + 1..];
    Some(rest.split_whitespace().map(str::to_owned).collect())
}

fn field(f: &[String], i: usize) -> u64 {
    f.get(i).and_then(|x| x.parse().ok()).unwrap_or(0)
}

fn kb(text: &str, key: &str) -> u64 {
    kv(text, key)
}

fn kv(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn iface(text: &str, name: &str) -> Option<(u64, u64)> {
    text.lines().find_map(|l| {
        let (n, rest) = l.split_once(':')?;
        if n.trim() != name {
            return None;
        }
        let v: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        Some((*v.first()?, *v.get(8)?))
    })
}

fn clock_ticks() -> f64 {
    // `getconf CLK_TCK`, without libc. Linux on x86-64 and arm64 uses 100.
    std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<f64>()
                .ok()
        })
        .filter(|t| *t > 0.0)
        .unwrap_or(100.0)
}

fn dir_size(dir: &Path) -> (u64, u64) {
    let mut bytes = 0;
    let mut files = 0;
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                todo.push(e.path());
            } else {
                bytes += m.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

// ------------------------------------------------------------ the page

/// Everything the Performance page draws after sample `since`.
#[must_use]
pub fn snapshot(since: u64) -> Value {
    let guard = lock(&TELEMETRY);
    let Some(t) = guard.as_ref() else {
        return json!({"running": false});
    };
    let samples: Vec<Value> = t
        .samples
        .iter()
        .filter(|s| s.seq > since)
        .map(Sample::json)
        .collect();
    let threads: Vec<Value> = t
        .threads
        .iter()
        .map(|r| json!({"tid": r.tid, "name": r.name, "state": r.state.to_string(),
                        "cpu": (r.cpu * 10.0).round() / 10.0, "total_s": (r.total_s * 100.0).round() / 100.0}))
        .collect();
    let store = json!({"bytes": t.store_bytes, "files": t.store_files});
    let besu = t.besu.clone();
    let started = t.started_unix;
    drop(guard);

    let kinds: Vec<Value> = lock(&KINDS)
        .iter()
        .map(|(k, u, d, n)| json!({"kind": k, "up": u, "down": d, "messages": n}))
        .collect();
    let totals = side_totals();
    json!({
        "running": true,
        "every_ms": SAMPLE_EVERY.as_millis() as u64,
        "started": started,
        "samples": samples,
        "threads": threads,
        "store_disk": store,
        "besu": besu,
        "seam": {"up": UP_BYTES.load(Relaxed), "down": DOWN_BYTES.load(Relaxed),
                 "messages": MESSAGES.load(Relaxed), "kinds": kinds},
        "chain": {"rpc_calls": RPC_CALLS.load(Relaxed), "rpc_up": RPC_UP.load(Relaxed),
                  "rpc_down": RPC_DOWN.load(Relaxed), "txs": TXS.load(Relaxed),
                  "gas": GAS.load(Relaxed), "tx_bytes": TX_BYTES.load(Relaxed)},
        "side_ms": SIDE_NAMES.iter().zip(totals).map(|(n, ns)| json!([n, ns / 1_000_000])).collect::<Vec<_>>(),
    })
}

/// The call tree and the recent-span timeline.
#[must_use]
pub fn profile() -> Value {
    let tree: Vec<Value> = lock(&TREE).as_ref().map_or_else(Vec::new, |t| {
        t.iter()
            .map(|(path, n)| {
                json!({"path": path, "calls": n.calls, "total_us": n.total_ns / 1000,
                       "max_us": n.max_ns / 1000, "side": SIDE_NAMES.get(n.side).copied().unwrap_or("idle")})
            })
            .collect()
    });
    let spans: Vec<Value> = lock(&SPANS)
        .iter()
        .map(|(path, side, a, b)| {
            json!({"path": path, "side": SIDE_NAMES.get(*side).copied().unwrap_or("idle"),
                   "start_us": a / 1000, "end_us": b / 1000})
        })
        .collect();
    json!({"tree": tree, "spans": spans, "now_us": now_ns() / 1000})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_nest_into_a_tree_and_charge_their_side() {
        reset_profile();
        let before = side_totals();
        {
            let _a = span(Side::Client, "outer-test");
            let _b = span(Side::Store, "inner-test");
            let mut x = 0u64;
            for i in 0..200_000u64 {
                x = x.wrapping_mul(31).wrapping_add(i);
            }
            assert_ne!(x, 1);
        }
        let after = side_totals();
        assert!(after[Side::Store as usize] > before[Side::Store as usize]);
        let p = profile();
        let paths: Vec<String> = p["tree"]
            .as_array()
            .map(|t| t.iter().map(|n| n["path"].to_string()).collect())
            .unwrap_or_default();
        assert!(
            paths.iter().any(|p| p == r#"["outer-test","inner-test"]"#),
            "{paths:?}"
        );
        assert_eq!(CUR_SIDE.load(Relaxed), IDLE);
    }

    #[test]
    fn proc_parsers_read_the_kernel_formats() {
        let stat = "123 (demo worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18";
        let f = stat_fields(stat).unwrap_or_default();
        assert_eq!(f[0], "S");
        assert_eq!(field(&f, 11), 11);
        let dev = "Inter-|...\n face |bytes\n    lo: 100 2 0 0 0 0 0 0 200 3 0 0 0 0 0 0\n  eth0: 1 1 0 0 0 0 0 0 9 1 0 0 0 0 0 0";
        assert_eq!(iface(dev, "lo"), Some((100, 200)));
        assert_eq!(kv("VmRSS:\t  4096 kB\n", "VmRSS:"), 4096);
    }
}
