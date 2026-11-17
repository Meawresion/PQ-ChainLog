# PQ-ChainLog

Post-quantum searchable logging with a verifiable chain of custody for digital forensics.

PQ-ChainLog seals each piece of evidence into an encrypted, searchable **Evidence Capsule** and
records everyone who collects, transfers, analyses or accesses it as encrypted, searchable **Custody
Records**. Both planes commit into a three-tier Merkle forest whose per-epoch root is anchored on a
permissioned blockchain (Hyperledger Besu, QBFT). Investigators search under a warrant with a
two-round conjunctive scheme built from symmetric primitives only. Signatures and key transport use
the NIST post-quantum standards: ML-DSA-65, SLH-DSA-SHAKE-192s and ML-KEM-768.

Senior project, Sirindhorn International Institute of Technology (SIIT), Thammasat University.
Authors: Krittapak Jairak, Chuesing Ni, Phurich Siangsoong, Pitinun Wiphumitsitsakul, Somchart Fugkeaw.

---

## Contents

- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Get the code](#get-the-code)
- [Build](#build)
- [Test](#test)
- [Run the demo](#run-the-demo)
- [Prebuilt demo (release)](#prebuilt-demo-release)
- [Experiments](#experiments)
- [Notes](#notes)
- [License](#license)

## Repository layout

The repository is a single Cargo workspace. Run every command below from the repository root.

| Path | What it is |
|---|---|
| `crates/pqcl-primitives` | ML-KEM-768, ML-DSA-65 (liboqs), SLH-DSA-SHAKE-192s (FIPS 205), AES-256-GCM, SHAKE256, with NIST ACVP/CAVP known-answer tests |
| `crates/pqcl-ggm` | GGM-tree range-constrained PRF |
| `crates/pqcl-dsse` | The searchable encryption: `Π_core` (single keyword, forward/backward private), `Π_XT` (two-round conjunctive), `Π_BOOL`, `Π_RANGE`, verified mode, and a plaintext oracle the tests check against |
| `crates/pqcl-forest` | The Merkle forest: per-capsule custody trees (Tier 1) and the per-epoch MMR (Tier 2) |
| `crates/pqcl-capsule` | Evidence Capsule, Custody Record, court disclosure bundle and its verifier |
| `crates/pqcl-sm` | The Secure Module interface: a host-software backend and a PKCS#11 (SoftHSM2) backend |
| `crates/pqcl-warrant` | Warrants, scopes, nullifiers and writer keys |
| `crates/pqcl-pipeline` | The end-to-end system: ingest, custody, transfer, epoch checkpoints, search, retrieval, audit and redaction |
| `crates/pqcl-chainproof` | Receipt and Merkle-Patricia proofs against a live Besu chain |
| `crates/pqcl-nitro` | The AWS Nitro Enclaves backend of the Secure Module |
| `crates/pqcl-investigator` | The investigator's dashboard and the demo (`pqcl-dashboard`) |
| `crates/pqcl-exp`, `crates/pqcl-bench` | The experiment binaries and the results-record writer |
| `crates/pqcl-interop` | Rust-to-Solidity ML-DSA interoperability fixture |
| `baselines/` | Our implementations of the comparison schemes (SDSSE-CQ, DSSE_SKQ, VCFB, the Doris follow-up, MDRSSE, ODXT, Zuo et al., PQ-ABL, GlassDB), the Doris reference container, and `UPGRADES.md`, which records every deviation from the original papers |
| `contracts/` | The anchoring contract `Anchor.sol`, the comparison contracts and the Foundry test suite (ML-DSA-65 verifier gated by ACVP vectors) |
| `besu/` | The pinned Besu image, the four-validator QBFT network used by the tests and experiments, and `besu/demo/`, the one-validator demo chain |
| `forensics/` | The pinned forensic tool container (The Sleuth Kit, tshark, Volatility 3) |
| `zk/` | The SP1 proof-of-warrant guest and host (STARK proofs only), and `zk/demo-proof/`, saved proofs the demo checks against |
| `datasets/` | Download scripts and pinned SHA-256 manifests (no data is stored in git) |
| `results/` | The measurement records behind the report's figures (JSON) |
| `tools/` | The results pipeline: checks the records and draws the figures |
| `aws/`, `nitro/` | Scripts for the measurement instances and the enclave build |
| `scripts/` | `demo.sh`, `softhsm2-init.sh`, `package-release.sh` |
| `xtask/` | `cargo xtask`: the formatting, lint, no-stubs, test and demo gates in one command |

## Requirements

The target is **Linux on x86_64**. The project was developed and tested on Ubuntu 24.04 (running
under WSL2); any recent distribution with the packages below should work.

| Tool | Needed for | Notes |
|---|---|---|
| Rust, via [rustup](https://rustup.rs) | everything | `rust-toolchain.toml` pins 1.97.1; rustup installs it on first use |
| C/C++ compiler, `make`, `cmake`, `clang` and `libclang` | building liboqs | `oqs-sys` compiles liboqs from source and generates bindings with bindgen |
| `pkg-config`, OpenSSL headers, `git`, `curl`, `python3` with `venv` | building, scripts | |
| matplotlib 3.10.8 (`tools/requirements.txt`) | the results pipeline and its self-test | install in a virtual environment, below |
| Docker Engine with the compose plugin | the chain, the forensic container, tests, demo | your user must be able to run `docker` without `sudo` |
| [Foundry](https://book.getfoundry.sh) v1.8.1 (`forge`, `cast`) | compiling the contracts, chain tests | |
| SoftHSM2 | the PKCS#11 tests | |
| `unzip` | optional | `fetch-artefacts.sh` unpacks the RAM image with it, or with Python if absent |
| `protobuf-compiler`, the SP1 toolchain | optional: `zk/` only | not part of the main workspace |

On Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake clang libclang-dev pkg-config libssl-dev \
    git curl python3 python3-venv unzip softhsm2 docker.io docker-compose-v2
sudo usermod -aG docker "$USER"            # then log out and back in

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
curl -L https://foundry.paradigm.xyz | bash
~/.foundry/bin/foundryup --install v1.8.1
export PATH="$HOME/.foundry/bin:$PATH"     # add this line to your shell profile
```

From the repository root (after cloning, below), the Python environment for `tools/`:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r tools/requirements.txt
```

Memory: building the workspace with two parallel jobs stays under about 6 GB; the demo itself needs
about 1 GB. Set `CARGO_BUILD_JOBS=2` on a machine with 8 GB of RAM.

## Get the code

The repository has three git submodules (Foundry's `forge-std`, the ETHDILITHIUM verifier, and the
Doris reference code). Clone with them:

```bash
git clone --recurse-submodules <repository-url> PQ-ChainLog
cd PQ-ChainLog
```

If you already cloned without them: `git submodule update --init --recursive`.

## Build

```bash
cargo build --release --locked          # the whole workspace
forge build --root contracts            # compiles Anchor.sol; the demo and the chain tests deploy it
```

The first build compiles liboqs and takes several minutes.

## Test

Each test checks the code against something independent: published NIST vectors, a plaintext
oracle, a live Besu node or a real HSM interface. A test whose prerequisite is missing **fails with
a message that names it**; none skip.

**1. Prerequisites for the full workspace suite**: the forensic artefacts, the Windows kernel
symbols Volatility needs for the memory image, a SoftHSM2 token and the four-validator chain.

```bash
sh datasets/fetch-artefacts.sh                         # ~680 MB, hash-checked; the pipeline tests ingest these
forensics/run.sh --fetch-symbols datasets/artefacts \
    vol -q -f charlie-2009-12-03.mddramimage windows.info   # once: Microsoft symbol server -> forensics/symbols/
eval "$(scripts/softhsm2-init.sh)"                     # throwaway token under ~/.pqcl-softhsm
(cd besu && ./generate.sh && docker compose up -d)     # QBFT chain on 127.0.0.1:8545
```

**2. Run the suite**, then stop the chain:

```bash
cargo test --workspace --locked --no-fail-fast
(cd besu && docker compose down -v)
```

**3. Optional extra checks**

```bash
forge test --root contracts                            # Solidity suite, incl. the ACVP gate
sh datasets/fetch-enron.sh                             # Enron corpus, ~423 MB download
PQCL_ENRON=$PWD/datasets/enron/maildir \
  cargo test --release -p pqcl-dsse --test corpus -- --ignored   # search vs. the oracle on 20,000 real emails
cargo xtask no-stubs                                   # the "no stubs, no simulation" source gate
python3 tools/mkfigs.py --check results/               # the publication rules over the committed records
cargo xtask ci                                         # fmt, no-stubs, clippy, tests, results pipeline,
                                                       # contracts and the demo walkthrough (needs all of
                                                       # the above, and the .venv active)
```

## Run the demo

The demo is the investigator's dashboard: a local web page bound to `127.0.0.1` that drives the real
system against a live one-validator chain. It has pages for evidence ingestion, the chain of custody
(a timeline of who held each item, with signed handoffs and role checks), warrant-scoped search,
a chain explorer showing exactly what is public on chain, and live performance counters. The
**Guide** page has a step-by-step script.

The evidence is two real public forensic images from [Digital Corpora](https://digitalcorpora.org)
(a camera-card disk image and a packet capture), plus synthetic log lines about a fictional case.

```bash
sh datasets/fetch-artefacts.sh          # ~680 MB, each file checked against datasets/artefacts.sha256
forge build --root contracts            # if not done already
scripts/demo.sh                         # builds, starts the chain, serves http://127.0.0.1:8080/
```

Open <http://127.0.0.1:8080/> in a browser. `Ctrl-C` stops the dashboard and removes the chain.
Set `PQCL_DEMO_PORT` for another port.

To check the whole demo end to end without a browser:

```bash
scripts/demo.sh --walk                  # every step in order on a fresh chain; exits non-zero on a failure
```

The first run builds the forensic container and pulls the Besu image, which takes a few minutes.

The warrant step checks STARK proofs that were produced beforehand on a 32 GB machine
(`zk/demo-proof/`, made with `aws/demo-proof.sh`): proving needs about 13 GB of RAM. Verifying them
live is optional (`target/release/pqcl-dashboard --live-stark`, after
`cargo build --release --bin warrant-demo` in `zk/warrant-host`) and peaks at about 7 GB.

## Prebuilt demo (release)

The release page has `pq-chainlog-demo-<version>-linux-x86_64.tar.gz`: the dashboard as a prebuilt
binary, with the compiled anchor contract and the scripts it needs. It needs only Docker, `curl`
and glibc 2.39 or newer (Ubuntu 24.04 or later, Debian 13 or later). No Rust or Foundry is needed.

```bash
sha256sum -c pq-chainlog-demo-<version>-linux-x86_64.tar.gz.sha256
tar -xzf pq-chainlog-demo-<version>-linux-x86_64.tar.gz
cd pq-chainlog-demo-<version>-linux-x86_64
sh datasets/fetch-artefacts.sh
./run-demo.sh                           # or ./run-demo.sh --walk
```

To build the same bundle from source: `scripts/package-release.sh`. It writes the bundle to
`target/dist/`.

## Experiments

`crates/pqcl-exp` holds one binary per experiment. Each writes a JSON record to `results/<exp>/`
that names the commit, the host and the build it ran on.

| Binary | Measures |
|---|---|
| `exp1` | ingestion throughput and post-quantum overhead |
| `exp2` | conjunctive search latency against SDSSE-CQ, SDSSE-CQ-S, VCFB and the Doris follow-up |
| `exp345` | leakage, epoch compaction, and the Bloom-filter cross-tag set |
| `exp7` | Boolean and range query latency |
| `size` | index size |
| `exp6`, `exp6chain` | anchoring cost, offline and on the Besu network against LEChain |
| `custody` | court disclosure: verifying one capsule's history |
| `tamper` | tamper detection and response |
| `exp8910` | verified mode, custody chain, integrity audit |
| `exp9redact`, `redaction` | court-ordered redaction |

Search experiments read the Enron corpus:

```bash
sh datasets/fetch-enron.sh
PQCL_ENRON=$PWD/datasets/enron/maildir PQCL_EXP2_TIERS=1000 \
  cargo run --release --locked -p pqcl-exp --bin exp2     # one small tier
```

The full-size runs need far more memory than a workstation has. The numbers in the report
come from AWS instances only: `aws/setup-instance.sh` provisions one, `aws/sync-to-instance.sh`
and `aws/run-campaign.sh` run the experiments, and `aws/pull-results.sh` brings the records back.
`tools/mkfigs.py --check results/` applies the publication rules. It refuses any record from a
non-AWS host, a debug build or a modified working tree, so a local run can never become a reported
number.

## Notes

- **No stubs, mocks or simulation.** The chain is a real Besu network, the HSM is a real PKCS#11
  token, and the forensic tools run on real images. `cargo xtask no-stubs` enforces this on the
  source tree.
- **The comparison schemes** were implemented from the original papers. Every interpretation and
  modernisation is recorded in `baselines/UPGRADES.md`.
- **Code comments** cite the project paper's equations and phases (as `draft6`–`draft9`, `eq:…`,
  `Phase N`). They also cite sections of the project's internal design record (`§1…`) and build
  plan (milestones `M…`). Neither internal document is part of this repository.
- **Cited papers** appear in comments by file name (`ref-papers/<name>.pdf`). They are the authors'
  copies of the published papers and are not redistributed here.
- **The measurement records** in `results/` carry the commit identifiers of the development
  repository they were measured in, which predates this one.

## License

Licensed under either of the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
