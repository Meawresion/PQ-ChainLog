# The enclave image. `nitro-cli build-enclave` turns this into an EIF, and the
# EIF's measurement is PCR0.
#
# ⭐ **Every byte here is in the trusted computing base, and every change moves
# PCR0.** A moved PCR0 means the KMS key policy no longer matches, so AWS stops
# releasing `K_mst` — which is exactly the intended behaviour and exactly why
# this file is as small as it is. Adding a debug shell here is not a
# convenience; it is a TCB expansion that silently invalidates the deployment.
#
# ⚠️ Pinned by digest, like every other image in this repo, for the stronger
# reason: an unpinned base would make PCR0 depend on when you happened to build.
# The measurement has to be a property of the source, not of the calendar.
#
# Build:  nitro/build-eif.sh

# Resolved from an actual `docker pull`, 2026-09-13 — not recalled, and not
# inferred from a tag. The toolchain is 1.97.1 to match `rust-toolchain.toml`; a
# mismatch there would move PCR0 for a reason unrelated to our source.
FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build

# ⚠️ **liboqs is built from source by `oqs-sys`, and `rust:slim` ships none of
# what that needs.** The list is the same one `implementation-plan.md` §P0.3
# records for the host, including the detail that bit someone there too:
# `libclang-dev`, not just `clang`, because `oqs-sys` runs bindgen. Without
# these the build dies with exit 101 part-way through the dependency graph, and
# the message points at a build script rather than at a missing package.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends         build-essential clang libclang-dev pkg-config libssl-dev cmake ninja-build     && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# `--features enclave` pulls in vsock; `--locked` so the build is the lockfile's
# and not whatever resolved today.
RUN cargo build --release --locked \
        --package pqcl-nitro \
        --features enclave \
        --bin pqcl-enclave

# ⭐ A scratch-adjacent final stage: the enclave needs no shell, no package
# manager and no init. The smaller this is, the less there is to measure and the
# less there is to go wrong inside the boundary.
# ---------------------------------------------------------------------------
# `kmstool_enclave_cli` — AWS's own tool for the attested `kms:Decrypt`.
#
# ⭐ **Used rather than reimplemented, and that is a TCB argument.** The call an
# enclave makes carries a `Recipient` holding the attestation document, and KMS
# answers with `CiphertextForRecipient`: an RFC 5652 CMS EnvelopedData under
# RSAES-OAEP. Unwrapping it needs a CMS parser and an RSA implementation *on the
# path that releases the case master key*. Writing our own would be more code
# and more attack surface inside the measurement, not less.
#
# ⚠️ It does add to PCR0. A real cost, accepted deliberately: the alternative is
# bespoke cryptographic parsing in the same place.
#
# ---------------------------------------------------------------------------
# ⛔ **CORRECTED 2026-09-16 — the image this used to name does not exist.**
#
# This line used to read:
#
#     FROM public.ecr.aws/aws-nitro-enclaves/aws-nitro-enclaves-sdk-c:v0.4.1
#
# with a comment claiming it was "the published artefact AWS's own samples use"
# and that only its *digest* was unresolved. Both halves were wrong. The registry
# answers `NAME_UNKNOWN` for that repository, under either plausible alias, and
# **AWS publishes no prebuilt kmstool image on ECR Public at all**. The reference
# was invented, and the digest guard would have hidden that behind a
# "just fill in the digest" message until the build failed on the instance.
#
# What AWS actually documents (`bin/kmstool-enclave-cli/README.md` →
# `build.sh`) is to build it from source:
#
#     docker build --target kmstool-enclave-cli -t kmstool-enclave-cli \
#         -f containers/Dockerfile.al2 .
#     docker cp $ID:/kmstool_enclave_cli ./
#     docker cp $ID:/usr/lib64/libnsm.so ./
#
# `nitro/build-eif.sh` does exactly that, from the SDK pinned at a commit, and
# tags the result `pqcl-kmstool:<commit>` — which is what this stage consumes.
# It is pinned by **source commit** rather than by registry digest, which is the
# stronger of the two: a digest pins bytes somebody else built, a commit pins
# what they built them from.
FROM pqcl-kmstool:cd61b618 AS kmstool

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# liboqs is linked dynamically by `oqs`, so its runtime is needed. ⛔ Resist
# adding tools here "for debugging" — see the PCR0 note above.
#
# ⛔ `ca-certificates` is NOT a debugging tool, and its absence failed M5b on
# AWS (campaign 02): kmstool reaches KMS over TLS through the vsock-proxy, and
# its s2n/aws-c-io stack found no trust store — `Error initializing trust
# store`, `ca_file (null)` — then aborted on an assertion before ever asking
# KMS. AWS's reference kmstool image is Amazon Linux, which ships a CA bundle;
# this slim Debian stage did not. aws-c-io finds Debian's at
# /etc/ssl/certs/ca-certificates.crt. Nothing off an enclave could catch it:
# locally kmstool stops at NSM seeding, before any TLS.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/target/release/pqcl-enclave /app/pqcl-enclave

# ⚠️ **Two files, and the second one is not optional.** `build.sh` copies the
# binary *and* `libnsm.so`; our previous version copied only the binary, so the
# tool would have died at load time on the campaign instance.
#
# ⭐ **Why an Amazon Linux 2 binary runs here.** Everything the SDK builds —
# aws-lc, s2n-tls, the aws-c-* libraries, json-c — is linked statically, because
# CMake's `BUILD_SHARED_LIBS` defaults to `OFF` and `Dockerfile.al2` never turns
# it on. That is why AWS's own `build.sh` extracts exactly these two files. So
# the binary's only dynamic dependencies are `libnsm.so` and glibc, and a
# glibc-2.26 binary against bookworm's 2.36 is the **forward-compatible**
# direction, which glibc guarantees.
#
# ⛔ That reasoning is checked, not trusted: `build-eif.sh` runs `ldd` on the
# extracted binary and fails the build if anything outside the allowlist appears.
#
# ✅ **Verified 2026-09-16, and it held.** Built from the pinned commit, `ldd`
# reports only `libnsm.so` plus glibc's own (`libc`, `libm`, `libdl`,
# `libpthread`, `librt`, `libgcc_s`, the loader, the vDSO) — every aws-c-*,
# s2n-tls, aws-lc and json-c symbol is static, exactly as the CMake default
# implies. Running the binary in *this* image then reaches
# `aws_nitro_enclaves_library_seed_entropy` and stops, which is the correct
# failure off an enclave and proof that glibc accepted an AL2 binary here.
# Dropping `LD_LIBRARY_PATH` reproduces the failure this guards against
# (`libnsm.so: cannot open shared object file`), so the guard was tested in
# both directions rather than only the passing one.
#
# `libnsm.so` goes under /opt rather than into the system library path so that
# AL2 libraries can never be picked up by *our* binary — the enclave sets
# `LD_LIBRARY_PATH` for the kmstool child process only (`kms` module).
COPY --from=kmstool /kmstool_enclave_cli /app/kmstool_enclave_cli
COPY --from=kmstool /usr/lib64/libnsm.so /opt/kmstool/lib/libnsm.so

CMD ["/app/pqcl-enclave"]
