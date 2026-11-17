#!/usr/bin/env bash
# Build the enclave image and record its measurements.
#
# ⭐ **This step needs no AWS credentials.** `nitro-cli build-enclave` turns a
# Docker image into an EIF and reports its PCR measurements; it makes no AWS API
# call. The plan's M5b line — *"build the EIF and pin PCR0 off-instance first"* —
# is exactly this. Credentials are needed later, to create the KMS key and run
# the enclave on an enclave-enabled instance.
#
# What comes out:
#   nitro/out/pqcl-enclave.eif    the enclave image
#   nitro/out/measurements.json   PCR0/PCR1/PCR2, and what they mean
#
# ⚠️ **PCR0 is the deployment's identity.** It measures the whole EIF, so any
# change to the enclave binary, its dependencies, or the Dockerfile moves it —
# and a moved PCR0 means the KMS key policy no longer matches and `K_mst` is not
# released. That is the intended behaviour. Re-pin the policy deliberately when
# you intend to change the image, never as a reflex to make a failure go away.
#
# Usage:
#   nitro/build-eif.sh                 build the image and the EIF
#   nitro/build-eif.sh --image-only    build and check the image, stop before the EIF
#
# ⭐ `--image-only` exists because the two halves need different things. Building
# the container — which is where the kmstool source pin, the cross-userland copy
# and the `ldd` assumption all get tested — needs only Docker. Only
# `nitro-cli build-enclave` needs nitro-cli. Keeping them separable means the
# risky half can be verified on a developer machine instead of first running on
# a billing instance, which is exactly how it was nearly done.
#
# ⛔ It is **not** a way to skip the EIF. No PCR0 comes out of this mode, so
# nothing it produces can be deployed or pinned in a KMS key policy.
#
# ⚠️ **And do not "fix" that by building nitro-cli from source locally.** PCR0
# measures the whole EIF, which includes the kernel, `init` and cmdline blobs
# that nitro-cli itself ships — so a different nitro-cli build produces a
# different PCR0 for identical application code. A locally computed PCR0 would
# therefore be a number the deployment never reproduces, and pinning a KMS key
# policy to it would fail in the most confusing way available: the mechanism
# working exactly as designed, against us. Build the EIF on the instance, with
# the distribution's packaged nitro-cli, and pin PCR0 from that run.

set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE_ONLY=0
case "${1:-}" in
    --image-only) IMAGE_ONLY=1 ;;
    "") ;;
    *) echo "unknown argument: $1 (expected --image-only or nothing)" >&2; exit 2 ;;
esac

IMAGE="pqcl-enclave:build"
OUT="nitro/out"

# --- the kmstool pin -------------------------------------------------------
#
# AWS publishes no prebuilt kmstool image (the registry answers NAME_UNKNOWN for
# every plausible path), so it is built from source at a pinned commit, exactly
# as `bin/kmstool-enclave-cli/README.md` documents. v0.4.5, 2026-03-31.
KMSTOOL_REPO="https://github.com/aws/aws-nitro-enclaves-sdk-c.git"
KMSTOOL_COMMIT="cd61b6187c8b20867ba4368d1ae62c5790c0269a"
KMSTOOL_TAG="pqcl-kmstool:${KMSTOOL_COMMIT:0:8}"

# Anything the extracted binary may link. Everything else the SDK builds is
# static (CMake's BUILD_SHARED_LIBS defaults to OFF), which is why AWS's own
# build.sh extracts two files and no libraries beyond libnsm. If that ever stops
# being true, the enclave must not be built as if it were.
KMSTOOL_ALLOWED_LIBS="libnsm.so libc.so.6 libm.so.6 libdl.so.2 libpthread.so.0 librt.so.1 libgcc_s.so.1 ld-linux-x86-64.so.2 linux-vdso.so.1"

# --- the Dockerfile's kmstool tag must be the one this script builds --------
#
# Two pins for one thing is how they drift. If someone bumps the SDK commit here
# and not there, the build would silently consume a stale local image — or
# succeed against whatever `pqcl-kmstool:*` happened to be lying around, which is
# worse, because PCR0 would then measure something no commit describes.
if ! grep -qF "FROM ${KMSTOOL_TAG} AS kmstool" nitro/Dockerfile; then
    cat >&2 <<EOF
⛔ nitro/Dockerfile does not consume the kmstool image this script builds.

    expected:  FROM ${KMSTOOL_TAG} AS kmstool
    found:     $(grep -E '^FROM .*AS kmstool' nitro/Dockerfile || echo '(no kmstool stage)')

KMSTOOL_COMMIT in this script and the FROM line in the Dockerfile are one pin
written twice. Change both, or neither.
EOF
    exit 1
fi

# --- every remote FROM must carry a digest ---------------------------------
#
# ⭐ Checked structurally rather than by looking for a marker word. A comment
# saying "resolve this" is only as good as the reader; this fails on any `FROM`
# without an `@sha256:`, so a new unpinned base cannot be added without the
# build refusing it.
#
# The kmstool stage is exempt and only it: it names a local image this script
# builds from `KMSTOOL_COMMIT`, checked immediately above. A source commit is a
# stronger pin than a registry digest, not a weaker one — a digest pins bytes
# somebody else built, a commit pins what they built them from.
UNPINNED=$(grep -E '^FROM ' nitro/Dockerfile | grep -v '@sha256:' | grep -vF "${KMSTOOL_TAG}" || true)
if [ -n "$UNPINNED" ]; then
    cat >&2 <<EOF
⛔ nitro/Dockerfile has a FROM without a digest:

$UNPINNED

PCR0 measures the whole image, so an unpinned base makes the measurement depend
on when you built rather than on what the source says — and the KMS key policy
is conditioned on that measurement.

Resolve each one from an actual pull, never from memory:

    docker pull <image>:<tag>
    docker image inspect <image>:<tag> --format '{{index .RepoDigests 0}}'

Or, without Docker, from the registry that would serve the pull — the digest is
the SHA-256 of the manifest bytes:

    curl -s "https://public.ecr.aws/token/?scope=repository:<repo>:pull&service=public.ecr.aws"
    curl -s -H "Authorization: Bearer <token>" \
         -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
         "https://public.ecr.aws/v2/<repo>/manifests/<tag>" | sha256sum

⛔ Never write a digest you have not obtained from one of those two. A
plausible-looking hash is indistinguishable from a real one until the build
fails somewhere expensive.
EOF
    exit 1
fi

# --- the guard that stops an unresolved pin reaching a build ---------------
if grep -q "UNRESOLVED-PIN" nitro/Dockerfile; then
    cat >&2 <<'EOF'
⛔ nitro/Dockerfile still carries the UNRESOLVED-PIN marker.

The Rust base image digest was never resolved — the network was unreachable when
the file was written, and a fabricated digest was deliberately not substituted.
PCR0 measures the whole image, so building against a floating tag would produce a
measurement that depends on when you built rather than on what the source says.

Resolve it, then re-run:

    docker pull rust:1.97.1-slim-bookworm
    docker image inspect rust:1.97.1-slim-bookworm --format '{{index .RepoDigests 0}}'
    # paste the sha256:... into nitro/Dockerfile's first FROM

EOF
    exit 1
fi

command -v nitro-cli >/dev/null 2>&1 || [ "$IMAGE_ONLY" = 1 ] || {
    cat >&2 <<'EOF'
nitro-cli not found.

(If you only want to verify that the container image builds — which is where the
kmstool pin and the `ldd` assumption are actually tested — re-run with
`--image-only`. That needs Docker and nothing else.)

On Amazon Linux 2023:
    sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
    sudo usermod -aG ne "$USER" && sudo usermod -aG docker "$USER"

Elsewhere it builds from source (it is a Rust project):
    https://github.com/aws/aws-nitro-enclaves-cli

⭐ Note that `build-enclave` needs no enclave and no credentials — only
`run-enclave` needs an enclave-enabled instance.
EOF
    exit 1
}

mkdir -p "$OUT"

# --- kmstool, from AWS's own recipe at a pinned commit ----------------------
#
# ⛔ **Do not substitute a hand-written build here.** This runs AWS's
# `containers/Dockerfile.al2` unmodified, which is the difference between using
# a maintained recipe and guessing at one for a C project whose output lands on
# the key-release path.
if docker image inspect "$KMSTOOL_TAG" >/dev/null 2>&1; then
    echo "== kmstool already built ($KMSTOOL_TAG) =="
else
    echo "== building kmstool from $KMSTOOL_COMMIT =="
    SDK_DIR=$(mktemp -d)
    trap 'rm -rf "$SDK_DIR"' EXIT

    git clone --quiet "$KMSTOOL_REPO" "$SDK_DIR"
    git -C "$SDK_DIR" checkout --quiet "$KMSTOOL_COMMIT"

    # Pinning by commit is only a pin if the commit is the one that was asked
    # for. A tag can be moved; a hash cannot.
    GOT=$(git -C "$SDK_DIR" rev-parse HEAD)
    if [ "$GOT" != "$KMSTOOL_COMMIT" ]; then
        echo "⛔ checked out $GOT, expected $KMSTOOL_COMMIT" >&2
        exit 1
    fi

    docker build \
        --target kmstool-enclave-cli \
        -t "$KMSTOOL_TAG" \
        -f "$SDK_DIR/containers/Dockerfile.al2" \
        "$SDK_DIR"
fi

# --- is the extracted binary really self-contained? ------------------------
#
# ⭐ The Dockerfile copies an Amazon Linux 2 binary into a Debian image and
# argues that it works: the SDK links aws-lc, s2n-tls, the aws-c-* libraries and
# json-c **statically** (CMake's BUILD_SHARED_LIBS defaults to OFF), so the only
# dynamic dependencies are libnsm.so and glibc, and an older glibc's binary on a
# newer glibc is the direction glibc guarantees.
#
# ⛔ That argument is load-bearing and was made by reading AWS's Dockerfile, not
# by running it. So it is checked here rather than trusted: if the SDK ever
# starts building shared libraries, this fails with the offending library named,
# instead of producing an enclave that dies at load time on a billing instance.
echo "== checking the kmstool binary's dynamic dependencies =="
LDD_OUT=$(docker run --rm --entrypoint /bin/sh "$KMSTOOL_TAG" -c 'ldd /kmstool_enclave_cli' 2>&1)
UNEXPECTED=""
if printf '%s\n' "$LDD_OUT" | grep -q 'not a dynamic executable'; then
    echo "   fully static — nothing to check"
else
    # ldd prints either `soname => /path (0x…)` or a bare `/path (0x…)`, so the
    # first field with any directory stripped is the library name in both cases.
    for soname in $(printf '%s\n' "$LDD_OUT" | awk '{print $1}' | sed 's#.*/##'); do
        case " $KMSTOOL_ALLOWED_LIBS " in
            *" $soname "*) ;;
            *) UNEXPECTED="$UNEXPECTED $soname" ;;
        esac
    done
fi

if [ -n "$UNEXPECTED" ]; then
    cat >&2 <<EOF
⛔ kmstool_enclave_cli links libraries the enclave image does not carry:
   $UNEXPECTED

full ldd output:
$LDD_OUT

The Dockerfile copies exactly two files out of the kmstool image — the binary
and libnsm.so — on the basis that everything else is statically linked. That is
no longer true, so either copy the missing libraries in and set LD_LIBRARY_PATH
for the child process, or stop copying the binary across userlands.

⛔ Do not add them to the allowlist to make this pass. The allowlist says what
glibc provides; it is not a list of things to ignore.
EOF
    exit 1
fi
echo "   only $KMSTOOL_ALLOWED_LIBS — as expected"

echo "== building the container image =="
docker build -q -f nitro/Dockerfile -t "$IMAGE" . >/dev/null

# ⭐ **The check that the whole cross-userland copy rests on.** An Amazon Linux 2
# binary is being run on Debian bookworm, on the argument that everything but
# `libnsm.so` and glibc is statically linked and that an older glibc's binary on
# a newer glibc is the direction glibc guarantees. That argument was made by
# reading AWS's Dockerfile; this is what tests it.
#
# Exactly two outcomes are acceptable, and they are the two places the binary
# can legitimately stop:
#
#   * **off an enclave** — it reaches `aws_nitro_enclaves_library_seed_entropy`
#     and dies, because seeding needs `/dev/nsm`. Reaching that line means the
#     loader resolved everything and the code actually ran.
#   * **on an enclave** — entropy seeding succeeds and `--help` prints usage.
#
# ⛔ Anything else fails the build. In particular a loader error means
# `libnsm.so` did not come across or the glibc direction is wrong, and that must
# not be discovered at key-release time on a billing instance.
echo "== checking kmstool runs inside the enclave image =="
KMS_OUT=$(docker run --rm --entrypoint /app/kmstool_enclave_cli \
    -e LD_LIBRARY_PATH=/opt/kmstool/lib "$IMAGE" --help 2>&1 || true)

if printf '%s' "$KMS_OUT" | grep -qiE 'error while loading shared libraries|cannot open shared object|symbol lookup error|GLIBC_'; then
    cat >&2 <<EOF
⛔ kmstool_enclave_cli cannot start inside the enclave image:

$KMS_OUT

The Dockerfile copies an Amazon Linux 2 binary into a Debian image and argues
that only libnsm.so and glibc are needed. That argument has just failed. Do not
work around it by loosening the copy — find out which library is missing and
either bring it across under /opt/kmstool/lib or stop crossing userlands.
EOF
    exit 1
elif printf '%s' "$KMS_OUT" | grep -q 'aws_nitro_enclaves_library_seed_entropy'; then
    echo "   ran to NSM entropy seeding and stopped — correct off an enclave,"
    echo "   and proof the loader resolved libnsm.so and glibc accepted the binary"
elif printf '%s' "$KMS_OUT" | grep -q 'usage: kmstool_enclave_cli'; then
    echo "   printed usage — entropy seeding succeeded, so this host has /dev/nsm"
else
    cat >&2 <<EOF
⛔ kmstool_enclave_cli produced output nobody has seen before:

$KMS_OUT

Expected either the NSM entropy failure (off an enclave) or its usage text (on
one). Something changed in the tool; read it before trusting the image.
EOF
    exit 1
fi

if [ "$IMAGE_ONLY" = 1 ]; then
    echo
    echo "== --image-only: stopping before the EIF =="
    echo "The image built and kmstool starts inside it. ⛔ No PCR0 was produced,"
    echo "so nothing here is deployable — run without --image-only on a host with"
    echo "nitro-cli to get the measurement the KMS key policy is conditioned on."
    exit 0
fi

echo "== converting to an EIF =="
# `--output-file` is relative to the current directory. nitro-cli prints the
# measurements as JSON on stdout, which is the artefact we actually care about.
nitro-cli build-enclave \
    --docker-uri "$IMAGE" \
    --output-file "$OUT/pqcl-enclave.eif" \
    > "$OUT/measurements.raw.json"

# Keep the measurements alongside the provenance needed to reproduce them. A
# PCR0 with no record of what produced it is a number nobody can check.
python3 - "$OUT" <<'PY'
import json, subprocess, sys, pathlib
out = pathlib.Path(sys.argv[1])
raw = json.loads((out / "measurements.raw.json").read_text())

def git(*args):
    try:
        return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"

doc = {
    "measurements": raw.get("Measurements", raw),
    "provenance": {
        "git_commit": git("rev-parse", "HEAD"),
        "git_dirty": git("status", "--porcelain") != "",
        "note": (
            "PCR0 measures the whole EIF. The KMS key policy conditions "
            "kms:Decrypt on this value, so changing the enclave image stops AWS "
            "releasing K_mst. That is the mechanism, not a bug."
        ),
    },
}
(out / "measurements.json").write_text(json.dumps(doc, indent=2) + "\n")
print(json.dumps(doc["measurements"], indent=2))

if doc["provenance"]["git_dirty"]:
    print("\n⚠️  the tree was dirty: this PCR0 does not correspond to any commit",
          file=sys.stderr)
PY

echo
echo "EIF:          $OUT/pqcl-enclave.eif"
echo "measurements: $OUT/measurements.json"
