#!/usr/bin/env bash
# Install everything campaign 02 and M5b need, on a fresh Amazon Linux 2023
# instance. **Runs on the instance**, once, before `sync-to-instance.sh`.
#
# ⭐ This exists because campaign 01 installed its tools by hand and nothing
# recorded which. `run-campaign.sh`'s preflight checks exactly the tools this
# installs; if the two ever disagree, the preflight is the authority and this
# file has a bug.
#
# Usage:  bash setup-instance.sh      (then log out and back in, for the groups)
#
# ⚠️ It installs the enclave allocator but does NOT start it. The allocator
# carves its memory out of the parent at start, and the Doris 10^6 tier is the
# memory-bound step of the campaign. Start it only for M5b, after the campaign:
#     sudo systemctl start nitro-enclaves-allocator.service

set -euo pipefail

echo "== system packages (dnf)"
# cmake + clang + clang-devel: oqs-sys builds liboqs from source and bindgen
# needs libclang — without them the build dies at exit 101 pointing at a build
# script, not at a missing package (M5b row).
sudo dnf install -y \
    git gcc gcc-c++ make cmake clang clang-devel openssl-devel pkgconf-pkg-config \
    python3 docker rsync \
    aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

echo "== docker"
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"

# ⚠️ AL2023's docker ships without the compose plugin, and `besu/exp6chain.sh`
# runs `docker compose up`. Campaign 03 lost its first exp6chain pass to this
# (exit 125): campaign 02 never ran exp6chain, so nothing had exercised it.
# Pinned, and checked against the release's own digest.
COMPOSE_VERSION=v5.5.1
COMPOSE_URL="https://github.com/docker/compose/releases/download/$COMPOSE_VERSION/docker-compose-linux-x86_64"
mkdir -p "$HOME/.docker/cli-plugins"
curl -fsSL -o "$HOME/.docker/cli-plugins/docker-compose" "$COMPOSE_URL"
echo "$(curl -fsSL "$COMPOSE_URL.sha256" | cut -d' ' -f1)  $HOME/.docker/cli-plugins/docker-compose" | sha256sum -c
chmod +x "$HOME/.docker/cli-plugins/docker-compose"
docker compose version

echo "== nitro enclaves: groups and allocator config (not started)"
sudo usermod -aG ne "$USER"
# 2 vCPU / 3 GiB: m5b-acceptance.sh boots with --cpu-count 2 --memory 2048, and
# the allocator must reserve at least that. Kept small on purpose — see above.
sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<'YAML'
---
memory_mib: 3072
cpu_count: 2
YAML
sudo systemctl enable nitro-enclaves-allocator.service

echo "== rust (rustup; the toolchain itself is pinned by rust-toolchain.toml)"
if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

echo "== foundry (forge writes the anchor gas exp6 needs)"
# ⚠️ Pinned to the version the local toolchain runs (commit 982849d314), and
# only `forge` is checked. foundryup's own post-install check runs `anvil -V`,
# and anvil needs GLIBC_2.35 while AL2023 ships 2.34 — so foundryup exits
# non-zero on AL2023 even though forge (GLIBC <= 2.34) is fine. The campaign
# never uses anvil. Found on campaign 02's instance, 2026-09-26.
FOUNDRY_VERSION=v1.8.1
if [ ! -x "$HOME/.foundry/bin/foundryup" ]; then
    curl -sSL https://foundry.paradigm.xyz | bash
fi
"$HOME/.foundry/bin/foundryup" --install "$FOUNDRY_VERSION" || true
FORGE="$HOME/.foundry/versions/foundry-rs/foundry/$FOUNDRY_VERSION/forge"
"$FORGE" -V || { echo "forge $FOUNDRY_VERSION does not run on this host" >&2; exit 1; }
ln -sfn "$FORGE" "$HOME/.foundry/bin/forge"
# ⚠️ `cast` too: besu/searchauth-fixture.sh needs it, and without it the five
# chainproof tests fail with "cast not found" (M12 rehearsal, 2026-09-27).
CAST="$HOME/.foundry/versions/foundry-rs/foundry/$FOUNDRY_VERSION/cast"
"$CAST" --version || { echo "cast $FOUNDRY_VERSION does not run on this host" >&2; exit 1; }
ln -sfn "$CAST" "$HOME/.foundry/bin/cast"

mkdir -p "$HOME/pqcl-logs" "$HOME/pq-chainlog"

cat <<'EOF'

✅ Installed. Next, in order:
  1. log out and back in              (docker + ne group membership)
  2. from your clone:     aws/sync-to-instance.sh ec2-user@<public-dns>
  3. on the instance:     cd ~/pq-chainlog && rustup show   (installs 1.97.1)
  4. on the instance:     aws/run-campaign.sh 2>&1 | tee ~/pqcl-logs/campaign-02.log
  5. then, for M5b:       sudo systemctl start nitro-enclaves-allocator.service
                          PQCL_KMS_KEY_ID=<id> bash nitro/m5b-acceptance.sh
EOF
