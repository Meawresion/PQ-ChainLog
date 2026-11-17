#!/usr/bin/env bash
# Runs ON the instance (case (b)): make the midterm
# demo's two warrant proofs and measure what verifying one costs.
#
#   bash aws/demo-proof.sh            from ~/pq-chainlog
#
# Output in zk/demo-proof/: bundle.json, evidence.proof, custody.proof, vk.bin,
# and verify-rss.log (peak RSS of a verify-only process, which decides whether
# the live verify fits the local ~5 GB rule). Then pull zk/demo-proof/ back.
#
# ⛔ Demo only: nothing here is a paper number, and no record is written.
# Recipe from campaign 01 (M6): protobuf-devel for protoc's well-known types,
# then sp1up for the succinct toolchain that builds the guest.

set -u
cd "$(dirname "$0")/.."
export PATH="$HOME/.sp1/bin:$HOME/.cargo/bin:$PATH"

sudo dnf install -y -q protobuf-devel >/dev/null 2>&1 || true
if ! command -v cargo-prove >/dev/null 2>&1; then
    curl -sSL https://sp1up.succinct.xyz | bash >/dev/null 2>&1
    "$HOME/.sp1/bin/sp1up" >/dev/null 2>&1
fi
cargo prove --version | head -1

cd zk/warrant-host
cargo build --release --locked --bin warrant-demo 2>&1 | tail -3
BUILD=${PIPESTATUS[0]}
echo "BUILD_EXIT=$BUILD"
[ "$BUILD" -eq 0 ] || { echo "DEMO_PROOF_EXIT=$BUILD"; exit "$BUILD"; }

OUT=../demo-proof
rm -rf "$OUT"
# IMDSv2: instances launch with HttpTokens=required, so a token comes first.
# Without it the plain GET is refused and the bundle's instance field is empty
# (found on the 2026-11-14 run).
IMDS_TOKEN="$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)"
INSTANCE_TYPE="$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null)"
PQCL_INSTANCE="${INSTANCE_TYPE:-unknown}" \
PQCL_GIT_SHA="$(git rev-parse HEAD)" \
    /usr/bin/time -v target/release/warrant-demo prove "$OUT" 2> "$OUT.prove-time.log"
PROVE=$?
grep -E "Maximum resident|Elapsed" "$OUT.prove-time.log"
echo "PROVE_EXIT=$PROVE"
[ "$PROVE" -eq 0 ] || { tail -20 "$OUT.prove-time.log"; echo "DEMO_PROOF_EXIT=$PROVE"; exit "$PROVE"; }
mv "$OUT.prove-time.log" "$OUT/prove-time.log"

# Verify-only, in a fresh process, bound to the bundle's own values: the cost
# the dashboard pays live.
args=$(python3 - "$OUT/bundle.json" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
w = next(w for w in b["warrants"] if w["name"] == "evidence")
print(w["nullifier"], w["scope_commit"], b["warrant_root"], b["epoch"])
PY
)
# shellcheck disable=SC2086
/usr/bin/time -v target/release/warrant-demo verify "$OUT" evidence $args > "$OUT/verify.json" 2> "$OUT/verify-rss.log"
VERIFY=$?
cat "$OUT/verify.json"
grep -E "Maximum resident|Elapsed" "$OUT/verify-rss.log"
ls -la "$OUT"
echo "DEMO_PROOF_EXIT=$VERIFY"
