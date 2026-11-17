#!/usr/bin/env bash
# M5b acceptance — **runs on an enclave-enabled EC2 instance, nowhere else.**
#
#   1. Build image A; record PCR0_A.
#   2. Bind the KMS key's Decrypt to PCR0_A; wrap K_mst under it.
#   3. Boot A and provision it              -> KMS MUST release K_mst  (exit 0)
#   4. Derive image B = A + one byte appended to the enclave binary; PCR0 MUST move.
#   5. Boot B and provision it              -> KMS MUST refuse         (exit 3)
#
# ⭐ Step 5 is the test. A happy path alone passes just as well against a key
# policy that conditions on nothing; the refusal is what shows the PCR0
# condition does anything (nitro/README.md, Secure Module standing rule).
#
# Usage, on the instance, from the repository root — two phases:
#     PQCL_KMS_KEY_ID=<id> bash nitro/m5b-acceptance.sh
#         builds A, writes nitro/out/m5b/key-policy.json bound to PCR0_A, stops.
#     (an ADMIN applies that policy — see below)
#     PQCL_KMS_KEY_ID=<id> bash nitro/m5b-acceptance.sh --policy-applied \
#         2>&1 | tee ~/pqcl-logs/m5b-acceptance.log
#
# ⛔ **The instance does not apply the policy, and A is never rebuilt once built.**
# The first version put the policy from the instance, whose role deliberately
# has no permissions of its own — so that call could not succeed. And it rebuilt
# A on every run: the Dockerfile's `apt-get update` drifts, so a rebuild after the
# policy was applied could carry a different PCR0 than the policy names, and A
# would be refused for a reason that has nothing to do with the test. Now the
# policy is applied by an administrator from outside (`aws kms put-key-policy
# --policy file://key-policy.json`), and phase two reuses A's
# EIF and measurements byte for byte. `--apply-key-policy` remains for an
# operator whose instance role is allowed to put key policies.
#
# Inputs: PQCL_KMS_KEY_ID (required, created beforehand with `aws kms create-key`),
#         PQCL_KMS_REGION (default us-east-1 — the region every run is pinned to).
# Needs:  nitro-cli + allocator, vsock-proxy, docker, aws CLI v2, python3, cargo.
#
# ⛔ K_mst never exists in plaintext outside an enclave, not even here: it is
# minted by GenerateDataKeyWithoutPlaintext, so the parent only ever holds the
# wrapped blob.

set -uo pipefail          # NOT -e: every outcome is inspected explicitly.
cd "$(dirname "$0")/.."

REGION="${PQCL_KMS_REGION:-us-east-1}"
KEY_ID="${PQCL_KMS_KEY_ID:?PQCL_KMS_KEY_ID is required: the KMS key to bind to PCR0}"
MODE=plan                                   # plan | apply | applied
[ "${1:-}" = "--apply-key-policy" ] && MODE=apply
[ "${1:-}" = "--policy-applied" ] && MODE=applied

CID=16
PROXY_PORT=8000
OUT="nitro/out/m5b"
LOGDIR="$HOME/pqcl-logs"
mkdir -p "$OUT" "$LOGDIR"
EVIDENCE="$LOGDIR/m5b-acceptance.json"

die() { echo "⛔ $*" >&2; exit 1; }
say() { echo; echo "== $* ($(date -u +%H:%M:%SZ))"; }
pcr0_of() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"]["PCR0"])' "$1"; }

# --- preflight --------------------------------------------------------------
for t in nitro-cli vsock-proxy docker aws python3 cargo curl; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
[ -e /dev/nitro_enclaves ] || die "/dev/nitro_enclaves absent: not an enclave-enabled instance"
systemctl is-active --quiet nitro-enclaves-allocator.service \
    || die "the enclave allocator is not running: sudo systemctl start nitro-enclaves-allocator.service"

# --- parent credentials, from IMDSv2 -----------------------------------------
# The parent role's own short-lived credentials. They travel to the enclave in
# the Provision message; they are NOT what authorises the decrypt (PCR0 is).
imds() {
    local tok
    tok=$(curl -sf -X PUT http://169.254.169.254/latest/api/token \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 300") || return 1
    curl -sf -H "X-aws-ec2-metadata-token: $tok" "http://169.254.169.254/latest/$1"
}
ROLE=$(imds meta-data/iam/security-credentials/) || die "no instance role attached (IMDSv2 returned nothing)"
CREDS=$(imds "meta-data/iam/security-credentials/$ROLE") || die "could not read role credentials"
export AWS_ACCESS_KEY_ID=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["AccessKeyId"])' "$CREDS")
export AWS_SECRET_ACCESS_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["SecretAccessKey"])' "$CREDS")
export AWS_SESSION_TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["Token"])' "$CREDS")
export PQCL_KMS_REGION="$REGION" PQCL_KMS_PROXY_PORT="$PROXY_PORT"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text --region "$REGION") || die "sts get-caller-identity failed"
ROLE_ARN="arn:aws:iam::$ACCOUNT:role/$ROLE"
echo "parent role: $ROLE_ARN"

# --- 1. image A --------------------------------------------------------------
if [ "$MODE" = plan ] || [ ! -f "$OUT/A.eif" ] || [ ! -f "$OUT/A.measurements.json" ]; then
    [ "$MODE" = applied ] && die "--policy-applied but no built A in $OUT: run the plan phase first"
    say "1. build image A (nitro/build-eif.sh)"
    bash nitro/build-eif.sh || die "build-eif.sh failed"
    cp nitro/out/pqcl-enclave.eif "$OUT/A.eif"
    cp nitro/out/measurements.raw.json "$OUT/A.measurements.json"
    # B is derived from A's docker image; keep that image under a name the
    # campaign's own EIF step (same `:build` tag) cannot overwrite.
    docker tag pqcl-enclave:build pqcl-enclave:m5b-a || die "could not pin A's image"
else
    say "1. reuse image A built in the plan phase (its PCR0 is what the policy names)"
fi
PCR0_A=$(pcr0_of "$OUT/A.measurements.json") || die "no PCR0 in A's measurements"
echo "PCR0_A = $PCR0_A"

# --- 2. key policy + wrapped K_mst -------------------------------------------
say "2. key policy bound to PCR0_A"
# Three statements. ⚠️ The explicit Deny is load-bearing: without it, an IAM
# identity policy granting the role kms:Decrypt would let the parent — or any
# image — decrypt with no attestation at all, and step 5 would (correctly) fail.
# With it, the role can decrypt ONLY with an attestation whose PCR0 matches.
python3 - "$ACCOUNT" "$ROLE_ARN" "$PCR0_A" > "$OUT/key-policy.json" <<'PY'
import json, sys
account, role, pcr0 = sys.argv[1:4]
print(json.dumps({
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "AccountAdmin", "Effect": "Allow",
     "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
     "Action": "kms:*", "Resource": "*"},
    {"Sid": "ParentMayMintWrappedKeysOnly", "Effect": "Allow",
     "Principal": {"AWS": role},
     "Action": ["kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"],
     "Resource": "*"},
    {"Sid": "OnlyThisEnclaveMayDecrypt", "Effect": "Allow",
     "Principal": {"AWS": role}, "Action": "kms:Decrypt", "Resource": "*",
     "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": pcr0}}},
    {"Sid": "NoDecryptWithoutThisPCR0", "Effect": "Deny",
     "Principal": {"AWS": role}, "Action": "kms:Decrypt", "Resource": "*",
     "Condition": {"StringNotEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": pcr0}}}
  ]
}, indent=2))
PY
echo "wrote $OUT/key-policy.json"
case "$MODE" in
    plan)
        echo
        echo "Stopping before changing the key. An administrator applies $OUT/key-policy.json"
        echo "(aws kms put-key-policy --key-id $KEY_ID --policy-name default --policy file://key-policy.json),"
        echo "then re-run with --policy-applied."
        exit 2 ;;
    apply)
        aws kms put-key-policy --region "$REGION" --key-id "$KEY_ID" --policy-name default \
            --policy "file://$OUT/key-policy.json" || die "put-key-policy failed" ;;
    applied)
        echo "policy applied externally; continuing with A as built" ;;
esac

aws kms generate-data-key-without-plaintext --region "$REGION" --key-id "$KEY_ID" \
    --key-spec AES_256 --query CiphertextBlob --output text > "$OUT/kmst.ciphertext.b64" \
    || die "could not mint a wrapped K_mst"
[ -s "$OUT/kmst.ciphertext.b64" ] || die "wrapped K_mst is empty"

# --- vsock-proxy to KMS, and the parent tool ---------------------------------
say "vsock-proxy $PROXY_PORT -> kms.$REGION.amazonaws.com:443"
vsock-proxy "$PROXY_PORT" "kms.$REGION.amazonaws.com" 443 > "$LOGDIR/vsock-proxy.log" 2>&1 &
PROXY_PID=$!
cleanup() {
    nitro-cli terminate-enclave --all >/dev/null 2>&1
    kill "$PROXY_PID" 2>/dev/null
}
trap cleanup EXIT

cargo build --release --locked -q -p pqcl-nitro --features enclave --bin pqcl-provision \
    || die "could not build pqcl-provision"
PROVISION="target/release/pqcl-provision"

# Boot an EIF, provision it, return pqcl-provision's exit code (0/3/1).
boot_and_provision() {
    local eif="$1" rc=1
    nitro-cli terminate-enclave --all >/dev/null 2>&1
    nitro-cli run-enclave --eif-path "$eif" --cpu-count 2 --memory 2048 \
        --enclave-cid "$CID" >/dev/null || { echo "run-enclave failed" >&2; return 1; }
    # Real waiting: the enclave takes seconds to boot and bind its port, and
    # until then the connect is refused (exit 1). Bounded, and only exit 1
    # retries — 0 and 3 are answers.
    for _ in $(seq 1 30); do
        "$PROVISION" --cid "$CID" --ciphertext-file "$OUT/kmst.ciphertext.b64"
        rc=$?
        [ "$rc" -ne 1 ] && break
        sleep 2
    done
    return "$rc"
}

# --- 3. A must be released ---------------------------------------------------
say "3. boot A and provision — KMS must RELEASE"
boot_and_provision "$OUT/A.eif"; RC_A=$?
nitro-cli terminate-enclave --all >/dev/null 2>&1

# --- 4. image B: one byte appended to the enclave binary ---------------------
say "4. derive B = A + one byte; PCR0 must move"
# Derived from A's own image, so the ONLY difference is the byte. Done outside
# nitro/Dockerfile on purpose: a mutation hook in the TCB's build recipe would
# itself be something PCR0 has to answer for.
printf 'FROM pqcl-enclave:m5b-a\nRUN printf "\\001" >> /app/pqcl-enclave\n' \
    | docker build -q -t pqcl-enclave:mutated - >/dev/null || die "could not build image B"
nitro-cli build-enclave --docker-uri pqcl-enclave:mutated --output-file "$OUT/B.eif" \
    > "$OUT/B.measurements.json" || die "could not build B.eif"
PCR0_B=$(pcr0_of "$OUT/B.measurements.json") || die "no PCR0 in B's measurements"
echo "PCR0_B = $PCR0_B"

# --- 5. B must be refused ----------------------------------------------------
say "5. boot B and provision — KMS must REFUSE"
boot_and_provision "$OUT/B.eif"; RC_B=$?

# --- verdict -----------------------------------------------------------------
VERDICT=pass
REASONS=()
[ "$RC_A" -eq 0 ] || { VERDICT=fail; REASONS+=("A was not released (exit $RC_A): the happy path is broken"); }
[ "$PCR0_A" != "$PCR0_B" ] || { VERDICT=fail; REASONS+=("PCR0 did not move: the mutation did not reach the measurement"); }
case "$RC_B" in
    3) ;;
    0) VERDICT=fail; REASONS+=("B was RELEASED: the key policy does not condition on PCR0") ;;
    *) VERDICT=inconclusive; REASONS+=("B gave no answer (exit $RC_B): transport failure, not a refusal") ;;
esac

python3 - "$EVIDENCE" "$VERDICT" "$PCR0_A" "$PCR0_B" "$RC_A" "$RC_B" "$(git rev-parse HEAD)" "${REASONS[@]}" <<'PY'
import json, sys, datetime
path, verdict, a, b, rc_a, rc_b, sha, *reasons = sys.argv[1:]
json.dump({
  "test": "M5b acceptance: mutate the image, KMS must refuse",
  "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
  "git_sha": sha, "verdict": verdict,
  "pcr0_a": a, "pcr0_b": b, "pcr0_moved": a != b,
  "provision_exit_a": int(rc_a), "provision_exit_b": int(rc_b),
  "exit_codes": {"0": "released", "3": "KMS refused (kmstool reached KMS, non-200)",
                 "4": "enclave error that is NOT a refusal (tool/TLS/crash)", "1": "no usable answer"},
  "reasons": reasons,
}, open(path, "w"), indent=2)
PY

say "verdict: $VERDICT"
for r in "${REASONS[@]}"; do echo "  - $r"; done
echo "evidence: $EVIDENCE"
[ "$VERDICT" = pass ]
