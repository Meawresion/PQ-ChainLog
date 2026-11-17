#!/usr/bin/env bash
# Campaign 08 (M13 A18): boot image A and release K_mst into it, so the
# custody-plane harnesses build every capsule and record inside the enclave.
# **Runs on the instance**, after `nitro/m5b-acceptance.sh --policy-applied`
# has passed there (it leaves A.eif and the wrapped K_mst in nitro/out/m5b/).
#
#     source aws/enclave-up.sh      # on success: PQCL_SECURE_MODULE=nitro:16
#
# Sourced, not run, because the export is the point. The vsock proxy stays in
# the background and the enclave stays up until
# `nitro-cli terminate-enclave --all`. The parent credentials exported here are
# the instance role's, needed only for the provisioning message; the enclave
# holds K_mst afterwards and calls KMS no more.
#
# ⚠️ `nitro/out/` is gitignored, so nothing here dirties the tree.

enclave_up() {
    local out=nitro/out/m5b cid=16 log="$HOME/pqcl-logs/enclave-up" rc=1 role creds t
    mkdir -p "$log"
    [ -f "$out/A.eif" ] && [ -s "$out/kmst.ciphertext.b64" ] \
        || { echo "no A.eif / wrapped key: run nitro/m5b-acceptance.sh first" >&2; return 1; }

    t=$(curl -sf -X PUT http://169.254.169.254/latest/api/token \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 300") || { echo "no IMDS token" >&2; return 1; }
    role=$(curl -sf -H "X-aws-ec2-metadata-token: $t" \
        http://169.254.169.254/latest/meta-data/iam/security-credentials/) || { echo "no role" >&2; return 1; }
    creds=$(curl -sf -H "X-aws-ec2-metadata-token: $t" \
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role")
    AWS_ACCESS_KEY_ID=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["AccessKeyId"])' "$creds")
    AWS_SECRET_ACCESS_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["SecretAccessKey"])' "$creds")
    AWS_SESSION_TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["Token"])' "$creds")
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    export PQCL_KMS_REGION=us-east-1 PQCL_KMS_PROXY_PORT=8000

    nohup vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 > "$log/vsock-proxy.log" 2>&1 &
    nitro-cli terminate-enclave --all > /dev/null 2>&1
    nitro-cli run-enclave --eif-path "$out/A.eif" --cpu-count 2 --memory 2048 \
        --enclave-cid "$cid" > "$log/run-enclave.json" || { echo "run-enclave failed" >&2; return 1; }
    for _ in $(seq 1 30); do
        target/release/pqcl-provision --cid "$cid" --ciphertext-file "$out/kmst.ciphertext.b64"
        rc=$?
        [ "$rc" -ne 1 ] && break
        sleep 2   # xtask-allow: sleep — waiting for a real enclave to boot
    done
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    [ "$rc" -eq 0 ] || { echo "A was not released (exit $rc)" >&2; return 1; }
    nitro-cli describe-enclaves > "$log/describe-enclaves.json"
    export PQCL_SECURE_MODULE="nitro:$cid"
    echo "enclave A released and serving: PQCL_SECURE_MODULE=$PQCL_SECURE_MODULE"
}
