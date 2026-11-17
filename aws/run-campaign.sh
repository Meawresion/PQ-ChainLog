#!/usr/bin/env bash
# A campaign, in one ordered pass per instance. **Runs on the instance, not here.**
#
# ⭐ Campaign 04 splits BY EXPERIMENT across two
# instance types, never by test point, so no table or curve mixes hardware:
#
#     aws/run-campaign.sh m7i    # m7i.4xlarge: everything except Exp. 1
#     aws/run-campaign.sh r7i    # r7i.4xlarge: Exp. 1 alone (Zuo'22 at y = 65 536
#                                #   needs ~62 GB, projected from 3 874.6 MB at 16 384)
#
# In parallel (user, 2026-09-27): start the r7i first (Exp. 1 is the long one),
# then the m7i. Safe because the split is by experiment: no number crosses
# between the two instances. Tear down and verify each as it finishes.
# The Doris tiers are NOT re-run: their harness is unchanged since 41047b6 and
# their counts are structural, so campaign 03's carve-out records are reused.
#
# ⭐ **This exists because the expensive failure is forgetting a flag, not a
# bug.** Every step below was already written down somewhere — a task
# description, a README, a consultation — and a paid session that reconstructs
# them from three documents under time pressure is how `--features
# classical-baseline` gets left off and the ECDSA row comes back empty after the
# instance is gone.
#
# ⛔ It does **not** terminate the instance. Do that from your workstation with
# `aws ec2 terminate-instances`, and confirm with `aws ec2 describe-instances`
# rather than trusting this script's opinion of what it left running.
#
# Usage, on the instance:
#     aws/run-campaign.sh 2>&1 | tee ~/pqcl-logs/campaign-02.log
#
# ⚠️ Log to `~`, never `/tmp`: the instance has its reasons to prefer a home
# directory. `pull-results.sh` collects
# `~/pqcl-logs/`.

set -uo pipefail          # ⛔ NOT -e: a failed step must not abandon the rest.
cd "$(dirname "$0")/.."

SET="${1:-}"
case "$SET" in
    c15r | c15a | c14r | c14a | m7i | r7i | c05 | c05a | c05b | c06 | c07r | c07a | c07b | c07c | c08r | c08a | c08b | c08c | c08c2 | c08d | c08e | c08f | c08g | c09a | c09b | c10a | c10b | c10c) echo "== campaign set: $SET ==" ;;
    *)
        echo "usage: aws/run-campaign.sh c15r|c15a|c14r|c14a|m7i|r7i|c05|c05a|c05b|c06|c07r|c07a|c07b|c07c|c08r|c08a|c08b|c08c|c08c2   (§1q.6: split by experiment; c07* = the draft8 re-run, §1ap; c08* = M13 phase C)" >&2
        exit 2
        ;;
esac

FAILED=""
step() {
    local name="$1"; shift
    echo
    echo "=============================================================="
    echo "== $name   $(date -u +%H:%M:%SZ)"
    echo "=============================================================="
    if "$@"; then
        echo "-- ok: $name"
    else
        # ⚠️ `$?` here is the function's, which is the command's, because there
        # is no pipeline. A `| tee` at the call site would make it tee's — that
        # trap has produced three wrong conclusions in this project, most
        # recently reading an OOM-killed Doris run as `exit=0`.
        echo "-- FAILED: $name (exit $?)" >&2
        FAILED="$FAILED
  - $name"
    fi
    # ⛔ Every record is stamped from `git status`, so a step that leaves the
    # tree dirty poisons every step after it — silently, since each later
    # record is well-formed and merely refused at the pull. That is exactly
    # what the Doris publishes did to each other (2026-09-25). Check the
    # precondition after every step rather than trusting each step to keep it.
    if [ -n "$(git status --porcelain)" ]; then
        echo "-- FAILED: $name left the tree DIRTY; every later record will be refused:" >&2
        git status --short >&2
        FAILED="$FAILED
  - $name (dirtied the tree)"
    fi
}

# --- preflight: every tool, before anything is measured ---------------------
#
# ⛔ Campaign 01 installed its tools by hand, and nothing lists them. A tool
# discovered missing at step 7 costs the instance-hours of steps 1–6; found
# here it costs ten seconds. `forge` resolves from ~/.foundry/bin too, because
# `foundryup` only edits the interactive profile.
echo "== preflight: tools and inputs =="
PREFLIGHT_OK=1
export PATH="$HOME/.foundry/bin:$PATH"
for tool in cargo git python3 docker forge cast cmake clang; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  ok       $tool"
    else
        echo "  MISSING  $tool" >&2
        PREFLIGHT_OK=0
    fi
done
if ! docker info >/dev/null 2>&1; then
    echo "  MISSING  a running Docker daemon usable by $USER" >&2
    PREFLIGHT_OK=0
fi
if [ ! -d "${PQCL_ENRON:-datasets/enron/maildir}" ]; then
    echo "  MISSING  Enron corpus at ${PQCL_ENRON:-datasets/enron/maildir} (sync from a clone that has it)" >&2
    PREFLIGHT_OK=0
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "  DIRTY    tree before the first step; every record would be refused:" >&2
    git status --short >&2
    PREFLIGHT_OK=0
fi
if [ "$PREFLIGHT_OK" -ne 1 ]; then
    echo "⛔ preflight refused. Nothing has been measured." >&2
    exit 1
fi

# --- 0. the hard gate ------------------------------------------------------
#
# ⛔ First, before anything is measured. If this is not an AWS box, every number
# the campaign produces is unpublishable and the run is wasted — better to learn
# that in the first ten seconds than at the pull.
echo "== gate: are we actually on AWS? =="
if ! cargo run --release --quiet --example emit_record -- results/ --require-aws; then
    cat >&2 <<'EOF'

⛔ The AWS gate refused. Nothing has been measured and nothing should be.

`detect_environment()` reads SMBIOS strings that do not exist off EC2, and it
fails closed to Local by design. If this IS an EC2 instance and the gate still
refuses, do not work around it: the same detection stamps every record, so a
gate that is wrong here means provenance that is wrong everywhere.
EOF
    exit 1
fi

# --- 1. our ten experiments ------------------------------------------------
#
# ⚠️ `--features classical-baseline` is **not optional**. Without it exp1 emits
# no ECDSA row, and `mkfigs.py` refuses to emit while the classical cells are
# missing — the comparison point §1d ruled in.
export PQCL_ENRON="${PQCL_ENRON:-datasets/enron/maildir}"

# ⛔ Before exp6, and not optional either. exp6 folds in
# `contracts/out/anchor-gas.json`, which only `forge` writes (GasProfile.t.sol).
# This step was missing, so exp6 would have recorded `anchor_gas: null` and
# every gas cell in tab:exp6 would have come back empty after the instance was
# gone. `contracts/out/` is gitignored, so this does not dirty the tree.
# §1q.2's axes, fixed before campaign 04: log-spaced, chosen before any result,
# each containing the table's declared operating point.
if [ "$SET" = r7i ]; then
    # Exp. 1 whole: every tab:exp-ingest cell comes from this pass, and the small
    # y share a curve with the large ones, so they run here too. The Zuo'22
    # budget admits y = 65 536 on 128 GiB; a point over it is recorded as skipped
    # with its estimate, never dropped.
    step "exp1 (ingestion; y axis to 65 536; ECDSA baseline)" \
        env PQCL_COLLECTION_N=256,512,1024,2048,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
            PQCL_ZUO_MEM_BUDGET_GIB=110 \
        cargo run --release -q -p pqcl-exp --bin exp1 --features classical-baseline
fi

if [ "$SET" = m7i ]; then
    # ⛔ Before exp6 and exp6chain: exp6 folds in contracts/out/anchor-gas.json,
    # which only forge writes, and exp6chain needs Anchor's build artefact.
    step "contracts (forge, writes anchor gas for exp6)" cargo xtask contracts

    # 250 000 documents is ~24 GB (590 B per pair, measured); the full corpus
    # would be ~50 GB and is not attempted.
    step "exp2 (1-2-5 tiers to 250k documents; Pi_XT, Pi_CD, ODXT)" \
        env PQCL_EXP2_TIERS=1000,2000,5000,10000,20000,50000,100000,250000 \
        cargo run --release -q -p pqcl-exp --bin exp2
    step "exp7 (N axis 2^8..2^16, x1.5 between)" \
        env PQCL_COLLECTION_N=256,384,512,768,1024,1536,2048,3072,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
        cargo run --release -q -p pqcl-exp --bin exp7
    step "index size (ours vs ODXT, 1-2-5 per decade)" \
        cargo run --release -q -p pqcl-exp --bin size
    for b in exp6 exp345 exp8910; do
        step "$b" cargo run --release -q -p pqcl-exp --bin "$b"
    done

    # Entries per epoch 25..10^6, parallel and single co-signer at every point,
    # the W sweep at 10^2 (the axis is compiled in: EPOCH_SIZES).
    step "exp6chain (LEChain vs anchor, live Besu; W sweep)" bash besu/exp6chain.sh

    step "fetch M8 artefacts" sh datasets/fetch-artefacts.sh
    step "tamper response (exp8)" \
        env PQCL_ARTEFACTS=datasets/artefacts PQCL_TAMPER_TRIALS=20 \
        cargo run --release -q -p pqcl-exp --features chain --bin tamper

    # 10^6 real signed records want ~20 GB; the audit-cores sweep 1..16 runs per case.
    step "custody disclosure (10^3..10^6, audit cores 1..16)" \
        env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000 \
        cargo run --release -q -p pqcl-exp --bin custody
fi

# Campaign 05: Exp. 6, 7, 8 rerun WHOLE, ours and
# every baseline, plus the new Exp. 9. Nothing of Exp. 1-5 runs; their
# campaign-04 records stand if tools/stale_guard.py agrees.
# c05a = Besu and the artefacts (Exp. 6, 8); c05b = the rest (Exp. 7, 9). Run on
# two instances in parallel (§1y.4), or c05 for all four on one.
A05=0; B05=0
case "$SET" in c05) A05=1; B05=1 ;; c05a) A05=1 ;; c05b) B05=1 ;; esac
if [ "$A05" = 1 ]; then
    # Anchor's build artefact for exp6chain, and the Redaction/ACVP gates.
    step "contracts (forge: Anchor build, redaction and ACVP gates)" cargo xtask contracts
    # tab:exp-anchor with one sweep order per disposing epoch (§1v.4), and
    # order_gas_by_k for tab:exp-redaction's caption.
    step "exp6chain (LEChain vs anchor, live Besu; orders; W sweep)" bash besu/exp6chain.sh
    step "fetch M8 artefacts" sh datasets/fetch-artefacts.sh
    step "tamper response (exp8, with payload deleted)"         env PQCL_ARTEFACTS=datasets/artefacts PQCL_TAMPER_TRIALS=20         cargo run --release -q -p pqcl-exp --features chain --bin tamper
fi
if [ "$B05" = 1 ]; then
    step "custody disclosure (10^3..10^6, redacted block, audit cores 1..16)"         env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000         cargo run --release -q -p pqcl-exp --bin custody
    # Exp. 3's axis 10^3..10^6 pairs; needs the Doris upstream data (submodule).
    step "exp9redact (redaction vs ODXT del and rebuild; sweep; detection)"         cargo run --release -q -p pqcl-exp --bin exp9redact
fi

# Campaign 06: two reruns, each whole. Exp. 2 with
# nested corpus tiers and one fixed query set (§1aa.4); Exp. 8 with the lawful
# deletion outside the measured artefacts (§1z.3).
if [ "$SET" = c06 ]; then
    step "exp2 (nested tiers, fixed query set; 1-2-5 tiers to 250k documents)"         env PQCL_EXP2_TIERS=1000,2000,5000,10000,20000,50000,100000,250000         cargo run --release -q -p pqcl-exp --bin exp2
    step "fetch M8 artefacts" sh datasets/fetch-artefacts.sh
    step "tamper response (exp8, lawful deletion outside the measured store)"         env PQCL_ARTEFACTS=datasets/artefacts PQCL_TAMPER_TRIALS=20         cargo run --release -q -p pqcl-exp --features chain --bin tamper
fi

# Campaign 07: the draft8 code revision
# re-run. tools/stale_guard.py flagged every record, so every experiment runs
# whole, on the same axes and workloads as before (rule 21). Four instances in
# parallel, the long one first: c07r on r7i.4xlarge (Exp. 1, ~6 h); c07a, c07b,
# c07c on m7i.4xlarge (~3 h each). Doris tiers stay reused (Python, unaffected).
if [ "$SET" = c07r ]; then
    step "exp1 (ingestion; y axis to 65 536; ECDSA baseline)" \
        env PQCL_COLLECTION_N=256,512,1024,2048,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
            PQCL_ZUO_MEM_BUDGET_GIB=110 \
        cargo run --release -q -p pqcl-exp --bin exp1 --features classical-baseline
fi
if [ "$SET" = c07a ]; then
    step "contracts (forge, writes anchor gas for exp6)" cargo xtask contracts
    step "exp2 (nested tiers, fixed query set; 1-2-5 tiers to 250k documents)" \
        env PQCL_EXP2_TIERS=1000,2000,5000,10000,20000,50000,100000,250000 \
        cargo run --release -q -p pqcl-exp --bin exp2
    step "exp7 (N axis 2^8..2^16, x1.5 between)" \
        env PQCL_COLLECTION_N=256,384,512,768,1024,1536,2048,3072,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
        cargo run --release -q -p pqcl-exp --bin exp7
    step "index size (ours vs ODXT, 1-2-5 per decade)" \
        cargo run --release -q -p pqcl-exp --bin size
    for b in exp6 exp345 exp8910; do
        step "$b" cargo run --release -q -p pqcl-exp --bin "$b"
    done
    step "fetch M8 artefacts" sh datasets/fetch-artefacts.sh
    step "tamper response (exp8, lawful deletion outside the measured store)" \
        env PQCL_ARTEFACTS=datasets/artefacts PQCL_TAMPER_TRIALS=20 \
        cargo run --release -q -p pqcl-exp --features chain --bin tamper
fi
if [ "$SET" = c07b ]; then
    step "contracts (forge: the D4 Anchor build)" cargo xtask contracts
    step "exp6chain (LEChain vs the D4 anchor, live Besu; orders; W sweep)" bash besu/exp6chain.sh
    step "exp9redact (redaction vs ODXT del and rebuild; sweep; detection)" \
        cargo run --release -q -p pqcl-exp --bin exp9redact
fi
if [ "$SET" = c07c ]; then
    step "custody disclosure (10^3..10^6, redacted block, audit cores 1..16)" \
        env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000 \
        cargo run --release -q -p pqcl-exp --bin custody
fi

# Campaign 08 (plan M13 phase C; G5 approved by the user 2026-10-13). Every
# campaign-07 record is stale under tools/stale_guard.py's own rule: `Domain`
# in pqcl-primitives' xof.rs gained `Roster = 0x16` inside the enum body, and
# every harness executes that file. So c07's split re-runs whole:
#   c08r  r7i.4xlarge                 Exp. 1 (the long one, start it first)
#   c08a  m7i.4xlarge                 the evidence-plane set
#   c08b  m7i.4xlarge  + enclave      exp6chain (SAC Exp. 1) and exp9redact
#   c08c  m7i.8xlarge  + enclave      custody (SAC Exp. 2) and tamper (SAC Exp. 3)
# ⭐ The custody-plane harnesses build every record inside the enclave (A18), so
# c08b and c08c boot image A first (aws/enclave-up.sh) and build with
# `--features enclave`; their records refuse to publish otherwise. c08c is an
# 8xlarge because the enclave takes 2 vCPUs from the parent, and custody's
# audit-cores axis {1,2,4,8,16} is capped at the parent's cores: on a 4xlarge
# the declared 16 would silently drop out.
if [ "$SET" = c08r ]; then
    step "exp1 (ingestion; y axis to 65 536; ECDSA baseline)" \
        env PQCL_COLLECTION_N=256,512,1024,2048,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
            PQCL_ZUO_MEM_BUDGET_GIB=110 \
        cargo run --release -q -p pqcl-exp --bin exp1 --features classical-baseline
fi
if [ "$SET" = c08a ]; then
    step "contracts (forge, writes anchor gas for exp6)" cargo xtask contracts
    step "exp2 (nested tiers, fixed query set; 1-2-5 tiers to 250k documents)" \
        env PQCL_EXP2_TIERS=1000,2000,5000,10000,20000,50000,100000,250000 \
        cargo run --release -q -p pqcl-exp --bin exp2
    step "exp7 (N axis 2^8..2^16, x1.5 between)" \
        env PQCL_COLLECTION_N=256,384,512,768,1024,1536,2048,3072,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
        cargo run --release -q -p pqcl-exp --bin exp7
    step "index size (ours vs ODXT, 1-2-5 per decade)" \
        cargo run --release -q -p pqcl-exp --bin size
    for b in exp6 exp345 exp8910; do
        step "$b" cargo run --release -q -p pqcl-exp --bin "$b"
    done
fi
if [ "$SET" = c08b ] || [ "$SET" = c08c ] || [ "$SET" = c08c2 ] || [ "$SET" = c08d ] || [ "$SET" = c08f ] || [ "$SET" = c08g ] || [ "$SET" = c09a ] || [ "$SET" = c09b ] || [ "$SET" = c10a ] || [ "$SET" = c10b ] || [ "$SET" = c10c ]; then
    # shellcheck source=aws/enclave-up.sh
    . aws/enclave-up.sh
    step "pqcl-provision (release build, for the enclave boot)" \
        cargo build --release --locked -q -p pqcl-nitro --features enclave --bin pqcl-provision
    step "enclave up (image A, K_mst released)" enclave_up
fi
if [ "$SET" = c08b ]; then
    step "contracts (forge: the D4 Anchor build)" cargo xtask contracts
    step "exp6chain (LEChain vs the anchor, live Besu; through the enclave)" \
        env PQCL_EXP_FEATURES="chain enclave" bash besu/exp6chain.sh
    step "exp9redact (redaction vs ODXT del and rebuild; sweep; detection)" \
        cargo run --release -q -p pqcl-exp --bin exp9redact
fi
if [ "$SET" = c08c ]; then
    step "custody disclosure (10^3..10^6, redacted block, audit cores 1..16; through the enclave)" \
        env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000 \
        cargo run --release -q -p pqcl-exp --features enclave --bin custody
    step "fetch M8 artefacts" sh datasets/fetch-artefacts.sh
    step "tamper response (exp8; through the enclave)" \
        env PQCL_ARTEFACTS=datasets/artefacts PQCL_TAMPER_TRIALS=20 \
        cargo run --release -q -p pqcl-exp --features "chain enclave" --bin tamper
fi
# c08c2: custody alone, re-run on c08c's instance after its first attempt
# stopped at the second size (the cases shared capsules; fixed in custody.rs).
if [ "$SET" = c08c2 ]; then
    step "custody disclosure (10^3..10^6, redacted block, audit cores 1..16; through the enclave)"         env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000         cargo run --release -q -p pqcl-exp --features enclave --bin custody
fi
# Campaign 08's second round: the three steps the first round lost.
#   c08e  m7i.4xlarge                 exp2, after the id = (e, j) fix in exp2.rs
#                                     (c08a: WrongEpoch at the first document
#                                     of epoch 1). Same type as c08a.
#   c08d  r7i.8xlarge  + enclave      custody, after its transfer check took the
#                                     body key from the enclave (c08c2:
#                                     Authentication), then exp6chain, which
#                                     c08b's m7i.4xlarge (64 GiB, 4 to the
#                                     enclave) could not hold at 10^6 leaves per
#                                     epoch (exit 137): every record and its 29
#                                     tokens live in the server for the run.
if [ "$SET" = c08e ]; then
    step "exp2 (nested tiers, fixed query set; 1-2-5 tiers to 250k documents)"         env PQCL_EXP2_TIERS=1000,2000,5000,10000,20000,50000,100000,250000         cargo run --release -q -p pqcl-exp --bin exp2
fi
if [ "$SET" = c08d ]; then
    step "custody disclosure (10^3..10^6, redacted block, audit cores 1..16; through the enclave)"         env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000         cargo run --release -q -p pqcl-exp --features enclave --bin custody
    step "contracts (forge: the D4 Anchor build)" cargo xtask contracts
    step "exp6chain (LEChain vs the anchor, live Besu; through the enclave)"         env PQCL_EXP_FEATURES="chain enclave" bash besu/exp6chain.sh
fi
# c08f  c08d's instance, re-used    exp6chain alone, after Ais::open_segments
#                                     became a kept count. It scanned every
#                                     segment the server held, once per record,
#                                     so ingest was O(records x segments): c08d's
#                                     run spent over 3 h at 10^6 leaves per epoch
#                                     and was stopped.
if [ "$SET" = c08f ]; then
    step "contracts (forge: the D4 Anchor build)" cargo xtask contracts
    step "exp6chain (LEChain vs the anchor, live Besu; through the enclave)"         env PQCL_EXP_FEATURES="chain enclave" bash besu/exp6chain.sh
fi
# c08g  m7i.8xlarge  + enclave      custody alone, after the flat MMR's check
#                                     hashed its leaves inside the timer as ours
#                                     and replay do.
if [ "$SET" = c08g ]; then
    step "custody disclosure (10^3..10^6, redacted block, audit cores 1..16; through the enclave)"         env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000         cargo run --release -q -p pqcl-exp --features enclave --bin custody
fi
# c09a  m7i.8xlarge  + enclave      custody alone, with SAC Exp. 2's 2023+ arms
#                                     (PQ-ABL, GlassDB) beside ours, the flat MMR
#                                     and replay.
if [ "$SET" = c09a ]; then
    step "custody disclosure (10^3..10^6, redacted block, audit cores 1..16; PQ-ABL and GlassDB arms; through the enclave)"         env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000         cargo run --release -q -p pqcl-exp --features enclave --bin custody
fi
# c09b  m7i.8xlarge  + enclave      SAC Exp. 4: court-ordered redaction against
#                                     B-DEMS on a live four-validator Besu network,
#                                     at c09a's case sizes; T1 and T2 at 10^6
#
if [ "$SET" = c09b ]; then
    step "contracts (forge: Anchor and BDems builds, their tests)" cargo xtask contracts
    step "redaction (SAC Exp. 4 vs B-DEMS, live Besu; through the enclave)"         env PQCL_EXP_FEATURES="chain enclave"         PQCL_REDACT_SIZES=1000,3000,10000,30000,100000,300000,1000000         bash besu/redaction.sh
fi
# Campaign 10: two published baselines per SAC
# experiment. Three instances in parallel, c10a first (the long one).
# c10a  r7i.8xlarge  + enclave      SAC Exp. 1: exp6chain whole (ours, LEChain)
#                                     with B-DEMS's workflow on LEChain's streams.
#                                     r7i as c08f: 10^6 leaves per epoch holds
#                                     8.3 M records.
# c10b  m7i.8xlarge  + enclave      SAC Exp. 4: ours, B-DEMS and PQ-ABL's
#                                     rebuild-and-re-anchor, 10^4-record epochs,
#                                     plus the labelled one-epoch series (1ci.6).
# c10c  m7i.8xlarge  + enclave      SAC Exp. 2: custody with 10^4-record epochs.
# --- campaign 14: 2023+ comparators for draft9's
# Exps. 1-5, with ours re-measured beside them at one commit on one instance.
# c14r  r7i.4xlarge  Exp. 1 alone, the long one; start it first. As c08r: DSSE_SKQ
#                    holds a y-bit ciphertext per label, like Zuo'22 (O(y^2) memory).
# c14a  m7i.8xlarge  Exps. 2-5 and the ablation records, as c08a's set. Search runs
#                    on one core, but an SDSSE build at Exp. 2's top tier (38M pairs)
#                    is about 50 GB. Arms are built and measured one after another.
if [ "$SET" = c14r ]; then
    step "exp1 (ingestion; y axis to 65 536; SDSSE, DSSE_SKQ; ECDSA baseline)" \
        env PQCL_COLLECTION_N=256,512,1024,2048,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
            PQCL_ZUO_MEM_BUDGET_GIB=110 \
        cargo run --release -q -p pqcl-exp --bin exp1 --features classical-baseline
fi
if [ "$SET" = c14a ]; then
    step "contracts (forge, writes anchor gas for exp6)" cargo xtask contracts
    step "exp2 (nested tiers to 250k documents; ours, ODXT, SDSSE-CQ, SDSSE-CQ-S)" \
        env PQCL_EXP2_TIERS=1000,2000,5000,10000,20000,50000,100000,250000 \
        cargo run --release -q -p pqcl-exp --bin exp2
    step "exp7 (N axis 2^8..2^16, x1.5 between; ours, Zuo'22, DSSE_SKQ)" \
        env PQCL_COLLECTION_N=256,384,512,768,1024,1536,2048,3072,4096,6144,8192,12288,16384,24576,32768,49152,65536 \
        cargo run --release -q -p pqcl-exp --bin exp7
    step "index size (1-2-5 per decade; SDSSE; the Doris follow-up's real filter)" \
        cargo run --release -q -p pqcl-exp --bin size
    for b in exp6 exp345 exp8910; do
        step "$b" cargo run --release -q -p pqcl-exp --bin "$b"
    done
fi
# --- campaign 15 (plan M15-1db.8): the second baselines.
# Approved by the user 2026-11-09. One comparison stays on one host; ours is re-measured
# beside the new arms at one commit. ODXT is not re-run (its macros were retired, 1cy.3).
# c15r  r7i.8xlarge  ALL of Exp. 2, in two passes (1db.8 fix A):
#                    pass 1: ours, SDSSE-CQ/-S and VCFB at every tier, one record;
#                    pass 2: the Doris follow-up alone, ONE TIER PER PROCESS and one record
#                    per tier, only after pass 1's record is on disk, so an OOM kill or a
#                    peel failure at its top tier costs that tier and nothing else. Its stop
#                    size is exp2.rs DORIS_FU_MAX_DOCS = 5e4 (~10 kB per pair stored, ~180 GB
#                    modelled at 5e4); 1e5 and 2.5e5 run only to record why they are skipped.
# c15a  m7i.8xlarge  The whole workspace's tests first (aws/c15-workspace-test.sh, 1db.8
#                    ruling 3); only if they pass, ALL of Exps. 4 and 5: exp7 (+ MDRSSE on
#                    both axes, + SDSSE on w1^w2^w3) and exp345 (+ VCFB, the Doris follow-up).
C15_TIERS="1000 2000 5000 10000 20000 50000 100000 250000"
if [ "$SET" = c15r ]; then
    mkdir -p "$HOME/pqcl-logs"
    touch "$HOME/pqcl-logs/c15r-pass1-start"
    step "exp2 pass 1 (tiers to 250k documents; ours, SDSSE-CQ/-S, VCFB)"         env PQCL_EXP2_TIERS="$(echo $C15_TIERS | tr ' ' ',')" PQCL_EXP2_PASS=main         cargo run --release -q -p pqcl-exp --bin exp2
    # ⛔ Pass 2 only after pass 1's record exists: the merge needs it, on this commit.
    if [ -n "$(find results/exp2-conjunctive-latency -name '*.json' -newer "$HOME/pqcl-logs/c15r-pass1-start" 2>/dev/null)" ]; then
        for t in $C15_TIERS; do
            step "exp2 pass 2: the Doris follow-up at $t documents (own process, own record)"                 env PQCL_EXP2_TIERS="$t" PQCL_EXP2_QUERY_TIER=1000 PQCL_EXP2_PASS=doris-fu                 cargo run --release -q -p pqcl-exp --bin exp2
        done
    else
        echo "⛔ exp2 pass 1 wrote no record: pass 2 (the Doris follow-up) is not run" >&2
        FAILED="$FAILED
  - exp2 pass 2 not run: pass 1 wrote no record"
    fi
fi
if [ "$SET" = c15a ]; then
    step "workspace tests (cargo test --workspace --no-fail-fast; subjects provisioned)"         bash aws/c15-workspace-test.sh
    if [ -e "$HOME/pqcl-logs/c15a-workspace-tests-passed" ]; then
        step "exp7 (N axis 2^8..2^16, x1.5 between; ours, Zuo'22, DSSE_SKQ, MDRSSE; SDSSE on w1^w2^w3)"             env PQCL_COLLECTION_N=256,384,512,768,1024,1536,2048,3072,4096,6144,8192,12288,16384,24576,32768,49152,65536             cargo run --release -q -p pqcl-exp --bin exp7
        step "exp345 (Exp. 5 leakage with VCFB and the Doris follow-up; Exps. 3-5 ablations)"             cargo run --release -q -p pqcl-exp --bin exp345
    else
        echo "⛔ c15a stops: the workspace tests did not pass, so exp7 and exp345 are not run (1db.8 ruling 3)" >&2
        FAILED="$FAILED
  - c15a stopped before exp7: workspace tests failed"
    fi
fi
if [ "$SET" = c10a ]; then
    step "contracts (forge: Anchor and BDems builds, their tests)" cargo xtask contracts
    step "exp6chain (ours, LEChain and B-DEMS, live Besu; through the enclave)"         env PQCL_EXP_FEATURES="chain enclave" bash besu/exp6chain.sh
fi
if [ "$SET" = c10b ]; then
    step "contracts (forge: Anchor, BDems and PqablAnchor builds, their tests)" cargo xtask contracts
    step "redaction (SAC Exp. 4: ours, B-DEMS, PQ-ABL; live Besu; through the enclave)"         env PQCL_EXP_FEATURES="chain enclave"         PQCL_REDACT_SIZES=1000,3000,10000,30000,100000,300000,1000000         bash besu/redaction.sh
fi
if [ "$SET" = c10c ]; then
    step "custody disclosure (10^3..10^6, 10^4-record epochs, PQ-ABL and GlassDB arms; through the enclave)"         env PQCL_CUSTODY_SIZES=1000,3000,10000,30000,100000,300000,1000000         cargo run --release -q -p pqcl-exp --features enclave --bin custody
fi
if [ "$SET" = c08b ] || [ "$SET" = c08c ] || [ "$SET" = c08c2 ] || [ "$SET" = c08d ] || [ "$SET" = c08f ] || [ "$SET" = c08g ] || [ "$SET" = c09a ] || [ "$SET" = c09b ] || [ "$SET" = c10a ] || [ "$SET" = c10b ] || [ "$SET" = c10c ]; then
    nitro-cli terminate-enclave --all > /dev/null 2>&1
fi

# Not in campaign 04, on purpose:
# * Doris tiers 0-4: reused from campaign 03 (harness unchanged since 41047b6;
#   structural, run-to-run identical). Keep results/doris-structural/ in place.
# * EIF + PCR0: M5b is accepted (campaign 02); no paper cell depends on it.

# --- 4. what the campaign is for -------------------------------------------
# (The paper-coverage step was removed permanently: user, 2026-10-07, §1an.3.)

echo
echo "== publication check =="
python3 tools/mkfigs.py --check results/
echo "   (exit ${PIPESTATUS[0]})"

# --- 5. report -------------------------------------------------------------
echo
if [ -n "$FAILED" ]; then
    echo "⛔ steps that FAILED:$FAILED" >&2
    echo >&2
    echo "Do not re-run blindly. A step that failed for memory will fail again;" >&2
    echo "one that failed for a missing tool will not." >&2
else
    echo "✅ every step passed"
fi

cat <<'EOF'

⛔ NEXT, AND NOT OPTIONAL:
     aws/pull-results.sh ec2-user@<public-dns>
     aws ec2 terminate-instances --instance-ids <id>   (then describe-instances to confirm)

   Then the other set (m7i first, then r7i), each on its own instance, each
   torn down and verified before the next is launched.

A stopped instance still bills for its EBS volume, so "stopped" is not "done".
EOF

[ -z "$FAILED" ]
