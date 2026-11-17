# M5b — the AWS Nitro Enclave Secure Module

The agent-side Secure Module, running inside a Nitro Enclave, reached from the
parent instance over vsock.

## What is built, and what still needs AWS

| | State |
|---|---|
| Wire protocol (`pqcl-nitro::proto`) | ✅ built, unit-tested — round-trip, unknown tags, truncation, oversized frames |
| Enclave server (`pqcl-nitro::enclave`) | ✅ built. Wraps `HostAgentModule` — **the same source** the host module runs, per the standing rule's condition 3 |
| Host proxy (`pqcl-nitro::host`) | ✅ built. Implements `KeyCustody` + `AgentModule` across the boundary |
| Dockerfile | ✅ built, both base images pinned by resolved digest |
| `build-eif.sh` | ✅ built. Needs `nitro-cli`, **no credentials**. `--image-only` verifies everything up to the EIF with Docker alone |
| NSM attestation (`/dev/nsm`) | ✅ written (`enclave::attest`); runnable only inside an enclave |
| KMS release of `K_mst` | ✅ written — `kmstool_enclave_cli decrypt`, fed by **boot-time provisioning over vsock** (below) |
| Parent tool `pqcl-provision` | ✅ built. Exit 0 released / **3 refused** / 1 no answer |
| **`m5b-acceptance.sh`** | ✅ the whole acceptance test, scripted. First real run is on AWS |

⭐ **Credentials are needed only from "Provision" onward.** Everything above the
line — including building the EIF and reading PCR0 — is local.

## ⭐ Provisioning: the enclave gets its inputs from the parent, never the image

The enclave boots holding nothing and accepts exactly one `Provision` message on
vsock port 5005: region, proxy port, the wrapped `K_mst`, and the parent role's
short-lived credentials. It runs `kmstool`, **replies with the outcome**, then
either serves or exits.

⛔ **Corrected 2026-09-25.** The first version read these from the enclave's
environment, "set by `nitro/Dockerfile`" — which set none of them, so the first
AWS boot would have died at `PQCL_KMS_REGION is unset`. And setting them there
would have been worse: an enclave's environment *is* its image, so live IAM
credentials would sit in the EIF, expire within hours, and move PCR0 on every
refresh. Provisioning keeps PCR0 a function of the code alone.

The credentials crossing the boundary is sound: they are the parent's own, and
they are not what authorises the decrypt — the PCR0 condition is. `Provision`'s
`Debug` redacts them anyway, and a test pins that.

The enclave still **fails closed**: a KMS refusal is reported to the parent and
the enclave exits rather than generating a key. A locally generated key would
produce signatures that verify against nothing and pseudonyms that do not match
what is already anchored.

## ⚠️ `K_mst` does not "never leave"

The Secure Module standing rule, correction 2, and it is a **paper defect** in
`draft6.tex` eq. (`eq:kmst`) until it is restated:

> An enclave has no persistent store. Across a restart `K_mst` survives only as
> a KMS-wrapped blob whose key policy conditions release on the enclave's PCR
> measurements — so it *does* leave, encrypted, and **AWS KMS joins the recovery
> TCB**.

The correct claim is: never leaves **in plaintext**; persistence is
attestation-gated.

⭐ **The acceptance test is the one that checks the property actually claimed:**
mutate the enclave image and assert KMS *refuses* the unwrap. A test that only
shows the happy path would pass just as well against a key policy that
conditions on nothing.

## Step 1 — base image pins (done)

Both `FROM` lines carry resolved digests. The toolchain must stay `1.97.1`,
matching `rust-toolchain.toml`; a mismatch moves PCR0 for a reason that has
nothing to do with our source.

⚠️ The final stage runs `apt-get update`, so PCR0 is **not reproducible across
days** — package versions drift. Harmless for the acceptance test, which builds
A and B in one session; it matters for any claim that a PCR0 can be rebuilt
later, and the key policy must be bound to the PCR0 of the EIF actually
deployed, never to one recomputed afterwards.

## Step 2 — build the EIF and pin PCR0 (no credentials)

```sh
nitro/build-eif.sh
```

Produces `nitro/out/pqcl-enclave.eif` and `nitro/out/measurements.json`, the
latter carrying PCR0/1/2 plus the git commit that produced them. ⚠️ The script
warns if the tree was dirty: a PCR0 that corresponds to no commit is not
reproducible.

## Step 3 — provision (⭐ **credentials needed from here**)

An enclave-enabled instance. `m7i` is the family the standing rule names for the
boundary-overhead measurement, and that measurement must compare **enclave
versus parent process on the same instance** — never local versus AWS, which
measures two machines rather than one boundary.

```sh
aws ec2 run-instances \
  --instance-type m7i.xlarge \
  --enclave-options 'Enabled=true' \
  --image-id <al2023-ami> ...
```

On the instance:

```sh
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
sudo usermod -aG ne "$USER"; sudo usermod -aG docker "$USER"
sudo systemctl enable --now nitro-enclaves-allocator.service
```

⚠️ The allocator reserves memory and vCPUs for enclaves at boot; its config is
`/etc/nitro_enclaves/allocator.yaml`. An enclave cannot start if the allocator
has not reserved enough.

⛔ **Never run the enclave and SP1 proving at the same time.** The allocator
carves its memory out of the parent, and compressed proving already needed
>10.2 GiB. A 4 GB enclave leaves 28 GiB of 32, and the failure mode is an OOM
kill that reads as a proving bug.

### ⭐ Step 3a — prove the results pipeline works, before measuring anything

Two minutes, and it protects the whole campaign. The pipeline refuses to publish
a record whose `environment` is not `aws`, and that field is **detected** from
SMBIOS — a detector that has never once been observed returning `Aws`, because
the strings it reads do not exist off EC2.

```sh
cargo run --release --example emit_record -- results/ --require-aws
python3 tools/mkfigs.py --check results/
```

Expected here, and **only** here: `environment detected as Aws`, `publishable:
yes`, and `mkfigs.py` exiting 0. Anywhere else both refuse, naming `not_aws`.

⛔ **`--require-aws` makes this a hard gate, not a printed warning.** It exits
non-zero when the record would be unpublishable, so a wrong detector stops the
campaign here rather than being discovered at the end. Put it in the campaign
script ahead of every experiment: a check enforced by "somebody reads stdout" is
the same class of control that let `RunMetadata` go unconstructed.

Then confirm the tree stays clean, since a dirty tree is also a refusal:

```sh
cargo test --workspace --all-features --locked && (cd contracts && forge test)
git status --porcelain     # must be empty
rm -rf results/pipeline-rehearsal
```

## ⭐ Steps 4–5 are one script

```sh
# admin side, once:     aws kms create-key --tags TagKey=Project,TagValue=PQ-ChainLog
# instance, phase 1 — build A, write the policy, stop:
PQCL_KMS_KEY_ID=<KeyId> bash nitro/m5b-acceptance.sh
# admin side: kms put-key-policy --key-id <KeyId> --policy-name default --policy file://key-policy.json
# instance, phase 2 — reuse A byte for byte, run the test:
PQCL_KMS_KEY_ID=<KeyId> bash nitro/m5b-acceptance.sh --policy-applied \
    2>&1 | tee ~/pqcl-logs/m5b-acceptance.log
```

⚠️ The instance role has **no permissions of its own**, so it cannot apply a key
policy; an administrator does, from outside. And A is **never rebuilt** between
the phases: the Dockerfile's `apt-get update` drifts, so a rebuild could carry a
PCR0 the applied policy does not name.

It builds A, binds the key to PCR0_A, mints `K_mst` with
**`GenerateDataKeyWithoutPlaintext`** — so `K_mst` never exists in plaintext
outside an enclave, not even during setup — boots A and expects release, derives
B by appending **one byte** to the enclave binary, checks PCR0 moved, boots B and
expects **refusal**. Verdict and both PCR0s land in
`~/pqcl-logs/m5b-acceptance.json`. The first run stops before touching the key
so the policy can be read first.

⚠️ **The policy the script writes adds an explicit `Deny`** on `kms:Decrypt`
for the parent role unless PCR0 matches. Without it, an IAM identity policy
granting the role `kms:Decrypt` would let anything decrypt with no attestation —
and step 5 would, correctly, fail. The sections below are the manual
equivalent, kept for reading.

## Step 4 — the KMS key and its policy

Create a key, then condition `kms:Decrypt` on the PCR0 from step 2:

```json
{
  "Sid": "OnlyThisEnclaveMayDecrypt",
  "Effect": "Allow",
  "Principal": {"AWS": "<parent instance role ARN>"},
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<PCR0 from measurements.json>"
    }
  }
}
```

⭐ **This condition is the entire security argument.** KMS verifies the
attestation document itself — which is why this repository does not contain a
second COSE/CBOR verifier. A weaker home-grown verifier for a property AWS
already enforces would be a liability, and if the two disagreed, ours would be
the wrong one.

Wrap `K_mst` once under this key and store the ciphertext where the parent can
read it. The parent cannot decrypt it; only the enclave can.

## Step 5 — run, and prove the property

```sh
nitro-cli run-enclave \
  --eif-path nitro/out/pqcl-enclave.eif \
  --cpu-count 2 --memory 2048 \
  --enclave-cid 16
```

⚠️ The enclave has no network. Reaching KMS needs a **vsock proxy** on the
parent (`vsock-proxy`, shipped with the CLI) forwarding to the KMS endpoint.

Then the acceptance test:

1. With the correct image, the enclave unwraps `K_mst` and serves.
2. **Change one byte of the enclave binary**, rebuild the EIF, confirm PCR0
   moved, and run again. **KMS must refuse the decrypt.** That refusal — not the
   happy path — is what demonstrates the key policy is doing anything at all.

## What to measure once it runs

- **Boundary overhead**: `σ_DEFR` throughput, enclave versus parent process, on
  the *same* instance. ⛔ Never enclave-on-AWS versus host-on-laptop.
- The identical `KeyCustody` suite that M5a ran against SoftHSM2 and the host
  module, now against `NitroAgentModule`, so all three backends answer the same
  questions — including the extraction refusal.

⛔ No number from here reaches the paper except through the results pipeline,
which refuses a dirty tree or a non-AWS run.
