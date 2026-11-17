# `CDSecLab/Doris` — OXT, HXT, ConjFilter and Doris, in the authors' own stack.
#
# ⭐ **This container deliberately does NOT modernize the runtime**, which is the
# opposite of what `implementation-plan.md` §7 asks for reimplemented baselines.
# The reason is specific and it is worth stating plainly:
#
# > Plan §5: our system is Rust, this is Python, so **comparing their wall-clock
# > is meaningless**. We take only the language-independent axes — index size,
# > communication volume, round count, leakage.
#
# Modernizing exists to stop a baseline being slow for reasons unrelated to its
# design. **We take no timing from this code at all**, so modernizing buys
# nothing and costs fidelity: every version bump is a chance to change behaviour
# in a reused implementation nobody here wrote. Reproducing the authors'
# environment exactly is the lower-risk choice *because* the metrics are
# language-independent. That reasoning is recorded in `../UPGRADES.md`, not left
# for a reader to reconstruct.
#
# One consequence worth noting: the usual "never build under `/mnt`, 9p will
# wreck your I/O measurements" rule does not bite here either, for the same
# reason — there is no timing to wreck.
#
# 📌 Ubuntu 20.04 is past its standard-support date but **`archive.ubuntu.com`
# still serves `focal`** (checked 2026-09-13: `dists/focal/Release` returns 200,
# while `old-releases.ubuntu.com` returns 404). An earlier version of this file
# rewrote the sources to `old-releases` on the assumption that EOL implies the
# move; it does not, and the rewrite is what broke the build. Left as-is, and
# recorded so nobody "fixes" it back.
#
# Build:  docker build -t pqcl-doris:1 baselines/doris/
# Run:    baselines/doris/run.sh setup

FROM ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-dev python3-pip \
        build-essential flex bison libgmp-dev \
        wget ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# PBC 0.5.14, exactly the version the README names, built from source because it
# is not packaged.
#
# The checksum below was taken from an actual download (654 515 bytes, verified
# 2026-09-13), not from recollection — `datasets/fetch-enron.sh` carries the same
# lesson in its own comments: a value nobody has checked is indistinguishable
# from a wrong one, and a checksum that rejects a good download teaches the next
# person to delete the check. Without it a truncated tarball surfaces as a
# linker error deep inside the pypbc build, which is a bad afternoon.
RUN wget -q https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && echo "772527404117587560080241cedaf441e5cac3269009cdde4c588a1dce4c23d2  pbc-0.5.14.tar.gz" | sha256sum -c - \
    && tar -xf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure --prefix=/usr --enable-shared \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && cd .. && rm -rf pbc-0.5.14 pbc-0.5.14.tar.gz

# `pypbc` is unmaintained — no release on PyPI, no tags, no CI. Pinned to an
# exact commit for the same reason the base image is pinned by digest: "the
# default branch as of whenever you built this" is not a reproducible input.
ARG PYPBC_COMMIT=c518d6ff074f538080c5794924f83ee441ed44ea
RUN git clone -q https://github.com/debatem1/pypbc /tmp/pypbc \
    && cd /tmp/pypbc \
    && git checkout -q "$PYPBC_COMMIT" \
    && pip3 install --no-cache-dir . \
    && rm -rf /tmp/pypbc

# The authors' own pinned requirements, unchanged.
COPY requirements-upstream.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Record what actually got installed, so a metric can be traced to the stack
# that produced it rather than to an assumption about it.
RUN { \
      echo "ubuntu=$(. /etc/os-release && echo "$VERSION_ID")"; \
      echo "python=$(python3 --version 2>&1)"; \
      echo "pbc=0.5.14"; \
      echo "pypbc=$PYPBC_COMMIT"; \
      pip3 freeze | grep -iE 'bitarray|mmh3|pycryptodome|pympler'; \
    } > /etc/pqcl-doris-versions

WORKDIR /work
