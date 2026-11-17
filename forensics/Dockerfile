# Real forensic tooling, pinned.
#
# ⭐ **Why a container rather than `apt install` on the host.** Three reasons,
# in order of weight:
#
# 1. **Reproducibility.** `implementation-plan.md` §4 already requires Docker
#    images to be pinned by digest for exactly this reason — a tool version that
#    changed silently between two runs makes them incomparable. A custody record
#    commits `params_c = H(tool ‖ version ‖ args ‖ just ‖ r_p)`, so the tool
#    *version* is inside a signed structure. It has to be a fact, not whatever
#    the host happened to have.
# 2. **No `sudo`.** The developer box cannot `apt-get install` without an
#    interactive password (`Require-Consultant.md` row P0.3), but the user is
#    already in the `docker` group.
# 3. **The tools stay real.** Ground rule #1 bans simulation. These are the
#    upstream Debian packages and upstream Volatility 3 — not reimplementations,
#    not wrappers that print plausible output.
#
# ⚠️ **Base pinned by digest, not by tag.** `debian:bookworm-slim` moves.
#
# Build:  docker build -t pqcl-forensics:1 forensics/
# Run:    forensics/run.sh <tool> [args...]

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# `sleuthkit` brings fls/icat/mmls/fsstat; `ewf-tools` + `libewf-dev` are what
# let TSK open an .E01 at all, which is the format the NPS drive corpus ships.
# `tshark` is the packet dissector. `python3-pip` is only for Volatility.
#
# ⚠️ No `apt-get upgrade`: it would pull whatever is current at build time and
# defeat the digest pin above. The base is the pinned thing; adding a floating
# upgrade on top makes the pin decorative.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        sleuthkit \
        ewf-tools \
        libewf2 \
        tshark \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Volatility 3 is not packaged in Debian, and the pip release is the upstream
# artefact. Pinned to an exact version for the same reason as the base image.
#
# `--break-system-packages` is required on bookworm (PEP 668). This is a
# single-purpose container with no other Python consumer, so there is no
# environment to break; a venv would add a layer and an activation step for no
# isolation benefit here.
RUN pip3 install --no-cache-dir --break-system-packages volatility3==2.11.0

# ⚠️ **Volatility writes downloaded symbols to a package-relative path**, not to
# whatever `-s` or `VOLATILITY3_SYMBOL_DIRS` names — those only tell it where to
# *read*. So the Windows symbol directory has to exist and be writable by the
# mapped (non-root) user, and `run.sh` bind-mounts a persistent host directory
# over it so a download survives the container.
#
# The path is pinned alongside the base image. `test -d` makes a base change
# fail at build time rather than as a confusing permissions warning at run time.
RUN test -d /usr/local/lib/python3.11/dist-packages/volatility3/symbols     && mkdir -p /usr/local/lib/python3.11/dist-packages/volatility3/symbols/windows     && chmod -R a+rwX /usr/local/lib/python3.11/dist-packages/volatility3/symbols

# Record what actually got installed, so `params_c` can commit a version that
# was observed rather than assumed. Read by `run.sh --versions`.
RUN { \
      echo "sleuthkit=$(fls -V 2>&1 | head -1)"; \
      echo "ewf-tools=$(ewfinfo -V 2>&1 | head -1)"; \
      echo "tshark=$(tshark -v 2>/dev/null | head -1)"; \
      echo "volatility3=$(vol -h 2>&1 | grep -oE 'Volatility 3 Framework [0-9.]+' | head -1)"; \
      echo "debian=$(cat /etc/debian_version)"; \
    } > /etc/pqcl-tool-versions

# tshark refuses to run as root by default and warns loudly; the wrapper passes
# --user anyway, so the container never needs a root shell.
WORKDIR /work
