#!/usr/bin/env bash
# Create a throwaway SoftHSM2 token for the pqcl-sm tests, and print the
# environment they need.
#
# Why a per-user token store rather than the packaged one: the Debian package
# creates /var/lib/softhsm/tokens owned by root:softhsm, so using it means
# adding the developer to a group and sharing mutable state between runs. A
# token under the user's own directory needs no privilege, and can be deleted
# and recreated, which is what makes the tests reproducible.
#
# Usage:
#   eval "$(scripts/softhsm2-init.sh)"
#   cargo test -p pqcl-sm
#
# The `eval` matters. SoftHSM2 reads SOFTHSM2_CONF at C_Initialize, which
# happens inside the test process before any of our code runs, so the variable
# must already be in the environment the test inherits.

set -euo pipefail

STORE="${PQCL_SOFTHSM_STORE:-$HOME/.pqcl-softhsm}"
LABEL="${PQCL_SOFTHSM_LABEL:-pqcl-test}"
PIN="${PQCL_SOFTHSM_PIN:-1234}"
SO_PIN="${PQCL_SOFTHSM_SO_PIN:-123456}"

# Resolve the module. The path differs between distributions and guessing wrong
# produces a confusing CKR_GENERAL_ERROR much later, so fail here instead.
MODULE=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so     /usr/lib64/pkcs11/libsofthsm2.so     /usr/lib64/softhsm/libsofthsm2.so
do
    if [ -e "$candidate" ]; then MODULE="$candidate"; break; fi
done

if [ -z "$MODULE" ]; then
    echo "error: libsofthsm2.so not found. Install with:" >&2
    echo "  sudo apt-get install -y softhsm2 libsofthsm2-dev opensc" >&2
    exit 1
fi

mkdir -p "$STORE/tokens"
cat > "$STORE/softhsm2.conf" <<CONF
directories.tokendir = $STORE/tokens
objectstore.backend = file
log.level = ERROR
CONF

export SOFTHSM2_CONF="$STORE/softhsm2.conf"

# Initialising an already-initialised label is an error, so only do it once.
# Re-running this script must be safe; a setup step that fails the second time
# is a setup step people work around.
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*$LABEL"; then
    softhsm2-util --init-token --free \
        --label "$LABEL" --so-pin "$SO_PIN" --pin "$PIN" >/dev/null
fi

echo "export SOFTHSM2_CONF='$STORE/softhsm2.conf'"
echo "export PQCL_PKCS11_MODULE='$MODULE'"
echo "export PQCL_PKCS11_PIN='$PIN'"
