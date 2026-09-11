#!/usr/bin/env bash
#
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
#
# Helper script to launch swtpm, provision required TPM keys/NV/PCRs,
# and execute the libspdm TPM test binary.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBSPDM_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TEST_BIN="${1:-${LIBSPDM_ROOT}/build/bin/test_spdm_tpm}"

if [ ! -x "${TEST_BIN}" ]; then
    echo "[ERROR] Test binary not found or not executable: ${TEST_BIN}"
    echo "Usage: $0 [path/to/test_spdm_tpm]"
    exit 1
fi

# Detect openssl modules path for tpm2 provider if not set
if [ -z "${OPENSSL_MODULES}" ]; then
    for mod_path in \
        /usr/lib/$(uname -m)-linux-gnu/ossl-modules \
        /usr/lib64/ossl-modules \
        /usr/lib/ossl-modules \
        /usr/local/lib/ossl-modules \
        /usr/local/lib64/ossl-modules ; do
        if [ -f "${mod_path}/tpm2.so" ]; then
            export OPENSSL_MODULES="${mod_path}"
            break
        fi
    done
fi

# Check if swtpm and tpm2-tools are available
if ! command -v swtpm >/dev/null 2>&1 || ! command -v tpm2_startup >/dev/null 2>&1; then
    echo "[WARN] swtpm or tpm2-tools not installed. Running offline tests only..."
    "${TEST_BIN}"
    exit $?
fi

# Find two adjacent free TCP ports for swtpm (tcti-swtpm uses server_port + 1 for ctrl)
PORTS=$(python3 -c '
import socket
for p in range(2321, 60000):
    try:
        s1 = socket.socket()
        s1.bind(("", p))
        s2 = socket.socket()
        s2.bind(("", p + 1))
        s1.close()
        s2.close()
        print(f"{p} {p+1}")
        break
    except:
        continue
')

SERVER_PORT=$(echo "${PORTS}" | cut -d' ' -f1)
CTRL_PORT=$(echo "${PORTS}" | cut -d' ' -f2)

TPM_DIR=$(mktemp -d -t tpm_test_XXXXXX)
SWTPM_PID=""

cleanup() {
    if [ -n "${SWTPM_PID}" ] && kill -0 "${SWTPM_PID}" 2>/dev/null; then
        kill "${SWTPM_PID}" 2>/dev/null || true
        wait "${SWTPM_PID}" 2>/dev/null || true
    fi
    if [ -n "${TPM_DIR}" ] && [ -d "${TPM_DIR}" ]; then
        rm -rf "${TPM_DIR}"
    fi
}
trap cleanup EXIT INT TERM

echo "[INFO] Starting swtpm on port ${SERVER_PORT} (ctrl: ${CTRL_PORT})..."
swtpm socket \
    --tpmstate dir="${TPM_DIR}" \
    --tpm2 \
    --ctrl type=tcp,port="${CTRL_PORT}" \
    --server type=tcp,port="${SERVER_PORT}" \
    --flags not-need-init &
SWTPM_PID=$!

# Wait briefly for swtpm socket readiness
sleep 0.5

export TPM2TOOLS_TCTI="swtpm:port=${SERVER_PORT}"
export TPM2OPENSSL_TCTI="swtpm:port=${SERVER_PORT}"

echo "[INFO] Initializing TPM simulator..."
tpm2_startup -c

# Locate sample keys
RESP_KEY="${LIBSPDM_ROOT}/unit_test/sample_key/ecp256/end_responder.key"
REQ_KEY="${LIBSPDM_ROOT}/unit_test/sample_key/ecp256/end_requester.key"
RESP_CERT="${LIBSPDM_ROOT}/unit_test/sample_key/ecp256/bundle_responder.certchain.der"
REQ_CERT="${LIBSPDM_ROOT}/unit_test/sample_key/ecp256/bundle_requester.certchain.der"

echo "[INFO] Provisioning primary parent handle 0x81000000..."
tpm2_createprimary -C o -g sha256 -G ecc -c "${TPM_DIR}/parent.ctx"
tpm2_evictcontrol -C o -c "${TPM_DIR}/parent.ctx" 0x81000000
tpm2_flushcontext -t

echo "[INFO] Importing Responder key to 0x81000021..."
tpm2_import -C 0x81000000 -G ecc256:ecdsa -i "${RESP_KEY}" -u "${TPM_DIR}/resp.pub" -r "${TPM_DIR}/resp.priv"
tpm2_flushcontext -t
tpm2_load -C 0x81000000 -u "${TPM_DIR}/resp.pub" -r "${TPM_DIR}/resp.priv" -c "${TPM_DIR}/resp.ctx"
tpm2_evictcontrol -C o -c "${TPM_DIR}/resp.ctx" 0x81000021
tpm2_flushcontext -t

echo "[INFO] Importing Requester key to 0x81000011..."
tpm2_import -C 0x81000000 -G ecc256:ecdsa -i "${REQ_KEY}" -u "${TPM_DIR}/req.pub" -r "${TPM_DIR}/req.priv"
tpm2_flushcontext -t
tpm2_load -C 0x81000000 -u "${TPM_DIR}/req.pub" -r "${TPM_DIR}/req.priv" -c "${TPM_DIR}/req.ctx"
tpm2_evictcontrol -C o -c "${TPM_DIR}/req.ctx" 0x81000011
tpm2_flushcontext -t

echo "[INFO] Provisioning Certificate NV Indices (0x1500021 and 0x1500011)..."
RESP_CERT_SIZE=$(stat -c %s "${RESP_CERT}")
REQ_CERT_SIZE=$(stat -c %s "${REQ_CERT}")

tpm2_nvdefine -C o -s "${RESP_CERT_SIZE}" -a "ownerread|ownerwrite|authread|authwrite|ppread|ppwrite" 0x1500021
tpm2_nvwrite -C o -i "${RESP_CERT}" 0x1500021

tpm2_nvdefine -C o -s "${REQ_CERT_SIZE}" -a "ownerread|ownerwrite|authread|authwrite|ppread|ppwrite" 0x1500011
tpm2_nvwrite -C o -i "${REQ_CERT}" 0x1500011

echo "[INFO] Extending PCRs 0 and 1..."
tpm2_pcrextend 0:sha256=1111111111111111111111111111111111111111111111111111111111111111
tpm2_pcrextend 1:sha256=2222222222222222222222222222222222222222222222222222222222222222

echo "[INFO] Executing test binary: ${TEST_BIN}..."
"${TEST_BIN}"
TEST_STATUS=$?

echo "[INFO] Test execution completed with exit code: ${TEST_STATUS}"
exit ${TEST_STATUS}
