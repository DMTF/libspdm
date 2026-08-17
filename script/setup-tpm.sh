#!/bin/sh -e

KEY_ALGORITHM=ecc
HASH_ALGORITHM=256

ROOT_CTX=0x81000000
ROOT_KEY=0x81000001
REQU_CTX=0x81000010
REQU_KEY=0x81000011
RESP_CTX=0x81000020
RESP_KEY=0x81000021

ROOT_CERT=0x1500000
REQU_CERT=0x1500010
RESP_CERT=0x1500020

REQU_CERT_CHAIN=0x1500011
RESP_CERT_CHAIN=0x1500021

usage() {
    echo "Usage: $0 [--start-swtpm] [--wait-swtpm] [--cleanup]"
    echo "          [--key-algorithm=<alg>] [--hash-algorithm=<bits>]"
}

while [ $# -gt 0 ] ; do
    case "$1" in
        --start-swtpm)
            START_SWTPM=1
            ;;
        --key-algorithm=*)
            KEY_ALGORITHM=${1#*=}
            ;;
        --hash-algorithm=*)
            HASH_ALGORITHM=${1#*=}
            ;;
        --wait-swtpm)
            WAIT_SWTPM=1
            ;;
        --cleanup)
            CLEANUP=1
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# Use a dedicated working directory so generated files (.ctx, .pub, .priv,
# .csr, .pem, .der, openssl.cnf) never collide with caller's CWD.
WORK_DIR="$(mktemp -d /tmp/spdm-tpm-setup.XXXXXXXXXX)"

if [ -n "$START_SWTPM" ] ; then
    SWTPM_STATE_DIR="$(mktemp -d /tmp/swtpm-state.XXXXXXXXXX)"

    cleanup() {
        if [ -n "$CLEANUP_DONE" ] ; then
            return
        fi
        CLEANUP_DONE=1

        echo "Killing swtpm ${SWTPM_PID}..."
        kill "${SWTPM_PID}" 2>/dev/null || true
        wait "${SWTPM_PID}" 2>/dev/null || true

        echo "Cleaning up swtpm state dir..."
        rm -rf "${SWTPM_STATE_DIR}"

        echo "Cleaning up work dir..."
        rm -rf "${WORK_DIR}"
    }

    trap cleanup EXIT INT

    echo "Starting SWTPM..."
    swtpm socket \
        --tpm2 \
        --flags not-need-init,startup-clear \
        --tpmstate dir="${SWTPM_STATE_DIR}" \
        --server type=tcp,port=2321 \
        --ctrl type=tcp,port=2322 &
    SWTPM_PID="$!"
    sleep 1

    # Route all tpm2-tools commands to the simulator we just started.
    export TPM2TOOLS_TCTI=swtpm:port=2321
    echo "TPM2TOOLS_TCTI set to swtpm:port=2321"
else
    # No simulator: clean up work dir on exit.
    cleanup() {
        rm -rf "${WORK_DIR}"
    }
    trap cleanup EXIT INT
fi

echo "Checking TPM availability..."
tpm2_getcap properties-fixed || {
    echo "tpm2_getcap failed"
    exit 1
}

if [ -n "$CLEANUP" ] ; then
    echo "Cleaning up persistent handles"
    for i in $ROOT_CTX $ROOT_KEY $REQU_CTX $REQU_KEY $RESP_CTX $RESP_KEY ; do
        tpm2_evictcontrol -C o -c "$i" 2>/dev/null || true
    done
    for i in $ROOT_CERT $REQU_CERT $RESP_CERT $REQU_CERT_CHAIN $RESP_CERT_CHAIN ; do
        tpm2_nvundefine -C o "$i" 2>/dev/null || true
    done
    tpm2_flushcontext --transient-object 2>/dev/null || true
fi

echo "Flushing any pre-existing transient/session handles..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

cat > "${WORK_DIR}/openssl.cnf" << EOF
[v3_ca]
basicConstraints = critical,CA:true

[ v3_req ]
basicConstraints = critical,CA:false
EOF

#
# Root CA
#

echo "Creating root ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} \
    -c "${WORK_DIR}/root_ca.ctx"
# Idempotent: evict any stale handle before persisting.
tpm2_evictcontrol -C o -c ${ROOT_CTX} 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/root_ca.ctx" ${ROOT_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating root keys..."
tpm2_create -C ${ROOT_CTX} -G ${KEY_ALGORITHM} \
    -u "${WORK_DIR}/root_ca.pub" -r "${WORK_DIR}/root_ca.priv"

echo "Loading root key..."
tpm2_load -C ${ROOT_CTX} \
    -u "${WORK_DIR}/root_ca.pub" -r "${WORK_DIR}/root_ca.priv" \
    -c "${WORK_DIR}/root_ca_key.ctx"

echo "Persisting root ca at ${ROOT_KEY}..."
tpm2_evictcontrol -C o -c ${ROOT_KEY} 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/root_ca_key.ctx" ${ROOT_KEY}
tpm2_flushcontext --transient-object 2>/dev/null || true

echo "Generating root ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Root CA" \
    -key "handle:${ROOT_KEY}" \
    -config "${WORK_DIR}/openssl.cnf" \
    -extensions v3_ca \
    -out "${WORK_DIR}/root_ca_cert.csr"

echo "Generating root ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in "${WORK_DIR}/root_ca_cert.csr" \
    -signkey "handle:${ROOT_KEY}" \
    -extfile "${WORK_DIR}/openssl.cnf" \
    -extensions v3_ca \
    -days 356 \
    -out "${WORK_DIR}/root_ca_cert.pem"

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in "${WORK_DIR}/root_ca_cert.pem" \
    -out "${WORK_DIR}/root_ca_cert.der"

echo "Storing root ca into TPM NVram..."
tpm2_nvundefine -C o ${ROOT_CERT} 2>/dev/null || true
tpm2_nvdefine ${ROOT_CERT} -C o \
    -s "$(stat -c %s "${WORK_DIR}/root_ca_cert.der")" \
    -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${ROOT_CERT} -C o -i "${WORK_DIR}/root_ca_cert.der"

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Requester
#

echo "Creating requester ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} \
    -c "${WORK_DIR}/requester.ctx"
tpm2_evictcontrol -C o -c ${REQU_CTX} 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/requester.ctx" ${REQU_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating requester keys..."
tpm2_create -C ${REQU_CTX} -G ${KEY_ALGORITHM} \
    -u "${WORK_DIR}/requester.pub" -r "${WORK_DIR}/requester.priv"

echo "Loading requester key..."
tpm2_load -C ${REQU_CTX} \
    -u "${WORK_DIR}/requester.pub" -r "${WORK_DIR}/requester.priv" \
    -c "${WORK_DIR}/requester_key.ctx"

echo "Persisting requester ca at ${REQU_KEY}..."
tpm2_evictcontrol -C o -c ${REQU_KEY} 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/requester_key.ctx" ${REQU_KEY}
tpm2_flushcontext --transient-object 2>/dev/null || true

echo "Generating requester ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Requester Certificates" \
    -config "${WORK_DIR}/openssl.cnf" \
    -extensions v3_req \
    -key "handle:${REQU_KEY}" \
    -out "${WORK_DIR}/requester_cert.csr"

echo "Generating requester ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in "${WORK_DIR}/requester_cert.csr" \
    -CA "${WORK_DIR}/root_ca_cert.pem" \
    -CAkey "handle:${ROOT_KEY}" \
    -days 356 \
    -extfile "${WORK_DIR}/openssl.cnf" \
    -extensions v3_req \
    -out "${WORK_DIR}/requester_cert.pem"

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in "${WORK_DIR}/requester_cert.pem" \
    -out "${WORK_DIR}/requester_cert.der"

echo "Creating certificate chain..."
cat "${WORK_DIR}/root_ca_cert.der" "${WORK_DIR}/requester_cert.der" \
    > "${WORK_DIR}/requester_certchain.der"

echo "Storing requester ca into TPM NVram..."
tpm2_nvundefine -C o ${REQU_CERT} 2>/dev/null || true
tpm2_nvdefine ${REQU_CERT} -C o \
    -s "$(stat -c %s "${WORK_DIR}/requester_cert.der")" \
    -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT} -C o -i "${WORK_DIR}/requester_cert.der"

echo "Storing requester ca chain into TPM NVram..."
tpm2_nvundefine -C o ${REQU_CERT_CHAIN} 2>/dev/null || true
tpm2_nvdefine ${REQU_CERT_CHAIN} -C o \
    -s "$(stat -c %s "${WORK_DIR}/requester_certchain.der")" \
    -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT_CHAIN} -C o -i "${WORK_DIR}/requester_certchain.der"

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Responder
#

echo "Creating responder ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} \
    -c "${WORK_DIR}/responder.ctx"
tpm2_evictcontrol -C o -c ${RESP_CTX} 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/responder.ctx" ${RESP_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating responder keys..."
tpm2_create -C ${RESP_CTX} -G ${KEY_ALGORITHM} \
    -u "${WORK_DIR}/responder.pub" -r "${WORK_DIR}/responder.priv"

echo "Loading responder key..."
tpm2_load -C ${RESP_CTX} \
    -u "${WORK_DIR}/responder.pub" -r "${WORK_DIR}/responder.priv" \
    -c "${WORK_DIR}/responder_key.ctx"

echo "Persisting responder ca at ${RESP_KEY}..."
tpm2_evictcontrol -C o -c ${RESP_KEY} 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/responder_key.ctx" ${RESP_KEY}
tpm2_flushcontext --transient-object 2>/dev/null || true

echo "Generating responder ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Responder Certificates" \
    -config "${WORK_DIR}/openssl.cnf" \
    -extensions v3_req \
    -key "handle:${RESP_KEY}" \
    -out "${WORK_DIR}/responder_cert.csr"

echo "Generating responder ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in "${WORK_DIR}/responder_cert.csr" \
    -CA "${WORK_DIR}/root_ca_cert.pem" \
    -CAkey "handle:${ROOT_KEY}" \
    -extfile "${WORK_DIR}/openssl.cnf" \
    -extensions v3_req \
    -days 356 \
    -out "${WORK_DIR}/responder_cert.pem"

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in "${WORK_DIR}/responder_cert.pem" \
    -out "${WORK_DIR}/responder_cert.der"

echo "Creating certificate chain..."
cat "${WORK_DIR}/root_ca_cert.der" "${WORK_DIR}/responder_cert.der" \
    > "${WORK_DIR}/responder_certchain.der"

echo "Storing responder ca into TPM NVram..."
tpm2_nvundefine -C o ${RESP_CERT} 2>/dev/null || true
tpm2_nvdefine ${RESP_CERT} -C o \
    -s "$(stat -c %s "${WORK_DIR}/responder_cert.der")" \
    -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT} -C o -i "${WORK_DIR}/responder_cert.der"

echo "Storing responder ca chain into TPM NVram..."
tpm2_nvundefine -C o ${RESP_CERT_CHAIN} 2>/dev/null || true
tpm2_nvdefine ${RESP_CERT_CHAIN} -C o \
    -s "$(stat -c %s "${WORK_DIR}/responder_certchain.der")" \
    -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT_CHAIN} -C o -i "${WORK_DIR}/responder_certchain.der"

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true

if [ -n "$START_SWTPM" ] ; then
    echo "Run the following command to use the SWTPM via tpm2-tools in another shell:"
    echo "  export TPM2TOOLS_TCTI=swtpm:port=2321"

    if [ -n "$WAIT_SWTPM" ] ; then
        echo "Press CTRL+C to stop swtpm"
        wait $SWTPM_PID
    fi
fi

echo "Done"
