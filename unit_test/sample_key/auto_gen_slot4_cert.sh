#!/bin/bash

# Auto gen script for the slot_4 certificate chain.
#
# slot_4 (rather than the next contiguous slot) is used on purpose to demonstrate a NON-CONTIGUOUS
# slot configuration: slots 0, 1 and 4 are populated while slots 2 and 3 are empty.
#
# Unlike bundle_*.certchain1.der (slot 1), which reuses the slot 0 leaf key under a new CA, the
# slot_4 chain uses a genuinely DIFFERENT leaf key endorsed by the EXISTING ca/inter of each
# algorithm directory. This is additive: it does not touch the slot 0 / slot 1 artifacts. It reads
# the checked-in inter.cert(.der)/inter.key of every directory and only writes the new
# end_*4.* and bundle_*.certchain4.der files.
#
# Use openssl 3.5+ (system openssl), which supports ML-DSA and SLH-DSA.

set -e

# On Windows/MSYS (Git bash), keep openssl subject/path args from being mangled.
export MSYS2_ARG_CONV_EXCL="*"
export MSYS_NO_PATHCONV=1

OPENSSL=${OPENSSL:-openssl}
CNF=../openssl.cnf

# Generate the slot_4 chain for one directory.
#   $1 dir, $2 new-leaf-key openssl command (writes end_responder4.key / end_requester4.key),
#   $3 csr/x509 hash flag (e.g. -sha256, -sm3, or empty for EdDSA/PQC).
gen_slot4 () {
    local dir="$1"
    local newkey_cmd="$2"
    local hash="$3"

    pushd "$dir" > /dev/null

    # New, different leaf keys for slot 4 (responder and requester).
    eval "$newkey_cmd end_responder4.key"
    eval "$newkey_cmd end_requester4.key"

    # CSRs for the new leaf keys.
    $OPENSSL req -new -key end_responder4.key -out end_responder4.req $hash -batch \
        -subj "/CN=DMTF libspdm $dir responder cert slot4"
    $OPENSSL req -new -key end_requester4.key -out end_requester4.req $hash -batch \
        -subj "/CN=DMTF libspdm $dir requester cert slot4"

    # Sign with the EXISTING intermediate (reuse ca/inter; no new CA).
    $OPENSSL x509 -req -in end_responder4.req -out end_responder4.cert \
        -CA inter.cert -CAkey inter.key $hash -days 3650 -set_serial 0x41 \
        -extensions v3_end -extfile $CNF
    $OPENSSL x509 -req -in end_requester4.req -out end_requester4.cert \
        -CA inter.cert -CAkey inter.key $hash -days 3650 -set_serial 0x42 \
        -extensions v3_end -extfile $CNF

    $OPENSSL asn1parse -in end_responder4.cert -out end_responder4.cert.der > /dev/null
    $OPENSSL asn1parse -in end_requester4.cert -out end_requester4.cert.der > /dev/null

    # slot_4 bundles: existing ca + existing inter + new leaf.
    cat ca.cert.der inter.cert.der end_responder4.cert.der > bundle_responder.certchain4.der
    cat ca.cert.der inter.cert.der end_requester4.cert.der > bundle_requester.certchain4.der

    popd > /dev/null
    echo "  [done] $dir"
}

echo "=== RSA ==="
gen_slot4 rsa2048 "$OPENSSL req -nodes -newkey rsa:2048 -batch -subj /CN=tmp -keyout" "-sha256"
gen_slot4 rsa3072 "$OPENSSL req -nodes -newkey rsa:3072 -batch -subj /CN=tmp -keyout" "-sha384"
gen_slot4 rsa4096 "$OPENSSL req -nodes -newkey rsa:4096 -batch -subj /CN=tmp -keyout" "-sha512"

echo "=== ECC ==="
gen_slot4 ecp256 "$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out" "-sha256"
gen_slot4 ecp384 "$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out" "-sha384"
gen_slot4 ecp521 "$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out" "-sha512"

echo "=== EdDSA ==="
gen_slot4 ed25519 "$OPENSSL genpkey -algorithm ed25519 -out" ""
gen_slot4 ed448 "$OPENSSL genpkey -algorithm ed448 -out" ""

echo "=== SM2 ==="
gen_slot4 sm2 "$OPENSSL ecparam -genkey -name SM2 -out" "-sm3"

echo "=== ML-DSA ==="
gen_slot4 mldsa44 "$OPENSSL genpkey -algorithm ML-DSA-44 -out" ""
gen_slot4 mldsa65 "$OPENSSL genpkey -algorithm ML-DSA-65 -out" ""
gen_slot4 mldsa87 "$OPENSSL genpkey -algorithm ML-DSA-87 -out" ""

echo "=== SLH-DSA ==="
for a in sha2-128s shake-128s sha2-128f shake-128f \
         sha2-192s shake-192s sha2-192f shake-192f \
         sha2-256s shake-256s sha2-256f shake-256f; do
    ALGO=$(echo "$a" | tr 'a-z' 'A-Z')
    gen_slot4 "slh-dsa-$a" "$OPENSSL genpkey -algorithm SLH-DSA-$ALGO -out" ""
done

echo "=== all slot_4 chains generated ==="
