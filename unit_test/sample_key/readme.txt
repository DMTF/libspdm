==== Note ====
Please use auto_gen_cert.sh to gen all cert in sample_key, then the raw_data_key_gen.py need run to generate sync raw data key.
Note: the rsa3072_Expiration have 1 day valid time.

==== RSA ====
Generate a root key:

    openssl genrsa -out TestRoot.key 2048

Generate a self-signed root certificate:

    openssl req -extensions v3_ca -new -x509 -days 3650 -key TestRoot.key -out TestRoot.crt
    openssl x509 -in TestRoot.crt -out TestRoot.cer -outform DER
    openssl x509 -inform DER -in TestRoot.cer -outform PEM -out TestRoot.pub.pem

==== ECC ====
Generate a root key: prime256v1(secp256r1/NIST P-256) / secp384r1 / secp521r1

    openssl ecparam -out EccTestRoot.key -name prime256v1 -genkey

Generate a self-signed root certificate:

    openssl req -extensions v3_ca -new -x509 -days 3650 -key EccTestRoot.key -out EccTestRoot.crt
    openssl x509 -in EccTestRoot.crt -out EccTestRoot.cer -outform DER
    openssl x509 -inform DER -in EccTestRoot.cer -outform PEM -out EccTestRoot.pub.pem

==== EdDSA ====
Generate a root key: ED25519  / ED448

    openssl genpkey -algorithm ED25519 > ed25519.key

Generate a self-signed root certificate:

    openssl req -new -out ed25519.csr -key ed25519.key -config openssl-25519.cnf
    openssl x509 -req -days 700 -in ed25519.csr -signkey ed25519.key -out ed25519.crt

=== RSA Certificate Chains ===

NOTE: Use "//CN" for windows and use "/CN" for Linux system.
RECOMMEND: Use openssl 1.1.1k


=== long_chains Certificate Chains(ShorterMAXUINT16_xxx.cert/ShorterMAXINT16_xxx.cert/Shorter1024B_xxx.cert) ===

For CA cert:
openssl req -nodes -x509 -days 3650 -newkey rsa:2048 -keyout ShorterMAXUINT16_ca.key -out ShorterMAXUINT16_ca.cert -sha256 -subj "/CN=DMTF libspdm RSA CA"

For inter cert:
Generate the remain cert in order

Generate cert chain:
cat ShorterMAXUINT16_ca.cert.der ShorterMAXUINT16_inter*.cert.der ShorterMAXUINT16_end_responder.cert.der >ShorterMAXUINT16_bundle_responder.certchain.der


==== More cert_chain for ecp256/384/521 rsa2048/3072/4096 ed448/25519 sm2 to gen ====

NOTE: The bundle_requester.certchain1.der and bundle_requester.certchain.der have same leaf cert key.
As same as bundle_responder.certchain1.der.
Gen new ca1.key; use old inter.key and end.key.


=== Add test cert in ecp256===
Gen ecp256/end_requester_ca_false.cert.der is same with ecp256/end_requester.cert.der, expect the openssl.cnf is follow:
[ v3_end_with_false_basicConstraints]
basicConstraints = critical,CA:true

Gen ecp256/end_requester_without_basic_constraint.cert.der is same with ecp256/end_requester.cert.der, expect the
basicConstraints is excluded in openssl.cnf [ v3_end_without_basicConstraints].

=== Gen rsa3072_Expiration ===
Gen rsa3072_Expiration is same with rsa3072, expect the cert validaty time is 1 day.


==== More alias_cert model cert_chain to gen ====
NOTE: The bundle_responder.certchain_alias_cert_partial_set.der and bundle_requester.certchain.der have same ca_cert and inter cert.
The only different is: the basic constraints is: CA: ture in leaf cert of bundle_responder.certchain_alias_cert_partial_set.der.
This alias cert chain is partial, from root CA to device certificate CA.

The bundle_responder.certchain_alias.der is the entire cert_chain in the alias_cert mode.

==== PQC key generation ====

0. Sample DER / PEM public key and private key.

The example is from https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates

They are under:
```
mldsa44/privkeyseed.pem
mldsa44/pubkey.pem
mldsa44/pubkey.der
mldsa65/privkeyseed.pem
mldsa65/pubkey.pem
mldsa65/pubkey.der
mldsa87/privkeyseed.pem
mldsa87/pubkey.pem
mldsa87/pubkey.der
```

openssl command can be used to view or convert the PEM or DER content.
```
openssl base64 -in pubkey.pem -d > pubkey.der
openssl base64 -in pubkey.der -e
openssl asn1parse -in pubkey.pem -inform PEM
openssl asn1parse -in pubkey.der -inform DER -i -dump
```

1. Generate DER / PEM public certificate with OQS. (deprecated)

Use https://github.com/open-quantum-safe/oqs-provider.

NOTE: The OID definition in https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates is
different from the one in https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md.

| Algorithm | OID in RFC draft        | OID in OQS provider      |
|-----------|-------------------------|--------------------------|
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | 1.3.6.1.4.1.2.267.12.4.4 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | 1.3.6.1.4.1.2.267.12.6.5 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | 1.3.6.1.4.1.2.267.12.8.7 |

NOTE: The PEM privatekey format is also different.

| Algorithm | priv key in RFC draft   | priv key in OQS provider (OCTET_STRING) |
|-----------|-------------------------|-----------------------------------------|
| ML-DSA-44 | 32 byte seed            | priv key (2560) + pub key (1312)        |
| ML-DSA-65 | 32 byte seed            | priv key (4032) + pub key (1952)        |
| ML-DSA-87 | 32 byte seed            | priv key (4896) + pub key (2592)        |

```
git clone https://github.com/open-quantum-safe/oqs-provider
cd oqs-provider
scripts/fullbuild.sh
cp _build/lib/oqsprovider.so .local/lib64/ossl-modules/
```

If you change and rebuild, just use
```
cmake --build _build
cp _build/lib/oqsprovider.so .local/lib64/ossl-modules/
```

The new `openssl` is at under `oqs-provider/openssl/apps/` 

```
export PQC_ALGO=mldsa44
export PQC_ALGO=mldsa65
export PQC_ALGO=mldsa87
```

Run below command after export the $PQC_ALGO.
```
mkdir $PQC_ALGO
cd $PQC_ALGO
../openssl req -nodes -x509 -days 3650 -newkey $PQC_ALGO -keyout ca.key -out ca.cert -subj "/CN=DMTF libspdm $PQC_ALGO ca" -provider oqsprovider -provider default
../openssl req -nodes -newkey $PQC_ALGO -keyout inter.key -out inter.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO intermediate cert" -provider oqsprovider -provider default
../openssl req -nodes -newkey $PQC_ALGO -keyout end_requester.key -out end_requester.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO requseter cert" -provider oqsprovider -provider default
../openssl req -nodes -newkey $PQC_ALGO -keyout end_responder.key -out end_responder.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO responder cert" -provider oqsprovider -provider default
../openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl asn1parse -in ca.key -out ca.key.der
../openssl asn1parse -in inter.key -out inter.key.der
../openssl asn1parse -in end_requester.key -out end_requester.key.der
../openssl asn1parse -in end_responder.key -out end_responder.key.der
../openssl asn1parse -in ca.cert -out ca.cert.der
../openssl asn1parse -in inter.cert -out inter.cert.der
../openssl asn1parse -in end_requester.cert -out end_requester.cert.der
../openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
../openssl x509 -in ca.cert.der -inform DER -text -provider oqsprovider -provider default
../openssl x509 -in inter.cert.der -inform DER -text -provider oqsprovider -provider default
../openssl x509 -in end_requester.cert.der -inform DER -text -provider oqsprovider -provider default
../openssl x509 -in end_responder.cert.der -inform DER -text -provider oqsprovider -provider default
# second slot
../openssl req -nodes -x509 -days 3650 -newkey $PQC_ALGO -keyout ca1.key -out ca1.cert -subj "/CN=DMTF libspdm $PQC_ALGO ca1" -provider oqsprovider -provider default
../openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl asn1parse -in ca1.key -out ca1.key.der
../openssl asn1parse -in ca1.cert -out ca1.cert.der
../openssl asn1parse -in inter1.cert -out inter1.cert.der
../openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
../openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
../openssl x509 -in ca1.cert.der -inform DER -text -provider oqsprovider -provider default
../openssl x509 -in inter1.cert.der -inform DER -text -provider oqsprovider -provider default
../openssl x509 -in end_requester1.cert.der -inform DER -text -provider oqsprovider -provider default
../openssl x509 -in end_responder1.cert.der -inform DER -text -provider oqsprovider -provider default
# alias cert
../openssl req -nodes -newkey $PQC_ALGO -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO alias cert" -provider oqsprovider -provider default
../openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl asn1parse -in end_responder_alias_partial.key -out end_responder_alias_partial.key.der
../openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der
../openssl x509 -req -in end_responder.req -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha256 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl_spdm.cnf -provider oqsprovider -provider default
../openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
cd ..
```

1. Generate DER / PEM public certificate with OpenSSL 3.5.

OID definition:
https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates
https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-slhdsa

```
export PQC_ALGO=mldsa44
export PQC_ALGO=mldsa65
export PQC_ALGO=mldsa87
export PQC_ALGO=slh-dsa-sha2-128s
export PQC_ALGO=slh-dsa-shake-128s
export PQC_ALGO=slh-dsa-sha2-128f
export PQC_ALGO=slh-dsa-shake-128f
export PQC_ALGO=slh-dsa-sha2-192s
export PQC_ALGO=slh-dsa-shake-192s
export PQC_ALGO=slh-dsa-sha2-192f
export PQC_ALGO=slh-dsa-shake-192f
export PQC_ALGO=slh-dsa-sha2-256s
export PQC_ALGO=slh-dsa-shake-256s
export PQC_ALGO=slh-dsa-sha2-256f
export PQC_ALGO=slh-dsa-shake-256f
```

Run below command after export the $PQC_ALGO.
```
mkdir $PQC_ALGO
cd $PQC_ALGO
../openssl req -nodes -x509 -days 3650 -newkey $PQC_ALGO -keyout ca.key -out ca.cert -subj "/CN=DMTF libspdm $PQC_ALGO ca"
../openssl req -nodes -newkey $PQC_ALGO -keyout inter.key -out inter.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO intermediate cert"
../openssl req -nodes -newkey $PQC_ALGO -keyout end_requester.key -out end_requester.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO requseter cert"
../openssl req -nodes -newkey $PQC_ALGO -keyout end_responder.key -out end_responder.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO responder cert"
../openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl_spdm.cnf
../openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl_spdm.cnf
../openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl_spdm.cnf
../openssl asn1parse -in ca.key -out ca.key.der
../openssl asn1parse -in inter.key -out inter.key.der
../openssl asn1parse -in end_requester.key -out end_requester.key.der
../openssl asn1parse -in end_responder.key -out end_responder.key.der
../openssl asn1parse -in ca.cert -out ca.cert.der
../openssl asn1parse -in inter.cert -out inter.cert.der
../openssl asn1parse -in end_requester.cert -out end_requester.cert.der
../openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
../openssl x509 -in ca.cert.der -inform DER -text
../openssl x509 -in inter.cert.der -inform DER -text
../openssl x509 -in end_requester.cert.der -inform DER -text
../openssl x509 -in end_responder.cert.der -inform DER -text
# second slot
../openssl req -nodes -x509 -days 3650 -newkey $PQC_ALGO -keyout ca1.key -out ca1.cert -subj "/CN=DMTF libspdm $PQC_ALGO ca1"
../openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl_spdm.cnf
../openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl_spdm.cnf
../openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl_spdm.cnf
../openssl asn1parse -in ca1.key -out ca1.key.der
../openssl asn1parse -in ca1.cert -out ca1.cert.der
../openssl asn1parse -in inter1.cert -out inter1.cert.der
../openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
../openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
../openssl x509 -in ca1.cert.der -inform DER -text
../openssl x509 -in inter1.cert.der -inform DER -text
../openssl x509 -in end_requester1.cert.der -inform DER -text
../openssl x509 -in end_responder1.cert.der -inform DER -text
# alias cert
../openssl req -nodes -newkey $PQC_ALGO -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -batch -subj "/CN=DMTF libspdm $PQC_ALGO alias cert"
../openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl_spdm.cnf
../openssl asn1parse -in end_responder_alias_partial.key -out end_responder_alias_partial.key.der
../openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der
../openssl x509 -req -in end_responder.req -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha256 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl_spdm.cnf
../openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
cd ..
```

2. Raw public key and private key generation:

User can use `gen_pqc_key` program to generate raw private and public binary key from the generated end_requester.key.der and end_responder.key.der.
```
cd libspdm/build
make
cd bin
gen_pqc_key
cd ..
```

They are under:
```
mldsa44/end_requester.key.priv.raw
mldsa44/end_requester.key.pub.der
mldsa44/end_responder.key.priv.raw
mldsa44/end_responder.key.pub.der
mldsa65/end_requester.key.priv.raw
mldsa65/end_requester.key.pub.der
mldsa65/end_responder.key.priv.raw
mldsa65/end_responder.key.pub.der
mldsa87/end_requester.key.priv.raw
mldsa87/end_requester.key.pub.der
mldsa87/end_responder.key.priv.raw
mldsa87/end_responder.key.pub.der
```

If the end_requester.key.der and end_responder.key.der are not generated, user can use `gen_pqc_key` program to generate raw binary key for ML-DSA-44, ML-DSA-65, ML-DSA-87.

