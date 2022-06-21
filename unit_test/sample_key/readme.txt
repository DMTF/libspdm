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

```openssl.cnf
[ v3_end ]
basicConstraints = critical,CA:false
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
subjectAltName = otherName:1.3.6.1.4.1.412.274.1;UTF8:ACME:WIDGET:1234567890
extendedKeyUsage = critical, serverAuth, clientAuth, OCSPSigning

[ v3_inter ]
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
subjectKeyIdentifier = hash
extendedKeyUsage = critical, serverAuth, clientAuth

```
pushd rsa2048
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha256 -subj "/CN=intel test RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha256 -batch -subj "/CN=intel test RSA intermediate cert"
openssl req -nodes -newkey rsa:2048 -keyout end_requester.key -out end_requester.req -sha256 -batch -subj "/CN=intel test RSA requseter cert"
openssl req -nodes -newkey rsa:2048 -keyout end_responder.key -out end_responder.req -sha256 -batch -subj "/CN=intel test RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl rsa -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl rsa -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
popd

pushd rsa3072
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha384 -subj "//CN=intel test RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha384 -batch -subj "//CN=intel test RSA intermediate cert"
openssl req -nodes -newkey rsa:3072 -keyout end_requester.key -out end_requester.req -sha384 -batch -subj "//CN=intel test RSA requseter cert"
openssl req -nodes -newkey rsa:3072 -keyout end_responder.key -out end_responder.req -sha384 -batch -subj "//CN=intel test RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl rsa -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl rsa -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
popd

pushd rsa4096
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha512 -subj "//CN=intel test RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha512 -batch -subj "//CN=intel test RSA intermediate cert"
openssl req -nodes -newkey rsa:4096 -keyout end_requester.key -out end_requester.req -sha512 -batch -subj "//CN=intel test RSA requseter cert"
openssl req -nodes -newkey rsa:4096 -keyout end_responder.key -out end_responder.req -sha512 -batch -subj "//CN=intel test RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl rsa -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl rsa -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
popd

=== EC Certificate Chains ===

pushd ecp256
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha256 -subj "/CN=intel test ECP256 CA"
openssl pkey -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha256 -batch -subj "/CN=intel test ECP256 intermediate cert"
openssl req -nodes -newkey ec:param.pem -keyout end_requester.key -out end_requester.req -sha256 -batch -subj "/CN=intel test ECP256 requseter cert"
openssl req -nodes -newkey ec:param.pem -keyout end_responder.key -out end_responder.req -sha256 -batch -subj "/CN=intel test ECP256 responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl ec -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl ec -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
popd

pushd ecp384
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha384 -subj "/CN=intel test ECP256 CA"
openssl pkey -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=intel test ECP256 intermediate cert"
openssl req -nodes -newkey ec:param.pem -keyout end_requester.key -out end_requester.req -sha384 -batch -subj "/CN=intel test ECP256 requseter cert"
openssl req -nodes -newkey ec:param.pem -keyout end_responder.key -out end_responder.req -sha384 -batch -subj "/CN=intel test ECP256 responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl ec -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl ec -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
popd

pushd ecp521
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-521
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha512 -subj "//CN=intel test ECP256 CA"
openssl pkey -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha512 -batch -subj "//CN=intel test ECP256 intermediate cert"
openssl req -nodes -newkey ec:param.pem -keyout end_requester.key -out end_requester.req -sha512 -batch -subj "//CN=intel test ECP256 requseter cert"
openssl req -nodes -newkey ec:param.pem -keyout end_responder.key -out end_responder.req -sha512 -batch -subj "//CN=intel test ECP256 responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl ec -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl ec -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
popd

=== Ed Certificate Chains ===

pushd ed25519
openssl genpkey -algorithm ed25519 -out ca.key
openssl req -nodes -x509 -days 3650 -key ca.key -out ca.cert -subj "/CN=intel test ED25519 CA"
openssl genpkey -algorithm ed25519 -out inter.key
openssl genpkey -algorithm ed25519 -out end_requester.key
openssl genpkey -algorithm ed25519 -out end_responder.key
openssl req -new -key inter.key -out inter.req -batch -subj "/CN=intel test ED25519 intermediate cert"
openssl req -new -key end_requester.key -out end_requester.req -batch -subj "/CN=intel test ED25519 requseter cert"
openssl req -new -key end_responder.key -out end_responder.req -batch -subj "/CN=intel test ED25519 responder cert"
openssl x509 -req -days 3650 -in inter.req -CA ca.cert -CAkey ca.key -out inter.cert -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester.cert -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder.cert -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl pkey -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl pkey -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
popd

pushd ed448
openssl genpkey -algorithm ed448 -out ca.key
openssl req -nodes -x509 -days 3650 -key ca.key -out ca.cert -subj "/CN=intel test ED448 CA"
openssl genpkey -algorithm ed448 -out inter.key
openssl genpkey -algorithm ed448 -out end_requester.key
openssl genpkey -algorithm ed448 -out end_responder.key
openssl req -new -key inter.key -out inter.req -batch -subj "/CN=intel test ED448 intermediate cert"
openssl req -new -key end_requester.key -out end_requester.req -batch -subj "/CN=intel test ED448 requseter cert"
openssl req -new -key end_responder.key -out end_responder.req -batch -subj "/CN=intel test ED448 responder cert"
openssl x509 -req -days 3650 -in inter.req -CA ca.cert -CAkey ca.key -out inter.cert -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester.cert -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder.cert -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl pkey -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl pkey -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_carequester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
popd

=== sm2 Certificate Chains ===

pushd sm2
openssl ecparam -genkey -name SM2 -out ca.key
openssl req -nodes -x509 -days 3650 -key ca.key -out ca.cert -sha256 -subj "//CN=intel test SM2 CA"
openssl ecparam -genkey -name SM2 -out inter.key
openssl ecparam -genkey -name SM2 -out end_requester.key
openssl ecparam -genkey -name SM2 -out end_responder.key
openssl req -new -key inter.key -out inter.req -sha256 -batch -subj '//CN=intel test SM2 intermediate cert'
openssl req -new -key end_requester.key -out end_requester.req -sha256 -batch -subj '//CN=intel test SM2 requseter cert'
openssl req -new -key end_responder.key -out end_responder.req -sha256 -batch -subj '//CN=intel test SM2 responder cert'
openssl x509 -req -days 3650 -in inter.req -CA ca.cert -CAkey ca.key -out inter.cert -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester.cert -set_serial 2 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder.cert -set_serial 3 -extensions v3_inter -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl pkey -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl pkey -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
popd

=== long_chains Certificate Chains ===

For CA cert:
openssl ecparam -genkey -name long_chains -out ShorterMAXUINT16_ca.key
openssl req -nodes -x509 -days 3650 -key ShorterMAXUINT16_ca.key -out ShorterMAXUINT16_ca.cert -sha256 -subj "/CN=intel test RSA CA"

For inter cert:
openssl ecparam -genkey -name long_chains -out ShorterMAXUINT16_inter1.key
openssl req -new -key ShorterMAXUINT16_inter1.key -out ShorterMAXUINT16_inter1.req -sha256 -batch -subj '/CN=intel test RSA intermediate cert'
openssl x509 -req -days 3650 -in ShorterMAXUINT16_inter1.req -CA ShorterMAXUINT16_ca.cert -CAkey ShorterMAXUINT16_ca.key -out ShorterMAXUINT16_inter1.cert -set_serial 3 -extensions v3_inter -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXUINT16_inter1.cert -out ShorterMAXUINT16_inter1.cert.der 

// Generate the remain cert in order

openssl ecparam -genkey -name long_chains -out ShorterMAXUINT16_inter47.key
openssl req -new -key ShorterMAXUINT16_inter47.key -out ShorterMAXUINT16_inter47.req -sha256 -batch -subj '/CN=intel test RSA intermediate cert'
openssl x509 -req -days 3650 -in ShorterMAXUINT16_inter47.req -CA ShorterMAXUINT16_inter46.cert -CAkey ShorterMAXUINT16_inter46.key -out ShorterMAXUINT16_inter47.cert -set_serial 3 -extensions v3_inter -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXUINT16_inter47.cert -out ShorterMAXUINT16_inter47.cert.der 

For end cert:
openssl ecparam -genkey -name long_chains -out ShorterMAXUINT16_end_responder.key
openssl req -new -key horterMAXUINT16_end_responder.key -out ShorterMAXUINT16_end_responder.req -sha256 -batch -subj '/CN=intel test RSA responder cert'
openssl x509 -req -days 3650 -in ShorterMAXUINT16_end_responder.req -CA ShorterMAXUINT16_inter47.cert -CAkey ShorterMAXUINT16_inter47.key -out ShorterMAXUINT16_end_responder.cert -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXUINT16_end_responder.cert -out ShorterMAXUINT16_end_responder.cert.der 

Generate cert chain:
cat ShorterMAXUINT16_ca.cert.der ShorterMAXUINT16_inter*.cert.der ShorterMAXUINT16_end_responder.cert.der >ShorterMAXUINT16_bundle_responder.certchain.der

pushd long_chains
openssl genpkey -algorithm long_chains -out Shorter1024B_ca.key
openssl req -nodes -x509 -days 3650 -key Shorter1024B_ca.key -out Shorter1024B_ca.cert -subj "//CN=intel test RSA CA"
openssl genpkey -algorithm long_chains -out Shorter1024B_end_requester.key
openssl genpkey -algorithm long_chains -out Shorter1024B_end_responder.key
openssl req -new -key Shorter1024B_end_requester.key -out Shorter1024B_end_requester.req -batch -subj "//CN=intel test RSA requseter cert"
openssl req -new -key Shorter1024B_end_responder.key -out Shorter1024B_end_responder.req -batch -subj "//CN=intel test RSA responder cert"
openssl x509 -req -days 3650 -in Shorter1024B_end_requester.req -CA Shorter1024B_ca.cert -CAkey Shorter1024B_ca.key -out Shorter1024B_end_requester.cert -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in Shorter1024B_end_responder.req -CA Shorter1024B_ca.cert -CAkey Shorter1024B_ca.key -out Shorter1024B_end_responder.cert -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in Shorter1024B_ca.cert -out Shorter1024B_ca.cert.der
openssl asn1parse -in Shorter1024B_end_requester.cert -out Shorter1024B_end_requester.cert.der
openssl asn1parse -in Shorter1024B_end_responder.cert -out Shorter1024B_end_responder.cert.der
cat Shorter1024B_ca.cert.der Shorter1024B_end_requester.cert.der > Shorter1024B_bundle_requester.certchain.der
cat Shorter1024B_ca.cert.der Shorter1024B_end_responder.cert.der > Shorter1024B_bundle_responder.certchain.der
popd


==== More cert_chain to gen ====

NOTE: The bundle_requester.certchain1.der and bundle_requester.certchain.der have same leaf cert key.
As same as bundle_responder.certchain1.der.
Gen new ca1.key; use old inter.key and end.key.

=== ecc256 Certificate Chains ===
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca1.key -out ca1.cert -sha256 -subj "/CN=intel test ECP256 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha256  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== ecc384 Certificate Chains ===
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca1.key -out ca1.cert -sha384 -subj "/CN=intel test ECP384 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha384  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== ecc521 Certificate Chains ===
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca1.key -out ca1.cert -sha512 -subj "/CN=intel test ECP521 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha512  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== rsa2048 Certificate Chains ===
openssl req -nodes -x509 -days 3650 -newkey rsa:2048 -keyout ca1.key -out ca1.cert -sha256 -subj "//CN=intel test RSA CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha256  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== rsa3072 Certificate Chains ===
openssl req -nodes -x509 -days 3650 -newkey rsa:3072 -keyout ca1.key -out ca1.cert -sha384 -subj "//CN=intel test RSA CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha384  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== rsa4096 Certificate Chains ===
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca1.key -out ca1.cert -sha512 -subj "//CN=intel test RSA CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha512  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== ed25519 Certificate Chains ===
openssl genpkey -algorithm ed25519 -out ca1.key
openssl req -nodes -x509 -days 3650 -key ca1.key -out ca1.cert -subj "/CN=intel test ED25519 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== ed448 Certificate Chains ===
openssl genpkey -algorithm ed448 -out ca1.key
openssl req -nodes -x509 -days 3650 -key ca1.key -out ca1.cert -subj "/CN=intel test ED448 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der

=== sm2 Certificate Chains ===
openssl ecparam -genkey -name SM2 -out ca1.key
openssl req -nodes -x509 -days 3650 -key ca1.key -out ca1.cert -sha256 -subj "//CN=intel test SM2 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha256  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der


=== Add test cert in ecp256===
Gen ecp256/end_requester_ca_false.cert.der is same with ecp256/end_requester.cert.der, expect the openssl.cnf is follow:
[ v3_end ]
basicConstraints = critical,CA:true

Gen ecp256/end_requester_without_basic_constraint.cert.der is same with ecp256/end_requester.cert.der, expect the
basicConstraints is excluded in openssl.cnf [ v3_end ].
