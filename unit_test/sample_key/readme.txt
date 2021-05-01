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
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha256 -days 365 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha256 -days 365 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
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
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha384 -subj "/CN=intel test RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=intel test RSA intermediate cert"
openssl req -nodes -newkey rsa:3072 -keyout end_requester.key -out end_requester.req -sha384 -batch -subj "/CN=intel test RSA requseter cert"
openssl req -nodes -newkey rsa:3072 -keyout end_responder.key -out end_responder.req -sha384 -batch -subj "/CN=intel test RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 365 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 365 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
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
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha256 -days 365 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha256 -days 365 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
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
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 365 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 365 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
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
openssl req -nodes -x509 -days 3650 -key ca.key -out ca.cert -sha256 -subj "/CN=intel test SM2 CA"
openssl ecparam -genkey -name SM2 -out inter.key
openssl ecparam -genkey -name SM2 -out end_requester.key
openssl ecparam -genkey -name SM2 -out end_responder.key
openssl req -new -key inter.key -out inter.req -sha256 -batch -subj '/CN=intel test SM2 intermediate cert'
openssl req -new -key end_requester.key -out end_requester.req -sha256 -batch -subj '/CN=intel test SM2 requseter cert'
openssl req -new -key end_responder.key -out end_responder.req -sha256 -batch -subj '/CN=intel test SM2 responder cert'
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

