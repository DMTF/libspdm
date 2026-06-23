#!/bin/bash

# Auto gen cert script.
# Please run: ./auto_gen_cert.sh in linux.
# Use the openssl version in linux: openssl 3.5+

gen_pqc_key () {
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
}


export PQC_ALGO=mldsa44
gen_pqc_key
export PQC_ALGO=mldsa65
gen_pqc_key
export PQC_ALGO=mldsa87
gen_pqc_key
export PQC_ALGO=slh-dsa-sha2-128s
gen_pqc_key
export PQC_ALGO=slh-dsa-shake-128s
gen_pqc_key
export PQC_ALGO=slh-dsa-sha2-128f
gen_pqc_key
export PQC_ALGO=slh-dsa-shake-128f
gen_pqc_key
export PQC_ALGO=slh-dsa-sha2-192s
gen_pqc_key
export PQC_ALGO=slh-dsa-shake-192s
gen_pqc_key
export PQC_ALGO=slh-dsa-sha2-192f
gen_pqc_key
export PQC_ALGO=slh-dsa-shake-192f
gen_pqc_key
export PQC_ALGO=slh-dsa-sha2-256s
gen_pqc_key
export PQC_ALGO=slh-dsa-shake-256s
gen_pqc_key
export PQC_ALGO=slh-dsa-sha2-256f
gen_pqc_key
export PQC_ALGO=slh-dsa-shake-256f
gen_pqc_key

echo "All cert generated, please check the log to ensure that there are no issues."
