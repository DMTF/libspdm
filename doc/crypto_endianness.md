# Crypto Endianness

## endianness of digital signature

SPDM 1.2+ defines the endianness of digital signature for RSA, ECDSA, SM2_DSA, and EdDSA.
* RSA: big endian for s.
* ECDSA and SMD2_DSA: big endian for r and s.
* EdDSA: big endian for R and little endian for S.

libspdm follows that for SPDM 1.2+. Because the definition aligns with existing crypto library such as OpenSSL and MbedTLS, no swap is required.

SPDM 1.0 and 1.1 do not specify the endianness of the RSA and ECDSA digital signatures.

libspdm uses big endian for RSA and ECDSA for SPDM 1.0/1.1, which algins with SPDM 1.2 and existing crypto library. No swap is required.

## endianness of key exchange data

SPDM 1.1+ defines the endianness of key exchange data for FFDHE, ECDHE, and SM2_KeyExchange.
* FFDHE: big endian for Y.
* ECDHE and SM2_KeyExchange: big endian for X and Y.

libspdm follows that for SPDM 1.1+. Because the definition aligns with existing crypto library such as openssl and mbedtls, no swap is required.

## endianness of AEAD IV

Secured SPDM 1.0/1.1 are not very clear on how to extend 64bit sequence number and XOR with the IV derived from SPDM key schedule.

libspdm uses little endian for the sequence number for Secured SPDM 1.0/1.1, which algins with default endianness defined in SPDM 1.0+. No swap is required.
