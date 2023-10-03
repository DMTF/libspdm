# Cryptography Endianness

## Endianness of digital signatures

SPDM 1.2 and later define the endianness of digital signatures for RSA, ECDSA, SM2_DSA, and EdDSA.
* RSA: big endian for s.
* ECDSA and SMD2_DSA: big endian for r and s.
* EdDSA: big endian for R and little endian for S.

When the negotiated SPDM version is 1.2 or later libspdm follows these definitions.

SPDM 1.0 and 1.1 did not specify the endianness of the RSA and ECDSA digital signatures. libspdm
allows an Integrator to specify the endianness when verifying RSA and ECDSA signatures through
`LIBSPDM_DATA_SPDM_VERSION_10_11_VERIFY_SIGNATURE_ENDIAN` when the negotiated SPDM version is 1.0 or
1.1.

## Endianness of key exchange data

SPDM 1.1 and later defines the endianness of key exchange data for FFDHE, ECDHE, and SM2_KeyExchange.
* FFDHE: big endian for Y.
* ECDHE and SM2_KeyExchange: big endian for X and Y.

libspdm follows that for SPDM 1.1+. Because the definition aligns with existing crypto library such as openssl and mbedtls, no swap is required.

## Endianness of AEAD IV

Versions 1.0 and 1.1 of the Secured Messages using SPDM specification do not explicitly specify how
the AEAD IV is formed. In particular the endianness of the sequence number is either missing (1.0)
or ill-defined (1.1). As such libspdm supports both little-endian and big-endian encoding of the
sequence number, as well as automatically swapping endianness if decryption fails.
