/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Defines base cryptographic library APIs.
 * The Base Cryptographic Library provides implementations of basic cryptography
 * primitives (hash Serials, HMAC, AES, RSA, Diffie-Hellman, Elliptic Curve, etc) for security
 * functionality enabling.
 **/

#ifndef CRYPTLIB_H
#define CRYPTLIB_H

#ifndef LIBSPDM_CONFIG
#include "library/spdm_lib_config.h"
#else
#include LIBSPDM_CONFIG
#endif

#define LIBSPDM_CRYPTO_NID_NULL 0x0000

/* Hash */
#define LIBSPDM_CRYPTO_NID_SHA256 0x0001
#define LIBSPDM_CRYPTO_NID_SHA384 0x0002
#define LIBSPDM_CRYPTO_NID_SHA512 0x0003
#define LIBSPDM_CRYPTO_NID_SHA3_256 0x0004
#define LIBSPDM_CRYPTO_NID_SHA3_384 0x0005
#define LIBSPDM_CRYPTO_NID_SHA3_512 0x0006
#define LIBSPDM_CRYPTO_NID_SM3_256 0x0007

/* Signing */
#define LIBSPDM_CRYPTO_NID_RSASSA2048 0x0101
#define LIBSPDM_CRYPTO_NID_RSASSA3072 0x0102
#define LIBSPDM_CRYPTO_NID_RSASSA4096 0x0103
#define LIBSPDM_CRYPTO_NID_RSAPSS2048 0x0104
#define LIBSPDM_CRYPTO_NID_RSAPSS3072 0x0105
#define LIBSPDM_CRYPTO_NID_RSAPSS4096 0x0106
#define LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256 0x0107
#define LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384 0x0108
#define LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521 0x0109
#define LIBSPDM_CRYPTO_NID_SM2_DSA_P256 0x010A
#define LIBSPDM_CRYPTO_NID_EDDSA_ED25519 0x010B
#define LIBSPDM_CRYPTO_NID_EDDSA_ED448 0x010C

/* Key Exchange */
#define LIBSPDM_CRYPTO_NID_FFDHE2048 0x0201
#define LIBSPDM_CRYPTO_NID_FFDHE3072 0x0202
#define LIBSPDM_CRYPTO_NID_FFDHE4096 0x0203
#define LIBSPDM_CRYPTO_NID_SECP256R1 0x0204
#define LIBSPDM_CRYPTO_NID_SECP384R1 0x0205
#define LIBSPDM_CRYPTO_NID_SECP521R1 0x0206
#define LIBSPDM_CRYPTO_NID_SM2_KEY_EXCHANGE_P256 0x0207
#define LIBSPDM_CRYPTO_NID_CURVE_X25519 0x0208
#define LIBSPDM_CRYPTO_NID_CURVE_X448 0x0209

/* AEAD */
#define LIBSPDM_CRYPTO_NID_AES_128_GCM 0x0301
#define LIBSPDM_CRYPTO_NID_AES_256_GCM 0x0302
#define LIBSPDM_CRYPTO_NID_CHACHA20_POLY1305 0x0303
#define LIBSPDM_CRYPTO_NID_SM4_128_GCM 0x0304

/* X.509 v3 key usage extension flags. */
#define LIBSPDM_CRYPTO_X509_KU_DIGITAL_SIGNATURE 0x80 /* bit 0 */
#define LIBSPDM_CRYPTO_X509_KU_NON_REPUDIATION 0x40 /* bit 1 */
#define LIBSPDM_CRYPTO_X509_KU_KEY_ENCIPHERMENT 0x20 /* bit 2 */
#define LIBSPDM_CRYPTO_X509_KU_DATA_ENCIPHERMENT 0x10 /* bit 3 */
#define LIBSPDM_CRYPTO_X509_KU_KEY_AGREEMENT 0x08 /* bit 4 */
#define LIBSPDM_CRYPTO_X509_KU_KEY_CERT_SIGN 0x04 /* bit 5 */
#define LIBSPDM_CRYPTO_X509_KU_CRL_SIGN 0x02 /* bit 6 */
#define LIBSPDM_CRYPTO_X509_KU_ENCIPHER_ONLY 0x01 /* bit 7 */
#define LIBSPDM_CRYPTO_X509_KU_DECIPHER_ONLY 0x8000 /* bit 8 */

/* These constants comply with the DER encoded ASN.1 type tags. */
#define LIBSPDM_CRYPTO_ASN1_BOOLEAN 0x01
#define LIBSPDM_CRYPTO_ASN1_INTEGER 0x02
#define LIBSPDM_CRYPTO_ASN1_BIT_STRING 0x03
#define LIBSPDM_CRYPTO_ASN1_OCTET_STRING 0x04
#define LIBSPDM_CRYPTO_ASN1_NULL 0x05
#define LIBSPDM_CRYPTO_ASN1_OID 0x06
#define LIBSPDM_CRYPTO_ASN1_UTF8_STRING 0x0C
#define LIBSPDM_CRYPTO_ASN1_SEQUENCE 0x10
#define LIBSPDM_CRYPTO_ASN1_SET 0x11
#define LIBSPDM_CRYPTO_ASN1_PRINTABLE_STRING 0x13
#define LIBSPDM_CRYPTO_ASN1_T61_STRING 0x14
#define LIBSPDM_CRYPTO_ASN1_IA5_STRING 0x16
#define LIBSPDM_CRYPTO_ASN1_UTC_TIME 0x17
#define LIBSPDM_CRYPTO_ASN1_GENERALIZED_TIME 0x18
#define LIBSPDM_CRYPTO_ASN1_UNIVERSAL_STRING 0x1C
#define LIBSPDM_CRYPTO_ASN1_BMP_STRING 0x1E
#define LIBSPDM_CRYPTO_ASN1_PRIMITIVE 0x00
#define LIBSPDM_CRYPTO_ASN1_CONSTRUCTED 0x20
#define LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC 0x80

#define LIBSPDM_CRYPTO_ASN1_TAG_CLASS_MASK 0xC0
#define LIBSPDM_CRYPTO_ASN1_TAG_PC_MASK 0x20
#define LIBSPDM_CRYPTO_ASN1_TAG_VALUE_MASK 0x1F

#include "hal/library/cryptlib/cryptlib_hash.h"
#include "hal/library/cryptlib/cryptlib_mac.h"
#include "hal/library/cryptlib/cryptlib_aead.h"
#include "hal/library/cryptlib/cryptlib_cert.h"
#include "hal/library/cryptlib/cryptlib_hkdf.h"
#include "hal/library/cryptlib/cryptlib_rsa.h"
#include "hal/library/cryptlib/cryptlib_ec.h"
#include "hal/library/cryptlib/cryptlib_dh.h"
#include "hal/library/cryptlib/cryptlib_ecd.h"
#include "hal/library/cryptlib/cryptlib_sm2.h"
#include "hal/library/cryptlib/cryptlib_rng.h"

/*=====================================================================================
 *    Montgomery-Curve Primitive
 *=====================================================================================*/

/**
 * Allocates and Initializes one Montgomery-Curve Context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Montgomery-Curve Context that has been initialized.
 *         If the allocations fails, libspdm_ecx_new_by_nid() returns NULL.
 *
 **/
void *libspdm_ecx_new_by_nid(size_t nid);

/**
 * Release the specified Ecx context.
 *
 * @param[in]  ecx_context  Pointer to the Ecx context to be released.
 *
 **/
void libspdm_ecx_free(const void *ecx_context);

/**
 * Generates Ecx key and returns Ecx public key.
 *
 * This function generates random secret, and computes the public key, which is
 * returned via parameter public, public_size.
 * Ecx context is updated accordingly.
 * If the public buffer is too small to hold the public key, false is returned and
 * public_size is set to the required buffer size to obtain the public key.
 *
 * For X25519, the public_size is 32.
 * For X448, the public_size is 56.
 *
 * If ecx_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  ecx_context      Pointer to the Ecx context.
 * @param[out]      public         Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   Ecx public key generation succeeded.
 * @retval false  Ecx public key generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_ecx_generate_key(void *ecx_context, uint8_t *public,
                              size_t *public_size);

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 *
 * If ecx_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 *
 * For X25519, the public_size is 32.
 * For X448, the public_size is 56.
 *
 * @param[in, out]  ecx_context          Pointer to the Ecx context.
 * @param[in]       peer_public         Pointer to the peer's public key.
 * @param[in]       peer_public_size     Size of peer's public key in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                    On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   Ecx exchanged key generation succeeded.
 * @retval false  Ecx exchanged key generation failed.
 * @retval false  key_size is not large enough.
 *
 **/
bool libspdm_ecx_compute_key(void *ecx_context, const uint8_t *peer_public,
                             size_t peer_public_size, uint8_t *key,
                             size_t *key_size);






#endif /* CRYPTLIB_H */
