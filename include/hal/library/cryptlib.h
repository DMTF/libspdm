/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Defines base cryptographic library APIs.
  The Base Cryptographic Library provides implementations of basic cryptography
  primitives (hash Serials, HMAC, AES, RSA, Diffie-Hellman, Elliptic Curve, etc) for UEFI security
  functionality enabling.
**/

#ifndef __BASE_CRYPT_LIB_H__
#define __BASE_CRYPT_LIB_H__

#define CRYPTO_NID_NULL 0x0000

// hash
#define CRYPTO_NID_SHA256 0x0001
#define CRYPTO_NID_SHA384 0x0002
#define CRYPTO_NID_SHA512 0x0003
#define CRYPTO_NID_SHA3_256 0x0004
#define CRYPTO_NID_SHA3_384 0x0005
#define CRYPTO_NID_SHA3_512 0x0006
#define CRYPTO_NID_SM3_256 0x0007

// Signing
#define CRYPTO_NID_RSASSA2048 0x0101
#define CRYPTO_NID_RSASSA3072 0x0102
#define CRYPTO_NID_RSASSA4096 0x0103
#define CRYPTO_NID_RSAPSS2048 0x0104
#define CRYPTO_NID_RSAPSS3072 0x0105
#define CRYPTO_NID_RSAPSS4096 0x0106
#define CRYPTO_NID_ECDSA_NIST_P256 0x0106
#define CRYPTO_NID_ECDSA_NIST_P384 0x0107
#define CRYPTO_NID_ECDSA_NIST_P521 0x0108
#define CRYPTO_NID_ECDSA_SM2_P256 0x0109
#define CRYPTO_NID_EDDSA_ED25519 0x010A
#define CRYPTO_NID_EDDSA_ED448 0x010B

// key Exchange
#define CRYPTO_NID_FFDHE2048 0x0201
#define CRYPTO_NID_FFDHE3072 0x0202
#define CRYPTO_NID_FFDHE4096 0x0203
#define CRYPTO_NID_SECP256R1 0x0204
#define CRYPTO_NID_SECP384R1 0x0205
#define CRYPTO_NID_SECP521R1 0x0206
#define CRYPTO_NID_SM2_P256 0x0207
#define CRYPTO_NID_CURVE_X25519 0x0208
#define CRYPTO_NID_CURVE_X448 0x0209

// AEAD
#define CRYPTO_NID_AES_128_GCM 0x0301
#define CRYPTO_NID_AES_256_GCM 0x0302
#define CRYPTO_NID_CHACHA20_POLY1305 0x0303
#define CRYPTO_NID_SM4_128_GCM 0x0304

///
/// X.509 v3 key usage Extension flags
///
#define CRYPTO_X509_KU_DIGITAL_SIGNATURE (0x80) // bit 0
#define CRYPTO_X509_KU_NON_REPUDIATION (0x40) // bit 1
#define CRYPTO_X509_KU_KEY_ENCIPHERMENT (0x20) // bit 2
#define CRYPTO_X509_KU_DATA_ENCIPHERMENT (0x10) // bit 3
#define CRYPTO_X509_KU_KEY_AGREEMENT (0x08) // bit 4
#define CRYPTO_X509_KU_KEY_CERT_SIGN (0x04) // bit 5
#define CRYPTO_X509_KU_CRL_SIGN (0x02) // bit 6
#define CRYPTO_X509_KU_ENCIPHER_ONLY (0x01) // bit 7
#define CRYPTO_X509_KU_DECIPHER_ONLY (0x8000) // bit 8

///
/// These constants comply with the DER encoded ASN.1 type tags.
///
#define CRYPTO_ASN1_BOOLEAN 0x01
#define CRYPTO_ASN1_INTEGER 0x02
#define CRYPTO_ASN1_BIT_STRING 0x03
#define CRYPTO_ASN1_OCTET_STRING 0x04
#define CRYPTO_ASN1_NULL 0x05
#define CRYPTO_ASN1_OID 0x06
#define CRYPTO_ASN1_UTF8_STRING 0x0C
#define CRYPTO_ASN1_SEQUENCE 0x10
#define CRYPTO_ASN1_SET 0x11
#define CRYPTO_ASN1_PRINTABLE_STRING 0x13
#define CRYPTO_ASN1_T61_STRING 0x14
#define CRYPTO_ASN1_IA5_STRING 0x16
#define CRYPTO_ASN1_UTC_TIME 0x17
#define CRYPTO_ASN1_GENERALIZED_TIME 0x18
#define CRYPTO_ASN1_UNIVERSAL_STRING 0x1C
#define CRYPTO_ASN1_BMP_STRING 0x1E
#define CRYPTO_ASN1_PRIMITIVE 0x00
#define CRYPTO_ASN1_CONSTRUCTED 0x20
#define CRYPTO_ASN1_CONTEXT_SPECIFIC 0x80

#define CRYPTO_ASN1_TAG_CLASS_MASK 0xC0
#define CRYPTO_ASN1_TAG_PC_MASK 0x20
#define CRYPTO_ASN1_TAG_VALUE_MASK 0x1F

///
/// SHA-256 digest size in bytes
///
#define SHA256_DIGEST_SIZE 32

///
/// SHA-384 digest size in bytes
///
#define SHA384_DIGEST_SIZE 48

///
/// SHA-512 digest size in bytes
///
#define SHA512_DIGEST_SIZE 64

///
/// SHA3-256 digest size in bytes
///
#define SHA3_256_DIGEST_SIZE 32

///
/// SHA3-384 digest size in bytes
///
#define SHA3_384_DIGEST_SIZE 48

///
/// SHA3-512 digest size in bytes
///
#define SHA3_512_DIGEST_SIZE 64

///
/// SHAKE256 digest size in bytes
///
#define SHAKE256_DIGEST_SIZE 32

///
/// SM3_256 digest size in bytes
///
#define SM3_256_DIGEST_SIZE 32

///
/// AES block size in bytes
///
#define AES_BLOCK_SIZE 16

///
/// RSA key Tags Definition used in rsa_set_key() function for key component identification.
///
typedef enum {
	RSA_KEY_N, ///< RSA public Modulus (N)
	RSA_KEY_E, ///< RSA public exponent (e)
	RSA_KEY_D, ///< RSA Private exponent (d)
	RSA_KEY_P, ///< RSA secret prime factor of Modulus (p)
	RSA_KEY_Q, ///< RSA secret prime factor of Modules (q)
	RSA_KEY_DP, ///< p's CRT exponent (== d mod (p - 1))
	RSA_KEY_DQ, ///< q's CRT exponent (== d mod (q - 1))
	RSA_KEY_Q_INV ///< The CRT coefficient (== 1/q mod p)
} rsa_key_tag_t;

//=====================================================================================
//    One-Way Cryptographic hash SHA Primitives
//=====================================================================================

/**
  Allocates and initializes one HASH_CTX context for subsequent SHA256 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, sha256_new() returns NULL.

**/
void *sha256_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  sha256_ctx  Pointer to the HASH_CTX context to be released.

**/
void sha256_free(IN void *sha256_ctx);

/**
  Initializes user-supplied memory pointed by sha256_context as SHA-256 hash context for
  subsequent use.

  If sha256_context is NULL, then return FALSE.

  @param[out]  sha256_context  Pointer to SHA-256 context being initialized.

  @retval TRUE   SHA-256 context initialization succeeded.
  @retval FALSE  SHA-256 context initialization failed.

**/
boolean sha256_init(OUT void *sha256_context);

/**
  Makes a copy of an existing SHA-256 context.

  If sha256_context is NULL, then return FALSE.
  If new_sha256_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha256_context     Pointer to SHA-256 context being copied.
  @param[out] new_sha256_context  Pointer to new SHA-256 context.

  @retval TRUE   SHA-256 context copy succeeded.
  @retval FALSE  SHA-256 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha256_duplicate(IN const void *sha256_context,
			 OUT void *new_sha256_context);

/**
  Digests the input data and updates SHA-256 context.

  This function performs SHA-256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-256 context should be already correctly initialized by sha256_init(), and should not be finalized
  by sha256_final(). Behavior with invalid context is undefined.

  If sha256_context is NULL, then return FALSE.

  @param[in, out]  sha256_context  Pointer to the SHA-256 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA-256 data digest succeeded.
  @retval FALSE  SHA-256 data digest failed.

**/
boolean sha256_update(IN OUT void *sha256_context, IN const void *data,
		      IN uintn data_size);

/**
  Completes computation of the SHA-256 digest value.

  This function completes SHA-256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-256 context cannot
  be used again.
  SHA-256 context should be already correctly initialized by sha256_init(), and should not be
  finalized by sha256_final(). Behavior with invalid SHA-256 context is undefined.

  If sha256_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha256_context  Pointer to the SHA-256 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA-256 digest
                                  value (32 bytes).

  @retval TRUE   SHA-256 digest computation succeeded.
  @retval FALSE  SHA-256 digest computation failed.

**/
boolean sha256_final(IN OUT void *sha256_context, OUT uint8 *hash_value);

/**
  Computes the SHA-256 message digest of a input data buffer.

  This function performs the SHA-256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA-256 digest
                           value (32 bytes).

  @retval TRUE   SHA-256 digest computation succeeded.
  @retval FALSE  SHA-256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha256_hash_all(IN const void *data, IN uintn data_size,
			OUT uint8 *hash_value);

/**
  Allocates and initializes one HASH_CTX context for subsequent SHA384 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, sha384_new() returns NULL.

**/
void *sha384_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  sha384_ctx  Pointer to the HASH_CTX context to be released.

**/
void sha384_free(IN void *sha384_ctx);

/**
  Initializes user-supplied memory pointed by sha384_context as SHA-384 hash context for
  subsequent use.

  If sha384_context is NULL, then return FALSE.

  @param[out]  sha384_context  Pointer to SHA-384 context being initialized.

  @retval TRUE   SHA-384 context initialization succeeded.
  @retval FALSE  SHA-384 context initialization failed.

**/
boolean sha384_init(OUT void *sha384_context);

/**
  Makes a copy of an existing SHA-384 context.

  If sha384_context is NULL, then return FALSE.
  If new_sha384_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha384_context     Pointer to SHA-384 context being copied.
  @param[out] new_sha384_context  Pointer to new SHA-384 context.

  @retval TRUE   SHA-384 context copy succeeded.
  @retval FALSE  SHA-384 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha384_duplicate(IN const void *sha384_context,
			 OUT void *new_sha384_context);

/**
  Digests the input data and updates SHA-384 context.

  This function performs SHA-384 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-384 context should be already correctly initialized by sha384_init(), and should not be finalized
  by sha384_final(). Behavior with invalid context is undefined.

  If sha384_context is NULL, then return FALSE.

  @param[in, out]  sha384_context  Pointer to the SHA-384 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA-384 data digest succeeded.
  @retval FALSE  SHA-384 data digest failed.

**/
boolean sha384_update(IN OUT void *sha384_context, IN const void *data,
		      IN uintn data_size);

/**
  Completes computation of the SHA-384 digest value.

  This function completes SHA-384 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-384 context cannot
  be used again.
  SHA-384 context should be already correctly initialized by sha384_init(), and should not be
  finalized by sha384_final(). Behavior with invalid SHA-384 context is undefined.

  If sha384_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha384_context  Pointer to the SHA-384 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA-384 digest
                                  value (48 bytes).

  @retval TRUE   SHA-384 digest computation succeeded.
  @retval FALSE  SHA-384 digest computation failed.

**/
boolean sha384_final(IN OUT void *sha384_context, OUT uint8 *hash_value);

/**
  Computes the SHA-384 message digest of a input data buffer.

  This function performs the SHA-384 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA-384 digest
                           value (48 bytes).

  @retval TRUE   SHA-384 digest computation succeeded.
  @retval FALSE  SHA-384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha384_hash_all(IN const void *data, IN uintn data_size,
			OUT uint8 *hash_value);

/**
  Allocates and initializes one HASH_CTX context for subsequent SHA512 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, sha512_new() returns NULL.

**/
void *sha512_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  sha512_ctx  Pointer to the HASH_CTX context to be released.

**/
void sha512_free(IN void *sha512_ctx);

/**
  Initializes user-supplied memory pointed by sha512_context as SHA-512 hash context for
  subsequent use.

  If sha512_context is NULL, then return FALSE.

  @param[out]  sha512_context  Pointer to SHA-512 context being initialized.

  @retval TRUE   SHA-512 context initialization succeeded.
  @retval FALSE  SHA-512 context initialization failed.

**/
boolean sha512_init(OUT void *sha512_context);

/**
  Makes a copy of an existing SHA-512 context.

  If sha512_context is NULL, then return FALSE.
  If new_sha512_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha512_context     Pointer to SHA-512 context being copied.
  @param[out] new_sha512_context  Pointer to new SHA-512 context.

  @retval TRUE   SHA-512 context copy succeeded.
  @retval FALSE  SHA-512 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha512_duplicate(IN const void *sha512_context,
			 OUT void *new_sha512_context);

/**
  Digests the input data and updates SHA-512 context.

  This function performs SHA-512 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-512 context should be already correctly initialized by sha512_init(), and should not be finalized
  by sha512_final(). Behavior with invalid context is undefined.

  If sha512_context is NULL, then return FALSE.

  @param[in, out]  sha512_context  Pointer to the SHA-512 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA-512 data digest succeeded.
  @retval FALSE  SHA-512 data digest failed.

**/
boolean sha512_update(IN OUT void *sha512_context, IN const void *data,
		      IN uintn data_size);

/**
  Completes computation of the SHA-512 digest value.

  This function completes SHA-512 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-512 context cannot
  be used again.
  SHA-512 context should be already correctly initialized by sha512_init(), and should not be
  finalized by sha512_final(). Behavior with invalid SHA-512 context is undefined.

  If sha512_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha512_context  Pointer to the SHA-512 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA-512 digest
                                  value (64 bytes).

  @retval TRUE   SHA-512 digest computation succeeded.
  @retval FALSE  SHA-512 digest computation failed.

**/
boolean sha512_final(IN OUT void *sha512_context, OUT uint8 *hash_value);

/**
  Computes the SHA-512 message digest of a input data buffer.

  This function performs the SHA-512 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA-512 digest
                           value (64 bytes).

  @retval TRUE   SHA-512 digest computation succeeded.
  @retval FALSE  SHA-512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha512_hash_all(IN const void *data, IN uintn data_size,
			OUT uint8 *hash_value);

//=====================================================================================
//    One-Way Cryptographic hash SHA3 Primitives
//=====================================================================================

/**
  Allocates and initializes one HASH_CTX context for subsequent SHA3-256 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, sha3_256_new() returns NULL.

**/
void *sha3_256_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  sha3_256_ctx  Pointer to the HASH_CTX context to be released.

**/
void sha3_256_free(IN void *sha3_256_ctx);

/**
  Initializes user-supplied memory pointed by sha3_256_context as SHA3-256 hash context for
  subsequent use.

  If sha3_256_context is NULL, then return FALSE.

  @param[out]  sha3_256_context  Pointer to SHA3-256 context being initialized.

  @retval TRUE   SHA3-256 context initialization succeeded.
  @retval FALSE  SHA3-256 context initialization failed.

**/
boolean sha3_256_init(OUT void *sha3_256_context);

/**
  Makes a copy of an existing SHA3-256 context.

  If sha3_256_context is NULL, then return FALSE.
  If new_sha3_256_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha3_256_context     Pointer to SHA3-256 context being copied.
  @param[out] new_sha3_256_context  Pointer to new SHA3-256 context.

  @retval TRUE   SHA3-256 context copy succeeded.
  @retval FALSE  SHA3-256 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_256_duplicate(IN const void *sha3_256_context,
			   OUT void *new_sha3_256_context);

/**
  Digests the input data and updates SHA3-256 context.

  This function performs SHA3-256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA3-256 context should be already correctly initialized by sha3_256_init(), and should not be finalized
  by sha3_256_final(). Behavior with invalid context is undefined.

  If sha3_256_context is NULL, then return FALSE.

  @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA3-256 data digest succeeded.
  @retval FALSE  SHA3-256 data digest failed.

**/
boolean sha3_256_update(IN OUT void *sha3_256_context, IN const void *data,
			IN uintn data_size);

/**
  Completes computation of the SHA3-256 digest value.

  This function completes SHA3-256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA3-256 context cannot
  be used again.
  SHA3-256 context should be already correctly initialized by sha3_256_init(), and should not be
  finalized by sha3_256_final(). Behavior with invalid SHA3-256 context is undefined.

  If sha3_256_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA3-256 digest
                                  value (256 / 8 bytes).

  @retval TRUE   SHA3-256 digest computation succeeded.
  @retval FALSE  SHA3-256 digest computation failed.

**/
boolean sha3_256_final(IN OUT void *sha3_256_context, OUT uint8 *hash_value);

/**
  Computes the SHA3-256 message digest of a input data buffer.

  This function performs the SHA3-256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA3-256 digest
                           value (256 / 8 bytes).

  @retval TRUE   SHA3-256 digest computation succeeded.
  @retval FALSE  SHA3-256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_256_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value);

/**
  Allocates and initializes one HASH_CTX context for subsequent SHA3-384 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, sha3_384_new() returns NULL.

**/
void *sha3_384_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  sha3_384_ctx  Pointer to the HASH_CTX context to be released.

**/
void sha3_384_free(IN void *sha3_384_ctx);

/**
  Initializes user-supplied memory pointed by sha3_384_context as SHA3-384 hash context for
  subsequent use.

  If sha3_384_context is NULL, then return FALSE.

  @param[out]  sha3_384_context  Pointer to SHA3-384 context being initialized.

  @retval TRUE   SHA3-384 context initialization succeeded.
  @retval FALSE  SHA3-384 context initialization failed.

**/
boolean sha3_384_init(OUT void *sha3_384_context);

/**
  Makes a copy of an existing SHA3-384 context.

  If sha3_384_context is NULL, then return FALSE.
  If new_sha3_384_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha3_384_context     Pointer to SHA3-384 context being copied.
  @param[out] new_sha3_384_context  Pointer to new SHA3-384 context.

  @retval TRUE   SHA3-384 context copy succeeded.
  @retval FALSE  SHA3-384 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_384_duplicate(IN const void *sha3_384_context,
			   OUT void *new_sha3_384_context);

/**
  Digests the input data and updates SHA3-384 context.

  This function performs SHA3-384 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA3-384 context should be already correctly initialized by sha3_384_init(), and should not be finalized
  by sha3_384_final(). Behavior with invalid context is undefined.

  If sha3_384_context is NULL, then return FALSE.

  @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA3-384 data digest succeeded.
  @retval FALSE  SHA3-384 data digest failed.

**/
boolean sha3_384_update(IN OUT void *sha3_384_context, IN const void *data,
			IN uintn data_size);

/**
  Completes computation of the SHA3-384 digest value.

  This function completes SHA3-384 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA3-384 context cannot
  be used again.
  SHA3-384 context should be already correctly initialized by sha3_384_init(), and should not be
  finalized by sha3_384_final(). Behavior with invalid SHA3-384 context is undefined.

  If sha3_384_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA3-384 digest
                                  value (384 / 8 bytes).

  @retval TRUE   SHA3-384 digest computation succeeded.
  @retval FALSE  SHA3-384 digest computation failed.

**/
boolean sha3_384_final(IN OUT void *sha3_384_context, OUT uint8 *hash_value);

/**
  Computes the SHA3-384 message digest of a input data buffer.

  This function performs the SHA3-384 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA3-384 digest
                           value (384 / 8 bytes).

  @retval TRUE   SHA3-384 digest computation succeeded.
  @retval FALSE  SHA3-384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_384_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value);

/**
  Allocates and initializes one HASH_CTX context for subsequent SHA3-512 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, sha3_512_new() returns NULL.

**/
void *sha3_512_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  sha3_512_ctx  Pointer to the HASH_CTX context to be released.

**/
void sha3_512_free(IN void *sha3_512_ctx);

/**
  Initializes user-supplied memory pointed by sha3_512_context as SHA3-512 hash context for
  subsequent use.

  If sha3_512_context is NULL, then return FALSE.

  @param[out]  sha3_512_context  Pointer to SHA3-512 context being initialized.

  @retval TRUE   SHA3-512 context initialization succeeded.
  @retval FALSE  SHA3-512 context initialization failed.

**/
boolean sha3_512_init(OUT void *sha3_512_context);

/**
  Makes a copy of an existing SHA3-512 context.

  If sha3_512_context is NULL, then return FALSE.
  If new_sha3_512_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sha3_512_context     Pointer to SHA3-512 context being copied.
  @param[out] new_sha3_512_context  Pointer to new SHA3-512 context.

  @retval TRUE   SHA3-512 context copy succeeded.
  @retval FALSE  SHA3-512 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_512_duplicate(IN const void *sha3_512_context,
			   OUT void *new_sha3_512_context);

/**
  Digests the input data and updates SHA3-512 context.

  This function performs SHA3-512 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA3-512 context should be already correctly initialized by sha3_512_init(), and should not be finalized
  by sha3_512_final(). Behavior with invalid context is undefined.

  If sha3_512_context is NULL, then return FALSE.

  @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHA3-512 data digest succeeded.
  @retval FALSE  SHA3-512 data digest failed.

**/
boolean sha3_512_update(IN OUT void *sha3_512_context, IN const void *data,
			IN uintn data_size);

/**
  Completes computation of the SHA3-512 digest value.

  This function completes SHA3-512 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA3-512 context cannot
  be used again.
  SHA3-512 context should be already correctly initialized by sha3_512_init(), and should not be
  finalized by sha3_512_final(). Behavior with invalid SHA3-512 context is undefined.

  If sha3_512_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHA3-512 digest
                                  value (512 / 8 bytes).

  @retval TRUE   SHA3-512 digest computation succeeded.
  @retval FALSE  SHA3-512 digest computation failed.

**/
boolean sha3_512_final(IN OUT void *sha3_512_context, OUT uint8 *hash_value);

/**
  Computes the SHA3-512 message digest of a input data buffer.

  This function performs the SHA3-512 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHA3-512 digest
                           value (512 / 8 bytes).

  @retval TRUE   SHA3-512 digest computation succeeded.
  @retval FALSE  SHA3-512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sha3_512_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value);

/**
  Allocates and initializes one HASH_CTX context for subsequent SHAKE-256 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, shake256_new() returns NULL.

**/
void *shake256_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  shake256_ctx  Pointer to the HASH_CTX context to be released.

**/
void shake256_free(IN void *shake256_ctx);

/**
  Initializes user-supplied memory pointed by shake256_context as SHAKE256 hash context for
  subsequent use.

  If shake256_context is NULL, then return FALSE.

  @param[out]  shake256_context  Pointer to SHAKE256 context being initialized.

  @retval TRUE   SHAKE256 context initialization succeeded.
  @retval FALSE  SHAKE256 context initialization failed.

**/
boolean shake256_init(OUT void *shake256_context);

/**
  Makes a copy of an existing SHAKE256 context.

  If shake256_context is NULL, then return FALSE.
  If new_shake256_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  shake256_context     Pointer to SHAKE256 context being copied.
  @param[out] new_shake256_context  Pointer to new SHAKE256 context.

  @retval TRUE   SHAKE256 context copy succeeded.
  @retval FALSE  SHAKE256 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean shake256_duplicate(IN const void *shake256_context,
			   OUT void *new_shake256_context);

/**
  Digests the input data and updates SHAKE256 context.

  This function performs SHAKE256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHAKE256 context should be already correctly initialized by shake256_init(), and should not be finalized
  by shake256_final(). Behavior with invalid context is undefined.

  If shake256_context is NULL, then return FALSE.

  @param[in, out]  shake256_context  Pointer to the SHAKE256 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SHAKE256 data digest succeeded.
  @retval FALSE  SHAKE256 data digest failed.

**/
boolean shake256_update(IN OUT void *shake256_context, IN const void *data,
			IN uintn data_size);

/**
  Completes computation of the SHAKE256 digest value.

  This function completes SHAKE256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHAKE256 context cannot
  be used again.
  SHAKE256 context should be already correctly initialized by shake256_init(), and should not be
  finalized by shake256_final(). Behavior with invalid SHAKE256 context is undefined.

  If shake256_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  shake256_context  Pointer to the SHAKE256 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SHAKE256 digest
                                  value (256 / 8 bytes).

  @retval TRUE   SHAKE256 digest computation succeeded.
  @retval FALSE  SHAKE256 digest computation failed.

**/
boolean shake256_final(IN OUT void *shake256_context, OUT uint8 *hash_value);

/**
  Computes the SHAKE256 message digest of a input data buffer.

  This function performs the SHAKE256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SHAKE256 digest
                           value (256 / 8 bytes).

  @retval TRUE   SHAKE256 digest computation succeeded.
  @retval FALSE  SHAKE256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean shake256_hash_all(IN const void *data, IN uintn data_size,
			  OUT uint8 *hash_value);

//=====================================================================================
//    One-Way Cryptographic hash SM3 Primitives
//=====================================================================================

/**
  Allocates and initializes one HASH_CTX context for subsequent SM3-256 use.

  @return  Pointer to the HASH_CTX context that has been initialized.
           If the allocations fails, sm3_256_new() returns NULL.

**/
void *sm3_256_new(void);

/**
  Release the specified HASH_CTX context.

  @param[in]  sm3_256_ctx  Pointer to the HASH_CTX context to be released.

**/
void sm3_256_free(IN void *sm3_256_ctx);

/**
  Initializes user-supplied memory pointed by sm3_context as SM3 hash context for
  subsequent use.

  If sm3_context is NULL, then return FALSE.

  @param[out]  sm3_context  Pointer to SM3 context being initialized.

  @retval TRUE   SM3 context initialization succeeded.
  @retval FALSE  SM3 context initialization failed.

**/
boolean sm3_256_init(OUT void *sm3_context);

/**
  Makes a copy of an existing SM3 context.

  If sm3_context is NULL, then return FALSE.
  If new_sm3_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  sm3_context     Pointer to SM3 context being copied.
  @param[out] new_sm3_context  Pointer to new SM3 context.

  @retval TRUE   SM3 context copy succeeded.
  @retval FALSE  SM3 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean sm3_256_duplicate(IN const void *sm3_context,
			  OUT void *new_sm3_context);

/**
  Digests the input data and updates SM3 context.

  This function performs SM3 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SM3 context should be already correctly initialized by sm3_init(), and should not be finalized
  by sm3_final(). Behavior with invalid context is undefined.

  If sm3_context is NULL, then return FALSE.

  @param[in, out]  sm3_context     Pointer to the SM3 context.
  @param[in]       data           Pointer to the buffer containing the data to be hashed.
  @param[in]       data_size       size of data buffer in bytes.

  @retval TRUE   SM3 data digest succeeded.
  @retval FALSE  SM3 data digest failed.

**/
boolean sm3_256_update(IN OUT void *sm3_context, IN const void *data,
		       IN uintn data_size);

/**
  Completes computation of the SM3 digest value.

  This function completes SM3 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SM3 context cannot
  be used again.
  SM3 context should be already correctly initialized by sm3_init(), and should not be
  finalized by sm3_final(). Behavior with invalid SM3 context is undefined.

  If sm3_context is NULL, then return FALSE.
  If hash_value is NULL, then return FALSE.

  @param[in, out]  sm3_context     Pointer to the SM3 context.
  @param[out]      hash_value      Pointer to a buffer that receives the SM3 digest
                                  value (32 bytes).

  @retval TRUE   SM3 digest computation succeeded.
  @retval FALSE  SM3 digest computation failed.

**/
boolean sm3_256_final(IN OUT void *sm3_context, OUT uint8 *hash_value);

/**
  Computes the SM3 message digest of a input data buffer.

  This function performs the SM3 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be hashed.
  @param[in]   data_size    size of data buffer in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the SM3 digest
                           value (32 bytes).

  @retval TRUE   SM3 digest computation succeeded.
  @retval FALSE  SM3 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean sm3_256_hash_all(IN const void *data, IN uintn data_size,
			 OUT uint8 *hash_value);

//=====================================================================================
//    MAC (message Authentication Code) Primitive
//=====================================================================================

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SHA256 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_sha256_new() returns NULL.

**/
void *hmac_sha256_new(void);

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_sha256_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_sha256_free(IN void *hmac_sha256_ctx);

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_sha256_update().

  If hmac_sha256_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[out]  hmac_sha256_ctx  Pointer to HMAC-SHA256 context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha256_set_key(OUT void *hmac_sha256_ctx, IN const uint8 *key,
			    IN uintn key_size);

/**
  Makes a copy of an existing HMAC-SHA256 context.

  If hmac_sha256_ctx is NULL, then return FALSE.
  If new_hmac_sha256_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  hmac_sha256_ctx     Pointer to HMAC-SHA256 context being copied.
  @param[out] new_hmac_sha256_ctx  Pointer to new HMAC-SHA256 context.

  @retval TRUE   HMAC-SHA256 context copy succeeded.
  @retval FALSE  HMAC-SHA256 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha256_duplicate(IN const void *hmac_sha256_ctx,
			      OUT void *new_hmac_sha256_ctx);

/**
  Digests the input data and updates HMAC-SHA256 context.

  This function performs HMAC-SHA256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SHA256 context should be initialized by hmac_sha256_new(), and should not be finalized
  by hmac_sha256_final(). Behavior with invalid context is undefined.

  If hmac_sha256_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha256_ctx Pointer to the HMAC-SHA256 context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-SHA256 data digest succeeded.
  @retval FALSE  HMAC-SHA256 data digest failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha256_update(IN OUT void *hmac_sha256_ctx, IN const void *data,
			   IN uintn data_size);

/**
  Completes computation of the HMAC-SHA256 digest value.

  This function completes HMAC-SHA256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SHA256 context cannot
  be used again.
  HMAC-SHA256 context should be initialized by hmac_sha256_new(), and should not be finalized
  by hmac_sha256_final(). Behavior with invalid HMAC-SHA256 context is undefined.

  If hmac_sha256_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha256_ctx  Pointer to the HMAC-SHA256 context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA256 digest
                                      value (32 bytes).

  @retval TRUE   HMAC-SHA256 digest computation succeeded.
  @retval FALSE  HMAC-SHA256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha256_final(IN OUT void *hmac_sha256_ctx, OUT uint8 *hmac_value);

/**
  Computes the HMAC-SHA256 digest of a input data buffer.

  This function performs the HMAC-SHA256 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA256 digest
                           value (32 bytes).

  @retval TRUE   HMAC-SHA256 digest computation succeeded.
  @retval FALSE  HMAC-SHA256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha256_all(IN const void *data, IN uintn data_size,
			IN const uint8 *key, IN uintn key_size,
			OUT uint8 *hmac_value);

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SHA384 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_sha384_new() returns NULL.

**/
void *hmac_sha384_new(void);

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_sha384_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_sha384_free(IN void *hmac_sha384_ctx);

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_sha384_update().

  If hmac_sha384_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[out]  hmac_sha384_ctx  Pointer to HMAC-SHA384 context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_set_key(OUT void *hmac_sha384_ctx, IN const uint8 *key,
			    IN uintn key_size);

/**
  Makes a copy of an existing HMAC-SHA384 context.

  If hmac_sha384_ctx is NULL, then return FALSE.
  If new_hmac_sha384_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  hmac_sha384_ctx     Pointer to HMAC-SHA384 context being copied.
  @param[out] new_hmac_sha384_ctx  Pointer to new HMAC-SHA384 context.

  @retval TRUE   HMAC-SHA384 context copy succeeded.
  @retval FALSE  HMAC-SHA384 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_duplicate(IN const void *hmac_sha384_ctx,
			      OUT void *new_hmac_sha384_ctx);

/**
  Digests the input data and updates HMAC-SHA384 context.

  This function performs HMAC-SHA384 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SHA384 context should be initialized by hmac_sha384_new(), and should not be finalized
  by hmac_sha384_final(). Behavior with invalid context is undefined.

  If hmac_sha384_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha384_ctx Pointer to the HMAC-SHA384 context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-SHA384 data digest succeeded.
  @retval FALSE  HMAC-SHA384 data digest failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_update(IN OUT void *hmac_sha384_ctx, IN const void *data,
			   IN uintn data_size);

/**
  Completes computation of the HMAC-SHA384 digest value.

  This function completes HMAC-SHA384 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SHA384 context cannot
  be used again.
  HMAC-SHA384 context should be initialized by hmac_sha384_new(), and should not be finalized
  by hmac_sha384_final(). Behavior with invalid HMAC-SHA384 context is undefined.

  If hmac_sha384_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha384_ctx  Pointer to the HMAC-SHA384 context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA384 digest
                                      value (48 bytes).

  @retval TRUE   HMAC-SHA384 digest computation succeeded.
  @retval FALSE  HMAC-SHA384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_final(IN OUT void *hmac_sha384_ctx, OUT uint8 *hmac_value);

/**
  Computes the HMAC-SHA384 digest of a input data buffer.

  This function performs the HMAC-SHA384 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA384 digest
                           value (48 bytes).

  @retval TRUE   HMAC-SHA384 digest computation succeeded.
  @retval FALSE  HMAC-SHA384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha384_all(IN const void *data, IN uintn data_size,
			IN const uint8 *key, IN uintn key_size,
			OUT uint8 *hmac_value);

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SHA512 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_sha512_new() returns NULL.

**/
void *hmac_sha512_new(void);

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_sha512_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_sha512_free(IN void *hmac_sha512_ctx);

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_sha512_update().

  If hmac_sha512_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[out]  hmac_sha512_ctx  Pointer to HMAC-SHA512 context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_set_key(OUT void *hmac_sha512_ctx, IN const uint8 *key,
			    IN uintn key_size);

/**
  Makes a copy of an existing HMAC-SHA512 context.

  If hmac_sha512_ctx is NULL, then return FALSE.
  If new_hmac_sha512_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  hmac_sha512_ctx     Pointer to HMAC-SHA512 context being copied.
  @param[out] new_hmac_sha512_ctx  Pointer to new HMAC-SHA512 context.

  @retval TRUE   HMAC-SHA512 context copy succeeded.
  @retval FALSE  HMAC-SHA512 context copy failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_duplicate(IN const void *hmac_sha512_ctx,
			      OUT void *new_hmac_sha512_ctx);

/**
  Digests the input data and updates HMAC-SHA512 context.

  This function performs HMAC-SHA512 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SHA512 context should be initialized by hmac_sha512_new(), and should not be finalized
  by hmac_sha512_final(). Behavior with invalid context is undefined.

  If hmac_sha512_ctx is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha512_ctx Pointer to the HMAC-SHA512 context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-SHA512 data digest succeeded.
  @retval FALSE  HMAC-SHA512 data digest failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_update(IN OUT void *hmac_sha512_ctx, IN const void *data,
			   IN uintn data_size);

/**
  Completes computation of the HMAC-SHA512 digest value.

  This function completes HMAC-SHA512 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SHA512 context cannot
  be used again.
  HMAC-SHA512 context should be initialized by hmac_sha512_new(), and should not be finalized
  by hmac_sha512_final(). Behavior with invalid HMAC-SHA512 context is undefined.

  If hmac_sha512_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  hmac_sha512_ctx  Pointer to the HMAC-SHA512 context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SHA512 digest
                                      value (64 bytes).

  @retval TRUE   HMAC-SHA512 digest computation succeeded.
  @retval FALSE  HMAC-SHA512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_final(IN OUT void *hmac_sha512_ctx, OUT uint8 *hmac_value);

/**
  Computes the HMAC-SHA512 digest of a input data buffer.

  This function performs the HMAC-SHA512 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA512 digest
                           value (64 bytes).

  @retval TRUE   HMAC-SHA512 digest computation succeeded.
  @retval FALSE  HMAC-SHA512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sha512_all(IN const void *data, IN uintn data_size,
			IN const uint8 *key, IN uintn key_size,
			OUT uint8 *hmac_value);

//=====================================================================================
//    Authenticated Encryption with Associated data (AEAD) Cryptography Primitive
//=====================================================================================

/**
  Performs AEAD AES-GCM authenticated encryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 16, 24 or 32, otherwise FALSE is returned.
  tag_size must be 12, 13, 14, 15, 16, otherwise FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be encrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[out]  tag_out      Pointer to a buffer that receives the authentication tag output.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the encryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD AES-GCM authenticated encryption succeeded.
  @retval FALSE  AEAD AES-GCM authenticated encryption failed.

**/
boolean aead_aes_gcm_encrypt(IN const uint8 *key, IN uintn key_size,
			     IN const uint8 *iv, IN uintn iv_size,
			     IN const uint8 *a_data, IN uintn a_data_size,
			     IN const uint8 *data_in, IN uintn data_in_size,
			     OUT uint8 *tag_out, IN uintn tag_size,
			     OUT uint8 *data_out, OUT uintn *data_out_size);

/**
  Performs AEAD AES-GCM authenticated decryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 16, 24 or 32, otherwise FALSE is returned.
  tag_size must be 12, 13, 14, 15, 16, otherwise FALSE is returned.
  If additional authenticated data verification fails, FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be decrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[in]   tag         Pointer to a buffer that contains the authentication tag.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the decryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD AES-GCM authenticated decryption succeeded.
  @retval FALSE  AEAD AES-GCM authenticated decryption failed.

**/
boolean aead_aes_gcm_decrypt(IN const uint8 *key, IN uintn key_size,
			     IN const uint8 *iv, IN uintn iv_size,
			     IN const uint8 *a_data, IN uintn a_data_size,
			     IN const uint8 *data_in, IN uintn data_in_size,
			     IN const uint8 *tag, IN uintn tag_size,
			     OUT uint8 *data_out, OUT uintn *data_out_size);

/**
  Performs AEAD ChaCha20Poly1305 authenticated encryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 32, otherwise FALSE is returned.
  tag_size must be 16, otherwise FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be encrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[out]  tag_out      Pointer to a buffer that receives the authentication tag output.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the encryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD ChaCha20Poly1305 authenticated encryption succeeded.
  @retval FALSE  AEAD ChaCha20Poly1305 authenticated encryption failed.

**/
boolean aead_chacha20_poly1305_encrypt(
	IN const uint8 *key, IN uintn key_size, IN const uint8 *iv,
	IN uintn iv_size, IN const uint8 *a_data, IN uintn a_data_size,
	IN const uint8 *data_in, IN uintn data_in_size, OUT uint8 *tag_out,
	IN uintn tag_size, OUT uint8 *data_out, OUT uintn *data_out_size);

/**
  Performs AEAD ChaCha20Poly1305 authenticated decryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 32, otherwise FALSE is returned.
  tag_size must be 16, otherwise FALSE is returned.
  If additional authenticated data verification fails, FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be decrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[in]   tag         Pointer to a buffer that contains the authentication tag.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the decryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD ChaCha20Poly1305 authenticated decryption succeeded.
  @retval FALSE  AEAD ChaCha20Poly1305 authenticated decryption failed.

**/
boolean aead_chacha20_poly1305_decrypt(
	IN const uint8 *key, IN uintn key_size, IN const uint8 *iv,
	IN uintn iv_size, IN const uint8 *a_data, IN uintn a_data_size,
	IN const uint8 *data_in, IN uintn data_in_size, IN const uint8 *tag,
	IN uintn tag_size, OUT uint8 *data_out, OUT uintn *data_out_size);

/**
  Performs AEAD SM4-GCM authenticated encryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 16, otherwise FALSE is returned.
  tag_size must be 16, otherwise FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be encrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[out]  tag_out      Pointer to a buffer that receives the authentication tag output.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the encryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD SM4-GCM authenticated encryption succeeded.
  @retval FALSE  AEAD SM4-GCM authenticated encryption failed.

**/
boolean aead_sm4_gcm_encrypt(IN const uint8 *key, IN uintn key_size,
			     IN const uint8 *iv, IN uintn iv_size,
			     IN const uint8 *a_data, IN uintn a_data_size,
			     IN const uint8 *data_in, IN uintn data_in_size,
			     OUT uint8 *tag_out, IN uintn tag_size,
			     OUT uint8 *data_out, OUT uintn *data_out_size);

/**
  Performs AEAD SM4-GCM authenticated decryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 16, otherwise FALSE is returned.
  tag_size must be 16, otherwise FALSE is returned.
  If additional authenticated data verification fails, FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be decrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[in]   tag         Pointer to a buffer that contains the authentication tag.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the decryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD SM4-GCM authenticated decryption succeeded.
  @retval FALSE  AEAD SM4-GCM authenticated decryption failed.

**/
boolean aead_sm4_gcm_decrypt(IN const uint8 *key, IN uintn key_size,
			     IN const uint8 *iv, IN uintn iv_size,
			     IN const uint8 *a_data, IN uintn a_data_size,
			     IN const uint8 *data_in, IN uintn data_in_size,
			     IN const uint8 *tag, IN uintn tag_size,
			     OUT uint8 *data_out, OUT uintn *data_out_size);

//=====================================================================================
//    Asymmetric Cryptography Primitive
//=====================================================================================

/**
  Allocates and initializes one RSA context for subsequent use.

  @return  Pointer to the RSA context that has been initialized.
           If the allocations fails, rsa_new() returns NULL.

**/
void *rsa_new(void);

/**
  Release the specified RSA context.

  If rsa_context is NULL, then return FALSE.

  @param[in]  rsa_context  Pointer to the RSA context to be released.

**/
void rsa_free(IN void *rsa_context);

/**
  Sets the tag-designated key component into the established RSA context.

  This function sets the tag-designated RSA key component into the established
  RSA context from the user-specified non-negative integer (octet string format
  represented in RSA PKCS#1).
  If big_number is NULL, then the specified key component in RSA context is cleared.

  If rsa_context is NULL, then return FALSE.

  @param[in, out]  rsa_context  Pointer to RSA context being set.
  @param[in]       key_tag      tag of RSA key component being set.
  @param[in]       big_number   Pointer to octet integer buffer.
                               If NULL, then the specified key component in RSA
                               context is cleared.
  @param[in]       bn_size      size of big number buffer in bytes.
                               If big_number is NULL, then it is ignored.

  @retval  TRUE   RSA key component was set successfully.
  @retval  FALSE  Invalid RSA key component tag.

**/
boolean rsa_set_key(IN OUT void *rsa_context, IN rsa_key_tag_t key_tag,
		    IN const uint8 *big_number, IN uintn bn_size);

/**
  Gets the tag-designated RSA key component from the established RSA context.

  This function retrieves the tag-designated RSA key component from the
  established RSA context as a non-negative integer (octet string format
  represented in RSA PKCS#1).
  If specified key component has not been set or has been cleared, then returned
  bn_size is set to 0.
  If the big_number buffer is too small to hold the contents of the key, FALSE
  is returned and bn_size is set to the required buffer size to obtain the key.

  If rsa_context is NULL, then return FALSE.
  If bn_size is NULL, then return FALSE.
  If bn_size is large enough but big_number is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  rsa_context  Pointer to RSA context being set.
  @param[in]       key_tag      tag of RSA key component being set.
  @param[out]      big_number   Pointer to octet integer buffer.
  @param[in, out]  bn_size      On input, the size of big number buffer in bytes.
                               On output, the size of data returned in big number buffer in bytes.

  @retval  TRUE   RSA key component was retrieved successfully.
  @retval  FALSE  Invalid RSA key component tag.
  @retval  FALSE  bn_size is too small.
  @retval  FALSE  This interface is not supported.

**/
boolean rsa_get_key(IN OUT void *rsa_context, IN rsa_key_tag_t key_tag,
		    OUT uint8 *big_number, IN OUT uintn *bn_size);

/**
  Generates RSA key components.

  This function generates RSA key components. It takes RSA public exponent E and
  length in bits of RSA modulus N as input, and generates all key components.
  If public_exponent is NULL, the default RSA public exponent (0x10001) will be used.

  Before this function can be invoked, pseudorandom number generator must be correctly
  initialized by random_seed().

  If rsa_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  rsa_context           Pointer to RSA context being set.
  @param[in]       modulus_length        length of RSA modulus N in bits.
  @param[in]       public_exponent       Pointer to RSA public exponent.
  @param[in]       public_exponent_size   size of RSA public exponent buffer in bytes.

  @retval  TRUE   RSA key component was generated successfully.
  @retval  FALSE  Invalid RSA key component tag.
  @retval  FALSE  This interface is not supported.

**/
boolean rsa_generate_key(IN OUT void *rsa_context, IN uintn modulus_length,
			 IN const uint8 *public_exponent,
			 IN uintn public_exponent_size);

/**
  Validates key components of RSA context.
  NOTE: This function performs integrity checks on all the RSA key material, so
        the RSA key structure must contain all the private key data.

  This function validates key components of RSA context in following aspects:
  - Whether p is a prime
  - Whether q is a prime
  - Whether n = p * q
  - Whether d*e = 1  mod lcm(p-1,q-1)

  If rsa_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  rsa_context  Pointer to RSA context to check.

  @retval  TRUE   RSA key components are valid.
  @retval  FALSE  RSA key components are not valid.
  @retval  FALSE  This interface is not supported.

**/
boolean rsa_check_key(IN void *rsa_context);

/**
  Carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme.

  This function carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme defined in
  RSA PKCS#1.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
  If sig_size is large enough but signature is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      rsa_context   Pointer to RSA context for signature generation.
  @param[in]      hash_nid      hash NID
  @param[in]      message_hash  Pointer to octet message hash to be signed.
  @param[in]      hash_size     size of the message hash in bytes.
  @param[out]     signature    Pointer to buffer to receive RSA PKCS1-v1_5 signature.
  @param[in, out] sig_size      On input, the size of signature buffer in bytes.
                               On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in PKCS1-v1_5.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
  @retval  FALSE  This interface is not supported.

**/
boolean rsa_pkcs1_sign_with_nid(IN void *rsa_context, IN uintn hash_nid,
				IN const uint8 *message_hash,
				IN uintn hash_size, OUT uint8 *signature,
				IN OUT uintn *sig_size);

/**
  Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
  RSA PKCS#1.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.

  @param[in]  rsa_context   Pointer to RSA context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message_hash  Pointer to octet message hash to be checked.
  @param[in]  hash_size     size of the message hash in bytes.
  @param[in]  signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in PKCS1-v1_5.
  @retval  FALSE  Invalid signature or invalid RSA context.

**/
boolean rsa_pkcs1_verify_with_nid(IN void *rsa_context, IN uintn hash_nid,
				  IN const uint8 *message_hash,
				  IN uintn hash_size, IN const uint8 *signature,
				  IN uintn sig_size);

/**
  Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme.

  This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
  RSA PKCS#1 v2.2.

  The salt length is same as digest length.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
  If sig_size is large enough but signature is NULL, then return FALSE.

  @param[in]       rsa_context   Pointer to RSA context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message_hash  Pointer to octet message hash to be signed.
  @param[in]       hash_size     size of the message hash in bytes.
  @param[out]      signature    Pointer to buffer to receive RSA-SSA PSS signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in RSA-SSA PSS.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean rsa_pss_sign(IN void *rsa_context, IN uintn hash_nid,
		     IN const uint8 *message_hash, IN uintn hash_size,
		     OUT uint8 *signature, IN OUT uintn *sig_size);

/**
  Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
  RSA PKCS#1 v2.2.

  The salt length is same as digest length.

  If rsa_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.

  @param[in]  rsa_context   Pointer to RSA context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message_hash  Pointer to octet message hash to be checked.
  @param[in]  hash_size     size of the message hash in bytes.
  @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in RSA-SSA PSS.
  @retval  FALSE  Invalid signature or invalid RSA context.

**/
boolean rsa_pss_verify(IN void *rsa_context, IN uintn hash_nid,
		       IN const uint8 *message_hash, IN uintn hash_size,
		       IN const uint8 *signature, IN uintn sig_size);

/**
  Retrieve the RSA Private key from the password-protected PEM key data.

  If pem_data is NULL, then return FALSE.
  If rsa_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
                           RSA private key component. Use rsa_free() function to free the
                           resource.

  @retval  TRUE   RSA Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
  @retval  FALSE  This interface is not supported.

**/
boolean rsa_get_private_key_from_pem(IN const uint8 *pem_data,
				     IN uintn pem_size,
				     IN const char8 *password,
				     OUT void **rsa_context);

/**
  Retrieve the RSA public key from one DER-encoded X509 certificate.

  If cert is NULL, then return FALSE.
  If rsa_context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
                           RSA public key component. Use rsa_free() function to free the
                           resource.

  @retval  TRUE   RSA public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve RSA public key from X509 certificate.
  @retval  FALSE  This interface is not supported.

**/
boolean rsa_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				     OUT void **rsa_context);

/**
  Retrieve the EC Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
                           EC private key component. Use ec_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If ec_context is NULL, then return FALSE.

  @retval  TRUE   EC Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean ec_get_private_key_from_pem(IN const uint8 *pem_data, IN uintn pem_size,
				    IN const char8 *password,
				    OUT void **ec_context);

/**
  Retrieve the EC public key from one DER-encoded X509 certificate.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
                           EC public key component. Use ec_free() function to free the
                           resource.

  If cert is NULL, then return FALSE.
  If ec_context is NULL, then return FALSE.

  @retval  TRUE   EC public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve EC public key from X509 certificate.

**/
boolean ec_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				    OUT void **ec_context);

/**
  Retrieve the Ed Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
                           Ed private key component. Use ecd_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If ecd_context is NULL, then return FALSE.

  @retval  TRUE   Ed Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean ecd_get_private_key_from_pem(IN const uint8 *pem_data,
				     IN uintn pem_size,
				     IN const char8 *password,
				     OUT void **ecd_context);

/**
  Retrieve the Ed public key from one DER-encoded X509 certificate.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
                           Ed public key component. Use ecd_free() function to free the
                           resource.

  If cert is NULL, then return FALSE.
  If ecd_context is NULL, then return FALSE.

  @retval  TRUE   Ed public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve Ed public key from X509 certificate.

**/
boolean ed_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				    OUT void **ecd_context);

/**
  Retrieve the sm2 Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
                           sm2 private key component. Use sm2_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If sm2_context is NULL, then return FALSE.

  @retval  TRUE   sm2 Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean sm2_get_private_key_from_pem(IN const uint8 *pem_data,
				     IN uintn pem_size,
				     IN const char8 *password,
				     OUT void **sm2_context);

/**
  Retrieve the sm2 public key from one DER-encoded X509 certificate.

  @param[in]  cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  cert_size     size of the X509 certificate in bytes.
  @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
                           sm2 public key component. Use sm2_free() function to free the
                           resource.

  If cert is NULL, then return FALSE.
  If sm2_context is NULL, then return FALSE.

  @retval  TRUE   sm2 public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve sm2 public key from X509 certificate.

**/
boolean sm2_get_public_key_from_x509(IN const uint8 *cert, IN uintn cert_size,
				     OUT void **sm2_context);

/**
  Retrieve the tag and length of the tag.

  @param ptr      The position in the ASN.1 data
  @param end      end of data
  @param length   The variable that will receive the length
  @param tag      The expected tag

  @retval      TRUE   Get tag successful
  @retval      FALSe  Failed to get tag or tag not match
**/
boolean asn1_get_tag(IN OUT uint8 **ptr, IN uint8 *end, OUT uintn *length,
		     IN uint32 tag);

/**
  Retrieve the subject bytes from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If subject_size is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     cert_subject  Pointer to the retrieved certificate subject bytes.
  @param[in, out] subject_size  The size in bytes of the cert_subject buffer on input,
                               and the size of buffer returned cert_subject on output.

  @retval  TRUE   The certificate subject retrieved successfully.
  @retval  FALSE  Invalid certificate, or the subject_size is too small for the result.
                  The subject_size will be updated with the required size.
  @retval  FALSE  This interface is not supported.

**/
boolean x509_get_subject_name(IN const uint8 *cert, IN uintn cert_size,
			      OUT uint8 *cert_subject,
			      IN OUT uintn *subject_size);

/**
  Retrieve the common name (CN) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     common_name       buffer to contain the retrieved certificate common
                                   name string (UTF8). At most common_name_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
                                   and the size of buffer returned common_name on output.
                                   If common_name is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate common_name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If common_name_size is NULL.
                                   If common_name is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no common_name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status x509_get_common_name(IN const uint8 *cert, IN uintn cert_size,
				   OUT char8 *common_name,
				   OPTIONAL IN OUT uintn *common_name_size);

/**
  Retrieve the organization name (O) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate organization
                                   name string. At most name_buffer_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Organization name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status
x509_get_organization_name(IN const uint8 *cert, IN uintn cert_size,
			   OUT char8 *name_buffer,
			   OPTIONAL IN OUT uintn *name_buffer_size);

/**
  Retrieve the version from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If cert_size is 0, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     version      Pointer to the retrieved version integer.

  @retval RETURN_SUCCESS           The certificate version retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If  cert is NULL or cert_size is Zero.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status x509_get_version(IN const uint8 *cert, IN uintn cert_size,
			       OUT uintn *version);

/**
  Retrieve the serialNumber from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If cert_size is 0, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     serial_number  Pointer to the retrieved certificate serial_number bytes.
  @param[in, out] serial_number_size  The size in bytes of the serial_number buffer on input,
                               and the size of buffer returned serial_number on output.

  @retval RETURN_SUCCESS           The certificate serialNumber retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL or cert_size is Zero.
                                   If serial_number_size is NULL.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no serial_number exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the serial_number is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   serial_number_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_serial_number(IN const uint8 *cert, IN uintn cert_size,
				     OUT uint8 *serial_number,
				     OPTIONAL IN OUT uintn *serial_number_size);

/**
  Retrieve the issuer bytes from one X.509 certificate.

  If cert is NULL, then return FALSE.
  If CertIssuerSize is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     CertIssuer  Pointer to the retrieved certificate subject bytes.
  @param[in, out] CertIssuerSize  The size in bytes of the CertIssuer buffer on input,
                               and the size of buffer returned cert_subject on output.

  @retval  TRUE   The certificate issuer retrieved successfully.
  @retval  FALSE  Invalid certificate, or the CertIssuerSize is too small for the result.
                  The CertIssuerSize will be updated with the required size.
  @retval  FALSE  This interface is not supported.

**/
boolean x509_get_issuer_name(IN const uint8 *cert, IN uintn cert_size,
			     OUT uint8 *CertIssuer,
			     IN OUT uintn *CertIssuerSize);

/**
  Retrieve the issuer common name (CN) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     common_name       buffer to contain the retrieved certificate issuer common
                                   name string. At most common_name_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
                                   and the size of buffer returned common_name on output.
                                   If common_name is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate Issuer common_name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If common_name_size is NULL.
                                   If common_name is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no common_name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status
x509_get_issuer_common_name(IN const uint8 *cert, IN uintn cert_size,
			    OUT char8 *common_name,
			    OPTIONAL IN OUT uintn *common_name_size);

/**
  Retrieve the issuer organization name (O) string from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     name_buffer       buffer to contain the retrieved certificate issuer organization
                                   name string. At most name_buffer_size bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
                                   and the size of buffer returned name on output.
                                   If name_buffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate issuer Organization name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If name_buffer_size is NULL.
                                   If name_buffer is not NULL and *common_name_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Organization name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   common_name_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
return_status
x509_get_issuer_orgnization_name(IN const uint8 *cert, IN uintn cert_size,
				 OUT char8 *name_buffer,
				 OPTIONAL IN OUT uintn *name_buffer_size);

/**
  Retrieve the signature algorithm from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     oid              signature algorithm Object identifier buffer
  @param[in,out]  oid_size          signature algorithm Object identifier buffer size

  @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If oid_size is NULL.
                                   If oid is not NULL and *oid_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SignatureType.
  @retval RETURN_BUFFER_TOO_SMALL  If the oid is NULL. The required buffer size
                                   is returned in the oid_size.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_signature_algorithm(IN const uint8 *cert,
					   IN uintn cert_size, OUT uint8 *oid,
					   OPTIONAL IN OUT uintn *oid_size);

/**
  Retrieve Extension data from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[in]      oid              Object identifier buffer
  @param[in]      oid_size          Object identifier buffer size
  @param[out]     extension_data    Extension bytes.
  @param[in, out] extension_data_size Extension bytes size.

  @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If extension_data_size is NULL.
                                   If extension_data is not NULL and *extension_data_size is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Extension entry match oid.
  @retval RETURN_BUFFER_TOO_SMALL  If the extension_data is NULL. The required buffer size
                                   is returned in the extension_data_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_extension_data(IN const uint8 *cert, IN uintn cert_size,
				      IN uint8 *oid, IN uintn oid_size,
				      OUT uint8 *extension_data,
				      IN OUT uintn *extension_data_size);

/**
  Retrieve the Validity from one X.509 certificate

  If cert is NULL, then return FALSE.
  If CertIssuerSize is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     from         notBefore Pointer to date_time object.
  @param[in,out]  from_size     notBefore date_time object size.
  @param[out]     to           notAfter Pointer to date_time object.
  @param[in,out]  to_size       notAfter date_time object size.

  Note: x509_compare_date_time to compare date_time oject
        x509SetDateTime to get a date_time object from a date_time_str

  @retval  TRUE   The certificate Validity retrieved successfully.
  @retval  FALSE  Invalid certificate, or Validity retrieve failed.
  @retval  FALSE  This interface is not supported.
**/
boolean x509_get_validity(IN const uint8 *cert, IN uintn cert_size,
			  IN uint8 *from, IN OUT uintn *from_size, IN uint8 *to,
			  IN OUT uintn *to_size);

/**
  format a date_time object into DataTime buffer

  If date_time_str is NULL, then return FALSE.
  If date_time_size is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      date_time_str      date_time string like YYYYMMDDhhmmssZ
                                   Ref: https://www.w3.org/TR/NOTE-datetime
                                   Z stand for UTC time
  @param[out]     date_time         Pointer to a date_time object.
  @param[in,out]  date_time_size     date_time object buffer size.

  @retval RETURN_SUCCESS           The date_time object create successfully.
  @retval RETURN_INVALID_PARAMETER If date_time_str is NULL.
                                   If date_time_size is NULL.
                                   If date_time is not NULL and *date_time_size is 0.
                                   If year month day hour minute second combination is invalid datetime.
  @retval RETURN_BUFFER_TOO_SMALL  If the date_time is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   date_time_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_set_date_time(char8 *date_time_str, IN OUT void *date_time,
				 IN OUT uintn *date_time_size);

/**
  Compare date_time1 object and date_time2 object.

  If date_time1 is NULL, then return -2.
  If date_time2 is NULL, then return -2.
  If date_time1 == date_time2, then return 0
  If date_time1 > date_time2, then return 1
  If date_time1 < date_time2, then return -1

  @param[in]      date_time1         Pointer to a date_time Ojbect
  @param[in]      date_time2         Pointer to a date_time Object

  @retval  0      If date_time1 == date_time2
  @retval  1      If date_time1 > date_time2
  @retval  -1     If date_time1 < date_time2
**/
intn x509_compare_date_time(IN void *date_time1, IN void *date_time2);

/**
  Retrieve the key usage from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     usage            key usage (CRYPTO_X509_KU_*)

  @retval  TRUE   The certificate key usage retrieved successfully.
  @retval  FALSE  Invalid certificate, or usage is NULL
  @retval  FALSE  This interface is not supported.
**/
boolean x509_get_key_usage(IN const uint8 *cert, IN uintn cert_size,
			   OUT uintn *usage);

/**
  Retrieve the Extended key usage from one X.509 certificate.

  @param[in]      cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      cert_size         size of the X509 certificate in bytes.
  @param[out]     usage            key usage bytes.
  @param[in, out] usage_size        key usage buffer sizs in bytes.

  @retval RETURN_SUCCESS           The usage bytes retrieve successfully.
  @retval RETURN_INVALID_PARAMETER If cert is NULL.
                                   If cert_size is NULL.
                                   If usage is not NULL and *usage_size is 0.
                                   If cert is invalid.
  @retval RETURN_BUFFER_TOO_SMALL  If the usage is NULL. The required buffer size
                                   is returned in the usage_size parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
return_status x509_get_extended_key_usage(IN const uint8 *cert,
					  IN uintn cert_size, OUT uint8 *usage,
					  IN OUT uintn *usage_size);

/**
  Verify one X509 certificate was issued by the trusted CA.

  If cert is NULL, then return FALSE.
  If ca_cert is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      cert         Pointer to the DER-encoded X509 certificate to be verified.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[in]      ca_cert       Pointer to the DER-encoded trusted CA certificate.
  @param[in]      ca_cert_size   size of the CA Certificate in bytes.

  @retval  TRUE   The certificate was issued by the trusted CA.
  @retval  FALSE  Invalid certificate or the certificate was not issued by the given
                  trusted CA.
  @retval  FALSE  This interface is not supported.

**/
boolean x509_verify_cert(IN const uint8 *cert, IN uintn cert_size,
			 IN const uint8 *ca_cert, IN uintn ca_cert_size);

/**
  Verify one X509 certificate was issued by the trusted CA.

  @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
                                    where the first certificate is signed by the Root
                                    Certificate or is the Root Cerificate itself. and
                                    subsequent cerificate is signed by the preceding
                                    cerificate.
  @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.

  @param[in]      root_cert          Trusted Root Certificate buffer

  @param[in]      root_cert_length    Trusted Root Certificate buffer length

  @retval  TRUE   All cerificates was issued by the first certificate in X509Certchain.
  @retval  FALSE  Invalid certificate or the certificate was not issued by the given
                  trusted CA.
**/
boolean x509_verify_cert_chain(IN uint8 *root_cert, IN uintn root_cert_length,
			       IN uint8 *cert_chain,
			       IN uintn cert_chain_length);

/**
  Get one X509 certificate from cert_chain.

  @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
                                    where the first certificate is signed by the Root
                                    Certificate or is the Root Cerificate itself. and
                                    subsequent cerificate is signed by the preceding
                                    cerificate.
  @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.

  @param[in]      cert_index         index of certificate. If index is -1 indecate the
                                    last certificate in cert_chain.

  @param[out]     cert              The certificate at the index of cert_chain.
  @param[out]     cert_length        The length certificate at the index of cert_chain.

  @retval  TRUE   Success.
  @retval  FALSE  Failed to get certificate from certificate chain.
**/
boolean x509_get_cert_from_cert_chain(IN uint8 *cert_chain,
				      IN uintn cert_chain_length,
				      IN int32 cert_index, OUT uint8 **cert,
				      OUT uintn *cert_length);

/**
  Construct a X509 object from DER-encoded certificate data.

  If cert is NULL, then return FALSE.
  If single_x509_cert is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]  cert            Pointer to the DER-encoded certificate data.
  @param[in]  cert_size        The size of certificate data in bytes.
  @param[out] single_x509_cert  The generated X509 object.

  @retval     TRUE            The X509 object generation succeeded.
  @retval     FALSE           The operation failed.
  @retval     FALSE           This interface is not supported.

**/
boolean x509_construct_certificate(IN const uint8 *cert, IN uintn cert_size,
				   OUT uint8 **single_x509_cert);

/**
  Construct a X509 stack object from a list of DER-encoded certificate data.

  If x509_stack is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
                              On output, pointer to the X509 stack object with new
                              inserted X509 certificate.
  @param           ...        A list of DER-encoded single certificate data followed
                              by certificate size. A NULL terminates the list. The
                              pairs are the arguments to x509_construct_certificate().

  @retval     TRUE            The X509 stack construction succeeded.
  @retval     FALSE           The construction operation failed.
  @retval     FALSE           This interface is not supported.

**/
boolean x509_construct_certificate_stack(IN OUT uint8 **x509_stack, ...);

/**
  Release the specified X509 object.

  If the interface is not supported, then ASSERT().

  @param[in]  x509_cert  Pointer to the X509 object to be released.

**/
void x509_free(IN void *x509_cert);

/**
  Release the specified X509 stack object.

  If the interface is not supported, then ASSERT().

  @param[in]  x509_stack  Pointer to the X509 stack object to be released.

**/
void x509_stack_free(IN void *x509_stack);

/**
  Retrieve the TBSCertificate from one given X.509 certificate.

  @param[in]      cert         Pointer to the given DER-encoded X509 certificate.
  @param[in]      cert_size     size of the X509 certificate in bytes.
  @param[out]     tbs_cert      DER-Encoded to-Be-Signed certificate.
  @param[out]     tbs_cert_size  size of the TBS certificate in bytes.

  If cert is NULL, then return FALSE.
  If tbs_cert is NULL, then return FALSE.
  If tbs_cert_size is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @retval  TRUE   The TBSCertificate was retrieved successfully.
  @retval  FALSE  Invalid X.509 certificate.

**/
boolean x509_get_tbs_cert(IN const uint8 *cert, IN uintn cert_size,
			  OUT uint8 **tbs_cert, OUT uintn *tbs_cert_size);

//=====================================================================================
//    DH key Exchange Primitive
//=====================================================================================

/**
  Allocates and Initializes one Diffie-Hellman context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Diffie-Hellman context that has been initialized.
           If the allocations fails, dh_new_by_nid() returns NULL.
           If the interface is not supported, dh_new_by_nid() returns NULL.

**/
void *dh_new_by_nid(IN uintn nid);

/**
  Release the specified DH context.

  If the interface is not supported, then ASSERT().

  @param[in]  dh_context  Pointer to the DH context to be released.

**/
void dh_free(IN void *dh_context);

/**
  Generates DH parameter.

  Given generator g, and length of prime number p in bits, this function generates p,
  and sets DH context according to value of g and p.

  Before this function can be invoked, pseudorandom number generator must be correctly
  initialized by random_seed().

  If dh_context is NULL, then return FALSE.
  If prime is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  dh_context    Pointer to the DH context.
  @param[in]       generator    value of generator.
  @param[in]       prime_length  length in bits of prime to be generated.
  @param[out]      prime        Pointer to the buffer to receive the generated prime number.

  @retval TRUE   DH parameter generation succeeded.
  @retval FALSE  value of generator is not supported.
  @retval FALSE  PRNG fails to generate random prime number with prime_length.
  @retval FALSE  This interface is not supported.

**/
boolean dh_generate_parameter(IN OUT void *dh_context, IN uintn generator,
			      IN uintn prime_length, OUT uint8 *prime);

/**
  Sets generator and prime parameters for DH.

  Given generator g, and prime number p, this function and sets DH
  context accordingly.

  If dh_context is NULL, then return FALSE.
  If prime is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  dh_context    Pointer to the DH context.
  @param[in]       generator    value of generator.
  @param[in]       prime_length  length in bits of prime to be generated.
  @param[in]       prime        Pointer to the prime number.

  @retval TRUE   DH parameter setting succeeded.
  @retval FALSE  value of generator is not supported.
  @retval FALSE  value of generator is not suitable for the prime.
  @retval FALSE  value of prime is not a prime number.
  @retval FALSE  value of prime is not a safe prime number.
  @retval FALSE  This interface is not supported.

**/
boolean dh_set_parameter(IN OUT void *dh_context, IN uintn generator,
			 IN uintn prime_length, IN const uint8 *prime);

/**
  Generates DH public key.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  If dh_context is NULL, then return FALSE.
  If public_key_size is NULL, then return FALSE.
  If public_key_size is large enough but public_key is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  For FFDHE2048, the public_size is 256.
  For FFDHE3072, the public_size is 384.
  For FFDHE4096, the public_size is 512.

  @param[in, out]  dh_context      Pointer to the DH context.
  @param[out]      public_key      Pointer to the buffer to receive generated public key.
  @param[in, out]  public_key_size  On input, the size of public_key buffer in bytes.
                                 On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DH public key generation succeeded.
  @retval FALSE  DH public key generation failed.
  @retval FALSE  public_key_size is not large enough.
  @retval FALSE  This interface is not supported.

**/
boolean dh_generate_key(IN OUT void *dh_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size);

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  If dh_context is NULL, then return FALSE.
  If peer_public_key is NULL, then return FALSE.
  If key_size is NULL, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.
  If this interface is not supported, then return FALSE.

  For FFDHE2048, the peer_public_size and key_size is 256.
  For FFDHE3072, the peer_public_size and key_size is 384.
  For FFDHE4096, the peer_public_size and key_size is 512.

  @param[in, out]  dh_context          Pointer to the DH context.
  @param[in]       peer_public_key      Pointer to the peer's public key.
  @param[in]       peer_public_key_size  size of peer's public key in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                     On output, the size of data returned in key buffer in bytes.

  @retval TRUE   DH exchanged key generation succeeded.
  @retval FALSE  DH exchanged key generation failed.
  @retval FALSE  key_size is not large enough.
  @retval FALSE  This interface is not supported.

**/
boolean dh_compute_key(IN OUT void *dh_context, IN const uint8 *peer_public_key,
		       IN uintn peer_public_key_size, OUT uint8 *key,
		       IN OUT uintn *key_size);

//=====================================================================================
//    Elliptic Curve Primitive
//=====================================================================================

/**
  Allocates and Initializes one Elliptic Curve context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Elliptic Curve context that has been initialized.
           If the allocations fails, ec_new_by_nid() returns NULL.

**/
void *ec_new_by_nid(IN uintn nid);

/**
  Release the specified EC context.

  @param[in]  ec_context  Pointer to the EC context to be released.

**/
void ec_free(IN void *ec_context);

/**
  Sets the public key component into the established EC context.

  For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
  For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
  For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.

  @param[in, out]  ec_context      Pointer to EC context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   EC public key component was set successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ec_set_pub_key(IN OUT void *ec_context, IN uint8 *public_key,
		       IN uintn public_key_size);

/**
  Gets the public key component from the established EC context.

  For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
  For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
  For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.

  @param[in, out]  ec_context      Pointer to EC context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   EC key component was retrieved successfully.
  @retval  FALSE  Invalid EC key component.

**/
boolean ec_get_pub_key(IN OUT void *ec_context, OUT uint8 *public_key,
		       IN OUT uintn *public_key_size);

/**
  Validates key components of EC context.
  NOTE: This function performs integrity checks on all the EC key material, so
        the EC key structure must contain all the private key data.

  If ec_context is NULL, then return FALSE.

  @param[in]  ec_context  Pointer to EC context to check.

  @retval  TRUE   EC key components are valid.
  @retval  FALSE  EC key components are not valid.

**/
boolean ec_check_key(IN void *ec_context);

/**
  Generates EC key and returns EC public key (X, Y).

  This function generates random secret, and computes the public key (X, Y), which is
  returned via parameter public, public_size.
  X is the first half of public with size being public_size / 2,
  Y is the second half of public with size being public_size / 2.
  EC context is updated accordingly.
  If the public buffer is too small to hold the public X, Y, FALSE is returned and
  public_size is set to the required buffer size to obtain the public X, Y.

  For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
  For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
  For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.

  If ec_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  ec_context      Pointer to the EC context.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   EC public X,Y generation succeeded.
  @retval FALSE  EC public X,Y generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean ec_generate_key(IN OUT void *ec_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size);

/**
  Computes exchanged common key.

  Given peer's public key (X, Y), this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.
  X is the first half of peer_public with size being peer_public_size / 2,
  Y is the second half of peer_public with size being peer_public_size / 2.

  If ec_context is NULL, then return FALSE.
  If peer_public is NULL, then return FALSE.
  If peer_public_size is 0, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.

  For P-256, the peer_public_size is 64. first 32-byte is X, second 32-byte is Y. The key_size is 32.
  For P-384, the peer_public_size is 96. first 48-byte is X, second 48-byte is Y. The key_size is 48.
  For P-521, the peer_public_size is 132. first 66-byte is X, second 66-byte is Y. The key_size is 66.

  @param[in, out]  ec_context          Pointer to the EC context.
  @param[in]       peer_public         Pointer to the peer's public X,Y.
  @param[in]       peer_public_size     size of peer's public X,Y in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                      On output, the size of data returned in key buffer in bytes.

  @retval TRUE   EC exchanged key generation succeeded.
  @retval FALSE  EC exchanged key generation failed.
  @retval FALSE  key_size is not large enough.

**/
boolean ec_compute_key(IN OUT void *ec_context, IN const uint8 *peer_public,
		       IN uintn peer_public_size, OUT uint8 *key,
		       IN OUT uintn *key_size);

/**
  Carries out the EC-DSA signature.

  This function carries out the EC-DSA signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If ec_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
  If sig_size is large enough but signature is NULL, then return FALSE.

  For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
  For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.

  @param[in]       ec_context    Pointer to EC context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message_hash  Pointer to octet message hash to be signed.
  @param[in]       hash_size     size of the message hash in bytes.
  @param[out]      signature    Pointer to buffer to receive EC-DSA signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in EC-DSA.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean ecdsa_sign(IN void *ec_context, IN uintn hash_nid,
		   IN const uint8 *message_hash, IN uintn hash_size,
		   OUT uint8 *signature, IN OUT uintn *sig_size);

/**
  Verifies the EC-DSA signature.

  If ec_context is NULL, then return FALSE.
  If message_hash is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.

  For P-256, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For P-384, the sig_size is 96. first 48-byte is R, second 48-byte is S.
  For P-521, the sig_size is 132. first 66-byte is R, second 66-byte is S.

  @param[in]  ec_context    Pointer to EC context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message_hash  Pointer to octet message hash to be checked.
  @param[in]  hash_size     size of the message hash in bytes.
  @param[in]  signature    Pointer to EC-DSA signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in EC-DSA.
  @retval  FALSE  Invalid signature or invalid EC context.

**/
boolean ecdsa_verify(IN void *ec_context, IN uintn hash_nid,
		     IN const uint8 *message_hash, IN uintn hash_size,
		     IN const uint8 *signature, IN uintn sig_size);

//=====================================================================================
//    Edwards-Curve Primitive
//=====================================================================================

/**
  Allocates and Initializes one Edwards-Curve context for subsequent use
  with the NID.

  The key is generated before the function returns.

  @param nid cipher NID

  @return  Pointer to the Edwards-Curve context that has been initialized.
           If the allocations fails, ecd_new_by_nid() returns NULL.

**/
void *ecd_new_by_nid(IN uintn nid);

/**
  Release the specified Ed context.

  @param[in]  ecd_context  Pointer to the Ed context to be released.

**/
void ecd_free(IN void *ecd_context);

/**
  Sets the public key component into the established Ed context.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  @param[in, out]  ecd_context      Pointer to Ed context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   Ed public key component was set successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ecd_set_pub_key(IN OUT void *ecd_context, IN uint8 *public_key,
			IN uintn public_key_size);

/**
  Gets the public key component from the established Ed context.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  @param[in, out]  ecd_context      Pointer to Ed context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   Ed key component was retrieved successfully.
  @retval  FALSE  Invalid EC public key component.

**/
boolean ecd_get_pub_key(IN OUT void *ecd_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size);

/**
  Validates key components of Ed context.
  NOTE: This function performs integrity checks on all the Ed key material, so
        the Ed key structure must contain all the private key data.

  If ecd_context is NULL, then return FALSE.

  @param[in]  ecd_context  Pointer to Ed context to check.

  @retval  TRUE   Ed key components are valid.
  @retval  FALSE  Ed key components are not valid.

**/
boolean ecd_check_key(IN void *ecd_context);

/**
  Generates Ed key and returns Ed public key.

  For ed25519, the public_size is 32.
  For ed448, the public_size is 57.

  If ecd_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  ecd_context      Pointer to the Ed context.
  @param[out]      public         Pointer to the buffer to receive generated public key.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   Ed public key generation succeeded.
  @retval FALSE  Ed public key generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean ecd_generate_key(IN OUT void *ecd_context, OUT uint8 *public_key,
			 IN OUT uintn *public_key_size);

/**
  Carries out the Ed-DSA signature.

  This function carries out the Ed-DSA signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If ecd_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  hash_nid must be NULL.
  If sig_size is large enough but signature is NULL, then return FALSE.

  For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.

  @param[in]       ecd_context    Pointer to Ed context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message      Pointer to octet message to be signed (before hash).
  @param[in]       size         size of the message in bytes.
  @param[out]      signature    Pointer to buffer to receive Ed-DSA signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in Ed-DSA.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean eddsa_sign(IN void *ecd_context, IN uintn hash_nid,
		   IN const uint8 *message, IN uintn size, OUT uint8 *signature,
		   IN OUT uintn *sig_size);

/**
  Verifies the Ed-DSA signature.

  If ecd_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  hash_nid must be NULL.

  For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
  For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.

  @param[in]  ecd_context    Pointer to Ed context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message      Pointer to octet message to be checked (before hash).
  @param[in]  size         size of the message in bytes.
  @param[in]  signature    Pointer to Ed-DSA signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in Ed-DSA.
  @retval  FALSE  Invalid signature or invalid Ed context.

**/
boolean eddsa_verify(IN void *ecd_context, IN uintn hash_nid,
		     IN const uint8 *message, IN uintn size,
		     IN const uint8 *signature, IN uintn sig_size);

//=====================================================================================
//    Montgomery-Curve Primitive
//=====================================================================================

/**
  Allocates and Initializes one Montgomery-Curve Context for subsequent use
  with the NID.

  @param nid cipher NID

  @return  Pointer to the Montgomery-Curve Context that has been initialized.
           If the allocations fails, ecx_new_by_nid() returns NULL.

**/
void *ecx_new_by_nid(IN uintn nid);

/**
  Release the specified Ecx context.

  @param[in]  ecx_context  Pointer to the Ecx context to be released.

**/
void ecx_free(IN void *ecx_context);

/**
  Generates Ecx key and returns Ecx public key.

  This function generates random secret, and computes the public key, which is
  returned via parameter public, public_size.
  Ecx context is updated accordingly.
  If the public buffer is too small to hold the public key, FALSE is returned and
  public_size is set to the required buffer size to obtain the public key.

  For X25519, the public_size is 32.
  For X448, the public_size is 56.

  If ecx_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  ecx_context      Pointer to the Ecx context.
  @param[out]      public         Pointer to the buffer to receive generated public key.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   Ecx public key generation succeeded.
  @retval FALSE  Ecx public key generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean ecx_generate_key(IN OUT void *ecx_context, OUT uint8 *public,
			 IN OUT uintn *public_size);

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.

  If ecx_context is NULL, then return FALSE.
  If peer_public is NULL, then return FALSE.
  If peer_public_size is 0, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.

  For X25519, the public_size is 32.
  For X448, the public_size is 56.

  @param[in, out]  ecx_context          Pointer to the Ecx context.
  @param[in]       peer_public         Pointer to the peer's public key.
  @param[in]       peer_public_size     Size of peer's public key in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                      On output, the size of data returned in key buffer in bytes.

  @retval TRUE   Ecx exchanged key generation succeeded.
  @retval FALSE  Ecx exchanged key generation failed.
  @retval FALSE  key_size is not large enough.

**/
boolean ecx_compute_key(IN OUT void *ecx_context, IN const uint8 *peer_public,
			IN uintn peer_public_size, OUT uint8 *key,
			IN OUT uintn *key_size);

//=====================================================================================
//    Shang-Mi2 Primitive
//=====================================================================================

/**
  Allocates and Initializes one Shang-Mi2 context for subsequent use.

  The key is generated before the function returns.

  @return  Pointer to the Shang-Mi2 context that has been initialized.
           If the allocations fails, sm2_new() returns NULL.

**/
void *sm2_new(void);

/**
  Release the specified sm2 context.

  @param[in]  sm2_context  Pointer to the sm2 context to be released.

**/
void sm2_free(IN void *sm2_context);

/**
  Sets the public key component into the established sm2 context.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  @param[in, out]  ec_context      Pointer to sm2 context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   sm2 public key component was set successfully.
  @retval  FALSE  Invalid sm2 public key component.

**/
boolean sm2_set_pub_key(IN OUT void *sm2_context, IN uint8 *public_key,
			IN uintn public_key_size);

/**
  Gets the public key component from the established sm2 context.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  @param[in, out]  sm2_context     Pointer to sm2 context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   sm2 key component was retrieved successfully.
  @retval  FALSE  Invalid sm2 key component.

**/
boolean sm2_get_pub_key(IN OUT void *sm2_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size);

/**
  Validates key components of sm2 context.
  NOTE: This function performs integrity checks on all the sm2 key material, so
        the sm2 key structure must contain all the private key data.

  If sm2_context is NULL, then return FALSE.

  @param[in]  sm2_context  Pointer to sm2 context to check.

  @retval  TRUE   sm2 key components are valid.
  @retval  FALSE  sm2 key components are not valid.

**/
boolean sm2_check_key(IN void *sm2_context);

/**
  Generates sm2 key and returns sm2 public key (X, Y).

  This function generates random secret, and computes the public key (X, Y), which is
  returned via parameter public, public_size.
  X is the first half of public with size being public_size / 2,
  Y is the second half of public with size being public_size / 2.
  sm2 context is updated accordingly.
  If the public buffer is too small to hold the public X, Y, FALSE is returned and
  public_size is set to the required buffer size to obtain the public X, Y.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  If sm2_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  sm2_context     Pointer to the sm2 context.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   sm2 public X,Y generation succeeded.
  @retval FALSE  sm2 public X,Y generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean sm2_generate_key(IN OUT void *sm2_context, OUT uint8 *public,
			 IN OUT uintn *public_size);

/**
  Computes exchanged common key.

  Given peer's public key (X, Y), this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.
  X is the first half of peer_public with size being peer_public_size / 2,
  Y is the second half of peer_public with size being peer_public_size / 2.

  If sm2_context is NULL, then return FALSE.
  If peer_public is NULL, then return FALSE.
  If peer_public_size is 0, then return FALSE.
  If key is NULL, then return FALSE.
  If key_size is not large enough, then return FALSE.

  The peer_public_size is 64. first 32-byte is X, second 32-byte is Y. The key_size is 32.

  @param[in, out]  sm2_context         Pointer to the sm2 context.
  @param[in]       peer_public         Pointer to the peer's public X,Y.
  @param[in]       peer_public_size     size of peer's public X,Y in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in, out]  key_size            On input, the size of key buffer in bytes.
                                      On output, the size of data returned in key buffer in bytes.

  @retval TRUE   sm2 exchanged key generation succeeded.
  @retval FALSE  sm2 exchanged key generation failed.
  @retval FALSE  key_size is not large enough.

**/
boolean sm2_compute_key(IN OUT void *sm2_context, IN const uint8 *peer_public,
			IN uintn peer_public_size, OUT uint8 *key,
			IN OUT uintn *key_size);

/**
  Carries out the SM2 signature.

  This function carries out the SM2 signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If sm2_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  hash_nid must be SM3_256.
  If sig_size is large enough but signature is NULL, then return FALSE.

  The sig_size is 64. first 32-byte is R, second 32-byte is S.

  @param[in]       sm2_context   Pointer to sm2 context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message      Pointer to octet message to be signed (before hash).
  @param[in]       size         size of the message in bytes.
  @param[out]      signature    Pointer to buffer to receive SM2 signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in SM2.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean sm2_ecdsa_sign(IN void *sm2_context, IN uintn hash_nid,
		       IN const uint8 *message, IN uintn size,
		       OUT uint8 *signature, IN OUT uintn *sig_size);

/**
  Verifies the SM2 signature.

  If sm2_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  hash_nid must be SM3_256.

  The sig_size is 64. first 32-byte is R, second 32-byte is S.

  @param[in]  sm2_context   Pointer to SM2 context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message      Pointer to octet message to be checked (before hash).
  @param[in]  size         size of the message in bytes.
  @param[in]  signature    Pointer to SM2 signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in SM2.
  @retval  FALSE  Invalid signature or invalid sm2 context.

**/
boolean sm2_ecdsa_verify(IN void *sm2_context, IN uintn hash_nid,
			 IN const uint8 *message, IN uintn size,
			 IN const uint8 *signature, IN uintn sig_size);

//=====================================================================================
//    Pseudo-Random Generation Primitive
//=====================================================================================

/**
  Sets up the seed value for the pseudorandom number generator.

  This function sets up the seed value for the pseudorandom number generator.
  If seed is not NULL, then the seed passed in is used.
  If seed is NULL, then default seed is used.
  If this interface is not supported, then return FALSE.

  @param[in]  seed      Pointer to seed value.
                        If NULL, default seed is used.
  @param[in]  seed_size  size of seed value.
                        If seed is NULL, this parameter is ignored.

  @retval TRUE   Pseudorandom number generator has enough entropy for random generation.
  @retval FALSE  Pseudorandom number generator does not have enough entropy for random generation.
  @retval FALSE  This interface is not supported.

**/
boolean random_seed(IN const uint8 *seed OPTIONAL, IN uintn seed_size);

/**
  Generates a pseudorandom byte stream of the specified size.

  If output is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[out]  output  Pointer to buffer to receive random value.
  @param[in]   size    size of random bytes to generate.

  @retval TRUE   Pseudorandom byte stream generated successfully.
  @retval FALSE  Pseudorandom number generator fails to generate due to lack of entropy.
  @retval FALSE  This interface is not supported.

**/
boolean random_bytes(OUT uint8 *output, IN uintn size);

//=====================================================================================
//    key Derivation Function Primitive
//=====================================================================================

/**
  Derive key data using HMAC-SHA256 based KDF.

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha256_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size);

/**
  Derive SHA256 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha256_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size);

/**
  Derive SHA256 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha256_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size);

/**
  Derive key data using HMAC-SHA384 based KDF.

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha384_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size);

/**
  Derive SHA384 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha384_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size);

/**
  Derive SHA384 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha384_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size);

/**
  Derive key data using HMAC-SHA512 based KDF.

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha512_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size);

/**
  Derive SHA512 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha512_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size);

/**
  Derive SHA512 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sha512_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size);

#endif // __BASE_CRYPT_LIB_H__
