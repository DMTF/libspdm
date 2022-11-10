/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_crypt_lib.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "hal/library/cryptlib.h"

/*max public key encryption algo oid len*/
#ifndef LIBSPDM_MAX_ENCRYPTION_ALGO_OID_LEN
#define LIBSPDM_MAX_ENCRYPTION_ALGO_OID_LEN 10
#endif

/*leaf cert basic constraints len,CA = false: 30 03 01 01 00*/
#ifndef BASIC_CONSTRAINTS_CA_LEN
#define BASIC_CONSTRAINTS_CA_LEN 5
#endif

/**pathLenConstraint is optional.
 * In https://www.pkisolutions.com/basic-constraints-certificate-extension/:
 * pathLenConstraint: How many CAs are allowed in the chain below current CA certificate.
 * This setting has no meaning for end entity certificates.
 **/

/**
 * leaf cert spdm extension len
 * len > 2 * (spdm id-DMTF-spdm size + 2)
 **/

#ifndef SPDM_EXTENDSION_LEN
#define SPDM_EXTENDSION_LEN 30
#endif

/**
 * 0x02 is integer;
 * 0x82 indicates that the length is expressed in two bytes;
 * 0x01 and 0x01 are rsa key len;
 **/
#define KEY_ENCRY_ALGO_RSA2048_FLAG {0x02, 0x82, 0x01, 0x01}
#define KEY_ENCRY_ALGO_RSA3072_FLAG {0x02, 0x82, 0x01, 0x81}
#define KEY_ENCRY_ALGO_RSA4096_FLAG {0x02, 0x82, 0x02, 0x01}

/* the other case is ASN1 code different when integer is 1 on highest position*/
#define KEY_ENCRY_ALGO_RSA2048_FLAG_OTHER {0x02, 0x82, 0x01, 0x00}
#define KEY_ENCRY_ALGO_RSA3072_FLAG_OTHER {0x02, 0x82, 0x01, 0x80}
#define KEY_ENCRY_ALGO_RSA4096_FLAG_OTHER {0x02, 0x82, 0x02, 0x00}

/**
 * http://oid-info.com/get/1.2.840.10045.3.1.7
 * ECC256 curve OID: 1.2.840.10045.3.1.7
 * http://oid-info.com/get/1.3.132.0.34
 * ECC384 curve OID: 1.3.132.0.34
 * http://oid-info.com/get/1.3.132.0.35
 * ECC521 curve OID: 1.3.132.0.35
 **/
#define KEY_ENCRY_ALGO_ECC256_OID {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
#define KEY_ENCRY_ALGO_ECC384_OID {0x2B, 0x81, 0x04, 0x00, 0x22}
#define KEY_ENCRY_ALGO_ECC521_OID {0x2B, 0x81, 0x04, 0x00, 0x23}

/**
 * EDxxx OID: https://datatracker.ietf.org/doc/html/rfc8420
 * ED448 OID: 1.3.101.113
 * ED25519 OID: 1.3.101.112
 **/
#define ENCRY_ALGO_ED25519_OID {0x2B, 0x65, 0x70}
#define ENCRY_ALGO_ED448_OID {0x2B, 0x65, 0x71}

/**
 * This function returns the SPDM hash algorithm size.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return SPDM hash algorithm size.
 **/
uint32_t libspdm_get_hash_size(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
        return 32;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
        return 48;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
        return 64;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
        return 32;
    default:
        return 0;
    }
}

/**
 * Return cipher ID, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash cipher ID
 **/
size_t libspdm_get_hash_nid(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
        return LIBSPDM_CRYPTO_NID_SHA256;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
        return LIBSPDM_CRYPTO_NID_SHA384;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
        return LIBSPDM_CRYPTO_NID_SHA512;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
        return LIBSPDM_CRYPTO_NID_SHA3_256;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
        return LIBSPDM_CRYPTO_NID_SHA3_384;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
        return LIBSPDM_CRYPTO_NID_SHA3_512;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
        return LIBSPDM_CRYPTO_NID_SM3_256;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

/**
 * Return asym NID, based upon the negotiated asym algorithm.
 *
 * @param  base_asym_algo                  SPDM base_asym_algo
 *
 * @return asym NID
 **/
size_t libspdm_get_aysm_nid(uint32_t base_asym_algo)
{
    switch (base_asym_algo)
    {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
        return LIBSPDM_CRYPTO_NID_RSASSA2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
        return LIBSPDM_CRYPTO_NID_RSASSA3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
        return LIBSPDM_CRYPTO_NID_RSASSA4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return LIBSPDM_CRYPTO_NID_RSAPSS2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return LIBSPDM_CRYPTO_NID_RSAPSS3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return LIBSPDM_CRYPTO_NID_RSAPSS4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        return LIBSPDM_CRYPTO_NID_EDDSA_ED25519;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        return LIBSPDM_CRYPTO_NID_EDDSA_ED448;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return LIBSPDM_CRYPTO_NID_SM2_DSA_P256;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

/**
 * Return hash new function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash new function
 **/
libspdm_hash_new_func libspdm_get_hash_new_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash free function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash free function
 **/
libspdm_hash_free_func libspdm_get_hash_free_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash init function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash init function
 **/
libspdm_hash_init_func libspdm_get_hash_init_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}


/**
 * Return hash duplicate function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash duplicate function
 **/
libspdm_hash_duplicate_func libspdm_get_hash_duplicate_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash update function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash update function
 **/
libspdm_hash_update_func libspdm_get_hash_update_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}
/**
 * Return hash final function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash final function
 **/
libspdm_hash_final_func libspdm_get_hash_final_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash function
 **/
libspdm_hash_all_func libspdm_get_hash_all_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent hash use.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_hash_new() returns NULL.
 **/
void *libspdm_hash_new(uint32_t base_hash_algo)
{
    libspdm_hash_new_func hash_function;
    hash_function = libspdm_get_hash_new_func(base_hash_algo);
    if (hash_function == NULL) {
        return NULL;
    }
    return hash_function();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  hash_context                   Pointer to the HASH_CTX context to be released.
 **/
void libspdm_hash_free(uint32_t base_hash_algo, void *hash_context)
{
    libspdm_hash_free_func hash_function;
    hash_function = libspdm_get_hash_free_func(base_hash_algo);
    if (hash_function == NULL) {
        return;
    }
    hash_function(hash_context);
}

/**
 * Initializes user-supplied memory pointed by hash_context as hash context for
 * subsequent use.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  hash_context                   Pointer to hash context being initialized.
 *
 * @retval true   Hash context initialization succeeded.
 * @retval false  Hash context initialization failed.
 **/
bool libspdm_hash_init(uint32_t base_hash_algo, void *hash_context)
{
    libspdm_hash_init_func hash_function;
    hash_function = libspdm_get_hash_init_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_context);
}

/**
 * Makes a copy of an existing hash context.
 *
 * If hash_ctx is NULL, then return false.
 * If new_hash_ctx is NULL, then return false.
 *
 * @param[in]  hash_ctx     Pointer to hash context being copied.
 * @param[out] new_hash_ctx  Pointer to new hash context.
 *
 * @retval true   hash context copy succeeded.
 * @retval false  hash context copy failed.
 *
 **/
bool libspdm_hash_duplicate(uint32_t base_hash_algo, const void *hash_ctx, void *new_hash_ctx)
{
    libspdm_hash_duplicate_func hash_function;
    hash_function = libspdm_get_hash_duplicate_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_ctx, new_hash_ctx);
}

/**
 * Digests the input data and updates hash context.
 *
 * This function performs hash digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * Hash context should be already correctly initialized by hash_init(), and should not be finalized
 * by hash_final(). Behavior with invalid context is undefined.
 *
 * If hash_context is NULL, then return false.
 *
 * @param[in, out]  hash_context   Pointer to the MD context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size      Size of data buffer in bytes.
 *
 * @retval true   hash data digest succeeded.
 * @retval false  hash data digest failed.
 **/
bool libspdm_hash_update(uint32_t base_hash_algo, void *hash_context,
                         const void *data, size_t data_size)
{
    libspdm_hash_update_func hash_function;
    hash_function = libspdm_get_hash_update_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_context, data, data_size);
}

/**
 * Completes computation of the hash digest value.
 *
 * This function completes hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the hash context cannot
 * be used again.
 * hash context should be already correctly initialized by hash_init(), and should not be
 * finalized by hash_final(). Behavior with invalid hash context is undefined.
 *
 * If hash_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  hash_context    Pointer to the hash context.
 * @param[out]      hash_value      Pointer to a buffer that receives the hash digest value.
 *
 * @retval true   hash digest computation succeeded.
 * @retval false  hash digest computation failed.
 **/
bool libspdm_hash_final(uint32_t base_hash_algo, void *hash_context,
                        uint8_t *hash_value)
{
    libspdm_hash_final_func hash_function;
    hash_function = libspdm_get_hash_final_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_context, hash_value);
}

/**
 * Computes the hash of a input data buffer, based upon the negotiated hash algorithm.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  data                         Pointer to the buffer containing the data to be hashed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
bool libspdm_hash_all(uint32_t base_hash_algo, const void *data,
                      size_t data_size, uint8_t *hash_value)
{
    libspdm_hash_all_func hash_function;
    hash_function = libspdm_get_hash_all_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(data, data_size, hash_value);
}

/**
 * This function returns the SPDM measurement hash algorithm size.
 *
 * @param  measurement_hash_algo          SPDM measurement_hash_algo
 *
 * @return SPDM measurement hash algorithm size.
 * @return 0xFFFFFFFF for RAW_BIT_STREAM_ONLY.
 **/
uint32_t libspdm_get_measurement_hash_size(uint32_t measurement_hash_algo)
{
    switch (measurement_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        return 32;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        return 48;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        return 64;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        return 32;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY:
        return 0xFFFFFFFF;
    default:
        return 0;
    }
}

/**
 * Return hash function, based upon the negotiated measurement hash algorithm.
 *
 * @param  measurement_hash_algo          SPDM measurement_hash_algo
 *
 * @return hash function
 **/
libspdm_hash_all_func libspdm_spdm_measurement_hash_func(uint32_t measurement_hash_algo)
{
    switch (measurement_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_sha256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_sha384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_sha512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_sha3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_sha3_384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_sha3_512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_sm3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  measurement_hash_algo          SPDM measurement_hash_algo
 * @param  data                         Pointer to the buffer containing the data to be hashed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
bool libspdm_measurement_hash_all(uint32_t measurement_hash_algo,
                                  const void *data, size_t data_size,
                                  uint8_t *hash_value)
{
    libspdm_hash_all_func hash_function;
    hash_function = libspdm_spdm_measurement_hash_func(measurement_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(data, data_size, hash_value);
}

/**
 * Return HMAC new function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC new function
 **/
libspdm_hmac_new_func libspdm_get_hmac_new_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hmac_sha256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hmac_sha384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hmac_sha512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hmac_sha3_256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hmac_sha3_384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hmac_sha3_512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hmac_sm3_256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return HMAC free function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC free function
 **/
libspdm_hmac_free_func libspdm_get_hmac_free_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hmac_sha256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hmac_sha384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hmac_sha512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hmac_sha3_256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hmac_sha3_384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hmac_sha3_512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hmac_sm3_256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return HMAC init function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC init function
 **/
libspdm_hmac_set_key_func libspdm_get_hmac_init_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hmac_sha256_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hmac_sha384_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hmac_sha512_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hmac_sha3_256_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hmac_sha3_384_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hmac_sha3_512_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hmac_sm3_256_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return HMAC duplicate function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC duplicate function
 **/
libspdm_hmac_duplicate_func libspdm_get_hmac_duplicate_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hmac_sha256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hmac_sha384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hmac_sha512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hmac_sha3_256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hmac_sha3_384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hmac_sha3_512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hmac_sm3_256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return HMAC update function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC update function
 **/
libspdm_hmac_update_func libspdm_get_hmac_update_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hmac_sha256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hmac_sha384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hmac_sha512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hmac_sha3_256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hmac_sha3_384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hmac_sha3_512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hmac_sm3_256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}
/**
 * Return HMAC final function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC final function
 **/
libspdm_hmac_final_func libspdm_get_hmac_final_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hmac_sha256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hmac_sha384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hmac_sha512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hmac_sha3_256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hmac_sha3_384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hmac_sha3_512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hmac_sm3_256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return HMAC all function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return HMAC function
 **/
libspdm_hmac_all_func libspdm_get_hmac_all_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hmac_sha256_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hmac_sha384_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hmac_sha512_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hmac_sha3_256_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hmac_sha3_384_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hmac_sha3_512_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hmac_sm3_256_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Allocates and initializes one HMAC context for subsequent use.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return  Pointer to the HMAC context that has been initialized.
 *         If the allocations fails, libspdm_hash_new() returns NULL.
 **/
void *libspdm_hmac_new(uint32_t base_hash_algo)
{
    libspdm_hmac_new_func hmac_function;
    hmac_function = libspdm_get_hmac_new_func(base_hash_algo);
    if (hmac_function == NULL) {
        return NULL;
    }
    return hmac_function();
}

/**
 * Release the specified HMAC context.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  hmac_ctx                   Pointer to the HMAC context to be released.
 **/
void libspdm_hmac_free(uint32_t base_hash_algo, void *hmac_ctx)
{
    libspdm_hmac_free_func hmac_function;
    hmac_function = libspdm_get_hmac_free_func(base_hash_algo);
    if (hmac_function == NULL) {
        return;
    }
    hmac_function(hmac_ctx);
}

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to hmac_update().
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[out]  hmac_ctx  Pointer to HMAC context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 *
 **/
bool libspdm_hmac_init(uint32_t base_hash_algo,
                       void *hmac_ctx, const uint8_t *key,
                       size_t key_size)
{
    libspdm_hmac_set_key_func hmac_function;
    hmac_function = libspdm_get_hmac_init_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, key, key_size);
}

/**
 * Makes a copy of an existing HMAC context.
 *
 * If hmac_ctx is NULL, then return false.
 * If new_hmac_ctx is NULL, then return false.
 *
 * @param[in]  hmac_ctx     Pointer to HMAC context being copied.
 * @param[out] new_hmac_ctx  Pointer to new HMAC context.
 *
 * @retval true   HMAC context copy succeeded.
 * @retval false  HMAC context copy failed.
 *
 **/
bool libspdm_hmac_duplicate(uint32_t base_hash_algo, const void *hmac_ctx, void *new_hmac_ctx)
{
    libspdm_hmac_duplicate_func hmac_function;
    hmac_function = libspdm_get_hmac_duplicate_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, new_hmac_ctx);
}

/**
 * Digests the input data and updates HMAC context.
 *
 * This function performs HMAC digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC context should be initialized by hmac_new(), and should not be finalized
 * by hmac_final(). Behavior with invalid context is undefined.
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx Pointer to the HMAC context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC data digest succeeded.
 * @retval false  HMAC data digest failed.
 *
 **/
bool libspdm_hmac_update(uint32_t base_hash_algo,
                         void *hmac_ctx, const void *data,
                         size_t data_size)
{
    libspdm_hmac_update_func hmac_function;
    hmac_function = libspdm_get_hmac_update_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, data, data_size);
}

/**
 * Completes computation of the HMAC digest value.
 *
 * This function completes HMAC hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC context cannot
 * be used again.
 *
 * If hmac_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx  Pointer to the HMAC context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC digest
 *                                    value.
 *
 * @retval true   HMAC digest computation succeeded.
 * @retval false  HMAC digest computation failed.
 *
 **/
bool libspdm_hmac_final(uint32_t base_hash_algo, void *hmac_ctx,  uint8_t *hmac_value)
{
    libspdm_hmac_final_func hmac_function;
    hmac_function = libspdm_get_hmac_final_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, hmac_value);
}

/**
 * Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.
 *
 * This function performs the HMAC of a given data buffer, and return the hash value.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  data                         Pointer to the buffer containing the data to be HMACed.
 * @param  data_size                     size of data buffer in bytes.
 * @param  key                          Pointer to the user-supplied key.
 * @param  key_size                      key size in bytes.
 * @param  hash_value                    Pointer to a buffer that receives the HMAC value.
 *
 * @retval true   HMAC computation succeeded.
 * @retval false  HMAC computation failed.
 **/
bool libspdm_hmac_all(uint32_t base_hash_algo, const void *data,
                      size_t data_size, const uint8_t *key,
                      size_t key_size, uint8_t *hmac_value)
{
    libspdm_hmac_all_func hmac_function;
    hmac_function = libspdm_get_hmac_all_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(data, data_size, key, key_size, hmac_value);
}

/**
 * Return HKDF extract function, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return HKDF extract function
 **/
libspdm_hkdf_extract_func get_spdm_hkdf_extract_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hkdf_sha256_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hkdf_sha384_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hkdf_sha512_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hkdf_sha3_256_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hkdf_sha3_384_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hkdf_sha3_512_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hkdf_sm3_256_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Derive HMAC-based Extract key Derivation Function (HKDF) Extract, based upon the negotiated HKDF algorithm.
 *
 * @param  ikm              Pointer to the input key material.
 * @param  ikm_size          key size in bytes.
 * @param  salt             Pointer to the salt value.
 * @param  salt_size         salt size in bytes.
 * @param  prk_out           Pointer to buffer to receive hkdf value.
 * @param  prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
bool libspdm_hkdf_extract(uint32_t base_hash_algo, const uint8_t *ikm, size_t ikm_size,
                          const uint8_t *salt, size_t salt_size,
                          uint8_t *prk_out, size_t prk_out_size)
{
    libspdm_hkdf_extract_func hkdf_extract_function;
    hkdf_extract_function = get_spdm_hkdf_extract_func(base_hash_algo);
    if (hkdf_extract_function == NULL) {
        return false;
    }
    return hkdf_extract_function(ikm, ikm_size, salt, salt_size, prk_out, prk_out_size);
}

/**
 * Return HKDF expand function, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return HKDF expand function
 **/
libspdm_hkdf_expand_func get_spdm_hkdf_expand_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT == 1
        return libspdm_hkdf_sha256_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT == 1
        return libspdm_hkdf_sha384_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT == 1
        return libspdm_hkdf_sha512_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT == 1
        return libspdm_hkdf_sha3_256_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT == 1
        return libspdm_hkdf_sha3_384_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT == 1
        return libspdm_hkdf_sha3_512_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT == 1
        return libspdm_hkdf_sm3_256_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  prk                          Pointer to the user-supplied key.
 * @param  prk_size                      key size in bytes.
 * @param  info                         Pointer to the application specific info.
 * @param  info_size                     info size in bytes.
 * @param  out                          Pointer to buffer to receive hkdf value.
 * @param  out_size                      size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
bool libspdm_hkdf_expand(uint32_t base_hash_algo, const uint8_t *prk,
                         size_t prk_size, const uint8_t *info,
                         size_t info_size, uint8_t *out, size_t out_size)
{
    libspdm_hkdf_expand_func hkdf_expand_function;
    hkdf_expand_function = get_spdm_hkdf_expand_func(base_hash_algo);
    if (hkdf_expand_function == NULL) {
        return false;
    }
    return hkdf_expand_function(prk, prk_size, info, info_size, out, out_size);
}

typedef struct {
    bool is_requester;
    uint8_t op_code;
    const void *context;
    size_t context_size;
    size_t zero_pad_size;
} libspdm_signing_context_str_t;

const libspdm_signing_context_str_t m_libspdm_signing_context_str_table[]={
    {false, SPDM_CHALLENGE_AUTH, SPDM_CHALLENGE_AUTH_SIGN_CONTEXT,
     SPDM_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE, 36 - SPDM_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE},
    {true, SPDM_CHALLENGE_AUTH, SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT,
     SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE, 36 - SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE},
    {false, SPDM_MEASUREMENTS, SPDM_MEASUREMENTS_SIGN_CONTEXT, SPDM_MEASUREMENTS_SIGN_CONTEXT_SIZE,
     36 - SPDM_MEASUREMENTS_SIGN_CONTEXT_SIZE},
    {false, SPDM_KEY_EXCHANGE_RSP, SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT,
     SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT_SIZE,
     36 - SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT_SIZE},
    {true, SPDM_FINISH, SPDM_FINISH_SIGN_CONTEXT, SPDM_FINISH_SIGN_CONTEXT_SIZE,
     36 - SPDM_FINISH_SIGN_CONTEXT_SIZE},
};

/**
 * Get the SPDM signing context string, which is required since SPDM 1.2.
 *
 * @param  spdm_version                         negotiated SPDM version
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  is_requester                         indicate if the signing is from a requester
 * @param  context_size                         SPDM signing context size
 **/
const void *libspdm_get_signing_context_string (
    spdm_version_number_t spdm_version,
    uint8_t op_code,
    bool is_requester,
    size_t *context_size)
{
    size_t index;

    /* It is introduced in SPDM 1.2*/
    LIBSPDM_ASSERT((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_signing_context_str_table); index++) {
        if (m_libspdm_signing_context_str_table[index].is_requester == is_requester &&
            m_libspdm_signing_context_str_table[index].op_code == op_code) {
            *context_size = m_libspdm_signing_context_str_table[index].context_size;
            return m_libspdm_signing_context_str_table[index].context;
        }
    }
    LIBSPDM_ASSERT(false);
    return NULL;
}

/**
 * Create SPDM signing context, which is required since SPDM 1.2.
 *
 * @param  spdm_version                         negotiated SPDM version
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  is_requester                         indicate if the signing is from a requester
 * @param  spdm_signing_context                 SPDM signing context
 **/
void libspdm_create_signing_context (
    spdm_version_number_t spdm_version,
    uint8_t op_code,
    bool is_requester,
    void *spdm_signing_context)
{
    size_t index;
    char *context_str;

    /* It is introduced in SPDM 1.2*/
    LIBSPDM_ASSERT((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11);

    /* So far, it only leaves 1 bytes for version*/
    LIBSPDM_ASSERT((((spdm_version >> 12) & 0xF) < 10) &&
                   (((spdm_version >> 8) & 0xF) < 10));

    context_str = spdm_signing_context;
    for (index = 0; index < 4; index++) {
        libspdm_copy_mem(context_str,
                         SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE,
                         SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT,
                         SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE);
        /* patch the version*/
        context_str[11] = (char)('0' + ((spdm_version >> 12) & 0xF));
        context_str[13] = (char)('0' + ((spdm_version >> 8) & 0xF));
        context_str[15] = (char)('*');
        context_str += SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE;
    }
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_signing_context_str_table); index++) {
        if (m_libspdm_signing_context_str_table[index].is_requester == is_requester &&
            m_libspdm_signing_context_str_table[index].op_code == op_code) {
            libspdm_zero_mem (
                context_str,
                m_libspdm_signing_context_str_table[index].zero_pad_size);
            libspdm_copy_mem(context_str + m_libspdm_signing_context_str_table[index].zero_pad_size,
                             m_libspdm_signing_context_str_table[index].context_size,
                             m_libspdm_signing_context_str_table[index].context,
                             m_libspdm_signing_context_str_table[index].context_size);
            return;
        }
    }
    LIBSPDM_ASSERT(false);
}

/**
 * This function returns the SPDM asymmetric algorithm size.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return SPDM asymmetric algorithm size.
 **/
uint32_t libspdm_get_asym_signature_size(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return 256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return 384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return 512;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return 32 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return 48 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return 66 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return 32 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        return 32 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        return 57 * 2;
    default:
        return 0;
    }
}

/**
 * Return asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric GET_PUBLIC_KEY_FROM_X509 function
 **/
libspdm_asym_get_public_key_from_x509_func
libspdm_get_asym_get_public_key_from_x509(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT == 1) || (LIBSPDM_RSA_PSS_SUPPORT == 1)
        return libspdm_rsa_get_public_key_from_x509;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT == 1
        return libspdm_ec_get_public_key_from_x509;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT == 1) || (LIBSPDM_EDDSA_ED448_SUPPORT == 1)
        return libspdm_ecd_get_public_key_from_x509;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT == 1
        return libspdm_sm2_get_public_key_from_x509;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  cert                         Pointer to the DER-encoded X509 certificate.
 * @param  cert_size                     size of the X509 certificate in bytes.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
bool libspdm_asym_get_public_key_from_x509(uint32_t base_asym_algo,
                                           const uint8_t *cert,
                                           size_t cert_size,
                                           void **context)
{
    libspdm_asym_get_public_key_from_x509_func get_public_key_from_x509_function;
    get_public_key_from_x509_function =
        libspdm_get_asym_get_public_key_from_x509(base_asym_algo);
    if (get_public_key_from_x509_function == NULL) {
        return false;
    }
    return get_public_key_from_x509_function(cert, cert_size, context);
}

/**
 * Return asymmetric free function, based upon the negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric free function
 **/
libspdm_asym_free_func libspdm_get_asym_free(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT == 1) || (LIBSPDM_RSA_PSS_SUPPORT == 1)
        return libspdm_rsa_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT == 1
        return libspdm_ec_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT == 1) || (LIBSPDM_EDDSA_ED448_SUPPORT == 1)
        return libspdm_ecd_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT == 1
        return libspdm_sm2_dsa_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Release the specified asymmetric context,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  context                      Pointer to the asymmetric context to be released.
 **/
void libspdm_asym_free(uint32_t base_asym_algo, void *context)
{
    libspdm_asym_free_func free_function;
    free_function = libspdm_get_asym_free(base_asym_algo);
    if (free_function == NULL) {
        return;
    }
    free_function(context);
}

/**
 * Return if asymmetric function need message hash.
 *
 * @param  base_asym_algo               SPDM base_asym_algo
 *
 * @retval true  asymmetric function need message hash
 * @retval false asymmetric function need raw message
 **/
bool libspdm_asym_func_need_hash(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return true;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return true;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return false;
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return false;
}

#if LIBSPDM_RSA_SSA_SUPPORT == 1
bool libspdm_rsa_pkcs1_verify_with_nid_wrap (void *context, size_t hash_nid,
                                             const uint8_t *param, size_t param_size,
                                             const uint8_t *message,
                                             size_t message_size,
                                             const uint8_t *signature,
                                             size_t sig_size)
{
    return libspdm_rsa_pkcs1_verify_with_nid (context, hash_nid,
                                              message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_RSA_PSS_SUPPORT == 1
bool libspdm_rsa_pss_verify_wrap (void *context, size_t hash_nid,
                                  const uint8_t *param, size_t param_size,
                                  const uint8_t *message,
                                  size_t message_size,
                                  const uint8_t *signature,
                                  size_t sig_size)
{
    return libspdm_rsa_pss_verify (context, hash_nid, message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_ECDSA_SUPPORT == 1
bool libspdm_ecdsa_verify_wrap (void *context, size_t hash_nid,
                                const uint8_t *param, size_t param_size,
                                const uint8_t *message,
                                size_t message_size,
                                const uint8_t *signature,
                                size_t sig_size)
{
    return libspdm_ecdsa_verify (context, hash_nid, message, message_size, signature, sig_size);
}
#endif

#if (LIBSPDM_EDDSA_ED25519_SUPPORT == 1) || (LIBSPDM_EDDSA_ED448_SUPPORT == 1)
bool libspdm_eddsa_verify_wrap (void *context, size_t hash_nid,
                                const uint8_t *param, size_t param_size,
                                const uint8_t *message,
                                size_t message_size,
                                const uint8_t *signature,
                                size_t sig_size)
{
    return libspdm_eddsa_verify (context, hash_nid, param, param_size,
                                 message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_SM2_DSA_SUPPORT == 1
bool libspdm_sm2_dsa_verify_wrap (void *context, size_t hash_nid,
                                  const uint8_t *param, size_t param_size,
                                  const uint8_t *message,
                                  size_t message_size,
                                  const uint8_t *signature,
                                  size_t sig_size)
{
    return libspdm_sm2_dsa_verify (context, hash_nid, param, param_size,
                                   message, message_size, signature, sig_size);
}
#endif

/**
 * Return asymmetric verify function, based upon the negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric verify function
 **/
libspdm_asym_verify_func libspdm_get_asym_verify(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if LIBSPDM_RSA_SSA_SUPPORT == 1
        return libspdm_rsa_pkcs1_verify_with_nid_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if LIBSPDM_RSA_PSS_SUPPORT == 1
        return libspdm_rsa_pss_verify_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT == 1
        return libspdm_ecdsa_verify_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT == 1) || (LIBSPDM_EDDSA_ED448_SUPPORT == 1)
        return libspdm_eddsa_verify_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT == 1
        return libspdm_sm2_dsa_verify_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Verifies the asymmetric signature,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message                      Pointer to octet message to be checked (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    size_t message_size, const uint8_t *signature,
    size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);

    verify_function = libspdm_get_asym_verify(base_asym_algo);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        return verify_function(context, hash_nid, param, param_size, message, message_size,
                               signature, sig_size);
    }
}

/**
 * Verifies the asymmetric signature,
 * based upon negotiated asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message_hash                      Pointer to octet message hash to be checked (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    size_t hash_size, const uint8_t *signature,
    size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    verify_function = libspdm_get_asym_verify(base_asym_algo);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return verify_function(context, hash_nid, param, param_size, full_message_hash,
                                   hash_size, signature, sig_size);
        } else {
            return verify_function(context, hash_nid, param, param_size, message, message_size,
                                   signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        LIBSPDM_ASSERT(false);
        return false;
    }
}

/**
 * Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
 **/
libspdm_asym_get_private_key_from_pem_func
libspdm_get_asym_get_private_key_from_pem(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT == 1) || (LIBSPDM_RSA_PSS_SUPPORT == 1)
        return libspdm_rsa_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT == 1
        return libspdm_ec_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT == 1) || (LIBSPDM_EDDSA_ED448_SUPPORT == 1)
        return libspdm_ecd_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT == 1
        return libspdm_sm2_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_asym_get_private_key_from_pem(uint32_t base_asym_algo,
                                           const uint8_t *pem_data,
                                           size_t pem_size,
                                           const char *password,
                                           void **context)
{
    libspdm_asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
    asym_get_private_key_from_pem =
        libspdm_get_asym_get_private_key_from_pem(base_asym_algo);
    if (asym_get_private_key_from_pem == NULL) {
        return false;
    }
    return asym_get_private_key_from_pem(pem_data, pem_size, password,
                                         context);
}

#if LIBSPDM_RSA_SSA_SUPPORT == 1
bool
libspdm_rsa_pkcs1_sign_with_nid_wrap (void *context, size_t hash_nid,
                                      const uint8_t *param, size_t param_size,
                                      const uint8_t *message,
                                      size_t message_size, uint8_t *signature,
                                      size_t *sig_size)
{
    return libspdm_rsa_pkcs1_sign_with_nid (context, hash_nid,
                                            message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_RSA_PSS_SUPPORT == 1
bool
libspdm_rsa_pss_sign_wrap (void *context, size_t hash_nid,
                           const uint8_t *param, size_t param_size,
                           const uint8_t *message,
                           size_t message_size, uint8_t *signature,
                           size_t *sig_size)
{
    return libspdm_rsa_pss_sign (context, hash_nid,
                                 message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_ECDSA_SUPPORT == 1
bool
libspdm_ecdsa_sign_wrap (void *context, size_t hash_nid,
                         const uint8_t *param, size_t param_size,
                         const uint8_t *message,
                         size_t message_size, uint8_t *signature,
                         size_t *sig_size)
{
    return libspdm_ecdsa_sign (context, hash_nid,
                               message, message_size, signature, sig_size);
}
#endif

#if (LIBSPDM_EDDSA_ED25519_SUPPORT == 1) || (LIBSPDM_EDDSA_ED448_SUPPORT == 1)
bool
libspdm_eddsa_sign_wrap (void *context, size_t hash_nid,
                         const uint8_t *param, size_t param_size,
                         const uint8_t *message,
                         size_t message_size, uint8_t *signature,
                         size_t *sig_size)
{
    return libspdm_eddsa_sign (context, hash_nid, param, param_size,
                               message, message_size, signature, sig_size);
}
#endif

#if LIBSPDM_SM2_DSA_SUPPORT == 1
bool
libspdm_sm2_dsa_sign_wrap (void *context, size_t hash_nid,
                           const uint8_t *param, size_t param_size,
                           const uint8_t *message,
                           size_t message_size, uint8_t *signature,
                           size_t *sig_size)
{
    return libspdm_sm2_dsa_sign (context, hash_nid, param, param_size,
                                 message, message_size, signature, sig_size);
}
#endif

/**
 * Return asymmetric sign function, based upon the asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric sign function
 **/
libspdm_asym_sign_func libspdm_get_asym_sign(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if LIBSPDM_RSA_SSA_SUPPORT == 1
        return libspdm_rsa_pkcs1_sign_with_nid_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if LIBSPDM_RSA_PSS_SUPPORT == 1
        return libspdm_rsa_pss_sign_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT == 1
        return libspdm_ecdsa_sign_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT == 1) || (LIBSPDM_EDDSA_ED448_SUPPORT == 1)
        return libspdm_eddsa_sign_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT == 1
        return libspdm_sm2_dsa_sign_wrap;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message                      Pointer to octet message to be signed (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message,
    size_t message_size, uint8_t *signature,
    size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);

    asym_sign = libspdm_get_asym_sign(base_asym_algo);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        return asym_sign(context, hash_nid, param, param_size, message, message_size,
                         signature, sig_size);
    }
}

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message_hash                      Pointer to octet message hash to be signed (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_asym_sign_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo,
    void *context, const uint8_t *message_hash,
    size_t hash_size, uint8_t *signature,
    size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    asym_sign = libspdm_get_asym_sign(base_asym_algo);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (base_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, false, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, false,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return asym_sign(context, hash_nid, param, param_size, full_message_hash, hash_size,
                             signature, sig_size);
        } else {
            return asym_sign(context, hash_nid, param, param_size, message, message_size,
                             signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}

/**
 * This function returns the SPDM requester asymmetric algorithm size.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return SPDM requester asymmetric algorithm size.
 **/
uint32_t libspdm_get_req_asym_signature_size(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_signature_size(req_base_asym_alg);
}

/**
 * Return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function
 **/
libspdm_asym_get_public_key_from_x509_func
libspdm_get_req_asym_get_public_key_from_x509(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_get_public_key_from_x509(req_base_asym_alg);
}

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  cert                         Pointer to the DER-encoded X509 certificate.
 * @param  cert_size                     size of the X509 certificate in bytes.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
bool libspdm_req_asym_get_public_key_from_x509(uint16_t req_base_asym_alg,
                                               const uint8_t *cert,
                                               size_t cert_size,
                                               void **context)
{
    libspdm_asym_get_public_key_from_x509_func get_public_key_from_x509_function;
    get_public_key_from_x509_function =
        libspdm_get_req_asym_get_public_key_from_x509(req_base_asym_alg);
    if (get_public_key_from_x509_function == NULL) {
        return false;
    }
    return get_public_key_from_x509_function(cert, cert_size, context);
}

/**
 * Return requester asymmetric free function, based upon the negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return requester asymmetric free function
 **/
libspdm_asym_free_func libspdm_get_req_asym_free(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_free(req_base_asym_alg);
}

/**
 * Release the specified asymmetric context,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  context                      Pointer to the asymmetric context to be released.
 **/
void libspdm_req_asym_free(uint16_t req_base_asym_alg, void *context)
{
    libspdm_asym_free_func free_function;
    free_function = libspdm_get_req_asym_free(req_base_asym_alg);
    if (free_function == NULL) {
        return;
    }
    free_function(context);
}

/**
 * Return if requester asymmetric function need message hash.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @retval true  requester asymmetric function need message hash
 * @retval false requester asymmetric function need raw message
 **/
bool libspdm_req_asym_func_need_hash(uint16_t req_base_asym_alg)
{
    return libspdm_asym_func_need_hash(req_base_asym_alg);
}

/**
 * Return requester asymmetric verify function, based upon the negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return requester asymmetric verify function
 **/
libspdm_asym_verify_func libspdm_get_req_asym_verify(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_verify(req_base_asym_alg);
}

/**
 * Verifies the asymmetric signature,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message                      Pointer to octet message to be checked (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_req_asym_verify(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);

    verify_function = libspdm_get_req_asym_verify(req_base_asym_alg);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        return verify_function(context, hash_nid, param, param_size, message, message_size,
                               signature, sig_size);
    }
}

/**
 * Verifies the asymmetric signature,
 * based upon negotiated requester asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature verification.
 * @param  message_hash                      Pointer to octet message hash to be checked (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to asymmetric signature to be verified.
 * @param  sig_size                      size of signature in bytes.
 *
 * @retval  true   Valid asymmetric signature.
 * @retval  false  Invalid asymmetric signature or invalid asymmetric context.
 **/
bool libspdm_req_asym_verify_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    const uint8_t *signature, size_t sig_size)
{
    libspdm_asym_verify_func verify_function;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    verify_function = libspdm_get_req_asym_verify(req_base_asym_alg);
    if (verify_function == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return verify_function(context, hash_nid, param, param_size, full_message_hash,
                                   hash_size, signature, sig_size);
        } else {
            return verify_function(context, hash_nid, param, param_size, message, message_size,
                                   signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return verify_function(context, hash_nid, param, param_size, message_hash,
                               hash_size, signature, sig_size);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}

/**
 * Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
 **/
libspdm_asym_get_private_key_from_pem_func
libspdm_get_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_get_private_key_from_pem(req_base_asym_alg);
}

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg,
                                               const uint8_t *pem_data,
                                               size_t pem_size,
                                               const char *password,
                                               void **context)
{
    libspdm_asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
    asym_get_private_key_from_pem =
        libspdm_get_req_asym_get_private_key_from_pem(req_base_asym_alg);
    if (asym_get_private_key_from_pem == NULL) {
        return false;
    }
    return asym_get_private_key_from_pem(pem_data, pem_size, password,
                                         context);
}

/**
 * Return asymmetric sign function, based upon the asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return asymmetric sign function
 **/
libspdm_asym_sign_func libspdm_get_req_asym_sign(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_sign(req_base_asym_alg);
}

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message                      Pointer to octet message to be signed (before hash).
 * @param  message_size                  size of the message in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_req_asym_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);

    asym_sign = libspdm_get_req_asym_sign(req_base_asym_alg);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  &spdm12_signing_context_with_hash[
                                      SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]);
        if (!result) {
            return false;
        }

        /* re-assign message and message_size for signing*/

        hash_size = libspdm_get_hash_size(base_hash_algo);
        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        /* Passthru*/

    }

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size,
                                  message_hash);
        if (!result) {
            return false;
        }
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        return asym_sign(context, hash_nid, param, param_size, message, message_size,
                         signature, sig_size);
    }
}

/**
 * Carries out the signature generation.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  context                      Pointer to asymmetric context for signature generation.
 * @param  message_hash                      Pointer to octet message hash to be signed (after hash).
 * @param  hash_size                  size of the hash in bytes.
 * @param  signature                    Pointer to buffer to receive signature.
 * @param  sig_size                      On input, the size of signature buffer in bytes.
 *                                     On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_req_asym_sign_hash(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, void *context,
    const uint8_t *message_hash, size_t hash_size,
    uint8_t *signature, size_t *sig_size)
{
    libspdm_asym_sign_func asym_sign;
    bool need_hash;
    uint8_t *message;
    size_t message_size;
    uint8_t full_message_hash[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t hash_nid;
    uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
                                             LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_req_asym_func_need_hash(req_base_asym_alg);
    LIBSPDM_ASSERT (hash_size == libspdm_get_hash_size(base_hash_algo));

    asym_sign = libspdm_get_req_asym_sign(req_base_asym_alg);
    if (asym_sign == NULL) {
        return false;
    }

    param = NULL;
    param_size = 0;

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) > SPDM_MESSAGE_VERSION_11) {

        /* Need use SPDM 1.2 signing*/

        switch (req_base_asym_alg) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
            param = "";
            param_size = 0;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
            hash_nid = LIBSPDM_CRYPTO_NID_NULL;
            param = libspdm_get_signing_context_string (spdm_version, op_code, true, &param_size);
            break;
        default:
            /* pass thru for rest algorithm */
            break;
        }

        libspdm_create_signing_context (spdm_version, op_code, true,
                                        spdm12_signing_context_with_hash);
        libspdm_copy_mem(&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
                         sizeof(spdm12_signing_context_with_hash)
                         - (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE]
                            - spdm12_signing_context_with_hash),
                         message_hash, hash_size);

        /* assign message and message_size for signing*/

        message = spdm12_signing_context_with_hash;
        message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

        if (need_hash) {
            result = libspdm_hash_all(base_hash_algo, message, message_size,
                                      full_message_hash);
            if (!result) {
                return false;
            }
            return asym_sign(context, hash_nid, param, param_size, full_message_hash, hash_size,
                             signature, sig_size);
        } else {
            return asym_sign(context, hash_nid, param, param_size, message, message_size,
                             signature, sig_size);
        }

        /* SPDM 1.2 signing done.*/

    }

    if (need_hash) {
        return asym_sign(context, hash_nid, param, param_size, message_hash, hash_size,
                         signature, sig_size);
    } else {
        LIBSPDM_ASSERT (false);
        return false;
    }
}

/**
 * This function returns the SPDM DHE algorithm key size.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return SPDM DHE algorithm key size.
 **/
uint32_t libspdm_get_dhe_pub_key_size(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
        return 256;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
        return 384;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
        return 512;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
        return 32 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
        return 48 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
        return 66 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
        return 32 * 2;
    default:
        return 0;
    }
}

/**
 * Return cipher ID, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE cipher ID
 **/
size_t libspdm_get_dhe_nid(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
        return LIBSPDM_CRYPTO_NID_FFDHE2048;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
        return LIBSPDM_CRYPTO_NID_FFDHE3072;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
        return LIBSPDM_CRYPTO_NID_FFDHE4096;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
        return LIBSPDM_CRYPTO_NID_SECP256R1;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
        return LIBSPDM_CRYPTO_NID_SECP384R1;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
        return LIBSPDM_CRYPTO_NID_SECP521R1;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
        return LIBSPDM_CRYPTO_NID_SM2_KEY_EXCHANGE_P256;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

/**
 * Return DHE new by NID function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE new by NID function
 **/
libspdm_dhe_new_by_nid_func libspdm_get_dhe_new(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT == 1
        return libspdm_dh_new_by_nid;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT == 1
        return libspdm_ec_new_by_nid;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 1
        return libspdm_sm2_key_exchange_new_by_nid;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use,
 * based upon negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  is_initiator                   if the caller is initiator.
 *                                       true: initiator
 *                                       false: not an initiator
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 **/
void *libspdm_dhe_new(spdm_version_number_t spdm_version,
                      uint16_t dhe_named_group, bool is_initiator)
{
    libspdm_dhe_new_by_nid_func new_function;
    size_t nid;
    void *context;

    new_function = libspdm_get_dhe_new(dhe_named_group);
    if (new_function == NULL) {
        return NULL;
    }
    nid = libspdm_get_dhe_nid(dhe_named_group);
    if (nid == 0) {
        return NULL;
    }
    context = new_function(nid);
    if (context == NULL) {
        return NULL;
    }

#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 1
    if (dhe_named_group == SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256) {
        bool result;
        uint8_t spdm12_key_change_requester_context[
            SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT_SIZE];
        uint8_t spdm12_key_change_responder_context[
            SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT_SIZE];

        libspdm_copy_mem(spdm12_key_change_requester_context,
                         sizeof(spdm12_key_change_requester_context),
                         SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT,
                         SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT_SIZE);
        libspdm_copy_mem(spdm12_key_change_responder_context,
                         sizeof(spdm12_key_change_responder_context),
                         SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT,
                         SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT_SIZE);
        /* patch the version*/
        spdm12_key_change_requester_context[25] = (char)('0' + ((spdm_version >> 12) & 0xF));
        spdm12_key_change_requester_context[27] = (char)('0' + ((spdm_version >> 8) & 0xF));
        spdm12_key_change_responder_context[25] = (char)('0' + ((spdm_version >> 12) & 0xF));
        spdm12_key_change_responder_context[27] = (char)('0' + ((spdm_version >> 8) & 0xF));

        result = libspdm_sm2_key_exchange_init (context, LIBSPDM_CRYPTO_NID_SM3_256,
                                                spdm12_key_change_requester_context,
                                                SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT_SIZE,
                                                spdm12_key_change_responder_context,
                                                SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT_SIZE,
                                                is_initiator);
        if (!result) {
            libspdm_sm2_key_exchange_free (context);
            return NULL;
        }
    }
#endif

    return context;
}

/**
 * Return DHE free function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE free function
 **/
libspdm_dhe_free_func libspdm_get_dhe_free(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT == 1
        return libspdm_dh_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT == 1
        return libspdm_ec_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 1
        return libspdm_sm2_key_exchange_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Release the specified DHE context,
 * based upon negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  context                      Pointer to the DHE context to be released.
 **/
void libspdm_dhe_free(uint16_t dhe_named_group, void *context)
{
    libspdm_dhe_free_func free_function;
    free_function = libspdm_get_dhe_free(dhe_named_group);
    if (free_function == NULL) {
        return;
    }
    free_function(context);
}

/**
 * Return DHE generate key function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE generate key function
 **/
libspdm_dhe_generate_key_func libspdm_get_dhe_generate_key(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT == 1
        return libspdm_dh_generate_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT == 1
        return libspdm_ec_generate_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 1
        return libspdm_sm2_key_exchange_generate_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Generates DHE public key,
 * based upon negotiated DHE algorithm.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  context                      Pointer to the DHE context.
 * @param  public_key                    Pointer to the buffer to receive generated public key.
 * @param  public_key_size                On input, the size of public_key buffer in bytes.
 *                                     On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DHE public key generation succeeded.
 * @retval false  DHE public key generation failed.
 * @retval false  public_key_size is not large enough.
 **/
bool libspdm_dhe_generate_key(uint16_t dhe_named_group, void *context,
                              uint8_t *public_key,
                              size_t *public_key_size)
{
    libspdm_dhe_generate_key_func generate_key_function;
    generate_key_function = libspdm_get_dhe_generate_key(dhe_named_group);
    if (generate_key_function == NULL) {
        return false;
    }
    return generate_key_function(context, public_key, public_key_size);
}

/**
 * Return DHE compute key function, based upon the negotiated DHE algorithm.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 *
 * @return DHE compute key function
 **/
libspdm_dhe_compute_key_func libspdm_get_dhe_compute_key(uint16_t dhe_named_group)
{
    switch (dhe_named_group) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if LIBSPDM_FFDHE_SUPPORT == 1
        return libspdm_dh_compute_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if LIBSPDM_ECDHE_SUPPORT == 1
        return libspdm_ec_compute_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256:
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 1
        return libspdm_sm2_key_exchange_compute_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Computes exchanged common key,
 * based upon negotiated DHE algorithm.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * @param  dhe_named_group                SPDM dhe_named_group
 * @param  context                      Pointer to the DHE context.
 * @param  peer_public_key                Pointer to the peer's public key.
 * @param  peer_public_key_size            size of peer's public key in bytes.
 * @param  key                          Pointer to the buffer to receive generated key.
 * @param  key_size                      On input, the size of key buffer in bytes.
 *                                     On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DHE exchanged key generation succeeded.
 * @retval false  DHE exchanged key generation failed.
 * @retval false  key_size is not large enough.
 **/
bool libspdm_dhe_compute_key(uint16_t dhe_named_group, void *context,
                             const uint8_t *peer_public,
                             size_t peer_public_size, uint8_t *key,
                             size_t *key_size)
{
    libspdm_dhe_compute_key_func compute_key_function;
    compute_key_function = libspdm_get_dhe_compute_key(dhe_named_group);
    if (compute_key_function == NULL) {
        return false;
    }
#if LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT == 1
    if (dhe_named_group == SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256) {
        /* SM2 key exchange can generate arbitrary length key_size. SPDM requires SM2 key_size to be 16. */
        LIBSPDM_ASSERT (*key_size >= 16);
        *key_size = 16;
    }
#endif
    return compute_key_function(context, peer_public, peer_public_size, key,
                                key_size);
}

/**
 * This function returns the SPDM AEAD algorithm key size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm key size.
 **/
uint32_t libspdm_get_aead_key_size(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
        return 32;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
        return 32;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
        return 16;
    default:
        return 0;
    }
}

/**
 * This function returns the SPDM AEAD algorithm iv size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm iv size.
 **/
uint32_t libspdm_get_aead_iv_size(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
        return 12;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
        return 12;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
        return 12;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
        return 12;
    default:
        return 0;
    }
}

/**
 * This function returns the SPDM AEAD algorithm tag size.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return SPDM AEAD algorithm tag size.
 **/
uint32_t libspdm_get_aead_tag_size(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
        return 16;
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
        return 16;
    default:
        return 0;
    }
}

/**
 * Return AEAD encryption function, based upon the negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return AEAD encryption function
 **/
libspdm_aead_encrypt_func libspdm_get_aead_enc_func(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead aes_128_gcm encrypt\n"));
        return libspdm_aead_aes_gcm_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead aes_256_gcm encrypt\n"));
        return libspdm_aead_aes_gcm_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead chacha20_poly1305 encrypt\n"));
        return libspdm_aead_chacha20_poly1305_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
#if LIBSPDM_AEAD_SM4_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead sm4_gcm encrypt\n"));
        return libspdm_aead_sm4_gcm_encrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
 * based upon negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 * @param  key                          Pointer to the encryption key.
 * @param  key_size                      size of the encryption key in bytes.
 * @param  iv                           Pointer to the IV value.
 * @param  iv_size                  ke     size of the IV value in bytes.
 * @param  a_data                        Pointer to the additional authenticated data (AAD).
 * @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
 * @param  data_in                       Pointer to the input data buffer to be encrypted.
 * @param  data_in_size                   size of the input data buffer in bytes.
 * @param  tag_out                       Pointer to a buffer that receives the authentication tag output.
 * @param  tag_size                      size of the authentication tag in bytes.
 * @param  data_out                      Pointer to a buffer that receives the encryption output.
 * @param  data_out_size                  size of the output data buffer in bytes.
 *
 * @retval true   AEAD authenticated encryption succeeded.
 * @retval false  AEAD authenticated encryption failed.
 **/
bool libspdm_aead_encryption(const spdm_version_number_t secured_message_version,
                             uint16_t aead_cipher_suite, const uint8_t *key,
                             size_t key_size, const uint8_t *iv,
                             size_t iv_size, const uint8_t *a_data,
                             size_t a_data_size, const uint8_t *data_in,
                             size_t data_in_size, uint8_t *tag_out,
                             size_t tag_size, uint8_t *data_out,
                             size_t *data_out_size)
{
    libspdm_aead_encrypt_func aead_enc_function;
    aead_enc_function = libspdm_get_aead_enc_func(aead_cipher_suite);
    if (aead_enc_function == NULL) {
        return false;
    }
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aead encrypt input:\n"));
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key:\n"));
libspdm_internal_dump_hex(key, key_size);
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "iv:\n"));
libspdm_internal_dump_hex(iv, iv_size);
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "a_data:\n"));
libspdm_internal_dump_hex(a_data, a_data_size);
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "data_in:\n"));
libspdm_internal_dump_hex(data_in, data_in_size);
    return aead_enc_function(key, key_size, iv, iv_size, a_data,
                             a_data_size, data_in, data_in_size, tag_out,
                             tag_size, data_out, data_out_size);
}

/**
 * Return AEAD decryption function, based upon the negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 *
 * @return AEAD decryption function
 **/
libspdm_aead_decrypt_func libspdm_get_aead_dec_func(uint16_t aead_cipher_suite)
{
    switch (aead_cipher_suite) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead aes_128_gcm decrypt\n"));
        return libspdm_aead_aes_gcm_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if LIBSPDM_AEAD_GCM_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead aes_256_gcm decrypt\n"));
        return libspdm_aead_aes_gcm_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead aes_256_gcm decrypt\n"));
        return libspdm_aead_chacha20_poly1305_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM:
#if LIBSPDM_AEAD_SM4_SUPPORT == 1
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "use aead sm4_gcm decrypt\n"));
        return libspdm_aead_sm4_gcm_decrypt;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
 * based upon negotiated AEAD algorithm.
 *
 * @param  aead_cipher_suite              SPDM aead_cipher_suite
 * @param  key                          Pointer to the encryption key.
 * @param  key_size                      size of the encryption key in bytes.
 * @param  iv                           Pointer to the IV value.
 * @param  iv_size                       size of the IV value in bytes.
 * @param  a_data                        Pointer to the additional authenticated data (AAD).
 * @param  a_data_size                    size of the additional authenticated data (AAD) in bytes.
 * @param  data_in                       Pointer to the input data buffer to be decrypted.
 * @param  data_in_size                   size of the input data buffer in bytes.
 * @param  tag                          Pointer to a buffer that contains the authentication tag.
 * @param  tag_size                      size of the authentication tag in bytes.
 * @param  data_out                      Pointer to a buffer that receives the decryption output.
 * @param  data_out_size                  size of the output data buffer in bytes.
 *
 * @retval true   AEAD authenticated decryption succeeded.
 * @retval false  AEAD authenticated decryption failed.
 **/
bool libspdm_aead_decryption(const spdm_version_number_t secured_message_version,
                             uint16_t aead_cipher_suite, const uint8_t *key,
                             size_t key_size, const uint8_t *iv,
                             size_t iv_size, const uint8_t *a_data,
                             size_t a_data_size, const uint8_t *data_in,
                             size_t data_in_size, const uint8_t *tag,
                             size_t tag_size, uint8_t *data_out,
                             size_t *data_out_size)
{
    libspdm_aead_decrypt_func aead_dec_function;
    aead_dec_function = libspdm_get_aead_dec_func(aead_cipher_suite);
    if (aead_dec_function == NULL) {
        return false;
    }
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aead decrypt input:\n"));
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key:\n"));
libspdm_internal_dump_hex(key, key_size);
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "iv:\n"));
libspdm_internal_dump_hex(iv, iv_size);
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "a_data:\n"));
libspdm_internal_dump_hex(a_data, a_data_size);
LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "data_in:\n"));
libspdm_internal_dump_hex(data_in, data_in_size);
    return aead_dec_function(key, key_size, iv, iv_size, a_data,
                             a_data_size, data_in, data_in_size, tag,
                             tag_size, data_out, data_out_size);
}

/**
 * Generates a random byte stream of the specified size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  size                         size of random bytes to generate.
 * @param  rand                         Pointer to buffer to receive random value.
 **/
bool libspdm_get_random_number(size_t size, uint8_t *rand)
{
    if (size == 0) {
        return true;
    }
    return libspdm_random_bytes(rand, size);
}

/**
 * Check the X509 DataTime is within a valid range.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  from                         notBefore Pointer to date_time object.
 * @param  from_size                     notBefore date_time object size.
 * @param  to                           notAfter Pointer to date_time object.
 * @param  to_size                       notAfter date_time object size.
 *
 * @retval  true   verification pass.
 * @retval  false  verification fail.
 **/
static bool libspdm_internal_x509_date_time_check(const uint8_t *from,
                                                  size_t from_size,
                                                  const uint8_t *to,
                                                  size_t to_size)
{
    int32_t ret;
    bool status;
    uint8_t f0[64];
    uint8_t t0[64];
    size_t f0_size;
    size_t t0_size;

    f0_size = 64;
    t0_size = 64;

    status = libspdm_x509_set_date_time("19700101000000Z", f0, &f0_size);
    if (!status) {
        return false;
    }

    status = libspdm_x509_set_date_time("99991231235959Z", t0, &t0_size);
    if (!status) {
        return false;
    }

    /* from >= f0*/
    ret = libspdm_x509_compare_date_time(from, f0);
    if (ret < 0) {
        return false;
    }

    /* to <= t0*/
    ret = libspdm_x509_compare_date_time(t0, to);
    if (ret < 0) {
        return false;
    }

    return true;
}

/**
 * This function returns the SPDM public key encryption algorithm OID len.
 *
 * @param[in]  base_asym_algo          SPDM base_asym_algo
 *
 * @return SPDM public key encryption algorithms OID len.
 **/
uint32_t libspdm_get_public_key_algo_OID_len(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return 4;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return 8;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return 5;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        return 3;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

/**
 * This function get the SPDM public key encryption algorithm OID.
 *
 * @param[in]      base_asym_algo                 SPDM base_asym_algo
 * @param[in,out]  oid                            SPDM public key encryption algorithm OID
 * @param[in,out]  oid_other                      Other SPDM public key encryption algorithm OID
 *                                                because of ASN1 code for integer
 *
 * @retval  true   get OID sucessful.
 * @retval  false  get OID fail.
 **/
bool libspdm_get_public_key_algo_OID(uint32_t base_asym_algo,
                                     uint8_t *oid, uint8_t *oid_other)
{
    uint32_t oid_len;
    oid_len = libspdm_get_public_key_algo_OID_len(base_asym_algo);

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048: {
        uint8_t encry_algo_oid_rsa2048[] = KEY_ENCRY_ALGO_RSA2048_FLAG;
        uint8_t encry_algo_oid_rsa2048_ohter[] = KEY_ENCRY_ALGO_RSA2048_FLAG_OTHER;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_rsa2048, oid_len);
        libspdm_copy_mem(oid_other, oid_len, encry_algo_oid_rsa2048_ohter, oid_len);
        break;
    }
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072: {
        uint8_t encry_algo_oid_rsa3072[] = KEY_ENCRY_ALGO_RSA3072_FLAG;
        uint8_t encry_algo_oid_rsa3072_ohter[] = KEY_ENCRY_ALGO_RSA3072_FLAG_OTHER;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_rsa3072, oid_len);
        libspdm_copy_mem(oid_other, oid_len, encry_algo_oid_rsa3072_ohter, oid_len);
        break;
    }
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096: {
        uint8_t encry_algo_oid_rsa4096[] = KEY_ENCRY_ALGO_RSA4096_FLAG;
        uint8_t encry_algo_oid_rsa4096_ohter[] = KEY_ENCRY_ALGO_RSA4096_FLAG_OTHER;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_rsa4096, oid_len);
        libspdm_copy_mem(oid_other, oid_len, encry_algo_oid_rsa4096_ohter, oid_len);
        break;
    }

    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256: {
        uint8_t encry_algo_oid_ecc256[] = KEY_ENCRY_ALGO_ECC256_OID;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_ecc256, oid_len);
        break;
    }
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384: {
        uint8_t encry_algo_oid_ecc384[] = KEY_ENCRY_ALGO_ECC384_OID;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_ecc384, oid_len);
        break;
    }
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521: {
        uint8_t encry_algo_oid_ecc521[] = KEY_ENCRY_ALGO_ECC521_OID;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_ecc521, oid_len);
        break;
    }

    /*sm2 oid  TBD*/
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return true;

    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519: {
        uint8_t encry_algo_oid_ed25519[] = ENCRY_ALGO_ED25519_OID;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_ed25519, oid_len);
        break;
    }
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448: {
        uint8_t encry_algo_oid_ed448[] = ENCRY_ALGO_ED448_OID;
        libspdm_copy_mem(oid, oid_len, encry_algo_oid_ed448, oid_len);
        break;
    }

    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    return true;
}

/**
 * Verify cert public key encryption algorithm is matched to negotiated base_aysm algo
 *
 * @param[in]      cert                  Pointer to the DER-encoded certificate data.
 * @param[in]      cert_size             The size of certificate data in bytes.
 * @param[in]      base_asym_algo        SPDM base_asym_algo
 * @param[out]     oid                   cert public key encryption algorithm OID
 * @param[in]      oid_size              the buffer size for required OID
 *
 * @retval  true   get public key oid from cert successfully
 * @retval  false  get public key oid from cert fail
 **/
bool libspdm_get_public_key_oid(const uint8_t *cert, size_t cert_size,
                                uint8_t *oid, size_t oid_size, uint32_t base_asym_algo)
{
    bool ret;
    uint8_t *ptr;
    int32_t length;
    size_t obj_len;
    uint8_t *end;
    uint8_t index;
    uint8_t sequence_time;

    length = (int32_t)cert_size;
    ptr = (uint8_t*)(size_t)cert;
    obj_len = 0;
    end = ptr + length;
    ret = true;

    /* TBSCertificate have 5 sequence before subjectPublicKeyInfo*/
    sequence_time = 5;

    /*all cert sequence*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /*TBSCertificate sequence*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    end = ptr + obj_len;
    /*version*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                               LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    ptr += obj_len;
    /*serialNumber*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    if (!ret) {
        return false;
    }

    /**
     * signature AlgorithmIdentifier,
     * issuer Name,
     * validity Validity,
     * subject Name,
     * subjectPublicKeyInfo
     **/
    for (index = 0; index < sequence_time; index++) {
        ptr += obj_len;
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (!ret) {
            return false;
        }
    }

    switch (base_asym_algo)
    {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (!ret) {
            return false;
        }

        ptr += obj_len;
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_BIT_STRING);
        if (!ret) {
            return false;
        }

        /*get rsa key len*/
        ptr++;
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (!ret) {
            return false;
        }
        libspdm_copy_mem(oid, oid_size, ptr, oid_size);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (!ret) {
            return false;
        }
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
        if (!ret) {
            return false;
        }

        /*get ecc second oid*/
        ptr +=obj_len;
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
        if (!ret) {
            return false;
        }

        if (oid_size != obj_len) {
            return false;
        }

        libspdm_copy_mem(oid, oid_size, ptr, obj_len);
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (!ret) {
            return false;
        }

        /*get eddsa oid*/
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
        if (!ret) {
            return false;
        }

        if (oid_size != obj_len) {
            return false;
        }

        libspdm_copy_mem(oid, oid_size, ptr, obj_len);
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    return true;
}

/**
 * Verify cert public key encryption algorithm is matched to negotiated base_aysm algo
 *
 * @param[in]  cert                  Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size             The size of certificate data in bytes.
 * @param[in]  base_asym_algo        SPDM base_asym_algo
 *
 * @retval  true   verify pass
 * @retval  false  verify fail
 **/
bool libspdm_verify_cert_subject_public_key_info(const uint8_t *cert, size_t cert_size,
                                                 uint32_t base_asym_algo)
{
    size_t oid_len;
    bool status;

    /*public key encrypt algo OID from cert*/
    uint8_t cert_public_key_crypt_algo_oid[LIBSPDM_MAX_ENCRYPTION_ALGO_OID_LEN];
    /*public key encrypt algo OID from libspdm stored*/
    uint8_t libspdm_public_key_crypt_algo_oid[LIBSPDM_MAX_ENCRYPTION_ALGO_OID_LEN];
    uint8_t libspdm_public_key_crypt_algo_oid_other[LIBSPDM_MAX_ENCRYPTION_ALGO_OID_LEN];

    libspdm_zero_mem(libspdm_public_key_crypt_algo_oid, LIBSPDM_MAX_ENCRYPTION_ALGO_OID_LEN);
    libspdm_zero_mem(libspdm_public_key_crypt_algo_oid_other, LIBSPDM_MAX_ENCRYPTION_ALGO_OID_LEN);

    /*work around: skip the sm2*/
    if (base_asym_algo == SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256) {
        return true;
    }

    oid_len = libspdm_get_public_key_algo_OID_len(base_asym_algo);
    if(oid_len == 0) {
        return false;
    }
    /*get public key encrypt algo OID from libspdm stored*/
    status = libspdm_get_public_key_algo_OID(base_asym_algo,
                                             libspdm_public_key_crypt_algo_oid,
                                             libspdm_public_key_crypt_algo_oid_other);
    if (!status) {
        return status;
    }

    /*get public key encrypt algo OID from cert*/
    status = libspdm_get_public_key_oid(cert, cert_size, cert_public_key_crypt_algo_oid, oid_len,
                                        base_asym_algo);
    if (!status || (libspdm_const_compare_mem(cert_public_key_crypt_algo_oid,
                                              libspdm_public_key_crypt_algo_oid, oid_len) &&
                    libspdm_const_compare_mem(cert_public_key_crypt_algo_oid,
                                              libspdm_public_key_crypt_algo_oid_other, oid_len))) {
        return false;
    }

    return status;
}

/**
 * Verify leaf cert basic_constraints CA is false
 *
 * @param[in]  cert                  Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size             The size of certificate data in bytes.
 *
 * @retval  true   verify pass,two case: 1.basic constraints is not present in cert;
 *                                       2. cert basic_constraints CA is false;
 * @retval  false  verify fail
 **/
bool libspdm_verify_leaf_cert_basic_constraints(const uint8_t *cert, size_t cert_size)
{
    bool status;
    /*basic_constraints from cert*/
    uint8_t cert_basic_constraints[BASIC_CONSTRAINTS_CA_LEN];
    size_t len;

    /*leaf cert basic_constraints case1: CA: false and CA object is excluded */
    #define BASIC_CONSTRAINTS_STRING_CASE1 {0x30, 0x00}
    uint8_t basic_constraints_case1[] = BASIC_CONSTRAINTS_STRING_CASE1;

    /*leaf cert basic_constraints case2: CA: false */
    #define BASIC_CONSTRAINTS_STRING_CASE2 {0x30, 0x03, 0x01, 0x01, 0x00}
    uint8_t basic_constraints_case2[] = BASIC_CONSTRAINTS_STRING_CASE2;

    len = BASIC_CONSTRAINTS_CA_LEN;

    status = libspdm_x509_get_extended_basic_constraints(cert, cert_size,
                                                         cert_basic_constraints, &len);

    if (len == 0) {
        /* basic constraints is not present in cert */
        return true;
    } else if (!status ) {
        return false;
    }

    if ((len == sizeof(basic_constraints_case1)) &&
        (!libspdm_const_compare_mem(cert_basic_constraints,
                                    basic_constraints_case1,
                                    sizeof(basic_constraints_case1)))) {
        return true;
    }

    if ((len == sizeof(basic_constraints_case2)) &&
        (!libspdm_const_compare_mem(cert_basic_constraints,
                                    basic_constraints_case2,
                                    sizeof(basic_constraints_case2)))) {
        return true;
    }

    return false;
}

/**
 * Verify leaf cert extend spdm OID
 *
 * @param[in]  cert                  Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size             The size of certificate data in bytes.
 *
 * @retval  true   verify pass
 * @retval  false  verify fail,two case: 1. return is not RETURN_SUCCESS or RETURN_NOT_FOUND;
 *                                       2. hardware_identity_oid is found in AliasCert model;
 **/
bool libspdm_verify_leaf_cert_eku_spdm_OID(const uint8_t *cert, size_t cert_size,
                                           bool is_device_cert_model)
{
    bool status;
    bool find_sucessful;
    uint8_t spdm_extension[SPDM_EXTENDSION_LEN];
    size_t index;
    size_t len;

    /* SPDM defined OID */

    uint8_t oid_spdm_extension[] = SPDM_OID_EXTENSION;
    uint8_t hardware_identity_oid[] = SPDM_OID_HARDWARE_IDENTITY;

    len = SPDM_EXTENDSION_LEN;

    if (cert == NULL || cert_size == 0) {
        return false;
    }

    status = libspdm_x509_get_extension_data(cert, cert_size,
                                             (const uint8_t *)oid_spdm_extension,
                                             sizeof(oid_spdm_extension),
                                             spdm_extension,
                                             &len);

    if(len == 0) {
        return true;
    } else if(!status) {
        return false;
    }

    /*find the spdm hardware identity OID*/
    find_sucessful = false;
    for(index = 0; index <= len - sizeof(hardware_identity_oid); index++) {
        if (!libspdm_const_compare_mem(spdm_extension + index, hardware_identity_oid,
                                       sizeof(hardware_identity_oid))) {
            find_sucessful = true;
            break;
        }
    }

    if ((find_sucessful) && (!is_device_cert_model)) {
        /* Hardware_identity_OID is found in alias cert model */
        return false;
    } else {
        return true;
    }
}

/**
 * Certificate Check for SPDM leaf cert.
 *
 * @param[in]  cert                  Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size             The size of certificate data in bytes.
 * @param[in]  base_asym_algo        SPDM base_asym_algo
 * @param[in]  base_hash_algo        SPDM base_hash_algo
 * @param[in]  is_device_cert_model  If true, the cert chain is DeviceCert model;
 *                                   If false, the cert chain is AliasCert model;
 *
 * @retval  true   Success.
 * @retval  false  Certificate is not valid
 **/
bool libspdm_x509_certificate_check(const uint8_t *cert, size_t cert_size,
                                    uint32_t base_asym_algo,
                                    uint32_t base_hash_algo,
                                    bool is_device_cert_model)
{
    uint8_t end_cert_from[64];
    size_t end_cert_from_len;
    uint8_t end_cert_to[64];
    size_t end_cert_to_len;
    size_t asn1_buffer_len;
    bool status;
    size_t cert_version;
    size_t value;
    void *context;

    if (cert == NULL || cert_size == 0) {
        return false;
    }

    status = true;
    context = NULL;
    end_cert_from_len = 64;
    end_cert_to_len = 64;

    /* 1. version*/
    cert_version = 0;
    status = libspdm_x509_get_version(cert, cert_size, &cert_version);
    if (!status) {
        goto cleanup;
    }
    if (cert_version != 2) {
        status = false;
        goto cleanup;
    }

    /* 2. serial_number*/
    asn1_buffer_len = 0;
    status = libspdm_x509_get_serial_number(cert, cert_size, NULL, &asn1_buffer_len);
    if (asn1_buffer_len == 0) {
        status = false;
        goto cleanup;
    }

    /* 3. Verify public key algorithm. */
    status =
        libspdm_verify_cert_subject_public_key_info(cert, cert_size, base_asym_algo);
    if (!status) {
        goto cleanup;
    }

    /* 4. issuer_name*/
    asn1_buffer_len = 0;
    status = libspdm_x509_get_issuer_name(cert, cert_size, NULL, &asn1_buffer_len);
    if (asn1_buffer_len == 0) {
        status = false;
        goto cleanup;
    }

    /* 5. subject_name*/
    asn1_buffer_len = 0;
    status = libspdm_x509_get_subject_name(cert, cert_size, NULL, &asn1_buffer_len);
    if (asn1_buffer_len == 0) {
        status = false;
        goto cleanup;
    }

    /* 6. validaity*/
    status = libspdm_x509_get_validity(cert, cert_size, end_cert_from,
                                       &end_cert_from_len, end_cert_to,
                                       &end_cert_to_len);
    if (!status) {
        goto cleanup;
    }

    status = libspdm_internal_x509_date_time_check(
        end_cert_from, end_cert_from_len, end_cert_to, end_cert_to_len);
    if (!status) {
        goto cleanup;
    }

    /* 7. subject_public_key*/
    status = libspdm_asym_get_public_key_from_x509(base_asym_algo, cert, cert_size, &context);
    if (!status) {
        goto cleanup;
    }

    /* 8. key_usage*/
    value = 0;
    status = libspdm_x509_get_key_usage(cert, cert_size, &value);
    if (!status) {
        goto cleanup;
    }
    if (LIBSPDM_CRYPTO_X509_KU_DIGITAL_SIGNATURE & value) {
        status = true;
    } else {
        status = false;
        goto cleanup;
    }

    /* 9. verify SPDM extension OID*/
    status = libspdm_verify_leaf_cert_eku_spdm_OID(cert, cert_size, is_device_cert_model);
    if (!status) {
        goto cleanup;
    }

    /* 10. verify basic constraints*/
    status = libspdm_verify_leaf_cert_basic_constraints(cert, cert_size);
    if (!status) {
        goto cleanup;
    }

    /* 11. extended_key_usage*/
    value = 0;
    status = libspdm_x509_get_extended_key_usage(cert, cert_size, NULL, &value);
    if (value == 0) {
        status = false;
        goto cleanup;
    }
    status = true;

cleanup:
    libspdm_asym_free(base_asym_algo, context);
    return status;
}

/**
 * Return certificate is root cert or not.
 * Certificate is considered as a root certificate if the subjectname equal issuername.
 *
 * @param[in]  cert            Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size        The size of certificate data in bytes.
 *
 * @retval  true   Certificate is self-signed.
 * @retval  false  Certificate is not self-signed.
 **/
bool libspdm_is_root_certificate(const uint8_t *cert, size_t cert_size)
{
    uint8_t issuer_name[LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE];
    size_t issuer_name_len;
    uint8_t subject_name[LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE];
    size_t subject_name_len;
    bool result;

    if (cert == NULL || cert_size == 0) {
        return false;
    }

    /* 1. issuer_name*/
    issuer_name_len = LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE;
    result = libspdm_x509_get_issuer_name(cert, cert_size, issuer_name, &issuer_name_len);
    if (!result) {
        return false;
    }

    /* 2. subject_name*/
    subject_name_len = LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE;
    result = libspdm_x509_get_subject_name(cert, cert_size, subject_name, &subject_name_len);
    if (!result) {
        return false;
    }

    if (issuer_name_len != subject_name_len) {
        return false;
    }
    if (libspdm_const_compare_mem(issuer_name, subject_name, issuer_name_len) != 0) {
        return false;
    }

    return true;
}

/**
 * Retrieve the SubjectAltName from SubjectAltName Bytes.
 *
 * @param[in]      buffer           Pointer to subjectAltName oct bytes.
 * @param[in]      len              size of buffer in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate
 *                                 SubjectAltName. At most name_buffer_size bytes will be
 *                                 written. Maybe NULL in order to determine the size
 *                                 buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 * @param[out]     oid              OID of otherName
 * @param[in,out]  oid_size          the buffersize for required OID
 *
 * @retval true                     get the subjectAltName string successfully
 * @retval failed                   get the subjectAltName string failed
 **/
bool libspdm_get_dmtf_subject_alt_name_from_bytes(
    uint8_t *buffer, const size_t len, char *name_buffer,
    size_t *name_buffer_size, uint8_t *oid,
    size_t *oid_size)
{
    uint8_t *ptr;
    int32_t length;
    size_t obj_len;
    int32_t ret;

    /*copy mem variable*/
    volatile uint8_t* dst;
    const volatile uint8_t* src;
    size_t dst_len;
    size_t src_len;

    length = (int32_t)len;
    ptr = buffer;
    obj_len = 0;

    /* Sequence*/
    ret = libspdm_asn1_get_tag(&ptr, ptr + length, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    ret = libspdm_asn1_get_tag(&ptr, ptr + obj_len, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                               LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);

    ret = libspdm_asn1_get_tag(&ptr, ptr + obj_len, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_OID);
    if (!ret) {
        return false;
    }
    /* CopyData to OID*/
    if (*oid_size < (size_t)obj_len) {
        *oid_size = (size_t)obj_len;
        return false;
    }
    if (oid != NULL) {
        libspdm_copy_mem(oid, *oid_size, ptr, obj_len);
        *oid_size = obj_len;
    }

    /* Move to next element*/
    ptr += obj_len;

    ret = libspdm_asn1_get_tag(&ptr, (uint8_t *)(buffer + length), &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                               LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    ret = libspdm_asn1_get_tag(&ptr, (uint8_t *)(buffer + length), &obj_len,
                               LIBSPDM_CRYPTO_ASN1_UTF8_STRING);
    if (!ret) {
        return false;
    }

    if (*name_buffer_size < (size_t)obj_len + 1) {
        *name_buffer_size = (size_t)obj_len + 1;
        return false;
    }

    /* the src and dst adress are overlap,
    * When the function is called by libspdm_get_dmtf_subject_alt_name.
    * libspdm_copy_mem can not be uesed */
    if ((name_buffer != NULL) && (ptr != NULL)) {
        dst = (volatile uint8_t*) name_buffer;
        src = (const volatile uint8_t*) ptr;
        dst_len = *name_buffer_size;
        src_len = obj_len;

        /* Check for case where "dst_len" may be invalid. Do not zero "dst" in this case. */
        if (dst_len > (SIZE_MAX >> 1)) {
            LIBSPDM_ASSERT(0);
            return false;
        }

        /* Guard against invalid lengths. Zero "dst" in these cases. */
        if (src_len > dst_len ||
            src_len > (SIZE_MAX >> 1)) {
            libspdm_zero_mem(name_buffer, dst_len);
            LIBSPDM_ASSERT(0);
            return false;
        }

        while (src_len-- != 0) {
            *(dst++) = *(src++);
        }

        /*encode name buffer to string*/
        *name_buffer_size = obj_len + 1;
        name_buffer[obj_len] = 0;
        return true;
    }

    return false;
}

/**
 * Retrieve the SubjectAltName from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate
 *                                 SubjectAltName. At most name_buffer_size bytes will be
 *                                 written. Maybe NULL in order to determine the size
 *                                 buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 * @param[out]     oid              OID of otherName
 * @param[in,out]  oid_size          the buffersize for required OID
 *
 * @retval true                     get the subjectAltName string successfully
 * @retval failed                   get the subjectAltName string failed
 **/
bool
libspdm_get_dmtf_subject_alt_name(const uint8_t *cert, const size_t cert_size,
                                  char *name_buffer,
                                  size_t *name_buffer_size,
                                  uint8_t *oid, size_t *oid_size)
{
    bool status;
    size_t extension_data_size;
    uint8_t oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };

    extension_data_size = 0;
    status = libspdm_x509_get_extension_data(cert, cert_size,
                                             oid_subject_alt_name,
                                             sizeof(oid_subject_alt_name), NULL,
                                             &extension_data_size);
    if (status || (extension_data_size == 0)) {
        *name_buffer_size = 0;
        return false;
    }
    if (extension_data_size > *name_buffer_size) {
        *name_buffer_size = extension_data_size;
        return false;
    }
    status =
        libspdm_x509_get_extension_data(cert, cert_size,
                                        oid_subject_alt_name,
                                        sizeof(oid_subject_alt_name),
                                        (uint8_t *)name_buffer, name_buffer_size);
    if (!status) {
        return status;
    }

    return libspdm_get_dmtf_subject_alt_name_from_bytes(
        (uint8_t *)name_buffer, *name_buffer_size, name_buffer,
        name_buffer_size, oid, oid_size);
}

/**
 * This function verifies the integrity of certificate chain data without spdm_cert_chain_t header.
 *
 * @param  cert_chain_data          The certificate chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size      size in bytes of the certificate chain data.
 * @param  base_hash_algo            SPDM base_hash_algo
 * @param  base_asym_algo            SPDM base_asym_algo
 * @param  is_device_cert_model      If true, the cert chain is DeviceCert model;
 *                                   If false, the cert chain is AliasCert model;
 *
 * @retval true  certificate chain data integrity verification pass.
 * @retval false certificate chain data integrity verification fail.
 **/
bool libspdm_verify_cert_chain_data(uint8_t *cert_chain_data, size_t cert_chain_data_size,
                                    uint32_t base_asym_algo, uint32_t base_hash_algo,
                                    bool is_device_cert_model)
{
    const uint8_t *root_cert_buffer;
    size_t root_cert_buffer_size;
    const uint8_t *leaf_cert_buffer;
    size_t leaf_cert_buffer_size;

    if (cert_chain_data_size >
        0xFFFF - (sizeof(spdm_cert_chain_t) + LIBSPDM_MAX_HASH_SIZE)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainData - FAIL (chain size too large) !!!\n"));
        return false;
    }

    if (!libspdm_x509_get_cert_from_cert_chain(
            cert_chain_data, cert_chain_data_size, 0, &root_cert_buffer,
            &root_cert_buffer_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainData - FAIL (get root certificate failed)!!!\n"));
        return false;
    }

    if (!libspdm_x509_verify_cert_chain(root_cert_buffer, root_cert_buffer_size,
                                        cert_chain_data, cert_chain_data_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainData - FAIL (cert chain verify failed)!!!\n"));
        return false;
    }

    if (!libspdm_x509_get_cert_from_cert_chain(
            cert_chain_data, cert_chain_data_size, -1,
            &leaf_cert_buffer, &leaf_cert_buffer_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainData - FAIL (get leaf certificate failed)!!!\n"));
        return false;
    }

    if (!libspdm_x509_certificate_check(leaf_cert_buffer, leaf_cert_buffer_size,
                                        base_asym_algo, base_hash_algo,
                                        is_device_cert_model)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainData - FAIL (leaf certificate check failed)!!!\n"));
        return false;
    }

    return true;
}

/**
 * This function verifies the integrity of certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  cert_chain_buffer              The certificate chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size         size in bytes of the certificate chain buffer.
 * @param  is_device_cert_model           If true, the cert chain is DeviceCert model;
 *                                        If false, the cert chain is AliasCert model;
 *
 * @retval true  certificate chain buffer integrity verification pass.
 * @retval false certificate chain buffer integrity verification fail.
 **/
bool libspdm_verify_certificate_chain_buffer(uint32_t base_hash_algo, uint32_t base_asym_algo,
                                             const void *cert_chain_buffer,
                                             size_t cert_chain_buffer_size,
                                             bool is_device_cert_model)
{
    const uint8_t *cert_chain_data;
    size_t cert_chain_data_size;
    const uint8_t *first_cert_buffer;
    size_t first_cert_buffer_size;
    size_t hash_size;
    uint8_t calc_root_cert_hash[LIBSPDM_MAX_HASH_SIZE];
    const uint8_t *leaf_cert_buffer;
    size_t leaf_cert_buffer_size;
    bool result;

    hash_size = libspdm_get_hash_size(base_hash_algo);

    if (cert_chain_buffer_size > LIBSPDM_MAX_MESSAGE_BUFFER_SIZE) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainBuffer - FAIL (buffer too large) !!!\n"));
        return false;
    }

    if (cert_chain_buffer_size <= sizeof(spdm_cert_chain_t) + hash_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainBuffer - FAIL (buffer too small) !!!\n"));
        return false;
    }

    cert_chain_data = (const uint8_t *)cert_chain_buffer +
                      sizeof(spdm_cert_chain_t) + hash_size;
    cert_chain_data_size =
        cert_chain_buffer_size - sizeof(spdm_cert_chain_t) - hash_size;
    if (!libspdm_x509_get_cert_from_cert_chain(
            cert_chain_data, cert_chain_data_size, 0, &first_cert_buffer,
            &first_cert_buffer_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainBuffer - FAIL (get root certificate failed)!!!\n"));
        return false;
    }

    if (libspdm_is_root_certificate(first_cert_buffer, first_cert_buffer_size)) {
        result = libspdm_hash_all(base_hash_algo, first_cert_buffer, first_cert_buffer_size,
                                  calc_root_cert_hash);
        if (!result) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "!!! VerifyCertificateChainBuffer - FAIL (hash calculation fail) !!!\n"));
            return false;
        }
        if (libspdm_const_compare_mem((const uint8_t *)cert_chain_buffer +
                                      sizeof(spdm_cert_chain_t),
                                      calc_root_cert_hash, hash_size) != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "!!! VerifyCertificateChainBuffer - FAIL (cert root hash mismatch) !!!\n"));
            return false;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainBuffer - PASS (cert root hash match) !!!\n"));
    }

    /*If the number of certificates in the certificate chain is more than 1,
     * other certificates need to be verified.*/
    if (cert_chain_data_size > first_cert_buffer_size) {
        if (!libspdm_x509_verify_cert_chain(first_cert_buffer, first_cert_buffer_size,
                                            cert_chain_data + first_cert_buffer_size,
                                            cert_chain_data_size - first_cert_buffer_size)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "!!! VerifyCertificateChainBuffer - FAIL (cert chain verify failed)!!!\n"));
            return false;
        }
    }

    if (!libspdm_x509_get_cert_from_cert_chain(
            cert_chain_data, cert_chain_data_size, -1,
            &leaf_cert_buffer, &leaf_cert_buffer_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainBuffer - FAIL (get leaf certificate failed)!!!\n"));
        return false;
    }

    if (!libspdm_x509_certificate_check(leaf_cert_buffer, leaf_cert_buffer_size,
                                        base_asym_algo, base_hash_algo,
                                        is_device_cert_model)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! VerifyCertificateChainBuffer - FAIL (leaf certificate check failed)!!!\n"));
        return false;
    }

    return true;
}

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate,
 * based upon negotiated asymmetric or requester asymmetric algorithm.
 *
 *
 * @param  base_hash_algo                SPDM base_hash_algo.
 * @param  base_asym_alg                 SPDM base_asym_algo or req_base_asym_alg.
 * @param  cert_chain_data               Certitiface chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size          size in bytes of the certitiface chain data.
 * @param  public_key                    Pointer to new-generated asymmetric context which contain the retrieved public key component.
 *
 * @retval  true   public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
bool libspdm_get_leaf_cert_public_key_from_cert_chain(uint32_t base_hash_algo,
                                                      uint32_t base_asym_alg,
                                                      uint8_t *cert_chain_data,
                                                      size_t cert_chain_data_size,
                                                      void **public_key)
{
    size_t hash_size;
    const uint8_t *cert_buffer;
    size_t cert_buffer_size;
    bool result;

    hash_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_data = cert_chain_data +
                      sizeof(spdm_cert_chain_t) + hash_size;
    cert_chain_data_size =
        cert_chain_data_size - (sizeof(spdm_cert_chain_t) + hash_size);

    /* Get leaf cert from cert chain */
    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data,
                                                   cert_chain_data_size, -1,
                                                   &cert_buffer, &cert_buffer_size);
    if (!result) {
        return false;
    }

    result = libspdm_asym_get_public_key_from_x509(
        base_asym_alg,
        cert_buffer, cert_buffer_size, public_key);
    if (!result) {
        return false;
    }

    return true;
}

/**
 * Verify req info format refer to PKCS#10
 *
 * @param[in]      req_info              requester info to gen CSR
 * @param[in]      req_info_len          The len of requester info
 *
 * @retval  true    Vaild req info, have three situations:
 *                                  1: no req_info
 *                                  2: good format req_info without attributes
 *                                  3: good format req_info with good format attributes
 * @retval  false   Invaild req info.
 **/
bool libspdm_verify_req_info(uint8_t *req_info, uint16_t req_info_len)
{
    bool ret;
    uint8_t *ptr;
    int32_t length;
    size_t obj_len;
    uint8_t *end;

    length = (int32_t)req_info_len;
    ptr = req_info;
    obj_len = 0;
    end = ptr + length;
    ret = true;

    if (req_info_len == 0) {
        return true;
    }

    /*req_info sequence*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /*integer:version*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    if (!ret) {
        return false;
    } else {
        ptr += obj_len;
    }

    /*sequence:subject name*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    } else {
        ptr += obj_len;
    }

    /*sequence:subject pkinfo*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    } else {
        ptr += obj_len;
    }

    /*[0]: attributes*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                               LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    /*req_info format error, don't have attributes tag*/
    if (!ret) {
        return false;
    }

    /*there is no attributes object*/
    if (ptr == end) {
        return true;
    }

    /*there is some attributes object: 0,1,2 ...*/
    while (ret)
    {
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE |
                                   LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (ret) {
            ptr += obj_len;
        } else {
            break;
        }
    }

    if (ptr == end) {
        return true;
    } else {
        return false;
    }
}
