/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation.
 *
 * This file implements following APIs which provide basic capabilities for RSA:
 * 1) rsa_new
 * 2) rsa_free
 * 3) rsa_set_key
 * 4) rsa_pkcs1_verify
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"

#include <mbedtls/rsa.h>

/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, rsa_new() returns NULL.
 *
 **/
void *rsa_new(void)
{
    void *rsa_context;

    rsa_context = allocate_zero_pool(sizeof(mbedtls_rsa_context));
    if (rsa_context == NULL) {
        return rsa_context;
    }

    mbedtls_rsa_init(rsa_context, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    return rsa_context;
}

/**
 * Release the specified RSA context.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 *
 **/
void rsa_free(IN void *rsa_context)
{
    mbedtls_rsa_free(rsa_context);
    free_pool(rsa_context);
}

/**
 * Sets the tag-designated key component into the established RSA context.
 *
 * This function sets the tag-designated RSA key component into the established
 * RSA context from the user-specified non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If big_number is NULL, then the specified key component in RSA context is cleared.
 *
 * If rsa_context is NULL, then return FALSE.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[in]       big_number   Pointer to octet integer buffer.
 *                             If NULL, then the specified key component in RSA
 *                             context is cleared.
 * @param[in]       bn_size      size of big number buffer in bytes.
 *                             If big_number is NULL, then it is ignored.
 *
 * @retval  TRUE   RSA key component was set successfully.
 * @retval  FALSE  Invalid RSA key component tag.
 *
 **/
boolean rsa_set_key(IN OUT void *rsa_context, IN rsa_key_tag_t key_tag,
                    IN const uint8_t *big_number, IN uintn bn_size)
{
    mbedtls_rsa_context *rsa_key;
    int32_t ret;
    mbedtls_mpi value;


    /* Check input parameters.*/

    if (rsa_context == NULL || bn_size > INT_MAX) {
        return FALSE;
    }

    mbedtls_mpi_init(&value);

    rsa_key = (mbedtls_rsa_context *)rsa_context;

    /* if big_number is Null clear*/
    if (big_number) {
        ret = mbedtls_mpi_read_binary(&value, big_number, bn_size);
        if (ret != 0) {
            return FALSE;
        }
    }

    switch (key_tag) {
    case RSA_KEY_N:
        ret = mbedtls_rsa_import(rsa_key, &value, NULL, NULL, NULL,
                                 NULL);
        break;
    case RSA_KEY_E:
        ret = mbedtls_rsa_import(rsa_key, NULL, NULL, NULL, NULL,
                                 &value);
        break;
    case RSA_KEY_D:
        ret = mbedtls_rsa_import(rsa_key, NULL, NULL, NULL, &value,
                                 NULL);
        break;
    case RSA_KEY_Q:
        ret = mbedtls_rsa_import(rsa_key, NULL, NULL, &value, NULL,
                                 NULL);
        break;
    case RSA_KEY_P:
        ret = mbedtls_rsa_import(rsa_key, NULL, &value, NULL, NULL,
                                 NULL);
        break;
    case RSA_KEY_DP:
    case RSA_KEY_DQ:
    case RSA_KEY_Q_INV:
    default:
        ret = -1;
        break;
    }
    mbedtls_rsa_complete(rsa_key);
    return ret == 0;
}

/**
 * Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 *
 * If rsa_context is NULL, then return FALSE.
 * If message_hash is NULL, then return FALSE.
 * If signature is NULL, then return FALSE.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  TRUE   Valid signature encoded in PKCS1-v1_5.
 * @retval  FALSE  Invalid signature or invalid RSA context.
 *
 **/
boolean rsa_pkcs1_verify_with_nid(IN void *rsa_context, IN uintn hash_nid,
                                  IN const uint8_t *message_hash,
                                  IN uintn hash_size, IN const uint8_t *signature,
                                  IN uintn sig_size)
{
    int32_t ret;
    mbedtls_md_type_t md_alg;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return FALSE;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return FALSE;
    }

    switch (hash_nid) {
    case CRYPTO_NID_SHA256:
        md_alg = MBEDTLS_MD_SHA256;
        if (hash_size != SHA256_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA384:
        md_alg = MBEDTLS_MD_SHA384;
        if (hash_size != SHA384_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA512:
        md_alg = MBEDTLS_MD_SHA512;
        if (hash_size != SHA512_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    default:
        return FALSE;
    }

    if (mbedtls_rsa_get_len(rsa_context) != sig_size) {
        return FALSE;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V15, md_alg);

    ret = mbedtls_rsa_pkcs1_verify(rsa_context, NULL, NULL,
                                   MBEDTLS_RSA_PUBLIC, md_alg,
                                   (uint32_t)hash_size, message_hash,
                                   signature);
    if (ret != 0) {
        return FALSE;
    }
    return TRUE;
}

/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If rsa_context is NULL, then return FALSE.
 * If message_hash is NULL, then return FALSE.
 * If signature is NULL, then return FALSE.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  TRUE   Valid signature encoded in RSA-SSA PSS.
 * @retval  FALSE  Invalid signature or invalid RSA context.
 *
 **/
boolean rsa_pss_verify(IN void *rsa_context, IN uintn hash_nid,
                       IN const uint8_t *message_hash, IN uintn hash_size,
                       IN const uint8_t *signature, IN uintn sig_size)
{
    int32_t ret;
    mbedtls_md_type_t md_alg;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return FALSE;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return FALSE;
    }

    switch (hash_nid) {
    case CRYPTO_NID_SHA256:
        md_alg = MBEDTLS_MD_SHA256;
        if (hash_size != SHA256_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA384:
        md_alg = MBEDTLS_MD_SHA384;
        if (hash_size != SHA384_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA512:
        md_alg = MBEDTLS_MD_SHA512;
        if (hash_size != SHA512_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    default:
        return FALSE;
    }

    if (mbedtls_rsa_get_len(rsa_context) != sig_size) {
        return FALSE;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V21, md_alg);

    ret = mbedtls_rsa_rsassa_pss_verify(rsa_context, NULL, NULL,
                                        MBEDTLS_RSA_PUBLIC, md_alg,
                                        (uint32_t)hash_size, message_hash,
                                        signature);
    if (ret != 0) {
        return FALSE;
    }
    return TRUE;
}
