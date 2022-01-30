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

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, rsa_new() returns NULL.
 *
 **/
void *rsa_new(void)
{

    /* Allocates & Initializes RSA context by OpenSSL RSA_new()*/

    return (void *)RSA_new();
}

/**
 * Release the specified RSA context.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 *
 **/
void rsa_free(IN void *rsa_context)
{

    /* Free OpenSSL RSA context*/

    RSA_free((RSA *)rsa_context);
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
    RSA *rsa_key;
    boolean status;
    BIGNUM *bn_n, *bn_n_tmp;
    BIGNUM *bn_e, *bn_e_tmp;
    BIGNUM *bn_d, *bn_d_tmp;
    BIGNUM *bn_p, *bn_p_tmp;
    BIGNUM *bn_q, *bn_q_tmp;
    BIGNUM *bn_dp, *bn_dp_tmp;
    BIGNUM *bn_dq, *bn_dq_tmp;
    BIGNUM *bn_q_inv, *bn_q_inv_tmp;


    /* Check input parameters.*/

    if (rsa_context == NULL || bn_size > INT_MAX) {
        return FALSE;
    }

    bn_n = NULL;
    bn_e = NULL;
    bn_d = NULL;
    bn_p = NULL;
    bn_q = NULL;
    bn_dp = NULL;
    bn_dq = NULL;
    bn_q_inv = NULL;

    bn_n_tmp = NULL;
    bn_e_tmp = NULL;
    bn_d_tmp = NULL;
    bn_p_tmp = NULL;
    bn_q_tmp = NULL;
    bn_dp_tmp = NULL;
    bn_dq_tmp = NULL;
    bn_q_inv_tmp = NULL;


    /* Retrieve the components from RSA object.*/

    rsa_key = (RSA *)rsa_context;
    RSA_get0_key(rsa_key, (const BIGNUM **)&bn_n, (const BIGNUM **)&bn_e,
                 (const BIGNUM **)&bn_d);
    RSA_get0_factors(rsa_key, (const BIGNUM **)&bn_p,
                     (const BIGNUM **)&bn_q);
    RSA_get0_crt_params(rsa_key, (const BIGNUM **)&bn_dp,
                        (const BIGNUM **)&bn_dq,
                        (const BIGNUM **)&bn_q_inv);


    /* Set RSA key Components by converting octet string to OpenSSL BN representation.
     * NOTE: For RSA public key (used in signature verification), only public components
     *       (N, e) are needed.*/

    switch (key_tag) {

    /* RSA public Modulus (N), public Exponent (e) and Private Exponent (d)*/

    case RSA_KEY_N:
    case RSA_KEY_E:
    case RSA_KEY_D:
        if (bn_n == NULL) {
            bn_n = BN_new();
            bn_n_tmp = bn_n;
        }
        if (bn_e == NULL) {
            bn_e = BN_new();
            bn_e_tmp = bn_e;
        }
        if (bn_d == NULL) {
            bn_d = BN_new();
            bn_d_tmp = bn_d;
        }

        if ((bn_n == NULL) || (bn_e == NULL) || (bn_d == NULL)) {
            status = FALSE;
            goto err;
        }

        switch (key_tag) {
        case RSA_KEY_N:
            bn_n = BN_bin2bn(big_number, (uint32_t)bn_size, bn_n);
            break;
        case RSA_KEY_E:
            bn_e = BN_bin2bn(big_number, (uint32_t)bn_size, bn_e);
            break;
        case RSA_KEY_D:
            bn_d = BN_bin2bn(big_number, (uint32_t)bn_size, bn_d);
            break;
        default:
            status = FALSE;
            goto err;
        }
        if (RSA_set0_key(rsa_key, BN_dup(bn_n), BN_dup(bn_e),
                         BN_dup(bn_d)) == 0) {
            status = FALSE;
            goto err;
        }

        break;


    /* RSA Secret prime Factor of Modulus (p and q)*/

    case RSA_KEY_P:
    case RSA_KEY_Q:
        if (bn_p == NULL) {
            bn_p = BN_new();
            bn_p_tmp = bn_p;
        }
        if (bn_q == NULL) {
            bn_q = BN_new();
            bn_q_tmp = bn_q;
        }
        if ((bn_p == NULL) || (bn_q == NULL)) {
            status = FALSE;
            goto err;
        }

        switch (key_tag) {
        case RSA_KEY_P:
            bn_p = BN_bin2bn(big_number, (uint32_t)bn_size, bn_p);
            break;
        case RSA_KEY_Q:
            bn_q = BN_bin2bn(big_number, (uint32_t)bn_size, bn_q);
            break;
        default:
            status = FALSE;
            goto err;
        }
        if (RSA_set0_factors(rsa_key, BN_dup(bn_p), BN_dup(bn_q)) ==
            0) {
            status = FALSE;
            goto err;
        }

        break;


    /* p's CRT Exponent (== d mod (p - 1)),  q's CRT Exponent (== d mod (q - 1)),
     * and CRT Coefficient (== 1/q mod p)*/

    case RSA_KEY_DP:
    case RSA_KEY_DQ:
    case RSA_KEY_Q_INV:
        if (bn_dp == NULL) {
            bn_dp = BN_new();
            bn_dp_tmp = bn_dp;
        }
        if (bn_dq == NULL) {
            bn_dq = BN_new();
            bn_dq_tmp = bn_dq;
        }
        if (bn_q_inv == NULL) {
            bn_q_inv = BN_new();
            bn_q_inv_tmp = bn_q_inv;
        }
        if ((bn_dp == NULL) || (bn_dq == NULL) || (bn_q_inv == NULL)) {
            status = FALSE;
            goto err;
        }

        switch (key_tag) {
        case RSA_KEY_DP:
            bn_dp = BN_bin2bn(big_number, (uint32_t)bn_size, bn_dp);
            break;
        case RSA_KEY_DQ:
            bn_dq = BN_bin2bn(big_number, (uint32_t)bn_size, bn_dq);
            break;
        case RSA_KEY_Q_INV:
            bn_q_inv = BN_bin2bn(big_number, (uint32_t)bn_size,
                                 bn_q_inv);
            break;
        default:
            status = FALSE;
            goto err;
        }
        if (RSA_set0_crt_params(rsa_key, BN_dup(bn_dp), BN_dup(bn_dq),
                                BN_dup(bn_q_inv)) == 0) {
            status = FALSE;
            goto err;
        }

        break;

    default:
        status = FALSE;
        goto err;
    }

    status = TRUE;

err:
    BN_free(bn_n_tmp);
    BN_free(bn_e_tmp);
    BN_free(bn_d_tmp);
    BN_free(bn_p_tmp);
    BN_free(bn_q_tmp);
    BN_free(bn_dp_tmp);
    BN_free(bn_dq_tmp);
    BN_free(bn_q_inv_tmp);

    return status;
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
    int32_t digest_type;
    uint8_t *sig_buf;


    /* Check input parameters.*/

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return FALSE;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return FALSE;
    }

    switch (hash_nid) {
    case CRYPTO_NID_SHA256:
        digest_type = NID_sha256;
        if (hash_size != SHA256_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA384:
        digest_type = NID_sha384;
        if (hash_size != SHA384_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA512:
        digest_type = NID_sha512;
        if (hash_size != SHA512_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA3_256:
        digest_type = NID_sha3_256;
        if (hash_size != SHA3_256_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA3_384:
        digest_type = NID_sha3_384;
        if (hash_size != SHA3_384_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA3_512:
        digest_type = NID_sha3_512;
        if (hash_size != SHA3_512_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    default:
        return FALSE;
    }

    sig_buf = (uint8_t *)signature;
    return (boolean)RSA_verify(digest_type, message_hash, (uint32_t)hash_size,
                               sig_buf, (uint32_t)sig_size,
                               (RSA *)rsa_context);
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
    RSA *rsa;
    boolean result;
    int32_t size;
    const EVP_MD *evp_md;
    void *buffer;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return FALSE;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return FALSE;
    }

    rsa = rsa_context;
    size = RSA_size(rsa);
    if (sig_size != (uintn)size) {
        return FALSE;
    }

    switch (hash_nid) {
    case CRYPTO_NID_SHA256:
        evp_md = EVP_sha256();
        if (hash_size != SHA256_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA384:
        evp_md = EVP_sha384();
        if (hash_size != SHA384_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA512:
        evp_md = EVP_sha512();
        if (hash_size != SHA512_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA3_256:
        evp_md = EVP_sha3_256();
        if (hash_size != SHA3_256_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA3_384:
        evp_md = EVP_sha3_384();
        if (hash_size != SHA3_384_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    case CRYPTO_NID_SHA3_512:
        evp_md = EVP_sha3_512();
        if (hash_size != SHA3_512_DIGEST_SIZE) {
            return FALSE;
        }
        break;

    default:
        return FALSE;
    }

    buffer = allocate_pool(size);
    if (buffer == NULL) {
        return FALSE;
    }

    size = RSA_public_decrypt(size, signature, buffer, rsa, RSA_NO_PADDING);
    if (size <= 0) {
        free_pool(buffer);
        return FALSE;
    }
    ASSERT(sig_size == (uintn)size);

    result = (boolean)RSA_verify_PKCS1_PSS(rsa, message_hash, evp_md,
                                           buffer, RSA_PSS_SALTLEN_DIGEST);
    free_pool(buffer);

    return result;
}
