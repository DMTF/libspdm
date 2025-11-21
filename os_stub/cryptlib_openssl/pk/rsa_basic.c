/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation.
 *
 * This file implements following APIs which provide basic capabilities for RSA:
 * 1) libspdm_rsa_new
 * 2) libspdm_rsa_free
 * 3) libspdm_rsa_set_key
 * 4) rsa_pkcs1_verify
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "key_context.h"

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Helper function to set RSA PSS padding parameters on a context.
 *
 * @param[in]  pctx        EVP_PKEY_CTX to configure
 * @param[in]  evp_md      EVP_MD to use for signature and MGF1
 * @param[in]  salt_len    Salt length for PSS (0 for FIPS, RSA_PSS_SALTLEN_DIGEST for digest length)
 *
 * @retval  true   Parameters set successfully.
 * @retval  false  Failed to set parameters.
 **/
static bool libspdm_rsa_pss_set_params(EVP_PKEY_CTX *pctx, const EVP_MD *evp_md, int salt_len)
{
    int rc;

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    if (rc != 1) {
        return false;
    }
    rc = EVP_PKEY_CTX_set_signature_md(pctx, evp_md);
    if (rc != 1) {
        return false;
    }
    rc = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, evp_md);
    if (rc != 1) {
        return false;
    }
    rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len);
    if (rc != 1) {
        return false;
    }
    return true;
}
#endif /* LIBSPDM_RSA_PSS_SUPPORT */

/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, libspdm_rsa_new() returns NULL.
 *
 **/
void *libspdm_rsa_new(void)
{
    libspdm_key_context *ctx;

    ctx = (libspdm_key_context *)allocate_pool(sizeof(libspdm_key_context));
    if (ctx == NULL) {
        return NULL;
    }
    libspdm_zero_mem(ctx, sizeof(*ctx));
    ctx->evp_pkey = NULL;
    return (void *)ctx;
}

/**
 * Release the specified RSA context.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 *
 **/
void libspdm_rsa_free(void *rsa_context)
{
    libspdm_key_context *ctx;

    if (rsa_context == NULL) {
        return;
    }
    ctx = (libspdm_key_context *)rsa_context;
    EVP_PKEY_free(ctx->evp_pkey);
    free_pool(ctx);
}

/**
 * Sets the tag-designated key component into the established RSA context.
 *
 * This function sets the tag-designated RSA key component into the established
 * RSA context from the user-specified non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If big_number is NULL, then the specified key component in RSA context is cleared.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[in]       big_number   Pointer to octet integer buffer.
 *                             If NULL, then the specified key component in RSA
 *                             context is cleared.
 * @param[in]       bn_size      size of big number buffer in bytes.
 *                             If big_number is NULL, then it is ignored.
 *
 * @retval  true   RSA key component was set successfully.
 * @retval  false  Invalid RSA key component tag.
 *
 **/
bool libspdm_rsa_set_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         const uint8_t *big_number, size_t bn_size)
{
    libspdm_key_context *ctx;
    bool status;
    BIGNUM *bn_n, *bn_n_tmp;
    BIGNUM *bn_e, *bn_e_tmp;
    BIGNUM *bn_d, *bn_d_tmp;
    BIGNUM *bn_p, *bn_p_tmp;
    BIGNUM *bn_q, *bn_q_tmp;
    BIGNUM *bn_dp, *bn_dp_tmp;
    BIGNUM *bn_dq, *bn_dq_tmp;
    BIGNUM *bn_q_inv, *bn_q_inv_tmp;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params;
    EVP_PKEY_CTX *pkctx;
    EVP_PKEY *new_pkey;
    int is_public_only;
    size_t i;

    /* Check input parameters. */
    if (rsa_context == NULL || bn_size > INT_MAX) {
        return false;
    }

    ctx = (libspdm_key_context *)rsa_context;

    /* Handle clear operation (big_number == NULL or bn_size == 0) */
    if (big_number == NULL || bn_size == 0) {
        /* Clear operation: free the EVP_PKEY */
        EVP_PKEY_free(ctx->evp_pkey);
        ctx->evp_pkey = NULL;
        return true;
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

    /* Retrieve the components from EVP_PKEY object. */
    if (ctx->evp_pkey != NULL) {
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n);
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e);
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_D, &bn_d);
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &bn_p);
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &bn_q);
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &bn_dp);
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &bn_dq);
        EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &bn_q_inv);
    }

    /* Set RSA key Components by converting octet string to OpenSSL BN representation.
     * NOTE: For RSA public key (used in signature verification), only public components
     *       (N, e) are needed. */
    switch (key_tag) {
    /* RSA public Modulus (N), public Exponent (e) and Private Exponent (d) */
    case LIBSPDM_RSA_KEY_N:
    case LIBSPDM_RSA_KEY_E:
    case LIBSPDM_RSA_KEY_D:
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
            status = false;
            goto err;
        }

        if (key_tag == LIBSPDM_RSA_KEY_N) {
            bn_n = BN_bin2bn(big_number, (uint32_t)bn_size, bn_n);
        } else if (key_tag == LIBSPDM_RSA_KEY_E) {
            bn_e = BN_bin2bn(big_number, (uint32_t)bn_size, bn_e);
        } else {
            bn_d = BN_bin2bn(big_number, (uint32_t)bn_size, bn_d);
        }
        break;

    /* RSA Secret prime Factor of Modulus (p and q) */
    case LIBSPDM_RSA_KEY_P:
    case LIBSPDM_RSA_KEY_Q:
        if (bn_p == NULL) {
            bn_p = BN_new();
            bn_p_tmp = bn_p;
        }
        if (bn_q == NULL) {
            bn_q = BN_new();
            bn_q_tmp = bn_q;
        }
        if ((bn_p == NULL) || (bn_q == NULL)) {
            status = false;
            goto err;
        }

        if (key_tag == LIBSPDM_RSA_KEY_P) {
            bn_p = BN_bin2bn(big_number, (uint32_t)bn_size, bn_p);
        } else {
            bn_q = BN_bin2bn(big_number, (uint32_t)bn_size, bn_q);
        }
        break;

    /* p's CRT Exponent (== d mod (p - 1)),  q's CRT Exponent (== d mod (q - 1)),
     * and CRT Coefficient (== 1/q mod p) */
    case LIBSPDM_RSA_KEY_DP:
    case LIBSPDM_RSA_KEY_DQ:
    case LIBSPDM_RSA_KEY_Q_INV:
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
            status = false;
            goto err;
        }

        if (key_tag == LIBSPDM_RSA_KEY_DP) {
            bn_dp = BN_bin2bn(big_number, (uint32_t)bn_size, bn_dp);
        } else if (key_tag == LIBSPDM_RSA_KEY_DQ) {
            bn_dq = BN_bin2bn(big_number, (uint32_t)bn_size, bn_dq);
        } else {
            bn_q_inv = BN_bin2bn(big_number, (uint32_t)bn_size, bn_q_inv);
        }
        break;

    default:
        status = false;
        goto err;
    }

    /* Build OSSL_PARAM array from all components */
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        status = false;
        goto err;
    }

    /* Push all components to builder */
    if (bn_n != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
    }
    if (bn_e != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);
    }
    if (bn_d != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, bn_d);
    }
    if (bn_p != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, bn_p);
    }
    if (bn_q != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, bn_q);
    }
    if (bn_dp != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, bn_dp);
    }
    if (bn_dq != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, bn_dq);
    }
    if (bn_q_inv != NULL) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, bn_q_inv);
    }

    /* Convert to params */
    params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (params == NULL) {
        status = false;
        goto err;
    }

    /* Build new EVP_PKEY from parameters */
    pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pkctx == NULL) {
        OSSL_PARAM_free(params);
        status = false;
        goto err;
    }
    if (EVP_PKEY_fromdata_init(pkctx) != 1) {
        EVP_PKEY_CTX_free(pkctx);
        OSSL_PARAM_free(params);
        status = false;
        goto err;
    }

    /* Determine if we have private key components */
    is_public_only = true;
    for (i = 0; params[i].key != NULL; i++) {
        if (strcmp(params[i].key, OSSL_PKEY_PARAM_RSA_D) == 0 ||
            strcmp(params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR1) == 0 ||
            strcmp(params[i].key, OSSL_PKEY_PARAM_RSA_FACTOR2) == 0) {
            is_public_only = false;
            break;
        }
    }

    new_pkey = NULL;
    if (!is_public_only) {
        (void)EVP_PKEY_fromdata(pkctx, &new_pkey, EVP_PKEY_KEYPAIR, params);
    }
    if (new_pkey == NULL) {
        (void)EVP_PKEY_fromdata(pkctx, &new_pkey, EVP_PKEY_PUBLIC_KEY, params);
    }

    EVP_PKEY_CTX_free(pkctx);
    OSSL_PARAM_free(params);

    if (new_pkey == NULL) {
        status = false;
        goto err;
    }

    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = new_pkey;
    status = true;

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
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_RSA_SSA_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in PKCS1-v1_5.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pkcs1_verify_with_nid(void *rsa_context, size_t hash_nid,
                                       const uint8_t *message_hash,
                                       size_t hash_size, const uint8_t *signature,
                                       size_t sig_size)
{
    EVP_MD *evp_md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc;
    bool result = false;
    libspdm_key_context *ctx = (libspdm_key_context *)rsa_context;

    /* Check input parameters.*/

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    if (ctx == NULL || ctx->evp_pkey == NULL) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA512", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-512", NULL);
        break;

    default:
        return false;
    }

    if (evp_md == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        EVP_MD_free(evp_md);
        return false;
    }

    {
        OSSL_PARAM params[2];
        const char *md_name = EVP_MD_get0_name(evp_md);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_verify_init_ex(pctx, params);
        if (rc != 1) {
            EVP_MD_free(evp_md);
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    rc = EVP_PKEY_CTX_set_signature_md(pctx, (const EVP_MD *)evp_md);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    if (rc == 1) {
        result = true;
    }

    EVP_MD_free(evp_md);
    EVP_PKEY_CTX_free(pctx);
    return result;
}
#endif /* LIBSPDM_RSA_SSA_SUPPORT */

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pss_verify(void *rsa_context, size_t hash_nid,
                            const uint8_t *message_hash, size_t hash_size,
                            const uint8_t *signature, size_t sig_size)
{
    EVP_MD *evp_md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc;
    bool result = false;
    libspdm_key_context *ctx = (libspdm_key_context *)rsa_context;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    if (ctx == NULL || ctx->evp_pkey == NULL) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA512", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-512", NULL);
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    if (evp_md == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        EVP_MD_free(evp_md);
        return false;
    }

    {
        OSSL_PARAM params[2];
        const char *md_name = EVP_MD_get0_name(evp_md);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_verify_init_ex(pctx, params);
        if (rc != 1) {
            EVP_MD_free(evp_md);
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    if (!libspdm_rsa_pss_set_params(pctx, evp_md, RSA_PSS_SALTLEN_DIGEST)) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    if (rc == 1) {
        result = true;
    }

    EVP_MD_free(evp_md);
    EVP_PKEY_CTX_free(pctx);
    return result;
}

#if LIBSPDM_FIPS_MODE
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2 for FIPS test.
 *
 * The salt length is zero.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pss_verify_fips(void *rsa_context, size_t hash_nid,
                                 const uint8_t *message_hash, size_t hash_size,
                                 const uint8_t *signature, size_t sig_size)
{
    EVP_MD *evp_md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc;
    bool result = false;
    libspdm_key_context *ctx = (libspdm_key_context *)rsa_context;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    if (ctx == NULL || ctx->evp_pkey == NULL) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA512", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-512", NULL);
        break;

    default:
        return false;
    }

    if (evp_md == NULL) {
        return false;
    }

    if (ctx == NULL || ctx->evp_pkey == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    {
        OSSL_PARAM params[2];
        const char *md_name = EVP_MD_get0_name(evp_md);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_verify_init_ex(pctx, params);
        if (rc != 1) {
            EVP_MD_free(evp_md);
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    /* salt len is 0 for FIPS test */
    if (!libspdm_rsa_pss_set_params(pctx, evp_md, 0)) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    if (rc == 1) {
        result = true;
    }

    EVP_MD_free(evp_md);
    EVP_PKEY_CTX_free(pctx);
    return result;
}
#endif /*LIBSPDM_FIPS_MODE*/

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
