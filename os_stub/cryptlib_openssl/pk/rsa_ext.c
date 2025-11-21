/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation.
 *
 * This file implements following APIs which provide more capabilities for RSA:
 * 1) libspdm_rsa_get_key
 * 2) libspdm_rsa_generate_key
 * 3) libspdm_rsa_check_key
 * 4) rsa_pkcs1_sign
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>
#include "key_context.h"

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

/**
 * Helper function to perform RSA signature with specified padding.
 *
 * @param[in]      ctx           libspdm_key_context containing EVP_PKEY
 * @param[in]      evp_md        EVP_MD to use for signature
 * @param[in]      padding       RSA padding mode (RSA_PKCS1_PADDING or RSA_PKCS1_PSS_PADDING)
 * @param[in]      salt_len      Salt length for PSS (ignored for PKCS1)
 * @param[in]      message_hash  Pointer to message hash to be signed
 * @param[in]      hash_size     Size of the message hash in bytes
 * @param[out]     signature     Pointer to buffer to receive signature
 * @param[in, out] sig_size      On input, size of signature buffer; on output, size of signature
 *
 * @retval  true   Signature generated successfully.
 * @retval  false  Signature generation failed.
 **/
static bool libspdm_rsa_sign_with_padding(libspdm_key_context *ctx, const EVP_MD *evp_md,
                                          int padding, int salt_len,
                                          const uint8_t *message_hash, size_t hash_size,
                                          uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_len;
    int rc;
    bool result = false;

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    {
        OSSL_PARAM params[2];
        const char *md_name = EVP_MD_get0_name(evp_md);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_sign_init_ex(pctx, params);
        if (rc != 1) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, padding);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    /* For PSS padding, set additional parameters */
    if (padding == RSA_PKCS1_PSS_PADDING) {
        rc = EVP_PKEY_CTX_set_signature_md(pctx, evp_md);
        if (rc != 1) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
        rc = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, evp_md);
        if (rc != 1) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
        rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len);
        if (rc != 1) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    out_len = *sig_size;
    rc = EVP_PKEY_sign(pctx, signature, &out_len, message_hash, hash_size);
    if (rc == 1) {
        *sig_size = out_len;
        result = true;
    }

    EVP_PKEY_CTX_free(pctx);
    return result;
}
/**
 * Gets the tag-designated RSA key component from the established RSA context.
 *
 * This function retrieves the tag-designated RSA key component from the
 * established RSA context as a non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If specified key component has not been set or has been cleared, then returned
 * bn_size is set to 0.
 * If the big_number buffer is too small to hold the contents of the key, false
 * is returned and bn_size is set to the required buffer size to obtain the key.
 *
 * If rsa_context is NULL, then return false.
 * If bn_size is NULL, then return false.
 * If bn_size is large enough but big_number is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[out]      big_number   Pointer to octet integer buffer.
 * @param[in, out]  bn_size      On input, the size of big number buffer in bytes.
 *                             On output, the size of data returned in big number buffer in bytes.
 *
 * @retval  true   RSA key component was retrieved successfully.
 * @retval  false  Invalid RSA key component tag.
 * @retval  false  bn_size is too small.
 *
 **/
bool libspdm_rsa_get_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         uint8_t *big_number, size_t *bn_size)
{
    libspdm_key_context *ctx;
    BIGNUM *bn_key = NULL;
    size_t size;
    const char *param_name;

    if (rsa_context == NULL || bn_size == NULL) {
        return false;
    }
    ctx = (libspdm_key_context *)rsa_context;

    if (ctx->evp_pkey == NULL) {
        if (big_number == NULL) {
            *bn_size = 0;
            return true;
        }
        return false;
    }

    /* Determine parameter name */
    switch (key_tag) {
    case LIBSPDM_RSA_KEY_N:
        param_name = OSSL_PKEY_PARAM_RSA_N;
        break;
    case LIBSPDM_RSA_KEY_E:
        param_name = OSSL_PKEY_PARAM_RSA_E;
        break;
    case LIBSPDM_RSA_KEY_D:
        param_name = OSSL_PKEY_PARAM_RSA_D;
        break;
    case LIBSPDM_RSA_KEY_P:
        param_name = OSSL_PKEY_PARAM_RSA_FACTOR1;
        break;
    case LIBSPDM_RSA_KEY_Q:
        param_name = OSSL_PKEY_PARAM_RSA_FACTOR2;
        break;
    case LIBSPDM_RSA_KEY_DP:
        param_name = OSSL_PKEY_PARAM_RSA_EXPONENT1;
        break;
    case LIBSPDM_RSA_KEY_DQ:
        param_name = OSSL_PKEY_PARAM_RSA_EXPONENT2;
        break;
    case LIBSPDM_RSA_KEY_Q_INV:
        param_name = OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
        break;
    default:
        return false;
    }

    /* Get BIGNUM from EVP_PKEY */
    EVP_PKEY_get_bn_param(ctx->evp_pkey, param_name, &bn_key);

    size = (bn_key != NULL) ? (size_t)BN_num_bytes(bn_key) : 0;

    if (big_number == NULL) {
        /* Match legacy behavior expected by unit tests:
         * - If component exists: return false and set required size
         * - If component not set: return true with size = 0 */
        if (bn_key == NULL) {
            *bn_size = 0;
            BN_free(bn_key);
            return true;
        }
        *bn_size = size;
        BN_free(bn_key);
        return false;
    }
    if (*bn_size < size) {
        *bn_size = size;
        BN_free(bn_key);
        return false;
    }
    if (bn_key == NULL) {
        *bn_size = 0;
        return true;
    }
    *bn_size = BN_bn2bin(bn_key, big_number);
    BN_free(bn_key);
    return true;
}

/**
 * Generates RSA key components.
 *
 * This function generates RSA key components. It takes RSA public exponent E and
 * length in bits of RSA modulus N as input, and generates all key components.
 * If public_exponent is NULL, the default RSA public exponent (0x10001) will be used.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context           Pointer to RSA context being set.
 * @param[in]       modulus_length        length of RSA modulus N in bits.
 * @param[in]       public_exponent       Pointer to RSA public exponent.
 * @param[in]       public_exponent_size   size of RSA public exponent buffer in bytes.
 *
 * @retval  true   RSA key component was generated successfully.
 * @retval  false  Invalid RSA key component tag.
 *
 **/
bool libspdm_rsa_generate_key(void *rsa_context, size_t modulus_length,
                              const uint8_t *public_exponent,
                              size_t public_exponent_size)
{
    libspdm_key_context *ctx;
    EVP_PKEY_CTX *pkctx;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params;
    BIGNUM *bn_e = NULL;
    int ok;

    if (rsa_context == NULL || modulus_length > INT_MAX ||
        public_exponent_size > INT_MAX) {
        return false;
    }

    ctx = (libspdm_key_context *)rsa_context;
    pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pkctx == NULL) {
        return false;
    }
    if (EVP_PKEY_keygen_init(pkctx) != 1) {
        EVP_PKEY_CTX_free(pkctx);
        return false;
    }
    /* build params: bits + e */
    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        EVP_PKEY_CTX_free(pkctx);
        return false;
    }
    if (!OSSL_PARAM_BLD_push_uint(bld, "bits", (unsigned int)modulus_length)) {
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(pkctx);
        return false;
    }
    /* public exponent */
    if (public_exponent == NULL) {
        bn_e = BN_new();
        if (bn_e == NULL || BN_set_word(bn_e, 0x10001) != 1) {
            BN_free(bn_e);
            OSSL_PARAM_BLD_free(bld);
            EVP_PKEY_CTX_free(pkctx);
            return false;
        }
    } else {
        bn_e = BN_bin2bn(public_exponent, (int)public_exponent_size, NULL);
        if (bn_e == NULL) {
            OSSL_PARAM_BLD_free(bld);
            EVP_PKEY_CTX_free(pkctx);
            return false;
        }
    }
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e)) {
        BN_free(bn_e);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(pkctx);
        return false;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (params == NULL) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(pkctx);
        return false;
    }
    ok = EVP_PKEY_CTX_set_params(pkctx, params);
    OSSL_PARAM_free(params);
    if (ok != 1) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(pkctx);
        return false;
    }

    /* Clear old pkey before generating new key */
    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = NULL;

    ok = EVP_PKEY_generate(pkctx, &ctx->evp_pkey);
    EVP_PKEY_CTX_free(pkctx);
    BN_free(bn_e);
    if (ok != 1) {
        return false;
    }
    return true;
}

/**
 * Validates key components of RSA context.
 * NOTE: This function performs integrity checks on all the RSA key material, so
 *      the RSA key structure must contain all the private key data.
 *
 * This function validates key components of RSA context in following aspects:
 * - Whether p is a prime
 * - Whether q is a prime
 * - Whether n = p * q
 * - Whether d*e = 1  mod lcm(p-1,q-1)
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in]  rsa_context  Pointer to RSA context to check.
 *
 * @retval  true   RSA key components are valid.
 * @retval  false  RSA key components are not valid.
 *
 **/
bool libspdm_rsa_check_key(void *rsa_context)
{
    libspdm_key_context *ctx;
    EVP_PKEY_CTX *pkctx;
    int ok;

    if (rsa_context == NULL) {
        return false;
    }
    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }
    pkctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->evp_pkey, NULL);
    if (pkctx == NULL) {
        return false;
    }
    ok = EVP_PKEY_check(pkctx);
    EVP_PKEY_CTX_free(pkctx);
    return ok == 1;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_RSA_SSA_SUPPORT
/**
 * Carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      rsa_context   Pointer to RSA context for signature generation.
 * @param[in]      hash_nid      hash NID
 * @param[in]      message_hash  Pointer to octet message hash to be signed.
 * @param[in]      hash_size     size of the message hash in bytes.
 * @param[out]     signature    Pointer to buffer to receive RSA PKCS1-v1_5 signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                             On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in PKCS1-v1_5.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_pkcs1_sign_with_nid(void *rsa_context, size_t hash_nid,
                                     const uint8_t *message_hash,
                                     size_t hash_size, uint8_t *signature,
                                     size_t *sig_size)
{
    libspdm_key_context *ctx = (libspdm_key_context *)rsa_context;
    EVP_MD *evp_md = NULL;
    bool result = false;

    if (rsa_context == NULL || message_hash == NULL || sig_size == NULL) {
        return false;
    }
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    /* Determine required signature size to match legacy behavior */
    {
        size_t need = (size_t)EVP_PKEY_size(ctx->evp_pkey);
        if ((signature == NULL) || (*sig_size < need)) {
            *sig_size = need;
            return false;
        }
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

    result = libspdm_rsa_sign_with_padding(ctx, evp_md, RSA_PKCS1_PADDING, 0,
                                           message_hash, hash_size, signature, sig_size);

    EVP_MD_free(evp_md);
    return result;
}
#endif /* LIBSPDM_RSA_SSA_SUPPORT */

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * @param[in]       rsa_context   Pointer to RSA context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature    Pointer to buffer to receive RSA-SSA PSS signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in RSA-SSA PSS.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_rsa_pss_sign(void *rsa_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          uint8_t *signature, size_t *sig_size)
{
    libspdm_key_context *ctx = (libspdm_key_context *)rsa_context;
    EVP_MD *evp_md = NULL;
    bool result = false;

    if (rsa_context == NULL || message_hash == NULL || sig_size == NULL) {
        return false;
    }
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    /* Determine required signature size to match legacy behavior */
    {
        size_t need = (size_t)EVP_PKEY_size(ctx->evp_pkey);
        if ((signature == NULL) || (*sig_size < need)) {
            *sig_size = need;
            return false;
        }
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

    result = libspdm_rsa_sign_with_padding(ctx, evp_md, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST,
                                           message_hash, hash_size, signature, sig_size);

    EVP_MD_free(evp_md);
    return result;
}

#if LIBSPDM_FIPS_MODE
/**
 * Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme for FIPS test.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2 for FIPS test.
 *
 * The salt length is zero.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * @param[in]       rsa_context   Pointer to RSA context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature    Pointer to buffer to receive RSA-SSA PSS signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in RSA-SSA PSS.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_rsa_pss_sign_fips(void *rsa_context, size_t hash_nid,
                               const uint8_t *message_hash, size_t hash_size,
                               uint8_t *signature, size_t *sig_size)
{
    libspdm_key_context *ctx = (libspdm_key_context *)rsa_context;
    EVP_MD *evp_md = NULL;
    bool result = false;

    if (rsa_context == NULL || message_hash == NULL || sig_size == NULL) {
        return false;
    }
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    /* Determine required signature size to match legacy behavior */
    {
        size_t need = (size_t)EVP_PKEY_size(ctx->evp_pkey);
        if ((signature == NULL) || (*sig_size < need)) {
            *sig_size = need;
            return false;
        }
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

    /* salt len is 0 for FIPS */
    result = libspdm_rsa_sign_with_padding(ctx, evp_md, RSA_PKCS1_PSS_PADDING, 0,
                                           message_hash, hash_size, signature, sig_size);

    EVP_MD_free(evp_md);
    return result;
}
#endif /*LIBSPDM_FIPS_MODE*/

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
