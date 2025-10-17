/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <crypto/evp.h>
#include <crypto/slh_dsa.h>

#if LIBSPDM_SLH_DSA_SUPPORT

size_t libspdm_slhdsa_type_name_to_nid(const char *type_name);

/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_slhdsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    uint32_t final_pri_key_size;
    EVP_PKEY *evp_key;
    EVP_PKEY *new_evp_key;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    evp_key = (EVP_PKEY *)dsa_context;
    switch (libspdm_slhdsa_type_name_to_nid(EVP_PKEY_get0_type_name(evp_key))) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
        final_pri_key_size = 64;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
        final_pri_key_size = 64;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
        final_pri_key_size = 96;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
        final_pri_key_size = 96;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
        final_pri_key_size = 128;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        final_pri_key_size = 128;
        break;
    default:
        return false;
    }

    if (final_pri_key_size != key_size) {
        return false;
    }

    new_evp_key = EVP_PKEY_new_raw_private_key_ex(NULL, EVP_PKEY_get0_type_name(evp_key), NULL,
                                                  key_data, key_size);
    if (new_evp_key == NULL) {
        return false;
    }

    if (evp_keymgmt_util_copy(evp_key, new_evp_key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 1) {
        EVP_PKEY_free(new_evp_key);
        return false;
    }

    EVP_PKEY_free(new_evp_key);
    return true;
}

/**
 * Carries out the SLHDSA signature generation.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The SLHDSA signing context.
 * @param[in]      context_size  Size of SLHDSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_slhdsa_sign(void *dsa_context,
                         const uint8_t *context, size_t context_size,
                         const uint8_t *message, size_t message_size,
                         uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t final_sig_size;
    int32_t result;
    OSSL_PARAM params[2];

    if (dsa_context == NULL || message == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)dsa_context;
    switch (libspdm_slhdsa_type_name_to_nid(EVP_PKEY_get0_type_name(pkey))) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
        final_sig_size = 7856;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
        final_sig_size = 17088;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
        final_sig_size = 16224;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
        final_sig_size = 35664;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
        final_sig_size = 29792;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        final_sig_size = 49856;
        break;
    default:
        return false;
    }
    if (*sig_size < final_sig_size) {
        *sig_size = final_sig_size;
        return false;
    }
    *sig_size = final_sig_size;
    libspdm_zero_mem(signature, *sig_size);

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                  (void *)(size_t)context, context_size);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    if (context_size == 0) {
        result = EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    } else {
        result = EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params);
    }
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    result = EVP_DigestSign(ctx, signature, sig_size, message, message_size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

#if LIBSPDM_FIPS_MODE
/**
 * Carries out the SLHDSA signature generation. This API can be used for FIPS test.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The SLHDSA signing context.
 * @param[in]      context_size  Size of SLHDSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 * @param[in]      deterministic If true, then generate the signature in deterministic way.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_slhdsa_sign_ex(void *dsa_context,
                            const uint8_t *context, size_t context_size,
                            const uint8_t *message, size_t message_size,
                            uint8_t *signature, size_t *sig_size,
                            bool deterministic)
{
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t final_sig_size;
    int32_t result;
    OSSL_PARAM params[3];

    if (dsa_context == NULL || message == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)dsa_context;
    switch (libspdm_slhdsa_type_name_to_nid(EVP_PKEY_get0_type_name(pkey))) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
        final_sig_size = 7856;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
        final_sig_size = 17088;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
        final_sig_size = 16224;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
        final_sig_size = 35664;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
        final_sig_size = 29792;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        final_sig_size = 49856;
        break;
    default:
        return false;
    }
    if (*sig_size < final_sig_size) {
        *sig_size = final_sig_size;
        return false;
    }
    *sig_size = final_sig_size;
    libspdm_zero_mem(signature, *sig_size);

    uint32_t params_cnt = 0;
    if (context_size != 0) {
        params[params_cnt] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                               (void *)(size_t)context, context_size);
        params_cnt++;
    }
    if (deterministic) {
        static int slh_dsa_deterministic = 1;
        params[params_cnt] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &slh_dsa_deterministic);
        params_cnt++;
    }
    params[params_cnt] = OSSL_PARAM_construct_end();

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    if (context_size == 0) {
        result = EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    } else {
        result = EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params);
    }
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    result = EVP_DigestSign(ctx, signature, sig_size, message, message_size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
