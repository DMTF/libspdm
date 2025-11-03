/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "key_context.h"

#if LIBSPDM_ML_DSA_SUPPORT

size_t libspdm_mldsa_type_name_to_nid(const char *type_name)
{
    if (type_name == NULL) {
        return LIBSPDM_CRYPTO_NID_NULL;
    }
    if (strcmp(type_name, "ML-DSA-44") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_44;
    } else if (strcmp(type_name, "ML-DSA-65") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_65;
    } else if (strcmp(type_name, "ML-DSA-87") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_87;
    }
    return LIBSPDM_CRYPTO_NID_NULL;
}

/**
 * Allocates and initializes one DSA context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the DSA context that has been initialized.
 **/
void *libspdm_mldsa_new(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    const char *sigalg_name;
    int ret;
    libspdm_key_context *ctx = NULL;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        sigalg_name = "ML-DSA-44";
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        sigalg_name = "ML-DSA-65";
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        sigalg_name = "ML-DSA-87";
        break;
    default:
        return NULL;
    }

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, sigalg_name, NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }

    ret = EVP_PKEY_keygen_init(pkey_ctx);
    if (ret <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    pkey = NULL;
    ret = EVP_PKEY_generate(pkey_ctx, &pkey);
    if (ret <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    ctx->evp_pkey = pkey;
    return (void *)ctx;
}

/**
 * Release the specified DSA context.
 *
 * @param[in]  dsa_context  Pointer to the DSA context to be released.
 **/
void libspdm_mldsa_free(void *dsa_context)
{
    if (dsa_context == NULL) {
        return;
    }
    libspdm_key_context *ctx = (libspdm_key_context *)dsa_context;
    EVP_PKEY_free(ctx->evp_pkey);
    free(ctx);
}


/**
 * Gets the key component from the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_mldsa_get_pubkey(void *dsa_context, uint8_t *key_data, size_t *key_size)
{
    uint32_t final_pub_key_size;
    int ret;
    if (dsa_context == NULL || key_size == NULL || key_data == NULL) {
        return false;
    }

    libspdm_key_context *ctx = (libspdm_key_context *)dsa_context;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    switch (libspdm_mldsa_type_name_to_nid(EVP_PKEY_get0_type_name(ctx->evp_pkey))) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        final_pub_key_size = 1312;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        final_pub_key_size = 1952;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        final_pub_key_size = 2592;
        break;
    default:
        return false;
    }

    if (*key_size < final_pub_key_size) {
        *key_size = final_pub_key_size;
        return false;
    }
    *key_size = final_pub_key_size;
    libspdm_zero_mem(key_data, *key_size);
    ret = EVP_PKEY_get_raw_public_key(ctx->evp_pkey, key_data, key_size);
    if (ret == 0) {
        return false;
    }

    return true;
}


/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_mldsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    uint32_t final_pub_key_size;
    EVP_PKEY *new_evp_key;
    const char *key_type;
    bool result = false;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    libspdm_key_context *ctx = (libspdm_key_context *)dsa_context;
    key_type = EVP_PKEY_get0_type_name(ctx->evp_pkey);
    switch (libspdm_mldsa_type_name_to_nid(key_type)) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        final_pub_key_size = 1312;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        final_pub_key_size = 1952;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        final_pub_key_size = 2592;
        break;
    default:
        return false;
    }

    if (final_pub_key_size != key_size) {
        return false;
    }

    /* Create a new EVP_PKEY with the provided public key */
    new_evp_key = EVP_PKEY_new_raw_public_key_ex(NULL, key_type, NULL, key_data, key_size);
    if (new_evp_key == NULL) {
        return false;
    }

    /* Replace the existing key with the new one */
    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = new_evp_key;
    result = true;
    return result;
}

/**
 * Verifies the MLDSA signature.
 *
 * @param[in]  dsa_context   Pointer to DSA context for signature verification.
 * @param[in]  context       The MLDSA signing context.
 * @param[in]  context_size  Size of MLDSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid DSA context.
 **/
bool libspdm_mldsa_verify(void *dsa_context,
                          const uint8_t *context, size_t context_size,
                          const uint8_t *message, size_t message_size,
                          const uint8_t *signature, size_t sig_size)
{
    libspdm_key_context *ctxobj;
    EVP_MD_CTX *ctx;
    size_t final_sig_size;
    int32_t result;
    OSSL_PARAM params[2];

    if (dsa_context == NULL || message == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    ctxobj = (libspdm_key_context *)dsa_context;
    switch (libspdm_mldsa_type_name_to_nid(EVP_PKEY_get0_type_name(ctxobj->evp_pkey))) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        final_sig_size = 2420;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        final_sig_size = 3309;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        final_sig_size = 4627;
        break;
    default:
        return false;
    }
    if (sig_size != final_sig_size) {
        return false;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                  (void *)(size_t)context, context_size);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    if (context_size == 0) {
        OSSL_PARAM params_default[1];
        params_default[0] = OSSL_PARAM_construct_end();
        result = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, ctxobj->evp_pkey, params_default);
    } else {
        result = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, ctxobj->evp_pkey, params);
    }
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    result = EVP_DigestVerify(ctx, signature, sig_size, message, message_size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */
