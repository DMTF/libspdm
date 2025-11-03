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

#if LIBSPDM_SLH_DSA_SUPPORT

size_t libspdm_slhdsa_type_name_to_nid(const char *type_name)
{
    if (type_name == NULL) {
        return LIBSPDM_CRYPTO_NID_NULL;
    }
    if (strcmp(type_name, "SLH-DSA-SHA2-128s") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S;
    } else if (strcmp(type_name, "SLH-DSA-SHAKE-128s") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S;
    } else if (strcmp(type_name, "SLH-DSA-SHA2-128f") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F;
    } else if (strcmp(type_name, "SLH-DSA-SHAKE-128f") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F;
    } else if (strcmp(type_name, "SLH-DSA-SHA2-192s") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S;
    } else if (strcmp(type_name, "SLH-DSA-SHAKE-192s") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S;
    } else if (strcmp(type_name, "SLH-DSA-SHA2-192f") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F;
    } else if (strcmp(type_name, "SLH-DSA-SHAKE-192f") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F;
    } else if (strcmp(type_name, "SLH-DSA-SHA2-256s") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S;
    } else if (strcmp(type_name, "SLH-DSA-SHAKE-256s") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S;
    } else if (strcmp(type_name, "SLH-DSA-SHA2-256f") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F;
    } else if (strcmp(type_name, "SLH-DSA-SHAKE-256f") == 0) {
        return LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F;
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
void *libspdm_slhdsa_new(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    const char *sigalg_name;
    int ret;
    libspdm_key_context *ctx;

    /* Convert nid to name */
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
        sigalg_name = "SLH-DSA-SHA2-128s";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
        sigalg_name = "SLH-DSA-SHAKE-128s";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
        sigalg_name = "SLH-DSA-SHA2-128f";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
        sigalg_name = "SLH-DSA-SHAKE-128f";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
        sigalg_name = "SLH-DSA-SHA2-192s";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
        sigalg_name = "SLH-DSA-SHAKE-192s";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
        sigalg_name = "SLH-DSA-SHA2-192f";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
        sigalg_name = "SLH-DSA-SHAKE-192f";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
        sigalg_name = "SLH-DSA-SHA2-256s";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
        sigalg_name = "SLH-DSA-SHAKE-256s";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
        sigalg_name = "SLH-DSA-SHA2-256f";
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        sigalg_name = "SLH-DSA-SHAKE-256f";
        break;
    default:
        sigalg_name = NULL;
        break;
    }
    if (sigalg_name == NULL) {
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
void libspdm_slhdsa_free(void *dsa_context)
{
    libspdm_key_context *ctx;
    if (dsa_context == NULL) {
        return;
    }
    ctx = (libspdm_key_context *)dsa_context;
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
bool libspdm_slhdsa_get_pubkey(void *dsa_context, uint8_t *key_data, size_t *key_size)
{
    libspdm_key_context *ctx;
    size_t need = 0;
    int ret;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    ctx = (libspdm_key_context *)dsa_context;

    /* First query required size */
    ret = EVP_PKEY_get_raw_public_key(ctx->evp_pkey, NULL, &need);
    if (ret != 1 || need == 0) {
        return false;
    }
    if (*key_size < need) {
        *key_size = need;
        return false;
    }
    libspdm_zero_mem(key_data, *key_size);
    *key_size = need;
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
bool libspdm_slhdsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    libspdm_key_context *ctx;
    EVP_PKEY *new_pkey;
    const char *type_name;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    ctx = (libspdm_key_context *)dsa_context;
    type_name = EVP_PKEY_get0_type_name(ctx->evp_pkey);
    if (type_name == NULL) {
        return false;
    }

    /* Rebuild a fresh EVP_PKEY from raw public key, then replace in context */
    new_pkey = EVP_PKEY_new_raw_public_key_ex(NULL, type_name, NULL, key_data, key_size);
    if (new_pkey == NULL) {
        return false;
    }
    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = new_pkey;
    return true;
}

/**
 * Verifies the SLHDSA signature.
 *
 * @param[in]  dsa_context   Pointer to DSA context for signature verification.
 * @param[in]  context       The SLHDSA signing context.
 * @param[in]  context_size  Size of SLHDSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid DSA context.
 **/
bool libspdm_slhdsa_verify(void *dsa_context,
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
    switch (libspdm_slhdsa_type_name_to_nid(EVP_PKEY_get0_type_name(ctxobj->evp_pkey))) {
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

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
