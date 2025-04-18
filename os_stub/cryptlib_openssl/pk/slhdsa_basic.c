/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"

#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <crypto/evp.h>
#include <crypto/slh_dsa.h>

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
    char *sigalg_name;
    int ret;

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

    return (void *)pkey;
}

/**
 * Release the specified DSA context.
 *
 * @param[in]  dsa_context  Pointer to the DSA context to be released.
 **/
void libspdm_slhdsa_free(void *dsa_context)
{
    EVP_PKEY_free((EVP_PKEY *)dsa_context);
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
    uint32_t final_pub_key_size;
    EVP_PKEY *evp_key;
    int ret;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    evp_key = (EVP_PKEY *)dsa_context;
    switch (libspdm_slhdsa_type_name_to_nid(EVP_PKEY_get0_type_name(evp_key))) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
        final_pub_key_size = 32;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
        final_pub_key_size = 48;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        final_pub_key_size = 64;
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
    ret = EVP_PKEY_get_raw_public_key(evp_key, key_data, key_size);
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
    uint32_t final_pub_key_size;
    EVP_PKEY *evp_key;
    EVP_PKEY *new_evp_key;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    evp_key = (EVP_PKEY *)dsa_context;
    switch (libspdm_slhdsa_type_name_to_nid(EVP_PKEY_get0_type_name(evp_key))) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
        final_pub_key_size = 32;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
        final_pub_key_size = 48;
        break;
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        final_pub_key_size = 64;
        break;
    default:
        return false;
    }

    if (final_pub_key_size != key_size) {
        return false;
    }

    new_evp_key = EVP_PKEY_new_raw_public_key_ex(NULL, EVP_PKEY_get0_type_name(evp_key), NULL,
                                                 key_data, key_size);
    if (new_evp_key == NULL) {
        return false;
    }

    if (evp_keymgmt_util_copy(evp_key, new_evp_key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 1) {
        EVP_PKEY_free(new_evp_key);
        return false;
    }

    EVP_PKEY_free(new_evp_key);
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
    EVP_PKEY *pkey;
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
        result = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
    } else {
        result = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params);
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
