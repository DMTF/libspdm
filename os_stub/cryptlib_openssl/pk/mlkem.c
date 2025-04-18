/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"

#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <crypto/evp.h>
#include <crypto/ml_kem.h>

#if LIBSPDM_ML_KEM_SUPPORT

size_t libspdm_mlkem_type_name_to_nid(const char *type_name)
{
    if (type_name == NULL) {
        return LIBSPDM_CRYPTO_NID_NULL;
    }
    if (strcmp(type_name, "ML-KEM-512") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_KEM_512;
    } else if (strcmp(type_name, "ML-KEM-768") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_KEM_768;
    } else if (strcmp(type_name, "ML-KEM-1024") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_KEM_1024;
    }
    return LIBSPDM_CRYPTO_NID_NULL;
}

/**
 * Allocates and initializes one KEM context for subsequent use with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the KEM context that has been initialized.
 **/
void *libspdm_mlkem_new_by_name(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    char *kemalg_name;
    int ret;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        kemalg_name = "ML-KEM-512";
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        kemalg_name = "ML-KEM-768";
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        kemalg_name = "ML-KEM-1024";
        break;
    default:
        return NULL;
    }

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, kemalg_name, NULL);
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
 * Release the specified KEM context.
 *
 * @param[in]  kem_context  Pointer to the KEM context to be released.
 **/
void libspdm_mlkem_free(void *kem_context)
{
    EVP_PKEY_free((EVP_PKEY *)kem_context);
}

/**
 * Generates KEM public key.
 *
 * @param[in, out]  kem_context       Pointer to the KEM context.
 * @param[out]      encap_key        Pointer to the buffer to receive generated public key.
 * @param[in, out]  encap_key_size   On input, the size of public_key buffer in bytes.
 *                                   On output, the size of data returned in public_key buffer in
 *                                   bytes.
 *
 * @retval true   KEM public key generation succeeded.
 * @retval false  KEM public key generation failed.
 * @retval false  public_key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_generate_key(void *kem_context, uint8_t *encap_key, size_t *encap_key_size)
{
    EVP_PKEY *pkey;
    int ret;
    uint32_t final_encap_key_size;

    pkey = (EVP_PKEY *)kem_context;

    switch (libspdm_mlkem_type_name_to_nid(EVP_PKEY_get0_type_name(pkey))) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_encap_key_size = 800;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_encap_key_size = 1184;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_encap_key_size = 1568;
        break;
    default:
        return false;
    }
    if (*encap_key_size < final_encap_key_size) {
        *encap_key_size = final_encap_key_size;
        return false;
    }
    *encap_key_size = final_encap_key_size;
    libspdm_zero_mem(encap_key, *encap_key_size);
    ret = EVP_PKEY_get_raw_public_key(pkey, encap_key, encap_key_size);
    if (ret == 0) {
        return false;
    }

    return true;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_encapsulate(void *kem_context, const uint8_t *peer_encap_key,
                               size_t peer_encap_key_size, uint8_t *cipher_text,
                               size_t *cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    EVP_PKEY *new_pkey;
    int ret;
    uint32_t final_encap_key_size;
    uint32_t final_cipher_text_size;
    uint32_t final_shared_secret_size;

    pkey = (EVP_PKEY *)kem_context;

    switch (libspdm_mlkem_type_name_to_nid(EVP_PKEY_get0_type_name(pkey))) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_encap_key_size = 800;
        final_cipher_text_size = 768;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_encap_key_size = 1184;
        final_cipher_text_size = 1088;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_encap_key_size = 1568;
        final_cipher_text_size = 1568;
        break;
    default:
        return false;
    }
    final_shared_secret_size = 32;
    if (peer_encap_key_size != final_encap_key_size) {
        return false;
    }
    if (*shared_secret_size < final_shared_secret_size) {
        *shared_secret_size = final_shared_secret_size;
        return false;
    }
    *shared_secret_size = final_shared_secret_size;
    libspdm_zero_mem(shared_secret, *shared_secret_size);
    if (*cipher_text_size < final_cipher_text_size) {
        *cipher_text_size = final_cipher_text_size;
        return false;
    }
    *cipher_text_size = final_cipher_text_size;
    libspdm_zero_mem(cipher_text, *cipher_text_size);

    new_pkey = EVP_PKEY_new_raw_public_key_ex(NULL, EVP_PKEY_get0_type_name(pkey), NULL,
                                              peer_encap_key, peer_encap_key_size);
    if (new_pkey == NULL) {
        return false;
    }

    /* ML-KEM does not allow key mutation.
     * To make evp_keymgmt_util_copy() work, we need to clear key */
    ossl_ml_kem_key_reset(pkey->keydata);

    if (evp_keymgmt_util_copy(pkey, new_pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 1) {
        EVP_PKEY_free(new_pkey);
        return false;
    }
    EVP_PKEY_free(new_pkey);

    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pkey_ctx == NULL) {
        return false;
    }
    ret = EVP_PKEY_encapsulate_init(pkey_ctx, NULL);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    ret = EVP_PKEY_encapsulate(pkey_ctx, cipher_text, cipher_text_size,
                               shared_secret, shared_secret_size);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    return true;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      key                   Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size              On input, the size of key buffer in bytes.
 *                                        On output, the size of data returned in key buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  key_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_decapsulate(void *kem_context, const uint8_t *peer_cipher_text,
                               size_t peer_cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    int ret;
    uint32_t final_cipher_text_size;
    uint32_t final_shared_secret_size;

    pkey = (EVP_PKEY *)kem_context;

    switch (libspdm_mlkem_type_name_to_nid(EVP_PKEY_get0_type_name(pkey))) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_cipher_text_size = 768;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_cipher_text_size = 1088;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_cipher_text_size = 1568;
        break;
    default:
        return false;
    }
    final_shared_secret_size = 32;
    if (peer_cipher_text_size != final_cipher_text_size) {
        return false;
    }
    if (*shared_secret_size < final_shared_secret_size) {
        *shared_secret_size = final_shared_secret_size;
        return false;
    }
    *shared_secret_size = final_shared_secret_size;
    libspdm_zero_mem(shared_secret, *shared_secret_size);

    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pkey_ctx == NULL) {
        return false;
    }
    ret = EVP_PKEY_decapsulate_init(pkey_ctx, NULL);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    ret = EVP_PKEY_decapsulate(pkey_ctx, shared_secret, shared_secret_size,
                               peer_cipher_text, peer_cipher_text_size);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    return true;
}

#endif /* LIBSPDM_ML_KEM_SUPPORT */
