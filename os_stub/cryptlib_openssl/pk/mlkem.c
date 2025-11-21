/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>

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

    /* Allocate key context wrapper */
    libspdm_key_context *kem_context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (kem_context == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    kem_context->evp_pkey = pkey;
    return kem_context;
}

/**
 * Release the specified KEM context.
 *
 * @param[in]  kem_context  Pointer to the KEM context to be released.
 **/
void libspdm_mlkem_free(void *kem_context)
{
    libspdm_key_context *key_ctx;

    if (kem_context == NULL) {
        return;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    if (key_ctx->evp_pkey != NULL) {
        EVP_PKEY_free(key_ctx->evp_pkey);
    }
    free(key_ctx);
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
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    int ret;
    uint32_t final_encap_key_size;
    const char *type_name;

    if (kem_context == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

    type_name = EVP_PKEY_get0_type_name(pkey);
    if (type_name == NULL) {
        return false;
    }

    switch (libspdm_mlkem_type_name_to_nid(type_name)) {
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

    /* Use raw public key get API */
    size_t out_len = *encap_key_size;
    ret = EVP_PKEY_get_raw_public_key(pkey, encap_key, &out_len);
    if (ret == 0) {
        return false;
    }

    *encap_key_size = out_len;
    return true;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   size of peer's public key in bytes.
 * @param[out]      cipher_text           Pointer to the buffer to receive generated cipher text.
 * @param[in, out]  cipher_text_size      On input, the size of cipher_text buffer in bytes.
 *                                        On output, the size of data returned in cipher_text buffer in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size    On input, the size of shared_secret buffer in bytes.
 *                                        On output, the size of data returned in shared_secret buffer in bytes.
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
    libspdm_key_context *key_ctx;
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *peer_pkey;
    EVP_PKEY *pkey;
    const char *type_name;
    int ret;
    uint32_t final_encap_key_size;
    uint32_t final_cipher_text_size;
    uint32_t final_shared_secret_size;

    if (kem_context == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

    type_name = EVP_PKEY_get0_type_name(pkey);
    if (type_name == NULL) {
        return false;
    }

    switch (libspdm_mlkem_type_name_to_nid(type_name)) {
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
    if (*cipher_text_size < final_cipher_text_size) {
        *cipher_text_size = final_cipher_text_size;
        return false;
    }

    /* Create peer public key */
    peer_pkey = EVP_PKEY_new_raw_public_key_ex(NULL, type_name, NULL,
                                               peer_encap_key, peer_encap_key_size);
    if (peer_pkey == NULL) {
        return false;
    }

    /* Perform encapsulation using peer public key */
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, peer_pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_PKEY_free(peer_pkey);
        return false;
    }

    ret = EVP_PKEY_encapsulate_init(pkey_ctx, NULL);
    if (ret != 1) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    size_t actual_cipher_text_size = *cipher_text_size;
    size_t actual_shared_secret_size = *shared_secret_size;

    ret = EVP_PKEY_encapsulate(pkey_ctx, cipher_text, &actual_cipher_text_size,
                               shared_secret, &actual_shared_secret_size);
    if (ret != 1) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    *cipher_text_size = actual_cipher_text_size;
    *shared_secret_size = actual_shared_secret_size;

    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_CTX_free(pkey_ctx);

    return true;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  kem_context           Pointer to the KEM context.
 * @param[in]       peer_cipher_text      Pointer to the peer's cipher text.
 * @param[in]       peer_cipher_text_size size of peer's cipher text in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size    On input, the size of shared_secret buffer in bytes.
 *                                        On output, the size of data returned in shared_secret buffer in
 *                                        bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  shared_secret_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_decapsulate(void *kem_context, const uint8_t *peer_cipher_text,
                               size_t peer_cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    const char *type_name;
    int ret;
    uint32_t final_cipher_text_size;
    uint32_t final_shared_secret_size;

    if (kem_context == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

    type_name = EVP_PKEY_get0_type_name(pkey);
    if (type_name == NULL) {
        return false;
    }

    switch (libspdm_mlkem_type_name_to_nid(type_name)) {
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

    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pkey_ctx == NULL) {
        return false;
    }
    ret = EVP_PKEY_decapsulate_init(pkey_ctx, NULL);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    size_t actual_shared_secret_size = *shared_secret_size;
    ret = EVP_PKEY_decapsulate(pkey_ctx, shared_secret, &actual_shared_secret_size,
                               peer_cipher_text, peer_cipher_text_size);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    *shared_secret_size = actual_shared_secret_size;
    EVP_PKEY_CTX_free(pkey_ctx);

    return true;
}

#if LIBSPDM_FIPS_MODE
/**
 * Encapsulate an ML-KEM public key and generate a shared secret.
 * This is an extended version that allows passing in entropy for deterministic testing.
 *
 * @param[in]       kem_context           Pointer to the KEM context.
 * @param[in]       peer_encap_key        Pointer to peer's encapsulation public key.
 * @param[in]       peer_encap_key_size   Size of peer's encapsulation public key in bytes.
 * @param[out]      cipher_text           Pointer to the buffer to receive cipher_text.
 * @param[in, out]  cipher_text_size      On input, size of cipher_text buffer in bytes.
 *                                        On output, size of data returned in cipher_text buffer in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive shared_secret.
 * @param[in, out]  shared_secret_size    On input, size of shared_secret buffer in bytes.
 *                                        On output, size of data returned in shared_secret buffer in bytes.
 * @param[in]       entropy               Pointer to the buffer to receive entropy.
 * @param[in]       entropy_size          size of entropy buffer in bytes.
 *
 * @retval true   KEM exchanged key generation succeeded.
 * @retval false  KEM exchanged key generation failed.
 * @retval false  cipher_text_size is not large enough.
 * @retval false  shared_secret_size is not large enough.
 * @retval false  entropy_size is not large enough.
 * @retval false  This interface is not supported.
 **/
bool libspdm_mlkem_encapsulate_ex(void *kem_context, const uint8_t *peer_encap_key,
                                  size_t peer_encap_key_size, uint8_t *cipher_text,
                                  size_t *cipher_text_size, uint8_t *shared_secret,
                                  size_t *shared_secret_size, uint8_t *entropy,
                                  size_t entropy_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey;
    EVP_PKEY *peer_pkey = NULL;
    int ret;
    uint32_t final_encap_key_size;
    uint32_t final_cipher_text_size;
    uint32_t final_shared_secret_size;
    bool result = false;

    if (kem_context == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

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

    if (entropy != NULL && entropy_size != 32) {
        return false;
    }

    /* Create peer public key from raw key data */
    peer_pkey = EVP_PKEY_new_raw_public_key_ex(NULL, EVP_PKEY_get0_type_name(pkey), NULL,
                                               peer_encap_key, peer_encap_key_size);
    if (peer_pkey == NULL) {
        goto cleanup;
    }

    /* Create encapsulation context using peer's public key */
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, peer_pkey, NULL);
    if (pkey_ctx == NULL) {
        goto cleanup;
    }

    /* FIPS-203, modify randomness during encapsulation */
    if (entropy != NULL){
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
                                                      (void *) entropy, entropy_size);
        params[1] = OSSL_PARAM_construct_end();
        ret = EVP_PKEY_encapsulate_init(pkey_ctx, params);
    } else {
        ret = EVP_PKEY_encapsulate_init(pkey_ctx, NULL);
    }
    if (ret != 1) {
        goto cleanup;
    }
    ret = EVP_PKEY_encapsulate(pkey_ctx, cipher_text, cipher_text_size,
                               shared_secret, shared_secret_size);
    if (ret != 1) {
        goto cleanup;
    }

    result = true;

cleanup:
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(peer_pkey);
    return result;
}

/**
 * Sets the key component into the established KEM context.
 *
 * Since EVP_PKEY is immutable in OpenSSL public API, this function creates
 * a new private key and replaces the old one in the context.
 *
 * @param[in, out]  kem_context  Pointer to KEM context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   KEM key component was set successfully.
 * @retval  false  Key setting failed.
 **/
bool libspdm_mlkem_set_privkey(void *kem_context, const uint8_t *key_data, size_t key_size)
{
    libspdm_key_context *key_ctx;
    uint32_t final_pri_key_size;
    EVP_PKEY *old_pkey;
    EVP_PKEY *new_pkey;
    const char *key_type;

    if ((kem_context == NULL) || (key_data == NULL)) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    old_pkey = key_ctx->evp_pkey;
    if (old_pkey == NULL) {
        return false;
    }

    key_type = EVP_PKEY_get0_type_name(old_pkey);
    switch (libspdm_mlkem_type_name_to_nid(key_type)) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_pri_key_size = 1632;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_pri_key_size = 2400;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_pri_key_size = 3168;
        break;
    default:
        return false;
    }

    if (final_pri_key_size != key_size) {
        return false;
    }

    /* Create new private key from raw key data */
    new_pkey = EVP_PKEY_new_raw_private_key_ex(NULL, key_type, NULL, key_data, key_size);
    if (new_pkey == NULL) {
        return false;
    }

    /* Replace old key with new key */
    EVP_PKEY_free(old_pkey);
    key_ctx->evp_pkey = new_pkey;

    return true;
}
#endif /* LIBSPDM_FIPS_MODE */
#endif /* LIBSPDM_ML_KEM_SUPPORT */
