/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * HMAC-SHA256/384/512 Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>

/**
 * Computes the HMAC-MD digest of a input data buffer.
 *
 * This function performs the HMAC-MD digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   md          message digest.
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-MD digest
 *                         value.
 *
 * @retval true   HMAC-MD digest computation succeeded.
 * @retval false  HMAC-MD digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool hmac_md_all(const EVP_MD *md, const void *data,
                 size_t data_size, const uint8_t *key, size_t key_size,
                 uint8_t *hmac_value)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    size_t out_len = 0;
    bool ret_val = false;

    /* Check input parameters */
    if (md == NULL || data == NULL || key == NULL || hmac_value == NULL) {
        return false;
    }

    /* Create MAC object and context */
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        goto done;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        goto done;
    }

    /* Get digest name */
    const char *digest_name = EVP_MD_get0_name(md);
    if (digest_name == NULL) {
        goto done;
    }

    /* Setup parameters */
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)(size_t)digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    /* Initialize with key */
    if (EVP_MAC_init(ctx, key, key_size, params) != 1) {
        goto done;
    }

    /* Update with data */
    if (data_size > 0 && EVP_MAC_update(ctx, data, data_size) != 1) {
        goto done;
    }

    /* Finalize and get result */
    size_t mac_size = EVP_MAC_CTX_get_mac_size(ctx);
    if (EVP_MAC_final(ctx, hmac_value, &out_len, mac_size) != 1) {
        goto done;
    }

    ret_val = true;

done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret_val;
}

/**
 * Computes the HMAC-SHA256 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA256 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA256 digest
 *                         value (32 bytes).
 *
 * @retval true   HMAC-SHA256 digest computation succeeded.
 * @retval false  HMAC-SHA256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha256_all(const void *data, size_t data_size,
                             const uint8_t *key, size_t key_size,
                             uint8_t *hmac_value)
{
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (md == NULL) {
        return false;
    }
    bool result = hmac_md_all(md, data, data_size, key, key_size, hmac_value);
    EVP_MD_free(md);
    return result;
}

/**
 * Computes the HMAC-SHA384 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA384 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA384 digest
 *                         value (48 bytes).
 *
 * @retval true   HMAC-SHA384 digest computation succeeded.
 * @retval false  HMAC-SHA384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha384_all(const void *data, size_t data_size,
                             const uint8_t *key, size_t key_size,
                             uint8_t *hmac_value)
{
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA384", NULL);
    if (md == NULL) {
        return false;
    }
    bool result = hmac_md_all(md, data, data_size, key, key_size, hmac_value);
    EVP_MD_free(md);
    return result;
}

/**
 * Computes the HMAC-SHA512 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA512 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA512 digest
 *                         value (64 bytes).
 *
 * @retval true   HMAC-SHA512 digest computation succeeded.
 * @retval false  HMAC-SHA512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha512_all(const void *data, size_t data_size,
                             const uint8_t *key, size_t key_size,
                             uint8_t *hmac_value)
{
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA512", NULL);
    if (md == NULL) {
        return false;
    }
    bool result = hmac_md_all(md, data, data_size, key, key_size, hmac_value);
    EVP_MD_free(md);
    return result;
}
