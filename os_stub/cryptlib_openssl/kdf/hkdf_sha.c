/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * HMAC-SHA256/384/512 KDF Wrapper Implementation.
 *
 * RFC 5869: HMAC-based Extract-and-Expand key Derivation Function (HKDF)
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

/**
 * Derive HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   md               message digest.
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_md_extract_and_expand(IN const EVP_MD *md, IN const uint8_t *key,
                                   IN uintn key_size, IN const uint8_t *salt,
                                   IN uintn salt_size, IN const uint8_t *info,
                                   IN uintn info_size, OUT uint8_t *out,
                                   IN uintn out_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    boolean result;

    if (key == NULL || salt == NULL || info == NULL || out == NULL ||
        key_size > INT_MAX || salt_size > INT_MAX || info_size > INT_MAX ||
        out_size > INT_MAX) {
        return FALSE;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pkey_ctx == NULL) {
        return FALSE;
    }

    result = EVP_PKEY_derive_init(pkey_ctx) > 0;
    if (result) {
        result = EVP_PKEY_CTX_set_hkdf_md(pkey_ctx, md) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_set1_hkdf_salt(pkey_ctx, salt,
                                             (uint32_t)salt_size) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_set1_hkdf_key(pkey_ctx, key,
                                            (uint32_t)key_size) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_add1_hkdf_info(pkey_ctx, info,
                                             (uint32_t)info_size) > 0;
    }
    if (result) {
        result = EVP_PKEY_derive(pkey_ctx, out, &out_size) > 0;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    pkey_ctx = NULL;
    return result;
}

/**
 * Derive HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   md               message digest.
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_md_extract(IN const EVP_MD *md, IN const uint8_t *key,
                        IN uintn key_size, IN const uint8_t *salt,
                        IN uintn salt_size, OUT uint8_t *prk_out,
                        IN uintn prk_out_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    boolean result;

    if (key == NULL || salt == NULL || prk_out == NULL ||
        key_size > INT_MAX || salt_size > INT_MAX ||
        prk_out_size > INT_MAX) {
        return FALSE;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pkey_ctx == NULL) {
        return FALSE;
    }

    result = EVP_PKEY_derive_init(pkey_ctx) > 0;
    if (result) {
        result = EVP_PKEY_CTX_set_hkdf_md(pkey_ctx, md) > 0;
    }
    if (result) {
        result =
            EVP_PKEY_CTX_hkdf_mode(
                pkey_ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_set1_hkdf_salt(pkey_ctx, salt,
                                             (uint32_t)salt_size) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_set1_hkdf_key(pkey_ctx, key,
                                            (uint32_t)key_size) > 0;
    }
    if (result) {
        result = EVP_PKEY_derive(pkey_ctx, prk_out, &prk_out_size) > 0;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    pkey_ctx = NULL;
    return result;
}

/**
 * Derive HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   md               message digest.
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_md_expand(IN const EVP_MD *md, IN const uint8_t *prk,
                       IN uintn prk_size, IN const uint8_t *info,
                       IN uintn info_size, OUT uint8_t *out, IN uintn out_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    boolean result;

    if (prk == NULL || info == NULL || out == NULL || prk_size > INT_MAX ||
        info_size > INT_MAX || out_size > INT_MAX) {
        return FALSE;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pkey_ctx == NULL) {
        return FALSE;
    }

    result = EVP_PKEY_derive_init(pkey_ctx) > 0;
    if (result) {
        result = EVP_PKEY_CTX_set_hkdf_md(pkey_ctx, md) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_hkdf_mode(
            pkey_ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_set1_hkdf_key(pkey_ctx, prk,
                                            (uint32_t)prk_size) > 0;
    }
    if (result) {
        result = EVP_PKEY_CTX_add1_hkdf_info(pkey_ctx, info,
                                             (uint32_t)info_size) > 0;
    }
    if (result) {
        result = EVP_PKEY_derive(pkey_ctx, out, &out_size) > 0;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    pkey_ctx = NULL;
    return result;
}

/**
 * Derive SHA256 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha256_extract_and_expand(IN const uint8_t *key, IN uintn key_size,
                                       IN const uint8_t *salt, IN uintn salt_size,
                                       IN const uint8_t *info, IN uintn info_size,
                                       OUT uint8_t *out, IN uintn out_size)
{
    return hkdf_md_extract_and_expand(EVP_sha256(), key, key_size, salt,
                                      salt_size, info, info_size, out,
                                      out_size);
}

/**
 * Derive SHA256 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha256_extract(IN const uint8_t *key, IN uintn key_size,
                            IN const uint8_t *salt, IN uintn salt_size,
                            OUT uint8_t *prk_out, IN uintn prk_out_size)
{
    return hkdf_md_extract(EVP_sha256(), key, key_size, salt, salt_size,
                           prk_out, prk_out_size);
}

/**
 * Derive SHA256 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha256_expand(IN const uint8_t *prk, IN uintn prk_size,
                           IN const uint8_t *info, IN uintn info_size,
                           OUT uint8_t *out, IN uintn out_size)
{
    return hkdf_md_expand(EVP_sha256(), prk, prk_size, info, info_size, out,
                          out_size);
}

/**
 * Derive SHA384 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha384_extract_and_expand(IN const uint8_t *key, IN uintn key_size,
                                       IN const uint8_t *salt, IN uintn salt_size,
                                       IN const uint8_t *info, IN uintn info_size,
                                       OUT uint8_t *out, IN uintn out_size)
{
    return hkdf_md_extract_and_expand(EVP_sha384(), key, key_size, salt,
                                      salt_size, info, info_size, out,
                                      out_size);
}

/**
 * Derive SHA384 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha384_extract(IN const uint8_t *key, IN uintn key_size,
                            IN const uint8_t *salt, IN uintn salt_size,
                            OUT uint8_t *prk_out, IN uintn prk_out_size)
{
    return hkdf_md_extract(EVP_sha384(), key, key_size, salt, salt_size,
                           prk_out, prk_out_size);
}

/**
 * Derive SHA384 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha384_expand(IN const uint8_t *prk, IN uintn prk_size,
                           IN const uint8_t *info, IN uintn info_size,
                           OUT uint8_t *out, IN uintn out_size)
{
    return hkdf_md_expand(EVP_sha384(), prk, prk_size, info, info_size, out,
                          out_size);
}

/**
 * Derive SHA512 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha512_extract_and_expand(IN const uint8_t *key, IN uintn key_size,
                                       IN const uint8_t *salt, IN uintn salt_size,
                                       IN const uint8_t *info, IN uintn info_size,
                                       OUT uint8_t *out, IN uintn out_size)
{
    return hkdf_md_extract_and_expand(EVP_sha512(), key, key_size, salt,
                                      salt_size, info, info_size, out,
                                      out_size);
}

/**
 * Derive SHA512 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha512_extract(IN const uint8_t *key, IN uintn key_size,
                            IN const uint8_t *salt, IN uintn salt_size,
                            OUT uint8_t *prk_out, IN uintn prk_out_size)
{
    return hkdf_md_extract(EVP_sha512(), key, key_size, salt, salt_size,
                           prk_out, prk_out_size);
}

/**
 * Derive SHA512 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval TRUE   Hkdf generated successfully.
 * @retval FALSE  Hkdf generation failed.
 *
 **/
boolean hkdf_sha512_expand(IN const uint8_t *prk, IN uintn prk_size,
                           IN const uint8_t *info, IN uintn info_size,
                           OUT uint8_t *out, IN uintn out_size)
{
    return hkdf_md_expand(EVP_sha512(), prk, prk_size, info, info_size, out,
                          out_size);
}
