/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

/** @file
 * HMAC-SHA256 KDF Wrapper Implementation.
 *
 * RFC 5869: HMAC-based Extract-and-Expand key Derivation Function (HKDF)
 **/

#include "internal_crypt_lib.h"

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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha256_extract_and_expand(const uint8_t *key, size_t key_size,
                                            const uint8_t *salt, size_t salt_size,
                                            const uint8_t *info, size_t info_size,
                                            uint8_t *out, size_t out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha256_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha256_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha384_extract_and_expand(const uint8_t *key, size_t key_size,
                                            const uint8_t *salt, size_t salt_size,
                                            const uint8_t *info, size_t info_size,
                                            uint8_t *out, size_t out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha384_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha384_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha512_extract_and_expand(const uint8_t *key, size_t key_size,
                                            const uint8_t *salt, size_t salt_size,
                                            const uint8_t *info, size_t info_size,
                                            uint8_t *out, size_t out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha512_extract(const uint8_t *key, size_t key_size,
                                 const uint8_t *salt, size_t salt_size,
                                 uint8_t *prk_out, size_t prk_out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
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
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha512_expand(const uint8_t *prk, size_t prk_size,
                                const uint8_t *info, size_t info_size,
                                uint8_t *out, size_t out_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}
