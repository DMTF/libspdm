/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * HMAC-SHA3_256/384/512 Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

/**
 * Computes the HMAC-SHA3_256 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA3_256 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA3_256 digest
 *                         value (32 bytes).
 *
 * @retval true   HMAC-SHA3_256 digest computation succeeded.
 * @retval false  HMAC-SHA3_256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha3_256_all(const void *data, size_t data_size,
                               const uint8_t *key, size_t key_size,
                               uint8_t *hmac_value)
{
    return false;
}

/**
 * Computes the HMAC-SHA3_384 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA3_384 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA3_384 digest
 *                         value (48 bytes).
 *
 * @retval true   HMAC-SHA3_384 digest computation succeeded.
 * @retval false  HMAC-SHA3_384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha3_384_all(const void *data, size_t data_size,
                               const uint8_t *key, size_t key_size,
                               uint8_t *hmac_value)
{
    return false;
}

/**
 * Computes the HMAC-SHA3_512 digest of a input data buffer.
 *
 * This function performs the HMAC-SHA3_512 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SHA3_512 digest
 *                         value (64 bytes).
 *
 * @retval true   HMAC-SHA3_512 digest computation succeeded.
 * @retval false  HMAC-SHA3_512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sha3_512_all(const void *data, size_t data_size,
                               const uint8_t *key, size_t key_size,
                               uint8_t *hmac_value)
{
    return false;
}
