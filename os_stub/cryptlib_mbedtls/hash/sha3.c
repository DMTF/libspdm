/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SHA3-256/384/512 and Shake-256 digest Wrapper Implementation
 **/

#include "internal_crypt_lib.h"
#include <mbedtls/sha3.h>

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA3-256 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha3_256_new() returns NULL.
 *
 **/
void *libspdm_sha3_256_new(void)
{
    void *hmac_md_ctx;

    hmac_md_ctx = allocate_zero_pool(sizeof(mbedtls_sha3_context));
    if (hmac_md_ctx == NULL) {
        return NULL;
    }

    return hmac_md_ctx;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha3_256_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha3_256_free(void *sha3_256_ctx)
{
    mbedtls_sha3_free(sha3_256_ctx);
    free_pool (sha3_256_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha3_256_context as SHA3-256 hash context for
 * subsequent use.
 *
 * If sha3_256_context is NULL, then return false.
 *
 * @param[out]  sha3_256_context  Pointer to SHA3-256 context being initialized.
 *
 * @retval true   SHA3-256 context initialization succeeded.
 * @retval false  SHA3-256 context initialization failed.
 *
 **/
bool libspdm_sha3_256_init(void *sha3_256_context)
{
    int ret;

    if (sha3_256_context == NULL) {
        return false;
    }

    mbedtls_sha3_init(sha3_256_context);

    ret = mbedtls_sha3_starts(sha3_256_context, MBEDTLS_SHA3_256);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Makes a copy of an existing SHA3-256 context.
 *
 * If sha3_256_context is NULL, then return false.
 * If new_sha3_256_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha3_256_context     Pointer to SHA3-256 context being copied.
 * @param[out] new_sha3_256_context  Pointer to new SHA3-256 context.
 *
 * @retval true   SHA3-256 context copy succeeded.
 * @retval false  SHA3-256 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_256_duplicate(const void *sha3_256_context,
                                void *new_sha3_256_context)
{
    if (sha3_256_context == NULL || new_sha3_256_context == NULL) {
        return false;
    }

    mbedtls_sha3_clone(new_sha3_256_context, sha3_256_context);

    return true;
}

/**
 * Digests the input data and updates SHA3-256 context.
 *
 * This function performs SHA3-256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA3-256 context should be already correctly initialized by libspdm_sha3_256_init(), and should not be finalized
 * by libspdm_sha3_256_final(). Behavior with invalid context is undefined.
 *
 * If sha3_256_context is NULL, then return false.
 *
 * @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA3-256 data digest succeeded.
 * @retval false  SHA3-256 data digest failed.
 *
 **/
bool libspdm_sha3_256_update(void *sha3_256_context, const void *data,
                             size_t data_size)
{
    int ret;

    if (sha3_256_context == NULL) {
        return false;
    }

    if (data == NULL && data_size != 0) {
        return false;
    }
    if (data_size > INT_MAX) {
        return false;
    }

    ret = mbedtls_sha3_update(sha3_256_context, data, data_size);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Completes computation of the SHA3-256 digest value.
 *
 * This function completes SHA3-256 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA3-256 context cannot
 * be used again.
 * SHA3-256 context should be already correctly initialized by libspdm_sha3_256_init(), and should not be
 * finalized by libspdm_sha3_256_final(). Behavior with invalid SHA3-256 context is undefined.
 *
 * If sha3_256_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA3-256 digest
 *                                value (256 / 8 bytes).
 *
 * @retval true   SHA3-256 digest computation succeeded.
 * @retval false  SHA3-256 digest computation failed.
 *
 **/
bool libspdm_sha3_256_final(void *sha3_256_context, uint8_t *hash_value)
{
    int ret;

    if (sha3_256_context == NULL || hash_value == NULL) {
        return false;
    }

    ret = mbedtls_sha3_finish(sha3_256_context, hash_value, LIBSPDM_SHA3_256_DIGEST_SIZE);
    mbedtls_sha3_free(sha3_256_context);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Computes the SHA3-256 message digest of a input data buffer.
 *
 * This function performs the SHA3-256 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA3-256 digest
 *                         value (256 / 8 bytes).
 *
 * @retval true   SHA3-256 digest computation succeeded.
 * @retval false  SHA3-256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_256_hash_all(const void *data, size_t data_size,
                               uint8_t *hash_value)
{
    int ret;

    if (hash_value == NULL) {
        return false;
    }
    if (data == NULL && data_size != 0) {
        return false;
    }
    if (data_size > INT_MAX) {
        return false;
    }

    ret = mbedtls_sha3(MBEDTLS_SHA3_256, data, data_size, hash_value, LIBSPDM_SHA3_256_DIGEST_SIZE);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA3-384 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha3_384_new() returns NULL.
 *
 **/
void *libspdm_sha3_384_new(void)
{
    void *hmac_md_ctx;

    hmac_md_ctx = allocate_zero_pool(sizeof(mbedtls_sha3_context));
    if (hmac_md_ctx == NULL) {
        return NULL;
    }

    return hmac_md_ctx;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha3_384_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha3_384_free(void *sha3_384_ctx)
{
    mbedtls_sha3_free(sha3_384_ctx);
    free_pool (sha3_384_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha3_384_context as SHA3-384 hash context for
 * subsequent use.
 *
 * If sha3_384_context is NULL, then return false.
 *
 * @param[out]  sha3_384_context  Pointer to SHA3-384 context being initialized.
 *
 * @retval true   SHA3-384 context initialization succeeded.
 * @retval false  SHA3-384 context initialization failed.
 *
 **/
bool libspdm_sha3_384_init(void *sha3_384_context)
{
    int ret;

    if (sha3_384_context == NULL) {
        return false;
    }

    mbedtls_sha3_init(sha3_384_context);

    ret = mbedtls_sha3_starts(sha3_384_context, MBEDTLS_SHA3_384);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Makes a copy of an existing SHA3-384 context.
 *
 * If sha3_384_context is NULL, then return false.
 * If new_sha3_384_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha3_384_context     Pointer to SHA3-384 context being copied.
 * @param[out] new_sha3_384_context  Pointer to new SHA3-384 context.
 *
 * @retval true   SHA3-384 context copy succeeded.
 * @retval false  SHA3-384 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_384_duplicate(const void *sha3_384_context,
                                void *new_sha3_384_context)
{
    if (sha3_384_context == NULL || new_sha3_384_context == NULL) {
        return false;
    }

    mbedtls_sha3_clone(new_sha3_384_context, sha3_384_context);

    return true;
}

/**
 * Digests the input data and updates SHA3-384 context.
 *
 * This function performs SHA3-384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA3-384 context should be already correctly initialized by libspdm_sha3_384_init(), and should not be finalized
 * by libspdm_sha3_384_final(). Behavior with invalid context is undefined.
 *
 * If sha3_384_context is NULL, then return false.
 *
 * @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA3-384 data digest succeeded.
 * @retval false  SHA3-384 data digest failed.
 *
 **/
bool libspdm_sha3_384_update(void *sha3_384_context, const void *data,
                             size_t data_size)
{
    int ret;

    if (sha3_384_context == NULL) {
        return false;
    }

    if (data == NULL && data_size != 0) {
        return false;
    }
    if (data_size > INT_MAX) {
        return false;
    }

    ret = mbedtls_sha3_update(sha3_384_context, data, data_size);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Completes computation of the SHA3-384 digest value.
 *
 * This function completes SHA3-384 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA3-384 context cannot
 * be used again.
 * SHA3-384 context should be already correctly initialized by libspdm_sha3_384_init(), and should not be
 * finalized by libspdm_sha3_384_final(). Behavior with invalid SHA3-384 context is undefined.
 *
 * If sha3_384_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA3-384 digest
 *                                value (384 / 8 bytes).
 *
 * @retval true   SHA3-384 digest computation succeeded.
 * @retval false  SHA3-384 digest computation failed.
 *
 **/
bool libspdm_sha3_384_final(void *sha3_384_context, uint8_t *hash_value)
{
    int ret;

    if (sha3_384_context == NULL || hash_value == NULL) {
        return false;
    }

    ret = mbedtls_sha3_finish(sha3_384_context, hash_value, LIBSPDM_SHA3_384_DIGEST_SIZE);
    mbedtls_sha3_free(sha3_384_context);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Computes the SHA3-384 message digest of a input data buffer.
 *
 * This function performs the SHA3-384 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA3-384 digest
 *                         value (384 / 8 bytes).
 *
 * @retval true   SHA3-384 digest computation succeeded.
 * @retval false  SHA3-384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_384_hash_all(const void *data, size_t data_size,
                               uint8_t *hash_value)
{
    int ret;

    if (hash_value == NULL) {
        return false;
    }
    if (data == NULL && data_size != 0) {
        return false;
    }
    if (data_size > INT_MAX) {
        return false;
    }

    ret = mbedtls_sha3(MBEDTLS_SHA3_384, data, data_size, hash_value, LIBSPDM_SHA3_384_DIGEST_SIZE);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA3-512 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha3_512_new() returns NULL.
 *
 **/
void *libspdm_sha3_512_new(void)
{
    void *hmac_md_ctx;

    hmac_md_ctx = allocate_zero_pool(sizeof(mbedtls_sha3_context));
    if (hmac_md_ctx == NULL) {
        return NULL;
    }

    return hmac_md_ctx;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha3_512_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha3_512_free(void *sha3_512_ctx)
{
    mbedtls_sha3_free(sha3_512_ctx);
    free_pool (sha3_512_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha3_512_context as SHA3-512 hash context for
 * subsequent use.
 *
 * If sha3_512_context is NULL, then return false.
 *
 * @param[out]  sha3_512_context  Pointer to SHA3-512 context being initialized.
 *
 * @retval true   SHA3-512 context initialization succeeded.
 * @retval false  SHA3-512 context initialization failed.
 *
 **/
bool libspdm_sha3_512_init(void *sha3_512_context)
{
    int ret;

    if (sha3_512_context == NULL) {
        return false;
    }

    mbedtls_sha3_init(sha3_512_context);

    ret = mbedtls_sha3_starts(sha3_512_context, MBEDTLS_SHA3_512);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Makes a copy of an existing SHA3-512 context.
 *
 * If sha3_512_context is NULL, then return false.
 * If new_sha3_512_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha3_512_context     Pointer to SHA3-512 context being copied.
 * @param[out] new_sha3_512_context  Pointer to new SHA3-512 context.
 *
 * @retval true   SHA3-512 context copy succeeded.
 * @retval false  SHA3-512 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_512_duplicate(const void *sha3_512_context,
                                void *new_sha3_512_context)
{
    if (sha3_512_context == NULL || new_sha3_512_context == NULL) {
        return false;
    }

    mbedtls_sha3_clone(new_sha3_512_context, sha3_512_context);

    return true;
}

/**
 * Digests the input data and updates SHA3-512 context.
 *
 * This function performs SHA3-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA3-512 context should be already correctly initialized by libspdm_sha3_512_init(), and should not be finalized
 * by libspdm_sha3_512_final(). Behavior with invalid context is undefined.
 *
 * If sha3_512_context is NULL, then return false.
 *
 * @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA3-512 data digest succeeded.
 * @retval false  SHA3-512 data digest failed.
 *
 **/
bool libspdm_sha3_512_update(void *sha3_512_context, const void *data,
                             size_t data_size)
{
    int ret;

    if (sha3_512_context == NULL) {
        return false;
    }

    if (data == NULL && data_size != 0) {
        return false;
    }
    if (data_size > INT_MAX) {
        return false;
    }

    ret = mbedtls_sha3_update(sha3_512_context, data, data_size);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Completes computation of the SHA3-512 digest value.
 *
 * This function completes SHA3-512 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA3-512 context cannot
 * be used again.
 * SHA3-512 context should be already correctly initialized by libspdm_sha3_512_init(), and should not be
 * finalized by libspdm_sha3_512_final(). Behavior with invalid SHA3-512 context is undefined.
 *
 * If sha3_512_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA3-512 digest
 *                                value (512 / 8 bytes).
 *
 * @retval true   SHA3-512 digest computation succeeded.
 * @retval false  SHA3-512 digest computation failed.
 *
 **/
bool libspdm_sha3_512_final(void *sha3_512_context, uint8_t *hash_value)
{
    int ret;

    if (sha3_512_context == NULL || hash_value == NULL) {
        return false;
    }

    ret = mbedtls_sha3_finish(sha3_512_context, hash_value, LIBSPDM_SHA3_512_DIGEST_SIZE);
    mbedtls_sha3_free(sha3_512_context);
    if (ret != 0) {
        return false;
    }
    return true;
}

/**
 * Computes the SHA3-512 message digest of a input data buffer.
 *
 * This function performs the SHA3-512 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA3-512 digest
 *                         value (512 / 8 bytes).
 *
 * @retval true   SHA3-512 digest computation succeeded.
 * @retval false  SHA3-512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_512_hash_all(const void *data, size_t data_size,
                               uint8_t *hash_value)
{
    int ret;

    if (hash_value == NULL) {
        return false;
    }
    if (data == NULL && data_size != 0) {
        return false;
    }
    if (data_size > INT_MAX) {
        return false;
    }

    ret = mbedtls_sha3(MBEDTLS_SHA3_512, data, data_size, hash_value, LIBSPDM_SHA3_512_DIGEST_SIZE);
    if (ret != 0) {
        return false;
    }
    return true;
}
