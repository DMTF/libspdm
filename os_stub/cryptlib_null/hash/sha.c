/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SHA-256/384/512 digest Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA256 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, sha256_new() returns NULL.
 *
 **/
void *sha256_new(void)
{
    ASSERT(false);
    return NULL;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha256_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void sha256_free(IN void *sha256_ctx)
{
    ASSERT(false);
}

/**
 * Initializes user-supplied memory pointed by sha256_context as SHA-256 hash context for
 * subsequent use.
 *
 * If sha256_context is NULL, then return false.
 *
 * @param[out]  sha256_context  Pointer to SHA-256 context being initialized.
 *
 * @retval true   SHA-256 context initialization succeeded.
 * @retval false  SHA-256 context initialization failed.
 *
 **/
bool sha256_init(OUT void *sha256_context)
{
    ASSERT(false);
    return false;
}

/**
 * Makes a copy of an existing SHA-256 context.
 *
 * If sha256_context is NULL, then return false.
 * If new_sha256_context is NULL, then return false.
 *
 * @param[in]  sha256_context     Pointer to SHA-256 context being copied.
 * @param[out] new_sha256_context  Pointer to new SHA-256 context.
 *
 * @retval true   SHA-256 context copy succeeded.
 * @retval false  SHA-256 context copy failed.
 *
 **/
bool sha256_duplicate(IN const void *sha256_context,
                         OUT void *new_sha256_context)
{
    ASSERT(false);
    return false;
}

/**
 * Digests the input data and updates SHA-256 context.
 *
 * This function performs SHA-256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-256 context should be already correctly initialized by sha256_init(), and should not be finalized
 * by sha256_final(). Behavior with invalid context is undefined.
 *
 * If sha256_context is NULL, then return false.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA-256 data digest succeeded.
 * @retval false  SHA-256 data digest failed.
 *
 **/
bool sha256_update(IN OUT void *sha256_context, IN const void *data,
                      IN uintn data_size)
{
    ASSERT(false);
    return false;
}

/**
 * Completes computation of the SHA-256 digest value.
 *
 * This function completes SHA-256 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA-256 context cannot
 * be used again.
 * SHA-256 context should be already correctly initialized by sha256_init(), and should not be
 * finalized by sha256_final(). Behavior with invalid SHA-256 context is undefined.
 *
 * If sha256_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-256 digest
 *                                value (32 bytes).
 *
 * @retval true   SHA-256 digest computation succeeded.
 * @retval false  SHA-256 digest computation failed.
 *
 **/
bool sha256_final(IN OUT void *sha256_context, OUT uint8_t *hash_value)
{
    ASSERT(false);
    return false;
}

/**
 * Computes the SHA-256 message digest of a input data buffer.
 *
 * This function performs the SHA-256 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-256 digest
 *                         value (32 bytes).
 *
 * @retval true   SHA-256 digest computation succeeded.
 * @retval false  SHA-256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool sha256_hash_all(IN const void *data, IN uintn data_size,
                        OUT uint8_t *hash_value)
{
    ASSERT(false);
    return false;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA384 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, sha384_new() returns NULL.
 *
 **/
void *sha384_new(void)
{
    ASSERT(false);
    return NULL;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha384_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void sha384_free(IN void *sha384_ctx)
{
    ASSERT(false);
}

/**
 * Initializes user-supplied memory pointed by sha384_context as SHA-384 hash context for
 * subsequent use.
 *
 * If sha384_context is NULL, then return false.
 *
 * @param[out]  sha384_context  Pointer to SHA-384 context being initialized.
 *
 * @retval true   SHA-384 context initialization succeeded.
 * @retval false  SHA-384 context initialization failed.
 *
 **/
bool sha384_init(OUT void *sha384_context)
{
    ASSERT(false);
    return false;
}

/**
 * Makes a copy of an existing SHA-384 context.
 *
 * If sha384_context is NULL, then return false.
 * If new_sha384_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha384_context     Pointer to SHA-384 context being copied.
 * @param[out] new_sha384_context  Pointer to new SHA-384 context.
 *
 * @retval true   SHA-384 context copy succeeded.
 * @retval false  SHA-384 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool sha384_duplicate(IN const void *sha384_context,
                         OUT void *new_sha384_context)
{
    ASSERT(false);
    return false;
}

/**
 * Digests the input data and updates SHA-384 context.
 *
 * This function performs SHA-384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-384 context should be already correctly initialized by sha384_init(), and should not be finalized
 * by sha384_final(). Behavior with invalid context is undefined.
 *
 * If sha384_context is NULL, then return false.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA-384 data digest succeeded.
 * @retval false  SHA-384 data digest failed.
 *
 **/
bool sha384_update(IN OUT void *sha384_context, IN const void *data,
                      IN uintn data_size)
{
    ASSERT(false);
    return false;
}

/**
 * Completes computation of the SHA-384 digest value.
 *
 * This function completes SHA-384 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA-384 context cannot
 * be used again.
 * SHA-384 context should be already correctly initialized by sha384_init(), and should not be
 * finalized by sha384_final(). Behavior with invalid SHA-384 context is undefined.
 *
 * If sha384_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-384 digest
 *                                value (48 bytes).
 *
 * @retval true   SHA-384 digest computation succeeded.
 * @retval false  SHA-384 digest computation failed.
 *
 **/
bool sha384_final(IN OUT void *sha384_context, OUT uint8_t *hash_value)
{
    ASSERT(false);
    return false;
}

/**
 * Computes the SHA-384 message digest of a input data buffer.
 *
 * This function performs the SHA-384 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-384 digest
 *                         value (48 bytes).
 *
 * @retval true   SHA-384 digest computation succeeded.
 * @retval false  SHA-384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool sha384_hash_all(IN const void *data, IN uintn data_size,
                        OUT uint8_t *hash_value)
{
    ASSERT(false);
    return false;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA512 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, sha512_new() returns NULL.
 *
 **/
void *sha512_new(void)
{
    ASSERT(false);
    return NULL;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha512_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void sha512_free(IN void *sha512_ctx)
{
    ASSERT(false);
}

/**
 * Initializes user-supplied memory pointed by sha512_context as SHA-512 hash context for
 * subsequent use.
 *
 * If sha512_context is NULL, then return false.
 *
 * @param[out]  sha512_context  Pointer to SHA-512 context being initialized.
 *
 * @retval true   SHA-512 context initialization succeeded.
 * @retval false  SHA-512 context initialization failed.
 *
 **/
bool sha512_init(OUT void *sha512_context)
{
    ASSERT(false);
    return false;
}

/**
 * Makes a copy of an existing SHA-512 context.
 *
 * If sha512_context is NULL, then return false.
 * If new_sha512_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha512_context     Pointer to SHA-512 context being copied.
 * @param[out] new_sha512_context  Pointer to new SHA-512 context.
 *
 * @retval true   SHA-512 context copy succeeded.
 * @retval false  SHA-512 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool sha512_duplicate(IN const void *sha512_context,
                         OUT void *new_sha512_context)
{
    ASSERT(false);
    return false;
}

/**
 * Digests the input data and updates SHA-512 context.
 *
 * This function performs SHA-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-512 context should be already correctly initialized by sha512_init(), and should not be finalized
 * by sha512_final(). Behavior with invalid context is undefined.
 *
 * If sha512_context is NULL, then return false.
 *
 * @param[in, out]  sha512_context  Pointer to the SHA-512 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA-512 data digest succeeded.
 * @retval false  SHA-512 data digest failed.
 *
 **/
bool sha512_update(IN OUT void *sha512_context, IN const void *data,
                      IN uintn data_size)
{
    ASSERT(false);
    return false;
}

/**
 * Completes computation of the SHA-512 digest value.
 *
 * This function completes SHA-512 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA-512 context cannot
 * be used again.
 * SHA-512 context should be already correctly initialized by sha512_init(), and should not be
 * finalized by sha512_final(). Behavior with invalid SHA-512 context is undefined.
 *
 * If sha512_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha512_context  Pointer to the SHA-512 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-512 digest
 *                                value (64 bytes).
 *
 * @retval true   SHA-512 digest computation succeeded.
 * @retval false  SHA-512 digest computation failed.
 *
 **/
bool sha512_final(IN OUT void *sha512_context, OUT uint8_t *hash_value)
{
    ASSERT(false);
    return false;
}

/**
 * Computes the SHA-512 message digest of a input data buffer.
 *
 * This function performs the SHA-512 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-512 digest
 *                         value (64 bytes).
 *
 * @retval true   SHA-512 digest computation succeeded.
 * @retval false  SHA-512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool sha512_hash_all(IN const void *data, IN uintn data_size,
                        OUT uint8_t *hash_value)
{
    ASSERT(false);
    return false;
}
