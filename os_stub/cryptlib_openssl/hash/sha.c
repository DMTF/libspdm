/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SHA-256/384/512 digest Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

/**
 * Allocates and initializes one HASH_CTX context for subsequent MD use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, hash_md_new() returns NULL.
 *
 **/
void *hash_md_new(void)
{
    return EVP_MD_CTX_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  md_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void hash_md_free(IN void *md_ctx)
{
    EVP_MD_CTX_free(md_ctx);
}

/**
 * Initializes user-supplied memory pointed by md_ctx as hash context for
 * subsequent use.
 *
 * If md_ctx is NULL, then return FALSE.
 *
 * @param[in]   md                 message digest.
 * @param[out]  md_ctx  Pointer to MD context being initialized.
 *
 * @retval TRUE   MD context initialization succeeded.
 * @retval FALSE  MD context initialization failed.
 *
 **/
boolean hash_md_init(IN const EVP_MD *md, OUT void *md_ctx)
{
    if (md_ctx == NULL) {
        return FALSE;
    }
    if (EVP_DigestInit(md_ctx, md) != 1) {
        return FALSE;
    }
    return TRUE;
}

/**
 * Makes a copy of an existing MD context.
 *
 * If md_ctx is NULL, then return FALSE.
 * If new_md_ctx is NULL, then return FALSE.
 * If this interface is not supported, then return FALSE.
 *
 * @param[in]  md_ctx     Pointer to MD context being copied.
 * @param[out] new_md_ctx  Pointer to new MD context.
 *
 * @retval TRUE   MD context copy succeeded.
 * @retval FALSE  MD context copy failed.
 * @retval FALSE  This interface is not supported.
 *
 **/
boolean hash_md_duplicate(IN const void *md_ctx, OUT void *new_md_ctx)
{
    if (md_ctx == NULL || new_md_ctx == NULL) {
        return FALSE;
    }
    if (EVP_MD_CTX_copy(new_md_ctx, md_ctx) != 1) {
        return FALSE;
    }
    return TRUE;
}

/**
 * Digests the input data and updates MD context.
 *
 * This function performs MD digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * MD context should be already correctly initialized by hash_md_init(), and should not be finalized
 * by hash_md_final(). Behavior with invalid context is undefined.
 *
 * If md_ctx is NULL, then return FALSE.
 *
 * @param[in, out]  md_ctx  Pointer to the MD context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval TRUE   MD data digest succeeded.
 * @retval FALSE  MD data digest failed.
 *
 **/
boolean hash_md_update(IN void *md_ctx, IN const void *data, IN uintn data_size)
{
    if (md_ctx == NULL) {
        return FALSE;
    }
    if (data == NULL && data_size != 0) {
        return FALSE;
    }
    if (EVP_DigestUpdate(md_ctx, data, data_size) != 1) {
        return FALSE;
    }
    return TRUE;
}

/**
 * Completes computation of the MD digest value.
 *
 * This function completes MD hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the MD context cannot
 * be used again.
 * MD context should be already correctly initialized by hash_md_init(), and should not be
 * finalized by hash_md_final(). Behavior with invalid MD context is undefined.
 *
 * If md_ctx is NULL, then return FALSE.
 * If hash_value is NULL, then return FALSE.
 *
 * @param[in, out]  md_ctx  Pointer to the MD context.
 * @param[out]      hash_value      Pointer to a buffer that receives the MD digest value.
 *
 * @retval TRUE   MD digest computation succeeded.
 * @retval FALSE  MD digest computation failed.
 *
 **/
boolean hash_md_final(IN void *md_ctx, OUT void *hash_value)
{
    if (md_ctx == NULL || hash_value == NULL) {
        return FALSE;
    }

    if (EVP_DigestFinal(md_ctx, hash_value, NULL) != 1) {
        return FALSE;
    }
    return TRUE;
}

/**
 * Computes the MD message digest of a input data buffer.
 *
 * This function performs the MD message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return FALSE.
 *
 * @param[in]   md                 message digest.
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the MD digest value.
 *
 * @retval TRUE   MD digest computation succeeded.
 * @retval FALSE  MD digest computation failed.
 * @retval FALSE  This interface is not supported.
 *
 **/
boolean hash_md_hash_all(IN const EVP_MD *md, IN const void *data, IN uintn data_size,
                         OUT uint8_t *hash_value)
{
    if (hash_value == NULL) {
        return FALSE;
    }
    if (data == NULL && data_size != 0) {
        return FALSE;
    }

    if (EVP_Digest(data, data_size, hash_value, NULL, md, NULL) != 1) {
        return FALSE;
    }
    return TRUE;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA256 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, sha256_new() returns NULL.
 *
 **/
void *sha256_new(void)
{
    return hash_md_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha256_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void sha256_free(IN void *sha256_ctx)
{
    hash_md_free(sha256_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha256_context as SHA-256 hash context for
 * subsequent use.
 *
 * If sha256_context is NULL, then return FALSE.
 *
 * @param[out]  sha256_context  Pointer to SHA-256 context being initialized.
 *
 * @retval TRUE   SHA-256 context initialization succeeded.
 * @retval FALSE  SHA-256 context initialization failed.
 *
 **/
boolean sha256_init(OUT void *sha256_context)
{
    return hash_md_init (EVP_sha256(), sha256_context);
}

/**
 * Makes a copy of an existing SHA-256 context.
 *
 * If sha256_context is NULL, then return FALSE.
 * If new_sha256_context is NULL, then return FALSE.
 *
 * @param[in]  sha256_context     Pointer to SHA-256 context being copied.
 * @param[out] new_sha256_context  Pointer to new SHA-256 context.
 *
 * @retval TRUE   SHA-256 context copy succeeded.
 * @retval FALSE  SHA-256 context copy failed.
 *
 **/
boolean sha256_duplicate(IN const void *sha256_context,
                         OUT void *new_sha256_context)
{
    return hash_md_duplicate (sha256_context, new_sha256_context);
}

/**
 * Digests the input data and updates SHA-256 context.
 *
 * This function performs SHA-256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-256 context should be already correctly initialized by sha256_init(), and should not be finalized
 * by sha256_final(). Behavior with invalid context is undefined.
 *
 * If sha256_context is NULL, then return FALSE.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval TRUE   SHA-256 data digest succeeded.
 * @retval FALSE  SHA-256 data digest failed.
 *
 **/
boolean sha256_update(IN OUT void *sha256_context, IN const void *data,
                      IN uintn data_size)
{
    return hash_md_update (sha256_context, data, data_size);
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
 * If sha256_context is NULL, then return FALSE.
 * If hash_value is NULL, then return FALSE.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-256 digest
 *                                value (32 bytes).
 *
 * @retval TRUE   SHA-256 digest computation succeeded.
 * @retval FALSE  SHA-256 digest computation failed.
 *
 **/
boolean sha256_final(IN OUT void *sha256_context, OUT uint8_t *hash_value)
{
    return hash_md_final (sha256_context, hash_value);
}

/**
 * Computes the SHA-256 message digest of a input data buffer.
 *
 * This function performs the SHA-256 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return FALSE.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-256 digest
 *                         value (32 bytes).
 *
 * @retval TRUE   SHA-256 digest computation succeeded.
 * @retval FALSE  SHA-256 digest computation failed.
 * @retval FALSE  This interface is not supported.
 *
 **/
boolean sha256_hash_all(IN const void *data, IN uintn data_size,
                        OUT uint8_t *hash_value)
{
    return hash_md_hash_all (EVP_sha256(), data, data_size, hash_value);
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
    return hash_md_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha384_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void sha384_free(IN void *sha384_ctx)
{
    hash_md_free(sha384_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha384_context as SHA-384 hash context for
 * subsequent use.
 *
 * If sha384_context is NULL, then return FALSE.
 *
 * @param[out]  sha384_context  Pointer to SHA-384 context being initialized.
 *
 * @retval TRUE   SHA-384 context initialization succeeded.
 * @retval FALSE  SHA-384 context initialization failed.
 *
 **/
boolean sha384_init(OUT void *sha384_context)
{
    return hash_md_init (EVP_sha384(), sha384_context);
}

/**
 * Makes a copy of an existing SHA-384 context.
 *
 * If sha384_context is NULL, then return FALSE.
 * If new_sha384_context is NULL, then return FALSE.
 * If this interface is not supported, then return FALSE.
 *
 * @param[in]  sha384_context     Pointer to SHA-384 context being copied.
 * @param[out] new_sha384_context  Pointer to new SHA-384 context.
 *
 * @retval TRUE   SHA-384 context copy succeeded.
 * @retval FALSE  SHA-384 context copy failed.
 * @retval FALSE  This interface is not supported.
 *
 **/
boolean sha384_duplicate(IN const void *sha384_context,
                         OUT void *new_sha384_context)
{
    return hash_md_duplicate (sha384_context, new_sha384_context);
}

/**
 * Digests the input data and updates SHA-384 context.
 *
 * This function performs SHA-384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-384 context should be already correctly initialized by sha384_init(), and should not be finalized
 * by sha384_final(). Behavior with invalid context is undefined.
 *
 * If sha384_context is NULL, then return FALSE.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval TRUE   SHA-384 data digest succeeded.
 * @retval FALSE  SHA-384 data digest failed.
 *
 **/
boolean sha384_update(IN OUT void *sha384_context, IN const void *data,
                      IN uintn data_size)
{
    return hash_md_update (sha384_context, data, data_size);
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
 * If sha384_context is NULL, then return FALSE.
 * If hash_value is NULL, then return FALSE.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-384 digest
 *                                value (48 bytes).
 *
 * @retval TRUE   SHA-384 digest computation succeeded.
 * @retval FALSE  SHA-384 digest computation failed.
 *
 **/
boolean sha384_final(IN OUT void *sha384_context, OUT uint8_t *hash_value)
{
    return hash_md_final (sha384_context, hash_value);
}

/**
 * Computes the SHA-384 message digest of a input data buffer.
 *
 * This function performs the SHA-384 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return FALSE.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-384 digest
 *                         value (48 bytes).
 *
 * @retval TRUE   SHA-384 digest computation succeeded.
 * @retval FALSE  SHA-384 digest computation failed.
 * @retval FALSE  This interface is not supported.
 *
 **/
boolean sha384_hash_all(IN const void *data, IN uintn data_size,
                        OUT uint8_t *hash_value)
{
    return hash_md_hash_all (EVP_sha384(), data, data_size, hash_value);
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
    return hash_md_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha512_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void sha512_free(IN void *sha512_ctx)
{
    hash_md_free(sha512_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha512_context as SHA-512 hash context for
 * subsequent use.
 *
 * If sha512_context is NULL, then return FALSE.
 *
 * @param[out]  sha512_context  Pointer to SHA-512 context being initialized.
 *
 * @retval TRUE   SHA-512 context initialization succeeded.
 * @retval FALSE  SHA-512 context initialization failed.
 *
 **/
boolean sha512_init(OUT void *sha512_context)
{
    return hash_md_init (EVP_sha512(), sha512_context);
}

/**
 * Makes a copy of an existing SHA-512 context.
 *
 * If sha512_context is NULL, then return FALSE.
 * If new_sha512_context is NULL, then return FALSE.
 * If this interface is not supported, then return FALSE.
 *
 * @param[in]  sha512_context     Pointer to SHA-512 context being copied.
 * @param[out] new_sha512_context  Pointer to new SHA-512 context.
 *
 * @retval TRUE   SHA-512 context copy succeeded.
 * @retval FALSE  SHA-512 context copy failed.
 * @retval FALSE  This interface is not supported.
 *
 **/
boolean sha512_duplicate(IN const void *sha512_context,
                         OUT void *new_sha512_context)
{
    return hash_md_duplicate (sha512_context, new_sha512_context);
}

/**
 * Digests the input data and updates SHA-512 context.
 *
 * This function performs SHA-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-512 context should be already correctly initialized by sha512_init(), and should not be finalized
 * by sha512_final(). Behavior with invalid context is undefined.
 *
 * If sha512_context is NULL, then return FALSE.
 *
 * @param[in, out]  sha512_context  Pointer to the SHA-512 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval TRUE   SHA-512 data digest succeeded.
 * @retval FALSE  SHA-512 data digest failed.
 *
 **/
boolean sha512_update(IN OUT void *sha512_context, IN const void *data,
                      IN uintn data_size)
{
    return hash_md_update (sha512_context, data, data_size);
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
 * If sha512_context is NULL, then return FALSE.
 * If hash_value is NULL, then return FALSE.
 *
 * @param[in, out]  sha512_context  Pointer to the SHA-512 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-512 digest
 *                                value (64 bytes).
 *
 * @retval TRUE   SHA-512 digest computation succeeded.
 * @retval FALSE  SHA-512 digest computation failed.
 *
 **/
boolean sha512_final(IN OUT void *sha512_context, OUT uint8_t *hash_value)
{
    return hash_md_final (sha512_context, hash_value);
}

/**
 * Computes the SHA-512 message digest of a input data buffer.
 *
 * This function performs the SHA-512 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return FALSE.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-512 digest
 *                         value (64 bytes).
 *
 * @retval TRUE   SHA-512 digest computation succeeded.
 * @retval FALSE  SHA-512 digest computation failed.
 * @retval FALSE  This interface is not supported.
 *
 **/
boolean sha512_hash_all(IN const void *data, IN uintn data_size,
                        OUT uint8_t *hash_value)
{
    return hash_md_hash_all (EVP_sha512(), data, data_size, hash_value);
}
