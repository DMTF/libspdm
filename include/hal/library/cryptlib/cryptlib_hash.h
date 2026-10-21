/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_HASH_H
#define CRYPTLIB_HASH_H

/* SHA-256 digest size in bytes. */
#define LIBSPDM_SHA256_DIGEST_SIZE 32

/* SHA-384 digest size in bytes. */
#define LIBSPDM_SHA384_DIGEST_SIZE 48

/* SHA-512 digest size in bytes. */
#define LIBSPDM_SHA512_DIGEST_SIZE 64

/* SHA3-256 digest size in bytes. */
#define LIBSPDM_SHA3_256_DIGEST_SIZE 32

/* SHA3-384 digest size in bytes. */
#define LIBSPDM_SHA3_384_DIGEST_SIZE 48

/* SHA3-512 digest size in bytes. */
#define LIBSPDM_SHA3_512_DIGEST_SIZE 64

/* SM3_256 digest size in bytes. */
#define LIBSPDM_SM3_256_DIGEST_SIZE 32

/*=====================================================================================
 *    One-way cryptographic hash SHA2 primitives.
 *=====================================================================================
 */
#if LIBSPDM_SHA256_SUPPORT
/**
 * Allocates one SHA-256 context.
 *
 * The context must be initialized by libspdm_sha256_init(), or be the destination of
 * libspdm_sha256_duplicate(), before any other use.
 *
 * @return  Pointer to the SHA-256 context, or NULL if the allocation fails.
 **/
extern void *libspdm_sha256_new(void);

/**
 * Release the specified SHA-256 context.
 *
 * @param[in]  sha256_context  Pointer to the SHA-256 context to be released.
 **/
extern void libspdm_sha256_free(void *sha256_context);

/**
 * Initializes a context, which libspdm_sha256_new() allocated, for subsequent SHA-256 use.
 *
 * If sha256_context is NULL, then return false.
 *
 * @param[out]  sha256_context  Pointer to SHA-256 context being initialized.
 *
 * @retval true   SHA-256 context initialization succeeded.
 * @retval false  SHA-256 context initialization failed.
 **/
extern bool libspdm_sha256_init(void *sha256_context);

/**
 * Makes a copy of an existing SHA-256 context.
 *
 * new_sha256_context is a context that libspdm_sha256_new() allocated and that has not been
 * initialized. The copy is independent of the original, so each can be updated, finalized and
 * released separately.
 *
 * If sha256_context is NULL, then return false.
 * If new_sha256_context is NULL, then return false.
 *
 * @param[in]  sha256_context      Pointer to SHA-256 context being copied.
 * @param[out] new_sha256_context  Pointer to new SHA-256 context.
 *
 * @retval true   SHA-256 context copy succeeded.
 * @retval false  SHA-256 context copy failed.
 **/
extern bool libspdm_sha256_duplicate(const void *sha256_context, void *new_sha256_context);

/**
 * Digests the input data and updates SHA-256 context.
 *
 * This function performs SHA-256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * The SHA-256 context should be already correctly initialized by libspdm_sha256_init() or
 * libspdm_sha256_duplicate(), and must not have been finalized by libspdm_sha256_final(). Behavior
 * with invalid context is undefined.
 *
 * If sha256_context is NULL, then return false.
 * If data is NULL and data_size is not 0, then return false.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[in]       data            Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       Size of data buffer in bytes.
 *
 * @retval true   SHA-256 data digest succeeded.
 * @retval false  SHA-256 data digest failed.
 **/
extern bool libspdm_sha256_update(void *sha256_context, const void *data, size_t data_size);

/**
 * Completes computation of the SHA-256 digest value.
 *
 * This function completes SHA-256 hash computation and populates the digest value into the
 * specified memory. After this function has been called, the SHA-256 context cannot be used again,
 * except to release it with libspdm_sha256_free(). The SHA-256 context should be already correctly
 * initialized by libspdm_sha256_init() or libspdm_sha256_duplicate(), and must not have been
 * finalized by libspdm_sha256_final(). Behavior with invalid SHA-256 context is undefined.
 *
 * If sha256_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-256 digest
 *                                  value (32 bytes).
 *
 * @retval true   SHA-256 digest computation succeeded.
 * @retval false  SHA-256 digest computation failed.
 **/
extern bool libspdm_sha256_final(void *sha256_context, uint8_t *hash_value);

/**
 * Computes the SHA-256 message digest of an input data buffer.
 *
 * This function performs the SHA-256 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Pointer to a buffer that receives the SHA-256 digest value (32 bytes).
 *
 * @retval true   SHA-256 digest computation succeeded.
 * @retval false  SHA-256 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_sha256_hash_all(const void *data, size_t data_size, uint8_t *hash_value);
#endif /* LIBSPDM_SHA256_SUPPORT */

#if LIBSPDM_SHA384_SUPPORT
/**
 * Allocates one SHA-384 context.
 *
 * The context must be initialized by libspdm_sha384_init(), or be the destination of
 * libspdm_sha384_duplicate(), before any other use.
 *
 * @return  Pointer to the SHA-384 context, or NULL if the allocation fails.
 **/
extern void *libspdm_sha384_new(void);

/**
 * Release the specified SHA-384 context.
 *
 * @param[in]  sha384_context  Pointer to the SHA-384 context to be released.
 **/
extern void libspdm_sha384_free(void *sha384_context);

/**
 * Initializes a context, which libspdm_sha384_new() allocated, for subsequent SHA-384 use.
 *
 * If sha384_context is NULL, then return false.
 *
 * @param[out]  sha384_context  Pointer to SHA-384 context being initialized.
 *
 * @retval true   SHA-384 context initialization succeeded.
 * @retval false  SHA-384 context initialization failed.
 **/
extern bool libspdm_sha384_init(void *sha384_context);

/**
 * Makes a copy of an existing SHA-384 context.
 *
 * new_sha384_context is a context that libspdm_sha384_new() allocated and that has not been
 * initialized. The copy is independent of the original, so each can be updated, finalized and
 * released separately.
 *
 * If sha384_context is NULL, then return false.
 * If new_sha384_context is NULL, then return false.
 *
 * @param[in]  sha384_context      Pointer to SHA-384 context being copied.
 * @param[out] new_sha384_context  Pointer to new SHA-384 context.
 *
 * @retval true   SHA-384 context copy succeeded.
 * @retval false  SHA-384 context copy failed.
 **/
extern bool libspdm_sha384_duplicate(const void *sha384_context, void *new_sha384_context);

/**
 * Digests the input data and updates SHA-384 context.
 *
 * This function performs SHA-384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * The SHA-384 context should be already correctly initialized by libspdm_sha384_init() or
 * libspdm_sha384_duplicate(), and must not have been finalized by libspdm_sha384_final(). Behavior
 * with invalid context is undefined.
 *
 * If sha384_context is NULL, then return false.
 * If data is NULL and data_size is not 0, then return false.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[in]       data            Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       Size of data buffer in bytes.
 *
 * @retval true   SHA-384 data digest succeeded.
 * @retval false  SHA-384 data digest failed.
 **/
extern bool libspdm_sha384_update(void *sha384_context, const void *data, size_t data_size);

/**
 * Completes computation of the SHA-384 digest value.
 *
 * This function completes SHA-384 hash computation and populates the digest value into the
 * specified memory. After this function has been called, the SHA-384 context cannot be used again,
 * except to release it with libspdm_sha384_free(). The SHA-384 context should be already correctly
 * initialized by libspdm_sha384_init() or libspdm_sha384_duplicate(), and must not have been
 * finalized by libspdm_sha384_final(). Behavior with invalid SHA-384 context is undefined.
 *
 * If sha384_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-384 digest
 *                                  value (48 bytes).
 *
 * @retval true   SHA-384 digest computation succeeded.
 * @retval false  SHA-384 digest computation failed.
 **/
extern bool libspdm_sha384_final(void *sha384_context, uint8_t *hash_value);

/**
 * Computes the SHA-384 message digest of an input data buffer.
 *
 * This function performs the SHA-384 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Pointer to a buffer that receives the SHA-384 digest value (48 bytes).
 *
 * @retval true   SHA-384 digest computation succeeded.
 * @retval false  SHA-384 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_sha384_hash_all(const void *data, size_t data_size, uint8_t *hash_value);
#endif /* LIBSPDM_SHA384_SUPPORT */

#if LIBSPDM_SHA512_SUPPORT
/**
 * Allocates one SHA-512 context.
 *
 * The context must be initialized by libspdm_sha512_init(), or be the destination of
 * libspdm_sha512_duplicate(), before any other use.
 *
 * @return  Pointer to the SHA-512 context, or NULL if the allocation fails.
 **/
extern void *libspdm_sha512_new(void);

/**
 * Release the specified SHA-512 context.
 *
 * @param[in]  sha512_context  Pointer to the SHA-512 context to be released.
 **/
extern void libspdm_sha512_free(void *sha512_context);

/**
 * Initializes a context, which libspdm_sha512_new() allocated, for subsequent SHA-512 use.
 *
 * If sha512_context is NULL, then return false.
 *
 * @param[out]  sha512_context  Pointer to SHA-512 context being initialized.
 *
 * @retval true   SHA-512 context initialization succeeded.
 * @retval false  SHA-512 context initialization failed.
 **/
extern bool libspdm_sha512_init(void *sha512_context);

/**
 * Makes a copy of an existing SHA-512 context.
 *
 * new_sha512_context is a context that libspdm_sha512_new() allocated and that has not been
 * initialized. The copy is independent of the original, so each can be updated, finalized and
 * released separately.
 *
 * If sha512_context is NULL, then return false.
 * If new_sha512_context is NULL, then return false.
 *
 * @param[in]  sha512_context      Pointer to SHA-512 context being copied.
 * @param[out] new_sha512_context  Pointer to new SHA-512 context.
 *
 * @retval true   SHA-512 context copy succeeded.
 * @retval false  SHA-512 context copy failed.
 **/
extern bool libspdm_sha512_duplicate(const void *sha512_context, void *new_sha512_context);

/**
 * Digests the input data and updates SHA-512 context.
 *
 * This function performs SHA-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * The SHA-512 context should be already correctly initialized by libspdm_sha512_init() or
 * libspdm_sha512_duplicate(), and must not have been finalized by libspdm_sha512_final(). Behavior
 * with invalid context is undefined.
 *
 * If sha512_context is NULL, then return false.
 * If data is NULL and data_size is not 0, then return false.
 *
 * @param[in, out]  sha512_context  Pointer to the SHA-512 context.
 * @param[in]       data            Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       Size of data buffer in bytes.
 *
 * @retval true   SHA-512 data digest succeeded.
 * @retval false  SHA-512 data digest failed.
 **/
extern bool libspdm_sha512_update(void *sha512_context, const void *data, size_t data_size);

/**
 * Completes computation of the SHA-512 digest value.
 *
 * This function completes SHA-512 hash computation and populates the digest value into the
 * specified memory. After this function has been called, the SHA-512 context cannot be used again,
 * except to release it with libspdm_sha512_free(). The SHA-512 context should be already correctly
 * initialized by libspdm_sha512_init() or libspdm_sha512_duplicate(), and must not have been
 * finalized by libspdm_sha512_final(). Behavior with invalid SHA-512 context is undefined.
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
 **/
extern bool libspdm_sha512_final(void *sha512_context, uint8_t *hash_value);

/**
 * Computes the SHA-512 message digest of an input data buffer.
 *
 * This function performs the SHA-512 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Pointer to a buffer that receives the SHA-512 digest value (64 bytes).
 *
 * @retval true   SHA-512 digest computation succeeded.
 * @retval false  SHA-512 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_sha512_hash_all(const void *data, size_t data_size, uint8_t *hash_value);
#endif /* LIBSPDM_SHA512_SUPPORT */

/*=====================================================================================
 *    One-way cryptographic hash SHA3 primitives.
 *=====================================================================================
 */
#if LIBSPDM_SHA3_256_SUPPORT
/**
 * Allocates one SHA3-256 context.
 *
 * The context must be initialized by libspdm_sha3_256_init(), or be the destination of
 * libspdm_sha3_256_duplicate(), before any other use.
 *
 * @return  Pointer to the SHA3-256 context, or NULL if the allocation fails.
 **/
extern void *libspdm_sha3_256_new(void);

/**
 * Release the specified SHA3-256 context.
 *
 * @param[in]  sha3_256_context  Pointer to the SHA3-256 context to be released.
 **/
extern void libspdm_sha3_256_free(void *sha3_256_context);

/**
 * Initializes a context, which libspdm_sha3_256_new() allocated, for subsequent SHA3-256 use.
 *
 * If sha3_256_context is NULL, then return false.
 *
 * @param[out]  sha3_256_context  Pointer to SHA3-256 context being initialized.
 *
 * @retval true   SHA3-256 context initialization succeeded.
 * @retval false  SHA3-256 context initialization failed.
 **/
extern bool libspdm_sha3_256_init(void *sha3_256_context);

/**
 * Makes a copy of an existing SHA3-256 context.
 *
 * new_sha3_256_context is a context that libspdm_sha3_256_new() allocated and that has not been
 * initialized. The copy is independent of the original, so each can be updated, finalized and
 * released separately.
 *
 * If sha3_256_context is NULL, then return false.
 * If new_sha3_256_context is NULL, then return false.
 *
 * @param[in]  sha3_256_context      Pointer to SHA3-256 context being copied.
 * @param[out] new_sha3_256_context  Pointer to new SHA3-256 context.
 *
 * @retval true   SHA3-256 context copy succeeded.
 * @retval false  SHA3-256 context copy failed.
 **/
extern bool libspdm_sha3_256_duplicate(const void *sha3_256_context, void *new_sha3_256_context);

/**
 * Digests the input data and updates SHA3-256 context.
 *
 * This function performs SHA3-256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * The SHA3-256 context should be already correctly initialized by libspdm_sha3_256_init() or
 * libspdm_sha3_256_duplicate(), and must not have been finalized by libspdm_sha3_256_final().
 * Behavior with invalid context is undefined.
 *
 * If sha3_256_context is NULL, then return false.
 * If data is NULL and data_size is not 0, then return false.
 *
 * @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
 * @param[in]       data              Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA3-256 data digest succeeded.
 * @retval false  SHA3-256 data digest failed.
 **/
extern bool libspdm_sha3_256_update(void *sha3_256_context, const void *data, size_t data_size);

/**
 * Completes computation of the SHA3-256 digest value.
 *
 * This function completes SHA3-256 hash computation and populates the digest value into the
 * specified memory. After this function has been called, the SHA3-256 context cannot be used again,
 * except to release it with libspdm_sha3_256_free(). The SHA3-256 context should be already
 * correctly initialized by libspdm_sha3_256_init() or libspdm_sha3_256_duplicate(), and must not
 * have been finalized by libspdm_sha3_256_final(). Behavior with invalid SHA3-256 context is
 * undefined.
 *
 * If sha3_256_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
 * @param[out]      hash_value        Pointer to a buffer that receives the SHA3-256 digest
 *                                    value (32 bytes).
 *
 * @retval true   SHA3-256 digest computation succeeded.
 * @retval false  SHA3-256 digest computation failed.
 **/
extern bool libspdm_sha3_256_final(void *sha3_256_context, uint8_t *hash_value);

/**
 * Computes the SHA3-256 message digest of an input data buffer.
 *
 * This function performs the SHA3-256 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Pointer to a buffer that receives the SHA3-256 digest value (32 bytes).
 *
 * @retval true   SHA3-256 digest computation succeeded.
 * @retval false  SHA3-256 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_sha3_256_hash_all(const void *data, size_t data_size, uint8_t *hash_value);
#endif /* LIBSPDM_SHA3_256_SUPPORT */

#if LIBSPDM_SHA3_384_SUPPORT
/**
 * Allocates one SHA3-384 context.
 *
 * The context must be initialized by libspdm_sha3_384_init(), or be the destination of
 * libspdm_sha3_384_duplicate(), before any other use.
 *
 * @return  Pointer to the SHA3-384 context, or NULL if the allocation fails.
 **/
extern void *libspdm_sha3_384_new(void);

/**
 * Release the specified SHA3-384 context.
 *
 * @param[in]  sha3_384_context  Pointer to the SHA3-384 context to be released.
 **/
extern void libspdm_sha3_384_free(void *sha3_384_context);

/**
 * Initializes a context, which libspdm_sha3_384_new() allocated, for subsequent SHA3-384 use.
 *
 * If sha3_384_context is NULL, then return false.
 *
 * @param[out]  sha3_384_context  Pointer to SHA3-384 context being initialized.
 *
 * @retval true   SHA3-384 context initialization succeeded.
 * @retval false  SHA3-384 context initialization failed.
 **/
extern bool libspdm_sha3_384_init(void *sha3_384_context);

/**
 * Makes a copy of an existing SHA3-384 context.
 *
 * new_sha3_384_context is a context that libspdm_sha3_384_new() allocated and that has not been
 * initialized. The copy is independent of the original, so each can be updated, finalized and
 * released separately.
 *
 * If sha3_384_context is NULL, then return false.
 * If new_sha3_384_context is NULL, then return false.
 *
 * @param[in]  sha3_384_context      Pointer to SHA3-384 context being copied.
 * @param[out] new_sha3_384_context  Pointer to new SHA3-384 context.
 *
 * @retval true   SHA3-384 context copy succeeded.
 * @retval false  SHA3-384 context copy failed.
 **/
extern bool libspdm_sha3_384_duplicate(const void *sha3_384_context, void *new_sha3_384_context);

/**
 * Digests the input data and updates SHA3-384 context.
 *
 * This function performs SHA3-384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * The SHA3-384 context should be already correctly initialized by libspdm_sha3_384_init() or
 * libspdm_sha3_384_duplicate(), and must not have been finalized by libspdm_sha3_384_final().
 * Behavior with invalid context is undefined.
 *
 * If sha3_384_context is NULL, then return false.
 * If data is NULL and data_size is not 0, then return false.
 *
 * @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
 * @param[in]       data              Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size         Size of data buffer in bytes.
 *
 * @retval true   SHA3-384 data digest succeeded.
 * @retval false  SHA3-384 data digest failed.
 **/
extern bool libspdm_sha3_384_update(void *sha3_384_context, const void *data, size_t data_size);

/**
 * Completes computation of the SHA3-384 digest value.
 *
 * This function completes SHA3-384 hash computation and populates the digest value into the
 * specified memory. After this function has been called, the SHA3-384 context cannot be used again,
 * except to release it with libspdm_sha3_384_free(). The SHA3-384 context should be already
 * correctly initialized by libspdm_sha3_384_init() or libspdm_sha3_384_duplicate(), and must not
 * have been finalized by libspdm_sha3_384_final(). Behavior with invalid SHA3-384 context is
 * undefined.
 *
 * If sha3_384_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
 * @param[out]      hash_value        Pointer to a buffer that receives the SHA3-384 digest
 *                                    value (48 bytes).
 *
 * @retval true   SHA3-384 digest computation succeeded.
 * @retval false  SHA3-384 digest computation failed.
 *
 **/
extern bool libspdm_sha3_384_final(void *sha3_384_context, uint8_t *hash_value);

/**
 * Computes the SHA3-384 message digest of an input data buffer.
 *
 * This function performs the SHA3-384 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Pointer to a buffer that receives the SHA3-384 digest value (48 bytes).
 *
 * @retval true   SHA3-384 digest computation succeeded.
 * @retval false  SHA3-384 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_sha3_384_hash_all(const void *data, size_t data_size, uint8_t *hash_value);
#endif /* LIBSPDM_SHA3_384_SUPPORT */

#if LIBSPDM_SHA3_512_SUPPORT
/**
 * Allocates one SHA3-512 context.
 *
 * The context must be initialized by libspdm_sha3_512_init(), or be the destination of
 * libspdm_sha3_512_duplicate(), before any other use.
 *
 * @return  Pointer to the SHA3-512 context, or NULL if the allocation fails.
 **/
extern void *libspdm_sha3_512_new(void);

/**
 * Release the specified SHA3-512 context.
 *
 * @param[in]  sha3_512_context  Pointer to the SHA3-512 context to be released.
 **/
extern void libspdm_sha3_512_free(void *sha3_512_context);

/**
 * Initializes a context, which libspdm_sha3_512_new() allocated, for subsequent SHA3-512 use.
 *
 * If sha3_512_context is NULL, then return false.
 *
 * @param[out]  sha3_512_context  Pointer to SHA3-512 context being initialized.
 *
 * @retval true   SHA3-512 context initialization succeeded.
 * @retval false  SHA3-512 context initialization failed.
 **/
extern bool libspdm_sha3_512_init(void *sha3_512_context);

/**
 * Makes a copy of an existing SHA3-512 context.
 *
 * new_sha3_512_context is a context that libspdm_sha3_512_new() allocated and that has not been
 * initialized. The copy is independent of the original, so each can be updated, finalized and
 * released separately.
 *
 * If sha3_512_context is NULL, then return false.
 * If new_sha3_512_context is NULL, then return false.
 *
 * @param[in]  sha3_512_context      Pointer to SHA3-512 context being copied.
 * @param[out] new_sha3_512_context  Pointer to new SHA3-512 context.
 *
 * @retval true   SHA3-512 context copy succeeded.
 * @retval false  SHA3-512 context copy failed.
 *
 **/
extern bool libspdm_sha3_512_duplicate(const void *sha3_512_context, void *new_sha3_512_context);

/**
 * Digests the input data and updates SHA3-512 context.
 *
 * This function performs SHA3-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * The SHA3-512 context should be already correctly initialized by libspdm_sha3_512_init() or
 * libspdm_sha3_512_duplicate(), and must not have been finalized by libspdm_sha3_512_final().
 * Behavior with invalid context is undefined.
 *
 * If sha3_512_context is NULL, then return false.
 * If data is NULL and data_size is not 0, then return false.
 *
 * @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
 * @param[in]       data              Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size         Size of data buffer in bytes.
 *
 * @retval true   SHA3-512 data digest succeeded.
 * @retval false  SHA3-512 data digest failed.
 **/
extern bool libspdm_sha3_512_update(void *sha3_512_context, const void *data, size_t data_size);

/**
 * Completes computation of the SHA3-512 digest value.
 *
 * This function completes SHA3-512 hash computation and populates the digest value into the
 * specified memory. After this function has been called, the SHA3-512 context cannot be used again,
 * except to release it with libspdm_sha3_512_free(). The SHA3-512 context should be already
 * correctly initialized by libspdm_sha3_512_init() or libspdm_sha3_512_duplicate(), and must not
 * have been finalized by libspdm_sha3_512_final(). Behavior with invalid SHA3-512 context is
 * undefined.
 *
 * If sha3_512_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
 * @param[out]      hash_value        Pointer to a buffer that receives the SHA3-512 digest
 *                                    value (64 bytes).
 *
 * @retval true   SHA3-512 digest computation succeeded.
 * @retval false  SHA3-512 digest computation failed.
 **/
extern bool libspdm_sha3_512_final(void *sha3_512_context, uint8_t *hash_value);

/**
 * Computes the SHA3-512 message digest of an input data buffer.
 *
 * This function performs the SHA3-512 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Pointer to a buffer that receives the SHA3-512 digest value (64 bytes).
 *
 * @retval true   SHA3-512 digest computation succeeded.
 * @retval false  SHA3-512 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_sha3_512_hash_all(const void *data, size_t data_size, uint8_t *hash_value);
#endif /* LIBSPDM_SHA3_512_SUPPORT */

/*=====================================================================================
 *    One-Way Cryptographic hash SM3 Primitives
 *=====================================================================================
 */

#if LIBSPDM_SM3_256_SUPPORT
/**
 * Allocates one SM3 context.
 *
 * The context must be initialized by libspdm_sm3_256_init(), or be the destination of
 * libspdm_sm3_256_duplicate(), before any other use.
 *
 * @return  Pointer to the SM3 context, or NULL if the allocation fails.
 **/
extern void *libspdm_sm3_256_new(void);

/**
 * Release the specified SM3 context.
 *
 * @param[in]  sm3_context  Pointer to the SM3 context to be released.
 **/
extern void libspdm_sm3_256_free(void *sm3_context);

/**
 * Initializes a context, which libspdm_sm3_256_new() allocated, for subsequent SM3 use.
 *
 * If sm3_context is NULL, then return false.
 *
 * @param[out]  sm3_context  Pointer to SM3 context being initialized.
 *
 * @retval true   SM3 context initialization succeeded.
 * @retval false  SM3 context initialization failed.
 **/
extern bool libspdm_sm3_256_init(void *sm3_context);

/**
 * Makes a copy of an existing SM3 context.
 *
 * new_sm3_context is a context that libspdm_sm3_256_new() allocated and that has not been
 * initialized. The copy is independent of the original, so each can be updated, finalized and
 * released separately.
 *
 * If sm3_context is NULL, then return false.
 * If new_sm3_context is NULL, then return false.
 *
 * @param[in]  sm3_context      Pointer to SM3 context being copied.
 * @param[out] new_sm3_context  Pointer to new SM3 context.
 *
 * @retval true   SM3 context copy succeeded.
 * @retval false  SM3 context copy failed.
 **/
extern bool libspdm_sm3_256_duplicate(const void *sm3_context, void *new_sm3_context);

/**
 * Digests the input data and updates SM3 context.
 *
 * This function performs SM3 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * The SM3 context should be already correctly initialized by libspdm_sm3_256_init() or
 * libspdm_sm3_256_duplicate(), and must not have been finalized by libspdm_sm3_256_final().
 * Behavior with invalid context is undefined.
 *
 * If sm3_context is NULL, then return false.
 * If data is NULL and data_size is not 0, then return false.
 *
 * @param[in, out]  sm3_context  Pointer to the SM3 context.
 * @param[in]       data         Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size    Size of data buffer in bytes.
 *
 * @retval true   SM3 data digest succeeded.
 * @retval false  SM3 data digest failed.
 **/
extern bool libspdm_sm3_256_update(void *sm3_context, const void *data, size_t data_size);

/**
 * Completes computation of the SM3 digest value.
 *
 * This function completes SM3 hash computation and populates the digest value into the specified
 * memory. After this function has been called, the SM3 context cannot be used again, except to
 * release it with libspdm_sm3_256_free(). The SM3 context should be already correctly initialized
 * by libspdm_sm3_256_init() or libspdm_sm3_256_duplicate(), and must not have been finalized by
 * libspdm_sm3_256_final(). Behavior with invalid SM3 context is undefined.
 *
 * If sm3_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sm3_context  Pointer to the SM3 context.
 * @param[out]      hash_value   Pointer to a buffer that receives the SM3 digest value (32 bytes).
 *
 * @retval true   SM3 digest computation succeeded.
 * @retval false  SM3 digest computation failed.
 **/
extern bool libspdm_sm3_256_final(void *sm3_context, uint8_t *hash_value);

/**
 * Computes the SM3 message digest of an input data buffer.
 *
 * This function performs the SM3 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size   Size of data buffer in bytes.
 * @param[out]  hash_value  Pointer to a buffer that receives the SM3 digest value (32 bytes).
 *
 * @retval true   SM3 digest computation succeeded.
 * @retval false  SM3 digest computation failed.
 * @retval false  This interface is not supported.
 **/
extern bool libspdm_sm3_256_hash_all(const void *data, size_t data_size, uint8_t *hash_value);
#endif /* LIBSPDM_SM3_256_SUPPORT */

#endif /* CRYPTLIB_HASH_H */
