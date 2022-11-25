/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

/**
 * Allocates and initializes one HASH_CTX context for subsequent hash use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *          If the allocations fails, libspdm_hash_new_func() returns NULL.
 **/
typedef void *(*libspdm_hash_new_func)(void);

/**
 * Release the specified HASH_CTX context.
 *
 * @param  hash_context Pointer to the HASH_CTX context to be released.
 **/
typedef void (*libspdm_hash_free_func)(void *hash_context);

/**
 * Initializes user-supplied memory pointed by hash_context as hash context for
 * subsequent use.
 *
 * @param  base_hash_algo  SPDM base_hash_algo
 * @param  hash_context    Pointer to hash context being initialized.
 *
 * @retval true   Hash context initialization succeeded.
 * @retval false  Hash context initialization failed.
 **/
typedef bool (*libspdm_hash_init_func)(void *hash_context);

/**
 * Makes a copy of an existing hash context.
 *
 * If hash_ctx is NULL, then return false.
 * If new_hash_ctx is NULL, then return false.
 *
 * @param[in]  hash_ctx      Pointer to hash context being copied.
 * @param[out] new_hash_ctx  Pointer to new hash context.
 *
 * @retval true   Hash context copy succeeded.
 * @retval false  Hash context copy failed.
 *
 **/
typedef bool (*libspdm_hash_duplicate_func)(const void *hash_ctx, void *new_hash_ctx);

/**
 * Digests the input data and updates hash context.
 *
 * This function performs hash digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * Hash context should be already correctly initialized by hash_init(), and should not be finalized
 * by hash_final(). Behavior with invalid context is undefined.
 *
 * If hash_context is NULL, then return false.
 *
 * @param[in, out]  hash_context   Pointer to the MD context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size      Size of data buffer in bytes.
 *
 * @retval true   hash data digest succeeded.
 * @retval false  hash data digest failed.
 **/
typedef bool (*libspdm_hash_update_func)(void *hash_context, const void *data, size_t data_size);

/**
 * Completes computation of the hash digest value.
 *
 * This function completes hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the hash context cannot
 * be used again.
 * hash context should be already correctly initialized by hash_init(), and should not be
 * finalized by hash_final(). Behavior with invalid hash context is undefined.
 *
 * If hash_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  hash_context    Pointer to the hash context.
 * @param[out]      hash_value      Pointer to a buffer that receives the hash digest value.
 *
 * @retval true   hash digest computation succeeded.
 * @retval false  hash digest computation failed.
 **/
typedef bool (*libspdm_hash_final_func)(void *hash_context, uint8_t *hash_value);

/**
 * Computes the hash of a input data buffer.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  data        Pointer to the buffer containing the data to be hashed.
 * @param  data_size   Size of data buffer in bytes.
 * @param  hash_value  Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
typedef bool (*libspdm_hash_all_func)(const void *data, size_t data_size, uint8_t *hash_value);

uint32_t libspdm_get_hash_size(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
        return 32;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
        return 48;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
        return 64;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
        return 32;
    default:
        return 0;
    }
}

size_t libspdm_get_hash_nid(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
        return LIBSPDM_CRYPTO_NID_SHA256;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
        return LIBSPDM_CRYPTO_NID_SHA384;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
        return LIBSPDM_CRYPTO_NID_SHA512;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
        return LIBSPDM_CRYPTO_NID_SHA3_256;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
        return LIBSPDM_CRYPTO_NID_SHA3_384;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
        return LIBSPDM_CRYPTO_NID_SHA3_512;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
        return LIBSPDM_CRYPTO_NID_SM3_256;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

/**
 * Return hash new function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash new function
 **/
static libspdm_hash_new_func libspdm_get_hash_new_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash free function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash free function
 **/
static libspdm_hash_free_func libspdm_get_hash_free_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash init function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash init function
 **/
static libspdm_hash_init_func libspdm_get_hash_init_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_init;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash duplicate function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash duplicate function
 **/
static libspdm_hash_duplicate_func libspdm_get_hash_duplicate_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash update function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash update function
 **/
static libspdm_hash_update_func libspdm_get_hash_update_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash final function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash final function
 **/
static libspdm_hash_final_func libspdm_get_hash_final_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Return hash function, based upon the negotiated hash algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return hash function
 **/
static libspdm_hash_all_func libspdm_get_hash_all_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

void *libspdm_hash_new(uint32_t base_hash_algo)
{
    libspdm_hash_new_func hash_function;
    hash_function = libspdm_get_hash_new_func(base_hash_algo);
    if (hash_function == NULL) {
        return NULL;
    }
    return hash_function();
}

void libspdm_hash_free(uint32_t base_hash_algo, void *hash_context)
{
    libspdm_hash_free_func hash_function;
    hash_function = libspdm_get_hash_free_func(base_hash_algo);
    if (hash_function == NULL) {
        return;
    }
    hash_function(hash_context);
}

bool libspdm_hash_init(uint32_t base_hash_algo, void *hash_context)
{
    libspdm_hash_init_func hash_function;
    hash_function = libspdm_get_hash_init_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_context);
}

bool libspdm_hash_duplicate(uint32_t base_hash_algo, const void *hash_ctx, void *new_hash_ctx)
{
    libspdm_hash_duplicate_func hash_function;
    hash_function = libspdm_get_hash_duplicate_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_ctx, new_hash_ctx);
}

bool libspdm_hash_update(uint32_t base_hash_algo, void *hash_context,
                         const void *data, size_t data_size)
{
    libspdm_hash_update_func hash_function;
    hash_function = libspdm_get_hash_update_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_context, data, data_size);
}

bool libspdm_hash_final(uint32_t base_hash_algo, void *hash_context, uint8_t *hash_value)
{
    libspdm_hash_final_func hash_function;
    hash_function = libspdm_get_hash_final_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(hash_context, hash_value);
}

bool libspdm_hash_all(uint32_t base_hash_algo, const void *data,
                      size_t data_size, uint8_t *hash_value)
{
    libspdm_hash_all_func hash_function;
    hash_function = libspdm_get_hash_all_func(base_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(data, data_size, hash_value);
}

uint32_t libspdm_get_measurement_hash_size(uint32_t measurement_hash_algo)
{
    switch (measurement_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        return 32;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        return 48;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        return 64;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        return 32;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY:
        return 0xFFFFFFFF;
    default:
        return 0;
    }
}
