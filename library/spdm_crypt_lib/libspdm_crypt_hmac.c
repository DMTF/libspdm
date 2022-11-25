/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

/**
 * Allocates and initializes one HMAC context for subsequent hash use.
 *
 * @return  Pointer to the HMAC context that has been initialized.
 *          If the allocations fails, libspdm_hmac_new_func() returns NULL.
 **/
typedef void *(*libspdm_hmac_new_func)(void);

/**
 * Release the specified HMAC context.
 *
 * @param  hmac_ctx  Pointer to the HMAC context to be released.
 **/
typedef void (*libspdm_hmac_free_func)(void *hmac_ctx);

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to hmac_update().
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[out]  hmac_ctx  Pointer to HMAC context.
 * @param[in]   key       Pointer to the user-supplied key.
 * @param[in]   key_size  Key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 *
 **/
typedef bool (*libspdm_hmac_set_key_func)(void *hmac_ctx, const uint8_t *key, size_t key_size);

/**
 * Makes a copy of an existing HMAC context.
 *
 * If hmac_ctx is NULL, then return false.
 * If new_hmac_ctx is NULL, then return false.
 *
 * @param[in]  hmac_ctx      Pointer to HMAC context being copied.
 * @param[out] new_hmac_ctx  Pointer to new HMAC context.
 *
 * @retval true   HMAC context copy succeeded.
 * @retval false  HMAC context copy failed.
 *
 **/
typedef bool (*libspdm_hmac_duplicate_func)(const void *hmac_ctx, void *new_hmac_ctx);

/**
 * Digests the input data and updates HMAC context.
 *
 * This function performs HMAC digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC context should be initialized by hmac_new(), and should not be finalized
 * by hmac_final(). Behavior with invalid context is undefined.
 *
 * If hmac_ctx is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx   Pointer to the HMAC context.
 * @param[in]       data       Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size  Size of data buffer in bytes.
 *
 * @retval true   HMAC data digest succeeded.
 * @retval false  HMAC data digest failed.
 *
 **/
typedef bool (*libspdm_hmac_update_func)(void *hmac_ctx, const void *data, size_t data_size);

/**
 * Completes computation of the HMAC digest value.
 *
 * This function completes HMAC hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC context cannot
 * be used again.
 *
 * If hmac_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 *
 * @param[in, out]  hmac_ctx    Pointer to the HMAC context.
 * @param[out]      hmac_value  Pointer to a buffer that receives the HMAC digest value.
 *
 * @retval true   HMAC digest computation succeeded.
 * @retval false  HMAC digest computation failed.
 *
 **/
typedef bool (*libspdm_hmac_final_func)(void *hmac_ctx, uint8_t *hmac_value);

/**
 * Computes the HMAC of a input data buffer.
 *
 * This function performs the HMAC of a given data buffer, and return the hash value.
 *
 * @param  data        Pointer to the buffer containing the data to be HMACed.
 * @param  data_size   Size of data buffer in bytes.
 * @param  key         Pointer to the user-supplied key.
 * @param  key_size    Key size in bytes.
 * @param  hash_value  Pointer to a buffer that receives the HMAC value.
 *
 * @retval true   HMAC computation succeeded.
 * @retval false  HMAC computation failed.
 **/
typedef bool (*libspdm_hmac_all_func)(const void *data, size_t data_size,
                                      const uint8_t *key, size_t key_size,
                                      uint8_t *hmac_value);

/**
 * Return HMAC new function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC new function
 **/
static libspdm_hmac_new_func libspdm_get_hmac_new_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hmac_sha256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hmac_sha384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hmac_sha512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hmac_sha3_256_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hmac_sha3_384_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hmac_sha3_512_new;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hmac_sm3_256_new;
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
 * Return HMAC free function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC free function
 **/
static libspdm_hmac_free_func libspdm_get_hmac_free_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hmac_sha256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hmac_sha384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hmac_sha512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hmac_sha3_256_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hmac_sha3_384_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hmac_sha3_512_free;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hmac_sm3_256_free;
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
 * Return HMAC init function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC init function
 **/
static libspdm_hmac_set_key_func libspdm_get_hmac_init_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hmac_sha256_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hmac_sha384_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hmac_sha512_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hmac_sha3_256_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hmac_sha3_384_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hmac_sha3_512_set_key;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hmac_sm3_256_set_key;
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
 * Return HMAC duplicate function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC duplicate function
 **/
static libspdm_hmac_duplicate_func libspdm_get_hmac_duplicate_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hmac_sha256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hmac_sha384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hmac_sha512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hmac_sha3_256_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hmac_sha3_384_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hmac_sha3_512_duplicate;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hmac_sm3_256_duplicate;
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
 * Return HMAC update function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC update function
 **/
static libspdm_hmac_update_func libspdm_get_hmac_update_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hmac_sha256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hmac_sha384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hmac_sha512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hmac_sha3_256_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hmac_sha3_384_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hmac_sha3_512_update;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hmac_sm3_256_update;
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
 * Return HMAC final function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                  SPDM base_hash_algo
 *
 * @return HMAC final function
 **/
static libspdm_hmac_final_func libspdm_get_hmac_final_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hmac_sha256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hmac_sha384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hmac_sha512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hmac_sha3_256_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hmac_sha3_384_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hmac_sha3_512_final;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hmac_sm3_256_final;
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
 * Return HMAC all function, based upon the negotiated HMAC algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return HMAC function
 **/
static libspdm_hmac_all_func libspdm_get_hmac_all_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hmac_sha256_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hmac_sha384_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hmac_sha512_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hmac_sha3_256_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hmac_sha3_384_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hmac_sha3_512_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hmac_sm3_256_all;
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

void *libspdm_hmac_new(uint32_t base_hash_algo)
{
    libspdm_hmac_new_func hmac_function;
    hmac_function = libspdm_get_hmac_new_func(base_hash_algo);
    if (hmac_function == NULL) {
        return NULL;
    }
    return hmac_function();
}

void libspdm_hmac_free(uint32_t base_hash_algo, void *hmac_ctx)
{
    libspdm_hmac_free_func hmac_function;
    hmac_function = libspdm_get_hmac_free_func(base_hash_algo);
    if (hmac_function == NULL) {
        return;
    }
    hmac_function(hmac_ctx);
}

bool libspdm_hmac_init(uint32_t base_hash_algo,
                       void *hmac_ctx, const uint8_t *key,
                       size_t key_size)
{
    libspdm_hmac_set_key_func hmac_function;
    hmac_function = libspdm_get_hmac_init_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, key, key_size);
}

bool libspdm_hmac_duplicate(uint32_t base_hash_algo, const void *hmac_ctx, void *new_hmac_ctx)
{
    libspdm_hmac_duplicate_func hmac_function;
    hmac_function = libspdm_get_hmac_duplicate_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, new_hmac_ctx);
}

bool libspdm_hmac_update(uint32_t base_hash_algo,
                         void *hmac_ctx, const void *data,
                         size_t data_size)
{
    libspdm_hmac_update_func hmac_function;
    hmac_function = libspdm_get_hmac_update_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, data, data_size);
}

bool libspdm_hmac_final(uint32_t base_hash_algo, void *hmac_ctx,  uint8_t *hmac_value)
{
    libspdm_hmac_final_func hmac_function;
    hmac_function = libspdm_get_hmac_final_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(hmac_ctx, hmac_value);
}

bool libspdm_hmac_all(uint32_t base_hash_algo, const void *data,
                      size_t data_size, const uint8_t *key,
                      size_t key_size, uint8_t *hmac_value)
{
    libspdm_hmac_all_func hmac_function;
    hmac_function = libspdm_get_hmac_all_func(base_hash_algo);
    if (hmac_function == NULL) {
        return false;
    }
    return hmac_function(data, data_size, key, key_size, hmac_value);
}
