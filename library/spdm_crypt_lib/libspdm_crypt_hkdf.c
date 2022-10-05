/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

/**
 * Return HKDF extract function, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return HKDF extract function
 **/
libspdm_hkdf_extract_func get_spdm_hkdf_extract_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hkdf_sha256_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hkdf_sha384_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hkdf_sha512_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hkdf_sha3_256_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hkdf_sha3_384_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hkdf_sha3_512_extract;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hkdf_sm3_256_extract;
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
 * Derive HMAC-based Extract key Derivation Function (HKDF) Extract, based upon the negotiated HKDF algorithm.
 *
 * @param  ikm              Pointer to the input key material.
 * @param  ikm_size          key size in bytes.
 * @param  salt             Pointer to the salt value.
 * @param  salt_size         salt size in bytes.
 * @param  prk_out           Pointer to buffer to receive hkdf value.
 * @param  prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
bool libspdm_hkdf_extract(uint32_t base_hash_algo, const uint8_t *ikm, size_t ikm_size,
                          const uint8_t *salt, size_t salt_size,
                          uint8_t *prk_out, size_t prk_out_size)
{
    libspdm_hkdf_extract_func hkdf_extract_function;
    hkdf_extract_function = get_spdm_hkdf_extract_func(base_hash_algo);
    if (hkdf_extract_function == NULL) {
        return false;
    }
    return hkdf_extract_function(ikm, ikm_size, salt, salt_size, prk_out, prk_out_size);
}

/**
 * Return HKDF expand function, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 *
 * @return HKDF expand function
 **/
libspdm_hkdf_expand_func get_spdm_hkdf_expand_func(uint32_t base_hash_algo)
{
    switch (base_hash_algo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_hkdf_sha256_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_hkdf_sha384_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_hkdf_sha512_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_hkdf_sha3_256_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_hkdf_sha3_384_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_hkdf_sha3_512_expand;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_hkdf_sm3_256_expand;
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
 * Derive HMAC-based Expand key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.
 *
 * @param  base_hash_algo                 SPDM base_hash_algo
 * @param  prk                          Pointer to the user-supplied key.
 * @param  prk_size                      key size in bytes.
 * @param  info                         Pointer to the application specific info.
 * @param  info_size                     info size in bytes.
 * @param  out                          Pointer to buffer to receive hkdf value.
 * @param  out_size                      size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 **/
bool libspdm_hkdf_expand(uint32_t base_hash_algo, const uint8_t *prk,
                         size_t prk_size, const uint8_t *info,
                         size_t info_size, uint8_t *out, size_t out_size)
{
    libspdm_hkdf_expand_func hkdf_expand_function;
    hkdf_expand_function = get_spdm_hkdf_expand_func(base_hash_algo);
    if (hkdf_expand_function == NULL) {
        return false;
    }
    return hkdf_expand_function(prk, prk_size, info, info_size, out, out_size);
}
