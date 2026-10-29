/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * FIPS signature API message hashing helper.
 **/

#include "internal_crypt_lib.h"

#if LIBSPDM_FIPS_MODE
bool libspdm_fips_hash_message(size_t hash_nid, const uint8_t *message,
                               size_t message_size, uint8_t *digest,
                               size_t *digest_size)
{
    switch (hash_nid) {
#if LIBSPDM_SHA256_SUPPORT
    case LIBSPDM_CRYPTO_NID_SHA256:
        *digest_size = LIBSPDM_SHA256_DIGEST_SIZE;
        return libspdm_sha256_hash_all(message, message_size, digest);
#endif
#if LIBSPDM_SHA384_SUPPORT
    case LIBSPDM_CRYPTO_NID_SHA384:
        *digest_size = LIBSPDM_SHA384_DIGEST_SIZE;
        return libspdm_sha384_hash_all(message, message_size, digest);
#endif
#if LIBSPDM_SHA512_SUPPORT
    case LIBSPDM_CRYPTO_NID_SHA512:
        *digest_size = LIBSPDM_SHA512_DIGEST_SIZE;
        return libspdm_sha512_hash_all(message, message_size, digest);
#endif
#if LIBSPDM_SHA3_256_SUPPORT
    case LIBSPDM_CRYPTO_NID_SHA3_256:
        *digest_size = LIBSPDM_SHA3_256_DIGEST_SIZE;
        return libspdm_sha3_256_hash_all(message, message_size, digest);
#endif
#if LIBSPDM_SHA3_384_SUPPORT
    case LIBSPDM_CRYPTO_NID_SHA3_384:
        *digest_size = LIBSPDM_SHA3_384_DIGEST_SIZE;
        return libspdm_sha3_384_hash_all(message, message_size, digest);
#endif
#if LIBSPDM_SHA3_512_SUPPORT
    case LIBSPDM_CRYPTO_NID_SHA3_512:
        *digest_size = LIBSPDM_SHA3_512_DIGEST_SIZE;
        return libspdm_sha3_512_hash_all(message, message_size, digest);
#endif
    default:
        return false;
    }
}
#endif /* LIBSPDM_FIPS_MODE */
