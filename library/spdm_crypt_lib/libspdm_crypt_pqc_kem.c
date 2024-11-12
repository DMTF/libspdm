/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

uint32_t libspdm_get_kem_encap_key_size(uint32_t kem_alg)
{
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
#if LIBSPDM_ML_KEM_512_SUPPORT
        return 800;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
#if LIBSPDM_ML_KEM_768_SUPPORT
        return 1184;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_1024_SUPPORT
        return 1568;
#else
        return 0;
#endif
    default:
        return 0;
    }
}

uint32_t libspdm_get_kem_cipher_text_size(uint32_t kem_alg)
{
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
#if LIBSPDM_ML_KEM_512_SUPPORT
        return 768;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
#if LIBSPDM_ML_KEM_768_SUPPORT
        return 1088;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_1024_SUPPORT
        return 1568;
#else
        return 0;
#endif
    default:
        return 0;
    }
}

uint32_t libspdm_get_kem_shared_secret_size(uint32_t kem_alg)
{
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
#if LIBSPDM_ML_KEM_512_SUPPORT
        return 32;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
#if LIBSPDM_ML_KEM_768_SUPPORT
        return 32;
#else
        return 0;
#endif
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_1024_SUPPORT
        return 32;
#else
        return 0;
#endif
    default:
        return 0;
    }
}

static size_t libspdm_get_kem_nid(uint32_t kem_alg)
{
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
        return LIBSPDM_CRYPTO_NID_ML_KEM_512;
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
        return LIBSPDM_CRYPTO_NID_ML_KEM_768;
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
        return LIBSPDM_CRYPTO_NID_ML_KEM_1024;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

void *libspdm_kem_new(spdm_version_number_t spdm_version,
                      uint32_t kem_alg, bool is_initiator)
{
    size_t nid;

    nid = libspdm_get_kem_nid(kem_alg);
    if (nid == LIBSPDM_CRYPTO_NID_NULL) {
        return NULL;
    }

    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_SUPPORT
#if !LIBSPDM_ML_KEM_512_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512);
#endif
#if !LIBSPDM_ML_KEM_768_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768);
#endif
#if !LIBSPDM_ML_KEM_1024_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024);
#endif
        return libspdm_mlkem_new_by_name(nid);
#else
        LIBSPDM_ASSERT(false);
        return NULL;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return NULL;
    }
}

void libspdm_kem_free(uint32_t kem_alg, void *context)
{
    if (context == NULL) {
        return;
    }
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_SUPPORT
        libspdm_mlkem_free(context);
#else
        LIBSPDM_ASSERT(false);
#endif
        break;
    default:
        LIBSPDM_ASSERT(false);
        break;
    }
}

bool libspdm_kem_generate_key(uint32_t kem_alg, void *context,
                              uint8_t *encap_key,
                              size_t *encap_key_size)
{
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_SUPPORT
#if !LIBSPDM_ML_KEM_512_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512);
#endif
#if !LIBSPDM_ML_KEM_768_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768);
#endif
#if !LIBSPDM_ML_KEM_1024_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024);
#endif
        return libspdm_mlkem_generate_key(context, encap_key, encap_key_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

bool libspdm_kem_encapsulate(uint32_t kem_alg, void *context,
                             const uint8_t *peer_encap_key,
                             size_t peer_encap_key_size,
                             uint8_t *cipher_text,
                             size_t *cipher_text_size,
                             uint8_t *shared_secret,
                             size_t *shared_secret_size)
{
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_SUPPORT
#if !LIBSPDM_ML_KEM_512_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512);
#endif
#if !LIBSPDM_ML_KEM_768_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768);
#endif
#if !LIBSPDM_ML_KEM_1024_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024);
#endif
        return libspdm_mlkem_encapsulate (context, peer_encap_key, peer_encap_key_size,
                                          cipher_text, cipher_text_size,
                                          shared_secret, shared_secret_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

bool libspdm_kem_decapsulate(uint32_t kem_alg, void *context,
                             const uint8_t *peer_cipher_text,
                             size_t peer_cipher_text_size,
                             uint8_t *shared_secret,
                             size_t *shared_secret_size)
{
    switch (kem_alg) {
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768:
    case SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024:
#if LIBSPDM_ML_KEM_SUPPORT
#if !LIBSPDM_ML_KEM_512_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512);
#endif
#if !LIBSPDM_ML_KEM_768_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768);
#endif
#if !LIBSPDM_ML_KEM_1024_SUPPORT
        LIBSPDM_ASSERT(kem_alg != SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024);
#endif
        return libspdm_mlkem_decapsulate (context, peer_cipher_text, peer_cipher_text_size,
                                          shared_secret, shared_secret_size);
#else
        LIBSPDM_ASSERT(false);
        return false;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}
