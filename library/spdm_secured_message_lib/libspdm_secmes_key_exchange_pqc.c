/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_secured_message_lib.h"

void *libspdm_secured_message_kem_new(spdm_version_number_t spdm_version,
                                      uint32_t kem_alg, bool is_initiator)
{
    return libspdm_kem_new(spdm_version, kem_alg, is_initiator);
}

void libspdm_secured_message_kem_free(uint32_t kem_alg, void *kem_context)
{
    libspdm_kem_free(kem_alg, kem_context);
}

bool libspdm_secured_message_kem_generate_key(uint32_t kem_alg,
                                              void *kem_context,
                                              uint8_t *encap_key,
                                              size_t *encap_key_size)
{
    return libspdm_kem_generate_key(kem_alg, kem_context, encap_key, encap_key_size);
}

bool libspdm_secured_message_kem_encapsulate(
    uint32_t kem_alg, void *kem_context,
    const uint8_t *peer_encap_key, size_t peer_encap_key_size,
    uint8_t *cipher_text, size_t *cipher_text_size,
    void *spdm_secured_message_context)
{
    libspdm_secured_message_context_t *secured_message_context;
    uint8_t final_key[LIBSPDM_MAX_KEM_SS_SIZE];
    size_t final_key_size;
    bool ret;

    secured_message_context = spdm_secured_message_context;

    final_key_size = sizeof(final_key);
    ret = libspdm_kem_encapsulate(kem_alg, kem_context, peer_encap_key,
                                  peer_encap_key_size, cipher_text,
                                  cipher_text_size, final_key,
                                  &final_key_size);
    if (!ret) {
        return ret;
    }
    libspdm_copy_mem(secured_message_context->master_secret.shared_secret,
                     sizeof(secured_message_context->master_secret.shared_secret),
                     final_key, final_key_size);
    libspdm_zero_mem(final_key, final_key_size);
    secured_message_context->shared_key_size = final_key_size;
    return true;
}

bool libspdm_secured_message_kem_decapsulate(
    uint32_t kem_alg, void *kem_context,
    const uint8_t *peer_cipher_text, size_t peer_cipher_text_size,
    void *spdm_secured_message_context)
{
    libspdm_secured_message_context_t *secured_message_context;
    uint8_t final_key[LIBSPDM_MAX_KEM_SS_SIZE];
    size_t final_key_size;
    bool ret;

    secured_message_context = spdm_secured_message_context;

    final_key_size = sizeof(final_key);
    ret = libspdm_kem_decapsulate(kem_alg, kem_context, peer_cipher_text,
                                  peer_cipher_text_size, final_key,
                                  &final_key_size);
    if (!ret) {
        return ret;
    }
    libspdm_copy_mem(secured_message_context->master_secret.shared_secret,
                     sizeof(secured_message_context->master_secret.shared_secret),
                     final_key, final_key_size);
    libspdm_zero_mem(final_key, final_key_size);
    secured_message_context->shared_key_size = final_key_size;
    return true;
}
