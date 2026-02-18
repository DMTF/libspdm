/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_secured_message_lib.h"

void *libspdm_secured_message_dhe_new(spdm_version_number_t spdm_version,
                                      uint16_t dhe_named_group, bool is_initiator)
{
    return libspdm_dhe_new(spdm_version, dhe_named_group, is_initiator);
}

void libspdm_secured_message_dhe_free(uint16_t dhe_named_group, void *dhe_context)
{
    libspdm_dhe_free(dhe_named_group, dhe_context);
}

bool libspdm_secured_message_dhe_generate_key(uint16_t dhe_named_group,
                                              void *dhe_context,
                                              uint8_t *public_key,
                                              size_t *public_key_size)
{
    return libspdm_dhe_generate_key(dhe_named_group, dhe_context, public_key, public_key_size);
}

bool libspdm_secured_message_dhe_compute_key(
    uint16_t dhe_named_group, void *dhe_context,
    const uint8_t *peer_public, size_t peer_public_size,
    void *spdm_secured_message_context)
{
    libspdm_secured_message_context_t *secured_message_context;
    uint8_t final_key[LIBSPDM_MAX_DHE_SS_SIZE];
    size_t final_key_size;
    bool ret;

    secured_message_context = spdm_secured_message_context;

    final_key_size = sizeof(final_key);
    ret = libspdm_dhe_compute_key(dhe_named_group, dhe_context, peer_public,
                                  peer_public_size, final_key,
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
