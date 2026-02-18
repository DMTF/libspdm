/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_secured_message_lib.h"

size_t libspdm_secured_message_get_context_size(void)
{
    return sizeof(libspdm_secured_message_context_t);
}

void libspdm_secured_message_init_context(void *spdm_secured_message_context)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    libspdm_zero_mem(secured_message_context, sizeof(libspdm_secured_message_context_t));
}

void libspdm_secured_message_set_use_psk(void *spdm_secured_message_context, bool use_psk)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->use_psk = use_psk;
}

void libspdm_secured_message_set_session_state(
    void *spdm_secured_message_context,
    libspdm_session_state_t session_state)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->session_state = session_state;

    if (session_state == LIBSPDM_SESSION_STATE_ESTABLISHED) {
        /* session handshake key should be zeroized after handshake phase. */
        libspdm_clear_handshake_secret(secured_message_context);
        libspdm_clear_master_secret(secured_message_context);
    }
}

libspdm_session_state_t
libspdm_secured_message_get_session_state(void *spdm_secured_message_context)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return secured_message_context->session_state;
}

void libspdm_secured_message_set_session_type(void *spdm_secured_message_context,
                                              libspdm_session_type_t session_type)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->session_type = session_type;
}

void libspdm_secured_message_set_algorithms(void *spdm_secured_message_context,
                                            const spdm_version_number_t version,
                                            const spdm_version_number_t secured_message_version,
                                            uint32_t base_hash_algo,
                                            uint16_t dhe_named_group,
                                            uint32_t kem_alg,
                                            uint16_t aead_cipher_suite,
                                            uint16_t key_schedule)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->version = version;
    secured_message_context->secured_message_version = secured_message_version;
    secured_message_context->base_hash_algo = base_hash_algo;
    secured_message_context->dhe_named_group = dhe_named_group;
    secured_message_context->kem_alg = kem_alg;
    secured_message_context->aead_cipher_suite = aead_cipher_suite;
    secured_message_context->key_schedule = key_schedule;

    secured_message_context->hash_size =
        libspdm_get_hash_size(secured_message_context->base_hash_algo);
    if (kem_alg != 0) {
        secured_message_context->shared_key_size = libspdm_get_kem_shared_secret_size(
            secured_message_context->kem_alg);
    } else {
        secured_message_context->shared_key_size = libspdm_get_dhe_shared_secret_size(
            secured_message_context->dhe_named_group);
    }
    secured_message_context->aead_key_size = libspdm_get_aead_key_size(
        secured_message_context->aead_cipher_suite);
    secured_message_context->aead_iv_size = libspdm_get_aead_iv_size(
        secured_message_context->aead_cipher_suite);
    secured_message_context->aead_tag_size = libspdm_get_aead_tag_size(
        secured_message_context->aead_cipher_suite);
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
void libspdm_secured_message_set_psk_hint(void *spdm_secured_message_context,
                                          const void *psk_hint,
                                          size_t psk_hint_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    if ((psk_hint != NULL) && (psk_hint_size > 0)) {
        secured_message_context->psk_hint_size = psk_hint_size;
        libspdm_copy_mem(secured_message_context->psk_hint,
                         LIBSPDM_PSK_MAX_HINT_LENGTH,
                         psk_hint,
                         psk_hint_size);
    }
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

void libspdm_secured_message_set_max_spdm_session_sequence_number(
    void *spdm_secured_message_context,
    uint64_t max_spdm_session_sequence_number)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->max_spdm_session_sequence_number = max_spdm_session_sequence_number;
}

void libspdm_secured_message_set_sequence_number_endian (
    void *spdm_secured_message_context,
    uint8_t endian_value)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->sequence_number_endian = endian_value;
}

bool libspdm_secured_message_import_shared_secret(void *spdm_secured_message_context,
                                                  const void *shared_secret,
                                                  size_t shared_secret_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    if (shared_secret_size > secured_message_context->shared_key_size) {
        return false;
    }
    secured_message_context->shared_key_size = shared_secret_size;
    libspdm_copy_mem(secured_message_context->master_secret.shared_secret,
                     sizeof(secured_message_context->master_secret.shared_secret),
                     shared_secret, shared_secret_size);
    return true;
}

bool libspdm_secured_message_export_master_secret(
    void *spdm_secured_message_context, void *export_master_secret,
    size_t *export_master_secret_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;

    if (*export_master_secret_size > secured_message_context->hash_size) {
        *export_master_secret_size = secured_message_context->hash_size;
    }

    libspdm_copy_mem(export_master_secret, *export_master_secret_size,
                     secured_message_context->export_master_secret,
                     *export_master_secret_size);

    return true;
}

void libspdm_secured_message_clear_export_master_secret(void *spdm_secured_message_context)
{
    libspdm_secured_message_context_t *secured_message_context;

    LIBSPDM_ASSERT(spdm_secured_message_context != NULL);

    secured_message_context = spdm_secured_message_context;

    libspdm_zero_mem(secured_message_context->export_master_secret,
                     sizeof(secured_message_context->export_master_secret));
}

bool libspdm_secured_message_export_session_keys(void *spdm_secured_message_context,
                                                 void *session_keys,
                                                 size_t *session_keys_size)
{
    libspdm_secured_message_context_t *secured_message_context;
    size_t struct_size;
    libspdm_secure_session_keys_struct_t *session_keys_struct;
    uint8_t *ptr;

    secured_message_context = spdm_secured_message_context;
    struct_size = sizeof(libspdm_secure_session_keys_struct_t) +
                  (secured_message_context->aead_key_size +
                   secured_message_context->aead_iv_size + sizeof(uint64_t)) * 2;

    if (*session_keys_size < struct_size) {
        *session_keys_size = struct_size;
        return false;
    }

    session_keys_struct = session_keys;
    session_keys_struct->version = LIBSPDM_SECURE_SESSION_KEYS_STRUCT_VERSION;
    session_keys_struct->aead_key_size = (uint32_t)secured_message_context->aead_key_size;
    session_keys_struct->aead_iv_size = (uint32_t)secured_message_context->aead_iv_size;

    ptr = (void *)(session_keys_struct + 1);
    libspdm_copy_mem(ptr,
                     *session_keys_size - (ptr - (uint8_t*)session_keys),
                     secured_message_context->application_secret.request_data_encryption_key,
                     secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    libspdm_copy_mem(ptr,
                     *session_keys_size - (ptr - (uint8_t*)session_keys),
                     secured_message_context->application_secret.request_data_salt,
                     secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    libspdm_copy_mem(ptr,
                     *session_keys_size - (ptr - (uint8_t*)session_keys),
                     &secured_message_context->application_secret.request_data_sequence_number,
                     sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    libspdm_copy_mem(ptr,
                     *session_keys_size - (ptr - (uint8_t*)session_keys),
                     secured_message_context->application_secret.response_data_encryption_key,
                     secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    libspdm_copy_mem(ptr,
                     *session_keys_size - (ptr - (uint8_t*)session_keys),
                     secured_message_context->application_secret.response_data_salt,
                     secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    libspdm_copy_mem(ptr,
                     *session_keys_size - (ptr - (uint8_t*)session_keys),
                     &secured_message_context->application_secret.response_data_sequence_number,
                     sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    return true;
}

bool libspdm_secured_message_import_session_keys(void *spdm_secured_message_context,
                                                 const void *session_keys,
                                                 size_t session_keys_size)
{
    libspdm_secured_message_context_t *secured_message_context;
    size_t struct_size;
    const libspdm_secure_session_keys_struct_t *session_keys_struct;
    const uint8_t *ptr;

    secured_message_context = spdm_secured_message_context;
    struct_size = sizeof(libspdm_secure_session_keys_struct_t) +
                  (secured_message_context->aead_key_size +
                   secured_message_context->aead_iv_size + sizeof(uint64_t)) * 2;

    if (session_keys_size != struct_size) {
        return false;
    }

    session_keys_struct = session_keys;
    if ((session_keys_struct->version !=
         LIBSPDM_SECURE_SESSION_KEYS_STRUCT_VERSION) ||
        (session_keys_struct->aead_key_size !=
         secured_message_context->aead_key_size) ||
        (session_keys_struct->aead_iv_size !=
         secured_message_context->aead_iv_size)) {
        return false;
    }

    ptr = (const void *)(session_keys_struct + 1);
    libspdm_copy_mem(secured_message_context->application_secret.request_data_encryption_key,
                     sizeof(secured_message_context->application_secret
                            .request_data_encryption_key),
                     ptr, secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    libspdm_copy_mem(secured_message_context->application_secret.request_data_salt,
                     sizeof(secured_message_context->application_secret
                            .request_data_salt),
                     ptr, secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    libspdm_copy_mem(&secured_message_context->application_secret.request_data_sequence_number,
                     sizeof(secured_message_context->application_secret
                            .request_data_sequence_number),
                     ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    libspdm_copy_mem(secured_message_context->application_secret
                     .response_data_encryption_key,
                     sizeof(secured_message_context->application_secret
                            .response_data_encryption_key),
                     ptr, secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    libspdm_copy_mem(secured_message_context->application_secret.response_data_salt,
                     sizeof(secured_message_context->application_secret.response_data_salt),
                     ptr, secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    libspdm_copy_mem(&secured_message_context->application_secret.response_data_sequence_number,
                     sizeof(secured_message_context->application_secret
                            .response_data_sequence_number),
                     ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    return true;
}

void libspdm_secured_message_get_last_spdm_error_struct(
    void *spdm_secured_message_context,
    libspdm_error_struct_t *last_spdm_error)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    libspdm_copy_mem(last_spdm_error, sizeof(libspdm_error_struct_t),
                     &secured_message_context->last_spdm_error,
                     sizeof(libspdm_error_struct_t));
}

void libspdm_secured_message_set_last_spdm_error_struct(
    void *spdm_secured_message_context,
    const libspdm_error_struct_t *last_spdm_error)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    libspdm_copy_mem(&secured_message_context->last_spdm_error,
                     sizeof(secured_message_context->last_spdm_error),
                     last_spdm_error,
                     sizeof(libspdm_error_struct_t));
}
