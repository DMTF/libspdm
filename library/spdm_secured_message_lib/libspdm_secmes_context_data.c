/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_secured_message_lib.h"

/**
 * Return the size in bytes of the SPDM secured message context.
 *
 * @return the size in bytes of the SPDM secured message context.
 **/
uintn libspdm_secured_message_get_context_size(void)
{
    return sizeof(spdm_secured_message_context_t);
}

/**
 * Initialize an SPDM secured message context.
 *
 * The size in bytes of the spdm_secured_message_context can be returned by libspdm_secured_message_get_context_size.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 */
void libspdm_secured_message_init_context(IN void *spdm_secured_message_context)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    zero_mem(secured_message_context,
             sizeof(spdm_secured_message_context_t));
}

/**
 * Set use_psk to an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  use_psk                       Indicate if the SPDM session use PSK.
 */
void libspdm_secured_message_set_use_psk(IN void *spdm_secured_message_context,
                                         IN bool use_psk)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->use_psk = use_psk;
}

/**
 * Return if finished_key is ready.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 *
 * @retval true  finished_key is ready.
 * @retval false finished_key is not ready.
 */
bool
libspdm_secured_message_is_finished_key_ready(IN void *spdm_secured_message_context)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return secured_message_context->finished_key_ready;
}

/**
 * Set session_state to an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  session_state                 Indicate the SPDM session state.
 */
void libspdm_secured_message_set_session_state(
    IN void *spdm_secured_message_context,
    IN libspdm_session_state_t session_state)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->session_state = session_state;

    if (session_state == LIBSPDM_SESSION_STATE_ESTABLISHED) {
        /* session handshake key should be zeroized after handshake phase. */
        libspdm_clear_handshake_secret(secured_message_context);
    }
}

/**
 * Return session_state of an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 *
 * @return the SPDM session state.
 */
libspdm_session_state_t
libspdm_secured_message_get_session_state(IN void *spdm_secured_message_context)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    return secured_message_context->session_state;
}

/**
 * Set session_type to an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  session_type                  Indicate the SPDM session type.
 */
void libspdm_secured_message_set_session_type(IN void *spdm_secured_message_context,
                                              IN libspdm_session_type_t session_type)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->session_type = session_type;
}

/**
 * Set algorithm to an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  base_hash_algo                 Indicate the negotiated base_hash_algo for the SPDM session.
 * @param  dhe_named_group                Indicate the negotiated dhe_named_group for the SPDM session.
 * @param  aead_cipher_suite              Indicate the negotiated aead_cipher_suite for the SPDM session.
 * @param  key_schedule                  Indicate the negotiated key_schedule for the SPDM session.
 */
void libspdm_secured_message_set_algorithms(IN void *spdm_secured_message_context,
                                            IN spdm_version_number_t version,
                                            IN spdm_version_number_t secured_message_version,
                                            IN uint32_t base_hash_algo,
                                            IN uint16_t dhe_named_group,
                                            IN uint16_t aead_cipher_suite,
                                            IN uint16_t key_schedule)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->version = version;
    secured_message_context->secured_message_version = secured_message_version;
    secured_message_context->base_hash_algo = base_hash_algo;
    secured_message_context->dhe_named_group = dhe_named_group;
    secured_message_context->aead_cipher_suite = aead_cipher_suite;
    secured_message_context->key_schedule = key_schedule;

    secured_message_context->hash_size =
        libspdm_get_hash_size(secured_message_context->base_hash_algo);
    secured_message_context->dhe_key_size = libspdm_get_dhe_pub_key_size(
        secured_message_context->dhe_named_group);
    secured_message_context->aead_key_size = libspdm_get_aead_key_size(
        secured_message_context->aead_cipher_suite);
    secured_message_context->aead_iv_size = libspdm_get_aead_iv_size(
        secured_message_context->aead_cipher_suite);
    secured_message_context->aead_tag_size = libspdm_get_aead_tag_size(
        secured_message_context->aead_cipher_suite);
}

/**
 * Set the psk_hint to an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  psk_hint                      Indicate the PSK hint.
 * @param  psk_hint_size                  The size in bytes of the PSK hint.
 */
void libspdm_secured_message_set_psk_hint(IN void *spdm_secured_message_context,
                                          IN void *psk_hint,
                                          IN uintn psk_hint_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    secured_message_context->psk_hint = psk_hint;
    secured_message_context->psk_hint_size = psk_hint_size;
}

/**
 * Import the DHE Secret to an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  dhe_secret                    Indicate the DHE secret.
 * @param  dhe_secret_size                The size in bytes of the DHE secret.
 *
 * @retval RETURN_SUCCESS  DHE Secret is imported.
 */
return_status
libspdm_secured_message_import_dhe_secret(IN void *spdm_secured_message_context,
                                          IN void *dhe_secret,
                                          IN uintn dhe_secret_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    if (dhe_secret_size > secured_message_context->dhe_key_size) {
        return RETURN_OUT_OF_RESOURCES;
    }
    secured_message_context->dhe_key_size = dhe_secret_size;
    copy_mem(secured_message_context->master_secret.dhe_secret, dhe_secret,
             dhe_secret_size);
    return RETURN_SUCCESS;
}

/**
 * Export the export_master_secret from an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  export_master_secret           Indicate the buffer to store the export_master_secret.
 * @param  export_master_secret_size       The size in bytes of the export_master_secret.
 *
 * @retval RETURN_SUCCESS  export_master_secret is exported.
 */
return_status libspdm_secured_message_export_master_secret(
    IN void *spdm_secured_message_context, OUT void *export_master_secret,
    IN OUT uintn *export_master_secret_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    if (*export_master_secret_size < secured_message_context->hash_size) {
        *export_master_secret_size = secured_message_context->hash_size;
        return RETURN_BUFFER_TOO_SMALL;
    }
    *export_master_secret_size = secured_message_context->hash_size;
    copy_mem(export_master_secret,
             secured_message_context->handshake_secret.export_master_secret,
             secured_message_context->hash_size);
    return RETURN_SUCCESS;
}

/**
 * Export the SessionKeys from an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  SessionKeys                  Indicate the buffer to store the SessionKeys in libspdm_secure_session_keys_struct_t.
 * @param  SessionKeysSize              The size in bytes of the SessionKeys in libspdm_secure_session_keys_struct_t.
 *
 * @retval RETURN_SUCCESS  SessionKeys are exported.
 */
return_status
libspdm_secured_message_export_session_keys(IN void *spdm_secured_message_context,
                                            OUT void *SessionKeys,
                                            IN OUT uintn *SessionKeysSize)
{
    spdm_secured_message_context_t *secured_message_context;
    uintn struct_size;
    libspdm_secure_session_keys_struct_t *session_keys_struct;
    uint8_t *ptr;

    secured_message_context = spdm_secured_message_context;
    struct_size = sizeof(libspdm_secure_session_keys_struct_t) +
                  (secured_message_context->aead_key_size +
                   secured_message_context->aead_iv_size + sizeof(uint64_t)) *
                  2;

    if (*SessionKeysSize < struct_size) {
        *SessionKeysSize = struct_size;
        return RETURN_BUFFER_TOO_SMALL;
    }

    session_keys_struct = SessionKeys;
    session_keys_struct->version = LIBSPDM_SECURE_SESSION_KEYS_STRUCT_VERSION;
    session_keys_struct->aead_key_size =
        (uint32_t)secured_message_context->aead_key_size;
    session_keys_struct->aead_iv_size =
        (uint32_t)secured_message_context->aead_iv_size;

    ptr = (void *)(session_keys_struct + 1);
    copy_mem(ptr,
             secured_message_context->application_secret
             .request_data_encryption_key,
             secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    copy_mem(ptr,
             secured_message_context->application_secret.request_data_salt,
             secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    copy_mem(ptr,
             &secured_message_context->application_secret
             .request_data_sequence_number,
             sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    copy_mem(ptr,
             secured_message_context->application_secret
             .response_data_encryption_key,
             secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    copy_mem(ptr,
             secured_message_context->application_secret.response_data_salt,
             secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    copy_mem(ptr,
             &secured_message_context->application_secret
             .response_data_sequence_number,
             sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    return RETURN_SUCCESS;
}

/**
 * Import the SessionKeys from an SPDM secured message context.
 *
 * @param  spdm_secured_message_context    A pointer to the SPDM secured message context.
 * @param  SessionKeys                  Indicate the buffer to store the SessionKeys in libspdm_secure_session_keys_struct_t.
 * @param  SessionKeysSize              The size in bytes of the SessionKeys in libspdm_secure_session_keys_struct_t.
 *
 * @retval RETURN_SUCCESS  SessionKeys are imported.
 */
return_status
spdm_secured_message_import_session_keys(IN void *spdm_secured_message_context,
                                         IN void *SessionKeys,
                                         IN uintn SessionKeysSize)
{
    spdm_secured_message_context_t *secured_message_context;
    uintn struct_size;
    libspdm_secure_session_keys_struct_t *session_keys_struct;
    uint8_t *ptr;

    secured_message_context = spdm_secured_message_context;
    struct_size = sizeof(libspdm_secure_session_keys_struct_t) +
                  (secured_message_context->aead_key_size +
                   secured_message_context->aead_iv_size + sizeof(uint64_t)) *
                  2;

    if (SessionKeysSize != struct_size) {
        return RETURN_INVALID_PARAMETER;
    }

    session_keys_struct = SessionKeys;
    if ((session_keys_struct->version !=
         LIBSPDM_SECURE_SESSION_KEYS_STRUCT_VERSION) ||
        (session_keys_struct->aead_key_size !=
         secured_message_context->aead_key_size) ||
        (session_keys_struct->aead_iv_size !=
         secured_message_context->aead_iv_size)) {
        return RETURN_INVALID_PARAMETER;
    }

    ptr = (void *)(session_keys_struct + 1);
    copy_mem(secured_message_context->application_secret
             .request_data_encryption_key,
             ptr, secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    copy_mem(secured_message_context->application_secret.request_data_salt,
             ptr, secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    copy_mem(&secured_message_context->application_secret
             .request_data_sequence_number,
             ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    copy_mem(secured_message_context->application_secret
             .response_data_encryption_key,
             ptr, secured_message_context->aead_key_size);
    ptr += secured_message_context->aead_key_size;
    copy_mem(secured_message_context->application_secret.response_data_salt,
             ptr, secured_message_context->aead_iv_size);
    ptr += secured_message_context->aead_iv_size;
    copy_mem(&secured_message_context->application_secret
             .response_data_sequence_number,
             ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    return RETURN_SUCCESS;
}

/**
 * Get the last SPDM error struct of an SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  last_spdm_error                Last SPDM error struct of an SPDM context.
 */
void libspdm_secured_message_get_last_spdm_error_struct(
    IN void *spdm_secured_message_context,
    OUT libspdm_error_struct_t *last_spdm_error)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    copy_mem(last_spdm_error, &secured_message_context->last_spdm_error,
             sizeof(libspdm_error_struct_t));
}

/**
 * Set the last SPDM error struct of an SPDM context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  last_spdm_error                Last SPDM error struct of an SPDM context.
 */
void libspdm_secured_message_set_last_spdm_error_struct(
    IN void *spdm_secured_message_context,
    IN libspdm_error_struct_t *last_spdm_error)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    copy_mem(&secured_message_context->last_spdm_error, last_spdm_error,
             sizeof(libspdm_error_struct_t));
}
