/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

static uint8_t m_libspdm_local_psk_hint[32];
static uint8_t m_libspdm_dummy_key_buffer[LIBSPDM_MAX_AEAD_KEY_SIZE];
static uint8_t m_libspdm_dummy_salt_buffer[LIBSPDM_MAX_AEAD_IV_SIZE];
uint8_t libspdm_test_message_header;

void libspdm_secured_message_set_response_data_encryption_key(void *spdm_secured_message_context,
                                                              const void *key, uintn key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->application_secret.response_data_encryption_key,
                     sizeof(secured_message_context->application_secret.response_data_encryption_key),
                     key, secured_message_context->aead_key_size);
}

void libspdm_secured_message_set_response_data_salt(void *spdm_secured_message_context,
                                                    const void *salt, uintn salt_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(salt_size == secured_message_context->aead_iv_size);
    libspdm_copy_mem(secured_message_context->application_secret.response_data_salt,
                     sizeof(secured_message_context->application_secret.response_data_salt),
                     salt, secured_message_context->aead_iv_size);
}

uintn libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status libspdm_device_send_message(void *spdm_context, uintn request_size,
                                          const void *request, uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status libspdm_device_receive_message(void *spdm_context, uintn *response_size,
                                             void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    uint8_t spdm_response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn spdm_response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t libspdm_test_message_header_size;

    spdm_test_context = libspdm_get_test_context();
    session_id = 0xFFFFFFFF;
    libspdm_test_message_header_size = 1;
    spdm_response_size = spdm_test_context->test_buffer_size - libspdm_test_message_header_size;

    libspdm_copy_mem((uint8_t *)spdm_response, sizeof(spdm_response),
                     (uint8_t *)spdm_test_context->test_buffer + libspdm_test_message_header_size,
                     spdm_response_size);

    libspdm_transport_test_encode_message(spdm_context, &session_id, false, false,
                                          spdm_response_size, spdm_response,
                                          response_size, response);
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return RETURN_DEVICE_ERROR;
    }
    /* WALKAROUND: If just use single context to encode message and then decode message */
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number--;
    return RETURN_SUCCESS;
}

void libspdm_test_requester_heartbeat_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    libspdm_test_message_header = LIBSPDM_TEST_MESSAGE_TYPE_SECURED_TEST;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#endif
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size = sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(
        m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->aead_key_size,
        (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->aead_key_size);
    libspdm_set_mem(
        m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->aead_iv_size,
        (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    libspdm_heartbeat(spdm_context, session_id);
    free(data);
}

libspdm_test_context_t m_libspdm_requester_heartbeat_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_heartbeat_test_context);

    m_libspdm_requester_heartbeat_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_requester_heartbeat_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_heartbeat_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
