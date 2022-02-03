/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

static uint8_t m_local_psk_hint[32];
static uint8_t m_dummy_key_buffer[LIBSPDM_MAX_AEAD_KEY_SIZE];
static uint8_t m_dummy_salt_buffer[LIBSPDM_MAX_AEAD_IV_SIZE];

static void
spdm_secured_message_set_response_data_encryption_key(IN void *spdm_secured_message_context,
                                                      IN void *key, IN uintn key_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    copy_mem(secured_message_context->application_secret.response_data_encryption_key, key,
             secured_message_context->aead_key_size);
}

static void spdm_secured_message_set_response_data_salt(IN void *spdm_secured_message_context,
                                                        IN void *salt, IN uintn salt_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    copy_mem(secured_message_context->application_secret.response_data_salt, salt,
             secured_message_context->aead_iv_size);
}
uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context, IN uintn request_size,
                                       IN void *request, IN uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context, IN OUT uintn *response_size,
                                          IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;
    spdm_session_info_t *session_info;
    spdm_end_session_response_t spdm_response;
    uintn spdm_response_size;
    uint32_t session_id;
    uint8_t test_message_header_size;

    session_id = 0xFFFFFFFF;
    test_message_header_size = 1;
    spdm_test_context = get_spdm_test_context();
    spdm_response_size = spdm_test_context->test_buffer_size - test_message_header_size;
    copy_mem(&spdm_response, (uint8_t *)spdm_test_context->test_buffer + test_message_header_size,
             spdm_response_size);



    spdm_transport_test_encode_message(spdm_context, &session_id, false, false, spdm_response_size,
                                       &spdm_response, response_size, response);

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return RETURN_DEVICE_ERROR;
    }
    /* WALKAROUND: If just use single context to encode message and then decode message */
    ((spdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number--;

    return RETURN_SUCCESS;
}

void test_spdm_requester_end_session(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, true);

    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    set_mem(
        m_dummy_key_buffer,
        ((spdm_secured_message_context_t *)(session_info->secured_message_context))->aead_key_size,
        (uint8_t)(0xFF));
    spdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((spdm_secured_message_context_t *)(session_info->secured_message_context))->aead_key_size);
    set_mem(
        m_dummy_salt_buffer,
        ((spdm_secured_message_context_t *)(session_info->secured_message_context))->aead_iv_size,
        (uint8_t)(0xFF));
    spdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((spdm_secured_message_context_t *)(session_info->secured_message_context))->aead_iv_size);
    ((spdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    spdm_send_receive_end_session(spdm_context, session_id, 0);
}

spdm_test_context_t m_spdm_requester_end_session_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_end_session_test_context);

    m_spdm_requester_end_session_test_context.test_buffer = test_buffer;
    m_spdm_requester_end_session_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_end_session(&State);
    spdm_unit_test_group_teardown(&State);
}
