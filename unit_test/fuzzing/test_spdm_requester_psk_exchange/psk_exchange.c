/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"

static uint8_t m_local_psk_hint[32];

uintn spdm_test_get_psk_exchange_request_size(IN void *spdm_context,
                          IN void *buffer,
                          IN uintn buffer_size)
{
    spdm_psk_exchange_request_t *spdm_request;
    uintn message_size;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code != SPDM_PSK_EXCHANGE) {
        return buffer_size;
    }

    message_size = sizeof(spdm_psk_exchange_request_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    message_size += spdm_request->psk_hint_length +
            spdm_request->context_length +
            spdm_request->opaque_length;
    if (buffer_size < message_size) {
        return buffer_size;
    }

    // Good message, return actual size
    return message_size;
}

uintn get_max_buffer_size(void)
{
    return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context,
                       IN uintn request_size, IN void *request,
                       IN uint64_t timeout)
{
        return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context,
                      IN OUT uintn *response_size,
                      IN OUT void *response,
                      IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    *response_size = spdm_test_context->test_buffer_size;
    copy_mem(response, spdm_test_context->test_buffer,
         spdm_test_context->test_buffer_size);

    return RETURN_SUCCESS;
}


void test_spdm_requester_psk_exchange(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state =
        SPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                        m_use_asym_algo, &data,
                        &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
         data, data_size);
    zero_mem(m_local_psk_hint, 32);
    copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING,
         sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, &session_id,
        &heartbeat_period, measurement_hash);
}

spdm_test_context_t m_spdm_requester_psk_exchange_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    TRUE,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_psk_exchange_test_context);

    m_spdm_requester_psk_exchange_test_context.test_buffer = test_buffer;
    m_spdm_requester_psk_exchange_test_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_requester_psk_exchange(&State);

    spdm_unit_test_group_teardown(&State);
}
