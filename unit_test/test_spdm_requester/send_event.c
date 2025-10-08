/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP

static uint32_t m_session_id = 0xffffffff;
static uint8_t m_spdm_request_buffer[0x1000];

static struct m_test_params {
    uint32_t event_count;
    size_t events_list_size;
    uint8_t events_list[0x1000];
} m_test_params;

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_return_t status;
    uint32_t session_id;
    uint32_t *message_session_id;
    spdm_send_event_request_t *spdm_message;
    bool is_app_message;
    void *spdm_request_buffer;
    size_t spdm_request_size;
    libspdm_session_info_t *session_info;
    uint8_t request_buffer[0x1000];

    /* Workaround request being const. */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer), request, request_size);

    session_id = m_session_id;
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT(session_info != NULL);

    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->
    application_secret.request_data_sequence_number--;

    spdm_request_buffer = m_spdm_request_buffer;
    spdm_request_size = sizeof(m_spdm_request_buffer);

    status = libspdm_transport_test_decode_message(spdm_context, &message_session_id,
                                                   &is_app_message, true,
                                                   request_size, request_buffer,
                                                   &spdm_request_size, &spdm_request_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_message = spdm_request_buffer;

    assert_int_equal(spdm_request_size,
                     sizeof(spdm_send_event_request_t) + m_test_params.events_list_size);
    assert_int_equal(spdm_message->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_message->header.request_response_code, SPDM_SEND_EVENT);
    assert_int_equal(spdm_message->header.param1, 0);
    assert_int_equal(spdm_message->header.param2, 0);
    assert_int_equal(spdm_message->event_count, m_test_params.event_count);

    for (unsigned int index = 0; index < m_test_params.events_list_size; index++) {
        assert_int_equal(((uint8_t *)(spdm_message + 1))[index], (uint8_t)index);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    spdm_event_ack_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    session_id = m_session_id;
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT((session_info != NULL));

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    spdm_response_size = sizeof(spdm_event_ack_response_t);
    libspdm_zero_mem(spdm_response, spdm_response_size);

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_EVENT_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
     * transport_message is always in sender buffer. */
    libspdm_get_scratch_buffer(spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
    libspdm_copy_mem(scratch_buffer + transport_header_size,
                     scratch_buffer_size - transport_header_size,
                     spdm_response, spdm_response_size);

    spdm_response = (void *)(scratch_buffer + transport_header_size);

    libspdm_transport_test_encode_message(spdm_context, &session_id,
                                          false, false, spdm_response_size,
                                          spdm_response, response_size, response);

    /* Workaround: Use single context to encode message and then decode message. */
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->
    application_secret.response_data_sequence_number--;

    return LIBSPDM_STATUS_SUCCESS;
}

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->latest_session_id = m_session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
}

/**
 * Test 1: Successfully send a SEND_EVENT message.
 * Expected behavior: returns with LIBSPDM_STATUS_SUCCESS.
 **/
static void req_send_event_case1(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

int libspdm_req_send_event_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_send_event_case1),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
