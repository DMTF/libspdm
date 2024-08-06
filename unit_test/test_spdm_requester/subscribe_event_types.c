/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT

static const uint32_t m_session_id = 0xffffffff;

static uint8_t m_spdm_request_buffer[0x1000];

static struct test_params {
    uint8_t subscribe_event_group_count;
    uint32_t subscribe_list_len;
    uint8_t subscribe_list[0x1000];
} test_params;

static void set_standard_state(libspdm_context_t *spdm_context, uint32_t *session_id)
{
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    *session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_ESTABLISHED);
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_return_t status;
    uint32_t session_id;
    uint32_t *message_session_id;
    spdm_subscribe_event_types_request_t *spdm_message;
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

    assert_int_equal(spdm_message->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_message->header.request_response_code, SPDM_SUBSCRIBE_EVENT_TYPES);
    assert_int_equal(spdm_message->header.param1, test_params.subscribe_event_group_count);
    assert_int_equal(spdm_message->header.param2, 0);

    if (test_params.subscribe_event_group_count == 0) {
        assert_int_equal(sizeof(spdm_message->header), spdm_request_size);
    } else {
        assert_int_equal(spdm_message->subscribe_list_len, test_params.subscribe_list_len);
        assert_memory_equal(spdm_message + 1, test_params.subscribe_list,
                            spdm_message->subscribe_list_len);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    spdm_subscribe_event_types_ack_response_t *spdm_response;
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

    spdm_response_size = sizeof(spdm_subscribe_event_types_ack_response_t);
    libspdm_zero_mem(spdm_response, spdm_response_size);

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES_ACK;
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

/**
 * Test 1: Successful response to subscribe event types that clears all subscriptions.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS.
 **/
static void libspdm_test_requester_subscribe_event_types_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context, &session_id);
    test_params.subscribe_event_group_count = 0;
    test_params.subscribe_list_len = 0;

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 2: Successful response to subscribe event types that includes one event group and two event
 *         types.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS.
 **/
static void libspdm_test_requester_subscribe_event_types_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context, &session_id);
    generate_dmtf_event_group(test_params.subscribe_list, &event_group_size, 0,
                              true, true, false, false);
    test_params.subscribe_event_group_count = 1;
    test_params.subscribe_list_len = event_group_size;

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 3: Successful response to subscribe event types that includes one event group and all event
 *         types using the AllEventTypes attribute.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS.
 **/
static void libspdm_test_requester_subscribe_event_types_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context, &session_id);
    generate_dmtf_event_group(test_params.subscribe_list, &event_group_size,
                              SPDM_SUBSCRIBE_EVENT_TYPES_REQUEST_ATTRIBUTE_ALL,
                              false, false, false, false);
    test_params.subscribe_event_group_count = 1;
    test_params.subscribe_list_len = event_group_size;

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

int libspdm_requester_subscribe_event_types_test_main(void)
{
    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    const struct CMUnitTest spdm_requester_get_event_types_tests[] = {
        cmocka_unit_test(libspdm_test_requester_subscribe_event_types_case1),
        cmocka_unit_test(libspdm_test_requester_subscribe_event_types_case2),
        cmocka_unit_test(libspdm_test_requester_subscribe_event_types_case3)
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(spdm_requester_get_event_types_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */
