/**
 *  Copyright Notice:
 *  Copyright 2024-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT

static const uint32_t m_session_id = 0xffffffff;

static uint8_t m_spdm_request_buffer[0x1000];

/* Larger than the SPDM message that the sender buffer can hold. */
static uint8_t m_oversized_subscribe_list[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];

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
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    *session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_ESTABLISHED);
}

/* Subscribe to two event types of the DMTF event group. */
static void set_standard_subscribe_list(void)
{
    uint8_t event_group_size;

    generate_dmtf_event_group(test_params.subscribe_list, &event_group_size, 0,
                              true, true, false, false);
    test_params.subscribe_event_group_count = 1;
    test_params.subscribe_list_len = event_group_size;
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
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    if (spdm_test_context->case_id == 0x7) {
        /* {ERROR} The transport fails to send the request. */
        return LIBSPDM_STATUS_SEND_FAIL;
    }

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
    assert_int_equal(sizeof(spdm_subscribe_event_types_request_t) + test_params.subscribe_list_len,
                     spdm_request_size);

    spdm_message = spdm_request_buffer;

    assert_int_equal(spdm_message->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_message->header.request_response_code, SPDM_SUBSCRIBE_EVENT_TYPES);
    assert_int_equal(spdm_message->header.param1, test_params.subscribe_event_group_count);
    assert_int_equal(spdm_message->header.param2, 0);
    assert_int_equal(spdm_message->subscribe_list_len, test_params.subscribe_list_len);

    assert_memory_equal(spdm_message + 1, test_params.subscribe_list,
                        spdm_message->subscribe_list_len);

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
    libspdm_test_context_t *spdm_test_context;

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    session_id = m_session_id;
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT((session_info != NULL));

    spdm_response_size = sizeof(spdm_subscribe_event_types_ack_response_t);
    libspdm_zero_mem(spdm_response, spdm_response_size);

    /* Each test case alters this valid response. */
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x9:
        /* {ERROR} The transport fails to receive the response. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    case 0xA:
        /* {ERROR} The response is one byte larger than SUBSCRIBE_EVENT_TYPES_ACK. */
        spdm_response_size++;
        break;
    case 0xB:
        /* {ERROR} The Responder is busy. */
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response_size = sizeof(spdm_error_response_t);
        break;
    case 0xC:
        /* {ERROR} The response code does not match the request. */
        spdm_response->header.request_response_code = SPDM_SUPPORTED_EVENT_TYPES;
        break;
    case 0xD:
        /* {ERROR} SPDMVersion does not match the request. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        break;
    default:
        break;
    }

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
 * Test 1: Test invalid arguments for subscribe_event_group_count, subscribe_list_len, and
 *         subscribe_list.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_PARAMETER.
 **/
static void req_subscribe_event_types_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context, &session_id);

    /* subscribe_event_group_count is zero but subscribe_list_len is non-zero and subscribe_list is
     * not NULL. */
    status = libspdm_subscribe_event_types(spdm_context, session_id, 0, 10, &session_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    /* subscribe_event_group_count is non-zero but subscribe_list_len is zero and subscribe_list is
     * NULL. */
    status = libspdm_subscribe_event_types(spdm_context, session_id, 5, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 2: Test invalid state with SPDM version less than 1.3.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void req_subscribe_event_types_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context, &session_id);
    /* Invalid version. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    status = libspdm_subscribe_event_types(spdm_context, session_id, 0, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: The Responder does not set EVENT_CAP, so it is not an event notifier.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void req_subscribe_event_types_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context, &session_id);
    /* Responder does not support event mechanism. */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;

    status = libspdm_subscribe_event_types(spdm_context, session_id, 0, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: The session is still in the handshake phase. SUBSCRIBE_EVENT_TYPES is only allowed in
 *         the application phase of a session.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_subscribe_event_types_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    /* {ERROR} The session has not been established. */
    libspdm_secured_message_set_session_state(
        spdm_context->session_info[0].secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 5: The Requester cannot acquire the sender buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_subscribe_event_types_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 6: The subscription list does not fit in the sender buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_BUFFER_TOO_SMALL without sending a request.
 **/
static void req_subscribe_event_types_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context, &session_id);

    /* {ERROR} The subscription list is larger than the sender buffer. */
    status = libspdm_subscribe_event_types(spdm_context, session_id, 1,
                                           sizeof(m_oversized_subscribe_list),
                                           m_oversized_subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

/**
 * Test 7: The transport fails to send the request.
 * Expected Behavior: Returns LIBSPDM_STATUS_SEND_FAIL.
 **/
static void req_subscribe_event_types_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 8: The request is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_subscribe_event_types_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 9: The transport fails to receive the response.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_subscribe_event_types_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 10: Responder returns SUBSCRIBE_EVENT_TYPES_ACK with one extra byte.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_subscribe_event_types_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 11: Responder returns an ERROR message with ErrorCode=Busy to the request and to its one
 *          retry.
 * Expected Behavior: Returns LIBSPDM_STATUS_BUSY_PEER.
 **/
static void req_subscribe_event_types_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();
    spdm_context->retry_times = 1;

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);

    spdm_context->retry_times = 0;
}

/**
 * Test 12: Responder returns SUPPORTED_EVENT_TYPES instead of SUBSCRIBE_EVENT_TYPES_ACK.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_subscribe_event_types_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 13: Responder returns SPDMVersion 1.2 in response to a 1.3 request.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_subscribe_event_types_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    set_standard_state(spdm_context, &session_id);
    set_standard_subscribe_list();

    status = libspdm_subscribe_event_types(spdm_context, session_id,
                                           test_params.subscribe_event_group_count,
                                           test_params.subscribe_list_len,
                                           test_params.subscribe_list);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

int libspdm_req_subscribe_event_types_error_test(void)
{
    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_subscribe_event_types_err_case1),
        cmocka_unit_test(req_subscribe_event_types_err_case2),
        cmocka_unit_test(req_subscribe_event_types_err_case3),
        cmocka_unit_test(req_subscribe_event_types_err_case4),
        cmocka_unit_test(req_subscribe_event_types_err_case5),
        cmocka_unit_test(req_subscribe_event_types_err_case6),
        cmocka_unit_test(req_subscribe_event_types_err_case7),
        cmocka_unit_test(req_subscribe_event_types_err_case8),
        cmocka_unit_test(req_subscribe_event_types_err_case9),
        cmocka_unit_test(req_subscribe_event_types_err_case10),
        cmocka_unit_test(req_subscribe_event_types_err_case11),
        cmocka_unit_test(req_subscribe_event_types_err_case12),
        cmocka_unit_test(req_subscribe_event_types_err_case13)
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */
