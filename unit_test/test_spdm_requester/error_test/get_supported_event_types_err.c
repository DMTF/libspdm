/**
 *  Copyright Notice:
 *  Copyright 2024-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT

static uint8_t m_supported_event_groups_list[0x1000];
static uint8_t m_spdm_request_buffer[0x1000];

static const uint32_t m_session_id = 0xffffffff;

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

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
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

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_return_t status;
    uint32_t session_id;
    uint32_t *message_session_id;
    spdm_get_supported_event_types_request_t *spdm_message;
    bool is_app_message;
    void *spdm_request_buffer;
    size_t spdm_request_size;
    libspdm_session_info_t *session_info;
    uint8_t request_buffer[0x1000];
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    if (spdm_test_context->case_id == 6) {
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
    assert_int_equal(sizeof(spdm_get_supported_event_types_request_t), spdm_request_size);

    spdm_message = spdm_request_buffer;

    assert_int_equal(spdm_message->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_message->header.request_response_code, SPDM_GET_SUPPORTED_EVENT_TYPES);
    assert_int_equal(spdm_message->header.param1, 0);
    assert_int_equal(spdm_message->header.param2, 0);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    spdm_supported_event_types_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t event_group_total_bytes;
    libspdm_test_context_t *spdm_test_context;

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    session_id = m_session_id;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT((session_info != NULL));

    /* Each test case alters this valid response. */
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_SUPPORTED_EVENT_TYPES;
    spdm_response->header.param1 = 1;
    spdm_response->header.param2 = 0;

    generate_dmtf_event_group(spdm_response + 1, &event_group_total_bytes, 0,
                              true, true, true, true);
    spdm_response->supported_event_groups_list_len = event_group_total_bytes;

    spdm_response_size = sizeof(spdm_supported_event_types_response_t) +
                         event_group_total_bytes;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 1:
        /* {ERROR} Illegal EventGroupCount value. */
        spdm_response->header.param1 = 0;
        break;
    case 8:
        /* {ERROR} The transport fails to receive the response. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    case 9:
        /* {ERROR} The Responder is busy. */
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;
        spdm_response_size = sizeof(spdm_error_response_t);
        break;
    case 10:
        /* {ERROR} The response code does not match the request. */
        spdm_response->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES_ACK;
        break;
    case 11:
        /* {ERROR} SPDMVersion does not match the request. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        break;
    case 12:
        /* {ERROR} The response ends before SupportedEventGroupsListLen. */
        spdm_response_size = sizeof(spdm_message_header_t);
        break;
    case 13:
        /* {ERROR} Illegal SupportedEventGroupsListLen value. */
        spdm_response->supported_event_groups_list_len = 0;
        break;
    case 14:
        /* The response is valid but larger than the Requester's buffer. */
        break;
    case 15:
        /* {ERROR} The response has one byte more than SupportedEventGroupsListLen indicates. */
        spdm_response_size++;
        break;
    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
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
 * Test 1: Responder returns a value of 0 for EventGroupCount (param1).
 * Expected Behavior: Returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_supported_event_types_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 2: The session is still in the handshake phase. GET_SUPPORTED_EVENT_TYPES is only allowed
 *         in the application phase of a session.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a
 *                    request.
 **/
static void req_get_supported_event_types_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;

    set_standard_state(spdm_context, &session_id);

    /* {ERROR} The session has not been established. */
    libspdm_secured_message_set_session_state(
        spdm_context->session_info[0].secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 3: The negotiated SPDM version is 1.2. GET_SUPPORTED_EVENT_TYPES was introduced in SPDM 1.3.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_supported_event_types_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 3;

    set_standard_state(spdm_context, &session_id);

    /* {ERROR} SPDM 1.2 does not define GET_SUPPORTED_EVENT_TYPES. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: The Responder does not set EVENT_CAP, so it is not an event notifier.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_supported_event_types_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 4;

    set_standard_state(spdm_context, &session_id);

    /* {ERROR} Responder is not an event notifier. */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 5: The Requester cannot acquire the sender buffer.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_supported_event_types_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 5;

    set_standard_state(spdm_context, &session_id);

    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 6: The transport fails to send the request.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_SEND_FAIL.
 **/
static void req_get_supported_event_types_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 6;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 7: The request is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_supported_event_types_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 7;

    set_standard_state(spdm_context, &session_id);

    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 8: The transport fails to receive the response.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_get_supported_event_types_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 8;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 9: Responder returns an ERROR message with ErrorCode=Busy to the request and to its one
 *         retry.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_BUSY_PEER.
 **/
static void req_get_supported_event_types_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 9;

    set_standard_state(spdm_context, &session_id);
    spdm_context->retry_times = 1;

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);

    spdm_context->retry_times = 0;
}

/**
 * Test 10: Responder returns SUBSCRIBE_EVENT_TYPES_ACK instead of SUPPORTED_EVENT_TYPES.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_supported_event_types_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 10;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 11: Responder returns SPDMVersion 1.2 in response to a 1.3 request.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_supported_event_types_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 11;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 12: Responder returns only the SPDM message header, with a valid EventGroupCount, so the
 *          SupportedEventGroupsListLen field is missing.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_supported_event_types_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 12;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 13: Responder returns a value of 0 for SupportedEventGroupsListLen.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_supported_event_types_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 13;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: The Requester's buffer is one byte smaller than the Responder's
 *          SupportedEventGroupsList.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_BUFFER_TOO_SMALL.
 **/
static void req_get_supported_event_types_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint8_t event_group_total_bytes;
    uint32_t supported_event_groups_list_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 14;

    set_standard_state(spdm_context, &session_id);

    /* Same event group as the one the Responder returns. */
    generate_dmtf_event_group(m_supported_event_groups_list, &event_group_total_bytes, 0,
                              true, true, true, true);
    /* {ERROR} The buffer cannot hold the whole list. */
    supported_event_groups_list_len = event_group_total_bytes - 1;

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

/**
 * Test 15: The size of the response is one byte larger than SupportedEventGroupsListLen indicates.
 * Expected Behavior: Returns with status LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_supported_event_types_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 15;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

int libspdm_req_get_supported_event_types_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_get_supported_event_types_err_case1),
        cmocka_unit_test(req_get_supported_event_types_err_case2),
        cmocka_unit_test(req_get_supported_event_types_err_case3),
        cmocka_unit_test(req_get_supported_event_types_err_case4),
        cmocka_unit_test(req_get_supported_event_types_err_case5),
        cmocka_unit_test(req_get_supported_event_types_err_case6),
        cmocka_unit_test(req_get_supported_event_types_err_case7),
        cmocka_unit_test(req_get_supported_event_types_err_case8),
        cmocka_unit_test(req_get_supported_event_types_err_case9),
        cmocka_unit_test(req_get_supported_event_types_err_case10),
        cmocka_unit_test(req_get_supported_event_types_err_case11),
        cmocka_unit_test(req_get_supported_event_types_err_case12),
        cmocka_unit_test(req_get_supported_event_types_err_case13),
        cmocka_unit_test(req_get_supported_event_types_err_case14),
        cmocka_unit_test(req_get_supported_event_types_err_case15)
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

#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */
