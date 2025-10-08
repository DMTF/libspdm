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

static struct m_test_params {
    uint32_t event_count;
    size_t events_list_size;
    uint8_t events_list[0x1000];
} m_test_params;

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context = libspdm_get_test_context();

    switch (spdm_test_context->case_id) {
    case 0x4:
    case 0x6:
    case 0x7:
    case 0x8:
    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        return LIBSPDM_STATUS_SEND_FAIL;
    default:
        assert_true(false);
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context = libspdm_get_test_context();
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

    switch (spdm_test_context->case_id) {
    case 0x7:
        /* Invalid response message size. */
        spdm_response_size++;
        break;
    case 0x8:
        /* Invalid RequestResponseCode to SEND_EVENT request. */
        spdm_response->header.request_response_code = SPDM_KEY_UPDATE_ACK;
        break;
    case 0x9:
        /* Invalid SPDMVersion field value. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
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

    switch (spdm_test_context->case_id) {
    case 0x6:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    case 0x7:
    case 0x8:
    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        assert_true(false);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
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
 * Test 1: Requester has not set EVENT_CAP.
 * Expected behavior: returns with LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void req_send_event_err_case1(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    /* Clear EVENT_CAP. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: Connection version does not support SEND_EVENT.
 * Expected behavior: returns with LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void req_send_event_err_case2(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    /* Set version to 1.2, which does not support SEND_EVENT. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: Unable to acquire send buffer.
 * Expected behavior: returns with LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_send_event_err_case3(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    /* Induce error when acquiring send buffer. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 4: Unable to acquire receive buffer.
 * Expected behavior: returns with LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_send_event_err_case4(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    /* Induce error when acquiring receive buffer. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 5: Unable to send message.
 * Expected behavior: returns with LIBSPDM_STATUS_SEND_FAIL.
 **/
static void req_send_event_err_case5(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 6: Unable to receive message.
 * Expected behavior: returns with LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_send_event_err_case6(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 7: Invalid size of EVENT_ACK response.
 * Expected behavior: returns with LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_send_event_err_case7(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 8: Invalid RequestResponseCode in response.
 * Expected behavior: returns with LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_send_event_err_case8(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 9: Invalid SPDMVersion in response.
 * Expected behavior: returns with LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_send_event_err_case9(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context);

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

int libspdm_req_send_event_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_send_event_err_case1),
        cmocka_unit_test(req_send_event_err_case2),
        cmocka_unit_test(req_send_event_err_case3),
        cmocka_unit_test(req_send_event_err_case4),
        cmocka_unit_test(req_send_event_err_case5),
        cmocka_unit_test(req_send_event_err_case6),
        cmocka_unit_test(req_send_event_err_case7),
        cmocka_unit_test(req_send_event_err_case8),
        cmocka_unit_test(req_send_event_err_case9),
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
