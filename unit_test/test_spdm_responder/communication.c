/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

/* The responses that send_message was given since the case started, and the last of them. */
static size_t m_response_count;
static uint8_t m_response[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static size_t m_response_size;

static libspdm_return_t send_message(
    void *spdm_context, size_t response_size, const void *response, uint64_t timeout)
{
    m_response_count++;
    libspdm_copy_mem(m_response, sizeof(m_response), response, response_size);
    m_response_size = response_size;

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *request_size, void **request, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        spdm_get_version_request_t *spdm_request;
        size_t spdm_request_size;
        size_t transport_header_size;

        spdm_request_size = sizeof(spdm_get_version_request_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_request = (void *)((uint8_t *)*request + transport_header_size);

        libspdm_zero_mem(spdm_request, spdm_request_size);
        spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_request->header.request_response_code = SPDM_GET_VERSION;
        spdm_request->header.param1 = 0;
        spdm_request->header.param2 = 0;

        return libspdm_transport_test_encode_message(spdm_context, NULL, false, true,
                                                     spdm_request_size, spdm_request,
                                                     request_size, request);
    }

    case 0x2:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Dispatch a GET_VERSION request.
 * Expected Behavior: libspdm_responder_dispatch_message returns success after sending one
 * VERSION response, and the connection state moves to after VERSION.
 **/
static void rsp_communication_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t *session_id;
    bool is_app_message;
    uint8_t *response;
    size_t response_size;
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    m_response_count = 0;

    status = libspdm_responder_dispatch_message(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(m_response_count, 1);

    libspdm_get_scratch_buffer(spdm_context, (void **)&response, &response_size);
    status = libspdm_transport_test_decode_message(spdm_context, &session_id, &is_app_message,
                                                   false, m_response_size, m_response,
                                                   &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AFTER_VERSION);
}

/**
 * Test 2: Receiving the request fails.
 * Expected Behavior: libspdm_responder_dispatch_message returns the receive failure without
 * sending a response.
 **/
static void rsp_communication_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    m_response_count = 0;

    status = libspdm_responder_dispatch_message(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
    assert_int_equal(m_response_count, 0);
}

int libspdm_rsp_communication_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_communication_case1),
        cmocka_unit_test(rsp_communication_case2),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
