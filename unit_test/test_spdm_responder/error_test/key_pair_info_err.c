/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

static uint8_t m_spdm_request_buffer[0x1000];
static uint8_t m_spdm_response_buffer[0x1000];

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP;
}

/**
 * Test 1: Negotiated SPDM version is less than 1.3, which does not support GET_KEY_PAIR_INFO.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void rsp_key_pair_info_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    /* SPDM 1.2 does not support GET_KEY_PAIR_INFO. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_request = (spdm_get_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_GET_KEY_PAIR_INFO;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_get_key_pair_info_request_t);

    status = libspdm_get_response_key_pair_info(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_KEY_PAIR_INFO);
}

/**
 * Test 2: SPDM version field in GET_KEY_PAIR_INFO request does not match the connection's
 *         negotiated version.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_VERSION_MISMATCH.
 **/
static void rsp_key_pair_info_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    spdm_request = (spdm_get_key_pair_info_request_t *)m_spdm_request_buffer;
    /* Version in message header does not match the negotiated version (1.3). */
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_GET_KEY_PAIR_INFO;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_get_key_pair_info_request_t);

    status = libspdm_get_response_key_pair_info(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 3: Responder is not in the normal response state when GET_KEY_PAIR_INFO is received.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_RESPONSE_NOT_READY.
 **/
static void rsp_key_pair_info_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    spdm_error_data_response_not_ready_t *error_data;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x03;

    set_standard_state(spdm_context);

    /* Force responder into not-ready state. */
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;

    spdm_request = (spdm_get_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_GET_KEY_PAIR_INFO;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_get_key_pair_info_request_t);

    status = libspdm_get_response_key_pair_info(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;
    error_data = (spdm_error_data_response_not_ready_t *)(spdm_response + 1);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_GET_KEY_PAIR_INFO);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

/**
 * Test 4: request_size is smaller than the minimum size of a GET_KEY_PAIR_INFO request message.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void rsp_key_pair_info_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;

    set_standard_state(spdm_context);

    spdm_request = (spdm_get_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_GET_KEY_PAIR_INFO;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    /* request_size is one byte too small. */
    request_size = sizeof(spdm_get_key_pair_info_request_t) - 1;

    status = libspdm_get_response_key_pair_info(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 5: Connection has not yet reached the NEGOTIATED state when GET_KEY_PAIR_INFO is received.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNEXPECTED_REQUEST.
 **/
static void rsp_key_pair_info_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x05;

    set_standard_state(spdm_context);

    /* Connection has not been negotiated yet. */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_request = (spdm_get_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_GET_KEY_PAIR_INFO;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_get_key_pair_info_request_t);

    status = libspdm_get_response_key_pair_info(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

int libspdm_rsp_key_pair_info_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_key_pair_info_err_case1),
        cmocka_unit_test(rsp_key_pair_info_err_case2),
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
        cmocka_unit_test(rsp_key_pair_info_err_case3),
#endif
        cmocka_unit_test(rsp_key_pair_info_err_case4),
        cmocka_unit_test(rsp_key_pair_info_err_case5),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */
