/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP

static uint8_t m_spdm_request_buffer[0x1000];
static uint8_t m_spdm_response_buffer[0x1000];

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    spdm_context->connection_info.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
}

/**
 * Test 1: Negotiated SPDM version is less than 1.3, which does not support
 *         GET_MEASUREMENT_EXTENSION_LOG.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void rsp_measurement_extension_log_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_measurement_extension_log_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    /* SPDM 1.2 does not support GET_MEASUREMENT_EXTENSION_LOG. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_request = (spdm_get_measurement_extension_log_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_GET_MEASUREMENT_EXTENSION_LOG;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->offset = 0;
    spdm_request->length = SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE;

    request_size = sizeof(spdm_get_measurement_extension_log_request_t);

    status = libspdm_get_response_measurement_extension_log(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_MEASUREMENT_EXTENSION_LOG);
}

/**
 * Test 2: SPDM version field in GET_MEASUREMENT_EXTENSION_LOG request does not match the
 *         connection's negotiated version.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_VERSION_MISMATCH.
 **/
static void rsp_measurement_extension_log_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_measurement_extension_log_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    spdm_request = (spdm_get_measurement_extension_log_request_t *)m_spdm_request_buffer;
    /* Version in message header does not match the negotiated version (1.3). */
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_GET_MEASUREMENT_EXTENSION_LOG;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->offset = 0;
    spdm_request->length = SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE;

    request_size = sizeof(spdm_get_measurement_extension_log_request_t);

    status = libspdm_get_response_measurement_extension_log(
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

/**
 * Test 3: Connection has not yet reached the NEGOTIATED state when
 *         GET_MEASUREMENT_EXTENSION_LOG is received.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNEXPECTED_REQUEST.
 **/
static void rsp_measurement_extension_log_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_measurement_extension_log_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x03;

    set_standard_state(spdm_context);

    /* Connection has not been negotiated yet. */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_request = (spdm_get_measurement_extension_log_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_GET_MEASUREMENT_EXTENSION_LOG;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->offset = 0;
    spdm_request->length = SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE;

    request_size = sizeof(spdm_get_measurement_extension_log_request_t);

    status = libspdm_get_response_measurement_extension_log(
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

/**
 * Test 4: Responder does not have MEL_CAP set in its local capabilities.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void rsp_measurement_extension_log_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_measurement_extension_log_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;

    set_standard_state(spdm_context);

    /* Clear MEL_CAP so the capability check fails. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    spdm_request = (spdm_get_measurement_extension_log_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_GET_MEASUREMENT_EXTENSION_LOG;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->offset = 0;
    spdm_request->length = SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE;

    request_size = sizeof(spdm_get_measurement_extension_log_request_t);

    status = libspdm_get_response_measurement_extension_log(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_MEASUREMENT_EXTENSION_LOG);
}

/**
 * Test 5: The negotiated MEL specification is zero (no MEL spec agreed upon).
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNEXPECTED_REQUEST.
 **/
static void rsp_measurement_extension_log_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_measurement_extension_log_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x05;

    set_standard_state(spdm_context);

    /* No MEL specification was negotiated. */
    spdm_context->connection_info.algorithm.mel_spec = 0;

    spdm_request = (spdm_get_measurement_extension_log_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_GET_MEASUREMENT_EXTENSION_LOG;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->offset = 0;
    spdm_request->length = SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE;

    request_size = sizeof(spdm_get_measurement_extension_log_request_t);

    status = libspdm_get_response_measurement_extension_log(
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

int libspdm_rsp_measurement_extension_log_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_measurement_extension_log_err_case1),
        cmocka_unit_test(rsp_measurement_extension_log_err_case2),
        cmocka_unit_test(rsp_measurement_extension_log_err_case3),
        cmocka_unit_test(rsp_measurement_extension_log_err_case4),
        cmocka_unit_test(rsp_measurement_extension_log_err_case5),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
