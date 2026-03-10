/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

static uint8_t m_spdm_request_buffer[0x1000];
static uint8_t m_spdm_response_buffer[0x1000];

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;
}

/**
 * Test 1: Negotiated SPDM version is less than 1.3, which does not support SET_KEY_PAIR_INFO.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void rsp_set_key_pair_info_ack_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_set_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    /* SPDM 1.2 does not support SET_KEY_PAIR_INFO. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_request = (spdm_set_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    spdm_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_set_key_pair_info_request_t);

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_SET_KEY_PAIR_INFO);
}

/**
 * Test 2: SPDM version field in SET_KEY_PAIR_INFO request does not match the connection's
 *         negotiated version.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_VERSION_MISMATCH.
 **/
static void rsp_set_key_pair_info_ack_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_set_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    spdm_request = (spdm_set_key_pair_info_request_t *)m_spdm_request_buffer;
    /* Version in message header does not match the negotiated version (1.3). */
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    spdm_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_set_key_pair_info_request_t);

    status = libspdm_get_response_set_key_pair_info_ack(
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
 * Test 3: request_size is smaller than the minimum size of a SET_KEY_PAIR_INFO request.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void rsp_set_key_pair_info_ack_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_set_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x03;

    set_standard_state(spdm_context);

    spdm_request = (spdm_set_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    spdm_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    /* request_size is one byte too small. */
    request_size = sizeof(spdm_set_key_pair_info_request_t) - 1;

    status = libspdm_get_response_set_key_pair_info_ack(
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
 * Test 4: Connection has not yet reached the NEGOTIATED state when SET_KEY_PAIR_INFO is received.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNEXPECTED_REQUEST.
 **/
static void rsp_set_key_pair_info_ack_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_set_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;

    set_standard_state(spdm_context);

    /* Connection has not been negotiated yet. */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_request = (spdm_set_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    spdm_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_set_key_pair_info_request_t);

    status = libspdm_get_response_set_key_pair_info_ack(
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
 * Test 5: Responder does not advertise SET_KEY_PAIR_INFO_CAP.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void rsp_set_key_pair_info_ack_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_set_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x05;

    set_standard_state(spdm_context);

    /* Clear SET_KEY_PAIR_INFO_CAP so the capability check fails. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;

    spdm_request = (spdm_set_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    spdm_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    request_size = sizeof(spdm_set_key_pair_info_request_t);

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_SET_KEY_PAIR_INFO);
}

/**
 * Test 6: Request specifies both a non-zero desired_asym_algo and a non-zero
 *         desired_pqc_asym_algo, which is not allowed. Requires SPDM 1.4 or above so
 *         that the desired_pqc_asym_algo field is parsed from the request.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void rsp_set_key_pair_info_ack_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_set_key_pair_info_request_t *spdm_request;
    size_t request_size;
    spdm_error_response_t *spdm_response;
    size_t response_size = sizeof(m_spdm_response_buffer);
    uint8_t *ptr;
    uint8_t desired_pqc_asym_algo_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x06;

    set_standard_state(spdm_context);

    /* SPDM 1.4 is required to include the desired_pqc_asym_algo field. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    desired_pqc_asym_algo_len = sizeof(uint32_t);

    request_size = sizeof(spdm_set_key_pair_info_request_t) +
                   sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                   sizeof(uint8_t) + desired_pqc_asym_algo_len;

    libspdm_zero_mem(m_spdm_request_buffer, request_size);

    spdm_request = (spdm_set_key_pair_info_request_t *)m_spdm_request_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    spdm_request->header.param1 = SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = 1;

    ptr = (uint8_t *)(spdm_request + 1);
    ptr += sizeof(uint8_t); /* reserved byte */

    libspdm_write_uint16(ptr, 0); /* desired_key_usage = 0 */
    ptr += sizeof(uint16_t);

    /* Set desired_asym_algo to a non-zero one-hot value. */
    libspdm_write_uint32(ptr, SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256);
    ptr += sizeof(uint32_t);

    *ptr = 0; /* desired_assoc_cert_slot_mask = 0 */
    ptr += sizeof(uint8_t);

    *ptr = desired_pqc_asym_algo_len;
    ptr += sizeof(uint8_t);

    /* Set desired_pqc_asym_algo to a non-zero one-hot value. Both asym_algo and
     * pqc_asym_algo being non-zero is invalid. */
    libspdm_write_uint32(ptr, SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44);

    status = libspdm_get_response_set_key_pair_info_ack(
        spdm_context, request_size, m_spdm_request_buffer,
        &response_size, m_spdm_response_buffer);

    spdm_response = (spdm_error_response_t *)m_spdm_response_buffer;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

int libspdm_rsp_set_key_pair_info_ack_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_set_key_pair_info_ack_err_case1),
        cmocka_unit_test(rsp_set_key_pair_info_ack_err_case2),
        cmocka_unit_test(rsp_set_key_pair_info_ack_err_case3),
        cmocka_unit_test(rsp_set_key_pair_info_ack_err_case4),
        cmocka_unit_test(rsp_set_key_pair_info_ack_err_case5),
        cmocka_unit_test(rsp_set_key_pair_info_ack_err_case6),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */
