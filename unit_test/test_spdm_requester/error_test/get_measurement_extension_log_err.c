/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    const spdm_get_measurement_extension_log_request_t *spdm_request;

    spdm_request = (const void *)((const uint8_t *)request + sizeof(libspdm_test_message_header_t));

    assert_int_equal(spdm_request->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_request->header.request_response_code,
                     SPDM_GET_MEASUREMENT_EXTENSION_LOG);
    assert_int_equal(spdm_request->offset, 0);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_measurement_extension_log_response_t *spdm_response;
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    size_t spdm_response_size;
    size_t transport_header_size;

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    /* Each test case alters this valid response, which carries a MEL with no entries. */
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = sizeof(spdm_measurement_extension_log_dmtf_t);
    spdm_response->remainder_length = 0;

    measurement_extension_log = (void *)(spdm_response + 1);
    measurement_extension_log->number_of_entries = 0;
    measurement_extension_log->mel_entries_len = 0;
    measurement_extension_log->reserved = 0;

    spdm_response_size = sizeof(spdm_measurement_extension_log_response_t) +
                         sizeof(spdm_measurement_extension_log_dmtf_t);

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x7:
        /* {ERROR} The transport fails to receive the response. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    case 0x8:
        /* {ERROR} The Responder is busy. */
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;
        spdm_response_size = sizeof(spdm_error_response_t);
        break;
    case 0x9:
        /* {ERROR} The response code does not match the request. */
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        break;
    case 0xA:
        /* {ERROR} SPDMVersion does not match the request. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        break;
    case 0xB:
        /* {ERROR} The response ends before PortionLength. */
        spdm_response_size = sizeof(spdm_message_header_t);
        break;
    case 0xC:
        /* {ERROR} PortionLength is one byte larger than the MEL in the response. */
        spdm_response->portion_length++;
        break;
    default:
        assert_true(false);
        break;
    }

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false, spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: The negotiated SPDM version is 1.2. GET_MEASUREMENT_EXTENSION_LOG was introduced in
 *         SPDM 1.3.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_measurement_extension_log_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    /* {ERROR} SPDM 1.2 does not define GET_MEASUREMENT_EXTENSION_LOG. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: The Responder does not set MEL_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_measurement_extension_log_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    /* {ERROR} Responder does not have a MEL. */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: GET_MEASUREMENT_EXTENSION_LOG is issued before the connection has negotiated
 *         algorithms.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_get_measurement_extension_log_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);

    /* {ERROR} Algorithms have not been negotiated. */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 4: GET_MEASUREMENT_EXTENSION_LOG is issued in a session that is still in the handshake
 *         phase.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_get_measurement_extension_log_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    /* {ERROR} The session has not been established. */
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_HANDSHAKING);

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, &session_id, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);

    libspdm_free_session_id(spdm_context, session_id);
}

/**
 * Test 5: The Requester cannot acquire the sender buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_measurement_extension_log_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 6: The request is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_measurement_extension_log_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 7: The transport fails to receive the response.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_get_measurement_extension_log_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context);

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 8: Responder returns an ERROR message with ErrorCode=Busy to the request and to its one
 *         retry.
 * Expected Behavior: Returns LIBSPDM_STATUS_BUSY_PEER.
 **/
static void req_get_measurement_extension_log_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);
    spdm_context->retry_times = 1;

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);

    spdm_context->retry_times = 0;
}

/**
 * Test 9: Responder returns MEASUREMENTS instead of MEASUREMENT_EXTENSION_LOG.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_measurement_extension_log_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context);

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 10: Responder returns SPDMVersion 1.2 in response to a 1.3 request.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_measurement_extension_log_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    set_standard_state(spdm_context);

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 11: Responder returns only the SPDM message header of MEASUREMENT_EXTENSION_LOG.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_measurement_extension_log_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    set_standard_state(spdm_context);

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 12: Responder returns a PortionLength one byte larger than the MEL that follows it.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_measurement_extension_log_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    size_t mel_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    set_standard_state(spdm_context);

    mel_size = sizeof(mel);
    status = libspdm_get_measurement_extension_log(spdm_context, NULL, &mel_size, mel);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

int libspdm_req_get_measurement_extension_log_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_get_measurement_extension_log_err_case1),
        cmocka_unit_test(req_get_measurement_extension_log_err_case2),
        cmocka_unit_test(req_get_measurement_extension_log_err_case3),
        cmocka_unit_test(req_get_measurement_extension_log_err_case4),
        cmocka_unit_test(req_get_measurement_extension_log_err_case5),
        cmocka_unit_test(req_get_measurement_extension_log_err_case6),
        cmocka_unit_test(req_get_measurement_extension_log_err_case7),
        cmocka_unit_test(req_get_measurement_extension_log_err_case8),
        cmocka_unit_test(req_get_measurement_extension_log_err_case9),
        cmocka_unit_test(req_get_measurement_extension_log_err_case10),
        cmocka_unit_test(req_get_measurement_extension_log_err_case11),
        cmocka_unit_test(req_get_measurement_extension_log_err_case12),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
