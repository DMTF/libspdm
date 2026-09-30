/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;
    spdm_context->local_context.secured_message_version.secured_message_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    const spdm_psk_exchange_request_t *spdm_request;

    spdm_request = (const void *)((const uint8_t *)request + sizeof(libspdm_test_message_header_t));

    assert_int_equal(spdm_request->header.request_response_code, SPDM_PSK_EXCHANGE);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *context;
    spdm_psk_exchange_response_t *spdm_response;
    spdm_general_opaque_data_table_header_t *general_opaque_data_table_header;
    size_t spdm_response_size;
    size_t transport_header_size;
    size_t opaque_data_size;
    uint16_t context_length;
    uint32_t hmac_size;
    uint8_t *ptr;

    context = spdm_context;
    spdm_test_context = libspdm_get_test_context();

    if (spdm_test_context->case_id == 0xC) {
        /* {ERROR} The transport fails to receive the response. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    /* {ERROR} Test 18 omits ResponderContext. */
    context_length = (spdm_test_context->case_id == 0x12) ? 0 : LIBSPDM_PSK_CONTEXT_LENGTH;

    hmac_size = libspdm_get_hash_size(context->connection_info.algorithm.base_hash_algo);
    opaque_data_size = libspdm_get_opaque_data_version_selection_data_size(context);

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    /* Each test case alters this response. The Requester rejects every alteration before it
     * verifies ResponderVerifyData, so ResponderVerifyData is left as zeros. */
    spdm_response->header.spdm_version = libspdm_get_connection_version(context);
    spdm_response->header.request_response_code = SPDM_PSK_EXCHANGE_RSP;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->rsp_session_id = 0xFFFF;
    spdm_response->reserved = 0;
    spdm_response->context_length = context_length;
    spdm_response->opaque_length = (uint16_t)opaque_data_size;

    ptr = (uint8_t *)(spdm_response + 1);
    libspdm_set_mem(ptr, context_length, 0xA5);
    ptr += context_length;
    libspdm_build_opaque_data_version_selection_data(
        context, SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, &opaque_data_size, ptr);
    general_opaque_data_table_header = (void *)ptr;
    ptr += opaque_data_size;
    libspdm_zero_mem(ptr, hmac_size);
    ptr += hmac_size;

    spdm_response_size = (size_t)ptr - (size_t)spdm_response;

    switch (spdm_test_context->case_id) {
    case 0xD:
        /* {ERROR} The response code does not match the request. */
        spdm_response->header.request_response_code = SPDM_KEY_EXCHANGE_RSP;
        break;
    case 0xE:
        /* {ERROR} SPDMVersion does not match the request. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        break;
    case 0xF:
        /* {ERROR} The response ends before RspSessionID. */
        spdm_response_size = sizeof(spdm_message_header_t);
        break;
    case 0x10:
        /* {ERROR} The general opaque data table has no elements. */
        general_opaque_data_table_header->total_elements = 0;
        break;
    case 0x11:
    case 0x12:
        break;
    case 0x13:
        /* {ERROR} The Responder is busy. */
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;
        spdm_response_size = sizeof(spdm_error_response_t);
        break;
    default:
        assert_true(false);
        break;
    }

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false, spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t send_receive_psk_exchange(libspdm_context_t *spdm_context)
{
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    return libspdm_send_receive_psk_exchange(
        spdm_context, LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
}

/**
 * Test 1: The negotiated SPDM version is 1.0. PSK_EXCHANGE was introduced in SPDM 1.1.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_psk_exchange_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    /* {ERROR} SPDM 1.0 does not define PSK_EXCHANGE. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: The Requester does not support PSK_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_psk_exchange_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    /* {ERROR} Requester does not support pre-shared keys. */
    spdm_context->local_context.capability.flags &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: The Responder does not support MAC_CAP. libspdm needs MAC_CAP for DSP0277 secured
 *         messages.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_psk_exchange_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);

    /* {ERROR} Responder does not support message authentication. */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: The negotiated SPDM version is 1.2 and OpaqueDataFmt1 was not selected.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_PEER without sending a request.
 **/
static void req_psk_exchange_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* {ERROR} The Responder selected OpaqueDataFmt0. */
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_PEER);
}

/**
 * Test 5: The Requester already has as many PSK sessions as it allows.
 * Expected Behavior: Returns LIBSPDM_STATUS_SESSION_NUMBER_EXCEED without sending a request.
 **/
static void req_psk_exchange_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    /* {ERROR} No PSK session is available. */
    spdm_context->max_psk_session_count = 1;
    spdm_context->current_psk_session_count = 1;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SESSION_NUMBER_EXCEED);

    spdm_context->max_psk_session_count = 0;
    spdm_context->current_psk_session_count = 0;
}

/**
 * Test 6: The Responder supports MEAS_CAP but the negotiated MeasurementSpecification is not DMTF.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_psk_exchange_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

    /* {ERROR} No measurement specification. */
    spdm_context->connection_info.algorithm.measurement_spec = 0;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 7: The Responder supports MEAS_CAP but no measurement hash algorithm was negotiated.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_psk_exchange_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

    /* {ERROR} No measurement hash algorithm. */
    spdm_context->connection_info.algorithm.measurement_hash_algo = 0;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 8: No base hash algorithm was negotiated.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_psk_exchange_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);

    /* {ERROR} No base hash algorithm. */
    spdm_context->connection_info.algorithm.base_hash_algo = 0;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 9: The negotiated key schedule is not the SPDM key schedule.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_psk_exchange_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context);

    /* {ERROR} No key schedule. */
    spdm_context->connection_info.algorithm.key_schedule = 0;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 10: The Requester cannot acquire the sender buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_psk_exchange_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = send_receive_psk_exchange(spdm_context);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 11: The request is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_psk_exchange_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = send_receive_psk_exchange(spdm_context);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 12: The transport fails to receive the response.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_psk_exchange_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    set_standard_state(spdm_context);

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 13: Responder returns KEY_EXCHANGE_RSP instead of PSK_EXCHANGE_RSP.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_psk_exchange_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    set_standard_state(spdm_context);

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: Responder returns SPDMVersion 1.2 in response to a 1.1 request.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_psk_exchange_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    set_standard_state(spdm_context);

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 15: Responder returns only the SPDM message header of PSK_EXCHANGE_RSP.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_psk_exchange_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    set_standard_state(spdm_context);

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 16: In SPDM 1.2 with OpaqueDataFmt1, the Responder's OpaqueData is a general opaque data
 *          table with no elements. DSP0274 requires at least one element.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_psk_exchange_err_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 17: The Responder supports PSK_CAP without context, but PSK_EXCHANGE_RSP carries a
 *          ResponderContext.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_psk_exchange_err_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    set_standard_state(spdm_context);

    /* {ERROR} A Responder without context must not return ResponderContext. */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER;

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 18: The Responder supports PSK_CAP with context, but PSK_EXCHANGE_RSP carries no
 *          ResponderContext.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_psk_exchange_err_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    set_standard_state(spdm_context);

    status = send_receive_psk_exchange(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 19: Through libspdm_send_receive_psk_exchange_ex, the Responder returns an ERROR message
 *          with ErrorCode=Busy to the request and to its one retry.
 * Expected Behavior: Returns LIBSPDM_STATUS_BUSY_PEER.
 **/
static void req_psk_exchange_err_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;

    set_standard_state(spdm_context);
    spdm_context->retry_times = 1;

    status = libspdm_send_receive_psk_exchange_ex(
        spdm_context, LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash,
        NULL, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);

    spdm_context->retry_times = 0;
}

int libspdm_req_psk_exchange_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_psk_exchange_err_case1),
        cmocka_unit_test(req_psk_exchange_err_case2),
        cmocka_unit_test(req_psk_exchange_err_case3),
        cmocka_unit_test(req_psk_exchange_err_case4),
        cmocka_unit_test(req_psk_exchange_err_case5),
        cmocka_unit_test(req_psk_exchange_err_case6),
        cmocka_unit_test(req_psk_exchange_err_case7),
        cmocka_unit_test(req_psk_exchange_err_case8),
        cmocka_unit_test(req_psk_exchange_err_case9),
        cmocka_unit_test(req_psk_exchange_err_case10),
        cmocka_unit_test(req_psk_exchange_err_case11),
        cmocka_unit_test(req_psk_exchange_err_case12),
        cmocka_unit_test(req_psk_exchange_err_case13),
        cmocka_unit_test(req_psk_exchange_err_case14),
        cmocka_unit_test(req_psk_exchange_err_case15),
        cmocka_unit_test(req_psk_exchange_err_case16),
        cmocka_unit_test(req_psk_exchange_err_case17),
        cmocka_unit_test(req_psk_exchange_err_case18),
        cmocka_unit_test(req_psk_exchange_err_case19),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
