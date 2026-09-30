/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP

/* The CSRdata that the Responder returns. The Requester does not parse it. */
static uint8_t m_csr[0x40];

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.multi_key_conn_rsp = false;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    const spdm_get_csr_request_t *spdm_request;

    spdm_request = (const void *)((const uint8_t *)request + sizeof(libspdm_test_message_header_t));

    assert_int_equal(spdm_request->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_request->header.request_response_code, SPDM_GET_CSR);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_csr_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    /* Each test case alters this valid response. */
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_CSR;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->csr_length = sizeof(m_csr);
    spdm_response->reserved = 0;
    libspdm_copy_mem(spdm_response + 1, sizeof(m_csr), m_csr, sizeof(m_csr));

    spdm_response_size = sizeof(spdm_csr_response_t) + sizeof(m_csr);

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0xA:
        /* {ERROR} The transport fails to receive the response. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    case 0xB:
        /* {ERROR} The Responder is busy. */
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response_size = sizeof(spdm_error_response_t);
        break;
    case 0xC:
        /* {ERROR} The response code does not match the request. */
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        break;
    case 0xD:
        /* {ERROR} SPDMVersion does not match the request. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        break;
    case 0xE:
        /* {ERROR} The response ends before CSRLength. */
        spdm_response_size = sizeof(spdm_message_header_t);
        break;
    case 0xF:
        /* {ERROR} Illegal CSRLength value. */
        spdm_response->csr_length = 0;
        break;
    case 0x10:
        /* {ERROR} CSRLength is one byte larger than the CSRdata in the response. */
        spdm_response->csr_length++;
        break;
    case 0x11:
        /* The response is valid but larger than the Requester's buffer. */
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
 * Test 1: The negotiated SPDM version is 1.1. GET_CSR was introduced in SPDM 1.2.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_csr_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    /* {ERROR} SPDM 1.1 does not define GET_CSR. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: The negotiated SPDM version is 1.2 and the Integrator passes a KeyPairID or request
 *         attributes, which were introduced in SPDM 1.3.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_PARAMETER without sending a request.
 **/
static void req_get_csr_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* {ERROR} Non-zero KeyPairID. */
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 1, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    /* {ERROR} Non-zero request attributes. */
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len,
                             SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 3: The Responder does not set CSR_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_csr_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);

    /* {ERROR} Responder cannot generate a CSR. */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: The Responder has multiple asymmetric keys (MULTI_KEY_CONN_RSP is true) and the
 *         Integrator passes KeyPairID 0 or a reserved CSRCertModel value.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_PARAMETER without sending a request.
 **/
static void req_get_csr_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);
    spdm_context->connection_info.multi_key_conn_rsp = true;

    /* {ERROR} KeyPairID 0 is reserved. */
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len,
                             SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    /* {ERROR} CSRCertModel is reserved. */
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len,
                             SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT + 1, 1, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 5: The Responder does not have multiple asymmetric keys (MULTI_KEY_CONN_RSP is false) and
 *         the Integrator passes a KeyPairID or a CSRCertModel.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_PARAMETER without sending a request.
 **/
static void req_get_csr_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    /* {ERROR} Non-zero KeyPairID. */
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 1, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    /* {ERROR} Non-zero CSRCertModel. */
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len,
                             SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 6: GET_CSR is issued before the connection has negotiated algorithms.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_get_csr_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);

    /* {ERROR} Algorithms have not been negotiated. */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 7: GET_CSR is issued in a session that is still in the handshake phase.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_get_csr_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context);

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    /* {ERROR} The session has not been established. */
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_HANDSHAKING);

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, &session_id, NULL, 0, NULL, 0, csr, &csr_len, 0, 0,
                             NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);

    libspdm_free_session_id(spdm_context, session_id);
}

/**
 * Test 8: The Requester cannot acquire the sender buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_csr_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 9: The request is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_csr_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 10: The transport fails to receive the response.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_get_csr_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    set_standard_state(spdm_context);

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 11: Responder returns an ERROR message with ErrorCode=Busy to the request and to its one
 *          retry.
 * Expected Behavior: Returns LIBSPDM_STATUS_BUSY_PEER.
 **/
static void req_get_csr_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    set_standard_state(spdm_context);
    spdm_context->retry_times = 1;

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);

    spdm_context->retry_times = 0;
}

/**
 * Test 12: Responder returns CERTIFICATE instead of CSR.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_csr_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    set_standard_state(spdm_context);

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 13: Responder returns SPDMVersion 1.2 in response to a 1.3 request.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_csr_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    set_standard_state(spdm_context);

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: Responder returns only the SPDM message header of CSR.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_csr_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    set_standard_state(spdm_context);

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 15: Responder returns a value of 0 for CSRLength.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_csr_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    set_standard_state(spdm_context);

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 16: Responder returns a CSRLength one byte larger than the CSRdata that follows it.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_csr_err_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr) + 1];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    set_standard_state(spdm_context);

    csr_len = sizeof(csr);
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 17: The Requester's buffer is one byte smaller than the CSR.
 * Expected Behavior: Returns LIBSPDM_STATUS_BUFFER_TOO_SMALL and the size of the CSR in csr_len.
 **/
static void req_get_csr_err_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t csr[sizeof(m_csr)];
    size_t csr_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    set_standard_state(spdm_context);

    /* {ERROR} The buffer cannot hold the CSR. */
    csr_len = sizeof(csr) - 1;
    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, csr, &csr_len, 0, 0, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(csr_len, sizeof(m_csr));
}

int libspdm_req_get_csr_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_get_csr_err_case1),
        cmocka_unit_test(req_get_csr_err_case2),
        cmocka_unit_test(req_get_csr_err_case3),
        cmocka_unit_test(req_get_csr_err_case4),
        cmocka_unit_test(req_get_csr_err_case5),
        cmocka_unit_test(req_get_csr_err_case6),
        cmocka_unit_test(req_get_csr_err_case7),
        cmocka_unit_test(req_get_csr_err_case8),
        cmocka_unit_test(req_get_csr_err_case9),
        cmocka_unit_test(req_get_csr_err_case10),
        cmocka_unit_test(req_get_csr_err_case11),
        cmocka_unit_test(req_get_csr_err_case12),
        cmocka_unit_test(req_get_csr_err_case13),
        cmocka_unit_test(req_get_csr_err_case14),
        cmocka_unit_test(req_get_csr_err_case15),
        cmocka_unit_test(req_get_csr_err_case16),
        cmocka_unit_test(req_get_csr_err_case17),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
