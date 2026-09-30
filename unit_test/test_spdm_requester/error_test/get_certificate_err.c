/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT

/* The CertChain that the Responder returns. The error cases fail before the Requester parses it. */
static uint8_t m_cert_chain[32];

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.multi_key_conn_rsp = false;
    spdm_context->connection_info.peer_cert_info[0] = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    spdm_context->local_context.verify_peer_spdm_cert_chain = NULL;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    libspdm_reset_message_b(spdm_context);
}

static bool verify_spdm_cert_chain_fail(void *spdm_context, uint8_t slot_id,
                                        size_t cert_chain_size, const void *cert_chain,
                                        const void **trust_anchor, size_t *trust_anchor_size)
{
    return false;
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    const spdm_get_certificate_request_t *spdm_request;

    spdm_request = (const void *)((const uint8_t *)request + sizeof(libspdm_test_message_header_t));

    assert_int_equal(spdm_request->header.request_response_code, SPDM_GET_CERTIFICATE);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_certificate_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    size_t cert_chain_length;

    spdm_test_context = libspdm_get_test_context();

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)*response + transport_header_size);

    /* Each test case alters this response, which returns all of m_cert_chain for slot 0. */
    spdm_response->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = sizeof(m_cert_chain);
    spdm_response->remainder_length = 0;
    cert_chain_length = sizeof(m_cert_chain);

    switch (spdm_test_context->case_id) {
    case 0x8:
        /* {ERROR} The transport fails to receive the response. */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    case 0x9:
        /* {ERROR} The response code does not match the request. */
        spdm_response->header.request_response_code = SPDM_DIGESTS;
        break;
    case 0xA:
        /* {ERROR} SPDMVersion does not match the request. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        break;
    case 0xB:
        /* {ERROR} The response ends before PortionLength. */
        cert_chain_length = 0;
        break;
    case 0xC:
        /* {ERROR} The response uses PortionLength and RemainderLength although the request used
         * LargeOffset and LargeLength. */
        break;
    case 0xD:
        /* {ERROR} LargeCertChain although the request did not set it. */
        spdm_response->header.param1 |= SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN;
        break;
    case 0xE:
        /* {ERROR} Reserved CertModel value. */
        spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT + 1;
        break;
    case 0xF:
    case 0x10:
        spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
        break;
    case 0x11:
        /* {ERROR} PortionLength is four bytes larger than the CertChain in the response. */
        spdm_response->portion_length += 4;
        break;
    case 0x12:
        /* {ERROR} RemainderLength makes the certificate chain larger than 0xFFFF bytes. */
        spdm_response->remainder_length = SPDM_MAX_CERTIFICATE_CHAIN_SIZE;
        break;
    case 0x13:
    /* {ERROR} Every response claims half of m_cert_chain remains, so the second response
     * disagrees with the size of the chain that the first response gave. */
    case 0x14:
        spdm_response->portion_length = sizeof(m_cert_chain) / 2;
        spdm_response->remainder_length = sizeof(m_cert_chain) / 2;
        cert_chain_length = sizeof(m_cert_chain) / 2;
        break;
    case 0x15:
        break;
    case 0x16:
        /* {ERROR} The Responder is busy. */
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        cert_chain_length = 0;
        break;
    default:
        assert_true(false);
        break;
    }

    libspdm_copy_mem(spdm_response + 1, cert_chain_length, m_cert_chain, cert_chain_length);
    if (spdm_test_context->case_id == 0xB || spdm_test_context->case_id == 0x16) {
        spdm_response_size = sizeof(spdm_message_header_t);
    } else {
        spdm_response_size = sizeof(spdm_certificate_response_t) + cert_chain_length;
    }

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false, spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: The Integrator requests more than 0xFFFF bytes per CERTIFICATE response in an SPDM 1.3
 *         connection. Only SPDM 1.4 can carry that much.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_certificate_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    cert_chain_size = sizeof(cert_chain);
    /* {ERROR} Length does not fit in the Length field of GET_CERTIFICATE. */
    status = libspdm_get_certificate_ex(spdm_context, NULL, 0,
                                        SPDM_MAX_CERTIFICATE_CHAIN_SIZE + 1,
                                        &cert_chain_size, cert_chain, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: The Integrator requests the slot storage size in an SPDM 1.2 connection.
 *         SlotSizeRequested was introduced in SPDM 1.3.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_certificate_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t slot_storage_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;

    /* {ERROR} SPDM 1.2 does not define SlotSizeRequested. */
    status = libspdm_get_slot_storage_size(spdm_context, NULL, 0, &slot_storage_size);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: The Integrator requests the slot storage size from a Responder without SET_CERT_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_certificate_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t slot_storage_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* {ERROR} SET_CERT_CAP is not set. */
    status = libspdm_get_slot_storage_size(spdm_context, NULL, 0, &slot_storage_size);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: The Responder does not support CERT_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_certificate_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);

    /* {ERROR} Responder does not have a certificate. */
    spdm_context->connection_info.capability.flags = 0;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 5: GET_CERTIFICATE is issued in a session that is still in the handshake phase.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_STATE_LOCAL without sending a request.
 **/
static void req_get_certificate_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    /* {ERROR} The session has not been established. */
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_HANDSHAKING);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, &session_id, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);

    libspdm_free_session_id(spdm_context, session_id);
}

/**
 * Test 6: The Requester cannot acquire the sender buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_certificate_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 7: The request is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_certificate_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 8: The transport fails to receive the response.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_get_certificate_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 9: Responder returns DIGESTS instead of CERTIFICATE.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 10: Responder returns SPDMVersion 1.1 in response to a 1.2 request.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    set_standard_state(spdm_context);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 11: Responder returns only the SPDM message header of CERTIFICATE.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_certificate_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    set_standard_state(spdm_context);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 12: The Responder supports LARGE_RESP_CAP in an SPDM 1.4 connection, so the Requester sets
 *          LargeCertChain, but the CERTIFICATE response does not set LargeCertChain.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 13: The Responder does not support LARGE_RESP_CAP in an SPDM 1.4 connection, but the
 *          CERTIFICATE response sets LargeCertChain.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: In an SPDM 1.3 connection where the Responder has multiple asymmetric keys, the
 *          CertModel in the CERTIFICATE response is a reserved value.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    spdm_context->connection_info.multi_key_conn_rsp = false;
}

/**
 * Test 15: In an SPDM 1.3 connection where the Responder does not have multiple asymmetric keys,
 *          the CERTIFICATE response reports a CertModel. DSP0274 requires 0 in that case.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 16: In an SPDM 1.3 connection where the Responder has multiple asymmetric keys, the
 *          CertModel in the CERTIFICATE response differs from the CertModel that the Requester
 *          already recorded for the slot.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.multi_key_conn_rsp = true;
    /* {ERROR} The Responder reported the AliasCert model for slot 0 earlier. */
    spdm_context->connection_info.peer_cert_info[0] = SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    spdm_context->connection_info.multi_key_conn_rsp = false;
    spdm_context->connection_info.peer_cert_info[0] = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
}

/**
 * Test 17: Responder returns a PortionLength larger than the CertChain in the response.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_certificate_err_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    set_standard_state(spdm_context);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 18: Responder returns a RemainderLength that makes the certificate chain larger than the
 *          Offset and Length fields can address.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    set_standard_state(spdm_context);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 19: The first CERTIFICATE response returns half of the certificate chain, and the second
 *          response implies a longer chain than the first one did.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;

    set_standard_state(spdm_context);

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 20: Both endpoints support CHUNK_CAP and the Requester asks for 0xFFFF bytes, the most that
 *          Length can request, but the Responder returns only part of the certificate chain.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_certificate_err_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate_ex(spdm_context, NULL, 0, SPDM_MAX_CERTIFICATE_CHAIN_SIZE,
                                        &cert_chain_size, cert_chain, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 21: The Integrator's verify_peer_spdm_cert_chain function rejects the certificate chain.
 * Expected Behavior: Returns LIBSPDM_STATUS_VERIF_FAIL.
 **/
static void req_get_certificate_err_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;

    set_standard_state(spdm_context);
    /* {ERROR} The Integrator does not accept the certificate chain. */
    spdm_context->local_context.verify_peer_spdm_cert_chain = verify_spdm_cert_chain_fail;

    cert_chain_size = sizeof(cert_chain);
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);

    spdm_context->local_context.verify_peer_spdm_cert_chain = NULL;
}

/**
 * Test 22: While the Integrator requests the slot storage size, the Responder returns an ERROR
 *          message with ErrorCode=Busy to the request and to its one retry.
 * Expected Behavior: Returns LIBSPDM_STATUS_BUSY_PEER.
 **/
static void req_get_certificate_err_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t slot_storage_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
    spdm_context->retry_times = 1;

    status = libspdm_get_slot_storage_size(spdm_context, NULL, 0, &slot_storage_size);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);

    spdm_context->retry_times = 0;
}

int libspdm_req_get_certificate_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_get_certificate_err_case1),
        cmocka_unit_test(req_get_certificate_err_case2),
        cmocka_unit_test(req_get_certificate_err_case3),
        cmocka_unit_test(req_get_certificate_err_case4),
        cmocka_unit_test(req_get_certificate_err_case5),
        cmocka_unit_test(req_get_certificate_err_case6),
        cmocka_unit_test(req_get_certificate_err_case7),
        cmocka_unit_test(req_get_certificate_err_case8),
        cmocka_unit_test(req_get_certificate_err_case9),
        cmocka_unit_test(req_get_certificate_err_case10),
        cmocka_unit_test(req_get_certificate_err_case11),
        cmocka_unit_test(req_get_certificate_err_case12),
        cmocka_unit_test(req_get_certificate_err_case13),
        cmocka_unit_test(req_get_certificate_err_case14),
        cmocka_unit_test(req_get_certificate_err_case15),
        cmocka_unit_test(req_get_certificate_err_case16),
        cmocka_unit_test(req_get_certificate_err_case17),
        cmocka_unit_test(req_get_certificate_err_case18),
        cmocka_unit_test(req_get_certificate_err_case19),
        cmocka_unit_test(req_get_certificate_err_case20),
        cmocka_unit_test(req_get_certificate_err_case21),
        cmocka_unit_test(req_get_certificate_err_case22),
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

#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
