/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

/* The encapsulated request that the Responder sends. libspdm has no handler of its own for it. */
#define ENCAP_REQUEST_CODE SPDM_VENDOR_DEFINED_REQUEST

static uint32_t m_session_id = 0xFFFFFFFF;

/* The code of the last request, and whether it was a secured message. The Responder answers in
 * kind. */
static uint8_t m_last_request_code;
static bool m_last_request_secured;

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.multi_key_conn_req = false;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    libspdm_register_get_encap_response_func(spdm_context, NULL);
}

#if !(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP)
/* Adds an established session to the standard state. */
static void set_session_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
}
#endif /* !(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP) */

/* Fails to process the encapsulated request. */
static libspdm_return_t get_encap_response_fail(void *spdm_context, size_t spdm_request_size,
                                                void *spdm_request, size_t *spdm_response_size,
                                                void *spdm_response)
{
    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
}

/* Answers the encapsulated request, and then makes the next acquisition of the receiver buffer
 * fail. */
static libspdm_return_t get_encap_response_fail_receiver_buffer(
    void *spdm_context, size_t spdm_request_size, void *spdm_request,
    size_t *spdm_response_size, void *spdm_response)
{
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    return libspdm_generate_encap_error_response(
        spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, ENCAP_REQUEST_CODE,
        spdm_response_size, spdm_response);
}

/* Answers the encapsulated request, and then makes the next acquisition of the sender buffer
 * fail. */
static libspdm_return_t get_encap_response_fail_sender_buffer(
    void *spdm_context, size_t spdm_request_size, void *spdm_request,
    size_t *spdm_response_size, void *spdm_response)
{
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    return libspdm_generate_encap_error_response(
        spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, ENCAP_REQUEST_CODE,
        spdm_response_size, spdm_response);
}

/* Writes an ERROR message with ErrorCode=ResponseNotReady for request_code, and returns its
 * size. */
static size_t write_not_ready_response(void *spdm_response, uint8_t spdm_version,
                                       uint8_t request_code)
{
    spdm_error_response_t *spdm_error;
    spdm_error_data_response_not_ready_t *not_ready;

    spdm_error = spdm_response;
    spdm_error->header.spdm_version = spdm_version;
    spdm_error->header.request_response_code = SPDM_ERROR;
    spdm_error->header.param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    spdm_error->header.param2 = 0;
    not_ready = (void *)(spdm_error + 1);
    not_ready->rd_exponent = 1;
    not_ready->request_code = request_code;
    not_ready->token = 0;
    not_ready->rd_tm = 2;

    return sizeof(spdm_error_response_t) + sizeof(spdm_error_data_response_not_ready_t);
}

/* Decodes a secured request and returns its SPDM message. */
static const spdm_message_header_t *decode_secured_request(void *spdm_context,
                                                           size_t request_size,
                                                           const void *request)
{
    static uint8_t transport_message[LIBSPDM_SENDER_BUFFER_SIZE];
    static uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t *message_session_id;
    bool is_app_message;
    void *message;
    size_t message_size;
    libspdm_return_t status;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, m_session_id);
    assert_non_null(session_info);
    /* Workaround: Use single context to encode message and then decode message. */
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->
    application_secret.request_data_sequence_number--;

    libspdm_copy_mem(transport_message, sizeof(transport_message), request, request_size);
    message = message_buffer;
    message_size = sizeof(message_buffer);
    status = libspdm_transport_test_decode_message(spdm_context, &message_session_id,
                                                   &is_app_message, true, request_size,
                                                   transport_message, &message_size, &message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    return message;
}

/* Encodes a secured response. The secured message is written where spdm_response is, so the
 * plaintext is first copied to the scratch buffer. */
static void encode_secured_response(void *spdm_context, size_t spdm_response_size,
                                    const void *spdm_response, size_t *response_size,
                                    void **response)
{
    libspdm_session_info_t *session_info;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t *message;

    libspdm_get_scratch_buffer(spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
    message = scratch_buffer + LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    libspdm_copy_mem(message, scratch_buffer_size - LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                     spdm_response, spdm_response_size);
    libspdm_transport_test_encode_message(spdm_context, &m_session_id, false, false,
                                          spdm_response_size, message, response_size, response);

    session_info = libspdm_get_session_info_via_session_id(spdm_context, m_session_id);
    assert_non_null(session_info);
    /* Workaround: Use single context to encode message and then decode message. */
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->
    application_secret.response_data_sequence_number--;
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    const spdm_message_header_t *spdm_request;

    m_last_request_secured = (((const libspdm_test_message_header_t *)request)->message_type ==
                              LIBSPDM_TEST_MESSAGE_TYPE_SECURED_TEST);
    if (m_last_request_secured) {
        spdm_request = decode_secured_request(spdm_context, request_size, request);
    } else {
        spdm_request = (const void *)((const uint8_t *)request +
                                      sizeof(libspdm_test_message_header_t));
    }
    m_last_request_code = spdm_request->request_response_code;

    spdm_test_context = libspdm_get_test_context();
    if ((spdm_test_context->case_id == 0x8) &&
        (m_last_request_code == SPDM_DELIVER_ENCAPSULATED_RESPONSE)) {
        /* {ERROR} The transport fails to send DELIVER_ENCAPSULATED_RESPONSE. */
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/* Answers GET_ENCAPSULATED_REQUEST with an ENCAPSULATED_REQUEST that carries a request with ID 1,
 * and DELIVER_ENCAPSULATED_RESPONSE with an ENCAPSULATED_RESPONSE_ACK that carries no request.
 * Each test case alters one of these responses. */
static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *spdm_encapsulated_request_response;
    spdm_encapsulated_response_ack_response_t *spdm_encapsulated_response_ack_response;
    spdm_message_header_t *encapsulated_request;
    uint8_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    uint8_t spdm_version;

    spdm_test_context = libspdm_get_test_context();
    spdm_version = libspdm_get_connection_version(spdm_context);

    transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (uint8_t *)*response + transport_header_size;

    if (m_last_request_code == SPDM_GET_ENCAPSULATED_REQUEST) {
        spdm_encapsulated_request_response = (void *)spdm_response;
        spdm_encapsulated_request_response->header.spdm_version = spdm_version;
        spdm_encapsulated_request_response->header.request_response_code =
            SPDM_ENCAPSULATED_REQUEST;
        spdm_encapsulated_request_response->header.param1 = 1;
        spdm_encapsulated_request_response->header.param2 = 0;
        encapsulated_request = (void *)(spdm_encapsulated_request_response + 1);
        encapsulated_request->spdm_version = spdm_version;
        encapsulated_request->request_response_code = ENCAP_REQUEST_CODE;
        encapsulated_request->param1 = 0;
        encapsulated_request->param2 = 0;
        spdm_response_size = sizeof(spdm_encapsulated_request_response_t) +
                             sizeof(spdm_message_header_t);

        switch (spdm_test_context->case_id) {
        case 0x4:
            /* {ERROR} The transport fails to receive ENCAPSULATED_REQUEST. */
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        case 0x5:
            /* {ERROR} SPDMVersion does not match the request. */
            spdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
            break;
        case 0x6:
            /* {ERROR} The response code does not match the request. */
            spdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            break;
        case 0x13:
            /* {ERROR} The Responder is not ready. */
            spdm_response_size = write_not_ready_response(spdm_response, spdm_version,
                                                          SPDM_GET_ENCAPSULATED_REQUEST);
            break;
        case 0x15:
            /* {ERROR} The ERROR message ends before Param1. */
            spdm_encapsulated_request_response->header.request_response_code = SPDM_ERROR;
            spdm_response_size = offsetof(spdm_message_header_t, param1);
            break;
        default:
            break;
        }
    } else {
        assert_int_equal(m_last_request_code, SPDM_DELIVER_ENCAPSULATED_RESPONSE);

        spdm_encapsulated_response_ack_response = (void *)spdm_response;
        spdm_encapsulated_response_ack_response->header.spdm_version = spdm_version;
        spdm_encapsulated_response_ack_response->header.request_response_code =
            SPDM_ENCAPSULATED_RESPONSE_ACK;
        spdm_encapsulated_response_ack_response->header.param1 = 2;
        spdm_encapsulated_response_ack_response->header.param2 =
            SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
        spdm_encapsulated_response_ack_response->ack_request_id = 1;
        libspdm_zero_mem(spdm_encapsulated_response_ack_response->reserved,
                         sizeof(spdm_encapsulated_response_ack_response->reserved));
        spdm_response_size = sizeof(spdm_encapsulated_response_ack_response_t);

        switch (spdm_test_context->case_id) {
        case 0xA:
            /* {ERROR} The transport fails to receive ENCAPSULATED_RESPONSE_ACK. */
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        case 0xB:
            /* {ERROR} SPDMVersion does not match the request. */
            spdm_encapsulated_response_ack_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_12;
            break;
        case 0xC:
            /* {ERROR} The response ends before AckRequestID. */
            spdm_response_size = sizeof(spdm_message_header_t);
            break;
        case 0xD:
            /* {ERROR} AckRequestID does not match the request ID of the encapsulated request. */
            spdm_encapsulated_response_ack_response->ack_request_id = 2;
            break;
        case 0xE:
        /* {ERROR} Slot 8 does not exist. */
        case 0xF:
            spdm_encapsulated_response_ack_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER;
            *(uint8_t *)(spdm_encapsulated_response_ack_response + 1) =
                (spdm_test_context->case_id == 0xE) ? SPDM_MAX_SLOT_COUNT : 1;
            spdm_response_size = sizeof(spdm_encapsulated_response_ack_response_t) +
                                 sizeof(uint8_t);
            break;
        case 0x10:
            /* {ERROR} The slot number is missing. */
            spdm_encapsulated_response_ack_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER;
            break;
        case 0x11:
            /* {ERROR} Reserved payload type. */
            spdm_encapsulated_response_ack_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER + 1;
            break;
        case 0x12:
            /* The ACK carries another encapsulated request. */
            spdm_encapsulated_response_ack_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT;
            encapsulated_request = (void *)(spdm_encapsulated_response_ack_response + 1);
            encapsulated_request->spdm_version = spdm_version;
            encapsulated_request->request_response_code = ENCAP_REQUEST_CODE;
            encapsulated_request->param1 = 0;
            encapsulated_request->param2 = 0;
            spdm_response_size = sizeof(spdm_encapsulated_response_ack_response_t) +
                                 sizeof(spdm_message_header_t);
            break;
        case 0x14:
            /* {ERROR} The Responder is not ready. */
            spdm_response_size = write_not_ready_response(spdm_response, spdm_version,
                                                          SPDM_DELIVER_ENCAPSULATED_RESPONSE);
            break;
        case 0x16:
            /* {ERROR} The ERROR message ends before Param1. */
            spdm_encapsulated_response_ack_response->header.request_response_code = SPDM_ERROR;
            spdm_response_size = offsetof(spdm_message_header_t, param1);
            break;
        default:
            break;
        }
    }

    if (m_last_request_secured) {
        encode_secured_response(spdm_context, spdm_response_size, spdm_response, response_size,
                                response);
    } else {
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              spdm_response_size, spdm_response, response_size,
                                              response);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: The Responder does not support ENCAP_CAP.
 * Expected Behavior: Returns LIBSPDM_STATUS_UNSUPPORTED_CAP without sending a request.
 **/
static void req_get_encapsulated_request_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    /* {ERROR} Responder does not support encapsulated requests. */
    spdm_context->connection_info.capability.flags = 0;

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: The Requester cannot acquire the sender buffer for GET_ENCAPSULATED_REQUEST.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_encapsulated_request_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the sender buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 3: GET_ENCAPSULATED_REQUEST is sent but the Requester cannot acquire the receiver buffer.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_encapsulated_request_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    set_standard_state(spdm_context);

    /* {ERROR} Acquiring the receiver buffer fails. */
    libspdm_force_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 4: The transport fails to receive ENCAPSULATED_REQUEST.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_get_encapsulated_request_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 5: Responder returns ENCAPSULATED_REQUEST with SPDMVersion 1.2 in response to a 1.3
 *         GET_ENCAPSULATED_REQUEST.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_encapsulated_request_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 6: Responder returns ENCAPSULATED_RESPONSE_ACK in response to GET_ENCAPSULATED_REQUEST.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_encapsulated_request_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 7: The Integrator's handler for the encapsulated request returns an error.
 * Expected Behavior: Returns the handler's status without sending DELIVER_ENCAPSULATED_RESPONSE.
 **/
static void req_get_encapsulated_request_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    set_standard_state(spdm_context);

    /* {ERROR} The handler fails. */
    libspdm_register_get_encap_response_func(spdm_context, get_encap_response_fail);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    assert_int_equal(m_last_request_code, SPDM_GET_ENCAPSULATED_REQUEST);

    libspdm_register_get_encap_response_func(spdm_context, NULL);
}

/**
 * Test 8: The transport fails to send DELIVER_ENCAPSULATED_RESPONSE.
 * Expected Behavior: Returns LIBSPDM_STATUS_SEND_FAIL.
 **/
static void req_get_encapsulated_request_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 9: DELIVER_ENCAPSULATED_RESPONSE is sent but the Requester cannot acquire the receiver
 *         buffer for ENCAPSULATED_RESPONSE_ACK.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_encapsulated_request_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    set_standard_state(spdm_context);

    /* {ERROR} The handler makes the next acquisition of the receiver buffer fail. */
    libspdm_register_get_encap_response_func(spdm_context,
                                             get_encap_response_fail_receiver_buffer);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
    assert_int_equal(m_last_request_code, SPDM_DELIVER_ENCAPSULATED_RESPONSE);

    libspdm_register_get_encap_response_func(spdm_context, NULL);
}

/**
 * Test 10: The transport fails to receive ENCAPSULATED_RESPONSE_ACK.
 * Expected Behavior: Returns LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_get_encapsulated_request_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 11: Responder returns ENCAPSULATED_RESPONSE_ACK with SPDMVersion 1.2 in response to a 1.3
 *          DELIVER_ENCAPSULATED_RESPONSE.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_encapsulated_request_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 12: Responder returns only the SPDM message header of ENCAPSULATED_RESPONSE_ACK, which
 *          since SPDM 1.2 also carries AckRequestID.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_encapsulated_request_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 13: Responder returns an AckRequestID that differs from the request ID of the encapsulated
 *          request.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_encapsulated_request_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: ENCAPSULATED_RESPONSE_ACK reports slot 8 for the Requester's key. DSP0274 limits slots
 *          to 0 through 7.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_encapsulated_request_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t req_slot_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    set_standard_state(spdm_context);

    req_slot_id = 0;
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, &req_slot_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 15: In an SPDM 1.3 connection where the Requester has multiple asymmetric keys,
 *          ENCAPSULATED_RESPONSE_ACK reports a slot whose key the Requester does not allow for key
 *          exchange.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_encapsulated_request_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t req_slot_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    set_standard_state(spdm_context);
    spdm_context->connection_info.multi_key_conn_req = true;
    /* {ERROR} The key in slot 1 cannot be used for key exchange. */
    spdm_context->local_context.local_key_usage_bit_mask[1] =
        SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE;

    req_slot_id = 0;
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, &req_slot_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    spdm_context->connection_info.multi_key_conn_req = false;
    spdm_context->local_context.local_key_usage_bit_mask[1] = 0;
}

/**
 * Test 16: ENCAPSULATED_RESPONSE_ACK reports that it carries the Requester's slot number, but the
 *          slot number is missing.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_encapsulated_request_err_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t req_slot_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    set_standard_state(spdm_context);

    req_slot_id = 0;
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, &req_slot_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 17: ENCAPSULATED_RESPONSE_ACK has a reserved payload type.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_encapsulated_request_err_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 18: ENCAPSULATED_RESPONSE_ACK carries another encapsulated request, but the Requester
 *          cannot acquire the sender buffer to answer it.
 * Expected Behavior: Returns LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void req_get_encapsulated_request_err_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    set_standard_state(spdm_context);

    /* {ERROR} The handler makes the next acquisition of the sender buffer fail. */
    libspdm_register_get_encap_response_func(spdm_context,
                                             get_encap_response_fail_sender_buffer);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    libspdm_release_error(LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
    assert_int_equal(m_last_request_code, SPDM_DELIVER_ENCAPSULATED_RESPONSE);

    libspdm_register_get_encap_response_func(spdm_context, NULL);
}

/**
 * Test 19: The Responder returns an ERROR message with ErrorCode=ResponseNotReady to
 *          GET_ENCAPSULATED_REQUEST, and RESPOND_IF_READY support is compiled out.
 * Expected Behavior: Returns LIBSPDM_STATUS_NOT_READY_PEER.
 *                    Skipped when RESPOND_IF_READY support is compiled in.
 **/
static void req_get_encapsulated_request_err_case19(void **state)
{
    #if !(LIBSPDM_RESPOND_IF_READY_SUPPORT)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    assert_int_equal(m_last_request_code, SPDM_GET_ENCAPSULATED_REQUEST);
    #else
    skip();
    #endif /* !(LIBSPDM_RESPOND_IF_READY_SUPPORT) */
}

/**
 * Test 20: The Responder returns an ERROR message with ErrorCode=ResponseNotReady to
 *          DELIVER_ENCAPSULATED_RESPONSE, and RESPOND_IF_READY support is compiled out.
 * Expected Behavior: Returns LIBSPDM_STATUS_NOT_READY_PEER.
 *                    Skipped when RESPOND_IF_READY support is compiled in.
 **/
static void req_get_encapsulated_request_err_case20(void **state)
{
    #if !(LIBSPDM_RESPOND_IF_READY_SUPPORT)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;

    set_standard_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    assert_int_equal(m_last_request_code, SPDM_DELIVER_ENCAPSULATED_RESPONSE);
    #else
    skip();
    #endif /* !(LIBSPDM_RESPOND_IF_READY_SUPPORT) */
}

/**
 * Test 21: In a session, the Responder returns an ERROR message to GET_ENCAPSULATED_REQUEST that
 *          ends before Param1. Outside a session the test transport pads messages to four bytes.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 *                    Skipped when CHUNK_CAP support is compiled in, as libspdm then rejects the
 *                    message before libspdm_encapsulated_request processes it.
 **/
static void req_get_encapsulated_request_err_case21(void **state)
{
    #if !(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;

    set_session_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, &m_session_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    assert_int_equal(m_last_request_code, SPDM_GET_ENCAPSULATED_REQUEST);
    #else
    skip();
    #endif /* !(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP) */
}

/**
 * Test 22: In a session, the Responder returns an ERROR message to DELIVER_ENCAPSULATED_RESPONSE
 *          that ends before Param1. Outside a session the test transport pads messages to four
 *          bytes.
 * Expected Behavior: Returns LIBSPDM_STATUS_INVALID_MSG_SIZE.
 *                    Skipped when CHUNK_CAP support is compiled in, as libspdm then rejects the
 *                    message before libspdm_encapsulated_request processes it.
 **/
static void req_get_encapsulated_request_err_case22(void **state)
{
    #if !(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;

    set_session_state(spdm_context);

    status = libspdm_send_receive_encap_request(spdm_context, &m_session_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    assert_int_equal(m_last_request_code, SPDM_DELIVER_ENCAPSULATED_RESPONSE);
    #else
    skip();
    #endif /* !(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP) */
}

int libspdm_req_get_encapsulated_request_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_get_encapsulated_request_err_case1),
        cmocka_unit_test(req_get_encapsulated_request_err_case2),
        cmocka_unit_test(req_get_encapsulated_request_err_case3),
        cmocka_unit_test(req_get_encapsulated_request_err_case4),
        cmocka_unit_test(req_get_encapsulated_request_err_case5),
        cmocka_unit_test(req_get_encapsulated_request_err_case6),
        cmocka_unit_test(req_get_encapsulated_request_err_case7),
        cmocka_unit_test(req_get_encapsulated_request_err_case8),
        cmocka_unit_test(req_get_encapsulated_request_err_case9),
        cmocka_unit_test(req_get_encapsulated_request_err_case10),
        cmocka_unit_test(req_get_encapsulated_request_err_case11),
        cmocka_unit_test(req_get_encapsulated_request_err_case12),
        cmocka_unit_test(req_get_encapsulated_request_err_case13),
        cmocka_unit_test(req_get_encapsulated_request_err_case14),
        cmocka_unit_test(req_get_encapsulated_request_err_case15),
        cmocka_unit_test(req_get_encapsulated_request_err_case16),
        cmocka_unit_test(req_get_encapsulated_request_err_case17),
        cmocka_unit_test(req_get_encapsulated_request_err_case18),
        cmocka_unit_test(req_get_encapsulated_request_err_case19),
        cmocka_unit_test(req_get_encapsulated_request_err_case20),
        cmocka_unit_test(req_get_encapsulated_request_err_case21),
        cmocka_unit_test(req_get_encapsulated_request_err_case22),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
