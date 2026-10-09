/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

/* A DataTransferSize, or a transmit buffer size, that is smaller than the default of the tests. */
#define RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE 64

/* A MaxSPDMmsgSize that is smaller than the default of the tests. */
#define RSP_RECEIVE_SEND_ERR_MAX_SPDM_MSG_SIZE 128

static uint8_t m_transport_message[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];

/* The size of the response that rsp_receive_send_err_get_response returns. */
static size_t m_response_size;

static libspdm_return_t rsp_receive_send_err_get_response(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size, void *response)
{
    assert_true(*response_size >= m_response_size);
    *response_size = m_response_size;

    return LIBSPDM_STATUS_SUCCESS;
}

/* Builds the response to a request that libspdm has no handler for. The Integrator's
 * get_response_func answers the request with a response of response_size bytes. Returns the SPDM
 * message that libspdm_build_response builds. */
static const spdm_error_response_t *rsp_receive_send_err_build_response(
    libspdm_context_t *spdm_context, size_t response_size)
{
    libspdm_return_t status;
    spdm_message_header_t spdm_request;
    void *transport_message;
    size_t transport_message_size;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request.request_response_code = 0x00;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_register_get_response_func(spdm_context, rsp_receive_send_err_get_response);
    m_response_size = response_size;

    libspdm_zero_mem(m_transport_message, sizeof(m_transport_message));
    transport_message = m_transport_message;
    transport_message_size = sizeof(m_transport_message);
    status = libspdm_build_response(spdm_context, NULL, false, &transport_message_size,
                                    &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    return (const void *)(m_transport_message +
                          spdm_context->local_context.capability.transport_header_size);
}

static void rsp_receive_send_err_assert_response_too_large(
    const spdm_error_response_t *spdm_response, size_t response_size)
{
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_TOO_LARGE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(libspdm_read_uint32((const uint8_t *)(spdm_response + 1)), response_size);
}

/**
 * Test 1: Both endpoints support chunking, and the response is larger than the MaxSPDMmsgSize of
 * the Requester.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=ResponseTooLarge, and
 * the size of the response in its ExtendedErrorData.
 **/
static void rsp_receive_send_err_case1(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.data_transfer_size =
        RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size =
        RSP_RECEIVE_SEND_ERR_MAX_SPDM_MSG_SIZE;

    spdm_response = rsp_receive_send_err_build_response(
        spdm_context, RSP_RECEIVE_SEND_ERR_MAX_SPDM_MSG_SIZE + 1);

    rsp_receive_send_err_assert_response_too_large(spdm_response,
                                                   RSP_RECEIVE_SEND_ERR_MAX_SPDM_MSG_SIZE + 1);
}

/**
 * Test 2: The Requester does not support chunking, and the response is larger than the transmit
 * buffer of the Responder but not larger than the DataTransferSize of the Requester.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=ResponseTooLarge, and
 * the size of the response in its ExtendedErrorData.
 **/
static void rsp_receive_send_err_case2(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.sender_data_transfer_size =
        RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_DATA_TRANSFER_SIZE;

    spdm_response = rsp_receive_send_err_build_response(
        spdm_context, RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE + 1);

    rsp_receive_send_err_assert_response_too_large(spdm_response,
                                                   RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE + 1);
}

/**
 * Test 3: The Requester supports chunking but the Responder does not, and the response is larger
 * than the DataTransferSize of the Requester but not larger than its MaxSPDMmsgSize.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=ResponseTooLarge, and
 * the size of the response in its ExtendedErrorData.
 **/
static void rsp_receive_send_err_case3(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.data_transfer_size =
        RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    spdm_response = rsp_receive_send_err_build_response(
        spdm_context, RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE + 1);

    rsp_receive_send_err_assert_response_too_large(spdm_response,
                                                   RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE + 1);
}

/**
 * Test 4: The Requester supports chunking but the Responder does not, and the response is larger
 * than the transmit buffer of the Responder but not larger than the DataTransferSize of the
 * Requester.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=ResponseTooLarge, and
 * the size of the response in its ExtendedErrorData.
 **/
static void rsp_receive_send_err_case4(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.sender_data_transfer_size =
        RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE;
    spdm_context->connection_info.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    spdm_response = rsp_receive_send_err_build_response(
        spdm_context, RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE + 1);

    rsp_receive_send_err_assert_response_too_large(spdm_response,
                                                   RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE + 1);
}

/**
 * Test 5: SPDM 1.1, which does not define ErrorCode=ResponseTooLarge, and the response is larger
 * than the transmit buffer of the Responder.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=Unspecified.
 **/
static void rsp_receive_send_err_case5(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.sender_data_transfer_size =
        RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.data_transfer_size = 0;
    spdm_context->connection_info.capability.max_spdm_msg_size = 0;

    spdm_response = rsp_receive_send_err_build_response(
        spdm_context, RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE + 1);

    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 6: Neither endpoint supports chunking, and a response in a session is larger than the
 * transmit buffer of the Responder. libspdm builds the response in the scratch buffer, and then
 * encrypts it into the response buffer, which is the size of the transmit buffer.
 * Expected behavior: the Responder returns an encrypted ERROR message with
 * ErrorCode=ResponseTooLarge, and the size of the response in its ExtendedErrorData.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP and LIBSPDM_ENABLE_CAPABILITY_PSK_CAP are both
 * disabled or LIBSPDM_AEAD_AES_256_GCM_SUPPORT is disabled, as the case runs in a session that
 * uses AES-256-GCM.
 **/
static void rsp_receive_send_err_case6(void **state)
{
#if ((LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)) && \
    (LIBSPDM_AEAD_AES_256_GCM_SUPPORT)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    uint8_t transport_message[RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE +
                              LIBSPDM_TEST_TRANSPORT_HEADER_SIZE +
                              LIBSPDM_TEST_TRANSPORT_TAIL_SIZE];
    void *response;
    size_t response_size;
    uint32_t *decoded_session_id;
    bool is_app_message;
    void *decoded_message;
    size_t decoded_message_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.sender_data_transfer_size =
        RSP_RECEIVE_SEND_ERR_TRANSFER_SIZE;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_DATA_TRANSFER_SIZE;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    secured_message_context = session_info->secured_message_context;
    libspdm_secured_message_set_session_state(secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.request_response_code = 0x00;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);
    spdm_context->last_spdm_request_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;

    libspdm_register_get_response_func(spdm_context, rsp_receive_send_err_get_response);
    /* Even without encryption, the response would not fit in the response buffer. */
    m_response_size = sizeof(transport_message) + 1;

    /* The response buffer is the size of the transmit buffer, as the sender buffer is when
     * libspdm_responder_dispatch_message builds a response without
     * LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP. */
    response = transport_message;
    response_size = sizeof(transport_message);
    status = libspdm_build_response(spdm_context, &session_id, false, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Decrypt the response as the Requester does, with the sequence number of the encryption. */
    secured_message_context->application_secret.response_data_sequence_number = 0;
    decoded_session_id = NULL;
    is_app_message = false;
    decoded_message = m_transport_message;
    decoded_message_size = sizeof(m_transport_message);
    status = spdm_context->transport_decode_message(
        spdm_context, &decoded_session_id, &is_app_message, false, response_size, response,
        &decoded_message_size, &decoded_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(decoded_session_id);

    rsp_receive_send_err_assert_response_too_large(decoded_message, m_response_size);
#else
    skip();
#endif
}

/**
 * Test 7: Both endpoints support Heartbeat, the Requester sends HEARTBEAT, and libspdm is built
 * without a HEARTBEAT handler.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=UnsupportedRequest.
 * Skipped if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP is enabled along with
 * LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP or LIBSPDM_ENABLE_CAPABILITY_PSK_CAP, as libspdm then has a
 * HEARTBEAT handler.
 **/
static void rsp_receive_send_err_case7(void **state)
{
#if !((LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP) && \
    ((LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)))
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_heartbeat_request_t spdm_request;
    void *transport_message;
    size_t transport_message_size;
    const spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_HEARTBEAT;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_zero_mem(m_transport_message, sizeof(m_transport_message));
    transport_message = m_transport_message;
    transport_message_size = sizeof(m_transport_message);
    status = libspdm_build_response(spdm_context, NULL, false, &transport_message_size,
                                    &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (const void *)(m_transport_message +
                                   spdm_context->local_context.capability.transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_HEARTBEAT);
#else
    skip();
#endif
}

int libspdm_rsp_receive_send_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(rsp_receive_send_err_case1, libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(rsp_receive_send_err_case2, libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(rsp_receive_send_err_case3, libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(rsp_receive_send_err_case4, libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(rsp_receive_send_err_case5, libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(rsp_receive_send_err_case6, libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(rsp_receive_send_err_case7, libspdm_unit_test_reset_context),
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
