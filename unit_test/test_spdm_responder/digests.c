/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

spdm_get_digest_request_t m_libspdm_get_digests_request1 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_DIGESTS,
    },
};
size_t m_libspdm_get_digests_request1_size = sizeof(m_libspdm_get_digests_request1);

spdm_get_digest_request_t m_libspdm_get_digests_request2 = {
    {
        SPDM_MESSAGE_VERSION_13,
        SPDM_GET_DIGESTS,
    },
};
size_t m_libspdm_get_digests_request2_size = sizeof(m_libspdm_get_digests_request2);

static uint8_t m_libspdm_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

/**
 * Test 1: receives a valid GET_DIGESTS request message from Requester
 * Expected Behavior: produces a valid DIGESTS response message
 **/
static void rsp_digests_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    /* SupportedSlotMask shall cover the populated slot. */
    spdm_context->local_context.local_supported_slot_mask = 0x01;
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_DIGESTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 2:
 * Expected Behavior:
 **/
static void rsp_digests_case2(void **state)
{
}

/**
 * Test 3: receives a valid GET_DIGESTS request message from Requester, but Responder is not ready to accept the new
 * request message (is busy) and may be able to process the request message if it is sent again in the future
 * Expected Behavior: produces an ERROR response message with error code = Busy
 **/
static void rsp_digests_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    /* SupportedSlotMask shall cover the populated slot. */
    spdm_context->local_context.local_supported_slot_mask = 0x01;
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_BUSY);
}

/**
 * Test 4: receives a valid GET_DIGESTS request message from Requester, but Responder needs the Requester to reissue GET_VERSION to resynchronize
 * Expected Behavior: produces an ERROR response message with error code = RequestResynch
 **/
static void rsp_digests_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    /* SupportedSlotMask shall cover the populated slot. */
    spdm_context->local_context.local_supported_slot_mask = 0x01;
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 5: receives a valid GET_DIGESTS request message from Requester, but Responder cannot produce the response message in time
 * Expected Behavior: produces an ERROR response message with error code = ResponseNotReady
 **/
static void rsp_digests_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    spdm_error_data_response_not_ready_t *error_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    /* SupportedSlotMask shall cover the populated slot. */
    spdm_context->local_context.local_supported_slot_mask = 0x01;
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data = (spdm_error_data_response_not_ready_t *)(spdm_response + 1);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_GET_DIGESTS);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

/**
 * Test 6: receives a valid GET_DIGESTS request message from Requester, but connection_state equals to zero and makes the check fail,
 * meaning that steps GET_CAPABILITIES-CAPABILITIES and NEGOTIATE_ALGORITHMS-ALGORITHMS of the protocol were not previously completed
 * Expected Behavior: produces an ERROR response message with error code = UnexpectedRequest
 **/
static void rsp_digests_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    /* SupportedSlotMask shall cover the populated slot. */
    spdm_context->local_context.local_supported_slot_mask = 0x01;
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 7: receives a valid GET_DIGESTS request message from Requester, but there is no local certificate chain, i.e. there is no digest to send
 * Expected Behavior: produces an ERROR response message with error code = Unspecified
 **/
static void rsp_digests_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        spdm_context->local_context.local_cert_chain_provision[index] = NULL;
        spdm_context->local_context
        .local_cert_chain_provision_size[index] = 0;
    }

    response_size = sizeof(response);
    libspdm_reset_message_b(spdm_context);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 08: receives a valid GET_DIGESTS request message from Requester in a session
 * Expected Behavior: produces a valid DIGESTS response message
 **/
static void rsp_digests_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_DIGESTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 9: receives a valid GET_DIGESTS request message from Requester , set multi_key_conn_rsp to check if it responds correctly
 * Expected Behavior: produces a valid DIGESTS response message
 **/
static void rsp_digests_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    /* SupportedSlotMask shall cover the populated slot. */
    spdm_context->local_context.local_supported_slot_mask = 0x01;
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    /* Sub Case 1: Set multi_key_conn_rsp to true*/
    /* A populated multi-key slot shall report a non-zero CertModel, and slot 0 shall set at
     * least one usage bit. */
    spdm_context->local_context.local_cert_info[0] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    spdm_context->local_context.local_key_usage_bit_mask[0] =
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    spdm_context->connection_info.multi_key_conn_rsp = true;
    libspdm_reset_message_d(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request2_size,
                                          &m_libspdm_get_digests_request2,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) + sizeof(spdm_key_pair_id_t) +
        sizeof(spdm_certificate_info_t) +
        sizeof(spdm_key_usage_bit_mask_t) +
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_DIGESTS);
    assert_int_equal(spdm_context->transcript.message_d.buffer_size,
                     sizeof(spdm_digest_response_t) +
                     sizeof(spdm_key_pair_id_t) +
                     sizeof(spdm_certificate_info_t) +
                     sizeof(spdm_key_usage_bit_mask_t) +
                     libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));

    /* Sub Case 2: Set multi_key_conn_rsp to false*/
    spdm_context->connection_info.multi_key_conn_rsp = false;
    libspdm_reset_message_d(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request2_size,
                                          &m_libspdm_get_digests_request2,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_DIGESTS);
    assert_int_equal(spdm_context->transcript.message_d.buffer_size, 0);
}

/**
 * Test10: a response message is successfully sent ,
 * Check KeyPairID CertificateInfo and KeyUsageMask
 * Expected Behavior: requester returns the status LIBSPDM_STATUS_SUCCESS
 **/
static void rsp_digests_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    uint8_t *digest;
    spdm_key_pair_id_t *key_pair_id;
    spdm_certificate_info_t *cert_info;
    spdm_key_usage_bit_mask_t *key_usage_bit_mask;
    uint32_t hash_size;
    uint8_t slot_count;
    size_t additional_size;

    slot_count = SPDM_MAX_SLOT_COUNT;
    additional_size = sizeof(spdm_key_pair_id_t) + sizeof(spdm_certificate_info_t) +
                      sizeof(spdm_key_usage_bit_mask_t);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0A;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    for (uint8_t index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        spdm_context->local_context.local_cert_chain_provision[index] =
            &m_libspdm_local_certificate_chain[hash_size *index];
        spdm_context->local_context.local_cert_chain_provision_size[index] = hash_size;
        /* A populated multi-key slot shall report a non-zero CertModel. */
        spdm_context->local_context.local_cert_info[index] =
            SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
        /* SupportedSlotMask shall cover every populated slot. */
        spdm_context->local_context.local_supported_slot_mask |= (uint8_t)(1 << index);
    }
    /* Slot 0 shall set at least one usage bit. */
    spdm_context->local_context.local_key_usage_bit_mask[0] =
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;

    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    spdm_context->connection_info.multi_key_conn_rsp = true;
    libspdm_reset_message_d(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request2_size,
                                          &m_libspdm_get_digests_request2,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_digest_response_t) +
                     (hash_size + additional_size) *
                     slot_count);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_DIGESTS);
    assert_int_equal(spdm_context->transcript.message_d.buffer_size,
                     sizeof(spdm_digest_response_t) + (hash_size + additional_size) * slot_count);

    digest = (void *)(spdm_response + 1);
    libspdm_zero_mem (digest, hash_size * slot_count);
    key_pair_id = (spdm_key_pair_id_t *)((uint8_t *)digest + (hash_size * slot_count));
    cert_info = (spdm_certificate_info_t *)((uint8_t *)key_pair_id +
                                            sizeof(spdm_key_pair_id_t) * slot_count);
    key_usage_bit_mask = (spdm_key_usage_bit_mask_t *)((uint8_t *)cert_info +
                                                       sizeof(spdm_certificate_info_t) *
                                                       slot_count);
    for (uint8_t index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        assert_memory_equal((void *)&key_pair_id[index],
                            (void *)&spdm_context->local_context.local_key_pair_id[index],
                            sizeof(spdm_key_pair_id_t));
        assert_memory_equal((void *)&cert_info[index],
                            (void *)&spdm_context->local_context.local_cert_info[index],
                            sizeof(spdm_certificate_info_t));
        assert_memory_equal((void *)&key_usage_bit_mask[index],
                            (void *)&spdm_context->local_context.local_key_usage_bit_mask[index],
                            sizeof(spdm_key_usage_bit_mask_t));
    }
}

/**
 * Test 11: GET_DIGESTS is sent when at least one certificate slot is in the reset state.
 * Expected Behavior: Responder responds with ResetRequired.
 **/
static void rsp_digests_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0B;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    /* Responder needs to be reset before DIGESTS can be successful. */
    spdm_context->local_context.cert_slot_reset_mask = 0x1a;

    spdm_context->connection_info.multi_key_conn_rsp = true;
    libspdm_reset_message_d(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request2_size,
                                          &m_libspdm_get_digests_request2,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);
}

/* Group setup runs once per group, so clear any per-slot state a prior case populated. */
static void rsp_digests_reset_slot_context(libspdm_context_t *spdm_context)
{
    uint8_t index;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        spdm_context->local_context.local_cert_chain_provision[index] = NULL;
        spdm_context->local_context.local_cert_chain_provision_size[index] = 0;
        spdm_context->local_context.local_key_pair_id[index] = 0;
        spdm_context->local_context.local_key_usage_bit_mask[index] = 0;
        spdm_context->local_context.local_cert_info[index] = 0;
    }
    spdm_context->local_context.local_supported_slot_mask = 0;
    spdm_context->local_context.cert_slot_reset_mask = 0;
}

/* Provision a populated slot with a cert chain and mark it supported. */
static void rsp_digests_provision_slot(libspdm_context_t *spdm_context, uint8_t index)
{
    spdm_context->local_context.local_cert_chain_provision[index] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[index] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain), (uint8_t)(0xFF));
    spdm_context->local_context.local_supported_slot_mask |= (uint8_t)(1 << index);
}

/**
 * Test 12: multi-key connection with per-slot values that are all consistent with KEY_PAIR_INFO:
 * slot 0 uses key pair 1 (whose AssocCertSlotMask includes slot 0), the reported KeyUsageMask
 * matches the key pair CurrentKeyUsage, and slot 0 is in SupportedSlotMask.
 * Expected Behavior: both checkers report success.
 **/
static void rsp_digests_case12(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0C;
    rsp_digests_reset_slot_context(spdm_context);
    /* Key pair 1 (mask 0x03) claims slots 0 and 1; its CurrentKeyUsage is KEY_EX_USE. Provision
     * both claimed slots so the mapping is consistent in both directions. */
    rsp_digests_provision_slot(spdm_context, 0);
    rsp_digests_provision_slot(spdm_context, 1);
    spdm_context->local_context.local_key_pair_id[0] = 1;
    spdm_context->local_context.local_key_pair_id[1] = 1;
    spdm_context->local_context.local_key_usage_bit_mask[0] = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    spdm_context->local_context.local_key_usage_bit_mask[1] = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    spdm_context->local_context.local_cert_info[0] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    spdm_context->local_context.local_cert_info[1] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    assert_int_equal(libspdm_validate_supported_slot_mask(spdm_context),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(libspdm_validate_multi_key_slot_info(spdm_context),
                     LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 13: a populated slot is not indicated in SupportedSlotMask.
 * Expected Behavior: the supported-slot-mask checker reports an error.
 **/
static void rsp_digests_case13(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0D;
    rsp_digests_reset_slot_context(spdm_context);
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    /* Slot 0 is populated but only slot 1 is marked supported. */
    spdm_context->local_context.local_supported_slot_mask = 0x02;

    assert_true(LIBSPDM_STATUS_IS_ERROR(libspdm_validate_supported_slot_mask(spdm_context)));
}

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
/**
 * Test 14: the KeyPairID reported for a slot does not claim that slot in its AssocCertSlotMask.
 * Expected Behavior: the multi-key slot-info checker reports an error.
 **/
static void rsp_digests_case14(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0E;
    rsp_digests_reset_slot_context(spdm_context);
    /* Populate slot 2, which key pair 1 (mask 0x03) does not claim. */
    rsp_digests_provision_slot(spdm_context, 2);
    spdm_context->local_context.local_key_pair_id[2] = 1;
    spdm_context->local_context.local_cert_info[2] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    assert_true(LIBSPDM_STATUS_IS_ERROR(libspdm_validate_multi_key_slot_info(spdm_context)));
}

/**
 * Test 15: the KeyUsageMask reported for a slot does not match the key pair CurrentKeyUsage.
 * Expected Behavior: the multi-key slot-info checker reports an error.
 **/
static void rsp_digests_case15(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0F;
    rsp_digests_reset_slot_context(spdm_context);
    /* Key pair 1 (mask 0x03) claims slots 0 and 1 with CurrentKeyUsage KEY_EX_USE. Provision both
     * consistently except slot 0's KeyUsageMask, so only the usage mismatch is exercised. */
    rsp_digests_provision_slot(spdm_context, 0);
    rsp_digests_provision_slot(spdm_context, 1);
    spdm_context->local_context.local_key_pair_id[0] = 1;
    spdm_context->local_context.local_key_pair_id[1] = 1;
    spdm_context->local_context.local_key_usage_bit_mask[0] =
        SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE;
    spdm_context->local_context.local_key_usage_bit_mask[1] =
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    spdm_context->local_context.local_cert_info[0] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    spdm_context->local_context.local_cert_info[1] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    assert_true(LIBSPDM_STATUS_IS_ERROR(libspdm_validate_multi_key_slot_info(spdm_context)));
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */

/* Provision a single populated slot for a multi-key connection with the given CertificateInfo,
 * then run the multi-key slot-info checker and return its status. */
static libspdm_return_t rsp_digests_run_cert_info_case(void **state, uint8_t case_id,
                                                       uint8_t index, uint8_t cert_info)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = case_id;
    rsp_digests_reset_slot_context(spdm_context);
    rsp_digests_provision_slot(spdm_context, index);
    /* Leave local_key_pair_id at 0 so the CertificateInfo check is exercised in isolation. */
    spdm_context->local_context.local_cert_info[index] = cert_info;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    return libspdm_validate_multi_key_slot_info(spdm_context);
}

/* Provision a single populated slot for a multi-key connection with a valid CertModel and the
 * given KeyUsageMask, then run the multi-key slot-info checker and return its status. */
static libspdm_return_t rsp_digests_run_key_usage_case(void **state, uint8_t case_id,
                                                       uint8_t index,
                                                       spdm_key_usage_bit_mask_t key_usage)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = case_id;
    rsp_digests_reset_slot_context(spdm_context);
    rsp_digests_provision_slot(spdm_context, index);
    /* Leave local_key_pair_id at 0 so the KeyUsageMask check is exercised in isolation. */
    spdm_context->local_context.local_cert_info[index] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    spdm_context->local_context.local_key_usage_bit_mask[index] = key_usage;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    return libspdm_validate_multi_key_slot_info(spdm_context);
}

/**
 * Test 16: a populated multi-key slot reports CertModel zero.
 * Expected Behavior: the checker reports an error.
 **/
static void rsp_digests_case16(void **state)
{
    assert_true(LIBSPDM_STATUS_IS_ERROR(rsp_digests_run_cert_info_case(
                                            state, 0x10, 0,
                                            SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE)));
}

/**
 * Test 17: CertificateInfo has reserved bits set.
 * Expected Behavior: the checker reports an error.
 **/
static void rsp_digests_case17(void **state)
{
    assert_true(LIBSPDM_STATUS_IS_ERROR(rsp_digests_run_cert_info_case(
                                            state, 0x11, 0,
                                            (uint8_t)(SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT |
                                                      0x08))));
}

/**
 * Test 18: CertModel is a reserved value (greater than GenericCert).
 * Expected Behavior: the checker reports an error.
 **/
static void rsp_digests_case18(void **state)
{
    assert_true(LIBSPDM_STATUS_IS_ERROR(rsp_digests_run_cert_info_case(
                                            state, 0x12, 0,
                                            (uint8_t)(SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT +
                                                      1))));
}

/**
 * Test 19: slot 0 uses the GenericCert model, which is only valid for slots greater than 0.
 * Expected Behavior: the checker reports an error.
 **/
static void rsp_digests_case19(void **state)
{
    assert_true(LIBSPDM_STATUS_IS_ERROR(rsp_digests_run_cert_info_case(
                                            state, 0x13, 0,
                                            SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT)));
}

/**
 * Test 20: GenericCert model in a slot greater than 0 is accepted.
 * Expected Behavior: the checker reports success.
 **/
static void rsp_digests_case20(void **state)
{
    assert_int_equal(rsp_digests_run_cert_info_case(
                         state, 0x14, 1, SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT),
                     LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 21: KeyUsageMask has reserved bits set.
 * Expected Behavior: the checker reports an error.
 **/
static void rsp_digests_case21(void **state)
{
    assert_true(LIBSPDM_STATUS_IS_ERROR(rsp_digests_run_key_usage_case(
                                            state, 0x15, 0,
                                            (spdm_key_usage_bit_mask_t)(
                                                SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE | 0x0010))));
}

/**
 * Test 22: slot 0 KeyUsageMask sets none of KeyEx/Challenge/Measurement/EndpointInfo use.
 * Expected Behavior: the checker reports an error.
 **/
static void rsp_digests_case22(void **state)
{
    assert_true(LIBSPDM_STATUS_IS_ERROR(rsp_digests_run_key_usage_case(
                                            state, 0x16, 0,
                                            SPDM_KEY_USAGE_BIT_MASK_VENDOR_KEY_USE)));
}

/**
 * Test 23: slot greater than 0 may set only VendorKeyUse (the slot-0 usage rule does not apply).
 * Expected Behavior: the checker reports success.
 **/
static void rsp_digests_case23(void **state)
{
    assert_int_equal(rsp_digests_run_key_usage_case(
                         state, 0x17, 1, SPDM_KEY_USAGE_BIT_MASK_VENDOR_KEY_USE),
                     LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 24: a slot uses the AliasCert model but the Responder does not set ALIAS_CERT_CAP.
 * Expected Behavior: the checker reports an error.
 **/
static void rsp_digests_case24(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    rsp_digests_reset_slot_context(spdm_context);
    rsp_digests_provision_slot(spdm_context, 0);
    /* ALIAS_CERT_CAP is not set, so an AliasCert slot is a misconfiguration. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->local_context.local_cert_info[0] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
    spdm_context->local_context.local_key_usage_bit_mask[0] =
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    assert_true(LIBSPDM_STATUS_IS_ERROR(libspdm_validate_multi_key_slot_info(spdm_context)));
}

/**
 * Test 25: a slot uses the AliasCert model and the Responder sets ALIAS_CERT_CAP.
 * Expected Behavior: the checker reports success.
 **/
static void rsp_digests_case25(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    rsp_digests_reset_slot_context(spdm_context);
    rsp_digests_provision_slot(spdm_context, 0);
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->local_context.local_cert_info[0] =
        SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
    spdm_context->local_context.local_key_usage_bit_mask[0] =
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    assert_int_equal(libspdm_validate_multi_key_slot_info(spdm_context),
                     LIBSPDM_STATUS_SUCCESS);
}

int libspdm_rsp_digests_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Success Case*/
        cmocka_unit_test(rsp_digests_case1),
        /* Can be populated with new test.*/
        cmocka_unit_test(rsp_digests_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(rsp_digests_case3),
        /* response_state: LIBSPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(rsp_digests_case4),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* response_state: LIBSPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(rsp_digests_case5),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* connection_state Check*/
        cmocka_unit_test(rsp_digests_case6),
        /* No digest to send*/
        cmocka_unit_test(rsp_digests_case7),
        /* Success Case in a session*/
        cmocka_unit_test(rsp_digests_case8),
        /* Set multi_key_conn_rsp to check if it responds correctly */
        cmocka_unit_test(rsp_digests_case9),
        /* Check KeyPairID CertificateInfo and KeyUsageMask*/
        cmocka_unit_test(rsp_digests_case10),
        cmocka_unit_test(rsp_digests_case11),
        /* Multi-key: all per-slot values consistent with KEY_PAIR_INFO */
        cmocka_unit_test(rsp_digests_case12),
        /* Populated slot missing from SupportedSlotMask */
        cmocka_unit_test(rsp_digests_case13),
#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
        /* KeyPairID does not claim the slot in AssocCertSlotMask */
        cmocka_unit_test(rsp_digests_case14),
        /* KeyUsageMask does not match key pair CurrentKeyUsage */
        cmocka_unit_test(rsp_digests_case15),
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */
        /* Populated multi-key slot reports CertModel zero */
        cmocka_unit_test(rsp_digests_case16),
        /* CertificateInfo reserved bits set */
        cmocka_unit_test(rsp_digests_case17),
        /* CertModel is a reserved value */
        cmocka_unit_test(rsp_digests_case18),
        /* Slot 0 uses the GenericCert model */
        cmocka_unit_test(rsp_digests_case19),
        /* GenericCert model in a slot greater than 0 is accepted */
        cmocka_unit_test(rsp_digests_case20),
        /* KeyUsageMask reserved bits set */
        cmocka_unit_test(rsp_digests_case21),
        /* Slot 0 KeyUsageMask sets no applicable usage bit */
        cmocka_unit_test(rsp_digests_case22),
        /* Slot greater than 0 may set only VendorKeyUse */
        cmocka_unit_test(rsp_digests_case23),
        /* AliasCert model without ALIAS_CERT_CAP */
        cmocka_unit_test(rsp_digests_case24),
        /* AliasCert model with ALIAS_CERT_CAP */
        cmocka_unit_test(rsp_digests_case25),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
