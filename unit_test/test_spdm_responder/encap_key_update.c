/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

static void libspdm_set_standard_key_update_test_state(libspdm_context_t *spdm_context,
                                                       uint32_t *session_id)
{
    libspdm_session_info_t *session_info;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    *session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = *session_id;
    spdm_context->last_spdm_request_session_id = *session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
}

static void libspdm_set_standard_key_update_test_secrets(
    libspdm_secured_message_context_t *secured_message_context,
    uint8_t *m_rsp_secret_buffer, uint8_t rsp_secret_fill,
    uint8_t *m_req_secret_buffer, uint8_t req_secret_fill)
{
    libspdm_set_mem(m_rsp_secret_buffer, secured_message_context->hash_size, rsp_secret_fill);
    libspdm_set_mem(m_req_secret_buffer, secured_message_context->hash_size, req_secret_fill);

    libspdm_copy_mem(secured_message_context->application_secret.response_data_secret,
                     sizeof(secured_message_context->application_secret.response_data_secret),
                     m_rsp_secret_buffer, secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->application_secret.request_data_secret,
                     sizeof(secured_message_context->application_secret.request_data_secret),
                     m_req_secret_buffer, secured_message_context->aead_key_size);

    libspdm_set_mem(secured_message_context->application_secret
                    .response_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xFF));
    libspdm_set_mem(secured_message_context->application_secret
                    .response_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xFF));

    libspdm_set_mem(secured_message_context->application_secret
                    .request_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xEE));
    libspdm_set_mem(secured_message_context->application_secret
                    .request_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xEE));

    secured_message_context->application_secret.response_data_sequence_number = 0;
    secured_message_context->application_secret.request_data_sequence_number = 0;
}

/**
 * Test 1: receiving a correct UPDATE_KEY_ACK message for updating
 * only the request data key.
 * Expected behavior: client returns a Status of LIBSPDM_STATUS_SUCCESS,Communication needs to continue.
 **/
static void rsp_encap_key_update_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x1;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state( spdm_context, &session_id);

    spdm_context->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE_ACK;
    spdm_context->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    spdm_context->encap_context.last_encap_request_header.param2 = 0;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(need_continue, true);
}

/**
 * Test 2: receiving a correct UPDATE_KEY_ACK message for updating
 * only the request data key.
 * Expected behavior: client returns a Status of LIBSPDM_STATUS_SUCCESS,Communication needs to continue.
 **/
static void rsp_encap_key_update_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x2;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state( spdm_context, &session_id);

    spdm_context->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE_ACK;
    spdm_context->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY;
    spdm_context->encap_context.last_encap_request_header.param2 = 0;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(need_continue, false);
}
/**
 * Test 3: receiving a correct UPDATE_KEY_ACK message for updating
 * only the request data key. last_spdm_request_session_id_valid invalid
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED,No further communication is required.
 **/
static void rsp_encap_key_update_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x3;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state( spdm_context, &session_id);

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code =    SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = 0;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: receives an ERROR message indicating InvalidParameters when updating key.
 * Expected behavior: client returns a Status of RETURN_SECURITY_VIOLATION, and
 * no keys should be updated.
 **/
static void rsp_encap_key_update_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x4;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state( spdm_context, &session_id);

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_ERROR;
    spdm_response.header.param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SESSION_MSG_ERROR);
}

/**
 * Test 5: spdm_response message is correct but does not match last_encap_request_header error message
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR
 **/
static void rsp_encap_key_update_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x5;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state( spdm_context, &session_id);

    spdm_context->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE_ACK;
    spdm_context->encap_context.last_encap_request_header.param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
    spdm_context->encap_context.last_encap_request_header.param2 = 0;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = 0;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 6: no session exists for last_spdm_request_session_id even though
 * last_spdm_request_session_id_valid is true.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
static void rsp_encap_key_update_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x6;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    /* Point at a session id that does not exist in session_info array
     * (and is not LIBSPDM_INVALID_SESSION_ID, which would assert). */
    spdm_context->last_spdm_request_session_id = 0x12345678;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = 0;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 7: session exists but is not in the ESTABLISHED state.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
static void rsp_encap_key_update_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x7;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = 0;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 8: the response's spdm_version does not match the negotiated
 * connection version.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR
 * (LIBSPDM_STATUS_INVALID_MSG_FIELD).
 **/
static void rsp_encap_key_update_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x8;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    /* Use SPDM 1.0 in the response, which mismatches the negotiated 1.1. */
    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = 0;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 9: the request was for VERIFY_NEW_KEY, but the response does not
 * match (mismatched param2), so the "SpdmVerifyKey[%x] failed" debug
 * branch is taken.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR
 * (LIBSPDM_STATUS_INVALID_MSG_FIELD).
 **/
static void rsp_encap_key_update_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x9;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    spdm_context->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE_ACK;
    spdm_context->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY;
    spdm_context->encap_context.last_encap_request_header.param2 = 1;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY;
    /* Mismatched param2 causes the response to be rejected. */
    spdm_response.header.param2 = 2;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 10: connection version is below SPDM 1.1.
 * Expected behavior: libspdm_get_encap_request_key_update returns
 * LIBSPDM_STATUS_UNSUPPORTED_CAP because KEY_UPDATE is only defined for
 * SPDM 1.1 and above.
 **/
static void rsp_encap_key_update_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    size_t encap_request_size;
    uint8_t encap_request[sizeof(spdm_key_update_request_t)];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    spdm_context->last_spdm_request_session_id_valid = true;

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_key_update(spdm_context, &encap_request_size,
                                                  encap_request);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 11: the KEY_UPD_CAP capability flag is not negotiated.
 * Expected behavior: libspdm_get_encap_request_key_update returns
 * LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void rsp_encap_key_update_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    size_t encap_request_size;
    uint8_t encap_request[sizeof(spdm_key_update_request_t)];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->local_context.capability.flags &=
        ~(uint32_t)SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_key_update(spdm_context, &encap_request_size,
                                                  encap_request);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 12: last_spdm_request_session_id_valid is false.
 * Expected behavior: libspdm_get_encap_request_key_update returns
 * LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void rsp_encap_key_update_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    size_t encap_request_size;
    uint8_t encap_request[sizeof(spdm_key_update_request_t)];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    spdm_context->last_spdm_request_session_id_valid = false;

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_key_update(spdm_context, &encap_request_size,
                                                  encap_request);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 13: no session exists for last_spdm_request_session_id.
 * Expected behavior: libspdm_get_encap_request_key_update returns
 * LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void rsp_encap_key_update_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    size_t encap_request_size;
    uint8_t encap_request[sizeof(spdm_key_update_request_t)];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    spdm_context->last_spdm_request_session_id_valid = true;
    /* Point at a session id that does not exist (and is not
     * LIBSPDM_INVALID_SESSION_ID, which would assert). */
    spdm_context->last_spdm_request_session_id = 0x12345678;

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_key_update(spdm_context, &encap_request_size,
                                                  encap_request);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 14: the session exists but is not in the ESTABLISHED state.
 * Expected behavior: libspdm_get_encap_request_key_update returns
 * LIBSPDM_STATUS_INVALID_STATE_LOCAL.
 **/
static void rsp_encap_key_update_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    size_t encap_request_size;
    uint8_t encap_request[sizeof(spdm_key_update_request_t)];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    spdm_context->last_spdm_request_session_id_valid = true;
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_key_update(spdm_context, &encap_request_size,
                                                  encap_request);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 15: first request in a KEY_UPDATE flow (last_encap_request_header
 * is not KEY_UPDATE).
 * Expected behavior: libspdm_get_encap_request_key_update succeeds and
 * produces a request with the UpdateKey operation.
 **/
static void rsp_encap_key_update_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    size_t encap_request_size;
    spdm_key_update_request_t encap_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->encap_context.last_encap_request_header.request_response_code = 0;

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_key_update(spdm_context, &encap_request_size,
                                                  &encap_request);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(encap_request_size, sizeof(spdm_key_update_request_t));
    assert_int_equal(encap_request.header.request_response_code, SPDM_KEY_UPDATE);
    assert_int_equal(encap_request.header.param1, SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY);
    assert_int_equal(spdm_context->encap_context.last_encap_request_header.request_response_code,
                     SPDM_KEY_UPDATE);
}

/**
 * Test 16: second request in a KEY_UPDATE flow (last_encap_request_header
 * is KEY_UPDATE), which produces the VerifyNewKey request. This also
 * exercises libspdm_create_update_session_data_key and
 * libspdm_activate_update_session_data_key.
 * Expected behavior: libspdm_get_encap_request_key_update succeeds and
 * produces a request with the VerifyNewKey operation, and the responder's
 * data keys are updated.
 **/
static void rsp_encap_key_update_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;
    size_t encap_request_size;
    spdm_key_update_request_t encap_request;
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    secured_message_context = session_info->secured_message_context;
    libspdm_set_standard_key_update_test_secrets(
        secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_key_update(spdm_context, &encap_request_size,
                                                  &encap_request);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(encap_request_size, sizeof(spdm_key_update_request_t));
    assert_int_equal(encap_request.header.request_response_code, SPDM_KEY_UPDATE);
    assert_int_equal(encap_request.header.param1,
                     SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY);
    /* Data key update should have moved the responder to the new key,
     * so the old (non-updated) response secret is no longer present. */
    assert_memory_not_equal(secured_message_context
                            ->application_secret.response_data_secret,
                            m_rsp_secret_buffer, secured_message_context->hash_size);
}

int libspdm_rsp_encap_key_update_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Successful response*/
        cmocka_unit_test(rsp_encap_key_update_case1),
        /* Successful response,No further communication is required.*/
        cmocka_unit_test(rsp_encap_key_update_case2),
        /* last_spdm_request_session_id_valid : false */
        cmocka_unit_test(rsp_encap_key_update_case3),
        /* Error response: RETURN_SECURITY_VIOLATION */
        cmocka_unit_test(rsp_encap_key_update_case4),
        /* Error response: RETURN_DEVICE_ERROR */
        cmocka_unit_test(rsp_encap_key_update_case5),
        /* process_encap_response_key_update: no session found */
        cmocka_unit_test(rsp_encap_key_update_case6),
        /* process_encap_response_key_update: session not established */
        cmocka_unit_test(rsp_encap_key_update_case7),
        /* process_encap_response_key_update: version mismatch */
        cmocka_unit_test(rsp_encap_key_update_case8),
        /* process_encap_response_key_update: SpdmVerifyKey failed debug branch */
        cmocka_unit_test(rsp_encap_key_update_case9),
        /* get_encap_request_key_update: connection version < 1.1 */
        cmocka_unit_test(rsp_encap_key_update_case10),
        /* get_encap_request_key_update: KEY_UPD_CAP not supported */
        cmocka_unit_test(rsp_encap_key_update_case11),
        /* get_encap_request_key_update: last_spdm_request_session_id_valid false */
        cmocka_unit_test(rsp_encap_key_update_case12),
        /* get_encap_request_key_update: no session found */
        cmocka_unit_test(rsp_encap_key_update_case13),
        /* get_encap_request_key_update: session not established */
        cmocka_unit_test(rsp_encap_key_update_case14),
        /* get_encap_request_key_update: success, UpdateKey operation */
        cmocka_unit_test(rsp_encap_key_update_case15),
        /* get_encap_request_key_update: success, VerifyNewKey operation */
        cmocka_unit_test(rsp_encap_key_update_case16),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/
