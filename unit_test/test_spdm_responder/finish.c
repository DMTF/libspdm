/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

#pragma pack()

spdm_finish_request_mine_t m_spdm_finish_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
uintn m_spdm_finish_request1_size = sizeof(m_spdm_finish_request1);

spdm_finish_request_mine_t m_spdm_finish_request2 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
uintn m_spdm_finish_request2_size = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;

spdm_finish_request_mine_t m_spdm_finish_request3 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 1, 0 },
};
uintn m_spdm_finish_request3_size = sizeof(m_spdm_finish_request3);

uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

void spdm_secured_message_set_request_finished_key(
    IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    ASSERT(key_size == secured_message_context->hash_size);
    copy_mem(secured_message_context->handshake_secret.request_finished_key,
             key, secured_message_context->hash_size);
    secured_message_context->finished_key_ready = true;
}

/**
 * Test 1: receiving a correct FINISH message from the requester with a
 * correct MAC, no signature (no mutual authentication), and 'handshake in
 * the clear'.
 * Expected behavior: the responder accepts the request and produces a valid
 * FINISH_RSP response message.
 **/
void test_spdm_responder_finish_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
    free(data1);
}

/**
 * Test 2: receiving a FINISH message larger than specified.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the InvalidRequest.
 **/
void test_spdm_responder_finish_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request2.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request2,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request2_size,
                                      &m_spdm_finish_request2,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 3: receiving a correct FINISH from the requester, but the
 * responder is in a Busy state.
 * Expected behavior: the responder accepts the request, but produces an
 * ERROR message indicating the Busy state.
 **/
void test_spdm_responder_finish_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_BUSY);
    free(data1);
}

/**
 * Test 4: receiving a correct FINISH from the requester, but the responder
 * requires resynchronization with the requester.
 * Expected behavior: the responder accepts the request, but produces an
 * ERROR message indicating the NeedResynch state.
 **/
void test_spdm_responder_finish_case4(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
    free(data1);
}

/**
 * Test 5: receiving a correct FINISH from the requester, but the responder
 * could not produce the response in time.
 * Expected behavior: the responder accepts the request, but produces an
 * ERROR message indicating the ResponseNotReady state.
 **/
void test_spdm_responder_finish_case5(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    spdm_error_data_response_not_ready_t *error_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data =
        (spdm_error_data_response_not_ready_t *)(spdm_response + 1);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_FINISH);
    free(data1);
}

/**
 * Test 6: receiving a correct FINISH from the requester, but the responder
 * is not set no receive a FINISH message because previous messages (namely,
 * GET_CAPABILITIES, NEGOTIATE_ALGORITHMS or GET_DIGESTS) have not been
 * received.
 * Expected behavior: the responder rejects the request, and produces an
 * ERROR message indicating the UnexpectedRequest.
 **/
void test_spdm_responder_finish_case6(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

void test_spdm_responder_finish_case7(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data1);
}

/**
 * Test 8: receiving a correct FINISH message from the requester with
 * correct MAC and signature (withmutual authentication), and 'handshake in
 * the clear'.
 * Expected behavior: the responder accepts the request and produces a valid
 * FINISH_RSP response message.
 **/
void test_spdm_responder_finish_case8(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    void *data2;
    uintn data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    uintn req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data2,
                                            &data_size2, NULL, NULL);
    spdm_context->local_context.peer_cert_chain_provision = data2;
    spdm_context->local_context.peer_cert_chain_provision_size =
        data_size2;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size2;
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data2, data_size2,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        data2,
        data_size2,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_use_req_asym_algo);
    ptr = m_spdm_finish_request3.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request3,
                          sizeof(spdm_finish_request_t));
    libspdm_requester_data_sign(
        m_spdm_finish_request3.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_use_req_asym_algo, m_use_hash_algo,
            false, get_managed_buffer(&th_curr),
            get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
    append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request3_size = sizeof(spdm_finish_request_t) +
                                  req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request3_size,
                                      &m_spdm_finish_request3,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
    free(data1);
    free(data2);
}

/**
 * Test 9: receiving a correct FINISH message from the requester, but the
 * responder has no capabilities for key exchange.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the UnsupportedRequest.
 **/
void test_spdm_responder_finish_case9(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    /* no key exchange capabilities (responder)*/
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_KEY_EXCHANGE);
    free(data1);
}

/**
 * Test 10: receiving a correct FINISH message from the requester, but the
 * responder is not correctly setup by not initializing a session during
 * KEY_EXCHANGE.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the UnsupportedRequest.
 **/
void test_spdm_responder_finish_case10(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_NOT_STARTED);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 11: receiving a FINISH message from the requester with an incorrect
 * MAC (all-zero).
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void test_spdm_responder_finish_case11(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    set_mem(ptr, hmac_size, (uint8_t)(0x00)); /*all-zero MAC*/
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 12: receiving a FINISH message from the requester with an incorrect
 * MAC (arbitrary).
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void test_spdm_responder_finish_case12(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    uint8_t zero_data[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    /*arbitrary MAC*/
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    set_mem(zero_data, hash_size, (uint8_t)(0x00));
    libspdm_hmac_all(m_use_hash_algo, zero_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 13: receiving a FINISH message from the requester with an incorrect
 * MAC size (a correct MAC repeated twice).
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the InvalidRequest.
 **/
void test_spdm_responder_finish_case13(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    copy_mem(ptr, ptr + hmac_size, hmac_size); /* 2x HMAC size*/
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + 2*hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 14: receiving a FINISH message from the requester with an incorrect
 * MAC size (only the correct first half of the MAC).
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the InvalidRequest.
 **/
void test_spdm_responder_finish_case14(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request1,
                          sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    set_mem(ptr + hmac_size/2, hmac_size/2, (uint8_t) 0x00); /* half HMAC size*/
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size/2;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request1_size,
                                      &m_spdm_finish_request1,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 15: receiving a FINISH message from the requester with an incorrect
 * signature (all-zero), but a correct MAC.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void test_spdm_responder_finish_case15(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    void *data2;
    uintn data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    uintn req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data2,
                                            &data_size2, NULL, NULL);
    spdm_context->local_context.peer_cert_chain_provision = data2;
    spdm_context->local_context.peer_cert_chain_provision_size =
        data_size2;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size2;
#endif

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_use_req_asym_algo);
    ptr = m_spdm_finish_request3.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request3,
                          sizeof(spdm_finish_request_t));
    libspdm_requester_data_sign(
        m_spdm_finish_request3.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_use_req_asym_algo, m_use_hash_algo,
            false, get_managed_buffer(&th_curr),
            get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
    append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    set_mem(m_spdm_finish_request3.signature,
            req_asym_signature_size, (uint8_t) 0x00); /*zero signature*/
    m_spdm_finish_request3_size = sizeof(spdm_finish_request_t) +
                                  req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request3_size,
                                      &m_spdm_finish_request3,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
    free(data2);
}

/**
 * Test 16: receiving a FINISH message from the requester with an incorrect
 * signature (arbitrary), but a correct MAC.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void test_spdm_responder_finish_case16(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    void *data2;
    uintn data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t random_buffer[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    uintn req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data2,
                                            &data_size2, NULL, NULL);
    spdm_context->local_context.peer_cert_chain_provision = data2;
    spdm_context->local_context.peer_cert_chain_provision_size =
        data_size2;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size2;
#endif

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_use_req_asym_algo);
    ptr = m_spdm_finish_request3.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    append_managed_buffer(&th_curr, (uint8_t *)&m_spdm_finish_request3,
                          sizeof(spdm_finish_request_t));
    /*randomize signature*/
    libspdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), random_buffer);
    libspdm_requester_data_sign(
        m_spdm_finish_request3.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_use_req_asym_algo, m_use_hash_algo,
            false, random_buffer, hash_size, ptr, &req_asym_signature_size);
    append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key,
                     hash_size, ptr);
    m_spdm_finish_request3_size = sizeof(spdm_finish_request_t) +
                                  req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = spdm_get_response_finish(spdm_context,
                                      m_spdm_finish_request3_size,
                                      &m_spdm_finish_request3,
                                      &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
    free(data2);
}

spdm_test_context_t m_spdm_responder_finish_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

int spdm_responder_finish_test_main(void)
{
    const struct CMUnitTest spdm_responder_finish_tests[] = {
        /* Success Case*/
        cmocka_unit_test(test_spdm_responder_finish_case1),
        /* Bad request size*/
        cmocka_unit_test(test_spdm_responder_finish_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(test_spdm_responder_finish_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(test_spdm_responder_finish_case4),
        /* response_state: LIBSPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(test_spdm_responder_finish_case5),
        /* connection_state Check*/
        cmocka_unit_test(test_spdm_responder_finish_case6),
        /* Buffer reset*/
        cmocka_unit_test(test_spdm_responder_finish_case7),
        /* Success Case*/
        cmocka_unit_test(test_spdm_responder_finish_case8),
        /* Unsupported KEY_EX capabilities*/
        cmocka_unit_test(test_spdm_responder_finish_case9),
        /* Uninitialized session*/
        cmocka_unit_test(test_spdm_responder_finish_case10),
        /* Incorrect MAC*/
        cmocka_unit_test(test_spdm_responder_finish_case11),
        cmocka_unit_test(test_spdm_responder_finish_case12),
        /* Incorrect MAC size*/
        cmocka_unit_test(test_spdm_responder_finish_case13),
        cmocka_unit_test(test_spdm_responder_finish_case14),
        /* Incorrect signature*/
        cmocka_unit_test(test_spdm_responder_finish_case15),
        cmocka_unit_test(test_spdm_responder_finish_case16),
    };

    setup_spdm_test_context(&m_spdm_responder_finish_test_context);

    return cmocka_run_group_tests(spdm_responder_finish_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
