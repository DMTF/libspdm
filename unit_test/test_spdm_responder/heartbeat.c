/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

spdm_heartbeat_request_t m_libspdm_heartbeat_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_HEARTBEAT, 0, 0 }
};
size_t m_libspdm_heartbeat_request1_size = sizeof(m_libspdm_heartbeat_request1);

spdm_heartbeat_request_t m_libspdm_heartbeat_request2 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_HEARTBEAT, 0, 0 }
};
size_t m_libspdm_heartbeat_request2_size = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;

static uint8_t m_libspdm_local_psk_hint[32];

void libspdm_test_responder_heartbeat_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_heartbeat_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
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
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
    status = libspdm_get_response_heartbeat(spdm_context,
                                            m_libspdm_heartbeat_request1_size,
                                            &m_libspdm_heartbeat_request1,
                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_heartbeat_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_HEARTBEAT_ACK);
    free(data1);
}

void libspdm_test_responder_heartbeat_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_heartbeat_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
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
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
    status = libspdm_get_response_heartbeat(spdm_context,
                                            m_libspdm_heartbeat_request2_size,
                                            &m_libspdm_heartbeat_request2,
                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

void libspdm_test_responder_heartbeat_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_heartbeat_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
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
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
    status = libspdm_get_response_heartbeat(spdm_context,
                                            m_libspdm_heartbeat_request1_size,
                                            &m_libspdm_heartbeat_request1,
                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
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

void libspdm_test_responder_heartbeat_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_heartbeat_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
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
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
    status = libspdm_get_response_heartbeat(spdm_context,
                                            m_libspdm_heartbeat_request1_size,
                                            &m_libspdm_heartbeat_request1,
                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
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

void libspdm_test_responder_heartbeat_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_heartbeat_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
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
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
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
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
    status = libspdm_get_response_heartbeat(spdm_context,
                                            m_libspdm_heartbeat_request1_size,
                                            &m_libspdm_heartbeat_request1,
                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
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
    assert_int_equal(error_data->request_code, SPDM_HEARTBEAT);
    free(data1);
}

void libspdm_test_responder_heartbeat_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_heartbeat_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
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
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
    status = libspdm_get_response_heartbeat(spdm_context,
                                            m_libspdm_heartbeat_request1_size,
                                            &m_libspdm_heartbeat_request1,
                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

void libspdm_test_responder_heartbeat_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_heartbeat_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
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
    libspdm_zero_mem(m_libspdm_local_psk_hint, 32);
    libspdm_copy_mem(&m_libspdm_local_psk_hint[0], sizeof(m_libspdm_local_psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_libspdm_local_psk_hint;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
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
    status = libspdm_get_response_heartbeat(spdm_context,
                                            m_libspdm_heartbeat_request1_size,
                                            &m_libspdm_heartbeat_request1,
                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_heartbeat_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_HEARTBEAT_ACK);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data1);
}

libspdm_test_context_t m_libspdm_responder_heartbeat_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

int libspdm_responder_heartbeat_test_main(void)
{
    const struct CMUnitTest spdm_responder_heartbeat_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_heartbeat_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_heartbeat_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_heartbeat_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_heartbeat_case4),
        /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(libspdm_test_responder_heartbeat_case5),
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_heartbeat_case6),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_responder_heartbeat_case7),
    };

    libspdm_setup_test_context(&m_libspdm_responder_heartbeat_test_context);

    return cmocka_run_group_tests(spdm_responder_heartbeat_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
