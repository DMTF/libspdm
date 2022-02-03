/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint8_t session_policy;
    uint8_t reserved;
    uint8_t random_data[SPDM_RANDOM_DATA_SIZE];
    uint8_t exchange_data[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} spdm_key_exchange_request_mine_t;

#pragma pack()

spdm_key_exchange_request_mine_t m_spdm_key_exchange_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
uintn m_spdm_key_exchange_request1_size = sizeof(m_spdm_key_exchange_request1);

spdm_key_exchange_request_mine_t m_spdm_key_exchange_request2 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
uintn m_spdm_key_exchange_request2_size = sizeof(spdm_key_exchange_request_t);

void test_spdm_responder_key_exchange_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uintn dhe_key_size;
    void *dhe_context;
    uintn opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_spdm_key_exchange_request1.random_data);
    m_spdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_spdm_key_exchange_request1.reserved = 0;
    ptr = m_spdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_use_dhe_algo, false);
    libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        spdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    spdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = spdm_get_response_key_exchange(
        spdm_context, m_spdm_key_exchange_request1_size,
        &m_spdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    free(data1);
}

void test_spdm_responder_key_exchange_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uintn dhe_key_size;
    void *dhe_context;
    uintn opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_spdm_key_exchange_request2.random_data);
    m_spdm_key_exchange_request2.req_session_id = 0xFFFF;
    m_spdm_key_exchange_request2.reserved = 0;
    ptr = m_spdm_key_exchange_request2.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_use_dhe_algo, false);
    libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        spdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    spdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = spdm_get_response_key_exchange(
        spdm_context, m_spdm_key_exchange_request2_size,
        &m_spdm_key_exchange_request2, &response_size, response);
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

void test_spdm_responder_key_exchange_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uintn dhe_key_size;
    void *dhe_context;
    uintn opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_spdm_key_exchange_request1.random_data);
    m_spdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_spdm_key_exchange_request1.reserved = 0;
    ptr = m_spdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_use_dhe_algo, false);
    libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        spdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    spdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = spdm_get_response_key_exchange(
        spdm_context, m_spdm_key_exchange_request1_size,
        &m_spdm_key_exchange_request1, &response_size, response);
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

void test_spdm_responder_key_exchange_case4(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uintn dhe_key_size;
    void *dhe_context;
    uintn opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_spdm_key_exchange_request1.random_data);
    m_spdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_spdm_key_exchange_request1.reserved = 0;
    ptr = m_spdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_use_dhe_algo, false);
    libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        spdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    spdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = spdm_get_response_key_exchange(
        spdm_context, m_spdm_key_exchange_request1_size,
        &m_spdm_key_exchange_request1, &response_size, response);
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

void test_spdm_responder_key_exchange_case5(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    spdm_error_data_response_not_ready_t *error_data;
    uint8_t *ptr;
    uintn dhe_key_size;
    void *dhe_context;
    uintn opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_spdm_key_exchange_request1.random_data);
    m_spdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_spdm_key_exchange_request1.reserved = 0;
    ptr = m_spdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_use_dhe_algo, false);
    libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        spdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    spdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = spdm_get_response_key_exchange(
        spdm_context, m_spdm_key_exchange_request1_size,
        &m_spdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data = (spdm_error_data_response_not_ready_t
                  *)(&spdm_response->rsp_session_id);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_KEY_EXCHANGE);
    free(data1);
}

void test_spdm_responder_key_exchange_case6(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uintn dhe_key_size;
    void *dhe_context;
    uintn opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_spdm_key_exchange_request1.random_data);
    m_spdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_spdm_key_exchange_request1.reserved = 0;
    ptr = m_spdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_use_dhe_algo, false);
    libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        spdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    spdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = spdm_get_response_key_exchange(
        spdm_context, m_spdm_key_exchange_request1_size,
        &m_spdm_key_exchange_request1, &response_size, response);
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

void test_spdm_responder_key_exchange_case7(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uintn dhe_key_size;
    void *dhe_context;
    uintn opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data1,
                                            &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_spdm_key_exchange_request1.random_data);
    m_spdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_spdm_key_exchange_request1.reserved = 0;
    ptr = m_spdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_use_dhe_algo, false);
    libspdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        spdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    spdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = spdm_get_response_key_exchange(
        spdm_context, m_spdm_key_exchange_request1_size,
        &m_spdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data1);
}

spdm_test_context_t m_spdm_responder_key_exchange_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

int spdm_responder_key_exchange_test_main(void)
{
    const struct CMUnitTest spdm_responder_key_exchange_tests[] = {
        /* Success Case*/
        cmocka_unit_test(test_spdm_responder_key_exchange_case1),
        /* Bad request size*/
        cmocka_unit_test(test_spdm_responder_key_exchange_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(test_spdm_responder_key_exchange_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(test_spdm_responder_key_exchange_case4),
        /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(test_spdm_responder_key_exchange_case5),
        /* connection_state Check*/
        cmocka_unit_test(test_spdm_responder_key_exchange_case6),
        /* Buffer reset*/
        cmocka_unit_test(test_spdm_responder_key_exchange_case7),
    };

    setup_spdm_test_context(&m_spdm_responder_key_exchange_test_context);

    return cmocka_run_group_tests(spdm_responder_key_exchange_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
