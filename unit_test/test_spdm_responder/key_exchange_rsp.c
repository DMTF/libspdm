/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

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
} libspdm_key_exchange_request_mine_t;
#pragma pack()

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request1_size = sizeof(m_libspdm_key_exchange_request1);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request2 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request2_size = sizeof(spdm_key_exchange_request_t);

/* Request TCB measurement hash */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request3 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0 },
};
size_t m_libspdm_key_exchange_request3_size = sizeof(m_libspdm_key_exchange_request3);

/* Request all measurement hash */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request4 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, 0 },
};
size_t m_libspdm_key_exchange_request4_size = sizeof(m_libspdm_key_exchange_request4);

/* Uses a reserved value in measurement hash */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request5 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      0x50, 0 },
};
size_t m_libspdm_key_exchange_request5_size = sizeof(m_libspdm_key_exchange_request5);

/* Asks for certificate in slot 1 */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request6 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 1 },
};
size_t m_libspdm_key_exchange_request6_size = sizeof(m_libspdm_key_exchange_request6);

/* Asks for previously provisioned raw public key */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request7 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0xFF },
};
size_t m_libspdm_key_exchange_request7_size = sizeof(m_libspdm_key_exchange_request7);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request8 = {
    { SPDM_MESSAGE_VERSION_12, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request8_size = sizeof(m_libspdm_key_exchange_request8);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request9 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 9 },
};
size_t m_libspdm_key_exchange_request9_size = sizeof(m_libspdm_key_exchange_request9);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request10 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request10_size = sizeof(m_libspdm_key_exchange_request10);

extern uint8_t g_key_exchange_start_mut_auth;
extern uint8_t g_key_exchange_req_slot_id;
extern bool g_mandatory_mut_auth;
extern bool g_generate_key_exchange_opaque_data;

extern bool g_event_all_subscribe;
extern bool g_event_all_unsubscribe;

static int rsp_key_exchange_rsp_setup(void **state)
{
    libspdm_key_exchange_request_mine_t *const requests[] = {
        &m_libspdm_key_exchange_request1, &m_libspdm_key_exchange_request2,
        &m_libspdm_key_exchange_request3, &m_libspdm_key_exchange_request4,
        &m_libspdm_key_exchange_request5, &m_libspdm_key_exchange_request6,
        &m_libspdm_key_exchange_request7, &m_libspdm_key_exchange_request8,
        &m_libspdm_key_exchange_request9, &m_libspdm_key_exchange_request10,
    };
    libspdm_context_t *spdm_context;
    size_t index;

    /* SessionPolicy is the only request field that a test writes and a later user of the same
     * request does not write before sending it. */
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(requests); index++) {
        requests[index]->session_policy = 0;
    }

    /* A test that turns on multi-key, or that narrows a slot's key usage, is the only one that
     * sets either field, so restore the values libspdm_init_context leaves them at. */
    spdm_context = libspdm_get_test_context()->spdm_context;
    spdm_context->connection_info.multi_key_conn_rsp = false;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        spdm_context->local_context.local_key_usage_bit_mask[index] = 0;
    }
    /* A test that starts an encapsulated flow leaves the response state set. */
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    g_key_exchange_start_mut_auth = 0;
    g_key_exchange_req_slot_id = 0;
    g_mandatory_mut_auth = false;
    g_generate_key_exchange_opaque_data = false;

    return 0;
}

static void rsp_key_exchange_rsp_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    session_id = (m_libspdm_key_exchange_request1.req_session_id << 16) |
                 spdm_response->rsp_session_id;
    libspdm_free_session_id(spdm_context, session_id);
    free(data1);
}

static void rsp_key_exchange_rsp_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request2.random_data);
    m_libspdm_key_exchange_request2.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request2.reserved = 0;
    ptr = m_libspdm_key_exchange_request2.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request2_size,
        &m_libspdm_key_exchange_request2, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

static void rsp_key_exchange_rsp_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_BUSY);
    free(data1);
}

static void rsp_key_exchange_rsp_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
    free(data1);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
static void rsp_key_exchange_rsp_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    spdm_error_data_response_not_ready_t *error_data;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data = (spdm_error_data_response_not_ready_t
                  *)(&spdm_response->rsp_session_id);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_KEY_EXCHANGE);
    free(data1);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

static void rsp_key_exchange_rsp_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

static void rsp_key_exchange_rsp_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
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

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data1);
}

static void rsp_key_exchange_rsp_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
    uint32_t measurement_summary_hash_size;
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    bool result;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request3.random_data);
    m_libspdm_key_exchange_request3.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request3.reserved = 0;
    ptr = m_libspdm_key_exchange_request3.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request3_size,
        &m_libspdm_key_exchange_request3, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, m_libspdm_key_exchange_request3.header.param1);

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    result = libspdm_generate_measurement_summary_hash(
        spdm_context,
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_key_exchange_request3.header.param1,
        measurement_hash,
        measurement_summary_hash_size);

    assert_true(result);

    assert_memory_equal((uint8_t *)response + sizeof(spdm_key_exchange_response_t) + dhe_key_size,
                        measurement_hash, measurement_summary_hash_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
    free(data1);
}

static void rsp_key_exchange_rsp_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
    uint32_t measurement_summary_hash_size;
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    uint32_t session_id;
    bool result;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request4.random_data);
    m_libspdm_key_exchange_request4.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request4.reserved = 0;
    ptr = m_libspdm_key_exchange_request4.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request4_size,
        &m_libspdm_key_exchange_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, m_libspdm_key_exchange_request4.header.param1);
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    result = libspdm_generate_measurement_summary_hash(
        spdm_context,
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_key_exchange_request4.header.param1,
        measurement_hash,
        measurement_summary_hash_size);

    assert_true(result);

    assert_memory_equal((uint8_t *)response + sizeof(spdm_key_exchange_response_t) + dhe_key_size,
                        measurement_hash, measurement_summary_hash_size);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

    session_id = (m_libspdm_key_exchange_request4.req_session_id << 16) |
                 spdm_response->rsp_session_id;
    libspdm_free_session_id(spdm_context, session_id);

    free(data1);
}

static void rsp_key_exchange_rsp_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request5.random_data);
    m_libspdm_key_exchange_request5.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request5.reserved = 0;
    ptr = m_libspdm_key_exchange_request5.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request5_size,
        &m_libspdm_key_exchange_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    free(data1);
}

static void rsp_key_exchange_rsp_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    /* Clear capabilities flag */
    spdm_context->local_context.capability.flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;

    /*set capabilities flags */
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request3.random_data);
    m_libspdm_key_exchange_request3.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request3.reserved = 0;
    ptr = m_libspdm_key_exchange_request3.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request3_size,
        &m_libspdm_key_exchange_request3, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    free(data1);
}

static void rsp_key_exchange_rsp_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data1, &data_size1)) {
        return;
    }
    spdm_context->local_context.local_public_key_provision = data1;
    spdm_context->local_context.local_public_key_provision_size = data_size1;
    if (!libspdm_read_requester_public_key(m_libspdm_use_req_asym_algo, &data2, &data_size2)) {
        return;
    }
    spdm_context->local_context.peer_public_key_provision = data2;
    spdm_context->local_context.peer_public_key_provision_size = data_size2;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request7.random_data);
    m_libspdm_key_exchange_request7.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request7.reserved = 0;
    ptr = m_libspdm_key_exchange_request7.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request7_size,
        &m_libspdm_key_exchange_request7, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    free(data1);
    free(data2);
}

static void rsp_key_exchange_rsp_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    size_t opaque_key_exchange_rsp_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    /* Required to compute response size independently */
    opaque_key_exchange_rsp_size =
        libspdm_get_opaque_data_version_selection_data_size(spdm_context);

    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    assert_int_equal(response_size,
                     sizeof(spdm_key_exchange_response_t) +
                     dhe_key_size +
                     sizeof(uint16_t) +
                     opaque_key_exchange_rsp_size +
                     libspdm_get_asym_signature_size(
                         spdm_context->connection_info.algorithm.base_asym_algo)
                     );

    free(data1);
}

static void rsp_key_exchange_rsp_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t current_request_size;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;

    current_request_size = sizeof(spdm_key_exchange_request_t) + dhe_key_size +
                           sizeof(uint16_t) + opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, current_request_size, &m_libspdm_key_exchange_request1,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->session_info[0].session_transcript.message_k.buffer_size,
                     current_request_size + response_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_k.buffer,
                        &m_libspdm_key_exchange_request1, current_request_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_k.buffer +
                        current_request_size,
                        response, response_size);
#endif
    free(data1);
}

static void rsp_key_exchange_rsp_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              0,
                              INVALID_SESSION_ID, false);
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request8.random_data);
    m_libspdm_key_exchange_request8.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request8.reserved = 0;
    m_libspdm_key_exchange_request8.session_policy = 0xFF;
    ptr = m_libspdm_key_exchange_request8.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request8_size,
        &m_libspdm_key_exchange_request8, &response_size, response);
    assert_int_equal(spdm_context->session_info[0].session_policy,
                     m_libspdm_key_exchange_request8.session_policy);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    free(data1);
}

/**
 * Test 18: SlotID in KEY_EXCHANGE request message is 9, but it should be 0xFF or between 0 and 7 inclusive.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void rsp_key_exchange_rsp_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request9.random_data);
    m_libspdm_key_exchange_request9.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request9.reserved = 0;
    ptr = m_libspdm_key_exchange_request9.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request9_size,
        &m_libspdm_key_exchange_request9, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

static void rsp_key_exchange_rsp_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->response_state = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request8.random_data);
    m_libspdm_key_exchange_request8.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request8.reserved = 0;
    ptr = m_libspdm_key_exchange_request8.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);

    size_t opaque_data_size;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_header_t
    * secured_message_element_header;
    uint8_t element_num;
    uint8_t element_index;
    size_t current_element_len;

    spdm_general_opaque_data_table_header =
        (spdm_general_opaque_data_table_header_t *)(ptr + sizeof(uint16_t));
    spdm_general_opaque_data_table_header->total_elements = 2;
    opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);

    element_num = spdm_general_opaque_data_table_header->total_elements;
    opaque_data_size = sizeof(spdm_general_opaque_data_table_header_t);

    for (element_index = 0; element_index < element_num; element_index++) {
        opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
        opaque_element_table_header->vendor_len = 0;
        /* When opaque_element_data_len is not four byte aligned*/
        opaque_element_table_header->opaque_element_data_len = 0xF;

        secured_message_element_header = (void *)(opaque_element_table_header + 1);
        secured_message_element_header->sm_data_id =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
        secured_message_element_header->sm_data_version =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;

        current_element_len = sizeof(secured_message_opaque_element_table_header_t) +
                              opaque_element_table_header->vendor_len +
                              sizeof(opaque_element_table_header->opaque_element_data_len) +
                              opaque_element_table_header->opaque_element_data_len;

        /*move to next element*/
        opaque_element_table_header =
            (secured_message_opaque_element_table_header_t *)
            ((uint8_t *)opaque_element_table_header + current_element_len);

        opaque_data_size += current_element_len;
    }

    libspdm_write_uint16(ptr, (uint16_t)opaque_data_size);

    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request8_size,
        &m_libspdm_key_exchange_request8, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

static void rsp_key_exchange_rsp_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              0,
                              INVALID_SESSION_ID, false);
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request8.random_data);
    m_libspdm_key_exchange_request8.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request8.reserved = 0;
    m_libspdm_key_exchange_request8.session_policy = 0xFF;
    ptr = m_libspdm_key_exchange_request8.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request8_size,
        &m_libspdm_key_exchange_request8, &response_size, response);
    assert_int_equal(spdm_context->session_info[0].session_policy,
                     m_libspdm_key_exchange_request8.session_policy);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    free(data1);
}

/**
 * Test 21: The key usage bit mask is not set, the SlotID fields in KEY_EXCHANGE and KEY_EXCHANGE_RSP shall not specify this certificate slot
 * Expected Behavior: get a SPDM_ERROR_CODE_INVALID_REQUEST return code
 **/
static void rsp_key_exchange_rsp_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    uint8_t slot_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              0,
                              INVALID_SESSION_ID, false);
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    /* If set, the SlotID fields in KEY_EXCHANGE and KEY_EXCHANGE_RSP can specify this certificate slot. If not set,
     * the SlotID fields in KEY_EXCHANGE and KEY_EXCHANGE_RSP shall not specify this certificate slot */
    slot_id = 0;
    m_libspdm_key_exchange_request10.header.param2 = slot_id;
    spdm_context->local_context.local_key_usage_bit_mask[slot_id] =
        SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
        SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request10.random_data);
    m_libspdm_key_exchange_request10.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request10.reserved = 0;
    m_libspdm_key_exchange_request10.session_policy = 0xFF;
    ptr = m_libspdm_key_exchange_request10.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request10_size,
        &m_libspdm_key_exchange_request10, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);

    free(data1);
}

/**
 * Test 21: The Requester subscribes to all events supported by the Responder.
 * Expected Behavior: Responder successfully subscribes the Requester to all events.
 **/
static void rsp_key_exchange_rsp_case22(void **state)
{
#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;
    spdm_context->connection_info.multi_key_conn_rsp = false;

    libspdm_session_info_init(spdm_context, spdm_context->session_info, INVALID_SESSION_ID,
                              0, false);
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request10.random_data);
    m_libspdm_key_exchange_request10.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request10.reserved = 0;
    m_libspdm_key_exchange_request10.session_policy =
        SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_EVENT_ALL_POLICY;
    ptr = m_libspdm_key_exchange_request10.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request10_size,
        &m_libspdm_key_exchange_request10, &response_size, response);

    assert_int_equal(spdm_context->session_info[0].session_policy,
                     m_libspdm_key_exchange_request10.session_policy);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    assert_true(g_event_all_subscribe && !g_event_all_unsubscribe);
    free(data1);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
static void rsp_key_exchange_rsp_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
    g_key_exchange_start_mut_auth = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    g_mandatory_mut_auth = true;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);

    free(data1);
}


static void rsp_key_exchange_rsp_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
    g_key_exchange_start_mut_auth = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    g_mandatory_mut_auth = true;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request10.random_data);
    m_libspdm_key_exchange_request10.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request10.reserved = 0;
    ptr = m_libspdm_key_exchange_request10.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request10_size,
        &m_libspdm_key_exchange_request10, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_POLICY);
    assert_int_equal(spdm_response->header.param2, 0);

    free(data1);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

/**
 * Test 25: Successful response to a valid KEY_EXCHANGE request.
 * Expected Behavior: get a valid KEY_EXCHANGE_RSP message
 *                    with integrator defined opaque data in the response
 **/
static void rsp_key_exchange_rsp_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    uint16_t opaque_length;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 2;
    g_generate_key_exchange_opaque_data = true;

    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              0,
                              INVALID_SESSION_ID, false);
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request8.random_data);
    m_libspdm_key_exchange_request8.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request8.reserved = 0;
    m_libspdm_key_exchange_request8.session_policy = 0xFF;
    ptr = m_libspdm_key_exchange_request8.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request8_size,
        &m_libspdm_key_exchange_request8, &response_size, response);
    assert_int_equal(spdm_context->session_info[0].session_policy,
                     m_libspdm_key_exchange_request8.session_policy);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    ptr = (uint8_t *)(spdm_response + 1);
    ptr += dhe_key_size;
    opaque_length = *(uint16_t *)ptr;
    assert_int_equal(opaque_length,
                     libspdm_get_opaque_data_version_selection_data_size(spdm_context));

    free(data1);
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
/**
 * Test 26: the Responder requests session-based mutual authentication with MUT_AUTH_REQUESTED
 * (bit 0) and a non-zero ReqSlotID. This is legal when the Responder already possesses the
 * Requester's certificate chain, so no encapsulated flow is needed to retrieve it.
 * Expected behavior: KEY_EXCHANGE_RSP conveys the slot to the Requester, and the slot is recorded
 * in the session so that FINISH is verified against the correct certificate chain.
 **/
static void rsp_key_exchange_rsp_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
    g_key_exchange_start_mut_auth = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    g_mandatory_mut_auth = false;
    /* The Responder already has the Requester's chain in a slot other than 0. */
    g_key_exchange_req_slot_id = 1;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->mut_auth_requested,
                     SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED);
    /* The slot is conveyed to the Requester ... */
    assert_int_equal(spdm_response->req_slot_id_param, 1);

    /* ... and recorded in the session, so FINISH verifies against the right chain. */
    session_info = libspdm_get_session_info_via_session_id(
        spdm_context, spdm_context->latest_session_id);
    assert_non_null(session_info);
    assert_int_equal(session_info->peer_used_cert_chain_slot_id, 1);

    free(data1);
}

/**
 * Test 27: the Requester's PUB_KEY_ID_CAP is set and the Integrator requests session-based mutual
 * authentication with MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST (bit 1). The Requester has no
 * certificate slots, so there is nothing for the encapsulated flow to retrieve.
 * Expected behavior: Responder returns ERROR(Unspecified).
 **/
static void rsp_key_exchange_rsp_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
    g_key_exchange_start_mut_auth =
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
    g_mandatory_mut_auth = false;

    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);

    free(data1);
}

/**
 * Test 28: the Integrator returns a MutAuthRequested value that is not one of the three legal
 * values. The specification allows at most one of Bit 0, Bit 1, or Bit 2 to be set.
 * Expected behavior: Responder returns ERROR(Unspecified) for every illegal value.
 **/
static void rsp_key_exchange_rsp_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    size_t index;
    /* Multiple bits set, then the reserved-bit singletons. A pure "at most one bit" test would
    * accept the latter, so they are what distinguishes the whitelist from a popcount check. */
    const uint8_t illegal_values[] = {0x03, 0x05, 0x06, 0x07, 0x08, 0x10, 0x80, 0xFF};

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    /* Tests in this group share one context and no per-test setup runs, so assign the
     * capability flags rather than OR into whatever a previous test left behind. In particular
     * PUB_KEY_ID_CAP, which an earlier test sets, would reject every value except
     * MUT_AUTH_REQUESTED and mask what this test is checking. */
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    g_mandatory_mut_auth = false;
    spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(illegal_values); index++) {
        g_key_exchange_start_mut_auth = illegal_values[index];

        libspdm_reset_message_a(spdm_context);

        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  m_libspdm_key_exchange_request1.random_data);
        m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
        m_libspdm_key_exchange_request1.reserved = 0;
        ptr = m_libspdm_key_exchange_request1.exchange_data;
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        dhe_context = libspdm_dhe_new(spdm_context->connection_info.version,
                                      m_libspdm_use_dhe_algo, false);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
        ptr += dhe_key_size;
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        opaque_key_exchange_req_size =
            libspdm_get_opaque_data_supported_version_data_size(spdm_context);
        libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_supported_version_data(
            spdm_context, &opaque_key_exchange_req_size, ptr);
        ptr += opaque_key_exchange_req_size;

        response_size = sizeof(response);
        status = libspdm_get_response_key_exchange(
            spdm_context, m_libspdm_key_exchange_request1_size,
            &m_libspdm_key_exchange_request1, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        assert_int_equal(response_size, sizeof(spdm_error_response_t));
        spdm_response = (void *)response;
        assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
        assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
        assert_int_equal(spdm_response->header.param2, 0);
    }

    free(data1);
}

/**
 * Test 29: the SlotIDParam that the Integrator returns alongside MutAuthRequested. It shall be
 * 0xF when the Requester's public key was provisioned to the Responder, 0 through 7 when the
 * Requester has a certificate chain, and 0 for the encapsulated flows, which convey the slot in
 * the final ENCAPSULATED_RESPONSE_ACK instead.
 * Expected behavior: a legal value is returned in KEY_EXCHANGE_RSP and recorded in the session;
 * an illegal one is rejected with ERROR(Unspecified).
 **/
static void rsp_key_exchange_rsp_case29(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    size_t index;
    size_t session_index;
    const struct {
        bool pub_key_id_cap;
        uint8_t mut_auth_requested;
        uint8_t req_slot_id;
        bool legal;
        /* The slot recorded in the session. Only checked when legal. */
        uint8_t peer_slot;
    } cases[] = {
        /* The Requester has a certificate chain, so the slot shall be 0 through 7. */
        { false, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, 0, true, 0 },
        { false, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, SPDM_MAX_SLOT_COUNT - 1, true,
          SPDM_MAX_SLOT_COUNT - 1 },
        { false, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, SPDM_MAX_SLOT_COUNT, false, 0 },
        { false, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, 0xF, false, 0 },
        /* The Requester's public key was provisioned, so the slot shall be 0xF. libspdm records
         * that as 0xFF. */
        { true, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, 0xF, true, 0xFF },
        { true, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, 0, false, 0 },
        /* The encapsulated flows convey the slot separately, so SlotIDParam shall be 0. */
#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
        /* The accepted row starts an encapsulated flow, which the Responder only supports when
         * it is built with LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP. */
        { false, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST, 0, true, 0 },
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
        { false, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST, 1, false, 0 },
        { false, SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS, 1, false, 0 },
    };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;

    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data1,
                                                         &data_size1, NULL, NULL)) {
        return;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(cases); index++) {
        /* Release every session so that the loop does not exhaust them, and clear the
         * encapsulated state that a preceding row starts, which would otherwise answer the next
         * row with ERROR(RequestInFlight). */
        for (session_index = 0; session_index < LIBSPDM_MAX_SESSION_COUNT; session_index++) {
            libspdm_session_info_init(spdm_context, &spdm_context->session_info[session_index],
                                      INVALID_SESSION_ID, 0, false);
        }
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        spdm_context->connection_info.capability.flags |=
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
        if (cases[index].pub_key_id_cap) {
            spdm_context->connection_info.capability.flags |=
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
        } else {
            spdm_context->connection_info.capability.flags &=
                ~(uint32_t)SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
        }
        spdm_context->local_context.capability.flags |=
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
        spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
        spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
        spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
        spdm_context->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
        spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
        spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
        spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                                SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_context->local_context.local_cert_chain_provision[0] = data1;
        spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
        spdm_context->local_context.secured_message_version.secured_message_version_count = 1;

        libspdm_reset_message_a(spdm_context);
        g_key_exchange_start_mut_auth = cases[index].mut_auth_requested;
        g_key_exchange_req_slot_id = cases[index].req_slot_id;
        g_mandatory_mut_auth = false;

        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  m_libspdm_key_exchange_request1.random_data);
        m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
        m_libspdm_key_exchange_request1.reserved = 0;
        ptr = m_libspdm_key_exchange_request1.exchange_data;
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        dhe_context = libspdm_dhe_new(spdm_context->connection_info.version,
                                      m_libspdm_use_dhe_algo, false);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
        ptr += dhe_key_size;
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        opaque_key_exchange_req_size =
            libspdm_get_opaque_data_supported_version_data_size(spdm_context);
        libspdm_write_uint16(ptr, (uint16_t)opaque_key_exchange_req_size);
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_supported_version_data(
            spdm_context, &opaque_key_exchange_req_size, ptr);
        ptr += opaque_key_exchange_req_size;

        response_size = sizeof(response);
        status = libspdm_get_response_key_exchange(
            spdm_context, m_libspdm_key_exchange_request1_size,
            &m_libspdm_key_exchange_request1, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response = (void *)response;

        if (cases[index].legal) {
            assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, spdm_context->latest_session_id);
            assert_non_null(session_info);
            assert_int_equal(session_info->peer_used_cert_chain_slot_id, cases[index].peer_slot);
        } else {
            assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
            assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
            assert_int_equal(spdm_response->header.param2, 0);
        }
    }

    free(data1);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

int libspdm_rsp_key_exchange_rsp_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Success Case*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case1, rsp_key_exchange_rsp_setup),
        /* Bad request size*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case2, rsp_key_exchange_rsp_setup),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case3, rsp_key_exchange_rsp_setup),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case4, rsp_key_exchange_rsp_setup),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case5, rsp_key_exchange_rsp_setup),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* connection_state Check*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case6, rsp_key_exchange_rsp_setup),
        /* Buffer reset*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case7, rsp_key_exchange_rsp_setup),
        /* TCB measurement hash requested */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case8, rsp_key_exchange_rsp_setup),
        /* All measurement hash requested */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case9, rsp_key_exchange_rsp_setup),
        /* Reserved value in Measurement summary. Error + Invalid */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case10, rsp_key_exchange_rsp_setup),
        /* TCB measurement hash requested, measurement flag not set */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case11, rsp_key_exchange_rsp_setup),
        /* Request previously provisioned public key, slot 0xFF */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case14, rsp_key_exchange_rsp_setup),
        /* HANDSHAKE_IN_THE_CLEAR set for requester and responder */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case15, rsp_key_exchange_rsp_setup),
        /* Buffer verification*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case16, rsp_key_exchange_rsp_setup),
        /* Successful response V1.2*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case17, rsp_key_exchange_rsp_setup),
        /* Invalid SlotID in KEY_EXCHANGE request message*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case18, rsp_key_exchange_rsp_setup),
        /* Only OpaqueDataFmt1 is supported, Bytes not aligned*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case19, rsp_key_exchange_rsp_setup),
        /* OpaqueData only supports OpaqueDataFmt1, Success Case */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case20, rsp_key_exchange_rsp_setup),
        /* The key usage bit mask is not set, failed Case*/
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case21, rsp_key_exchange_rsp_setup),
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case22, rsp_key_exchange_rsp_setup),
        #if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
        /* The Responder requires mutual authentication, but the Requester does not support it */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case23, rsp_key_exchange_rsp_setup),
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case24, rsp_key_exchange_rsp_setup),
        #endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
        /* The Responder using integrator defined opaque data */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case25, rsp_key_exchange_rsp_setup),
        #if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
        /* MUT_AUTH_REQUESTED (bit 0) with a non-zero ReqSlotID is recorded in the session */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case26, rsp_key_exchange_rsp_setup),
        /* Only MUT_AUTH_REQUESTED (bit 0) is legal when the Requester's PUB_KEY_ID_CAP is set */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case27, rsp_key_exchange_rsp_setup),
        /* MutAuthRequested values that are not one of the three legal values */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case28, rsp_key_exchange_rsp_setup),
        /* SlotIDParam values that go with each MutAuthRequested value */
        cmocka_unit_test_setup(rsp_key_exchange_rsp_case29, rsp_key_exchange_rsp_setup),
        #endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
