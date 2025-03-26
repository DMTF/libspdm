/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    /* param1 - subcode of the request
     * param2 - Bit[7:4]: reserved
     *          Bit[3:0]: slot_id */
    uint8_t request_attributes;
    uint8_t reserved[3];
    uint8_t nonce[32];
} spdm_get_endpoint_info_request_max_t;
#pragma pack()

/* request signature, correct */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request1 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request1_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* request signature, correct, with slot_id == 0xF */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request2 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0xF},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request2_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* request signature, correct, with slot_id == 0x1 */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request3 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 1},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request3_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* not request signature, correct */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request4 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0},
    0,
    {0, 0, 0},
};
size_t m_libspdm_get_endpoint_info_request4_size =
    sizeof(spdm_get_endpoint_info_request_t);

/**
 * Test 1: Successful response to get endpoint_info with signature
 * Expected Behavior: get a RETURN_SUCCESS return code,
 *                    correct transcript.message_e size,
 *                    correct response message size and fields
 *                    correct signature verification
 **/
void libspdm_test_responder_endpoint_info_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_endpoint_info_response_t *spdm_response;
    uint32_t endpoint_info_size;
    uint8_t endpoint_info_buffer[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    void* signature;
    size_t signature_size;
    bool result;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    session_info = NULL;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif


    libspdm_reset_message_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request1.nonce);

    status = libspdm_get_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request1_size,
        &m_libspdm_get_endpoint_info_request1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    endpoint_info_size = 0;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, endpoint_info_buffer);
    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    assert_int_equal(response_size,
                     sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE +
                     sizeof(uint32_t) + endpoint_info_size + signature_size);
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ENDPOINT_INFO);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_e size check */
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif

    /* signature verification */
    status = libspdm_append_message_e(spdm_context, session_info,
                                      &m_libspdm_get_endpoint_info_request1,
                                      m_libspdm_get_endpoint_info_request1_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_e(spdm_context, session_info, spdm_response,
                                      response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    signature = (void *)((uint8_t *)spdm_response + response_size - signature_size);
    result = libspdm_verify_endpoint_info_signature(
        spdm_context, session_info, true, signature, signature_size);
    assert_true(result);
}

/**
 * Test 2: Successful response to get endpoint_info with signature, slot_id == 0xF
 * Expected Behavior: get a RETURN_SUCCESS return code,
 *                    correct transcript.message_e size,
 *                    correct response message size and fields
 *                    correct signature verification
 **/
void libspdm_test_responder_endpoint_info_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_endpoint_info_response_t *spdm_response;
    uint32_t endpoint_info_size;
    uint8_t endpoint_info_buffer[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    void* signature;
    size_t signature_size;
    bool result;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    session_info = NULL;
    libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data, &data_size);
    spdm_context->local_context.local_public_key_provision = data;
    spdm_context->local_context.local_public_key_provision_size = data_size;
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0xF;
    spdm_context->local_context.peer_public_key_provision = data;
    spdm_context->local_context.peer_public_key_provision_size = data_size;

    libspdm_reset_message_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request2.nonce);

    status = libspdm_get_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request2_size,
        &m_libspdm_get_endpoint_info_request2, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    endpoint_info_size = 0;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, endpoint_info_buffer);
    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    assert_int_equal(response_size,
                     sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE +
                     sizeof(uint32_t) + endpoint_info_size + signature_size);
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ENDPOINT_INFO);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_e size check */
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif

    /* signature verification */
    status = libspdm_append_message_e(spdm_context, session_info,
                                      &m_libspdm_get_endpoint_info_request2,
                                      m_libspdm_get_endpoint_info_request2_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_e(spdm_context, session_info, spdm_response,
                                      response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    signature = (void *)((uint8_t *)spdm_response + response_size - signature_size);
    result = libspdm_verify_endpoint_info_signature(
        spdm_context, session_info, true, signature, signature_size);
    assert_true(result);
}

/**
 * Test 3: Successful response to get endpoint_info with signature,
 *          multi_key_conn_rsp is set, slot_id = 0x1
 * Expected Behavior: get a RETURN_SUCCESS return code,
 *                    correct transcript.message_e size,
 *                    correct response message size and fields
 *                    correct signature verification
 **/
void libspdm_test_responder_endpoint_info_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_endpoint_info_response_t *spdm_response;
    uint32_t endpoint_info_size;
    uint8_t endpoint_info_buffer[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    void* signature;
    size_t signature_size;
    bool result;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    session_info = NULL;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 1;
    spdm_context->connection_info.multi_key_conn_rsp = true;
    spdm_context->local_context.local_key_usage_bit_mask[1] =
        SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[1].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[1].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[1].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[1].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[1].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[1].leaf_cert_public_key);
#endif

    libspdm_reset_message_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request3.nonce);

    status = libspdm_get_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request3_size,
        &m_libspdm_get_endpoint_info_request3, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    endpoint_info_size = 0;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, endpoint_info_buffer);
    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    assert_int_equal(response_size,
                     sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE +
                     sizeof(uint32_t) + endpoint_info_size + signature_size);
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ENDPOINT_INFO);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_e size check */
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif

    /* signature verification */
    status = libspdm_append_message_e(spdm_context, session_info,
                                      &m_libspdm_get_endpoint_info_request3,
                                      m_libspdm_get_endpoint_info_request3_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_e(spdm_context, session_info, spdm_response,
                                      response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    signature = (void *)((uint8_t *)spdm_response + response_size - signature_size);
    result = libspdm_verify_endpoint_info_signature(
        spdm_context, session_info, true, signature, signature_size);
    assert_true(result);
}

/**
 * Test 4: Successful response to get endpoint_info without signature
 * Expected Behavior: get a RETURN_SUCCESS return code,
 *                    correct response message size and fields
 **/
void libspdm_test_responder_endpoint_info_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_endpoint_info_response_t *spdm_response;
    uint32_t endpoint_info_size;
    uint8_t endpoint_info_buffer[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    session_info = NULL;

    libspdm_reset_message_e(spdm_context, session_info);
    response_size = sizeof(response);
    status = libspdm_get_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request4_size,
        &m_libspdm_get_endpoint_info_request4, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    endpoint_info_size = 0;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, endpoint_info_buffer);
    assert_int_equal(response_size,
                     sizeof(spdm_endpoint_info_response_t) +
                     sizeof(uint32_t) + endpoint_info_size);
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ENDPOINT_INFO);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 5: Successful response to get session-based endpoint_info with signature
 * Expected Behavior: get a RETURN_SUCCESS return code,
 *                    correct transcript.message_e size,
 *                    correct response message size and fields
 *                    correct signature verification
 **/
void libspdm_test_responder_endpoint_info_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_endpoint_info_response_t *spdm_response;
    uint32_t endpoint_info_size;
    uint8_t endpoint_info_buffer[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    void* signature;
    size_t signature_size;
    bool result;
    void *data;
    size_t data_size;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.multi_key_conn_rsp = false;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif


    libspdm_reset_message_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request1.nonce);

    status = libspdm_get_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request1_size,
        &m_libspdm_get_endpoint_info_request1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    endpoint_info_size = 0;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, endpoint_info_buffer);
    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    assert_int_equal(response_size,
                     sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE +
                     sizeof(uint32_t) + endpoint_info_size + signature_size);
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ENDPOINT_INFO);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_e size check */
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif

    /* signature verification */
    status = libspdm_append_message_e(spdm_context, session_info,
                                      &m_libspdm_get_endpoint_info_request1,
                                      m_libspdm_get_endpoint_info_request1_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_e(spdm_context, session_info, spdm_response,
                                      response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    signature = (void *)((uint8_t *)spdm_response + response_size - signature_size);
    result = libspdm_verify_endpoint_info_signature(
        spdm_context, session_info, true, signature, signature_size);
    assert_true(result);
}

int libspdm_responder_endpoint_info_test_main(void)
{
    const struct CMUnitTest spdm_responder_endpoint_info_tests[] = {
        cmocka_unit_test(libspdm_test_responder_endpoint_info_case1),
        cmocka_unit_test(libspdm_test_responder_endpoint_info_case2),
        cmocka_unit_test(libspdm_test_responder_endpoint_info_case3),
        cmocka_unit_test(libspdm_test_responder_endpoint_info_case4),
        cmocka_unit_test(libspdm_test_responder_endpoint_info_case5),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(spdm_responder_endpoint_info_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP*/
