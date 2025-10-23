/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT) && \
    (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)

#define LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE 0x20

static uint8_t m_endpoint_info_buffer_receive[LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE];

libspdm_return_t get_endpoint_info_callback_in_err (
    void *spdm_context,
    uint8_t subcode,
    uint8_t param2,
    uint8_t request_attributes,
    uint32_t endpoint_info_size,
    const void *endpoint_info)
{
    /* should never reach here */
    LIBSPDM_ASSERT (0);
    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

/**
 * Test 1: Error case, get an error response
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 *                    with an empty transcript.message_e
 **/
void libspdm_test_responder_encap_get_endpoint_info_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_SENDER_BUFFER_SIZE];
    bool need_continue;
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x1;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback_in_err;

    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_encap_e(spdm_context, NULL);

    for (uint32_t index = 0; index < 2; index++) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_size = data_size;
        libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[index].buffer,
                         sizeof(spdm_context->connection_info.peer_used_cert_chain[index].buffer),
                         data, data_size);
#else
        libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            data, data_size,
            spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash);
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash_size =
            libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
        libspdm_get_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            data, data_size,
            &spdm_context->connection_info.peer_used_cert_chain[index].leaf_cert_public_key);
#endif
    }
    spdm_context->encap_context.req_slot_id = 0;

    response_size = sizeof(spdm_error_response_t);

    spdm_response = (void *)temp_buf;

    /* Subcase 1: SPDM_ERROR_CODE_INVALID_REQUEST */
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    spdm_response->header.param2 = 0;

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif

    /* Subcase 2: SPDM_ERROR_CODE_UNSUPPORTED_REQUEST */
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = SPDM_ERROR_CODE_UNSUPPORTED_REQUEST;
    spdm_response->header.param2 = SPDM_GET_ENDPOINT_INFO;

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 2: Error case, get incorrect response
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 *                    with an empty transcript.message_e
 **/
void libspdm_test_responder_encap_get_endpoint_info_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_endpoint_info_response_t *spdm_response;
    uint8_t temp_buf_valid[LIBSPDM_SENDER_BUFFER_SIZE];
    uint8_t temp_buf_error[LIBSPDM_SENDER_BUFFER_SIZE];
    bool need_continue;
    uint8_t *ptr;
    size_t sig_size;
    size_t response_size;
    uint32_t endpoint_info_size;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x2;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback_in_err;

    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_encap_e(spdm_context, NULL);

    for (uint32_t index = 0; index < 2; index++) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_size = data_size;
        libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[index].buffer,
                         sizeof(spdm_context->connection_info.peer_used_cert_chain[index].buffer),
                         data, data_size);
#else
        libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            data, data_size,
            spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash);
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash_size =
            libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
        libspdm_get_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            data, data_size,
            &spdm_context->connection_info.peer_used_cert_chain[index].leaf_cert_public_key);
#endif
    }
    spdm_context->encap_context.req_slot_id = 0;

    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    SPDM_NONCE_SIZE + sizeof(uint32_t) +
                    endpoint_info_size + sig_size;

    /* create a valid response */
    spdm_response = (void *)temp_buf_valid;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = spdm_context->encap_context.req_slot_id &
                                   SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK;
    spdm_response->reserved = 0;

    ptr = (void *)(spdm_response + 1);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;

    *(uint32_t *)ptr = endpoint_info_size; /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size,
                     m_endpoint_info_buffer_receive, endpoint_info_size);
    ptr += endpoint_info_size;

    libspdm_requester_data_sign(
        spdm_context,
        spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            0, SPDM_ENDPOINT_INFO,
            m_libspdm_use_req_asym_algo, m_libspdm_use_req_pqc_asym_algo, m_libspdm_use_hash_algo,
            false, (uint8_t*)spdm_response, response_size - sig_size,
            ptr, &sig_size);

    /* Subcase 1: wrong version */
    libspdm_copy_mem(temp_buf_error, response_size,
                     temp_buf_valid, response_size);
    spdm_response = (void *)temp_buf_error;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif

    /* Subcase 2: wrong response code */
    libspdm_copy_mem(temp_buf_error, response_size,
                     temp_buf_valid, response_size);
    spdm_response = (void *)temp_buf_error;
    spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO + 1;

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif

    /* Subcase 3: wrong slot_id */
    libspdm_copy_mem(temp_buf_error, response_size,
                     temp_buf_valid, response_size);
    spdm_response = (void *)temp_buf_error;
    spdm_response->header.param2 = 0x1; /* slot_id = 1 */

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif

    /* Subcase 4: wrong ep_info_len */
    libspdm_copy_mem(temp_buf_error, response_size,
                     temp_buf_valid, response_size);
    spdm_response = (void *)temp_buf_error;
    ptr = (void *)(spdm_response + 1);
    ptr += SPDM_NONCE_SIZE;
    *(uint32_t *)ptr = endpoint_info_size + 1; /* ep_info_len */

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif

    /* Subcase 5: wrong signature */
    libspdm_copy_mem(temp_buf_error, response_size,
                     temp_buf_valid, response_size);
    spdm_response = (void *)temp_buf_error;
    ptr = (void *)(spdm_response + 1);
    ptr += SPDM_NONCE_SIZE + sizeof(uint32_t) + endpoint_info_size;
    libspdm_get_random_number(sig_size, ptr);

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 3: Error case, request signature but get response without signature
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 *                    with an empty transcript.message_e
 **/
void libspdm_test_responder_encap_get_endpoint_info_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_endpoint_info_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_SENDER_BUFFER_SIZE];
    bool need_continue;
    uint8_t *ptr;
    size_t response_size;
    uint32_t endpoint_info_size;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x3;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback_in_err;

    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_encap_e(spdm_context, NULL);

    for (uint32_t index = 0; index < 2; index++) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_size = data_size;
        libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[index].buffer,
                         sizeof(spdm_context->connection_info.peer_used_cert_chain[index].buffer),
                         data, data_size);
#else
        libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            data, data_size,
            spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash);
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash_size =
            libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
        libspdm_get_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            data, data_size,
            &spdm_context->connection_info.peer_used_cert_chain[index].leaf_cert_public_key);
#endif
    }
    spdm_context->encap_context.req_slot_id = 0;

    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    sizeof(uint32_t) + endpoint_info_size;

    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->reserved = 0;

    ptr = (void *)(spdm_response + 1);
    *(uint32_t *)ptr = endpoint_info_size; /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size,
                     m_endpoint_info_buffer_receive, endpoint_info_size);

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 4: Error case, request no signature but get response with signature
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_responder_encap_get_endpoint_info_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_endpoint_info_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_SENDER_BUFFER_SIZE];
    bool need_continue;
    uint8_t *ptr;
    size_t sig_size;
    size_t response_size;
    uint32_t endpoint_info_size;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x4;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG; /* no signature */
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback_in_err;

    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_encap_e(spdm_context, NULL);

    for (uint32_t index = 0; index < 2; index++) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_size = data_size;
        libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[index].buffer,
                         sizeof(spdm_context->connection_info.peer_used_cert_chain[index].buffer),
                         data, data_size);
#else
        libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            data, data_size,
            spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash);
        spdm_context->connection_info.peer_used_cert_chain[index].buffer_hash_size =
            libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
        libspdm_get_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            data, data_size,
            &spdm_context->connection_info.peer_used_cert_chain[index].leaf_cert_public_key);
#endif
    }
    spdm_context->encap_context.req_slot_id = 0;

    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    SPDM_NONCE_SIZE + sizeof(uint32_t) +
                    endpoint_info_size + sig_size;

    /* create a valid response */
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = spdm_context->encap_context.req_slot_id &
                                   SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK;
    spdm_response->reserved = 0;

    ptr = (void *)(spdm_response + 1);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;

    *(uint32_t *)ptr = endpoint_info_size; /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size,
                     m_endpoint_info_buffer_receive, endpoint_info_size);
    ptr += endpoint_info_size;

    libspdm_requester_data_sign(
        spdm_context,
        spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            0, SPDM_ENDPOINT_INFO,
            m_libspdm_use_req_asym_algo, m_libspdm_use_req_pqc_asym_algo, m_libspdm_use_hash_algo,
            false, (uint8_t*)spdm_response, response_size - sig_size,
            ptr, &sig_size);

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 5: Error case, get incorrect response when request no signature
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_responder_encap_get_endpoint_info_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_endpoint_info_response_t *spdm_response;
    uint8_t temp_buf_valid[LIBSPDM_SENDER_BUFFER_SIZE];
    uint8_t temp_buf_error[LIBSPDM_SENDER_BUFFER_SIZE];
    bool need_continue;
    uint8_t *ptr;
    size_t response_size;
    uint32_t endpoint_info_size;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x5;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG; /* no signature */
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback_in_err;

    spdm_context->encap_context.req_slot_id = 0;

    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    sizeof(uint32_t) + endpoint_info_size;

    /* create a valid response */
    spdm_response = (void *)temp_buf_valid;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->reserved = 0;

    ptr = (void *)(spdm_response + 1);
    *(uint32_t *)ptr = endpoint_info_size; /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size,
                     m_endpoint_info_buffer_receive, endpoint_info_size);
    ptr += endpoint_info_size;

    /* Subcase 1: wrong slot id */
    libspdm_copy_mem(temp_buf_error, response_size,
                     temp_buf_valid, response_size);
    spdm_response = (void *)temp_buf_error;
    spdm_response->header.param2 = 0x1; /* slot_id = 1 */

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Subcase 2: wrong ep_info_len */
    libspdm_copy_mem(temp_buf_error, response_size,
                     temp_buf_valid, response_size);
    spdm_response = (void *)temp_buf_error;
    ptr = (void *)(spdm_response + 1);
    *(uint32_t *)ptr = endpoint_info_size + 1; /* ep_info_len */
    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}


int libspdm_rsp_encap_get_endpoint_info_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Get an error response */
        cmocka_unit_test(libspdm_test_responder_encap_get_endpoint_info_err_case1),
        /* Get an incorrect response */
        cmocka_unit_test(libspdm_test_responder_encap_get_endpoint_info_err_case2),
        /* Request signature but get response without signature */
        cmocka_unit_test(libspdm_test_responder_encap_get_endpoint_info_err_case3),
        /* Request no signature but get response with signature */
        cmocka_unit_test(libspdm_test_responder_encap_get_endpoint_info_err_case4),
        /* Request no signature and get incorrect response */
        cmocka_unit_test(libspdm_test_responder_encap_get_endpoint_info_err_case5),
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

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (...) */
