/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT) && \
    (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)

#define LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE 0x20

static uint8_t m_endpoint_info_buffer_receive[LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE];
static uint8_t m_endpoint_info_buffer_send[LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE];

/**
 * Test 1: Normal case, request a endpoint info with signature
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code, correct endpoint_info
 *                    and an empty transcript.message_encap_e
 **/
static void rsp_encap_get_endpoint_info_case1(void **state)
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
    spdm_test_context->case_id = 0x1;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->encap_context.payload_buffer = m_endpoint_info_buffer_send;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_endpoint_info_buffer_send);
    spdm_context->encap_context.payload_buffer_size = 0;

    if (!libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_req_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        return;
    }
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

    /* Subcase 1: slot_id = 0 */
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.req_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    SPDM_NONCE_SIZE + sizeof(uint32_t) +
                    endpoint_info_size + sig_size;

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

    libspdm_write_uint32(ptr, endpoint_info_size); /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size, m_endpoint_info_buffer_receive, endpoint_info_size);
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
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (uint32_t index = 0; index < endpoint_info_size; index++) {
        assert_int_equal (m_endpoint_info_buffer_receive[index],
                          m_endpoint_info_buffer_send[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets mut IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_encap_il1il2);
#endif


    /* Subcase 2: slot_id = 1 */
    spdm_context->encap_context.req_slot_id = 1;
    spdm_context->encap_context.req_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    SPDM_NONCE_SIZE + sizeof(uint32_t) +
                    endpoint_info_size + sig_size;

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

    libspdm_write_uint32(ptr, endpoint_info_size); /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size, m_endpoint_info_buffer_receive, endpoint_info_size);
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
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (uint32_t index = 0; index < endpoint_info_size; index++) {
        assert_int_equal (m_endpoint_info_buffer_receive[index],
                          m_endpoint_info_buffer_send[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets mut IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_encap_il1il2);
#endif
}

/**
 * Test 2: Normal case, request a endpoint info with signature, req_slot_id = 0xF
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code, correct endpoint_info
 *                    and an empty transcript.message_encap_e
 **/
static void rsp_encap_get_endpoint_info_case2(void **state)
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
    spdm_test_context->case_id = 0x2;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->encap_context.payload_buffer = m_endpoint_info_buffer_send;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_endpoint_info_buffer_send);
    spdm_context->encap_context.payload_buffer_size = 0;

    if (!libspdm_read_requester_public_key(m_libspdm_use_req_asym_algo, &data, &data_size)) {
        return;
    }
    spdm_context->local_context.peer_public_key_provision = data;
    spdm_context->local_context.peer_public_key_provision_size = data_size;

    spdm_context->encap_context.req_slot_id = 0xF;
    spdm_context->encap_context.req_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    SPDM_NONCE_SIZE + sizeof(uint32_t) +
                    endpoint_info_size + sig_size;

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

    libspdm_write_uint32(ptr, endpoint_info_size); /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size, m_endpoint_info_buffer_receive, endpoint_info_size);
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
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (uint32_t index = 0; index < endpoint_info_size; index++) {
        assert_int_equal (m_endpoint_info_buffer_receive[index],
                          m_endpoint_info_buffer_send[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets mut IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_encap_il1il2);
#endif
}

/**
 * Test 3: Normal case, request a endpoint info without signature
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code, correct endpoint_info
 **/
static void rsp_encap_get_endpoint_info_case3(void **state)
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

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x3;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG;
    spdm_context->encap_context.payload_buffer = m_endpoint_info_buffer_send;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_endpoint_info_buffer_send);
    spdm_context->encap_context.payload_buffer_size = 0;

    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.req_attributes = 0;
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
    spdm_response->header.param2 = spdm_context->encap_context.req_slot_id &
                                   SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK;
    spdm_response->reserved = 0;

    ptr = (void *)(spdm_response + 1);
    libspdm_write_uint32(ptr, endpoint_info_size); /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size, m_endpoint_info_buffer_receive, endpoint_info_size);
    ptr += endpoint_info_size;

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (uint32_t index = 0; index < endpoint_info_size; index++) {
        assert_int_equal (m_endpoint_info_buffer_receive[index],
                          m_endpoint_info_buffer_send[index]);
    }
}

/**
 * Test 4: Normal case, request a endpoint info with signature within session
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code, correct endpoint_info
 *                    and an empty session_transcript.message_encap_e
 **/
static void rsp_encap_get_endpoint_info_case4(void **state)
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
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x4;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->encap_context.payload_buffer = m_endpoint_info_buffer_send;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_endpoint_info_buffer_send);
    spdm_context->encap_context.payload_buffer_size = 0;

    if (!libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_req_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        return;
    }

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_encap_e(spdm_context, session_info);

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
    spdm_context->encap_context.req_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);

    response_size = sizeof(spdm_endpoint_info_response_t) +
                    SPDM_NONCE_SIZE + sizeof(uint32_t) +
                    endpoint_info_size + sig_size;

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

    libspdm_write_uint32(ptr, endpoint_info_size); /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size, m_endpoint_info_buffer_receive, endpoint_info_size);
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
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (uint32_t index = 0; index < endpoint_info_size; index++) {
        assert_int_equal (m_endpoint_info_buffer_receive[index],
                          m_endpoint_info_buffer_send[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets mut IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_encap_e.buffer_size, 0);
#else
    assert_null(session_info->session_transcript.digest_context_encap_il1il2);
#endif
}

/**
 * Test 5: Normal case, request an endpoint info without a signature while the Requester's
 * EP_INFO_CAP_SIG is set.
 * Expected Behavior: get a LIBSPDM_STATUS_SUCCESS return code and correct endpoint_info. The
 * response is processed according to the RequestAttributes that were sent, not the Requester's
 * capability.
 **/
static void rsp_encap_get_endpoint_info_case5(void **state)
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

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x5;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    /* The Requester can sign, but the Integrator did not ask for a signature. */
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->encap_context.payload_buffer = m_endpoint_info_buffer_send;
    spdm_context->encap_context.payload_buffer_max_size = sizeof(m_endpoint_info_buffer_send);
    spdm_context->encap_context.payload_buffer_size = 0;

    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.req_attributes = 0;
    endpoint_info_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_size, m_endpoint_info_buffer_receive);

    response_size = sizeof(spdm_endpoint_info_response_t) + sizeof(uint32_t) + endpoint_info_size;

    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = spdm_context->encap_context.req_slot_id &
                                   SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK;
    spdm_response->reserved = 0;

    ptr = (void *)(spdm_response + 1);
    libspdm_write_uint32(ptr, endpoint_info_size); /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size, m_endpoint_info_buffer_receive, endpoint_info_size);
    ptr += endpoint_info_size;

    status = libspdm_process_encap_response_endpoint_info(spdm_context, response_size,
                                                          spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (uint32_t index = 0; index < endpoint_info_size; index++) {
        assert_int_equal (m_endpoint_info_buffer_receive[index],
                          m_endpoint_info_buffer_send[index]);
    }
}

/**
 * Test 6: the Integrator supplies the endpoint information buffer at the call site, and reads the
 * retrieved size back with libspdm_get_encap_payload_size.
 * Expected Behavior: a NULL buffer or a zero size is rejected with
 * LIBSPDM_STATUS_INVALID_PARAMETER, and a successful call records the buffer and resets the size.
 **/
static void rsp_encap_get_endpoint_info_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t encap_request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t encap_request_size;
    size_t payload_size;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x6;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG;
    spdm_context->last_spdm_request_session_id_valid = false;

    /* The buffer is mandatory. */
    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_get_endpoint_info(
        spdm_context, NULL, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0, 0,
        sizeof(m_endpoint_info_buffer_send), NULL, &encap_request_size, encap_request);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_get_endpoint_info(
        spdm_context, NULL, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0, 0,
        0, m_endpoint_info_buffer_send, &encap_request_size, encap_request);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    /* A successful call records the buffer and discards any earlier payload. */
    spdm_context->encap_context.payload_buffer_size = 0x1234;
    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_get_endpoint_info(
        spdm_context, NULL, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0, 0,
        sizeof(m_endpoint_info_buffer_send), m_endpoint_info_buffer_send,
        &encap_request_size, encap_request);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(spdm_context->encap_context.payload_buffer, m_endpoint_info_buffer_send);
    assert_int_equal(spdm_context->encap_context.payload_buffer_max_size,
                     sizeof(m_endpoint_info_buffer_send));

    payload_size = 0xFFFF;
    status = libspdm_get_encap_payload_size(spdm_context, NULL, &payload_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(payload_size, 0);
}

/**
 * Test 8: the slot of the Requester's certificate chain is bounds-checked.
 * Expected Behavior: a slot that is not less than SPDM_MAX_SLOT_COUNT is rejected with
 * LIBSPDM_STATUS_INVALID_PARAMETER before anything is recorded, as ENDPOINT_INFO would otherwise be
 * verified against per-slot state that has no such entry. SlotID is a four-bit field, so 0xFF is
 * rejected too. 0xF, which designates the Requester's provisioned public key, and the highest valid
 * slot are accepted and placed in the request.
 **/
static void rsp_encap_get_endpoint_info_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    const spdm_get_endpoint_info_request_t *spdm_request;
    uint8_t encap_request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t encap_request_size;
    size_t index;
    const uint8_t invalid_slot_id[] = { SPDM_MAX_SLOT_COUNT, 0xE, 0xFF };
    const uint8_t valid_slot_id[] = { SPDM_MAX_SLOT_COUNT - 1, 0xF };

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x8;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->last_spdm_request_session_id_valid = false;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(invalid_slot_id); index++) {
        spdm_context->encap_context.req_slot_id = 0;
        spdm_context->encap_context.payload_buffer = NULL;

        encap_request_size = sizeof(encap_request);
        status = libspdm_get_encap_request_get_endpoint_info(
            spdm_context, NULL, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
            invalid_slot_id[index], SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
            sizeof(m_endpoint_info_buffer_send), m_endpoint_info_buffer_send,
            &encap_request_size, encap_request);
        assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

        /* Neither the slot nor the buffer was recorded. */
        assert_int_equal(spdm_context->encap_context.req_slot_id, 0);
        assert_null(spdm_context->encap_context.payload_buffer);
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(valid_slot_id); index++) {
        libspdm_reset_message_encap_e(spdm_context, NULL);

        encap_request_size = sizeof(encap_request);
        status = libspdm_get_encap_request_get_endpoint_info(
            spdm_context, NULL, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
            valid_slot_id[index], SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
            sizeof(m_endpoint_info_buffer_send), m_endpoint_info_buffer_send,
            &encap_request_size, encap_request);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_request = (const void *)encap_request;
        assert_int_equal(spdm_request->header.param2, valid_slot_id[index]);
        assert_int_equal(spdm_context->encap_context.req_slot_id, valid_slot_id[index]);
    }

    libspdm_reset_message_encap_e(spdm_context, NULL);
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.payload_buffer = m_endpoint_info_buffer_send;
}

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/**
 * Test 9: an encapsulated GET_ENDPOINT_INFO that requests a signature starts a fresh IL1/IL2
 * transcript.
 * Expected Behavior: a request left behind by an exchange that never completed, such as one the
 * Requester answered with an ERROR, is discarded rather than being signed over. Outside a session
 * that leftover state is connection-scoped, so it would otherwise persist for the whole connection.
 **/
static void rsp_encap_get_endpoint_info_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t encap_request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t encap_request_size;
    uint8_t stale[16];

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x9;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->last_spdm_request_session_id_valid = false;

    /* Stand in for the request of an exchange that was abandoned before its response arrived. */
    libspdm_reset_message_encap_e(spdm_context, NULL);
    libspdm_set_mem(stale, sizeof(stale), 0xAA);
    status = libspdm_append_message_encap_e(spdm_context, NULL, stale, sizeof(stale));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(libspdm_get_managed_buffer_size(&spdm_context->transcript.message_encap_e),
                     sizeof(stale));

    encap_request_size = sizeof(encap_request);
    status = libspdm_get_encap_request_get_endpoint_info(
        spdm_context, NULL, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        sizeof(m_endpoint_info_buffer_send), m_endpoint_info_buffer_send,
        &encap_request_size, encap_request);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* The transcript holds the new request and nothing else. */
    assert_int_equal(libspdm_get_managed_buffer_size(&spdm_context->transcript.message_encap_e),
                     encap_request_size);

    libspdm_reset_message_encap_e(spdm_context, NULL);
}
#endif /* LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT */

int libspdm_rsp_encap_get_endpoint_info_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Success request endpoint info with signature */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case1),
        /* Success request endpoint info with signature, req_slot_id = 0xF */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case2),
        /* Success request endpoint info without signature */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case3),
        /* Success request endpoint info with signature in a session */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case4),
        /* no signature requested while the Requester's EP_INFO_CAP_SIG is set */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case5),
        /* The endpoint information buffer is supplied at the call site */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case6),
        /* The slot of the Requester's certificate chain is bounds-checked */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case8),
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        /* A signed request starts a fresh IL1/IL2 transcript */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case9),
#endif /* LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT */
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
