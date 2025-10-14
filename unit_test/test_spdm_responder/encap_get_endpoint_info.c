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
static uint8_t m_endpoint_info_buffer_send[LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE];

libspdm_return_t get_endpoint_info_callback (
    void *spdm_context,
    uint8_t subcode,
    uint8_t param2,
    uint8_t request_attributes,
    uint32_t endpoint_info_size,
    const void *endpoint_info)
{
    LIBSPDM_ASSERT (endpoint_info_size <= LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE);
    libspdm_copy_mem (m_endpoint_info_buffer_send, endpoint_info_size,
                      endpoint_info, endpoint_info_size);
    return LIBSPDM_STATUS_SUCCESS;
}

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
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback;

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

    /* Subcase 1: slot_id = 0 */
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
 * Test 2: Normal case, request a endpoint info with signature, req_slot_id = 0xFF
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
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback;

    libspdm_read_requester_public_key(m_libspdm_use_req_asym_algo, &data, &data_size);
    spdm_context->local_context.peer_public_key_provision = data;
    spdm_context->local_context.peer_public_key_provision_size = data_size;

    spdm_context->encap_context.req_slot_id = 0xFF;
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
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback;

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
    spdm_response->header.param2 = spdm_context->encap_context.req_slot_id &
                                   SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK;
    spdm_response->reserved = 0;

    ptr = (void *)(spdm_response + 1);
    *(uint32_t *)ptr = endpoint_info_size; /* ep_info_len */
    ptr += sizeof(uint32_t);

    libspdm_copy_mem(ptr, endpoint_info_size,
                     m_endpoint_info_buffer_receive, endpoint_info_size);
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
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback;

    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size, NULL, NULL);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;

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

int libspdm_rsp_encap_get_endpoint_info_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Success requeset endpoint info with signature */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case1),
        /* Success requeset endpoint info with signature, req_slot_id = 0xFF */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case2),
        /* Success requeset endpoint info without signature */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case3),
        /* Success requeset endpoint info with signature in a session */
        cmocka_unit_test(rsp_encap_get_endpoint_info_case4),
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
