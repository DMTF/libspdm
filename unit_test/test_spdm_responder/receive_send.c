/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

#define CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE (64)

typedef struct {
    spdm_message_header_t header;
    /* param1 == RSVD
     * param2 == RSVD*/
    uint16_t standard_id;
    uint8_t len;
    /*uint8_t                vendor_id[len];*/
    uint16_t payload_length;
    /* uint8_t                vendor_defined_payload[payload_length];*/
} my_spdm_vendor_defined_request_msg_t;


libspdm_return_t my_test_get_response_func(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response)
{
    /* response message size is greater than the sending transmit buffer size of responder */
    *response_size = CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE + 1;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t my_test_get_response_func2(
    void *spdm_context,
    const uint32_t *session_id,
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint32_t req_size,
    const void *req_data,
    uint32_t *resp_size,
    void *resp_data)
{
    /* response message size is greater than the sending transmit buffer size of responder */
    *resp_size = CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE + 1;
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: Test Responder Receive Send flow triggers chunk get mode
 * if response buffer is larger than requester data_transfer_size.
 **/
static void libspdm_test_responder_receive_send_rsp_case1(void** state)
{
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    /* This test case is partially copied from test_requester_get_measurement_case4 */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    spdm_get_measurements_request_t spdm_request;
    void* message;
    size_t message_size;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;
    uint32_t transport_header_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    if (!libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo,
            m_libspdm_use_asym_algo, &data,
            &data_size,
            &hash, &hash_size)) {
        return;
    }

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    libspdm_reset_message_m(spdm_context, NULL);

    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(
        spdm_context->connection_info.peer_used_cert_chain[0].buffer,
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

    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    spdm_request.header.param2 =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
    spdm_request.slot_id_param = 0;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned error large response with chunk_handle == 1
     * and responder is in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_LARGE_RESPONSE);
    assert_int_equal(spdm_response->header.param2, 0);

    chunk_handle = *(uint8_t*)(spdm_response + 1);
    assert_int_equal(chunk_handle, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, true);
    libspdm_release_sender_buffer(spdm_context);

    free(data);
    libspdm_reset_message_m(spdm_context, NULL);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    #endif
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
}

/**
 * Test 2: Test Responder Receive Send flow triggers chunk get mode
 * if response message size is larger than responder sending transmit buffer size.
 **/
static void libspdm_test_responder_receive_send_rsp_case2(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    my_spdm_vendor_defined_request_msg_t spdm_request;
    void* message;
    size_t message_size;
    uint32_t transport_header_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    /* The local Responder transmit buffer size for sending a single and complete SPDM message */
    spdm_context->local_context.capability.sender_data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;
    /* The peer Requester buffer size for receiving a single and complete SPDM message */
    spdm_context->connection_info.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);

    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    /* Make response message size greater than the sending transmit buffer size of responder */
    spdm_context->get_response_func = (void *)my_test_get_response_func;

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned error large response with chunk_handle == 1
     * and responder is in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_LARGE_RESPONSE);
    assert_int_equal(spdm_response->header.param2, 0);

    chunk_handle = *(uint8_t*)(spdm_response + 1);
    assert_int_equal(chunk_handle, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, true);
    libspdm_release_sender_buffer(spdm_context);
}


#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
/**
 * Test 3: Test Responder Receive Send flow triggers chunk get mode
 * if response message size is larger than responder sending transmit buffer size.
 **/
static void libspdm_test_responder_receive_send_rsp_case3(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    my_spdm_vendor_defined_request_msg_t spdm_request;
    void* message;
    size_t message_size;
    uint32_t transport_header_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    /* The local Responder transmit buffer size for sending a single and complete SPDM message */
    spdm_context->local_context.capability.sender_data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;
    /* The peer Requester buffer size for receiving a single and complete SPDM message */
    spdm_context->connection_info.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);

    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    /* Make response message size greater than the sending transmit buffer size of responder */
    libspdm_register_vendor_callback_func(spdm_context, my_test_get_response_func2);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned error large response with chunk_handle == 1
     * and responder is in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_LARGE_RESPONSE);
    assert_int_equal(spdm_response->header.param2, 0);

    chunk_handle = *(uint8_t*)(spdm_response + 1);
    assert_int_equal(chunk_handle, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, true);
    libspdm_release_sender_buffer(spdm_context);
}
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

/**
 * Test 4: Test Responder Receive Send flow triggers chunk get mode
 * if response buffer is larger than requester max_spdm_msg_size.
 * expect: SPDM_ERROR_CODE_RESPONSE_TOO_LARGE
 **/
static void libspdm_test_responder_receive_send_rsp_case4(void** state)
{
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    /* This test case is partially copied from test_requester_get_measurement_case4 */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    spdm_get_measurements_request_t spdm_request;
    void* message;
    size_t message_size;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    if (!libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo,
            m_libspdm_use_asym_algo, &data,
            &data_size,
            &hash, &hash_size)) {
        return;
    }

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    libspdm_reset_message_m(spdm_context, NULL);

    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(
        spdm_context->connection_info.peer_used_cert_chain[0].buffer,
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

    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;

    /*set requester small max_spdm_msg_size*/
    spdm_context->connection_info.capability.max_spdm_msg_size = 100;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    spdm_request.header.param2 =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
    spdm_request.slot_id_param = 0;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned SPDM_ERROR_CODE_RESPONSE_TOO_LARGE response with chunk_handle == 0
     * and responder is not in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);

    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_TOO_LARGE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(0, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_release_sender_buffer(spdm_context);

    free(data);
    libspdm_reset_message_m(spdm_context, NULL);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    #endif
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
}

/**
 * Test 5: During an active chunk GET transfer, a non-chunk, non-GET_VERSION
 * request should be rejected with UnexpectedRequest error, and
 * the chunk transfer sequence should NOT be terminated.
 **/
static void libspdm_test_responder_receive_send_rsp_case5(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t *response;
    spdm_error_response_t *spdm_response;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    uint32_t transport_header_size;
    uint8_t saved_chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.data_transfer_size =
        LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size =
        LIBSPDM_MAX_SPDM_MSG_SIZE;

    /* Simulate an active chunk GET transfer. */
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = 1;
    spdm_context->chunk_context.get.chunk_seq_no = 2;
    saved_chunk_handle = spdm_context->chunk_context.get.chunk_handle;

    /* Send a GET_CAPABILITIES request (non-chunk, non-GET_VERSION). */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.request_response_code = SPDM_GET_CAPABILITIES;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false,
                                    &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    transport_header_size =
        spdm_context->local_context.capability.transport_header_size;
    spdm_response = (spdm_error_response_t *)((uint8_t *)message + transport_header_size);

    /* Verify error UnexpectedRequest is returned. */
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);

    /* Verify chunk transfer sequence is NOT terminated. */
    assert_true(spdm_context->chunk_context.get.chunk_in_use);
    assert_int_equal(spdm_context->chunk_context.get.chunk_handle,
                     saved_chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_seq_no, 2);

    libspdm_release_sender_buffer(spdm_context);

    /* Clean up chunk state for subsequent tests. */
    spdm_context->chunk_context.get.chunk_in_use = false;
}

/**
 * Test 6: During an active chunk GET transfer, a GET_VERSION request
 * should be allowed to interrupt: the chunk transfer should be
 * terminated and GET_VERSION processed normally.
 **/
static void libspdm_test_responder_receive_send_rsp_case6(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t *response;
    spdm_message_header_t *spdm_response;
    spdm_get_version_request_t spdm_request;
    void *message;
    size_t message_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.data_transfer_size =
        LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size =
        LIBSPDM_MAX_SPDM_MSG_SIZE;

    /* Simulate an active chunk GET transfer. */
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = 1;
    spdm_context->chunk_context.get.chunk_seq_no = 2;

    /* Send a GET_VERSION request. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false,
                                    &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    transport_header_size =
        spdm_context->local_context.capability.transport_header_size;
    spdm_response = (spdm_message_header_t *)((uint8_t *)message + transport_header_size);

    /* Verify GET_VERSION was processed: response should be VERSION. */
    assert_int_equal(spdm_response->request_response_code, SPDM_VERSION);

    /* Verify chunk transfer was terminated. */
    assert_false(spdm_context->chunk_context.get.chunk_in_use);
    assert_int_equal(spdm_context->chunk_context.get.chunk_seq_no, 0);

    libspdm_release_sender_buffer(spdm_context);
}

/**
 * Test 7: During an active chunk SEND transfer, a non-chunk, non-GET_VERSION
 * request should be rejected with UnexpectedRequest error, and
 * the chunk transfer sequence should NOT be terminated.
 **/
static void libspdm_test_responder_receive_send_rsp_case7(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t *response;
    spdm_error_response_t *spdm_response;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.data_transfer_size =
        LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size =
        LIBSPDM_MAX_SPDM_MSG_SIZE;

    /* Simulate an active chunk SEND transfer. */
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = 1;
    spdm_context->chunk_context.send.chunk_seq_no = 3;

    /* Send a GET_CAPABILITIES request (non-chunk, non-GET_VERSION). */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.request_response_code = SPDM_GET_CAPABILITIES;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false,
                                    &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    transport_header_size =
        spdm_context->local_context.capability.transport_header_size;
    spdm_response = (spdm_error_response_t *)((uint8_t *)message + transport_header_size);

    /* Verify error UnexpectedRequest is returned. */
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);

    /* Verify chunk SEND transfer sequence is NOT terminated. */
    assert_true(spdm_context->chunk_context.send.chunk_in_use);
    assert_int_equal(spdm_context->chunk_context.send.chunk_handle, 1);
    assert_int_equal(spdm_context->chunk_context.send.chunk_seq_no, 3);

    libspdm_release_sender_buffer(spdm_context);

    /* Clean up chunk state for subsequent tests. */
    spdm_context->chunk_context.send.chunk_in_use = false;
}

/**
 * Test 8: During an active chunk SEND transfer, a GET_VERSION request
 * should be allowed to interrupt: the chunk send transfer should be
 * terminated and GET_VERSION processed normally.
 **/
static void libspdm_test_responder_receive_send_rsp_case8(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t *response;
    spdm_message_header_t *spdm_response;
    spdm_get_version_request_t spdm_request;
    void *message;
    size_t message_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.data_transfer_size =
        LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.max_spdm_msg_size =
        LIBSPDM_MAX_SPDM_MSG_SIZE;

    /* Simulate an active chunk SEND transfer. */
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = 1;
    spdm_context->chunk_context.send.chunk_seq_no = 3;

    /* Send a GET_VERSION request. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false,
                                    &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    transport_header_size =
        spdm_context->local_context.capability.transport_header_size;
    spdm_response = (spdm_message_header_t *)((uint8_t *)message + transport_header_size);

    /* Verify GET_VERSION was processed: response should be VERSION. */
    assert_int_equal(spdm_response->request_response_code, SPDM_VERSION);

    /* Verify chunk send transfer was terminated. */
    assert_false(spdm_context->chunk_context.send.chunk_in_use);
    assert_int_equal(spdm_context->chunk_context.send.chunk_seq_no, 0);

    libspdm_release_sender_buffer(spdm_context);
}

/**
 * Test 9: libspdm_process_request() returns INVALID_PARAMETER when request is NULL
 * or request_size is 0.
 **/
void libspdm_test_responder_process_request_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t *session_id;
    bool is_app_message;
    uint8_t request_buffer[16];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 9;

    status = libspdm_process_request(spdm_context, &session_id, &is_app_message, 16, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    status = libspdm_process_request(spdm_context, &session_id, &is_app_message, 0,
                                     request_buffer);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 10: libspdm_process_request() successfully decodes a normal (non-session)
 * GET_VERSION message via the test transport layer.
 **/
void libspdm_test_responder_process_request_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t *session_id;
    bool is_app_message;
    spdm_get_version_request_t spdm_request;
    void *message;
    size_t message_size;
    uint32_t transport_header_size;
    void *transport_message;
    size_t transport_message_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 10;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;

    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    status = libspdm_acquire_receiver_buffer(spdm_context, &message_size, &message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    libspdm_copy_mem((uint8_t *)message + transport_header_size,
                     message_size - transport_header_size,
                     &spdm_request, sizeof(spdm_request));

    transport_message_size = message_size;
    status = spdm_context->transport_encode_message(
        spdm_context, NULL, false, true, sizeof(spdm_request),
        (uint8_t *)message + transport_header_size,
        &transport_message_size, &transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    is_app_message = false;
    session_id = NULL;
    status = libspdm_process_request(spdm_context, &session_id, &is_app_message,
                                     transport_message_size, transport_message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    assert_false(is_app_message);
    assert_int_equal(((spdm_message_header_t *)spdm_context->last_spdm_request)
                     ->request_response_code, SPDM_GET_VERSION);

    libspdm_release_receiver_buffer(spdm_context);
}

/**
 * Test 11: libspdm_register_get_response_func(), libspdm_register_session_state_callback_func(),
 * libspdm_register_connection_state_callback_func(), and libspdm_register_key_update_callback_func()
 * correctly register callbacks, and the corresponding trigger functions
 * (libspdm_set_session_state(), libspdm_set_connection_state(), libspdm_trigger_key_update_callback())
 * invoke them only when state actually changes.
 **/
static uint32_t m_session_state_callback_count;
static libspdm_session_state_t m_session_state_callback_last_state;
static uint32_t m_connection_state_callback_count;
static libspdm_connection_state_t m_connection_state_callback_last_state;
static uint32_t m_key_update_callback_count;

static libspdm_return_t libspdm_test_get_response_func_stub(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response)
{
    return LIBSPDM_STATUS_SUCCESS;
}

static void libspdm_test_session_state_callback(
    void *spdm_context, uint32_t session_id, libspdm_session_state_t session_state)
{
    m_session_state_callback_count++;
    m_session_state_callback_last_state = session_state;
}

static void libspdm_test_connection_state_callback(
    void *spdm_context, libspdm_connection_state_t connection_state)
{
    m_connection_state_callback_count++;
    m_connection_state_callback_last_state = connection_state;
}

static void libspdm_test_key_update_callback(
    void *spdm_context, uint32_t session_id,
    libspdm_key_update_operation_t key_update_op,
    libspdm_key_update_action_t key_update_action)
{
    m_key_update_callback_count++;
}

void libspdm_test_responder_process_request_case11(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 11;

    m_session_state_callback_count = 0;
    m_connection_state_callback_count = 0;
    m_key_update_callback_count = 0;

    /* Register callbacks. */
    libspdm_register_get_response_func(spdm_context, libspdm_test_get_response_func_stub);
    assert_ptr_equal(spdm_context->get_response_func, libspdm_test_get_response_func_stub);

    libspdm_register_session_state_callback_func(spdm_context,
                                                 libspdm_test_session_state_callback);
    libspdm_register_connection_state_callback_func(spdm_context,
                                                    libspdm_test_connection_state_callback);
    libspdm_register_key_update_callback_func(spdm_context, libspdm_test_key_update_callback);

    /* Set up a session so libspdm_set_session_state() can find it. */
    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_NOT_STARTED);

    /* Changing session state should trigger the callback. */
    libspdm_set_session_state(spdm_context, session_id, LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(m_session_state_callback_count, 1);
    assert_int_equal(m_session_state_callback_last_state, LIBSPDM_SESSION_STATE_HANDSHAKING);

    /* Setting the same state again should not trigger the callback. */
    libspdm_set_session_state(spdm_context, session_id, LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(m_session_state_callback_count, 1);

    /* Changing connection state should trigger the callback. */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    libspdm_set_connection_state(spdm_context, LIBSPDM_CONNECTION_STATE_NEGOTIATED);
    assert_int_equal(m_connection_state_callback_count, 1);
    assert_int_equal(m_connection_state_callback_last_state,
                     LIBSPDM_CONNECTION_STATE_NEGOTIATED);

    /* Setting the same connection state again should not trigger the callback. */
    libspdm_set_connection_state(spdm_context, LIBSPDM_CONNECTION_STATE_NEGOTIATED);
    assert_int_equal(m_connection_state_callback_count, 1);

    /* Trigger the key update callback directly. */
    libspdm_trigger_key_update_callback(spdm_context, session_id,
                                        LIBSPDM_KEY_UPDATE_OPERATION_CREATE_UPDATE,
                                        LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
    assert_int_equal(m_key_update_callback_count, 1);

    /* libspdm_terminate_session() on a valid session succeeds, resets the session state to
     * NOT_STARTED (triggering the callback again), and frees the session id. */
    m_session_state_callback_count = 0;
    assert_int_equal(libspdm_terminate_session(spdm_context, session_id),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(m_session_state_callback_count, 1);
    assert_int_equal(m_session_state_callback_last_state, LIBSPDM_SESSION_STATE_NOT_STARTED);
    assert_int_equal(session_info->session_id, INVALID_SESSION_ID);

    /* libspdm_terminate_session() on a nonexistent session id returns INVALID_PARAMETER. */
    assert_int_equal(libspdm_terminate_session(spdm_context, 0x12345678),
                     LIBSPDM_STATUS_INVALID_PARAMETER);

    /* Clean up registrations for other tests. */
    spdm_context->get_response_func = NULL;
    spdm_context->spdm_session_state_callback = NULL;
    spdm_context->spdm_connection_state_callback = NULL;
    spdm_context->spdm_key_update_callback = NULL;
}

/**
 * Test 12: libspdm_get_response_func_via_request_code() returns NULL for a request code
 * that has no registered handler. This is exercised indirectly by building a response to
 * an unrecognized (unsupported) SPDM request code, and observing that libspdm_build_response()
 * falls back on context->get_response_func (which is NULL by default), then converts the
 * resulting LIBSPDM_STATUS_UNSUPPORTED_CAP into an UNSUPPORTED_REQUEST error response.
 **/
void libspdm_test_responder_process_request_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t *response;
    spdm_error_response_t *spdm_response;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 12;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->get_response_func = NULL;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_10;
    /* An unregistered/reserved request code, not present in the internal dispatch table. */
    spdm_request.request_response_code = 0x00;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    status = libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size,
                                    (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    spdm_response = (spdm_error_response_t *)((uint8_t *)message + transport_header_size);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0x00);

    libspdm_release_sender_buffer(spdm_context);
}

/**
 * Test 13: libspdm_build_response() when context->last_spdm_error.error_code is
 * SPDM_ERROR_CODE_DECRYPT_ERROR. Covers both the "generate error response and send it"
 * branch (drop-on-decrypt-error policy bit not set) and the "silently drop" branch
 * (policy bit set).
 **/
void libspdm_test_responder_process_request_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    size_t response_size;
    uint8_t *response;
    void *message;
    size_t message_size;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 13;

    /* Set up algorithms and encrypt/mac capabilities so the session's secured message context
     * has a valid session type (ENC_MAC) and valid hash/AEAD sizes. */
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    /* Set up a session so the session-based encode path has a valid session_info. */
    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    /* Case A: drop-on-decrypt-error policy NOT set: an error response is generated and sent. */
    spdm_context->handle_error_return_policy = 0;
    spdm_context->last_spdm_error.error_code = SPDM_ERROR_CODE_DECRYPT_ERROR;
    spdm_context->last_spdm_error.session_id = session_id;

    status = libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size,
                                    (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    /* Session should have been freed as part of decrypt-error handling. */
    assert_int_equal(session_info->session_id, INVALID_SESSION_ID);
    assert_int_equal(spdm_context->last_spdm_error.error_code, 0);

    libspdm_release_sender_buffer(spdm_context);

    /* Case B: drop-on-decrypt-error policy set: message is silently dropped. */
    session_id = 0xFFFFFFFE;
    spdm_context->latest_session_id = session_id;
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    spdm_context->handle_error_return_policy =
        LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR;
    spdm_context->last_spdm_error.error_code = SPDM_ERROR_CODE_DECRYPT_ERROR;
    spdm_context->last_spdm_error.session_id = session_id;

    status = libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size,
                                    (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(response_size, 0);

    libspdm_release_sender_buffer(spdm_context);
    spdm_context->handle_error_return_policy = 0;

    /* Case C: SPDM_ERROR_CODE_INVALID_SESSION: message is silently dropped
     * (no valid session id needed). */
    spdm_context->last_spdm_error.error_code = SPDM_ERROR_CODE_INVALID_SESSION;
    spdm_context->last_spdm_error.session_id = 0;

    status = libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size,
                                    (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_int_equal(response_size, 0);

    libspdm_release_sender_buffer(spdm_context);

    libspdm_zero_mem(&spdm_context->last_spdm_error, sizeof(spdm_context->last_spdm_error));
}

/**
 * Test 14: libspdm_build_response() rejects a NULL *response, a zero *response_size,
 * and a zero context->last_spdm_request_size (INVALID_STATE_LOCAL).
 **/
/**
 * Test 14: libspdm_build_response() rejects a zero context->last_spdm_request_size,
 * returning INVALID_STATE_LOCAL. Note: the *response==NULL and *response_size==0 checks
 * that precede this in the source are not exercised here because my_response is computed
 * (and immediately zeroed) from response/response_size before those checks run whenever
 * session_id is NULL, so invalid values there would fault instead of hitting the checks.
 **/
void libspdm_test_responder_process_request_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t *response;
    void *message;
    size_t message_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 14;

    libspdm_zero_mem(&spdm_context->last_spdm_error, sizeof(spdm_context->last_spdm_error));

    spdm_context->last_spdm_request_size = 0;
    status = libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    response = message;
    response_size = message_size;
    status = libspdm_build_response(spdm_context, NULL, false, &response_size,
                                    (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    libspdm_release_sender_buffer(spdm_context);
}

int libspdm_rsp_receive_send_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* response message size is larger than requester data_transfer_size */
        cmocka_unit_test(libspdm_test_responder_receive_send_rsp_case1),
        /* response message size is larger than responder sending transmit buffer size */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case2,
                               libspdm_unit_test_group_setup),
        #if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
        /* response message size is larger than responder sending transmit buffer size
         * using the new Vendor Defined Message API */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case3,
                               libspdm_unit_test_group_setup),
        #endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
        /* response message size is larger than requester max_spdm_msg_size */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case4,
                               libspdm_unit_test_group_setup),
        /* non-chunk request during active chunk GET transfer returns UnexpectedRequest
         * and does not terminate chunk transfer */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case5,
                               libspdm_unit_test_group_setup),
        /* GET_VERSION during active chunk GET transfer terminates chunk and proceeds */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case6,
                               libspdm_unit_test_group_setup),
        /* non-chunk request during active chunk SEND transfer returns UnexpectedRequest
         * and does not terminate chunk transfer */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case7,
                               libspdm_unit_test_group_setup),
        /* GET_VERSION during active chunk SEND transfer terminates chunk and proceeds */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case8,
                               libspdm_unit_test_group_setup),
        /* libspdm_process_request() rejects NULL request / zero request_size */
        cmocka_unit_test_setup(libspdm_test_responder_process_request_case9,
                               libspdm_unit_test_group_setup),
        /* libspdm_process_request() successfully decodes a normal GET_VERSION message */
        cmocka_unit_test_setup(libspdm_test_responder_process_request_case10,
                               libspdm_unit_test_group_setup),
        /* register/trigger session state, connection state, and key update callbacks;
         * libspdm_terminate_session() success and failure paths */
        cmocka_unit_test_setup(libspdm_test_responder_process_request_case11,
                               libspdm_unit_test_group_setup),
        /* libspdm_get_response_func_via_request_code() NULL-return branch */
        cmocka_unit_test_setup(libspdm_test_responder_process_request_case12,
                               libspdm_unit_test_group_setup),
        /* libspdm_build_response() DECRYPT_ERROR / INVALID_SESSION error-code handling */
        cmocka_unit_test_setup(libspdm_test_responder_process_request_case13,
                               libspdm_unit_test_group_setup),
        /* libspdm_build_response() NULL response / zero response_size / zero request_size */
        cmocka_unit_test_setup(libspdm_test_responder_process_request_case14,
                               libspdm_unit_test_group_setup),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
