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
    assert_int_equal(spdm_context->chunk_context.get.large_message_capacity,
                     spdm_context->local_context.capability.max_spdm_msg_size);
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
    assert_int_equal(spdm_context->chunk_context.get.large_message_capacity,
                     spdm_context->local_context.capability.max_spdm_msg_size);
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
    assert_int_equal(spdm_context->chunk_context.get.large_message_capacity,
                     spdm_context->local_context.capability.max_spdm_msg_size);
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
    void *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t *large_message;
    size_t large_message_capacity;
    size_t i;

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
    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);
    large_message = (uint8_t *)scratch_buffer +
                    libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    large_message_capacity = libspdm_get_scratch_buffer_large_message_capacity(spdm_context);
    libspdm_set_mem(large_message, large_message_capacity, 0xa5);

    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = 1;
    spdm_context->chunk_context.get.chunk_seq_no = 2;
    spdm_context->chunk_context.get.large_message = large_message;
    spdm_context->chunk_context.get.large_message_size = large_message_capacity;
    spdm_context->chunk_context.get.large_message_capacity = large_message_capacity;

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

    assert_null(spdm_context->chunk_context.get.large_message);
    assert_int_equal(spdm_context->chunk_context.get.large_message_size, 0);
    assert_int_equal(spdm_context->chunk_context.get.large_message_capacity, 0);
    for (i = 0; i < large_message_capacity; i++) {
        assert_int_equal(large_message[i], 0);
    }

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
    void *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t *large_message;
    size_t large_message_capacity;
    size_t i;

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
    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);
    large_message = (uint8_t *)scratch_buffer +
                    libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    large_message_capacity = libspdm_get_scratch_buffer_large_message_capacity(spdm_context);
    libspdm_set_mem(large_message, large_message_capacity, 0xa5);

    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = 1;
    spdm_context->chunk_context.send.chunk_seq_no = 3;
    spdm_context->chunk_context.send.large_message = large_message;
    spdm_context->chunk_context.send.large_message_size = large_message_capacity;
    spdm_context->chunk_context.send.large_message_capacity = large_message_capacity;

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

    assert_null(spdm_context->chunk_context.send.large_message);
    assert_int_equal(spdm_context->chunk_context.send.large_message_size, 0);
    assert_int_equal(spdm_context->chunk_context.send.large_message_capacity, 0);
    for (i = 0; i < large_message_capacity; i++) {
        assert_int_equal(large_message[i], 0);
    }

    libspdm_release_sender_buffer(spdm_context);
}

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP)

/**
 * Set up a session in the HANDSHAKING state for session-based mut_auth enforcement testing.
 * Returns true on success, false if the test should be skipped (e.g. DHE not configured).
 **/
static bool setup_handshaking_session(libspdm_context_t *spdm_context,
                                      libspdm_session_info_t **session_info_out,
                                      uint32_t *session_id_out)
{
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_ctx;
    const uint32_t session_id = 0xFFFFFFFF;
    uint8_t dummy_shared_secret[LIBSPDM_MAX_SHARED_KEY_SIZE];
    uint8_t dummy_th1[LIBSPDM_MAX_HASH_SIZE];

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;

    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);

    secured_ctx = (libspdm_secured_message_context_t*)session_info->secured_message_context;
    if (secured_ctx->shared_key_size == 0) {
        return false;
    }
    libspdm_set_mem(dummy_shared_secret, sizeof(dummy_shared_secret), 0xFF);
    libspdm_copy_mem(secured_ctx->master_secret.shared_secret,
                     sizeof(secured_ctx->master_secret.shared_secret),
                     dummy_shared_secret, secured_ctx->shared_key_size);

    libspdm_set_mem(dummy_th1, sizeof(dummy_th1), 0xAA);
    if (!libspdm_generate_session_handshake_key(session_info->secured_message_context, dummy_th1)) {
        return false;
    }

    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    /* The enforcement under test keys off session_info->mut_auth_requested, which each test case
     * sets. Deliberately no encapsulated state is primed here, so the test exercises the same
     * state that KEY_EXCHANGE_RSP actually produces. */
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    *session_info_out = session_info;
    *session_id_out = session_id;
    return true;
}

/**
 * Verify that an encrypted response in the sender buffer contains UNEXPECTED_REQUEST.
 * Releases the sender buffer, then acquires the receiver buffer to decrypt and check.
 **/
/* Decrypts the response the Responder built inside the session and checks it. When
 * expected_error is non-zero the response shall be that ERROR, otherwise it shall be a
 * successful response carrying expected_code. */
static void verify_session_response(libspdm_context_t *spdm_context,
                                    libspdm_session_info_t *session_info,
                                    void *response, size_t response_size,
                                    uint8_t expected_error, uint8_t expected_code)
{
    libspdm_secured_message_context_t *secured_ctx;
    uint8_t saved_response[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    void *message;
    size_t message_size;
    void *decoded_msg;
    size_t decoded_msg_size;
    void *scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t *decoded_session_id_ptr;
    bool is_app_msg;
    uint32_t transport_header_size;
    spdm_error_response_t *spdm_response;
    libspdm_return_t status;

    /* Save the encrypted response before releasing the sender buffer. */
    libspdm_copy_mem(saved_response, sizeof(saved_response), response, response_size);
    libspdm_release_sender_buffer(spdm_context);

    /* Reset sequence number so decode uses the same sequence (0) as encode. */
    secured_ctx = (libspdm_secured_message_context_t*)session_info->secured_message_context;
    secured_ctx->handshake_secret.response_handshake_sequence_number = 0;

    /* Load the encrypted response into the receiver buffer. */
    libspdm_acquire_receiver_buffer(spdm_context, &message_size, &message);
    libspdm_copy_mem(message, message_size, saved_response, response_size);

    /* Use the scratch buffer's secure-message section as the decryption output area.
     * With CHUNK_CAP the ciphertext lives in the large-sender-receiver section of the
     * same scratch buffer, so the output size must be capped at secure_message_capacity
     * to avoid the zero-on-entry in libspdm_decode_secured_message overwriting the
     * ciphertext before it is read. */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);
    decoded_msg = (uint8_t*)scratch_buffer + transport_header_size;
    decoded_msg_size = libspdm_get_scratch_buffer_secure_message_capacity(spdm_context) -
                       transport_header_size;
    decoded_session_id_ptr = NULL;
    is_app_msg = false;

    status = spdm_context->transport_decode_message(
        spdm_context, &decoded_session_id_ptr, &is_app_msg, false,
        response_size, message,
        &decoded_msg_size, &decoded_msg);

    libspdm_release_receiver_buffer(spdm_context);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(decoded_session_id_ptr);
    spdm_response = (spdm_error_response_t*)decoded_msg;
    if (expected_error != 0) {
        assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
        assert_int_equal(spdm_response->header.param1, expected_error);
        assert_int_equal(spdm_response->header.param2, 0);
    } else {
        assert_int_equal(spdm_response->header.request_response_code, expected_code);
    }
}

static void verify_unexpected_request_response(libspdm_context_t *spdm_context,
                                               libspdm_session_info_t *session_info,
                                               void *response, size_t response_size)
{
    verify_session_response(spdm_context, session_info, response, response_size,
                            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0);
}

/**
 * Test 9: Session-based mutual authentication enforcement for MUT_AUTH_REQUESTED (bit 0).
 * After KEY_EXCHANGE_RSP with MUT_AUTH_REQUESTED, the Responder must only accept FINISH.
 * Expected behavior: any other request produces SPDM_ERROR / UNEXPECTED_REQUEST.
 **/
static void libspdm_test_responder_receive_send_rsp_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    void *response;
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 9;
    if (!setup_handshaking_session(spdm_context, &session_info, &session_id)) {
        return;
    }
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    /* Wrong request: GET_VERSION instead of FINISH. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.request_response_code = SPDM_GET_VERSION;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    verify_unexpected_request_response(spdm_context, session_info, response, response_size);
}

/* Bits 1 and 2 are only reachable when the encapsulated flow is available. Bit 0, tested above,
 * is not, and is the only legal value when the Requester has set PUB_KEY_ID_CAP. */
#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
/**
 * Test 10: Session-based mutual authentication enforcement for
 * MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST (bit 1).
 * After KEY_EXCHANGE_RSP with this bit set, the Responder must only accept
 * GET_ENCAPSULATED_REQUEST. Expected behavior: any other request produces
 * SPDM_ERROR / UNEXPECTED_REQUEST.
 **/
static void libspdm_test_responder_receive_send_rsp_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    void *response;
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 10;
    if (!setup_handshaking_session(spdm_context, &session_info, &session_id)) {
        return;
    }
    session_info->mut_auth_requested =
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;

    /* Wrong request: GET_VERSION instead of GET_ENCAPSULATED_REQUEST. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.request_response_code = SPDM_GET_VERSION;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    verify_unexpected_request_response(spdm_context, session_info, response, response_size);
}

/**
 * Test 11: Session-based mutual authentication enforcement for
 * MUT_AUTH_REQUESTED_WITH_GET_DIGESTS (bit 2).
 * After KEY_EXCHANGE_RSP with this bit set, the Responder must only accept
 * DELIVER_ENCAPSULATED_RESPONSE. Expected behavior: any other request produces
 * SPDM_ERROR / RequestInFlight, as the optimized flow has already started.
 **/
static void libspdm_test_responder_receive_send_rsp_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    void *response;
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 11;
    if (!setup_handshaking_session(spdm_context, &session_info, &session_id)) {
        return;
    }
    session_info->mut_auth_requested =
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS;

    /* Wrong request: GET_VERSION instead of DELIVER_ENCAPSULATED_RESPONSE. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.request_response_code = SPDM_GET_VERSION;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    verify_session_response(spdm_context, session_info, response, response_size,
                            SPDM_ERROR_CODE_REQUEST_IN_FLIGHT, 0);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)

/**
 * Put the connection into the basic mutual authentication encapsulated flow, as it would be
 * after the Responder signals mutual authentication in its CHALLENGE_AUTH response.
 **/
static void set_basic_mut_auth_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0;
}

/**
 * Test 12: Basic mutual authentication enforcement. After the Responder signals mutual
 * authentication in CHALLENGE_AUTH, the next request must be GET_ENCAPSULATED_REQUEST.
 * Expected behavior: any other request produces SPDM_ERROR / UNEXPECTED_REQUEST.
 **/
static void libspdm_test_responder_receive_send_rsp_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_message_header_t spdm_request;
    spdm_error_response_t *spdm_response;
    void *message;
    size_t message_size;
    uint8_t *response;
    size_t response_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 12;
    set_basic_mut_auth_state(spdm_context);

    /* Wrong request: GET_DIGESTS instead of GET_ENCAPSULATED_REQUEST. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.request_response_code = SPDM_GET_DIGESTS;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    spdm_response = (spdm_error_response_t *)((uint8_t *)message + transport_header_size);

    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /* The flow is not terminated by the rejected request. */
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);

    libspdm_release_sender_buffer(spdm_context);
}

/**
 * Test 13: Basic mutual authentication enforcement must not reject GET_VERSION, which resets
 * the connection.
 * Expected behavior: GET_VERSION is processed normally and returns a VERSION response.
 **/
static void libspdm_test_responder_receive_send_rsp_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_version_request_t spdm_request;
    spdm_message_header_t *spdm_response;
    void *message;
    size_t message_size;
    uint8_t *response;
    size_t response_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 13;
    set_basic_mut_auth_state(spdm_context);

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

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    spdm_response = (spdm_message_header_t *)((uint8_t *)message + transport_header_size);

    assert_int_equal(spdm_response->request_response_code, SPDM_VERSION);

    libspdm_release_sender_buffer(spdm_context);
}

/* Minimal handler: ends the flow as soon as libspdm asks for a request. Registered because
 * ENCAP_CAP requires a handler; the tests below are about which requests reach libspdm at all. */
static libspdm_return_t receive_send_encap_handler(
    void *spdm_context, const uint32_t *session_id, libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code, uint8_t error_code, bool *terminate_flow, size_t *request_size,
    void *request)
{
    *terminate_flow = true;
    *request_size = 0;
    return LIBSPDM_STATUS_SUCCESS;
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT

/**
 * Test 14: an encapsulated ERROR(ResponseNotReady) terminated the flow, but the encapsulated
 * request is still outstanding.
 * Expected behavior: an unrelated request is rejected with ERROR(RequestInFlight), while
 * GET_ENCAPSULATED_REQUEST and, outside of a session, GET_VERSION are accepted.
 * GET_ENCAPSULATED_REQUEST reissues the outstanding request with RESPOND_IF_READY without
 * consulting the Integrator's handler.
 **/
static void libspdm_test_responder_receive_send_rsp_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_message_header_t spdm_request;
    spdm_error_response_t *spdm_response;
    void *message;
    size_t message_size;
    uint8_t *response;
    size_t response_size;
    uint32_t transport_header_size;
    size_t index;
    const uint8_t codes[] = {SPDM_GET_DIGESTS, SPDM_GET_ENCAPSULATED_REQUEST, SPDM_GET_VERSION};

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 14;
    set_basic_mut_auth_state(spdm_context);
    libspdm_register_encap_flow_handler(spdm_context, receive_send_encap_handler);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(codes); index++) {
        /* The state an encapsulated ResponseNotReady leaves behind: the flow is terminated but the
         * GET_DIGESTS it interrupted is still outstanding. */
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        spdm_context->encap_context.response_not_ready = true;
        spdm_context->encap_context.response_not_ready_flow_type =
            LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
        spdm_context->encap_context.response_not_ready_data.request_code = SPDM_GET_DIGESTS;
        spdm_context->encap_context.response_not_ready_data.token = 0x5A;
        spdm_context->encap_context.last_encap_request_header.request_response_code =
            SPDM_GET_DIGESTS;
        spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);

        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        /* GET_VERSION always carries the 1.0 version, unlike the rest of the connection. */
        spdm_request.spdm_version = (codes[index] == SPDM_GET_VERSION) ?
                                    SPDM_MESSAGE_VERSION_10 : SPDM_MESSAGE_VERSION_11;
        spdm_request.request_response_code = codes[index];
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

        transport_header_size = spdm_context->local_context.capability.transport_header_size;
        spdm_response = (spdm_error_response_t *)((uint8_t *)message + transport_header_size);

        if (codes[index] == SPDM_GET_DIGESTS) {
            /* Unrelated request while the encapsulated request is outstanding. */
            assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
            assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_REQUEST_IN_FLIGHT);
            /* The retained state survives the rejection. */
            assert_true(spdm_context->encap_context.response_not_ready);
        } else if (codes[index] == SPDM_GET_ENCAPSULATED_REQUEST) {
            /* The flow resumes and libspdm reissues the outstanding request itself.
             * receive_send_encap_handler would have terminated the flow, so reaching
             * RESPOND_IF_READY shows that the handler was not consulted. */
            const spdm_message_header_t *encap_request =
                (const void *)((const uint8_t *)spdm_response +
                               sizeof(spdm_encapsulated_request_response_t));

            assert_int_equal(spdm_response->header.request_response_code,
                             SPDM_ENCAPSULATED_REQUEST);
            assert_int_equal(encap_request->request_response_code, SPDM_RESPOND_IF_READY);
            assert_int_equal(encap_request->param1, SPDM_GET_DIGESTS);
            assert_int_equal(encap_request->param2, 0x5A);
            assert_int_equal(spdm_context->encap_context.flow_type,
                             LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
        } else {
            /* GET_VERSION resets the connection rather than being rejected by the gate. */
            assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
        }

        libspdm_release_sender_buffer(spdm_context);
    }
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
/**
 * Test 15: session-based mutual authentication when both endpoints have set
 * HANDSHAKE_IN_THE_CLEAR_CAP. The encapsulated flow is then conducted outside of a session, so the
 * enforcement applies to the channel outside of a session.
 * Expected behavior: before the flow has issued a request only the message that MutAuthRequested
 * calls for is accepted, plus GET_VERSION. Bit 1 calls for GET_ENCAPSULATED_REQUEST and bit 2
 * for DELIVER_ENCAPSULATED_RESPONSE. Once the flow has issued a request the messages that
 * advance it are accepted.
 **/
static void libspdm_test_responder_receive_send_rsp_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    spdm_message_header_t spdm_request;
    spdm_error_response_t *spdm_response;
    void *message;
    size_t message_size;
    uint8_t *response;
    size_t response_size;
    uint32_t transport_header_size;
    uint32_t session_id;
    size_t index;
    const struct {
        uint8_t mut_auth_requested;
        uint8_t code;
        size_t last_encap_request_size;
        /* The enforcement error expected, or 0 if the request must not be rejected. */
        uint8_t expected_error;
    } cases[] = {
        /* Bit 1: the flow has not issued a request, so only GET_ENCAPSULATED_REQUEST
         * advances it. */
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
          SPDM_GET_DIGESTS, 0, SPDM_ERROR_CODE_UNEXPECTED_REQUEST },
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
          SPDM_DELIVER_ENCAPSULATED_RESPONSE, 0, SPDM_ERROR_CODE_UNEXPECTED_REQUEST },
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
          SPDM_GET_ENCAPSULATED_REQUEST, 0, 0 },
        /* GET_VERSION resets the connection, so it is legal outside of a session. */
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
          SPDM_GET_VERSION, 0, 0 },
        /* The flow has issued a request, so the message that delivers its response is legal. */
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
          SPDM_DELIVER_ENCAPSULATED_RESPONSE, sizeof(spdm_message_header_t), 0 },
        /* Anything that does not advance the flow is rejected on that channel. */
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
          SPDM_GET_DIGESTS, sizeof(spdm_message_header_t), SPDM_ERROR_CODE_REQUEST_IN_FLIGHT },

        /* Bit 2 embeds GET_DIGESTS in KEY_EXCHANGE_RSP, so the next non-session message is
         * DELIVER_ENCAPSULATED_RESPONSE rather than GET_ENCAPSULATED_REQUEST. */
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,
          SPDM_DELIVER_ENCAPSULATED_RESPONSE, 0, 0 },
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,
          SPDM_GET_ENCAPSULATED_REQUEST, 0, SPDM_ERROR_CODE_REQUEST_IN_FLIGHT },
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,
          SPDM_GET_DIGESTS, 0, SPDM_ERROR_CODE_REQUEST_IN_FLIGHT },
        { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,
          SPDM_GET_VERSION, 0, 0 },
    };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 15;
    session_id = 0xFFFFFFFF;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(cases); index++) {
        set_basic_mut_auth_state(spdm_context);
        libspdm_register_encap_flow_handler(spdm_context, receive_send_encap_handler);

        /* 1.3 and above so that terminating the flow yields NoPendingRequests rather than
         * UnexpectedRequest, which would be indistinguishable from the enforcement below. */
        spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                                SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_context->connection_info.capability.flags |=
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
        spdm_context->local_context.capability.flags |=
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;

        /* Basic mutual authentication is not in play here. */
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        spdm_context->encap_context.last_encap_request_size = 0;

        /* The state that KEY_EXCHANGE_RSP with MutAuthRequested bit 1 leaves behind. */
        session_info = &spdm_context->session_info[0];
        libspdm_session_info_init(spdm_context, session_info, session_id,
                                  SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
        libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                                  LIBSPDM_SESSION_STATE_HANDSHAKING);
        spdm_context->latest_session_id = session_id;
        session_info->mut_auth_requested = cases[index].mut_auth_requested;
        session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
        session_info->encap_context.last_encap_request_size = cases[index].last_encap_request_size;

        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.spdm_version = (cases[index].code == SPDM_GET_VERSION) ?
                                    SPDM_MESSAGE_VERSION_10 : SPDM_MESSAGE_VERSION_13;
        spdm_request.request_response_code = cases[index].code;
        libspdm_copy_mem(spdm_context->last_spdm_request,
                         libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                         &spdm_request, sizeof(spdm_request));
        spdm_context->last_spdm_request_size = sizeof(spdm_request);
        spdm_context->last_spdm_request_session_id_valid = false;

        libspdm_acquire_sender_buffer(spdm_context, &message_size, (void **)&message);
        response = message;
        response_size = message_size;
        libspdm_zero_mem(response, response_size);

        status = libspdm_build_response(spdm_context, NULL, false,
                                        &response_size, (void **)&response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        transport_header_size = spdm_context->local_context.capability.transport_header_size;
        spdm_response = (spdm_error_response_t *)((uint8_t *)message + transport_header_size);

        if (cases[index].expected_error != 0) {
            assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
            assert_int_equal(spdm_response->header.param1, cases[index].expected_error);
        } else if (cases[index].code == SPDM_GET_VERSION) {
            assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
        } else {
            assert_int_not_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
            assert_int_not_equal(spdm_response->header.param1, SPDM_ERROR_CODE_REQUEST_IN_FLIGHT);
        }

        libspdm_release_sender_buffer(spdm_context);
    }

    spdm_context->session_info[0].encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->session_info[0].mut_auth_requested = 0;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 16: an encapsulated ERROR(ResponseNotReady) terminated a flow that belongs to a session,
 * and the encapsulated request is still outstanding. Unlike the flow outside of a session in
 * test 14, GET_VERSION is not an escape here, because within a session the next request message
 * must be GET_ENCAPSULATED_REQUEST.
 * Expected behavior: GET_VERSION and an unrelated request are both rejected with
 * ERROR(RequestInFlight), while GET_ENCAPSULATED_REQUEST resumes the flow.
 **/
static void libspdm_test_responder_receive_send_rsp_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    void *response;
    size_t response_size;
    size_t index;
    const struct {
        uint8_t code;
        /* The enforcement error expected, or 0 if the request must be accepted. */
        uint8_t expected_error;
    } cases[] = {
        /* Unrelated request while the encapsulated request is outstanding. */
        { SPDM_GET_DIGESTS, SPDM_ERROR_CODE_REQUEST_IN_FLIGHT },
        /* Within a session GET_VERSION does not release the Requester from the flow, which is
         * what distinguishes this from test 14. */
        { SPDM_GET_VERSION, SPDM_ERROR_CODE_REQUEST_IN_FLIGHT },
        /* Returning to the flow is how the Requester makes progress. */
        { SPDM_GET_ENCAPSULATED_REQUEST, 0 },
    };

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 16;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(cases); index++) {
        if (!setup_handshaking_session(spdm_context, &session_info, &session_id)) {
            return;
        }
        libspdm_register_encap_flow_handler(spdm_context, receive_send_encap_handler);

        /* The mutual authentication enforcement keys off mut_auth_requested, so leave it clear to
         * isolate the ResponseNotReady enforcement under test. */
        session_info->mut_auth_requested = 0;

        /* The state an encapsulated ResponseNotReady leaves behind on the session's channel: the
         * flow is terminated but the GET_DIGESTS it interrupted is still outstanding. */
        session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        session_info->encap_context.response_not_ready = true;
        session_info->encap_context.response_not_ready_flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
        session_info->encap_context.response_not_ready_data.request_code = SPDM_GET_DIGESTS;
        session_info->encap_context.response_not_ready_data.token = 0x5A;
        session_info->encap_context.response_not_ready_data.rd_exponent = 1;
        session_info->encap_context.response_not_ready_data.rd_tm = 1;
        session_info->encap_context.last_encap_request_header.request_response_code =
            SPDM_GET_DIGESTS;
        session_info->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);

        /* The request arrives on the session's channel, so that is the channel the enforcement
         * resolves to. */
        spdm_context->last_spdm_request_session_id_valid = true;
        spdm_context->last_spdm_request_session_id = session_id;

        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        /* GET_VERSION always carries the 1.0 version, unlike the rest of the connection. */
        spdm_request.spdm_version = (cases[index].code == SPDM_GET_VERSION) ?
                                    SPDM_MESSAGE_VERSION_10 : SPDM_MESSAGE_VERSION_11;
        spdm_request.request_response_code = cases[index].code;
        libspdm_copy_mem(spdm_context->last_spdm_request,
                         libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                         &spdm_request, sizeof(spdm_request));
        spdm_context->last_spdm_request_size = sizeof(spdm_request);

        libspdm_acquire_sender_buffer(spdm_context, &message_size, &message);
        response = message;
        response_size = message_size;
        libspdm_zero_mem(response, response_size);

        status = libspdm_build_response(spdm_context, &session_id, false,
                                        &response_size, &response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        verify_session_response(spdm_context, session_info, response, response_size,
                                cases[index].expected_error, SPDM_ENCAPSULATED_REQUEST);

        if (cases[index].expected_error != 0) {
            /* The retained state survives the rejection, so the flow can still be resumed. */
            assert_true(session_info->encap_context.response_not_ready);
        }
    }

    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) */

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
        #if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP)
        /* session-based mutual auth enforcement: MUT_AUTH_REQUESTED (bit 0). This has no
         * encapsulated flow, so it is also exercised without ENCAP_CAP. */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case9,
                               libspdm_unit_test_group_setup),
        #if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
        /* session-based mutual auth enforcement: MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST (bit 1) */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case10,
                               libspdm_unit_test_group_setup),
        /* session-based mutual auth enforcement: MUT_AUTH_REQUESTED_WITH_GET_DIGESTS (bit 2) */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case11,
                               libspdm_unit_test_group_setup),
        #endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
        #endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
        #if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)
        /* basic mutual auth enforcement: next request must be GET_ENCAPSULATED_REQUEST */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case12,
                               libspdm_unit_test_group_setup),
        /* basic mutual auth enforcement: GET_VERSION is not rejected */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case13,
                               libspdm_unit_test_group_setup),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* ResponseNotReady outstanding: only GET_ENCAPSULATED_REQUEST or GET_VERSION */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case14,
                               libspdm_unit_test_group_setup),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        /* session-based mutual auth enforcement with the handshake in the clear */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case15,
                               libspdm_unit_test_group_setup),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* ResponseNotReady outstanding in a session: GET_VERSION is not an escape */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case16,
                               libspdm_unit_test_group_setup),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
        #endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) */
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
