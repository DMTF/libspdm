/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

#define CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE (64)

libspdm_return_t my_test_get_response_func(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response)
{
    /* response message size is greater than the sending transmit buffer size of responder */
    *response_size = CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE + 1;
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: Test Responder Receive Send flow triggers chunk get mode
 * if response buffer is larger than requester data_transfer_size.
 **/
void libspdm_test_responder_receive_send_rsp_case1(void** state)
{
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

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size,
        &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);

    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

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

    spdm_context->connection_info.capability.max_spdm_msg_size =
        LIBSPDM_MAX_SPDM_MSG_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
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

    status = libspdm_build_response(spdm_context, NULL, false,
                                    &response_size, (void**)&response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->transport_get_header_size(spdm_context);

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
}

/**
 * Test 2: Test Responder Receive Send flow triggers chunk get mode
 * if response message size is larger than responder sending transmit buffer size.
 **/
void libspdm_test_responder_receive_send_rsp_case2(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    spdm_vendor_defined_request_msg_t spdm_request;
    void* message;
    size_t message_size;
    uint32_t transport_header_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    /* The local Responder transmit buffer size for sending a single and complete SPDM message */
    spdm_context->local_context.capability.sender_data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;
    /* The peer Requester buffer size for receiving a single and complete SPDM message */
    spdm_context->connection_info.capability.data_transfer_size =
        LIBSPDM_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.capability.max_spdm_msg_size =
        LIBSPDM_MAX_SPDM_MSG_SIZE;

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

    status = libspdm_build_response(spdm_context, NULL, false,
                                    &response_size, (void**)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->transport_get_header_size(spdm_context);

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

libspdm_test_context_t m_libspdm_responder_receive_send_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_receive_send_test_main(void)
{
    const struct CMUnitTest spdm_responder_receive_send_tests[] = {
        /* response message size is larger than requester data_transfer_size */
        cmocka_unit_test(libspdm_test_responder_receive_send_rsp_case1),
        /* response message size is larger than responder sending transmit buffer size */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case2,
                               libspdm_unit_test_group_setup),
    };

    libspdm_setup_test_context(&m_libspdm_responder_receive_send_test_context);

    return cmocka_run_group_tests(spdm_responder_receive_send_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
