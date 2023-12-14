/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint16_t vendor_id;
    uint16_t data_len;
    uint8_t data[16];
} libspdm_vendor_request_test;

typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint16_t vendor_id;
    uint16_t data_len;
    uint8_t data[64];
} libspdm_vendor_response_test;
#pragma pack()

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];

libspdm_return_t libspdm_vendor_response_func_err_test(
    void *spdm_context,
    uint16_t standard_id,
    uint8_t vendor_id_len,
    const void *vendor_id,
    const void *request,
    size_t request_len,
    void *resp,
    size_t *resp_len)
{
    libspdm_vendor_response_test test_response;
    /* get pointer to response length and populate */
    uint16_t *response_len = (uint16_t *)resp;
    *response_len = sizeof(test_response.data);
    *resp_len = *response_len; /* for output */
    /* get pointer to response data payload and populate */
    uint8_t *resp_payload = (uint8_t *)resp;
    /* store length of response */
    libspdm_set_mem(resp_payload, *response_len, 0xFF);

    *response_len = 65000;

    printf("Got request 0x%x, sent response 0x%x\n",
           ((const uint8_t*)request)[0], ((uint8_t*)resp)[0]);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t libspdm_requester_vendor_cmds_err_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        const uint8_t *ptr = (const uint8_t *)request;

        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         ptr, request_size);
        m_libspdm_local_buffer_size += request_size;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

/* Acts as the Responder Integration */
static libspdm_return_t libspdm_requester_vendor_cmds_err_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_return_t status = LIBSPDM_STATUS_SUCCESS;

    uint32_t* session_id = NULL;
    bool is_app_message = false;
    size_t transport_message_size = sizeof(libspdm_vendor_request_test);

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        libspdm_vendor_response_test *spdm_response;
        libspdm_vendor_request_test* spdm_request = NULL;
        status = libspdm_transport_test_decode_message(
            spdm_test_context, &session_id, &is_app_message, true,
            m_libspdm_local_buffer_size, m_libspdm_local_buffer,
            &transport_message_size, (void **)(&spdm_request));
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_vendor_response_test);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        spdm_response->standard_id = spdm_request->standard_id;
        spdm_response->vendor_id_len = spdm_request->vendor_id_len;
        /* usually 2 bytes for vendor id */
        assert_int_equal(spdm_response->vendor_id_len, sizeof(uint16_t));
        spdm_response->vendor_id = spdm_request->vendor_id;
        spdm_response->data_len = sizeof(spdm_response->data) + 65000;
        libspdm_set_mem(spdm_response->data, sizeof(spdm_response->data), 0xff);

        status = libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                                       false, spdm_response_size,
                                                       spdm_response,
                                                       response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Sending a vendor defined request
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD
 * due to invalid length of data field in the response
 **/
static void libspdm_test_requester_vendor_cmds_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_vendor_request_test request;
    libspdm_vendor_response_test response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.is_requester = true;

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.standard_id = 6;
    request.vendor_id_len = 2;
    request.vendor_id = 0xAAAA;
    request.data_len = sizeof(request.data);
    libspdm_set_mem(request.data, sizeof(request.data), 0xAA);

    size_t response_len = sizeof(response.data);

    status = libspdm_vendor_request(spdm_context,
                                    request.standard_id, request.vendor_id_len,
                                    &request.vendor_id, &(request.data),
                                    request.data_len,
                                    &response.data, &response_len
                                    );
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_10);

    printf("case 1 %d\n", response.data[0]);
}

/**
 * Test 2: Sending a vendor defined request with one parameter NULL
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_PARAMETER
 **/
static void libspdm_test_requester_vendor_cmds_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_vendor_request_test request;
    libspdm_vendor_response_test response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.is_requester = true;

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.standard_id = 6;
    request.vendor_id_len = 2;
    request.vendor_id = 0xAAAA;
    request.data_len = sizeof(request.data);
    libspdm_set_mem(request.data, sizeof(request.data), 0xAA);

    size_t response_len = sizeof(response);

    status = libspdm_get_vendor_defined_response(spdm_context, sizeof(request),
                                                 &request, &response_len, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_10);

    response.data_len = (uint16_t)response_len;
}

libspdm_test_context_t m_libspdm_requester_vendor_cmds_err_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_vendor_cmds_err_test_send_message,
    libspdm_requester_vendor_cmds_err_test_receive_message,
};

int libspdm_requester_vendor_cmds_error_test_main(void)
{
    const struct CMUnitTest spdm_requester_vendor_cmds_tests[] = {
        cmocka_unit_test(libspdm_test_requester_vendor_cmds_err_case1),
        cmocka_unit_test(libspdm_test_requester_vendor_cmds_err_case2)
    };

    libspdm_setup_test_context(&m_libspdm_requester_vendor_cmds_err_test_context);

    return cmocka_run_group_tests(spdm_requester_vendor_cmds_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}


#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
