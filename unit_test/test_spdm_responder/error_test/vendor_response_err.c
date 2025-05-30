/**
 *  Copyright Notice:
 *  Copyright 2023-2025 DMTF. All rights reserved.
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
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
    uint16_t data_len;
    uint8_t data[16];
} libspdm_vendor_request_test;

typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
    uint16_t data_len;
    uint8_t data[64];
} libspdm_vendor_response_test;
#pragma pack()

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
}

static libspdm_return_t libspdm_vendor_response_func_err_test(
    void *spdm_context,
#if LIBSPDM_PASS_SESSION_ID
    const uint32_t *session_id,
#endif
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint16_t req_size,
    const void *req_data,
    uint16_t *resp_size,
    void *resp_data)
{
    libspdm_vendor_response_test test_response;
    /* get pointer to response data payload and populate */
    uint8_t *resp_payload = (uint8_t *)resp_data;
    /* get pointer to response length and populate */
    *resp_size = sizeof(test_response.data);
    /* store length of response */
    libspdm_set_mem(resp_payload, *resp_size, 0xFF);

    if (resp_size == NULL || *resp_size == 0)
        return LIBSPDM_STATUS_INVALID_PARAMETER;

    /* TBD make an error here, like response len 65000, but different this time. */

    printf("Got request 0x%x, sent response 0x%x\n",
           ((const uint8_t*)req_data)[0], ((uint8_t*)resp_data)[0]);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: Sending a vendor defined request with one parameter NULL
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_PARAMETER
 **/
static void libspdm_test_responder_vendor_cmds_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request;
    libspdm_vendor_response_test response = {0};
    response.vendor_id_len = sizeof(response.vendor_id);
    response.data_len = sizeof(response.data);
    size_t response_len = 0;

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
    request.vendor_id_len = sizeof(request.vendor_id);
    libspdm_set_mem(request.vendor_id, sizeof(request.vendor_id), 0xAA);
    request.data_len = sizeof(request.data);
    libspdm_set_mem(request.data, sizeof(request.data), 0xAA);

    response_len = sizeof(response);

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer), &request,
                     sizeof(request.header) + 3 + request.vendor_id_len);
    /* copy the request data to the correct offset in the request_buffer */
    libspdm_copy_mem(request_buffer + sizeof(request.header) + 3 + request.vendor_id_len,
                     request.data_len + 2, &request.data_len, request.data_len + 2);

    /* requires correctly encoded spdm vendor request message */
    status = libspdm_get_vendor_defined_response(spdm_context, sizeof(request),
                                                 request_buffer, &response_len, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_10);

    response.data_len = (uint16_t)response_len;
}

/**
 * Test 2: Responder does not support VDMs.
 * Expected behavior: Responder replies with UnsupportedRequest.
 **/
static void libspdm_test_responder_vendor_cmds_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_vendor_request_test request;
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    size_t response_size;
    spdm_error_response_t *response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    status = libspdm_register_vendor_callback_func(spdm_context, NULL);
    status = libspdm_register_vendor_get_id_callback_func(spdm_context, NULL);

    request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = 0;
    request.header.param2 = 0;
    request.standard_id = SPDM_REGISTRY_ID_IANA;
    request.vendor_id_len = 4;
    request.vendor_id[0] = 33;
    request.data_len = 2;
    request.data[0] = 0;
    request.data[1] = 1;

    response_size = sizeof(response_buffer);

    status = libspdm_get_vendor_defined_response(spdm_context, sizeof(request),
                                                 &request, &response_size, &response_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    response = (spdm_error_response_t *)response_buffer;

    assert_int_equal(response->header.spdm_version, SPDM_MESSAGE_VERSION_10);
    assert_int_equal(response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(response->header.param2, SPDM_VENDOR_DEFINED_REQUEST);
}

int libspdm_responder_vendor_cmds_error_test_main(void)
{
    const struct CMUnitTest spdm_responder_vendor_cmds_tests[] = {
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case1),
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case2),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(spdm_responder_vendor_cmds_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
