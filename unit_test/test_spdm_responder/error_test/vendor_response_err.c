/**
 *  Copyright Notice:
 *  Copyright 2023-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/


#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

#define VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE  16
#define VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE  64

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
} libspdm_vendor_request_test;

typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
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
    const uint32_t *session_id,
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint32_t req_size,
    const void *req_data,
    uint16_t *resp_standard_id,
    uint8_t *resp_vendor_id_len,
    void *resp_vendor_id,
    uint32_t *resp_size,
    void *resp_data)
{
    /* Validate required parameters */
    if (resp_standard_id == NULL || resp_vendor_id_len == NULL || resp_vendor_id == NULL ||
        resp_size == NULL || *resp_size == 0 || req_data == NULL || resp_data == NULL)
        return LIBSPDM_STATUS_INVALID_PARAMETER;

    /* Set response IDs */
    *resp_standard_id = 6;
    if (*resp_vendor_id_len < 2)
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    *resp_vendor_id_len = 2;
    ((uint8_t*)resp_vendor_id)[0] = 0xAA;
    ((uint8_t*)resp_vendor_id)[1] = 0xAA;

    /* Set response payload */
    uint8_t *resp_payload = (uint8_t *)resp_data;
    *resp_size = VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;
    libspdm_set_mem(resp_payload, *resp_size, 0xFF);

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
    size_t response_len = 0;
    uint8_t *request_ptr;

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

    response_len = sizeof(response) + sizeof(uint16_t)
                   + VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer), &request,
                     sizeof(request.header) + 3 + request.vendor_id_len);
    /* write the request data len to the correct offset in the request_buffer */
    request_ptr = request_buffer + sizeof(request.header) + 3 + request.vendor_id_len;
    libspdm_write_uint16(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE);
    /* set the request data to the correct offset in the request_buffer */
    request_ptr += sizeof(uint16_t);
    libspdm_set_mem(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE, 0xAA);

    /* requires correctly encoded spdm vendor request message */
    status = libspdm_get_vendor_defined_response(spdm_context, sizeof(request),
                                                 request_buffer, &response_len, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_10);
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
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    size_t response_size;
    spdm_error_response_t *response;
    uint8_t *request_ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    status = libspdm_register_vendor_callback_func(spdm_context, NULL);

    request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = 0;
    request.header.param2 = 0;
    request.standard_id = SPDM_REGISTRY_ID_IANA;
    request.vendor_id_len = 4;
    request.vendor_id[0] = 33;

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer), &request,
                     sizeof(request.header) + 3 + request.vendor_id_len);
    /* write the request data len to the correct offset in the request_buffer */
    request_ptr = request_buffer + sizeof(request.header) + 3 + request.vendor_id_len;
    libspdm_write_uint16(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE);
    /* set the request data to the correct offset in the request_buffer */
    request_ptr += sizeof(uint16_t);
    libspdm_set_mem(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE, 0xAA);

    response_size = sizeof(response_buffer);

    status = libspdm_get_vendor_defined_response(spdm_context, sizeof(request),
                                                 request_buffer, &response_size, response_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    response = (spdm_error_response_t *)response_buffer;

    assert_int_equal(response->header.spdm_version, SPDM_MESSAGE_VERSION_10);
    assert_int_equal(response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(response->header.param2, SPDM_VENDOR_DEFINED_REQUEST);
}

/**
 * Test 3: Responder does not support Large Resp Cap when Large payload requested.
 * Expected behavior: Responder replies with InvalidRequest.
 **/

static void libspdm_test_responder_vendor_cmds_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request = {0};
    spdm_error_response_t *response;
    size_t response_len = 0;
    size_t request_len = 0;
    uint8_t *request_ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.capability.flags = 0; /* responder not support large payload */
    spdm_context->local_context.is_requester = false;

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = SPDM_VENDOR_DEFINED_REQUEST_LARGE_REQ;
    request.standard_id = 6;
    request.vendor_id_len = sizeof(request.vendor_id);
    libspdm_set_mem(request.vendor_id, sizeof(request.vendor_id), 0xAA);

    response_len = sizeof(response) + sizeof(uint16_t) + sizeof(uint32_t)
                   + VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer),
                     &request, sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len);
    /* write the request data len to the correct offset in the request_buffer */
    request_ptr = request_buffer + sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len;
    libspdm_write_uint16(request_ptr, 0);
    request_ptr += sizeof(uint16_t);
    libspdm_write_uint32(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE);
    /* set the request data to the correct offset in the request_buffer */
    request_ptr += sizeof(uint32_t);
    libspdm_set_mem(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE, 0xAA);
    request_len = sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len + sizeof(uint16_t) +
                  sizeof(uint32_t) + VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE;

    /* requires correctly encoded spdm vendor request message */
    status = libspdm_get_vendor_defined_response(spdm_context, request_len,
                                                 request_buffer, &response_len, response_buffer);

    response = (spdm_error_response_t *)response_buffer;

    assert_int_equal(response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(response->header.param2, 0);
}

/**
 * Test 4: When payload requested, request size mismatch.
 * Expected behavior: Responder replies with InvalidRequest.
 **/
static void libspdm_test_responder_vendor_cmds_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request = {0};
    spdm_error_response_t *response;
    size_t response_len = 0;
    size_t request_len = 0;
    uint8_t *request_ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.is_requester = false;

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = 0;
    request.standard_id = 6;
    request.vendor_id_len = sizeof(request.vendor_id);
    libspdm_set_mem(request.vendor_id, sizeof(request.vendor_id), 0xAA);

    response_len = sizeof(response) + sizeof(uint16_t) + sizeof(uint32_t)
                   + VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer),
                     &request, sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len);
    /* write the request data len to the correct offset in the request_buffer */
    request_ptr = request_buffer + sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len;
    libspdm_write_uint16(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE);
    /* set the request data to the correct offset in the request_buffer */
    request_ptr += sizeof(uint16_t);
    libspdm_set_mem(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE, 0xAA);

    request_len = sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len; /* incorrect request len */
    /* requires correctly encoded spdm vendor request message */
    status = libspdm_get_vendor_defined_response(spdm_context, request_len,
                                                 request_buffer, &response_len, response_buffer);

    response = (spdm_error_response_t *)response_buffer;

    assert_int_equal(response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(response->header.param2, 0);
}

/**
 * Test 5: When payload requested, request payload size mismatch.
 * Expected behavior: Responder replies with InvalidRequest.
 **/
static void libspdm_test_responder_vendor_cmds_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request = {0};
    spdm_error_response_t *response;
    size_t response_len = 0;
    size_t request_len = 0;
    uint8_t *request_ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.is_requester = false;

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = 0;
    request.standard_id = 6;
    request.vendor_id_len = sizeof(request.vendor_id);
    libspdm_set_mem(request.vendor_id, sizeof(request.vendor_id), 0xAA);

    response_len = sizeof(response) + sizeof(uint16_t) + sizeof(uint32_t)
                   + VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer),
                     &request, sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len);
    /* write the request data len to the correct offset in the request_buffer */
    request_ptr = request_buffer + sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len;
    libspdm_write_uint16(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE);
    /* set the request data to the correct offset in the request_buffer */
    request_ptr += sizeof(uint16_t);
    libspdm_set_mem(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE, 0xAA);
    request_len = sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len + sizeof(uint16_t) +
                  VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE - 1; /* incorrect request data len */
    /* requires correctly encoded spdm vendor request message */
    status = libspdm_get_vendor_defined_response(spdm_context, request_len,
                                                 request_buffer, &response_len, response_buffer);

    response = (spdm_error_response_t *)response_buffer;

    assert_int_equal(response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(response->header.param2, 0);
}

/**
 * Test 6: When Large payload requested, request size mismatch.
 * Expected behavior: Responder replies with InvalidRequest.
 **/
static void libspdm_test_responder_vendor_cmds_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request = {0};
    spdm_error_response_t *response;
    size_t response_len = 0;
    size_t request_len = 0;
    uint8_t *request_ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.is_requester = false;

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = SPDM_VENDOR_DEFINED_REQUEST_LARGE_REQ;
    request.standard_id = 6;
    request.vendor_id_len = sizeof(request.vendor_id);
    libspdm_set_mem(request.vendor_id, sizeof(request.vendor_id), 0xAA);

    response_len = sizeof(response) + sizeof(uint16_t) + sizeof(uint32_t)
                   + VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer),
                     &request, sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len);
    /* write the request data len to the correct offset in the request_buffer */
    request_ptr = request_buffer + sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len;
    libspdm_write_uint16(request_ptr, 0);
    request_ptr += sizeof(uint16_t);
    libspdm_write_uint32(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE);
    /* set the request data to the correct offset in the request_buffer */
    request_ptr += sizeof(uint32_t);
    libspdm_set_mem(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE, 0xAA);
    /* incorrect request len*/
    request_len = sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len + sizeof(uint16_t);

    /* requires correctly encoded spdm vendor request message */
    status = libspdm_get_vendor_defined_response(spdm_context, request_len,
                                                 request_buffer, &response_len, response_buffer);

    response = (spdm_error_response_t *)response_buffer;

    assert_int_equal(response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(response->header.param2, 0);
}

/**
 * Test 7: When Large payload requested, request payload size mismatch.
 * Expected behavior: Responder replies with InvalidRequest.
 **/
static void libspdm_test_responder_vendor_cmds_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request = {0};
    spdm_error_response_t *response;
    size_t response_len = 0;
    size_t request_len = 0;
    uint8_t *request_ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.is_requester = false;

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = SPDM_VENDOR_DEFINED_REQUEST_LARGE_REQ;
    request.standard_id = 6;
    request.vendor_id_len = sizeof(request.vendor_id);
    libspdm_set_mem(request.vendor_id, sizeof(request.vendor_id), 0xAA);

    response_len = sizeof(response) + sizeof(uint16_t) + sizeof(uint32_t)
                   + VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

    /* copy header of request structure to buffer */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer),
                     &request, sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len);
    /* write the request data len to the correct offset in the request_buffer */
    request_ptr = request_buffer + sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len;
    libspdm_write_uint16(request_ptr, 0);
    request_ptr += sizeof(uint16_t);
    libspdm_write_uint32(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE);
    /* set the request data to the correct offset in the request_buffer */
    request_ptr += sizeof(uint32_t);
    libspdm_set_mem(request_ptr, VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE, 0xAA);
    request_len = sizeof(spdm_vendor_defined_request_msg_t) + request.vendor_id_len + sizeof(uint16_t) +
                  sizeof(uint32_t) + VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE - 1; /* incorrect request data len */

    /* requires correctly encoded spdm vendor request message */
    status = libspdm_get_vendor_defined_response(spdm_context, request_len,
                                                 request_buffer, &response_len, response_buffer);

    response = (spdm_error_response_t *)response_buffer;

    assert_int_equal(response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(response->header.param2, 0);
}

int libspdm_rsp_vendor_defined_response_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case1),
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case2),
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case3),
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case4),
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case5),
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case6),
        cmocka_unit_test(libspdm_test_responder_vendor_cmds_err_case7),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
