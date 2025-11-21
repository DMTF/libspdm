/**
 *  Copyright Notice:
 *  Copyright 2023-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
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

static uint32_t m_session_id = 0xffffffff;

static libspdm_return_t libspdm_vendor_response_func_test(
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
        resp_size == NULL || req_data == NULL || resp_data == NULL)
        return LIBSPDM_STATUS_INVALID_PARAMETER;

    assert_int_equal(*session_id, m_session_id);

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
 * Test 1: Sending a vendor defined request using the internal response handler
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS and expected response
 **/
static void rsp_vendor_defined_response_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request = {0};
    libspdm_vendor_response_test response = {0};
    size_t response_len = 0;
    libspdm_session_info_t *session_info;
    uint8_t *request_ptr;

    response.vendor_id_len = sizeof(response.vendor_id);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.is_requester = true;

    spdm_context->latest_session_id = m_session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_test);
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
                                                 request_buffer, &response_len, response_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 2: Sending a vendor defined request using the internal response handler with Large VDM support
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS and expected response
 **/
static void rsp_vendor_defined_response_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t request_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE] = {0};
    libspdm_vendor_request_test request = {0};
    libspdm_vendor_response_test response = {0};
    size_t response_len = 0;
    size_t request_len = 0;
    libspdm_session_info_t *session_info;
    uint8_t *request_ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_context->connection_info.version = request.header.spdm_version <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.is_requester = false;

    spdm_context->latest_session_id = m_session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    request.header.param1 = SPDM_VENDOR_DEFINED_REQUEST_LARGE_REQ;
    request.standard_id = 6;
    request.vendor_id_len = 2;
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

    /* copy to response data structure in the same way as for request */
    libspdm_copy_mem(&response, sizeof(response),
                     response_buffer, sizeof(spdm_vendor_defined_response_msg_t));

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response.header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(response.header.request_response_code, SPDM_VENDOR_DEFINED_RESPONSE);
    assert_int_equal(response.header.param1, SPDM_VENDOR_DEFINED_RESPONSE_LARGE_RESP);
}

int libspdm_rsp_vendor_defined_response_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_vendor_defined_response_case1),
        cmocka_unit_test(rsp_vendor_defined_response_case2),
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
