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

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
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
    case 0x2: {
        const uint8_t *ptr = (const uint8_t *)request;

        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         ptr, request_size);
        m_libspdm_local_buffer_size += request_size;
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

/* Acts as the Responder Integration */
static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_return_t status = LIBSPDM_STATUS_SUCCESS;

    uint32_t* session_id = NULL;
    bool is_app_message = false;
    size_t transport_message_size = sizeof(libspdm_vendor_request_test)
                                    + sizeof(uint16_t) + sizeof(uint32_t)
                                    + VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        libspdm_vendor_response_test *spdm_response;
        libspdm_vendor_request_test* spdm_request = NULL;
        uint8_t *response_ptr;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t response_data_len;

        status = libspdm_transport_test_decode_message(
            spdm_context, &session_id, &is_app_message, true,
            m_libspdm_local_buffer_size, m_libspdm_local_buffer,
            &transport_message_size, (void **)(&spdm_request));
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

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
        libspdm_copy_mem(spdm_response->vendor_id, spdm_request->vendor_id_len,
                         spdm_request->vendor_id, spdm_request->vendor_id_len);
        response_ptr = (uint8_t *)&spdm_response->vendor_id_len + sizeof(uint8_t) + spdm_response->vendor_id_len;
        response_data_len = VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;
        libspdm_copy_mem(response_ptr, sizeof(uint16_t), &response_data_len, sizeof(uint16_t));
        response_ptr += sizeof(uint16_t);
        libspdm_set_mem(response_ptr, VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE, 0xff);
        spdm_response_size = sizeof(spdm_vendor_defined_response_msg_t) +
                             spdm_response->vendor_id_len + sizeof(uint16_t) +
                             VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

        status = libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                                       false, spdm_response_size,
                                                       spdm_response,
                                                       response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x2: {
        libspdm_vendor_response_test *spdm_response;
        libspdm_vendor_request_test* spdm_request = NULL;
        uint8_t *response_ptr;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t response_data_len;

        status = libspdm_transport_test_decode_message(
            spdm_context, &session_id, &is_app_message, true,
            m_libspdm_local_buffer_size, m_libspdm_local_buffer,
            &transport_message_size, (void **)(&spdm_request));
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        spdm_response_size = sizeof(libspdm_vendor_response_test);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
        spdm_response->header.param1 = spdm_request->header.param1 & SPDM_VENDOR_DEFINED_REQUEST_LARGE_REQ;
        spdm_response->header.param2 = 0;

        spdm_response->standard_id = spdm_request->standard_id;
        spdm_response->vendor_id_len = spdm_request->vendor_id_len;
        /* usually 2 bytes for vendor id */
        assert_int_equal(spdm_response->vendor_id_len, sizeof(uint16_t));
        libspdm_copy_mem(spdm_response->vendor_id, spdm_request->vendor_id_len,
                         spdm_request->vendor_id, spdm_request->vendor_id_len);
        response_ptr = (uint8_t *)&spdm_response->vendor_id_len + sizeof(uint8_t) + spdm_response->vendor_id_len;
        libspdm_set_mem(response_ptr, sizeof(uint16_t), 0);
        response_ptr += sizeof(uint16_t);
        response_data_len = VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;
        libspdm_copy_mem(response_ptr, sizeof(uint32_t), &response_data_len, sizeof(uint32_t));
        response_ptr += sizeof(uint32_t);
        libspdm_set_mem(response_ptr, VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE, 0xff);
        spdm_response_size = sizeof(spdm_vendor_defined_response_msg_t) +
                             spdm_response->vendor_id_len + sizeof(uint16_t) + sizeof(uint32_t) +
                             VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE;

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
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS and expected response
 **/
static void req_vendor_defined_request_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_vendor_request_test request;
    libspdm_vendor_response_test response = {0};
    uint32_t request_data_len;
    uint8_t request_data[VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE];
    uint32_t response_data_len;
    uint8_t response_data[VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE];
    response.vendor_id_len = sizeof(response.vendor_id);
    response_data_len = sizeof(response_data);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.is_requester = true;

    request.standard_id = 6;
    request.vendor_id_len = 2;
    request.vendor_id[0] = 0xAA;
    request.vendor_id[1] = 0xAA;
    request_data_len = sizeof(request_data);
    libspdm_set_mem(request_data, sizeof(request_data), 0xAA);

    status = libspdm_vendor_send_request_receive_response(spdm_context, NULL,
                                                          request.standard_id,
                                                          request.vendor_id_len,
                                                          request.vendor_id, request_data_len,
                                                          request_data,
                                                          &response.standard_id,
                                                          &response.vendor_id_len,
                                                          response.vendor_id, &response_data_len,
                                                          response_data);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_10);

    printf("case 1 %d\n", response_data[0]);
}

/**
 * Test 2: Sending a vendor defined request with LargeReq supported
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS and expected response
 **/
static void req_vendor_defined_request_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_vendor_request_test request;
    libspdm_vendor_response_test response = {0};
    uint32_t request_data_len;
    uint8_t request_data[VENDOR_DEFINED_REQUEST_PAYLOAD_SIZE];
    uint32_t response_data_len;
    uint8_t response_data[VENDOR_DEFINED_RESPONSE_PAYLOAD_SIZE];
    response.vendor_id_len = sizeof(response.vendor_id);
    response_data_len = sizeof(response_data);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP;
    spdm_context->local_context.is_requester = true;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;

    request.standard_id = 6;
    request.vendor_id_len = 2;
    request.vendor_id[0] = 0xAA;
    request.vendor_id[1] = 0xAA;
    request_data_len = sizeof(request_data);
    libspdm_set_mem(request_data, sizeof(request_data), 0xAA);

    status = libspdm_vendor_send_request_receive_response(spdm_context, NULL,
                                                          request.standard_id,
                                                          request.vendor_id_len,
                                                          request.vendor_id, request_data_len,
                                                          request_data,
                                                          &response.standard_id,
                                                          &response.vendor_id_len,
                                                          response.vendor_id, &response_data_len,
                                                          response_data);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_14);

    printf("case 2 %d\n", response_data[0]);
}


int libspdm_req_vendor_defined_request_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_vendor_defined_request_case1),
        cmocka_unit_test(req_vendor_defined_request_case2),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
