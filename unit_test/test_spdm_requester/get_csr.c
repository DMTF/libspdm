/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

uint8_t csr_pointer[LIBSPDM_MAX_CSR_SIZE] = {0};
uint8_t *csr_data_pointer = csr_pointer;
size_t global_csr_len;

bool libspdm_read_requester_gen_csr(void **csr_data, size_t *csr_len)
{
    char *file;
    bool res;

    file = "test_csr/ecc384_csr";
    res = libspdm_read_input_file(file, csr_data, csr_len);
    if (!res) {
        return res;
    }

    return res;
}

libspdm_return_t libspdm_requester_get_csr_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    uint8_t message_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    memcpy(message_buffer, request, request_size);

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_get_csr_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_csr_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_requester_gen_csr((void *)&csr_data_pointer, &global_csr_len);

        spdm_response_size = sizeof(spdm_csr_response_t) + global_csr_len;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CSR;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = global_csr_len;
        spdm_response->reserved = 0;

        libspdm_copy_mem(spdm_response + 1, global_csr_len, csr_data_pointer, global_csr_len);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_requester_get_csr_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    status = libspdm_get_csr(spdm_context, NULL, 0, NULL, 0, NULL, csr_form_get,
                             LIBSPDM_MAX_CSR_SIZE);

    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 2: Successful response to set certificate for slot 0
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
void libspdm_test_requester_get_csr_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    status = libspdm_get_csr(spdm_context, NULL, 0, NULL, 0, NULL, csr_form_get,
                             LIBSPDM_MAX_CSR_SIZE);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(csr_form_get, csr_data_pointer, global_csr_len);
}

libspdm_test_context_t m_libspdm_requester_get_csr_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_get_csr_test_send_message,
    libspdm_requester_get_csr_test_receive_message,
};

int libspdm_requester_get_csr_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_csr_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_get_csr_case1),
        /* Successful response to set certificate*/
        cmocka_unit_test(libspdm_test_requester_get_csr_case2),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_get_csr_test_context);

    return cmocka_run_group_tests(spdm_requester_get_csr_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
