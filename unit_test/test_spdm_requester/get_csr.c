/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP

#define LIBSPDM_MAX_CSR_SIZE 0x1000

uint8_t csr_pointer[LIBSPDM_MAX_CSR_SIZE] = {0};
uint8_t *csr_data_pointer = csr_pointer;
size_t global_csr_len;

uint8_t m_csr_opaque_data[8] = "libspdm";
uint16_t m_csr_opaque_data_size = sizeof(m_csr_opaque_data);

/*ECC 256 req_info(include right req_info attribute)*/
static uint8_t right_req_info[] = {
    0x30, 0x81, 0xBF, 0x02, 0x01, 0x00, 0x30, 0x45, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x18, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4C, 0x74,
    0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xDB, 0xC2, 0xB2, 0xB7,
    0x83, 0x3C, 0xC8, 0x85, 0xE4, 0x3D, 0xE1, 0xF3, 0xBA, 0xE2, 0xF2, 0x90, 0x8E, 0x30, 0x25, 0x14,
    0xE1, 0xF7, 0xA9, 0x82, 0x29, 0xDB, 0x9D, 0x76, 0x2F, 0x80, 0x11, 0x32, 0xEE, 0xAB, 0xE2, 0x68,
    0xD1, 0x22, 0xE7, 0xBD, 0xB4, 0x71, 0x27, 0xC8, 0x79, 0xFB, 0xDC, 0x7C, 0x9E, 0x33, 0xA6, 0x67,
    0xC2, 0x10, 0x47, 0x36, 0x32, 0xC5, 0xA1, 0xAA, 0x6B, 0x2B, 0xAA, 0xC9, 0xA0, 0x18, 0x30, 0x16,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07, 0x31, 0x09, 0x0C, 0x07, 0x74,
    0x65, 0x73, 0x74, 0x31, 0x32, 0x33
};
static uint16_t right_req_info_size = sizeof(right_req_info);

bool libspdm_read_requester_gen_csr(void **csr_data, size_t *csr_len)
{
    char *file;
    bool res;

    file = "test_csr/ecp384.csr";
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

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4: {
        const spdm_get_csr_request_t *spdm_request;
        uint16_t requester_info_length;
        uint16_t opaque_data_length;
        uint8_t *opaque_data;
        uint8_t *requester_info;

        /* Obtain the real spdm_request */
        spdm_request =
            (const spdm_get_csr_request_t *)((const uint8_t *)request +
                                             sizeof(libspdm_test_message_header_t));

        requester_info_length = spdm_request->requester_info_length;
        opaque_data_length = spdm_request->opaque_data_length;

        requester_info = (void*)((size_t)(spdm_request + 1));
        assert_memory_equal(requester_info, right_req_info, requester_info_length);
        opaque_data = (void *)(requester_info + requester_info_length);
        assert_memory_equal(opaque_data, m_csr_opaque_data, opaque_data_length);
        return LIBSPDM_STATUS_SUCCESS;
    }
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_get_csr_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *context;

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
        spdm_response->csr_length = (uint16_t)global_csr_len;
        spdm_response->reserved = 0;

        libspdm_copy_mem(spdm_response + 1, global_csr_len, csr_data_pointer, global_csr_len);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_csr_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_requester_gen_csr((void *)&csr_data_pointer, &global_csr_len);

        spdm_response_size = sizeof(spdm_csr_response_t) + global_csr_len;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = (uint16_t)global_csr_len;
        spdm_response->reserved = 0;

        context = spdm_context;

        if (context->connection_info.capability.flags &
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) {
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_RESET_REQUIRED;
        } else {
            spdm_response->header.request_response_code = SPDM_CSR;
            spdm_response->header.param1 = 0;

            libspdm_copy_mem(spdm_response + 1, global_csr_len, csr_data_pointer, global_csr_len);
        }

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4: {
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
        spdm_response->csr_length = (uint16_t)global_csr_len;
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
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

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
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(csr_len, global_csr_len);
    assert_memory_equal(csr_form_get, csr_data_pointer, global_csr_len);
}

/**
 * Test 3: Successful response to set certificate for slot 0,
 * with a reset required
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
void libspdm_test_requester_get_csr_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_RESET_REQUIRED_PEER);

    /* Let's reset the responder and send the request again */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(csr_len, global_csr_len);
    assert_memory_equal(csr_form_get, csr_data_pointer, global_csr_len);
}

/**
 * Test 4: Send correct req_info and opaque_data
 * Expected Behavior: get a RETURN_SUCCESS return code and determine if req_info and opaque_data are correct
 **/
void libspdm_test_requester_get_csr_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    status = libspdm_get_csr(spdm_context, NULL,
                             right_req_info, right_req_info_size,
                             m_csr_opaque_data, m_csr_opaque_data_size,
                             (void *)&csr_form_get, &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(csr_len, global_csr_len);
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
        /* Successful response to set certificate with a reset required */
        cmocka_unit_test(libspdm_test_requester_get_csr_case3),
        /* Send req_info and opaque_data Successful response to get csr */
        cmocka_unit_test(libspdm_test_requester_get_csr_case4),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_get_csr_test_context);

    return cmocka_run_group_tests(spdm_requester_get_csr_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP*/
