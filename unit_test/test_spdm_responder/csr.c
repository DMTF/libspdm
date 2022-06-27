/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

/**
 * Test 1: receives a valid GET_CSR request message from Requester to set cert in slot_id:0
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->local_context.slot_count = 1;

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_get_csr_request_t));

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    m_libspdm_set_certificate_request->opaque_data_length = 0;
    m_libspdm_set_certificate_request->requester_info_length = 0;

    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_get_csr_request_t);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_set_certificate_request_size,
                                      m_libspdm_set_certificate_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    free(m_libspdm_set_certificate_request);
}

/**
 * Test 2: Wrong GET_CSR message size (larger than expected)
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_csr_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_set_certificate_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->local_context.slot_count = 1;

    m_libspdm_set_certificate_request = malloc(sizeof(spdm_get_csr_request_t));

    m_libspdm_set_certificate_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_set_certificate_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_set_certificate_request->header.param1 = 0;
    m_libspdm_set_certificate_request->header.param2 = 0;

    m_libspdm_set_certificate_request->opaque_data_length = 0;
    m_libspdm_set_certificate_request->requester_info_length = 0;

    /* Bad request size*/
    size_t m_libspdm_set_certificate_request_size = sizeof(spdm_get_csr_request_t) - 1;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_set_certificate_request_size,
                                      m_libspdm_set_certificate_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(m_libspdm_set_certificate_request);
}


libspdm_test_context_t m_libspdm_responder_csr_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_csr_test_main(void)
{
    const struct CMUnitTest spdm_responder_csr_tests[] = {
        /* Success Case for csr response  */
        cmocka_unit_test(libspdm_test_responder_csr_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_csr_case2),
    };

    libspdm_setup_test_context(&m_libspdm_responder_csr_test_context);

    return cmocka_run_group_tests(spdm_responder_csr_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
