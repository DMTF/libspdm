/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

static uint8_t m_response[LIBSPDM_MAX_SPDM_MSG_SIZE];

static uint32_t m_case_id;

static libspdm_return_t libspdm_encap_state_handler(
    void *spdm_context, const uint32_t *session_id, libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code, bool *terminate_flow, size_t *request_size, void *request)
{
    *terminate_flow = false;

    switch (m_case_id) {
    case 0x1:
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
        assert_int_equal(last_request_code, 0);
        *terminate_flow = true;
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               request_size, request);
    default:
        assert_true(false);
        break;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->encap_context.session_id = INVALID_SESSION_ID;

    libspdm_register_encap_flow_handler(spdm_context, libspdm_encap_state_handler);
}

static void rsp_encapsulated_request_err_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_encapsulated_request_request_t request;
    size_t response_size;
    spdm_error_response_t *error_response;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;

    request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    request.header.request_response_code = SPDM_GET_ENCAPSULATED_REQUEST;
    request.header.param1 = 0;
    request.header.param2 = 0;

    response_size = sizeof(m_response);
    status = libspdm_get_response_encapsulated_request(
        spdm_context, sizeof(spdm_get_encapsulated_request_request_t),
        &request,
        &response_size,
        m_response);

    error_response = (spdm_error_response_t *)m_response;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(error_response->header.param2, 0);
}

int libspdm_rsp_encapsulated_request_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_encapsulated_request_err_case1)
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
