/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP)

/* GET_CERTIFICATE for slot 1. */
static spdm_get_certificate_request_t m_libspdm_get_certificate_request_err1 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_GET_CERTIFICATE, 1, 0},
    0,
    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
};
static size_t m_libspdm_get_certificate_request_err1_size =
    sizeof(m_libspdm_get_certificate_request_err1);

/**
 * Test 1: Error case, the Responder requests the certificate chain of a slot that holds none. The
 * Requester's DIGESTS told the Responder which slots are populated, so the request is the
 * Responder's mistake rather than a failure of the Requester's own.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void req_encap_certificate_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    /* Slot 0 holds a certificate chain and slot 1 does not. */
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[1] = NULL;
    spdm_context->local_context.local_cert_chain_provision_size[1] = 0;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, m_libspdm_get_certificate_request_err1_size,
        &m_libspdm_get_certificate_request_err1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    spdm_context->local_context.local_cert_chain_provision[0] = NULL;
    spdm_context->local_context.local_cert_chain_provision_size[0] = 0;
    free(data);
}

int libspdm_req_encap_certificate_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_encap_certificate_err_case1),
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

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP) */
