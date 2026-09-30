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

/* One byte larger than the Offset and Length fields can address. */
static uint8_t m_libspdm_large_cert_chain[SPDM_MAX_CERTIFICATE_CHAIN_SIZE + 1];

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

/**
 * Test 2: Error case, the Responder requests a certificate chain larger than 0xFFFF bytes with the
 * Offset and Length fields rather than with LargeOffset and LargeLength. DSP0274 1.4 requires an
 * ERROR message with ErrorCode=DataTooLarge, whose ExtendedErrorData holds the ActualSize of the
 * certificate chain.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_DATA_TOO_LARGE and the
 * size of the certificate chain in its extended error data.
 **/
static void req_encap_certificate_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_request_t spdm_request;
    spdm_error_response_cert_chain_too_large_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    /* {ERROR} The certificate chain in slot 0 needs the LargeOffset and LargeLength fields. */
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_large_cert_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_large_cert_chain);

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request), &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_cert_chain_too_large_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_DATA_TOO_LARGE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_response->extend_error_data.cert_chain_length,
                     sizeof(m_libspdm_large_cert_chain));

    spdm_context->local_context.local_cert_chain_provision[0] = NULL;
    spdm_context->local_context.local_cert_chain_provision_size[0] = 0;
}

/**
 * Test 3: Error case, the negotiated SPDM version is 1.0, which does not define encapsulated
 * requests.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNSUPPORTED_REQUEST and
 * the request code GET_CERTIFICATE as its error data.
 **/
static void req_encap_certificate_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_request_t spdm_request;
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    /* {ERROR} SPDM 1.0 connection. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request), &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_10);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_CERTIFICATE);
}

/**
 * Test 4: Error case, the SPDMVersion of the request does not match the negotiated version.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_VERSION_MISMATCH.
 **/
static void req_encap_certificate_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_request_t spdm_request;
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    /* {ERROR} SPDM 1.2 request in an SPDM 1.1 connection. */
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request), &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 5: Error case, the Requester does not support CERT_CAP.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNSUPPORTED_REQUEST and
 * the request code GET_CERTIFICATE as its error data.
 **/
static void req_encap_certificate_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_request_t spdm_request;
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    /* {ERROR} The Requester does not have a certificate. */
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request), &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_CERTIFICATE);
}

/**
 * Test 6: Error case, the Responder sets LargeCertChain in Param1 but the Requester does not
 * support LARGE_RESP_CAP. DSP0274 1.4 requires LargeCertChain to be 0b in that case.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNSUPPORTED_REQUEST and
 * the request code GET_CERTIFICATE as its error data.
 **/
static void req_encap_certificate_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_large_request_t spdm_request;
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    /* {ERROR} LargeCertChain without LARGE_RESP_CAP. */
    spdm_request.header.param1 = SPDM_GET_CERTIFICATE_REQUEST_LARGE_CERT_CHAIN;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = 0;
    spdm_request.large_offset = 0;
    spdm_request.large_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request), &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_CERTIFICATE);
}

/**
 * Test 7: Error case, the request is one byte shorter than GET_CERTIFICATE.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void req_encap_certificate_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_request_t spdm_request;
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    /* {ERROR} The request is truncated. */
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request) - 1, &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 8: Error case, the Responder requests slot 8. DSP0274 limits SlotID to between 0 and 7
 * inclusive.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void req_encap_certificate_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_request_t spdm_request;
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    /* {ERROR} SlotID is out of range. */
    spdm_request.header.param1 = SPDM_MAX_SLOT_COUNT;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request), &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

int libspdm_req_encap_certificate_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_encap_certificate_err_case1),
        cmocka_unit_test(req_encap_certificate_err_case2),
        cmocka_unit_test(req_encap_certificate_err_case3),
        cmocka_unit_test(req_encap_certificate_err_case4),
        cmocka_unit_test(req_encap_certificate_err_case5),
        cmocka_unit_test(req_encap_certificate_err_case6),
        cmocka_unit_test(req_encap_certificate_err_case7),
        cmocka_unit_test(req_encap_certificate_err_case8),
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
