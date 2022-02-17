/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_unit_test.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

spdm_get_digest_request_t m_spdm_get_digests_request1 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_DIGESTS,
    },
};
uintn m_spdm_get_digests_request1_size = sizeof(m_spdm_get_digests_request1);

spdm_get_digest_request_t m_spdm_get_digests_request2 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_DIGESTS,
    },
};
uintn m_spdm_get_digests_request2_size = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;

static uint8_t m_local_certificate_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

/**
 * Test 1: receives a valid GET_DIGESTS request message from Requester
 * Expected Behavior: produces a valid DIGESTS response message
 **/
void test_spdm_requester_challenge_auth_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
            (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = spdm_get_encap_response_digest(spdm_context,
                                            m_spdm_get_digests_request1_size,
                                            &m_spdm_get_digests_request1,
                                            &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
}

/**
 * Test 2: receives a GET_DIGESTS request message with bad size from Requester
 * Expected Behavior: produces an ERROR response message with error code = InvalidRequest
 **/
void test_spdm_requester_challenge_auth_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
            (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;

    response_size = sizeof(response);
    status = spdm_get_encap_response_digest(spdm_context,
                                            m_spdm_get_digests_request2_size,
                                            &m_spdm_get_digests_request2,
                                            &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 3: receives a valid GET_DIGESTS request message from Requester, but the request message cannot be appended to the internal cache since the internal cache is full
 * Expected Behavior: produces an ERROR response message with error code = Unspecified
 **/
void test_spdm_requester_challenge_auth_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_digest_response_t *spdm_response;
#endif
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
            (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;

    response_size = sizeof(response);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
#endif
    status = spdm_get_encap_response_digest(spdm_context,
                                            m_spdm_get_digests_request1_size,
                                            &m_spdm_get_digests_request1,
                                            &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
    assert_int_equal(spdm_response->header.param1,
                     0);
    assert_int_equal(spdm_response->header.param2, SPDM_ERROR_CODE_INVALID_REQUEST);
#endif
}

/**
 * Test 4: receives a valid GET_DIGESTS request message from Requester, but the response message cannot be appended to the internal cache since the internal cache is full
 * Expected Behavior: produces an ERROR response message with error code = Unspecified
 **/
void test_spdm_requester_challenge_auth_case4(void **state)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    return_status status;
    spdm_digest_response_t *spdm_response;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
            (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size -
        sizeof(spdm_get_digest_request_t);
    response_size = sizeof(response);
    status = spdm_get_encap_response_digest(spdm_context,
                                            m_spdm_get_digests_request1_size,
                                            &m_spdm_get_digests_request1,
                                            &response_size, response);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
    assert_int_equal(spdm_response->header.param1,
                     0);
    assert_int_equal(spdm_response->header.param2, SPDM_ERROR_CODE_INVALID_REQUEST);
#endif
}

spdm_test_context_t m_spdm_requester_digests_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

int spdm_requester_encap_digests_test_main(void)
{
    const struct CMUnitTest spdm_requester_digests_tests[] = {
        /* Success Case*/
        cmocka_unit_test(test_spdm_requester_challenge_auth_case1),
        /* Bad request size*/
        cmocka_unit_test(test_spdm_requester_challenge_auth_case2),
        /* Internal cache full (request message)*/
        cmocka_unit_test(test_spdm_requester_challenge_auth_case3),
        /* Internal cache full (response message)*/
        cmocka_unit_test(test_spdm_requester_challenge_auth_case4),
    };

    setup_spdm_test_context(&m_spdm_requester_digests_test_context);

    return cmocka_run_group_tests(spdm_requester_digests_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
