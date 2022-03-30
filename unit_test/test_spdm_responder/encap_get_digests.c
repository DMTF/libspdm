/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link:
 * https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

uint8_t m_local_digests_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
static uint8_t m_libspdm_local_certificate_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

/**
 * Test 1: Response message received successfully
 * Expected Behavior: requester returns the status RETURN_SUCCESS and a DIGESTS message is received
 **/
void test_spdm_responder_encap_get_digests_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_digest_response_t *spdm_response;
    uint8_t *digest;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.peer_cert_chain_provision =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.peer_cert_chain_provision_size =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    libspdm_set_mem(m_libspdm_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
                    (uint8_t)(0xFF));
    libspdm_reset_message_b(spdm_context);

    ((libspdm_context_t *)spdm_context)
    ->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_response_size = sizeof(spdm_digest_response_t) +
                         libspdm_get_hash_size(m_libspdm_use_hash_algo) * SPDM_MAX_SLOT_COUNT;
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.param1 = 0;
    spdm_response->header.request_response_code = SPDM_DIGESTS;
    spdm_response->header.param2 = 0;
    libspdm_set_mem(m_libspdm_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
                    (uint8_t)(0xFF));

    digest = (void *)(spdm_response + 1);
    /*send all eight certchains digest
     * but only No.7 is right*/
    digest += libspdm_get_hash_size(m_libspdm_use_hash_algo) * (SPDM_MAX_SLOT_COUNT - 2);
    libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                     LIBSPDM_MAX_MESSAGE_BUFFER_SIZE, &digest[0]);
    spdm_response->header.param2 |= (0xFF << 0);

    status = libspdm_process_encap_response_digest(spdm_context, spdm_response_size,
                                                   spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 2: Error response message with error code busy
 * Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
 **/
void test_spdm_responder_encap_get_digests_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t spdm_response;
    size_t spdm_response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.peer_cert_chain_provision =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.peer_cert_chain_provision_size =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    libspdm_set_mem(m_libspdm_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
                    (uint8_t)(0xFF));
    libspdm_reset_message_b(spdm_context);

    spdm_response_size = sizeof(spdm_error_response_t);
    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response.header.request_response_code = SPDM_ERROR;
    spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_digest(spdm_context, spdm_response_size,
                                                   &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 3: Error response message with error code busy reponse seize incorrect
 * Expected Behavior:  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
 **/
void test_spdm_responder_encap_get_digests_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.peer_cert_chain_provision =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.peer_cert_chain_provision_size =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    libspdm_set_mem(m_libspdm_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
                    (uint8_t)(0xFF));
    libspdm_reset_message_b(spdm_context);

    spdm_digest_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE] = {0};
    size_t spdm_response_size;

    spdm_response_size = 0;
    spdm_response = (void *)temp_buf;

    status = libspdm_process_encap_response_digest(spdm_context, spdm_response_size,
                                                   spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 4: The code of the request_response_code  summary in the response message is different
 * Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
 **/
void test_spdm_responder_encap_get_digests_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.peer_cert_chain_provision =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.peer_cert_chain_provision_size =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;

    spdm_digest_response_t *spdm_response;
    uint8_t *digest;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;

    spdm_response_size = sizeof(spdm_digest_response_t) +
                         libspdm_get_hash_size(m_libspdm_use_hash_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    libspdm_set_mem(m_libspdm_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
                    (uint8_t)(0xFF));

    digest = (void *)(spdm_response + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                     LIBSPDM_MAX_MESSAGE_BUFFER_SIZE, &digest[0]);
    spdm_response->header.param2 |= (1 << 0);

    status = libspdm_process_encap_response_digest(spdm_context, spdm_response_size,
                                                   spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 5: flag cert_cap from CAPABILITIES is not setted meaning the Requester does not support DIGESTS and
 * CERTIFICATE response messages
 * Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
 **/
void test_spdm_responder_encap_get_digests_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_digest_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE] = {0};
    size_t spdm_response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.peer_cert_chain_provision =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.peer_cert_chain_provision_size =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    libspdm_set_mem(m_libspdm_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE,
                    (uint8_t)(0xFF));
    libspdm_reset_message_b(spdm_context);

    spdm_response_size = sizeof(spdm_digest_response_t);
    spdm_response = (void *)temp_buf;

    status = libspdm_process_encap_response_digest(spdm_context, spdm_response_size,
                                                   spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

libspdm_test_context_t m_spdm_responder_encap_get_digests_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int spdm_responder_encap_get_digests_test_main(void)
{
    const struct CMUnitTest spdm_responder_digests_tests[] = {
        /* Success Case*/
        cmocka_unit_test(test_spdm_responder_encap_get_digests_case1),
        /* Error response: SPDM_ERROR*/
        cmocka_unit_test(test_spdm_responder_encap_get_digests_case2),
        /* Error response: RETURN_DEVICE_ERROR*/
        cmocka_unit_test(test_spdm_responder_encap_get_digests_case3),
        /* request_response_code wrong in response*/
        cmocka_unit_test(test_spdm_responder_encap_get_digests_case4),
        /* capability flags check failed*/
        cmocka_unit_test(test_spdm_responder_encap_get_digests_case5),
    };

    libspdm_setup_test_context(&m_spdm_responder_encap_get_digests_test_context);

    return cmocka_run_group_tests(spdm_responder_digests_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
