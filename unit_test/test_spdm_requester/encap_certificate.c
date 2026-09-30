/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP)

/* #define TEST_DEBUG*/
#ifdef TEST_DEBUG
#define TEST_DEBUG_PRINT(format, ...) printf(format, ## __VA_ARGS__)
#else
#define TEST_DEBUG_PRINT(...)
#endif

spdm_get_certificate_request_t m_spdm_get_certificate_request1 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_GET_CERTIFICATE, 0, 0},
    0,
    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
};
size_t m_spdm_get_certificate_request1_size = sizeof(m_spdm_get_certificate_request1);

spdm_get_certificate_request_t m_spdm_get_certificate_request3 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_GET_CERTIFICATE, 0, 0}, 0, 0
};
size_t m_spdm_get_certificate_request3_size = sizeof(m_spdm_get_certificate_request3);

spdm_get_certificate_request_t m_spdm_get_certificate_request4 = {
    {SPDM_MESSAGE_VERSION_13, SPDM_GET_CERTIFICATE, 0, 0},
    0,
    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
};
size_t m_spdm_get_certificate_request4_size = sizeof(m_spdm_get_certificate_request4);

/**
 * Test 1: request the first LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN bytes of the
 * certificate chain Expected Behavior: generate a correctly formed Certificate
 * message, including its portion_length and remainder_length fields
 **/
static void req_encap_certificate_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_certificate_response_t *spdm_response;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, m_spdm_get_certificate_request1_size,
        &m_spdm_get_certificate_request1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_certificate_response_t) +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->portion_length, LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_int_equal(spdm_response->remainder_length, data_size - LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 2: request the first LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN bytes of the certificate chain with
 * the LargeOffset and LargeLength fields of SPDM 1.4.
 * Expected Behavior: generate a correctly formed CERTIFICATE message with LargeCertChain set in
 * Param1, PortionLength and RemainderLength set to 0, and the lengths in LargePortionLength and
 * LargeRemainderLength.
 **/
static void req_encap_certificate_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_large_request_t spdm_request;
    spdm_certificate_large_response_t *spdm_response;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
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
    assert_int_equal(response_size, sizeof(spdm_certificate_large_response_t) +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
    assert_int_equal(spdm_response->header.param1, SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_response->portion_length, 0);
    assert_int_equal(spdm_response->remainder_length, 0);
    assert_int_equal(spdm_response->large_portion_length, LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_int_equal(spdm_response->large_remainder_length,
                     data_size - LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_memory_equal(spdm_response + 1, data, LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    spdm_context->local_context.local_cert_chain_provision[0] = NULL;
    spdm_context->local_context.local_cert_chain_provision_size[0] = 0;
    free(data);
}

/**
 * Test 3: request length at the boundary of maximum integer values, while
 * keeping offset 0 Expected Behavior: generate correctly formed Certificate
 * messages, including its portion_length and remainder_length fields
 **/
static void req_encap_certificate_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_certificate_response_t *spdm_response;
    void *data;
    size_t data_size;

    /* Testing Lengths at the boundary of maximum integer values*/
    uint16_t test_lengths[] = {
        0,
        0x7F,
        (uint16_t)(0x7F + 1),
        0xFF,
        0x7FFF,
        (uint16_t)(0x7FFF + 1),
        0xFFFF,
    };
    uint16_t expected_chunk_size;

    /* Setting up the spdm_context and loading a sample certificate chain*/
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    /* This tests considers only offset = 0, other tests vary offset value*/
    m_spdm_get_certificate_request3.offset = 0;

    for (int i = 0; i < sizeof(test_lengths) / sizeof(test_lengths[0]); i++)
    {
        TEST_DEBUG_PRINT("i:%d test_lengths[i]:%u\n", i, test_lengths[i]);
        m_spdm_get_certificate_request3.length = test_lengths[i];
        /* Expected received length is limited by the response_size*/
        response_size = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + sizeof(spdm_certificate_response_t);
        expected_chunk_size =
            (uint16_t) LIBSPDM_MIN(response_size - sizeof(spdm_certificate_response_t),
                                   SPDM_MAX_CERTIFICATE_CHAIN_SIZE);
        expected_chunk_size = LIBSPDM_MIN(expected_chunk_size, m_spdm_get_certificate_request3.length);

        /* resetting an internal buffer to avoid overflow and prevent tests to
         * succeed*/
        libspdm_reset_message_mut_b(spdm_context);
        m_spdm_get_certificate_request3_size = sizeof(m_spdm_get_certificate_request3);
        status = libspdm_get_encap_response_certificate(
            spdm_context, m_spdm_get_certificate_request3_size,
            &m_spdm_get_certificate_request3, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(response_size, sizeof(spdm_certificate_response_t) + expected_chunk_size);
        spdm_response = (void *)response;
        assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
        assert_int_equal(spdm_response->header.param1, 0);
        assert_int_equal(spdm_response->portion_length, expected_chunk_size);
        assert_int_equal(spdm_response->remainder_length, data_size - expected_chunk_size);
    }
    free(data);
}

/**
 * Test 4: request offset at the boundary of maximum integer values, while
 * keeping length 0 Expected Behavior: generate correctly formed Certificate
 * messages, including its portion_length and remainder_length fields
 **/
static void req_encap_certificate_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_certificate_response_t *spdm_response;
    spdm_error_response_t *spdm_responseError;
    void *data;
    size_t data_size;

    /* Testing offsets at the boundary of maximum integer values and at the
     * boundary of certificate length (first three positions)*/
    uint16_t test_offsets[] = {(uint16_t)(-1),
                               0,
                               +1,
                               0,
                               0x7F,
                               (uint16_t)(0x7F + 1),
                               0xFF,
                               0x7FFF,
                               (uint16_t)(0x7FFF + 1),
                               0xFFFF,
                               (uint16_t)(-1)};

    /* Setting up the spdm_context and loading a sample certificate chain*/
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    /* This tests considers only length = 0, other tests vary length value*/
    m_spdm_get_certificate_request3.length = 0;
    /* Setting up offset values at the boundary of certificate length*/
    test_offsets[0] = (uint16_t)(test_offsets[0] + data_size);
    test_offsets[1] = (uint16_t)(test_offsets[1] + data_size);
    test_offsets[2] = (uint16_t)(test_offsets[2] + data_size);

    for (int i = 0; i < sizeof(test_offsets) / sizeof(test_offsets[0]); i++)
    {
        TEST_DEBUG_PRINT("i:%d test_offsets[i]:%u\n", i, test_offsets[i]);
        m_spdm_get_certificate_request3.offset = test_offsets[i];

        /* resetting an internal buffer to avoid overflow and prevent tests to
         * succeed*/
        libspdm_reset_message_mut_b(spdm_context);
        response_size = sizeof(response);
        status = libspdm_get_encap_response_certificate(
            spdm_context, m_spdm_get_certificate_request3_size,
            &m_spdm_get_certificate_request3, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        if (m_spdm_get_certificate_request3.offset >= data_size) {
            /* A too long of an offset should return an error*/
            spdm_responseError = (void *)response;
            assert_int_equal(spdm_responseError->header.request_response_code, SPDM_ERROR);
            assert_int_equal(spdm_responseError->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
        } else {
            /* Otherwise it should work properly, considering length = 0*/
            assert_int_equal(response_size, sizeof(spdm_certificate_response_t));
            spdm_response = (void *)response;
            assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
            assert_int_equal(spdm_response->header.param1, 0);
            assert_int_equal(spdm_response->portion_length, 0);
            assert_int_equal(
                spdm_response->remainder_length,
                (uint16_t)(data_size - m_spdm_get_certificate_request3.offset));
        }
    }
    free(data);
}

/**
 * Test 5: request LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN bytes of long certificate
 * chains, with the largest valid offset Expected Behavior: generate correctly
 * formed Certificate messages, including its portion_length and remainder_length
 * fields
 **/
static void req_encap_certificate_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_certificate_response_t *spdm_response;
    spdm_error_response_t *spdm_responseError;
    void *data;
    size_t data_size;

    uint16_t test_cases[] = {LIBSPDM_TEST_CERT_MAXINT16, LIBSPDM_TEST_CERT_MAXUINT16};

    size_t expected_chunk_size;
    size_t expected_remainder;

    /* Setting up the spdm_context and loading a sample certificate chain*/
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    m_spdm_get_certificate_request3.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
    {
        if (!libspdm_read_responder_public_certificate_chain_by_size(
                /*MAXUINT16_CERT signature_algo is SHA256RSA */
                m_libspdm_use_hash_algo, SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                test_cases[i], &data, &data_size, NULL, NULL)) {
            assert_true(false);
            return;
        }

        spdm_context->local_context.local_cert_chain_provision[0] = data;
        spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

        m_spdm_get_certificate_request3.offset = (uint16_t)(LIBSPDM_MIN(data_size - 1, 0xFFFF));
        TEST_DEBUG_PRINT("data_size: %u\n", data_size);
        TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.offset: %u\n",
                         m_spdm_get_certificate_request3.offset);
        TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.length: %u\n",
                         m_spdm_get_certificate_request3.length);
        TEST_DEBUG_PRINT("offset + length: %u\n",
                         m_spdm_get_certificate_request3.offset +
                         m_spdm_get_certificate_request3.length);

        /* resetting an internal buffer to avoid overflow and prevent tests to
         * succeed*/
        libspdm_reset_message_mut_b(spdm_context);
        response_size = sizeof(response);
        status = libspdm_get_encap_response_certificate(
            spdm_context, m_spdm_get_certificate_request3_size,
            &m_spdm_get_certificate_request3, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        /* Expected received length is limited by LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
         * and by the remaining length*/
        expected_chunk_size =
            (uint16_t)(LIBSPDM_MIN(m_spdm_get_certificate_request3.length,
                                   data_size - m_spdm_get_certificate_request3.offset));
        expected_chunk_size = LIBSPDM_MIN(expected_chunk_size, LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
        /* Expected certificate length left*/
        expected_remainder =
            (uint16_t)(data_size - m_spdm_get_certificate_request3.offset - expected_chunk_size);

        TEST_DEBUG_PRINT("expected_chunk_size %u\n", expected_chunk_size);
        TEST_DEBUG_PRINT("expected_remainder %u\n", expected_remainder);

        if (expected_remainder > 0xFFFF || expected_chunk_size > 0xFFFF) {
            spdm_responseError = (void *)response;
            assert_int_equal(spdm_responseError->header.request_response_code, SPDM_ERROR);
            assert_int_equal(spdm_responseError->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
        } else {
            assert_int_equal(response_size, sizeof(spdm_certificate_response_t) +
                             expected_chunk_size);
            spdm_response = (void *)response;
            assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
            assert_int_equal(spdm_response->header.param1, 0);
            assert_int_equal(spdm_response->portion_length, expected_chunk_size);
            assert_int_equal(spdm_response->remainder_length, expected_remainder);
        }

        TEST_DEBUG_PRINT("\n");

        spdm_context->local_context.local_cert_chain_provision[0] = NULL;
        spdm_context->local_context.local_cert_chain_provision_size[0] = 0;
        free(data);
    }
}

/**
 * Test 6: request a whole certificate chain byte by byte
 * Expected Behavior: generate correctly formed Certificate messages, including
 * its portion_length and remainder_length fields
 **/
static void req_encap_certificate_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_certificate_response_t *spdm_response;
    void *data;
    size_t data_size;
    uint16_t expected_chunk_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif
    /* Setting up the spdm_context and loading a sample certificate chain*/
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    /* This tests considers only length = 1*/
    m_spdm_get_certificate_request3.length = 1;
    expected_chunk_size = 1;

    /* resetting an internal buffer to avoid overflow and prevent tests to
     * succeed*/
    libspdm_reset_message_mut_b(spdm_context);

    spdm_response = NULL;
    for (size_t offset = 0; offset < data_size; offset++)
    {
        TEST_DEBUG_PRINT("offset:%u \n", offset);
        m_spdm_get_certificate_request3.offset = (uint16_t)offset;

        response_size = sizeof(response);
        status = libspdm_get_encap_response_certificate(
            spdm_context, m_spdm_get_certificate_request3_size,
            &m_spdm_get_certificate_request3, &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response = (void *)response;
        /* It may fail because the spdm does not support too many messages.
         * assert_int_equal (spdm_response->header.request_response_code,
         * SPDM_CERTIFICATE);*/
        if (spdm_response->header.request_response_code == SPDM_CERTIFICATE) {
            assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
            assert_int_equal(response_size, sizeof(spdm_certificate_response_t) +
                             expected_chunk_size);
            assert_int_equal(spdm_response->header.param1, 0);
            assert_int_equal(spdm_response->portion_length, expected_chunk_size);
            assert_int_equal(spdm_response->remainder_length,
                             data_size - offset - expected_chunk_size);
            assert_int_equal(((uint8_t *)data)[offset],
                             (response + sizeof(spdm_certificate_response_t))[0]);
        } else {
            assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
            break;
        }
    }
    if (spdm_response != NULL) {
        if (spdm_response->header.request_response_code == SPDM_CERTIFICATE) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
            count = (data_size + m_spdm_get_certificate_request3.length - 1) /
                    m_spdm_get_certificate_request3.length;
            assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size,
                             sizeof(spdm_get_certificate_request_t) * count +
                             sizeof(spdm_certificate_response_t) * count +
                             data_size);
#endif
        }
    }
    free(data);
}

/**
 * Test 7: check request attributes and response attributes , SlotSizeRequested=1b the Offset and Length fields in the
 * GET_CERTIFICATE request shall be ignored by the Responder
 * Expected Behavior: generate a correctly formed Certificate message, including its portion_length and remainder_length fields
 **/
static void req_encap_certificate_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_certificate_response_t *spdm_response;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_mut_b.buffer_size = 0;
#endif

    /* When SlotSizeRequested=1b , the Offset and Length fields in the GET_CERTIFICATE request shall be ignored by the Responder */
    m_spdm_get_certificate_request4.header.param2 =
        SPDM_GET_CERTIFICATE_REQUEST_ATTRIBUTES_SLOT_SIZE_REQUESTED;
    m_spdm_get_certificate_request4.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    m_spdm_get_certificate_request4.offset = 0xFF;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, m_spdm_get_certificate_request4_size,
        &m_spdm_get_certificate_request4, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_certificate_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->portion_length,0);
    assert_int_equal(spdm_response->remainder_length, data_size);

    free(data);
}

/**
 * Test 8: request the certificate chain of slot 0 in a connection where the Requester has multiple
 * asymmetric keys (MULTI_KEY_CONN_REQ is true).
 * Expected Behavior: generate a correctly formed CERTIFICATE message whose Param2 holds the
 * CertificateInfo of slot 0.
 **/
static void req_encap_certificate_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_certificate_request_t spdm_request;
    spdm_certificate_response_t *spdm_response;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.multi_key_conn_req = true;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data, &data_size, NULL, NULL)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_info[0] = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request.header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.offset = 0;
    spdm_request.length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_certificate(
        spdm_context, sizeof(spdm_request), &spdm_request, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_certificate_response_t) +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CERTIFICATE);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->header.param2, SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
    assert_int_equal(spdm_response->portion_length, LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_int_equal(spdm_response->remainder_length, data_size - LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    spdm_context->connection_info.multi_key_conn_req = false;
    spdm_context->local_context.local_cert_info[0] = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    spdm_context->local_context.local_cert_chain_provision[0] = NULL;
    spdm_context->local_context.local_cert_chain_provision_size[0] = 0;
    free(data);
}

int libspdm_req_encap_certificate_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Success Case*/
        cmocka_unit_test(req_encap_certificate_case1),
        /* Large certificate chain fields*/
        cmocka_unit_test(req_encap_certificate_case2),
        cmocka_unit_test(req_encap_certificate_case3),
        /* Tests varying offset*/
        cmocka_unit_test(req_encap_certificate_case4),
        /* Tests large certificate chains*/
        cmocka_unit_test(req_encap_certificate_case5),
        /* Requests byte by byte*/
        cmocka_unit_test(req_encap_certificate_case6),
        /* check request attributes and response attributes*/
        cmocka_unit_test(req_encap_certificate_case7),
        /* CertificateInfo in a multi-key connection*/
        cmocka_unit_test(req_encap_certificate_case8),
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

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (..) */
