/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)

static void *m_libspdm_local_certificate_chain;
static size_t m_libspdm_local_certificate_chain_size;

spdm_certificate_response_t m_spdm_get_certificate_response1;
size_t m_spdm_get_certificate_response1_size;

spdm_certificate_response_t m_spdm_get_certificate_response2 = {
    {SPDM_MESSAGE_VERSION_10, SPDM_ERROR, SPDM_ERROR_CODE_INVALID_REQUEST, 0},
    0,
    0
};
size_t m_spdm_get_certificate_response2_size = sizeof(m_spdm_get_certificate_response2);


/**
 * Test 1: Normal case, request a certificate chain
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void test_spdm_responder_encap_get_certificate_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;
    spdm_certificate_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t temp_buf_size;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;
    size_t spdm_response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    libspdm_init_managed_buffer(&spdm_context->encap_context.certificate_chain_buffer,
                                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    if (m_libspdm_local_certificate_chain == NULL)
    {
        libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &m_libspdm_local_certificate_chain,
            &m_libspdm_local_certificate_chain_size, NULL, NULL);
    }

    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    remainder_length =
        (uint16_t)(m_libspdm_local_certificate_chain_size -
                   LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                   (calling_index + 1));

    temp_buf_size =
        sizeof(spdm_certificate_response_t) + portion_length;
    spdm_response_size = temp_buf_size;
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = portion_length;
    spdm_response->remainder_length = remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response),
                     (uint8_t *)m_libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(m_libspdm_local_certificate_chain);
    m_libspdm_local_certificate_chain = NULL;
    m_libspdm_local_certificate_chain_size = 0;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}


/**
 * Test 2: force responder to send an ERROR message with code SPDM_ERROR_CODE_INVALID_REQUEST
 * Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void test_spdm_responder_encap_get_certificate_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    status = libspdm_process_encap_response_certificate(spdm_context,
                                                        m_spdm_get_certificate_response2_size,
                                                        &m_spdm_get_certificate_response2,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 3: Fail case, request a certificate chain,
 * spdm_request.offset + spdm_response.portion_length + spdm_response.remainder_length !=
 * total_responder_cert_chain_buffer_length.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_responder_encap_get_certificate_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;
    spdm_certificate_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t temp_buf_size;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;
    size_t spdm_response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;


    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    libspdm_init_managed_buffer(&spdm_context->encap_context.certificate_chain_buffer,
                                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    if (m_libspdm_local_certificate_chain == NULL)
    {
        libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &m_libspdm_local_certificate_chain,
            &m_libspdm_local_certificate_chain_size, NULL, NULL);
    }

    portion_length = 0;
    /* Fail response: spdm_request.offset + spdm_response.portion_length + spdm_response.remainder_length !=
     * total_responder_cert_chain_buffer_length.*/
    remainder_length =
        (uint16_t)(m_libspdm_local_certificate_chain_size - 1 -
                   LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (calling_index + 1));

    temp_buf_size =
        sizeof(spdm_certificate_response_t) + portion_length;
    spdm_response_size = temp_buf_size;
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = portion_length;
    spdm_response->remainder_length = remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response),
                     (uint8_t *)m_libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(m_libspdm_local_certificate_chain);
    m_libspdm_local_certificate_chain = NULL;
    m_libspdm_local_certificate_chain_size = 0;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 4: Fail case, request a certificate chain, responder return portion_length > spdm_request.length.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_responder_encap_get_certificate_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;
    spdm_certificate_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t temp_buf_size;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;
    size_t spdm_response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    libspdm_init_managed_buffer(&spdm_context->encap_context.certificate_chain_buffer,
                                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    if (m_libspdm_local_certificate_chain == NULL)
    {
        libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &m_libspdm_local_certificate_chain,
            &m_libspdm_local_certificate_chain_size, NULL, NULL);
    }

    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1; /* Fail response: responder return portion_length > spdm_request.length*/
    remainder_length =
        (uint16_t)(m_libspdm_local_certificate_chain_size - 1 -
                   LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (calling_index + 1));

    temp_buf_size =
        sizeof(spdm_certificate_response_t) + portion_length;
    spdm_response_size = temp_buf_size;
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = portion_length;
    spdm_response->remainder_length = remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response),
                     (uint8_t *)m_libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(m_libspdm_local_certificate_chain);
    m_libspdm_local_certificate_chain = NULL;
    m_libspdm_local_certificate_chain_size = 0;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

libspdm_test_context_t m_spdm_responder_encap_get_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int spdm_responder_encap_get_certificate_test_main(void)
{
    const struct CMUnitTest spdm_responder_certificate_tests[] = {
        /* Success Case*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case1),
        /* Bad request size ,remaining length is 0*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case2),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case2),
        /* Fail response: spdm_request.offset + spdm_response.portion_length + spdm_response.remainder_length !=
         * total_responder_cert_chain_buffer_length.*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case3),
        /* Fail response: responder return portion_length > spdm_request.length*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case4),
    };

    libspdm_setup_test_context(&m_spdm_responder_encap_get_certificate_test_context);

    return cmocka_run_group_tests(spdm_responder_certificate_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)*/
