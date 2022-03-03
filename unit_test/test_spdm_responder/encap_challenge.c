/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_test.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

spdm_challenge_auth_response_t m_spdm_challenge_response1 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE_AUTH, 0,
     SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH}};

uintn m_spdm_challenge_response1_size = sizeof(m_spdm_challenge_response1);

spdm_challenge_auth_response_t m_spdm_challenge_response2 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE_AUTH, 0,
     SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH},
};
uintn m_spdm_challenge_response2_size = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;

spdm_challenge_auth_response_t m_spdm_challenge_response3 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE_AUTH, SPDM_MAX_SLOT_COUNT,
     SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH},
};
uintn m_spdm_challenge_response3_size = sizeof(m_spdm_challenge_response3);

spdm_challenge_auth_response_t m_spdm_challenge_response4 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE_AUTH, 1,
     SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH},
};
uintn m_spdm_challenge_response4_size = sizeof(m_spdm_challenge_response4);

spdm_challenge_auth_response_t m_spdm_challenge_response5 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE_AUTH, 0,
     SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH},
};
uintn m_spdm_challenge_response5_size = sizeof(m_spdm_challenge_response5);

spdm_challenge_auth_response_t m_spdm_challenge_response6 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE_AUTH, 0,
     SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH},
};
uintn m_spdm_challenge_response6_size = sizeof(m_spdm_challenge_response6);

uint8_t m_opaque_challenge_auth_rsp[9] = "openspdm";

/**
 * Test 1: receiving a correct CHALLENGE message from the requester with
 * no opaque data, no measurements, and slot number 0.
 * Expected behavior: the responder accepts the request and produces a valid
 * CHALLENGE_AUTH response message.
 **/
static uintn m_local_buffer_size;
static uint8_t m_local_buffer[LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE];
void test_spdm_responder_encap_challenge_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t *ptr;
    uintn spdm_response_size;
    uintn sig_size;
    void *data;
    uintn data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    spdm_response_size = sizeof(m_spdm_challenge_response1);
    spdm_response = &m_spdm_challenge_response1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_use_req_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(m_use_hash_algo, spdm_context->local_context.local_cert_chain_provision[0],
                     spdm_context->local_context.local_cert_chain_provision_size[0], ptr);
    ptr += libspdm_get_hash_size(m_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;
    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);
    copy_mem_s(&m_local_buffer[m_local_buffer_size],
               sizeof(m_local_buffer) - (&m_local_buffer[m_local_buffer_size] - m_local_buffer),
               spdm_response, (uintn)ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
    internal_dump_hex(m_local_buffer, m_local_buffer_size);
    libspdm_hash_all(m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    internal_dump_hex(m_local_buffer, m_local_buffer_size);

    sig_size = libspdm_get_asym_signature_size(m_use_asym_algo);

    ptr += sig_size;

    status = spdm_process_encap_response_challenge_auth(spdm_context, spdm_response_size, spdm_response,
                                                        NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_challenge_auth_response_t) +
                         libspdm_get_hash_size(m_use_hash_algo) +
                         SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                         libspdm_get_asym_signature_size(m_use_asym_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CHALLENGE_AUTH);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->header.param2, 1 << 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data);
}

/**
 * Test 2: receiving a CHALLENGE message larger than specified.
 * Expected behavior: the responder refuses the CHALLENGE message and produces an
 * ERROR message indicating the InvalidRequest.
 **/
void test_spdm_responder_encap_challenge_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;

    spdm_challenge_auth_response_t *spdm_response;
    void *data;
    uintn data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->local_context.slot_count = 1;
    spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
    libspdm_reset_message_c(spdm_context);

    status = spdm_process_encap_response_challenge_auth(
        spdm_context, m_spdm_challenge_response2_size,
        &m_spdm_challenge_response2, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data);
}

/**
 * Test 3: receiving a correct CHALLENGE from the requester, but the responder is in
 * a Busy state.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the Busy state.
 **/
void test_spdm_responder_encap_challenge_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;

    spdm_challenge_auth_response_t *spdm_response;
    void *data;
    uintn data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->local_context.slot_count = 1;
    spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
    libspdm_reset_message_c(spdm_context);

    status = spdm_process_encap_response_challenge_auth(
        spdm_context, m_spdm_challenge_response1_size,
        &m_spdm_challenge_response1, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_BUSY);
    free(data);
}

/**
 * Test 4: receiving a correct CHALLENGE from the requester, but the responder requires
 * resynchronization with the requester.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the NeedResynch state.
 **/
void test_spdm_responder_encap_challenge_case4(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;

    spdm_challenge_auth_response_t *spdm_response;
    void *data;
    uintn data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->local_context.slot_count = 1;
    spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
    libspdm_reset_message_c(spdm_context);

    status = spdm_process_encap_response_challenge_auth(
        spdm_context, m_spdm_challenge_response1_size,
        &m_spdm_challenge_response1, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
    free(data);
}

/**
 * Test 5: receiving a correct CHALLENGE from the requester, but the responder could not
 * produce the response in time.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the ResponseNotReady state.
 **/
void test_spdm_responder_encap_challenge_case5(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;

    spdm_challenge_auth_response_t *spdm_response;
    void *data;
    uintn data_size;
    spdm_error_data_response_not_ready_t *error_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->local_context.slot_count = 1;
    spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
    libspdm_reset_message_c(spdm_context);

    status = spdm_process_encap_response_challenge_auth(
        spdm_context, m_spdm_challenge_response1_size,
        &m_spdm_challenge_response1, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                         sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data =
        (spdm_error_data_response_not_ready_t *)(spdm_response + 1);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_CHALLENGE);
    free(data);
}

/**
 * Test 6: receiving a correct CHALLENGE from the requester, but the responder is not set
 * no receive a CHALLENGE message because previous messages (namely, GET_CAPABILITIES,
 * NEGOTIATE_ALGORITHMS or GET_DIGESTS) have not been received.
 * Expected behavior: the responder rejects the request, and produces an ERROR message
 * indicating the UnexpectedRequest.
 **/
void test_spdm_responder_encap_challenge_case6(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;

    spdm_challenge_auth_response_t *spdm_response;
    void *data;
    uintn data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->local_context.slot_count = 1;
    spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
    libspdm_reset_message_c(spdm_context);

    status = spdm_process_encap_response_challenge_auth(
        spdm_context, m_spdm_challenge_response1_size,
        &m_spdm_challenge_response1, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data);
}

spdm_test_context_t m_spdm_responder_encap_challenge_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

int spdm_responder_encap_challenge_test_main(void)
{
    const struct CMUnitTest spdm_responder_encap_challenge_tests[] = {
        /* Success Case*/
        cmocka_unit_test(test_spdm_responder_encap_challenge_case1),
        /* Bad request size*/
        cmocka_unit_test(test_spdm_responder_encap_challenge_case2),
        /* response_state: LIBSPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(test_spdm_responder_encap_challenge_case3),
        /* response_state: LIBSPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(test_spdm_responder_encap_challenge_case4),
        /* response_state: LIBSPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(test_spdm_responder_encap_challenge_case5),
        /* connection_state Check*/
        cmocka_unit_test(test_spdm_responder_encap_challenge_case6),
    };

    setup_spdm_test_context(&m_spdm_responder_encap_challenge_test_context);

    return cmocka_run_group_tests(spdm_responder_encap_challenge_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
