/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_encap_challenge_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

static uintn m_local_buffer_size;
static uint8_t m_local_buffer[LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE];

void test_spdm_responder_encap_challenge_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t *ptr;
    uintn spdm_response_size;
    uintn sig_size;
    void *data;
    uintn data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_response_size = spdm_test_context->test_buffer_size;
    spdm_response = (spdm_challenge_auth_response_t *)spdm_test_context->test_buffer;

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

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);
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

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(m_use_hash_algo, (spdm_context)->local_context.local_cert_chain_provision[0],
                     (spdm_context)->local_context.local_cert_chain_provision_size[0], ptr);
    ptr += libspdm_get_hash_size(m_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;

    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);
    copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
             (uintn)ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
    internal_dump_hex(m_local_buffer, m_local_buffer_size);
    libspdm_hash_all(m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    internal_dump_hex(m_local_buffer, m_local_buffer_size);
    sig_size = libspdm_get_asym_signature_size(m_use_asym_algo);

    ptr += sig_size;

    spdm_process_encap_response_challenge_auth(spdm_context, spdm_response_size, spdm_response,
                                               NULL);
    free(data);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    free(spdm_context->transcript.digest_context_mut_m1m2);
    #endif
}

void test_spdm_get_encap_request_challenge_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn encap_request_size;
    void *data;
    uintn data_size;

    spdm_challenge_request_t *spdm_request;
    spdm_request = malloc(sizeof(spdm_challenge_request_t));

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;
    if (encap_request_size < sizeof(spdm_get_certificate_request_t)) {
        encap_request_size = sizeof(spdm_get_certificate_request_t);
    }
    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_c(spdm_context);

    spdm_get_encap_request_challenge(spdm_context, &encap_request_size, spdm_request);
    free(spdm_request);
    free(data);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    free(spdm_context->transcript.digest_context_mut_m1m2);
    #endif
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_encap_challenge_test_context);

    m_spdm_responder_encap_challenge_test_context.test_buffer = test_buffer;
    m_spdm_responder_encap_challenge_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_encap_challenge_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_get_encap_request_challenge_case2(&State);
    spdm_unit_test_group_teardown(&State);
}
#else
uintn get_max_buffer_size(void)
{
    return 0;
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
