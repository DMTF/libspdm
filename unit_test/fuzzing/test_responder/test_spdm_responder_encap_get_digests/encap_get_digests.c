/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_encap_get_digests_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void test_spdm_responder_encap_get_digests_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    bool need_continue;
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    set_mem(m_local_certificate_chain, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE, (uint8_t)(0xFF));
    spdm_context->local_context.slot_count = 1;

    spdm_process_encap_response_digest(spdm_context, spdm_test_context->test_buffer_size,
                                       spdm_test_context->test_buffer, &need_continue);
}

void test_spdm_get_encap_request_get_digest_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_get_digest_request_t *spdm_request;
    spdm_context_t *spdm_context;
    uintn encap_request_size;
    void *data;
    uintn data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;

    if (encap_request_size < sizeof(spdm_get_digest_request_t)) {
        encap_request_size = sizeof(spdm_get_digest_request_t);
    }
    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    spdm_get_encap_request_get_digest(spdm_context, &encap_request_size, spdm_request);
    free(spdm_request);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_encap_get_digests_test_context);

    m_spdm_responder_encap_get_digests_test_context.test_buffer = test_buffer;
    m_spdm_responder_encap_get_digests_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_encap_get_digests_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_get_encap_request_get_digest_case2(&State);
    spdm_unit_test_group_teardown(&State);
}
