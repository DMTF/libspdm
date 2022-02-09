/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_encap_get_certificate_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void test_spdm_responder_encap_get_certificate_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_certificate_response_t *spdm_response;
    uintn spdm_response_size;
    bool need_continue;

    spdm_context_t *spdm_context;
    void *data;
    uintn data_size;

    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_response_size = spdm_test_context->test_buffer_size;
    spdm_response = (spdm_certificate_response_t *)spdm_test_context->test_buffer;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                  data_size - sizeof(spdm_cert_chain_t) - hash_size, 0, &root_cert,
                                  &root_cert_size);
    internal_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.slot_count = 1;

    spdm_process_encap_response_certificate(spdm_context, spdm_response_size, spdm_response,
                                            &need_continue);
}

void test_spdm_get_encap_request_get_certificate_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn encap_request_size;
    void *data;
    uintn data_size;

    spdm_get_certificate_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;

    if (encap_request_size < sizeof(spdm_get_certificate_request_t)) {
        encap_request_size = sizeof(spdm_get_certificate_request_t);
    }

    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    spdm_get_encap_request_get_certificate(spdm_context, &encap_request_size, spdm_request);
    free(spdm_request);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_encap_get_certificate_test_context);

    m_spdm_responder_encap_get_certificate_test_context.test_buffer = test_buffer;
    m_spdm_responder_encap_get_certificate_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_responder_encap_get_certificate_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_get_encap_request_get_certificate_case2(&State);
    spdm_unit_test_group_teardown(&State);
}
#else
uintn get_max_buffer_size(void)
{
    return 0;
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
