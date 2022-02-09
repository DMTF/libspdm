/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_requester_encap_certificate(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn request_size;
    uintn response_size;
    uint8_t test_message_header_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;

    spdm_test_context = *State;
    test_message_header_size = 1;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;

    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);

    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.slot_count = 1;

    request_size = spdm_test_context->test_buffer_size;
    if (request_size > sizeof(spdm_get_certificate_request_t)) {
        request_size = sizeof(spdm_get_certificate_request_t);
    }

    response_size = sizeof(response);
    spdm_get_encap_response_certificate(spdm_context, request_size,
                                        (uint8_t *)spdm_test_context->test_buffer +
                                        test_message_header_size,
                                        &response_size, response);
}

spdm_test_context_t m_spdm_requester_encap_certificate_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_encap_certificate_test_context);

    m_spdm_requester_encap_certificate_test_context.test_buffer = test_buffer;
    m_spdm_requester_encap_certificate_test_context.test_buffer_size = test_buffer_size;

    /* Successful response */
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_encap_certificate(&State);
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
