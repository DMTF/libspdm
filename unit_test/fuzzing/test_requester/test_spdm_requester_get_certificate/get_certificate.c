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

return_status test_libspdm_verify_spdm_cert_chain(void *spdm_context, uint8_t slot_id,
                                                  uintn cert_chain_size, const void *cert_chain,
                                                  void **trust_anchor,
                                                  uintn *trust_anchor_size)
{
    return RETURN_SUCCESS;
}

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(void *spdm_context, uintn request_size,
                                       const void *request, uint64_t timeout)
{
    return RETURN_SUCCESS;
}

#define FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN 0x408
uintn calling_index = 0;

return_status spdm_device_receive_message(void *spdm_context, uintn *response_size,
                                          void *response, uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    uintn portion_length;
    uint8_t spdm_transport_header = TEST_MESSAGE_TYPE_SPDM;
    portion_length = FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    spdm_test_context = get_spdm_test_context();

    copy_mem_s(response, *response_size, &spdm_transport_header, 1);
    copy_mem_s((uint8_t *)response + 1, *response_size - 1,
               (uint8_t *)spdm_test_context->test_buffer + TEST_MESSAGE_TYPE_SPDM +
               FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
               FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    *response_size = portion_length + 1;
    calling_index++;

    return RETURN_SUCCESS;
}

void test_spdm_requester_get_certificate_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
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
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

    cert_chain_size = sizeof(cert_chain);
    zero_mem(cert_chain, sizeof(cert_chain));

    libspdm_get_certificate(spdm_context, 0, &cert_chain_size, cert_chain);
    free(data);
}

void test_spdm_requester_get_certificate_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.verify_peer_spdm_cert_chain = test_libspdm_verify_spdm_cert_chain;
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
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

    cert_chain_size = sizeof(cert_chain);
    zero_mem(cert_chain, sizeof(cert_chain));

    libspdm_get_certificate(spdm_context, 0, &cert_chain_size, cert_chain);
    free(data);
}

void test_spdm_requester_get_certificate_ex_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.verify_peer_spdm_cert_chain = test_libspdm_verify_spdm_cert_chain;
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
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

    cert_chain_size = sizeof(cert_chain);
    zero_mem(cert_chain, sizeof(cert_chain));
    libspdm_get_certificate_ex(spdm_context, 0, &cert_chain_size, cert_chain, NULL, NULL);
    free(data);
}

spdm_test_context_t m_spdm_requester_get_certificate_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_get_certificate_test_context);

    m_spdm_requester_get_certificate_test_context.test_buffer = (void *)test_buffer;
    m_spdm_requester_get_certificate_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_get_certificate_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /*Support local_context.verify_peer_spdm_cert_chain  */
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_get_certificate_case2(&State);
    spdm_unit_test_group_teardown(&State);

    spdm_unit_test_group_setup(&State);
    test_spdm_requester_get_certificate_ex_case1(&State);
    spdm_unit_test_group_teardown(&State);
}
#else
uintn get_max_buffer_size(void)
{
    return 0;
}

void run_test_harness(const void *test_buffer, uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
