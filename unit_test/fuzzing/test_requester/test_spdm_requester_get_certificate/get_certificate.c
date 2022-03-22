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

return_status libspdm_test_verify_spdm_cert_chain(void *spdm_context, uint8_t slot_id,
                                                  size_t cert_chain_size, const void *cert_chain,
                                                  void **trust_anchor,
                                                  size_t *trust_anchor_size)
{
    return RETURN_SUCCESS;
}

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status libspdm_device_send_message(void *spdm_context, size_t request_size,
                                          const void *request, uint64_t timeout)
{
    return RETURN_SUCCESS;
}

#define FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN 0x408
size_t calling_index = 0;

return_status libspdm_device_receive_message(void *spdm_context, size_t *response_size,
                                             void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    size_t portion_length;
    uint8_t spdm_transport_header = LIBSPDM_TEST_MESSAGE_TYPE_SPDM;
    portion_length = FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    spdm_test_context = libspdm_get_test_context();

    libspdm_copy_mem(response, *response_size, &spdm_transport_header, 1);
    libspdm_copy_mem((uint8_t *)response + 1, *response_size - 1,
                     (uint8_t *)spdm_test_context->test_buffer + LIBSPDM_TEST_MESSAGE_TYPE_SPDM +
                     FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     FUZZING_LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    *response_size = portion_length + 1;
    calling_index++;

    return RETURN_SUCCESS;
}

void libspdm_test_requester_get_certificate_case1(void **State)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t *root_cert;
    size_t root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size, cert_chain);
    free(data);
    if (RETURN_NO_RESPONSE != status)
    {
        libspdm_reset_message_b(spdm_context);
    }
}

void libspdm_test_requester_get_certificate_case2(void **State)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t *root_cert;
    size_t root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.verify_peer_spdm_cert_chain = libspdm_test_verify_spdm_cert_chain;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size, cert_chain);
    free(data);
    if (RETURN_NO_RESPONSE != status)
    {
        libspdm_reset_message_b(spdm_context);
    }
}

void libspdm_test_requester_get_certificate_ex_case1(void **State)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t *root_cert;
    size_t root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.verify_peer_spdm_cert_chain = libspdm_test_verify_spdm_cert_chain;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size, cert_chain);
    free(data);
    if (RETURN_NO_RESPONSE != status)
    {
        libspdm_reset_message_b(spdm_context);
    }
}

libspdm_test_context_t m_libspdm_requester_get_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_get_certificate_test_context);

    m_libspdm_requester_get_certificate_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_requester_get_certificate_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /*Support local_context.verify_peer_spdm_cert_chain  */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_ex_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(const void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
