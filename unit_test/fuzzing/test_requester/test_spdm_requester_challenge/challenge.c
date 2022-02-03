/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

static uintn m_local_buffer_size;
static uint8_t m_local_buffer[LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE];

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_receive_message(IN void *spdm_context, IN OUT uintn *response_size,
                                          IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;
    spdm_challenge_auth_response_t *spdm_response;
    void *data;
    uintn data_size;
    uint8_t *ptr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uintn sig_size;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn temp_buf_size;
    uintn test_message_header_size;

    spdm_test_context = get_spdm_test_context();
    test_message_header_size = 1;
    copy_mem((uint8_t *)temp_buf,
             (uint8_t *)spdm_test_context->test_buffer + test_message_header_size,
             spdm_test_context->test_buffer_size);
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    ((spdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t *)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t *)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t *)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
                    libspdm_get_hash_size(m_use_hash_algo) + SPDM_NONCE_SIZE + 0 +
                    sizeof(uint16_t) + 0 + libspdm_get_asym_signature_size(m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(
        m_use_hash_algo,
        ((spdm_context_t *)spdm_context)->local_context.local_cert_chain_provision[0],
        ((spdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0], ptr);
    free(data);
    ptr += libspdm_get_hash_size(m_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;
    /* zero_mem (ptr, libspdm_get_hash_size (m_use_hash_algo));
     * ptr += libspdm_get_hash_size (m_use_hash_algo);*/
    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);
    copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
             (uintn)ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
    internal_dump_hex(m_local_buffer, m_local_buffer_size);
    libspdm_hash_all(m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    internal_dump_hex(m_local_buffer, m_local_buffer_size);
    sig_size = libspdm_get_asym_signature_size(m_use_asym_algo);
    libspdm_responder_data_sign(spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                                SPDM_CHALLENGE_AUTH, m_use_asym_algo, m_use_hash_algo, false,
                                m_local_buffer, m_local_buffer_size, ptr, &sig_size);
    ptr += sig_size;

    spdm_transport_test_encode_message(spdm_context, NULL, false, false, temp_buf_size, temp_buf,
                                       response_size, response);

    return RETURN_SUCCESS;
}

return_status spdm_device_send_message(IN void *spdm_context, IN uintn request_size,
                                       IN void *request, IN uint64_t timeout)
{
    uint8_t *ptr;

    ptr = (uint8_t *)request;
    m_local_buffer_size = 0;
    copy_mem(m_local_buffer, &ptr[1], request_size - 1);
    m_local_buffer_size += (request_size - 1);

    return RETURN_SUCCESS;
}

void test_spdm_requester_challenge_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#endif

    zero_mem(measurement_hash, sizeof(measurement_hash));
    libspdm_challenge(spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                      measurement_hash, NULL);
}

void test_spdm_requester_challenge_ex_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t requester_nonce_in[LIBSPDM_MAX_BUFFER_SIZE];
    uint8_t requester_nonce[LIBSPDM_MAX_BUFFER_SIZE];
    uint8_t responder_nonce[LIBSPDM_MAX_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#endif

    zero_mem(measurement_hash, sizeof(measurement_hash));
    libspdm_challenge_ex(spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                         measurement_hash, NULL, requester_nonce_in, requester_nonce,
                         responder_nonce);
}
spdm_test_context_t m_spdm_requester_challenge_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_challenge_test_context);

    m_spdm_requester_challenge_test_context.test_buffer = test_buffer;
    m_spdm_requester_challenge_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_challenge_case1(&State);
    spdm_unit_test_group_teardown(&State);

    spdm_unit_test_group_setup(&State);
    test_spdm_requester_challenge_ex_case1(&State);
    spdm_unit_test_group_teardown(&State);
}
