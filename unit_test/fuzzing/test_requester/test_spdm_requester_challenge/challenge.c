/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

static uintn m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE];

uintn libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status libspdm_device_receive_message(void *spdm_context, uintn *response_size,
                                             void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_challenge_auth_response_t *spdm_response;
    void *data;
    uintn data_size;
    uint8_t *ptr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uintn sig_size;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn temp_buf_size;
    uintn test_message_header_size;

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = 1;
    libspdm_copy_mem((uint8_t *)temp_buf, sizeof(temp_buf),
                     (uint8_t *)spdm_test_context->test_buffer + test_message_header_size,
                     spdm_test_context->test_buffer_size);
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0] =
        data_size;
    ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
                    libspdm_get_hash_size(m_libspdm_use_hash_algo) + SPDM_NONCE_SIZE + 0 +
                    sizeof(uint16_t) + 0 + libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    spdm_response = (void *)temp_buf;

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(
        m_libspdm_use_hash_algo,
        ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision[0],
        ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0], ptr);
    free(data);
    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;
    /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
     * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);
    libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                     sizeof(m_libspdm_local_buffer),
                     spdm_response, (uintn)ptr - (uintn)spdm_response);
    m_libspdm_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                     hash_data);
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    /* The caller need guarantee the version is correct, both of MajorVersion and MinorVersion should be less than 10.*/
    if (((spdm_response->header.spdm_version & 0xF) >= 10) ||
        (((spdm_response->header.spdm_version >> 4) & 0xF) >= 10)) {
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    }
    libspdm_responder_data_sign(spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                                SPDM_CHALLENGE_AUTH, m_libspdm_use_asym_algo,
                                m_libspdm_use_hash_algo, false,
                                m_libspdm_local_buffer, m_libspdm_local_buffer_size, ptr,
                                &sig_size);
    ptr += sig_size;

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false, temp_buf_size, temp_buf,
                                          response_size, response);

    return RETURN_SUCCESS;
}

return_status libspdm_device_send_message(void *spdm_context, uintn request_size,
                                          const void *request, uint64_t timeout)
{
    uint8_t *ptr;

    ptr = (uint8_t *)request;
    m_libspdm_local_buffer_size = 0;
    libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                     request_size - 1);
    m_libspdm_local_buffer_size += (request_size - 1);

    return RETURN_SUCCESS;
}

void libspdm_test_requester_challenge_case1(void **State)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
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
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                               measurement_hash, NULL);
    free(data);
    if (RETURN_NO_RESPONSE != status)
    {
        libspdm_reset_message_c(spdm_context);
    }
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
}

void libspdm_test_requester_challenge_ex_case1(void **State)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
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
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge_ex(spdm_context, 0,
                                  SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                  measurement_hash, NULL, requester_nonce_in, requester_nonce,
                                  responder_nonce);
    free(data);
    if (RETURN_NO_RESPONSE != status)
    {
        libspdm_reset_message_c(spdm_context);
    }
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
}
libspdm_test_context_t m_libspdm_requester_challenge_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_challenge_test_context);

    m_libspdm_requester_challenge_test_context.test_buffer = test_buffer;
    m_libspdm_requester_challenge_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_challenge_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_challenge_ex_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
uintn libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
