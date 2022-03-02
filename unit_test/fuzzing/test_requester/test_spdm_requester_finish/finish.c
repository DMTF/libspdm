/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

void libspdm_secured_message_set_response_finished_key(void *spdm_secured_message_context,
                                                       const void *key, uintn key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->hash_size);
    copy_mem(secured_message_context->handshake_secret.response_finished_key,
             sizeof(secured_message_context->handshake_secret.response_finished_key),
             key, secured_message_context->hash_size);
    secured_message_context->finished_key_ready = true;
}

uintn libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status libspdm_device_send_message(void *spdm_context, uintn request_size,
                                          const void *request, uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status libspdm_device_receive_message(void *spdm_context, uintn *response_size,
                                             void *response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();

    copy_mem(response, *response_size,
             spdm_test_context->test_buffer, spdm_test_context->test_buffer_size);
    *response_size = spdm_test_context->test_buffer_size;
    return RETURN_SUCCESS;
}

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_finish_request_mine_t;

libspdm_finish_request_mine_t m_libspdm_finish_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
uintn m_libspdm_finish_request1_size = sizeof(m_libspdm_finish_request1);

void libspdm_test_send_receive_finish_case1(void **State)
{
    return_status status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    libspdm_session_info_t *session_info;
    uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
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

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_response_finished_key(session_info->secured_message_context,
                                                      m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;

    req_slot_id_param = 0;
    status = libspdm_send_receive_finish(spdm_context, session_id, req_slot_id_param);

    free(data);
    if (RETURN_NO_RESPONSE != status)
    {
        libspdm_reset_message_f(spdm_context, session_info);
        libspdm_reset_message_k(spdm_context, session_info);
    }
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif
}

libspdm_test_context_t m_libspdm_requester_finish_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_finish_test_context);

    m_libspdm_requester_finish_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_requester_finish_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_send_receive_finish_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
uintn libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
