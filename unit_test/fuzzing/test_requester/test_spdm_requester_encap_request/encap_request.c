/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context, IN uintn request_size,
                                       IN void *request, IN uint64_t timeout)
{
    return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context, IN OUT uintn *response_size,
                                          IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;
    spdm_session_info_t *session_info;
    static uint8_t sub_index = 0;
    uint32_t session_id;
    uint8_t test_message_header_size;
    uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn temp_buf_size;
    uint8_t test_message_size;

    session_id = 0xFFFFFFFF;

    spdm_test_context = get_spdm_test_context();

    test_message_header_size = 1;
    switch (sub_index) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
        temp_buf_size = 16;
        test_message_size = 16;

        copy_mem((uint8_t *)temp_buf,
                 (uint8_t *)spdm_test_context->test_buffer + test_message_header_size +
                 test_message_size * sub_index,
                 temp_buf_size);
        break;
    case 5:
        temp_buf_size = 44;
        test_message_size = 16;

        copy_mem((uint8_t *)temp_buf,
                 (uint8_t *)spdm_test_context->test_buffer + test_message_header_size +
                 temp_buf_size * sub_index,
                 temp_buf_size);
        break;
    case 6:
        temp_buf_size = 8;
        test_message_size = 16;
        copy_mem((uint8_t *)temp_buf,
                 (uint8_t *)spdm_test_context->test_buffer + test_message_header_size +
                 test_message_size * sub_index + 28,
                 temp_buf_size);
        sub_index = 0;
        break;
    }
    spdm_transport_test_encode_message(spdm_context, &session_id, false, false, temp_buf_size,
                                       temp_buf, response_size, response);

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return RETURN_DEVICE_ERROR;
    }
    /* WALKAROUND: If just use single context to encode message and then decode message */
    ((spdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number--;

    sub_index++;
    return RETURN_SUCCESS;
}

spdm_test_context_t m_spdm_requester_encap_request_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void test_spdm_requester_encap_request(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_register_get_encap_response_func(spdm_context,spdm_get_encap_response_digest);
    libspdm_send_receive_encap_request(spdm_context, &session_id);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_encap_request_test_context);

    m_spdm_requester_encap_request_test_context.test_buffer = test_buffer;
    m_spdm_requester_encap_request_test_context.test_buffer_size = test_buffer_size;

    /* Successful response */
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_encap_request(&State);
    spdm_unit_test_group_teardown(&State);
}
