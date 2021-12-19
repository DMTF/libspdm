/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"
#include "spdm_secured_message_lib.h"
#include "spdm_transport_mctp_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_encode_secured_message(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn secured_message_size;
    uint8_t secured_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    spdm_secured_message_callbacks_t spdm_secured_message_callbacks_t;
    spdm_session_info_t *session_info;
    boolean is_requester;
    uint32_t session_id;
    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    is_requester = spdm_test_context->is_requester;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_secured_message_callbacks_t.version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks_t.get_sequence_number = spdm_mctp_get_sequence_number;
    spdm_secured_message_callbacks_t.get_max_random_number_count =
        spdm_mctp_get_max_random_number_count;
    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
    secured_message_context = session_info->secured_message_context;
    secured_message_context->session_type = SPDM_SESSION_TYPE_MAC_ONLY;
    secured_message_context->session_state = SPDM_SESSION_STATE_HANDSHAKING;
    secured_message_context->aead_key_size = MAX_AEAD_KEY_SIZE;
    secured_message_context->aead_iv_size = MAX_AEAD_IV_SIZE;

    secured_message_size = sizeof(secured_message);

    spdm_encode_secured_message(secured_message_context, session_id, is_requester,
                                spdm_test_context->test_buffer_size, spdm_test_context->test_buffer,
                                &secured_message_size, secured_message,
                                &spdm_secured_message_callbacks_t);
}

spdm_test_context_t m_spdm_transport_mctp_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    FALSE,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_transport_mctp_test_context);

    m_spdm_transport_mctp_test_context.test_buffer = test_buffer;
    m_spdm_transport_mctp_test_context.test_buffer_size = test_buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_encode_secured_message(&State);

    spdm_unit_test_group_teardown(&State);
}
