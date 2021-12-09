/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_responder_lib.h"


static void
spdm_set_standard_key_update_test_state(IN OUT spdm_context_t *spdm_context,
                    IN OUT uint32_t *session_id)
{
    spdm_session_info_t *session_info;

    spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        SPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;

    *session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = *session_id;
    spdm_context->last_spdm_request_session_id_valid = TRUE;
    spdm_context->last_spdm_request_session_id = *session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, *session_id, TRUE);
    spdm_secured_message_set_session_state(
        session_info->secured_message_context,
        SPDM_SESSION_STATE_ESTABLISHED);

    set_mem(spdm_context->last_update_request, 4, 0x00);
}

static void spdm_set_standard_key_update_test_secrets(
    IN OUT spdm_secured_message_context_t *secured_message_context,
    OUT uint8_t *m_rsp_secret_buffer, IN uint8_t rsp_secret_fill,
    OUT uint8_t *m_req_secret_buffer, IN uint8_t req_secret_fill)
{
    set_mem(m_rsp_secret_buffer, secured_message_context->hash_size,
        rsp_secret_fill);
    set_mem(m_req_secret_buffer, secured_message_context->hash_size,
        req_secret_fill);

    copy_mem(
        secured_message_context->application_secret.response_data_secret,
        m_rsp_secret_buffer, secured_message_context->aead_key_size);
    copy_mem(
        secured_message_context->application_secret.request_data_secret,
        m_req_secret_buffer, secured_message_context->aead_key_size);

    set_mem(secured_message_context->application_secret
            .response_data_encryption_key,
        secured_message_context->aead_key_size, (uint8_t)(0xFF));
    set_mem(secured_message_context->application_secret.response_data_salt,
        secured_message_context->aead_iv_size, (uint8_t)(0xFF));

    set_mem(secured_message_context->application_secret
            .request_data_encryption_key,
        secured_message_context->aead_key_size, (uint8_t)(0xEE));
    set_mem(secured_message_context->application_secret.request_data_salt,
        secured_message_context->aead_iv_size, (uint8_t)(0xEE));

    secured_message_context->application_secret
        .response_data_sequence_number = 0;
    secured_message_context->application_secret
        .request_data_sequence_number = 0;
}

static void spdm_compute_secret_update(uintn hash_size,
                       IN const uint8_t *in_secret,
                       OUT uint8_t *out_secret,
                       IN uintn out_secret_size)
{
    uint8_t m_bin_str9[128];
    uintn m_bin_str9_size;
    uint16_t length;

    length = (uint16_t)hash_size;
    copy_mem(m_bin_str9, &length, sizeof(uint16_t));
    copy_mem(m_bin_str9 + sizeof(uint16_t), BIN_CONCAT_LABEL,
         sizeof(BIN_CONCAT_LABEL) - 1);
    copy_mem(m_bin_str9 + sizeof(uint16_t) + sizeof(BIN_CONCAT_LABEL) - 1,
         BIN_STR_9_LABEL, sizeof(BIN_STR_9_LABEL));
    m_bin_str9_size = sizeof(uint16_t) + sizeof(BIN_CONCAT_LABEL) - 1 +
              sizeof(BIN_STR_9_LABEL) - 1;
    //context is NULL for key update

    spdm_hkdf_expand(m_use_hash_algo, in_secret, hash_size, m_bin_str9,
             m_bin_str9_size, out_secret, out_secret_size);
}

uintn get_max_buffer_size(void)
{
    return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_encap_get_digests_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    FALSE,
};

void test_spdm_responder_encap_get_digests(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    boolean need_continue;
    spdm_session_info_t *session_info;
    spdm_secured_message_context_t *secured_message_context;
    uint8_t m_req_secret_buffer[MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[MAX_HASH_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context, m_rsp_secret_buffer,
        (uint8_t)(0xFF), m_req_secret_buffer, (uint8_t)(0xEE));

    spdm_compute_secret_update(secured_message_context->hash_size,
                   m_req_secret_buffer, m_req_secret_buffer,
                   secured_message_context->hash_size);

    need_continue = FALSE;
    spdm_process_encap_response_key_update(
        spdm_context, spdm_test_context->test_buffer_size,
        spdm_test_context->test_buffer, &need_continue);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_encap_get_digests_test_context);

    m_spdm_responder_encap_get_digests_test_context.test_buffer = test_buffer;
    m_spdm_responder_encap_get_digests_test_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_responder_encap_get_digests(&State);

    spdm_unit_test_group_teardown(&State);
}
