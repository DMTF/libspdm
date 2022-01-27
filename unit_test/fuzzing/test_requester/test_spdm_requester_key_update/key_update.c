/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

static void spdm_set_standard_key_update_test_state(IN OUT spdm_context_t *spdm_context,
                                                    IN OUT uint32_t *session_id)
{
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            &hash, &hash_size);
    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
         data, data_size);
#endif
    *session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, *session_id, TRUE);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    free(data);
}

static void spdm_compute_secret_update(uintn hash_size, IN const uint8_t *in_secret,
                                       OUT uint8_t *out_secret, IN uintn out_secret_size)
{
    uint8_t m_bin_str9[128];
    uintn m_bin_str9_size;
    uint16_t length;

    length = (uint16_t)hash_size;
    copy_mem(m_bin_str9, &length, sizeof(uint16_t));
    copy_mem(m_bin_str9 + sizeof(uint16_t), SPDM_BIN_CONCAT_LABEL,
             sizeof(SPDM_BIN_CONCAT_LABEL) - 1);
    copy_mem(m_bin_str9 + sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1,
             SPDM_BIN_STR_9_LABEL, sizeof(SPDM_BIN_STR_9_LABEL));
    m_bin_str9_size =
        sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1 + sizeof(SPDM_BIN_STR_9_LABEL) - 1;

    libspdm_hkdf_expand(m_use_hash_algo, in_secret, hash_size, m_bin_str9, m_bin_str9_size,
                        out_secret, out_secret_size);
}

static void spdm_set_standard_key_update_test_secrets(
    IN OUT spdm_secured_message_context_t *secured_message_context,
    OUT uint8_t *m_rsp_secret_buffer, IN uint8_t rsp_secret_fill, OUT uint8_t *m_req_secret_buffer,
    IN uint8_t req_secret_fill)
{
    set_mem(m_rsp_secret_buffer, secured_message_context->hash_size, rsp_secret_fill);
    set_mem(m_req_secret_buffer, secured_message_context->hash_size, req_secret_fill);

    copy_mem(secured_message_context->application_secret.response_data_secret, m_rsp_secret_buffer,
             secured_message_context->aead_key_size);
    copy_mem(secured_message_context->application_secret.request_data_secret, m_req_secret_buffer,
             secured_message_context->aead_key_size);

    set_mem(secured_message_context->application_secret.response_data_encryption_key,
            secured_message_context->aead_key_size, (uint8_t)(0xFF));
    set_mem(secured_message_context->application_secret.response_data_salt,
            secured_message_context->aead_iv_size, (uint8_t)(0xFF));

    set_mem(secured_message_context->application_secret.request_data_encryption_key,
            secured_message_context->aead_key_size, (uint8_t)(0xEE));
    set_mem(secured_message_context->application_secret.request_data_salt,
            secured_message_context->aead_iv_size, (uint8_t)(0xEE));

    secured_message_context->application_secret.response_data_sequence_number = 0;
    secured_message_context->application_secret.request_data_sequence_number = 0;
}

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
    static uint8_t sub_index = 0;
    spdm_key_update_response_t spdm_response;
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t test_message_header_size;
    uint8_t spdm_response_size;
    session_id = 0xFFFFFFFF;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return RETURN_DEVICE_ERROR;
    }

    test_message_header_size = 1;
    spdm_test_context_t *spdm_test_context;
    spdm_test_context = get_spdm_test_context();
    spdm_response_size = sizeof(spdm_key_update_response_t);
    copy_mem(&spdm_response,
             (uint8_t *)spdm_test_context->test_buffer + test_message_header_size +
                 spdm_response_size * sub_index,
             sizeof(spdm_key_update_response_t));
    if (sub_index != 0) {
        sub_index = 0;
    }
    spdm_transport_test_encode_message(spdm_context, &session_id, FALSE, FALSE,
                                       sizeof(spdm_response), &spdm_response, response_size,
                                       response);
    /* WALKAROUND: If just use single context to encode
           message and then decode message */
    ((spdm_secured_message_context_t *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

    sub_index++;
    return RETURN_SUCCESS;
}

void test_spdm_requester_key_update_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;
    session_id = 0xFFFFFFFF;

    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                              m_rsp_secret_buffer, (uint8_t)(0xFF),
                                              m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(
        ((spdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_req_secret_buffer, m_req_secret_buffer, sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    libspdm_key_update(spdm_context, session_id, TRUE);
}

void test_spdm_requester_key_update_case2(void **state)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    spdm_session_info_t *session_info;
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    session_id = 0xFFFFFFFF;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                              m_rsp_secret_buffer, (uint8_t)(0xFF),
                                              m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(
        ((spdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_req_secret_buffer, m_req_secret_buffer, sizeof(m_req_secret_buffer));
    /*response side updated*/
    spdm_compute_secret_update(
        ((spdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_rsp_secret_buffer, m_rsp_secret_buffer, sizeof(m_rsp_secret_buffer));

    libspdm_key_update(spdm_context, session_id, FALSE);
}

spdm_test_context_t m_spdm_requester_key_update_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    TRUE,
    spdm_device_send_message,
    spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_requester_key_update_test_context);

    m_spdm_requester_key_update_test_context.test_buffer = test_buffer;
    m_spdm_requester_key_update_test_context.test_buffer_size = test_buffer_size;

    /* Successful response. update single key */
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_key_update_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Sucessful response  update all keys*/
    spdm_unit_test_group_setup(&State);
    test_spdm_requester_key_update_case2(&State);
    spdm_unit_test_group_teardown(&State);
}
