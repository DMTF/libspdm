/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

static void libspdm_set_standard_key_update_test_state(libspdm_context_t *spdm_context,
                                                       uint32_t *session_id)
{
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
                     data, data_size);
#endif
    *session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    free(data);
}

static void libspdm_compute_secret_update(uintn hash_size, const uint8_t *in_secret,
                                          uint8_t *out_secret, uintn out_secret_size)
{
    uint8_t m_bin_str9[128];
    uintn m_bin_str9_size;
    uint16_t length;

    length = (uint16_t)hash_size;
    libspdm_copy_mem(m_bin_str9, sizeof(m_bin_str9), &length, sizeof(uint16_t));
    libspdm_copy_mem(m_bin_str9 + sizeof(uint16_t), sizeof(m_bin_str9) - sizeof(uint16_t),
                     SPDM_BIN_CONCAT_LABEL, sizeof(SPDM_BIN_CONCAT_LABEL) - 1);
    libspdm_copy_mem(m_bin_str9 + sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1,
                     sizeof(m_bin_str9) - (sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1),
                     SPDM_BIN_STR_9_LABEL, sizeof(SPDM_BIN_STR_9_LABEL));
    m_bin_str9_size =
        sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1 + sizeof(SPDM_BIN_STR_9_LABEL) - 1;

    libspdm_hkdf_expand(m_libspdm_use_hash_algo, in_secret, hash_size, m_bin_str9, m_bin_str9_size,
                        out_secret, out_secret_size);
}

static void libspdm_set_standard_key_update_test_secrets(
    libspdm_secured_message_context_t *secured_message_context,
    uint8_t *m_rsp_secret_buffer, uint8_t rsp_secret_fill, uint8_t *m_req_secret_buffer,
    uint8_t req_secret_fill)
{
    libspdm_set_mem(m_rsp_secret_buffer, secured_message_context->hash_size, rsp_secret_fill);
    libspdm_set_mem(m_req_secret_buffer, secured_message_context->hash_size, req_secret_fill);

    libspdm_copy_mem(secured_message_context->application_secret.response_data_secret,
                     sizeof(secured_message_context->application_secret.response_data_secret),
                     m_rsp_secret_buffer, secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->application_secret.request_data_secret,
                     sizeof(secured_message_context->application_secret.request_data_secret),
                     m_req_secret_buffer, secured_message_context->aead_key_size);

    libspdm_set_mem(secured_message_context->application_secret.response_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xFF));
    libspdm_set_mem(secured_message_context->application_secret.response_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xFF));

    libspdm_set_mem(secured_message_context->application_secret.request_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xEE));
    libspdm_set_mem(secured_message_context->application_secret.request_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xEE));

    secured_message_context->application_secret.response_data_sequence_number = 0;
    secured_message_context->application_secret.request_data_sequence_number = 0;
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
                                             void **response, uint64_t timeout)
{
    static uint8_t sub_index = 0;
    spdm_key_update_response_t spdm_response;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t test_message_header_size;
    uint8_t spdm_response_size;
    session_id = 0xFFFFFFFF;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return RETURN_DEVICE_ERROR;
    }

    test_message_header_size = 1;
    libspdm_test_context_t *spdm_test_context;
    spdm_test_context = libspdm_get_test_context();
    spdm_response_size = sizeof(spdm_key_update_response_t);
    libspdm_copy_mem(&spdm_response, sizeof(spdm_response),
                     (uint8_t *)spdm_test_context->test_buffer + test_message_header_size +
                     spdm_response_size * sub_index,
                     sizeof(spdm_key_update_response_t));
    if (sub_index != 0) {
        sub_index = 0;
    }
    libspdm_transport_test_encode_message(spdm_context, &session_id, false, false,
                                          sizeof(spdm_response), &spdm_response, response_size,
                                          response);
    /* WALKAROUND: If just use single context to encode
     *     message and then decode message */
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number--;

    sub_index++;
    return RETURN_SUCCESS;
}

void libspdm_test_requester_key_update_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;
    session_id = 0xFFFFFFFF;

    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                                 m_rsp_secret_buffer, (uint8_t)(0xFF),
                                                 m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_req_secret_buffer, m_req_secret_buffer, sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    libspdm_key_update(spdm_context, session_id, true);
}

void libspdm_test_requester_key_update_case2(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    session_id = 0xFFFFFFFF;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                                 m_rsp_secret_buffer, (uint8_t)(0xFF),
                                                 m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_req_secret_buffer, m_req_secret_buffer, sizeof(m_req_secret_buffer));
    /*response side updated*/
    libspdm_compute_secret_update(
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_rsp_secret_buffer, m_rsp_secret_buffer, sizeof(m_rsp_secret_buffer));

    libspdm_key_update(spdm_context, session_id, false);
}

libspdm_test_context_t m_libspdm_requester_key_update_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_key_update_test_context);

    m_libspdm_requester_key_update_test_context.test_buffer = test_buffer;
    m_libspdm_requester_key_update_test_context.test_buffer_size = test_buffer_size;

    /* Successful response. update single key */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_update_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Sucessful response  update all keys*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_update_case2(&State);
    libspdm_unit_test_group_teardown(&State);
}
