/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

static void spdm_set_standard_key_update_test_state(libspdm_context_t *spdm_context,
                                                    uint32_t *session_id)
{
    libspdm_session_info_t *session_info;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;

    *session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = *session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = *session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    set_mem(spdm_context->last_update_request, 4, 0x00);
}

static void spdm_set_standard_key_update_test_secrets(
    spdm_secured_message_context_t *secured_message_context,
    uint8_t *m_rsp_secret_buffer, uint8_t rsp_secret_fill, uint8_t *m_req_secret_buffer,
    uint8_t req_secret_fill)
{
    set_mem(m_rsp_secret_buffer, secured_message_context->hash_size, rsp_secret_fill);
    set_mem(m_req_secret_buffer, secured_message_context->hash_size, req_secret_fill);

    copy_mem(secured_message_context->application_secret.response_data_secret,
             sizeof(secured_message_context->application_secret.response_data_secret),
             m_rsp_secret_buffer, secured_message_context->aead_key_size);
    copy_mem(secured_message_context->application_secret.request_data_secret,
             sizeof(secured_message_context->application_secret.request_data_secret),
             m_req_secret_buffer, secured_message_context->aead_key_size);

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

static void spdm_compute_secret_update(uintn hash_size, const uint8_t *in_secret,
                                       uint8_t *out_secret, uintn out_secret_size)
{
    uint8_t m_bin_str9[128];
    uintn m_bin_str9_size;
    uint16_t length;

    length = (uint16_t)hash_size;
    copy_mem(m_bin_str9, sizeof(m_bin_str9), &length, sizeof(uint16_t));
    copy_mem(m_bin_str9 + sizeof(uint16_t),
             sizeof(m_bin_str9) - sizeof(uint16_t),
             SPDM_BIN_CONCAT_LABEL, sizeof(SPDM_BIN_CONCAT_LABEL) - 1);
    copy_mem(m_bin_str9 + sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1,
             sizeof(m_bin_str9) - (sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1),
             SPDM_BIN_STR_9_LABEL, sizeof(SPDM_BIN_STR_9_LABEL));
    m_bin_str9_size =
        sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1 + sizeof(SPDM_BIN_STR_9_LABEL) - 1;
    /*context is NULL for key update*/

    libspdm_hkdf_expand(m_use_hash_algo, in_secret, hash_size, m_bin_str9, m_bin_str9_size,
                        out_secret, out_secret_size);
}

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_encap_get_digests_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void test_spdm_process_encap_response_key_update_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;
    libspdm_session_info_t *session_info;
    spdm_secured_message_context_t *secured_message_context;
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                              m_rsp_secret_buffer, (uint8_t)(0xFF),
                                              m_req_secret_buffer, (uint8_t)(0xEE));

    spdm_compute_secret_update(secured_message_context->hash_size, m_req_secret_buffer,
                               m_req_secret_buffer, secured_message_context->hash_size);

    libspdm_init_key_update_encap_state(spdm_context);

    spdm_process_encap_response_key_update(spdm_context, spdm_test_context->test_buffer_size,
                                           spdm_test_context->test_buffer, &need_continue);
}

void test_spdm_get_encap_request_key_update_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_key_update_request_t *spdm_request;
    libspdm_context_t *spdm_context;
    uintn encap_request_size;
    void *data;
    uintn data_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;

    if (encap_request_size < sizeof(spdm_key_update_request_t)) {
        encap_request_size = sizeof(spdm_key_update_request_t);
    }
    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    spdm_get_encap_request_key_update(spdm_context, &encap_request_size, spdm_request);
    free(spdm_request);
    free(data);
}

void test_spdm_get_encap_request_key_update_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_key_update_request_t *spdm_request;
    libspdm_context_t *spdm_context;
    uintn encap_request_size;
    void *data;
    uintn data_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;

    if (encap_request_size < sizeof(spdm_key_update_request_t)) {
        encap_request_size = sizeof(spdm_key_update_request_t);
    }
    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                            NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_KEY_UPDATE;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    spdm_get_encap_request_key_update(spdm_context, &encap_request_size, spdm_request);
    free(spdm_request);
    free(data);
}

void run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_encap_get_digests_test_context);

    m_spdm_responder_encap_get_digests_test_context.test_buffer = test_buffer;
    m_spdm_responder_encap_get_digests_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_process_encap_response_key_update_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* Success Case */
    spdm_unit_test_group_setup(&State);
    test_spdm_get_encap_request_key_update_case1(&State);
    spdm_unit_test_group_teardown(&State);

    /* request_response_code: SPDM_KEY_UPDATE */
    spdm_unit_test_group_setup(&State);
    test_spdm_get_encap_request_key_update_case2(&State);
    spdm_unit_test_group_teardown(&State);
}
