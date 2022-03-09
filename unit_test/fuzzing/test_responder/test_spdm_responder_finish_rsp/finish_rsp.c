/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

uintn libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

libspdm_test_context_t m_libspdm_responder_finish_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void libspdm_secured_message_set_request_finished_key(void *spdm_secured_message_context,
                                                      const void *key, uintn key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->hash_size);
    libspdm_copy_mem(secured_message_context->handshake_secret.request_finished_key,
                     sizeof(secured_message_context->handshake_secret.request_finished_key),
                     key, secured_message_context->hash_size);
    secured_message_context->finished_key_ready = true;
}

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_finish_request_mine_t;

void libspdm_test_responder_finish_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    libspdm_large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;

    libspdm_finish_request_mine_t m_spdm_finish_request1;
    uintn m_spdm_finish_request1_size;
    m_spdm_finish_request1 = *(libspdm_finish_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_finish_request1_size = spdm_test_context->test_buffer_size;

    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context.connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo,
                                                    &data1, &data_size1,
                                                    NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data1;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context.connection_info.local_used_cert_chain_buffer = data1;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size1;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    spdm_context.local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context.latest_session_id = session_id;
    session_info = &spdm_context.session_info[0];
    libspdm_session_info_init(&spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, &m_spdm_finish_request1, sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), request_finished_key, hash_size,
                     ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, m_spdm_finish_request1_size, &m_spdm_finish_request1,
                                &response_size, response);
    free(data1);
}

void libspdm_test_responder_finish_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;

    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_finish_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.local_context.capability.flags = 0;

    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_finish_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_finish_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;

    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_finish_case6(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;

    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context.last_spdm_request_session_id_valid = !false;
    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_finish_case7(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data1;
    uintn data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;

    uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    spdm_test_context = *State;

    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context.connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo,
                                                    &data1, &data_size1,
                                                    NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data1;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context.connection_info.local_used_cert_chain_buffer = data1;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size1;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    spdm_context.local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context.latest_session_id = session_id;
    session_info = &spdm_context.session_info[0];
    libspdm_session_info_init(&spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_NOT_STARTED);
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     m_dummy_buffer, hash_size);

    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
    free(data1);
}

void libspdm_test_responder_finish_case8(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data1;
    uintn data_size1;
    void *data2;
    uintn data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    libspdm_large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    uintn req_asym_signature_size;
    uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    libspdm_finish_request_mine_t m_spdm_finish_request;
    uintn m_spdm_finish_request_size;

    spdm_test_context = *State;

    m_spdm_finish_request = *(libspdm_finish_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_finish_request_size = spdm_test_context->test_buffer_size;

    spdm_context = *(libspdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context.connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context.connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo,
                                                    &data1, &data_size1,
                                                    NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data1;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context.connection_info.local_used_cert_chain_buffer = data1;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size1;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    spdm_context.local_context.mut_auth_requested = 1;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo,
                                                    &data2,
                                                    &data_size2, NULL, NULL);
    spdm_context.local_context.peer_cert_chain_provision = data2;
    spdm_context.local_context.peer_cert_chain_provision_size = data_size2;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context.connection_info.peer_used_cert_chain_buffer,
                     sizeof(spdm_context.connection_info.peer_used_cert_chain_buffer),
                     data2, data_size2);
    spdm_context.connection_info.peer_used_cert_chain_buffer_size = data_size2;
#endif
    session_id = 0xFFFFFEE;
    spdm_context.latest_session_id = session_id;
    session_info = &spdm_context.session_info[0];
    libspdm_session_info_init(&spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size = libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_spdm_finish_request.signature;
    libspdm_init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, &m_spdm_finish_request, sizeof(spdm_finish_request_t));
    /* The caller need guarantee the version is correct, both of MajorVersion and MinorVersion should be less than 10.*/
    if (((m_spdm_finish_request.header.spdm_version & 0xF) >= 10) ||
        (((m_spdm_finish_request.header.spdm_version >> 4) & 0xF) >= 10)) {
        m_spdm_finish_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    }
    libspdm_requester_data_sign(
        m_spdm_finish_request.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo, false,
            libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr), ptr, &req_asym_signature_size);
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), request_finished_key, hash_size,
                     ptr);
    m_spdm_finish_request_size =
        sizeof(spdm_finish_request_t) + req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    libspdm_get_response_finish(&spdm_context, m_spdm_finish_request_size, &m_spdm_finish_request,
                                &response_size, response);
    free(data1);
    free(data2);
}

void libspdm_run_test_harness(const void *test_buffer, uintn test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_responder_finish_test_context);

    m_libspdm_responder_finish_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_responder_finish_test_context.test_buffer_size = test_buffer_size;

    libspdm_unit_test_group_setup(&State);

    /* Success Case*/
    libspdm_test_responder_finish_case1(&State);
    /*response_state: LIBSPDM_RESPONSE_STATE_NOT_READY */
    libspdm_test_responder_finish_case2(&State);
    /*not supported capabilities_flag */
    libspdm_test_responder_finish_case3(&State);
    /* connection_state Check */
    libspdm_test_responder_finish_case4(&State);
    /* No handshake in clear, then it must be in a session.*/
    libspdm_test_responder_finish_case5(&State);
    /* handshake in clear, then it must not be in a session.*/
    libspdm_test_responder_finish_case6(&State);
    /* secured_message_context:= LIBSPDM_SESSION_STATE_NOT_STARTED */
    libspdm_test_responder_finish_case7(&State);
    /* Success Case */
    libspdm_test_responder_finish_case8(&State);

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
