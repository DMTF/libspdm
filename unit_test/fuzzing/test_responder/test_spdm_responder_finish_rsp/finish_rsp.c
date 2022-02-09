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

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_finish_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    false,
};

void spdm_secured_message_set_request_finished_key(IN void *spdm_secured_message_context,
                                                   IN void *key, IN uintn key_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    ASSERT(key_size == secured_message_context->hash_size);
    copy_mem(secured_message_context->handshake_secret.request_finished_key, key,
             secured_message_context->hash_size);
    secured_message_context->finished_key_ready = true;
}

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

void test_spdm_responder_finish_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data1;
    uintn data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;

    spdm_finish_request_mine_t m_spdm_finish_request1;
    uintn m_spdm_finish_request1_size;
    m_spdm_finish_request1 = *(spdm_finish_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_finish_request1_size = spdm_test_context->test_buffer_size;

    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data1, &data_size1,
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
    spdm_session_info_init(&spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                  m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    ptr = m_spdm_finish_request1.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, &m_spdm_finish_request1, sizeof(spdm_finish_request_t));
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key, hash_size, ptr);
    m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    spdm_get_response_finish(&spdm_context, m_spdm_finish_request1_size, &m_spdm_finish_request1,
                             &response_size, response);
}

void test_spdm_responder_finish_case2(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;

    response_size = sizeof(response);
    spdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                             spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_finish_case3(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.local_context.capability.flags = 0;

    response_size = sizeof(response);
    spdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                             spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_finish_case4(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;
    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    response_size = sizeof(response);
    spdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                             spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_finish_case5(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;

    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    response_size = sizeof(response);
    spdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                             spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_finish_case6(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    spdm_test_context = *State;

    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
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
    spdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                             spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_finish_case7(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
    uintn response_size;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    void *data1;
    uintn data_size1;
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;

    uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    spdm_test_context = *State;

    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data1, &data_size1,
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
    spdm_session_info_init(&spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                  m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_NOT_STARTED);
    spdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                  m_dummy_buffer, hash_size);

    response_size = sizeof(response);
    spdm_get_response_finish(&spdm_context, spdm_test_context->test_buffer_size,
                             spdm_test_context->test_buffer, &response_size, response);
}

void test_spdm_responder_finish_case8(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t spdm_context;
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
    large_managed_buffer_t th_curr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    uintn req_asym_signature_size;
    uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    spdm_finish_request_mine_t m_spdm_finish_request;
    uintn m_spdm_finish_request_size;

    spdm_test_context = *State;

    m_spdm_finish_request = *(spdm_finish_request_mine_t *)spdm_test_context->test_buffer;
    m_spdm_finish_request_size = spdm_test_context->test_buffer_size;

    spdm_context = *(spdm_context_t *)spdm_test_context->spdm_context;
    spdm_context.connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context.connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context.local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context.connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context.connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context.connection_info.algorithm.req_base_asym_alg = m_use_req_asym_algo;
    spdm_context.connection_info.algorithm.measurement_spec = m_use_measurement_spec;
    spdm_context.connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
    spdm_context.connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context.connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo, m_use_asym_algo, &data1, &data_size1,
                                            NULL, NULL);
    spdm_context.local_context.local_cert_chain_provision[0] = data1;
    spdm_context.local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context.connection_info.local_used_cert_chain_buffer = data1;
    spdm_context.connection_info.local_used_cert_chain_buffer_size = data_size1;
    spdm_context.local_context.slot_count = 1;
    libspdm_reset_message_a(&spdm_context);
    spdm_context.local_context.mut_auth_requested = 1;
    read_requester_public_certificate_chain(m_use_hash_algo, m_use_req_asym_algo, &data2,
                                            &data_size2, NULL, NULL);
    spdm_context.local_context.peer_cert_chain_provision = data2;
    spdm_context.local_context.peer_cert_chain_provision_size = data_size2;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    copy_mem(spdm_context.connection_info.peer_used_cert_chain_buffer, data2, data_size2);
    spdm_context.connection_info.peer_used_cert_chain_buffer_size = data_size2;
#endif
    session_id = 0xFFFFFEE;
    spdm_context.latest_session_id = session_id;
    session_info = &spdm_context.session_info[0];
    spdm_session_info_init(&spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                  m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context.connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context.local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_use_hash_algo);
    req_asym_signature_size = libspdm_get_req_asym_signature_size(m_use_req_asym_algo);
    ptr = m_spdm_finish_request.signature;
    init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size, req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    append_managed_buffer(&th_curr, &m_spdm_finish_request, sizeof(spdm_finish_request_t));
    libspdm_requester_data_sign(
        m_spdm_finish_request.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_use_req_asym_algo, m_use_hash_algo, false, get_managed_buffer(&th_curr),
            get_managed_buffer_size(&th_curr), ptr, &req_asym_signature_size);
    append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                     get_managed_buffer_size(&th_curr), request_finished_key, hash_size, ptr);
    m_spdm_finish_request_size =
        sizeof(spdm_finish_request_t) + req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    spdm_get_response_finish(&spdm_context, m_spdm_finish_request_size, &m_spdm_finish_request,
                             &response_size, response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_finish_test_context);

    m_spdm_responder_finish_test_context.test_buffer = test_buffer;
    m_spdm_responder_finish_test_context.test_buffer_size = test_buffer_size;

    spdm_unit_test_group_setup(&State);

    /* Success Case*/
    test_spdm_responder_finish_case1(&State);
    /*response_state: LIBSPDM_RESPONSE_STATE_NOT_READY */
    test_spdm_responder_finish_case2(&State);
    /*not supported capabilities_flag */
    test_spdm_responder_finish_case3(&State);
    /* connection_state Check */
    test_spdm_responder_finish_case4(&State);
    /* No handshake in clear, then it must be in a session.*/
    test_spdm_responder_finish_case5(&State);
    /* handshake in clear, then it must not be in a session.*/
    test_spdm_responder_finish_case6(&State);
    /* secured_message_context:= LIBSPDM_SESSION_STATE_NOT_STARTED */
    test_spdm_responder_finish_case7(&State);
    /* Success Case */
    test_spdm_responder_finish_case8(&State);

    spdm_unit_test_group_teardown(&State);
}
#else
uintn get_max_buffer_size(void)
{
    return 0;
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
