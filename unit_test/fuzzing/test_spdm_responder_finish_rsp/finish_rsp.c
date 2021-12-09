/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <internal/libspdm_responder_lib.h>
#include <spdm_device_secret_lib_internal.h>

uintn get_max_buffer_size(void)
{
    return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_finish_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    FALSE,
};

void spdm_secured_message_set_request_finished_key(
    IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    ASSERT(key_size == secured_message_context->hash_size);
    copy_mem(secured_message_context->handshake_secret.request_finished_key,
         key, secured_message_context->hash_size);
    secured_message_context->finished_key_ready = TRUE;
}

void test_spdm_responder_finish_case1(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn response_size;
    uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    void *data;
    uintn data_size;
    spdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint8_t m_dummy_buffer[MAX_HASH_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state =
        SPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    read_responder_public_certificate_chain(m_use_hash_algo,
                        m_use_asym_algo, &data,
                        &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size;
    spdm_context->local_context.slot_count = 1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
    hash_size = spdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    spdm_secured_message_set_session_state(
        session_info->secured_message_context,
        SPDM_SESSION_STATE_HANDSHAKING);

    response_size = sizeof(response);
    spdm_get_response_finish(spdm_context,
                 spdm_test_context->test_buffer_size,
                 spdm_test_context->test_buffer, &response_size,
                 response);
}

void test_spdm_responder_finish_case2(void **state)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8_t response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	void *data1;
	uintn data_size1;
	void *data2;
	uintn data_size2;
	spdm_session_info_t *session_info;
	uint32_t session_id;
	uint32_t hash_size;
	uint8_t m_dummy_buffer[MAX_HASH_SIZE];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.req_base_asym_alg =
		m_use_req_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	libspdm_reset_message_a(spdm_context);
	spdm_context->local_context.mut_auth_requested = 1;
	read_requester_public_certificate_chain(m_use_hash_algo,
						m_use_req_asym_algo, &data2,
						&data_size2, NULL, NULL);
	spdm_context->local_context.peer_cert_chain_provision = data2;
	spdm_context->local_context.peer_cert_chain_provision_size = data_size2;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data2, data_size2);
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size2;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);
	session_info->mut_auth_requested = 1;

	response_size = sizeof(response);
	spdm_get_response_finish(spdm_context,
				 spdm_test_context->test_buffer_size,
				 spdm_test_context->test_buffer, &response_size,
				 response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;

    setup_spdm_test_context(&m_spdm_responder_finish_test_context);

    m_spdm_responder_finish_test_context.test_buffer = test_buffer;
    m_spdm_responder_finish_test_context.test_buffer_size =
        test_buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_responder_finish_case1(&State);
    test_spdm_responder_finish_case2(&State);

    spdm_unit_test_group_teardown(&State);
}
