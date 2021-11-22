/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_device_secret_lib_internal.h>
#include <spdm_responder_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_psk_finish_rsp_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

typedef struct {
	spdm_message_header_t header;
	uint8 verify_data[MAX_HASH_SIZE];
} spdm_psk_finish_request_mine_t;

static void spdm_secured_message_set_request_finished_key(
	IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(key_size == secured_message_context->hash_size);
	copy_mem(secured_message_context->handshake_secret.request_finished_key,
		 key, secured_message_context->hash_size);
	secured_message_context->finished_key_ready = TRUE;
}

void test_spdm_responder_psk_finish_rsp(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	void *data1;
	uintn data_size1;
	static uint8 m_dummy_buffer[MAX_HASH_SIZE];

	uint8 m_local_psk_hint[32];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
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
	spdm_reset_message_a(spdm_context);
	spdm_context->local_context.mut_auth_requested = 0;
	zero_mem(m_local_psk_hint, 32);
	copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING,
		 sizeof(TEST_PSK_HINT_STRING));
	spdm_context->local_context.psk_hint_size =
		sizeof(TEST_PSK_HINT_STRING);
	spdm_context->local_context.psk_hint = m_local_psk_hint;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	spdm_context->last_spdm_request_session_id_valid = TRUE;
	spdm_context->last_spdm_request_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, TRUE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	response_size = sizeof(response);
	spdm_get_response_psk_finish(spdm_context,
				     spdm_test_context->test_buffer_size,
				     spdm_test_context->test_buffer,
				     &response_size, response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(&m_spdm_responder_psk_finish_rsp_test_context);

	m_spdm_responder_psk_finish_rsp_test_context.test_buffer = test_buffer;
	m_spdm_responder_psk_finish_rsp_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_responder_psk_finish_rsp(&State);

	spdm_unit_test_group_teardown(&State);
}
