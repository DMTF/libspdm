/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_device_secret_lib_internal.h>
#include <spdm_requester_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

static void spdm_secured_message_set_dummy_finished_key(
	IN void *spdm_secured_message_context)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	secured_message_context->finished_key_ready = TRUE;
}

void spdm_secured_message_set_response_handshake_encryption_key(
	IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(key_size == secured_message_context->aead_key_size);
	copy_mem(secured_message_context->handshake_secret
			 .response_handshake_encryption_key,
		 key, secured_message_context->aead_key_size);
}

void spdm_secured_message_set_response_handshake_salt(
	IN void *spdm_secured_message_context, IN void *salt,
	IN uintn salt_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(salt_size == secured_message_context->aead_iv_size);
	copy_mem(secured_message_context->handshake_secret
			 .response_handshake_salt,
		 salt, secured_message_context->aead_iv_size);
}

uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_receive_message(IN void *spdm_context,
					  IN OUT uintn *response_size,
					  IN OUT void *response,
					  IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	*response_size = spdm_test_context->test_buffer_size;
	copy_mem(response, spdm_test_context->test_buffer,
		 spdm_test_context->test_buffer_size);
	return RETURN_SUCCESS;
}

void test_spdm_requester_psk_finish(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	static uint8 m_local_psk_hint[32];
	static uint8 m_dummy_key_buffer[MAX_AEAD_KEY_SIZE];
	static uint8 m_dummy_salt_buffer[MAX_AEAD_IV_SIZE];

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_reset_message_a(spdm_context);
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);
	zero_mem(m_local_psk_hint, 32);
	copy_mem(&m_local_psk_hint[0], TEST_PSK_HINT_STRING,
		 sizeof(TEST_PSK_HINT_STRING));
	spdm_context->local_context.psk_hint_size =
		sizeof(TEST_PSK_HINT_STRING);
	spdm_context->local_context.psk_hint = m_local_psk_hint;

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, TRUE);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_handshake_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_handshake_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->handshake_secret.response_handshake_sequence_number = 0;
	spdm_secured_message_set_dummy_finished_key(
		session_info->secured_message_context);

	spdm_send_receive_psk_finish(spdm_context, session_id);
}

return_status spdm_device_send_message(IN void *spdm_context,
				       IN uintn request_size, IN void *request,
				       IN uint64 timeout)
{
	return RETURN_SUCCESS;
}

spdm_test_context_t m_spdm_requester_psk_finish_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_device_send_message,
	spdm_device_receive_message,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(&m_spdm_requester_psk_finish_test_context);

	m_spdm_requester_psk_finish_test_context.test_buffer = test_buffer;
	m_spdm_requester_psk_finish_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_requester_psk_finish(&State);

	spdm_unit_test_group_teardown(&State);
}
