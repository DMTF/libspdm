/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

static uint8 m_local_psk_hint[32];
static uint8 m_dummy_key_buffer[MAX_AEAD_KEY_SIZE];
static uint8 m_dummy_salt_buffer[MAX_AEAD_IV_SIZE];

void spdm_secured_message_set_response_data_encryption_key(
	IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(key_size == secured_message_context->aead_key_size);
	copy_mem(secured_message_context->application_secret
			 .response_data_encryption_key,
		 key, secured_message_context->aead_key_size);
}

void spdm_secured_message_set_response_data_salt(
	IN void *spdm_secured_message_context, IN void *salt,
	IN uintn salt_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(salt_size == secured_message_context->aead_iv_size);
	copy_mem(secured_message_context->application_secret.response_data_salt,
		 salt, secured_message_context->aead_iv_size);
}

return_status spdm_requester_heartbeat_test_send_message(IN void *spdm_context,
							 IN uintn request_size,
							 IN void *request,
							 IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;
	case 0x2:
		return RETURN_SUCCESS;
	case 0x3:
		return RETURN_SUCCESS;
	case 0x4:
		return RETURN_SUCCESS;
	case 0x5:
		return RETURN_SUCCESS;
	case 0x6:
		return RETURN_SUCCESS;
	case 0x7:
		return RETURN_SUCCESS;
	case 0x8:
		return RETURN_SUCCESS;
	case 0x9:
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

return_status spdm_requester_heartbeat_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_heartbeat_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint32 session_id;
		spdm_session_info_t *session_info;

		session_id = 0xFFFFFFFF;
		temp_buf_size = sizeof(spdm_heartbeat_response_t);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response->header.request_response_code =
			SPDM_HEARTBEAT_ACK;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, &session_id,
						   FALSE, FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_DEVICE_ERROR;
		}
		/* WALKAROUND: If just use single context to encode message and then decode message */
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->application_secret.response_data_sequence_number--;
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_heartbeat_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint32 session_id;
		spdm_session_info_t *session_info;

		session_id = 0xFFFFFFFF;
		temp_buf_size = sizeof(spdm_heartbeat_response_t);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response->header.request_response_code =
			SPDM_HEARTBEAT_ACK;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, &session_id,
						   FALSE, FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_DEVICE_ERROR;
		}
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->application_secret.response_data_sequence_number--;
	}
		return RETURN_SUCCESS;

	case 0x4: {
		spdm_error_response_t spdm_response;
		uint32 session_id;
		spdm_session_info_t *session_info;

		session_id = 0xFFFFFFFF;
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, &session_id,
						   FALSE, FALSE,
						   sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_DEVICE_ERROR;
		}
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->application_secret.response_data_sequence_number--;
	}
		return RETURN_SUCCESS;

	case 0x5: {
		spdm_error_response_t spdm_response;
		uint32 session_id;
		spdm_session_info_t *session_info;

		session_id = 0xFFFFFFFF;
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, &session_id,
						   FALSE, FALSE,
						   sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_DEVICE_ERROR;
		}
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->application_secret.response_data_sequence_number--;
	}
		return RETURN_SUCCESS;

	case 0x6: {
		static uintn sub_index1 = 0;
		if (sub_index1 == 0) {
			spdm_error_response_t spdm_response;
			uint32 session_id;
			spdm_session_info_t *session_info;

			session_id = 0xFFFFFFFF;
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
			spdm_response.header.param2 = 0;

			spdm_transport_test_encode_message(
				spdm_context, &session_id, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
			sub_index1++;
			session_info = spdm_get_session_info_via_session_id(
				spdm_context, session_id);
			if (session_info == NULL) {
				return RETURN_DEVICE_ERROR;
			}
			((spdm_secured_message_context_t
				  *)(session_info->secured_message_context))
				->application_secret
				.response_data_sequence_number--;
		} else if (sub_index1 == 1) {
			spdm_heartbeat_response_t *spdm_response;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;
			uint32 session_id;
			spdm_session_info_t *session_info;

			session_id = 0xFFFFFFFF;
			temp_buf_size = sizeof(spdm_heartbeat_response_t);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response->header.request_response_code =
				SPDM_HEARTBEAT_ACK;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = 0;

			spdm_transport_test_encode_message(
				spdm_context, &session_id, FALSE, FALSE,
				temp_buf_size, temp_buf, response_size,
				response);
			session_info = spdm_get_session_info_via_session_id(
				spdm_context, session_id);
			if (session_info == NULL) {
				return RETURN_DEVICE_ERROR;
			}
			((spdm_secured_message_context_t
				  *)(session_info->secured_message_context))
				->application_secret
				.response_data_sequence_number--;
		}
	}
		return RETURN_SUCCESS;

	case 0x7: {
		spdm_error_response_t spdm_response;
		uint32 session_id;
		spdm_session_info_t *session_info;

		session_id = 0xFFFFFFFF;
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, &session_id,
						   FALSE, FALSE,
						   sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_DEVICE_ERROR;
		}
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->application_secret.response_data_sequence_number--;
	}
		return RETURN_SUCCESS;

	case 0x8: {
		spdm_error_response_data_response_not_ready_t spdm_response;
		uint32 session_id;
		spdm_session_info_t *session_info;

		session_id = 0xFFFFFFFF;
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 =
			SPDM_ERROR_CODE_RESPONSE_NOT_READY;
		spdm_response.header.param2 = 0;
		spdm_response.extend_error_data.rd_exponent = 1;
		spdm_response.extend_error_data.rd_tm = 1;
		spdm_response.extend_error_data.request_code = SPDM_HEARTBEAT;
		spdm_response.extend_error_data.token = 0;

		spdm_transport_test_encode_message(spdm_context, &session_id,
						   FALSE, FALSE,
						   sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, session_id);
		if (session_info == NULL) {
			return RETURN_DEVICE_ERROR;
		}
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->application_secret.response_data_sequence_number--;
	}
		return RETURN_SUCCESS;

	case 0x9: {
		static uintn sub_index2 = 0;
		if (sub_index2 == 0) {
			spdm_error_response_data_response_not_ready_t
				spdm_response;
			uint32 session_id;
			spdm_session_info_t *session_info;

			session_id = 0xFFFFFFFF;
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 =
				SPDM_ERROR_CODE_RESPONSE_NOT_READY;
			spdm_response.header.param2 = 0;
			spdm_response.extend_error_data.rd_exponent = 1;
			spdm_response.extend_error_data.rd_tm = 1;
			spdm_response.extend_error_data.request_code =
				SPDM_HEARTBEAT;
			spdm_response.extend_error_data.token = 1;

			spdm_transport_test_encode_message(
				spdm_context, &session_id, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
			sub_index2++;
			session_info = spdm_get_session_info_via_session_id(
				spdm_context, session_id);
			if (session_info == NULL) {
				return RETURN_DEVICE_ERROR;
			}
			((spdm_secured_message_context_t
				  *)(session_info->secured_message_context))
				->application_secret
				.response_data_sequence_number--;
		} else if (sub_index2 == 1) {
			spdm_heartbeat_response_t *spdm_response;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;
			uint32 session_id;
			spdm_session_info_t *session_info;

			session_id = 0xFFFFFFFF;
			temp_buf_size = sizeof(spdm_heartbeat_response_t);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response->header.request_response_code =
				SPDM_HEARTBEAT_ACK;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = 0;

			spdm_transport_test_encode_message(
				spdm_context, &session_id, FALSE, FALSE,
				temp_buf_size, temp_buf, response_size,
				response);
			session_info = spdm_get_session_info_via_session_id(
				spdm_context, session_id);
			if (session_info == NULL) {
				return RETURN_DEVICE_ERROR;
			}
			((spdm_secured_message_context_t
				  *)(session_info->secured_message_context))
				->application_secret
				.response_data_sequence_number--;
		}
	}
		return RETURN_SUCCESS;

	default:
		return RETURN_DEVICE_ERROR;
	}
}

void test_spdm_requester_heartbeat_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_heartbeat_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_SUCCESS);
	free(data);
}

void test_spdm_requester_heartbeat_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_UNSUPPORTED);
	free(data);
}

void test_spdm_requester_heartbeat_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_heartbeat_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_NO_RESPONSE);
	free(data);
}

void test_spdm_requester_heartbeat_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_SUCCESS);
	free(data);
}

void test_spdm_requester_heartbeat_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
	free(data);
}

void test_spdm_requester_heartbeat_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_heartbeat_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	spdm_session_info_t *session_info;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
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
		SPDM_SESSION_STATE_ESTABLISHED);
	set_mem(m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_encryption_key(
		session_info->secured_message_context, m_dummy_key_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_key_size);
	set_mem(m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size,
		(uint8)(0xFF));
	spdm_secured_message_set_response_data_salt(
		session_info->secured_message_context, m_dummy_salt_buffer,
		((spdm_secured_message_context_t
			  *)(session_info->secured_message_context))
			->aead_iv_size);
	((spdm_secured_message_context_t *)(session_info
						    ->secured_message_context))
		->application_secret.response_data_sequence_number = 0;

	status = spdm_heartbeat(spdm_context, session_id);
	assert_int_equal(status, RETURN_SUCCESS);
	free(data);
}

spdm_test_context_t m_spdm_requester_heartbeat_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_heartbeat_test_send_message,
	spdm_requester_heartbeat_test_receive_message,
};

int spdm_requester_heartbeat_test_main(void)
{
	const struct CMUnitTest spdm_requester_heartbeat_tests[] = {
		// SendRequest failed
		cmocka_unit_test(test_spdm_requester_heartbeat_case1),
		// Successful response
		cmocka_unit_test(test_spdm_requester_heartbeat_case2),
		// connection_state check failed
		cmocka_unit_test(test_spdm_requester_heartbeat_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(test_spdm_requester_heartbeat_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(test_spdm_requester_heartbeat_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(test_spdm_requester_heartbeat_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(test_spdm_requester_heartbeat_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		cmocka_unit_test(test_spdm_requester_heartbeat_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(test_spdm_requester_heartbeat_case9),
	};

	setup_spdm_test_context(&m_spdm_requester_heartbeat_test_context);

	return cmocka_run_group_tests(spdm_requester_heartbeat_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
