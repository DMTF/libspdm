/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

static uintn m_local_buffer_size;
static uint8 m_local_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

uint8 m_dummy_buffer[MAX_HASH_SIZE];

void spdm_secured_message_set_response_finished_key(
	IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(key_size == secured_message_context->hash_size);
	copy_mem(
		secured_message_context->handshake_secret.response_finished_key,
		key, secured_message_context->hash_size);
}

return_status spdm_requester_finish_test_send_message(IN void *spdm_context,
						      IN uintn request_size,
						      IN void *request,
						      IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;
	uint8 *ptr;

	spdm_test_context = get_spdm_test_context();
	ptr = (uint8 *)request;
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;
	case 0x2:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
		return RETURN_SUCCESS;
	case 0x3:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
		return RETURN_SUCCESS;
	case 0x4:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
		return RETURN_SUCCESS;
	case 0x5:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
		return RETURN_SUCCESS;
	case 0x6:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
		return RETURN_SUCCESS;
	case 0x7:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
		return RETURN_SUCCESS;
	case 0x8:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
		return RETURN_SUCCESS;
	case 0x9: {
		static uintn sub_index = 0;
		if (sub_index == 0) {
			m_local_buffer_size = 0;
			copy_mem(m_local_buffer, &ptr[1], request_size - 1);
			m_local_buffer_size += (request_size - 1);
			sub_index++;
		}
	}
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

return_status spdm_requester_finish_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_finish_response_t *spdm_response;
		uint32 hash_size;
		uint32 hmac_size;
		uint8 *ptr;
		void *data;
		uintn data_size;
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uint8 cert_buffer_hash[MAX_HASH_SIZE];
		large_managed_buffer_t th_curr;
		uint8 response_finished_key[MAX_HASH_SIZE];
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_asym_algo =
			m_use_asym_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.dhe_named_group =
			m_use_dhe_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.measurement_hash_algo =
			m_use_measurement_hash_algo;
		hash_size = spdm_get_hash_size(m_use_hash_algo);
		hmac_size = spdm_get_hash_size(m_use_hash_algo);
		temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response->header.request_response_code = SPDM_FINISH_RSP;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		ptr = (void *)(spdm_response + 1);
		copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
			 sizeof(spdm_finish_response_t));
		m_local_buffer_size += sizeof(spdm_finish_response_t);
		read_responder_public_certificate_chain(m_use_hash_algo,
							m_use_asym_algo, &data,
							&data_size, NULL, NULL);
		init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
		cert_buffer =
			(uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size;
		cert_buffer_size =
			data_size - (sizeof(spdm_cert_chain_t) + hash_size);
		spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
			      cert_buffer_hash);
		// transcript.message_a size is 0
		append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
		// session_transcript.message_k is 0
		append_managed_buffer(&th_curr, m_local_buffer,
				      m_local_buffer_size);
		set_mem(response_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
		spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      response_finished_key, hash_size, ptr);
		ptr += hmac_size;
		free(data);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_finish_response_t *spdm_response;
		uint32 hash_size;
		uint32 hmac_size;
		uint8 *ptr;
		void *data;
		uintn data_size;
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uint8 cert_buffer_hash[MAX_HASH_SIZE];
		large_managed_buffer_t th_curr;
		uint8 response_finished_key[MAX_HASH_SIZE];
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_asym_algo =
			m_use_asym_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.dhe_named_group =
			m_use_dhe_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.measurement_hash_algo =
			m_use_measurement_hash_algo;
		hash_size = spdm_get_hash_size(m_use_hash_algo);
		hmac_size = spdm_get_hash_size(m_use_hash_algo);
		temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response->header.request_response_code = SPDM_FINISH_RSP;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		ptr = (void *)(spdm_response + 1);
		copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
			 sizeof(spdm_finish_response_t));
		m_local_buffer_size += sizeof(spdm_finish_response_t);
		read_responder_public_certificate_chain(m_use_hash_algo,
							m_use_asym_algo, &data,
							&data_size, NULL, NULL);
		init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
		cert_buffer =
			(uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size;
		cert_buffer_size =
			data_size - (sizeof(spdm_cert_chain_t) + hash_size);
		spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
			      cert_buffer_hash);
		// transcript.message_a size is 0
		append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
		// session_transcript.message_k is 0
		append_managed_buffer(&th_curr, m_local_buffer,
				      m_local_buffer_size);
		set_mem(response_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
		spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      response_finished_key, hash_size, ptr);
		ptr += hmac_size;
		free(data);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x4: {
		spdm_error_response_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x5: {
		spdm_error_response_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x6: {
		static uintn sub_index1 = 0;
		if (sub_index1 == 0) {
			spdm_error_response_t spdm_response;

			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
			spdm_response.header.param2 = 0;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
			sub_index1++;
		} else if (sub_index1 == 1) {
			spdm_finish_response_t *spdm_response;
			uint32 hash_size;
			uint32 hmac_size;
			uint8 *ptr;
			void *data;
			uintn data_size;
			uint8 *cert_buffer;
			uintn cert_buffer_size;
			uint8 cert_buffer_hash[MAX_HASH_SIZE];
			large_managed_buffer_t th_curr;
			uint8 response_finished_key[MAX_HASH_SIZE];
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;

			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_asym_algo =
				m_use_asym_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_hash_algo =
				m_use_hash_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.dhe_named_group =
				m_use_dhe_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm
				.measurement_hash_algo =
				m_use_measurement_hash_algo;
			hash_size = spdm_get_hash_size(m_use_hash_algo);
			hmac_size = spdm_get_hash_size(m_use_hash_algo);
			temp_buf_size =
				sizeof(spdm_finish_response_t) + hmac_size;
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response->header.request_response_code =
				SPDM_FINISH_RSP;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = 0;
			ptr = (void *)(spdm_response + 1);
			copy_mem(&m_local_buffer[m_local_buffer_size],
				 spdm_response, sizeof(spdm_finish_response_t));
			m_local_buffer_size += sizeof(spdm_finish_response_t);
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo, &data,
				&data_size, NULL, NULL);
			init_managed_buffer(&th_curr,
					    MAX_SPDM_MESSAGE_BUFFER_SIZE);
			cert_buffer = (uint8 *)data +
				      sizeof(spdm_cert_chain_t) + hash_size;
			cert_buffer_size =
				data_size -
				(sizeof(spdm_cert_chain_t) + hash_size);
			spdm_hash_all(m_use_hash_algo, cert_buffer,
				      cert_buffer_size, cert_buffer_hash);
			// transcript.message_a size is 0
			append_managed_buffer(&th_curr, cert_buffer_hash,
					      hash_size);
			// session_transcript.message_k is 0
			append_managed_buffer(&th_curr, m_local_buffer,
					      m_local_buffer_size);
			set_mem(response_finished_key, MAX_HASH_SIZE,
				(uint8)(0xFF));
			spdm_hmac_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      response_finished_key, hash_size, ptr);
			ptr += hmac_size;
			free(data);

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);
		}
	}
		return RETURN_SUCCESS;

	case 0x7: {
		spdm_error_response_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x8: {
		spdm_error_response_data_response_not_ready_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 =
			SPDM_ERROR_CODE_RESPONSE_NOT_READY;
		spdm_response.header.param2 = 0;
		spdm_response.extend_error_data.rd_exponent = 1;
		spdm_response.extend_error_data.rd_tm = 1;
		spdm_response.extend_error_data.request_code = SPDM_FINISH;
		spdm_response.extend_error_data.token = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x9: {
		static uintn sub_index2 = 0;
		if (sub_index2 == 0) {
			spdm_error_response_data_response_not_ready_t
				spdm_response;

			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 =
				SPDM_ERROR_CODE_RESPONSE_NOT_READY;
			spdm_response.header.param2 = 0;
			spdm_response.extend_error_data.rd_exponent = 1;
			spdm_response.extend_error_data.rd_tm = 1;
			spdm_response.extend_error_data.request_code =
				SPDM_FINISH;
			spdm_response.extend_error_data.token = 1;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
			sub_index2++;
		} else if (sub_index2 == 1) {
			spdm_finish_response_t *spdm_response;
			uint32 hash_size;
			uint32 hmac_size;
			uint8 *ptr;
			void *data;
			uintn data_size;
			uint8 *cert_buffer;
			uintn cert_buffer_size;
			uint8 cert_buffer_hash[MAX_HASH_SIZE];
			large_managed_buffer_t th_curr;
			uint8 response_finished_key[MAX_HASH_SIZE];
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;

			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_asym_algo =
				m_use_asym_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_hash_algo =
				m_use_hash_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.dhe_named_group =
				m_use_dhe_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm
				.measurement_hash_algo =
				m_use_measurement_hash_algo;
			hash_size = spdm_get_hash_size(m_use_hash_algo);
			hmac_size = spdm_get_hash_size(m_use_hash_algo);
			temp_buf_size =
				sizeof(spdm_finish_response_t) + hmac_size;
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response->header.request_response_code =
				SPDM_FINISH_RSP;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = 0;
			ptr = (void *)(spdm_response + 1);
			copy_mem(&m_local_buffer[m_local_buffer_size],
				 spdm_response, sizeof(spdm_finish_response_t));
			m_local_buffer_size += sizeof(spdm_finish_response_t);
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo, &data,
				&data_size, NULL, NULL);
			init_managed_buffer(&th_curr,
					    MAX_SPDM_MESSAGE_BUFFER_SIZE);
			cert_buffer = (uint8 *)data +
				      sizeof(spdm_cert_chain_t) + hash_size;
			cert_buffer_size =
				data_size -
				(sizeof(spdm_cert_chain_t) + hash_size);
			spdm_hash_all(m_use_hash_algo, cert_buffer,
				      cert_buffer_size, cert_buffer_hash);
			// transcript.message_a size is 0
			append_managed_buffer(&th_curr, cert_buffer_hash,
					      hash_size);
			// session_transcript.message_k is 0
			append_managed_buffer(&th_curr, m_local_buffer,
					      m_local_buffer_size);
			set_mem(response_finished_key, MAX_HASH_SIZE,
				(uint8)(0xFF));
			spdm_hmac_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      response_finished_key, hash_size, ptr);
			ptr += hmac_size;
			free(data);

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);
		}
	}
		return RETURN_SUCCESS;

	default:
		return RETURN_DEVICE_ERROR;
	}
}

void test_spdm_requester_finish_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_finish_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(
		spdm_secured_message_get_session_state(
			spdm_context->session_info[0].secured_message_context),
		SPDM_SESSION_STATE_ESTABLISHED);
	free(data);
}

void test_spdm_requester_finish_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_UNSUPPORTED);
	free(data);
}

void test_spdm_requester_finish_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_finish_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_NO_RESPONSE);
	free(data);
}

void test_spdm_requester_finish_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(
		spdm_secured_message_get_session_state(
			spdm_context->session_info[0].secured_message_context),
		SPDM_SESSION_STATE_ESTABLISHED);
	free(data);
}

void test_spdm_requester_finish_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
	free(data);
}

void test_spdm_requester_finish_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_finish_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 req_slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
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

	session_id = 0xFFFFFFFF;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_response_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	req_slot_id_param = 0;
	status = spdm_send_receive_finish(spdm_context, session_id,
					  req_slot_id_param);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(
		spdm_secured_message_get_session_state(
			spdm_context->session_info[0].secured_message_context),
		SPDM_SESSION_STATE_ESTABLISHED);
	free(data);
}

spdm_test_context_t m_spdm_requester_finish_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_finish_test_send_message,
	spdm_requester_finish_test_receive_message,
};

int spdm_requester_finish_test_main(void)
{
	const struct CMUnitTest spdm_requester_finish_tests[] = {
		// SendRequest failed
		cmocka_unit_test(test_spdm_requester_finish_case1),
		// Successful response
		cmocka_unit_test(test_spdm_requester_finish_case2),
		// connection_state check failed
		cmocka_unit_test(test_spdm_requester_finish_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(test_spdm_requester_finish_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(test_spdm_requester_finish_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(test_spdm_requester_finish_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(test_spdm_requester_finish_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		cmocka_unit_test(test_spdm_requester_finish_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(test_spdm_requester_finish_case9),
	};

	setup_spdm_test_context(&m_spdm_requester_finish_test_context);

	return cmocka_run_group_tests(spdm_requester_finish_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
