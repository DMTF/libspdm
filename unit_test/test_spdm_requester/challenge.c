/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>

static uintn m_local_buffer_size;
static uint8 m_local_buffer[MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE];

return_status spdm_requester_challenge_test_send_message(IN void *spdm_context,
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

return_status spdm_requester_challenge_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_challenge_auth_response_t *spdm_response;
		void *data;
		uintn data_size;
		uint8 *ptr;
		uint8 hash_data[MAX_HASH_SIZE];
		uintn sig_size;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		read_responder_public_certificate_chain(m_use_hash_algo,
							m_use_asym_algo, &data,
							&data_size, NULL, NULL);
		((spdm_context_t *)spdm_context)
			->local_context.local_cert_chain_provision_size[0] =
			data_size;
		((spdm_context_t *)spdm_context)
			->local_context.local_cert_chain_provision[0] = data;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_asym_algo =
			m_use_asym_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.bash_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code =
			SPDM_CHALLENGE_AUTH;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = (1 << 0);
		ptr = (void *)(spdm_response + 1);
		spdm_hash_all(
			m_use_hash_algo,
			((spdm_context_t *)spdm_context)
				->local_context.local_cert_chain_provision[0],
			((spdm_context_t *)spdm_context)
				->local_context
				.local_cert_chain_provision_size[0],
			ptr);
		free(data);
		ptr += spdm_get_hash_size(m_use_hash_algo);
		spdm_get_random_number(SPDM_NONCE_SIZE, ptr);
		ptr += SPDM_NONCE_SIZE;
		// zero_mem (ptr, spdm_get_hash_size (m_use_hash_algo));
		// ptr += spdm_get_hash_size (m_use_hash_algo);
		*(uint16 *)ptr = 0;
		ptr += sizeof(uint16);
		copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
			 (uintn)ptr - (uintn)spdm_response);
		m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
		DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
		       m_local_buffer_size));
		internal_dump_hex(m_local_buffer, m_local_buffer_size);
		spdm_hash_all(m_use_hash_algo, m_local_buffer,
			      m_local_buffer_size, hash_data);
		DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n",
		       spdm_get_hash_size(m_use_hash_algo)));
		internal_dump_hex(m_local_buffer, m_local_buffer_size);
		sig_size = spdm_get_asym_signature_size(m_use_asym_algo);
		spdm_responder_data_sign(m_use_asym_algo, m_use_hash_algo,
					 m_local_buffer, m_local_buffer_size,
					 ptr, &sig_size);
		ptr += sig_size;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_challenge_auth_response_t *spdm_response;
		void *data;
		uintn data_size;
		uint8 *ptr;
		uint8 hash_data[MAX_HASH_SIZE];
		uintn sig_size;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		read_responder_public_certificate_chain(m_use_hash_algo,
							m_use_asym_algo, &data,
							&data_size, NULL, NULL);
		((spdm_context_t *)spdm_context)
			->local_context.local_cert_chain_provision_size[0] =
			data_size;
		((spdm_context_t *)spdm_context)
			->local_context.local_cert_chain_provision[0] = data;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_asym_algo =
			m_use_asym_algo;
		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.bash_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code =
			SPDM_CHALLENGE_AUTH;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = (1 << 0);
		ptr = (void *)(spdm_response + 1);
		spdm_hash_all(
			m_use_hash_algo,
			((spdm_context_t *)spdm_context)
				->local_context.local_cert_chain_provision[0],
			((spdm_context_t *)spdm_context)
				->local_context
				.local_cert_chain_provision_size[0],
			ptr);
		free(data);
		ptr += spdm_get_hash_size(m_use_hash_algo);
		spdm_get_random_number(SPDM_NONCE_SIZE, ptr);
		ptr += SPDM_NONCE_SIZE;
		// zero_mem (ptr, spdm_get_hash_size (m_use_hash_algo));
		// ptr += spdm_get_hash_size (m_use_hash_algo);
		*(uint16 *)ptr = 0;
		ptr += sizeof(uint16);
		copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
			 (uintn)ptr - (uintn)spdm_response);
		m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
		spdm_hash_all(m_use_hash_algo, m_local_buffer,
			      m_local_buffer_size, hash_data);
		sig_size = spdm_get_asym_signature_size(m_use_asym_algo);
		spdm_responder_data_sign(m_use_asym_algo, m_use_hash_algo,
					 m_local_buffer, m_local_buffer_size,
					 ptr, &sig_size);
		ptr += sig_size;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x4: {
		spdm_error_response_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
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
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
			spdm_response.header.param2 = 0;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
			sub_index1++;
		} else if (sub_index1 == 1) {
			spdm_challenge_auth_response_t *spdm_response;
			void *data;
			uintn data_size;
			uint8 *ptr;
			uint8 hash_data[MAX_HASH_SIZE];
			uintn sig_size;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;

			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo, &data,
				&data_size, NULL, NULL);
			((spdm_context_t *)spdm_context)
				->local_context
				.local_cert_chain_provision_size[0] = data_size;
			((spdm_context_t *)spdm_context)
				->local_context.local_cert_chain_provision[0] =
				data;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_asym_algo =
				m_use_asym_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.bash_hash_algo =
				m_use_hash_algo;
			temp_buf_size =
				sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response->header.request_response_code =
				SPDM_CHALLENGE_AUTH;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = (1 << 0);
			ptr = (void *)(spdm_response + 1);
			spdm_hash_all(
				m_use_hash_algo,
				((spdm_context_t *)spdm_context)
					->local_context
					.local_cert_chain_provision[0],
				((spdm_context_t *)spdm_context)
					->local_context
					.local_cert_chain_provision_size[0],
				ptr);
			free(data);
			ptr += spdm_get_hash_size(m_use_hash_algo);
			spdm_get_random_number(SPDM_NONCE_SIZE, ptr);
			ptr += SPDM_NONCE_SIZE;
			// zero_mem (ptr, spdm_get_hash_size (m_use_hash_algo));
			// ptr += spdm_get_hash_size (m_use_hash_algo);
			*(uint16 *)ptr = 0;
			ptr += sizeof(uint16);
			copy_mem(&m_local_buffer[m_local_buffer_size],
				 spdm_response,
				 (uintn)ptr - (uintn)spdm_response);
			m_local_buffer_size +=
				((uintn)ptr - (uintn)spdm_response);
			spdm_hash_all(m_use_hash_algo, m_local_buffer,
				      m_local_buffer_size, hash_data);
			sig_size =
				spdm_get_asym_signature_size(m_use_asym_algo);
			spdm_responder_data_sign(m_use_asym_algo,
						 m_use_hash_algo,
						 m_local_buffer,
						 m_local_buffer_size, ptr,
						 &sig_size);
			ptr += sig_size;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);
		}
	}
		return RETURN_SUCCESS;

	case 0x7: {
		spdm_error_response_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 =
			SPDM_ERROR_CODE_RESPONSE_NOT_READY;
		spdm_response.header.param2 = 0;
		spdm_response.extend_error_data.rd_exponent = 1;
		spdm_response.extend_error_data.rd_tm = 1;
		spdm_response.extend_error_data.request_code = SPDM_CHALLENGE;
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
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 =
				SPDM_ERROR_CODE_RESPONSE_NOT_READY;
			spdm_response.header.param2 = 0;
			spdm_response.extend_error_data.rd_exponent = 1;
			spdm_response.extend_error_data.rd_tm = 1;
			spdm_response.extend_error_data.request_code =
				SPDM_CHALLENGE;
			spdm_response.extend_error_data.token = 1;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
			sub_index2++;
		} else if (sub_index2 == 1) {
			spdm_challenge_auth_response_t *spdm_response;
			void *data;
			uintn data_size;
			uint8 *ptr;
			uint8 hash_data[MAX_HASH_SIZE];
			uintn sig_size;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;

			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo, &data,
				&data_size, NULL, NULL);
			((spdm_context_t *)spdm_context)
				->local_context
				.local_cert_chain_provision_size[0] = data_size;
			((spdm_context_t *)spdm_context)
				->local_context.local_cert_chain_provision[0] =
				data;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_asym_algo =
				m_use_asym_algo;
			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.bash_hash_algo =
				m_use_hash_algo;
			temp_buf_size =
				sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response->header.request_response_code =
				SPDM_CHALLENGE_AUTH;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = (1 << 0);
			ptr = (void *)(spdm_response + 1);
			spdm_hash_all(
				m_use_hash_algo,
				((spdm_context_t *)spdm_context)
					->local_context
					.local_cert_chain_provision[0],
				((spdm_context_t *)spdm_context)
					->local_context
					.local_cert_chain_provision_size[0],
				ptr);
			free(data);
			ptr += spdm_get_hash_size(m_use_hash_algo);
			spdm_get_random_number(SPDM_NONCE_SIZE, ptr);
			ptr += SPDM_NONCE_SIZE;
			// zero_mem (ptr, spdm_get_hash_size (m_use_hash_algo));
			// ptr += spdm_get_hash_size (m_use_hash_algo);
			*(uint16 *)ptr = 0;
			ptr += sizeof(uint16);
			copy_mem(&m_local_buffer[m_local_buffer_size],
				 spdm_response,
				 (uintn)ptr - (uintn)spdm_response);
			m_local_buffer_size +=
				((uintn)ptr - (uintn)spdm_response);
			spdm_hash_all(m_use_hash_algo, m_local_buffer,
				      m_local_buffer_size, hash_data);
			sig_size =
				spdm_get_asym_signature_size(m_use_asym_algo);
			spdm_responder_data_sign(m_use_asym_algo,
						 m_use_hash_algo,
						 m_local_buffer,
						 m_local_buffer_size, ptr,
						 &sig_size);
			ptr += sig_size;

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

void test_spdm_requester_challenge_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
	free(data);
}

void test_spdm_requester_challenge_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_SUCCESS);
	free(data);
}

void test_spdm_requester_challenge_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_UNSUPPORTED);
	assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
	free(data);
}

void test_spdm_requester_challenge_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
	free(data);
}

void test_spdm_requester_challenge_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_NO_RESPONSE);
	assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
	free(data);
}

void test_spdm_requester_challenge_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_SUCCESS);
	free(data);
}

void test_spdm_requester_challenge_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
	assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
	free(data);
}

void test_spdm_requester_challenge_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_challenge_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 measurement_hash[MAX_HASH_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_challenge(
		spdm_context, 0,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
		measurement_hash);
	assert_int_equal(status, RETURN_SUCCESS);
	free(data);
}

spdm_test_context_t m_spdm_requester_challenge_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_challenge_test_send_message,
	spdm_requester_challenge_test_receive_message,
};

int spdm_requester_challenge_test_main(void)
{
	const struct CMUnitTest spdm_requester_challenge_tests[] = {
		// SendRequest failed
		cmocka_unit_test(test_spdm_requester_challenge_case1),
		// Successful response
		cmocka_unit_test(test_spdm_requester_challenge_case2),
		// connection_state check failed
		cmocka_unit_test(test_spdm_requester_challenge_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(test_spdm_requester_challenge_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(test_spdm_requester_challenge_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(test_spdm_requester_challenge_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(test_spdm_requester_challenge_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		cmocka_unit_test(test_spdm_requester_challenge_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(test_spdm_requester_challenge_case9),
	};

	setup_spdm_test_context(&m_spdm_requester_challenge_test_context);

	return cmocka_run_group_tests(spdm_requester_challenge_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
