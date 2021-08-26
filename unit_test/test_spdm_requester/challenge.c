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
	case 0xA:
	case 0xB:
	case 0xC:
	case 0xD:
	case 0xE:
	case 0xF:
	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
		m_local_buffer_size = 0;
		copy_mem(m_local_buffer, &ptr[1], request_size - 1);
		m_local_buffer_size += (request_size - 1);
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

	case 0x2: { //correct CHALLENGE_AUTH message
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
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
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

	case 0x3: { //correct CHALLENGE_AUTH message
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
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
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

	case 0x4: { //correct ERROR message (invalid request)
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

	case 0x5: { //correct ERROR message (busy)
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

	case 0x6: { //correct ERROR message (busy) + correct CHALLENGE_AUTH message
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
				->connection_info.algorithm.base_hash_algo =
				m_use_hash_algo;
			temp_buf_size =
				sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
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

	case 0x7: { //correct ERROR message (request resync)
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

	case 0x8: { //correct ERROR message (response net ready)
		spdm_error_response_data_response_not_ready_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
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

	case 0x9: { //correct ERROR message (response not ready) + correct CHALLENGE_AUTH message
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
				->connection_info.algorithm.base_hash_algo =
				m_use_hash_algo;
			temp_buf_size =
				sizeof(spdm_challenge_auth_response_t) +
				spdm_get_hash_size(m_use_hash_algo) +
				SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				spdm_get_asym_signature_size(m_use_asym_algo);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
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

  case 0xA:  //correct CHALLENGE_AUTH message
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(uint16) + 0 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    // Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 0;
    Ptr += sizeof(uint16);
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, m_local_buffer, m_local_buffer_size, Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0xB: //CHALLENGE_AUTH message smaller than a SPDM header
  {
    spdm_challenge_auth_response_t  *spdm_response;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;
    spdm_response = (void *)temp_buf;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) - 1; //smaller than standard message size

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0xC: //CHALLENGE_AUTH message with wrong version (1.0)
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              spdm_get_hash_size (m_use_hash_algo) +
              sizeof(uint16) + 0 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10; //wrong version
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    // Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 0;
    Ptr += sizeof(uint16);
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, m_local_buffer, m_local_buffer_size, Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0xD: //SPDM (mostly CHALLENGE_AUTH) message with wrong response code (0x83)
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(uint16) + 0 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE; //wrong response code
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    // Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 0;
    Ptr += sizeof(uint16);
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, m_local_buffer, m_local_buffer_size, Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0xE:  //correct CHALLENGE_AUTH message with wrong slot number
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(uint16) + 0 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 1;
    spdm_response->header.param2 = (1 << 1); //wrong slot number
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    // Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 0;
    Ptr += sizeof(uint16);
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, m_local_buffer, m_local_buffer_size, Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0xF: //CHALLENGE_AUTH message with slot number overflow
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(uint16) + 0 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 8; //slot number overflow
    spdm_response->header.param2 = (1 << 0);
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    // Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 0;
    Ptr += sizeof(uint16);
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, m_local_buffer, m_local_buffer_size, Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0x10: //correct CHALLENGE_AUTH message with "openspdm" opaque data
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(uint16) + 8 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    // Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 8;
    Ptr += sizeof(uint16);
    copy_mem (Ptr, "openspdm", 8);
    Ptr += 8;
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, m_local_buffer, m_local_buffer_size, Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0x11: //correct CHALLENGE_AUTH message with invalid signature
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(uint16) + 0 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    // Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 0;
    Ptr += sizeof(uint16);
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    spdm_hash_all (m_use_hash_algo, hash_data, spdm_get_hash_size (m_use_hash_algo), hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, hash_data, spdm_get_hash_size (m_use_hash_algo), Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0x12:  //correct CHALLENGE_AUTH message
  case 0x13:  //correct CHALLENGE_AUTH message
  {
    spdm_challenge_auth_response_t  *spdm_response;
    void                          *data;
    uintn                         data_size;
    uint8                         *Ptr;
    uint8                         hash_data[MAX_HASH_SIZE];
    uintn                         sig_size;
    uint8                         temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn                         temp_buf_size;

    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] = data_size;
    ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    ((spdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    temp_buf_size = sizeof(spdm_challenge_auth_response_t) +
              spdm_get_hash_size (m_use_hash_algo) +
              SPDM_NONCE_SIZE +
              spdm_get_hash_size (m_use_hash_algo) +
              sizeof(uint16) + 0 +
              spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);
    Ptr = (void *)(spdm_response + 1);
    spdm_hash_all (m_use_hash_algo, ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0], ((spdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0], Ptr);
    free(data);
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    spdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    zero_mem (Ptr, spdm_get_hash_size (m_use_hash_algo));
    Ptr += spdm_get_hash_size (m_use_hash_algo);
    *(uint16 *)Ptr = 0;
    Ptr += sizeof(uint16);
    copy_mem (&m_local_buffer[m_local_buffer_size], spdm_response, (uintn)Ptr - (uintn)spdm_response);
    m_local_buffer_size += ((uintn)Ptr - (uintn)spdm_response);
    spdm_hash_all (m_use_hash_algo, m_local_buffer, m_local_buffer_size, hash_data);
    sig_size = spdm_get_asym_signature_size (m_use_asym_algo);
    spdm_responder_data_sign (m_use_asym_algo, m_use_hash_algo, m_local_buffer, m_local_buffer_size, Ptr, &sig_size);
    Ptr += sig_size;

    spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, temp_buf_size, temp_buf, response_size, response);
  }
    return RETURN_SUCCESS;

  case 0x14:
  {
    static uint16 error_code = SPDM_ERROR_CODE_RESERVED_00;

    spdm_error_response_t    spdm_response;

    if(error_code <= 0xff) {
      zero_mem (&spdm_response, sizeof(spdm_response));
      spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
      spdm_response.header.request_response_code = SPDM_ERROR;
      spdm_response.header.param1 = (uint8) error_code;
      spdm_response.header.param2 = 0;

      spdm_transport_test_encode_message (spdm_context, NULL, FALSE, FALSE, sizeof(spdm_response), &spdm_response, response_size, response);
    }

    error_code++;
    if(error_code == SPDM_ERROR_CODE_BUSY) { //busy is treated in cases 5 and 6
      error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
    }
    if(error_code == SPDM_ERROR_CODE_RESERVED_0D) { //skip some reserved error codes (0d to 3e)
      error_code = SPDM_ERROR_CODE_RESERVED_3F;
    }
    if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { //skip response not ready, request resync, and some reserved codes (44 to fc)
      error_code = SPDM_ERROR_CODE_RESERVED_FD;
    }
  }
    return RETURN_SUCCESS;

	default:
		return RETURN_DEVICE_ERROR;
	}
}

/**
  Test 1: when no CHALLENGE_AUTH message is received, and the client returns a
  device error.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 2: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (param1=0) and do not request measurements (param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a status of RETURN_SUCCESS.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 3: the requester is not setup correctly to send a CHALLENGE message:
  - it has *no* flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, GET_DIGESTS); but
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (param1=0) and do not request measurements (param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is not set.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 4: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating InvalidParameters.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is reset.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 5: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the Busy status of the responder.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is reset.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 6: the requester is setup correctly (see Test 2), but, on the first try,
  receiving a Busy ERROR message, and on retry, receiving a correct CHALLENGE_AUTH
  message to the challenge, with no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a status of RETURN_SUCCESS.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 7: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the RequestResynch status of the responder.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, the "C"
  transcript buffer is reset, and the communication is reset to expect a new
  GET_VERSION message.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 8: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the ResponseNotReady status of the responder.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
  buffer stores nothing.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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
	assert_int_equal (spdm_context->transcript.message_c.buffer_size, 0);
	free(data);
}

/**
  Test 9: the requester is setup correctly (see Test 2), but, on the first try,
  receiving a ResponseNotReady ERROR message, and on retry, receiving a correct
  CHALLENGE_AUTH message to the challenge, with no opaque data and a signature
  on the sent nonce.
  Expected behavior: client returns a status of RETURN_SUCCESS.
**/
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
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
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

/**
  Test 10: the requester is not setup correctly to send a CHALLENGE message.
  Specifically, it has *not* received the capability for challenge, although it
  has received capability for executing both hash and signature algorithms.
  The remaining setup and message exchange were executed correctly (see Test 2).
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is not set.
**/
void test_spdm_requester_challenge_case10(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xA;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  // spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_UNSUPPORTED);
  assert_int_equal (spdm_context->transcript.message_c.buffer_size, 0);
  free(data);
}

/**
  Test 11: the requester is setup correctly (see Test 2), but receives a malformed
  response message, smaller then a standard SPDM message header.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR,.
**/
void test_spdm_requester_challenge_case11(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xB;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_DEVICE_ERROR);
  free(data);
}

/**
  Test 12: the requester is setup correctly (see Test 2), but receives a malformed
  response message, with version (1.0) different from the request (1.1).
  The remaining message data is as a correct CHALLENGE_AUTH message.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
**/
void test_spdm_requester_challenge_case12(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xC;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_DEVICE_ERROR);
  free(data);
}

/**
  Test 13: the requester is setup correctly (see Test 2), but receives a malformed
  response message, with wrong request_response_code (CHALLENGE 0x83 instead of
  CHALLENGE_AUTH 0x03).
  The remaining message data is as a correct CHALLENGE_AUTH message.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
**/
void test_spdm_requester_challenge_case13(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xD;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_DEVICE_ERROR);
  free(data);
}

/**
  Test 14: the requester is setup correctly (see Test 2), but receives a malformed
  response message, with a slot number different from the requested.
  The remaining message data is as a correct CHALLENGE_AUTH message.
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
**/
void test_spdm_requester_challenge_case14(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xE;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_DEVICE_ERROR);
  free(data);
}

/**
  Test 15: the requester is not setup correctly to send a CHALLENGE message.
  Specifically, it attemps to request a certificate at a slot number larger than
  the one supported by the specification.
  The remaining setup and message exchange were executed correctly (see Test 2).
  Expected behavior: client returns a status of RETURN_INVALID_PARAMETER.
**/
void test_spdm_requester_challenge_case15(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xF;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, MAX_SPDM_SLOT_COUNT, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_INVALID_PARAMETER);;
  free(data);
}

/**
  Test 16: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (param1=0) and do not request measurements (param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, opaque
  data with bytes from the string "openspdm", and a signature on the sent nonce.
  Expected behavior: client returns a status of RETURN_SUCCESS.
**/
void test_spdm_requester_challenge_case16(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x10;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_SUCCESS);
  free(data);
}

/**
  Test 17: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (param1=0) and do not request measurements (param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, 
  but with an invalid signature.
  Expected behavior: client returns a status of RETURN_SECURITY_VIOLATION.
**/
void test_spdm_requester_challenge_case17(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x11;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
  assert_int_equal (status, RETURN_SECURITY_VIOLATION);
  free(data);
}

/**
  Test 18: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, the use of challenges, and of measurements.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (param1=0) and request TCB measurements (param2=1).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a status of RETURN_SUCCESS.
**/
void test_spdm_requester_challenge_case18(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x12;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, measurement_hash);
  assert_int_equal (status, RETURN_SUCCESS);
}

/**
  Test 19: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, the use of challenges, and of measurements.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (param1=0) and request TCB measurements (param2=1).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a status of RETURN_SUCCESS.
**/
void test_spdm_requester_challenge_case19(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x13;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->transcript.message_a.buffer_size = 0;
  spdm_context->transcript.message_b.buffer_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH, measurement_hash);
  assert_int_equal (status, RETURN_SUCCESS);
}

/**
  Test 20: receiving an unexpected ERROR message from the responder.
  There are tests for all named codes, including some reserved ones
  (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
  However, for having specific test cases, it is excluded from this case:
  Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
**/
void test_spdm_requester_challenge_case20(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                measurement_hash[MAX_HASH_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;
  uint16                error_code;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x14;
  spdm_context->connection_info.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  error_code = SPDM_ERROR_CODE_RESERVED_00;
  while(error_code <= 0xff) {
    spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->transcript.message_b.buffer_size = 0;
    spdm_context->transcript.message_c.buffer_size = 0;

    zero_mem (measurement_hash, sizeof(measurement_hash));
    status = spdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, measurement_hash);
    // assert_int_equal (status, RETURN_DEVICE_ERROR);
    // assert_int_equal (spdm_context->transcript.message_c.buffer_size, 0);
    ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
    ASSERT_INT_EQUAL_CASE (spdm_context->transcript.message_c.buffer_size, 0, error_code);

    error_code++;
    if(error_code == SPDM_ERROR_CODE_BUSY) { //busy is treated in cases 5 and 6
      error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
    }
    if(error_code == SPDM_ERROR_CODE_RESERVED_0D) { //skip some reserved error codes (0d to 3e)
      error_code = SPDM_ERROR_CODE_RESERVED_3F;
    }
    if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { //skip response not ready, request resync, and some reserved codes (44 to fc)
      error_code = SPDM_ERROR_CODE_RESERVED_FD;
    }
  }

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
		// SpdmCmdReceiveState check failed
		cmocka_unit_test(test_spdm_requester_challenge_case10),
		// Successful response + device error
		cmocka_unit_test(test_spdm_requester_challenge_case11),
		cmocka_unit_test(test_spdm_requester_challenge_case12),
		cmocka_unit_test(test_spdm_requester_challenge_case13),
		cmocka_unit_test(test_spdm_requester_challenge_case14),
		// Invalid parameter
		cmocka_unit_test(test_spdm_requester_challenge_case15),
		// Successful response
		cmocka_unit_test(test_spdm_requester_challenge_case16),
		// Signature check failed
		cmocka_unit_test(test_spdm_requester_challenge_case17),
		// Successful response
		cmocka_unit_test(test_spdm_requester_challenge_case18),
		cmocka_unit_test(test_spdm_requester_challenge_case19),
		// Unexpected errors
		cmocka_unit_test(test_spdm_requester_challenge_case20),
	};

	setup_spdm_test_context(&m_spdm_requester_challenge_test_context);

	return cmocka_run_group_tests(spdm_requester_challenge_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
