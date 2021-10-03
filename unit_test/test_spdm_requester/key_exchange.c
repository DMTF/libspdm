/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>

#define BIN_CONCAT_LABEL "spdm1.1 "
#define BIN_STR_0_LABEL "derived"
#define BIN_STR_2_LABEL "rsp hs data"

static uintn m_local_buffer_size;
static uint8 m_local_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

static GLOBAL_REMOVE_IF_UNREFERENCED uint8 m_zero_filled_buffer[64];

uintn spdm_test_get_key_exchange_request_size(IN void *spdm_context,
					      IN void *buffer,
					      IN uintn buffer_size)
{
	spdm_key_exchange_request_t *spdm_request;
	uintn message_size;
	uintn dhe_key_size;
	uint16 opaque_length;

	spdm_request = buffer;
	message_size = sizeof(spdm_message_header_t);
	if (buffer_size < message_size) {
		return buffer_size;
	}

	if (spdm_request->header.request_response_code != SPDM_KEY_EXCHANGE) {
		return buffer_size;
	}

	message_size = sizeof(spdm_key_exchange_request_t);
	if (buffer_size < message_size) {
		return buffer_size;
	}

	dhe_key_size = spdm_get_dhe_pub_key_size(m_use_dhe_algo);
	message_size += dhe_key_size + sizeof(uint16);
	if (buffer_size < message_size) {
		return buffer_size;
	}

	opaque_length =
		*(uint16 *)((uintn)buffer +
			    sizeof(spdm_key_exchange_request_t) + dhe_key_size);
	message_size += opaque_length;
	if (buffer_size < message_size) {
		return buffer_size;
	}

	// Good message, return actual size
	return message_size;
}

return_status spdm_requester_key_exchange_test_send_message(
	IN void *spdm_context, IN uintn request_size, IN void *request,
	IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;
	uintn header_size;
	uintn message_size;

	spdm_test_context = get_spdm_test_context();
	header_size = sizeof(test_message_header_t);
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;
	case 0x2:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0x3:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0x4:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0x5:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0x6:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0x7:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0x8:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0x9: {
		static uintn sub_index = 0;
		if (sub_index == 0) {
			m_local_buffer_size = 0;
			message_size = spdm_test_get_key_exchange_request_size(
				spdm_context, (uint8 *)request + header_size,
				request_size - header_size);
			copy_mem(m_local_buffer, (uint8 *)request + header_size,
				 message_size);
			m_local_buffer_size += message_size;
			sub_index++;
		}
	}
		return RETURN_SUCCESS;
	case 0xA:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	case 0xB:
		m_local_buffer_size = 0;
		message_size = spdm_test_get_key_exchange_request_size(
			spdm_context, (uint8 *)request + header_size,
			request_size - header_size);
		copy_mem(m_local_buffer, (uint8 *)request + header_size,
			 message_size);
		m_local_buffer_size += message_size;
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

return_status spdm_requester_key_exchange_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;
	spdm_version_number_t spdm_version = {0, 0, 1, 1};

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_key_exchange_response_t *spdm_response;
		uintn dhe_key_size;
		uint32 hash_size;
		uintn signature_size;
		uint32 hmac_size;
		uint8 *ptr;
		void *dhe_context;
		uint8 final_key[MAX_DHE_KEY_SIZE];
		uintn final_key_size;
		uintn opaque_key_exchange_rsp_size;
		void *data;
		uintn data_size;
		uint8 hash_data[MAX_HASH_SIZE];
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uint8 cert_buffer_hash[MAX_HASH_SIZE];
		large_managed_buffer_t th_curr;
		uint8 THCurrHashData[64];
		uint8 bin_str0[128];
		uintn bin_str0_size;
		uint8 bin_str2[128];
		uintn bin_str2_size;
		uint8 bin_str7[128];
		uintn bin_str7_size;
		uint8 handshake_secret[MAX_HASH_SIZE];
		uint8 response_handshake_secret[MAX_HASH_SIZE];
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
		signature_size = spdm_get_asym_signature_size(m_use_asym_algo);
		hash_size = spdm_get_hash_size(m_use_hash_algo);
		hmac_size = spdm_get_hash_size(m_use_hash_algo);
		dhe_key_size = spdm_get_dhe_pub_key_size(m_use_dhe_algo);
		opaque_key_exchange_rsp_size =
			spdm_get_opaque_data_version_selection_data_size(
				spdm_context);
		temp_buf_size = sizeof(spdm_key_exchange_response_t) +
				dhe_key_size + 0 + sizeof(uint16) +
				opaque_key_exchange_rsp_size + signature_size +
				hmac_size;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response->header.request_response_code =
			SPDM_KEY_EXCHANGE_RSP;
		spdm_response->header.param1 = 0;
		spdm_response->rsp_session_id =
			spdm_allocate_rsp_session_id(spdm_context);
		spdm_response->mut_auth_requested = 0;
		spdm_response->req_slot_id_param = 0;
		spdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
				       spdm_response->random_data);
		ptr = (void *)(spdm_response + 1);
		dhe_context = spdm_dhe_new(m_use_dhe_algo);
		spdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr,
				      &dhe_key_size);
		final_key_size = sizeof(final_key);
		spdm_dhe_compute_key(
			m_use_dhe_algo, dhe_context,
			(uint8 *)&m_local_buffer[0] +
				sizeof(spdm_key_exchange_request_t),
			dhe_key_size, final_key, &final_key_size);
		spdm_dhe_free(m_use_dhe_algo, dhe_context);
		ptr += dhe_key_size;
		// zero_mem (ptr, hash_size);
		// ptr += hash_size;
		*(uint16 *)ptr = (uint16)opaque_key_exchange_rsp_size;
		ptr += sizeof(uint16);
		spdm_build_opaque_data_version_selection_data(
			spdm_context, &opaque_key_exchange_rsp_size, ptr);
		ptr += opaque_key_exchange_rsp_size;
		read_responder_public_certificate_chain(m_use_hash_algo,
							m_use_asym_algo, &data,
							&data_size, NULL, NULL);
		copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
			 (uintn)ptr - (uintn)spdm_response);
		m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
		DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
		       m_local_buffer_size));
		internal_dump_hex(m_local_buffer, m_local_buffer_size);
		init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
		cert_buffer = (uint8 *)data;
		cert_buffer_size = data_size;
		spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
			      cert_buffer_hash);
		// transcript.message_a size is 0
		append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
		append_managed_buffer(&th_curr, m_local_buffer,
				      m_local_buffer_size);
		spdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr), hash_data);
		free(data);
		spdm_responder_data_sign(spdm_version, SPDM_KEY_EXCHANGE_RSP,
					 m_use_asym_algo, m_use_hash_algo,
					 FALSE, get_managed_buffer(&th_curr),
					 get_managed_buffer_size(&th_curr), ptr,
					 &signature_size);
		copy_mem(&m_local_buffer[m_local_buffer_size], ptr,
			 signature_size);
		m_local_buffer_size += signature_size;
		append_managed_buffer(&th_curr, ptr, signature_size);
		ptr += signature_size;
		spdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      THCurrHashData);
		bin_str0_size = sizeof(bin_str0);
		spdm_bin_concat(BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1,
				NULL, (uint16)hash_size, hash_size, bin_str0,
				&bin_str0_size);
		spdm_hmac_all(m_use_hash_algo, m_zero_filled_buffer, hash_size,
			      final_key, final_key_size, handshake_secret);
		bin_str2_size = sizeof(bin_str2);
		spdm_bin_concat(BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1,
				THCurrHashData, (uint16)hash_size, hash_size,
				bin_str2, &bin_str2_size);
		spdm_hkdf_expand(m_use_hash_algo, handshake_secret, hash_size,
				 bin_str2, bin_str2_size,
				 response_handshake_secret, hash_size);
		bin_str7_size = sizeof(bin_str7);
		spdm_bin_concat(BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1,
				NULL, (uint16)hash_size, hash_size, bin_str7,
				&bin_str7_size);
		spdm_hkdf_expand(m_use_hash_algo, response_handshake_secret,
				 hash_size, bin_str7, bin_str7_size,
				 response_finished_key, hash_size);
		spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      response_finished_key, hash_size, ptr);
		ptr += hmac_size;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_key_exchange_response_t *spdm_response;
		uintn dhe_key_size;
		uint32 hash_size;
		uintn signature_size;
		uint32 hmac_size;
		uint8 *ptr;
		void *dhe_context;
		uint8 final_key[MAX_DHE_KEY_SIZE];
		uintn final_key_size;
		uintn opaque_key_exchange_rsp_size;
		void *data;
		uintn data_size;
		uint8 hash_data[MAX_HASH_SIZE];
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uint8 cert_buffer_hash[MAX_HASH_SIZE];
		large_managed_buffer_t th_curr;
		uint8 THCurrHashData[64];
		uint8 bin_str0[128];
		uintn bin_str0_size;
		uint8 bin_str2[128];
		uintn bin_str2_size;
		uint8 bin_str7[128];
		uintn bin_str7_size;
		uint8 handshake_secret[MAX_HASH_SIZE];
		uint8 response_handshake_secret[MAX_HASH_SIZE];
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
		signature_size = spdm_get_asym_signature_size(m_use_asym_algo);
		hash_size = spdm_get_hash_size(m_use_hash_algo);
		hmac_size = spdm_get_hash_size(m_use_hash_algo);
		dhe_key_size = spdm_get_dhe_pub_key_size(m_use_dhe_algo);
		opaque_key_exchange_rsp_size =
			spdm_get_opaque_data_version_selection_data_size(
				spdm_context);
		temp_buf_size = sizeof(spdm_key_exchange_response_t) +
				dhe_key_size + 0 + sizeof(uint16) +
				opaque_key_exchange_rsp_size + signature_size +
				hmac_size;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response->header.request_response_code =
			SPDM_KEY_EXCHANGE_RSP;
		spdm_response->header.param1 = 0;
		spdm_response->rsp_session_id =
			spdm_allocate_rsp_session_id(spdm_context);
		spdm_response->mut_auth_requested = 0;
		spdm_response->req_slot_id_param = 0;
		spdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
				       spdm_response->random_data);
		ptr = (void *)(spdm_response + 1);
		dhe_context = spdm_dhe_new(m_use_dhe_algo);
		spdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr,
				      &dhe_key_size);
		final_key_size = sizeof(final_key);
		spdm_dhe_compute_key(
			m_use_dhe_algo, dhe_context,
			(uint8 *)&m_local_buffer[0] +
				sizeof(spdm_key_exchange_request_t),
			dhe_key_size, final_key, &final_key_size);
		spdm_dhe_free(m_use_dhe_algo, dhe_context);
		ptr += dhe_key_size;
		// zero_mem (ptr, hash_size);
		// ptr += hash_size;
		*(uint16 *)ptr = (uint16)opaque_key_exchange_rsp_size;
		ptr += sizeof(uint16);
		spdm_build_opaque_data_version_selection_data(
			spdm_context, &opaque_key_exchange_rsp_size, ptr);
		ptr += opaque_key_exchange_rsp_size;
		read_responder_public_certificate_chain(m_use_hash_algo,
							m_use_asym_algo, &data,
							&data_size, NULL, NULL);
		copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
			 (uintn)ptr - (uintn)spdm_response);
		m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
		DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
		       m_local_buffer_size));
		internal_dump_hex(m_local_buffer, m_local_buffer_size);
		init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
		cert_buffer = (uint8 *)data;
		cert_buffer_size = data_size;
		spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
			      cert_buffer_hash);
		// transcript.message_a size is 0
		append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
		append_managed_buffer(&th_curr, m_local_buffer,
				      m_local_buffer_size);
		spdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr), hash_data);
		free(data);
		spdm_responder_data_sign(spdm_version, SPDM_KEY_EXCHANGE_RSP,
					 m_use_asym_algo, m_use_hash_algo,
					 FALSE, get_managed_buffer(&th_curr),
					 get_managed_buffer_size(&th_curr), ptr,
					 &signature_size);
		copy_mem(&m_local_buffer[m_local_buffer_size], ptr,
			 signature_size);
		m_local_buffer_size += signature_size;
		append_managed_buffer(&th_curr, ptr, signature_size);
		ptr += signature_size;
		spdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      THCurrHashData);
		bin_str0_size = sizeof(bin_str0);
		spdm_bin_concat(BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1,
				NULL, (uint16)hash_size, hash_size, bin_str0,
				&bin_str0_size);
		spdm_hmac_all(m_use_hash_algo, m_zero_filled_buffer, hash_size,
			      final_key, final_key_size, handshake_secret);
		bin_str2_size = sizeof(bin_str2);
		spdm_bin_concat(BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1,
				THCurrHashData, (uint16)hash_size, hash_size,
				bin_str2, &bin_str2_size);
		spdm_hkdf_expand(m_use_hash_algo, handshake_secret, hash_size,
				 bin_str2, bin_str2_size,
				 response_handshake_secret, hash_size);
		bin_str7_size = sizeof(bin_str7);
		spdm_bin_concat(BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1,
				NULL, (uint16)hash_size, hash_size, bin_str7,
				&bin_str7_size);
		spdm_hkdf_expand(m_use_hash_algo, response_handshake_secret,
				 hash_size, bin_str7, bin_str7_size,
				 response_finished_key, hash_size);
		spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      response_finished_key, hash_size, ptr);
		ptr += hmac_size;

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
			spdm_key_exchange_response_t *spdm_response;
			uintn dhe_key_size;
			uint32 hash_size;
			uintn signature_size;
			uint32 hmac_size;
			uint8 *ptr;
			void *dhe_context;
			uint8 final_key[MAX_DHE_KEY_SIZE];
			uintn final_key_size;
			uintn opaque_key_exchange_rsp_size;
			void *data;
			uintn data_size;
			uint8 hash_data[MAX_HASH_SIZE];
			uint8 *cert_buffer;
			uintn cert_buffer_size;
			uint8 cert_buffer_hash[MAX_HASH_SIZE];
			large_managed_buffer_t th_curr;
			uint8 THCurrHashData[64];
			uint8 bin_str0[128];
			uintn bin_str0_size;
			uint8 bin_str2[128];
			uintn bin_str2_size;
			uint8 bin_str7[128];
			uintn bin_str7_size;
			uint8 handshake_secret[MAX_HASH_SIZE];
			uint8 response_handshake_secret[MAX_HASH_SIZE];
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
			signature_size =
				spdm_get_asym_signature_size(m_use_asym_algo);
			hash_size = spdm_get_hash_size(m_use_hash_algo);
			hmac_size = spdm_get_hash_size(m_use_hash_algo);
			dhe_key_size =
				spdm_get_dhe_pub_key_size(m_use_dhe_algo);
			opaque_key_exchange_rsp_size =
				spdm_get_opaque_data_version_selection_data_size(
					spdm_context);
			temp_buf_size = sizeof(spdm_key_exchange_response_t) +
					dhe_key_size + 0 + sizeof(uint16) +
					opaque_key_exchange_rsp_size +
					signature_size + hmac_size;
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response->header.request_response_code =
				SPDM_KEY_EXCHANGE_RSP;
			spdm_response->header.param1 = 0;
			spdm_response->rsp_session_id =
				spdm_allocate_rsp_session_id(spdm_context);
			spdm_response->mut_auth_requested = 0;
			spdm_response->req_slot_id_param = 0;
			spdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
					       spdm_response->random_data);
			ptr = (void *)(spdm_response + 1);
			dhe_context = spdm_dhe_new(m_use_dhe_algo);
			spdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr,
					      &dhe_key_size);
			final_key_size = sizeof(final_key);
			spdm_dhe_compute_key(
				m_use_dhe_algo, dhe_context,
				(uint8 *)&m_local_buffer[0] +
					sizeof(spdm_key_exchange_request_t),
				dhe_key_size, final_key, &final_key_size);
			spdm_dhe_free(m_use_dhe_algo, dhe_context);
			ptr += dhe_key_size;
			// zero_mem (ptr, hash_size);
			// ptr += hash_size;
			*(uint16 *)ptr = (uint16)opaque_key_exchange_rsp_size;
			ptr += sizeof(uint16);
			spdm_build_opaque_data_version_selection_data(
				spdm_context, &opaque_key_exchange_rsp_size,
				ptr);
			ptr += opaque_key_exchange_rsp_size;
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo, &data,
				&data_size, NULL, NULL);
			copy_mem(&m_local_buffer[m_local_buffer_size],
				 spdm_response,
				 (uintn)ptr - (uintn)spdm_response);
			m_local_buffer_size +=
				((uintn)ptr - (uintn)spdm_response);
			DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
			       m_local_buffer_size));
			internal_dump_hex(m_local_buffer, m_local_buffer_size);
			init_managed_buffer(&th_curr,
					    MAX_SPDM_MESSAGE_BUFFER_SIZE);
			cert_buffer = (uint8 *)data;
			cert_buffer_size = data_size;
			spdm_hash_all(m_use_hash_algo, cert_buffer,
				      cert_buffer_size, cert_buffer_hash);
			// transcript.message_a size is 0
			append_managed_buffer(&th_curr, cert_buffer_hash,
					      hash_size);
			append_managed_buffer(&th_curr, m_local_buffer,
					      m_local_buffer_size);
			spdm_hash_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      hash_data);
			free(data);
			spdm_responder_data_sign(spdm_version, SPDM_KEY_EXCHANGE_RSP,
				m_use_asym_algo, m_use_hash_algo,
				FALSE, get_managed_buffer(&th_curr),
				get_managed_buffer_size(&th_curr), ptr,
				&signature_size);
			copy_mem(&m_local_buffer[m_local_buffer_size], ptr,
				 signature_size);
			m_local_buffer_size += signature_size;
			append_managed_buffer(&th_curr, ptr, signature_size);
			ptr += signature_size;
			spdm_hash_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      THCurrHashData);
			bin_str0_size = sizeof(bin_str0);
			spdm_bin_concat(BIN_STR_0_LABEL,
					sizeof(BIN_STR_0_LABEL) - 1, NULL,
					(uint16)hash_size, hash_size, bin_str0,
					&bin_str0_size);
			spdm_hmac_all(m_use_hash_algo, m_zero_filled_buffer,
				      hash_size, final_key, final_key_size,
				      handshake_secret);
			bin_str2_size = sizeof(bin_str2);
			spdm_bin_concat(BIN_STR_2_LABEL,
					sizeof(BIN_STR_2_LABEL) - 1,
					THCurrHashData, (uint16)hash_size,
					hash_size, bin_str2, &bin_str2_size);
			spdm_hkdf_expand(m_use_hash_algo, handshake_secret,
					 hash_size, bin_str2, bin_str2_size,
					 response_handshake_secret, hash_size);
			bin_str7_size = sizeof(bin_str7);
			spdm_bin_concat(BIN_STR_7_LABEL,
					sizeof(BIN_STR_7_LABEL) - 1, NULL,
					(uint16)hash_size, hash_size, bin_str7,
					&bin_str7_size);
			spdm_hkdf_expand(m_use_hash_algo,
					 response_handshake_secret, hash_size,
					 bin_str7, bin_str7_size,
					 response_finished_key, hash_size);
			spdm_hmac_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      response_finished_key, hash_size, ptr);
			ptr += hmac_size;

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
		spdm_response.extend_error_data.request_code =
			SPDM_KEY_EXCHANGE;
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
				SPDM_KEY_EXCHANGE;
			spdm_response.extend_error_data.token = 1;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
			sub_index2++;
		} else if (sub_index2 == 1) {
			spdm_key_exchange_response_t *spdm_response;
			uintn dhe_key_size;
			uint32 hash_size;
			uintn signature_size;
			uint32 hmac_size;
			uint8 *ptr;
			void *dhe_context;
			uint8 final_key[MAX_DHE_KEY_SIZE];
			uintn final_key_size;
			uintn opaque_key_exchange_rsp_size;
			void *data;
			uintn data_size;
			uint8 hash_data[MAX_HASH_SIZE];
			uint8 *cert_buffer;
			uintn cert_buffer_size;
			uint8 cert_buffer_hash[MAX_HASH_SIZE];
			large_managed_buffer_t th_curr;
			uint8 THCurrHashData[64];
			uint8 bin_str0[128];
			uintn bin_str0_size;
			uint8 bin_str2[128];
			uintn bin_str2_size;
			uint8 bin_str7[128];
			uintn bin_str7_size;
			uint8 handshake_secret[MAX_HASH_SIZE];
			uint8 response_handshake_secret[MAX_HASH_SIZE];
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
			signature_size =
				spdm_get_asym_signature_size(m_use_asym_algo);
			hash_size = spdm_get_hash_size(m_use_hash_algo);
			hmac_size = spdm_get_hash_size(m_use_hash_algo);
			dhe_key_size =
				spdm_get_dhe_pub_key_size(m_use_dhe_algo);
			opaque_key_exchange_rsp_size =
				spdm_get_opaque_data_version_selection_data_size(
					spdm_context);
			temp_buf_size = sizeof(spdm_key_exchange_response_t) +
					dhe_key_size + 0 + sizeof(uint16) +
					opaque_key_exchange_rsp_size +
					signature_size + hmac_size;
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
			spdm_response->header.request_response_code =
				SPDM_KEY_EXCHANGE_RSP;
			spdm_response->header.param1 = 0;
			spdm_response->rsp_session_id =
				spdm_allocate_rsp_session_id(spdm_context);
			spdm_response->mut_auth_requested = 0;
			spdm_response->req_slot_id_param = 0;
			spdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
					       spdm_response->random_data);
			ptr = (void *)(spdm_response + 1);
			dhe_context = spdm_dhe_new(m_use_dhe_algo);
			spdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr,
					      &dhe_key_size);
			final_key_size = sizeof(final_key);
			spdm_dhe_compute_key(
				m_use_dhe_algo, dhe_context,
				(uint8 *)&m_local_buffer[0] +
					sizeof(spdm_key_exchange_request_t),
				dhe_key_size, final_key, &final_key_size);
			spdm_dhe_free(m_use_dhe_algo, dhe_context);
			ptr += dhe_key_size;
			// zero_mem (ptr, hash_size);
			// ptr += hash_size;
			*(uint16 *)ptr = (uint16)opaque_key_exchange_rsp_size;
			ptr += sizeof(uint16);
			spdm_build_opaque_data_version_selection_data(
				spdm_context, &opaque_key_exchange_rsp_size,
				ptr);
			ptr += opaque_key_exchange_rsp_size;
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo, &data,
				&data_size, NULL, NULL);
			copy_mem(&m_local_buffer[m_local_buffer_size],
				 spdm_response,
				 (uintn)ptr - (uintn)spdm_response);
			m_local_buffer_size +=
				((uintn)ptr - (uintn)spdm_response);
			DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
			       m_local_buffer_size));
			internal_dump_hex(m_local_buffer, m_local_buffer_size);
			init_managed_buffer(&th_curr,
					    MAX_SPDM_MESSAGE_BUFFER_SIZE);
			cert_buffer = (uint8 *)data;
			cert_buffer_size = data_size;
			spdm_hash_all(m_use_hash_algo, cert_buffer,
				      cert_buffer_size, cert_buffer_hash);
			// transcript.message_a size is 0
			append_managed_buffer(&th_curr, cert_buffer_hash,
					      hash_size);
			append_managed_buffer(&th_curr, m_local_buffer,
					      m_local_buffer_size);
			spdm_hash_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      hash_data);
			free(data);
			spdm_responder_data_sign(spdm_version, SPDM_KEY_EXCHANGE_RSP,
				m_use_asym_algo, m_use_hash_algo,
				FALSE, get_managed_buffer(&th_curr),
				get_managed_buffer_size(&th_curr), ptr,
				&signature_size);
			copy_mem(&m_local_buffer[m_local_buffer_size], ptr,
				 signature_size);
			m_local_buffer_size += signature_size;
			append_managed_buffer(&th_curr, ptr, signature_size);
			ptr += signature_size;
			spdm_hash_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      THCurrHashData);
			bin_str0_size = sizeof(bin_str0);
			spdm_bin_concat(BIN_STR_0_LABEL,
					sizeof(BIN_STR_0_LABEL) - 1, NULL,
					(uint16)hash_size, hash_size, bin_str0,
					&bin_str0_size);
			spdm_hmac_all(m_use_hash_algo, m_zero_filled_buffer,
				      hash_size, final_key, final_key_size,
				      handshake_secret);
			bin_str2_size = sizeof(bin_str2);
			spdm_bin_concat(BIN_STR_2_LABEL,
					sizeof(BIN_STR_2_LABEL) - 1,
					THCurrHashData, (uint16)hash_size,
					hash_size, bin_str2, &bin_str2_size);
			spdm_hkdf_expand(m_use_hash_algo, handshake_secret,
					 hash_size, bin_str2, bin_str2_size,
					 response_handshake_secret, hash_size);
			bin_str7_size = sizeof(bin_str7);
			spdm_bin_concat(BIN_STR_7_LABEL,
					sizeof(BIN_STR_7_LABEL) - 1, NULL,
					(uint16)hash_size, hash_size, bin_str7,
					&bin_str7_size);
			spdm_hkdf_expand(m_use_hash_algo,
					 response_handshake_secret, hash_size,
					 bin_str7, bin_str7_size,
					 response_finished_key, hash_size);
			spdm_hmac_all(m_use_hash_algo,
				      get_managed_buffer(&th_curr),
				      get_managed_buffer_size(&th_curr),
				      response_finished_key, hash_size, ptr);
			ptr += hmac_size;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);
		}
	}
		return RETURN_SUCCESS;

  case 0xA:
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
	case 0xB: {
		spdm_key_exchange_response_t *spdm_response;
		uintn dhe_key_size;
		uint32 hash_size;
		uintn signature_size;
		uint32 hmac_size;
		uint8 *ptr;
		void *dhe_context;
		uint8 final_key[MAX_DHE_KEY_SIZE];
		uintn final_key_size;
		uintn opaque_key_exchange_rsp_size;
		void *data;
		uintn data_size;
		uint8 hash_data[MAX_HASH_SIZE];
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uint8 cert_buffer_hash[MAX_HASH_SIZE];
		large_managed_buffer_t th_curr;
		uint8 THCurrHashData[64];
		uint8 bin_str0[128];
		uintn bin_str0_size;
		uint8 bin_str2[128];
		uintn bin_str2_size;
		uint8 bin_str7[128];
		uintn bin_str7_size;
		uint8 handshake_secret[MAX_HASH_SIZE];
		uint8 response_handshake_secret[MAX_HASH_SIZE];
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
		signature_size = spdm_get_asym_signature_size(m_use_asym_algo);
		hash_size = spdm_get_hash_size(m_use_hash_algo);
		hmac_size = spdm_get_hash_size(m_use_hash_algo);
		dhe_key_size = spdm_get_dhe_pub_key_size(m_use_dhe_algo);
		opaque_key_exchange_rsp_size =
			spdm_get_opaque_data_version_selection_data_size(
				spdm_context);
		temp_buf_size = sizeof(spdm_key_exchange_response_t) +
				dhe_key_size + 0 + sizeof(uint16) +
				opaque_key_exchange_rsp_size + signature_size +
				hmac_size;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response->header.request_response_code =
			SPDM_KEY_EXCHANGE_RSP;
		spdm_response->header.param1 = 0;
		spdm_response->rsp_session_id =
			spdm_allocate_rsp_session_id(spdm_context);
		spdm_response->mut_auth_requested = 0;
		spdm_response->req_slot_id_param = 0;
		spdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
				       spdm_response->random_data);
		ptr = (void *)(spdm_response + 1);
		dhe_context = spdm_dhe_new(m_use_dhe_algo);
		spdm_dhe_generate_key(m_use_dhe_algo, dhe_context, ptr,
				      &dhe_key_size);
		final_key_size = sizeof(final_key);
		spdm_dhe_compute_key(
			m_use_dhe_algo, dhe_context,
			(uint8 *)&m_local_buffer[0] +
				sizeof(spdm_key_exchange_request_t),
			dhe_key_size, final_key, &final_key_size);
		spdm_dhe_free(m_use_dhe_algo, dhe_context);
		ptr += dhe_key_size;
		// zero_mem (ptr, hash_size);
		// ptr += hash_size;
		*(uint16 *)ptr = (uint16)opaque_key_exchange_rsp_size;
		ptr += sizeof(uint16);
		spdm_build_opaque_data_version_selection_data(
			spdm_context, &opaque_key_exchange_rsp_size, ptr);
		ptr += opaque_key_exchange_rsp_size;
		read_responder_public_certificate_chain(m_use_hash_algo,
							m_use_asym_algo, &data,
							&data_size, NULL, NULL);
		copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
			 (uintn)ptr - (uintn)spdm_response);
		m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
		DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
		       m_local_buffer_size));
		internal_dump_hex(m_local_buffer, m_local_buffer_size);
		init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
		cert_buffer = (uint8 *)data;
		cert_buffer_size = data_size;
		spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
			      cert_buffer_hash);
		// transcript.message_a size is 0
		append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
		append_managed_buffer(&th_curr, m_local_buffer,
				      m_local_buffer_size);
		spdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr), hash_data);
		free(data);
		spdm_responder_data_sign(spdm_version, SPDM_KEY_EXCHANGE_RSP,
					 m_use_asym_algo, m_use_hash_algo,
					 FALSE, get_managed_buffer(&th_curr),
					 get_managed_buffer_size(&th_curr), ptr,
					 &signature_size);
		copy_mem(&m_local_buffer[m_local_buffer_size], ptr,
			 signature_size);
		m_local_buffer_size += signature_size;
		append_managed_buffer(&th_curr, ptr, signature_size);
		ptr += signature_size;
		spdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      THCurrHashData);
		bin_str0_size = sizeof(bin_str0);
		spdm_bin_concat(BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1,
				NULL, (uint16)hash_size, hash_size, bin_str0,
				&bin_str0_size);
		spdm_hmac_all(m_use_hash_algo, m_zero_filled_buffer, hash_size,
			      final_key, final_key_size, handshake_secret);
		bin_str2_size = sizeof(bin_str2);
		spdm_bin_concat(BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1,
				THCurrHashData, (uint16)hash_size, hash_size,
				bin_str2, &bin_str2_size);
		spdm_hkdf_expand(m_use_hash_algo, handshake_secret, hash_size,
				 bin_str2, bin_str2_size,
				 response_handshake_secret, hash_size);
		bin_str7_size = sizeof(bin_str7);
		spdm_bin_concat(BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1,
				NULL, (uint16)hash_size, hash_size, bin_str7,
				&bin_str7_size);
		spdm_hkdf_expand(m_use_hash_algo, response_handshake_secret,
				 hash_size, bin_str7, bin_str7_size,
				 response_finished_key, hash_size);
		spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
			      get_managed_buffer_size(&th_curr),
			      response_finished_key, hash_size, ptr);
		ptr += hmac_size;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

void test_spdm_requester_key_exchange_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_UNSUPPORTED);
	free(data);
}

void test_spdm_requester_key_exchange_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(session_id, 0xFFFFFFFF);
	assert_int_equal(
		spdm_secured_message_get_session_state(
			spdm_context->session_info[0].secured_message_context),
		SPDM_SESSION_STATE_HANDSHAKING);
	free(data);
}

void test_spdm_requester_key_exchange_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_UNSUPPORTED);
	free(data);
}

void test_spdm_requester_key_exchange_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_key_exchange_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_NO_RESPONSE);
	free(data);
}

void test_spdm_requester_key_exchange_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(session_id, 0xFFFEFFFE);
	assert_int_equal(
		spdm_secured_message_get_session_state(
			spdm_context->session_info[0].secured_message_context),
		SPDM_SESSION_STATE_HANDSHAKING);
	free(data);
}

void test_spdm_requester_key_exchange_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
	free(data);
}

void test_spdm_requester_key_exchange_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

void test_spdm_requester_key_exchange_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
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
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(session_id, 0xFFFDFFFD);
	assert_int_equal(
		spdm_secured_message_get_session_state(
			spdm_context->session_info[0].secured_message_context),
		SPDM_SESSION_STATE_HANDSHAKING);
	free(data);
}

void test_spdm_requester_key_exchange_case10(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint32               session_id;
  uint8                heartbeat_period;
  uint8                measurement_hash[MAX_HASH_SIZE];
  uint8                slot_id_param;
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;
  uint16               error_code;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xA;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo; 
  spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
  copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);

  error_code = SPDM_ERROR_CODE_RESERVED_00;
  while(error_code <= 0xff) {
    spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_reset_message_a(spdm_context);

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_key_exchange (spdm_context, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
               0, &session_id, &heartbeat_period, &slot_id_param, measurement_hash);
    // assert_int_equal (status, RETURN_DEVICE_ERROR);
    ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);

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

void test_spdm_requester_key_exchange_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 slot_id_param;
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xb;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	spdm_context->transcript.message_m.buffer_size =
							spdm_context->transcript.message_m.max_buffer_size;
	spdm_context->transcript.message_b.buffer_size =
							spdm_context->transcript.message_b.max_buffer_size;
	spdm_context->transcript.message_c.buffer_size =
							spdm_context->transcript.message_c.max_buffer_size;
	spdm_context->transcript.message_mut_b.buffer_size =
							spdm_context->transcript.message_mut_b.max_buffer_size;
	spdm_context->transcript.message_mut_c.buffer_size =
							spdm_context->transcript.message_mut_c.max_buffer_size;
#endif
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_send_receive_key_exchange(
		spdm_context,
		SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
		&session_id, &heartbeat_period, &slot_id_param,
		measurement_hash);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(
		spdm_secured_message_get_session_state(
			spdm_context->session_info[0].secured_message_context),
		SPDM_SESSION_STATE_HANDSHAKING);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif
	free(data);
}

spdm_test_context_t m_spdm_requester_key_exchange_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_key_exchange_test_send_message,
	spdm_requester_key_exchange_test_receive_message,
};

int spdm_requester_key_exchange_test_main(void)
{
	const struct CMUnitTest spdm_requester_key_exchange_tests[] = {
		// SendRequest failed
		cmocka_unit_test(test_spdm_requester_key_exchange_case1),
		// Successful response
		cmocka_unit_test(test_spdm_requester_key_exchange_case2),
		// connection_state check failed
		cmocka_unit_test(test_spdm_requester_key_exchange_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(test_spdm_requester_key_exchange_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(test_spdm_requester_key_exchange_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(test_spdm_requester_key_exchange_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(test_spdm_requester_key_exchange_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		cmocka_unit_test(test_spdm_requester_key_exchange_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(test_spdm_requester_key_exchange_case9),
		// Unexpected errors
		cmocka_unit_test(test_spdm_requester_key_exchange_case10),
		// Buffer reset
		cmocka_unit_test(test_spdm_requester_key_exchange_case11),

	};

	setup_spdm_test_context(&m_spdm_requester_key_exchange_test_context);

	return cmocka_run_group_tests(spdm_requester_key_exchange_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
