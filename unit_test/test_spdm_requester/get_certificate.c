/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>

static void *m_local_certificate_chain;
static uintn m_local_certificate_chain_size;

return_status spdm_requester_get_certificate_test_send_message(
	IN void *spdm_context, IN uintn request_size, IN void *request,
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
	case 0xA:
		return RETURN_SUCCESS;
	case 0xB:
		return RETURN_SUCCESS;
	case 0xC:
		return RETURN_SUCCESS;
	case 0xD:
		return RETURN_SUCCESS;
	case 0xE:
		return RETURN_SUCCESS;
	case 0xF:
		return RETURN_SUCCESS;
	case 0x10:
		return RETURN_SUCCESS;
	case 0x11:
		return RETURN_SUCCESS;
	case 0x12:
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

return_status spdm_requester_get_certificate_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
		}
		if (m_local_certificate_chain == NULL) {
			return RETURN_OUT_OF_RESOURCES;
		}
		count = (m_local_certificate_chain_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				m_local_certificate_chain_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
		}
		if (m_local_certificate_chain == NULL) {
			return RETURN_OUT_OF_RESOURCES;
		}
		count = (m_local_certificate_chain_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				m_local_certificate_chain_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
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
			sub_index1++;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		} else if (sub_index1 == 1) {
			spdm_certificate_response_t *spdm_response;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;
			uint16 portion_length;
			uint16 remainder_length;
			uintn count;
			static uintn calling_index = 0;

			if (m_local_certificate_chain == NULL) {
				read_responder_public_certificate_chain(
					m_use_hash_algo, m_use_asym_algo,
					&m_local_certificate_chain,
					&m_local_certificate_chain_size, NULL,
					NULL);
			}
			if (m_local_certificate_chain == NULL) {
				return RETURN_OUT_OF_RESOURCES;
			}
			count = (m_local_certificate_chain_size +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			if (calling_index != count - 1) {
				portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
				remainder_length = (uint16)(
					m_local_certificate_chain_size -
					MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						(calling_index + 1));
			} else {
				portion_length = (uint16)(
					m_local_certificate_chain_size -
					MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						(count - 1));
				remainder_length = 0;
			}

			temp_buf_size = sizeof(spdm_certificate_response_t) +
					portion_length;
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response->header.request_response_code =
				SPDM_CERTIFICATE;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = 0;
			spdm_response->portion_length = portion_length;
			spdm_response->remainder_length = remainder_length;
			copy_mem(spdm_response + 1,
				 (uint8 *)m_local_certificate_chain +
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 calling_index,
				 portion_length);

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);

			calling_index++;
			if (calling_index == count) {
				calling_index = 0;
				free(m_local_certificate_chain);
				m_local_certificate_chain = NULL;
				m_local_certificate_chain_size = 0;
			}
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
		spdm_response.extend_error_data.request_code =
			SPDM_GET_CERTIFICATE;
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
				SPDM_GET_CERTIFICATE;
			spdm_response.extend_error_data.token = 1;
			sub_index2++;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		} else if (sub_index2 == 1) {
			spdm_certificate_response_t *spdm_response;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;
			uint16 portion_length;
			uint16 remainder_length;
			uintn count;
			static uintn calling_index = 0;

			if (m_local_certificate_chain == NULL) {
				read_responder_public_certificate_chain(
					m_use_hash_algo, m_use_asym_algo,
					&m_local_certificate_chain,
					&m_local_certificate_chain_size, NULL,
					NULL);
			}
			if (m_local_certificate_chain == NULL) {
				return RETURN_OUT_OF_RESOURCES;
			}
			count = (m_local_certificate_chain_size +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			if (calling_index != count - 1) {
				portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
				remainder_length = (uint16)(
					m_local_certificate_chain_size -
					MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						(calling_index + 1));
			} else {
				portion_length = (uint16)(
					m_local_certificate_chain_size -
					MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						(count - 1));
				remainder_length = 0;
			}

			temp_buf_size = sizeof(spdm_certificate_response_t) +
					portion_length;
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response->header.request_response_code =
				SPDM_CERTIFICATE;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = 0;
			spdm_response->portion_length = portion_length;
			spdm_response->remainder_length = remainder_length;
			copy_mem(spdm_response + 1,
				 (uint8 *)m_local_certificate_chain +
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 calling_index,
				 portion_length);

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);

			calling_index++;
			if (calling_index == count) {
				calling_index = 0;
				free(m_local_certificate_chain);
				m_local_certificate_chain = NULL;
				m_local_certificate_chain_size = 0;
			}
		}
	}
		return RETURN_SUCCESS;

	case 0xA: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
		}
		if (m_local_certificate_chain == NULL) {
			return RETURN_OUT_OF_RESOURCES;
		}
		count = (m_local_certificate_chain_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				m_local_certificate_chain_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

	case 0xB: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		uint8 *leaf_cert_buffer;
		uintn leaf_cert_buffer_size;
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uintn hash_size;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
			if (m_local_certificate_chain == NULL) {
				return RETURN_OUT_OF_RESOURCES;
			}

			// load certificate
			hash_size = spdm_get_hash_size(m_use_hash_algo);
			cert_buffer = (uint8 *)m_local_certificate_chain +
				      sizeof(spdm_cert_chain_t) + hash_size;
			cert_buffer_size = m_local_certificate_chain_size -
					   sizeof(spdm_cert_chain_t) -
					   hash_size;
			if (!x509_get_cert_from_cert_chain(
				    cert_buffer, cert_buffer_size, -1,
				    &leaf_cert_buffer,
				    &leaf_cert_buffer_size)) {
				DEBUG((DEBUG_INFO,
				       "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
				return RETURN_DEVICE_ERROR;
			}
			// tamper certificate signature on purpose
			// arbitrarily change the last byte of the certificate signature
			cert_buffer[cert_buffer_size - 1]++;
		}
		count = (m_local_certificate_chain_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				m_local_certificate_chain_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

	case 0xC: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
		}
		if (m_local_certificate_chain == NULL) {
			return RETURN_OUT_OF_RESOURCES;
		}
		count = (m_local_certificate_chain_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				m_local_certificate_chain_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

	case 0xD: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain_by_size(
				m_use_hash_algo, m_use_asym_algo,
				TEST_CERT_SMALL, &m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
		}
		if (m_local_certificate_chain == NULL) {
			return RETURN_OUT_OF_RESOURCES;
		}
		count = (m_local_certificate_chain_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				m_local_certificate_chain_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

	case 0xE: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uint16 get_cert_length;
		uintn count;
		static uintn calling_index = 0;

		// this should match the value on the test function
		get_cert_length = 1;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
		}
		if (m_local_certificate_chain == NULL) {
			return RETURN_OUT_OF_RESOURCES;
		}
		count = (m_local_certificate_chain_size + get_cert_length + 1) /
			get_cert_length;
		if (calling_index != count - 1) {
			portion_length = get_cert_length;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 get_cert_length * (calling_index + 1));
		} else {
			portion_length =
				(uint16)(m_local_certificate_chain_size -
					 get_cert_length * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 get_cert_length * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

	case 0xF: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain_by_size(
				m_use_hash_algo, m_use_asym_algo,
				TEST_CERT_MAXUINT16, &m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
		}
		if (m_local_certificate_chain == NULL) {
			return RETURN_OUT_OF_RESOURCES;
		}
		count = (m_local_certificate_chain_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(m_local_certificate_chain_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				m_local_certificate_chain_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		copy_mem(spdm_response + 1,
			 (uint8 *)m_local_certificate_chain +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

  case 0x10:
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

	case 0x11: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		uint8 *leaf_cert_buffer;
		uintn leaf_cert_buffer_size;
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uintn hash_size;
		uint8 cert_chain_without_root[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn cert_chain_without_root_size;
		void *root_cert_data;
		uintn root_cert_size;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
			if (m_local_certificate_chain == NULL) {
				return RETURN_OUT_OF_RESOURCES;
			}
			// read root certificate size
			read_responder_root_public_certificate(
				m_use_hash_algo, m_use_asym_algo,
				&root_cert_data,
				&root_cert_size, NULL, NULL);
			// load certificate
			hash_size = spdm_get_hash_size(m_use_hash_algo);
			root_cert_size = root_cert_size -
					  sizeof(spdm_cert_chain_t) - hash_size;
			cert_buffer = (uint8 *)m_local_certificate_chain +
				      sizeof(spdm_cert_chain_t) + hash_size + root_cert_size;
			cert_buffer_size = m_local_certificate_chain_size -
					   sizeof(spdm_cert_chain_t) -
					   hash_size - root_cert_size;
			DEBUG((DEBUG_INFO,
				       "root_cert_size %d \n",root_cert_size));
			if (!x509_get_cert_from_cert_chain(
				    cert_buffer, cert_buffer_size, -1,
				    &leaf_cert_buffer,
				    &leaf_cert_buffer_size)) {
				DEBUG((DEBUG_INFO,
				       "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
				return RETURN_DEVICE_ERROR;
			}
		}
		copy_mem(cert_chain_without_root,
			 m_local_certificate_chain,
			 sizeof(spdm_cert_chain_t) + hash_size);
		copy_mem(cert_chain_without_root + sizeof(spdm_cert_chain_t) + hash_size,
			 cert_buffer,
			 cert_buffer_size);
		cert_chain_without_root_size = m_local_certificate_chain_size - root_cert_size;
		count = (cert_chain_without_root_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(cert_chain_without_root_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				cert_chain_without_root_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		// send certchain without root
		copy_mem(spdm_response + 1,
			 (uint8 *)cert_chain_without_root +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			free(root_cert_data);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;

	case 0x12: {
		spdm_certificate_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uint16 portion_length;
		uint16 remainder_length;
		uintn count;
		static uintn calling_index = 0;

		uint8 *leaf_cert_buffer;
		uintn leaf_cert_buffer_size;
		uint8 *cert_buffer;
		uintn cert_buffer_size;
		uintn hash_size;
		uint8 cert_chain_without_root[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn cert_chain_without_root_size;
		void *root_cert_data;
		uintn root_cert_size;

		if (m_local_certificate_chain == NULL) {
			read_responder_public_certificate_chain(
				m_use_hash_algo, m_use_asym_algo,
				&m_local_certificate_chain,
				&m_local_certificate_chain_size, NULL, NULL);
			if (m_local_certificate_chain == NULL) {
				return RETURN_OUT_OF_RESOURCES;
			}
			// read root certificate size
			read_responder_root_public_certificate(
				m_use_hash_algo, m_use_asym_algo,
				&root_cert_data,
				&root_cert_size, NULL, NULL);
			// load certificate
			hash_size = spdm_get_hash_size(m_use_hash_algo);
			root_cert_size = root_cert_size -
					  sizeof(spdm_cert_chain_t) - hash_size;
			cert_buffer = (uint8 *)m_local_certificate_chain +
				      sizeof(spdm_cert_chain_t) + hash_size + root_cert_size;
			cert_buffer_size = m_local_certificate_chain_size -
					   sizeof(spdm_cert_chain_t) -
					   hash_size - root_cert_size;
			DEBUG((DEBUG_INFO,
				       "root_cert_size %d \n",root_cert_size));
			if (!x509_get_cert_from_cert_chain(
				    cert_buffer, cert_buffer_size, -1,
				    &leaf_cert_buffer,
				    &leaf_cert_buffer_size)) {
				DEBUG((DEBUG_INFO,
				       "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
				return RETURN_DEVICE_ERROR;
			}
			// tamper certificate signature on purpose
			// arbitrarily change the last byte of the certificate signature
			cert_buffer[cert_buffer_size - 1]++;
		}
		copy_mem(cert_chain_without_root,
			 m_local_certificate_chain,
			 sizeof(spdm_cert_chain_t) + hash_size);
		copy_mem(cert_chain_without_root + sizeof(spdm_cert_chain_t) + hash_size,
			 cert_buffer,
			 cert_buffer_size);
		cert_chain_without_root_size = m_local_certificate_chain_size - root_cert_size;
		count = (cert_chain_without_root_size +
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) /
			MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
		if (calling_index != count - 1) {
			portion_length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
			remainder_length =
				(uint16)(cert_chain_without_root_size -
					 MAX_SPDM_CERT_CHAIN_BLOCK_LEN *
						 (calling_index + 1));
		} else {
			portion_length = (uint16)(
				cert_chain_without_root_size -
				MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (count - 1));
			remainder_length = 0;
		}

		temp_buf_size =
			sizeof(spdm_certificate_response_t) + portion_length;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->portion_length = portion_length;
		spdm_response->remainder_length = remainder_length;
		// send certchain without root
		copy_mem(spdm_response + 1,
			 (uint8 *)cert_chain_without_root +
				 MAX_SPDM_CERT_CHAIN_BLOCK_LEN * calling_index,
			 portion_length);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);

		calling_index++;
		if (calling_index == count) {
			calling_index = 0;
			free(m_local_certificate_chain);
			free(root_cert_data);
			m_local_certificate_chain = NULL;
			m_local_certificate_chain_size = 0;
		}
	}
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

/**
  Test 1: message could not be sent
  Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
**/
void test_spdm_requester_get_certificate_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
	free(data);
}

/**
  Test 2: Normal case, request a certificate chain
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
		DEBUG((DEBUG_INFO, "root cert data :\n"));
		internal_dump_hex(
			root_cert,
			get_managed_buffer_size(
				&spdm_context->transcript.message_mut_b));
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	spdm_context->transcript.message_m.buffer_size =
							spdm_context->transcript.message_m.max_buffer_size;
	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_certificate_request_t) * count +
				 sizeof(spdm_certificate_response_t) * count +
				 data_size);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
	free(data);
}

/**
  Test 3: simulate wrong connection_state when sending GET_CERTIFICATE (missing SPDM_GET_DIGESTS_RECEIVE_FLAG and SPDM_GET_CAPABILITIES_RECEIVE_FLAG)
  Expected Behavior: get a RETURN_UNSUPPORTED, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
**/
void test_spdm_requester_get_certificate_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_UNSUPPORTED);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
	free(data);
}

/**
  Test 4: force responder to send an ERROR message with code SPDM_ERROR_CODE_INVALID_REQUEST
  Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
**/
void test_spdm_requester_get_certificate_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
	free(data);
}

/**
  Test 5: force responder to send an ERROR message with code SPDM_ERROR_CODE_BUSY
  Expected Behavior: get a RETURN_NO_RESPONSE, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
**/
void test_spdm_requester_get_certificate_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_NO_RESPONSE);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
	free(data);
}

/**
  Test 6: force responder to first send an ERROR message with code SPDM_ERROR_CODE_BUSY, but functions normally afterwards
  Expected Behavior: receives the correct number of CERTIFICATE messages
**/
void test_spdm_requester_get_certificate_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_certificate_request_t) * count +
				 sizeof(spdm_certificate_response_t) * count +
				 data_size);
	free(data);
}

/**
  Test 7: force responder to send an ERROR message with code SPDM_ERROR_CODE_REQUEST_RESYNCH
  Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
**/
void test_spdm_requester_get_certificate_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
	free(data);
}

/**
  Test 8: force responder to send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
  Expected Behavior: get a RETURN_NO_RESPONSE
**/
void test_spdm_requester_get_certificate_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	free(data);
}

/**
  Test 9: force responder to first send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY, but functions normally afterwards
  Expected Behavior: receives the correct number of CERTIFICATE messages
**/
void test_spdm_requester_get_certificate_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_certificate_request_t) * count +
				 sizeof(spdm_certificate_response_t) * count +
				 data_size);
	free(data);
}

/**
  Test 10: Normal case, request a certificate chain. Validates certificate by using a prelaoded chain instead of root hash
  Expected Behavior: receives the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case10(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xA;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	spdm_context->local_context.peer_root_cert_provision_size = 0;
	spdm_context->local_context.peer_root_cert_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision = data;
	spdm_context->local_context.peer_cert_chain_provision_size = data_size;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_certificate_request_t) * count +
				 sizeof(spdm_certificate_response_t) * count +
				 data_size);
	free(data);
}

/**
  Test 11: Normal procedure, but the retrieved certificate chain has an invalid signature
  Expected Behavior: get a RETURN_SECURITY_VIOLATION, and receives the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xB;
	// Setting SPDM context as the first steps of the protocol has been accomplished
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	// Loading certificate chain and saving root certificate hash
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	// Reseting message buffer
	spdm_context->transcript.message_b.buffer_size = 0;
	// Calculating expected number of messages received
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_certificate_request_t) * count +
				 sizeof(spdm_certificate_response_t) * count +
				 data_size);
	free(data);
}

/**
  Test 12: Normal procedure, but the retrieved root certificate does not match
  Expected Behavior: get a RETURN_SECURITY_VIOLATION, and receives the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case12(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xC;
	// Setting SPDM context as the first steps of the protocol has been accomplished
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	// arbitrarily changes the root certificate on purpose
	if (root_cert != NULL) {
		((uint8 *)root_cert)[0]++;
	}
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	// Reseting message buffer
	spdm_context->transcript.message_b.buffer_size = 0;
	// Calculating expected number of messages received
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_certificate_request_t) * count +
				 sizeof(spdm_certificate_response_t) * count +
				 data_size);
	free(data);
}

/**
  Test 13: Gets a short certificate chain (fits in 1 message)
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case13(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xD;
	// Setting SPDM context as the first steps of the protocol has been accomplished
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	// Loading Root certificate and saving its hash
	read_responder_public_certificate_chain_by_size(
		m_use_hash_algo, m_use_asym_algo, TEST_CERT_SMALL, &data,
		&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	// Reseting message buffer
	spdm_context->transcript.message_b.buffer_size = 0;
	// Calculating expected number of messages received
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_certificate_request_t) * count +
				 sizeof(spdm_certificate_response_t) * count +
				 data_size);
	free(data);
}

/**
  Test 14: request a whole certificate chain byte by byte
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case14(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;
	uint16 get_cert_length;

	// Get certificate chain byte by byte
	get_cert_length = 1;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xE;
	// Setting SPDM context as the first steps of the protocol has been accomplished
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	// Loading Root certificate and saving its hash
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	// Reseting message buffer
	spdm_context->transcript.message_b.buffer_size = 0;
	// Calculating expected number of messages received
	count = (data_size + get_cert_length - 1) / get_cert_length;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate_choose_length(
		spdm_context, 0, get_cert_length, &cert_chain_size, cert_chain);
	// It may fail because the spdm does not support too many messages.
	//assert_int_equal (status, RETURN_SUCCESS);
	if (status == RETURN_SUCCESS) {
		assert_int_equal(
			spdm_context->transcript.message_b.buffer_size,
			sizeof(spdm_get_certificate_request_t) * count +
				sizeof(spdm_certificate_response_t) * count +
				data_size);
	}
	free(data);
}

/**
  Test 15: request a long certificate chain
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case15(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uint8 *root_cert;
	uintn root_cert_size;
	uintn count;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xF;
	// Setting SPDM context as the first steps of the protocol has been accomplished
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	// Loading Root certificate and saving its hash
	read_responder_public_certificate_chain_by_size(
		m_use_hash_algo, m_use_asym_algo, TEST_CERT_MAXUINT16, &data,
		&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	spdm_context->local_context.peer_root_cert_provision_size =
		root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	// Reseting message buffer
	spdm_context->transcript.message_b.buffer_size = 0;
	// Calculating expected number of messages received
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	// It may fail because the spdm does not support too long message.
	//assert_int_equal (status, RETURN_SUCCESS);
	if (status == RETURN_SUCCESS) {
		assert_int_equal(
			spdm_context->transcript.message_b.buffer_size,
			sizeof(spdm_get_certificate_request_t) * count +
				sizeof(spdm_certificate_response_t) * count +
				data_size);
	}
	free(data);
}

/**
  Test 16: receiving an unexpected ERROR message from the responder.
  There are tests for all named codes, including some reserved ones
  (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
  However, for having specific test cases, it is excluded from this case:
  Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
**/
void test_spdm_requester_get_certificate_case16(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                cert_chain_size;
  uint8                cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
  void                 *data;
  uintn                data_size;
  void                 *hash;
  uintn                hash_size;
  uint8                 *root_cert;
  uintn                root_cert_size;
  uint16                error_code;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x10;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
  x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
					data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
					&root_cert, &root_cert_size);
  spdm_context->local_context.peer_root_cert_provision_size = root_cert_size;
  spdm_context->local_context.peer_root_cert_provision = root_cert;
  spdm_context->local_context.peer_cert_chain_provision = NULL;
  spdm_context->local_context.peer_cert_chain_provision_size = 0;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;

  error_code = SPDM_ERROR_CODE_RESERVED_00;
  while(error_code <= 0xff) {
    spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->transcript.message_b.buffer_size = 0;

    cert_chain_size = sizeof(cert_chain);
    zero_mem (cert_chain, sizeof(cert_chain));
    status = spdm_get_certificate (spdm_context, 0, &cert_chain_size, cert_chain);
    // assert_int_equal (status, RETURN_DEVICE_ERROR);
    // assert_int_equal (spdm_context->transcript.message_b.buffer_size, 0);
    ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
    ASSERT_INT_EQUAL_CASE (spdm_context->transcript.message_b.buffer_size, 0, error_code);

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

/**
  Test 17: Normal case, get a certificate chain start not with root cert. Validates certificate by using a prelaoded chain.
  Expected Behavior: receives the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case17(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uintn count;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x11;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	spdm_context->local_context.peer_root_cert_provision_size = root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SUCCESS);
	free(data);
}

/**
  Test 18: Fail case, get a certificate chain start not with root cert and with wrong signature. Validates certificate by using a prelaoded chain.
  Expected Behavior: receives the correct number of Certificate messages
**/
void test_spdm_requester_get_certificate_case18(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn cert_chain_size;
	uint8 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
	void *data;
	uintn data_size;
	void *hash;
	uintn hash_size;
	uintn count;
	uint8 *root_cert;
	uintn root_cert_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x12;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, &hash, &hash_size);
	x509_get_cert_from_cert_chain((uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size,
						data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
						&root_cert, &root_cert_size);
	count = (data_size + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) /
		MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	spdm_context->local_context.peer_root_cert_provision_size = root_cert_size;
	spdm_context->local_context.peer_root_cert_provision = root_cert;
	spdm_context->local_context.peer_cert_chain_provision = NULL;
	spdm_context->local_context.peer_cert_chain_provision_size = 0;
	spdm_context->transcript.message_b.buffer_size = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	cert_chain_size = sizeof(cert_chain);
	zero_mem(cert_chain, sizeof(cert_chain));
	status = spdm_get_certificate(spdm_context, 0, &cert_chain_size,
				      cert_chain);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	free(data);
}

spdm_test_context_t m_spdm_requester_get_certificate_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_get_certificate_test_send_message,
	spdm_requester_get_certificate_test_receive_message,
};

int spdm_requester_get_certificate_test_main(void)
{
	const struct CMUnitTest spdm_requester_get_certificate_tests[] = {
		// SendRequest failed
		cmocka_unit_test(test_spdm_requester_get_certificate_case1),
		// Successful response: check root certificate hash
		cmocka_unit_test(test_spdm_requester_get_certificate_case2),
		// connection_state check failed
		cmocka_unit_test(test_spdm_requester_get_certificate_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(test_spdm_requester_get_certificate_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(test_spdm_requester_get_certificate_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(test_spdm_requester_get_certificate_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(test_spdm_requester_get_certificate_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		cmocka_unit_test(test_spdm_requester_get_certificate_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(test_spdm_requester_get_certificate_case9),
		// Successful response: check certificate chain
		cmocka_unit_test(test_spdm_requester_get_certificate_case10),
		// Invalid certificate signature
		cmocka_unit_test(test_spdm_requester_get_certificate_case11),
		// Fail certificate chain check
		cmocka_unit_test(test_spdm_requester_get_certificate_case12),
		// Sucessful response: get a certificate chain that fits in one single message
		cmocka_unit_test(test_spdm_requester_get_certificate_case13),
		// Sucessful response: get certificate chain byte by byte
		cmocka_unit_test(test_spdm_requester_get_certificate_case14),
		// Sucessful response: get a long certificate chain
		cmocka_unit_test(test_spdm_requester_get_certificate_case15),
		// Unexpected errors
		cmocka_unit_test(test_spdm_requester_get_certificate_case16),
		// Sucessful response: get a certificate chain not start with root cert.
		cmocka_unit_test(test_spdm_requester_get_certificate_case17),
		// Fail response: get a certificate chain not start with root cert but with wrong signature.
		cmocka_unit_test(test_spdm_requester_get_certificate_case18),
	};

	setup_spdm_test_context(&m_spdm_requester_get_certificate_test_context);

	return cmocka_run_group_tests(spdm_requester_get_certificate_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
