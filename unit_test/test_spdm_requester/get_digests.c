/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <internal/libspdm_requester_lib.h>

#if SPDM_ENABLE_CAPABILITY_CERT_CAP

static uint8 m_local_certificate_chain[MAX_SPDM_MESSAGE_BUFFER_SIZE];

return_status spdm_requester_get_digests_test_send_message(
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
	case 0x13:
		return RETURN_SUCCESS;
	case 0x14:
		return RETURN_SUCCESS;
	case 0x15:
		return RETURN_SUCCESS;
	case 0x16:
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

return_status spdm_requester_get_digests_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_digest_response_t) +
				spdm_get_hash_size(m_use_hash_algo) * MAX_SPDM_SLOT_COUNT;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);
		//send all eight certchains digest
		//but only No.7 is right
		digest += spdm_get_hash_size(m_use_hash_algo) * (MAX_SPDM_SLOT_COUNT - 2);
		spdm_hash_all(m_use_hash_algo, m_local_certificate_chain,
			      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
		spdm_response->header.param2 |= (0xFF << 0);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_digest_response_t) +
				spdm_get_hash_size(m_use_hash_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);
		spdm_hash_all(m_use_hash_algo, m_local_certificate_chain,
			      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
		spdm_response->header.param2 |= (1 << 0);

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
		} else if (sub_index1 == 1) {
			spdm_digest_response_t *spdm_response;
			uint8 *digest;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;

			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_hash_algo =
				m_use_hash_algo;
			temp_buf_size = sizeof(spdm_digest_response_t) +
					spdm_get_hash_size(m_use_hash_algo);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response->header.param1 = 0;
			spdm_response->header.request_response_code =
				SPDM_DIGESTS;
			spdm_response->header.param2 = 0;
			set_mem(m_local_certificate_chain,
				MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));

			digest = (void *)(spdm_response + 1);
			spdm_hash_all(m_use_hash_algo,
				      m_local_certificate_chain,
				      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
			spdm_response->header.param2 |= (1 << 0);

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);
		}
		sub_index1++;
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
		spdm_response.extend_error_data.request_code = SPDM_GET_DIGESTS;
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
				SPDM_GET_DIGESTS;
			spdm_response.extend_error_data.token = 1;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		} else if (sub_index2 == 1) {
			spdm_digest_response_t *spdm_response;
			uint8 *digest;
			uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
			uintn temp_buf_size;

			((spdm_context_t *)spdm_context)
				->connection_info.algorithm.base_hash_algo =
				m_use_hash_algo;
			temp_buf_size = sizeof(spdm_digest_response_t) +
					spdm_get_hash_size(m_use_hash_algo);
			spdm_response = (void *)temp_buf;

			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response->header.param1 = 0;
			spdm_response->header.request_response_code =
				SPDM_DIGESTS;
			spdm_response->header.param2 = 0;
			set_mem(m_local_certificate_chain,
				MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));

			digest = (void *)(spdm_response + 1);
			spdm_hash_all(m_use_hash_algo,
				      m_local_certificate_chain,
				      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
			spdm_response->header.param2 |= (1 << 0);

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE, temp_buf_size,
				temp_buf, response_size, response);
		}
		sub_index2++;
	}
		return RETURN_SUCCESS;

	case 0xA:
		return RETURN_SUCCESS;

	case 0xB:
		return RETURN_DEVICE_ERROR;

	case 0xC: {
		spdm_digest_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = 2;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0xD: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_digest_response_t) +
				spdm_get_hash_size(m_use_hash_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_CERTIFICATE;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);
		spdm_hash_all(m_use_hash_algo, m_local_certificate_chain,
			      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
		spdm_response->header.param2 |= (1 << 0);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0xE: {
		spdm_digest_response_t spdm_response;

		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.param1 = 0;
		spdm_response.header.request_response_code = SPDM_DIGESTS;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0xF:
		return RETURN_SUCCESS;

	case 0x10: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_digest_response_t) +
				spdm_get_hash_size(m_use_hash_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);
		spdm_hash_all(m_use_hash_algo, m_local_certificate_chain,
			      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
		spdm_response->header.param2 |= (1 << 0);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x11: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_digest_response_t) +
				spdm_get_hash_size(m_use_hash_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);
		spdm_hash_all(m_use_hash_algo, m_local_certificate_chain,
			      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
		digest[spdm_get_hash_size(m_use_hash_algo) - 1] = 0;
		spdm_response->header.param2 |= (1 << 0);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x12: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uintn digest_count;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uintn index;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		digest_count = 4;
		temp_buf_size = sizeof(spdm_digest_response_t) +
				spdm_get_hash_size(m_use_hash_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);

		spdm_hash_all(m_use_hash_algo, m_local_certificate_chain,
			      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
		for (index = 0; index < digest_count; index++) {
			spdm_response->header.param2 |= (1 << index);
		}

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x13: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uintn digest_count;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;
		uintn index;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		digest_count = 4;
		temp_buf_size =
			sizeof(spdm_digest_response_t) +
			digest_count * spdm_get_hash_size(m_use_hash_algo);
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);

		for (index = 0; index < digest_count; index++) {
			spdm_hash_all(
				m_use_hash_algo, m_local_certificate_chain,
				MAX_SPDM_MESSAGE_BUFFER_SIZE,
				&digest[index *
					spdm_get_hash_size(m_use_hash_algo)]);
			spdm_response->header.param2 |= (1 << index);
			if (index == 0)
				continue;
			digest[(index + 1) * spdm_get_hash_size(m_use_hash_algo) -
			       1] = 0;
		}

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x14: {
		spdm_digest_response_t *spdm_response;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = 5;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

	case 0x15: {
		spdm_digest_response_t *spdm_response;
		uint8 *digest;
		uint8 temp_buf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
		uintn temp_buf_size;

		((spdm_context_t *)spdm_context)
			->connection_info.algorithm.base_hash_algo =
			m_use_hash_algo;
		temp_buf_size = sizeof(spdm_message_header_t) +
				MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT + 1;
		spdm_response = (void *)temp_buf;

		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response->header.param1 = 0;
		spdm_response->header.request_response_code = SPDM_DIGESTS;
		spdm_response->header.param2 = 0;
		set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
			(uint8)(0xFF));

		digest = (void *)(spdm_response + 1);
		spdm_hash_all(m_use_hash_algo, m_local_certificate_chain,
			      MAX_SPDM_MESSAGE_BUFFER_SIZE, &digest[0]);
		spdm_response->header.param2 |= (1 << 0);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, temp_buf_size,
						   temp_buf, response_size,
						   response);
	}
		return RETURN_SUCCESS;

  case 0x16:
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
  Test 1: a failure occurs during the sending of the request message
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
**/
void test_spdm_requester_get_digests_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
}

/**
  Test 2: a request message is successfully sent and a response message is successfully received
  Expected Behavior: requester returns the status RETURN_SUCCESS and a DIGESTS message is received
**/
void test_spdm_requester_get_digests_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	spdm_context->transcript.message_m.buffer_size =
							spdm_context->transcript.message_m.max_buffer_size;
#endif
	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(
		spdm_context->transcript.message_b.buffer_size,
		sizeof(spdm_get_digest_request_t) +
			sizeof(spdm_digest_response_t) +
			spdm_get_hash_size(spdm_context->connection_info
						   .algorithm.base_hash_algo) * MAX_SPDM_SLOT_COUNT);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
  Test 3: connection_state equals to zero and makes the check fail, meaning that steps
  GET_CAPABILITIES-CAPABILITIES and NEGOTIATE_ALGORITHMS-ALGORITHMS of the protocol were not previously completed
  Expected Behavior: requester returns the status RETURN_UNSUPPORTED, with no DIGESTS message received
**/
void test_spdm_requester_get_digests_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_UNSUPPORTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
}

/**
  Test 4: a request message is successfully sent and an ERROR response message with error code = InvalidRequest is received
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
**/
void test_spdm_requester_get_digests_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
}

/**
  Test 5: request messages are successfully sent and ERROR response messages with error code = Busy are received in all attempts
  Expected Behavior: requester returns the status RETURN_NO_RESPONSE, with no DIGESTS message received
**/
void test_spdm_requester_get_digests_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_NO_RESPONSE);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
}

/**
  Test 6: request messages are successfully sent and an ERROR response message with error code = Busy is received in the
  first attempt followed by a successful response
  Expected Behavior: requester returns the status RETURN_SUCCESS and a DIGESTS message is received
**/
void test_spdm_requester_get_digests_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(
		spdm_context->transcript.message_b.buffer_size,
		sizeof(spdm_get_digest_request_t) +
			sizeof(spdm_digest_response_t) +
			spdm_get_hash_size(spdm_context->connection_info
						   .algorithm.base_hash_algo));
#endif
}

/**
  Test 7: a request message is successfully sent and an ERROR response message with error code = RequestResynch
  (Meaning Responder is requesting Requester to reissue GET_VERSION to resynchronize) is received
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
**/
void test_spdm_requester_get_digests_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
}

/**
  Test 8: request messages are successfully sent and ERROR response messages with error code = ResponseNotReady
  are received in all attempts
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR
**/
void test_spdm_requester_get_digests_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
  Test 9: request messages are successfully sent and an ERROR response message with error code = ResponseNotReady
  is received in the first attempt followed by a successful response to RESPOND_IF_READY
  Expected Behavior: requester returns the status RETURN_SUCCESS and a DIGESTS message is received
**/
void test_spdm_requester_get_digests_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(
		spdm_context->transcript.message_b.buffer_size,
		sizeof(spdm_get_digest_request_t) +
			sizeof(spdm_digest_response_t) +
			spdm_get_hash_size(spdm_context->connection_info
						   .algorithm.base_hash_algo));
#endif
}

/**
  Test 10: flag cert_cap from CAPABILITIES is not setted meaning the Requester does not support DIGESTS and
  CERTIFICATE response messages
  Expected Behavior: requester returns the status RETURN_UNSUPPORTED, with no DIGESTS message received
**/
void test_spdm_requester_get_digests_case10(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xA;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_UNSUPPORTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
}

/**
  Test 11: a request message is successfully sent but a failure occurs during the receiving of the response message
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
**/
void test_spdm_requester_get_digests_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xB;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 0);
#endif
}

/**
  Test 12: a request message is successfully sent but the size of the response message is smaller than the size of the SPDM message header,
  meaning it is an invalid response message
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void test_spdm_requester_get_digests_case12(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_digest_request_t));
#endif
}

/**
  Test 13: a request message is successfully sent but the request_response_code from the response message is different than the code of SPDM_DIGESTS
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received 
**/
void test_spdm_requester_get_digests_case13(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xD;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 0);
#endif
}

/**
  Test 14: a request message is successfully sent but the number of digests in the response message is equal to zero
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received
**/
void test_spdm_requester_get_digests_case14(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xE;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 0);
#endif
}

/**
  Test 15: a request message is successfully sent but it cannot be appended to the internal cache since the internal cache is full
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR
**/
void test_spdm_requester_get_digests_case15(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xF;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	spdm_context->transcript.message_b.buffer_size =
		spdm_context->transcript.message_b.max_buffer_size;
#endif

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
  Test 16: a request message is successfully sent but the response message cannot be appended to the internal cache since the internal cache is full
  Expected Behavior: requester returns the status RETURN_SECURITY_VIOLATION
**/
void test_spdm_requester_get_digests_case16(void **state)
{
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	return_status status;
	uint8 slot_mask;
#endif
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x10;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	spdm_context->transcript.message_b.buffer_size =
		spdm_context->transcript.message_b.max_buffer_size -
		(sizeof(spdm_digest_response_t));
#endif

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#endif
}

/**
  Test 17: a request message is successfully sent but the single digest received in the response message is invalid
  Expected Behavior: requester returns the status RETURN_SECURITY_VIOLATION, with error state SPDM_STATUS_ERROR_CERTIFICATE_FAILURE
**/
void test_spdm_requester_get_digests_case17(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x11;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	assert_int_equal(spdm_context->error_state,
			 SPDM_STATUS_ERROR_CERTIFICATE_FAILURE);
}

/**
  Test 18: a request message is successfully sent but the number of digests received in the response message is different than
  the number of bits set in param2 - Slot mask
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void test_spdm_requester_get_digests_case18(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x12;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 0);
#endif
}

/**
  Test 19: a request message is successfully sent but several digests (except the first) received in the response message are invalid
  Expected Behavior: requester returns the status RETURN_SECURITY_VIOLATION, with error state SPDM_STATUS_ERROR_CERTIFICATE_FAILURE
**/
void test_spdm_requester_get_digests_case19(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x13;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	assert_int_equal(spdm_context->error_state,
			 SPDM_STATUS_ERROR_CERTIFICATE_FAILURE);
}

/**
  Test 20: a request message is successfully sent but the size of the response message is smaller than the minimum size of a SPDM DIGESTS response,
  meaning it is an invalid response message.
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void test_spdm_requester_get_digests_case20(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x14;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_digest_request_t));
#endif
}

/**
  Test 21: a request message is successfully sent but the size of the response message is bigger than the maximum size of a SPDM DIGESTS response,
  meaning it is an invalid response message.
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void test_spdm_requester_get_digests_case21(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 slot_mask;
	uint8 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x15;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->local_context.peer_cert_chain_provision =
		m_local_certificate_chain;
	spdm_context->local_context.peer_cert_chain_provision_size =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_reset_message_b(spdm_context);

	zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
	status =
		libspdm_get_digest(spdm_context, &slot_mask, &total_digest_buffer);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_b.buffer_size,
			 sizeof(spdm_get_digest_request_t));
#endif
}

/**
  Test 22: receiving an unexpected ERROR message from the responder.
  There are tests for all named codes, including some reserved ones
  (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
  However, for having specific test cases, it is excluded from this case:
  Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
**/
void test_spdm_requester_get_digests_case22(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint8                 slot_mask;
  uint8                 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
  uint16                error_code;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x16;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.peer_cert_chain_provision = m_local_certificate_chain;
  spdm_context->local_context.peer_cert_chain_provision_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));

  error_code = SPDM_ERROR_CODE_RESERVED_00;
  while(error_code <= 0xff) {
    spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_reset_message_b(spdm_context);
    
    zero_mem (total_digest_buffer, sizeof(total_digest_buffer));
    status = libspdm_get_digest (spdm_context, &slot_mask, &total_digest_buffer);
    // assert_int_equal (status, RETURN_DEVICE_ERROR);
    // assert_int_equal (spdm_context->transcript.message_b.buffer_size, 0);
    ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    ASSERT_INT_EQUAL_CASE (spdm_context->transcript.message_b.buffer_size, 0, error_code);
#endif

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
}

spdm_test_context_t m_spdm_requester_get_digests_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_get_digests_test_send_message,
	spdm_requester_get_digests_test_receive_message,
};

int spdm_requester_get_digests_test_main(void)
{
	const struct CMUnitTest spdm_requester_get_digests_tests[] = {
		// SendRequest failed
		cmocka_unit_test(test_spdm_requester_get_digests_case1),
		// Successful response
		cmocka_unit_test(test_spdm_requester_get_digests_case2),
		// connection_state check failed
		cmocka_unit_test(test_spdm_requester_get_digests_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(test_spdm_requester_get_digests_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(test_spdm_requester_get_digests_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(test_spdm_requester_get_digests_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(test_spdm_requester_get_digests_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		cmocka_unit_test(test_spdm_requester_get_digests_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(test_spdm_requester_get_digests_case9),
		// capability flags check failed
		cmocka_unit_test(test_spdm_requester_get_digests_case10),
		// ReceiveResponse failed
		cmocka_unit_test(test_spdm_requester_get_digests_case11),
		// size of response < spdm_message_header_t
		//cmocka_unit_test(test_spdm_requester_get_digests_case12),
		// request_response_code wrong in response
		cmocka_unit_test(test_spdm_requester_get_digests_case13),
		// Zero digests received
		cmocka_unit_test(test_spdm_requester_get_digests_case14),
		// Internal cache full (request message)
		// If request text is appending when reponse successfully instead of request,
		// case15 will useless and will cause a bug
		// cmocka_unit_test(test_spdm_requester_get_digests_case15),
		// Internal cache full (response message)
		cmocka_unit_test(test_spdm_requester_get_digests_case16),
		// Invalid digest
		cmocka_unit_test(test_spdm_requester_get_digests_case17),
		// Slot mask != number of digests
		cmocka_unit_test(test_spdm_requester_get_digests_case18),
		// Several invalid digests
		//cmocka_unit_test(test_spdm_requester_get_digests_case19),
		// size of response < spdm_digest_response_t
		//cmocka_unit_test(test_spdm_requester_get_digests_case20),
		// size of response > Max size of SPDM DIGESTS response
		//cmocka_unit_test(test_spdm_requester_get_digests_case21),
		// Unexpected errors
		cmocka_unit_test(test_spdm_requester_get_digests_case22),
	};

	setup_spdm_test_context(&m_spdm_requester_get_digests_test_context);

	return cmocka_run_group_tests(spdm_requester_get_digests_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}

#endif // SPDM_ENABLE_CAPABILITY_CERT_CAP