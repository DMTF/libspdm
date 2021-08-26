/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>

#define DEFAULT_CAPABILITY_FLAG                                                \
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |                        \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP)
#define DEFAULT_CAPABILITY_FLAG_VERSION_11                                     \
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |                        \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |                        \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |                     \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |                         \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |                    \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |                      \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |               \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |                       \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |                       \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |                     \
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
#define DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11                            \
	(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |                      \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |                       \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |                       \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |                   \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP |                 \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |                    \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |                        \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |                   \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |                     \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT | \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |                      \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |                      \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP |                    \
	 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)

return_status spdm_requester_get_capabilities_test_send_message(
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
	case 0xa:
		return RETURN_SUCCESS;
	case 0xb:
		return RETURN_SUCCESS;
	case 0xc:
		return RETURN_SUCCESS;
	case 0xd:
		return RETURN_SUCCESS;
	case 0xe:
		return RETURN_SUCCESS;
	case 0xf:
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
	case 0x17:
		return RETURN_SUCCESS;
	case 0x18:
		return RETURN_SUCCESS;
	case 0x19:
		return RETURN_SUCCESS;
	case 0x1a:
		return RETURN_SUCCESS;
	case 0x1b:
		return RETURN_SUCCESS;
	case 0x1c:
		return RETURN_SUCCESS;
	case 0x1d:
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

return_status spdm_requester_get_capabilities_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags = DEFAULT_CAPABILITY_FLAG;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags = DEFAULT_CAPABILITY_FLAG;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x4: {
		spdm_error_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
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

		zero_mem(&spdm_response, sizeof(spdm_response));
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

			zero_mem(&spdm_response, sizeof(spdm_response));
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
			spdm_capabilities_response spdm_response;

			zero_mem(&spdm_response, sizeof(spdm_response));
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code =
				SPDM_CAPABILITIES;
			spdm_response.header.param1 = 0;
			spdm_response.header.param2 = 0;
			spdm_response.ct_exponent = 0;
			spdm_response.flags = DEFAULT_CAPABILITY_FLAG;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		}
		sub_index1++;
	}
		return RETURN_SUCCESS;

	case 0x7: {
		spdm_error_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
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

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 =
			SPDM_ERROR_CODE_RESPONSE_NOT_READY;
		spdm_response.header.param2 = 0;
		spdm_response.extend_error_data.rd_exponent = 1;
		spdm_response.extend_error_data.rd_tm = 1;
		spdm_response.extend_error_data.request_code =
			SPDM_GET_CAPABILITIES;
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

			zero_mem(&spdm_response, sizeof(spdm_response));
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 =
				SPDM_ERROR_CODE_RESPONSE_NOT_READY;
			spdm_response.header.param2 = 0;
			spdm_response.extend_error_data.rd_exponent = 1;
			spdm_response.extend_error_data.rd_tm = 1;
			spdm_response.extend_error_data.request_code =
				SPDM_GET_CAPABILITIES;
			spdm_response.extend_error_data.token = 1;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		} else if (sub_index2 == 1) {
			spdm_capabilities_response spdm_response;

			zero_mem(&spdm_response, sizeof(spdm_response));
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code =
				SPDM_CAPABILITIES;
			spdm_response.header.param1 = 0;
			spdm_response.header.param2 = 0;
			spdm_response.ct_exponent = 0;
			spdm_response.flags = DEFAULT_CAPABILITY_FLAG;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		}
		sub_index2++;
	}
		return RETURN_SUCCESS;

	case 0xa: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
			 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
			 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
			 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
			 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0xb: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			!(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0xc: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0xd: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(
			spdm_context, NULL, FALSE, FALSE,
			sizeof(spdm_message_header_t), &spdm_response,
			response_size, response);
	}
		return RETURN_SUCCESS;

	case 0xe: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags = DEFAULT_CAPABILITY_FLAG;

		spdm_transport_test_encode_message(
			spdm_context, NULL, FALSE, FALSE,
			sizeof(spdm_response) + sizeof(uint8), &spdm_response,
			response_size, response);
	}
		return RETURN_DEVICE_ERROR;

	case 0xf: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags = DEFAULT_CAPABILITY_FLAG;

		spdm_transport_test_encode_message(
			spdm_context, NULL, FALSE, FALSE,
			sizeof(spdm_response) - sizeof(uint8), &spdm_response,
			response_size, response);
	}
		return RETURN_DEVICE_ERROR;

	case 0x10: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x11: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x12: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x13: {
		spdm_capabilities_response spdm_response;
		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));
		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x14: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x15: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x16: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x17: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x18: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x19: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
			(0xFFFFFFFF ^
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP));

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x1a: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 |
			SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x1b: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_response.header.request_response_code =
			SPDM_GET_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x1c: {
		spdm_capabilities_response spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = 0xFF;
		spdm_response.header.request_response_code = SPDM_CAPABILITIES;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.ct_exponent = 0;
		spdm_response.flags =
			DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

  case 0x1d:
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

void test_spdm_requester_get_capabilities_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	spdm_context->transcript.message_m.buffer_size =
						spdm_context->transcript.message_m.max_buffer_size;


	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->connection_info.capability.ct_exponent,
			 0);
	assert_int_equal(spdm_context->connection_info.capability.flags,
			 DEFAULT_CAPABILITY_FLAG);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

void test_spdm_requester_get_capabilities_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_UNSUPPORTED);
}

void test_spdm_requester_get_capabilities_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_NO_RESPONSE);
}

void test_spdm_requester_get_capabilities_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->connection_info.capability.ct_exponent,
			 0);
	assert_int_equal(spdm_context->connection_info.capability.flags,
			 DEFAULT_CAPABILITY_FLAG);
}

void test_spdm_requester_get_capabilities_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
}

void test_spdm_requester_get_capabilities_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//  assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//  assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_FLAG);
}

void test_spdm_requester_get_capabilities_case10(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xa;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->connection_info.capability.ct_exponent,
			 0);
	assert_int_equal(spdm_context->connection_info.capability.flags,
			 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
			  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP));
}

void test_spdm_requester_get_capabilities_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xb;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->connection_info.capability.ct_exponent,
			 0);
	assert_int_equal(
		spdm_context->connection_info.capability.flags,
		!(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
		  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
		  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
		  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
		  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP));
}

void test_spdm_requester_get_capabilities_case12(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xc;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->connection_info.capability.ct_exponent,
			 0);
	assert_int_equal(spdm_context->connection_info.capability.flags,
			 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);
}

void test_spdm_requester_get_capabilities_case13(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xd;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case14(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xe;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case15(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xf;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case16(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x10;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->connection_info.capability.ct_exponent,
			 0);
	assert_int_equal(spdm_context->connection_info.capability.flags,
			 DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11);
}

void test_spdm_requester_get_capabilities_case17(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x11;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void test_spdm_requester_get_capabilities_case18(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x12;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void test_spdm_requester_get_capabilities_case19(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x13;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void test_spdm_requester_get_capabilities_case20(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x14;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void test_spdm_requester_get_capabilities_case21(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x15;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void test_spdm_requester_get_capabilities_case22(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x16;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void test_spdm_requester_get_capabilities_case23(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x17;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)));
}

void test_spdm_requester_get_capabilities_case24(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x18;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)));
}

void test_spdm_requester_get_capabilities_case25(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x19;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)));
}

void test_spdm_requester_get_capabilities_case26(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1a;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
	//assert_int_equal (spdm_context->connection_info.capability.flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP);
}

void test_spdm_requester_get_capabilities_case27(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1b;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case28(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1c;
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	reset_managed_buffer(&spdm_context->transcript.message_a);

	spdm_context->local_context.capability.ct_exponent = 0;
	spdm_context->local_context.capability.flags =
		DEFAULT_CAPABILITY_FLAG_VERSION_11;
	status = spdm_get_capabilities(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_get_capabilities_case29(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uint16               error_code;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x1d;
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.capability.ct_exponent = 0;
  spdm_context->local_context.capability.flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;

  error_code = SPDM_ERROR_CODE_RESERVED_00;
  while(error_code <= 0xff) {
    spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_VERSION;
    reset_managed_buffer(&spdm_context->transcript.message_a);

    status = spdm_get_capabilities (spdm_context);
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
}

spdm_test_context_t m_spdm_requester_get_capabilities_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_get_capabilities_test_send_message,
	spdm_requester_get_capabilities_test_receive_message,
};

int spdm_requester_get_capabilities_test_main(void)
{
	const struct CMUnitTest m_spdm_requester_get_capabilities_tests[] = {
		// SendRequest failed
		cmocka_unit_test(test_spdm_requester_get_capabilities_case1),
		// Successful response
		cmocka_unit_test(test_spdm_requester_get_capabilities_case2),
		// connection_state check failed
		cmocka_unit_test(test_spdm_requester_get_capabilities_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(test_spdm_requester_get_capabilities_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(test_spdm_requester_get_capabilities_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(test_spdm_requester_get_capabilities_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(test_spdm_requester_get_capabilities_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		// CORRECTION for both case 8 and 9: A RESPONSE_NOT_READY is an invalid response for GET_CAPABILITIES
		// file spdm_requester_libHandleErrorResponse.c was corrected to reflect the documentation and now returns a RETURN_DEVICE_ERROR.
		cmocka_unit_test(test_spdm_requester_get_capabilities_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(test_spdm_requester_get_capabilities_case9),
		// All flags set in response
		cmocka_unit_test(test_spdm_requester_get_capabilities_case10),
		// All flags cleared in response
		cmocka_unit_test(test_spdm_requester_get_capabilities_case11),
		// meas_fresh_cap set, others cleared in response. This behaviour is undefined in the protocol
		cmocka_unit_test(test_spdm_requester_get_capabilities_case12),
		// Receives just header
		cmocka_unit_test(test_spdm_requester_get_capabilities_case13),
		// Receives a message 1 byte bigger than the capabilites response message
		cmocka_unit_test(test_spdm_requester_get_capabilities_case14),
		// Receives a message 1 byte smaller than the capabilites response message
		cmocka_unit_test(test_spdm_requester_get_capabilities_case15),
		// from this point forward, tests are performed with version 1.1
		// Requester sends all flags set and receives successful response with all flags set
		cmocka_unit_test(test_spdm_requester_get_capabilities_case16),
		// Requester sends all flags set and receives successful response with flags encrypt_cap and mac_cap set, and key_ex_cap and psk_cap cleared
		cmocka_unit_test(test_spdm_requester_get_capabilities_case17),
		// Requester sends all flags set and receives successful response with flags encrypt_cap set and mac_cap cleared, and key_ex_cap and psk_cap cleared
		cmocka_unit_test(test_spdm_requester_get_capabilities_case18),
		// Requester sends all flags set and receives successful response with flags encrypt_cap cleared and mac_cap set, and key_ex_cap and psk_cap cleared
		cmocka_unit_test(test_spdm_requester_get_capabilities_case19),
		// Requester sends all flags set and receives successful response with flags encrypt_cap cleared and mac_cap cleared, and key_ex_cap and psk_cap set
		cmocka_unit_test(test_spdm_requester_get_capabilities_case20),
		// Requester sends all flags set and receives successful response with flags encrypt_cap and mac_cap cleared, and key_ex_cap set and psk_cap cleared
		cmocka_unit_test(test_spdm_requester_get_capabilities_case21),
		// Requester sends all flags set and receives successful response with flags encrypt_cap and mac_cap cleared, and key_ex_cap cleared and psk_cap set
		cmocka_unit_test(test_spdm_requester_get_capabilities_case22),
		// Requester sends all flags set and receives successful response with flags mut_auth_cap set, and encap_cap cleared
		cmocka_unit_test(test_spdm_requester_get_capabilities_case23),
		// Requester sends all flags set and receives successful response with flags handshake_in_the_clear_cap set, and key_ex_cap cleared
		cmocka_unit_test(test_spdm_requester_get_capabilities_case24),
		// Requester sends all flags set and receives successful response with flags handshake_in_the_clear_cap set, and encrypt_cap and mac_cap cleared
		cmocka_unit_test(test_spdm_requester_get_capabilities_case25),
		// Requester sends all flags set and receives successful response with flags pub_key_id_cap set, and cert_cap set
		cmocka_unit_test(test_spdm_requester_get_capabilities_case26),
		// Requester sends all flags set and receives response with get_capabilities request code (wrong response code)
		cmocka_unit_test(test_spdm_requester_get_capabilities_case27),
		// Requester sends all flags set and receives response with 0xFF as version code (wrong version code)
		cmocka_unit_test(test_spdm_requester_get_capabilities_case28),
		// Unexpected errors
		cmocka_unit_test(test_spdm_requester_get_capabilities_case29),
	};

	setup_spdm_test_context(
		&m_spdm_requester_get_capabilities_test_context);

	return cmocka_run_group_tests(m_spdm_requester_get_capabilities_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
