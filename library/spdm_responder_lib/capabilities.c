/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_responder_lib_internal.h"

/**
  This function checks the compability of the received CAPABILITES flag.
  Some flags are mutually inclusive/exclusive.

  @param  capabilities_flag             The received CAPABILITIES Flag.
  @param  version                      The SPMD message version.


  @retval True                         The received Capabilities flag is valid.
  @retval False                        The received Capabilities flag is invalid.
**/
boolean spdm_check_request_flag_compability(IN uint32 capabilities_flag,
					    IN uint8 version)
{
	uint8 cert_cap = (uint8)(capabilities_flag >> 1) & 0x01;
	//uint8 chal_cap = (uint8)(capabilities_flag>>2)&0x01;
	uint8 meas_cap = (uint8)(capabilities_flag >> 3) & 0x03;
	uint8 meas_fresh_cap = (uint8)(capabilities_flag >> 5) & 0x01;
	uint8 encrypt_cap = (uint8)(capabilities_flag >> 6) & 0x01;
	uint8 mac_cap = (uint8)(capabilities_flag >> 7) & 0x01;
	uint8 mut_auth_cap = (uint8)(capabilities_flag >> 8) & 0x01;
	uint8 key_ex_cap = (uint8)(capabilities_flag >> 9) & 0x01;
	uint8 psk_cap = (uint8)(capabilities_flag >> 10) & 0x03;
	uint8 encap_cap = (uint8)(capabilities_flag >> 12) & 0x01;
	//uint8 hbeat_cap = (uint8)(capabilities_flag>>13)&0x01;
	//uint8 key_upd_cap = (uint8)(capabilities_flag>>14)&0x01;
	uint8 handshake_in_the_clear_cap =
		(uint8)(capabilities_flag >> 15) & 0x01;
	uint8 pub_key_id_cap = (uint8)(capabilities_flag >> 16) & 0x01;

	switch (version) {
	case SPDM_MESSAGE_VERSION_10:
		return TRUE;

	case SPDM_MESSAGE_VERSION_11: {
		//meas_cap shall be set to 00b
		if (meas_cap != 0) {
			return FALSE;
		}
		//meas_fresh_cap shall be set to 0b
		if (meas_fresh_cap != 0) {
			return FALSE;
		}
		//Encrypt_cap set and psk_cap+key_ex_cap cleared
		if (encrypt_cap != 0 && (psk_cap == 0 && key_ex_cap == 0)) {
			return FALSE;
		}
		//MAC_cap set and psk_cap+key_ex_cap cleared
		if (mac_cap != 0 && (psk_cap == 0 && key_ex_cap == 0)) {
			return FALSE;
		}
		//Key_ex_cap set and encrypt_cap+mac_cap cleared
		if (key_ex_cap != 0 && (encrypt_cap == 0 && mac_cap == 0)) {
			return FALSE;
		}
		//PSK_cap set and encrypt_cap+mac_cap cleared
		if (psk_cap != 0 && (encrypt_cap == 0 && mac_cap == 0)) {
			return FALSE;
		}
		//Muth_auth_cap set and encap_cap cleared
		if (mut_auth_cap != 0 && encap_cap == 0) {
			return FALSE;
		}
		//Handshake_in_the_clear_cap set and key_ex_cap cleared
		if (handshake_in_the_clear_cap != 0 && key_ex_cap == 0) {
			return FALSE;
		}
		//Handshake_in_the_clear_cap set and encrypt_cap+mac_cap cleared
		if ((encrypt_cap == 0 && mac_cap == 0) &&
		    handshake_in_the_clear_cap != 0) {
			return FALSE;
		}
		//Pub_key_id_cap set and cert_cap set
		if (pub_key_id_cap != 0 && cert_cap != 0) {
			return FALSE;
		}
		//reserved values selected in flags
		if (psk_cap == 2 || psk_cap == 3) {
			return FALSE;
		}
	}
		return TRUE;

	default:
		return TRUE;
	}
}

/**
  Process the SPDM GET_CAPABILITIES request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_capabilities(IN void *context,
					     IN uintn request_size,
					     IN void *request,
					     IN OUT uintn *response_size,
					     OUT void *response)
{
	spdm_get_capabilities_request *spdm_request;
	uintn spdm_request_size;
	spdm_capabilities_response *spdm_response;
	spdm_context_t *spdm_context;
	return_status status;

	spdm_context = context;
	spdm_request = request;

	if (spdm_context->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		return spdm_responder_handle_response_state(
			spdm_context,
			spdm_request->header.request_response_code,
			response_size, response);
	}
	if (spdm_context->connection_info.connection_state !=
	    SPDM_CONNECTION_STATE_AFTER_VERSION) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
					     0, response_size, response);
		return RETURN_SUCCESS;
	}

	if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
		if (request_size != sizeof(spdm_get_capabilities_request)) {
			spdm_generate_error_response(
				spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
				0, response_size, response);
			return RETURN_SUCCESS;
		}
	} else {
		if (request_size != sizeof(spdm_message_header_t)) {
			spdm_generate_error_response(
				spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
				0, response_size, response);
			return RETURN_SUCCESS;
		}
	}

	if (!spdm_check_request_flag_compability(
		    spdm_request->flags, spdm_request->header.spdm_version)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	spdm_request_size = request_size;

	ASSERT(*response_size >= sizeof(spdm_capabilities_response));
	*response_size = sizeof(spdm_capabilities_response);
	zero_mem(response, *response_size);
	spdm_response = response;

	if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	} else {
		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
	}
	spdm_response->header.request_response_code = SPDM_CAPABILITIES;
	spdm_response->header.param1 = 0;
	spdm_response->header.param2 = 0;
	spdm_response->ct_exponent =
		spdm_context->local_context.capability.ct_exponent;
	spdm_response->flags = spdm_context->local_context.capability.flags;
	//
	// Cache
	//
	status = append_managed_buffer(&spdm_context->transcript.message_a, spdm_request,
			      spdm_request_size);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
						SPDM_ERROR_CODE_UNSPECIFIED, 0,
						response_size, response);
		return RETURN_SUCCESS;
	}
	status = append_managed_buffer(&spdm_context->transcript.message_a,
			      spdm_response, *response_size);

	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
						SPDM_ERROR_CODE_UNSPECIFIED, 0,
						response_size, response);
		return RETURN_SUCCESS;
	}
	if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
		spdm_context->connection_info.capability.ct_exponent =
			spdm_request->ct_exponent;
		spdm_context->connection_info.capability.flags =
			spdm_request->flags;
	} else {
		spdm_context->connection_info.capability.ct_exponent = 0;
		spdm_context->connection_info.capability.flags = 0;
	}
	spdm_set_connection_state(spdm_context,
				  SPDM_CONNECTION_STATE_AFTER_CAPABILITIES);

	return RETURN_SUCCESS;
}
