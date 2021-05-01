/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"
#include <stdio.h>

/**
  This function checks the compability of the received CAPABILITES flag.
  Some flags are mutually inclusive/exclusive.

  @param  capabilities_flag             The received CAPABILITIES Flag.
  @param  version                      The SPMD message version.


  @retval True                         The received Capabilities flag is valid.
  @retval False                        The received Capabilities flag is invalid.
**/
boolean spdm_check_response_flag_compability(IN uint32 capabilities_flag,
					     IN uint8 version)
{
	//uint8 cache_cap = (uint8)(capabilities_flag)&0x01;
	uint8 cert_cap = (uint8)(capabilities_flag >> 1) & 0x01;
	//uint8 chal_cap = (uint8)(capabilities_flag>>2)&0x01;
	uint8 meas_cap = (uint8)(capabilities_flag >> 3) & 0x03;
	//uint8 meas_fresh_cap = (uint8)(capabilities_flag>>5)&0x01;
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
		if (meas_cap == 3 || psk_cap == 3) {
			return FALSE;
		}
	}
		return TRUE;

	default:
		return TRUE;
	}
}

/**
  This function sends GET_CAPABILITIES and receives CAPABILITIES.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_CAPABILITIES is sent and the CAPABILITIES is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_get_capabilities(IN spdm_context_t *spdm_context)
{
	return_status status;
	spdm_get_capabilities_request spdm_request;
	uintn spdm_request_size;
	spdm_capabilities_response spdm_response;
	uintn spdm_response_size;

	if (spdm_context->connection_info.connection_state !=
	    SPDM_CONNECTION_STATE_AFTER_VERSION) {
		return RETURN_UNSUPPORTED;
	}

	zero_mem(&spdm_request, sizeof(spdm_request));
	if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
		spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_request_size = sizeof(spdm_request);
	} else {
		spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_request_size = sizeof(spdm_request.header);
	}
	spdm_request.header.request_response_code = SPDM_GET_CAPABILITIES;
	spdm_request.header.param1 = 0;
	spdm_request.header.param2 = 0;
	spdm_request.ct_exponent =
		spdm_context->local_context.capability.ct_exponent;
	spdm_request.flags = spdm_context->local_context.capability.flags;
	status = spdm_send_spdm_request(spdm_context, NULL, spdm_request_size,
					&spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}

	//
	// Cache data
	//
	status = spdm_append_message_a(spdm_context, &spdm_request,
				       spdm_request_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_response_size = sizeof(spdm_response);
	zero_mem(&spdm_response, sizeof(spdm_response));
	status = spdm_receive_spdm_response(
		spdm_context, NULL, &spdm_response_size, &spdm_response);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_message_header_t)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.header.request_response_code == SPDM_ERROR) {
		shrink_managed_buffer(&spdm_context->transcript.message_a,
				      spdm_request_size);
		status = spdm_handle_simple_error_response(
			spdm_context, spdm_response.header.param1);
		if (RETURN_ERROR(status)) {
			return status;
		}
	} else if (spdm_response.header.request_response_code !=
		   SPDM_CAPABILITIES) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_capabilities_response)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size > sizeof(spdm_response)) {
		return RETURN_DEVICE_ERROR;
	}
	//Check if received message version matches sent message version
	if (spdm_request.header.spdm_version !=
	    spdm_response.header.spdm_version) {
		return RETURN_DEVICE_ERROR;
	}
	spdm_response_size = sizeof(spdm_capabilities_response);

	if (!spdm_check_response_flag_compability(
		    spdm_response.flags, spdm_response.header.spdm_version)) {
		return RETURN_DEVICE_ERROR;
	}

	//
	// Cache data
	//
	status = spdm_append_message_a(spdm_context, &spdm_response,
				       spdm_response_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_context->connection_info.capability.ct_exponent =
		spdm_response.ct_exponent;
	spdm_context->connection_info.capability.flags = spdm_response.flags;

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

	return RETURN_SUCCESS;
}

/**
  This function sends GET_CAPABILITIES and receives CAPABILITIES.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_CAPABILITIES is sent and the CAPABILITIES is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_get_capabilities(IN spdm_context_t *spdm_context)
{
	uintn retry;
	return_status status;

	retry = spdm_context->retry_times;
	do {
		status = try_spdm_get_capabilities(spdm_context);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}
