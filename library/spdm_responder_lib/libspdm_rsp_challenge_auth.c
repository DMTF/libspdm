/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"


#if SPDM_ENABLE_CAPABILITY_CHAL_CAP

/**
  Process the SPDM CHALLENGE request and return the response.

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
return_status spdm_get_response_challenge_auth(IN void *context,
					       IN uintn request_size,
					       IN void *request,
					       IN OUT uintn *response_size,
					       OUT void *response)
{
	spdm_challenge_request_t *spdm_request;
	uintn spdm_request_size;
	spdm_challenge_auth_response_t *spdm_response;
	boolean result;
	uintn signature_size;
	uint8 slot_id;
	uint32 hash_size;
	uint32 measurement_summary_hash_size;
	uint8 *ptr;
	uintn total_size;
	spdm_context_t *spdm_context;
	spdm_challenge_auth_response_attribute_t auth_attribute;
	return_status status;

	spdm_context = context;
	spdm_request = request;

	if (spdm_context->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		return spdm_responder_handle_response_state(
			spdm_context,
			spdm_request->header.request_response_code,
			response_size, response);
	}
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
		return libspdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_CHALLENGE, response_size, response);
	}
	if (spdm_context->connection_info.connection_state <
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		return libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
					     0, response_size, response);
	}

	if (request_size != sizeof(spdm_challenge_request_t)) {
		return libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
	}
	if (!spdm_is_capabilities_flag_supported(spdm_context, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) &&
		spdm_request->header.param2 > 0) {
		return libspdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHALLENGE, response_size, response);
	}

	spdm_request_size = request_size;

	slot_id = spdm_request->header.param1;

	if ((slot_id != 0xFF) &&
	    (slot_id >= spdm_context->local_context.slot_count)) {
		return libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
	}

	signature_size = spdm_get_asym_signature_size(
		spdm_context->connection_info.algorithm.base_asym_algo);
	hash_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	measurement_summary_hash_size = spdm_get_measurement_summary_hash_size(
		spdm_context, FALSE, spdm_request->header.param2);
	if ((measurement_summary_hash_size == 0) &&
		(spdm_request->header.param2 != SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH)) {
		return libspdm_generate_error_response(spdm_context,
						SPDM_ERROR_CODE_INVALID_REQUEST,
						0, response_size, response);
	}
	total_size =
		sizeof(spdm_challenge_auth_response_t) + hash_size +
		SPDM_NONCE_SIZE + measurement_summary_hash_size +
		sizeof(uint16) +
		spdm_context->local_context.opaque_challenge_auth_rsp_size +
		signature_size;

	ASSERT(*response_size >= total_size);
	*response_size = total_size;
	zero_mem(response, *response_size);
	spdm_response = response;

	if (spdm_request->header.spdm_version == SPDM_MESSAGE_VERSION_11 &&
		spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	} else if (spdm_request->header.spdm_version == SPDM_MESSAGE_VERSION_10 &&
		spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_10)) {
		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
	} else {
		return libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
	}

	spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
						spdm_request->header.request_response_code);

	spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
	auth_attribute.slot_id = (uint8)(slot_id & 0xF);
	auth_attribute.reserved = 0;
	auth_attribute.basic_mut_auth_req = 0;
	if (spdm_request->header.spdm_version == SPDM_MESSAGE_VERSION_11) {
		if (spdm_is_capabilities_flag_supported(
			    spdm_context, FALSE,
			    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
			    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) &&
		    spdm_is_capabilities_flag_supported(
			    spdm_context, FALSE,
			    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0) &&
		    (spdm_is_capabilities_flag_supported(
			     spdm_context, FALSE,
			     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0) ||
		     spdm_is_capabilities_flag_supported(
			     spdm_context, FALSE,
			     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0))) {
			auth_attribute.basic_mut_auth_req =
				spdm_context->local_context.basic_mut_auth_requested;
		}
		if (auth_attribute.basic_mut_auth_req != 0) {
			spdm_init_basic_mut_auth_encap_state(
				context, auth_attribute.basic_mut_auth_req);
		}
	}

	spdm_response->header.param1 = *(uint8 *)&auth_attribute;
	spdm_response->header.param2 = (1 << slot_id);
	if (slot_id == 0xFF) {
		spdm_response->header.param2 = 0;

		slot_id = spdm_context->local_context.provisioned_slot_id;
	}

	ptr = (void *)(spdm_response + 1);
	spdm_generate_cert_chain_hash(spdm_context, slot_id, ptr);
	ptr += hash_size;

	spdm_get_random_number(SPDM_NONCE_SIZE, ptr);
	ptr += SPDM_NONCE_SIZE;

	result = spdm_generate_measurement_summary_hash(
		spdm_context, FALSE, spdm_request->header.param2, ptr);
	if (!result) {
		return libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNSPECIFIED, 0,
					     response_size, response);
	}
	ptr += measurement_summary_hash_size;

	*(uint16 *)ptr = (uint16)spdm_context->local_context
				 .opaque_challenge_auth_rsp_size;
	ptr += sizeof(uint16);
	copy_mem(ptr, spdm_context->local_context.opaque_challenge_auth_rsp,
		 spdm_context->local_context.opaque_challenge_auth_rsp_size);
	ptr += spdm_context->local_context.opaque_challenge_auth_rsp_size;

	//
	// Calc Sign
	//
	status = spdm_append_message_c(spdm_context, spdm_request,
				       spdm_request_size);
	if (RETURN_ERROR(status)) {
		libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNSPECIFIED, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	status = spdm_append_message_c(spdm_context, spdm_response,
				       (uintn)ptr - (uintn)spdm_response);
	if (RETURN_ERROR(status)) {
		spdm_reset_message_c(spdm_context);
		return libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNSPECIFIED, 0,
					     response_size, response);
	}
	result = spdm_generate_challenge_auth_signature(spdm_context, FALSE,
							ptr);
	if (!result) {
		spdm_reset_message_c(spdm_context);
		return libspdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
			0, response_size, response);
	}
	ptr += signature_size;

	if (auth_attribute.basic_mut_auth_req == 0) {
		spdm_set_connection_state(spdm_context,
					  SPDM_CONNECTION_STATE_AUTHENTICATED);
	}

	return RETURN_SUCCESS;
}

#endif // SPDM_ENABLE_CAPABILITY_CHAL_CAP