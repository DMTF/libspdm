/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/
#include "spdm_responder_lib_internal.h"

/**
  Process the SPDM GET_CERTIFICATE request and return the response.

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
return_status spdm_get_response_certificate(IN void *context,
					    IN uintn request_size,
					    IN void *request,
					    IN OUT uintn *response_size,
					    OUT void *response)
{
	spdm_get_certificate_request_t *spdm_request;
	uintn spdm_request_size;
	spdm_certificate_response_t *spdm_response;
	uint16 offset;
	uint16 length;
	uintn remainder_length;
	uint8 slot_id;
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
	if ((spdm_context->connection_info.connection_state !=
	     SPDM_CONNECTION_STATE_NEGOTIATED) &&
	    (spdm_context->connection_info.connection_state !=
	     SPDM_CONNECTION_STATE_AFTER_DIGESTS) &&
	    (spdm_context->connection_info.connection_state !=
	     SPDM_CONNECTION_STATE_AFTER_CERTIFICATE)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
					     0, response_size, response);
		return RETURN_SUCCESS;
	}
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_GET_CERTIFICATE, response_size, response);
		return RETURN_SUCCESS;
	}

	if (request_size != sizeof(spdm_get_certificate_request_t)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	spdm_request_size = request_size;

	if (spdm_context->local_context.local_cert_chain_provision == NULL) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_GET_CERTIFICATE, response_size, response);
		return RETURN_SUCCESS;
	}

	slot_id = spdm_request->header.param1;

	if (slot_id >= spdm_context->local_context.slot_count) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	offset = spdm_request->offset;
	length = spdm_request->length;
	if (length > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
		length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	}

	if (offset >= spdm_context->local_context
			      .local_cert_chain_provision_size[slot_id]) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	if ((uintn)(offset + length) >
	    spdm_context->local_context
		    .local_cert_chain_provision_size[slot_id]) {
		length = (uint16)(
			spdm_context->local_context
				.local_cert_chain_provision_size[slot_id] -
			offset);
	}
	remainder_length = spdm_context->local_context
				   .local_cert_chain_provision_size[slot_id] -
			   (length + offset);

	ASSERT(*response_size >= sizeof(spdm_certificate_response_t) + length);
	*response_size = sizeof(spdm_certificate_response_t) + length;
	zero_mem(response, *response_size);
	spdm_response = response;

	if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	} else {
		spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
	}
	spdm_response->header.request_response_code = SPDM_CERTIFICATE;
	spdm_response->header.param1 = slot_id;
	spdm_response->header.param2 = 0;
	spdm_response->portion_length = length;
	spdm_response->remainder_length = (uint16)remainder_length;
	copy_mem(spdm_response + 1,
		 (uint8 *)spdm_context->local_context
				 .local_cert_chain_provision[slot_id] +
			 offset,
		 length);
	//
	// Cache
	//
	status = spdm_append_message_b(spdm_context, spdm_request,
				       spdm_request_size);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	status = spdm_append_message_b(spdm_context, spdm_response,
				       *response_size);
	if (RETURN_ERROR(status)) {
		shrink_managed_buffer(&spdm_context->transcript.message_b,
						 spdm_request_size);
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	spdm_set_connection_state(spdm_context,
				  SPDM_CONNECTION_STATE_AFTER_CERTIFICATE);

	return RETURN_SUCCESS;
}
