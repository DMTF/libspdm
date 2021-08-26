/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_responder_lib_internal.h"

#pragma pack(1)
typedef struct {
	spdm_message_header_t header;
	uint8 reserved;
	uint8 version_number_entry_count;
	spdm_version_number_t version_number_entry[MAX_SPDM_VERSION_COUNT];
} spdm_version_response_mine_t;
#pragma pack()

/**
  Process the SPDM GET_VERSION request and return the response.

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
return_status spdm_get_response_version(IN void *context, IN uintn request_size,
					IN void *request,
					IN OUT uintn *response_size,
					OUT void *response)
{
	spdm_get_version_request_t *spdm_request;
	uintn spdm_request_size;
	spdm_version_response_mine_t *spdm_response;
	spdm_context_t *spdm_context;
	return_status status;

	spdm_context = context;
	spdm_request = request;

	spdm_set_connection_state(spdm_context,
				  SPDM_CONNECTION_STATE_NOT_STARTED);

	if (spdm_request->header.spdm_version != SPDM_MESSAGE_VERSION_10) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	if (request_size != sizeof(spdm_get_version_request_t)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	if ((spdm_context->response_state == SPDM_RESPONSE_STATE_NEED_RESYNC) ||
	    (spdm_context->response_state ==
	     SPDM_RESPONSE_STATE_PROCESSING_ENCAP)) {
		// receiving a GET_VERSION resets a need to resynchronization
		spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	}
	if (spdm_context->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		return spdm_responder_handle_response_state(
			spdm_context,
			spdm_request->header.request_response_code,
			response_size, response);
	}
	spdm_request_size = request_size;

	spdm_reset_message_buffer_via_request_code(spdm_context,
						spdm_request->header.request_response_code);

	//
	// Cache
	//
	reset_managed_buffer(&spdm_context->transcript.message_a);
	reset_managed_buffer(&spdm_context->transcript.message_b);
	reset_managed_buffer(&spdm_context->transcript.message_c);
	status = spdm_append_message_a(spdm_context, spdm_request,
				       spdm_request_size);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNSPECIFIED, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	spdm_reset_context(spdm_context);

	ASSERT(*response_size >= sizeof(spdm_version_response_mine_t));
	*response_size =
		sizeof(spdm_version_response) +
		spdm_context->local_context.version.spdm_version_count *
			sizeof(spdm_version_number_t);
	zero_mem(response, *response_size);
	spdm_response = response;

	spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
	spdm_response->header.request_response_code = SPDM_VERSION;
	spdm_response->header.param1 = 0;
	spdm_response->header.param2 = 0;
	spdm_response->version_number_entry_count =
		spdm_context->local_context.version.spdm_version_count;
	copy_mem(
		spdm_response->version_number_entry,
		spdm_context->local_context.version.spdm_version,
		sizeof(spdm_version_number_t) *
			spdm_context->local_context.version.spdm_version_count);

	//
	// Cache
	//
	status = spdm_append_message_a(spdm_context, spdm_response,
				       *response_size);
	if (RETURN_ERROR(status)) {
		reset_managed_buffer(&spdm_context->transcript.message_a);
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNSPECIFIED, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	spdm_set_connection_state(spdm_context,
				  SPDM_CONNECTION_STATE_AFTER_VERSION);

	return RETURN_SUCCESS;
}
