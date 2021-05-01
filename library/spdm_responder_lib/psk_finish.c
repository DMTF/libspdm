/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_responder_lib_internal.h"

/**
  Process the SPDM PSK_FINISH request and return the response.

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
return_status spdm_get_response_psk_finish(IN void *context,
					   IN uintn request_size,
					   IN void *request,
					   IN OUT uintn *response_size,
					   OUT void *response)
{
	uint32 session_id;
	boolean result;
	uint32 hmac_size;
	spdm_psk_finish_response_t *spdm_response;
	spdm_context_t *spdm_context;
	spdm_session_info_t *session_info;
	uint8 th2_hash_data[64];
	spdm_psk_finish_request_t *spdm_request;
	return_status status;
	spdm_session_state_t session_state;

	spdm_context = context;
	spdm_request = request;

	if (spdm_context->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		return spdm_responder_handle_response_state(
			spdm_context,
			spdm_request->header.request_response_code,
			response_size, response);
	}
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_PSK_EXCHANGE, response_size, response);
		return RETURN_SUCCESS;
	}
	if (spdm_context->connection_info.connection_state <
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
					     0, response_size, response);
		return RETURN_SUCCESS;
	}

	if (!spdm_context->last_spdm_request_session_id_valid) {
		spdm_generate_error_response(context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	session_id = spdm_context->last_spdm_request_session_id;
	session_info =
		spdm_get_session_info_via_session_id(spdm_context, session_id);
	if (session_info == NULL) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	session_state = spdm_secured_message_get_session_state(
		session_info->secured_message_context);
	if (session_state != SPDM_SESSION_STATE_HANDSHAKING) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	// remove HMAC
	hmac_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.bash_hash_algo);

	if (request_size != sizeof(spdm_psk_finish_request_t) + hmac_size) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	status = spdm_append_message_f(session_info, request,
				       request_size - hmac_size);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	ASSERT(*response_size >= sizeof(spdm_psk_finish_response_t));
	*response_size = sizeof(spdm_psk_finish_response_t);
	zero_mem(response, *response_size);
	spdm_response = response;

	spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_response->header.request_response_code = SPDM_PSK_FINISH_RSP;
	spdm_response->header.param1 = 0;
	spdm_response->header.param2 = 0;

	result = spdm_verify_psk_finish_req_hmac(
		spdm_context, session_info,
		(uint8 *)request + sizeof(spdm_psk_finish_request_t),
		hmac_size);
	if (!result) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	status = spdm_append_message_f(
		session_info, (uint8 *)request + request_size - hmac_size,
		hmac_size);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	status = spdm_append_message_f(session_info, spdm_response,
				       *response_size);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	DEBUG((DEBUG_INFO, "spdm_generate_session_data_key[%x]\n", session_id));
	status = spdm_calculate_th2_hash(spdm_context, session_info, FALSE,
					 th2_hash_data);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	status = spdm_generate_session_data_key(
		session_info->secured_message_context, th2_hash_data);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	return RETURN_SUCCESS;
}
