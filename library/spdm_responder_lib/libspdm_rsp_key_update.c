/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"

/**
  Process the SPDM KEY_UPDATE request and return the response.

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
return_status spdm_get_response_key_update(IN void *context,
					   IN uintn request_size,
					   IN void *request,
					   IN OUT uintn *response_size,
					   OUT void *response)
{
	uint32 session_id;
	spdm_key_update_response_t *spdm_response;
	spdm_key_update_request_t *spdm_request;
	spdm_key_update_request_t *prev_spdm_request;
	spdm_context_t *spdm_context;
	spdm_session_info_t *session_info;
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
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
		libspdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_KEY_UPDATE, response_size, response);
		return RETURN_SUCCESS;
	}
	if (spdm_context->connection_info.connection_state <
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
					     0, response_size, response);
		return RETURN_SUCCESS;
	}

	if (!spdm_context->last_spdm_request_session_id_valid) {
		libspdm_generate_error_response(context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	session_id = spdm_context->last_spdm_request_session_id;
	session_info =
		spdm_get_session_info_via_session_id(spdm_context, session_id);
	if (session_info == NULL) {
		libspdm_generate_error_response(context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}
	session_state = spdm_secured_message_get_session_state(
		session_info->secured_message_context);
	if (session_state != SPDM_SESSION_STATE_ESTABLISHED) {
		libspdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	if (request_size != sizeof(spdm_key_update_request_t)) {
		libspdm_generate_error_response(context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	prev_spdm_request = (spdm_key_update_request_t *) 
		  spdm_context->last_update_request;

	if(spdm_request->header.param2 != prev_spdm_request->header.param2 ||
		  spdm_request->header.param1 != prev_spdm_request->header.param1) {
		switch (spdm_request->header.param1) {
		case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
			if(prev_spdm_request->header.param1 ==
				      SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY ||
				 prev_spdm_request->header.param1 ==
				      SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS) {
				libspdm_generate_error_response(context,
							     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
							     response_size, response);
				return RETURN_SUCCESS;
			}

			DEBUG((DEBUG_INFO,
			       "spdm_create_update_session_data_key[%x] Requester\n",
			       session_id));
			spdm_create_update_session_data_key(
				session_info->secured_message_context,
				SPDM_KEY_UPDATE_ACTION_REQUESTER);
			break;
		case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
			if(prev_spdm_request->header.param1 ==
				      SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY ||
				 prev_spdm_request->header.param1 ==
				      SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS) {
				libspdm_generate_error_response(context,
							     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
							     response_size, response);
				return RETURN_SUCCESS;
			}

			DEBUG((DEBUG_INFO,
			       "spdm_create_update_session_data_key[%x] Requester\n",
			       session_id));
			spdm_create_update_session_data_key(
				session_info->secured_message_context,
				SPDM_KEY_UPDATE_ACTION_REQUESTER);
			DEBUG((DEBUG_INFO,
			       "spdm_create_update_session_data_key[%x] Responder\n",
			       session_id));
			spdm_create_update_session_data_key(
				session_info->secured_message_context,
				SPDM_KEY_UPDATE_ACTION_RESPONDER);

			DEBUG((DEBUG_INFO,
			       "spdm_activate_update_session_data_key[%x] Responder new\n",
			       session_id));
			spdm_activate_update_session_data_key(
				session_info->secured_message_context,
				SPDM_KEY_UPDATE_ACTION_RESPONDER, TRUE);
			break;
		case SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY:
			if(prev_spdm_request->header.param1 !=
				      SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY &&
				prev_spdm_request->header.param1 !=
				      SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS) {
				libspdm_generate_error_response(context,
							     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
							     response_size, response);
				return RETURN_SUCCESS;
			}
			DEBUG((DEBUG_INFO,
			       "spdm_activate_update_session_data_key[%x] Requester new\n",
			       session_id));
			spdm_activate_update_session_data_key(
				session_info->secured_message_context,
				SPDM_KEY_UPDATE_ACTION_REQUESTER, TRUE);
			break;
		default:
			DEBUG((DEBUG_INFO, "espurious case\n"));
			libspdm_generate_error_response(context,
						     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
						     response_size, response);
			return RETURN_SUCCESS;
		}
	}

	copy_mem(prev_spdm_request, spdm_request, request_size);

	spdm_reset_message_buffer_via_request_code(spdm_context, session_info,
						spdm_request->header.request_response_code);

	ASSERT(*response_size >= sizeof(spdm_key_update_response_t));
	*response_size = sizeof(spdm_key_update_response_t);
	zero_mem(response, *response_size);
	spdm_response = response;

	spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_response->header.request_response_code = SPDM_KEY_UPDATE_ACK;
	spdm_response->header.param1 = spdm_request->header.param1;
	spdm_response->header.param2 = spdm_request->header.param2;

	return RETURN_SUCCESS;
}
