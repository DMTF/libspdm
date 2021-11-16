/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)

typedef struct {
	spdm_message_header_t header;
	uint8_t dummy_data[sizeof(spdm_error_data_response_not_ready_t)];
} spdm_key_update_response_mine_t;

#pragma pack()

/**
  This function sends KEY_UPDATE
  to update keys for an SPDM Session.

  After keys are updated, this function also uses VERIFY_NEW_KEY to verify the key.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    The session ID of the session.
  @param  single_direction              TRUE means the operation is UPDATE_KEY.
                                       FALSE means the operation is UPDATE_ALL_KEYS.
  @param  key_updated                   TRUE means the operation is to verify key(s).
                                       FALSE means the operation is to update and verify key(s).

  @retval RETURN_SUCCESS               The keys of the session are updated.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status try_spdm_key_update(IN void *context, IN uint32_t session_id,
			      IN boolean single_direction, IN OUT boolean *key_updated)
{
	return_status status;
	spdm_key_update_request_t spdm_request;
	spdm_key_update_response_mine_t spdm_response;
	uintn spdm_response_size;
	spdm_key_update_action_t action;
	spdm_context_t *spdm_context;
	spdm_session_info_t *session_info;
	spdm_session_state_t session_state;

	spdm_context = context;
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
		return RETURN_UNSUPPORTED;
	}

	if (spdm_context->connection_info.connection_state <
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		return RETURN_UNSUPPORTED;
	}
	session_info =
		libspdm_get_session_info_via_session_id(spdm_context, session_id);
	if (session_info == NULL) {
		ASSERT(FALSE);
		return RETURN_UNSUPPORTED;
	}
	session_state = spdm_secured_message_get_session_state(
		session_info->secured_message_context);
	if (session_state != SPDM_SESSION_STATE_ESTABLISHED) {
		return RETURN_UNSUPPORTED;
	}

	if (single_direction) {
		action = SPDM_KEY_UPDATE_ACTION_REQUESTER;
	} else {
		action = SPDM_KEY_UPDATE_ACTION_ALL;
	}

	spdm_reset_message_buffer_via_request_code(spdm_context, session_info,
										SPDM_KEY_UPDATE);

	if(!(*key_updated)) {
		//
		// Update key
		//
		spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
		if (single_direction) {
			spdm_request.header.param1 =
				SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
		} else {
			spdm_request.header.param1 =
				SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
		}
		spdm_request.header.param2 = 0;
		spdm_get_random_number(sizeof(spdm_request.header.param2),
				       &spdm_request.header.param2);

		// Create new key
		if ((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) {
			DEBUG((DEBUG_INFO,
			       "spdm_create_update_session_data_key[%x] Responder\n",
			       session_id));
			spdm_create_update_session_data_key(
				session_info->secured_message_context,
				SPDM_KEY_UPDATE_ACTION_RESPONDER);
		}

		status = spdm_send_spdm_request(spdm_context, &session_id,
						sizeof(spdm_request), &spdm_request);
		if (RETURN_ERROR(status)) {
			return RETURN_DEVICE_ERROR;
		}

		spdm_response_size = sizeof(spdm_response);
		zero_mem(&spdm_response, sizeof(spdm_response));
		status = spdm_receive_spdm_response(
			spdm_context, &session_id, &spdm_response_size, &spdm_response);

		if (RETURN_ERROR(status) || 
		    spdm_response_size < sizeof(spdm_message_header_t)) {
			if ((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) {
				DEBUG((DEBUG_INFO,
				       "spdm_activate_update_session_data_key[%x] Responder old\n",
				       session_id));
				spdm_activate_update_session_data_key(
					session_info->secured_message_context,
					SPDM_KEY_UPDATE_ACTION_RESPONDER, FALSE);
			}
			return RETURN_DEVICE_ERROR;
		}

		if (spdm_response.header.request_response_code == SPDM_ERROR) {
			status = spdm_handle_error_response_main(
				spdm_context, &session_id,
				&spdm_response_size, &spdm_response,
				SPDM_KEY_UPDATE, SPDM_KEY_UPDATE_ACK,
				sizeof(spdm_key_update_response_mine_t));
			if (RETURN_ERROR(status)) {
				if ((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) {
					DEBUG((DEBUG_INFO,
					       "spdm_activate_update_session_data_key[%x] Responder old\n",
					       session_id));
					spdm_activate_update_session_data_key(
						session_info->secured_message_context,
						SPDM_KEY_UPDATE_ACTION_RESPONDER, FALSE);
				}
				return status;
			}
		}

		if ((spdm_response.header.request_response_code != 
		    SPDM_KEY_UPDATE_ACK) ||
		    (spdm_response.header.param1 != spdm_request.header.param1) ||
		    (spdm_response.header.param2 != spdm_request.header.param2)) {
			if ((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) {
				DEBUG((DEBUG_INFO,
				       "spdm_activate_update_session_data_key[%x] Responder old\n",
				       session_id));
				spdm_activate_update_session_data_key(
					session_info->secured_message_context,
					SPDM_KEY_UPDATE_ACTION_RESPONDER, FALSE);
			}
			return RETURN_DEVICE_ERROR;
		}

		if ((action & SPDM_KEY_UPDATE_ACTION_RESPONDER) != 0) {
			DEBUG((DEBUG_INFO,
			       "spdm_activate_update_session_data_key[%x] Responder new\n",
			       session_id, SPDM_KEY_UPDATE_ACTION_RESPONDER));
			spdm_activate_update_session_data_key(
				session_info->secured_message_context,
				SPDM_KEY_UPDATE_ACTION_RESPONDER, TRUE);
		}

		DEBUG((DEBUG_INFO,
		       "spdm_create_update_session_data_key[%x] Requester\n",
		       session_id));
		spdm_create_update_session_data_key(
			session_info->secured_message_context,
			SPDM_KEY_UPDATE_ACTION_REQUESTER);
		DEBUG((DEBUG_INFO,
		       "spdm_activate_update_session_data_key[%x] Requester new\n",
		       session_id));
		spdm_activate_update_session_data_key(
			session_info->secured_message_context,
			SPDM_KEY_UPDATE_ACTION_REQUESTER, TRUE);
	}

	*key_updated = TRUE;

	//
	// Verify key
	//
	spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
	spdm_request.header.param1 =
		SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
	spdm_request.header.param2 = 1;
	spdm_get_random_number(sizeof(spdm_request.header.param2),
			       &spdm_request.header.param2);

	status = spdm_send_spdm_request(spdm_context, &session_id,
					sizeof(spdm_request), &spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}

	spdm_response_size = sizeof(spdm_response);
	zero_mem(&spdm_response, sizeof(spdm_response));
	status = spdm_receive_spdm_response(
		spdm_context, &session_id, &spdm_response_size, &spdm_response);

	if (RETURN_ERROR(status) || 
	    spdm_response_size < sizeof(spdm_message_header_t)) {
		DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Failed\n", session_id));
		return RETURN_DEVICE_ERROR;
	}

	if (spdm_response.header.request_response_code == SPDM_ERROR) {
		status = spdm_handle_error_response_main(
			spdm_context, &session_id,
			&spdm_response_size, &spdm_response,
			SPDM_KEY_UPDATE, SPDM_KEY_UPDATE_ACK,
			sizeof(spdm_key_update_response_mine_t));
		if (RETURN_ERROR(status)) {
			DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Failed\n", session_id));
			return status;
		}
	}

	if ((spdm_response.header.request_response_code != 
	    SPDM_KEY_UPDATE_ACK) ||
	    (spdm_response.header.param1 != spdm_request.header.param1) ||
	    (spdm_response.header.param2 != spdm_request.header.param2)) {
		DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Failed\n", session_id));
		return RETURN_DEVICE_ERROR;
	}
	DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Success\n", session_id));

	return RETURN_SUCCESS;
}

return_status libspdm_key_update(IN void *context, IN uint32_t session_id,
			      IN boolean single_direction)
{
	spdm_context_t *spdm_context;
	uintn retry;
	return_status status;
	boolean key_updated;

	spdm_context = context;
	key_updated = FALSE;
	retry = spdm_context->retry_times;
	do {
		status = try_spdm_key_update(context, session_id,
						      single_direction, &key_updated);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}
