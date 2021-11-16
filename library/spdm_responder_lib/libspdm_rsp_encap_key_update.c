/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"

/**
  Get the SPDM encapsulated KEY_UPDATE request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  encap_request                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_get_encap_request_key_update(IN spdm_context_t *spdm_context,
				  IN OUT uintn *encap_request_size,
				  OUT void *encap_request)
{
	spdm_key_update_request_t *spdm_request;
	uint32_t session_id;
	spdm_session_info_t *session_info;
	spdm_session_state_t session_state;

	spdm_context->encap_context.last_encap_request_size = 0;

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
		return RETURN_UNSUPPORTED;
	}

	if (!spdm_context->last_spdm_request_session_id_valid) {
		return RETURN_UNSUPPORTED;
	}
	session_id = spdm_context->last_spdm_request_session_id;
	session_info =
		libspdm_get_session_info_via_session_id(spdm_context, session_id);
	if (session_info == NULL) {
		return RETURN_UNSUPPORTED;
	}
	session_state = spdm_secured_message_get_session_state(
		session_info->secured_message_context);
	if (session_state != SPDM_SESSION_STATE_ESTABLISHED) {
		return RETURN_UNSUPPORTED;
	}

	ASSERT(*encap_request_size >= sizeof(spdm_key_update_request_t));
	*encap_request_size = sizeof(spdm_key_update_request_t);

	spdm_request = encap_request;

	spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_request->header.request_response_code = SPDM_KEY_UPDATE;

	spdm_reset_message_buffer_via_request_code(spdm_context, session_info,
						spdm_request->header.request_response_code);

	if (spdm_context->encap_context.last_encap_request_header
		    .request_response_code != SPDM_KEY_UPDATE) {
		spdm_request->header.param1 =
			SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
		spdm_request->header.param2 = 0;
		spdm_get_random_number(sizeof(spdm_request->header.param2),
				       &spdm_request->header.param2);
	} else {
		spdm_request->header.param1 =
			SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
		spdm_request->header.param2 = 1;
		spdm_get_random_number(sizeof(spdm_request->header.param2),
				       &spdm_request->header.param2);

		// Create new key
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
	}

	copy_mem(&spdm_context->encap_context.last_encap_request_header,
		 &spdm_request->header, sizeof(spdm_message_header_t));
	spdm_context->encap_context.last_encap_request_size =
		*encap_request_size;

	return RETURN_SUCCESS;
}

/**
  Process the SPDM encapsulated KEY_UPDATE response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_response_size            size in bytes of the encapsulated response data.
  @param  encap_response                A pointer to the encapsulated response data.
  @param  need_continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_process_encap_response_key_update(
	IN spdm_context_t *spdm_context, IN uintn encap_response_size,
	IN void *encap_response, OUT boolean *need_continue)
{
	spdm_key_update_request_t *spdm_request;
	spdm_key_update_response_t *spdm_response;
	uintn spdm_response_size;
	uint32_t session_id;
	spdm_session_info_t *session_info;
	spdm_session_state_t session_state;

	if (!spdm_context->last_spdm_request_session_id_valid) {
		return RETURN_UNSUPPORTED;
	}
	session_id = spdm_context->last_spdm_request_session_id;
	session_info =
		libspdm_get_session_info_via_session_id(spdm_context, session_id);
	if (session_info == NULL) {
		return RETURN_UNSUPPORTED;
	}
	session_state = spdm_secured_message_get_session_state(
		session_info->secured_message_context);
	if (session_state != SPDM_SESSION_STATE_ESTABLISHED) {
		return RETURN_UNSUPPORTED;
	}

	spdm_request =
		(void *)&spdm_context->encap_context.last_encap_request_header;

	spdm_response = encap_response;
	spdm_response_size = encap_response_size;

	if ((spdm_response_size != sizeof(spdm_key_update_response_t)) ||
	    (spdm_response->header.request_response_code !=
	     SPDM_KEY_UPDATE_ACK) ||
	    (spdm_response->header.param1 != spdm_request->header.param1) ||
	    (spdm_response->header.param2 != spdm_request->header.param2)) {
		if (spdm_request->header.param1 !=
		    SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY) {
			DEBUG((DEBUG_INFO, "libspdm_key_update[%x] failed\n",
			       session_id));
		} else {
			DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] failed\n",
			       session_id));
		}
		return RETURN_DEVICE_ERROR;
	}

	if (spdm_request->header.param1 !=
	    SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY) {
		DEBUG((DEBUG_INFO, "libspdm_key_update[%x] success\n",
		       session_id));
		*need_continue = TRUE;
	} else {
		DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Success\n", session_id));
		*need_continue = FALSE;
	}

	return RETURN_SUCCESS;
}
