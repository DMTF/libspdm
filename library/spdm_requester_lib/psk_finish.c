/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"

#pragma pack(1)

typedef struct {
	spdm_message_header_t header;
	uint8 verify_data[MAX_HASH_SIZE];
} spdm_psk_finish_request_mine_t;

typedef struct {
	spdm_message_header_t header;
	uint8 dummy_data[sizeof(spdm_error_data_response_not_ready_t)];
} spdm_psk_finish_response_max_t;

#pragma pack()

/**
  This function sends PSK_FINISH and receives PSK_FINISH_RSP for SPDM PSK finish.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    session_id to the PSK_FINISH request.

  @retval RETURN_SUCCESS               The PSK_FINISH is sent and the PSK_FINISH_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_send_receive_psk_finish(IN spdm_context_t *spdm_context,
					       IN uint32 session_id)
{
	return_status status;
	spdm_psk_finish_request_mine_t spdm_request;
	uintn spdm_request_size;
	uintn hmac_size;
	spdm_psk_finish_response_max_t spdm_response;
	uintn spdm_response_size;
	spdm_session_info_t *session_info;
	uint8 th2_hash_data[64];
	spdm_session_state_t session_state;

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
		return RETURN_UNSUPPORTED;
	}
	spdm_reset_message_buffer_via_request_code(spdm_context,
										SPDM_PSK_FINISH);
	if (spdm_context->connection_info.connection_state <
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		return RETURN_UNSUPPORTED;
	}

	session_info =
		spdm_get_session_info_via_session_id(spdm_context, session_id);
	if (session_info == NULL) {
		ASSERT(FALSE);
		return RETURN_UNSUPPORTED;
	}
	session_state = spdm_secured_message_get_session_state(
		session_info->secured_message_context);
	if (session_state != SPDM_SESSION_STATE_HANDSHAKING) {
		return RETURN_UNSUPPORTED;
	}

	spdm_context->error_state = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

	spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_request.header.request_response_code = SPDM_PSK_FINISH;
	spdm_request.header.param1 = 0;
	spdm_request.header.param2 = 0;

	hmac_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);
	spdm_request_size = sizeof(spdm_finish_request_t) + hmac_size;

	status = spdm_append_message_f(spdm_context, session_info, TRUE, (uint8 *)&spdm_request,
				       spdm_request_size - hmac_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_generate_psk_exchange_req_hmac(spdm_context, session_info,
					    spdm_request.verify_data);

	status = spdm_append_message_f(spdm_context, session_info, TRUE,
				       (uint8 *)&spdm_request +
					       spdm_request_size - hmac_size,
				       hmac_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	status = spdm_send_spdm_request(spdm_context, &session_id,
					spdm_request_size, &spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}

	spdm_response_size = sizeof(spdm_response);
	zero_mem(&spdm_response, sizeof(spdm_response));
	status = spdm_receive_spdm_response(
		spdm_context, &session_id, &spdm_response_size, &spdm_response);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_message_header_t)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.header.request_response_code == SPDM_ERROR) {
		status = spdm_handle_error_response_main(
			spdm_context, &session_id,
			NULL,
			0, &spdm_response_size, &spdm_response,
			SPDM_PSK_FINISH, SPDM_PSK_FINISH_RSP,
			sizeof(spdm_psk_finish_response_max_t));
		if (RETURN_ERROR(status)) {
			return status;
		}
	} else if (spdm_response.header.request_response_code !=
		   SPDM_PSK_FINISH_RSP) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size != sizeof(spdm_psk_finish_response_t)) {
		return RETURN_DEVICE_ERROR;
	}

	status = spdm_append_message_f(spdm_context, session_info, TRUE, &spdm_response,
				       spdm_response_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	DEBUG((DEBUG_INFO, "spdm_generate_session_data_key[%x]\n", session_id));
	status = spdm_calculate_th2_hash(spdm_context, session_info, TRUE,
					 th2_hash_data);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}
	status = spdm_generate_session_data_key(
		session_info->secured_message_context, th2_hash_data);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_ESTABLISHED);
	spdm_context->error_state = SPDM_STATUS_SUCCESS;

	return RETURN_SUCCESS;
}

return_status spdm_send_receive_psk_finish(IN spdm_context_t *spdm_context,
					   IN uint32 session_id)
{
	uintn retry;
	return_status status;

	retry = spdm_context->retry_times;
	do {
		status = try_spdm_send_receive_psk_finish(spdm_context,
							  session_id);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}
