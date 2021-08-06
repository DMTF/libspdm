/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"

#pragma pack(1)

typedef struct {
	spdm_message_header_t header;
	uint16 req_session_id;
	uint16 psk_hint_length;
	uint16 context_length;
	uint16 opaque_length;
	uint8 psk_hint[MAX_SPDM_PSK_HINT_LENGTH];
	uint8 context[DEFAULT_CONTEXT_LENGTH];
	uint8 opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
} spdm_psk_exchange_request_mine_t;

typedef struct {
	spdm_message_header_t header;
	uint16 rsp_session_id;
	uint16 reserved;
	uint16 context_length;
	uint16 opaque_length;
	uint8 measurement_summary_hash[MAX_HASH_SIZE];
	uint8 context[DEFAULT_CONTEXT_LENGTH];
	uint8 opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
	uint8 verify_data[MAX_HASH_SIZE];
} spdm_psk_exchange_response_max_t;

#pragma pack()

/**
  This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  measurement_hash_type          measurement_hash_type to the PSK_EXCHANGE request.
  @param  heartbeat_period              heartbeat_period from the PSK_EXCHANGE_RSP response.
  @param  session_id                    session_id from the PSK_EXCHANGE_RSP response.
  @param  measurement_hash              measurement_hash from the PSK_EXCHANGE_RSP response.

  @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_send_receive_psk_exchange(
	IN spdm_context_t *spdm_context, IN uint8 measurement_hash_type,
	OUT uint32 *session_id, OUT uint8 *heartbeat_period,
	OUT void *measurement_hash)
{
	boolean result;
	return_status status;
	spdm_psk_exchange_request_mine_t spdm_request;
	uintn spdm_request_size;
	spdm_psk_exchange_response_max_t spdm_response;
	uintn spdm_response_size;
	uint32 measurement_summary_hash_size;
	uint32 hmac_size;
	uint8 *ptr;
	void *measurement_summary_hash;
	uint8 *verify_data;
	uint16 req_session_id;
	uint16 rsp_session_id;
	spdm_session_info_t *session_info;
	uintn opaque_psk_exchange_req_size;
	uint8 th1_hash_data[64];
	uint8 th2_hash_data[64];
	uint32 algo_size;

	// Check capabilities even if GET_CAPABILITIES is not sent.
	// Assuming capabilities are provisioned.
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
		return RETURN_UNSUPPORTED;
	}
	if (spdm_context->connection_info.connection_state <
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		return RETURN_UNSUPPORTED;
	}

	{
		// Double check if algorithm has been provisioned, because ALGORITHM might be skipped.
		if (spdm_is_capabilities_flag_supported(
			    spdm_context, TRUE, 0,
			    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
			if (spdm_context->connection_info.algorithm
				    .measurement_spec !=
			    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
				return RETURN_DEVICE_ERROR;
			}
			algo_size = spdm_get_measurement_hash_size(
				spdm_context->connection_info.algorithm
					.measurement_hash_algo);
			if (algo_size == 0) {
				return RETURN_DEVICE_ERROR;
			}
		}
		algo_size = spdm_get_hash_size(
			spdm_context->connection_info.algorithm.base_hash_algo);
		if (algo_size == 0) {
			return RETURN_DEVICE_ERROR;
		}
		if (spdm_context->connection_info.algorithm.key_schedule !=
		    SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
			return RETURN_DEVICE_ERROR;
		}
	}

	spdm_context->error_state = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

	spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_request.header.request_response_code = SPDM_PSK_EXCHANGE;
	spdm_request.header.param1 = measurement_hash_type;
	spdm_request.header.param2 = 0;
	spdm_request.psk_hint_length =
		(uint16)spdm_context->local_context.psk_hint_size;
	spdm_request.context_length = DEFAULT_CONTEXT_LENGTH;
	opaque_psk_exchange_req_size =
		spdm_get_opaque_data_supported_version_data_size(spdm_context);
	spdm_request.opaque_length = (uint16)opaque_psk_exchange_req_size;

	req_session_id = spdm_allocate_req_session_id(spdm_context);
	spdm_request.req_session_id = req_session_id;

	ptr = spdm_request.psk_hint;
	copy_mem(ptr, spdm_context->local_context.psk_hint,
		 spdm_context->local_context.psk_hint_size);
	DEBUG((DEBUG_INFO, "psk_hint (0x%x) - ", spdm_request.psk_hint_length));
	internal_dump_data(ptr, spdm_request.psk_hint_length);
	DEBUG((DEBUG_INFO, "\n"));
	ptr += spdm_request.psk_hint_length;

	spdm_get_random_number(DEFAULT_CONTEXT_LENGTH, ptr);
	DEBUG((DEBUG_INFO, "ClientRandomData (0x%x) - ",
	       spdm_request.context_length));
	internal_dump_data(ptr, spdm_request.context_length);
	DEBUG((DEBUG_INFO, "\n"));
	ptr += spdm_request.context_length;

	status = spdm_build_opaque_data_supported_version_data(
		spdm_context, &opaque_psk_exchange_req_size, ptr);
	ASSERT_RETURN_ERROR(status);
	ptr += opaque_psk_exchange_req_size;

	spdm_request_size = (uintn)ptr - (uintn)&spdm_request;
	status = spdm_send_spdm_request(spdm_context, NULL, spdm_request_size,
					&spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
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
		status = spdm_handle_error_response_main(
			spdm_context, NULL, NULL, 0, &spdm_response_size,
			&spdm_response, SPDM_PSK_EXCHANGE,
			SPDM_PSK_EXCHANGE_RSP,
			sizeof(spdm_psk_exchange_response_max_t));
		if (RETURN_ERROR(status)) {
			return status;
		}
	} else if (spdm_response.header.request_response_code !=
		   SPDM_PSK_EXCHANGE_RSP) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_psk_exchange_response_t)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size > sizeof(spdm_response)) {
		return RETURN_DEVICE_ERROR;
	}
	if (heartbeat_period != NULL) {
		*heartbeat_period = spdm_response.header.param1;
	}
	rsp_session_id = spdm_response.rsp_session_id;
	*session_id = (req_session_id << 16) | rsp_session_id;
	session_info = spdm_assign_session_id(spdm_context, *session_id, TRUE);
	if (session_info == NULL) {
		return RETURN_DEVICE_ERROR;
	}

	//
	// Cache session data
	//
	status = spdm_append_message_k(spdm_context, session_info, &spdm_request,
				       spdm_request_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	measurement_summary_hash_size = spdm_get_measurement_summary_hash_size(
		spdm_context, TRUE, measurement_hash_type);
	hmac_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	if (spdm_response_size <
	    sizeof(spdm_psk_exchange_response_t) +
		    spdm_response.context_length + spdm_response.opaque_length +
		    measurement_summary_hash_size + hmac_size) {
		spdm_free_session_id(spdm_context, *session_id);
		return RETURN_DEVICE_ERROR;
	}

	ptr = (uint8 *)&spdm_response + sizeof(spdm_psk_exchange_response_t) +
	      measurement_summary_hash_size + spdm_response.context_length;
	status = spdm_process_opaque_data_version_selection_data(
		spdm_context, spdm_response.opaque_length, ptr);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		return RETURN_UNSUPPORTED;
	}

	spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
			     spdm_response.context_length +
			     spdm_response.opaque_length +
			     measurement_summary_hash_size + hmac_size;

	ptr = (uint8 *)(spdm_response.measurement_summary_hash);
	measurement_summary_hash = ptr;
	DEBUG((DEBUG_INFO, "measurement_summary_hash (0x%x) - ",
	       measurement_summary_hash_size));
	internal_dump_data(measurement_summary_hash,
			   measurement_summary_hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	ptr += measurement_summary_hash_size;

	DEBUG((DEBUG_INFO, "ServerRandomData (0x%x) - ",
	       spdm_response.context_length));
	internal_dump_data(ptr, spdm_response.context_length);
	DEBUG((DEBUG_INFO, "\n"));

	ptr += spdm_response.context_length;

	ptr += spdm_response.opaque_length;

	status = spdm_append_message_k(spdm_context, session_info, &spdm_response,
				       spdm_response_size - hmac_size);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		return RETURN_SECURITY_VIOLATION;
	}

	DEBUG((DEBUG_INFO, "spdm_generate_session_handshake_key[%x]\n",
	       *session_id));
	status = spdm_calculate_th1_hash(spdm_context, session_info, TRUE,
					 th1_hash_data);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		return RETURN_SECURITY_VIOLATION;
	}
	status = spdm_generate_session_handshake_key(
		session_info->secured_message_context, th1_hash_data);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		return RETURN_SECURITY_VIOLATION;
	}

	verify_data = ptr;
	DEBUG((DEBUG_INFO, "verify_data (0x%x):\n", hmac_size));
	internal_dump_hex(verify_data, hmac_size);
	result = spdm_verify_psk_exchange_rsp_hmac(spdm_context, session_info,
						   verify_data, hmac_size);
	if (!result) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_context->error_state =
			SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
		return RETURN_SECURITY_VIOLATION;
	}

	status = spdm_append_message_k(spdm_context, session_info, verify_data, hmac_size);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		return RETURN_SECURITY_VIOLATION;
	}

	if (measurement_hash != NULL) {
		copy_mem(measurement_hash, measurement_summary_hash,
			 measurement_summary_hash_size);
	}

	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);
	spdm_context->error_state = SPDM_STATUS_SUCCESS;

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
		// No need to send PSK_FINISH, enter application phase directly.

		DEBUG((DEBUG_INFO, "spdm_generate_session_data_key[%x]\n",
		       session_id));
		status = spdm_calculate_th2_hash(spdm_context, session_info,
						 TRUE, th2_hash_data);
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
	}

	return RETURN_SUCCESS;
}

return_status spdm_send_receive_psk_exchange(IN spdm_context_t *spdm_context,
					     IN uint8 measurement_hash_type,
					     OUT uint32 *session_id,
					     OUT uint8 *heartbeat_period,
					     OUT void *measurement_hash)
{
	uintn retry;
	return_status status;

	retry = spdm_context->retry_times;
	do {
		status = try_spdm_send_receive_psk_exchange(
			spdm_context, measurement_hash_type, session_id,
			heartbeat_period, measurement_hash);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}
