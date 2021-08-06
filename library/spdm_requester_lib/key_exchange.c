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
	uint16 reserved;
	uint8 random_data[SPDM_RANDOM_DATA_SIZE];
	uint8 exchange_data[MAX_DHE_KEY_SIZE];
	uint16 opaque_length;
	uint8 opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
} spdm_key_exchange_request_mine_t;

typedef struct {
	spdm_message_header_t header;
	uint16 rsp_session_id;
	uint8 mut_auth_requested;
	uint8 req_slot_id_param;
	uint8 random_data[SPDM_RANDOM_DATA_SIZE];
	uint8 exchange_data[MAX_DHE_KEY_SIZE];
	uint8 measurement_summary_hash[MAX_HASH_SIZE];
	uint16 opaque_length;
	uint8 opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
	uint8 signature[MAX_ASYM_KEY_SIZE];
	uint8 verify_data[MAX_HASH_SIZE];
} spdm_key_exchange_response_max_t;

#pragma pack()

/**
  This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  measurement_hash_type          measurement_hash_type to the KEY_EXCHANGE request.
  @param  slot_id                      slot_id to the KEY_EXCHANGE request.
  @param  heartbeat_period              heartbeat_period from the KEY_EXCHANGE_RSP response.
  @param  session_id                    session_id from the KEY_EXCHANGE_RSP response.
  @param  req_slot_id_param               req_slot_id_param from the KEY_EXCHANGE_RSP response.
  @param  measurement_hash              measurement_hash from the KEY_EXCHANGE_RSP response.

  @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_send_receive_key_exchange(
	IN spdm_context_t *spdm_context, IN uint8 measurement_hash_type,
	IN uint8 slot_id, OUT uint32 *session_id, OUT uint8 *heartbeat_period,
	OUT uint8 *req_slot_id_param, OUT void *measurement_hash)
{
	boolean result;
	return_status status;
	spdm_key_exchange_request_mine_t spdm_request;
	uintn spdm_request_size;
	spdm_key_exchange_response_max_t spdm_response;
	uintn spdm_response_size;
	uintn dhe_key_size;
	uint32 measurement_summary_hash_size;
	uint32 signature_size;
	uint32 hmac_size;
	uint8 *ptr;
	void *measurement_summary_hash;
	uint16 opaque_length;
	uint8 *signature;
	uint8 *verify_data;
	void *dhe_context;
	uint16 req_session_id;
	uint16 rsp_session_id;
	spdm_session_info_t *session_info;
	uintn opaque_key_exchange_req_size;
	uint8 th1_hash_data[64];

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
		return RETURN_UNSUPPORTED;
	}
	if (spdm_context->connection_info.connection_state <
	    SPDM_CONNECTION_STATE_NEGOTIATED) {
		return RETURN_UNSUPPORTED;
	}

	if ((slot_id >= MAX_SPDM_SLOT_COUNT) && (slot_id != 0xFF)) {
		return RETURN_INVALID_PARAMETER;
	}
	if ((slot_id == 0xFF) &&
	    (spdm_context->local_context.peer_cert_chain_provision_size == 0)) {
		return RETURN_INVALID_PARAMETER;
	}

	spdm_context->error_state = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

	spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_request.header.request_response_code = SPDM_KEY_EXCHANGE;
	spdm_request.header.param1 = measurement_hash_type;
	spdm_request.header.param2 = slot_id;
	spdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_request.random_data);
	DEBUG((DEBUG_INFO, "ClientRandomData (0x%x) - ",
	       SPDM_RANDOM_DATA_SIZE));
	internal_dump_data(spdm_request.random_data, SPDM_RANDOM_DATA_SIZE);
	DEBUG((DEBUG_INFO, "\n"));

	req_session_id = spdm_allocate_req_session_id(spdm_context);
	spdm_request.req_session_id = req_session_id;
	spdm_request.reserved = 0;

	ptr = spdm_request.exchange_data;
	dhe_key_size = spdm_get_dhe_pub_key_size(
		spdm_context->connection_info.algorithm.dhe_named_group);
	dhe_context = spdm_secured_message_dhe_new(
		spdm_context->connection_info.algorithm.dhe_named_group);
	spdm_secured_message_dhe_generate_key(
		spdm_context->connection_info.algorithm.dhe_named_group,
		dhe_context, ptr, &dhe_key_size);
	DEBUG((DEBUG_INFO, "ClientKey (0x%x):\n", dhe_key_size));
	internal_dump_hex(ptr, dhe_key_size);
	ptr += dhe_key_size;

	opaque_key_exchange_req_size =
		spdm_get_opaque_data_supported_version_data_size(spdm_context);
	*(uint16 *)ptr = (uint16)opaque_key_exchange_req_size;
	ptr += sizeof(uint16);
	status = spdm_build_opaque_data_supported_version_data(
		spdm_context, &opaque_key_exchange_req_size, ptr);
	ASSERT_RETURN_ERROR(status);
	ptr += opaque_key_exchange_req_size;

	spdm_request_size = (uintn)ptr - (uintn)&spdm_request;
	status = spdm_send_spdm_request(spdm_context, NULL, spdm_request_size,
					&spdm_request);
	if (RETURN_ERROR(status)) {
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}

	spdm_response_size = sizeof(spdm_response);
	zero_mem(&spdm_response, sizeof(spdm_response));
	status = spdm_receive_spdm_response(
		spdm_context, NULL, &spdm_response_size, &spdm_response);
	if (RETURN_ERROR(status)) {
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_message_header_t)) {
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.header.request_response_code == SPDM_ERROR) {
		status = spdm_handle_error_response_main(
			spdm_context, NULL, NULL, 0, &spdm_response_size,
			&spdm_response, SPDM_KEY_EXCHANGE,
			SPDM_KEY_EXCHANGE_RSP,
			sizeof(spdm_key_exchange_response_max_t));
		if (RETURN_ERROR(status)) {
			spdm_secured_message_dhe_free(
				spdm_context->connection_info.algorithm
					.dhe_named_group,
				dhe_context);
			return status;
		}
	} else if (spdm_response.header.request_response_code !=
		   SPDM_KEY_EXCHANGE_RSP) {
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_key_exchange_response_t)) {
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size > sizeof(spdm_response)) {
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}

	if (heartbeat_period != NULL) {
		*heartbeat_period = spdm_response.header.param1;
	}
	*req_slot_id_param = spdm_response.req_slot_id_param;
	if (spdm_response.mut_auth_requested != 0) {
		if ((*req_slot_id_param != 0xF) &&
		    (*req_slot_id_param >=
		     spdm_context->local_context.slot_count)) {
			spdm_secured_message_dhe_free(
				spdm_context->connection_info.algorithm
					.dhe_named_group,
				dhe_context);
			return RETURN_DEVICE_ERROR;
		}
	} else {
		if (*req_slot_id_param != 0) {
			spdm_secured_message_dhe_free(
				spdm_context->connection_info.algorithm
					.dhe_named_group,
				dhe_context);
			return RETURN_DEVICE_ERROR;
		}
	}
	rsp_session_id = spdm_response.rsp_session_id;
	*session_id = (req_session_id << 16) | rsp_session_id;
	session_info = spdm_assign_session_id(spdm_context, *session_id, FALSE);
	if (session_info == NULL) {
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}

	//
	// Cache session data
	//
	status = spdm_append_message_k(spdm_context, session_info, &spdm_request,
				       spdm_request_size);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_SECURITY_VIOLATION;
	}

	signature_size = spdm_get_asym_signature_size(
		spdm_context->connection_info.algorithm.base_asym_algo);
	measurement_summary_hash_size = spdm_get_measurement_summary_hash_size(
		spdm_context, TRUE, measurement_hash_type);
	hmac_size = spdm_get_hash_size(
		spdm_context->connection_info.algorithm.base_hash_algo);

	if (spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
		hmac_size = 0;
	}

	if (spdm_response_size <
	    sizeof(spdm_key_exchange_response_t) + dhe_key_size +
		    measurement_summary_hash_size + sizeof(uint16) +
		    signature_size + hmac_size) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}

	DEBUG((DEBUG_INFO, "ServerRandomData (0x%x) - ",
	       SPDM_RANDOM_DATA_SIZE));
	internal_dump_data(spdm_response.random_data, SPDM_RANDOM_DATA_SIZE);
	DEBUG((DEBUG_INFO, "\n"));

	DEBUG((DEBUG_INFO, "ServerKey (0x%x):\n", dhe_key_size));
	internal_dump_hex(spdm_response.exchange_data, dhe_key_size);

	ptr = spdm_response.exchange_data;
	ptr += dhe_key_size;

	measurement_summary_hash = ptr;
	DEBUG((DEBUG_INFO, "measurement_summary_hash (0x%x) - ",
	       measurement_summary_hash_size));
	internal_dump_data(measurement_summary_hash,
			   measurement_summary_hash_size);
	DEBUG((DEBUG_INFO, "\n"));

	ptr += measurement_summary_hash_size;

	opaque_length = *(uint16 *)ptr;
	if (opaque_length > MAX_SPDM_OPAQUE_DATA_SIZE) {
		return RETURN_SECURITY_VIOLATION;
	}
	ptr += sizeof(uint16);
	if (spdm_response_size <
	    sizeof(spdm_key_exchange_response_t) + dhe_key_size +
		    measurement_summary_hash_size + sizeof(uint16) +
		    opaque_length + signature_size + hmac_size) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_DEVICE_ERROR;
	}
	status = spdm_process_opaque_data_version_selection_data(
		spdm_context, opaque_length, ptr);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_UNSUPPORTED;
	}

	ptr += opaque_length;

	spdm_response_size = sizeof(spdm_key_exchange_response_t) +
			     dhe_key_size + measurement_summary_hash_size +
			     sizeof(uint16) + opaque_length + signature_size +
			     hmac_size;

	status = spdm_append_message_k(spdm_context, session_info, &spdm_response,
				       spdm_response_size - signature_size -
					       hmac_size);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_SECURITY_VIOLATION;
	}

	signature = ptr;
	DEBUG((DEBUG_INFO, "signature (0x%x):\n", signature_size));
	internal_dump_hex(signature, signature_size);
	ptr += signature_size;
	result = spdm_verify_key_exchange_rsp_signature(
		spdm_context, session_info, signature, signature_size);
	if (!result) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		spdm_context->error_state =
			SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
		return RETURN_SECURITY_VIOLATION;
	}

	status = spdm_append_message_k(spdm_context, session_info, signature, signature_size);
	if (RETURN_ERROR(status)) {
		spdm_free_session_id(spdm_context, *session_id);
		spdm_secured_message_dhe_free(
			spdm_context->connection_info.algorithm.dhe_named_group,
			dhe_context);
		return RETURN_SECURITY_VIOLATION;
	}

	//
	// Fill data to calc Secret for HMAC verification
	//
	result = spdm_secured_message_dhe_compute_key(
		spdm_context->connection_info.algorithm.dhe_named_group,
		dhe_context, spdm_response.exchange_data, dhe_key_size,
		session_info->secured_message_context);
	spdm_secured_message_dhe_free(
		spdm_context->connection_info.algorithm.dhe_named_group,
		dhe_context);
	if (!result) {
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

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
		verify_data = ptr;
		DEBUG((DEBUG_INFO, "verify_data (0x%x):\n", hmac_size));
		internal_dump_hex(verify_data, hmac_size);
		result = spdm_verify_key_exchange_rsp_hmac(
			spdm_context, session_info, verify_data, hmac_size);
		if (!result) {
			spdm_free_session_id(spdm_context, *session_id);
			spdm_context->error_state =
				SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
			return RETURN_SECURITY_VIOLATION;
		}
		ptr += hmac_size;

		status = spdm_append_message_k(spdm_context, session_info, verify_data,
					       hmac_size);
		if (RETURN_ERROR(status)) {
			spdm_free_session_id(spdm_context, *session_id);
			return RETURN_SECURITY_VIOLATION;
		}
	}

	if (measurement_hash != NULL) {
		copy_mem(measurement_hash, measurement_summary_hash,
			 measurement_summary_hash_size);
	}
	session_info->mut_auth_requested = spdm_response.mut_auth_requested;

	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);
	spdm_context->error_state = SPDM_STATUS_SUCCESS;

	return RETURN_SUCCESS;
}

return_status spdm_send_receive_key_exchange(
	IN spdm_context_t *spdm_context, IN uint8 measurement_hash_type,
	IN uint8 slot_id, OUT uint32 *session_id, OUT uint8 *heartbeat_period,
	OUT uint8 *req_slot_id_param, OUT void *measurement_hash)
{
	uintn retry;
	return_status status;

	retry = spdm_context->retry_times;
	do {
		status = try_spdm_send_receive_key_exchange(
			spdm_context, measurement_hash_type, slot_id,
			session_id, heartbeat_period, req_slot_id_param,
			measurement_hash);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}
