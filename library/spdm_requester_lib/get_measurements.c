/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"

#pragma pack(1)
typedef struct {
	spdm_message_header_t header;
	uint8 number_of_blocks;
	uint8 measurement_record_length[3];
	uint8 measurement_record[(sizeof(spdm_measurement_block_dmtf_t) +
				  MAX_HASH_SIZE) *
				 MAX_SPDM_MEASUREMENT_BLOCK_COUNT];
	uint8 nonce[SPDM_NONCE_SIZE];
	uint16 opaque_length;
	uint8 opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
	uint8 signature[MAX_ASYM_KEY_SIZE];
} spdm_measurements_response_max_t;
#pragma pack()

/**
  This function sends GET_MEASUREMENT
  to get measurement from the device.

  If the signature is requested, this function verifies the signature of the measurement.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  request_attribute             The request attribute of the request message.
  @param  measurement_operation         The measurement operation of the request message.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  number_of_blocks               The number of blocks of the measurement record.
  @param  measurement_record_length      On input, indicate the size in bytes of the destination buffer to store the measurement record.
                                       On output, indicate the size in bytes of the measurement record.
  @param  measurement_record            A pointer to a destination buffer to store the measurement record.

  @retval RETURN_SUCCESS               The measurement is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status try_spdm_get_measurement(IN void *context, IN uint32 *session_id,
				       IN uint8 request_attribute,
				       IN uint8 measurement_operation,
				       IN uint8 slot_id_param,
				       OUT uint8 *number_of_blocks,
				       IN OUT uint32 *measurement_record_length,
				       OUT void *measurement_record)
{
	boolean result;
	return_status status;
	spdm_get_measurements_request_t spdm_request;
	uintn spdm_request_size;
	spdm_measurements_response_max_t spdm_response;
	uintn spdm_response_size;
	uint32 measurement_record_data_length;
	uint8 *measurement_record_data;
	spdm_measurement_block_common_header_t *measurement_block_header;
	uint32 measurement_block_size;
	uint8 measurement_block_count;
	uint8 *ptr;
	void *nonce;
	uint16 opaque_length;
	void *opaque;
	void *signature;
	uintn signature_size;
	spdm_context_t *spdm_context;
	spdm_session_info_t *session_info;
	spdm_session_state_t session_state;

	spdm_context = context;
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
		return RETURN_UNSUPPORTED;
	}
	if (session_id == NULL) {
		if (spdm_context->connection_info.connection_state <
		    SPDM_CONNECTION_STATE_AUTHENTICATED) {
			return RETURN_UNSUPPORTED;
		}
	} else {
		if (spdm_context->connection_info.connection_state <
		    SPDM_CONNECTION_STATE_NEGOTIATED) {
			return RETURN_UNSUPPORTED;
		}
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, *session_id);
		if (session_info == NULL) {
			ASSERT(FALSE);
			return RETURN_UNSUPPORTED;
		}
		session_state = spdm_secured_message_get_session_state(
			session_info->secured_message_context);
		if (session_state != SPDM_SESSION_STATE_ESTABLISHED) {
			return RETURN_UNSUPPORTED;
		}
	}

	if ((slot_id_param >= MAX_SPDM_SLOT_COUNT) && (slot_id_param != 0xF)) {
		return RETURN_INVALID_PARAMETER;
	}
	if ((slot_id_param == 0xF) &&
	    (spdm_context->local_context.peer_cert_chain_provision_size == 0)) {
		return RETURN_INVALID_PARAMETER;
	}

	spdm_context->error_state = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

	if (spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG) &&
	    (request_attribute != 0)) {
		return RETURN_INVALID_PARAMETER;
	}

	if (request_attribute ==
	    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
		signature_size = spdm_get_asym_signature_size(
			spdm_context->connection_info.algorithm.base_asym_algo);
	} else {
		signature_size = 0;
	}

	if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
		spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
	} else {
		spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
	}
	spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
	spdm_request.header.param1 = request_attribute;
	spdm_request.header.param2 = measurement_operation;
	if (request_attribute ==
	    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
		if (spdm_is_version_supported(spdm_context,
					      SPDM_MESSAGE_VERSION_11)) {
			spdm_request_size = sizeof(spdm_request);
		} else {
			spdm_request_size = sizeof(spdm_request) -
					    sizeof(spdm_request.SlotIDParam);
		}

		spdm_get_random_number(SPDM_NONCE_SIZE, spdm_request.nonce);
		DEBUG((DEBUG_INFO, "ClientNonce - "));
		internal_dump_data(spdm_request.nonce, SPDM_NONCE_SIZE);
		DEBUG((DEBUG_INFO, "\n"));
		spdm_request.SlotIDParam = slot_id_param;
	} else {
		spdm_request_size = sizeof(spdm_request.header);
	}
	status = spdm_send_spdm_request(spdm_context, session_id,
					spdm_request_size, &spdm_request);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}

	//
	// Cache data
	//
	status = spdm_append_message_m(spdm_context, &spdm_request,
				       spdm_request_size);
	if (RETURN_ERROR(status)) {
		return RETURN_SECURITY_VIOLATION;
	}

	spdm_response_size = sizeof(spdm_response);
	zero_mem(&spdm_response, sizeof(spdm_response));
	status = spdm_receive_spdm_response(
		spdm_context, session_id, &spdm_response_size, &spdm_response);
	if (RETURN_ERROR(status)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_message_header_t)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response.header.request_response_code == SPDM_ERROR) {
		status = spdm_handle_error_response_main(
			spdm_context, session_id,
			&spdm_context->transcript.message_m, spdm_request_size,
			&spdm_response_size, &spdm_response,
			SPDM_GET_MEASUREMENTS, SPDM_MEASUREMENTS,
			sizeof(spdm_measurements_response_max_t));
		if (RETURN_ERROR(status)) {
			return status;
		}
	} else if (spdm_response.header.request_response_code !=
		   SPDM_MEASUREMENTS) {
		reset_managed_buffer(&spdm_context->transcript.message_m);
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size < sizeof(spdm_measurements_response_t)) {
		return RETURN_DEVICE_ERROR;
	}
	if (spdm_response_size > sizeof(spdm_response)) {
		return RETURN_DEVICE_ERROR;
	}

	if (measurement_operation ==
	    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
		if (spdm_response.number_of_blocks != 0) {
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_DEVICE_ERROR;
		}
	} else if (measurement_operation ==
		   SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
		if (spdm_response.number_of_blocks == 0) {
			return RETURN_DEVICE_ERROR;
		}
	} else {
		if (spdm_response.number_of_blocks != 1) {
			return RETURN_DEVICE_ERROR;
		}
	}

	measurement_record_data_length =
		spdm_read_uint24(spdm_response.measurement_record_length);
	if (measurement_operation ==
	    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
		if (measurement_record_data_length != 0) {
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_DEVICE_ERROR;
		}
	} else {
		if (spdm_response_size <
		    sizeof(spdm_measurements_response_t) +
			    measurement_record_data_length) {
			return RETURN_DEVICE_ERROR;
		}
		if (measurement_record_data_length >=
		    sizeof(spdm_response.measurement_record)) {
			return RETURN_DEVICE_ERROR;
		}
		DEBUG((DEBUG_INFO, "measurement_record_length - 0x%06x\n",
		       measurement_record_data_length));
	}

	measurement_record_data = spdm_response.measurement_record;

	if (request_attribute ==
	    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
		if (spdm_response_size <
		    sizeof(spdm_measurements_response_t) +
			    measurement_record_data_length + SPDM_NONCE_SIZE +
			    sizeof(uint16)) {
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_DEVICE_ERROR;
		}
		if (spdm_is_version_supported(spdm_context,
					      SPDM_MESSAGE_VERSION_11) &&
		    spdm_response.header.param2 != slot_id_param) {
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_SECURITY_VIOLATION;
		}
		ptr = measurement_record_data + measurement_record_data_length;
		nonce = ptr;
		DEBUG((DEBUG_INFO, "nonce (0x%x) - ", SPDM_NONCE_SIZE));
		internal_dump_data(nonce, SPDM_NONCE_SIZE);
		DEBUG((DEBUG_INFO, "\n"));
		ptr += SPDM_NONCE_SIZE;

		opaque_length = *(uint16 *)ptr;
		if (opaque_length > MAX_SPDM_OPAQUE_DATA_SIZE) {
			return RETURN_SECURITY_VIOLATION;
		}
		ptr += sizeof(uint16);

		if (spdm_response_size <
		    sizeof(spdm_measurements_response_t) +
			    measurement_record_data_length + SPDM_NONCE_SIZE +
			    sizeof(uint16) + opaque_length + signature_size) {
			return RETURN_DEVICE_ERROR;
		}
		spdm_response_size = sizeof(spdm_measurements_response_t) +
				     measurement_record_data_length +
				     SPDM_NONCE_SIZE + sizeof(uint16) +
				     opaque_length + signature_size;
		status = spdm_append_message_m(spdm_context, &spdm_response,
					       spdm_response_size -
						       signature_size);
		if (RETURN_ERROR(status)) {
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_SECURITY_VIOLATION;
		}

		opaque = ptr;
		ptr += opaque_length;
		DEBUG((DEBUG_INFO, "opaque (0x%x):\n", opaque_length));
		internal_dump_hex(opaque, opaque_length);

		signature = ptr;
		DEBUG((DEBUG_INFO, "signature (0x%x):\n", signature_size));
		internal_dump_hex(signature, signature_size);

		result = spdm_verify_measurement_signature(
			spdm_context, signature, signature_size);
		if (!result) {
			spdm_context->error_state =
				SPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE;
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_SECURITY_VIOLATION;
		}

		reset_managed_buffer(&spdm_context->transcript.message_m);
	} else {
		//
		// nonce is absent if there is not signature
		//
		if (spdm_response_size <
		    sizeof(spdm_measurements_response_t) +
			    measurement_record_data_length + sizeof(uint16)) {
			return RETURN_DEVICE_ERROR;
		}
		ptr = measurement_record_data + measurement_record_data_length;

		opaque_length = *(uint16 *)ptr;
		if (opaque_length > MAX_SPDM_OPAQUE_DATA_SIZE) {
			return RETURN_SECURITY_VIOLATION;
		}
		ptr += sizeof(uint16);

		if (spdm_response_size <
		    sizeof(spdm_measurements_response_t) +
			    measurement_record_data_length + sizeof(uint16) +
			    opaque_length) {
			return RETURN_DEVICE_ERROR;
		}
		spdm_response_size = sizeof(spdm_measurements_response_t) +
				     measurement_record_data_length +
				     sizeof(uint16) + opaque_length;
		status = spdm_append_message_m(spdm_context, &spdm_response,
					       spdm_response_size);
		if (RETURN_ERROR(status)) {
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_SECURITY_VIOLATION;
		}
	}

	if (measurement_operation ==
	    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
		*number_of_blocks = spdm_response.header.param1;
		if (*number_of_blocks == 0xFF) {
			// the number of block cannot be 0xFF, because index 0xFF will brings confusing.
			return RETURN_DEVICE_ERROR;
		}
		if (*number_of_blocks == 0x0) {
			// the number of block cannot be 0x0, because a responder without measurement should clear capability flags.
			return RETURN_DEVICE_ERROR;
		}
	} else {
		*number_of_blocks = spdm_response.number_of_blocks;
		if (*measurement_record_length <
		    measurement_record_data_length) {
			return RETURN_BUFFER_TOO_SMALL;
		}
		if (measurement_record_data_length <
		    sizeof(spdm_measurement_block_common_header_t)) {
			return RETURN_DEVICE_ERROR;
		}

		measurement_block_size = 0;
		measurement_block_count = 1;
		while (measurement_block_size <
		       measurement_record_data_length) {
			measurement_block_header =
				(spdm_measurement_block_common_header_t
					 *)&measurement_record_data
					[measurement_block_size];
			if (measurement_block_header->measurement_size >
			    measurement_record_data_length -
				    ((uint8 *)measurement_block_header -
				     (uint8 *)measurement_record_data)) {
				return RETURN_DEVICE_ERROR;
			}
			if (measurement_block_header
					    ->measurement_specification == 0 ||
			    (measurement_block_header->measurement_specification &
			     (measurement_block_header
				      ->measurement_specification -
			      1))) {
				return RETURN_DEVICE_ERROR;
			}
			if (measurement_block_header->measurement_specification !=
			    spdm_context->connection_info.algorithm
				    .measurement_spec) {
				return RETURN_DEVICE_ERROR;
			}
			if (measurement_block_header->index == 0 ||
				measurement_block_header->index == 0xFF) {	
				return RETURN_DEVICE_ERROR;
			}
			if (measurement_operation !=
				SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
				if (measurement_block_header->index != 
						measurement_operation) {	
					return RETURN_DEVICE_ERROR;
				}
			}
			if (measurement_block_count > *number_of_blocks) {
				return RETURN_DEVICE_ERROR;
			}
			measurement_block_count++;
			measurement_block_size = (uint32)(
				measurement_block_size +
				sizeof(spdm_measurement_block_common_header_t) +
				measurement_block_header->measurement_size);
		}

		*measurement_record_length = measurement_record_data_length;
		copy_mem(measurement_record, measurement_record_data,
			 measurement_record_data_length);
	}

	spdm_context->error_state = SPDM_STATUS_SUCCESS;
	return RETURN_SUCCESS;
}

return_status spdm_get_measurement(IN void *context, IN uint32 *session_id,
				   IN uint8 request_attribute,
				   IN uint8 measurement_operation,
				   IN uint8 slot_id_param,
				   OUT uint8 *number_of_blocks,
				   IN OUT uint32 *measurement_record_length,
				   OUT void *measurement_record)
{
	spdm_context_t *spdm_context;
	uintn retry;
	return_status status;

	spdm_context = context;
	retry = spdm_context->retry_times;
	do {
		status = try_spdm_get_measurement(
			spdm_context, session_id, request_attribute,
			measurement_operation, slot_id_param, number_of_blocks,
			measurement_record_length, measurement_record);
		if (RETURN_NO_RESPONSE != status) {
			return status;
		}
	} while (retry-- != 0);

	return status;
}
