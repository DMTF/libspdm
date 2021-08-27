/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_responder_lib_internal.h"

/**
  This function creates the measurement signature to response message based upon l1l2.
  @param  spdm_context                  A pointer to the SPDM context.
  @param  response_message              The measurement response message with empty signature to be filled.
  @param  response_message_size          Total size in bytes of the response message including signature.

  @retval TRUE  measurement signature is created.
  @retval FALSE measurement signature is not created.
**/
boolean spdm_create_measurement_signature(IN spdm_context_t *spdm_context,
					  IN OUT void *response_message,
					  IN uintn response_message_size)
{
	uint8 *ptr;
	uintn measurment_sig_size;
	uintn signature_size;
	boolean result;
	return_status status;

	signature_size = spdm_get_asym_signature_size(
		spdm_context->connection_info.algorithm.base_asym_algo);
	measurment_sig_size =
		SPDM_NONCE_SIZE + sizeof(uint16) +
		spdm_context->local_context.opaque_measurement_rsp_size +
		signature_size;
	ASSERT(response_message_size > measurment_sig_size);
	ptr = (void *)((uint8 *)response_message + response_message_size -
		       measurment_sig_size);

	spdm_get_random_number(SPDM_NONCE_SIZE, ptr);
	ptr += SPDM_NONCE_SIZE;

	*(uint16 *)ptr =
		(uint16)spdm_context->local_context.opaque_measurement_rsp_size;
	ptr += sizeof(uint16);
	copy_mem(ptr, spdm_context->local_context.opaque_measurement_rsp,
		 spdm_context->local_context.opaque_measurement_rsp_size);
	ptr += spdm_context->local_context.opaque_measurement_rsp_size;

	status = spdm_append_message_m(spdm_context, response_message,
				       response_message_size - signature_size);
	if (RETURN_ERROR(status)) {
		return FALSE;
	}

	result = spdm_generate_measurement_signature(spdm_context, ptr);

	return result;
}

/**
  This function creates the opaque data to response message.
  @param  spdm_context                  A pointer to the SPDM context.
  @param  response_message              The measurement response message with empty signature to be filled.
  @param  response_message_size          Total size in bytes of the response message including signature.
**/
void spdm_create_measurement_opaque(IN spdm_context_t *spdm_context,
				    IN OUT void *response_message,
				    IN uintn response_message_size)
{
	uint8 *ptr;
	uintn measurment_no_sig_size;

	measurment_no_sig_size =
		SPDM_NONCE_SIZE + sizeof(uint16) +
		spdm_context->local_context.opaque_measurement_rsp_size;
	ASSERT(response_message_size > measurment_no_sig_size);
	ptr = (void *)((uint8 *)response_message + response_message_size -
		       measurment_no_sig_size);

	spdm_get_random_number(SPDM_NONCE_SIZE, ptr);
	ptr += SPDM_NONCE_SIZE;
	
	*(uint16 *)ptr =
		(uint16)spdm_context->local_context.opaque_measurement_rsp_size;
	ptr += sizeof(uint16);
	copy_mem(ptr, spdm_context->local_context.opaque_measurement_rsp,
		 spdm_context->local_context.opaque_measurement_rsp_size);
	ptr += spdm_context->local_context.opaque_measurement_rsp_size;

	return;
}

/**
  Process the SPDM GET_MEASUREMENT request and return the response.

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
return_status spdm_get_response_measurements(IN void *context,
					     IN uintn request_size,
					     IN void *request,
					     IN OUT uintn *response_size,
					     OUT void *response)
{
	uint8 index;
	spdm_get_measurements_request_t *spdm_request;
	spdm_measurements_response_t *spdm_response;
	uintn spdm_response_size;
	return_status status;
	uintn signature_size;
	uintn measurment_sig_size;
	uintn measurment_no_sig_size;
	uintn measurment_record_size;
	uintn measurment_block_size;
	spdm_measurement_block_dmtf_t *measurment_block;
	spdm_measurement_block_dmtf_t *cached_measurment_block;
	spdm_context_t *spdm_context;
	uint8 slot_id_param;
	uint8 device_measurement[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
	uint8 device_measurement_count;
	uintn device_measurement_size;
	boolean ret;
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
	// check local context here, because meas_cap is reserved for requester.
	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE, 0,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_GET_MEASUREMENTS, response_size, response);
		return RETURN_SUCCESS;
	}
	if (!spdm_context->last_spdm_request_session_id_valid) {
		if (spdm_context->connection_info.connection_state <
		    SPDM_CONNECTION_STATE_AUTHENTICATED) {
			spdm_generate_error_response(
				spdm_context,
				SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
				response_size, response);
			return RETURN_SUCCESS;
		}
	} else {
		if (spdm_context->connection_info.connection_state <
		    SPDM_CONNECTION_STATE_NEGOTIATED) {
			spdm_generate_error_response(
				spdm_context,
				SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
				response_size, response);
			return RETURN_SUCCESS;
		}
		session_info = spdm_get_session_info_via_session_id(
			spdm_context,
			spdm_context->last_spdm_request_session_id);
		if (session_info == NULL) {
			spdm_generate_error_response(
				spdm_context,
				SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
				response_size, response);
			return RETURN_SUCCESS;
		}
		session_state = spdm_secured_message_get_session_state(
			session_info->secured_message_context);
		if (session_state != SPDM_SESSION_STATE_ESTABLISHED) {
			spdm_generate_error_response(
				spdm_context,
				SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
				response_size, response);
			return RETURN_UNSUPPORTED;
		}
	}

	if (spdm_request->header.param1 ==
	    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
		if (spdm_is_version_supported(spdm_context,
					      SPDM_MESSAGE_VERSION_11)) {
			if (request_size <
			    sizeof(spdm_get_measurements_request_t)) {
				spdm_generate_error_response(
					spdm_context,
					SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					response_size, response);
				return RETURN_SUCCESS;
			}
			request_size = sizeof(spdm_get_measurements_request_t);
		} else {
			if (request_size <
			    sizeof(spdm_get_measurements_request_t) -
				    sizeof(spdm_request->SlotIDParam)) {
				spdm_generate_error_response(
					spdm_context,
					SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					response_size, response);
				return RETURN_SUCCESS;
			}
			request_size = sizeof(spdm_get_measurements_request_t) -
				       sizeof(spdm_request->SlotIDParam);
		}
	} else {
		if (request_size != sizeof(spdm_message_header_t)) {
			spdm_generate_error_response(
				spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
				0, response_size, response);
			return RETURN_SUCCESS;
		}
	}

	if ((spdm_request->header.param1 &
	     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
	    0) {
		if (!spdm_is_capabilities_flag_supported(
			    spdm_context, FALSE, 0,
			    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG)) {
			spdm_generate_error_response(
				spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
				0, response_size, response);
			return RETURN_SUCCESS;
		}
	}

	device_measurement_size = sizeof(device_measurement);
	ret = spdm_measurement_collection(
		spdm_context->connection_info.algorithm.measurement_spec,
		spdm_context->connection_info.algorithm.measurement_hash_algo,
		&device_measurement_count, device_measurement,
		&device_measurement_size);
	if (!ret) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_UNSPECIFIED,
					     0, response_size, response);
		return RETURN_SUCCESS;
	}
	ASSERT(device_measurement_count <= MAX_SPDM_MEASUREMENT_BLOCK_COUNT);

	signature_size = spdm_get_asym_signature_size(
		spdm_context->connection_info.algorithm.base_asym_algo);
	measurment_sig_size =
		SPDM_NONCE_SIZE + sizeof(uint16) +
		spdm_context->local_context.opaque_measurement_rsp_size +
		signature_size;
	measurment_no_sig_size =
		SPDM_NONCE_SIZE + sizeof(uint16) +
		spdm_context->local_context.opaque_measurement_rsp_size;

	switch (spdm_request->header.param2) {
	case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
		spdm_response_size = sizeof(spdm_measurements_response_t);
		if ((spdm_request->header.param1 &
		     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
		    0) {
			spdm_response_size += measurment_sig_size;
		} else {
			spdm_response_size += measurment_no_sig_size;
		}

		ASSERT(*response_size >= spdm_response_size);
		*response_size = spdm_response_size;
		zero_mem(response, *response_size);
		spdm_response = response;

		if (spdm_is_version_supported(spdm_context,
					      SPDM_MESSAGE_VERSION_11)) {
			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
		} else {
			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
		}
		spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
		spdm_response->header.param1 = device_measurement_count;
		spdm_response->header.param2 = 0;
		spdm_response->number_of_blocks = 0;
		spdm_write_uint24(spdm_response->measurement_record_length, 0);

		if ((spdm_request->header.param1 &
		     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
		    0) {
			if (spdm_response->header.spdm_version >=
			    SPDM_MESSAGE_VERSION_11) {
				slot_id_param = spdm_request->SlotIDParam;
				if ((slot_id_param != 0xF) &&
				    (slot_id_param >=
				     spdm_context->local_context.slot_count)) {
					spdm_generate_error_response(
						spdm_context,
						SPDM_ERROR_CODE_INVALID_REQUEST,
						0, response_size, response);
					return RETURN_SUCCESS;
				}
				spdm_response->header.param2 = slot_id_param;
			}
		} else {
			spdm_create_measurement_opaque(spdm_context,
						       spdm_response,
						       spdm_response_size);
		}
		break;

	case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
		measurment_record_size = 0;
		cached_measurment_block = (void *)device_measurement;
		for (index = 0; index < device_measurement_count; index++) {
			measurment_block_size =
				sizeof(spdm_measurement_block_dmtf_t) +
				cached_measurment_block
					->Measurement_block_dmtf_header
					.dmtf_spec_measurement_value_size;
			measurment_record_size += measurment_block_size;
			cached_measurment_block =
				(void *)((uintn)cached_measurment_block +
					 measurment_block_size);
		}

		spdm_response_size = sizeof(spdm_measurements_response_t) +
				     measurment_record_size;
		if ((spdm_request->header.param1 &
		     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
		    0) {
			spdm_response_size += measurment_sig_size;
		} else {
			spdm_response_size += measurment_no_sig_size;
		}

		ASSERT(*response_size >= spdm_response_size);
		*response_size = spdm_response_size;
		zero_mem(response, *response_size);
		spdm_response = response;

		if (spdm_is_version_supported(spdm_context,
					      SPDM_MESSAGE_VERSION_11)) {
			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_11;
		} else {
			spdm_response->header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
		}
		spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
		spdm_response->header.param1 = 0;
		spdm_response->header.param2 = 0;
		spdm_response->number_of_blocks = device_measurement_count;
		spdm_write_uint24(spdm_response->measurement_record_length,
				  (uint32)measurment_record_size);

		measurment_block = (void *)(spdm_response + 1);
		cached_measurment_block = (void *)device_measurement;
		for (index = 0; index < device_measurement_count; index++) {
			measurment_block_size =
				sizeof(spdm_measurement_block_dmtf_t) +
				cached_measurment_block
					->Measurement_block_dmtf_header
					.dmtf_spec_measurement_value_size;
			copy_mem(measurment_block, cached_measurment_block,
				 measurment_block_size);
			cached_measurment_block =
				(void *)((uintn)cached_measurment_block +
					 measurment_block_size);
			measurment_block = (void *)((uintn)measurment_block +
						    measurment_block_size);
		}

		if ((spdm_request->header.param1 &
		     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
		    0) {
			if (spdm_response->header.spdm_version >=
			    SPDM_MESSAGE_VERSION_11) {
				slot_id_param = spdm_request->SlotIDParam;
				if ((slot_id_param != 0xF) &&
				    (slot_id_param >=
				     spdm_context->local_context.slot_count)) {
					spdm_generate_error_response(
						spdm_context,
						SPDM_ERROR_CODE_INVALID_REQUEST,
						0, response_size, response);
					return RETURN_SUCCESS;
				}
				spdm_response->header.param2 = slot_id_param;
			}
		} else {
			spdm_create_measurement_opaque(spdm_context,
						       spdm_response,
						       spdm_response_size);
		}
		break;

	default:
		measurment_record_size = 0;
		cached_measurment_block = (void *)device_measurement;
		for (index = 0; index < device_measurement_count;
				index++) {
			measurment_block_size =
				sizeof(spdm_measurement_block_dmtf_t) +
				cached_measurment_block
					->Measurement_block_dmtf_header
					.dmtf_spec_measurement_value_size;
			if (cached_measurment_block->Measurement_block_common_header.index == 
				spdm_request->header.param2) {
				measurment_record_size =
					measurment_block_size;
				break;
			}
			cached_measurment_block =
				(void *)((uintn)cached_measurment_block +
						measurment_block_size);
		}
		if (index != device_measurement_count ) {
			spdm_response_size =
				sizeof(spdm_measurements_response_t) +
				measurment_record_size;
			if ((spdm_request->header.param1 &
			     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
			    0) {
				spdm_response_size += measurment_sig_size;
			} else {
				spdm_response_size += measurment_no_sig_size;
			}

			ASSERT(*response_size >= spdm_response_size);
			*response_size = spdm_response_size;
			zero_mem(response, *response_size);
			spdm_response = response;

			if (spdm_is_version_supported(
				    spdm_context, SPDM_MESSAGE_VERSION_11)) {
				spdm_response->header.spdm_version =
					SPDM_MESSAGE_VERSION_11;
			} else {
				spdm_response->header.spdm_version =
					SPDM_MESSAGE_VERSION_10;
			}
			spdm_response->header.request_response_code =
				SPDM_MEASUREMENTS;
			spdm_response->header.param1 = 0;
			spdm_response->header.param2 = 0;
			spdm_response->number_of_blocks = 1;
			spdm_write_uint24(
				spdm_response->measurement_record_length,
				(uint32)measurment_record_size);

			measurment_block = (void *)(spdm_response + 1);
			copy_mem(measurment_block,
					cached_measurment_block,
					measurment_block_size);

			if ((spdm_request->header.param1 &
			     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
			    0) {
				if (spdm_response->header.spdm_version >=
				    SPDM_MESSAGE_VERSION_11) {
					slot_id_param =
						spdm_request->SlotIDParam;
					if ((slot_id_param != 0xF) &&
					    (slot_id_param >=
					     spdm_context->local_context
						     .slot_count)) {
						spdm_generate_error_response(
							spdm_context,
							SPDM_ERROR_CODE_INVALID_REQUEST,
							0, response_size,
							response);
						return RETURN_SUCCESS;
					}
					spdm_response->header.param2 =
						slot_id_param;
				}
			} else {
				spdm_create_measurement_opaque(
					spdm_context, spdm_response,
					spdm_response_size);
			}
		} else {
			//Block not found
			spdm_generate_error_response(
				spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
				0, response_size, response);
			return RETURN_SUCCESS;
		}
		break;
	}

	spdm_reset_message_buffer_via_request_code(spdm_context,
						spdm_request->header.request_response_code);

	status = spdm_append_message_m(
			spdm_context, spdm_request,
			request_size);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(spdm_context,
						SPDM_ERROR_CODE_UNSPECIFIED, 0,
						response_size, response);
		return RETURN_SUCCESS;
	}

	if ((spdm_request->header.param1 &
	     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
	    0) {

		ret = spdm_create_measurement_signature(
			spdm_context, spdm_response,
			spdm_response_size);
		if (!ret) {
			spdm_generate_error_response(
				spdm_context,
				SPDM_ERROR_CODE_UNSPECIFIED,
				SPDM_GET_MEASUREMENTS,
				response_size, response);
			reset_managed_buffer(
				&spdm_context->transcript
						.message_m);
			return RETURN_SUCCESS;
		}
		//reset
		reset_managed_buffer(
			&spdm_context->transcript.message_m);
	} else {
		status = spdm_append_message_m(spdm_context, spdm_response,
					       *response_size);
		if (RETURN_ERROR(status)) {
			spdm_generate_error_response(
				spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
				0, response_size, response);
			reset_managed_buffer(
				&spdm_context->transcript.message_m);
			return RETURN_SUCCESS;
		}
	}

	return RETURN_SUCCESS;
}
