/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"

/**
  Get the SPDM encapsulated request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  encap_request                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
typedef return_status (*spdm_get_encap_request_func)(
	IN spdm_context_t *spdm_context, IN OUT uintn *encap_request_size,
	OUT void *encap_request);

/**
  Process the SPDM encapsulated response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_response_size            size in bytes of the encapsulated response data.
  @param  encap_response                A pointer to the encapsulated response data.
  @param  need_continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
typedef return_status (*spdm_process_encap_response_func)(
	IN spdm_context_t *spdm_context, IN uintn encap_response_size,
	IN void *encap_response, OUT boolean *need_continue);

typedef struct {
	uint8 request_op_code;
	spdm_get_encap_request_func get_encap_request;
	spdm_process_encap_response_func process_encap_response;
} spdm_encap_response_struct_t;

spdm_encap_response_struct_t m_encap_response_struct[] = {
	#if SPDM_ENABLE_CAPABILITY_CERT_CAP
	{ SPDM_GET_DIGESTS, spdm_get_encap_request_get_digest,
	  spdm_process_encap_response_digest },

	{ SPDM_GET_CERTIFICATE, spdm_get_encap_request_get_certificate,
	  spdm_process_encap_response_certificate },
	#endif // SPDM_ENABLE_CAPABILITY_CERT_CAP

	#if SPDM_ENABLE_CAPABILITY_CHAL_CAP
	{ SPDM_CHALLENGE, spdm_get_encap_request_challenge,
	  spdm_process_encap_response_challenge_auth },
	#endif // SPDM_ENABLE_CAPABILITY_CHAL_CAP

	{ SPDM_KEY_UPDATE, spdm_get_encap_request_key_update,
	  spdm_process_encap_response_key_update },
};

spdm_encap_response_struct_t *
spdm_get_encap_struct_via_op_code(IN spdm_context_t *spdm_context,
				  IN uint8 request_op_code)
{
	uintn index;

	for (index = 0; index < ARRAY_SIZE(m_encap_response_struct); index++) {
		if (m_encap_response_struct[index].request_op_code ==
		    request_op_code) {
			return &m_encap_response_struct[index];
		}
	}
	ASSERT(FALSE);
	return NULL;
}

void spdm_encap_move_to_next_op_code(IN spdm_context_t *spdm_context)
{
	uint8 index;

	ASSERT(spdm_context->encap_context.request_op_code_count <=
	       MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT);
	if (spdm_context->encap_context.current_request_op_code == 0) {
		spdm_context->encap_context.current_request_op_code =
			spdm_context->encap_context.request_op_code_sequence[0];
		return;
	}
	for (index = 0;
	     index < spdm_context->encap_context.request_op_code_count;
	     index++) {
		if (spdm_context->encap_context.current_request_op_code ==
		    spdm_context->encap_context.request_op_code_sequence[index]) {
			spdm_context->encap_context.current_request_op_code =
				spdm_context->encap_context
					.request_op_code_sequence[index + 1];
			return;
		}
	}
	ASSERT(FALSE);
}

/**
  Process a SPDM encapsulated response.

  @param  spdm_context                  The SPDM context for the device.
  @param  encap_response_size            size in bytes of the request data.
  @param  encap_response                A pointer to the request data.
  @param  encap_request_size             size in bytes of the response data.
  @param  encap_request                 A pointer to the response data.

  @retval RETURN_SUCCESS               The SPDM encapsulated request is generated successfully.
  @retval RETURN_UNSUPPORTED           Do not know how to process the request.
**/
return_status spdm_process_encapsulated_response(
	IN spdm_context_t *spdm_context, IN uintn encap_response_size,
	IN void *encap_response, IN OUT uintn *encap_request_size,
	OUT void *encap_request)
{
	return_status status;
	boolean need_continue;
	spdm_encap_response_struct_t *encap_response_struct;

	// Process previous response
	need_continue = FALSE;

	if (spdm_context->encap_context.current_request_op_code != 0) {
		encap_response_struct = spdm_get_encap_struct_via_op_code(
			spdm_context,
			spdm_context->encap_context.current_request_op_code);
		ASSERT(encap_response_struct != NULL);
		if (encap_response_struct == NULL) {
			return RETURN_UNSUPPORTED;
		}
		ASSERT(encap_response_struct->process_encap_response != NULL);
		if (encap_response_struct->process_encap_response == NULL) {
			return RETURN_UNSUPPORTED;
		}
		status = encap_response_struct->process_encap_response(
			spdm_context, encap_response_size, encap_response,
			&need_continue);
		if (RETURN_ERROR(status)) {
			return status;
		}
	}

	spdm_context->encap_context.request_id += 1;

	// Move to next request
	if (!need_continue) {
		spdm_encap_move_to_next_op_code(spdm_context);
	}

	if (spdm_context->encap_context.current_request_op_code == 0) {
		// No more work to do - stop
		*encap_request_size = 0;
		spdm_context->encap_context.current_request_op_code = 0;
		return RETURN_SUCCESS;
	}

	// Process the next request
	encap_response_struct = spdm_get_encap_struct_via_op_code(
		spdm_context,
		spdm_context->encap_context.current_request_op_code);
	ASSERT(encap_response_struct != NULL);
	if (encap_response_struct == NULL) {
		return RETURN_UNSUPPORTED;
	}
	ASSERT(encap_response_struct->get_encap_request != NULL);
	if (encap_response_struct->get_encap_request == NULL) {
		return RETURN_UNSUPPORTED;
	}
	status = encap_response_struct->get_encap_request(
		spdm_context, encap_request_size, encap_request);
	return status;
}

/**
  This function initializes the mut_auth encapsulated state.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  mut_auth_requested             Indicate of the mut_auth_requested through KEY_EXCHANGE or CHALLENG response.
**/
void spdm_init_mut_auth_encap_state(IN spdm_context_t *spdm_context,
				    IN uint8 mut_auth_requested)
{
	spdm_context->encap_context.error_state = 0;
	spdm_context->encap_context.current_request_op_code = 0x00;
	if (mut_auth_requested ==
	    SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS) {
		spdm_context->encap_context.current_request_op_code =
			SPDM_GET_DIGESTS;
	}
	spdm_context->encap_context.request_id = 0;
	spdm_context->encap_context.last_encap_request_size = 0;
	zero_mem(&spdm_context->encap_context.last_encap_request_header,
		 sizeof(spdm_context->encap_context.last_encap_request_header));
	spdm_context->encap_context.certificate_chain_buffer.buffer_size = 0;
	spdm_context->response_state = SPDM_RESPONSE_STATE_PROCESSING_ENCAP;

	//
	// Clear Cache
	//
	spdm_reset_message_mut_b(spdm_context);
	spdm_reset_message_mut_c(spdm_context);

	//
	// Possible Sequence:
	// 2. Session Mutual Auth: (spdm_context->last_spdm_request_session_id_valid)
	//    2.1 GET_DIGEST/GET_CERTIFICATE (spdm_context->encap_context.req_slot_id != 0xFF)
	//    2.2 GET_DIGEST (spdm_context->encap_context.req_slot_id == 0xFF)
	//    2.3 N/A (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
	//
	zero_mem(spdm_context->encap_context.request_op_code_sequence,
		 sizeof(spdm_context->encap_context.request_op_code_sequence));
	// Session Mutual Auth
	if (spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0) ||
	    (mut_auth_requested ==
	     SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED)) {
		// no encap is required
		spdm_context->encap_context.request_op_code_count = 0;
	} else if (spdm_context->encap_context.req_slot_id != 0xFF) {
		spdm_context->encap_context.request_op_code_count = 2;
		spdm_context->encap_context.request_op_code_sequence[0] =
			SPDM_GET_DIGESTS;
		spdm_context->encap_context.request_op_code_sequence[1] =
			SPDM_GET_CERTIFICATE;
	} else {
		spdm_context->encap_context.request_op_code_count = 1;
		spdm_context->encap_context.request_op_code_sequence[0] =
			SPDM_GET_DIGESTS;
	}
}

/**
  This function initializes the basic_mut_auth encapsulated state.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  basic_mut_auth_requested        Indicate of the mut_auth_requested through CHALLENG response.
**/
void spdm_init_basic_mut_auth_encap_state(IN spdm_context_t *spdm_context,
					  IN uint8 basic_mut_auth_requested)
{
	spdm_context->encap_context.error_state = 0;
	spdm_context->encap_context.current_request_op_code = 0x00;
	spdm_context->encap_context.request_id = 0;
	spdm_context->encap_context.last_encap_request_size = 0;
	zero_mem(&spdm_context->encap_context.last_encap_request_header,
		 sizeof(spdm_context->encap_context.last_encap_request_header));
	spdm_context->encap_context.certificate_chain_buffer.buffer_size = 0;
	spdm_context->response_state = SPDM_RESPONSE_STATE_PROCESSING_ENCAP;

	//
	// Clear Cache
	//
	spdm_reset_message_mut_b(spdm_context);
	spdm_reset_message_mut_c(spdm_context);

	//
	// Possible Sequence:
	// 1. Basic Mutual Auth:
	//    1.1 GET_DIGEST/GET_CERTIFICATE/CHALLENGE (spdm_context->encap_context.req_slot_id != 0xFF)
	//    1.2 GET_DIGEST/CHALLENGE (spdm_context->encap_context.req_slot_id == 0xFF)
	//    1.3 CHALLENGE (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
	//
	zero_mem(spdm_context->encap_context.request_op_code_sequence,
		 sizeof(spdm_context->encap_context.request_op_code_sequence));
	// Basic Mutual Auth
	if (spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0)) {
		spdm_context->encap_context.request_op_code_count = 1;
		spdm_context->encap_context.request_op_code_sequence[0] =
			SPDM_CHALLENGE;
	} else if (spdm_context->encap_context.req_slot_id != 0xFF) {
		spdm_context->encap_context.request_op_code_count = 3;
		spdm_context->encap_context.request_op_code_sequence[0] =
			SPDM_GET_DIGESTS;
		spdm_context->encap_context.request_op_code_sequence[1] =
			SPDM_GET_CERTIFICATE;
		spdm_context->encap_context.request_op_code_sequence[2] =
			SPDM_CHALLENGE;
	} else {
		spdm_context->encap_context.request_op_code_count = 2;
		spdm_context->encap_context.request_op_code_sequence[0] =
			SPDM_GET_DIGESTS;
		spdm_context->encap_context.request_op_code_sequence[1] =
			SPDM_CHALLENGE;
	}
}

/**
  This function initializes the key_update encapsulated state.

  @param  spdm_context                  A pointer to the SPDM context.
**/
void spdm_init_key_update_encap_state(IN void *context)
{
	spdm_context_t *spdm_context;

	spdm_context = context;

	spdm_context->encap_context.error_state = 0;
	spdm_context->encap_context.current_request_op_code = 0x00;
	spdm_context->encap_context.request_id = 0;
	spdm_context->encap_context.last_encap_request_size = 0;
	zero_mem(&spdm_context->encap_context.last_encap_request_header,
		 sizeof(spdm_context->encap_context.last_encap_request_header));
	spdm_context->encap_context.certificate_chain_buffer.buffer_size = 0;
	spdm_context->response_state = SPDM_RESPONSE_STATE_PROCESSING_ENCAP;

	spdm_reset_message_mut_b(spdm_context);
	spdm_reset_message_mut_c(spdm_context);

	zero_mem(spdm_context->encap_context.request_op_code_sequence,
		 sizeof(spdm_context->encap_context.request_op_code_sequence));
	spdm_context->encap_context.request_op_code_count = 1;
	spdm_context->encap_context.request_op_code_sequence[0] =
		SPDM_KEY_UPDATE;
}

/**
  Process the SPDM ENCAPSULATED_REQUEST request and return the response.

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
return_status spdm_get_response_encapsulated_request(
	IN void *context, IN uintn request_size, IN void *request,
	IN OUT uintn *response_size, OUT void *response)
{
	spdm_encapsulated_request_response_t *spdm_response;
	spdm_context_t *spdm_context;
	void *encap_request;
	uintn encap_request_size;
	return_status status;
	spdm_get_encapsulated_request_request_t *spdm_request;

	spdm_context = context;
	spdm_request = request;

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_GET_ENCAPSULATED_REQUEST, response_size, response);
		return RETURN_SUCCESS;
	}
	if (spdm_context->response_state !=
	    SPDM_RESPONSE_STATE_PROCESSING_ENCAP) {
		if (spdm_context->response_state ==
		    SPDM_RESPONSE_STATE_NORMAL) {
			spdm_generate_error_response(
				spdm_context,
				SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
				response_size, response);
			return RETURN_SUCCESS;
		}
		return spdm_responder_handle_response_state(
			spdm_context,
			spdm_request->header.request_response_code,
			response_size, response);
	}

	if (request_size != sizeof(spdm_get_encapsulated_request_request_t)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
						spdm_request->header.request_response_code);

	ASSERT(*response_size > sizeof(spdm_encapsulated_request_response_t));
	zero_mem(response, *response_size);

	spdm_response = response;
	spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_response->header.request_response_code = SPDM_ENCAPSULATED_REQUEST;
	spdm_response->header.param1 = 0;
	spdm_response->header.param2 = 0;

	encap_request_size =
		*response_size - sizeof(spdm_encapsulated_request_response_t);
	encap_request = spdm_response + 1;

	status = spdm_process_encapsulated_response(
		context, 0, NULL, &encap_request_size, encap_request);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
			response_size, response);
		spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
		return RETURN_SUCCESS;
	}
	*response_size = sizeof(spdm_encapsulated_request_response_t) +
			 encap_request_size;
	spdm_response->header.param1 = spdm_context->encap_context.request_id;

	if (encap_request_size == 0) {
		spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	}

	return RETURN_SUCCESS;
}

/**
  Process the SPDM ENCAPSULATED_RESPONSE_ACK request and return the response.

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
return_status spdm_get_response_encapsulated_response_ack(
	IN void *context, IN uintn request_size, IN void *request,
	IN OUT uintn *response_size, OUT void *response)
{
	spdm_deliver_encapsulated_response_request_t *spdm_request;
	uintn spdm_request_size;
	spdm_encapsulated_response_ack_response_t *spdm_response;
	spdm_context_t *spdm_context;
	void *encap_response;
	uintn encap_response_size;
	void *encap_request;
	uintn encap_request_size;
	return_status status;

	spdm_context = context;
	spdm_request = request;

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, FALSE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			SPDM_DELIVER_ENCAPSULATED_RESPONSE, response_size,
			response);
		return RETURN_SUCCESS;
	}
	if (spdm_context->response_state !=
	    SPDM_RESPONSE_STATE_PROCESSING_ENCAP) {
		if (spdm_context->response_state ==
		    SPDM_RESPONSE_STATE_NORMAL) {
			spdm_generate_error_response(
				spdm_context,
				SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
				response_size, response);
			return RETURN_SUCCESS;
		}
		return spdm_responder_handle_response_state(
			spdm_context,
			spdm_request->header.request_response_code,
			response_size, response);
	}

	if (request_size <=
	    sizeof(spdm_deliver_encapsulated_response_request_t)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	spdm_request_size = request_size;

	if (spdm_request->header.param1 !=
	    spdm_context->encap_context.request_id) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	encap_response = (spdm_request + 1);
	encap_response_size =
		spdm_request_size -
		sizeof(spdm_deliver_encapsulated_response_request_t);

	ASSERT(*response_size >
	       sizeof(spdm_encapsulated_response_ack_response_t));
	zero_mem(response, *response_size);

	spdm_response = response;
	spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
	spdm_response->header.request_response_code =
		SPDM_ENCAPSULATED_RESPONSE_ACK;
	spdm_response->header.param1 = 0;
	spdm_response->header.param2 =
		SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT;

	encap_request_size = *response_size -
			     sizeof(spdm_encapsulated_response_ack_response_t);
	encap_request = spdm_response + 1;
	if (encap_response_size < sizeof(spdm_message_header_t)) {
		spdm_generate_error_response(spdm_context,
					     SPDM_ERROR_CODE_INVALID_REQUEST, 0,
					     response_size, response);
		return RETURN_SUCCESS;
	}

	spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
						spdm_request->header.request_response_code);

	status = spdm_process_encapsulated_response(
		context, encap_response_size, encap_response,
		&encap_request_size, encap_request);
	if (RETURN_ERROR(status)) {
		spdm_generate_error_response(
			spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
			response_size, response);
		spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
		return RETURN_SUCCESS;
	}

	*response_size = sizeof(spdm_encapsulated_response_ack_response_t) +
			 encap_request_size;
	spdm_response->header.param1 = spdm_context->encap_context.request_id;
	if (encap_request_size == 0) {
		spdm_response->header.param2 =
			SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
		if (spdm_context->encap_context.req_slot_id != 0) {
			spdm_response->header.param2 =
				SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER;
			*response_size =
				sizeof(spdm_encapsulated_response_ack_response_t) +
				1;
			*(uint8 *)(spdm_response + 1) =
				spdm_context->encap_context.req_slot_id;
		}
		spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	}

	return RETURN_SUCCESS;
}

/**
  This function handles the encap error response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  error_code                    Indicate the error code.

  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_handle_encap_error_response_main(
	IN spdm_context_t *spdm_context, IN uint8 error_code)
{
	//
	// According to "Timing Specification for SPDM messages", RESPONSE_NOT_READY is only for responder.
	// RESPONSE_NOT_READY should not be sent by requester. No need to check it.
	//
	return RETURN_DEVICE_ERROR;
}
