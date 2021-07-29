/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester_lib_internal.h"

typedef struct {
	uint8 request_response_code;
	spdm_get_encap_response_func get_encap_response_func;
} spdm_get_encap_response_struct_t;

spdm_get_encap_response_struct_t m_spdm_get_encap_response_struct[] = {
	{ SPDM_GET_DIGESTS, spdm_get_encap_response_digest },
	{ SPDM_GET_CERTIFICATE, spdm_get_encap_response_certificate },
	{ SPDM_CHALLENGE, spdm_get_encap_response_challenge_auth },
	{ SPDM_KEY_UPDATE, spdm_get_encap_response_key_update },
};

/**
  Register an SPDM encapsulated message process function.

  If the default encapsulated message process function cannot handle the encapsulated message,
  this function will be invoked.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  get_encap_response_func         The function to process the encapsuled message.
**/
void spdm_register_get_encap_response_func(IN void *context,
					   IN spdm_get_encap_response_func
						   get_encap_response_func)
{
	spdm_context_t *spdm_context;

	spdm_context = context;
	spdm_context->get_encap_response_func = (uintn)get_encap_response_func;

	return;
}

/**
  Return the GET_ENCAP_RESPONSE function via request code.

  @param  request_code                  The SPDM request code.

  @return GET_ENCAP_RESPONSE function according to the request code.
**/
spdm_get_encap_response_func
SpdmGetEncapResponseFuncViaRequestCode(IN uint8 request_response_code)
{
	uintn index;

	for (index = 0;
	     index < sizeof(m_spdm_get_encap_response_struct) /
			     sizeof(m_spdm_get_encap_response_struct[0]);
	     index++) {
		if (request_response_code ==
		    m_spdm_get_encap_response_struct[index]
			    .request_response_code) {
			return m_spdm_get_encap_response_struct[index]
				.get_encap_response_func;
		}
	}
	return NULL;
}

/**
  This function processes encapsulated request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the request data buffer.
  @param  encap_request                 A pointer to a destination buffer to store the request.
  @param  encap_response_size            size in bytes of the response data buffer.
  @param  encap_response                A pointer to a destination buffer to store the response.

  @retval RETURN_SUCCESS               The SPDM response is processed successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is sent to the device.
**/
return_status SpdmProcessEncapsulatedRequest(IN spdm_context_t *spdm_context,
					     IN uintn encap_request_size,
					     IN void *encap_request,
					     IN OUT uintn *encap_response_size,
					     OUT void *encap_response)
{
	spdm_get_encap_response_func get_encap_response_func;
	return_status status;
	spdm_message_header_t *spdm_requester;

	spdm_requester = encap_request;
	if (encap_request_size < sizeof(spdm_message_header_t)) {
		spdm_generate_encap_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			spdm_requester->request_response_code,
			encap_response_size, encap_response);
	}

	get_encap_response_func = SpdmGetEncapResponseFuncViaRequestCode(
		spdm_requester->request_response_code);
	if (get_encap_response_func == NULL) {
		get_encap_response_func =
			(spdm_get_encap_response_func)
				spdm_context->get_encap_response_func;
	}
	if (get_encap_response_func != NULL) {
		status = get_encap_response_func(
			spdm_context, encap_request_size, encap_request,
			encap_response_size, encap_response);
	} else {
		status = RETURN_NOT_FOUND;
	}
	if (status != RETURN_SUCCESS) {
		spdm_generate_encap_error_response(
			spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
			spdm_requester->request_response_code,
			encap_response_size, encap_response);
	}

	return RETURN_SUCCESS;
}

/**
  This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.

  This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
  and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicate if the encapsulated request is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  mut_auth_requested             Indicate of the mut_auth_requested through KEY_EXCHANGE or CHALLENG response.
  @param  req_slot_id_param               req_slot_id_param from the RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER.

  @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_encapsulated_request(IN spdm_context_t *spdm_context,
					IN uint32 *session_id,
					IN uint8 mut_auth_requested,
					OUT uint8 *req_slot_id_param)
{
	return_status status;
	uint8 request[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn spdm_request_size;
	spdm_get_encapsulated_request_request_t
		*spdm_get_encapsulated_request_request;
	spdm_deliver_encapsulated_response_request_t
		*spdm_deliver_encapsulated_response_request;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn spdm_response_size;
	spdm_encapsulated_request_response_t *spdm_encapsulated_request_response;
	spdm_encapsulated_response_ack_response_t
		*spdm_encapsulated_response_ack_response;
	spdm_session_info_t *session_info;
	uint8 request_id;
	void *encapsulated_request;
	uintn encapsulated_request_size;
	void *encapsulated_response;
	uintn encapsulated_response_size;
	spdm_get_digest_request_t get_digests;

	if (!spdm_is_capabilities_flag_supported(
		    spdm_context, TRUE,
		    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP,
		    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)) {
		return RETURN_UNSUPPORTED;
	}

	if (session_id != NULL) {
		session_info = spdm_get_session_info_via_session_id(
			spdm_context, *session_id);
		if (session_info == NULL) {
			ASSERT(FALSE);
			return RETURN_UNSUPPORTED;
		}
		ASSERT((mut_auth_requested == 0) ||
		       (mut_auth_requested ==
			SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST) ||
		       (mut_auth_requested ==
			SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS));
	} else {
		ASSERT(mut_auth_requested == 0);
	}

	//
	// Cache
	//
	reset_managed_buffer(&spdm_context->transcript.message_mut_b);
	reset_managed_buffer(&spdm_context->transcript.message_mut_c);

	if (session_id == NULL) {
		spdm_context->last_spdm_request_session_id_valid = FALSE;
		spdm_context->last_spdm_request_session_id = 0;
	} else {
		spdm_context->last_spdm_request_session_id_valid = TRUE;
		spdm_context->last_spdm_request_session_id = *session_id;
	}

	if (mut_auth_requested ==
	    SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS) {
		get_digests.header.spdm_version = SPDM_MESSAGE_VERSION_11;
		get_digests.header.request_response_code = SPDM_GET_DIGESTS;
		get_digests.header.param1 = 0;
		get_digests.header.param2 = 0;
		encapsulated_request = (void *)&get_digests;
		encapsulated_request_size = sizeof(get_digests);

		request_id = 0;
	} else {
		spdm_get_encapsulated_request_request = (void *)request;
		spdm_get_encapsulated_request_request->header.spdm_version =
			SPDM_MESSAGE_VERSION_11;
		spdm_get_encapsulated_request_request->header
			.request_response_code = SPDM_GET_ENCAPSULATED_REQUEST;
		spdm_get_encapsulated_request_request->header.param1 = 0;
		spdm_get_encapsulated_request_request->header.param2 = 0;
		spdm_request_size =
			sizeof(spdm_get_encapsulated_request_request_t);
		spdm_reset_message_buffer_via_request_code(spdm_context,
							spdm_get_encapsulated_request_request->header.request_response_code);
		status = spdm_send_spdm_request(
			spdm_context, session_id, spdm_request_size,
			spdm_get_encapsulated_request_request);

		if (RETURN_ERROR(status)) {
			return RETURN_DEVICE_ERROR;
		}

		spdm_encapsulated_request_response = (void *)response;
		spdm_response_size = sizeof(response);
		zero_mem(&response, sizeof(response));
		status = spdm_receive_spdm_response(
			spdm_context, session_id, &spdm_response_size,
			spdm_encapsulated_request_response);
		if (RETURN_ERROR(status)) {
			return RETURN_DEVICE_ERROR;
		}
		if (spdm_encapsulated_request_response->header
			    .request_response_code !=
		    SPDM_ENCAPSULATED_REQUEST) {
			return RETURN_DEVICE_ERROR;
		}
		if (spdm_response_size <
		    sizeof(spdm_encapsulated_request_response_t)) {
			return RETURN_DEVICE_ERROR;
		}
		if (spdm_response_size ==
		    sizeof(spdm_encapsulated_request_response_t)) {
			//
			// Done
			//
			return RETURN_SUCCESS;
		}
		request_id = spdm_encapsulated_request_response->header.param1;

		encapsulated_request =
			(void *)(spdm_encapsulated_request_response + 1);
		encapsulated_request_size =
			spdm_response_size -
			sizeof(spdm_encapsulated_request_response_t);
	}

	while (TRUE) {
		//
		// Process request
		//
		spdm_deliver_encapsulated_response_request = (void *)request;
		spdm_deliver_encapsulated_response_request->header.spdm_version =
			SPDM_MESSAGE_VERSION_11;
		spdm_deliver_encapsulated_response_request->header
			.request_response_code =
			SPDM_DELIVER_ENCAPSULATED_RESPONSE;
		spdm_deliver_encapsulated_response_request->header.param1 =
			request_id;
		spdm_deliver_encapsulated_response_request->header.param2 = 0;
		encapsulated_response =
			(void *)(spdm_deliver_encapsulated_response_request +
				 1);
		encapsulated_response_size =
			sizeof(request) -
			sizeof(spdm_deliver_encapsulated_response_request_t);

		status = SpdmProcessEncapsulatedRequest(
			spdm_context, encapsulated_request_size,
			encapsulated_request, &encapsulated_response_size,
			encapsulated_response);
		if (RETURN_ERROR(status)) {
			return RETURN_DEVICE_ERROR;
		}

		spdm_request_size =
			sizeof(spdm_deliver_encapsulated_response_request_t) +
			encapsulated_response_size;
		status = spdm_send_spdm_request(
			spdm_context, session_id, spdm_request_size,
			spdm_deliver_encapsulated_response_request);
		if (RETURN_ERROR(status)) {
			return RETURN_DEVICE_ERROR;
		}

		spdm_encapsulated_response_ack_response = (void *)response;
		spdm_response_size = sizeof(response);
		zero_mem(&response, sizeof(response));
		status = spdm_receive_spdm_response(
			spdm_context, session_id, &spdm_response_size,
			spdm_encapsulated_response_ack_response);
		if (RETURN_ERROR(status)) {
			return RETURN_DEVICE_ERROR;
		}
		if (spdm_encapsulated_response_ack_response->header
			    .request_response_code !=
		    SPDM_ENCAPSULATED_RESPONSE_ACK) {
			return RETURN_DEVICE_ERROR;
		}
		if (spdm_response_size <
		    sizeof(spdm_encapsulated_response_ack_response_t)) {
			return RETURN_DEVICE_ERROR;
		}
		switch (spdm_encapsulated_response_ack_response->header.param2) {
		case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT:
			if (spdm_response_size ==
			    sizeof(spdm_encapsulated_response_ack_response_t)) {
				return RETURN_SUCCESS;
			} else {
				return RETURN_DEVICE_ERROR;
			}
			break;
		case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT:
			break;
		case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER:
			if (spdm_response_size >=
			    sizeof(spdm_encapsulated_response_ack_response_t) +
				    sizeof(uint8)) {
				if ((req_slot_id_param != NULL) &&
				    (*req_slot_id_param == 0)) {
					*req_slot_id_param = *(
						uint8 *)(spdm_encapsulated_response_ack_response +
							 1);
					if (*req_slot_id_param >=
					    spdm_context->local_context
						    .slot_count) {
						return RETURN_DEVICE_ERROR;
					}
				}
				return RETURN_SUCCESS;
			} else {
				return RETURN_DEVICE_ERROR;
			}
			break;
		default:
			return RETURN_DEVICE_ERROR;
		}
		request_id =
			spdm_encapsulated_response_ack_response->header.param1;

		encapsulated_request =
			(void *)(spdm_encapsulated_response_ack_response + 1);
		encapsulated_request_size =
			spdm_response_size -
			sizeof(spdm_encapsulated_response_ack_response_t);
	}

	return RETURN_SUCCESS;
}

/**
  This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.

  This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
  and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicate if the encapsulated request is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.

  @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_send_receive_encap_request(IN void *spdm_context,
					      IN uint32 *session_id)
{
	return spdm_encapsulated_request(spdm_context, session_id, 0, NULL);
}