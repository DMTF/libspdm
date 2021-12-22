/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"

/**
  Process the SPDM END_SESSION request and return the response.

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
return_status spdm_get_response_end_session(IN void *context,
                        IN uintn request_size,
                        IN void *request,
                        IN OUT uintn *response_size,
                        OUT void *response)
{
    spdm_end_session_response_t *spdm_response;
    spdm_end_session_request_t *spdm_request;
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    spdm_context = context;
    spdm_request = request;

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return spdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                         0, response_size, response);
    }

    if (!spdm_context->last_spdm_request_session_id_valid) {
        return libspdm_generate_error_response(context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
    }
    session_info = libspdm_get_session_info_via_session_id(
        spdm_context, spdm_context->last_spdm_request_session_id);
    if (session_info == NULL) {
        return libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
    }

    if (request_size != sizeof(spdm_end_session_request_t)) {
        return libspdm_generate_error_response(context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
    }

    spdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                        spdm_request->header.request_response_code);

    session_info->end_session_attributes = spdm_request->header.param1;

    ASSERT(*response_size >= sizeof(spdm_end_session_response_t));
    *response_size = sizeof(spdm_end_session_response_t);
    zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_END_SESSION_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    return RETURN_SUCCESS;
}
