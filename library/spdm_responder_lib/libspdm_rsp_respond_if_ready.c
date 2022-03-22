/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

/**
 * Process the SPDM RESPONSE_IF_READY request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_get_response_respond_if_ready(void *context,
                                                    size_t request_size,
                                                    const void *request,
                                                    size_t *response_size,
                                                    void *response)
{
    const spdm_message_header_t *spdm_request;
    libspdm_context_t *spdm_context;
    libspdm_get_spdm_response_func get_response_func;
    return_status status;

    spdm_context = context;
    spdm_request = request;

    if (spdm_request->spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NEED_RESYNC ||
        spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NOT_READY) {
        return libspdm_responder_handle_response_state(
            spdm_context, spdm_request->request_response_code,
            response_size, response);
    }

    if (request_size != sizeof(spdm_message_header_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_request->param1 != spdm_context->error_data.request_code) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->param1 == SPDM_RESPOND_IF_READY) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->param2 != spdm_context->error_data.token) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    get_response_func = NULL;
    get_response_func =
        libspdm_get_response_func_via_request_code(spdm_request->param1);
    if (get_response_func == NULL) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            spdm_request->param1, response_size, response);
    }
    status = get_response_func(spdm_context,
                               spdm_context->cache_spdm_request_size,
                               spdm_context->cache_spdm_request,
                               response_size, response);

    return status;
}
