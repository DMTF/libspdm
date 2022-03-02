/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

/**
 * Build the response when the response state is incorrect.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_code                  The SPDM request code.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_responder_handle_response_state(void *context,
                                                      uint8_t request_code,
                                                      uintn *response_size,
                                                      void *response)
{
    libspdm_context_t *spdm_context;
    return_status status;

    spdm_context = context;
    switch (spdm_context->response_state) {
    case LIBSPDM_RESPONSE_STATE_BUSY:
        return libspdm_generate_error_response(spdm_context, SPDM_ERROR_CODE_BUSY,
                                               0, response_size, response);
    /* NOTE: Need to reset status to Normal in up level*/
    case LIBSPDM_RESPONSE_STATE_NEED_RESYNC:
        status = libspdm_generate_error_response(spdm_context,
                                                 SPDM_ERROR_CODE_REQUEST_RESYNCH, 0,
                                                 response_size, response);
        if (RETURN_ERROR(status)) {
            return status;
        }
        /* NOTE: Need to let SPDM_VERSION reset the State*/
        libspdm_set_connection_state(spdm_context,
                                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
        return RETURN_SUCCESS;
    case LIBSPDM_RESPONSE_STATE_NOT_READY:
        /*do not update ErrorData if a previous request has not been completed*/
        if(request_code != SPDM_RESPOND_IF_READY) {
            spdm_context->cache_spdm_request_size =
                spdm_context->last_spdm_request_size;
            libspdm_copy_mem(spdm_context->cache_spdm_request,
                             sizeof(spdm_context->cache_spdm_request),
                             spdm_context->last_spdm_request,
                             spdm_context->last_spdm_request_size);
            spdm_context->error_data.rd_exponent = 1;
            spdm_context->error_data.rd_tm = 1;
            spdm_context->error_data.request_code = request_code;
            spdm_context->error_data.token = spdm_context->current_token++;
        }
        return libspdm_generate_extended_error_response(
            spdm_context, SPDM_ERROR_CODE_RESPONSE_NOT_READY, 0,
            sizeof(spdm_error_data_response_not_ready_t),
            (uint8_t *)(void *)&spdm_context->error_data,
            response_size, response);
    /* NOTE: Need to reset status to Normal in up level*/
    case LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP:
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_REQUEST_IN_FLIGHT,
                                               0, response_size, response);
    /* NOTE: Need let SPDM_ENCAPSULATED_RESPONSE_ACK reset the State*/
    default:
        return RETURN_SUCCESS;
    }
}
