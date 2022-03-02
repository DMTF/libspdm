/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

/**
 * Process a transport layer message.
 *
 * The message can be a normal message or a secured message in SPDM session.
 * The message can be an SPDM message or an APP message.
 *
 * This function is called in libspdm_responder_dispatch_message to process the message.
 * The alternative is: an SPDM responder may receive the request message directly
 * and call this function to process it, then send the response message.
 *
 * Note: request and response may point to the same buffer. The implementation
 * must handle that case.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  request                      A pointer to the request data.
 * @param  request_size                  size in bytes of the request data.
 * @param  response                     A pointer to the response data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 *
 * @retval RETURN_SUCCESS               The SPDM request is set successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_process_message(void *context, uint32_t **session_id,
                                      const void *request, uintn request_size,
                                      void *response,
                                      uintn *response_size)
{
    return_status status;
    libspdm_context_t *spdm_context;
    bool is_app_message;
    uint32_t tmp_session_id;
    uint32_t *session_id_ptr;

    spdm_context = context;

    status = libspdm_process_request(spdm_context, session_id, &is_app_message,
                                     request_size, request);
    if (RETURN_ERROR(status)) {
        return status;
    }

    /* save the value of session_id */
    if(*session_id != NULL) {
        tmp_session_id = **session_id;
        session_id_ptr = &tmp_session_id;
    } else {
        session_id_ptr = NULL;
    }
    libspdm_zero_mem(response, *response_size);

    status = libspdm_build_response(spdm_context, session_id_ptr, is_app_message,
                                    response_size, response);
    if (RETURN_ERROR(status)) {
        return status;
    }
    return RETURN_SUCCESS;
}

/**
 * This is the main dispatch function in SPDM responder.
 *
 * It receives one request message, processes it and sends the response message.
 *
 * It should be called in a while loop or an timer/interrupt handler.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS               One SPDM request message is processed.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_UNSUPPORTED           One request message is not supported.
 **/
return_status libspdm_responder_dispatch_message(void *context)
{
    return_status status;
    libspdm_context_t *spdm_context;
    uint8_t *request;
    uintn request_size;
    uint8_t *response;
    uintn response_size;
    uint32_t *session_id;

    spdm_context = context;

    request_size = sizeof(spdm_context->request_response);
    request = spdm_context->request_response;
    status = spdm_context->receive_message(spdm_context, &request_size,
                                           request, 0);
    if (RETURN_ERROR(status)) {
        return status;
    }

    response_size = sizeof(spdm_context->request_response);
    response = spdm_context->request_response;
    status = libspdm_process_message(spdm_context, &session_id, request,
                                     request_size, response, &response_size);
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = spdm_context->send_message(spdm_context, response_size,
                                        response, 0);

    return status;
}
