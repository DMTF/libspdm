/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

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
    uint32_t tmp_session_id;
    uint32_t *session_id;
    uint32_t *session_id_ptr;
    bool is_app_message;
    void *message;
    uintn message_size;

    spdm_context = context;

    /* receive and process request message */
    libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    request = message;
    request_size = message_size;
    status = spdm_context->receive_message(spdm_context, &request_size,
                                           (void **)&request, 0);
    if (RETURN_ERROR(status)) {
        libspdm_release_receiver_buffer (spdm_context, message);
        return status;
    }
    status = libspdm_process_request(spdm_context, &session_id, &is_app_message,
                                     request_size, request);
    libspdm_release_receiver_buffer (spdm_context, message);
    if (RETURN_ERROR(status)) {
        return status;
    }

    /* save the value of session_id */
    if(session_id != NULL) {
        tmp_session_id = *session_id;
        session_id_ptr = &tmp_session_id;
    } else {
        session_id_ptr = NULL;
    }

    /* build and send response message */
    libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, session_id_ptr, is_app_message,
                                    &response_size, (void **)&response);
    if (RETURN_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context, message);
        return status;
    }

    status = spdm_context->send_message(spdm_context, response_size,
                                        response, 0);
    libspdm_release_sender_buffer (spdm_context, message);

    return status;
}
