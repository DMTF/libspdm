/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"

/**
 * Send an SPDM or an APP request to a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  request_size                  size in bytes of the request data buffer.
 * @param  request                      A pointer to a destination buffer to store the request.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *                                      For normal message, requester pointer point to transport_message + transport header size
 *                                      For secured message, requester pointer will point to the scratch buffer + transport header size in spdm_context.
 *
 * @retval RETURN_SUCCESS               The SPDM request is sent successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
 **/
return_status libspdm_send_request(void *context, const uint32_t *session_id,
                                   bool is_app_message,
                                   uintn request_size, const void *request)
{
    libspdm_context_t *spdm_context;
    return_status status;
    uint8_t *message;
    uintn message_size;
    uint64_t timeout;
    uint8_t *scratch_buffer;
    uintn scratch_buffer_size;
    uintn transport_header_size;
    uint8_t *sender_buffer;
    uintn sender_buffer_size;

    spdm_context = context;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_send_spdm_request[%x] (0x%x): \n",
                   (session_id != NULL) ? *session_id : 0x0, request_size));
    libspdm_internal_dump_hex(request, request_size);

    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_get_sender_buffer (spdm_context, (void **)&sender_buffer, &sender_buffer_size);
    message = sender_buffer;
    message_size = sender_buffer_size;

    if (session_id != NULL) {
        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          request, request_size);
        request = scratch_buffer + transport_header_size;
    }

    /* backup it to last_spdm_request, because the caller wants to compare it with response */
    if (((spdm_message_header_t *)request)->request_response_code != SPDM_RESPOND_IF_READY) {
        libspdm_copy_mem (spdm_context->last_spdm_request,
                          sizeof(spdm_context->last_spdm_request),
                          request,
                          request_size
                          );
        spdm_context->last_spdm_request_size = request_size;
    }

    status = spdm_context->transport_encode_message(
        spdm_context, session_id, is_app_message, true, request_size,
        request, &message_size, (void **)&message);
    if (RETURN_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_encode_message status - %p\n",
                       status));
        return status;
    }

    timeout = spdm_context->local_context.capability.rtt;

    status = spdm_context->send_message(spdm_context, message_size, message,
                                        timeout);
    if (RETURN_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_send_spdm_request[%x] status - %p\n",
                       (session_id != NULL) ? *session_id : 0x0, status));
    }

    return status;
}

/**
 * Receive an SPDM or an APP response from a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the response is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  response_size                 size in bytes of the response data buffer.
 * @param  response                     A pointer to a destination buffer to store the response.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *
 * @retval RETURN_SUCCESS               The SPDM response is received successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
 **/
return_status libspdm_receive_response(void *context, const uint32_t *session_id,
                                       bool is_app_message,
                                       uintn *response_size,
                                       void **response)
{
    libspdm_context_t *spdm_context;
    return_status status;
    uint8_t *message;
    uintn message_size;
    uint32_t *message_session_id;
    bool is_message_app_message;
    uint64_t timeout;

    spdm_context = context;

    LIBSPDM_ASSERT(*response_size <= LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    if (spdm_context->crypto_request) {
        timeout = spdm_context->local_context.capability.rtt +
                  (2 << spdm_context->local_context.capability.ct_exponent);
    } else {
        timeout = spdm_context->local_context.capability.rtt +
                  spdm_context->local_context.capability.st1;
    }

    message = *response;
    message_size = *response_size;
    status = spdm_context->receive_message(spdm_context, &message_size,
                                           (void **)&message, timeout);
    if (RETURN_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_receive_spdm_response[%x] status - %p\n",
                       (session_id != NULL) ? *session_id : 0x0, status));
        return status;
    }

    message_session_id = NULL;
    is_message_app_message = false;
    status = spdm_context->transport_decode_message(
        spdm_context, &message_session_id, &is_message_app_message,
        false, message_size, message, response_size, response);

    if (session_id != NULL) {
        if (message_session_id == NULL) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_receive_spdm_response[%x] GetSessionId - NULL\n",
                           (session_id != NULL) ? *session_id : 0x0));
            goto error;
        }
        if (*message_session_id != *session_id) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_receive_spdm_response[%x] GetSessionId - %x\n",
                           (session_id != NULL) ? *session_id : 0x0,
                           *message_session_id));
            goto error;
        }
    } else {
        if (message_session_id != NULL) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_receive_spdm_response[%x] GetSessionId - %x\n",
                           (session_id != NULL) ? *session_id : 0x0,
                           *message_session_id));
            goto error;
        }
    }

    if ((is_app_message && !is_message_app_message) ||
        (!is_app_message && is_message_app_message)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_receive_spdm_response[%x] app_message mismatch\n",
                       (session_id != NULL) ? *session_id : 0x0));
        goto error;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_receive_spdm_response[%x] (0x%x): \n",
                   (session_id != NULL) ? *session_id : 0x0, *response_size));
    if (RETURN_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_receive_spdm_response[%x] status - %p\n",
                       (session_id != NULL) ? *session_id : 0x0, status));
    } else {
        libspdm_internal_dump_hex(*response, *response_size);
    }
    return status;

error:
    if (spdm_context->last_spdm_error.error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
        return RETURN_SECURITY_VIOLATION;
    } else {
        return RETURN_DEVICE_ERROR;
    }
}

/**
 * Send an SPDM request to a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  request_size                  size in bytes of the request data buffer.
 * @param  request                      A pointer to a destination buffer to store the request.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *
 * @retval RETURN_SUCCESS               The SPDM request is sent successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
 **/
return_status libspdm_send_spdm_request(libspdm_context_t *spdm_context,
                                        const uint32_t *session_id,
                                        uintn request_size, const void *request)
{
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    if ((spdm_context->connection_info.capability.data_transfer_size != 0) &&
        (request_size > spdm_context->connection_info.capability.data_transfer_size)) {
        return RETURN_BAD_BUFFER_SIZE;
    }

    if ((session_id != NULL) &&
        libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        LIBSPDM_ASSERT(session_info != NULL);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if ((session_state == LIBSPDM_SESSION_STATE_HANDSHAKING) &&
            !session_info->use_psk) {
            session_id = NULL;
        }
    }

    return libspdm_send_request(spdm_context, session_id, false, request_size,
                                request);
}

/**
 * Receive an SPDM response from a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the response is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  response_size                 size in bytes of the response data buffer.
 * @param  response                     A pointer to a destination buffer to store the response.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *
 * @retval RETURN_SUCCESS               The SPDM response is received successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
 **/
return_status libspdm_receive_spdm_response(libspdm_context_t *spdm_context,
                                            const uint32_t *session_id,
                                            uintn *response_size,
                                            void **response)
{
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    if ((session_id != NULL) &&
        libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        LIBSPDM_ASSERT(session_info != NULL);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if ((session_state == LIBSPDM_SESSION_STATE_HANDSHAKING) &&
            !session_info->use_psk) {
            session_id = NULL;
        }
    }

    return libspdm_receive_response(spdm_context, session_id, false,
                                    response_size, response);
}
