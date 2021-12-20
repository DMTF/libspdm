/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"

/**
  Send an SPDM or an APP request to a device.

  @param  spdm_context                  The SPDM context for the device.
  @param  session_id                    Indicate if the request is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  request_size                  size in bytes of the request data buffer.
  @param  request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
**/
return_status libspdm_send_request(IN void *context, IN uint32_t *session_id,
                IN boolean is_app_message,
                IN uintn request_size, IN void *request)
{
    spdm_context_t *spdm_context;
    return_status status;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn message_size;

    spdm_context = context;

    DEBUG((DEBUG_INFO, "spdm_send_spdm_request[%x] (0x%x): \n",
           (session_id != NULL) ? *session_id : 0x0, request_size));
    internal_dump_hex(request, request_size);

    message_size = sizeof(message);
    status = spdm_context->transport_encode_message(
        spdm_context, session_id, is_app_message, TRUE, request_size,
        request, &message_size, message);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_INFO, "transport_encode_message status - %p\n",
               status));
        return status;
    }

    status = spdm_context->send_message(spdm_context, message_size, message,
                        0);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_INFO, "spdm_send_spdm_request[%x] status - %p\n",
               (session_id != NULL) ? *session_id : 0x0, status));
    }

    return status;
}

/**
  Receive an SPDM or an APP response from a device.

  @param  spdm_context                  The SPDM context for the device.
  @param  session_id                    Indicate if the response is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  response_size                 size in bytes of the response data buffer.
  @param  response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
**/
return_status libspdm_receive_response(IN void *context, IN uint32_t *session_id,
                    IN boolean is_app_message,
                    IN OUT uintn *response_size,
                    OUT void *response)
{
    spdm_context_t *spdm_context;
    return_status status;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn message_size;
    uint32_t *message_session_id;
    boolean is_message_app_message;

    spdm_context = context;

    ASSERT(*response_size <= LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    message_size = sizeof(message);
    status = spdm_context->receive_message(spdm_context, &message_size,
                           message, 0);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_INFO,
               "spdm_receive_spdm_response[%x] status - %p\n",
               (session_id != NULL) ? *session_id : 0x0, status));
        return status;
    }

    message_session_id = NULL;
    is_message_app_message = FALSE;
    status = spdm_context->transport_decode_message(
        spdm_context, &message_session_id, &is_message_app_message,
        FALSE, message_size, message, response_size, response);

    if (session_id != NULL) {
        if (message_session_id == NULL) {
            DEBUG((DEBUG_INFO,
                   "spdm_receive_spdm_response[%x] GetSessionId - NULL\n",
                   (session_id != NULL) ? *session_id : 0x0));
            goto error;
        }
        if (*message_session_id != *session_id) {
            DEBUG((DEBUG_INFO,
                   "spdm_receive_spdm_response[%x] GetSessionId - %x\n",
                   (session_id != NULL) ? *session_id : 0x0,
                   *message_session_id));
            goto error;
        }
    } else {
        if (message_session_id != NULL) {
            DEBUG((DEBUG_INFO,
                   "spdm_receive_spdm_response[%x] GetSessionId - %x\n",
                   (session_id != NULL) ? *session_id : 0x0,
                   *message_session_id));
            goto error;
        }
    }

    if ((is_app_message && !is_message_app_message) ||
        (!is_app_message && is_message_app_message)) {
        DEBUG((DEBUG_INFO,
               "spdm_receive_spdm_response[%x] app_message mismatch\n",
               (session_id != NULL) ? *session_id : 0x0));
        goto error;
    }

    DEBUG((DEBUG_INFO, "spdm_receive_spdm_response[%x] (0x%x): \n",
           (session_id != NULL) ? *session_id : 0x0, *response_size));
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_INFO,
               "spdm_receive_spdm_response[%x] status - %p\n",
               (session_id != NULL) ? *session_id : 0x0, status));
    } else {
        internal_dump_hex(response, *response_size);
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
  Send an SPDM request to a device.

  @param  spdm_context                  The SPDM context for the device.
  @param  session_id                    Indicate if the request is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  request_size                  size in bytes of the request data buffer.
  @param  request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
**/
return_status spdm_send_spdm_request(IN spdm_context_t *spdm_context,
                     IN uint32_t *session_id,
                     IN uintn request_size, IN void *request)
{
    spdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    if ((session_id != NULL) &&
        spdm_is_capabilities_flag_supported(
            spdm_context, TRUE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        ASSERT(session_info != NULL);
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

    return libspdm_send_request(spdm_context, session_id, FALSE, request_size,
                 request);
}

/**
  Receive an SPDM response from a device.

  @param  spdm_context                  The SPDM context for the device.
  @param  session_id                    Indicate if the response is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  response_size                 size in bytes of the response data buffer.
  @param  response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
**/
return_status spdm_receive_spdm_response(IN spdm_context_t *spdm_context,
                     IN uint32_t *session_id,
                     IN OUT uintn *response_size,
                     OUT void *response)
{
    spdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    if ((session_id != NULL) &&
        spdm_is_capabilities_flag_supported(
            spdm_context, TRUE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        ASSERT(session_info != NULL);
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

    return libspdm_receive_response(spdm_context, session_id, FALSE,
                     response_size, response);
}
