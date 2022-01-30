/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "hal/library/platform_lib.h"

typedef struct {
    uint8_t request_response_code;
    spdm_get_spdm_response_func get_response_func;
} spdm_get_response_struct_t;

spdm_get_response_struct_t mSpdmGetResponseStruct[] = {
    { SPDM_GET_VERSION, spdm_get_response_version },
    { SPDM_GET_CAPABILITIES, spdm_get_response_capabilities },
    { SPDM_NEGOTIATE_ALGORITHMS, spdm_get_response_algorithms },

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    { SPDM_GET_DIGESTS, spdm_get_response_digests },
    { SPDM_GET_CERTIFICATE, spdm_get_response_certificate },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    { SPDM_CHALLENGE, spdm_get_response_challenge_auth },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    { SPDM_GET_MEASUREMENTS, spdm_get_response_measurements },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    { SPDM_KEY_EXCHANGE, spdm_get_response_key_exchange },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_PSK_EXCHANGE, spdm_get_response_psk_exchange },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_GET_ENCAPSULATED_REQUEST,
      spdm_get_response_encapsulated_request },
    { SPDM_DELIVER_ENCAPSULATED_RESPONSE,
      spdm_get_response_encapsulated_response_ack },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    { SPDM_RESPOND_IF_READY, spdm_get_response_respond_if_ready },

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    { SPDM_FINISH, spdm_get_response_finish },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_PSK_FINISH, spdm_get_response_psk_finish },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_END_SESSION, spdm_get_response_end_session },
    { SPDM_HEARTBEAT, spdm_get_response_heartbeat },
    { SPDM_KEY_UPDATE, spdm_get_response_key_update },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
};

/**
 * Return the GET_SPDM_RESPONSE function via request code.
 *
 * @param  request_code                  The SPDM request code.
 *
 * @return GET_SPDM_RESPONSE function according to the request code.
 **/
spdm_get_spdm_response_func
spdm_get_response_func_via_request_code(IN uint8_t request_code)
{
    uintn index;

    ASSERT(request_code != SPDM_RESPOND_IF_READY);
    for (index = 0; index < sizeof(mSpdmGetResponseStruct) /
         sizeof(mSpdmGetResponseStruct[0]);
         index++) {
        if (request_code ==
            mSpdmGetResponseStruct[index].request_response_code) {
            return mSpdmGetResponseStruct[index].get_response_func;
        }
    }
    return NULL;
}

/**
 * Return the GET_SPDM_RESPONSE function via last request.
 *
 * @param  spdm_context                  The SPDM context for the device.
 *
 * @return GET_SPDM_RESPONSE function according to the last request.
 **/
spdm_get_spdm_response_func
spdm_get_response_func_via_last_request(IN spdm_context_t *spdm_context)
{
    spdm_message_header_t *spdm_request;

    spdm_request = (void *)spdm_context->last_spdm_request;
    return spdm_get_response_func_via_request_code(
        spdm_request->request_response_code);
}

/**
 * Process a SPDM request from a device.
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
 *
 * @retval RETURN_SUCCESS               The SPDM request is received successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is received from the device.
 **/
return_status libspdm_process_request(IN void *context, OUT uint32_t **session_id,
                                      OUT bool *is_app_message,
                                      IN uintn request_size, IN void *request)
{
    spdm_context_t *spdm_context;
    return_status status;
    spdm_session_info_t *session_info;
    uint32_t *message_session_id;

    spdm_context = context;

    if (request == NULL) {
        return RETURN_INVALID_PARAMETER;
    }
    if (request_size == 0) {
        return RETURN_INVALID_PARAMETER;
    }

    DEBUG((DEBUG_INFO, "SpdmReceiveRequest[.] ...\n"));

    message_session_id = NULL;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->last_spdm_request_size =
        sizeof(spdm_context->last_spdm_request);
    status = spdm_context->transport_decode_message(
        spdm_context, &message_session_id, is_app_message, true,
        request_size, request, &spdm_context->last_spdm_request_size,
        spdm_context->last_spdm_request);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_INFO, "transport_decode_message : %p\n", status));
        if (spdm_context->last_spdm_error.error_code != 0) {

            /* If the SPDM error code is Non-Zero, that means we need send the error message back to requester.
             * In this case, we need return SUCCESS and let caller invoke libspdm_build_response() to send an ERROR message.*/

            *session_id = &spdm_context->last_spdm_error.session_id;
            *is_app_message = false;
            return RETURN_SUCCESS;
        }
        return status;
    }

    if (!(*is_app_message)) {

        /* check minimal SPDM message size*/

        if (spdm_context->last_spdm_request_size <
            sizeof(spdm_message_header_t)) {
            return RETURN_UNSUPPORTED;
        }
    }

    *session_id = message_session_id;

    if (message_session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *message_session_id);
        if (session_info == NULL) {
            return RETURN_UNSUPPORTED;
        }
        spdm_context->last_spdm_request_session_id =
            *message_session_id;
        spdm_context->last_spdm_request_session_id_valid = true;
    }

    DEBUG((DEBUG_INFO, "SpdmReceiveRequest[%x] (0x%x): \n",
           (message_session_id != NULL) ? *message_session_id : 0,
           spdm_context->last_spdm_request_size));
    internal_dump_hex((uint8_t *)spdm_context->last_spdm_request,
                      spdm_context->last_spdm_request_size);

    return RETURN_SUCCESS;
}

/**
 * Notify the session state to a session APP.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session_id of a session.
 * @param  session_state                 The state of a session.
 **/
void spdm_trigger_session_state_callback(IN spdm_context_t *spdm_context,
                                         IN uint32_t session_id,
                                         IN libspdm_session_state_t session_state)
{
    uintn index;

    for (index = 0; index < LIBSPDM_MAX_SESSION_STATE_CALLBACK_NUM; index++) {
        if (spdm_context->spdm_session_state_callback[index] != 0) {
            ((libspdm_session_state_callback_func)spdm_context
             ->spdm_session_state_callback[index])(
                spdm_context, session_id, session_state);
        }
    }
}

/**
 * Set session_state to an SPDM secured message context and trigger callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicate the SPDM session ID.
 * @param  session_state                 Indicate the SPDM session state.
 */
void spdm_set_session_state(IN spdm_context_t *spdm_context,
                            IN uint32_t session_id,
                            IN libspdm_session_state_t session_state)
{
    spdm_session_info_t *session_info;
    libspdm_session_state_t old_session_state;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        ASSERT(false);
        return;
    }

    old_session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (old_session_state != session_state) {
        libspdm_secured_message_set_session_state(
            session_info->secured_message_context, session_state);
        spdm_trigger_session_state_callback(
            spdm_context, session_info->session_id, session_state);
    }
}

/**
 * Notify the connection state to an SPDM context register.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 **/
void spdm_trigger_connection_state_callback(IN spdm_context_t *spdm_context,
                                            IN libspdm_connection_state_t
                                            connection_state)
{
    uintn index;

    for (index = 0; index < LIBSPDM_MAX_CONNECTION_STATE_CALLBACK_NUM;
         index++) {
        if (spdm_context->spdm_connection_state_callback[index] != 0) {
            ((libspdm_connection_state_callback_func)spdm_context
             ->spdm_connection_state_callback[index])(
                spdm_context, connection_state);
        }
    }
}

/**
 * Set connection_state to an SPDM context and trigger callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 */
void spdm_set_connection_state(IN spdm_context_t *spdm_context,
                               IN libspdm_connection_state_t connection_state)
{
    if (spdm_context->connection_info.connection_state !=
        connection_state) {
        spdm_context->connection_info.connection_state =
            connection_state;
        spdm_trigger_connection_state_callback(spdm_context,
                                               connection_state);
    }
}

/**
 * Build a SPDM response to a device.
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
 * @retval RETURN_SUCCESS               The SPDM response is sent successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is sent to the device.
 * @retval RETURN_UNSUPPORTED           Just ignore this message: return UNSUPPORTED and clear response_size.
 *                                      Continue the dispatch without send response.
 **/
return_status libspdm_build_response(IN void *context, IN uint32_t *session_id,
                                     IN bool is_app_message,
                                     IN OUT uintn *response_size,
                                     OUT void *response)
{
    spdm_context_t *spdm_context;
    uint8_t my_response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn my_response_size;
    return_status status;
    spdm_get_spdm_response_func get_response_func;
    spdm_session_info_t *session_info;
    spdm_message_header_t *spdm_request;
    spdm_message_header_t *spdm_response;
    bool session_state_established;
    bool result;
    uint32_t watchdog_session_id;

    spdm_context = context;
    status = RETURN_UNSUPPORTED;
    session_state_established = false;

    if (spdm_context->last_spdm_error.error_code != 0) {

        /* Error in libspdm_process_request(), and we need send error message directly.*/

        my_response_size = sizeof(my_response);
        zero_mem(my_response, sizeof(my_response));
        switch (spdm_context->last_spdm_error.error_code) {
        case SPDM_ERROR_CODE_DECRYPT_ERROR:
            /* session ID is valid. Use it to encrypt the error message.*/
            if((spdm_context->handle_error_return_policy & BIT0) == 0) {
                status = libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
                    response_size, response);
            } else {
                /**
                 * just ignore this message
                 * return UNSUPPORTED and clear response_size to continue the dispatch without send response
                 **/
                *response_size = 0;
                status = RETURN_UNSUPPORTED;
            }
            break;
        case SPDM_ERROR_CODE_INVALID_SESSION:
            /**
             * don't use session ID, because we dont know which right session ID should be used.
             * just ignore this message
             * return UNSUPPORTED and clear response_size to continue the dispatch without send response
             **/
            *response_size = 0;
            status = RETURN_UNSUPPORTED;
            break;
        default:
            ASSERT(false);
            status = RETURN_UNSUPPORTED;
        }

        if (RETURN_ERROR(status)) {
            return status;
        }

        DEBUG((DEBUG_INFO, "SpdmSendResponse[%x] (0x%x): \n",
               (session_id != NULL) ? *session_id : 0,
               my_response_size));
        internal_dump_hex(my_response, my_response_size);

        status = spdm_context->transport_encode_message(
            spdm_context, session_id, false, false,
            my_response_size, my_response, response_size, response);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_INFO, "transport_encode_message : %p\n",
                   status));
            return status;
        }

        zero_mem(&spdm_context->last_spdm_error,
                 sizeof(spdm_context->last_spdm_error));
        return RETURN_SUCCESS;
    }

    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        if (session_info == NULL) {
            ASSERT(false);
            return RETURN_UNSUPPORTED;
        }
    }

    if (response == NULL) {
        return RETURN_INVALID_PARAMETER;
    }
    if (response_size == NULL) {
        return RETURN_INVALID_PARAMETER;
    }
    if (*response_size == 0) {
        return RETURN_INVALID_PARAMETER;
    }

    DEBUG((DEBUG_INFO, "SpdmSendResponse[%x] ...\n",
           (session_id != NULL) ? *session_id : 0));

    spdm_request = (void *)spdm_context->last_spdm_request;
    if (spdm_context->last_spdm_request_size == 0) {
        return RETURN_NOT_READY;
    }

    my_response_size = sizeof(my_response);
    zero_mem(my_response, sizeof(my_response));
    get_response_func = NULL;
    if (!is_app_message) {
        get_response_func =
            spdm_get_response_func_via_last_request(spdm_context);
        if (get_response_func != NULL) {
            status = get_response_func(
                spdm_context,
                spdm_context->last_spdm_request_size,
                spdm_context->last_spdm_request,
                &my_response_size, my_response);
        }
    }
    if (is_app_message || (get_response_func == NULL)) {
        if (spdm_context->get_response_func != 0) {
            status = ((libspdm_get_response_func)
                      spdm_context->get_response_func)(
                spdm_context, session_id, is_app_message,
                spdm_context->last_spdm_request_size,
                spdm_context->last_spdm_request,
                &my_response_size, my_response);
        } else {
            status = RETURN_NOT_FOUND;
        }
    }
    /* if return the status: Responder drop the response
     * just ignore this message
     * return UNSUPPORTED and clear response_size to continue the dispatch without send response.*/
    if((my_response_size == 0) && (status == RETURN_UNSUPPORTED)) {
        *response_size = 0;
        return RETURN_UNSUPPORTED;
    }

    if (RETURN_ERROR(status)) {
        status = libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            spdm_request->request_response_code, &my_response_size,
            my_response);
        if (RETURN_ERROR(status)) {
            return status;
        }
    }

    DEBUG((DEBUG_INFO, "SpdmSendResponse[%x] (0x%x): \n",
           (session_id != NULL) ? *session_id : 0, my_response_size));
    internal_dump_hex(my_response, my_response_size);

    status = spdm_context->transport_encode_message(
        spdm_context, session_id, is_app_message, false,
        my_response_size, my_response, response_size, response);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_INFO, "transport_encode_message : %p\n", status));
        return status;
    }

    spdm_response = (void *)my_response;
    if (session_id != NULL) {
        switch (spdm_response->request_response_code) {
        case SPDM_FINISH_RSP:
            if (!spdm_is_capabilities_flag_supported(
                    spdm_context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
                spdm_set_session_state(
                    spdm_context, *session_id,
                    LIBSPDM_SESSION_STATE_ESTABLISHED);
                watchdog_session_id = *session_id;
                session_state_established = true;
            }
            break;
        case SPDM_PSK_FINISH_RSP:
            spdm_set_session_state(spdm_context, *session_id,
                                   LIBSPDM_SESSION_STATE_ESTABLISHED);
            watchdog_session_id = *session_id;
            session_state_established = true;
            break;
        case SPDM_END_SESSION_ACK:
            spdm_set_session_state(spdm_context, *session_id,
                                   LIBSPDM_SESSION_STATE_NOT_STARTED);
            result = libspdm_stop_watchdog(*session_id);
            if (!result) {
                return RETURN_DEVICE_ERROR;
            }
            libspdm_free_session_id(spdm_context, *session_id);
            break;
        default:
            /* No session state update needed */
            break;
        }
    } else {
        switch (spdm_response->request_response_code) {
        case SPDM_FINISH_RSP:
            if (spdm_is_capabilities_flag_supported(
                    spdm_context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
                spdm_set_session_state(
                    spdm_context,
                    spdm_context->latest_session_id,
                    LIBSPDM_SESSION_STATE_ESTABLISHED);
                watchdog_session_id = spdm_context->latest_session_id;
                session_state_established = true;
            }
            break;
        default:
            /* No session state update needed */
            break;
        }
    }

    if (session_state_established) {
        result = libspdm_start_watchdog(watchdog_session_id,
                                        spdm_context->local_context.heartbeat_period);
        if (!result) {
            return RETURN_DEVICE_ERROR;
        }
    }
    return RETURN_SUCCESS;
}

/**
 * Register an SPDM or APP message process function.
 *
 * If the default message process function cannot handle the message,
 * this function will be invoked.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  get_response_func              The function to process the encapsuled message.
 **/
void libspdm_register_get_response_func(
    IN void *context, IN libspdm_get_response_func get_response_func)
{
    spdm_context_t *spdm_context;

    spdm_context = context;
    spdm_context->get_response_func = (uintn)get_response_func;

    return;
}

/**
 * Register an SPDM session state callback function.
 *
 * This function can be called multiple times to let different session APPs register its own callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_session_state_callback     The function to be called in SPDM session state change.
 *
 * @retval RETURN_SUCCESS          The callback is registered.
 * @retval RETURN_ALREADY_STARTED  No enough memory to register the callback.
 **/
return_status libspdm_register_session_state_callback_func(
    IN void *context,
    IN libspdm_session_state_callback_func spdm_session_state_callback)
{
    spdm_context_t *spdm_context;
    uintn index;

    spdm_context = context;
    for (index = 0; index < LIBSPDM_MAX_SESSION_STATE_CALLBACK_NUM; index++) {
        if (spdm_context->spdm_session_state_callback[index] == 0) {
            spdm_context->spdm_session_state_callback[index] =
                (uintn)spdm_session_state_callback;
            return RETURN_SUCCESS;
        }
    }
    ASSERT(false);

    return RETURN_ALREADY_STARTED;
}

/**
 * Register an SPDM connection state callback function.
 *
 * This function can be called multiple times to let different register its own callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  spdm_connection_state_callback  The function to be called in SPDM connection state change.
 *
 * @retval RETURN_SUCCESS          The callback is registered.
 * @retval RETURN_ALREADY_STARTED  No enough memory to register the callback.
 **/
return_status libspdm_register_connection_state_callback_func(
    IN void *context,
    IN libspdm_connection_state_callback_func spdm_connection_state_callback)
{
    spdm_context_t *spdm_context;
    uintn index;

    spdm_context = context;
    for (index = 0; index < LIBSPDM_MAX_CONNECTION_STATE_CALLBACK_NUM;
         index++) {
        if (spdm_context->spdm_connection_state_callback[index] == 0) {
            spdm_context->spdm_connection_state_callback[index] =
                (uintn)spdm_connection_state_callback;
            return RETURN_SUCCESS;
        }
    }
    ASSERT(false);

    return RETURN_ALREADY_STARTED;
}
