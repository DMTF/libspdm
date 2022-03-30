/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "hal/library/platform_lib.h"

typedef struct {
    uint8_t request_response_code;
    libspdm_get_spdm_response_func get_response_func;
} libspdm_get_response_struct_t;

libspdm_get_response_struct_t m_libspdm_get_response_struct[] = {
    { SPDM_GET_VERSION, libspdm_get_response_version },
    { SPDM_GET_CAPABILITIES, libspdm_get_response_capabilities },
    { SPDM_NEGOTIATE_ALGORITHMS, libspdm_get_response_algorithms },

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    { SPDM_GET_DIGESTS, libspdm_get_response_digests },
    { SPDM_GET_CERTIFICATE, libspdm_get_response_certificate },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    { SPDM_CHALLENGE, libspdm_get_response_challenge_auth },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    { SPDM_GET_MEASUREMENTS, libspdm_get_response_measurements },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    { SPDM_KEY_EXCHANGE, libspdm_get_response_key_exchange },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_PSK_EXCHANGE, libspdm_get_response_psk_exchange },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_GET_ENCAPSULATED_REQUEST,
      libspdm_get_response_encapsulated_request },
    { SPDM_DELIVER_ENCAPSULATED_RESPONSE,
      libspdm_get_response_encapsulated_response_ack },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    { SPDM_RESPOND_IF_READY, libspdm_get_response_respond_if_ready },

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    { SPDM_FINISH, libspdm_get_response_finish },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_PSK_FINISH, libspdm_get_response_psk_finish },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    { SPDM_END_SESSION, libspdm_get_response_end_session },
    { SPDM_HEARTBEAT, libspdm_get_response_heartbeat },
    { SPDM_KEY_UPDATE, libspdm_get_response_key_update },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
};

/**
 * Return the GET_SPDM_RESPONSE function via request code.
 *
 * @param  request_code                  The SPDM request code.
 *
 * @return GET_SPDM_RESPONSE function according to the request code.
 **/
libspdm_get_spdm_response_func
libspdm_get_response_func_via_request_code(uint8_t request_code)
{
    size_t index;

    LIBSPDM_ASSERT(request_code != SPDM_RESPOND_IF_READY);
    for (index = 0; index < sizeof(m_libspdm_get_response_struct) /
         sizeof(m_libspdm_get_response_struct[0]);
         index++) {
        if (request_code ==
            m_libspdm_get_response_struct[index].request_response_code) {
            return m_libspdm_get_response_struct[index].get_response_func;
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
libspdm_get_spdm_response_func
libspdm_get_response_func_via_last_request(libspdm_context_t *spdm_context)
{
    spdm_message_header_t *spdm_request;

    spdm_request = (void *)spdm_context->last_spdm_request;
    return libspdm_get_response_func_via_request_code(
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
libspdm_return_t libspdm_process_request(void *context, uint32_t **session_id,
                                         bool *is_app_message,
                                         size_t request_size, const void *request)
{
    libspdm_context_t *spdm_context;
    libspdm_return_t status;
    libspdm_session_info_t *session_info;
    uint32_t *message_session_id;
    uint8_t *decoded_message_ptr;
    size_t decoded_message_size;

    spdm_context = context;

    if (request == NULL) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (request_size == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmReceiveRequest[.] ...\n"));

    message_session_id = NULL;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->last_spdm_request_size =
        sizeof(spdm_context->last_spdm_request);

    /* always use scratch buffer to response.
     * if it is secured message, this scratch buffer will be used.
     * if it is normal message, the response ptr will point to receiver buffer. */
    libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message_ptr, &decoded_message_size);
    status = spdm_context->transport_decode_message(
        spdm_context, &message_session_id, is_app_message, true,
        request_size, request, &decoded_message_size,
        (void **)&decoded_message_ptr);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_decode_message : %p\n", status));
        if (spdm_context->last_spdm_error.error_code != 0) {

            /* If the SPDM error code is Non-Zero, that means we need send the error message back to requester.
             * In this case, we need return SUCCESS and let caller invoke libspdm_build_response() to send an ERROR message.*/

            *session_id = &spdm_context->last_spdm_error.session_id;
            *is_app_message = false;
            return LIBSPDM_STATUS_SUCCESS;
        }
        return status;
    }
    spdm_context->last_spdm_request_size = decoded_message_size;
    libspdm_copy_mem (spdm_context->last_spdm_request,
                      sizeof(spdm_context->last_spdm_request),
                      decoded_message_ptr,
                      decoded_message_size
                      );

    if (!(*is_app_message)) {

        /* check minimal SPDM message size*/

        if (spdm_context->last_spdm_request_size <
            sizeof(spdm_message_header_t)) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }

    *session_id = message_session_id;

    if (message_session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *message_session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
        spdm_context->last_spdm_request_session_id =
            *message_session_id;
        spdm_context->last_spdm_request_session_id_valid = true;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmReceiveRequest[%x] (0x%x): \n",
                   (message_session_id != NULL) ? *message_session_id : 0,
                   spdm_context->last_spdm_request_size));
    libspdm_internal_dump_hex((uint8_t *)spdm_context->last_spdm_request,
                              spdm_context->last_spdm_request_size);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Notify the session state to a session APP.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session_id of a session.
 * @param  session_state                 The state of a session.
 **/
void libspdm_trigger_session_state_callback(libspdm_context_t *spdm_context,
                                            uint32_t session_id,
                                            libspdm_session_state_t session_state)
{
    size_t index;

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
void libspdm_set_session_state(libspdm_context_t *spdm_context,
                               uint32_t session_id,
                               libspdm_session_state_t session_state)
{
    libspdm_session_info_t *session_info;
    libspdm_session_state_t old_session_state;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return;
    }

    old_session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (old_session_state != session_state) {
        libspdm_secured_message_set_session_state(
            session_info->secured_message_context, session_state);
        libspdm_trigger_session_state_callback(
            spdm_context, session_info->session_id, session_state);
    }
}

/**
 * Notify the connection state to an SPDM context register.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 **/
void libspdm_trigger_connection_state_callback(libspdm_context_t *spdm_context,
                                               const libspdm_connection_state_t
                                               connection_state)
{
    size_t index;

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
void libspdm_set_connection_state(libspdm_context_t *spdm_context,
                                  libspdm_connection_state_t connection_state)
{
    if (spdm_context->connection_info.connection_state !=
        connection_state) {
        spdm_context->connection_info.connection_state =
            connection_state;
        libspdm_trigger_connection_state_callback(spdm_context,
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
libspdm_return_t libspdm_build_response(void *context, const uint32_t *session_id,
                                        bool is_app_message,
                                        size_t *response_size,
                                        void **response)
{
    libspdm_context_t *spdm_context;
    uint8_t *my_response;
    size_t my_response_size;
    libspdm_return_t status;
    libspdm_get_spdm_response_func get_response_func;
    libspdm_session_info_t *session_info;
    spdm_message_header_t *spdm_request;
    spdm_message_header_t *spdm_response;
    bool result;
    size_t transport_header_size;

    spdm_context = context;
    status = LIBSPDM_STATUS_UNSUPPORTED_CAP;

    /* For secure message, setup my_response to scratch buffer
     * For non-secure message, setup my_response to sender buffer*/
    if (session_id != NULL) {
        libspdm_get_scratch_buffer (spdm_context, (void **)&my_response, &my_response_size);
    } else {
        transport_header_size = spdm_context->transport_get_header_size(spdm_context);
        my_response = (uint8_t *)*response + transport_header_size;
        my_response_size = *response_size - transport_header_size;
    }
    libspdm_zero_mem(my_response, my_response_size);

    if (spdm_context->last_spdm_error.error_code != 0) {

        /* Error in libspdm_process_request(), and we need send error message directly.*/

        switch (spdm_context->last_spdm_error.error_code) {
        case SPDM_ERROR_CODE_DECRYPT_ERROR:
            /* session ID is valid. Use it to encrypt the error message.*/
            if((spdm_context->handle_error_return_policy &
                LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR) == 0) {
                status = libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
                    &my_response_size, my_response);
            } else {
                /**
                 * just ignore this message
                 * return UNSUPPORTED and clear response_size to continue the dispatch without send response
                 **/
                *response_size = 0;
                status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
            }
            break;
        case SPDM_ERROR_CODE_INVALID_SESSION:
            /**
             * don't use session ID, because we dont know which right session ID should be used.
             * just ignore this message
             * return UNSUPPORTED and clear response_size to continue the dispatch without send response
             **/
            *response_size = 0;
            status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
            break;
        default:
            LIBSPDM_ASSERT(false);
            status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }

        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmSendResponse[%x] (0x%x): \n",
                       (session_id != NULL) ? *session_id : 0,
                       my_response_size));
        libspdm_internal_dump_hex(my_response, my_response_size);

        status = spdm_context->transport_encode_message(
            spdm_context, session_id, false, false,
            my_response_size, my_response, response_size, response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_encode_message : %p\n",
                           status));
            return status;
        }

        libspdm_zero_mem(&spdm_context->last_spdm_error,
                         sizeof(spdm_context->last_spdm_error));
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }

    if (*response == NULL) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (response_size == NULL) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (*response_size == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmSendResponse[%x] ...\n",
                   (session_id != NULL) ? *session_id : 0));

    spdm_request = (void *)spdm_context->last_spdm_request;
    if (spdm_context->last_spdm_request_size == 0) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    get_response_func = NULL;
    if (!is_app_message) {
        get_response_func =
            libspdm_get_response_func_via_last_request(spdm_context);
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
            status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }

    if ((spdm_context->connection_info.capability.data_transfer_size != 0) &&
        (my_response_size > spdm_context->connection_info.capability.data_transfer_size)) {
        status = libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_LARGE_RESPONSE,
            spdm_request->request_response_code, &my_response_size,
            my_response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    /* if return the status: Responder drop the response
     * just ignore this message
     * return UNSUPPORTED and clear response_size to continue the dispatch without send response.*/
    if((my_response_size == 0) && (status == LIBSPDM_STATUS_UNSUPPORTED_CAP)) {
        *response_size = 0;
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        status = libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            spdm_request->request_response_code, &my_response_size,
            my_response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmSendResponse[%x] (0x%x): \n",
                   (session_id != NULL) ? *session_id : 0, my_response_size));
    libspdm_internal_dump_hex(my_response, my_response_size);

    status = spdm_context->transport_encode_message(
        spdm_context, session_id, is_app_message, false,
        my_response_size, my_response, response_size, response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_encode_message : %p\n", status));
        return status;
    }

    spdm_response = (void *)my_response;
    if (session_id != NULL) {
        switch (spdm_response->request_response_code) {
        case SPDM_FINISH_RSP:
            if (!libspdm_is_capabilities_flag_supported(
                    spdm_context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
                libspdm_set_session_state(
                    spdm_context, *session_id,
                    LIBSPDM_SESSION_STATE_ESTABLISHED);
            }
            break;
        case SPDM_PSK_FINISH_RSP:
            libspdm_set_session_state(spdm_context, *session_id,
                                      LIBSPDM_SESSION_STATE_ESTABLISHED);
            break;
        case SPDM_END_SESSION_ACK:
            libspdm_set_session_state(spdm_context, *session_id,
                                      LIBSPDM_SESSION_STATE_NOT_STARTED);
            result = libspdm_stop_watchdog(*session_id);
            if (!result) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_stop_watchdog error\n"));
                /* No need return error for internal watchdog error */
            }
            libspdm_free_session_id(spdm_context, *session_id);
            break;
        default:
            /* reset watchdog in any session messages. */
            result = libspdm_reset_watchdog(*session_id);
            if (!result) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_reset_watchdog error\n"));
                /* No need return error for internal watchdog error */
            }
            break;
        }
    } else {
        switch (spdm_response->request_response_code) {
        case SPDM_FINISH_RSP:
            if (libspdm_is_capabilities_flag_supported(
                    spdm_context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
                libspdm_set_session_state(
                    spdm_context,
                    spdm_context->latest_session_id,
                    LIBSPDM_SESSION_STATE_ESTABLISHED);
            }
            break;
        default:
            /* No session state update needed */
            break;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
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
    void *context, libspdm_get_response_func get_response_func)
{
    libspdm_context_t *spdm_context;

    spdm_context = context;
    spdm_context->get_response_func = (size_t)get_response_func;

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
libspdm_return_t libspdm_register_session_state_callback_func(
    void *context,
    libspdm_session_state_callback_func spdm_session_state_callback)
{
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_context = context;
    for (index = 0; index < LIBSPDM_MAX_SESSION_STATE_CALLBACK_NUM; index++) {
        if (spdm_context->spdm_session_state_callback[index] == 0) {
            spdm_context->spdm_session_state_callback[index] =
                (size_t)spdm_session_state_callback;
            return LIBSPDM_STATUS_SUCCESS;
        }
    }
    LIBSPDM_ASSERT(false);

    return LIBSPDM_STATUS_BUFFER_FULL;
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
libspdm_return_t libspdm_register_connection_state_callback_func(
    void *context,
    libspdm_connection_state_callback_func spdm_connection_state_callback)
{
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_context = context;
    for (index = 0; index < LIBSPDM_MAX_CONNECTION_STATE_CALLBACK_NUM;
         index++) {
        if (spdm_context->spdm_connection_state_callback[index] == 0) {
            spdm_context->spdm_connection_state_callback[index] =
                (size_t)spdm_connection_state_callback;
            return LIBSPDM_STATUS_SUCCESS;
        }
    }
    LIBSPDM_ASSERT(false);

    return LIBSPDM_STATUS_BUFFER_FULL;
}
