/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_secured_message_lib.h"

/**
  Encode a normal message or secured message to a transport message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status mctp_encode_message(IN uint32_t *session_id, IN uintn message_size,
                  IN void *message,
                  IN OUT uintn *transport_message_size,
                  OUT void *transport_message);

/**
  Decode a transport message to a normal message or secured message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status mctp_decode_message(OUT uint32_t **session_id,
                  IN uintn transport_message_size,
                  IN void *transport_message,
                  IN OUT uintn *message_size,
                  OUT void *message);

/**
  Encode a normal message or secured message to a transport message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
typedef return_status (*transport_encode_message_func)(
    IN uint32_t *session_id, IN uintn message_size, IN void *message,
    IN OUT uintn *transport_message_size, OUT void *transport_message);

/**
  Decode a transport message to a normal message or secured message.

  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
typedef return_status (*transport_decode_message_func)(
    OUT uint32_t **session_id, IN uintn transport_message_size,
    IN void *transport_message, IN OUT uintn *message_size,
    OUT void *message);

/**
  Encode an SPDM or APP message to a transport layer message.

  For normal SPDM message, it adds the transport layer wrapper.
  For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
  For secured APP message, it encrypts a secured message then adds the transport layer wrapper.

  The APP message is encoded to a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  is_requester                  Indicates if it is a requester message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a source buffer to store the message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
**/
return_status spdm_transport_mctp_encode_message(
    IN void *spdm_context, IN uint32_t *session_id, IN boolean is_app_message,
    IN boolean is_requester, IN uintn message_size, IN void *message,
    IN OUT uintn *transport_message_size, OUT void *transport_message)
{
    return_status status;
    transport_encode_message_func transport_encode_message;
    uint8_t app_message_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    void *app_message;
    uintn app_message_size;
    uint8_t secured_message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn secured_message_size;
    spdm_secured_message_callbacks_t spdm_secured_message_callbacks_t;
    void *secured_message_context;

    spdm_secured_message_callbacks_t.version =
        SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks_t.get_sequence_number =
        spdm_mctp_get_sequence_number;
    spdm_secured_message_callbacks_t.get_max_random_number_count =
        spdm_mctp_get_max_random_number_count;

    if (is_app_message && (session_id == NULL)) {
        return RETURN_UNSUPPORTED;
    }

    transport_encode_message = mctp_encode_message;
    if (session_id != NULL) {
        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                spdm_context, *session_id);
        if (secured_message_context == NULL) {
            return RETURN_UNSUPPORTED;
        }

        if (!is_app_message) {
            // SPDM message to APP message
            app_message = app_message_buffer;
            app_message_size = sizeof(app_message_buffer);
            status = transport_encode_message(NULL, message_size,
                              message,
                              &app_message_size,
                              app_message_buffer);
            if (RETURN_ERROR(status)) {
                DEBUG((DEBUG_ERROR,
                       "transport_encode_message - %p\n",
                       status));
                return RETURN_UNSUPPORTED;
            }
        } else {
            app_message = message;
            app_message_size = message_size;
        }
        // APP message to secured message
        secured_message_size = sizeof(secured_message);
        status = spdm_encode_secured_message(
            secured_message_context, *session_id, is_requester,
            app_message_size, app_message, &secured_message_size,
            secured_message, &spdm_secured_message_callbacks_t);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_ERROR,
                   "spdm_encode_secured_message - %p\n", status));
            return status;
        }

        // secured message to secured MCTP message
        status = transport_encode_message(
            session_id, secured_message_size, secured_message,
            transport_message_size, transport_message);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_ERROR, "transport_encode_message - %p\n",
                   status));
            return RETURN_UNSUPPORTED;
        }
    } else {
        // SPDM message to normal MCTP message
        status = transport_encode_message(NULL, message_size, message,
                          transport_message_size,
                          transport_message);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_ERROR, "transport_encode_message - %p\n",
                   status));
            return RETURN_UNSUPPORTED;
        }
    }

    return RETURN_SUCCESS;
}

/**
  Decode an SPDM or APP message from a transport layer message.

  For normal SPDM message, it removes the transport layer wrapper,
  For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
  For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.

  The APP message is decoded from a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    Indicates if it is a secured message protected via SPDM session.
                                       If *session_id is NULL, it is a normal message.
                                       If *session_id is NOT NULL, it is a secured message.
  @param  is_app_message                 Indicates if it is an APP message or SPDM message.
  @param  is_requester                  Indicates if it is a requester message.
  @param  transport_message_size         size in bytes of the transport message data buffer.
  @param  transport_message             A pointer to a source buffer to store the transport message.
  @param  message_size                  size in bytes of the message data buffer.
  @param  message                      A pointer to a destination buffer to store the message.

  @retval RETURN_SUCCESS               The message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
  @retval RETURN_UNSUPPORTED           The transport_message is unsupported.
**/
return_status spdm_transport_mctp_decode_message(
    IN void *spdm_context, OUT uint32_t **session_id,
    OUT boolean *is_app_message, IN boolean is_requester,
    IN uintn transport_message_size, IN void *transport_message,
    IN OUT uintn *message_size, OUT void *message)
{
    return_status status;
    transport_decode_message_func transport_decode_message;
    uint32_t *SecuredMessageSessionId;
    uint8_t secured_message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn secured_message_size;
    uint8_t app_message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn app_message_size;
    spdm_secured_message_callbacks_t spdm_secured_message_callbacks_t;
    void *secured_message_context;
    spdm_error_struct_t spdm_error;

    spdm_error.error_code = 0;
    spdm_error.session_id = 0;
    libspdm_set_last_spdm_error_struct(spdm_context, &spdm_error);

    spdm_secured_message_callbacks_t.version =
        SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks_t.get_sequence_number =
        spdm_mctp_get_sequence_number;
    spdm_secured_message_callbacks_t.get_max_random_number_count =
        spdm_mctp_get_max_random_number_count;

    if ((session_id == NULL) || (is_app_message == NULL)) {
        return RETURN_UNSUPPORTED;
    }

    transport_decode_message = mctp_decode_message;

    SecuredMessageSessionId = NULL;
    // Detect received message
    secured_message_size = sizeof(secured_message);
    status = transport_decode_message(
        &SecuredMessageSessionId, transport_message_size,
        transport_message, &secured_message_size, secured_message);
    if (RETURN_ERROR(status)) {
        DEBUG((DEBUG_ERROR, "transport_decode_message - %p\n", status));
        return RETURN_UNSUPPORTED;
    }

    if (SecuredMessageSessionId != NULL) {
        *session_id = SecuredMessageSessionId;

        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                spdm_context, *SecuredMessageSessionId);
        if (secured_message_context == NULL) {
            spdm_error.error_code = SPDM_ERROR_CODE_INVALID_SESSION;
            spdm_error.session_id = *SecuredMessageSessionId;
            libspdm_set_last_spdm_error_struct(spdm_context,
                            &spdm_error);
            return RETURN_UNSUPPORTED;
        }

        // Secured message to APP message
        app_message_size = sizeof(app_message);
        status = spdm_decode_secured_message(
            secured_message_context, *SecuredMessageSessionId,
            is_requester, secured_message_size, secured_message,
            &app_message_size, app_message,
            &spdm_secured_message_callbacks_t);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_ERROR,
                   "spdm_decode_secured_message - %p\n", status));
            spdm_secured_message_get_last_spdm_error_struct(
                secured_message_context, &spdm_error);
            libspdm_set_last_spdm_error_struct(spdm_context,
                            &spdm_error);
            return RETURN_UNSUPPORTED;
        }

        // APP message to SPDM message.
        status = transport_decode_message(&SecuredMessageSessionId,
                          app_message_size, app_message,
                          message_size, message);
        if (RETURN_ERROR(status)) {
            *is_app_message = TRUE;
            // just return APP message.
            if (*message_size < app_message_size) {
                *message_size = app_message_size;
                return RETURN_BUFFER_TOO_SMALL;
            }
            *message_size = app_message_size;
            copy_mem(message, app_message, *message_size);
            return RETURN_SUCCESS;
        } else {
            *is_app_message = FALSE;
            if (SecuredMessageSessionId == NULL) {
                return RETURN_SUCCESS;
            } else {
                // get encapsulated secured message - cannot handle it.
                DEBUG((DEBUG_ERROR,
                       "transport_decode_message - expect encapsulated normal but got session (%08x)\n",
                       *SecuredMessageSessionId));
                return RETURN_UNSUPPORTED;
            }
        }
    } else {
        // get non-secured message
        status = transport_decode_message(&SecuredMessageSessionId,
                          transport_message_size,
                          transport_message,
                          message_size, message);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_ERROR, "transport_decode_message - %p\n",
                   status));
            return RETURN_UNSUPPORTED;
        }
        ASSERT(SecuredMessageSessionId == NULL);
        *session_id = NULL;
        *is_app_message = FALSE;
        return RETURN_SUCCESS;
    }
}
