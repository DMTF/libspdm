/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"

libspdm_return_t libspdm_send_request(void *spdm_context, const uint32_t *session_id,
                                      bool is_app_message,
                                      size_t request_size, void *request)
{
    libspdm_context_t *context;
    libspdm_return_t status;
    uint8_t *message;
    size_t message_size;
    uint64_t timeout;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    size_t transport_header_size;
    uint8_t *sender_buffer;
    size_t sender_buffer_size;

    context = spdm_context;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "libspdm_send_spdm_request[%x] msg %s(0x%x), size (0x%zx): \n",
                   (session_id != NULL) ? *session_id : 0x0,
                   libspdm_get_code_str(((spdm_message_header_t *)request)->
                                        request_response_code),
                   ((spdm_message_header_t *)request)->request_response_code,
                   request_size));
    LIBSPDM_INTERNAL_DUMP_HEX(request, request_size);

    transport_header_size = context->local_context.capability.transport_header_size;
    libspdm_get_scratch_buffer(context, (void**) &scratch_buffer, &scratch_buffer_size);
    libspdm_get_sender_buffer(context, (void**) &sender_buffer, &sender_buffer_size);

    /* This is a problem because original code assumes request is in the sender buffer,
     * when it can really be using the scratch space for chunking.
     * Did not want to modify ally request handlers to pass this information,
     * so just making the determination here by examining scratch/sender buffers.
     * This may be something that should be refactored in the future. */
    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    if ((uint8_t*) request >= sender_buffer &&
        (uint8_t*)request < sender_buffer + sender_buffer_size) {
        message = sender_buffer;
        message_size = sender_buffer_size;
    } else {
        if ((uint8_t*)request >=
            scratch_buffer + libspdm_get_scratch_buffer_sender_receiver_offset(spdm_context)
            && (uint8_t*)request <
            scratch_buffer + libspdm_get_scratch_buffer_sender_receiver_offset(spdm_context)
            + libspdm_get_scratch_buffer_sender_receiver_capacity(spdm_context)) {
            message = scratch_buffer +
                      libspdm_get_scratch_buffer_sender_receiver_offset(spdm_context);
            message_size = libspdm_get_scratch_buffer_sender_receiver_capacity(spdm_context);
        } else if ((uint8_t*)request >=
                   scratch_buffer +
                   libspdm_get_scratch_buffer_large_sender_receiver_offset(spdm_context)
                   && (uint8_t*)request <
                   scratch_buffer +
                   libspdm_get_scratch_buffer_large_sender_receiver_offset(spdm_context) +
                   libspdm_get_scratch_buffer_large_sender_receiver_capacity(spdm_context)) {
            message = scratch_buffer +
                      libspdm_get_scratch_buffer_large_sender_receiver_offset(spdm_context);
            message_size = libspdm_get_scratch_buffer_large_sender_receiver_capacity(spdm_context);
        }
    }
    #else /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
    message = sender_buffer;
    message_size = sender_buffer_size;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

    if (session_id != NULL) {
        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */

        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          request, request_size);
        request = scratch_buffer + transport_header_size;
    }

    /* backup it to last_spdm_request, because the caller wants to compare it with response */
    if (((const spdm_message_header_t *)request)->request_response_code != SPDM_RESPOND_IF_READY
        && ((const spdm_message_header_t *)request)->request_response_code != SPDM_CHUNK_GET
        && ((const spdm_message_header_t*) request)->request_response_code != SPDM_CHUNK_SEND) {
        libspdm_copy_mem (context->last_spdm_request,
                          libspdm_get_scratch_buffer_last_spdm_request_capacity(context),
                          request,
                          request_size
                          );
        context->last_spdm_request_size = request_size;
    }

    status = context->transport_encode_message(
        context, session_id, is_app_message, true, request_size,
        request, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_encode_message status - %xu\n",
                       status));
        if ((session_id != NULL) &&
            ((status == LIBSPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW) ||
             (status == LIBSPDM_STATUS_CRYPTO_ERROR))) {
            libspdm_free_session_id(context, *session_id);
        }
        return status;
    }

    timeout = context->local_context.capability.rtt;

    status = context->send_message(context, message_size, message,
                                   timeout);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_send_spdm_request[%x] status - %xu\n",
                       (session_id != NULL) ? *session_id : 0x0, status));
    }

    return status;
}

libspdm_return_t libspdm_receive_response(void *spdm_context, const uint32_t *session_id,
                                          bool is_app_message,
                                          size_t *response_size,
                                          void **response)
{
    libspdm_context_t *context;
    void *temp_session_context;
    libspdm_return_t status;
    uint8_t *message;
    size_t message_size;
    uint32_t *message_session_id;
    bool is_message_app_message;
    uint64_t timeout;
    size_t transport_header_size;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    void *backup_response;
    size_t backup_response_size;
    bool reset_key_update;
    bool result;

    context = spdm_context;

    if (context->crypto_request) {
        timeout = context->local_context.capability.rtt +
                  ((uint64_t)1 << context->connection_info.capability.ct_exponent);
    } else {
        timeout = context->local_context.capability.rtt +
                  context->local_context.capability.st1;
    }

    message = *response;
    message_size = *response_size;
    status = context->receive_message(context, &message_size,
                                      (void **)&message, timeout);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_receive_spdm_response[%x] status - %xu\n",
                       (session_id != NULL) ? *session_id : 0x0, status));
        return status;
    }

    message_session_id = NULL;
    is_message_app_message = false;

    /* always use scratch buffer to response.
     * if it is secured message, this scratch buffer will be used.
     * if it is normal message, the response ptr will point to receiver buffer. */
    transport_header_size = context->local_context.capability.transport_header_size;
    libspdm_get_scratch_buffer (context, (void **)&scratch_buffer, &scratch_buffer_size);
    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    *response = scratch_buffer + libspdm_get_scratch_buffer_secure_message_offset(context) +
                transport_header_size;
    *response_size = libspdm_get_scratch_buffer_secure_message_capacity(context) -
                     transport_header_size;
    #else
    *response = scratch_buffer + transport_header_size;
    *response_size = scratch_buffer_size - transport_header_size;
    #endif

    backup_response = *response;
    backup_response_size = *response_size;

    status = context->transport_decode_message(
        context, &message_session_id, &is_message_app_message,
        false, message_size, message, response_size, response);

    reset_key_update = false;
    temp_session_context = NULL;

    if (status == LIBSPDM_STATUS_SESSION_TRY_DISCARD_KEY_UPDATE) {
        /* Failed to decode, but have backup keys. Try rolling back before aborting.
         * message_session_id must be valid for us to have attempted decryption. */
        if (message_session_id == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        temp_session_context = libspdm_get_secured_message_context_via_session_id(
            context, *message_session_id);
        if (temp_session_context == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        result = libspdm_activate_update_session_data_key(
            temp_session_context, LIBSPDM_KEY_UPDATE_ACTION_RESPONDER, false);
        if (!result) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        /* Retry decoding message with backup Requester key.
         * Must reset some of the parameters in case they were modified */
        message_session_id = NULL;
        is_message_app_message = false;
        *response = backup_response;
        *response_size = backup_response_size;
        status = context->transport_decode_message(
            context, &message_session_id, &is_message_app_message,
            false, message_size, message, response_size, response);

        reset_key_update = true;
    }

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

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        if ((session_id != NULL) &&
            (context->last_spdm_error.error_code == SPDM_ERROR_CODE_DECRYPT_ERROR)) {
            libspdm_free_session_id(context, *session_id);
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_receive_spdm_response[%x] status - %xu\n",
                       (session_id != NULL) ? *session_id : 0x0, status));
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_receive_spdm_response[%x] msg %s(0x%x), size (0x%zx): \n",
                       (session_id != NULL) ? *session_id : 0x0,
                       libspdm_get_code_str(((spdm_message_header_t *)*response)->
                                            request_response_code),
                       ((spdm_message_header_t *)*response)->request_response_code,
                       *response_size));
        LIBSPDM_INTERNAL_DUMP_HEX(*response, *response_size);
    }

    /* Handle special case:
     * If the Responder returns RESPONSE_NOT_READY error to KEY_UPDATE, the Requester needs
     * to activate backup key to parse the error. Then later the Responder will return SUCCESS,
     * the Requester needs new key. So we need to restore the environment by
     * libspdm_create_update_session_data_key() again.*/
    if (reset_key_update) {
        /* temp_session_context and message_session_id must necessarily
         * be valid for us to reach here. */
        if (temp_session_context == NULL || message_session_id == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        result = libspdm_create_update_session_data_key(
            temp_session_context, LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
        if (!result) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    return status;

error:
    if (context->last_spdm_error.error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
        return LIBSPDM_STATUS_SESSION_MSG_ERROR;
    } else {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

libspdm_return_t libspdm_send_data(void *spdm_context, const uint32_t *session_id,
                                   bool is_app_message,
                                   const void *request, size_t request_size)
{
    libspdm_return_t status;
    libspdm_context_t *context;
    spdm_message_header_t *spdm_request;
    size_t spdm_request_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;

    context = spdm_context;
    transport_header_size = context->local_context.capability.transport_header_size;

    status = libspdm_acquire_sender_buffer(context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        context->local_context.capability.transport_tail_size;
    libspdm_copy_mem (spdm_request, spdm_request_size, request, request_size);
    spdm_request_size = request_size;

    status = libspdm_send_request(context, session_id, is_app_message,
                                  spdm_request_size, spdm_request);

    libspdm_release_sender_buffer(context);

    return status;
}

libspdm_return_t libspdm_receive_data(void *spdm_context, const uint32_t *session_id,
                                      bool is_app_message,
                                      void *response, size_t *response_size)
{
    libspdm_return_t status;
    libspdm_context_t *context;
    spdm_error_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;

    context = spdm_context;

    status = libspdm_acquire_receiver_buffer(context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_response(context, session_id, is_app_message,
                                      &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_receiver_buffer (context);
        return status;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        if ((spdm_response->header.param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) &&
            (session_id != NULL)) {
            libspdm_free_session_id(context, *session_id);
            libspdm_release_receiver_buffer (context);
            return LIBSPDM_STATUS_SESSION_MSG_ERROR;
        }
    }

    if (*response_size >= spdm_response_size) {
        libspdm_copy_mem (response, *response_size, spdm_response, spdm_response_size);
        *response_size = spdm_response_size;
    } else {
        *response_size = spdm_response_size;
        libspdm_release_receiver_buffer (context);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    libspdm_release_receiver_buffer(context);

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_send_receive_data(void *spdm_context, const uint32_t *session_id,
                                           bool is_app_message,
                                           const void *request, size_t request_size,
                                           void *response, size_t *response_size)
{
    libspdm_return_t status;

    status = libspdm_send_data(spdm_context, session_id, is_app_message, request, request_size);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return libspdm_receive_data(spdm_context, session_id, is_app_message, response, response_size);
}
