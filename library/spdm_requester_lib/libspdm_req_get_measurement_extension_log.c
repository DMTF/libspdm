/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint32_t portion_length;
    uint32_t remainder_length;
    uint8_t measure_exten_log[LIBSPDM_MAX_MEL_BLOCK_LEN];
} libspdm_measurement_extension_log_response_max_t;
#pragma pack()

/**
 * This function sends GET_MEASUREMENT_EXTENSION_LOG and receives MEASUREMENT_EXTENSION_LOG.
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  session_id                 Indicates if it is a secured message protected via SPDM session.
 *                                    If session_id is NULL, it is a normal message.
 *                                    If session_id is not NULL, it is a secured message.
 * @param  length                     The len of get MEL in every time.
 * @param  mel_size                   On input, indicate the size in bytes of the destination buffer to store.
 *                                    On output, indicate the size in bytes of the MEL.
 * @param  measure_exten_log          A pointer to a destination buffer to store the MEL.
 *
 **/
static libspdm_return_t libspdm_try_get_measurement_extension_log(libspdm_context_t *spdm_context,
                                                                  const uint32_t *session_id,
                                                                  uint32_t length,
                                                                  size_t *mel_size,
                                                                  void *measure_exten_log)
{
    libspdm_return_t status;
    spdm_get_measurement_extension_log_request_t *spdm_request;
    size_t spdm_request_size;
    libspdm_measurement_extension_log_response_max_t *spdm_response;
    size_t spdm_response_size;
    uint32_t total_responder_mel_buffer_length;
    size_t mel_capacity;
    size_t mel_size_internal;
    uint32_t remainder_length;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(mel_size != NULL);
    LIBSPDM_ASSERT(*mel_size > 0);
    LIBSPDM_ASSERT(measure_exten_log != NULL);

    /* -=[Verify State Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  SPDM_GET_MEASUREMENT_EXTENSION_LOG);

    remainder_length = 0;
    total_responder_mel_buffer_length = 0;
    mel_capacity = *mel_size;
    mel_size_internal = 0;

    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    do {
        /* -=[Construct Request Phase]=- */
        status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        LIBSPDM_ASSERT (message_size >= transport_header_size +
                        spdm_context->local_context.capability.transport_tail_size);
        spdm_request = (void *)(message + transport_header_size);
        spdm_request_size = message_size - transport_header_size -
                            spdm_context->local_context.capability.transport_tail_size;

        spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
        spdm_request->header.request_response_code = SPDM_GET_MEASUREMENT_EXTENSION_LOG;
        spdm_request->header.param1 = 0;
        spdm_request->header.param2 = 0;
        spdm_request->offset = (uint32_t)mel_size_internal;
        if (spdm_request->offset == 0) {
            spdm_request->length = length;
        } else {
            spdm_request->length = LIBSPDM_MIN(length, remainder_length);
        }
        spdm_request_size = sizeof(spdm_get_measurement_extension_log_request_t);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "request (offset 0x%x, size 0x%x):\n",
                       spdm_request->offset, spdm_request->length));

        /* -=[Send Request Phase]=- */
        status =
            libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_release_sender_buffer (spdm_context);
            status = LIBSPDM_STATUS_SEND_FAIL;
            goto done;
        }
        libspdm_release_sender_buffer (spdm_context);
        spdm_request = (void *)spdm_context->last_spdm_request;

        /* -=[Receive Response Phase]=- */
        status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        LIBSPDM_ASSERT (message_size >= transport_header_size);
        spdm_response = (void *)(message);
        spdm_response_size = message_size;

        status = libspdm_receive_spdm_response(spdm_context, session_id,
                                               &spdm_response_size,
                                               (void **)&spdm_response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_RECEIVE_FAIL;
            goto done;
        }

        /* -=[Validate Response Phase]=- */
        if (spdm_response_size < sizeof(spdm_message_header_t)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto done;
        }
        if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_response->header.request_response_code == SPDM_ERROR) {
            status = libspdm_handle_error_response_main(
                spdm_context, session_id,
                &spdm_response_size,
                (void **)&spdm_response, SPDM_GET_MEASUREMENT_EXTENSION_LOG,
                SPDM_MEASUREMENT_EXTENSION_LOG);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_release_receiver_buffer (spdm_context);
                goto done;
            }
        } else if (spdm_response->header.request_response_code != SPDM_MEASUREMENT_EXTENSION_LOG) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_response_size < sizeof(spdm_measurement_extension_log_response_t)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto done;
        }
        if ((spdm_response->portion_length > spdm_request->length) ||
            (spdm_response->portion_length == 0)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_response_size < sizeof(spdm_measurement_extension_log_response_t) +
            spdm_response->portion_length) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto done;
        }
        if (spdm_response->portion_length > 0xFFFFFFFF - spdm_request->offset) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_response->remainder_length > 0xFFFFFFFF - spdm_request->offset -
            spdm_response->portion_length) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_request->offset == 0) {
            total_responder_mel_buffer_length = spdm_response->portion_length +
                                                spdm_response->remainder_length;
        } else if (spdm_request->offset + spdm_response->portion_length +
                   spdm_response->remainder_length < total_responder_mel_buffer_length) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }

        /* -=[Process Response Phase]=- */
        remainder_length = spdm_response->remainder_length;
        spdm_response_size = sizeof(spdm_measurement_extension_log_response_t) +
                             spdm_response->portion_length;

        if (mel_size_internal + spdm_response->portion_length > mel_capacity) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_BUFFER_FULL;
            goto done;
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "MEL (offset 0x%x, size 0x%x):\n",
                       spdm_request->offset, spdm_response->portion_length));
        LIBSPDM_INTERNAL_DUMP_HEX(spdm_response->measure_exten_log, spdm_response->portion_length);

        libspdm_copy_mem((uint8_t *)measure_exten_log + mel_size_internal,
                         mel_capacity - mel_size_internal,
                         spdm_response->measure_exten_log,
                         spdm_response->portion_length);

        mel_size_internal += spdm_response->portion_length;

        /* -=[Log Message Phase]=- */
        #if LIBSPDM_ENABLE_MSG_LOG
        libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
        #endif /* LIBSPDM_ENABLE_MSG_LOG */

        libspdm_release_receiver_buffer (spdm_context);
        measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)measure_exten_log;
    } while (mel_size_internal < sizeof(spdm_measurement_extension_log_dmtf_t) +
             measurement_extension_log->mel_entries_len);

    *mel_size = mel_size_internal;
    LIBSPDM_ASSERT(*mel_size <= SPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE);

    status = LIBSPDM_STATUS_SUCCESS;

done:
    return status;
}

libspdm_return_t libspdm_get_measurement_extension_log(void *spdm_context,
                                                       const uint32_t *session_id,
                                                       size_t *mel_size,
                                                       void *measure_exten_log)
{
    return libspdm_get_measurement_extension_log_choose_length(spdm_context, session_id,
                                                               LIBSPDM_MAX_MEL_BLOCK_LEN,
                                                               mel_size, measure_exten_log);
}

libspdm_return_t libspdm_get_measurement_extension_log_choose_length(void *spdm_context,
                                                                     const uint32_t *session_id,
                                                                     uint32_t length,
                                                                     size_t *mel_size,
                                                                     void *measure_exten_log)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_get_measurement_extension_log(context, session_id,
                                                           length,
                                                           mel_size, measure_exten_log);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
