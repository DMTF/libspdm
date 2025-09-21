/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP

static libspdm_return_t libspdm_try_send_event(
    libspdm_context_t *spdm_context, uint32_t session_id,
    uint32_t event_count, size_t events_list_size, void *events_list)
{
    libspdm_return_t status;
    libspdm_session_info_t *session_info;
    spdm_send_event_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_event_ack_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    uint8_t *message;
    size_t message_size;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(event_count != 0);
    LIBSPDM_ASSERT(events_list_size != 0);
    LIBSPDM_ASSERT(events_list != NULL);

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);

    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    if (libspdm_secured_message_get_session_state(session_info->secured_message_context) !=
        LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    /* -=[Verify State Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    if (spdm_request_size < sizeof(spdm_send_event_request_t) + events_list_size) {
        libspdm_release_sender_buffer(spdm_context);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    spdm_request->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request->header.request_response_code = SPDM_SEND_EVENT;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->event_count = event_count;

    libspdm_copy_mem(spdm_request + 1, spdm_request_size - sizeof(spdm_send_event_request_t),
                     events_list, events_list_size);

    spdm_request_size = sizeof(spdm_send_event_request_t) + events_list_size;

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, &session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }

    libspdm_release_sender_buffer(spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer(spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(
        spdm_context, &session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size != sizeof(spdm_event_ack_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, &session_id,
            &spdm_response_size, (void **)&spdm_response,
            SPDM_SEND_EVENT, SPDM_EVENT_ACK);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_EVENT_ACK) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

receive_done:
    libspdm_release_receiver_buffer(spdm_context);

    return status;
}

libspdm_return_t libspdm_send_event(void *spdm_context, uint32_t session_id, uint32_t event_count,
                                    size_t events_list_size, void *events_list)
{
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;
    libspdm_context_t *context;

    context = spdm_context;
    context->crypto_request = false;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;

    do {
        status = libspdm_try_send_event(context, session_id, event_count, events_list_size,
                                        events_list);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
