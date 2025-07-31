/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP)

libspdm_return_t libspdm_get_encap_request_send_event(
    libspdm_context_t *spdm_context,
    size_t *encap_request_size,
    void *encap_request)
{
    spdm_send_event_request_t *spdm_request;
    uint32_t session_id;
    uint32_t event_count;
    size_t events_list_size;

    spdm_request = encap_request;

    if (spdm_context->last_spdm_request_session_id_valid) {
        libspdm_session_info_t *session_info;
        libspdm_session_state_t session_state;

        session_id = spdm_context->last_spdm_request_session_id;
        session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);

        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);

        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    } else {
        return LIBSPDM_STATUS_ERROR_PEER;
    }

    spdm_request->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request->header.request_response_code = SPDM_SEND_EVENT;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;

    events_list_size = *encap_request_size - sizeof(spdm_send_event_request_t);

    if (!libspdm_generate_event_list(spdm_context, libspdm_get_connection_version(spdm_context),
                                     session_id, &event_count, &events_list_size,
                                     (uint8_t *)(spdm_request + 1))) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    LIBSPDM_ASSERT(event_count != 0);
    LIBSPDM_ASSERT(events_list_size != 0);

    spdm_request->event_count = event_count;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_event_ack(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    libspdm_return_t status;
    const spdm_event_ack_response_t *spdm_response;
    size_t spdm_response_size;
    uint32_t session_id;

    if (spdm_context->last_spdm_request_session_id_valid) {
        libspdm_session_info_t *session_info;
        libspdm_session_state_t session_state;

        session_id = spdm_context->last_spdm_request_session_id;
        session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);

        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);

        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    } else {
        return LIBSPDM_STATUS_ERROR_PEER;
    }

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    if (spdm_response->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(
            spdm_context, spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code != SPDM_EVENT_ACK) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response_size != sizeof(spdm_event_ack_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    *need_continue = false;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP) */
