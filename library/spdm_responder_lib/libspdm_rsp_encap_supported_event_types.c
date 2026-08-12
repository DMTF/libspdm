/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP)

libspdm_return_t libspdm_get_encap_request_get_supported_event_types(
    libspdm_context_t *spdm_context,
    size_t *encap_request_size,
    void *encap_request)
{
    spdm_get_supported_event_types_request_t *spdm_request;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!spdm_context->last_spdm_request_session_id_valid) {
        return LIBSPDM_STATUS_ERROR_PEER;
    }

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

    LIBSPDM_ASSERT(*encap_request_size >= sizeof(spdm_get_supported_event_types_request_t));

    spdm_request = encap_request;

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  SPDM_GET_SUPPORTED_EVENT_TYPES);

    spdm_request->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;

    *encap_request_size = sizeof(spdm_get_supported_event_types_request_t);

    libspdm_copy_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size = *encap_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_supported_event_types(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    libspdm_return_t status;
    const spdm_supported_event_types_response_t *spdm_response;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len;

    if (!spdm_context->last_spdm_request_session_id_valid) {
        return LIBSPDM_STATUS_ERROR_PEER;
    }

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

    spdm_response = encap_response;

    if (encap_response_size < sizeof(spdm_supported_event_types_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    if (spdm_response->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SUPPORTED_EVENT_TYPES) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    event_group_count = spdm_response->header.param1;
    supported_event_groups_list_len = spdm_response->supported_event_groups_list_len;

    if (event_group_count == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (supported_event_groups_list_len == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (encap_response_size != sizeof(spdm_supported_event_types_response_t) +
        supported_event_groups_list_len) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    *need_continue = false;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP) */
