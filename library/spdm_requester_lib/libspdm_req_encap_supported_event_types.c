/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP)

libspdm_return_t libspdm_get_encap_supported_event_types(void *spdm_context,
                                                         size_t request_size,
                                                         void *request,
                                                         size_t *response_size,
                                                         void *response)
{
    uint32_t session_id;
    spdm_supported_event_types_response_t *spdm_response;
    spdm_get_supported_event_types_request_t *spdm_request;
    const size_t response_buffer_size = *response_size;
    libspdm_context_t *context;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint32_t supported_event_groups_list_len;
    uint8_t event_group_count;

    context = spdm_context;
    spdm_request = request;

    if (libspdm_get_connection_version(context) < SPDM_MESSAGE_VERSION_13) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_SUPPORTED_EVENT_TYPES,
            response_size, response);
    }
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(context)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_VERSION_MISMATCH, 0, response_size, response);
    }
    if (!libspdm_is_capabilities_flag_supported(
            context, true, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP, 0)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_SUPPORTED_EVENT_TYPES,
            response_size, response);
    }
    if (!context->last_spdm_request_session_id_valid) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_SESSION_REQUIRED, 0, response_size, response);
    }

    session_id = context->last_spdm_request_session_id;
    session_info = libspdm_get_session_info_via_session_id(context, session_id);
    if (session_info == NULL) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    }

    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(context, session_info,
                                                  spdm_request->header.request_response_code);

    /* This message can only be in secured session.
     * Thus don't need to consider transport layer padding, just check its exact size. */
    if (request_size != sizeof(spdm_get_supported_event_types_request_t)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    spdm_response = response;

    spdm_response->header.spdm_version = libspdm_get_connection_version(context);
    spdm_response->header.request_response_code = SPDM_SUPPORTED_EVENT_TYPES;
    spdm_response->header.param2 = 0;

    supported_event_groups_list_len = (uint32_t)(response_buffer_size -
                                                 sizeof(spdm_supported_event_types_response_t));

    if (!libspdm_event_get_types(context, context->connection_info.version, session_id,
                                 (void *)(spdm_response + 1), &supported_event_groups_list_len,
                                 &event_group_count)) {
        return libspdm_generate_encap_error_response(context,
                                                     SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                     response_size, response);
    }

    LIBSPDM_ASSERT(supported_event_groups_list_len > 0);
    LIBSPDM_ASSERT(supported_event_groups_list_len <=
                   (response_buffer_size - sizeof(spdm_supported_event_types_response_t)));
    LIBSPDM_ASSERT(event_group_count > 0);

    spdm_response->header.param1 = event_group_count;
    spdm_response->supported_event_groups_list_len = supported_event_groups_list_len;

    *response_size = sizeof(spdm_supported_event_types_response_t) +
                     supported_event_groups_list_len;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP) */
