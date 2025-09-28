/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

 #include "internal/libspdm_requester_lib.h"

 #if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT)

libspdm_return_t libspdm_get_encap_response_event_ack(void *spdm_context,
                                                      size_t request_size,
                                                      void *request,
                                                      size_t *response_size,
                                                      void *response)
{
    spdm_send_event_request_t *spdm_request;
    spdm_event_ack_response_t *spdm_response;
    libspdm_context_t *context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint64_t index;
    uint32_t prev_event_instance_id;
    uint32_t event_instance_id_min;
    uint32_t event_instance_id_max;
    bool events_list_is_sequential;
    uint8_t *ptr;
    const uint8_t *end_ptr = (uint8_t *)request + request_size;
    size_t calculated_request_size;

    context = spdm_context;
    spdm_request = request;

    if (libspdm_get_connection_version(context) < SPDM_MESSAGE_VERSION_13) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_SEND_EVENT, response_size, response);
    }
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(context)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_VERSION_MISMATCH, 0, response_size, response);
    }
    if (!libspdm_is_capabilities_flag_supported(
            context, true, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_SEND_EVENT, response_size, response);
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

    libspdm_reset_message_buffer_via_request_code(context, NULL,
                                                  spdm_request->header.request_response_code);

    if (!libspdm_check_for_space((uint8_t *)request, end_ptr, sizeof(spdm_send_event_request_t))) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    }

    if (spdm_request->event_count == 0) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    }

    ptr = (uint8_t *)(spdm_request + 1);

    event_instance_id_min = UINT32_MAX;
    event_instance_id_max = 0;
    events_list_is_sequential = true;

    calculated_request_size = sizeof(spdm_send_event_request_t);

    /* Parse and validate all events for size and fields. */
    for (index = 0; index < spdm_request->event_count; index++) {
        uint32_t event_instance_id;
        uint8_t svh_id;
        uint8_t svh_vendor_id_len;
        uint16_t event_type_id;
        uint16_t event_detail_len;

        if (!libspdm_check_for_space(ptr, end_ptr,
                                     sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                                     sizeof(uint8_t))) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        }

        event_instance_id = libspdm_read_uint32(ptr);

        if ((index != 0) && events_list_is_sequential) {
            if (event_instance_id != (prev_event_instance_id + 1)) {
                events_list_is_sequential = false;
            }
        }
        if (event_instance_id < event_instance_id_min) {
            event_instance_id_min = event_instance_id;
        }
        if (event_instance_id > event_instance_id_max) {
            event_instance_id_max = event_instance_id;
        }
        prev_event_instance_id = event_instance_id;

        ptr += sizeof(uint32_t) + sizeof(uint32_t);
        svh_id = *ptr;
        ptr += sizeof(uint8_t);
        svh_vendor_id_len = *ptr;
        ptr += sizeof(uint8_t);

        if (!libspdm_validate_svh_vendor_id_len(svh_id, svh_vendor_id_len)) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        }

        if (!libspdm_check_for_space(
                ptr, end_ptr, (size_t)svh_vendor_id_len + sizeof(uint16_t) + sizeof(uint16_t))) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        }

        ptr += svh_vendor_id_len;

        event_type_id = libspdm_read_uint16(ptr);
        ptr += sizeof(uint16_t);
        event_detail_len = libspdm_read_uint16(ptr);
        ptr += sizeof(uint16_t);

        if (svh_id == SPDM_REGISTRY_ID_DMTF) {
            if (!libspdm_validate_dmtf_event_type(event_type_id, event_detail_len)) {
                return libspdm_generate_encap_error_response(
                    context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
            }
        }

        if (!libspdm_check_for_space(ptr, end_ptr, (size_t)event_detail_len)) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        }

        ptr += event_detail_len;
        calculated_request_size += sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                                   sizeof(uint8_t) + (size_t)svh_vendor_id_len + sizeof(uint16_t) +
                                   sizeof(uint16_t) + (size_t)event_detail_len;
    }

    /* Event must be sent in a secure session so message size can be calculated exactly. */
    if (request_size != calculated_request_size) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    }

    /* If event instance IDs are not sequential then ensure there are no gaps or duplicates before
     * sending individual events to Integrator. */
    if (!events_list_is_sequential) {
        void *event_data = spdm_request + 1;

        if ((event_instance_id_max - event_instance_id_min + 1) != spdm_request->event_count) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        }

        for (index = 0; index < spdm_request->event_count; index++) {
            if (libspdm_find_event_instance_id(event_data, spdm_request->event_count,
                                               event_instance_id_min + (uint32_t)index) == NULL) {
                return libspdm_generate_encap_error_response(
                    context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
            }
        }
    }

    if (context->process_event != NULL) {
        const void *next_event_data = spdm_request + 1;

        for (index = 0; index < spdm_request->event_count; index++) {
            if (events_list_is_sequential) {
                if (!libspdm_parse_and_send_event(
                        context, session_id, next_event_data, &next_event_data)) {
                    return libspdm_generate_encap_error_response(
                        context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
                }
            } else {
                const void *event_data;

                event_data = libspdm_find_event_instance_id(
                    next_event_data, spdm_request->event_count,
                    event_instance_id_min + (uint32_t)index);
                if (event_data == NULL) {
                    return libspdm_generate_encap_error_response(
                        context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
                }

                if (!libspdm_parse_and_send_event(context, session_id, event_data, NULL)) {
                    return libspdm_generate_encap_error_response(
                        context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
                }
            }
        }
    }

    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_EVENT_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    *response_size = sizeof(spdm_event_ack_response_t);

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT) */
