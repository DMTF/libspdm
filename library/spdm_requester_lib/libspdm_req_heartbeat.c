/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t dummy_data[sizeof(spdm_error_data_response_not_ready_t)];
} spdm_heartbeat_response_mine_t;

#pragma pack()

/**
 * This function sends HEARTBEAT
 * to an SPDM Session.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session ID of the session.
 *
 * @retval RETURN_SUCCESS               The heartbeat is sent and received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status try_spdm_heartbeat(IN void *context, IN uint32_t session_id)
{
    return_status status;
    spdm_heartbeat_request_t spdm_request;
    spdm_heartbeat_response_mine_t spdm_response;
    uintn spdm_response_size;
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    spdm_context = context;
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, TRUE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP)) {
        return RETURN_UNSUPPORTED;
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return RETURN_UNSUPPORTED;
    }
    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        ASSERT(FALSE);
        return RETURN_UNSUPPORTED;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return RETURN_UNSUPPORTED;
    }

    spdm_request.header.spdm_version = spdm_get_connection_version (spdm_context);
    spdm_request.header.request_response_code = SPDM_HEARTBEAT;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    status = spdm_send_spdm_request(spdm_context, &session_id,
                                    sizeof(spdm_request), &spdm_request);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }

    spdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                               SPDM_HEARTBEAT);

    spdm_response_size = sizeof(spdm_response);
    zero_mem(&spdm_response, sizeof(spdm_response));
    status = spdm_receive_spdm_response(
        spdm_context, &session_id, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = spdm_handle_error_response_main(
            spdm_context, &session_id, &spdm_response_size,
            &spdm_response, SPDM_HEARTBEAT, SPDM_HEARTBEAT_ACK,
            sizeof(spdm_heartbeat_response_mine_t));
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else if (spdm_response.header.request_response_code !=
               SPDM_HEARTBEAT_ACK) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size != sizeof(spdm_heartbeat_response_t)) {
        return RETURN_DEVICE_ERROR;
    }

    return RETURN_SUCCESS;
}

return_status libspdm_heartbeat(IN void *context, IN uint32_t session_id)
{
    uintn retry;
    return_status status;
    spdm_context_t *spdm_context;

    spdm_context = context;
    retry = spdm_context->retry_times;
    do {
        status = try_spdm_heartbeat(spdm_context, session_id);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
