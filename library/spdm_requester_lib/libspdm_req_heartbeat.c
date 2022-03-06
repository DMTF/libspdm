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
} libspdm_heartbeat_response_mine_t;

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
return_status libspdm_try_heartbeat(void *context, uint32_t session_id)
{
    return_status status;
    spdm_heartbeat_request_t *spdm_request;
    uintn spdm_request_size;
    libspdm_heartbeat_response_mine_t *spdm_response;
    uintn spdm_response_size;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t *message;
    uintn message_size;
    uintn transport_header_size;

    spdm_context = context;
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
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
        LIBSPDM_ASSERT(false);
        return RETURN_UNSUPPORTED;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return RETURN_UNSUPPORTED;
    }

    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_HEARTBEAT;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request_size = sizeof(spdm_heartbeat_request_t);
    status = libspdm_send_spdm_request(spdm_context, &session_id,
                                       spdm_request_size, spdm_request);
    if (RETURN_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context, message);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context, message);
    spdm_request = (void *)spdm_context->last_spdm_request;

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  SPDM_HEARTBEAT);

    /* receive */

    libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(
        spdm_context, &session_id, &spdm_response_size, (void **)&spdm_response);
    if (RETURN_ERROR(status)) {
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, &session_id, &spdm_response_size,
            (void **)&spdm_response, SPDM_HEARTBEAT, SPDM_HEARTBEAT_ACK,
            sizeof(libspdm_heartbeat_response_mine_t));
        if (RETURN_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_HEARTBEAT_ACK) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response_size != sizeof(spdm_heartbeat_response_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    status = RETURN_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context, message);
    return status;
}

return_status libspdm_heartbeat(void *context, uint32_t session_id)
{
    uintn retry;
    return_status status;
    libspdm_context_t *spdm_context;

    spdm_context = context;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_heartbeat(spdm_context, session_id);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
