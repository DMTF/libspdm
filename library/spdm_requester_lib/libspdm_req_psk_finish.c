/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_psk_finish_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint8_t dummy_data[sizeof(spdm_error_data_response_not_ready_t)];
} libspdm_psk_finish_response_max_t;

#pragma pack()

/**
 * This function sends PSK_FINISH and receives PSK_FINISH_RSP for SPDM PSK finish.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    session_id to the PSK_FINISH request.
 *
 * @retval RETURN_SUCCESS               The PSK_FINISH is sent and the PSK_FINISH_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_try_send_receive_psk_finish(libspdm_context_t *spdm_context,
                                                  uint32_t session_id)
{
    return_status status;
    libspdm_psk_finish_request_mine_t *spdm_request;
    uintn spdm_request_size;
    uintn hmac_size;
    libspdm_psk_finish_response_max_t *spdm_response;
    uintn spdm_response_size;
    libspdm_session_info_t *session_info;
    uint8_t th2_hash_data[64];
    libspdm_session_state_t session_state;
    bool result;
    uint8_t *message;
    uintn message_size;
    uintn transport_header_size;

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        status = RETURN_UNSUPPORTED;
        goto error;
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        status = RETURN_UNSUPPORTED;
        goto error;
    }

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        status = RETURN_UNSUPPORTED;
        goto error;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_HANDSHAKING) {
        status = RETURN_UNSUPPORTED;
        goto error;
    }

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_PSK_FINISH;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;

    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    spdm_request_size = sizeof(spdm_psk_finish_request_t) + hmac_size;

    status = libspdm_append_message_f(spdm_context, session_info, true, (uint8_t *)spdm_request,
                                      spdm_request_size - hmac_size);
    if (RETURN_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }

    result = libspdm_generate_psk_exchange_req_hmac(spdm_context, session_info,
                                                    spdm_request->verify_data);
    if (!result) {
        libspdm_release_sender_buffer (spdm_context);
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }

    status = libspdm_append_message_f(spdm_context, session_info, true,
                                      (uint8_t *)spdm_request +
                                      spdm_request_size - hmac_size,
                                      hmac_size);
    if (RETURN_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }

    status = libspdm_send_spdm_request(spdm_context, &session_id,
                                       spdm_request_size, spdm_request);
    if (RETURN_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        goto error;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  SPDM_PSK_FINISH);

    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

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
        if (spdm_response->header.param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) {
            status = RETURN_SECURITY_VIOLATION;
            goto receive_done;
        }
        status = libspdm_handle_error_response_main(
            spdm_context, &session_id,
            &spdm_response_size, (void **)&spdm_response,
            SPDM_PSK_FINISH, SPDM_PSK_FINISH_RSP,
            sizeof(libspdm_psk_finish_response_max_t));
        if (RETURN_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_PSK_FINISH_RSP) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response_size != sizeof(spdm_psk_finish_response_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }

    status = libspdm_append_message_f(spdm_context, session_info, true, spdm_response,
                                      spdm_response_size);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n", session_id));
    status = libspdm_calculate_th2_hash(spdm_context, session_info, true,
                                        th2_hash_data);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }
    status = libspdm_generate_session_data_key(
        session_info->secured_message_context, th2_hash_data);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }

    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;

    libspdm_release_receiver_buffer (spdm_context);
    return RETURN_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
error:
    if (RETURN_NO_RESPONSE != status) {
        libspdm_free_session_id(spdm_context, session_id);
    }
    return status;
}

return_status libspdm_send_receive_psk_finish(libspdm_context_t *spdm_context,
                                              uint32_t session_id)
{
    uintn retry;
    return_status status;

    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_send_receive_psk_finish(spdm_context,
                                                     session_id);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
