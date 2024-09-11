/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

/**
 * This function sends SET_KEY_PAIR_INFO and receives SET_KEY_PAIR_INFO_ACK
 *
 * @param  context             A pointer to the SPDM context.
 *
 **/
static libspdm_return_t libspdm_try_set_key_pair_info(libspdm_context_t *spdm_context,
                                                      const uint32_t *session_id,
                                                      uint8_t key_pair_id,
                                                      uint8_t operation,
                                                      uint16_t desired_key_usage,
                                                      uint32_t desired_asym_algo,
                                                      uint8_t desired_assoc_cert_slot_mask
                                                      )
{
    libspdm_return_t status;
    spdm_set_key_pair_info_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_set_key_pair_info_ack_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t *ptr;

    /* -=[Check Parameters Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (key_pair_id == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if (operation > SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
        if ((desired_key_usage != 0) || (desired_asym_algo != 0) ||
            (desired_assoc_cert_slot_mask != 0)) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
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

    LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_set_key_pair_info_request_t));
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_SET_KEY_PAIR_INFO;
    spdm_request->header.param1 = operation;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = key_pair_id;

    if (operation != SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
        LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_set_key_pair_info_request_t) +
                       sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t));
        ptr = (uint8_t*)(spdm_request + 1);
        *ptr = 0;
        ptr += sizeof(uint8_t);

        libspdm_write_uint16 (ptr, desired_key_usage);
        ptr += sizeof(uint16_t);

        libspdm_write_uint32 (ptr, desired_asym_algo);
        ptr += sizeof(uint32_t);

        *ptr = desired_assoc_cert_slot_mask;
        ptr += sizeof(uint8_t);
        spdm_request_size = sizeof(spdm_set_key_pair_info_request_t);
        spdm_request_size += ((size_t)ptr - (size_t)spdm_request);
    } else {
        spdm_request_size = sizeof(spdm_set_key_pair_info_request_t);
    }

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
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

    status = libspdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_SET_KEY_PAIR_INFO, SPDM_SET_KEY_PAIR_INFO_ACK);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SET_KEY_PAIR_INFO_ACK) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    spdm_response_size = sizeof(spdm_set_key_pair_info_ack_response_t);

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_set_key_pair_info(void *spdm_context, const uint32_t *session_id,
                                           uint8_t key_pair_id,
                                           uint8_t operation,
                                           uint16_t desired_key_usage,
                                           uint32_t desired_asym_algo,
                                           uint8_t desired_assoc_cert_slot_mask
                                           )
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
        status = libspdm_try_set_key_pair_info(context, session_id, key_pair_id,
                                               operation,
                                               desired_key_usage,
                                               desired_asym_algo,
                                               desired_assoc_cert_slot_mask);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */
