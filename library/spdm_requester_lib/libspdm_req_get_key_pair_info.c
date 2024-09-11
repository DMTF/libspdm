/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

typedef struct {
    spdm_message_header_t header;
    uint8_t total_key_pairs;
    uint8_t key_pair_id;
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t public_key_info[SPDM_MAX_PUBLIC_KEY_INFO_LEN];
} libspdm_key_pair_info_response_max_t;

/**
 * This function sends GET_KEY_PAIR_INFO and receives KEY_PAIR_INFO *
 *
 * @param  context             A pointer to the SPDM context.
 *
 **/
static libspdm_return_t libspdm_try_get_key_pair_info(libspdm_context_t *spdm_context,
                                                      const uint32_t *session_id,
                                                      uint8_t key_pair_id,
                                                      uint8_t *total_key_pairs,
                                                      uint16_t *capabilities,
                                                      uint16_t *key_usage_capabilities,
                                                      uint16_t *current_key_usage,
                                                      uint32_t *asym_algo_capabilities,
                                                      uint32_t *current_asym_algo,
                                                      uint8_t *assoc_cert_slot_mask,
                                                      uint16_t *public_key_info_len,
                                                      void *public_key_info
                                                      )
{
    libspdm_return_t status;
    spdm_get_key_pair_info_request_t *spdm_request;
    size_t spdm_request_size;
    libspdm_key_pair_info_response_max_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    /* -=[Check Parameters Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (key_pair_id == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP)) {
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

    LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_get_key_pair_info_request_t));
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_KEY_PAIR_INFO;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->key_pair_id = key_pair_id;
    spdm_request_size = sizeof(spdm_get_key_pair_info_request_t);

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
            (void **)&spdm_response, SPDM_GET_KEY_PAIR_INFO, SPDM_KEY_PAIR_INFO);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_KEY_PAIR_INFO) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    if ((spdm_response->key_pair_id != key_pair_id) ||
        (spdm_response->key_pair_id > (spdm_response->total_key_pairs))) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    if (spdm_response_size < sizeof(spdm_key_pair_info_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    if (spdm_response_size < sizeof(spdm_key_pair_info_response_t) +
        spdm_response->public_key_info_len) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    spdm_response_size = sizeof(spdm_key_pair_info_response_t) + spdm_response->public_key_info_len;

    /* -=[Process Response Phase]=- */
    *key_usage_capabilities = (spdm_response->key_usage_capabilities) & SPDM_KEY_USAGE_BIT_MASK;
    if (*key_usage_capabilities == 0) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    *current_key_usage = (spdm_response->current_key_usage) & SPDM_KEY_USAGE_BIT_MASK;
    if ((*key_usage_capabilities | *current_key_usage) != *key_usage_capabilities) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    *asym_algo_capabilities = (spdm_response->asym_algo_capabilities) &
                              SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    if (*asym_algo_capabilities == 0) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    *current_asym_algo = (spdm_response->current_asym_algo) & SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    if (!libspdm_onehot0(*current_asym_algo)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if ((*asym_algo_capabilities | *current_asym_algo) != *asym_algo_capabilities) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    /*If responder doesn't support SET_KEY_PAIR_INFO_CAP,the capabilities should be 0*/
    if ((!libspdm_is_capabilities_flag_supported(
             spdm_context, true, 0,
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP)) &&
        ((spdm_response->capabilities & SPDM_KEY_PAIR_CAP_MASK) != 0)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    *total_key_pairs = spdm_response->total_key_pairs;
    *capabilities = spdm_response->capabilities & SPDM_KEY_PAIR_CAP_MASK;

    if (*public_key_info_len < spdm_response->public_key_info_len) {
        status = LIBSPDM_STATUS_BUFFER_FULL;
        goto receive_done;
    }
    *public_key_info_len = spdm_response->public_key_info_len;
    *assoc_cert_slot_mask = spdm_response->assoc_cert_slot_mask;

    libspdm_copy_mem(public_key_info,
                     spdm_response->public_key_info_len,
                     spdm_response->public_key_info,
                     spdm_response->public_key_info_len);

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_get_key_pair_info(void *spdm_context, const uint32_t *session_id,
                                           uint8_t key_pair_id, uint8_t *total_key_pairs,
                                           uint16_t *capabilities,
                                           uint16_t *key_usage_capabilities,
                                           uint16_t *current_key_usage,
                                           uint32_t *asym_algo_capabilities,
                                           uint32_t *current_asym_algo,
                                           uint8_t *assoc_cert_slot_mask,
                                           uint16_t *public_key_info_len,
                                           void *public_key_info
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
        status = libspdm_try_get_key_pair_info(context, session_id, key_pair_id,
                                               total_key_pairs, capabilities,
                                               key_usage_capabilities, current_key_usage,
                                               asym_algo_capabilities, current_asym_algo,
                                               assoc_cert_slot_mask, public_key_info_len,
                                               public_key_info);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */
