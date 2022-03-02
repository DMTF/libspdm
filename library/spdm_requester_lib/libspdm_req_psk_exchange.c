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
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t psk_hint[LIBSPDM_PSK_MAX_HINT_LENGTH];
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_psk_exchange_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t rsp_session_id;
    uint16_t reserved;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t measurement_summary_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_psk_exchange_response_max_t;

#pragma pack()

/**
 * This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the PSK_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the PSK_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the PSK_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the PSK_EXCHANGE_RSP response.
 * @param  requester_context_in          A buffer to hold the requester context as input, if not NULL.
 * @param  requester_context_in_size     The size of requester_context_in.
 *                                      It must be 32 bytes at least, but not exceed LIBSPDM_PSK_CONTEXT_LENGTH.
 * @param  requester_context             A buffer to hold the requester context, if not NULL.
 * @param  requester_context_size        On input, the size of requester_context buffer.
 *                                      On output, the size of data returned in requester_context buffer.
 *                                      It must be 32 bytes at least.
 * @param  responder_context             A buffer to hold the responder context, if not NULL.
 * @param  responder_context_size        On input, the size of requester_context buffer.
 *                                      On output, the size of data returned in requester_context buffer.
 *                                      It could be 0 if device does not support context.
 *
 * @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_try_send_receive_psk_exchange(
    libspdm_context_t *spdm_context, uint8_t measurement_hash_type,
    uint8_t session_policy,
    uint32_t *session_id, uint8_t *heartbeat_period,
    void *measurement_hash,
    const void *requester_context_in,
    uintn requester_context_in_size,
    void *requester_context,
    uintn *requester_context_size,
    void *responder_context,
    uintn *responder_context_size)
{
    bool result;
    return_status status;
    libspdm_psk_exchange_request_mine_t spdm_request;
    uintn spdm_request_size;
    libspdm_psk_exchange_response_max_t spdm_response;
    uintn spdm_response_size;
    uint32_t measurement_summary_hash_size;
    uint32_t hmac_size;
    uint8_t *ptr;
    void *measurement_summary_hash;
    uint8_t *verify_data;
    uint16_t req_session_id;
    uint16_t rsp_session_id;
    libspdm_session_info_t *session_info;
    uintn opaque_psk_exchange_req_size;
    uint8_t th1_hash_data[64];
    uint8_t th2_hash_data[64];
    uint32_t algo_size;

    /* Check capabilities even if GET_CAPABILITIES is not sent.
     * Assuming capabilities are provisioned.*/
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
        return RETURN_UNSUPPORTED;
    }
    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  SPDM_PSK_EXCHANGE);
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return RETURN_UNSUPPORTED;
    }

    {
        /* Double check if algorithm has been provisioned, because ALGORITHM might be skipped.*/
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
            if (spdm_context->connection_info.algorithm
                .measurement_spec !=
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
                return RETURN_DEVICE_ERROR;
            }
            algo_size = libspdm_get_measurement_hash_size(
                spdm_context->connection_info.algorithm
                .measurement_hash_algo);
            if (algo_size == 0) {
                return RETURN_DEVICE_ERROR;
            }
        }
        algo_size = libspdm_get_hash_size(
            spdm_context->connection_info.algorithm.base_hash_algo);
        if (algo_size == 0) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_context->connection_info.algorithm.key_schedule !=
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
            return RETURN_DEVICE_ERROR;
        }
    }

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    spdm_request.header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request.header.request_response_code = SPDM_PSK_EXCHANGE;
    spdm_request.header.param1 = measurement_hash_type;
    if (spdm_request.header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.header.param2 = session_policy;
    } else {
        spdm_request.header.param2 = 0;
    }
    spdm_request.psk_hint_length =
        (uint16_t)spdm_context->local_context.psk_hint_size;
    if (requester_context_in == NULL) {
        spdm_request.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    } else {
        LIBSPDM_ASSERT (requester_context_in_size <= LIBSPDM_PSK_CONTEXT_LENGTH);
        spdm_request.context_length = (uint16_t)requester_context_in_size;
    }
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    spdm_request.opaque_length = (uint16_t)opaque_psk_exchange_req_size;

    req_session_id = libspdm_allocate_req_session_id(spdm_context);
    spdm_request.req_session_id = req_session_id;

    ptr = spdm_request.psk_hint;
    libspdm_copy_mem(ptr, sizeof(spdm_request.psk_hint),
                     spdm_context->local_context.psk_hint,
                     spdm_context->local_context.psk_hint_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "psk_hint (0x%x) - ", spdm_request.psk_hint_length));
    libspdm_internal_dump_data(ptr, spdm_request.psk_hint_length);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    ptr += spdm_request.psk_hint_length;

    if (requester_context_in == NULL) {
        if(!libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr)) {
            return RETURN_DEVICE_ERROR;
        }
    } else {
        libspdm_copy_mem(ptr, sizeof(spdm_request.context),
                         requester_context_in, spdm_request.context_length);
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ClientContextData (0x%x) - ",
                   spdm_request.context_length));
    libspdm_internal_dump_data(ptr, spdm_request.context_length);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (requester_context != NULL) {
        if (*requester_context_size > spdm_request.context_length) {
            *requester_context_size = spdm_request.context_length;
        }
        libspdm_copy_mem(requester_context, *requester_context_size,
                         ptr, *requester_context_size);
    }
    ptr += spdm_request.context_length;

    status = libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    LIBSPDM_ASSERT_RETURN_ERROR(status);
    ptr += opaque_psk_exchange_req_size;

    spdm_request_size = (uintn)ptr - (uintn)&spdm_request;
    status = libspdm_send_spdm_request(spdm_context, NULL, spdm_request_size,
                                       &spdm_request);
    if (RETURN_ERROR(status)) {
        return status;
    }

    spdm_response_size = sizeof(spdm_response);
    libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
    status = libspdm_receive_spdm_response(
        spdm_context, NULL, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        return status;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, NULL, &spdm_response_size,
            &spdm_response, SPDM_PSK_EXCHANGE,
            SPDM_PSK_EXCHANGE_RSP,
            sizeof(libspdm_psk_exchange_response_max_t));
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else if (spdm_response.header.request_response_code !=
               SPDM_PSK_EXCHANGE_RSP) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_psk_exchange_response_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return RETURN_DEVICE_ERROR;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP)) {
        if (spdm_response.header.param1 != 0) {
            return RETURN_DEVICE_ERROR;
        }
    }
    if (heartbeat_period != NULL) {
        *heartbeat_period = spdm_response.header.param1;
    }
    rsp_session_id = spdm_response.rsp_session_id;
    *session_id = (req_session_id << 16) | rsp_session_id;
    session_info = libspdm_assign_session_id(spdm_context, *session_id, true);
    if (session_info == NULL) {
        return RETURN_DEVICE_ERROR;
    }

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, true, measurement_hash_type);
    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (spdm_response_size <
        sizeof(spdm_psk_exchange_response_t) +
        spdm_response.context_length + spdm_response.opaque_length +
        measurement_summary_hash_size + hmac_size) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_DEVICE_ERROR;
    }

    ptr = (uint8_t *)&spdm_response + sizeof(spdm_psk_exchange_response_t) +
          measurement_summary_hash_size + spdm_response.context_length;
    status = libspdm_process_opaque_data_version_selection_data(
        spdm_context, spdm_response.opaque_length, ptr);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_UNSUPPORTED;
    }

    spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
                         spdm_response.context_length +
                         spdm_response.opaque_length +
                         measurement_summary_hash_size + hmac_size;

    ptr = (uint8_t *)(spdm_response.measurement_summary_hash);
    measurement_summary_hash = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "measurement_summary_hash (0x%x) - ",
                   measurement_summary_hash_size));
    libspdm_internal_dump_data(measurement_summary_hash,
                               measurement_summary_hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    ptr += measurement_summary_hash_size;

    if ( spdm_response.opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_SECURITY_VIOLATION;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ServerContextData (0x%x) - ",
                   spdm_response.context_length));
    libspdm_internal_dump_data(ptr, spdm_response.context_length);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (responder_context != NULL) {
        if (*responder_context_size > spdm_response.context_length) {
            *responder_context_size = spdm_response.context_length;
        }
        libspdm_copy_mem(responder_context, *responder_context_size,
                         ptr, *responder_context_size);
    }

    ptr += spdm_response.context_length;

    ptr += spdm_response.opaque_length;


    /* Cache session data*/

    status = libspdm_append_message_k(spdm_context, session_info, true, &spdm_request,
                                      spdm_request_size);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_SECURITY_VIOLATION;
    }

    status = libspdm_append_message_k(spdm_context, session_info, true, &spdm_response,
                                      spdm_response_size - hmac_size);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_SECURITY_VIOLATION;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%x]\n",
                   *session_id));
    status = libspdm_calculate_th1_hash(spdm_context, session_info, true,
                                        th1_hash_data);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_SECURITY_VIOLATION;
    }
    status = libspdm_generate_session_handshake_key(
        session_info->secured_message_context, th1_hash_data);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_SECURITY_VIOLATION;
    }

    verify_data = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "verify_data (0x%x):\n", hmac_size));
    libspdm_internal_dump_hex(verify_data, hmac_size);
    result = libspdm_verify_psk_exchange_rsp_hmac(spdm_context, session_info,
                                                  verify_data, hmac_size);
    if (!result) {
        libspdm_free_session_id(spdm_context, *session_id);
        spdm_context->error_state =
            LIBSPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
        return RETURN_SECURITY_VIOLATION;
    }

    status = libspdm_append_message_k(spdm_context, session_info, true, verify_data, hmac_size);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        return RETURN_SECURITY_VIOLATION;
    }

    if (measurement_hash != NULL) {
        libspdm_copy_mem(measurement_hash, measurement_summary_hash_size,
                         measurement_summary_hash, measurement_summary_hash_size);
    }

    session_info->session_policy = session_policy;

    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        /* No need to send PSK_FINISH, enter application phase directly.*/

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n",
                       session_id));
        status = libspdm_calculate_th2_hash(spdm_context, session_info,
                                            true, th2_hash_data);
        if (RETURN_ERROR(status)) {
            libspdm_free_session_id(spdm_context, *session_id);
            return RETURN_SECURITY_VIOLATION;
        }
        status = libspdm_generate_session_data_key(
            session_info->secured_message_context, th2_hash_data);
        if (RETURN_ERROR(status)) {
            libspdm_free_session_id(spdm_context, *session_id);
            return RETURN_SECURITY_VIOLATION;
        }

        libspdm_secured_message_set_session_state(
            session_info->secured_message_context,
            LIBSPDM_SESSION_STATE_ESTABLISHED);
    }

    return RETURN_SUCCESS;
}

/**
 * This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the PSK_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the PSK_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the PSK_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the PSK_EXCHANGE_RSP response.
 *
 * @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_send_receive_psk_exchange(libspdm_context_t *spdm_context,
                                                uint8_t measurement_hash_type,
                                                uint8_t session_policy,
                                                uint32_t *session_id,
                                                uint8_t *heartbeat_period,
                                                void *measurement_hash)
{
    uintn retry;
    return_status status;

    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_send_receive_psk_exchange(
            spdm_context, measurement_hash_type, session_policy, session_id,
            heartbeat_period, measurement_hash,
            NULL, 0, NULL, NULL, NULL, NULL);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

/**
 * This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the PSK_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the PSK_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the PSK_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the PSK_EXCHANGE_RSP response.
 * @param  requester_context_in          A buffer to hold the requester context as input, if not NULL.
 * @param  requester_context_in_size     The size of requester_context_in.
 *                                      It must be 32 bytes at least, but not exceed LIBSPDM_PSK_CONTEXT_LENGTH.
 * @param  requester_context             A buffer to hold the requester context, if not NULL.
 * @param  requester_context_size        On input, the size of requester_context buffer.
 *                                      On output, the size of data returned in requester_context buffer.
 *                                      It must be 32 bytes at least.
 * @param  responder_context             A buffer to hold the responder context, if not NULL.
 * @param  responder_context_size        On input, the size of requester_context buffer.
 *                                      On output, the size of data returned in requester_context buffer.
 *                                      It could be 0 if device does not support context.
 *
 * @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_send_receive_psk_exchange_ex(libspdm_context_t *spdm_context,
                                                   uint8_t measurement_hash_type,
                                                   uint8_t session_policy,
                                                   uint32_t *session_id,
                                                   uint8_t *heartbeat_period,
                                                   void *measurement_hash,
                                                   const void *requester_context_in,
                                                   uintn requester_context_in_size,
                                                   void *requester_context,
                                                   uintn *requester_context_size,
                                                   void *responder_context,
                                                   uintn *responder_context_size)
{
    uintn retry;
    return_status status;

    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_send_receive_psk_exchange(
            spdm_context, measurement_hash_type, session_policy, session_id,
            heartbeat_period, measurement_hash,
            requester_context_in, requester_context_in_size,
            requester_context, requester_context_size,
            responder_context, responder_context_size);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
