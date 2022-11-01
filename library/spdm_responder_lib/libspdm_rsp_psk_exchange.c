/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP

/**
 * This function generates the PSK exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the PSK exchange HMAC.
 *
 * @retval true  PSK exchange HMAC is generated.
 * @retval false PSK exchange HMAC is not generated.
 **/
static bool libspdm_generate_psk_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                                   libspdm_session_info_t *session_info,
                                                   uint8_t *hmac)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
#endif

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(spdm_context, session_info,
                                               NULL, 0, &th_curr_data_size,
                                               th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hash_all (spdm_context->connection_info.algorithm.base_hash_algo,
                               th_curr_data, th_curr_data_size, hash_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, hash_data,
        hash_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, false, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    libspdm_copy_mem(hmac, hash_size, hmac_data, hash_size);

    return true;
}

/**
 * Process the SPDM PSK_EXCHANGE request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t libspdm_get_response_psk_exchange(void *context,
                                                   size_t request_size,
                                                   const void *request,
                                                   size_t *response_size,
                                                   void *response)
{
    const spdm_psk_exchange_request_t *spdm_request;
    spdm_psk_exchange_response_t *spdm_response;
    bool result;
    uint32_t session_id;
    size_t measurement_summary_hash_size;
    uint32_t hmac_size;
    const uint8_t *cptr;
    uint8_t *ptr;
    libspdm_session_info_t *session_info;
    size_t total_size;
    libspdm_context_t *spdm_context;
    uint16_t req_session_id;
    uint16_t rsp_session_id;
    libspdm_return_t status;
    size_t opaque_psk_exchange_rsp_size;
    uint8_t th1_hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t th2_hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint32_t algo_size;
    uint16_t context_length;
    const void *psk_hint;
    size_t psk_hint_size;

    spdm_context = context;
    spdm_request = request;

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    /* Check capabilities even if GET_CAPABILITIES is not sent.
     * Assuming capabilities are provisioned.*/
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_PSK_EXCHANGE, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }
    if (spdm_context->last_spdm_request_session_id_valid) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    {
        /* Double check if algorithm has been provisioned, because ALGORITHM might be skipped.*/
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
            if (spdm_context->connection_info.algorithm
                .measurement_spec !=
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST,
                    SPDM_PSK_EXCHANGE, response_size,
                    response);
            }
            algo_size = libspdm_get_measurement_hash_size(
                spdm_context->connection_info.algorithm
                .measurement_hash_algo);
            if (algo_size == 0) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST,
                    SPDM_PSK_EXCHANGE, response_size,
                    response);
            }
        }
        algo_size = libspdm_get_hash_size(
            spdm_context->connection_info.algorithm.base_hash_algo);
        if (algo_size == 0) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_INVALID_REQUEST,
                SPDM_PSK_EXCHANGE, response_size, response);
        }
        if (spdm_context->connection_info.algorithm.key_schedule !=
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_INVALID_REQUEST,
                SPDM_PSK_EXCHANGE, response_size, response);
        }
    }

    if (spdm_request->header.param1 > 0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ||
            (spdm_context->connection_info.algorithm.measurement_spec == 0) ||
            (spdm_context->connection_info.algorithm.measurement_hash_algo == 0) ) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                SPDM_PSK_EXCHANGE, response_size, response);
        }
    }

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, spdm_request->header.param1);
    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (request_size < sizeof(spdm_psk_exchange_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (request_size < sizeof(spdm_psk_exchange_request_t) +
        spdm_request->psk_hint_length +
        spdm_request->context_length +
        spdm_request->opaque_length) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    request_size = sizeof(spdm_psk_exchange_request_t) +
                   spdm_request->psk_hint_length +
                   spdm_request->context_length +
                   spdm_request->opaque_length;

    if (spdm_request->opaque_length != 0) {
        cptr = (const uint8_t *)request + sizeof(spdm_psk_exchange_request_t) +
               spdm_request->psk_hint_length + spdm_request->context_length;
        status = libspdm_process_opaque_data_supported_version_data(
            spdm_context, spdm_request->opaque_length, cptr);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    opaque_psk_exchange_rsp_size =
        libspdm_get_opaque_data_version_selection_data_size(spdm_context);
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    } else {
        context_length = 0;
    }
    total_size = sizeof(spdm_psk_exchange_response_t) +
                 measurement_summary_hash_size + context_length +
                 opaque_psk_exchange_rsp_size + hmac_size;

    LIBSPDM_ASSERT(*response_size >= total_size);
    *response_size = total_size;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_PSK_EXCHANGE_RSP;
    spdm_response->header.param1 = spdm_context->local_context.heartbeat_period;

    req_session_id = spdm_request->req_session_id;
    rsp_session_id = libspdm_allocate_rsp_session_id(spdm_context);
    if (rsp_session_id == (INVALID_SESSION_ID & 0xFFFF)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0,
            response_size, response);
    }
    if (spdm_request->psk_hint_length == 0) {
        psk_hint_size = 0;
        psk_hint = NULL;
    } else if(spdm_request->psk_hint_length < LIBSPDM_PSK_MAX_HINT_LENGTH ) {
        psk_hint_size = spdm_request->psk_hint_length;
        psk_hint = (const uint8_t *)request +
                   sizeof(spdm_psk_exchange_request_t);
    } else {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }
    session_id = (req_session_id << 16) | rsp_session_id;
    session_info = libspdm_assign_session_id(spdm_context, session_id, true);
    if (session_info == NULL) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0,
            response_size, response);
    }
    libspdm_session_info_set_psk_hint(session_info, psk_hint, psk_hint_size);

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    spdm_response->rsp_session_id = rsp_session_id;
    spdm_response->reserved = 0;

    spdm_response->context_length = context_length;
    spdm_response->opaque_length = (uint16_t)opaque_psk_exchange_rsp_size;

    ptr = (void *)(spdm_response + 1);

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {

        result = libspdm_generate_measurement_summary_hash(
            spdm_context->connection_info.version,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm.measurement_hash_algo,
            spdm_request->header.param1,
            ptr,
            &measurement_summary_hash_size);
    }
    else {
        result = true;
    }

    if ((measurement_summary_hash_size == 0) &&
        (spdm_request->header.param2 != SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST,
                                               0, response_size, response);
    }
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += measurement_summary_hash_size;

    if (context_length != 0) {
        if(!libspdm_get_random_number(context_length, ptr)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }
        ptr += context_length;
    }

    status = libspdm_build_opaque_data_version_selection_data(
        spdm_context, &opaque_psk_exchange_rsp_size, ptr);
    LIBSPDM_ASSERT(status == LIBSPDM_STATUS_SUCCESS);
    ptr += opaque_psk_exchange_rsp_size;


    status = libspdm_append_message_k(spdm_context, session_info, false, request, request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_k(spdm_context, session_info, false, spdm_response,
                                      (size_t)ptr - (size_t)spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%x]\n",
                   session_id));
    result = libspdm_calculate_th1_hash(spdm_context, session_info, false,
                                        th1_hash_data);
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    result = libspdm_generate_session_handshake_key(
        session_info->secured_message_context, th1_hash_data);
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    result = libspdm_generate_psk_exchange_rsp_hmac(spdm_context, session_info,
                                                    ptr);
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }
    status = libspdm_append_message_k(spdm_context, session_info, false, ptr, hmac_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += hmac_size;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        session_info->session_policy = spdm_request->header.param2;
    }
    libspdm_set_session_state(spdm_context, session_id, LIBSPDM_SESSION_STATE_HANDSHAKING);

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        /* No need to receive PSK_FINISH, enter application phase directly.*/

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n",
                       session_id));
        result = libspdm_calculate_th2_hash(spdm_context, session_info,
                                            false, th2_hash_data);
        if (!result) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
        result = libspdm_generate_session_data_key(
            session_info->secured_message_context, th2_hash_data);
        if (!result) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }

        libspdm_set_session_state(spdm_context, session_id, LIBSPDM_SESSION_STATE_ESTABLISHED);
    }

    session_info->heartbeat_period = spdm_context->local_context.heartbeat_period;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
