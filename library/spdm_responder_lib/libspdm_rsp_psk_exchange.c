/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"

#if SPDM_ENABLE_CAPABILITY_PSK_EX_CAP

/**
  Process the SPDM PSK_EXCHANGE request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_psk_exchange(IN void *context,
                         IN uintn request_size,
                         IN void *request,
                         IN OUT uintn *response_size,
                         OUT void *response)
{
    spdm_psk_exchange_request_t *spdm_request;
    spdm_psk_exchange_response_t *spdm_response;
    boolean result;
    uint8_t slot_id;
    uint32_t session_id;
    uintn    measurement_summary_hash_size;
    uint32_t hmac_size;
    uint8_t *ptr;
    spdm_session_info_t *session_info;
    uintn total_size;
    spdm_context_t *spdm_context;
    uint16_t req_session_id;
    uint16_t rsp_session_id;
    return_status status;
    uintn opaque_psk_exchange_rsp_size;
    uint8_t th1_hash_data[64];
    uint8_t th2_hash_data[64];
    uint32_t algo_size;
    uint16_t context_length;

    spdm_context = context;
    spdm_request = request;

    if (spdm_context->response_state != SPDM_RESPONSE_STATE_NORMAL) {
        return spdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    // Check capabilities even if GET_CAPABILITIES is not sent.
    // Assuming capabilities are provisioned.
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, FALSE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_PSK_EXCHANGE, response_size, response);
        return RETURN_SUCCESS;
    }
    if (spdm_context->connection_info.connection_state <
        SPDM_CONNECTION_STATE_NEGOTIATED) {
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                         0, response_size, response);
        return RETURN_SUCCESS;
    }

    {
        // Double check if algorithm has been provisioned, because ALGORITHM might be skipped.
        if (spdm_is_capabilities_flag_supported(
                spdm_context, TRUE, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
            if (spdm_context->connection_info.algorithm
                    .measurement_spec !=
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
                libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                    SPDM_PSK_EXCHANGE, response_size,
                    response);
                return RETURN_SUCCESS;
            }
            algo_size = spdm_get_measurement_hash_size(
                spdm_context->connection_info.algorithm
                    .measurement_hash_algo);
            if (algo_size == 0) {
                libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                    SPDM_PSK_EXCHANGE, response_size,
                    response);
                return RETURN_SUCCESS;
            }
        }
        algo_size = spdm_get_hash_size(
            spdm_context->connection_info.algorithm.base_hash_algo);
        if (algo_size == 0) {
            libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                SPDM_PSK_EXCHANGE, response_size, response);
            return RETURN_SUCCESS;
        }
        if (spdm_context->connection_info.algorithm.key_schedule !=
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
            libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                SPDM_PSK_EXCHANGE, response_size, response);
            return RETURN_SUCCESS;
        }
    }

    if (spdm_is_capabilities_flag_supported(
            spdm_context, FALSE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
        if (spdm_context->encap_context.error_state !=
            SPDM_STATUS_SUCCESS) {
            DEBUG((DEBUG_INFO,
                   "spdm_get_response_psk_exchange fail due to Mutual Auth fail\n"));
            libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
            return RETURN_SUCCESS;
        }
    }
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, FALSE,
            0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) &&
            spdm_request->header.param1 > 0) {
        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_PSK_EXCHANGE, response_size, response);
        return RETURN_SUCCESS;
    }
    slot_id = spdm_request->header.param2;
    if (slot_id >= spdm_context->local_context.slot_count) {
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }

    measurement_summary_hash_size = spdm_get_measurement_summary_hash_size(
        spdm_context, FALSE, spdm_request->header.param1);
    hmac_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (request_size < sizeof(spdm_psk_exchange_request_t)) {
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }
    if (request_size < sizeof(spdm_psk_exchange_request_t) +
                   spdm_request->psk_hint_length +
                   spdm_request->context_length +
                   spdm_request->opaque_length) {
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }
    request_size = sizeof(spdm_psk_exchange_request_t) +
               spdm_request->psk_hint_length +
               spdm_request->context_length +
               spdm_request->opaque_length;

    ptr = (uint8_t *)request + sizeof(spdm_psk_exchange_request_t) +
          spdm_request->psk_hint_length + spdm_request->context_length;
    status = spdm_process_opaque_data_supported_version_data(
        spdm_context, spdm_request->opaque_length, ptr);
    if (RETURN_ERROR(status)) {
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }

    opaque_psk_exchange_rsp_size =
        spdm_get_opaque_data_version_selection_data_size(spdm_context);
    if (spdm_is_capabilities_flag_supported(
            spdm_context, FALSE, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        context_length = DEFAULT_CONTEXT_LENGTH;
    } else {
        context_length = 0;
    }
    total_size = sizeof(spdm_psk_exchange_response_t) +
             measurement_summary_hash_size + context_length +
             opaque_psk_exchange_rsp_size + hmac_size;

    ASSERT(*response_size >= total_size);
    *response_size = total_size;
    zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_PSK_EXCHANGE_RSP;
    spdm_response->header.param1 = spdm_context->local_context.heartbeat_period;

    req_session_id = spdm_request->req_session_id;
    rsp_session_id = spdm_allocate_rsp_session_id(spdm_context);
    if (rsp_session_id == (INVALID_SESSION_ID & 0xFFFF)) {
        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0,
            response_size, response);
        return RETURN_SUCCESS;
    }
    session_id = (req_session_id << 16) | rsp_session_id;
    session_info = libspdm_assign_session_id(spdm_context, session_id, TRUE);
    if (session_info == NULL) {
        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0,
            response_size, response);
        return RETURN_SUCCESS;
    }

    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                        spdm_request->header.request_response_code);

    spdm_response->rsp_session_id = rsp_session_id;
    spdm_response->reserved = 0;

    spdm_response->context_length = context_length;
    spdm_response->opaque_length = (uint16_t)opaque_psk_exchange_rsp_size;

    ptr = (void *)(spdm_response + 1);

    if (spdm_is_capabilities_flag_supported(
        spdm_context, FALSE, 0,  SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {

        result = spdm_generate_measurement_summary_hash(
            spdm_context->connection_info.version,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm.measurement_hash_algo,
            spdm_request->header.param1,
            ptr,
	    &measurement_summary_hash_size);
    }
    else {
        result = TRUE;
    }

    if ((measurement_summary_hash_size == 0) &&
        (spdm_request->header.param2 != SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH)) {
        return libspdm_generate_error_response(spdm_context,
                        SPDM_ERROR_CODE_INVALID_REQUEST,
                        0, response_size, response);
    }
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }
    ptr += measurement_summary_hash_size;

    if (context_length != 0) {
        if(!spdm_get_random_number(context_length, ptr)) {
            return RETURN_DEVICE_ERROR;
        }
        ptr += context_length;
    }

    status = spdm_build_opaque_data_version_selection_data(
        spdm_context, &opaque_psk_exchange_rsp_size, ptr);
    ASSERT_RETURN_ERROR(status);
    ptr += opaque_psk_exchange_rsp_size;


    status = libspdm_append_message_k(spdm_context, session_info, FALSE, request, request_size);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }
    
    status = libspdm_append_message_k(spdm_context, session_info, FALSE, spdm_response,
                       (uintn)ptr - (uintn)spdm_response);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }

    DEBUG((DEBUG_INFO, "spdm_generate_session_handshake_key[%x]\n",
           session_id));
    status = libspdm_calculate_th1_hash(spdm_context, session_info, FALSE,
                     th1_hash_data);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }
    status = spdm_generate_session_handshake_key(
        session_info->secured_message_context, th1_hash_data);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }

    result = spdm_generate_psk_exchange_rsp_hmac(spdm_context, session_info,
                             ptr);
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
        return RETURN_SUCCESS;
    }
    status = libspdm_append_message_k(spdm_context, session_info, FALSE, ptr, hmac_size);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
        return RETURN_SUCCESS;
    }
    ptr += hmac_size;

    spdm_set_session_state(spdm_context, session_id,
                   SPDM_SESSION_STATE_HANDSHAKING);

    if (!spdm_is_capabilities_flag_supported(
            spdm_context, FALSE, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        // No need to receive PSK_FINISH, enter application phase directly.

        DEBUG((DEBUG_INFO, "spdm_generate_session_data_key[%x]\n",
               session_id));
        status = libspdm_calculate_th2_hash(spdm_context, session_info,
                         FALSE, th2_hash_data);
        if (RETURN_ERROR(status)) {
            libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
            return RETURN_SUCCESS;
        }
        status = spdm_generate_session_data_key(
            session_info->secured_message_context, th2_hash_data);
        if (RETURN_ERROR(status)) {
            libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
            return RETURN_SUCCESS;
        }

        spdm_set_session_state(spdm_context, session_id,
                       SPDM_SESSION_STATE_ESTABLISHED);
    }

    return RETURN_SUCCESS;
}

#endif // SPDM_ENABLE_CAPABILITY_PSK_EX_CAP
