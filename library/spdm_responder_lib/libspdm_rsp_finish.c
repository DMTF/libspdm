/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "hal/library/platform_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

/**
 * Process the SPDM FINISH request and return the response.
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
return_status spdm_get_response_finish(IN void *context, IN uintn request_size,
                                       IN void *request,
                                       IN OUT uintn *response_size,
                                       OUT void *response)
{
    uint32_t session_id;
    bool result;
    uint32_t hmac_size;
    uint32_t signature_size;
    uint8_t req_slot_id;
    spdm_finish_request_t *spdm_request;
    spdm_finish_response_t *spdm_response;
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    uint8_t th2_hash_data[64];
    return_status status;
    libspdm_session_state_t session_state;

    spdm_context = context;
    spdm_request = request;

    if (spdm_request->header.spdm_version != spdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return spdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_KEY_EXCHANGE, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        /* No handshake in clear, then it must be in a session.*/
        if (!spdm_context->last_spdm_request_session_id_valid) {
            return libspdm_generate_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
    } else {
        /* handshake in clear, then it must not be in a session.*/
        if (spdm_context->last_spdm_request_session_id_valid) {
            return libspdm_generate_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
    }
    if (spdm_context->last_spdm_request_session_id_valid) {
        session_id = spdm_context->last_spdm_request_session_id;
    } else {
        session_id = spdm_context->latest_session_id;
    }
    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_HANDSHAKING) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (((session_info->mut_auth_requested == 0) &&
         (spdm_request->header.param1 != 0)) ||
        ((session_info->mut_auth_requested != 0) &&
         (spdm_request->header.param1 == 0))) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (session_info->mut_auth_requested) {
        signature_size = libspdm_get_req_asym_signature_size(
            spdm_context->connection_info.algorithm
            .req_base_asym_alg);
    } else {
        signature_size = 0;
    }

    if (request_size !=
        sizeof(spdm_finish_request_t) + signature_size + hmac_size) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    req_slot_id = spdm_request->header.param2;
    if ((req_slot_id != 0xFF) &&
        (req_slot_id >= spdm_context->local_context.slot_count)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (req_slot_id == 0xFF) {
        req_slot_id = spdm_context->encap_context.req_slot_id;
    }
    if (req_slot_id != spdm_context->encap_context.req_slot_id) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    spdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                               spdm_request->header.request_response_code);

    status = libspdm_append_message_f(spdm_context, session_info, false, request,
                                      sizeof(spdm_finish_request_t));
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    if (session_info->mut_auth_requested) {
        result = spdm_verify_finish_req_signature(
            spdm_context, session_info,
            (uint8_t *)request + sizeof(spdm_finish_request_t),
            signature_size);
        if (!result) {
            if((spdm_context->handle_error_return_policy & BIT0) == 0) {
                return libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
                    response_size, response);
            } else {
                /**
                 * just ignore this message
                 * return UNSUPPORTED and clear response_size to continue the dispatch without send response.
                 **/
                *response_size = 0;
                return RETURN_UNSUPPORTED;
            }
        }
        status = libspdm_append_message_f(
            spdm_context, session_info, false,
            (uint8_t *)request + sizeof(spdm_finish_request_t),
            signature_size);
        if (RETURN_ERROR(status)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    result = spdm_verify_finish_req_hmac(
        spdm_context, session_info,
        (uint8_t *)request + signature_size +
        sizeof(spdm_finish_request_t),
        hmac_size);
    if (!result) {
        if((spdm_context->handle_error_return_policy & BIT0) == 0) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
                response_size, response);
        } else {
            /**
             * just ignore this message
             * return UNSUPPORTED and clear response_size to continue the dispatch without send response
             **/
            *response_size = 0;
            return RETURN_UNSUPPORTED;
        }
    }

    status = libspdm_append_message_f(spdm_context, session_info, false,
                                      (uint8_t *)request + signature_size +
                                      sizeof(spdm_finish_request_t),
                                      hmac_size);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if (!spdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        hmac_size = 0;
    }

    ASSERT(*response_size >= sizeof(spdm_finish_response_t) + hmac_size);
    *response_size = sizeof(spdm_finish_response_t) + hmac_size;
    zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_FINISH_RSP;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    status = libspdm_append_message_f(spdm_context, session_info, false, spdm_response,
                                      sizeof(spdm_finish_response_t));
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if (spdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        result = spdm_generate_finish_rsp_hmac(
            spdm_context, session_info,
            (uint8_t *)spdm_response + sizeof(spdm_finish_request_t));
        if (!result) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }

        status = libspdm_append_message_f(
            spdm_context, session_info, false,
            (uint8_t *)spdm_response + sizeof(spdm_finish_request_t),
            hmac_size);
        if (RETURN_ERROR(status)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    DEBUG((DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n", session_id));
    status = libspdm_calculate_th2_hash(spdm_context, session_info, false,
                                        th2_hash_data);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    status = libspdm_generate_session_data_key(
        session_info->secured_message_context, th2_hash_data);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    result = libspdm_start_watchdog(session_id,
                                    spdm_context->local_context.heartbeat_period * 2);
    if (!result) {
        return RETURN_DEVICE_ERROR;
    }

    return RETURN_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
