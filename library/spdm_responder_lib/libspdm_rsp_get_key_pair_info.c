/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

libspdm_return_t libspdm_get_response_key_pair_info(libspdm_context_t *spdm_context,
                                                    size_t request_size, const void *request,
                                                    size_t *response_size, void *response)
{
    const spdm_get_key_pair_info_request_t *spdm_request;
    spdm_key_pair_info_response_t *spdm_response;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    uint8_t total_key_pairs;
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t key_pair_id;
    bool result;
    uint8_t *public_key_info;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_KEY_PAIR_INFO);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_GET_KEY_PAIR_INFO,
                                               response_size, response);
    }

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(spdm_context,
                                                       spdm_request->header.request_response_code,
                                                       response_size, response);
    }

    if (request_size < sizeof(spdm_get_key_pair_info_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    if (spdm_context->last_spdm_request_session_id_valid) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context,
            spdm_context->last_spdm_request_session_id);
        if (session_info == NULL) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_KEY_PAIR_INFO, response_size, response);
    }

    total_key_pairs = spdm_context->local_context.total_key_pairs;
    key_pair_id = spdm_request->key_pair_id;
    if ((key_pair_id == 0) || (key_pair_id > total_key_pairs)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_key_pair_info_response_t));
    public_key_info_len = (uint16_t)(*response_size - sizeof(spdm_key_pair_info_response_t));
    libspdm_zero_mem(response, *response_size);

    public_key_info = (uint8_t*)response + sizeof(spdm_key_pair_info_response_t);
    result = libspdm_read_key_pair_info(
        spdm_context,
        key_pair_id,
        &capabilities,
        &key_usage_capabilities,
        &current_key_usage,
        &asym_algo_capabilities,
        &current_asym_algo,
        &assoc_cert_slot_mask,
        &public_key_info_len,
        public_key_info);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /*If responder doesn't support SET_KEY_PAIR_INFO_CAP,the capabilities should be 0*/
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP)) {
        capabilities = 0;
    }

    spdm_response = response;
    *response_size = sizeof(spdm_key_pair_info_response_t) + public_key_info_len;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_KEY_PAIR_INFO;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->total_key_pairs = total_key_pairs;
    spdm_response->key_pair_id = key_pair_id;
    spdm_response->capabilities = capabilities & SPDM_KEY_PAIR_CAP_MASK;
    spdm_response->key_usage_capabilities = key_usage_capabilities & SPDM_KEY_USAGE_BIT_MASK;
    spdm_response->current_key_usage = current_key_usage & SPDM_KEY_USAGE_BIT_MASK;
    spdm_response->asym_algo_capabilities = asym_algo_capabilities &
                                            SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    spdm_response->current_asym_algo = current_asym_algo & SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    spdm_response->public_key_info_len = public_key_info_len;
    spdm_response->assoc_cert_slot_mask = assoc_cert_slot_mask;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/
