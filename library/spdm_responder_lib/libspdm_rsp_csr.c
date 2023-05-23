/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP

libspdm_return_t libspdm_get_response_csr(libspdm_context_t *spdm_context,
                                          size_t request_size, const void *request,
                                          size_t *response_size, void *response)
{
    const spdm_get_csr_request_t *spdm_request;
    spdm_csr_response_t *spdm_response;
    bool result;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    size_t csr_len;
    uint8_t *csr_p;
    uint16_t requester_info_length;
    uint16_t opaque_data_length;
    uint8_t *opaque_data;
    uint8_t *requester_info;
    bool need_reset;

    spdm_request = request;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_12) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, 0,
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

    if (request_size < sizeof(spdm_get_csr_request_t)) {
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
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_CSR, response_size, response);
    }

    requester_info_length = spdm_request->requester_info_length;
    opaque_data_length = spdm_request->opaque_data_length;

    if (opaque_data_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (opaque_data_length >
        request_size - sizeof(spdm_get_csr_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (requester_info_length >
        request_size - sizeof(spdm_get_csr_request_t) - opaque_data_length) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    requester_info = (void *)((size_t)(spdm_request + 1));

    opaque_data = (void *)(requester_info + requester_info_length);

    need_reset = libspdm_is_capabilities_flag_supported(
        spdm_context, false, 0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP);

    result = libspdm_verify_req_info(requester_info, requester_info_length);
    if (!result) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_csr_response_t));

    spdm_response = response;
    libspdm_zero_mem(response, *response_size);

    csr_len = *response_size - sizeof(spdm_csr_response_t);
    csr_p = (uint8_t*)(spdm_response + 1);
    result = libspdm_gen_csr(spdm_context->connection_info.algorithm.base_hash_algo,
                             spdm_context->connection_info.algorithm.base_asym_algo,
                             &need_reset, request, request_size,
                             requester_info, requester_info_length,
                             opaque_data, opaque_data_length,
                             &csr_len, csr_p);
    if (!result) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_csr_response_t) + csr_len);
    *response_size = sizeof(spdm_csr_response_t) + csr_len;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) &&
        need_reset) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    } else {
        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_CSR;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = (uint16_t)csr_len;
        spdm_response->reserved = 0;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP*/
