/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP

libspdm_return_t libspdm_get_response_measurement_extension_log(libspdm_context_t *spdm_context,
                                                                size_t request_size,
                                                                const void *request,
                                                                size_t *response_size,
                                                                void *response)
{
    const spdm_get_measurement_extension_log_request_t *spdm_request;
    spdm_measurement_extension_log_response_t *spdm_response;
    uint32_t offset;
    uint32_t length;
    size_t remainder_length;
    size_t response_capacity;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    spdm_measurement_extension_log_dmtf_t *spdm_mel;
    size_t spdm_mel_len;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code ==
                   SPDM_GET_MEASUREMENT_EXTENSION_LOG);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               0,
                                               response_size, response);
    }

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
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    session_info = NULL;
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
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            0, response_size, response);
    }

    if ((spdm_context->connection_info.algorithm.mel_spec == 0) ||
        (spdm_context->connection_info.algorithm.measurement_hash_algo == 0) ) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
            0, response_size, response);
    }

    if (request_size < sizeof(spdm_get_measurement_extension_log_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    offset = spdm_request->offset;
    length = spdm_request->length;

    if (!libspdm_is_capabilities_flag_supported(spdm_context, false,
                                                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP,
                                                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP)) {
        if (length > LIBSPDM_MAX_MEL_BLOCK_LEN) {
            length = LIBSPDM_MAX_MEL_BLOCK_LEN;
        }
    }

    spdm_mel = NULL;
    spdm_mel_len = 0;
    if (!libspdm_measurement_extension_log_collection(
            spdm_context,
            spdm_context->connection_info.algorithm.mel_spec,
            spdm_context->connection_info.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm.measurement_hash_algo,
            (void **)&spdm_mel, &spdm_mel_len)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                                               response_size, response);
    }

    if (offset >= spdm_mel_len) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if ((uint64_t)(offset + length) > spdm_mel_len) {
        length = (uint32_t)(spdm_mel_len - offset);
    }
    remainder_length = spdm_mel_len - (length + offset);

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_measurement_extension_log_response_t) + length);

    response_capacity = *response_size;
    *response_size = sizeof(spdm_measurement_extension_log_response_t) + length;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_MEASUREMENT_EXTENSION_LOG;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    spdm_response->portion_length = length;
    spdm_response->remainder_length = (uint32_t)remainder_length;

    libspdm_copy_mem(spdm_response + 1,
                     response_capacity - sizeof(spdm_measurement_extension_log_response_t),
                     (const uint8_t *)spdm_mel + offset, length);

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
