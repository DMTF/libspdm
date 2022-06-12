/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "library/spdm_device_secret_lib.h"

/**
 * Process the SPDM GET_CSR request and return the response.
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
libspdm_return_t libspdm_get_response_csr(void *context, size_t request_size,
                                          const void *request, size_t *response_size,
                                          void *response)
{
    const spdm_get_csr_request_t *spdm_request;
    spdm_csr_response_t *spdm_response;
    libspdm_context_t *spdm_context;
    bool result;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    size_t csr_len;
    uint8_t csr_pointer[LIBSPDM_MAX_CSR_SIZE];
    uint8_t *csr_p = csr_pointer;
    uint16_t requester_info_length;
    uint16_t opaque_data_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    uint8_t requester_info[LIBSPDM_MAX_REQUSET_INFO_SIZE];
    bool need_reset;

    spdm_context = context;
    spdm_request = request;

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

    requester_info_length = spdm_request->requester_info_length;
    if (requester_info_length < 0) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    opaque_data_length = spdm_request->opaque_data_length;
    if ((opaque_data_length < 0) || (opaque_data_length > SPDM_MAX_OPAQUE_DATA_SIZE)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_copy_mem(opaque_data, opaque_data_length,
                     (const void*)(spdm_request + 1), opaque_data_length);

    libspdm_copy_mem(requester_info, requester_info_length,
                     (const void*)((const uint8_t*)(spdm_request + 1) + opaque_data_length),
                     requester_info_length);

    need_reset = spdm_context->need_reset_to_get_csr;

    result = libspdm_verify_req_info(requester_info, requester_info_length);
    if (!result) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    csr_len = LIBSPDM_MAX_CSR_SIZE;
    result = libspdm_gen_csr(spdm_context->connection_info.algorithm.base_hash_algo,
                             spdm_context->connection_info.algorithm.base_asym_algo,
                             &need_reset, requester_info, requester_info_length,
                             &csr_len, &csr_p);
    if (!result) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_csr_response_t) + LIBSPDM_MAX_CSR_SIZE);
    *response_size = sizeof(spdm_csr_response_t) + csr_len;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    if (spdm_context->need_reset_to_get_csr && need_reset) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    } else {
        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_CSR;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = csr_len;
        spdm_response->reserved = 0;
    }

    libspdm_copy_mem(spdm_response + 1, spdm_response->csr_length,
                     csr_pointer, spdm_response->csr_length);

    return LIBSPDM_STATUS_SUCCESS;
}
