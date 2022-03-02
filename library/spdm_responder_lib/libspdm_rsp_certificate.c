/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * Process the SPDM GET_CERTIFICATE request and return the response.
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
return_status libspdm_get_response_certificate(void *context,
                                               uintn request_size,
                                               const void *request,
                                               uintn *response_size,
                                               void *response)
{
    const spdm_get_certificate_request_t *spdm_request;
    spdm_certificate_response_t *spdm_response;
    uint16_t offset;
    uint16_t length;
    uintn remainder_length;
    uint8_t slot_id;
    libspdm_context_t *spdm_context;
    return_status status;
    uintn response_capacity;

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
    if ((spdm_context->connection_info.connection_state !=
         LIBSPDM_CONNECTION_STATE_NEGOTIATED) &&
        (spdm_context->connection_info.connection_state !=
         LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS) &&
        (spdm_context->connection_info.connection_state !=
         LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_CERTIFICATE, response_size, response);
    }

    if (request_size != sizeof(spdm_get_certificate_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    slot_id = spdm_request->header.param1 & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK;

    if (slot_id >= spdm_context->local_context.slot_count) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->local_context
        .local_cert_chain_provision[slot_id] == NULL) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }

    offset = spdm_request->offset;
    length = spdm_request->length;
    if (length > LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN) {
        length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    }

    if (offset >= spdm_context->local_context
        .local_cert_chain_provision_size[slot_id]) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    if ((uintn)(offset + length) >
        spdm_context->local_context
        .local_cert_chain_provision_size[slot_id]) {
        length = (uint16_t)(
            spdm_context->local_context
            .local_cert_chain_provision_size[slot_id] -
            offset);
    }
    remainder_length = spdm_context->local_context
                       .local_cert_chain_provision_size[slot_id] -
                       (length + offset);

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_certificate_response_t) + length);
    response_capacity = *response_size;
    *response_size = sizeof(spdm_certificate_response_t) + length;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = slot_id;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = length;
    spdm_response->remainder_length = (uint16_t)remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     response_capacity - sizeof(spdm_certificate_response_t),
                     (uint8_t *)spdm_context->local_context
                     .local_cert_chain_provision[slot_id] + offset,
                     length);

    /* Cache*/

    status = libspdm_append_message_b(spdm_context, spdm_request,
                                      request_size);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_b(spdm_context, spdm_response,
                                      *response_size);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    libspdm_set_connection_state(spdm_context,
                                 LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE);

    return RETURN_SUCCESS;
}


#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
