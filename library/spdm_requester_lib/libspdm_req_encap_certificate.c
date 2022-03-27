/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * Process the SPDM encapsulated GET_CERTIFICATE request and return the response.
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
return_status libspdm_get_encap_response_certificate(void *context,
                                                     size_t request_size,
                                                     void *request,
                                                     size_t *response_size,
                                                     void *response)
{
    spdm_get_certificate_request_t *spdm_request;
    spdm_certificate_response_t *spdm_response;
    uint16_t offset;
    uint16_t length;
    size_t remainder_length;
    uint8_t slot_id;
    libspdm_context_t *spdm_context;
    return_status status;
    size_t response_capacity;

    spdm_context = context;
    spdm_request = request;

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_VERSION_MISMATCH,
            SPDM_GET_CERTIFICATE, response_size, response);
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_CERTIFICATE, response_size, response);
    }

    if (request_size != sizeof(spdm_get_certificate_request_t)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    slot_id = spdm_request->header.param1;

    if (slot_id >= spdm_context->local_context.slot_count) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    if (spdm_context->local_context
        .local_cert_chain_provision[slot_id] == NULL) {
        return libspdm_generate_encap_error_response(
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
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    if ((size_t)(offset + length) >
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

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

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

    status = libspdm_append_message_mut_b(spdm_context, spdm_request,
                                          request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    status = libspdm_append_message_mut_b(spdm_context, spdm_response,
                                          *response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    return RETURN_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
