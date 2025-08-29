/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP)

libspdm_return_t libspdm_get_encap_response_certificate(void *spdm_context,
                                                        size_t request_size,
                                                        void *request,
                                                        size_t *response_size,
                                                        void *response)
{
    spdm_get_certificate_large_request_t *spdm_request;
    spdm_certificate_large_response_t *spdm_response;
    uint32_t offset;
    uint32_t length;
    uint32_t remainder_length;
    uint8_t slot_id;
    libspdm_context_t *context;
    libspdm_return_t status;
    size_t response_capacity;
    bool use_large_cert_chain;
    uint32_t req_msg_header_size;
    uint32_t rsp_msg_header_size;
    size_t cert_chain_size;

    context = spdm_context;
    spdm_request = request;

    if (libspdm_get_connection_version(context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_CERTIFICATE, response_size, response);
    }

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(context)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_VERSION_MISMATCH,
            0, response_size, response);
    }

    if (!libspdm_is_capabilities_flag_supported(
            context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_CERTIFICATE, response_size, response);
    }

    if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
        ((spdm_request->header.param1 & SPDM_GET_CERTIFICATE_REQUEST_LARGE_CERT_CHAIN) != 0)) {
        if (!libspdm_is_capabilities_flag_supported(
                context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP, 0)) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                SPDM_GET_CERTIFICATE, response_size, response);
        }
        use_large_cert_chain = true;
    } else {
        use_large_cert_chain = false;
    }

    if (use_large_cert_chain) {
        req_msg_header_size = sizeof(spdm_get_certificate_large_request_t);
        rsp_msg_header_size = sizeof(spdm_certificate_large_response_t);
    } else {
        req_msg_header_size = sizeof(spdm_get_certificate_request_t);
        rsp_msg_header_size = sizeof(spdm_certificate_response_t);
    }

    if (request_size < req_msg_header_size) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    slot_id = spdm_request->header.param1 & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK;

    if (slot_id >= SPDM_MAX_SLOT_COUNT) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    if (context->local_context.local_cert_chain_provision[slot_id] == NULL) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }

    cert_chain_size = context->local_context.local_cert_chain_provision_size[slot_id];

    if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
        (!use_large_cert_chain) && (cert_chain_size > SPDM_MAX_CERTIFICATE_CHAIN_SIZE)) {
        return libspdm_generate_encap_extended_error_response(
            context, SPDM_ERROR_CODE_DATA_TOO_LARGE, 0,
            sizeof(spdm_error_data_cert_chain_too_large_t),
            (const uint8_t *)&cert_chain_size,
            response_size, response);
    }

    if (use_large_cert_chain) {
        offset = spdm_request->large_offset;
        length = spdm_request->large_length;
    } else {
        offset = spdm_request->offset;
        length = spdm_request->length;
    }

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (spdm_request->header.param2 &
            SPDM_GET_CERTIFICATE_REQUEST_ATTRIBUTES_SLOT_SIZE_REQUESTED) {
            offset = 0;
            length = 0;
        }
    }

    if (length > LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN) {
        length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    }

    if (offset >= cert_chain_size) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    if ((size_t)(offset + length) > cert_chain_size) {
        length = (uint32_t)(cert_chain_size - offset);
    }
    remainder_length = (uint32_t)(cert_chain_size - (length + offset));

    libspdm_reset_message_buffer_via_request_code(context, NULL,
                                                  spdm_request->header.request_response_code);

    LIBSPDM_ASSERT(*response_size >= rsp_msg_header_size + length);
    response_capacity = *response_size;
    *response_size = rsp_msg_header_size + length;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = slot_id;
    spdm_response->header.param2 = 0;
    if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        context->connection_info.multi_key_conn_req) {
        spdm_response->header.param2 = context->local_context.local_cert_info[slot_id];
    }
    if (use_large_cert_chain) {
        spdm_response->header.param1 |= SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN;
    }

    if (use_large_cert_chain) {
        spdm_response->portion_length = 0;
        spdm_response->remainder_length = 0;
        spdm_response->large_portion_length = length;
        spdm_response->large_remainder_length = remainder_length;
    } else {
        spdm_response->portion_length = (uint16_t)length;
        spdm_response->remainder_length = (uint16_t)remainder_length;
    }

    libspdm_copy_mem((uint8_t *)spdm_response + rsp_msg_header_size,
                     response_capacity - rsp_msg_header_size,
                     (const uint8_t *)context->local_context
                     .local_cert_chain_provision[slot_id] + offset, length);

    /* Cache*/

    status = libspdm_append_message_mut_b(context, spdm_request,
                                          request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    status = libspdm_append_message_mut_b(context, spdm_response,
                                          *response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (..) */
