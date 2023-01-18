/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP

libspdm_return_t libspdm_get_response_set_certificate(libspdm_context_t *spdm_context,
                                                      size_t request_size, const void *request,
                                                      size_t *response_size, void *response)
{
    const spdm_set_certificate_request_t *spdm_request;
    spdm_set_certificate_response_t *spdm_response;

    bool result;
    uint8_t slot_id;

    size_t root_cert_hash_size;
    const spdm_cert_chain_t *cert_chain_header;
    size_t cert_chain_size;
    const void * cert_chain;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

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
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_SET_CERTIFICATE, response_size, response);
    }

    slot_id = spdm_request->header.param1 & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK;
    if (slot_id >= SPDM_MAX_SLOT_COUNT) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    root_cert_hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (request_size < sizeof(spdm_set_certificate_request_t) +
        sizeof(spdm_cert_chain_t) + root_cert_hash_size) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /*point to full SPDM certificate chain*/
    cert_chain = (const void*)(spdm_request + 1);
    cert_chain_header = cert_chain;

    if (cert_chain_header->length < sizeof(spdm_cert_chain_t) + root_cert_hash_size) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (cert_chain_header->length > request_size - sizeof(spdm_set_certificate_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /*get actual cert_chain size*/
    cert_chain_size = cert_chain_header->length - sizeof(spdm_cert_chain_t) - root_cert_hash_size;

    /*point to actual cert_chain*/
    cert_chain = (const void*)((const uint8_t *)cert_chain
                               + sizeof(spdm_cert_chain_t) + root_cert_hash_size);

    /* set certificate to NV*/
    result = libspdm_write_certificate_to_nvm(slot_id, cert_chain,
                                              cert_chain_size);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_set_certificate_response_t));
    *response_size = sizeof(spdm_set_certificate_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    /*requires a reset to complete the SET_CERTIFICATE request*/
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    } else {
        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_SET_CERTIFICATE_RSP;
        spdm_response->header.param1 = slot_id;
        spdm_response->header.param2 = 0;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP*/
