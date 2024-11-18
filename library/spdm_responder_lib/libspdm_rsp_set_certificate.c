/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP

#if LIBSPDM_CERT_PARSE_SUPPORT
/*set_cert verify cert_chain*/
static bool libspdm_set_cert_verify_certchain(uint8_t spdm_version,
                                              const uint8_t *cert_chain, size_t cert_chain_size,
                                              uint32_t base_asym_algo, uint32_t base_hash_algo,
                                              uint8_t cert_model)
{
    const uint8_t *root_cert_buffer;
    size_t root_cert_buffer_size;
    const uint8_t *leaf_cert_buffer;
    size_t leaf_cert_buffer_size;

    /*get root cert*/
    if (!libspdm_x509_get_cert_from_cert_chain(
            cert_chain, cert_chain_size, 0, &root_cert_buffer,
            &root_cert_buffer_size)) {
        return false;
    }

    /*verify cert_chain*/
    if (!libspdm_x509_verify_cert_chain(root_cert_buffer, root_cert_buffer_size,
                                        cert_chain, cert_chain_size)) {
        return false;
    }

    /*get leaf cert*/
    if (!libspdm_x509_get_cert_from_cert_chain(
            cert_chain, cert_chain_size, -1, &leaf_cert_buffer,
            &leaf_cert_buffer_size)) {
        return false;
    }

    if (spdm_version == SPDM_MESSAGE_VERSION_12) {
        const bool is_device_cert_model =
            (cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);

        /*verify leaf cert*/
        if (!libspdm_x509_set_cert_certificate_check(leaf_cert_buffer, leaf_cert_buffer_size,
                                                     base_asym_algo, base_hash_algo,
                                                     false, is_device_cert_model)) {
            return false;
        }
    } else {
        if (!libspdm_x509_set_cert_certificate_check_ex(leaf_cert_buffer, leaf_cert_buffer_size,
                                                        base_asym_algo, base_hash_algo,
                                                        false, cert_model)) {
            return false;
        }
    }

    return true;
}
#endif /*LIBSPDM_CERT_PARSE_SUPPORT*/

libspdm_return_t libspdm_get_response_set_certificate(libspdm_context_t *spdm_context,
                                                      size_t request_size, const void *request,
                                                      size_t *response_size, void *response)
{
    const spdm_set_certificate_request_t *spdm_request;
    spdm_set_certificate_response_t *spdm_response;

    bool result;
    uint8_t spdm_version;
    uint8_t slot_id;
    bool need_reset;
    bool is_busy;
    bool erase;
    uint8_t set_cert_model;

    size_t root_cert_hash_size;
    const spdm_cert_chain_t *cert_chain_header;
    size_t cert_chain_size;
    const void * cert_chain;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_SET_CERTIFICATE);

    spdm_version = libspdm_get_connection_version(spdm_context);

    if (spdm_version < SPDM_MESSAGE_VERSION_12) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_SET_CERTIFICATE,
                                               response_size, response);
    }

    if (spdm_request->header.spdm_version != spdm_version) {
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

    slot_id = spdm_request->header.param1 & SPDM_SET_CERTIFICATE_REQUEST_SLOT_ID_MASK;
    if (slot_id >= SPDM_MAX_SLOT_COUNT) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if ((!libspdm_is_in_trusted_environment(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
             spdm_context
#endif
             )) &&
        (slot_id != 0) &&
        (!spdm_context->last_spdm_request_session_id_valid)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                               response_size, response);
    }

    root_cert_hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (spdm_version >= SPDM_MESSAGE_VERSION_13) {
        const uint8_t key_pair_id = spdm_request->header.param2;

        set_cert_model =
            (spdm_request->header.param1 &
             SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_CERT_MODEL_MASK) >>
            SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_CERT_MODEL_OFFSET;
        erase = (spdm_request->header.param1 & SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_ERASE) != 0;

        if (spdm_context->connection_info.multi_key_conn_rsp) {
            if (key_pair_id == 0) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                       response_size, response);
            }
            if (!erase) {
                if ((set_cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) ||
                    (set_cert_model > SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT)) {
                    return libspdm_generate_error_response(spdm_context,
                                                           SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                           response_size, response);
                }
            }
        } else {
            if ((key_pair_id != 0) || (set_cert_model != 0)) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                       response_size, response);
            }
            if ((spdm_context->local_context.capability.flags &
                 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP) != 0) {
                set_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
            } else {
                set_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
            }
        }
    } else {
        if ((spdm_context->local_context.capability.flags &
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP) != 0) {
            set_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
        } else {
            set_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
        }
    }

    need_reset = libspdm_is_capabilities_flag_supported(
        spdm_context, false, 0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP);
    is_busy = false;

    if ((spdm_version >= SPDM_MESSAGE_VERSION_13) && erase) {
        /*the CertChain field shall be absent;the value of SetCertModel shall be zero*/
        if ((request_size < sizeof(spdm_set_certificate_request_t)) ||
            ((spdm_request->header.param1 &
              SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_CERT_MODEL_MASK) != 0)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }

        /* erase slot_id cert_chain*/
        result = libspdm_write_certificate_to_nvm(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            slot_id, NULL, 0, 0, 0
#if LIBSPDM_SET_CERT_CSR_PARAMS
            , &need_reset, &is_busy
#endif /* LIBSPDM_SET_CERT_CSR_PARAMS */
            );
        if (!result) {
            if (is_busy) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_BUSY, 0,
                                                       response_size, response);
            } else {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                                                       response_size, response);
            }
        }
    } else {
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
        cert_chain_size = cert_chain_header->length - sizeof(spdm_cert_chain_t) -
                          root_cert_hash_size;

        /*point to actual cert_chain*/
        cert_chain = (const void*)((const uint8_t *)cert_chain
                                   + sizeof(spdm_cert_chain_t) + root_cert_hash_size);

#if LIBSPDM_CERT_PARSE_SUPPORT
        /*check the cert_chain*/
        result = libspdm_set_cert_verify_certchain(spdm_version,
                                                   cert_chain, cert_chain_size,
                                                   spdm_context->connection_info.algorithm.base_asym_algo,
                                                   spdm_context->connection_info.algorithm.base_hash_algo,
                                                   set_cert_model);
        if (!result) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }
#endif /*LIBSPDM_CERT_PARSE_SUPPORT*/

        /* set certificate to NV*/
        result = libspdm_write_certificate_to_nvm(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            slot_id, cert_chain,
            cert_chain_size,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.base_asym_algo
#if LIBSPDM_SET_CERT_CSR_PARAMS
            , &need_reset, &is_busy
#endif /* LIBSPDM_SET_CERT_CSR_PARAMS */
            );

        if (!result) {
            if (is_busy) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_BUSY, 0,
                                                       response_size, response);
            } else {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                       response_size, response);
            }
        }
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_set_certificate_response_t));
    *response_size = sizeof(spdm_set_certificate_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    /*requires a reset to complete the SET_CERTIFICATE request*/
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) && need_reset) {
        spdm_context->local_context.cert_slot_reset_mask |= (1 << slot_id);

        /*the device will reset to set cert*/
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

#endif /*LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP*/
