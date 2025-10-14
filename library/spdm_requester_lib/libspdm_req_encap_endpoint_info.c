/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)

libspdm_return_t libspdm_get_encap_response_endpoint_info(void *spdm_context,
                                                          size_t request_size,
                                                          void *request,
                                                          size_t *response_size,
                                                          void *response)
{
    uint32_t session_id;
    spdm_get_endpoint_info_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_endpoint_info_response_t *spdm_response;
    size_t spdm_response_size;
    libspdm_return_t status;
    libspdm_context_t *context;
    size_t signature_size;
    uint32_t endpoint_info_size;
    uint8_t slot_id;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t *ptr;
    bool result;

    context = spdm_context;
    spdm_request = request;

    /* -=[Verify State Phase]=- */
    if (libspdm_get_connection_version(context) < SPDM_MESSAGE_VERSION_13) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_ENDPOINT_INFO, response_size, response);
    }

    if (context->last_spdm_request_session_id_valid) {
        session_id = context->last_spdm_request_session_id;
        session_info = libspdm_get_session_info_via_session_id(context, session_id);
        if (session_info == NULL) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
        }
    } else {
        session_info = NULL;
    }

    if (!libspdm_is_capabilities_flag_supported(
            context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP, 0)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_ENDPOINT_INFO, response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(context)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_VERSION_MISMATCH,
            0, response_size, response);
    }

    if (spdm_request->header.param1 !=
        SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_INVALID_REQUEST,
            0, response_size, response);
    }

    if ((spdm_request->request_attributes &
         SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        if (context->connection_info.algorithm.req_pqc_asym_alg != 0) {
            signature_size = libspdm_get_req_pqc_asym_signature_size(
                context->connection_info.algorithm.req_pqc_asym_alg);
        } else {
            signature_size = libspdm_get_req_asym_signature_size(
                context->connection_info.algorithm.req_base_asym_alg);
        }
        if (request_size <
            sizeof(spdm_get_endpoint_info_request_t) +
            SPDM_NONCE_SIZE) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
        spdm_request_size = sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;
    } else {
        if (request_size < sizeof(spdm_get_endpoint_info_request_t)) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
        spdm_request_size = sizeof(spdm_get_endpoint_info_request_t);
    }

    slot_id = 0;
    if ((spdm_request->request_attributes &
         SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        if (!libspdm_is_capabilities_flag_supported(
                context, false, 0,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG)) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                SPDM_GET_ENDPOINT_INFO, response_size, response);
        }

        slot_id = spdm_request->header.param2 & SPDM_GET_ENDPOINT_INFO_REQUEST_SLOT_ID_MASK;

        if ((slot_id != 0xF) && (slot_id >= SPDM_MAX_SLOT_COUNT)) {
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }

        if (slot_id != 0xF) {
            if (context->local_context.local_cert_chain_provision[slot_id] == NULL) {
                return libspdm_generate_encap_error_response(
                    context, SPDM_ERROR_CODE_INVALID_REQUEST,
                    0, response_size, response);
            }
        } else {
            if (context->local_context.local_public_key_provision == NULL) {
                return libspdm_generate_encap_error_response(
                    context, SPDM_ERROR_CODE_INVALID_REQUEST,
                    0, response_size, response);
            }
        }

        if (context->connection_info.multi_key_conn_req && slot_id != 0xF) {
            if ((context->local_context.local_key_usage_bit_mask[slot_id] &
                 SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE) == 0) {
                return libspdm_generate_encap_error_response(
                    context, SPDM_ERROR_CODE_INVALID_REQUEST,
                    0, response_size, response);
            }
        }
    }

    /* -=[Construct Response Phase]=- */
    /* response_size should be large enough to hold a ENDPOINT_INFO response without
     * EPInfo. */
    if ((spdm_request->request_attributes &
         SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        LIBSPDM_ASSERT(*response_size >= (sizeof(spdm_endpoint_info_response_t) +
                                          SPDM_NONCE_SIZE + sizeof(uint32_t) +
                                          signature_size));
        spdm_response_size = sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE +
                             sizeof(uint32_t) + signature_size;
    } else {
        LIBSPDM_ASSERT(*response_size >= (sizeof(spdm_endpoint_info_response_t) +
                                          sizeof(uint32_t)));
        spdm_response_size = sizeof(spdm_endpoint_info_response_t) + sizeof(uint32_t);
    }

    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    libspdm_reset_message_buffer_via_request_code(context, NULL,
                                                  spdm_request->header.request_response_code);

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = slot_id;
    ptr = (uint8_t *)spdm_response + sizeof(spdm_endpoint_info_response_t);

    if ((spdm_request->request_attributes &
         SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        if (!libspdm_get_random_number(SPDM_NONCE_SIZE, ptr)) {
            libspdm_reset_message_encap_e(context, session_info);
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
        ptr += SPDM_NONCE_SIZE;
    }
    ptr += sizeof(uint32_t);

    endpoint_info_size = (uint32_t) (*response_size - spdm_response_size);
    status = libspdm_generate_device_endpoint_info(
        context, spdm_request->header.param1,
        spdm_request->request_attributes,
        &endpoint_info_size, ptr);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_ENDPOINT_INFO, response_size, response);
    }
    libspdm_write_uint32(ptr - sizeof(uint32_t), endpoint_info_size);
    spdm_response_size += endpoint_info_size;
    *response_size = spdm_response_size;
    ptr += endpoint_info_size;

    if ((spdm_request->request_attributes &
         SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {

        status = libspdm_append_message_encap_e(context, session_info, spdm_request,
                                                spdm_request_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_reset_message_e(context, session_info);
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }

        status = libspdm_append_message_encap_e(context, session_info, spdm_response,
                                                spdm_response_size - signature_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_reset_message_e(context, session_info);
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }

        result = libspdm_generate_endpoint_info_signature(
            context, session_info, true, slot_id, ptr);

        if (!result) {
            libspdm_reset_message_encap_e(context, session_info);
            return libspdm_generate_encap_error_response(
                context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    libspdm_reset_message_encap_e(context, session_info);

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (..) */
