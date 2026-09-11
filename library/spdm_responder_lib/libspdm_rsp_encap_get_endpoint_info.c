/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT)

libspdm_return_t libspdm_get_encap_request_get_endpoint_info(
    void *context,
    const uint32_t *session_id,
    uint8_t sub_code,
    uint8_t slot_id,
    uint8_t request_attributes,
    size_t ep_info_size,
    void *ep_info,
    size_t *encap_request_size,
    void *encap_request)
{
    libspdm_encap_context_t *encap_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;
    spdm_get_endpoint_info_request_t *spdm_request;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t *spdm_nonce;

    spdm_context = context;

    if ((ep_info == NULL) || (ep_info_size == 0)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if ((slot_id >= SPDM_MAX_SLOT_COUNT) && (slot_id != 0xF)) {
        /* SlotID is a four-bit field in which 0xF designates the Requester's provisioned public
         * key. Any other slot indexes per-slot state of SPDM_MAX_SLOT_COUNT entries, which
         * ENDPOINT_INFO is verified against. */
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    encap_context = libspdm_get_encap_context(spdm_context, session_id);
    if (encap_context == NULL) {
        /* session_id does not refer to an existing session. */
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    encap_context->last_encap_request_size = 0;

    /* The endpoint information is written here once the ENDPOINT_INFO response is verified. */
    encap_context->payload_buffer = ep_info;
    encap_context->payload_buffer_max_size = ep_info_size;
    encap_context->payload_buffer_size = 0;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (((request_attributes &
          SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) &&
        !libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG, 0)) {
        /* The Requester cannot sign ENDPOINT_INFO, and would reject the request with
         * ERROR(UnsupportedRequest), so do not send it. */
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    } else {
        session_info = NULL;
    }

    LIBSPDM_ASSERT(*encap_request_size >= sizeof(spdm_get_endpoint_info_request_t));

    /* Store slot_id in context so process_encap_response can retrieve it. */
    encap_context->req_slot_id = slot_id;

    spdm_request = encap_request;

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_ENDPOINT_INFO;
    spdm_request->header.param1 = sub_code;
    spdm_request->header.param2 = slot_id & SPDM_GET_ENDPOINT_INFO_REQUEST_SLOT_ID_MASK;

    if (request_attributes & SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) {
        LIBSPDM_ASSERT(
            *encap_request_size >= sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE);
        *encap_request_size = sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

        spdm_request->request_attributes =
            SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
        libspdm_write_uint24(spdm_request->reserved, 0);

        spdm_nonce = (uint8_t *)(spdm_request + 1);
        if (!libspdm_get_random_number(SPDM_NONCE_SIZE, spdm_nonce)) {
            libspdm_release_sender_buffer (spdm_context);
            return LIBSPDM_STATUS_LOW_ENTROPY;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap RequesterNonce - "));
        LIBSPDM_INTERNAL_DUMP_DATA(spdm_nonce, SPDM_NONCE_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

        libspdm_reset_message_encap_e(spdm_context, session_info);

        status = libspdm_append_message_encap_e(spdm_context, session_info,
                                                spdm_request, *encap_request_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }

    } else {
        *encap_request_size = sizeof(spdm_get_endpoint_info_request_t);
        spdm_request->request_attributes = 0;
        libspdm_write_uint24(spdm_request->reserved, 0);
    }

    /* Store the RequestAttributes that were sent, as last_encap_request_header only retains the
     * message header and process_encap_response must honour what was requested. */
    encap_context->req_attributes = spdm_request->request_attributes;

    libspdm_copy_mem(&encap_context->last_encap_request_header,
                     sizeof(encap_context->last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    encap_context->last_encap_request_size = *encap_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_endpoint_info(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    libspdm_encap_context_t *encap_context;
    libspdm_return_t status;
    const spdm_endpoint_info_response_t *spdm_response;
    size_t spdm_response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    const uint8_t *ptr;
    const uint8_t *ep_info_data;
    uint32_t ep_info_data_len;
    size_t signature_size;
    const void *signature;
    uint8_t slot_id;
    bool result;
    uint8_t request_attributes;

    if (spdm_context->last_spdm_request_session_id_valid) {
        session_id = spdm_context->last_spdm_request_session_id;
        session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    } else {
        session_info = NULL;
    }

    encap_context = libspdm_get_encap_context_via_last_request(spdm_context);

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    if (spdm_response->header.spdm_version != libspdm_get_connection_version (spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code != SPDM_ENDPOINT_INFO) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response_size < sizeof(spdm_endpoint_info_response_t) + sizeof(uint32_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    slot_id = encap_context->req_slot_id & SPDM_GET_ENDPOINT_INFO_REQUEST_SLOT_ID_MASK;

    /* The Integrator decides whether a signature is requested, so the response is processed
     * according to the RequestAttributes that were sent. */
    request_attributes = encap_context->req_attributes;

    if ((request_attributes & SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        if (spdm_context->connection_info.algorithm.req_pqc_asym_alg != 0) {
            signature_size = libspdm_get_req_pqc_asym_signature_size(
                spdm_context->connection_info.algorithm.req_pqc_asym_alg);
        } else {
            signature_size = libspdm_get_req_asym_signature_size(
                spdm_context->connection_info.algorithm.req_base_asym_alg);
        }
        if ((spdm_response->header.param2 & SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK) != slot_id) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        if (spdm_response_size <
            sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE + signature_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }

        ptr = (const uint8_t *)(spdm_response + 1);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap ResponderNonce (0x%x) - ", SPDM_NONCE_SIZE));
        LIBSPDM_INTERNAL_DUMP_DATA(ptr, SPDM_NONCE_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

        ptr += SPDM_NONCE_SIZE;
        ep_info_data_len = *(const uint32_t *) ptr;

        if (spdm_response_size !=
            sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE +
            signature_size + ep_info_data_len + sizeof(uint32_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ep_info_data_len - 0x%06x\n",
                       ep_info_data_len));
        ptr += sizeof(uint32_t);
        ep_info_data = ptr;

        status = libspdm_append_message_encap_e(spdm_context, session_info, spdm_response,
                                                spdm_response_size - signature_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }

        ptr += ep_info_data_len;
        signature = ptr;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature (0x%zx):\n", signature_size));
        LIBSPDM_INTERNAL_DUMP_HEX(signature, signature_size);

        result = libspdm_verify_endpoint_info_signature(
            spdm_context, session_info, false, slot_id, signature, signature_size);
        if (!result) {
            return LIBSPDM_STATUS_VERIF_FAIL;
        }

        libspdm_reset_message_encap_e(spdm_context, session_info);
    } else {
        /* responder's slot_id should be 0 */
        if ((spdm_response->header.param2 & SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK) != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        /* nonce and signature not present */
        ptr = (const uint8_t *)(spdm_response + 1);
        ep_info_data_len = *(const uint32_t *) ptr;
        if (spdm_response_size <
            sizeof(spdm_endpoint_info_response_t) + ep_info_data_len + sizeof(uint32_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ep_info_data_len - 0x%06x\n",
                       ep_info_data_len));
        ptr += sizeof(uint32_t);
        ep_info_data = ptr;
    }

    *need_continue = false;

    if (ep_info_data_len > encap_context->payload_buffer_max_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "endpoint info buffer too small\n"));
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (ep_info_data_len != 0) {
        libspdm_copy_mem(encap_context->payload_buffer,
                         encap_context->payload_buffer_max_size,
                         ep_info_data, ep_info_data_len);
    }
    encap_context->payload_buffer_size = ep_info_data_len;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (...) */
