/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT)

libspdm_return_t libspdm_register_get_endpoint_info_callback_func(
    void *spdm_context, libspdm_get_endpoint_info_callback_func get_endpoint_info_callback)
{
    libspdm_context_t *context = (libspdm_context_t *)spdm_context;
    context->get_endpoint_info_callback = get_endpoint_info_callback;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_get_encap_request_get_endpoint_info(
    libspdm_context_t *spdm_context,
    size_t *encap_request_size,
    void *encap_request)
{
    libspdm_return_t status;
    spdm_get_endpoint_info_request_t *spdm_request;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t *spdm_nonce;

    LIBSPDM_ASSERT(spdm_context->get_endpoint_info_callback != NULL);

    spdm_context->encap_context.last_encap_request_size = 0;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

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

    LIBSPDM_ASSERT(*encap_request_size >= sizeof(spdm_get_endpoint_info_request_t));

    spdm_request = encap_request;

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_ENDPOINT_INFO;
    spdm_request->header.param1 = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    spdm_request->header.param2 =
        spdm_context->encap_context.req_slot_id & SPDM_GET_ENDPOINT_INFO_REQUEST_SLOT_ID_MASK;

    /* request signature if requester support */
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG, 0)) {
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

    libspdm_copy_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size =
        *encap_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_endpoint_info(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    libspdm_return_t status;
    spdm_get_endpoint_info_request_t *spdm_request;
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

    LIBSPDM_ASSERT(spdm_context->get_endpoint_info_callback != NULL);

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

    spdm_request =
        (void *)&spdm_context->encap_context.last_encap_request_header;

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    if (spdm_response->header.spdm_version != libspdm_get_connection_version (spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(
            spdm_context, spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code != SPDM_ENDPOINT_INFO) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response_size < sizeof(spdm_endpoint_info_response_t) + sizeof(uint32_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    slot_id = spdm_context->encap_context.req_slot_id & SPDM_GET_ENDPOINT_INFO_REQUEST_SLOT_ID_MASK;
    spdm_context->connection_info.peer_used_cert_chain_slot_id = slot_id;

    /* request signature if requester support */
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG, 0)) {
        if (spdm_context->connection_info.algorithm.req_pqc_asym_alg != 0) {
            signature_size = libspdm_get_req_pqc_asym_signature_size(
                spdm_context->connection_info.algorithm.req_pqc_asym_alg);
        } else {
            signature_size = libspdm_get_req_asym_signature_size(
                spdm_context->connection_info.algorithm.req_base_asym_alg);
        }
        request_attributes = SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;

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
            spdm_context, session_info, false, signature, signature_size);
        if (!result) {
            return LIBSPDM_STATUS_VERIF_FAIL;
        }

        libspdm_reset_message_encap_e(spdm_context, session_info);
    } else {
        request_attributes = 0;

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

    status = spdm_context->get_endpoint_info_callback(
        spdm_context, spdm_request->header.param1, spdm_request->header.param2,
        request_attributes, ep_info_data_len, ep_info_data);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (...) */
