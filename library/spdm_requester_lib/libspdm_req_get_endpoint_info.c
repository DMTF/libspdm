/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT

/**
 * This function sends GET_ENDPOINT_INFO and receives ENDPOINT_INFO *
 *
 *
 * @param  context                    A pointer to the SPDM context.
 * @param  session_id                 Indicates if it is a secured message protected via SPDM session.
 *                                    If session_id is NULL, it is a normal message.
 *                                    If session_id is not NULL, it is a secured message.
 * @param  request_attributes         The request attribute of the request message.
 * @param  sub_code                   The subcode of endpoint info.
 * @param  slot_id                    The number of slot for the endpoint info.
 * @param  ep_info_len                On input, indicate the size in bytes of the destination buffer
 *                                    to store the endpoint info record.
 *                                    On output, indicate the size in bytes of the endpoint info record.
 * @param  ep_info                    A pointer to a destination buffer to store the endpoint info record.
 * @param  requester_nonce_in         If not NULL, a buffer that holds the requester nonce (32 bytes)
 * @param  requester_nonce            If not NULL, a buffer to hold the requester nonce (32 bytes).
 * @param  responder_nonce            If not NULL, a buffer to hold the responder nonce (32 bytes).
 *
 **/
static libspdm_return_t libspdm_try_get_endpoint_info(libspdm_context_t *spdm_context,
                                                      const uint32_t *session_id,
                                                      uint8_t request_attributes,
                                                      uint8_t sub_code,
                                                      uint8_t slot_id,
                                                      uint32_t *ep_info_len,
                                                      void *ep_info,
                                                      const void *requester_nonce_in,
                                                      void *requester_nonce,
                                                      void *responder_nonce)
{
    bool result;
    libspdm_return_t status;
    spdm_get_endpoint_info_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_endpoint_info_response_t *spdm_response;
    size_t spdm_response_size;

    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t *spdm_nonce;
    void *signature;
    size_t signature_size;
    uint32_t ep_info_data_len;
    uint8_t *ep_info_data;
    uint8_t *ptr;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xF));
    LIBSPDM_ASSERT((slot_id != 0xF) ||
                   (spdm_context->local_context.peer_public_key_provision_size != 0));

    /* -=[Verify State Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (session_id == NULL) {
        session_info = NULL;
    } else {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG) &&
        ((request_attributes & SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) !=
         0)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if ((slot_id != 0) &&
        (request_attributes & SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if ((request_attributes & SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        signature_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
    } else {
        signature_size = 0;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  SPDM_GET_ENDPOINT_INFO);

    /* -=[Construct Request Phase]=- */
    spdm_context->connection_info.peer_used_cert_chain_slot_id = slot_id;
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    LIBSPDM_ASSERT (spdm_request_size >= sizeof(spdm_get_endpoint_info_request_t));
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_ENDPOINT_INFO;
    spdm_request->header.param1 = sub_code;
    spdm_request->header.param2 = slot_id;
    spdm_request->request_attributes = request_attributes;
    libspdm_write_uint24(spdm_request->reserved, 0);

    if ((request_attributes & SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        spdm_request_size = sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;
        spdm_nonce = (uint8_t *)(spdm_request + 1);

        if (requester_nonce_in == NULL) {
            if(!libspdm_get_random_number(SPDM_NONCE_SIZE, spdm_nonce)) {
                libspdm_release_sender_buffer (spdm_context);
                return LIBSPDM_STATUS_LOW_ENTROPY;
            }
        } else {
            libspdm_copy_mem(spdm_nonce, SPDM_NONCE_SIZE,
                             requester_nonce_in, SPDM_NONCE_SIZE);
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "RequesterNonce - "));
        LIBSPDM_INTERNAL_DUMP_DATA(spdm_nonce, SPDM_NONCE_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

        if (requester_nonce != NULL) {
            libspdm_copy_mem(requester_nonce, SPDM_NONCE_SIZE,
                             spdm_nonce, SPDM_NONCE_SIZE);
        }
    } else {
        spdm_request_size = sizeof(spdm_get_endpoint_info_request_t);
    }

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_GET_ENDPOINT_INFO, SPDM_ENDPOINT_INFO);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_ENDPOINT_INFO) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_endpoint_info_response_t) + sizeof(uint32_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    /* -=[Process Response Phase]=- */
    if ((request_attributes & SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED) != 0) {
        if ((spdm_response->header.param2 & SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK) != slot_id) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }

        /* nonce and signature should present if signature is requested */
        if (spdm_response_size <
            sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE + signature_size) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }

        ptr = (uint8_t *)(spdm_response + 1);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ResponderNonce (0x%x) - ", SPDM_NONCE_SIZE));
        LIBSPDM_INTERNAL_DUMP_DATA(ptr, SPDM_NONCE_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

        if (responder_nonce != NULL) {
            libspdm_copy_mem(responder_nonce, SPDM_NONCE_SIZE,
                             ptr, SPDM_NONCE_SIZE);
        }

        ptr += SPDM_NONCE_SIZE;
        ep_info_data_len = *(uint32_t *) ptr;
        if (spdm_response_size !=
            sizeof(spdm_endpoint_info_response_t) + SPDM_NONCE_SIZE +
            signature_size + ep_info_data_len + sizeof(uint32_t)) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ep_info_data_len - 0x%06x\n",
                       ep_info_data_len));
        ptr += sizeof(uint32_t);
        ep_info_data = ptr;

        status = libspdm_append_message_e(spdm_context, session_info, spdm_request,
                                          spdm_request_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }

        status = libspdm_append_message_e(spdm_context, session_info, spdm_response,
                                          spdm_response_size - signature_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }

        ptr += ep_info_data_len;
        signature = ptr;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature (0x%zx):\n", signature_size));
        LIBSPDM_INTERNAL_DUMP_HEX(signature, signature_size);

        result = libspdm_verify_endpoint_info_signature(
            spdm_context, session_info, true, signature, signature_size);
        if (!result) {
            status = LIBSPDM_STATUS_VERIF_FAIL;
            goto receive_done;
        }

        libspdm_reset_message_e(spdm_context, session_info);
    } else {
        /* responder's slot_id should be 0 */
        if ((spdm_response->header.param2 & SPDM_ENDPOINT_INFO_RESPONSE_SLOT_ID_MASK) != 0) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }

        /* nonce and signature not present */
        ptr = (uint8_t *)(spdm_response + 1);
        ep_info_data_len = *(uint32_t *) ptr;
        if (spdm_response_size <
            sizeof(spdm_endpoint_info_response_t) + ep_info_data_len + sizeof(uint32_t)) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ep_info_data_len - 0x%06x\n",
                       ep_info_data_len));

        ptr += sizeof(uint32_t);
        ep_info_data = ptr;
    }


    if (*ep_info_len < ep_info_data_len) {
        *ep_info_len = ep_info_data_len;
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto receive_done;
    }

    *ep_info_len = ep_info_data_len;
    libspdm_copy_mem(ep_info, ep_info_data_len,
                     ep_info_data, ep_info_data_len);

    status = LIBSPDM_STATUS_SUCCESS;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_get_endpoint_info(void *spdm_context,
                                           const uint32_t *session_id,
                                           uint8_t request_attributes,
                                           uint8_t sub_code,
                                           uint8_t slot_id,
                                           uint32_t *ep_info_len,
                                           void *ep_info,
                                           const void *requester_nonce_in,
                                           void *requester_nonce,
                                           void *responder_nonce)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_get_endpoint_info(
            context, session_id, request_attributes, sub_code, slot_id,
            ep_info_len, ep_info, requester_nonce_in,
            requester_nonce, responder_nonce);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
