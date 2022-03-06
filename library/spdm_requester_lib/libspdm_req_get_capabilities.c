/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

/**
 * This function validates the Responder's capabilities.
 *
 * @param  capabilities_flag The Responder's CAPABILITIES.Flags field.
 * @param  version           The SPDM message version.
 *
 * @retval true  The field is valid.
 * @retval false The field is invalid.
 **/
static bool validate_responder_capability(uint32_t capabilities_flag,
                                          uint8_t version)
{
    /*uint8_t cache_cap = (uint8_t)(capabilities_flag)&0x01;*/
    uint8_t cert_cap = (uint8_t)(capabilities_flag >> 1) & 0x01;
    /*uint8_t chal_cap = (uint8_t)(capabilities_flag>>2)&0x01;*/
    uint8_t meas_cap = (uint8_t)(capabilities_flag >> 3) & 0x03;
    /*uint8_t meas_fresh_cap = (uint8_t)(capabilities_flag>>5)&0x01;*/
    uint8_t encrypt_cap = (uint8_t)(capabilities_flag >> 6) & 0x01;
    uint8_t mac_cap = (uint8_t)(capabilities_flag >> 7) & 0x01;
    uint8_t mut_auth_cap = (uint8_t)(capabilities_flag >> 8) & 0x01;
    uint8_t key_ex_cap = (uint8_t)(capabilities_flag >> 9) & 0x01;
    uint8_t psk_cap = (uint8_t)(capabilities_flag >> 10) & 0x03;
    uint8_t encap_cap = (uint8_t)(capabilities_flag >> 12) & 0x01;
    /*uint8_t hbeat_cap = (uint8_t)(capabilities_flag>>13)&0x01;
     * uint8_t key_upd_cap = (uint8_t)(capabilities_flag>>14)&0x01;*/
    uint8_t handshake_in_the_clear_cap = (uint8_t)(capabilities_flag >> 15) & 0x01;
    uint8_t pub_key_id_cap = (uint8_t)(capabilities_flag >> 16) & 0x01;

    switch (version) {
    case SPDM_MESSAGE_VERSION_10:
        return true;

    case SPDM_MESSAGE_VERSION_11:
    case SPDM_MESSAGE_VERSION_12: {
        /*Encrypt_cap set and psk_cap+key_ex_cap cleared*/
        if (encrypt_cap != 0 && (psk_cap == 0 && key_ex_cap == 0)) {
            return false;
        }
        /*MAC_cap set and psk_cap+key_ex_cap cleared*/
        if (mac_cap != 0 && (psk_cap == 0 && key_ex_cap == 0)) {
            return false;
        }
        /*Key_ex_cap set and encrypt_cap+mac_cap cleared*/
        if (key_ex_cap != 0 && (encrypt_cap == 0 && mac_cap == 0)) {
            return false;
        }
        /*PSK_cap set and encrypt_cap+mac_cap cleared*/
        if (psk_cap != 0 && (encrypt_cap == 0 && mac_cap == 0)) {
            return false;
        }
        /*Muth_auth_cap set and encap_cap cleared*/
        if (mut_auth_cap != 0 && encap_cap == 0) {
            return false;
        }
        /*Handshake_in_the_clear_cap set and key_ex_cap cleared*/
        if (handshake_in_the_clear_cap != 0 && key_ex_cap == 0) {
            return false;
        }
        /*Case "Handshake_in_the_clear_cap set and encrypt_cap+mac_cap cleared"
         * It will be verified by "Key_ex_cap set and encrypt_cap+mac_cap cleared" and
         *"Handshake_in_the_clear_cap set and key_ex_cap cleared" in above if statement,
         * so we don't add new if statement.*/

        /*Pub_key_id_cap set and cert_cap set*/
        if (pub_key_id_cap != 0 && cert_cap != 0) {
            return false;
        }
        /*reserved values selected in flags*/
        if (meas_cap == 3 || psk_cap == 3) {
            return false;
        }

        return true;
    }

    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
}

/**
 * This function sends GET_CAPABILITIES and receives CAPABILITIES.
 *
 * @param  spdm_context A pointer to the SPDM context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         GET_CAPABILITIES was sent and CAPABILITIES was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send GET_CAPABILITIES due to Requester's state. Send GET_VERSION first.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the CAPABILITIES response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The CAPABILITIES response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 **/
libspdm_return_t libspdm_try_get_capabilities(libspdm_context_t *spdm_context)
{
    libspdm_return_t status;
    spdm_get_capabilities_request_t *spdm_request;
    uintn spdm_request_size;
    spdm_capabilities_response_t *spdm_response;
    uintn spdm_response_size;
    uint8_t *message;
    uintn message_size;
    uintn transport_header_size;

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL, SPDM_GET_CAPABILITIES);
    if (spdm_context->connection_info.connection_state != LIBSPDM_CONNECTION_STATE_AFTER_VERSION) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;

    libspdm_zero_mem(spdm_request, sizeof(spdm_get_capabilities_request_t));
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request_size = sizeof(spdm_get_capabilities_request_t);
    } else if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request_size = sizeof(spdm_get_capabilities_request_t) -
                            sizeof(spdm_request->data_transfer_size) -
                            sizeof(spdm_request->max_spdm_msg_size);
    } else {
        spdm_request_size = sizeof(spdm_request->header);
    }
    spdm_request->header.request_response_code = SPDM_GET_CAPABILITIES;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request->ct_exponent = spdm_context->local_context.capability.ct_exponent;
    spdm_request->flags = spdm_context->local_context.capability.flags;
    spdm_request->data_transfer_size = spdm_context->local_context.capability.data_transfer_size;
    spdm_request->max_spdm_msg_size = spdm_context->local_context.capability.max_spdm_msg_size;
    status = libspdm_send_spdm_request(spdm_context, NULL, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context, message);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context, message);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* receive */

    libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(spdm_context, NULL, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_simple_error_response(
            spdm_context, spdm_response->header.param1);

        /* TODO: Replace this with LIBSPDM_RET_ON_ERR once libspdm_handle_simple_error_response
         * uses the new error codes. */
        if (status == RETURN_DEVICE_ERROR) {
            status = LIBSPDM_STATUS_ERROR_PEER;
            goto receive_done;
        }
        else if (status == RETURN_NO_RESPONSE) {
            status = LIBSPDM_STATUS_BUSY_PEER;
            goto receive_done;
        }
        else if (status == LIBSPDM_STATUS_RESYNCH_PEER) {
            status = LIBSPDM_STATUS_RESYNCH_PEER;
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_CAPABILITIES) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if (spdm_response_size < sizeof(spdm_capabilities_response_t)) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }
    } else {
        if (spdm_response_size < sizeof(spdm_capabilities_response_t) -
            sizeof(spdm_response->data_transfer_size) -
            sizeof(spdm_response->max_spdm_msg_size)) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_response_size = sizeof(spdm_capabilities_response_t);
    } else {
        spdm_response_size = sizeof(spdm_capabilities_response_t) -
                             sizeof(spdm_response->data_transfer_size) -
                             sizeof(spdm_response->max_spdm_msg_size);
    }

    if (!validate_responder_capability(spdm_response->flags, spdm_response->header.spdm_version)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    /* Cache data*/

    status = libspdm_append_message_a(spdm_context, spdm_request, spdm_request_size);
    /* TODO: Replace with LIBSPDM_RET_ON_ERR. */
    if (RETURN_ERROR(status)) {
        status = LIBSPDM_STATUS_BUFFER_FULL;
        goto receive_done;
    }

    status = libspdm_append_message_a(spdm_context, spdm_response, spdm_response_size);
    /* TODO: Replace with LIBSPDM_RET_ON_ERR. */
    if (RETURN_ERROR(status)) {
        status = LIBSPDM_STATUS_BUFFER_FULL;
        goto receive_done;
    }

    spdm_context->connection_info.capability.ct_exponent =
        spdm_response->ct_exponent;
    spdm_context->connection_info.capability.flags = spdm_response->flags;

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.capability.data_transfer_size =
            spdm_response->data_transfer_size;
        spdm_context->connection_info.capability.max_spdm_msg_size =
            spdm_response->max_spdm_msg_size;
    } else {
        spdm_context->connection_info.capability.data_transfer_size = 0;
        spdm_context->connection_info.capability.max_spdm_msg_size = 0;
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context, message);
    return status;
}

/**
 * This function sends GET_CAPABILITIES and receives CAPABILITIES. It may retry GET_CAPABILITIES
 * multiple times if the Responder replies with a Busy error.
 *
 * @param  spdm_context A pointer to the SPDM context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         GET_CAPABILITIES was sent and CAPABILITIES was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send GET_CAPABILITIES due to Requester's state. Send GET_VERSION first.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the CAPABILITIES response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The CAPABILITIES response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 **/
libspdm_return_t libspdm_get_capabilities(libspdm_context_t *spdm_context)
{
    uintn retry;
    libspdm_return_t status;

    spdm_context->crypto_request = false;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_get_capabilities(spdm_context);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
