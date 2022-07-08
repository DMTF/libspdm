/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

/**
 * This function checks the compability of the received SPDM version,
 * if received version is valid, subsequent spdm communication will follow this version.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  version                      The SPMD message version.
 *
 *
 * @retval True                         The received SPDM version is valid.
 * @retval False                        The received SPDM version is invalid.
 **/
static bool libspdm_check_request_version_compability(libspdm_context_t *spdm_context,
                                                      uint8_t version)
{
    uint8_t local_ver;
    size_t index;

    for (index = 0;
         index < spdm_context->local_context.version.spdm_version_count;
         index++) {
        local_ver = libspdm_get_version_from_version_number(
            spdm_context->local_context.version.spdm_version[index]);
        if (local_ver == version) {
            spdm_context->connection_info.version = version << SPDM_VERSION_NUMBER_SHIFT_BIT;
            return true;
        }
    }
    return false;
}

/**
 * This function checks the compability of the received CAPABILITES flag.
 * Some flags are mutually inclusive/exclusive.
 *
 * @param  capabilities_flag             The received CAPABILITIES Flag.
 * @param  version                      The SPMD message version.
 *
 *
 * @retval True                         The received Capabilities flag is valid.
 * @retval False                        The received Capabilities flag is invalid.
 **/
static bool libspdm_check_request_flag_compability(uint32_t capabilities_flag,
                                                   uint8_t version)
{
    uint8_t cert_cap = (uint8_t)(capabilities_flag >> 1) & 0x01;
    /*uint8_t chal_cap = (uint8_t)(capabilities_flag>>2)&0x01;*/
    uint8_t meas_cap = (uint8_t)(capabilities_flag >> 3) & 0x03;
    uint8_t meas_fresh_cap = (uint8_t)(capabilities_flag >> 5) & 0x01;
    uint8_t encrypt_cap = (uint8_t)(capabilities_flag >> 6) & 0x01;
    uint8_t mac_cap = (uint8_t)(capabilities_flag >> 7) & 0x01;
    uint8_t mut_auth_cap = (uint8_t)(capabilities_flag >> 8) & 0x01;
    uint8_t key_ex_cap = (uint8_t)(capabilities_flag >> 9) & 0x01;
    uint8_t psk_cap = (uint8_t)(capabilities_flag >> 10) & 0x03;
    uint8_t encap_cap = (uint8_t)(capabilities_flag >> 12) & 0x01;
    /*uint8_t hbeat_cap = (uint8_t)(capabilities_flag>>13)&0x01;
     * uint8_t key_upd_cap = (uint8_t)(capabilities_flag>>14)&0x01;*/
    uint8_t handshake_in_the_clear_cap =
        (uint8_t)(capabilities_flag >> 15) & 0x01;
    uint8_t pub_key_id_cap = (uint8_t)(capabilities_flag >> 16) & 0x01;

    switch (version) {
    case SPDM_MESSAGE_VERSION_10:
        return true;

    case SPDM_MESSAGE_VERSION_11:
    case SPDM_MESSAGE_VERSION_12:
    {
        /*meas_cap shall be set to 00b*/
        if (meas_cap != 0) {
            return false;
        }
        /*meas_fresh_cap shall be set to 0b*/
        if (meas_fresh_cap != 0) {
            return false;
        }
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
        if (psk_cap == 2 || psk_cap == 3) {
            return false;
        }
    }
        return true;

    default:
        return true;
    }
}

/**
 * Process the SPDM GET_CAPABILITIES request and return the response.
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
libspdm_return_t libspdm_get_response_capabilities(void *context,
                                                   size_t request_size,
                                                   const void *request,
                                                   size_t *response_size,
                                                   void *response)
{
    const spdm_get_capabilities_request_t *spdm_request;
    spdm_capabilities_response_t *spdm_response;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_context = context;
    spdm_request = request;

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    if (spdm_context->connection_info.connection_state !=
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (!libspdm_check_request_version_compability(
            spdm_context, spdm_request->header.spdm_version)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if (request_size != sizeof(spdm_get_capabilities_request_t)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    } else if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (request_size != sizeof(spdm_get_capabilities_request_t) -
            sizeof(spdm_request->data_transfer_size) -
            sizeof(spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    } else {
        if (request_size != sizeof(spdm_message_header_t)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }

    if (!libspdm_check_request_flag_compability(
            spdm_request->flags, spdm_request->header.spdm_version)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if ((spdm_request->data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12) ||
            (spdm_request->data_transfer_size > spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }

        if (((spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP) == 0) &&
            (spdm_request->data_transfer_size != spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_capabilities_response_t));
    *response_size = sizeof(spdm_capabilities_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CAPABILITIES;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->ct_exponent =
        spdm_context->local_context.capability.ct_exponent;
    spdm_response->flags = spdm_context->local_context.capability.flags;
    spdm_response->data_transfer_size = spdm_context->local_context.capability.data_transfer_size;
    spdm_response->max_spdm_msg_size = spdm_context->local_context.capability.max_spdm_msg_size;

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        *response_size = sizeof(spdm_capabilities_response_t);
    } else {
        *response_size = sizeof(spdm_capabilities_response_t) -
                         sizeof(spdm_response->data_transfer_size) -
                         sizeof(spdm_response->max_spdm_msg_size);
    }


    /* Cache*/

    status = libspdm_append_message_a(spdm_context, spdm_request,
                                      request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    status = libspdm_append_message_a(spdm_context,
                                      spdm_response, *response_size);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_context->connection_info.capability.ct_exponent =
            spdm_request->ct_exponent;
        spdm_context->connection_info.capability.flags =
            spdm_request->flags;
    } else {
        spdm_context->connection_info.capability.ct_exponent = 0;
        spdm_context->connection_info.capability.flags = 0;
    }
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.capability.data_transfer_size =
            spdm_request->data_transfer_size;
        spdm_context->connection_info.capability.max_spdm_msg_size =
            spdm_request->max_spdm_msg_size;
    } else {
        spdm_context->connection_info.capability.data_transfer_size = 0;
        spdm_context->connection_info.capability.max_spdm_msg_size = 0;
    }
    libspdm_set_connection_state(spdm_context,
                                 LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES);

    return LIBSPDM_STATUS_SUCCESS;
}
