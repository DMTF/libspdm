/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t number_of_blocks;
    uint8_t measurement_record_length[3];
    uint8_t measurement_record[(sizeof(spdm_measurement_block_dmtf_t) +
                                LIBSPDM_MAX_HASH_SIZE) *
                               LIBSPDM_MAX_MEASUREMENT_BLOCK_COUNT];
    uint8_t nonce[SPDM_NONCE_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
} spdm_measurements_response_max_t;
#pragma pack()

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

/**
 * This function sends GET_MEASUREMENT
 * to get measurement from the device.
 *
 * If the signature is requested, this function verifies the signature of the measurement.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  request_attribute             The request attribute of the request message.
 * @param  measurement_operation         The measurement operation of the request message.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  content_changed               The measurement content changed output param.
 * @param  number_of_blocks               The number of blocks of the measurement record.
 * @param  measurement_record_length      On input, indicate the size in bytes of the destination buffer to store the measurement record.
 *                                     On output, indicate the size in bytes of the measurement record.
 * @param  measurement_record            A pointer to a destination buffer to store the measurement record.
 * @param  requester_nonce_in            A buffer to hold the requester nonce (32 bytes) as input, if not NULL.
 * @param  requester_nonce               A buffer to hold the requester nonce (32 bytes), if not NULL.
 * @param  responder_nonce               A buffer to hold the responder nonce (32 bytes), if not NULL.
 *
 * @retval RETURN_SUCCESS               The measurement is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status try_spdm_get_measurement(void *context, const uint32_t *session_id,
                                       uint8_t request_attribute,
                                       uint8_t measurement_operation,
                                       uint8_t slot_id_param,
                                       uint8_t *content_changed,
                                       uint8_t *number_of_blocks,
                                       uint32_t *measurement_record_length,
                                       void *measurement_record,
                                       const void *requester_nonce_in,
                                       void *requester_nonce,
                                       void *responder_nonce)
{
    bool result;
    return_status status;
    spdm_get_measurements_request_t spdm_request;
    uintn spdm_request_size;
    spdm_measurements_response_max_t spdm_response;
    uintn spdm_response_size;
    uint32_t measurement_record_data_length;
    uint8_t *measurement_record_data;
    spdm_measurement_block_common_header_t *measurement_block_header;
    uint32_t measurement_block_size;
    uint8_t measurement_block_count;
    uint8_t *ptr;
    void *nonce;
    uint16_t opaque_length;
    void *opaque;
    void *signature;
    uintn signature_size;
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    spdm_context = context;
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
        return RETURN_UNSUPPORTED;
    }
    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                               SPDM_GET_MEASUREMENTS);
    if (session_id == NULL) {
        if (spdm_context->connection_info.connection_state <
            LIBSPDM_CONNECTION_STATE_AUTHENTICATED) {
            return RETURN_UNSUPPORTED;
        }
        session_info = NULL;
    } else {
        if (spdm_context->connection_info.connection_state <
            LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
            return RETURN_UNSUPPORTED;
        }
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        if (session_info == NULL) {
            ASSERT(false);
            return RETURN_UNSUPPORTED;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return RETURN_UNSUPPORTED;
        }
    }

    if ((slot_id_param >= SPDM_MAX_SLOT_COUNT) && (slot_id_param != 0xF)) {
        return RETURN_INVALID_PARAMETER;
    }
    if ((slot_id_param == 0xF) &&
        (spdm_context->local_context.peer_cert_chain_provision_size == 0)) {
        return RETURN_INVALID_PARAMETER;
    }

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    if (spdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG) &&
        (request_attribute != 0)) {
        return RETURN_INVALID_PARAMETER;
    }

    if ((request_attribute &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        signature_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
    } else {
        signature_size = 0;
    }

    spdm_request.header.spdm_version = spdm_get_connection_version (spdm_context);
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = request_attribute;
    spdm_request.header.param2 = measurement_operation;
    if ((request_attribute &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_request.header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
            spdm_request_size = sizeof(spdm_request);
        } else {
            spdm_request_size = sizeof(spdm_request) -
                                sizeof(spdm_request.slot_id_param);
        }

        if (requester_nonce_in == NULL) {
            if(!libspdm_get_random_number(SPDM_NONCE_SIZE, spdm_request.nonce)) {
                return RETURN_DEVICE_ERROR;
            }
        } else {
            copy_mem(spdm_request.nonce, sizeof(spdm_request.nonce),
                     requester_nonce_in, SPDM_NONCE_SIZE);
        }
        DEBUG((DEBUG_INFO, "ClientNonce - "));
        internal_dump_data(spdm_request.nonce, SPDM_NONCE_SIZE);
        DEBUG((DEBUG_INFO, "\n"));
        spdm_request.slot_id_param = slot_id_param;

        if (requester_nonce != NULL) {
            copy_mem(requester_nonce, SPDM_NONCE_SIZE,
                     spdm_request.nonce, SPDM_NONCE_SIZE);
        }
    } else {
        spdm_request_size = sizeof(spdm_request.header);

        if (requester_nonce != NULL) {
            zero_mem (requester_nonce, SPDM_NONCE_SIZE);
        }
    }
    status = spdm_send_spdm_request(spdm_context, session_id,
                                    spdm_request_size, &spdm_request);
    if (RETURN_ERROR(status)) {
        return status;
    }

    spdm_response_size = sizeof(spdm_response);
    zero_mem(&spdm_response, sizeof(spdm_response));
    status = spdm_receive_spdm_response(
        spdm_context, session_id, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        return status;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = spdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size, &spdm_response,
            SPDM_GET_MEASUREMENTS, SPDM_MEASUREMENTS,
            sizeof(spdm_measurements_response_max_t));
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else if (spdm_response.header.request_response_code !=
               SPDM_MEASUREMENTS) {
        libspdm_reset_message_m(spdm_context, session_info);
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_measurements_response_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return RETURN_DEVICE_ERROR;
    }

    if (measurement_operation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        if (spdm_response.number_of_blocks != 0) {
            libspdm_reset_message_m(spdm_context, session_info);
            return RETURN_DEVICE_ERROR;
        }
    } else if (measurement_operation ==
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
        if (spdm_response.number_of_blocks == 0) {
            return RETURN_DEVICE_ERROR;
        }
    } else {
        if (spdm_response.number_of_blocks != 1) {
            return RETURN_DEVICE_ERROR;
        }
    }

    measurement_record_data_length =
        libspdm_read_uint24(spdm_response.measurement_record_length);
    if (measurement_operation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        if (measurement_record_data_length != 0) {
            libspdm_reset_message_m(spdm_context, session_info);
            return RETURN_DEVICE_ERROR;
        }
    } else {
        if (spdm_response_size <
            sizeof(spdm_measurements_response_t) +
            measurement_record_data_length) {
            return RETURN_DEVICE_ERROR;
        }
        if (measurement_record_data_length >=
            sizeof(spdm_response.measurement_record)) {
            return RETURN_DEVICE_ERROR;
        }
        DEBUG((DEBUG_INFO, "measurement_record_length - 0x%06x\n",
               measurement_record_data_length));
    }

    measurement_record_data = spdm_response.measurement_record;

    if ((request_attribute &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_response_size <
            sizeof(spdm_measurements_response_t) +
            measurement_record_data_length + SPDM_NONCE_SIZE +
            sizeof(uint16_t)) {
            libspdm_reset_message_m(spdm_context, session_info);
            return RETURN_DEVICE_ERROR;
        }
        if ((spdm_response.header.spdm_version >=
             SPDM_MESSAGE_VERSION_11) &&
            ((spdm_response.header.param2 & SPDM_MEASUREMENTS_RESPONSE_SLOT_ID_MASK)
             != slot_id_param)) {
            libspdm_reset_message_m(spdm_context, session_info);
            return RETURN_SECURITY_VIOLATION;
        }
        ptr = measurement_record_data + measurement_record_data_length;
        nonce = ptr;
        DEBUG((DEBUG_INFO, "nonce (0x%x) - ", SPDM_NONCE_SIZE));
        internal_dump_data(nonce, SPDM_NONCE_SIZE);
        DEBUG((DEBUG_INFO, "\n"));
        ptr += SPDM_NONCE_SIZE;
        if (responder_nonce != NULL) {
            copy_mem(responder_nonce, SPDM_NONCE_SIZE, nonce, SPDM_NONCE_SIZE);
        }

        opaque_length = *(uint16_t *)ptr;
        if (opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
            return RETURN_SECURITY_VIOLATION;
        }
        ptr += sizeof(uint16_t);

        if (spdm_response_size <
            sizeof(spdm_measurements_response_t) +
            measurement_record_data_length + SPDM_NONCE_SIZE +
            sizeof(uint16_t) + opaque_length + signature_size) {
            return RETURN_DEVICE_ERROR;
        }
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             measurement_record_data_length +
                             SPDM_NONCE_SIZE + sizeof(uint16_t) +
                             opaque_length + signature_size;

        /* Cache data*/

        status = libspdm_append_message_m(spdm_context, session_info, &spdm_request,
                                          spdm_request_size);
        if (RETURN_ERROR(status)) {
            return RETURN_SECURITY_VIOLATION;
        }

        status = libspdm_append_message_m(spdm_context, session_info, &spdm_response,
                                          spdm_response_size -
                                          signature_size);
        if (RETURN_ERROR(status)) {
            libspdm_reset_message_m(spdm_context, session_info);
            return RETURN_SECURITY_VIOLATION;
        }

        opaque = ptr;
        ptr += opaque_length;
        DEBUG((DEBUG_INFO, "opaque (0x%x):\n", opaque_length));
        internal_dump_hex(opaque, opaque_length);

        signature = ptr;
        DEBUG((DEBUG_INFO, "signature (0x%x):\n", signature_size));
        internal_dump_hex(signature, signature_size);

        result = spdm_verify_measurement_signature(
            spdm_context, session_info, signature, signature_size);
        if (!result) {
            spdm_context->error_state =
                LIBSPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE;
            libspdm_reset_message_m(spdm_context, session_info);
            return RETURN_SECURITY_VIOLATION;
        }

        libspdm_reset_message_m(spdm_context, session_info);
    } else {
        if (spdm_response_size <
            sizeof(spdm_measurements_response_t) +
            measurement_record_data_length + sizeof(uint16_t)) {
            return RETURN_DEVICE_ERROR;
        }
        ptr = measurement_record_data + measurement_record_data_length;

        nonce = ptr;
        DEBUG((DEBUG_INFO, "nonce (0x%x) - ", SPDM_NONCE_SIZE));
        internal_dump_data(nonce, SPDM_NONCE_SIZE);
        DEBUG((DEBUG_INFO, "\n"));
        ptr += SPDM_NONCE_SIZE;
        if (responder_nonce != NULL) {
            copy_mem(responder_nonce, SPDM_NONCE_SIZE, nonce, SPDM_NONCE_SIZE);
        }

        opaque_length = *(uint16_t *)ptr;
        if (opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
            return RETURN_SECURITY_VIOLATION;
        }
        ptr += sizeof(uint16_t);

        if (spdm_response_size <
            sizeof(spdm_measurements_response_t) +
            measurement_record_data_length + SPDM_NONCE_SIZE +
            sizeof(uint16_t) + opaque_length) {
            return RETURN_DEVICE_ERROR;
        }
        spdm_response_size = sizeof(spdm_measurements_response_t) +
                             measurement_record_data_length +
                             SPDM_NONCE_SIZE + sizeof(uint16_t) +
                             opaque_length;

        /* Cache data*/

        status = libspdm_append_message_m(spdm_context, session_info, &spdm_request,
                                          spdm_request_size);
        if (RETURN_ERROR(status)) {
            return RETURN_SECURITY_VIOLATION;
        }

        status = libspdm_append_message_m(spdm_context, session_info, &spdm_response,
                                          spdm_response_size);
        if (RETURN_ERROR(status)) {
            libspdm_reset_message_m(spdm_context, session_info);
            return RETURN_SECURITY_VIOLATION;
        }
    }

    if (content_changed != NULL) {
        *content_changed = 0;
        if ((spdm_response.header.spdm_version >= SPDM_MESSAGE_VERSION_12) &&
            ((request_attribute &
              SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0)) {
            *content_changed =
                (spdm_response.header.param2 & SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK);
        }
    }
    if (measurement_operation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        *number_of_blocks = spdm_response.header.param1;
        if (*number_of_blocks == 0xFF) {
            /* the number of block cannot be 0xFF, because index 0xFF will brings confusing.*/
            return RETURN_DEVICE_ERROR;
        }
        if (*number_of_blocks == 0x0) {
            /* the number of block cannot be 0x0, because a responder without measurement should clear capability flags.*/
            return RETURN_DEVICE_ERROR;
        }
    } else {
        *number_of_blocks = spdm_response.number_of_blocks;
        if (*measurement_record_length <
            measurement_record_data_length) {
            return RETURN_BUFFER_TOO_SMALL;
        }
        if (measurement_record_data_length <
            sizeof(spdm_measurement_block_common_header_t)) {
            return RETURN_DEVICE_ERROR;
        }

        measurement_block_size = 0;
        measurement_block_count = 1;
        while (measurement_block_size <
               measurement_record_data_length) {
            measurement_block_header =
                (spdm_measurement_block_common_header_t
                 *)&measurement_record_data
                [measurement_block_size];
            if (measurement_block_header->measurement_size >
                measurement_record_data_length -
                ((uint8_t *)measurement_block_header -
                 (uint8_t *)measurement_record_data)) {
                return RETURN_DEVICE_ERROR;
            }
            if (measurement_block_header
                ->measurement_specification == 0 ||
                (measurement_block_header->measurement_specification &
                 (measurement_block_header
                  ->measurement_specification -
                  1))) {
                return RETURN_DEVICE_ERROR;
            }
            if (measurement_block_header->measurement_specification !=
                spdm_context->connection_info.algorithm
                .measurement_spec) {
                return RETURN_DEVICE_ERROR;
            }
            if (measurement_block_header->index == 0 ||
                measurement_block_header->index == 0xFF) {
                return RETURN_DEVICE_ERROR;
            }
            if (measurement_operation !=
                SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
                if (measurement_block_header->index !=
                    measurement_operation) {
                    return RETURN_DEVICE_ERROR;
                }
            }
            if (measurement_block_count > *number_of_blocks) {
                return RETURN_DEVICE_ERROR;
            }
            measurement_block_count++;
            measurement_block_size = (uint32_t)(
                measurement_block_size +
                sizeof(spdm_measurement_block_common_header_t) +
                measurement_block_header->measurement_size);
        }

        *measurement_record_length = measurement_record_data_length;
        copy_mem(measurement_record,
                 measurement_record_data_length,
                 measurement_record_data,
                 measurement_record_data_length);
    }

    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;
    return RETURN_SUCCESS;
}

/**
 * This function sends GET_MEASUREMENT
 * to get measurement from the device.
 *
 * If the signature is requested, this function verifies the signature of the measurement.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  request_attribute             The request attribute of the request message.
 * @param  measurement_operation         The measurement operation of the request message.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  content_changed               The measurement content changed output param.
 * @param  number_of_blocks               The number of blocks of the measurement record.
 * @param  measurement_record_length      On input, indicate the size in bytes of the destination buffer to store the measurement record.
 *                                     On output, indicate the size in bytes of the measurement record.
 * @param  measurement_record            A pointer to a destination buffer to store the measurement record.
 *
 * @retval RETURN_SUCCESS               The measurement is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_get_measurement(void *context, const uint32_t *session_id,
                                      uint8_t request_attribute,
                                      uint8_t measurement_operation,
                                      uint8_t slot_id_param,
                                      uint8_t *content_changed,
                                      uint8_t *number_of_blocks,
                                      uint32_t *measurement_record_length,
                                      void *measurement_record)
{
    spdm_context_t *spdm_context;
    uintn retry;
    return_status status;

    spdm_context = context;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = try_spdm_get_measurement(
            spdm_context, session_id, request_attribute,
            measurement_operation, slot_id_param, content_changed, number_of_blocks,
            measurement_record_length, measurement_record, NULL, NULL, NULL);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

/**
 * This function sends GET_MEASUREMENT
 * to get measurement from the device.
 *
 * If the signature is requested, this function verifies the signature of the measurement.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  request_attribute             The request attribute of the request message.
 * @param  measurement_operation         The measurement operation of the request message.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  content_changed               The measurement content changed output param.
 * @param  number_of_blocks               The number of blocks of the measurement record.
 * @param  measurement_record_length      On input, indicate the size in bytes of the destination buffer to store the measurement record.
 *                                     On output, indicate the size in bytes of the measurement record.
 * @param  measurement_record            A pointer to a destination buffer to store the measurement record.
 * @param  requester_nonce_in            A buffer to hold the requester nonce (32 bytes) as input, if not NULL.
 * @param  requester_nonce               A buffer to hold the requester nonce (32 bytes), if not NULL.
 * @param  responder_nonce               A buffer to hold the responder nonce (32 bytes), if not NULL.
 *
 * @retval RETURN_SUCCESS               The measurement is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_get_measurement_ex(void *context, const uint32_t *session_id,
                                         uint8_t request_attribute,
                                         uint8_t measurement_operation,
                                         uint8_t slot_id_param,
                                         uint8_t *content_changed,
                                         uint8_t *number_of_blocks,
                                         uint32_t *measurement_record_length,
                                         void *measurement_record,
                                         const void *requester_nonce_in,
                                         void *requester_nonce,
                                         void *responder_nonce) {
    spdm_context_t *spdm_context;
    uintn retry;
    return_status status;

    spdm_context = context;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = try_spdm_get_measurement(
            spdm_context, session_id, request_attribute,
            measurement_operation, slot_id_param, content_changed, number_of_blocks,
            measurement_record_length, measurement_record,
            requester_nonce_in,
            requester_nonce, responder_nonce);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
