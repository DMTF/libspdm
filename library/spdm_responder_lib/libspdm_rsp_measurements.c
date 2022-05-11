/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

/**
 * This function creates the measurement signature to response message based upon l1l2.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  response_message              The measurement response message with empty signature to be filled.
 * @param  response_message_size          Total size in bytes of the response message including signature.
 *
 * @retval true  measurement signature is created.
 * @retval false measurement signature is not created.
 **/
bool libspdm_create_measurement_signature(libspdm_context_t *spdm_context,
                                          libspdm_session_info_t *session_info,
                                          void *response_message,
                                          size_t response_message_size)
{
    uint8_t *ptr;
    size_t measurment_sig_size;
    size_t signature_size;
    bool result;
    libspdm_return_t status;

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    measurment_sig_size =
        SPDM_NONCE_SIZE + sizeof(uint16_t) +
        spdm_context->local_context.opaque_measurement_rsp_size +
        signature_size;
    LIBSPDM_ASSERT(response_message_size > measurment_sig_size);
    ptr = (void *)((uint8_t *)response_message + response_message_size -
                   measurment_sig_size);

    if(!libspdm_get_random_number(SPDM_NONCE_SIZE, ptr)) {
        return false;
    }
    ptr += SPDM_NONCE_SIZE;

    *(uint16_t *)ptr =
        (uint16_t)spdm_context->local_context.opaque_measurement_rsp_size;
    ptr += sizeof(uint16_t);

    if (spdm_context->local_context.opaque_measurement_rsp != NULL) {
        libspdm_copy_mem(ptr,
                         response_message_size - (ptr - (uint8_t*)response_message),
                         spdm_context->local_context.opaque_measurement_rsp,
                         spdm_context->local_context.opaque_measurement_rsp_size);
        ptr += spdm_context->local_context.opaque_measurement_rsp_size;
    }

    status = libspdm_append_message_m(spdm_context, session_info, response_message,
                                      response_message_size - signature_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    result = libspdm_generate_measurement_signature(spdm_context, session_info, ptr);

    return result;
}

/**
 * This function creates the opaque data to response message.
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  response_message              The measurement response message with empty signature to be filled.
 * @param  response_message_size          Total size in bytes of the response message including signature.
 **/
bool libspdm_create_measurement_opaque(libspdm_context_t *spdm_context,
                                       void *response_message,
                                       size_t response_message_size)
{
    uint8_t *ptr;
    size_t measurment_no_sig_size;

    measurment_no_sig_size =
        SPDM_NONCE_SIZE + sizeof(uint16_t) +
        spdm_context->local_context.opaque_measurement_rsp_size;
    LIBSPDM_ASSERT(response_message_size > measurment_no_sig_size);
    ptr = (void *)((uint8_t *)response_message + response_message_size -
                   measurment_no_sig_size);

    if(!libspdm_get_random_number(SPDM_NONCE_SIZE, ptr)) {
        return false;
    }
    ptr += SPDM_NONCE_SIZE;

    *(uint16_t *)ptr =
        (uint16_t)spdm_context->local_context.opaque_measurement_rsp_size;
    ptr += sizeof(uint16_t);

    if (spdm_context->local_context.opaque_measurement_rsp != NULL) {
        libspdm_copy_mem(ptr,
                         response_message_size - (ptr - (uint8_t*)response_message),
                         spdm_context->local_context.opaque_measurement_rsp,
                         spdm_context->local_context.opaque_measurement_rsp_size);
        ptr += spdm_context->local_context.opaque_measurement_rsp_size;
    }

    return true;
}

/**
 * Process the SPDM GET_MEASUREMENT request and return the response.
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
libspdm_return_t libspdm_get_response_measurements(void *context,
                                                   size_t request_size,
                                                   const void *request,
                                                   size_t *response_size,
                                                   void *response)
{
    uint8_t index;
    const spdm_get_measurements_request_t *spdm_request;
    spdm_measurements_response_t *spdm_response;
    size_t spdm_response_size;
    libspdm_return_t status;
    size_t signature_size;
    size_t measurements_sig_size;
    size_t measurements_no_sig_size;

    libspdm_context_t *spdm_context;
    uint8_t slot_id_param;
    uint8_t measurements_index;
    uint8_t *measurements;
    uint8_t measurements_count;
    size_t measurements_size;
    bool ret;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t content_changed;

    spdm_context = context;
    spdm_request = request;

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    /* check local context here, because meas_cap is reserved for requester.*/
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_MEASUREMENTS, response_size, response);
    }
    if ((spdm_context->connection_info.algorithm.measurement_spec == 0) ||
        (spdm_context->connection_info.algorithm.measurement_hash_algo == 0) ) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
            0, response_size, response);
    }
    if (!spdm_context->last_spdm_request_session_id_valid) {
        if (spdm_context->connection_info.connection_state <
            LIBSPDM_CONNECTION_STATE_AUTHENTICATED) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_info = NULL;
    } else {
        if (spdm_context->connection_info.connection_state <
            LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
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

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_11) {
            if (request_size <
                sizeof(spdm_get_measurements_request_t)) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            request_size = sizeof(spdm_get_measurements_request_t);
        } else {
            if (request_size <
                sizeof(spdm_get_measurements_request_t) -
                sizeof(spdm_request->slot_id_param)) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            request_size = sizeof(spdm_get_measurements_request_t) -
                           sizeof(spdm_request->slot_id_param);
        }
    } else {
        if (request_size != sizeof(spdm_message_header_t)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
        0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, false, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                0, response_size, response);
        }
    }

    spdm_response_size = sizeof(spdm_measurements_response_t);

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);

    measurements_sig_size =
        SPDM_NONCE_SIZE + sizeof(uint16_t) +
        spdm_context->local_context.opaque_measurement_rsp_size +
        signature_size;
    measurements_no_sig_size =
        SPDM_NONCE_SIZE + sizeof(uint16_t) +
        spdm_context->local_context.opaque_measurement_rsp_size;

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
        0) {
        spdm_response_size += measurements_sig_size;
    } else {
        spdm_response_size += measurements_no_sig_size;
    }

    libspdm_zero_mem(response, *response_size);

    measurements_index = spdm_request->header.param2;
    measurements_count = 0;

    /* The response buffer must hold the spdm_measurements_response_t,
     * followed by the actual measurements, followed by the signature,
     * if there is one. Here we calculate the maximum size allowed for
     * measurements and store it in "measurements_size", by subtracting
     * out "spdm_responze_size", which contains the sizeof the
     * spdm_measurements_response_t + signature if there is one.*/

    measurements_size = *response_size;
    if (measurements_size > spdm_response_size) {
        measurements_size -= spdm_response_size;
    } else {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED,
                                               0, response_size, response);
    }

    measurements = (uint8_t*)response + sizeof(spdm_measurements_response_t);

    status = libspdm_measurement_collection(
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        measurements_index,
        spdm_request->header.param1,
        &content_changed,
        &measurements_count,
        measurements,
        &measurements_size);


    if (LIBSPDM_STATUS_IS_ERROR(status)) {

        if (status == LIBSPDM_STATUS_MEAS_INVALID_INDEX) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
        else {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    LIBSPDM_ASSERT(measurements_count <= LIBSPDM_MAX_MEASUREMENT_BLOCK_COUNT);

    switch (spdm_request->header.param2) {
    case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:

        spdm_response_size += 0; /* Just to match code pattern in other case blocks*/
        LIBSPDM_ASSERT(*response_size >= spdm_response_size);
        *response_size = spdm_response_size;
        spdm_response = response;

        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = measurements_count;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 0;
        libspdm_write_uint24(spdm_response->measurement_record_length, 0);

        break;

    case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
        LIBSPDM_DEBUG_CODE_BEGIN();
        size_t debug_measurements_record_size;
        size_t debug_measurements_block_size;
        spdm_measurement_block_dmtf_t *debug_measurement_block;

        debug_measurements_record_size = 0;
        debug_measurement_block = (void *)measurements;
        for (index = 0; index < measurements_count; index++) {
            debug_measurements_block_size =
                sizeof(spdm_measurement_block_dmtf_t) +
                debug_measurement_block
                ->measurement_block_dmtf_header
                .dmtf_spec_measurement_value_size;
            debug_measurements_record_size += debug_measurements_block_size;
            debug_measurement_block =
                (void *)((size_t)debug_measurement_block +
                         debug_measurements_block_size);
        }
        LIBSPDM_ASSERT(debug_measurements_record_size == measurements_size);
        LIBSPDM_DEBUG_CODE_END();

        spdm_response_size += measurements_size;
        LIBSPDM_ASSERT(*response_size >= spdm_response_size);
        *response_size = spdm_response_size;
        spdm_response = response;

        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = measurements_count;
        libspdm_write_uint24(spdm_response->measurement_record_length,
                             (uint32_t)measurements_size);

        break;

    default:

        LIBSPDM_ASSERT(measurements_count == 1);

        spdm_response_size += measurements_size;
        LIBSPDM_ASSERT(*response_size >= spdm_response_size);
        *response_size = spdm_response_size;
        spdm_response = response;

        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(spdm_response->measurement_record_length,
                             (uint32_t)measurements_size);

        break;
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
        0) {
        if (spdm_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_11) {
            slot_id_param = spdm_request->slot_id_param &
                            SPDM_GET_MEASUREMENTS_REQUEST_SLOT_ID_MASK;
            if ((slot_id_param != 0xF) &&
                (slot_id_param >=
                 spdm_context->local_context.slot_count)) {
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            spdm_response->header.param2 = slot_id_param;
            if (spdm_response->header.spdm_version >=
                SPDM_MESSAGE_VERSION_12) {
                spdm_response->header.param2 = slot_id_param |
                                               (content_changed &
                                                SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK);
            }
        }
    } else {
        if(!libspdm_create_measurement_opaque(spdm_context, spdm_response,
                                              spdm_response_size)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    status = libspdm_append_message_m(
        spdm_context, session_info, spdm_request,
        request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
        0) {

        ret = libspdm_create_measurement_signature(
            spdm_context, session_info, spdm_response,
            spdm_response_size);
        if (!ret) {
            status = libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNSPECIFIED,
                0,
                response_size, response);
            libspdm_reset_message_m(spdm_context, session_info);
            return status;
        }
        /*reset*/
        libspdm_reset_message_m(spdm_context, session_info);
    } else {
        status = libspdm_append_message_m(spdm_context, session_info, spdm_response,
                                          *response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            status = libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
            libspdm_reset_message_m(spdm_context, session_info);
            return status;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
