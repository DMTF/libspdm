/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"


#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

/**
 * Process the SPDM CHALLENGE request and return the response.
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
libspdm_return_t libspdm_get_response_challenge_auth(void *context,
                                                     size_t request_size,
                                                     const void *request,
                                                     size_t *response_size,
                                                     void *response)
{
    const spdm_challenge_request_t *spdm_request;
    spdm_challenge_auth_response_t *spdm_response;
    bool result;
    size_t signature_size;
    uint8_t slot_id;
    uint32_t hash_size;
    size_t measurement_summary_hash_size;
    uint8_t *ptr;
    size_t total_size;
    libspdm_context_t *spdm_context;
    uint8_t auth_attribute;
    libspdm_return_t status;
    size_t response_capacity;
    uint8_t slot_mask;

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
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_CHALLENGE, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (request_size != sizeof(spdm_challenge_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.param2 > 0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, false, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ||
            (spdm_context->connection_info.algorithm.measurement_spec == 0) ||
            (spdm_context->connection_info.algorithm.measurement_hash_algo == 0) ) {
            return libspdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                                                    SPDM_CHALLENGE, response_size, response);
        }
    }

    slot_id = spdm_request->header.param1;

    if ((slot_id != 0xFF) &&
        (slot_id >= SPDM_MAX_SLOT_COUNT)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (slot_id != 0xFF) {
        if (spdm_context->local_context
            .local_cert_chain_provision[slot_id] == NULL) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, spdm_request->header.param2);
    if ((measurement_summary_hash_size == 0) &&
        (spdm_request->header.param2 != SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST,
                                               0, response_size, response);
    }
    total_size =
        sizeof(spdm_challenge_auth_response_t) + hash_size +
        SPDM_NONCE_SIZE + measurement_summary_hash_size +
        sizeof(uint16_t) +
        spdm_context->local_context.opaque_challenge_auth_rsp_size +
        signature_size;

    LIBSPDM_ASSERT(*response_size >= total_size);
    response_capacity = *response_size;
    *response_size = total_size;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    auth_attribute = (uint8_t)(slot_id & 0xF);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) &&
            libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0) &&
            (libspdm_is_capabilities_flag_supported(
                 spdm_context, false,
                 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0) ||
             libspdm_is_capabilities_flag_supported(
                 spdm_context, false,
                 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0))) {
            if (spdm_context->local_context.basic_mut_auth_requested) {
                auth_attribute =
                    (uint8_t)(auth_attribute |
                              SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ);
            }
        }
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) != 0) {
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP || LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
            libspdm_init_basic_mut_auth_encap_state(context);
#else
            auth_attribute =
                (uint8_t)(auth_attribute &
                          ~SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ);
#endif
        }
    }

    spdm_response->header.param1 = auth_attribute;

    if (slot_id == 0xFF) {
        spdm_response->header.param2 = 0;

        slot_id = spdm_context->local_context.provisioned_slot_id;
    } else {
        slot_mask = libspdm_get_cert_slot_mask(spdm_context);
        if (slot_mask != 0) {
            spdm_response->header.param2 = slot_mask;
        } else {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    ptr = (void *)(spdm_response + 1);
    result = libspdm_generate_cert_chain_hash(spdm_context, slot_id, ptr);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += hash_size;

    result = libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += SPDM_NONCE_SIZE;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {

        result = libspdm_generate_measurement_summary_hash(
            spdm_context->connection_info.version,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm.measurement_hash_algo,
            spdm_request->header.param2,
            ptr,
            &measurement_summary_hash_size);
    }
    else {
        result = true;
    }

    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += measurement_summary_hash_size;

    libspdm_write_uint16 (ptr, (uint16_t)spdm_context->local_context
                          .opaque_challenge_auth_rsp_size);
    ptr += sizeof(uint16_t);

    if (spdm_context->local_context.opaque_challenge_auth_rsp != NULL) {
        libspdm_copy_mem(ptr,
                         response_capacity - (ptr - (uint8_t*)response),
                         spdm_context->local_context.opaque_challenge_auth_rsp,
                         spdm_context->local_context.opaque_challenge_auth_rsp_size);
        ptr += spdm_context->local_context.opaque_challenge_auth_rsp_size;
    }

    /* Calc Sign*/

    status = libspdm_append_message_c(spdm_context, spdm_request,
                                      request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_c(spdm_context, spdm_response,
                                      (size_t)ptr - (size_t)spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_c(spdm_context);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    result = libspdm_generate_challenge_auth_signature(spdm_context, false,
                                                       ptr);
    if (!result) {
        libspdm_reset_message_c(spdm_context);
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }
    ptr += signature_size;

    if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) == 0) {
        libspdm_set_connection_state(spdm_context,
                                     LIBSPDM_CONNECTION_STATE_AUTHENTICATED);
    }

    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
