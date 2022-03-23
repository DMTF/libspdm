/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

/**
 * Process the SPDM KEY_EXCHANGE request and return the response.
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
return_status libspdm_get_response_key_exchange(void *context,
                                                size_t request_size,
                                                const void *request,
                                                size_t *response_size,
                                                void *response)
{
    const spdm_key_exchange_request_t *spdm_request;
    spdm_key_exchange_response_t *spdm_response;
    size_t dhe_key_size;
    size_t measurement_summary_hash_size;
    uint32_t signature_size;
    uint32_t hmac_size;
    uint8_t *ptr;
    uint16_t opaque_data_length;
    bool result;
    uint8_t slot_id;
    uint32_t session_id;
    void *dhe_context;
    libspdm_session_info_t *session_info;
    size_t total_size;
    libspdm_context_t *spdm_context;
    uint16_t req_session_id;
    uint16_t rsp_session_id;
    return_status status;
    size_t opaque_key_exchange_rsp_size;
    uint8_t th1_hash_data[64];

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
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_KEY_EXCHANGE, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
        if (spdm_context->encap_context.error_state !=
            LIBSPDM_STATUS_SUCCESS) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "libspdm_get_response_key_exchange fail due to Mutual Auth fail\n"));
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) &&
        spdm_request->header.param1 > 0) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
            SPDM_KEY_EXCHANGE, response_size, response);
    }

    slot_id = spdm_request->header.param2;
    if ((slot_id != 0xFF) &&
        (slot_id >= spdm_context->local_context.slot_count)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (slot_id == 0xFF) {
        slot_id = spdm_context->local_context.provisioned_slot_id;
    }

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    dhe_key_size = libspdm_get_dhe_pub_key_size(
        spdm_context->connection_info.algorithm.dhe_named_group);
    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, spdm_request->header.param1);

    if ((measurement_summary_hash_size == 0) &&
        (spdm_request->header.param1 != SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST,
                                               0, response_size, response);
    }
    if (request_size < sizeof(spdm_key_exchange_request_t) + dhe_key_size +
        sizeof(uint16_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    opaque_data_length =
        *(uint16_t *)((uint8_t *)request +
                      sizeof(spdm_key_exchange_request_t) + dhe_key_size);
    if (request_size < sizeof(spdm_key_exchange_request_t) + dhe_key_size +
        sizeof(uint16_t) + opaque_data_length) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    request_size = sizeof(spdm_key_exchange_request_t) + dhe_key_size +
                   sizeof(uint16_t) + opaque_data_length;

    ptr = (uint8_t *)request + sizeof(spdm_key_exchange_request_t) +
          dhe_key_size + sizeof(uint16_t);
    status = libspdm_process_opaque_data_supported_version_data(
        spdm_context, opaque_data_length, ptr);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    opaque_key_exchange_rsp_size =
        libspdm_get_opaque_data_version_selection_data_size(spdm_context);

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        hmac_size = 0;
    }

    total_size = sizeof(spdm_key_exchange_response_t) + dhe_key_size +
                 measurement_summary_hash_size + sizeof(uint16_t) +
                 opaque_key_exchange_rsp_size + signature_size + hmac_size;

    LIBSPDM_ASSERT(*response_size >= total_size);
    *response_size = total_size;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_KEY_EXCHANGE_RSP;
    spdm_response->header.param1 = spdm_context->local_context.heartbeat_period;

    req_session_id = spdm_request->req_session_id;
    rsp_session_id = libspdm_allocate_rsp_session_id(spdm_context);
    if (rsp_session_id == (INVALID_SESSION_ID & 0xFFFF)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0,
            response_size, response);
    }
    session_id = (req_session_id << 16) | rsp_session_id;
    session_info = libspdm_assign_session_id(spdm_context, session_id, false);
    if (session_info == NULL) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0,
            response_size, response);
    }

    spdm_response->rsp_session_id = rsp_session_id;

    spdm_response->mut_auth_requested = 0;
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) &&
        (libspdm_is_capabilities_flag_supported(
             spdm_context, false,
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0) ||
         libspdm_is_capabilities_flag_supported(
             spdm_context, false,
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0))) {
        spdm_response->mut_auth_requested =
            spdm_context->local_context.mut_auth_requested;
    }
    if (spdm_response->mut_auth_requested != 0) {
        libspdm_init_mut_auth_encap_state(
            context, spdm_response->mut_auth_requested);
        spdm_response->req_slot_id_param =
            (spdm_context->encap_context.req_slot_id & 0xF);
    } else {
        spdm_response->req_slot_id_param = 0;
    }

    if(!libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data)) {
        return RETURN_DEVICE_ERROR;
    }

    ptr = (void *)(spdm_response + 1);
    dhe_context = libspdm_secured_message_dhe_new(
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.dhe_named_group, false);
    result = libspdm_secured_message_dhe_generate_key(
        spdm_context->connection_info.algorithm.dhe_named_group,
        dhe_context, ptr, &dhe_key_size);
    if (!result) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Calc SelfKey (0x%x):\n", dhe_key_size));
    libspdm_internal_dump_hex(ptr, dhe_key_size);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Calc peer_key (0x%x):\n", dhe_key_size));
    libspdm_internal_dump_hex((uint8_t *)request +
                              sizeof(spdm_key_exchange_request_t),
                              dhe_key_size);

    result = libspdm_secured_message_dhe_compute_key(
        spdm_context->connection_info.algorithm.dhe_named_group,
        dhe_context,
        (uint8_t *)request + sizeof(spdm_key_exchange_request_t),
        dhe_key_size, session_info->secured_message_context);
    libspdm_secured_message_dhe_free(
        spdm_context->connection_info.algorithm.dhe_named_group,
        dhe_context);
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    ptr += dhe_key_size;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {

        result = libspdm_generate_measurement_summary_hash(
            spdm_context->connection_info.version,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm.measurement_hash_algo,
            spdm_request->header.param1,
            ptr,
            &measurement_summary_hash_size);
    }
    else {
        result = true;
    }

    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += measurement_summary_hash_size;

    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
    ptr += sizeof(uint16_t);
    status = libspdm_build_opaque_data_version_selection_data(
        spdm_context, &opaque_key_exchange_rsp_size, ptr);
    LIBSPDM_ASSERT_RETURN_ERROR(status);
    ptr += opaque_key_exchange_rsp_size;

    spdm_context->connection_info.local_used_cert_chain_buffer =
        spdm_context->local_context.local_cert_chain_provision[slot_id];
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        spdm_context->local_context
        .local_cert_chain_provision_size[slot_id];

    status = libspdm_append_message_k(spdm_context, session_info, false, request, request_size);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_k(spdm_context, session_info, false, spdm_response,
                                      (size_t)ptr - (size_t)spdm_response);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    result = libspdm_generate_key_exchange_rsp_signature(spdm_context,
                                                         session_info, ptr);
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            SPDM_KEY_EXCHANGE_RSP, response_size, response);
    }

    status = libspdm_append_message_k(spdm_context, session_info, false, ptr, signature_size);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%x]\n",
                   session_id));
    status = libspdm_calculate_th1_hash(spdm_context, session_info, false,
                                        th1_hash_data);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    status = libspdm_generate_session_handshake_key(
        session_info->secured_message_context, th1_hash_data);
    if (RETURN_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    ptr += signature_size;

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        result = libspdm_generate_key_exchange_rsp_hmac(spdm_context,
                                                        session_info, ptr);
        if (!result) {
            libspdm_free_session_id(spdm_context, session_id);
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
        status = libspdm_append_message_k(spdm_context, session_info, false, ptr, hmac_size);
        if (RETURN_ERROR(status)) {
            libspdm_free_session_id(spdm_context, session_id);
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }

        ptr += hmac_size;
    }

    session_info->mut_auth_requested = spdm_response->mut_auth_requested;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        session_info->session_policy = spdm_request->session_policy;
    }
    libspdm_set_session_state(spdm_context, session_id,
                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    return RETURN_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
