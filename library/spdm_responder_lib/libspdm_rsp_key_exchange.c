/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

/**
 * This function generates the key exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the key exchange HMAC.
 *
 * @retval true  key exchange HMAC is generated.
 * @retval false key exchange HMAC is not generated.
 **/
bool libspdm_generate_key_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                            libspdm_session_info_t *session_info,
                                            uint8_t *hmac)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
#endif
    bool result;

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hash_all (spdm_context->connection_info.algorithm.base_hash_algo,
                               th_curr_data, th_curr_data_size, hash_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, hash_data,
        hash_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, false, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    libspdm_copy_mem(hmac, hash_size, hmac_data, hash_size);

    return true;
}

/**
 * This function generates the key exchange signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  signature                    The buffer to store the key exchange signature.
 *
 * @retval true  key exchange signature is generated.
 * @retval false key exchange signature is not generated.
 **/
bool libspdm_generate_key_exchange_rsp_signature(libspdm_context_t *spdm_context,
                                                 libspdm_session_info_t *session_info,
                                                 uint8_t *signature)
{
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    const uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    bool result;
    size_t signature_size;
    size_t hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    /* Debug code only - required for debug print of th_curr hash below*/
    LIBSPDM_DEBUG_CODE(
        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
        return false;
    }
        );
#else
    result = libspdm_calculate_th_hash_for_exchange(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hash - "));
    libspdm_internal_dump_data(hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        false, th_curr_data, th_curr_data_size, signature, &signature_size);
#else
    result = libspdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        true, hash_data, hash_size, signature, &signature_size);
#endif
    if (result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature - "));
        libspdm_internal_dump_data(signature, signature_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }
    return result;
}

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
libspdm_return_t libspdm_get_response_key_exchange(void *context,
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
    const uint8_t *cptr;
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
    libspdm_return_t status;
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
    if (spdm_context->last_spdm_request_session_id_valid) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (spdm_request->header.param1 > 0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ||
            (spdm_context->connection_info.algorithm.measurement_spec == 0) ||
            (spdm_context->connection_info.algorithm.measurement_hash_algo == 0) ) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                SPDM_KEY_EXCHANGE, response_size, response);
        }
    }

    slot_id = spdm_request->header.param2;
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
        *(const uint16_t *)((const uint8_t *)request +
                            sizeof(spdm_key_exchange_request_t) + dhe_key_size);
    if (request_size < sizeof(spdm_key_exchange_request_t) + dhe_key_size +
        sizeof(uint16_t) + opaque_data_length) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    request_size = sizeof(spdm_key_exchange_request_t) + dhe_key_size +
                   sizeof(uint16_t) + opaque_data_length;

    cptr = (const uint8_t *)request + sizeof(spdm_key_exchange_request_t) +
           dhe_key_size + sizeof(uint16_t);
    status = libspdm_process_opaque_data_supported_version_data(
        spdm_context, opaque_data_length, cptr);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
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
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP || LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
        libspdm_init_mut_auth_encap_state(
            context, spdm_response->mut_auth_requested);
        spdm_response->req_slot_id_param =
            (spdm_context->encap_context.req_slot_id & 0xF);
#else
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
#endif
    } else {
        spdm_response->req_slot_id_param = 0;
    }

    if(!libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
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
    libspdm_internal_dump_hex((const uint8_t *)request +
                              sizeof(spdm_key_exchange_request_t),
                              dhe_key_size);

    result = libspdm_secured_message_dhe_compute_key(
        spdm_context->connection_info.algorithm.dhe_named_group,
        dhe_context,
        (const uint8_t *)request + sizeof(spdm_key_exchange_request_t),
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
    LIBSPDM_ASSERT(status == LIBSPDM_STATUS_SUCCESS);
    ptr += opaque_key_exchange_rsp_size;

    spdm_context->connection_info.local_used_cert_chain_buffer =
        spdm_context->local_context.local_cert_chain_provision[slot_id];
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        spdm_context->local_context
        .local_cert_chain_provision_size[slot_id];

    status = libspdm_append_message_k(spdm_context, session_info, false, request, request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_k(spdm_context, session_info, false, spdm_response,
                                      (size_t)ptr - (size_t)spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
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
            0, response_size, response);
    }

    status = libspdm_append_message_k(spdm_context, session_info, false, ptr, signature_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%x]\n",
                   session_id));
    result = libspdm_calculate_th1_hash(spdm_context, session_info, false,
                                        th1_hash_data);
    if (!result) {
        libspdm_free_session_id(spdm_context, session_id);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    result = libspdm_generate_session_handshake_key(
        session_info->secured_message_context, th1_hash_data);
    if (!result) {
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
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
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

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
