/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint8_t session_policy;
    uint8_t reserved;
    uint8_t random_data[SPDM_RANDOM_DATA_SIZE];
    uint8_t exchange_data[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_key_exchange_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t rsp_session_id;
    uint8_t mut_auth_requested;
    uint8_t req_slot_id_param;
    uint8_t random_data[SPDM_RANDOM_DATA_SIZE];
    uint8_t exchange_data[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint8_t measurement_summary_hash[LIBSPDM_MAX_HASH_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_key_exchange_response_max_t;

#pragma pack()

/**
 * This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the KEY_EXCHANGE request.
 * @param  slot_id                      slot_id to the KEY_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the KEY_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the KEY_EXCHANGE_RSP response.
 * @param  req_slot_id_param               req_slot_id_param from the KEY_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the KEY_EXCHANGE_RSP response.
 * @param  requester_random_in           A buffer to hold the requester random (32 bytes) as input, if not NULL.
 * @param  requester_random              A buffer to hold the requester random (32 bytes), if not NULL.
 * @param  responder_random              A buffer to hold the responder random (32 bytes), if not NULL.
 *
 * @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
libspdm_return_t libspdm_try_send_receive_key_exchange(
    libspdm_context_t *spdm_context, uint8_t measurement_hash_type,
    uint8_t slot_id, uint8_t session_policy, uint32_t *session_id,
    uint8_t *heartbeat_period,
    uint8_t *req_slot_id_param, void *measurement_hash,
    const void *requester_random_in,
    void *requester_random,
    void *responder_random)
{
    bool result;
    libspdm_return_t status;
    libspdm_key_exchange_request_mine_t *spdm_request;
    size_t spdm_request_size;
    libspdm_key_exchange_response_max_t *spdm_response;
    size_t spdm_response_size;
    size_t dhe_key_size;
    uint32_t measurement_summary_hash_size;
    uint32_t signature_size;
    uint32_t hmac_size;
    uint8_t *ptr;
    void *measurement_summary_hash;
    uint16_t opaque_length;
    uint8_t *signature;
    uint8_t *verify_data;
    void *dhe_context;
    uint16_t req_session_id;
    uint16_t rsp_session_id;
    libspdm_session_info_t *session_info;
    size_t opaque_key_exchange_req_size;
    uint8_t th1_hash_data[64];
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;

    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xff));

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  SPDM_KEY_EXCHANGE);
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if ((slot_id == 0xFF) &&
        (spdm_context->local_context.peer_cert_chain_provision_size == 0)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_KEY_EXCHANGE;
    spdm_request->header.param1 = measurement_hash_type;
    spdm_request->header.param2 = slot_id;
    if (requester_random_in == NULL) {
        if(!libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_request->random_data)) {
            libspdm_release_sender_buffer (spdm_context);
            return LIBSPDM_STATUS_LOW_ENTROPY;
        }
    } else {
        libspdm_copy_mem(spdm_request->random_data, sizeof(spdm_request->random_data),
                         requester_random_in, SPDM_RANDOM_DATA_SIZE);
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ClientRandomData (0x%x) - ",
                   SPDM_RANDOM_DATA_SIZE));
    libspdm_internal_dump_data(spdm_request->random_data, SPDM_RANDOM_DATA_SIZE);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (requester_random != NULL) {
        libspdm_copy_mem(requester_random, SPDM_RANDOM_DATA_SIZE,
                         spdm_request->random_data, SPDM_RANDOM_DATA_SIZE);
    }

    req_session_id = libspdm_allocate_req_session_id(spdm_context);
    spdm_request->req_session_id = req_session_id;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request->session_policy = session_policy;
    } else {
        spdm_request->session_policy = 0;
    }
    spdm_request->reserved = 0;

    ptr = spdm_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(
        spdm_context->connection_info.algorithm.dhe_named_group);
    dhe_context = libspdm_secured_message_dhe_new(
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.dhe_named_group, true);
    if (dhe_context == NULL) {
        libspdm_release_sender_buffer (spdm_context);
        return LIBSPDM_STATUS_CRYPTO_ERROR;
    }

    result = libspdm_secured_message_dhe_generate_key(
        spdm_context->connection_info.algorithm.dhe_named_group,
        dhe_context, ptr, &dhe_key_size);
    if (!result) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        libspdm_release_sender_buffer (spdm_context);
        return LIBSPDM_STATUS_CRYPTO_ERROR;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ClientKey (0x%x):\n", dhe_key_size));
    libspdm_internal_dump_hex(ptr, dhe_key_size);
    ptr += dhe_key_size;

    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    status = libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    LIBSPDM_ASSERT(status == LIBSPDM_STATUS_SUCCESS);
    ptr += opaque_key_exchange_req_size;

    spdm_request_size = (size_t)ptr - (size_t)spdm_request;
    status = libspdm_send_spdm_request(spdm_context, NULL, spdm_request_size,
                                       spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* receive */

    libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(
        spdm_context, NULL, true,
        &spdm_response_size, (void **)&spdm_response);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, NULL, &spdm_response_size,
            (void **)&spdm_response, SPDM_KEY_EXCHANGE,
            SPDM_KEY_EXCHANGE_RSP,
            sizeof(libspdm_key_exchange_response_max_t));
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_secured_message_dhe_free(
                spdm_context->connection_info.algorithm
                .dhe_named_group,
                dhe_context);
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_KEY_EXCHANGE_RSP) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_key_exchange_response_t)) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP)) {
        if (spdm_response->header.param1 != 0) {
            libspdm_secured_message_dhe_free(
                spdm_context->connection_info.algorithm
                .dhe_named_group,
                dhe_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }
    if (heartbeat_period != NULL) {
        *heartbeat_period = spdm_response->header.param1;
    }
    *req_slot_id_param = spdm_response->req_slot_id_param;
    if (spdm_response->mut_auth_requested != 0) {
        if ((spdm_response->mut_auth_requested != SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED) &&
            (spdm_response->mut_auth_requested !=
             SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST) &&
            (spdm_response->mut_auth_requested !=
             SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS)) {
            libspdm_secured_message_dhe_free(
                spdm_context->connection_info.algorithm
                .dhe_named_group,
                dhe_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
        if ((*req_slot_id_param != 0xF) &&
            (*req_slot_id_param >=
             spdm_context->local_context.slot_count)) {
            libspdm_secured_message_dhe_free(
                spdm_context->connection_info.algorithm
                .dhe_named_group,
                dhe_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    } else {
        if (*req_slot_id_param != 0) {
            libspdm_secured_message_dhe_free(
                spdm_context->connection_info.algorithm
                .dhe_named_group,
                dhe_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }
    rsp_session_id = spdm_response->rsp_session_id;
    *session_id = (req_session_id << 16) | rsp_session_id;
    session_info = libspdm_assign_session_id(spdm_context, *session_id, false);
    if (session_info == NULL) {
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_SESSION_NUMBER_EXCEED;
        goto receive_done;
    }

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, true, measurement_hash_type);
    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        hmac_size = 0;
    }

    if (spdm_response_size <
        sizeof(spdm_key_exchange_response_t) + dhe_key_size +
        measurement_summary_hash_size + sizeof(uint16_t) +
        signature_size + hmac_size) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ServerRandomData (0x%x) - ",
                   SPDM_RANDOM_DATA_SIZE));
    libspdm_internal_dump_data(spdm_response->random_data, SPDM_RANDOM_DATA_SIZE);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (responder_random != NULL) {
        libspdm_copy_mem(responder_random, SPDM_RANDOM_DATA_SIZE,
                         spdm_response->random_data, SPDM_RANDOM_DATA_SIZE);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ServerKey (0x%x):\n", dhe_key_size));
    libspdm_internal_dump_hex(spdm_response->exchange_data, dhe_key_size);

    ptr = spdm_response->exchange_data;
    ptr += dhe_key_size;

    measurement_summary_hash = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "measurement_summary_hash (0x%x) - ",
                   measurement_summary_hash_size));
    libspdm_internal_dump_data(measurement_summary_hash,
                               measurement_summary_hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    ptr += measurement_summary_hash_size;

    opaque_length = *(uint16_t *)ptr;
    if (opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    ptr += sizeof(uint16_t);
    if (spdm_response_size <
        sizeof(spdm_key_exchange_response_t) + dhe_key_size +
        measurement_summary_hash_size + sizeof(uint16_t) +
        opaque_length + signature_size + hmac_size) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    status = libspdm_process_opaque_data_version_selection_data(
        spdm_context, opaque_length, ptr);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    ptr += opaque_length;

    spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                         dhe_key_size + measurement_summary_hash_size +
                         sizeof(uint16_t) + opaque_length + signature_size +
                         hmac_size;


    /* Cache session data*/

    status = libspdm_append_message_k(spdm_context, session_info, true, spdm_request,
                                      spdm_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_BUFFER_FULL;
        goto receive_done;
    }

    status = libspdm_append_message_k(spdm_context, session_info, true, spdm_response,
                                      spdm_response_size - signature_size -
                                      hmac_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_BUFFER_FULL;
        goto receive_done;
    }

    signature = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature (0x%x):\n", signature_size));
    libspdm_internal_dump_hex(signature, signature_size);
    ptr += signature_size;
    result = libspdm_verify_key_exchange_rsp_signature(
        spdm_context, session_info, signature, signature_size);
    if (!result) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_VERIF_FAIL;
        goto receive_done;
    }

    status = libspdm_append_message_k(spdm_context, session_info, true, signature, signature_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_free_session_id(spdm_context, *session_id);
        libspdm_secured_message_dhe_free(
            spdm_context->connection_info.algorithm.dhe_named_group,
            dhe_context);
        status = LIBSPDM_STATUS_BUFFER_FULL;
        goto receive_done;
    }


    /* Fill data to calc Secret for HMAC verification*/

    result = libspdm_secured_message_dhe_compute_key(
        spdm_context->connection_info.algorithm.dhe_named_group,
        dhe_context, spdm_response->exchange_data, dhe_key_size,
        session_info->secured_message_context);
    libspdm_secured_message_dhe_free(
        spdm_context->connection_info.algorithm.dhe_named_group,
        dhe_context);
    if (!result) {
        libspdm_free_session_id(spdm_context, *session_id);
        status = LIBSPDM_STATUS_CRYPTO_ERROR;
        goto receive_done;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%x]\n",
                   *session_id));
    result = libspdm_calculate_th1_hash(spdm_context, session_info, true,
                                        th1_hash_data);
    if (!result) {
        libspdm_free_session_id(spdm_context, *session_id);
        return LIBSPDM_STATUS_CRYPTO_ERROR;
    }
    result = libspdm_generate_session_handshake_key(
        session_info->secured_message_context, th1_hash_data);
    if (!result) {
        libspdm_free_session_id(spdm_context, *session_id);
        status = LIBSPDM_STATUS_CRYPTO_ERROR;
        goto receive_done;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        verify_data = ptr;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "verify_data (0x%x):\n", hmac_size));
        libspdm_internal_dump_hex(verify_data, hmac_size);
        result = libspdm_verify_key_exchange_rsp_hmac(
            spdm_context, session_info, verify_data, hmac_size);
        if (!result) {
            libspdm_free_session_id(spdm_context, *session_id);
            status = LIBSPDM_STATUS_VERIF_FAIL;
            goto receive_done;
        }
        ptr += hmac_size;

        status = libspdm_append_message_k(spdm_context, session_info, true, verify_data,
                                          hmac_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_free_session_id(spdm_context, *session_id);
            status = LIBSPDM_STATUS_BUFFER_FULL;
            goto receive_done;
        }
    }

    if (measurement_hash != NULL) {
        libspdm_copy_mem(measurement_hash, measurement_summary_hash_size,
                         measurement_summary_hash, measurement_summary_hash_size);
    }
    session_info->mut_auth_requested = spdm_response->mut_auth_requested;
    session_info->session_policy = session_policy;

    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

/**
 * This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the KEY_EXCHANGE request.
 * @param  slot_id                      slot_id to the KEY_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the KEY_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the KEY_EXCHANGE_RSP response.
 * @param  req_slot_id_param               req_slot_id_param from the KEY_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the KEY_EXCHANGE_RSP response.
 *
 * @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
libspdm_return_t libspdm_send_receive_key_exchange(
    libspdm_context_t *spdm_context, uint8_t measurement_hash_type,
    uint8_t slot_id, uint8_t session_policy, uint32_t *session_id,
    uint8_t *heartbeat_period,
    uint8_t *req_slot_id_param, void *measurement_hash)
{
    size_t retry;
    libspdm_return_t status;

    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_send_receive_key_exchange(
            spdm_context, measurement_hash_type, slot_id, session_policy,
            session_id, heartbeat_period, req_slot_id_param,
            measurement_hash, NULL, NULL, NULL);
        if (LIBSPDM_STATUS_BUSY_PEER != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

/**
 * This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  measurement_hash_type          measurement_hash_type to the KEY_EXCHANGE request.
 * @param  slot_id                      slot_id to the KEY_EXCHANGE request.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    session_id from the KEY_EXCHANGE_RSP response.
 * @param  heartbeat_period              heartbeat_period from the KEY_EXCHANGE_RSP response.
 * @param  req_slot_id_param               req_slot_id_param from the KEY_EXCHANGE_RSP response.
 * @param  measurement_hash              measurement_hash from the KEY_EXCHANGE_RSP response.
 * @param  requester_random_in           A buffer to hold the requester random (32 bytes) as input, if not NULL.
 * @param  requester_random              A buffer to hold the requester random (32 bytes), if not NULL.
 * @param  responder_random              A buffer to hold the responder random (32 bytes), if not NULL.
 *
 * @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
libspdm_return_t libspdm_send_receive_key_exchange_ex(
    libspdm_context_t *spdm_context, uint8_t measurement_hash_type,
    uint8_t slot_id, uint8_t session_policy, uint32_t *session_id,
    uint8_t *heartbeat_period,
    uint8_t *req_slot_id_param, void *measurement_hash,
    const void *requester_random_in,
    void *requester_random,
    void *responder_random)
{
    size_t retry;
    libspdm_return_t status;

    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_send_receive_key_exchange(
            spdm_context, measurement_hash_type, slot_id, session_policy,
            session_id, heartbeat_period, req_slot_id_param,
            measurement_hash, requester_random_in,
            requester_random, responder_random);
        if (LIBSPDM_STATUS_BUSY_PEER != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
