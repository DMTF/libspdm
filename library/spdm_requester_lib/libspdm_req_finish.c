/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} spdm_finish_response_mine_t;

#pragma pack()

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

/**
  This function sends FINISH and receives FINISH_RSP for SPDM finish.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_id                    session_id to the FINISH request.
  @param  req_slot_id_param               req_slot_id_param to the FINISH request.

  @retval RETURN_SUCCESS               The FINISH is sent and the FINISH_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_send_receive_finish(IN spdm_context_t *spdm_context,
                       IN uint32_t session_id,
                       IN uint8_t req_slot_id_param)
{
    return_status status;
    spdm_finish_request_mine_t spdm_request;
    uintn spdm_request_size;
    uintn signature_size;
    uintn hmac_size;
    spdm_finish_response_mine_t spdm_response;
    uintn spdm_response_size;
    spdm_session_info_t *session_info;
    uint8_t *ptr;
    boolean result;
    uint8_t th2_hash_data[64];
    libspdm_session_state_t session_state;

    if (!spdm_is_capabilities_flag_supported(
            spdm_context, TRUE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
        status = RETURN_UNSUPPORTED;
        goto error;
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        status = RETURN_UNSUPPORTED;
        goto error;
    }

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        ASSERT(FALSE);
        status = RETURN_UNSUPPORTED;
        goto error;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_HANDSHAKING) {
        status = RETURN_UNSUPPORTED;
        goto error;
    }

    if (session_info->mut_auth_requested != 0) {
        if ((req_slot_id_param >=
             spdm_context->local_context.slot_count) &&
            (req_slot_id_param != 0xFF)) {
            status = RETURN_INVALID_PARAMETER;
            goto error;
        }
    } else {
        if (req_slot_id_param != 0) {
            status = RETURN_INVALID_PARAMETER;
            goto error;
        }
    }

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    spdm_request.header.spdm_version = spdm_get_connection_version (spdm_context);
    spdm_request.header.request_response_code = SPDM_FINISH;
    if (session_info->mut_auth_requested) {
        spdm_request.header.param1 =
            SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED;
        spdm_request.header.param2 = req_slot_id_param;
        signature_size = libspdm_get_req_asym_signature_size(
            spdm_context->connection_info.algorithm
                .req_base_asym_alg);
    } else {
        spdm_request.header.param1 = 0;
        spdm_request.header.param2 = 0;
        signature_size = 0;
    }

    if (req_slot_id_param == 0xFF) {
        req_slot_id_param =
            spdm_context->local_context.provisioned_slot_id;
    }

    if (session_info->mut_auth_requested) {
        spdm_context->connection_info.local_used_cert_chain_buffer =
            spdm_context->local_context
                .local_cert_chain_provision[req_slot_id_param];
        spdm_context->connection_info.local_used_cert_chain_buffer_size =
            spdm_context->local_context
                .local_cert_chain_provision_size
                    [req_slot_id_param];
    }

    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    spdm_request_size =
        sizeof(spdm_finish_request_t) + signature_size + hmac_size;
    ptr = spdm_request.signature;

    status = libspdm_append_message_f(spdm_context, session_info, TRUE, (uint8_t *)&spdm_request,
                       sizeof(spdm_finish_request_t));
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }
    if (session_info->mut_auth_requested) {
        result = spdm_generate_finish_req_signature(spdm_context,
                                session_info, ptr);
        if (!result) {
            status = RETURN_SECURITY_VIOLATION;
            goto error;
        }
        status = libspdm_append_message_f(spdm_context, session_info, TRUE, ptr,
                           signature_size);
        if (RETURN_ERROR(status)) {
            status = RETURN_SECURITY_VIOLATION;
            goto error;
        }
        ptr += signature_size;
    }

    result = spdm_generate_finish_req_hmac(spdm_context, session_info, ptr);
    if (!result) {
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }

    status = libspdm_append_message_f(spdm_context, session_info, TRUE, ptr, hmac_size);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }

    status = spdm_send_spdm_request(spdm_context, &session_id,
                    spdm_request_size, &spdm_request);
    if (RETURN_ERROR(status)) {
        status = RETURN_DEVICE_ERROR;
        goto error;
    }

    spdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                        SPDM_FINISH);

    spdm_response_size = sizeof(spdm_response);
    zero_mem(&spdm_response, sizeof(spdm_response));
    status = spdm_receive_spdm_response(
        spdm_context, &session_id, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        status = RETURN_DEVICE_ERROR;
        goto error;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = RETURN_DEVICE_ERROR;
        goto error;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        status = RETURN_DEVICE_ERROR;
        goto error;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        if (spdm_response.header.param1 != SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            libspdm_reset_message_f (spdm_context, session_info);
        }
        status = spdm_handle_error_response_main(
            spdm_context, &session_id,
            &spdm_response_size, &spdm_response,
            SPDM_FINISH, SPDM_FINISH_RSP,
            sizeof(spdm_finish_response_mine_t));
        if (RETURN_ERROR(status)) {
            goto error;
        }
    } else if (spdm_response.header.request_response_code !=
           SPDM_FINISH_RSP) {
        status = RETURN_DEVICE_ERROR;
        goto error;
    }

    if (!spdm_is_capabilities_flag_supported(
            spdm_context, TRUE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        hmac_size = 0;
    }

    if (spdm_response_size != sizeof(spdm_finish_response_t) + hmac_size) {
        status = RETURN_DEVICE_ERROR;
        goto error;
    }

    status = libspdm_append_message_f(spdm_context, session_info, TRUE, &spdm_response,
                       sizeof(spdm_finish_response_t));
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }

    if (spdm_is_capabilities_flag_supported(
            spdm_context, TRUE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        DEBUG((DEBUG_INFO, "verify_data (0x%x):\n", hmac_size));
        internal_dump_hex(spdm_response.verify_data, hmac_size);
        result = spdm_verify_finish_rsp_hmac(spdm_context, session_info,
                             spdm_response.verify_data,
                             hmac_size);
        if (!result) {
            status = RETURN_SECURITY_VIOLATION;
            goto error;
        }

        status = libspdm_append_message_f(
            spdm_context, session_info, TRUE,
            (uint8_t *)&spdm_response +
                sizeof(spdm_finish_response_t),
            hmac_size);
        if (RETURN_ERROR(status)) {
            status = RETURN_SECURITY_VIOLATION;
            goto error;
        }
    }

    DEBUG((DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n", session_id));
    status = libspdm_calculate_th2_hash(spdm_context, session_info, TRUE,
                     th2_hash_data);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }
    status = libspdm_generate_session_data_key(
        session_info->secured_message_context, th2_hash_data);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto error;
    }

    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;

    return RETURN_SUCCESS;
error:
    if (RETURN_NO_RESPONSE != status) {
        libspdm_free_session_id(spdm_context, session_id);
        if (session_state == LIBSPDM_SESSION_STATE_HANDSHAKING) {
            libspdm_clear_handshake_secret(session_info->secured_message_context);
        }
    }
    return status;
}

return_status spdm_send_receive_finish(IN spdm_context_t *spdm_context,
                       IN uint32_t session_id,
                       IN uint8_t req_slot_id_param)
{
    uintn retry;
    return_status status;

    retry = spdm_context->retry_times;
    do {
        status = try_spdm_send_receive_finish(spdm_context, session_id,
                              req_slot_id_param);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/