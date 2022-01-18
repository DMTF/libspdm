/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

/**
 * This function sends GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHM
 * to initialize the connection with SPDM responder.
 *
 * Before this function, the requester configuration data can be set via libspdm_set_data.
 * After this function, the negotiated configuration data can be got via libspdm_get_data.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS               The connection is initialized successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_init_connection(IN void *context,
                                      IN bool get_version_only)
{
    return_status status;
    spdm_context_t *spdm_context;

    spdm_context = context;

    status = spdm_get_version(spdm_context);
    if (RETURN_ERROR(status)) {
        return status;
    }

    if (!get_version_only) {
        status = spdm_get_capabilities(spdm_context);
        if (RETURN_ERROR(status)) {
            return status;
        }
        status = spdm_negotiate_algorithms(spdm_context);
        if (RETURN_ERROR(status)) {
            return status;
        }
    }
    return RETURN_SUCCESS;
}

/**
 * This function sends KEY_EXCHANGE/FINISH or PSK_EXCHANGE/PSK_FINISH
 * to start an SPDM Session.
 *
 * If encapsulated mutual authentication is requested from the responder,
 * this function also perform the encapsulated mutual authentication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  use_psk                       false means to use KEY_EXCHANGE/FINISH to start a session.
 *                                     true means to use PSK_EXCHANGE/PSK_FINISH to start a session.
 * @param  measurement_hash_type          The type of the measurement hash.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  session_policy               The policy for the session.
 * @param  session_id                    The session ID of the session.
 * @param  heartbeat_period              The heartbeat period for the session.
 * @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.
 *
 * @retval RETURN_SUCCESS               The SPDM session is started.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_start_session(IN void *context, IN bool use_psk,
                                    IN uint8_t measurement_hash_type,
                                    IN uint8_t slot_id,
                                    IN uint8_t session_policy,
                                    OUT uint32_t *session_id,
                                    OUT uint8_t *heartbeat_period,
                                    OUT void *measurement_hash)
{
    return_status status;
    spdm_context_t *spdm_context;

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    spdm_session_info_t *session_info;
    uint8_t req_slot_id_param;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    spdm_context = context;
    status = RETURN_UNSUPPORTED;

    if (!use_psk) {
    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        status = spdm_send_receive_key_exchange(
            spdm_context, measurement_hash_type, slot_id, session_policy,
            session_id, heartbeat_period, &req_slot_id_param,
            measurement_hash);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_send_receive_key_exchange - %p\n",
                   status));
            return status;
        }

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        if (session_info == NULL) {
            ASSERT(false);
            return RETURN_UNSUPPORTED;
        }

        switch (session_info->mut_auth_requested) {
        case 0:
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
            status = spdm_encapsulated_request(
                spdm_context, session_id,
                session_info->mut_auth_requested,
                &req_slot_id_param);
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_encapsulated_request - %p\n",
                   status));
            if (RETURN_ERROR(status)) {
                return status;
            }
            break;
        default:
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - unknown mut_auth_requested - 0x%x\n",
                   session_info->mut_auth_requested));
            return RETURN_UNSUPPORTED;
        }

        if (req_slot_id_param == 0xF) {
            req_slot_id_param = 0xFF;
        }
        status = spdm_send_receive_finish(spdm_context, *session_id,
                                          req_slot_id_param);
        DEBUG((DEBUG_INFO,
               "libspdm_start_session - spdm_send_receive_finish - %p\n",
               status));
    #else /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
        ASSERT(false);
        return RETURN_UNSUPPORTED;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
    } else {
    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
        status = spdm_send_receive_psk_exchange(
            spdm_context, measurement_hash_type, session_policy, session_id,
            heartbeat_period, measurement_hash);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_send_receive_psk_exchange - %p\n",
                   status));
            return status;
        }

        /* send PSK_FINISH only if Responder supports context.*/
        if (spdm_is_capabilities_flag_supported(
                spdm_context, true, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
            status = spdm_send_receive_psk_finish(spdm_context,
                                                  *session_id);
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_send_receive_psk_finish - %p\n",
                   status));
        }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
    }
    return status;
}

/**
 * This function sends KEY_EXCHANGE/FINISH or PSK_EXCHANGE/PSK_FINISH
 * to start an SPDM Session.
 *
 * If encapsulated mutual authentication is requested from the responder,
 * this function also perform the encapsulated mutual authentication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  use_psk                       false means to use KEY_EXCHANGE/FINISH to start a session.
 *                                     true means to use PSK_EXCHANGE/PSK_FINISH to start a session.
 * @param  measurement_hash_type          The type of the measurement hash.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  session_id                    The session ID of the session.
 * @param  session_policy               The policy for the session.
 * @param  heartbeat_period              The heartbeat period for the session.
 * @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.
 * @param  requester_random_in           A buffer to hold the requester random as input, if not NULL.
 * @param  requester_random_in_size      The size of requester_random_in.
 *                                      If use_psk is false, it must be 32 bytes.
 *                                      If use_psk is true, it means the PSK context and must be 32 bytes at least,
 *                                      but not exceed LIBSPDM_PSK_CONTEXT_LENGTH.
 * @param  requester_random              A buffer to hold the requester random, if not NULL.
 * @param  requester_random_size         On input, the size of requester_random buffer.
 *                                      On output, the size of data returned in requester_random buffer.
 *                                      If use_psk is false, it must be 32 bytes.
 *                                      If use_psk is true, it means the PSK context and must be 32 bytes at least.
 * @param  responder_random              A buffer to hold the responder random, if not NULL.
 * @param  responder_random_size         On input, the size of requester_random buffer.
 *                                      On output, the size of data returned in requester_random buffer.
 *                                      If use_psk is false, it must be 32 bytes.
 *                                      If use_psk is true, it means the PSK context. It could be 0 if device does not support context.
 *
 * @retval RETURN_SUCCESS               The SPDM session is started.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_start_session_ex(IN void *context, IN bool use_psk,
                                       IN uint8_t measurement_hash_type,
                                       IN uint8_t slot_id,
                                       IN uint8_t session_policy,
                                       OUT uint32_t *session_id,
                                       OUT uint8_t *heartbeat_period,
                                       OUT void *measurement_hash,
                                       IN void *requester_random_in OPTIONAL,
                                       IN uintn requester_random_in_size OPTIONAL,
                                       OUT void *requester_random OPTIONAL,
                                       OUT uintn *requester_random_size OPTIONAL,
                                       OUT void *responder_random OPTIONAL,
                                       OUT uintn *responder_random_size OPTIONAL)
{
    return_status status;
    spdm_context_t *spdm_context;

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    spdm_session_info_t *session_info;
    uint8_t req_slot_id_param;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    spdm_context = context;
    status = RETURN_UNSUPPORTED;

    if (!use_psk) {
    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        ASSERT (requester_random_in_size == 0 || requester_random_in_size == SPDM_RANDOM_DATA_SIZE);
        ASSERT (requester_random_size == NULL || *requester_random_size == SPDM_RANDOM_DATA_SIZE);
        ASSERT (responder_random_size == NULL || *responder_random_size == SPDM_RANDOM_DATA_SIZE);
        status = spdm_send_receive_key_exchange_ex(
            spdm_context, measurement_hash_type, slot_id, session_policy,
            session_id, heartbeat_period, &req_slot_id_param,
            measurement_hash, requester_random_in,
            requester_random, responder_random);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_send_receive_key_exchange - %p\n",
                   status));
            return status;
        }

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        if (session_info == NULL) {
            ASSERT(false);
            return RETURN_UNSUPPORTED;
        }

        switch (session_info->mut_auth_requested) {
        case 0:
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
            break;
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
        case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
            status = spdm_encapsulated_request(
                spdm_context, session_id,
                session_info->mut_auth_requested,
                &req_slot_id_param);
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_encapsulated_request - %p\n",
                   status));
            if (RETURN_ERROR(status)) {
                return status;
            }
            break;
        default:
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - unknown mut_auth_requested - 0x%x\n",
                   session_info->mut_auth_requested));
            return RETURN_UNSUPPORTED;
        }

        if (req_slot_id_param == 0xF) {
            req_slot_id_param = 0xFF;
        }
        status = spdm_send_receive_finish(spdm_context, *session_id,
                                          req_slot_id_param);
        DEBUG((DEBUG_INFO,
               "libspdm_start_session - spdm_send_receive_finish - %p\n",
               status));
    #else /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
        ASSERT(false);
        return RETURN_UNSUPPORTED;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
    } else {
    #if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
        status = spdm_send_receive_psk_exchange_ex(
            spdm_context, measurement_hash_type, session_policy, session_id,
            heartbeat_period, measurement_hash,
            requester_random_in, requester_random_in_size,
            requester_random, requester_random_size,
            responder_random, responder_random_size);
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_send_receive_psk_exchange - %p\n",
                   status));
            return status;
        }

        /* send PSK_FINISH only if Responder supports context.*/
        if (spdm_is_capabilities_flag_supported(
                spdm_context, true, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
            status = spdm_send_receive_psk_finish(spdm_context,
                                                  *session_id);
            DEBUG((DEBUG_INFO,
                   "libspdm_start_session - spdm_send_receive_psk_finish - %p\n",
                   status));
        }
    #else /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
        ASSERT(false);
        return RETURN_UNSUPPORTED;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
    }
    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
    return status;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
}

/**
 * This function sends END_SESSION
 * to stop an SPDM Session.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session ID of the session.
 * @param  end_session_attributes         The end session attribute for the session.
 *
 * @retval RETURN_SUCCESS               The SPDM session is stopped.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_stop_session(IN void *context, IN uint32_t session_id,
                                   IN uint8_t end_session_attributes)
{
    return_status status;
    spdm_context_t *spdm_context;

    spdm_context = context;

    status = spdm_send_receive_end_session(spdm_context, session_id,
                                           end_session_attributes);
    DEBUG((DEBUG_INFO, "libspdm_stop_session - %p\n", status));

    return status;
}

/**
 * Send and receive an SPDM or APP message.
 *
 * The SPDM message can be a normal message or a secured message in SPDM session.
 *
 * The APP message is encoded to a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 * Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  request                      A pointer to the request data.
 * @param  request_size                  size in bytes of the request data.
 * @param  response                     A pointer to the response data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 *
 * @retval RETURN_SUCCESS               The SPDM request is set successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_send_receive_data(IN void *context, IN uint32_t *session_id,
                                        IN bool is_app_message,
                                        IN void *request, IN uintn request_size,
                                        IN OUT void *response,
                                        IN OUT uintn *response_size)
{
    return_status status;
    spdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;

    spdm_context = context;
    spdm_response = response;

    status = libspdm_send_request(spdm_context, session_id, is_app_message,
                                  request_size, request);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }

    status = libspdm_receive_response(spdm_context, session_id, is_app_message,
                                      response_size, response);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        if ((spdm_response->header.param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) &&
            (session_id != NULL)) {
            libspdm_free_session_id(spdm_context, *session_id);
            return RETURN_SECURITY_VIOLATION;
        }
    }

    return RETURN_SUCCESS;
}
