/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t dummy_data[sizeof(spdm_error_data_response_not_ready_t)];
} libspdm_key_update_response_mine_t;

#pragma pack()

/**
 * This function sends KEY_UPDATE
 * to update keys for an SPDM Session.
 *
 * After keys are updated, this function also uses VERIFY_NEW_KEY to verify the key.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session ID of the session.
 * @param  single_direction              true means the operation is UPDATE_KEY.
 *                                     false means the operation is UPDATE_ALL_KEYS.
 * @param  key_updated                   true means the operation is to verify key(s).
 *                                     false means the operation is to update and verify key(s).
 *
 * @retval RETURN_SUCCESS               The keys of the session are updated.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_try_key_update(void *context, uint32_t session_id,
                                     bool single_direction, bool *key_updated)
{
    return_status status;
    return_status temp_status;
    spdm_key_update_request_t spdm_request;
    libspdm_key_update_response_mine_t spdm_response;
    uintn spdm_response_size;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    spdm_context = context;
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
        return RETURN_UNSUPPORTED;
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return RETURN_UNSUPPORTED;
    }
    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        ASSERT(false);
        return RETURN_UNSUPPORTED;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return RETURN_UNSUPPORTED;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  SPDM_KEY_UPDATE);

    if(!(*key_updated)) {

        /* Update key*/

        spdm_request.header.spdm_version = libspdm_get_connection_version (spdm_context);
        spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
        if (single_direction) {
            spdm_request.header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
        } else {
            spdm_request.header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
        }
        spdm_request.header.param2 = 0;
        if(!libspdm_get_random_number(sizeof(spdm_request.header.param2),
                                      &spdm_request.header.param2)) {
            return RETURN_DEVICE_ERROR;
        }

        /* If updating both, create new responder key*/
        if (!single_direction) {
            DEBUG((DEBUG_INFO,
                   "libspdm_create_update_session_data_key[%x] Responder\n",
                   session_id));
            status = libspdm_create_update_session_data_key(
                session_info->secured_message_context,
                LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
            if (RETURN_ERROR(status)) {
                return status;
            }
        }

        status = libspdm_send_spdm_request(spdm_context, &session_id,
                                           sizeof(spdm_request), &spdm_request);
        if (RETURN_ERROR(status)) {
            return status;
        }

        spdm_response_size = sizeof(spdm_response);
        zero_mem(&spdm_response, sizeof(spdm_response));
        status = libspdm_receive_spdm_response(
            spdm_context, &session_id, &spdm_response_size, &spdm_response);

        if (RETURN_ERROR(status) ||
            spdm_response_size < sizeof(spdm_message_header_t)) {
            if (!single_direction) {
                DEBUG((DEBUG_INFO,
                       "libspdm_activate_update_session_data_key[%x] Responder old\n",
                       session_id));
                status = libspdm_activate_update_session_data_key(
                    session_info->secured_message_context,
                    LIBSPDM_KEY_UPDATE_ACTION_RESPONDER, false);
                if (RETURN_ERROR(status)) {
                    return status;
                }
            }
            return status;
        }

        if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_response.header.request_response_code == SPDM_ERROR) {
            status = libspdm_handle_error_response_main(
                spdm_context, &session_id,
                &spdm_response_size, &spdm_response,
                SPDM_KEY_UPDATE, SPDM_KEY_UPDATE_ACK,
                sizeof(libspdm_key_update_response_mine_t));
            if (RETURN_ERROR(status)) {
                if (!single_direction) {
                    DEBUG((DEBUG_INFO,
                           "libspdm_activate_update_session_data_key[%x] Responder old\n",
                           session_id));
                    temp_status = libspdm_activate_update_session_data_key(
                        session_info->secured_message_context,
                        LIBSPDM_KEY_UPDATE_ACTION_RESPONDER, false);
                    /* Try and return most relevant error*/
                    if (RETURN_ERROR(temp_status)) {
                        return temp_status;
                    }
                }
                return status;
            }
        }

        if ((spdm_response.header.request_response_code !=
             SPDM_KEY_UPDATE_ACK) ||
            (spdm_response.header.param1 != spdm_request.header.param1) ||
            (spdm_response.header.param2 != spdm_request.header.param2)) {
            if (!single_direction) {
                DEBUG((DEBUG_INFO,
                       "libspdm_activate_update_session_data_key[%x] Responder old\n",
                       session_id));
                status = libspdm_activate_update_session_data_key(
                    session_info->secured_message_context,
                    LIBSPDM_KEY_UPDATE_ACTION_RESPONDER, false);
                if (RETURN_ERROR(status)) {
                    return status;
                }
            }
            return RETURN_DEVICE_ERROR;
        }

        if (!single_direction) {
            DEBUG((DEBUG_INFO,
                   "libspdm_activate_update_session_data_key[%x] Responder new\n",
                   session_id, LIBSPDM_KEY_UPDATE_ACTION_RESPONDER));
            status = libspdm_activate_update_session_data_key(
                session_info->secured_message_context,
                LIBSPDM_KEY_UPDATE_ACTION_RESPONDER, true);
            if (RETURN_ERROR(status)) {
                return status;
            }
        }

        DEBUG((DEBUG_INFO,
               "libspdm_create_update_session_data_key[%x] Requester\n",
               session_id));
        status = libspdm_create_update_session_data_key(
            session_info->secured_message_context,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
        if (RETURN_ERROR(status)) {
            return status;
        }
        DEBUG((DEBUG_INFO,
               "libspdm_activate_update_session_data_key[%x] Requester new\n",
               session_id));
        status = libspdm_activate_update_session_data_key(
            session_info->secured_message_context,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER, true);
        if (RETURN_ERROR(status)) {
            return status;
        }
    }

    *key_updated = true;


    /* Verify key*/

    spdm_request.header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request.header.request_response_code = SPDM_KEY_UPDATE;
    spdm_request.header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
    spdm_request.header.param2 = 1;
    if(!libspdm_get_random_number(sizeof(spdm_request.header.param2),
                                  &spdm_request.header.param2)) {
        return RETURN_DEVICE_ERROR;
    }

    status = libspdm_send_spdm_request(spdm_context, &session_id,
                                       sizeof(spdm_request), &spdm_request);
    if (RETURN_ERROR(status)) {
        return status;
    }

    spdm_response_size = sizeof(spdm_response);
    zero_mem(&spdm_response, sizeof(spdm_response));
    status = libspdm_receive_spdm_response(
        spdm_context, &session_id, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        return status;
    } else if (spdm_response_size < sizeof(spdm_message_header_t)) {
        DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Failed\n", session_id));
        return RETURN_DEVICE_ERROR;
    }

    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, &session_id,
            &spdm_response_size, &spdm_response,
            SPDM_KEY_UPDATE, SPDM_KEY_UPDATE_ACK,
            sizeof(libspdm_key_update_response_mine_t));
        if (RETURN_ERROR(status)) {
            DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Failed\n", session_id));
            return status;
        }
    }

    if ((spdm_response.header.request_response_code !=
         SPDM_KEY_UPDATE_ACK) ||
        (spdm_response.header.param1 != spdm_request.header.param1) ||
        (spdm_response.header.param2 != spdm_request.header.param2)) {
        DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Failed\n", session_id));
        return RETURN_DEVICE_ERROR;
    }
    DEBUG((DEBUG_INFO, "SpdmVerifyKey[%x] Success\n", session_id));

    return RETURN_SUCCESS;
}

return_status libspdm_key_update(void *context, uint32_t session_id,
                                 bool single_direction)
{
    libspdm_context_t *spdm_context;
    uintn retry;
    return_status status;
    bool key_updated;

    spdm_context = context;
    key_updated = false;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_key_update(context, session_id,
                                        single_direction, &key_updated);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
