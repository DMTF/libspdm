/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

typedef struct {
    uint8_t request_response_code;
    libspdm_get_encap_response_func get_encap_response_func;
} libspdm_get_encap_response_struct_t;

libspdm_get_encap_response_struct_t m_libspdm_get_encap_response_struct[] = {

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    { SPDM_GET_DIGESTS, libspdm_get_encap_response_digest },
    { SPDM_GET_CERTIFICATE, libspdm_get_encap_response_certificate },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    { SPDM_CHALLENGE, libspdm_get_encap_response_challenge_auth },
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    { SPDM_KEY_UPDATE, libspdm_get_encap_response_key_update },
};

/**
 * Register an SPDM encapsulated message process function.
 *
 * If the default encapsulated message process function cannot handle the encapsulated message,
 * this function will be invoked.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  get_encap_response_func         The function to process the encapsuled message.
 **/
void libspdm_register_get_encap_response_func(void *context,
                                              const libspdm_get_encap_response_func
                                              get_encap_response_func)
{
    libspdm_context_t *spdm_context;

    spdm_context = context;
    spdm_context->get_encap_response_func = (uintn)get_encap_response_func;

    return;
}

/**
 * Return the GET_ENCAP_RESPONSE function via request code.
 *
 * @param  request_code                  The SPDM request code.
 *
 * @return GET_ENCAP_RESPONSE function according to the request code.
 **/
libspdm_get_encap_response_func
libspdm_get_encap_response_func_via_request_code(uint8_t request_response_code)
{
    uintn index;

    for (index = 0;
         index < sizeof(m_libspdm_get_encap_response_struct) /
         sizeof(m_libspdm_get_encap_response_struct[0]);
         index++) {
        if (request_response_code ==
            m_libspdm_get_encap_response_struct[index]
            .request_response_code) {
            return m_libspdm_get_encap_response_struct[index]
                   .get_encap_response_func;
        }
    }
    return NULL;
}

/**
 * This function processes encapsulated request.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  encap_request_size             size in bytes of the request data buffer.
 * @param  encap_request                 A pointer to a destination buffer to store the request.
 * @param  encap_response_size            size in bytes of the response data buffer.
 * @param  encap_response                A pointer to a destination buffer to store the response.
 *
 * @retval RETURN_SUCCESS               The SPDM response is processed successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is sent to the device.
 **/
return_status libspdm_process_encapsulated_request(libspdm_context_t *spdm_context,
                                                   uintn encap_request_size,
                                                   void *encap_request,
                                                   uintn *encap_response_size,
                                                   void *encap_response)
{
    libspdm_get_encap_response_func get_encap_response_func;
    return_status status;
    spdm_message_header_t *spdm_requester;

    spdm_requester = encap_request;
    if (encap_request_size < sizeof(spdm_message_header_t)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            spdm_requester->request_response_code,
            encap_response_size, encap_response);
    }

    get_encap_response_func = libspdm_get_encap_response_func_via_request_code(
        spdm_requester->request_response_code);
    if (get_encap_response_func == NULL) {
        get_encap_response_func =
            (libspdm_get_encap_response_func)
            spdm_context->get_encap_response_func;
    }
    if (get_encap_response_func != NULL) {
        status = get_encap_response_func(
            spdm_context, encap_request_size, encap_request,
            encap_response_size, encap_response);
    } else {
        status = RETURN_NOT_FOUND;
    }
    if (status != RETURN_SUCCESS) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            spdm_requester->request_response_code,
            encap_response_size, encap_response);
    }

    return RETURN_SUCCESS;
}

/**
 * This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.
 *
 * This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
 * and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicate if the encapsulated request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  mut_auth_requested             Indicate of the mut_auth_requested through KEY_EXCHANGE or CHALLENG response.
 * @param  req_slot_id_param               req_slot_id_param from the RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER.
 *
 * @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_encapsulated_request(libspdm_context_t *spdm_context,
                                           const uint32_t *session_id,
                                           uint8_t mut_auth_requested,
                                           uint8_t *req_slot_id_param)
{
    return_status status;
    uint8_t request[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn spdm_request_size;
    spdm_get_encapsulated_request_request_t
    *spdm_get_encapsulated_request_request;
    spdm_deliver_encapsulated_response_request_t
    *spdm_deliver_encapsulated_response_request;
    uint8_t response[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn spdm_response_size;
    spdm_encapsulated_request_response_t *libspdm_encapsulated_request_response;
    spdm_encapsulated_response_ack_response_t
    *spdm_encapsulated_response_ack_response;
    libspdm_session_info_t *session_info;
    uint8_t request_id;
    void *encapsulated_request;
    uintn encapsulated_request_size;
    void *encapsulated_response;
    uintn encapsulated_response_size;
    uintn ack_header_size;

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    spdm_get_digest_request_t get_digests;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)) {
        return RETURN_UNSUPPORTED;
    }

    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return RETURN_UNSUPPORTED;
        }
        LIBSPDM_ASSERT((mut_auth_requested == 0) ||
                       (mut_auth_requested ==
                        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST) ||
                       (mut_auth_requested ==
                        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS));
    } else {
        LIBSPDM_ASSERT(mut_auth_requested == 0);
    }


    /* Cache*/

    libspdm_reset_message_mut_b(spdm_context);
    libspdm_reset_message_mut_c(spdm_context);

    if (session_id == NULL) {
        spdm_context->last_spdm_request_session_id_valid = false;
        spdm_context->last_spdm_request_session_id = 0;
    } else {
        spdm_context->last_spdm_request_session_id_valid = true;
        spdm_context->last_spdm_request_session_id = *session_id;
    }

    if (mut_auth_requested ==
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS) {

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

        get_digests.header.spdm_version = libspdm_get_connection_version (spdm_context);
        get_digests.header.request_response_code = SPDM_GET_DIGESTS;
        get_digests.header.param1 = 0;
        get_digests.header.param2 = 0;
        encapsulated_request = (void *)&get_digests;
        encapsulated_request_size = sizeof(get_digests);
        request_id = 0;
#else /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
        return RETURN_UNSUPPORTED;
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    } else {
        spdm_context->crypto_request = true;
        spdm_get_encapsulated_request_request = (void *)request;
        spdm_get_encapsulated_request_request->header.spdm_version =
            libspdm_get_connection_version (spdm_context);
        spdm_get_encapsulated_request_request->header
        .request_response_code = SPDM_GET_ENCAPSULATED_REQUEST;
        spdm_get_encapsulated_request_request->header.param1 = 0;
        spdm_get_encapsulated_request_request->header.param2 = 0;
        spdm_request_size =
            sizeof(spdm_get_encapsulated_request_request_t);
        libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                      spdm_get_encapsulated_request_request->header.request_response_code);
        status = libspdm_send_spdm_request(
            spdm_context, session_id, spdm_request_size,
            spdm_get_encapsulated_request_request);
        if (RETURN_ERROR(status)) {
            return status;
        }

        libspdm_encapsulated_request_response = (void *)response;
        spdm_response_size = sizeof(response);
        zero_mem(&response, sizeof(response));
        status = libspdm_receive_spdm_response(
            spdm_context, session_id, &spdm_response_size,
            libspdm_encapsulated_request_response);
        if (RETURN_ERROR(status)) {
            return status;
        }
        if (libspdm_encapsulated_request_response->header
            .request_response_code !=
            SPDM_ENCAPSULATED_REQUEST) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_response_size <
            sizeof(spdm_encapsulated_request_response_t)) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_response_size ==
            sizeof(spdm_encapsulated_request_response_t)) {

            /* Done*/

            return RETURN_SUCCESS;
        }
        request_id = libspdm_encapsulated_request_response->header.param1;

        encapsulated_request =
            (void *)(libspdm_encapsulated_request_response + 1);
        encapsulated_request_size =
            spdm_response_size -
            sizeof(spdm_encapsulated_request_response_t);
    }

    while (true) {

        /* Process request*/
        spdm_context->crypto_request = true;
        spdm_deliver_encapsulated_response_request = (void *)request;
        spdm_deliver_encapsulated_response_request->header.spdm_version =
            libspdm_get_connection_version (spdm_context);
        spdm_deliver_encapsulated_response_request->header
        .request_response_code =
            SPDM_DELIVER_ENCAPSULATED_RESPONSE;
        spdm_deliver_encapsulated_response_request->header.param1 =
            request_id;
        spdm_deliver_encapsulated_response_request->header.param2 = 0;
        encapsulated_response =
            (void *)(spdm_deliver_encapsulated_response_request +
                     1);
        encapsulated_response_size =
            sizeof(request) -
            sizeof(spdm_deliver_encapsulated_response_request_t);

        status = libspdm_process_encapsulated_request(
            spdm_context, encapsulated_request_size,
            encapsulated_request, &encapsulated_response_size,
            encapsulated_response);
        if (RETURN_ERROR(status)) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_request_size =
            sizeof(spdm_deliver_encapsulated_response_request_t) +
            encapsulated_response_size;
        status = libspdm_send_spdm_request(
            spdm_context, session_id, spdm_request_size,
            spdm_deliver_encapsulated_response_request);
        if (RETURN_ERROR(status)) {
            return status;
        }

        spdm_encapsulated_response_ack_response = (void *)response;
        spdm_response_size = sizeof(response);
        zero_mem(&response, sizeof(response));
        status = libspdm_receive_spdm_response(
            spdm_context, session_id, &spdm_response_size,
            spdm_encapsulated_response_ack_response);
        if (RETURN_ERROR(status)) {
            return status;
        }
        if (spdm_encapsulated_response_ack_response->header
            .request_response_code !=
            SPDM_ENCAPSULATED_RESPONSE_ACK) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_encapsulated_response_ack_response->header.spdm_version !=
            spdm_deliver_encapsulated_response_request->header.spdm_version) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_encapsulated_response_ack_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_12) {
            ack_header_size = sizeof(spdm_encapsulated_response_ack_response_t);
        } else {
            ack_header_size = sizeof(spdm_message_header_t);
        }
        if (spdm_response_size < ack_header_size) {
            return RETURN_DEVICE_ERROR;
        }

        if (spdm_encapsulated_response_ack_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_12) {
            if (spdm_encapsulated_response_ack_response->ack_request_id !=
                spdm_deliver_encapsulated_response_request->header.param1) {
                return RETURN_DEVICE_ERROR;
            }
        }

        switch (spdm_encapsulated_response_ack_response->header.param2) {
        case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT:
            if (spdm_response_size == ack_header_size) {
                return RETURN_SUCCESS;
            } else {
                return RETURN_DEVICE_ERROR;
            }
            break;
        case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT:
            break;
        case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER:
            if (spdm_response_size >= ack_header_size + sizeof(uint8_t)) {
                if ((req_slot_id_param != NULL) &&
                    (*req_slot_id_param == 0)) {
                    *req_slot_id_param =
                        *((uint8_t *)spdm_encapsulated_response_ack_response + ack_header_size);
                    if (*req_slot_id_param >=
                        spdm_context->local_context
                        .slot_count) {
                        return RETURN_DEVICE_ERROR;
                    }
                }
                return RETURN_SUCCESS;
            } else {
                return RETURN_DEVICE_ERROR;
            }
            break;
        default:
            return RETURN_DEVICE_ERROR;
        }
        request_id =
            spdm_encapsulated_response_ack_response->header.param1;

        encapsulated_request =
            ((uint8_t *)spdm_encapsulated_response_ack_response + ack_header_size);
        encapsulated_request_size = spdm_response_size - ack_header_size;
    }

    return RETURN_SUCCESS;
}

/**
 * This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.
 *
 * This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
 * and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicate if the encapsulated request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 *
 * @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_send_receive_encap_request(void *spdm_context,
                                                 const uint32_t *session_id)
{
    return libspdm_encapsulated_request(spdm_context, session_id, 0, NULL);
}
