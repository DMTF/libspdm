/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "hal/library/platform_lib.h"

/**
 * This function sends RESPOND_IF_READY and receives an expected SPDM response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  response_size                 The size of the response.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
 * @param  response                     The SPDM response message.
 * @param  expected_response_code         Indicate the expected response code.
 * @param  expected_response_size         Indicate the expected response size.
 *
 * @retval RETURN_SUCCESS               The RESPOND_IF_READY is sent and an expected SPDM response is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_requester_respond_if_ready(libspdm_context_t *spdm_context,
                                                 const uint32_t *session_id,
                                                 size_t *response_size,
                                                 void **response,
                                                 uint8_t expected_response_code,
                                                 size_t expected_response_size)
{
    return_status status;
    spdm_response_if_ready_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_message_header_t *spdm_response;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;

    /* the response might be in response buffer in normal SPDM message
     * or it is in scratch buffer in case of secure SPDM message
     * the response buffer is in acquired state, so we release it*/
    libspdm_release_receiver_buffer (spdm_context);

    /* now we can get sender buffer */
    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;

    spdm_context->crypto_request = true;
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_RESPOND_IF_READY;
    spdm_request->header.param1 = spdm_context->error_data.request_code;
    spdm_request->header.param2 = spdm_context->error_data.token;
    spdm_request_size = sizeof(spdm_response_if_ready_request_t);
    status = libspdm_send_spdm_request(spdm_context, session_id,
                                       spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        /* need acquire response buffer, so that the caller can release it */
        libspdm_acquire_receiver_buffer (spdm_context, response_size, response);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* receive
     * do not release response buffer in case of error, because caller will release it*/

    libspdm_acquire_receiver_buffer (spdm_context, response_size, response);
    LIBSPDM_ASSERT (*response_size >= transport_header_size);

    libspdm_zero_mem(*response, *response_size);
    status = libspdm_receive_spdm_response(spdm_context, session_id,
                                           response_size, response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    spdm_response = (void *)(*response);
    if (*response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response->spdm_version != spdm_request->header.spdm_version) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response->request_response_code != expected_response_code) {
        return RETURN_DEVICE_ERROR;
    }
    /* For response like SPDM_ALGORITHMS, we just can expect the max response size*/
    if (*response_size > expected_response_size) {
        return RETURN_DEVICE_ERROR;
    }
    return RETURN_SUCCESS;
}

/**
 * This function handles simple error code.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  error_code                    Indicate the error code.
 *
 * @retval RETURN_NO_RESPONSE           If the error code is BUSY.
 * @retval RETURN_DEVICE_ERROR          If the error code is REQUEST_RESYNCH or others.
 **/
return_status libspdm_handle_simple_error_response(void *context,
                                                   uint8_t error_code)
{
    libspdm_context_t *spdm_context;

    spdm_context = context;


    /* NOT_READY is treated as error here.
     * Use libspdm_handle_error_response_main to handle NOT_READY message in long latency command.*/

    if (error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
        return RETURN_DEVICE_ERROR;
    }

    if (error_code == SPDM_ERROR_CODE_BUSY) {
        return RETURN_NO_RESPONSE;
    }

    if (error_code == SPDM_ERROR_CODE_REQUEST_RESYNCH) {
        spdm_context->connection_info.connection_state =
            LIBSPDM_CONNECTION_STATE_NOT_STARTED;
        return LIBSPDM_STATUS_RESYNCH_PEER;
    }

    return RETURN_DEVICE_ERROR;
}

/**
 * This function handles RESPONSE_NOT_READY error code.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  response_size                 The size of the response.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
 * @param  response                     The SPDM response message.
 * @param  original_request_code          Indicate the orginal request code.
 * @param  expected_response_code         Indicate the expected response code.
 * @param  expected_response_size         Indicate the expected response size.
 *
 * @retval RETURN_SUCCESS               The RESPOND_IF_READY is sent and an expected SPDM response is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_handle_response_not_ready(libspdm_context_t *spdm_context,
                                                const uint32_t *session_id,
                                                size_t *response_size,
                                                void **response,
                                                uint8_t original_request_code,
                                                uint8_t expected_response_code,
                                                size_t expected_response_size)
{
    spdm_error_response_t *spdm_response;
    spdm_error_data_response_not_ready_t *extend_error_data;

    if(*response_size != sizeof(spdm_error_response_t) +
       sizeof(spdm_error_data_response_not_ready_t)) {
        return RETURN_DEVICE_ERROR;
    }

    spdm_response = *response;
    extend_error_data =
        (spdm_error_data_response_not_ready_t *)(spdm_response + 1);
    LIBSPDM_ASSERT(spdm_response->header.request_response_code == SPDM_ERROR);
    LIBSPDM_ASSERT(spdm_response->header.param1 ==
                   SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    if (extend_error_data->request_code != original_request_code) {
        return RETURN_DEVICE_ERROR;
    }

    spdm_context->error_data.rd_exponent = extend_error_data->rd_exponent;
    spdm_context->error_data.request_code = extend_error_data->request_code;
    spdm_context->error_data.token = extend_error_data->token;
    spdm_context->error_data.rd_tm = extend_error_data->rd_tm;

    libspdm_sleep((2 << extend_error_data->rd_exponent)/1000);
    return libspdm_requester_respond_if_ready(spdm_context, session_id,
                                              response_size, response,
                                              expected_response_code,
                                              expected_response_size);
}

/**
 * This function handles the error response.
 *
 * The SPDM response code must be SPDM_ERROR.
 * For error code RESPONSE_NOT_READY, this function sends RESPOND_IF_READY and receives an expected SPDM response.
 * For error code BUSY, this function shrinks the managed buffer, and return RETURN_NO_RESPONSE.
 * For error code REQUEST_RESYNCH, this function shrinks the managed buffer, clears connection_state, and return RETURN_DEVICE_ERROR.
 * For error code DECRYPT_ERROR, end the session: free session id and session key, return RETURN_SECURITY_VIOLATION.
 * For any other error code, this function shrinks the managed buffer, and return RETURN_DEVICE_ERROR.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                       If session_id is NULL, it is a normal message.
 *                                       If session_id is NOT NULL, it is a secured message.
 * @param  response_size                 The size of the response.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
 * @param  response                     The SPDM response message.
 * @param  original_request_code          Indicate the original request code.
 * @param  expected_response_code         Indicate the expected response code.
 * @param  expected_response_size         Indicate the expected response size.
 *
 * @retval RETURN_SUCCESS               The error code is RESPONSE_NOT_READY. The RESPOND_IF_READY is sent and an expected SPDM response is received.
 * @retval RETURN_NO_RESPONSE           The error code is BUSY.
 * @retval RETURN_DEVICE_ERROR          The error code is REQUEST_RESYNCH or others.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    The error code is DECRYPT_ERROR and session_id is NOT NULL.
 **/
return_status libspdm_handle_error_response_main(
    libspdm_context_t *spdm_context, const uint32_t *session_id,
    size_t *response_size, void **response,
    uint8_t original_request_code, uint8_t expected_response_code,
    size_t expected_response_size)
{
    spdm_message_header_t *spdm_response;

    spdm_response = *response;
    LIBSPDM_ASSERT(spdm_response->request_response_code == SPDM_ERROR);

    if ((spdm_response->param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) &&
        (session_id != NULL)) {
        libspdm_free_session_id(spdm_context, *session_id);
        return LIBSPDM_STATUS_SESSION_MSG_ERROR;
    } else if(spdm_response->param1 == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
        return libspdm_handle_response_not_ready(spdm_context, session_id,
                                                 response_size, response,
                                                 original_request_code,
                                                 expected_response_code,
                                                 expected_response_size);
    } else {
        return libspdm_handle_simple_error_response(spdm_context,
                                                    spdm_response->param1);
    }
}
