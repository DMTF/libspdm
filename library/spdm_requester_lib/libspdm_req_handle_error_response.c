/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"

/**
  This function sends RESPOND_IF_READY and receives an expected SPDM response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  response_size                 The size of the response.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
  @param  response                     The SPDM response message.
  @param  expected_response_code         Indicate the expected response code.
  @param  expected_response_size         Indicate the expected response size.

  @retval RETURN_SUCCESS               The RESPOND_IF_READY is sent and an expected SPDM response is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_requester_respond_if_ready(IN spdm_context_t *spdm_context,
                          IN uint32_t *session_id,
                          IN OUT uintn *response_size,
                          OUT void *response,
                          IN uint8_t expected_response_code,
                          IN uintn expected_response_size)
{
    return_status status;
    spdm_response_if_ready_request_t spdm_request;
    spdm_message_header_t *spdm_response;

    spdm_response = response;

    if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
        spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    } else {
        spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    }
    spdm_request.header.request_response_code = SPDM_RESPOND_IF_READY;
    spdm_request.header.param1 = spdm_context->error_data.request_code;
    spdm_request.header.param2 = spdm_context->error_data.token;
    status = spdm_send_spdm_request(spdm_context, session_id,
                    sizeof(spdm_request), &spdm_request);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }

    *response_size = expected_response_size;
    zero_mem(response, expected_response_size);
    status = spdm_receive_spdm_response(spdm_context, session_id,
                        response_size, response);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }
    if (*response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response->request_response_code != expected_response_code) {
        return RETURN_DEVICE_ERROR;
    }
    // For response like SPDM_ALGORITHMS, we just can expect the max response size
    if (*response_size > expected_response_size) {
        return RETURN_DEVICE_ERROR;
    }
    return RETURN_SUCCESS;
}

/**
  This function handles simple error code.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  error_code                    Indicate the error code.

  @retval RETURN_NO_RESPONSE           If the error code is BUSY.
  @retval RETURN_DEVICE_ERROR          If the error code is REQUEST_RESYNCH or others.
**/
return_status spdm_handle_simple_error_response(IN void *context,
                        IN uint8_t error_code)
{
    spdm_context_t *spdm_context;

    spdm_context = context;

    //
    // NOT_READY is treated as error here.
    // Use spdm_handle_error_response_main to handle NOT_READY message in long latency command.
    //
    if (error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
        return RETURN_DEVICE_ERROR;
    }

    if (error_code == SPDM_ERROR_CODE_BUSY) {
        return RETURN_NO_RESPONSE;
    }

    if (error_code == SPDM_ERROR_CODE_REQUEST_RESYNCH) {
        spdm_context->connection_info.connection_state =
            SPDM_CONNECTION_STATE_NOT_STARTED;
    }

    return RETURN_DEVICE_ERROR;
}

/**
  This function handles RESPONSE_NOT_READY error code.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  response_size                 The size of the response.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
  @param  response                     The SPDM response message.
  @param  original_request_code          Indicate the orginal request code.
  @param  expected_response_code         Indicate the expected response code.
  @param  expected_response_size         Indicate the expected response size.

  @retval RETURN_SUCCESS               The RESPOND_IF_READY is sent and an expected SPDM response is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_handle_response_not_ready(IN spdm_context_t *spdm_context,
                         IN uint32_t *session_id,
                         IN OUT uintn *response_size,
                         OUT void *response,
                         IN uint8_t original_request_code,
                         IN uint8_t expected_response_code,
                         IN uintn expected_response_size)
{
    spdm_error_response_t *spdm_response;
    spdm_error_data_response_not_ready_t *extend_error_data;

    if(*response_size != sizeof(spdm_error_response_t) +
           sizeof(spdm_error_data_response_not_ready_t)) {
        return RETURN_DEVICE_ERROR;
    }

    spdm_response = response;
    extend_error_data =
        (spdm_error_data_response_not_ready_t *)(spdm_response + 1);
    ASSERT(spdm_response->header.request_response_code == SPDM_ERROR);
    ASSERT(spdm_response->header.param1 ==
           SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    ASSERT(extend_error_data->request_code == original_request_code);

    spdm_context->error_data.rd_exponent = extend_error_data->rd_exponent;
    spdm_context->error_data.request_code = extend_error_data->request_code;
    spdm_context->error_data.token = extend_error_data->token;
    spdm_context->error_data.rd_tm = extend_error_data->rd_tm;

    return spdm_requester_respond_if_ready(spdm_context, session_id,
                           response_size, response,
                           expected_response_code,
                           expected_response_size);
}

/**
  This function handles the error response.

  The SPDM response code must be SPDM_ERROR.
  For error code RESPONSE_NOT_READY, this function sends RESPOND_IF_READY and receives an expected SPDM response.
  For error code BUSY, this function shrinks the managed buffer, and return RETURN_NO_RESPONSE.
  For error code REQUEST_RESYNCH, this function shrinks the managed buffer, clears connection_state, and return RETURN_DEVICE_ERROR.
  For any other error code, this function shrinks the managed buffer, and return RETURN_DEVICE_ERROR.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  response_size                 The size of the response.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
  @param  response                     The SPDM response message.
  @param  original_request_code          Indicate the original request code.
  @param  expected_response_code         Indicate the expected response code.
  @param  expected_response_size         Indicate the expected response size.

  @retval RETURN_SUCCESS               The error code is RESPONSE_NOT_READY. The RESPOND_IF_READY is sent and an expected SPDM response is received.
  @retval RETURN_NO_RESPONSE           The error code is BUSY.
  @retval RETURN_DEVICE_ERROR          The error code is REQUEST_RESYNCH or others.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_handle_error_response_main(
    IN spdm_context_t *spdm_context, IN uint32_t *session_id,
    IN OUT uintn *response_size, IN OUT void *response,
    IN uint8_t original_request_code, IN uint8_t expected_response_code,
    IN uintn expected_response_size)
{
    spdm_message_header_t *spdm_response;

    spdm_response = response;
    ASSERT(spdm_response->request_response_code == SPDM_ERROR);
    if (spdm_response->param1 != SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
        return spdm_handle_simple_error_response(spdm_context,
                             spdm_response->param1);
    } else {
        return spdm_handle_response_not_ready(spdm_context, session_id,
                              response_size, response,
                              original_request_code,
                              expected_response_code,
                              expected_response_size);
    }
}
