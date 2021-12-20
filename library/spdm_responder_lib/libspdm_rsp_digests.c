/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
  Process the SPDM GET_DIGESTS request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_get_response_digests(IN void *context, IN uintn request_size,
                    IN void *request,
                    IN OUT uintn *response_size,
                    OUT void *response)
{
    spdm_get_digest_request_t *spdm_request;
    uintn spdm_request_size;
    spdm_digest_response_t *spdm_response;
    uintn index;
    boolean no_local_cert_chain;
    uint32_t hash_size;
    uint8_t *digest;
    spdm_context_t *spdm_context;
    return_status status;
    boolean result;

    spdm_context = context;
    spdm_request = request;

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return spdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, FALSE, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_DIGESTS, response_size, response);
    }
    if (spdm_context->connection_info.connection_state !=
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                         0, response_size, response);
    }

    if (request_size != sizeof(spdm_get_digest_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                         response_size, response);
    }

    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                        spdm_request->header.request_response_code);

    spdm_request_size = request_size;

    no_local_cert_chain = TRUE;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context
                .local_cert_chain_provision[index] != NULL) {
            no_local_cert_chain = FALSE;
        }
    }
    if (no_local_cert_chain) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_DIGESTS, response_size, response);
    }

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*response_size >=
           sizeof(spdm_digest_response_t) +
               hash_size * spdm_context->local_context.slot_count);
    *response_size = sizeof(spdm_digest_response_t) +
             hash_size * spdm_context->local_context.slot_count;
    zero_mem(response, *response_size);
    spdm_response = response;

    if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    } else {
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    }
    spdm_response->header.request_response_code = SPDM_DIGESTS;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    digest = (void *)(spdm_response + 1);
    for (index = 0; index < spdm_context->local_context.slot_count;
         index++) {
        if (spdm_context->local_context
                          .local_cert_chain_provision[index] == NULL) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
        spdm_response->header.param2 |= (1 << index);
        result = spdm_generate_cert_chain_hash(spdm_context, index,
                          &digest[hash_size * index]);
        if (!result) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }
    
    /* Cache*/
    
    status = libspdm_append_message_b(spdm_context, spdm_request,
                       spdm_request_size);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
    }

    status = libspdm_append_message_b(spdm_context, spdm_response,
                       *response_size);
    if (RETURN_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                         SPDM_ERROR_CODE_UNSPECIFIED, 0,
                         response_size, response);
    }

    spdm_set_connection_state(spdm_context,
                  LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS);

    return RETURN_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/