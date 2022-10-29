/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)

/**
 * Process the SPDM encapsulated GET_DIGESTS request and return the response.
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
libspdm_return_t libspdm_get_encap_response_digest(void *context,
                                                   size_t request_size,
                                                   void *request,
                                                   size_t *response_size,
                                                   void *response)
{
    spdm_get_digest_request_t *spdm_request;
    spdm_digest_response_t *spdm_response;
    size_t index;
    uint32_t hash_size;
    uint8_t *digest;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;
    bool result;
    /*total populated solt count*/
    uint8_t slot_count;
    /*populated solt index*/
    uint8_t slot_index;

    spdm_context = context;
    spdm_request = request;

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_VERSION_MISMATCH,
            SPDM_GET_DIGESTS, response_size, response);
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_DIGESTS, response_size, response);
    }

    if (request_size != sizeof(spdm_get_digest_request_t)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    slot_count = libspdm_get_cert_slot_count(spdm_context);
    LIBSPDM_ASSERT(*response_size >=
                   sizeof(spdm_digest_response_t) + hash_size * slot_count);
    *response_size = sizeof(spdm_digest_response_t) + hash_size * slot_count;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_DIGESTS;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    digest = (void *)(spdm_response + 1);
    slot_index = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context
            .local_cert_chain_provision[index] != NULL) {
            spdm_response->header.param2 |= (1 << index);
            result = libspdm_generate_cert_chain_hash(spdm_context, index,
                                                      &digest[hash_size * slot_index]);
            slot_index++;
            if (!result) {
                return libspdm_generate_encap_error_response(
                    spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                    0, response_size, response);
            }
        }
    }

    /* Cache*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_request,
                                          request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    status = libspdm_append_message_mut_b(spdm_context, spdm_response,
                                          *response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_encap_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0,
            response_size, response);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)*/
