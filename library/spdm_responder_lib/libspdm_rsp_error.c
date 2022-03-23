/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

/**
 * Generate ERROR message.
 *
 * This function can be called in libspdm_get_response_func.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  error_code                    The error code of the message.
 * @param  error_data                    The error data of the message.
 * @param  spdm_response_size             size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  spdm_response                 A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The error message is generated.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
return_status libspdm_generate_error_response(const void *context,
                                              uint8_t error_code,
                                              uint8_t error_data,
                                              size_t *response_size,
                                              void *response)
{
    spdm_error_response_t *spdm_response;

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_error_response_t));
    *response_size = sizeof(spdm_error_response_t);
    spdm_response = response;

    spdm_response->header.spdm_version = libspdm_get_connection_version (context);
    if (spdm_response->header.spdm_version == 0) {
        /* if version is not negotiated, then use default version 1.0 */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    }
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = error_code;
    spdm_response->header.param2 = error_data;

    return RETURN_SUCCESS;
}

/**
 * Generate ERROR message with extended error data.
 *
 * This function can be called in libspdm_get_response_func.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  error_code                    The error code of the message.
 * @param  error_data                    The error data of the message.
 * @param  extended_error_data_size        The size in bytes of the extended error data.
 * @param  extended_error_data            A pointer to the extended error data.
 * @param  spdm_response_size             size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  spdm_response                 A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The error message is generated.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
return_status libspdm_generate_extended_error_response(
    const void *context, uint8_t error_code, uint8_t error_data,
    size_t extended_error_data_size, const uint8_t *extended_error_data,
    size_t *response_size, void *response)
{
    spdm_error_response_t *spdm_response;
    size_t response_capacity;

    LIBSPDM_ASSERT(*response_size >=
                   sizeof(spdm_error_response_t) + extended_error_data_size);
    response_capacity = *response_size;
    *response_size =
        sizeof(spdm_error_response_t) + extended_error_data_size;
    spdm_response = response;

    spdm_response->header.spdm_version = libspdm_get_connection_version (context);
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = error_code;
    spdm_response->header.param2 = error_data;
    libspdm_copy_mem(spdm_response + 1, response_capacity - sizeof(spdm_error_response_t),
                     extended_error_data, extended_error_data_size);

    return RETURN_SUCCESS;
}
