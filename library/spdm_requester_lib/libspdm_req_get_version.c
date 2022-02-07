/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];
} spdm_version_response_max_t;
#pragma pack()


/**
 * This function sends GET_VERSION and receives VERSION.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status try_spdm_get_version(IN spdm_context_t *spdm_context,
                                   IN OUT uint8_t *version_number_entry_count,
                                   OUT spdm_version_number_t *version_number_entry)
{
    return_status status;
    bool result;
    spdm_get_version_request_t spdm_request;
    spdm_version_response_max_t spdm_response;
    uintn spdm_response_size;
    spdm_version_number_t common_version;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.header.request_response_code = SPDM_GET_VERSION;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    libspdm_reset_context(spdm_context);

    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                               spdm_request.header.request_response_code);

    status = spdm_send_spdm_request(spdm_context, NULL,
                                    sizeof(spdm_request), &spdm_request);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }

    spdm_response_size = sizeof(spdm_response);
    zero_mem(&spdm_response, sizeof(spdm_response));
    status = spdm_receive_spdm_response(
        spdm_context, NULL, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.spdm_version != SPDM_MESSAGE_VERSION_10) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = spdm_handle_simple_error_response(
            spdm_context, spdm_response.header.param1);
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else if (spdm_response.header.request_response_code != SPDM_VERSION) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_version_response_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.version_number_entry_count > LIBSPDM_MAX_VERSION_COUNT) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.version_number_entry_count == 0) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size <
        sizeof(spdm_version_response_t) +
        spdm_response.version_number_entry_count *
        sizeof(spdm_version_number_t)) {
        return RETURN_DEVICE_ERROR;
    }
    spdm_response_size = sizeof(spdm_version_response_t) +
                         spdm_response.version_number_entry_count *
                         sizeof(spdm_version_number_t);


    /* Cache data*/

    status = libspdm_append_message_a(spdm_context, &spdm_request,
                                      sizeof(spdm_request));
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }
    status = libspdm_append_message_a(spdm_context, &spdm_response,
                                      spdm_response_size);
    if (RETURN_ERROR(status)) {
        libspdm_reset_message_a(spdm_context);
        return RETURN_SECURITY_VIOLATION;
    }

    /* spdm_negotiate_connection_version will change the spdm_response.
     * It must be done after append_message_a.*/
    result = spdm_negotiate_connection_version(&common_version,
                                               spdm_context->local_context.version.spdm_version,
                                               spdm_context->local_context.version.spdm_version_count,
                                               spdm_response.version_number_entry,
                                               spdm_response.version_number_entry_count);
    if (result == false) {
        libspdm_reset_message_a(spdm_context);
        return RETURN_DEVICE_ERROR;
    } else {
        copy_mem(&(spdm_context->connection_info.version),
                 &(common_version),
                 sizeof(spdm_version_number_t));
    }

    if (version_number_entry_count != NULL && version_number_entry != NULL) {
        if (*version_number_entry_count < spdm_response.version_number_entry_count) {
            *version_number_entry_count = spdm_response.version_number_entry_count;
            libspdm_reset_message_a(spdm_context);
            return RETURN_BUFFER_TOO_SMALL;
        } else {
            *version_number_entry_count = spdm_response.version_number_entry_count;
            copy_mem (version_number_entry, spdm_response.version_number_entry,
                      spdm_response.version_number_entry_count * sizeof(spdm_version_number_t));
            spdm_version_number_sort (version_number_entry, *version_number_entry_count);
        }
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    return RETURN_SUCCESS;
}

/**
 * This function sends GET_VERSION and receives VERSION.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  version_count                 version_count from the VERSION response.
 * @param  VersionNumberEntries         VersionNumberEntries from the VERSION response.
 *
 * @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status spdm_get_version(IN spdm_context_t *spdm_context,
                               IN OUT uint8_t *version_number_entry_count,
                               OUT spdm_version_number_t *version_number_entry)
{
    uintn retry;
    return_status status;

    retry = spdm_context->retry_times;
    do {
        status = try_spdm_get_version(spdm_context,
                                      version_number_entry_count, version_number_entry);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
