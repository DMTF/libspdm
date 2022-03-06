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
} libspdm_version_response_max_t;
#pragma pack()


/**
 * This function sends GET_VERSION and receives VERSION.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
return_status libspdm_try_get_version(libspdm_context_t *spdm_context,
                                      uint8_t *version_number_entry_count,
                                      spdm_version_number_t *version_number_entry)
{
    return_status status;
    bool result;
    spdm_get_version_request_t *spdm_request;
    uintn spdm_request_size;
    libspdm_version_response_max_t *spdm_response;
    uintn spdm_response_size;
    spdm_version_number_t common_version;
    uint8_t *message;
    uintn message_size;
    uintn transport_header_size;

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    libspdm_reset_context(spdm_context);

    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_acquire_sender_buffer (spdm_context, &message_size, &message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;

    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request->header.request_response_code = SPDM_GET_VERSION;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request_size = sizeof(spdm_get_version_request_t);

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    status = libspdm_send_spdm_request(spdm_context, NULL,
                                       spdm_request_size, spdm_request);
    if (RETURN_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context, message);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context, message);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* receive */

    libspdm_acquire_receiver_buffer (spdm_context, &message_size, &message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;
    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(
        spdm_context, NULL, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != SPDM_MESSAGE_VERSION_10) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_simple_error_response(
            spdm_context, spdm_response->header.param1);
        if (RETURN_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_VERSION) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_version_response_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->version_number_entry_count > LIBSPDM_MAX_VERSION_COUNT) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->version_number_entry_count == 0) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response_size <
        sizeof(spdm_version_response_t) +
        spdm_response->version_number_entry_count *
        sizeof(spdm_version_number_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    spdm_response_size = sizeof(spdm_version_response_t) +
                         spdm_response->version_number_entry_count *
                         sizeof(spdm_version_number_t);

    /* Cache data*/

    status = libspdm_append_message_a(spdm_context, spdm_request,
                                      spdm_request_size);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }
    status = libspdm_append_message_a(spdm_context, spdm_response,
                                      spdm_response_size);
    if (RETURN_ERROR(status)) {
        libspdm_reset_message_a(spdm_context);
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }

    /* libspdm_negotiate_connection_version will change the spdm_response.
     * It must be done after append_message_a.*/
    result = libspdm_negotiate_connection_version(&common_version,
                                                  spdm_context->local_context.version.spdm_version,
                                                  spdm_context->local_context.version.spdm_version_count,
                                                  spdm_response->version_number_entry,
                                                  spdm_response->version_number_entry_count);
    if (result == false) {
        libspdm_reset_message_a(spdm_context);
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    } else {
        libspdm_copy_mem(&(spdm_context->connection_info.version),
                         sizeof(spdm_context->connection_info.version),
                         &(common_version),
                         sizeof(spdm_version_number_t));
    }

    if (version_number_entry_count != NULL && version_number_entry != NULL) {
        if (*version_number_entry_count < spdm_response->version_number_entry_count) {
            *version_number_entry_count = spdm_response->version_number_entry_count;
            libspdm_reset_message_a(spdm_context);
            status = RETURN_BUFFER_TOO_SMALL;
            goto receive_done;
        } else {
            *version_number_entry_count = spdm_response->version_number_entry_count;
            libspdm_copy_mem(version_number_entry,
                             spdm_response->version_number_entry_count * sizeof(spdm_version_number_t),
                             spdm_response->version_number_entry,
                             spdm_response->version_number_entry_count *
                             sizeof(spdm_version_number_t));
            libspdm_version_number_sort (version_number_entry, *version_number_entry_count);
        }
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    status = RETURN_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context, message);
    return status;
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
return_status libspdm_get_version(libspdm_context_t *spdm_context,
                                  uint8_t *version_number_entry_count,
                                  spdm_version_number_t *version_number_entry)
{
    uintn retry;
    return_status status;

    spdm_context->crypto_request = false;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_get_version(spdm_context,
                                         version_number_entry_count, version_number_entry);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
