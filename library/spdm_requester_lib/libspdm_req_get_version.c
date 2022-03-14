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
 * @param  spdm_context         A pointer to the SPDM context.
 * @param  version_count        The number of SPDM versions that the Responder supports.
 * @param  VersionNumberEntries The list of SPDM versions that the Responder supports.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         GET_VERSION was sent and VERSION was received.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the VERSION response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The VERSION response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_NEGOTIATION_FAIL
 *         The Requester and Responder do not support a common SPDM version.
 **/
libspdm_return_t libspdm_try_get_version(libspdm_context_t *spdm_context,
                                         uint8_t *version_number_entry_count,
                                         spdm_version_number_t *version_number_entry)
{
    libspdm_return_t status;
    bool result;
    spdm_get_version_request_t spdm_request;
    libspdm_version_response_max_t spdm_response;
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

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request.header.request_response_code);

    status = libspdm_send_spdm_request(spdm_context, NULL,
                                       sizeof(spdm_request), &spdm_request);
    LIBSPDM_RET_ON_ERR(status);

    spdm_response_size = sizeof(spdm_response);
    libspdm_zero_mem(&spdm_response, sizeof(spdm_response));

    status = libspdm_receive_spdm_response(spdm_context, NULL, &spdm_response_size, &spdm_response);
    LIBSPDM_RET_ON_ERR(status);

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response.header.spdm_version != SPDM_MESSAGE_VERSION_10) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_simple_error_response(spdm_context, spdm_response.header.param1);

        /* TODO: Replace this with LIBSPDM_RET_ON_ERR once libspdm_handle_simple_error_response
         * uses the new error codes. */
        if (status == RETURN_DEVICE_ERROR) {
            return LIBSPDM_STATUS_ERROR_PEER;
        }
        else if (status == RETURN_NO_RESPONSE) {
            return LIBSPDM_STATUS_BUSY_PEER;
        }
        else if (status == LIBSPDM_STATUS_RESYNCH_PEER) {
            return LIBSPDM_STATUS_RESYNCH_PEER;
        }
    } else if (spdm_response.header.request_response_code != SPDM_VERSION) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size < sizeof(spdm_version_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response.version_number_entry_count > LIBSPDM_MAX_VERSION_COUNT) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response.version_number_entry_count == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size <
        sizeof(spdm_version_response_t) +
        spdm_response.version_number_entry_count *
        sizeof(spdm_version_number_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    spdm_response_size = sizeof(spdm_version_response_t) +
                         spdm_response.version_number_entry_count *
                         sizeof(spdm_version_number_t);

    /* Cache data*/

    status = libspdm_append_message_a(spdm_context, &spdm_request,
                                      sizeof(spdm_request));
    LIBSPDM_RET_ON_ERR(status);

    status = libspdm_append_message_a(spdm_context, &spdm_response,
                                      spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_a(spdm_context);
        return status;
    }

    /* libspdm_negotiate_connection_version will change the spdm_response.
     * It must be done after append_message_a.*/
    result = libspdm_negotiate_connection_version(&common_version,
                                                  spdm_context->local_context.version.spdm_version,
                                                  spdm_context->local_context.version.spdm_version_count,
                                                  spdm_response.version_number_entry,
                                                  spdm_response.version_number_entry_count);
    if (result == false) {
        libspdm_reset_message_a(spdm_context);
        return LIBSPDM_STATUS_NEGOTIATION_FAIL;
    }

    libspdm_copy_mem(&(spdm_context->connection_info.version),
                     sizeof(spdm_context->connection_info.version),
                     &(common_version),
                     sizeof(spdm_version_number_t));

    if (version_number_entry_count != NULL && version_number_entry != NULL) {
        if (*version_number_entry_count < spdm_response.version_number_entry_count) {
            *version_number_entry_count = spdm_response.version_number_entry_count;
            libspdm_reset_message_a(spdm_context);
            return RETURN_BUFFER_TOO_SMALL;
        } else {
            *version_number_entry_count = spdm_response.version_number_entry_count;
            libspdm_copy_mem(version_number_entry,
                             spdm_response.version_number_entry_count * sizeof(spdm_version_number_t),
                             spdm_response.version_number_entry,
                             spdm_response.version_number_entry_count *
                             sizeof(spdm_version_number_t));
            libspdm_version_number_sort (version_number_entry, *version_number_entry_count);
        }
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function sends GET_VERSION and receives VERSION. It may retry GET_VERSION multiple times
 * if the Responder replies with a Busy error.
 *
 * @param  spdm_context         A pointer to the SPDM context.
 * @param  version_count        The number of SPDM versions that the Responder supports.
 * @param  VersionNumberEntries The list of SPDM versions that the Responder supports.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         GET_VERSION was sent and VERSION was received.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the VERSION response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The VERSION response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_NEGOTIATION_FAIL
 *         The Requester and Responder do not support a common SPDM version.
 **/
libspdm_return_t libspdm_get_version(libspdm_context_t *spdm_context,
                                     uint8_t *version_number_entry_count,
                                     spdm_version_number_t *version_number_entry)
{
    uintn retry;
    libspdm_return_t status;

    spdm_context->crypto_request = false;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_get_version(spdm_context,
                                         version_number_entry_count, version_number_entry);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
