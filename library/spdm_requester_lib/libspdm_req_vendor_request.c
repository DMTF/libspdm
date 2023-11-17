/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

#define SPDM_VENDOR_PAYLOAD_LEN (LIBSPDM_MAX_VENDOR_DEFINED_RESPONSE_LEN - \
                                 sizeof(spdm_vendor_defined_response_msg_t))

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_plus_request[SPDM_VENDOR_PAYLOAD_LEN];
} libspdm_vendor_defined_response_msg_max_t;
#pragma pack()

libspdm_return_t libspdm_try_vendor_request(libspdm_context_t *spdm_context,
                                            uint16_t standard_id,
                                            uint8_t vendor_id_len,
                                            uint8_t *vendor_id,
                                            uint8_t *request,
                                            uint16_t request_len,
                                            uint8_t *response,
                                            size_t *response_len)
{
    int i;
    libspdm_return_t status;
    spdm_vendor_defined_request_msg_t *spdm_request;
    size_t spdm_request_size;
    libspdm_vendor_defined_response_msg_max_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    const uint32_t* session_id = NULL;

    /* -=[Check Parameters Phase]=- */
    if (vendor_id == NULL ||
        request == NULL ||
        response == NULL ||
        response_len == NULL) {
        status = LIBSPDM_STATUS_INVALID_PARAMETER;
        goto done;
    }

    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    /* do not accept requests exceeding maximum allowed payload */
    if (request_len > SPDM_VENDOR_PAYLOAD_LEN) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* -=[Construct Request Phase]=- */
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    /* Message header here */
    spdm_request->standard_id = standard_id;
    spdm_request->len = vendor_id_len;

    /* Copy Vendor id */
    uint8_t* vendor_request = ((uint8_t *)spdm_request) + sizeof(spdm_vendor_defined_request_msg_t);
    libspdm_copy_mem(vendor_request, vendor_id_len, vendor_id, vendor_id_len);
    vendor_request += vendor_id_len;

    /* Copy request_len */
    libspdm_copy_mem(vendor_request, sizeof(uint16_t), &request_len, sizeof(uint16_t));
    vendor_request += sizeof(uint16_t);

    /* Copy payload */
    size_t vendor_request_len = SPDM_VENDOR_PAYLOAD_LEN - sizeof(uint16_t);
    libspdm_copy_mem(vendor_request, vendor_request_len, request, request_len);

    spdm_request_size = sizeof(spdm_vendor_defined_request_msg_t) +
                        vendor_id_len + sizeof(uint16_t) + request_len;

    /* -=[Send Request Phase]=- */
    status =
        libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        status = LIBSPDM_STATUS_SEND_FAIL;
        goto done;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(spdm_context, session_id,
                                           &spdm_response_size,
                                           (void **)&spdm_response);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        status = LIBSPDM_STATUS_RECEIVE_FAIL;
        goto done;
    }

    /* -=[Validate Response Phase]=- */
    /* check response buffer size at least spdm response default header plus
     * number of bytes required by vendor id and 2 bytes for response payload size */
    if (spdm_response_size < sizeof(spdm_vendor_defined_response_msg_t) +
        spdm_response->vendor_id_len + sizeof(uint16_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_VENDOR_DEFINED_REQUEST,
            SPDM_VENDOR_DEFINED_RESPONSE);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }
    if (spdm_response->standard_id != spdm_request->standard_id) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }
    if (spdm_response->vendor_id_len != spdm_request->len) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }
    vendor_request = ((uint8_t *)spdm_request) + sizeof(spdm_vendor_defined_request_msg_t);
    uint8_t* vendor_response = spdm_response->vendor_plus_request;
    for (i = 0; i < spdm_response->vendor_id_len; i++) {
        if (*vendor_request != *vendor_response) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        vendor_request++;
        vendor_response++;
    }

    /* -=[Process Response Phase]=- */
    uint8_t *response_ptr = spdm_response->vendor_plus_request + spdm_response->vendor_id_len;
    uint16_t response_size = *((uint16_t*)response_ptr);
    if (spdm_response_size < response_size +
        sizeof(spdm_vendor_defined_response_msg_t) +
        spdm_response->vendor_id_len + sizeof(uint16_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }
    response_ptr += sizeof(uint16_t);
    if (*response_len < response_size) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto done;
    }
    libspdm_copy_mem(response, *response_len, response_ptr, response_size);
    *response_len = response_size;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

    status = LIBSPDM_STATUS_SUCCESS;
done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_vendor_request(void *spdm_context,
                                        uint16_t standard_id,
                                        uint8_t vendor_id_len,
                                        void *vendor_id,
                                        void *request,
                                        size_t request_len,
                                        void *response,
                                        size_t *response_len)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_vendor_request(context,
                                            standard_id,
                                            vendor_id_len, (uint8_t *)vendor_id,
                                            (uint8_t *)request, (uint16_t)request_len,
                                            (uint8_t *)response, response_len);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
