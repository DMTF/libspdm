#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CHUNK_CAP

libspdm_return_t libspdm_get_response_chunk_get(
    void* context,
    size_t request_size,
    const void* request,
    size_t* response_size,
    void* response)
{
    libspdm_context_t* spdm_context;
    libspdm_chunk_info_t* get_info;

    const spdm_chunk_get_request_t* spdm_request;
    spdm_chunk_response_response_t* spdm_response;

    uint8_t* spdm_chunk;

    spdm_context = (libspdm_context_t*) context;
    spdm_request = (const spdm_chunk_get_request_t*) request;
    spdm_response = (spdm_chunk_response_response_t*) response;
    get_info = &spdm_context->chunk_context.get;

    if ((spdm_context->local_context.capability.flags &
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP) == 0) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    if (request_size < sizeof(spdm_chunk_get_request_t)) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    if (spdm_request->header.spdm_version < SPDM_MESSAGE_VERSION_12) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, 0,
            response_size, response);
    }

    if (spdm_request->header.spdm_version
        != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
            response_size, response);
    }

    if (get_info->chunk_in_use == false) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    if (spdm_request->header.param2 != get_info->chunk_handle) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    if (spdm_request->chunk_seq_no != get_info->chunk_seq_no) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    libspdm_zero_mem(response, *response_size);

    /* Assert the data transfer size is smaller than the response size.
     * Otherwise there is no reason to chunk this response. */
    LIBSPDM_ASSERT(spdm_context->connection_info.capability.data_transfer_size < *response_size);

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CHUNK_RESPONSE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = get_info->chunk_handle;
    spdm_response->chunk_seq_no = get_info->chunk_seq_no;

    if (spdm_request->chunk_seq_no == 0) {
        spdm_response->chunk_size =
            spdm_context->connection_info.capability.data_transfer_size
            - sizeof(spdm_chunk_response_response_t)
            - sizeof(uint32_t);

        /* No reason to do chunking if message is smaller than largest chunk size. */
        LIBSPDM_ASSERT(spdm_response->chunk_size < get_info->large_message_size);

        spdm_chunk = (uint8_t*) (spdm_response + 1);

        /* Set LargeMessageSize only in first chunk. */
        *((uint32_t*) (spdm_chunk)) = (uint32_t)get_info->large_message_size;
        spdm_chunk += sizeof(uint32_t);

        *response_size = sizeof(spdm_chunk_response_response_t)
                         + sizeof(uint32_t)
                         + spdm_response->chunk_size;
    }
    else {
        spdm_response->chunk_size =
            LIBSPDM_MIN(spdm_context->connection_info.capability.data_transfer_size
                        - sizeof(spdm_chunk_response_response_t),
                        (uint32_t) (get_info->large_message_size
                                    - get_info->chunk_bytes_transferred));

        spdm_chunk = (uint8_t*) (spdm_response + 1);

        *response_size = sizeof(spdm_chunk_response_response_t)
                         + spdm_response->chunk_size;
    }

    libspdm_copy_mem(spdm_chunk, spdm_response->chunk_size,
                     (uint8_t*) get_info->large_message + get_info->chunk_bytes_transferred,
                     spdm_response->chunk_size);

    get_info->chunk_seq_no++;
    get_info->chunk_bytes_transferred += spdm_response->chunk_size;

    LIBSPDM_ASSERT(get_info->chunk_bytes_transferred <= get_info->large_message_size);
    if (get_info->chunk_bytes_transferred == get_info->large_message_size) {
        get_info->chunk_in_use = false;
        get_info->chunk_handle++; /* implicit wrap - around to 0. */
        get_info->chunk_seq_no = 0;
        get_info->large_message = NULL;
        get_info->large_message_size = 0;
        get_info->chunk_bytes_transferred = 0;

        spdm_response->header.param1 |= SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CHUNK_CAP */
