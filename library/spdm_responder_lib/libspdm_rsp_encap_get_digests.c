/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * Get the SPDM encapsulated GET_DIGESTS request.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  encap_request_size             size in bytes of the encapsulated request data.
 *                                     On input, it means the size in bytes of encapsulated request data buffer.
 *                                     On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  encap_request                 A pointer to the encapsulated request data.
 *
 * @retval RETURN_SUCCESS               The encapsulated request is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
libspdm_return_t
libspdm_get_encap_request_get_digest(libspdm_context_t *spdm_context,
                                     size_t *encap_request_size,
                                     void *encap_request)
{
    spdm_get_digest_request_t *spdm_request;
    libspdm_return_t status;

    spdm_context->encap_context.last_encap_request_size = 0;

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    LIBSPDM_ASSERT(*encap_request_size >= sizeof(spdm_get_digest_request_t));
    *encap_request_size = sizeof(spdm_get_digest_request_t);

    spdm_request = encap_request;

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_DIGESTS;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;


    /* Cache data*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_request,
                                          *encap_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    libspdm_copy_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size =
        *encap_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Process the SPDM encapsulated DIGESTS response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  encap_response_size            size in bytes of the encapsulated response data.
 * @param  encap_response                A pointer to the encapsulated response data.
 * @param  need_continue                     Indicate if encapsulated communication need continue.
 *
 * @retval RETURN_SUCCESS               The encapsulated response is processed.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t libspdm_process_encap_response_digest(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    bool result;
    const spdm_digest_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *digest;
    size_t digest_size;
    size_t digest_count;
    size_t index;
    libspdm_return_t status;

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response->header.spdm_version != libspdm_get_connection_version (spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(
            spdm_context,
            spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_DIGESTS) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size < sizeof(spdm_digest_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    digest_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    digest_count = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_response->header.param2 & (1 << index)) {
            digest_count++;
        }
    }
    if (digest_count == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size <
        sizeof(spdm_digest_response_t) + digest_count * digest_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    spdm_response_size =
        sizeof(spdm_digest_response_t) + digest_count * digest_size;

    /* Cache data*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_response,
                                          spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    digest = (void *)(spdm_response + 1);
    for (index = 0; index < digest_count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "digest (0x%x) - ", index));
        libspdm_internal_dump_data(&digest[digest_size * index], digest_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    result = libspdm_verify_peer_digests(spdm_context, digest,
                                         digest_count);
    if (!result) {
        return LIBSPDM_STATUS_VERIF_FAIL;
    }

    *need_continue = false;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
