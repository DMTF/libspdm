/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_responder_lib.h"

#if SPDM_ENABLE_CAPABILITY_CERT_CAP

/**
  Get the SPDM encapsulated GET_DIGESTS request.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_request_size             size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  encap_request                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
return_status
spdm_get_encap_request_get_digest(IN spdm_context_t *spdm_context,
                  IN OUT uintn *encap_request_size,
                  OUT void *encap_request)
{
    spdm_get_digest_request_t *spdm_request;
    return_status status;

    spdm_context->encap_context.last_encap_request_size = 0;

    if (!spdm_is_capabilities_flag_supported(
            spdm_context, FALSE,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return RETURN_DEVICE_ERROR;
    }

    ASSERT(*encap_request_size >= sizeof(spdm_get_digest_request_t));
    *encap_request_size = sizeof(spdm_get_digest_request_t);

    spdm_request = encap_request;

    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                        spdm_request->header.request_response_code);

    if (spdm_is_version_supported(spdm_context, SPDM_MESSAGE_VERSION_11)) {
        spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    } else {
        spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    }
    spdm_request->header.request_response_code = SPDM_GET_DIGESTS;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;

    //
    // Cache data
    //
    status = libspdm_append_message_mut_b(spdm_context, spdm_request,
                       *encap_request_size);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    copy_mem(&spdm_context->encap_context.last_encap_request_header,
         &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size =
        *encap_request_size;

    return RETURN_SUCCESS;
}

/**
  Process the SPDM encapsulated DIGESTS response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  encap_response_size            size in bytes of the encapsulated response data.
  @param  encap_response                A pointer to the encapsulated response data.
  @param  need_continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status spdm_process_encap_response_digest(
    IN spdm_context_t *spdm_context, IN uintn encap_response_size,
    IN void *encap_response, OUT boolean *need_continue)
{
    boolean result;
    spdm_digest_response_t *spdm_response;
    uintn spdm_response_size;
    uint8_t *digest;
    uintn digest_size;
    uintn digest_count;
    uintn index;
    return_status status;

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = spdm_handle_encap_error_response_main(
            spdm_context,
            spdm_response->header.param1);
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code !=
           SPDM_DIGESTS) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_digest_response_t)) {
        return RETURN_DEVICE_ERROR;
    }

    digest_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    digest_count = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_response->header.param2 & (1 << index)) {
            digest_count++;
        }
    }
    if (digest_count == 0) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size <
        sizeof(spdm_digest_response_t) + digest_count * digest_size) {
        return RETURN_DEVICE_ERROR;
    }
    spdm_response_size =
        sizeof(spdm_digest_response_t) + digest_count * digest_size;
    //
    // Cache data
    //
    status = libspdm_append_message_mut_b(spdm_context, spdm_response,
                       spdm_response_size);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    digest = (void *)(spdm_response + 1);
    for (index = 0; index < digest_count; index++) {
        DEBUG((DEBUG_INFO, "digest (0x%x) - ", index));
        internal_dump_data(&digest[digest_size * index], digest_size);
        DEBUG((DEBUG_INFO, "\n"));
    }

    result = spdm_verify_peer_digests(spdm_context, digest,
                      digest_count);
    if (!result) {
        return RETURN_SECURITY_VIOLATION;
    }

    *need_continue = FALSE;

    return RETURN_SUCCESS;
}

#endif // SPDM_ENABLE_CAPABILITY_CERT_CAP