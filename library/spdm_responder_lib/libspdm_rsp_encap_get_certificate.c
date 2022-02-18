/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * Get the SPDM encapsulated GET_CERTIFICATE request.
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
return_status
spdm_get_encap_request_get_certificate(IN spdm_context_t *spdm_context,
                                       IN OUT uintn *encap_request_size,
                                       OUT void *encap_request)
{
    spdm_get_certificate_request_t *spdm_request;
    return_status status;

    spdm_context->encap_context.last_encap_request_size = 0;

    if (!spdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return RETURN_DEVICE_ERROR;
    }

    ASSERT(*encap_request_size >= sizeof(spdm_get_certificate_request_t));
    *encap_request_size = sizeof(spdm_get_certificate_request_t);

    spdm_request = encap_request;

    spdm_request->header.spdm_version = spdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request->header.param1 = spdm_context->encap_context.req_slot_id;
    spdm_request->header.param2 = 0;
    spdm_request->offset = (uint16_t)get_managed_buffer_size(
        &spdm_context->encap_context.certificate_chain_buffer);
    spdm_request->length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    DEBUG((DEBUG_INFO, "request (offset 0x%x, size 0x%x):\n",
           spdm_request->offset, spdm_request->length));

    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                               spdm_request->header.request_response_code);


    /* Cache data*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_request,
                                          *encap_request_size);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    copy_mem_s(&spdm_context->encap_context.last_encap_request_header,
               sizeof(spdm_context->encap_context.last_encap_request_header),
               &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size =
        *encap_request_size;

    return RETURN_SUCCESS;
}

/**
 * Process the SPDM encapsulated CERTIFICATE response.
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
return_status spdm_process_encap_response_certificate(
    IN spdm_context_t *spdm_context, IN uintn encap_response_size,
    IN void *encap_response, OUT bool *need_continue)
{
    spdm_certificate_response_t *spdm_response;
    uintn spdm_response_size;
    bool result;
    return_status status;
    uint16_t request_offset;

    spdm_context->encap_context.error_state =
        LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response->header.spdm_version != spdm_get_connection_version (spdm_context)) {
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
               SPDM_CERTIFICATE) {
        return RETURN_DEVICE_ERROR;
    }
    if (encap_response_size < sizeof(spdm_certificate_response_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if ((spdm_response->portion_length > LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN) ||
        (spdm_response->portion_length == 0)) {
        return RETURN_DEVICE_ERROR;
    }
    request_offset = (uint16_t)get_managed_buffer_size(
        &spdm_context->encap_context.certificate_chain_buffer);
    if (request_offset == 0) {
        spdm_context->encap_context.cert_chain_total_len = spdm_response->portion_length +
                                                           spdm_response->remainder_length;
    } else if (spdm_context->encap_context.cert_chain_total_len !=
               request_offset + spdm_response->portion_length + spdm_response->remainder_length) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response->header.param1 !=
        spdm_context->encap_context.req_slot_id) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_certificate_response_t) +
        spdm_response->portion_length) {
        return RETURN_DEVICE_ERROR;
    }
    spdm_response_size = sizeof(spdm_certificate_response_t) +
                         spdm_response->portion_length;

    /* Cache data*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_response,
                                          spdm_response_size);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    DEBUG((DEBUG_INFO, "Certificate (offset 0x%x, size 0x%x):\n",
           get_managed_buffer_size(
               &spdm_context->encap_context.certificate_chain_buffer),
           spdm_response->portion_length));
    internal_dump_hex((void *)(spdm_response + 1),
                      spdm_response->portion_length);

    status = append_managed_buffer(
        &spdm_context->encap_context.certificate_chain_buffer,
        (void *)(spdm_response + 1), spdm_response->portion_length);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    if (spdm_response->remainder_length != 0) {
        *need_continue = true;
        return RETURN_SUCCESS;
    }

    *need_continue = false;

    if (spdm_context->local_context.verify_peer_spdm_cert_chain != NULL) {
        status = spdm_context->local_context.verify_peer_spdm_cert_chain (
            spdm_context, spdm_context->encap_context.req_slot_id,
            get_managed_buffer_size(
                &spdm_context->encap_context.certificate_chain_buffer),
            get_managed_buffer(
                &spdm_context->encap_context.certificate_chain_buffer),
            NULL, NULL);
        if (RETURN_ERROR(status)) {
            spdm_context->encap_context.error_state =
                LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
            return RETURN_SECURITY_VIOLATION;
        }
    } else {
        result = spdm_verify_peer_cert_chain_buffer(
            spdm_context,
            get_managed_buffer(
                &spdm_context->encap_context.certificate_chain_buffer),
            get_managed_buffer_size(
                &spdm_context->encap_context.certificate_chain_buffer),
            NULL, NULL);
        if (!result) {
            spdm_context->encap_context.error_state =
                LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
            return RETURN_SECURITY_VIOLATION;
        }
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        get_managed_buffer_size(
            &spdm_context->encap_context.certificate_chain_buffer);
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               get_managed_buffer(
                   &spdm_context->encap_context.certificate_chain_buffer),
               get_managed_buffer_size(
                   &spdm_context->encap_context.certificate_chain_buffer));
#else
    result = libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        get_managed_buffer(
            &spdm_context->encap_context.certificate_chain_buffer),
        get_managed_buffer_size(
            &spdm_context->encap_context.certificate_chain_buffer),
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    if (!result) {
        spdm_context->encap_context.error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        return RETURN_SECURITY_VIOLATION;
    }
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        get_managed_buffer(
            &spdm_context->encap_context.certificate_chain_buffer),
        get_managed_buffer_size(
            &spdm_context->encap_context.certificate_chain_buffer),
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
    if (!result) {
        spdm_context->encap_context.error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        return RETURN_SECURITY_VIOLATION;
    }
#endif

    spdm_context->encap_context.error_state = LIBSPDM_STATUS_SUCCESS;

    return RETURN_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
