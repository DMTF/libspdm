/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

/**
 * Get the SPDM encapsulated CHALLENGE request.
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
return_status spdm_get_encap_request_challenge(IN spdm_context_t *spdm_context,
                                               IN OUT uintn *encap_request_size,
                                               OUT void *encap_request)
{
    spdm_challenge_request_t *spdm_request;
    return_status status;

    spdm_context->encap_context.last_encap_request_size = 0;

    if (!spdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0)) {
        return RETURN_DEVICE_ERROR;
    }

    ASSERT(*encap_request_size >= sizeof(spdm_challenge_request_t));
    *encap_request_size = sizeof(spdm_challenge_request_t);

    spdm_request = encap_request;

    spdm_request->header.spdm_version = spdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_CHALLENGE;
    spdm_request->header.param1 = spdm_context->encap_context.req_slot_id;
    spdm_request->header.param2 =
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
    if(!libspdm_get_random_number(SPDM_NONCE_SIZE, spdm_request->nonce)) {
        return RETURN_DEVICE_ERROR;
    }
    DEBUG((DEBUG_INFO, "Encap ClientNonce - "));
    internal_dump_data(spdm_request->nonce, SPDM_NONCE_SIZE);
    DEBUG((DEBUG_INFO, "\n"));

    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                               spdm_request->header.request_response_code);


    /* Cache data*/

    status = libspdm_append_message_mut_c(spdm_context, spdm_request,
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
 * Process the SPDM encapsulated CHALLENGE_AUTH response.
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
return_status spdm_process_encap_response_challenge_auth(
    IN spdm_context_t *spdm_context, IN uintn encap_response_size,
    IN void *encap_response, OUT bool *need_continue)
{
    bool result;
    spdm_challenge_auth_response_t *spdm_response;
    uintn spdm_response_size;
    uint8_t *ptr;
    void *cert_chain_hash;
    uintn hash_size;
    uintn measurement_summary_hash_size;
    void *nonce;
    void *measurement_summary_hash;
    uint16_t opaque_length;
    void *opaque;
    void *signature;
    uintn signature_size;
    uint8_t auth_attribute;
    return_status status;

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
               SPDM_CHALLENGE_AUTH) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_challenge_auth_response_t)) {
        return RETURN_DEVICE_ERROR;
    }

    auth_attribute = spdm_response->header.param1;
    if (spdm_context->encap_context.req_slot_id == 0xFF) {
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) != 0xF) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_response->header.param2 != 0) {
            return RETURN_DEVICE_ERROR;
        }
    } else {
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) !=
            spdm_context->encap_context.req_slot_id) {
            return RETURN_DEVICE_ERROR;
        }
        if ((spdm_response->header.param2 &
             (1 << spdm_context->encap_context.req_slot_id)) == 0) {
            return RETURN_DEVICE_ERROR;
        }
    }
    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    signature_size = libspdm_get_req_asym_signature_size(
        spdm_context->connection_info.algorithm.req_base_asym_alg);
    measurement_summary_hash_size = 0;

    if (spdm_response_size <= sizeof(spdm_challenge_auth_response_t) +
        hash_size + SPDM_NONCE_SIZE +
        measurement_summary_hash_size +
        sizeof(uint16_t)) {
        return RETURN_DEVICE_ERROR;
    }

    ptr = (void *)(spdm_response + 1);

    cert_chain_hash = ptr;
    ptr += hash_size;
    DEBUG((DEBUG_INFO, "Encap cert_chain_hash (0x%x) - ", hash_size));
    internal_dump_data(cert_chain_hash, hash_size);
    DEBUG((DEBUG_INFO, "\n"));
    result = spdm_verify_certificate_chain_hash(spdm_context,
                                                cert_chain_hash, hash_size);
    if (!result) {
        spdm_context->encap_context.error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        return RETURN_SECURITY_VIOLATION;
    }

    nonce = ptr;
    DEBUG((DEBUG_INFO, "Encap nonce (0x%x) - ", SPDM_NONCE_SIZE));
    internal_dump_data(nonce, SPDM_NONCE_SIZE);
    DEBUG((DEBUG_INFO, "\n"));
    ptr += SPDM_NONCE_SIZE;

    measurement_summary_hash = ptr;
    ptr += measurement_summary_hash_size;
    DEBUG((DEBUG_INFO, "Encap measurement_summary_hash (0x%x) - ",
           measurement_summary_hash_size));
    internal_dump_data(measurement_summary_hash,
                       measurement_summary_hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    opaque_length = *(uint16_t *)ptr;
    if (opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        return RETURN_SECURITY_VIOLATION;
    }
    ptr += sizeof(uint16_t);

    if (spdm_response_size <
        sizeof(spdm_challenge_auth_response_t) + hash_size +
        SPDM_NONCE_SIZE + measurement_summary_hash_size +
        sizeof(uint16_t) + opaque_length + signature_size) {
        return RETURN_DEVICE_ERROR;
    }
    spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                         hash_size + SPDM_NONCE_SIZE +
                         measurement_summary_hash_size + sizeof(uint16_t) +
                         opaque_length + signature_size;
    status = libspdm_append_message_mut_c(spdm_context, spdm_response,
                                          spdm_response_size - signature_size);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    opaque = ptr;
    ptr += opaque_length;
    DEBUG((DEBUG_INFO, "Encap opaque (0x%x):\n", opaque_length));
    internal_dump_hex(opaque, opaque_length);

    signature = ptr;
    DEBUG((DEBUG_INFO, "Encap signature (0x%x):\n", signature_size));
    internal_dump_hex(signature, signature_size);
    result = spdm_verify_challenge_auth_signature(
        spdm_context, false, signature, signature_size);
    if (!result) {
        spdm_context->encap_context.error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        return RETURN_SECURITY_VIOLATION;
    }

    spdm_context->encap_context.error_state = LIBSPDM_STATUS_SUCCESS;
    spdm_set_connection_state(spdm_context,
                              LIBSPDM_CONNECTION_STATE_AUTHENTICATED);

    *need_continue = false;

    return RETURN_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
