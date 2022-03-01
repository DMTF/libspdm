/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t digest[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
} libspdm_digests_response_max_t;

#pragma pack()

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * This function sends GET_DIGEST
 * to get all digest of the certificate chains from device.
 *
 * If the peer certificate chain is deployed,
 * this function also verifies the digest with the certificate chain.
 *
 * TotalDigestSize = sizeof(digest) * count in slot_mask
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_mask                     The slots which deploy the CertificateChain.
 * @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.
 *
 * @retval RETURN_SUCCESS               The digests are got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_try_get_digest(void *context, uint8_t *slot_mask,
                                     void *total_digest_buffer)
{
    bool result;
    return_status status;
    spdm_get_digest_request_t spdm_request;
    libspdm_digests_response_max_t spdm_response;
    uintn spdm_response_size;
    uintn digest_size;
    uintn digest_count;
    uintn index;
    libspdm_context_t *spdm_context;

    spdm_context = context;
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        return RETURN_UNSUPPORTED;
    }
    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  SPDM_GET_DIGESTS);
    if (spdm_context->connection_info.connection_state !=
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return RETURN_UNSUPPORTED;
    }

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    spdm_request.header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request.header.request_response_code = SPDM_GET_DIGESTS;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    status = libspdm_send_spdm_request(spdm_context, NULL,
                                       sizeof(spdm_request), &spdm_request);
    if (RETURN_ERROR(status)) {
        return status;
    }
    spdm_response_size = sizeof(spdm_response);
    zero_mem(&spdm_response, sizeof(spdm_response));
    status = libspdm_receive_spdm_response(
        spdm_context, NULL, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        return status;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, NULL,
            &spdm_response_size,
            &spdm_response, SPDM_GET_DIGESTS, SPDM_DIGESTS,
            sizeof(libspdm_digests_response_max_t));
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else if (spdm_response.header.request_response_code != SPDM_DIGESTS) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_digest_response_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return RETURN_DEVICE_ERROR;
    }

    digest_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (slot_mask != NULL) {
        *slot_mask = spdm_response.header.param2;
    }
    digest_count = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_response.header.param2 & (1 << index)) {
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

    /* Cache data*/

    status = libspdm_append_message_b(spdm_context, &spdm_request,
                                      sizeof(spdm_request));
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    status = libspdm_append_message_b(spdm_context, &spdm_response,
                                      spdm_response_size);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    for (index = 0; index < digest_count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "digest (0x%x) - ", index));
        libspdm_internal_dump_data(&spdm_response.digest[digest_size * index],
                                   digest_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    result = libspdm_verify_peer_digests(
        spdm_context, spdm_response.digest, digest_count);
    if (!result) {
        spdm_context->error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        return RETURN_SECURITY_VIOLATION;
    }

    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;

    if (total_digest_buffer != NULL) {
        copy_mem(total_digest_buffer, digest_size * digest_count,
                 spdm_response.digest, digest_size * digest_count);
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    return RETURN_SUCCESS;
}

/**
 * This function sends GET_DIGEST
 * to get all digest of the certificate chains from device.
 *
 * If the peer certificate chain is deployed,
 * this function also verifies the digest with the certificate chain.
 *
 * TotalDigestSize = sizeof(digest) * count in slot_mask
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_mask                     The slots which deploy the CertificateChain.
 * @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.
 *
 * @retval RETURN_SUCCESS               The digests are got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_get_digest(void *context, uint8_t *slot_mask,
                                 void *total_digest_buffer)
{
    libspdm_context_t *spdm_context;
    uintn retry;
    return_status status;

    spdm_context = context;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_get_digest(spdm_context, slot_mask,
                                        total_digest_buffer);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
