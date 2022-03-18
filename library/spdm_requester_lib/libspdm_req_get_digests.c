/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t digest[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
} libspdm_digests_response_max_t;
#pragma pack()

/**
 * This function sends GET_DIGESTS and receives DIGESTS *
 *
 * @param  context             A pointer to the SPDM context.
 * @param  slot_mask           Bitmask of the slots that contain certificates.
 * @param  total_digest_buffer A pointer to a destination buffer to store the digests.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         GET_DIGETS was sent and DIGESTS was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send GET_DIGESTS due to Requester's state.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP
 *         Cannot send GET_DIGESTS because the Requester's and/or Responder's CERT_CAP = 0.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the DIGESTS response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The DIGESTS response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 * @retval LIBSPDM_STATUS_VERIF_FAIL
 *         The digest of the stored certificate chain does not match the digest returned by
 *         the Responder.
 *         Note: This return value may be removed in the future.
 **/
libspdm_return_t libspdm_try_get_digest(void *context, uint8_t *slot_mask,
                                        void *total_digest_buffer)
{
    bool result;
    libspdm_return_t status;
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
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL, SPDM_GET_DIGESTS);
    if (spdm_context->connection_info.connection_state != LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    spdm_request.header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request.header.request_response_code = SPDM_GET_DIGESTS;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_send_spdm_request(spdm_context, NULL, sizeof(spdm_request), &spdm_request);
    LIBSPDM_RET_ON_ERR(status);

    spdm_response_size = sizeof(spdm_response);
    libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
    status = libspdm_receive_spdm_response(spdm_context, NULL, &spdm_response_size, &spdm_response);
    LIBSPDM_RET_ON_ERR(status);

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, NULL,
            &spdm_response_size,
            &spdm_response, SPDM_GET_DIGESTS, SPDM_DIGESTS,
            sizeof(libspdm_digests_response_max_t));

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
    } else if (spdm_response.header.request_response_code != SPDM_DIGESTS) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size < sizeof(spdm_digest_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    digest_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
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
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response_size < sizeof(spdm_digest_response_t) + digest_count * digest_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    spdm_response_size = sizeof(spdm_digest_response_t) + digest_count * digest_size;

    /* Cache data*/

    status = libspdm_append_message_b(spdm_context, &spdm_request, sizeof(spdm_request));
    /* TODO: Replace with LIBSPDM_RET_ON_ERR. */
    if (RETURN_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    status = libspdm_append_message_b(spdm_context, &spdm_response, spdm_response_size);
    /* TODO: Replace with LIBSPDM_RET_ON_ERR. */
    if (RETURN_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    for (index = 0; index < digest_count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "digest (0x%x) - ", index));
        libspdm_internal_dump_data(&spdm_response.digest[digest_size * index], digest_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    result = libspdm_verify_peer_digests(spdm_context, spdm_response.digest, digest_count);
    if (!result) {
        spdm_context->error_state = LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        return LIBSPDM_STATUS_VERIF_FAIL;
    }

    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;

    if (total_digest_buffer != NULL) {
        libspdm_copy_mem(total_digest_buffer, digest_size * digest_count,
                         spdm_response.digest, digest_size * digest_count);
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function sends GET_DIGESTS and receives DIGESTS. It may retry GET_DIGESTS multiple times
 * if the Responder replies with a Busy error.
 *
 * If the peer certificate chain is deployed,
 * this function also verifies the digest with the certificate chain.
 *
 * TotalDigestSize = sizeof(digest) * count in slot_mask
 *
 * @param  context             A pointer to the SPDM context.
 * @param  slot_mask           Bitmask of the slots that contain certificates.
 * @param  total_digest_buffer A pointer to a destination buffer to store the digests.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         GET_DIGETS was sent and DIGESTS was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send GET_DIGESTS due to Requester's state.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP
 *         Cannot send GET_DIGESTS because the Requester's and/or Responder's CERT_CAP = 0.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the DIGESTS response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The DIGESTS response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 * @retval LIBSPDM_STATUS_VERIF_FAIL
 *         The digest of the stored certificate chain does not match the digest returned by
 *         the Responder.
 *         Note: This return value may be removed in the future.
 **/
libspdm_return_t libspdm_get_digest(void *context, uint8_t *slot_mask, void *total_digest_buffer)
{
    libspdm_context_t *spdm_context;
    uintn retry;
    libspdm_return_t status;

    spdm_context = context;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_get_digest(spdm_context, slot_mask, total_digest_buffer);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
