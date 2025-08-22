/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT

/**
 * This function sends GET_CERTIFICATE and receives CERTIFICATE.
 *
 * This function verify the integrity of the certificate chain.
 * root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.
 *
 * If the peer root certificate hash is deployed,
 * this function also verifies the digest with the root hash in the certificate chain.
 *
 * @param  spdm_context      A pointer to the SPDM context.
 * @param  slot_id           The number of slot for the certificate chain.
 * @param  cert_chain_size   On input, indicate the size in bytes of the destination buffer to store
 *                           the digest buffer.
 *                           On output, indicate the size in bytes of the certificate chain.
 * @param  cert_chain        A pointer to a destination buffer to store the certificate chain.
 * @param  trust_anchor      A buffer to hold the trust_anchor which is used to validate the peer
 *                           certificate, if not NULL.
 * @param  trust_anchor_size A buffer to hold the trust_anchor_size, if not NULL.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         GET_CERTIFICATE was sent and CERTIFICATE was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send GET_CERTIFICATE due to Requester's state.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP
 *         Cannot send GET_CERTIFICATE because the Requester's and/or Responder's CERT_CAP = 0.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the CERTIFICATE response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The CERTIFICATE response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 * @retval LIBSPDM_STATUS_VERIF_FAIL
 *         Verification of the certificate chain failed.
 * @retval LIBSPDM_STATUS_INVALID_CERT
 *         The certificate is unable to be parsed or contains invalid field values.
 * @retval LIBSPDM_STATUS_CRYPTO_ERROR
 *         A generic cryptography error occurred.
 **/
static libspdm_return_t libspdm_try_get_large_certificate(libspdm_context_t *spdm_context,
                                                          const uint32_t *session_id,
                                                          uint8_t slot_id,
                                                          uint32_t length,
                                                          size_t *cert_chain_size,
                                                          void *cert_chain,
                                                          const void **trust_anchor,
                                                          size_t *trust_anchor_size)
{
    bool result;
    libspdm_return_t status;
    spdm_get_certificate_large_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_certificate_large_response_t *spdm_response;
    size_t spdm_response_size;
    uint32_t total_responder_cert_chain_buffer_length;
    size_t cert_chain_capacity;
    size_t cert_chain_size_internal;
    uint32_t remainder_length;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    bool chunk_enabled;
    uint8_t cert_model;
    uint32_t req_msg_length;
    uint32_t req_msg_offset;
    uint32_t rsp_msg_portion_length;
    uint32_t rsp_msg_remainder_length;
    bool use_large_cert_chain;
    uint32_t req_msg_header_size;
    uint32_t rsp_msg_header_size;
    uint32_t max_cert_chain_size;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(slot_id < SPDM_MAX_SLOT_COUNT);
    LIBSPDM_ASSERT(cert_chain_size != NULL);
    LIBSPDM_ASSERT(*cert_chain_size > 0);
    LIBSPDM_ASSERT(cert_chain != NULL);

    if ((length > SPDM_MAX_CERTIFICATE_CHAIN_SIZE) &&
        (libspdm_get_connection_version (spdm_context) < SPDM_MESSAGE_VERSION_14)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if ((length == SPDM_MAX_CERTIFICATE_CHAIN_SIZE) &&
        (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_14)) {
        /* support compatibility */
        length = SPDM_MAX_CERTIFICATE_CHAIN_SIZE_14;
    }

    if ((libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_14) &&
        libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_RESP_CAP)) {
        use_large_cert_chain = true;
    } else {
        use_large_cert_chain = false;
    }

    if (use_large_cert_chain) {
        max_cert_chain_size = SPDM_MAX_CERTIFICATE_CHAIN_SIZE_14;
        req_msg_header_size = sizeof(spdm_get_certificate_large_request_t);
        rsp_msg_header_size = sizeof(spdm_certificate_large_response_t);
    } else {
        max_cert_chain_size = SPDM_MAX_CERTIFICATE_CHAIN_SIZE;
        req_msg_header_size = sizeof(spdm_get_certificate_request_t);
        rsp_msg_header_size = sizeof(spdm_certificate_response_t);
    }

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    session_info = NULL;
    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info, SPDM_GET_CERTIFICATE);

    chunk_enabled =
        libspdm_is_capabilities_flag_supported(spdm_context, true,
                                               SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP,
                                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    remainder_length = 0;
    total_responder_cert_chain_buffer_length = 0;
    cert_chain_capacity = *cert_chain_size;
    cert_chain_size_internal = 0;

    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    do {
        /* -=[Construct Request Phase]=- */
        status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        LIBSPDM_ASSERT (message_size >= transport_header_size +
                        spdm_context->local_context.capability.transport_tail_size);
        spdm_request = (void *)(message + transport_header_size);
        spdm_request_size = message_size - transport_header_size -
                            spdm_context->local_context.capability.transport_tail_size;

        LIBSPDM_ASSERT (spdm_request_size >= req_msg_header_size);
        spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
        spdm_request->header.request_response_code = SPDM_GET_CERTIFICATE;
        spdm_request->header.param1 = slot_id;
        spdm_request->header.param2 = 0;
        req_msg_offset = (uint32_t)cert_chain_size_internal;
        if (req_msg_offset == 0) {
            req_msg_length = length;
        } else {
            req_msg_length = LIBSPDM_MIN(length, remainder_length);
        }
        if (use_large_cert_chain) {
            spdm_request->header.param1 |= SPDM_GET_CERTIFICATE_REQUEST_LARGE_CERT_CHAIN;
            spdm_request->offset = 0;
            spdm_request->length = 0;
            spdm_request->large_offset = req_msg_offset;
            spdm_request->large_length = req_msg_length;
        } else {
            spdm_request->offset = (uint16_t)req_msg_offset;
            spdm_request->length = (uint16_t)req_msg_length;
        }
        spdm_request_size = req_msg_header_size;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "request (offset 0x%x, size 0x%x):\n",
                       req_msg_offset,req_msg_length));

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

        status = libspdm_receive_spdm_response(spdm_context, session_id,
                                               &spdm_response_size,
                                               (void **)&spdm_response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_RECEIVE_FAIL;
            goto done;
        }

        /* -=[Validate Response Phase]=- */
        if (spdm_response_size < sizeof(spdm_message_header_t)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto done;
        }
        if (spdm_response->header.request_response_code == SPDM_ERROR) {
            status = libspdm_handle_error_response_main(
                spdm_context, session_id,
                &spdm_response_size,
                (void **)&spdm_response, SPDM_GET_CERTIFICATE,
                SPDM_CERTIFICATE);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_release_receiver_buffer (spdm_context);
                goto done;
            }
        } else if (spdm_response->header.request_response_code != SPDM_CERTIFICATE) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_response_size < rsp_msg_header_size) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto done;
        }
        if (use_large_cert_chain) {
            if ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN) == 0) {
                libspdm_release_receiver_buffer (spdm_context);
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto done;
            }
        } else {
            if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
                ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN) != 0)) {
                libspdm_release_receiver_buffer (spdm_context);
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto done;
            }
        }
        if (use_large_cert_chain) {
            rsp_msg_portion_length = spdm_response->large_portion_length;
            rsp_msg_remainder_length = spdm_response->large_remainder_length;
        } else {
            rsp_msg_portion_length = spdm_response->portion_length;
            rsp_msg_remainder_length = spdm_response->remainder_length;
        }

        if ((rsp_msg_portion_length > req_msg_length) ||
            (rsp_msg_portion_length == 0)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_SLOT_ID_MASK) != slot_id) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "cert_info - 0x%02x\n",
                           spdm_response->header.param2));
            cert_model = spdm_response->header.param2 &
                         SPDM_CERTIFICATE_RESPONSE_ATTRIBUTES_CERTIFICATE_INFO_MASK;
            if (spdm_context->connection_info.multi_key_conn_rsp) {
                if (cert_model > SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT) {
                    libspdm_release_receiver_buffer (spdm_context);
                    status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                    goto done;
                }
                if ((slot_id == 0) &&
                    (cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT)) {
                    libspdm_release_receiver_buffer (spdm_context);
                    status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                    goto done;
                }
                if ((cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) &&
                    (rsp_msg_portion_length != 0)) {
                    libspdm_release_receiver_buffer (spdm_context);
                    status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                    goto done;
                }
            } else {
                if (cert_model != SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) {
                    libspdm_release_receiver_buffer (spdm_context);
                    status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                    goto done;
                }
            }
            if (spdm_context->connection_info.peer_cert_info[slot_id] ==
                SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) {
                spdm_context->connection_info.peer_cert_info[slot_id] = cert_model;
            } else if (spdm_context->connection_info.peer_cert_info[slot_id] != cert_model) {
                libspdm_release_receiver_buffer (spdm_context);
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto done;
            }
        }
        if (spdm_response_size < rsp_msg_header_size +
            rsp_msg_portion_length) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto done;
        }
        if (rsp_msg_portion_length > max_cert_chain_size - req_msg_offset) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (rsp_msg_remainder_length > max_cert_chain_size - req_msg_offset -
            rsp_msg_portion_length) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (req_msg_offset == 0) {
            total_responder_cert_chain_buffer_length = rsp_msg_portion_length +
                                                       rsp_msg_remainder_length;
            if (total_responder_cert_chain_buffer_length > cert_chain_capacity) {
                libspdm_release_receiver_buffer (spdm_context);
                status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
                goto done;
            }
        } else if (req_msg_offset + rsp_msg_portion_length +
                   rsp_msg_remainder_length != total_responder_cert_chain_buffer_length) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }
        if (chunk_enabled && (req_msg_offset == 0) && (req_msg_length == max_cert_chain_size) &&
            (rsp_msg_remainder_length != 0)) {
            libspdm_release_receiver_buffer (spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto done;
        }

        /* -=[Process Response Phase]=- */
        remainder_length = rsp_msg_remainder_length;
        spdm_response_size = rsp_msg_header_size + rsp_msg_portion_length;

        if (session_id == NULL) {
            status = libspdm_append_message_b(spdm_context, spdm_request, spdm_request_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_release_receiver_buffer (spdm_context);
                goto done;
            }
            status = libspdm_append_message_b(spdm_context, spdm_response, spdm_response_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                libspdm_release_receiver_buffer (spdm_context);
                goto done;
            }
        }

        if (cert_chain_size_internal + rsp_msg_portion_length > cert_chain_capacity) {
            libspdm_release_receiver_buffer (spdm_context);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "cert_chain_buffer full\n"));
            status = LIBSPDM_STATUS_BUFFER_FULL;
            goto done;
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Certificate (offset 0x%x, size 0x%x):\n",
                       req_msg_offset, rsp_msg_portion_length));
        LIBSPDM_INTERNAL_DUMP_HEX((uint8_t *)spdm_response + rsp_msg_header_size,
                                  rsp_msg_portion_length);

        libspdm_copy_mem((uint8_t *)cert_chain + cert_chain_size_internal,
                         cert_chain_capacity - cert_chain_size_internal,
                         (uint8_t *)spdm_response + rsp_msg_header_size,
                         rsp_msg_portion_length);

        cert_chain_size_internal += rsp_msg_portion_length;

        if (spdm_context->connection_info.connection_state <
            LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE) {
            spdm_context->connection_info.connection_state =
                LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE;
        }

        /* -=[Log Message Phase]=- */
        #if LIBSPDM_ENABLE_MSG_LOG
        libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
        #endif /* LIBSPDM_ENABLE_MSG_LOG */

        libspdm_release_receiver_buffer (spdm_context);
    } while (remainder_length != 0);

    *cert_chain_size = cert_chain_size_internal;
    LIBSPDM_ASSERT(*cert_chain_size <= SPDM_MAX_CERTIFICATE_CHAIN_SIZE_14);

    if (spdm_context->local_context.verify_peer_spdm_cert_chain != NULL) {
        result = spdm_context->local_context.verify_peer_spdm_cert_chain (
            spdm_context, slot_id, cert_chain_size_internal, cert_chain,
            trust_anchor, trust_anchor_size);
        if (!result) {
            status = LIBSPDM_STATUS_VERIF_FAIL;
            goto done;
        }
    } else {
        result = libspdm_verify_peer_cert_chain_buffer_integrity(
            spdm_context, cert_chain, cert_chain_size_internal);
        if (!result) {
            status = LIBSPDM_STATUS_VERIF_FAIL;
            goto done;
        }

        /*verify peer cert chain authority*/
        result = libspdm_verify_peer_cert_chain_buffer_authority(
            spdm_context, cert_chain,cert_chain_size_internal,
            trust_anchor, trust_anchor_size);
        if (!result) {
            status = LIBSPDM_STATUS_VERIF_NO_AUTHORITY;
        }
    }

    spdm_context->connection_info.peer_used_cert_chain_slot_id = slot_id;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer_size =
        cert_chain_size_internal;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer),
                     cert_chain, cert_chain_size_internal);
#else
    result = libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        cert_chain, cert_chain_size_internal,
        spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer_hash);
    if (!result) {
        status = LIBSPDM_STATUS_CRYPTO_ERROR;
        goto done;
    }

    spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

    if (spdm_context->connection_info.algorithm.pqc_asym_algo != 0) {
        result = libspdm_get_pqc_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.pqc_asym_algo,
            cert_chain, cert_chain_size_internal,
            &spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key);
    } else {
        result = libspdm_get_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.base_asym_algo,
            cert_chain, cert_chain_size_internal,
            &spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key);
    }
    if (!result) {
        status = LIBSPDM_STATUS_INVALID_CERT;
        goto done;
    }
#endif

    if (status != LIBSPDM_STATUS_VERIF_NO_AUTHORITY) {
        status = LIBSPDM_STATUS_SUCCESS;
    }
done:
    return status;
}

static libspdm_return_t libspdm_try_get_certificate(libspdm_context_t *spdm_context,
                                                    const uint32_t *session_id,
                                                    uint8_t slot_id,
                                                    uint16_t length,
                                                    size_t *cert_chain_size,
                                                    void *cert_chain,
                                                    const void **trust_anchor,
                                                    size_t *trust_anchor_size)
{
    return libspdm_try_get_large_certificate(spdm_context, session_id, slot_id, length,
                                             cert_chain_size, cert_chain,
                                             trust_anchor, trust_anchor_size);
}

libspdm_return_t libspdm_get_certificate(void *spdm_context, const uint32_t *session_id,
                                         uint8_t slot_id,
                                         size_t *cert_chain_size,
                                         void *cert_chain)
{
    return libspdm_get_certificate_choose_length(spdm_context, session_id, slot_id,
                                                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN,
                                                 cert_chain_size, cert_chain);
}

libspdm_return_t libspdm_get_certificate_ex(void *spdm_context, const uint32_t *session_id,
                                            uint8_t slot_id,
                                            size_t *cert_chain_size,
                                            void *cert_chain,
                                            const void **trust_anchor,
                                            size_t *trust_anchor_size)
{
    return libspdm_get_certificate_choose_length_ex(spdm_context, session_id, slot_id,
                                                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN,
                                                    cert_chain_size, cert_chain,
                                                    trust_anchor, trust_anchor_size);
}

libspdm_return_t libspdm_get_certificate_choose_length(void *spdm_context,
                                                       const uint32_t *session_id,
                                                       uint8_t slot_id,
                                                       uint16_t length,
                                                       size_t *cert_chain_size,
                                                       void *cert_chain)
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
        status = libspdm_try_get_certificate(context, session_id, slot_id, length,
                                             cert_chain_size, cert_chain, NULL, NULL);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

libspdm_return_t libspdm_get_certificate_choose_length_ex(void *spdm_context,
                                                          const uint32_t *session_id,
                                                          uint8_t slot_id,
                                                          uint32_t length,
                                                          size_t *cert_chain_size,
                                                          void *cert_chain,
                                                          const void **trust_anchor,
                                                          size_t *trust_anchor_size)
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
        status = libspdm_try_get_large_certificate(context, session_id, slot_id, length,
                                                   cert_chain_size, cert_chain, trust_anchor,
                                                   trust_anchor_size);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
