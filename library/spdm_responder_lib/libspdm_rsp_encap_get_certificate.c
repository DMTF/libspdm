/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)

libspdm_return_t libspdm_get_encap_request_get_certificate(libspdm_context_t *spdm_context,
                                                           size_t *encap_request_size,
                                                           void *encap_request)
{
    spdm_get_certificate_large_request_t *spdm_request;
    libspdm_return_t status;
    uint32_t req_msg_length;
    uint32_t req_msg_offset;
    bool use_large_cert_chain;
    uint32_t req_msg_header_size;

    spdm_context->encap_context.last_encap_request_size = 0;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if ((libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_14) &&
        libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_RESP_CAP, 0)) {
        use_large_cert_chain = true;
        spdm_context->encap_context.use_large_cert_chain = true;
    } else {
        use_large_cert_chain = false;
        spdm_context->encap_context.use_large_cert_chain = false;
    }

    if (use_large_cert_chain) {
        req_msg_header_size = sizeof(spdm_get_certificate_large_request_t);
    } else {
        req_msg_header_size = sizeof(spdm_get_certificate_request_t);
    }

    LIBSPDM_ASSERT(*encap_request_size >= req_msg_header_size);
    *encap_request_size = req_msg_header_size;

    spdm_request = encap_request;

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_CERTIFICATE;
    spdm_request->header.param1 = spdm_context->encap_context.req_slot_id;
    spdm_request->header.param2 = 0;
    req_msg_offset = (uint32_t)spdm_context->mut_auth_cert_chain_buffer_size;
    req_msg_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
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
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "request (offset 0x%x, size 0x%x):\n",
                   req_msg_offset, req_msg_length));

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    /* Cache data*/
    status = libspdm_append_message_mut_b(spdm_context, spdm_request, *encap_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    libspdm_copy_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size = *encap_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_certificate(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    const spdm_certificate_large_response_t *spdm_response;
    size_t spdm_response_size;
    bool result;
    libspdm_return_t status;
    uint32_t request_offset;
    uint8_t slot_id;
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    size_t cert_chain_buffer_max_size;
    uint8_t cert_model;
    uint32_t rsp_msg_portion_length;
    uint32_t rsp_msg_remainder_length;
    bool use_large_cert_chain;
    uint32_t rsp_msg_header_size;
    uint32_t max_cert_chain_size;

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    cert_chain_buffer = (uint8_t *)spdm_context->mut_auth_cert_chain_buffer;
    cert_chain_buffer_size = spdm_context->mut_auth_cert_chain_buffer_size;
    cert_chain_buffer_max_size = spdm_context->mut_auth_cert_chain_buffer_max_size;

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response->header.spdm_version != libspdm_get_connection_version (spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(
            spdm_context, spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code != SPDM_CERTIFICATE) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    use_large_cert_chain = spdm_context->encap_context.use_large_cert_chain;
    if (use_large_cert_chain) {
        if ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN) == 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
            ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN) != 0)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    if (use_large_cert_chain) {
        max_cert_chain_size = SPDM_MAX_CERTIFICATE_CHAIN_SIZE_14;
        rsp_msg_header_size = sizeof(spdm_certificate_large_response_t);
    } else {
        max_cert_chain_size = SPDM_MAX_CERTIFICATE_CHAIN_SIZE;
        rsp_msg_header_size = sizeof(spdm_certificate_response_t);
    }

    if (encap_response_size < rsp_msg_header_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (use_large_cert_chain) {
        rsp_msg_portion_length = spdm_response->large_portion_length;
        rsp_msg_remainder_length = spdm_response->large_remainder_length;
    } else {
        rsp_msg_portion_length = spdm_response->portion_length;
        rsp_msg_remainder_length = spdm_response->remainder_length;
    }

    if ((rsp_msg_portion_length > LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN) ||
        (rsp_msg_portion_length == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    request_offset = (uint32_t)cert_chain_buffer_size;

    if (rsp_msg_portion_length > max_cert_chain_size - request_offset) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (rsp_msg_remainder_length > max_cert_chain_size - request_offset - rsp_msg_portion_length) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (request_offset == 0) {
        spdm_context->encap_context.cert_chain_total_len = rsp_msg_portion_length +
                                                           rsp_msg_remainder_length;
    } else if (spdm_context->encap_context.cert_chain_total_len !=
               request_offset + rsp_msg_portion_length + rsp_msg_remainder_length) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    slot_id = spdm_context->encap_context.req_slot_id;
    if ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_SLOT_ID_MASK) != slot_id) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "cert_info - 0x%02x\n",
                       spdm_response->header.param2));
        cert_model = spdm_response->header.param2 &
                     SPDM_CERTIFICATE_RESPONSE_ATTRIBUTES_CERTIFICATE_INFO_MASK;
        if (spdm_context->connection_info.multi_key_conn_req) {
            if (cert_model > SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
            if ((slot_id == 0) &&
                (cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT)) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
            if ((cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) &&
                (spdm_response->portion_length != 0)) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
        } else {
            if (cert_model != SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
        }
        if (spdm_context->connection_info.peer_cert_info[slot_id] ==
            SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) {
            spdm_context->connection_info.peer_cert_info[slot_id] = cert_model;
        } else if (spdm_context->connection_info.peer_cert_info[slot_id] != cert_model) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    if (spdm_response_size < rsp_msg_header_size + rsp_msg_portion_length) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    spdm_response_size = rsp_msg_header_size + rsp_msg_portion_length;

    /* Cache data*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_response, spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Certificate (offset 0x%x, size 0x%x):\n",
                   request_offset, rsp_msg_portion_length));
    LIBSPDM_INTERNAL_DUMP_HEX((const uint8_t *)spdm_response + rsp_msg_header_size,
                              rsp_msg_portion_length);

    if (cert_chain_buffer_size + rsp_msg_portion_length > cert_chain_buffer_max_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "cert_chain_buffer full\n"));
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    libspdm_copy_mem(cert_chain_buffer + cert_chain_buffer_size,
                     cert_chain_buffer_max_size - cert_chain_buffer_size,
                     (const uint8_t *)spdm_response + rsp_msg_header_size,
                     rsp_msg_portion_length);

    cert_chain_buffer_size += rsp_msg_portion_length;
    spdm_context->mut_auth_cert_chain_buffer_size = cert_chain_buffer_size;

    if (rsp_msg_remainder_length != 0) {
        *need_continue = true;

        return LIBSPDM_STATUS_SUCCESS;
    }

    *need_continue = false;

    if (spdm_context->local_context.verify_peer_spdm_cert_chain != NULL) {
        result = spdm_context->local_context.verify_peer_spdm_cert_chain (
            spdm_context, spdm_context->encap_context.req_slot_id,
            cert_chain_buffer_size, cert_chain_buffer, NULL, NULL);
        if (!result) {
            return LIBSPDM_STATUS_VERIF_FAIL;
        }
    } else {
        result = libspdm_verify_peer_cert_chain_buffer_integrity(
            spdm_context, cert_chain_buffer, cert_chain_buffer_size);
        if (!result) {
            return LIBSPDM_STATUS_VERIF_FAIL;
        }

        /*verify peer cert chain authority*/
        result = libspdm_verify_peer_cert_chain_buffer_authority(
            spdm_context, cert_chain_buffer, cert_chain_buffer_size, NULL, NULL);
        if (!result) {
            status = LIBSPDM_STATUS_VERIF_NO_AUTHORITY;
        }
    }

    spdm_context->connection_info.peer_used_cert_chain_slot_id =
        spdm_context->encap_context.req_slot_id;
    slot_id = spdm_context->encap_context.req_slot_id;
    LIBSPDM_ASSERT(slot_id < SPDM_MAX_SLOT_COUNT);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer_size =
        cert_chain_buffer_size;

    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer),
                     cert_chain_buffer, cert_chain_buffer_size);
#else
    result = libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        cert_chain_buffer, cert_chain_buffer_size,
        spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer_hash);
    if (!result) {
        return LIBSPDM_STATUS_CRYPTO_ERROR;
    }
    spdm_context->connection_info.peer_used_cert_chain[slot_id].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

    if (spdm_context->connection_info.algorithm.req_pqc_asym_alg != 0) {
        result = libspdm_get_pqc_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.req_pqc_asym_alg,
            cert_chain_buffer, cert_chain_buffer_size,
            &spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key);
    } else {
        result = libspdm_get_leaf_cert_public_key_from_cert_chain(
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            cert_chain_buffer, cert_chain_buffer_size,
            &spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key);
    }
    if (!result) {
        return LIBSPDM_STATUS_INVALID_CERT;
    }
#endif
    if (status != LIBSPDM_STATUS_VERIF_NO_AUTHORITY) {
        return LIBSPDM_STATUS_SUCCESS;
    } else {
        return LIBSPDM_STATUS_VERIF_NO_AUTHORITY;
    }
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (...) */
