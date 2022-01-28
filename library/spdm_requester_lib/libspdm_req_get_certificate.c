/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint16_t portion_length;
    uint16_t remainder_length;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN];
} spdm_certificate_response_max_t;

#pragma pack()

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  length                       length parameter in the get_certificate message (limited by LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN).
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.
  @param  trust_anchor                  A buffer to hold the trust_anchor which is used to validate the peer certificate, if not NULL.
  @param  trust_anchor_size             A buffer to hold the trust_anchor_size, if not NULL.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status try_spdm_get_certificate(IN void *context, IN uint8_t slot_id,
                       IN uint16_t length,
                       IN OUT uintn *cert_chain_size,
                       OUT void *cert_chain,
                       OUT void **trust_anchor OPTIONAL,
                       OUT uintn *trust_anchor_size OPTIONAL)
{
    boolean result;
    return_status status;
    spdm_get_certificate_request_t spdm_request;
    spdm_certificate_response_max_t spdm_response;
    uintn spdm_response_size;
    large_managed_buffer_t certificate_chain_buffer;
    spdm_context_t *spdm_context;
    uint16_t total_responder_cert_chain_buffer_length;

    ASSERT(slot_id < SPDM_MAX_SLOT_COUNT);

    spdm_context = context;
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, TRUE, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        return RETURN_UNSUPPORTED;
    }
    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                            SPDM_GET_CERTIFICATE);
    if ((spdm_context->connection_info.connection_state !=
         LIBSPDM_CONNECTION_STATE_NEGOTIATED) &&
        (spdm_context->connection_info.connection_state !=
         LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS) &&
        (spdm_context->connection_info.connection_state !=
         LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE)) {
        return RETURN_UNSUPPORTED;
    }

    init_managed_buffer(&certificate_chain_buffer,
                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    length = MIN(length, LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    do {
        spdm_request.header.spdm_version =
            spdm_get_connection_version (spdm_context);
        spdm_request.header.request_response_code =
            SPDM_GET_CERTIFICATE;
        spdm_request.header.param1 = slot_id;
        spdm_request.header.param2 = 0;
        spdm_request.offset = (uint16_t)get_managed_buffer_size(
            &certificate_chain_buffer);
        if (spdm_request.offset == 0) {
            spdm_request.length = length;
        } else {
            spdm_request.length = MIN(length, spdm_response.remainder_length);
        }
        DEBUG((DEBUG_INFO, "request (offset 0x%x, size 0x%x):\n",
               spdm_request.offset, spdm_request.length));

        status = spdm_send_spdm_request(spdm_context, NULL,
                        sizeof(spdm_request),
                        &spdm_request);
        if (RETURN_ERROR(status)) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }

        spdm_response_size = sizeof(spdm_response);
        zero_mem(&spdm_response, sizeof(spdm_response));
        status = spdm_receive_spdm_response(spdm_context, NULL,
                            &spdm_response_size,
                            &spdm_response);
        if (RETURN_ERROR(status)) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if (spdm_response_size < sizeof(spdm_message_header_t)) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
            return RETURN_DEVICE_ERROR;
        }
        if (spdm_response.header.request_response_code == SPDM_ERROR) {
            status = spdm_handle_error_response_main(
                spdm_context, NULL,
                &spdm_response_size,
                &spdm_response, SPDM_GET_CERTIFICATE,
                SPDM_CERTIFICATE,
                sizeof(spdm_certificate_response_max_t));
            if (RETURN_ERROR(status)) {
                goto done;
            }
        } else if (spdm_response.header.request_response_code !=
               SPDM_CERTIFICATE) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if (spdm_response_size < sizeof(spdm_certificate_response_t)) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if (spdm_response_size > sizeof(spdm_response)) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if ((spdm_response.portion_length > spdm_request.length) || (spdm_response.portion_length == 0)) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if ((spdm_response.header.param1 & SPDM_CERTIFICATE_RESPONSE_SLOT_ID_MASK) != slot_id) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if (spdm_response_size < sizeof(spdm_certificate_response_t) +
                         spdm_response.portion_length) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }
        if (spdm_request.offset == 0) {
            total_responder_cert_chain_buffer_length = spdm_response.portion_length + spdm_response.remainder_length;
        } else if (spdm_request.offset + spdm_response.portion_length + spdm_response.remainder_length != total_responder_cert_chain_buffer_length) {
            status = RETURN_DEVICE_ERROR;
            goto done;
        }

        spdm_response_size = sizeof(spdm_certificate_response_t) +
                     spdm_response.portion_length;

        /* Cache data*/

        status = libspdm_append_message_b(spdm_context, &spdm_request,
                           sizeof(spdm_request));
        if (RETURN_ERROR(status)) {
            status = RETURN_SECURITY_VIOLATION;
            goto done;
        }
        status = libspdm_append_message_b(spdm_context, &spdm_response,
                           spdm_response_size);
        if (RETURN_ERROR(status)) {
            status = RETURN_SECURITY_VIOLATION;
            goto done;
        }

        DEBUG((DEBUG_INFO, "Certificate (offset 0x%x, size 0x%x):\n",
               spdm_request.offset, spdm_response.portion_length));
        internal_dump_hex(spdm_response.cert_chain,
                  spdm_response.portion_length);

        status = append_managed_buffer(&certificate_chain_buffer,
                           spdm_response.cert_chain,
                           spdm_response.portion_length);
        if (RETURN_ERROR(status)) {
            status = RETURN_SECURITY_VIOLATION;
            goto done;
        }
        spdm_context->connection_info.connection_state =
            LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE;

    } while (spdm_response.remainder_length != 0);

    if (spdm_context->local_context.verify_peer_spdm_cert_chain != NULL) {
        status = spdm_context->local_context.verify_peer_spdm_cert_chain (
            spdm_context, slot_id, get_managed_buffer_size(&certificate_chain_buffer),
            get_managed_buffer(&certificate_chain_buffer),
            trust_anchor, trust_anchor_size);
        if (RETURN_ERROR(status)) {
            spdm_context->error_state =
                LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
            status = RETURN_SECURITY_VIOLATION;
            goto done;
        }
    } else {
        result = spdm_verify_peer_cert_chain_buffer(
            spdm_context, get_managed_buffer(&certificate_chain_buffer),
            get_managed_buffer_size(&certificate_chain_buffer),
            trust_anchor, trust_anchor_size);
        if (!result) {
            spdm_context->error_state =
                LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
            status = RETURN_SECURITY_VIOLATION;
            goto done;
        }
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        get_managed_buffer_size(&certificate_chain_buffer);
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
         get_managed_buffer(&certificate_chain_buffer),
         get_managed_buffer_size(&certificate_chain_buffer));
#else
    result = libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        get_managed_buffer(&certificate_chain_buffer),
        get_managed_buffer_size(&certificate_chain_buffer),
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    if (!result) {
        spdm_context->error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        status = RETURN_SECURITY_VIOLATION;
        goto done;
    }

    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        get_managed_buffer(&certificate_chain_buffer),
        get_managed_buffer_size(&certificate_chain_buffer),
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
    if (!result) {
        spdm_context->error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        status = RETURN_SECURITY_VIOLATION;
        goto done;
    }
#endif

    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;

    if (cert_chain_size != NULL) {
        if (*cert_chain_size <
            get_managed_buffer_size(&certificate_chain_buffer)) {
            *cert_chain_size = get_managed_buffer_size(
                &certificate_chain_buffer);
            return RETURN_BUFFER_TOO_SMALL;
        }
        *cert_chain_size =
            get_managed_buffer_size(&certificate_chain_buffer);
        if (cert_chain != NULL) {
            copy_mem(cert_chain,
                 get_managed_buffer(&certificate_chain_buffer),
                 get_managed_buffer_size(
                     &certificate_chain_buffer));
        }
    }

    status = RETURN_SUCCESS;
done:
    return status;
}

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status libspdm_get_certificate(IN void *context, IN uint8_t slot_id,
                   IN OUT uintn *cert_chain_size,
                   OUT void *cert_chain)
{
    return libspdm_get_certificate_choose_length(context, slot_id,
                          LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN,
                          cert_chain_size, cert_chain);
}

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.
  @param  trust_anchor                  A buffer to hold the trust_anchor which is used to validate the peer certificate, if not NULL.
  @param  trust_anchor_size             A buffer to hold the trust_anchor_size, if not NULL.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status libspdm_get_certificate_ex(IN void *context, IN uint8_t slot_id,
                   IN OUT uintn *cert_chain_size,
                   OUT void *cert_chain,
                   OUT void **trust_anchor,
                   OUT uintn *trust_anchor_size)
{
    return libspdm_get_certificate_choose_length_ex(context, slot_id,
                          LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN,
                          cert_chain_size, cert_chain,
                          trust_anchor, trust_anchor_size);
}

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  length                       length parameter in the get_certificate message (limited by LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN).
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status libspdm_get_certificate_choose_length(IN void *context,
                         IN uint8_t slot_id,
                         IN uint16_t length,
                         IN OUT uintn *cert_chain_size,
                         OUT void *cert_chain)
{
    spdm_context_t *spdm_context;
    uintn retry;
    return_status status;

    spdm_context = context;
    retry = spdm_context->retry_times;
    do {
        status = try_spdm_get_certificate(spdm_context, slot_id, length,
                          cert_chain_size, cert_chain, NULL, NULL);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  root_hash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  length                       length parameter in the get_certificate message (limited by LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN).
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.
  @param  trust_anchor                  A buffer to hold the trust_anchor which is used to validate the peer certificate, if not NULL.
  @param  trust_anchor_size             A buffer to hold the trust_anchor_size, if not NULL.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status libspdm_get_certificate_choose_length_ex(IN void *context,
                         IN uint8_t slot_id,
                         IN uint16_t length,
                         IN OUT uintn *cert_chain_size,
                         OUT void *cert_chain,
                         OUT void **trust_anchor,
                         OUT uintn *trust_anchor_size)
{
    spdm_context_t *spdm_context;
    uintn retry;
    return_status status;

    spdm_context = context;
    retry = spdm_context->retry_times;
    do {
        status = try_spdm_get_certificate(spdm_context, slot_id, length,
                          cert_chain_size, cert_chain, trust_anchor, trust_anchor_size);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
