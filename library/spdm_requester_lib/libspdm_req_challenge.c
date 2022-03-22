/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t cert_chain_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t nonce[SPDM_NONCE_SIZE];
    uint8_t measurement_summary_hash[LIBSPDM_MAX_HASH_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
} libspdm_challenge_auth_response_max_t;

#pragma pack()

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

/**
 * This function sends CHALLENGE
 * to authenticate the device based upon the key in one slot.
 *
 * This function verifies the signature in the challenge auth.
 *
 * If basic mutual authentication is requested from the responder,
 * this function also perform the basic mutual authentication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_id                      The number of slot for the challenge.
 * @param  measurement_hash_type          The type of the measurement hash.
 * @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.
 * @param  slot_mask                     A pointer to a destination to store the slot mask.
 * @param  requester_nonce_in            A buffer to hold the requester nonce (32 bytes) as input, if not NULL.
 * @param  requester_nonce               A buffer to hold the requester nonce (32 bytes), if not NULL.
 * @param  responder_nonce               A buffer to hold the responder nonce (32 bytes), if not NULL.
 *
 * @retval RETURN_SUCCESS               The challenge auth is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_try_challenge(void *context, uint8_t slot_id,
                                    uint8_t measurement_hash_type,
                                    void *measurement_hash,
                                    uint8_t *slot_mask,
                                    const void *requester_nonce_in,
                                    void *requester_nonce,
                                    void *responder_nonce)
{
    return_status status;
    bool result;
    spdm_challenge_request_t *spdm_request;
    size_t spdm_request_size;
    libspdm_challenge_auth_response_max_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *ptr;
    void *cert_chain_hash;
    size_t hash_size;
    size_t measurement_summary_hash_size;
    void *nonce;
    void *measurement_summary_hash;
    uint16_t opaque_length;
    void *opaque;
    void *signature;
    size_t signature_size;
    libspdm_context_t *spdm_context;
    uint8_t auth_attribute;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;

    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xff));

    spdm_context = context;
    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  SPDM_CHALLENGE);
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        return RETURN_UNSUPPORTED;
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return RETURN_UNSUPPORTED;
    }

    if ((slot_id == 0xFF) &&
        (spdm_context->local_context.peer_cert_chain_provision_size == 0)) {
        return RETURN_INVALID_PARAMETER;
    }

    spdm_context->error_state = LIBSPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

    transport_header_size = spdm_context->transport_get_header_size(spdm_context);
    libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size;

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_CHALLENGE;
    spdm_request->header.param1 = slot_id;
    spdm_request->header.param2 = measurement_hash_type;
    spdm_request_size = sizeof(spdm_challenge_request_t);
    if (requester_nonce_in == NULL) {
        if(!libspdm_get_random_number(SPDM_NONCE_SIZE, spdm_request->nonce)) {
            libspdm_release_sender_buffer (spdm_context);
            return RETURN_DEVICE_ERROR;
        }
    } else {
        libspdm_copy_mem(spdm_request->nonce, sizeof(spdm_request->nonce),
                         requester_nonce_in, SPDM_NONCE_SIZE);
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ClientNonce - "));
    libspdm_internal_dump_data(spdm_request->nonce, SPDM_NONCE_SIZE);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (requester_nonce != NULL) {
        libspdm_copy_mem(requester_nonce, SPDM_NONCE_SIZE,
                         spdm_request->nonce, SPDM_NONCE_SIZE);
    }

    status = libspdm_send_spdm_request(spdm_context, NULL,
                                       spdm_request_size, spdm_request);
    if (RETURN_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* receive */

    libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(
        spdm_context, NULL, &spdm_response_size, (void **)&spdm_response);
    if (RETURN_ERROR(status)) {
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, NULL,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_CHALLENGE, SPDM_CHALLENGE_AUTH,
            sizeof(libspdm_challenge_auth_response_max_t));
        if (RETURN_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_CHALLENGE_AUTH) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_challenge_auth_response_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }
    auth_attribute = spdm_response->header.param1;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11 && slot_id == 0xFF) {
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) != 0xF) {
            status = RETURN_DEVICE_ERROR;
            goto receive_done;
        }
        if (spdm_response->header.param2 != 0) {
            status = RETURN_DEVICE_ERROR;
            goto receive_done;
        }
    } else {
        if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11 &&
             (auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) != slot_id) ||
            (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_10 &&
             auth_attribute != slot_id)) {
            status = RETURN_DEVICE_ERROR;
            goto receive_done;
        }
        if ((spdm_response->header.param2 & (1 << slot_id)) == 0) {
            status = RETURN_DEVICE_ERROR;
            goto receive_done;
        }
    }
    if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) != 0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
            status = RETURN_DEVICE_ERROR;
            goto receive_done;
        }
    }
    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, true, measurement_hash_type);

    if (spdm_response_size <= sizeof(spdm_challenge_auth_response_t) +
        hash_size + SPDM_NONCE_SIZE +
        measurement_summary_hash_size +
        sizeof(uint16_t)) {
        status = RETURN_DEVICE_ERROR;
        goto receive_done;
    }

    ptr = spdm_response->cert_chain_hash;

    cert_chain_hash = ptr;
    ptr += hash_size;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "cert_chain_hash (0x%x) - ", hash_size));
    libspdm_internal_dump_data(cert_chain_hash, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    result = libspdm_verify_certificate_chain_hash(spdm_context,
                                                   cert_chain_hash, hash_size);
    if (!result) {
        spdm_context->error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }

    nonce = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "nonce (0x%x) - ", SPDM_NONCE_SIZE));
    libspdm_internal_dump_data(nonce, SPDM_NONCE_SIZE);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    ptr += SPDM_NONCE_SIZE;
    if (responder_nonce != NULL) {
        libspdm_copy_mem(responder_nonce, SPDM_NONCE_SIZE, nonce, SPDM_NONCE_SIZE);
    }

    measurement_summary_hash = ptr;
    ptr += measurement_summary_hash_size;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "measurement_summary_hash (0x%x) - ",
                   measurement_summary_hash_size));
    libspdm_internal_dump_data(measurement_summary_hash,
                               measurement_summary_hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    opaque_length = *(uint16_t *)ptr;
    if (opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }
    ptr += sizeof(uint16_t);

    /* Cache data*/

    status = libspdm_append_message_c(spdm_context, spdm_request,
                                      spdm_request_size);
    if (RETURN_ERROR(status)) {
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }
    if (spdm_response_size <
        sizeof(spdm_challenge_auth_response_t) + hash_size +
        SPDM_NONCE_SIZE + measurement_summary_hash_size +
        sizeof(uint16_t) + opaque_length + signature_size) {
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }
    spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                         hash_size + SPDM_NONCE_SIZE +
                         measurement_summary_hash_size + sizeof(uint16_t) +
                         opaque_length + signature_size;
    status = libspdm_append_message_c(spdm_context, spdm_response,
                                      spdm_response_size - signature_size);
    if (RETURN_ERROR(status)) {
        libspdm_reset_message_c(spdm_context);
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }

    opaque = ptr;
    ptr += opaque_length;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "opaque (0x%x):\n", opaque_length));
    libspdm_internal_dump_hex(opaque, opaque_length);

    signature = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature (0x%x):\n", signature_size));
    libspdm_internal_dump_hex(signature, signature_size);
    result = libspdm_verify_challenge_auth_signature(
        spdm_context, true, signature, signature_size);
    if (!result) {
        libspdm_reset_message_c(spdm_context);
        spdm_context->error_state =
            LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
        status = RETURN_SECURITY_VIOLATION;
        goto receive_done;
    }

    spdm_context->error_state = LIBSPDM_STATUS_SUCCESS;

    if (measurement_hash != NULL) {
        libspdm_copy_mem(measurement_hash, measurement_summary_hash_size,
                         measurement_summary_hash, measurement_summary_hash_size);
    }
    if (slot_mask != NULL) {
        *slot_mask = spdm_response->header.param2;
    }

    if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) != 0) {
        /* we must release it here, because libspdm_encapsulated_request() will acquire again. */
        libspdm_release_receiver_buffer (spdm_context);

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "BasicMutAuth :\n"));
        status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_challenge - libspdm_encapsulated_request - %p\n",
                       status));
        if (RETURN_ERROR(status)) {
            libspdm_reset_message_c(spdm_context);
            spdm_context->error_state =
                LIBSPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
            return RETURN_SECURITY_VIOLATION;
        }
        spdm_context->connection_info.connection_state =
            LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
        return RETURN_SUCCESS;
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    status = RETURN_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

/**
 * This function sends CHALLENGE
 * to authenticate the device based upon the key in one slot.
 *
 * This function verifies the signature in the challenge auth.
 *
 * If basic mutual authentication is requested from the responder,
 * this function also perform the basic mutual authentication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_id                      The number of slot for the challenge.
 * @param  measurement_hash_type          The type of the measurement hash.
 * @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.
 * @param  slot_mask                     A pointer to a destination to store the slot mask.
 *
 * @retval RETURN_SUCCESS               The challenge auth is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_challenge(void *context, uint8_t slot_id,
                                uint8_t measurement_hash_type,
                                void *measurement_hash,
                                uint8_t *slot_mask)
{
    libspdm_context_t *spdm_context;
    size_t retry;
    return_status status;

    spdm_context = context;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_challenge(spdm_context, slot_id,
                                       measurement_hash_type,
                                       measurement_hash, slot_mask, NULL, NULL, NULL);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

/**
 * This function sends CHALLENGE
 * to authenticate the device based upon the key in one slot.
 *
 * This function verifies the signature in the challenge auth.
 *
 * If basic mutual authentication is requested from the responder,
 * this function also perform the basic mutual authentication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_id                      The number of slot for the challenge.
 * @param  measurement_hash_type          The type of the measurement hash.
 * @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.
 * @param  slot_mask                     A pointer to a destination to store the slot mask.
 * @param  requester_nonce_in            A buffer to hold the requester nonce (32 bytes) as input, if not NULL.
 * @param  requester_nonce               A buffer to hold the requester nonce (32 bytes), if not NULL.
 * @param  responder_nonce               A buffer to hold the responder nonce (32 bytes), if not NULL.
 *
 * @retval RETURN_SUCCESS               The challenge auth is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
return_status libspdm_challenge_ex(void *context, uint8_t slot_id,
                                   uint8_t measurement_hash_type,
                                   void *measurement_hash,
                                   uint8_t *slot_mask,
                                   const void *requester_nonce_in,
                                   void *requester_nonce,
                                   void *responder_nonce)
{
    libspdm_context_t *spdm_context;
    size_t retry;
    return_status status;

    spdm_context = context;
    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_challenge(spdm_context, slot_id,
                                       measurement_hash_type,
                                       measurement_hash,
                                       slot_mask,
                                       requester_nonce_in,
                                       requester_nonce, responder_nonce);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
