/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

libspdm_return_t libspdm_validate_supported_slot_mask(libspdm_context_t *spdm_context)
{
    uint8_t index;
    uint8_t supported_slot_mask;
    bool support_slot_mask_version;

    /* SupportedSlotMask is only emitted for SPDM 1.3 and later. If the responder is not
     * provisioned to support any such version there is nothing to validate. */
    support_slot_mask_version = false;
    for (index = 0; index < spdm_context->local_context.version.spdm_version_count; index++) {
        if (libspdm_get_version_from_version_number(
                spdm_context->local_context.version.spdm_version[index]) >=
            SPDM_MESSAGE_VERSION_13) {
            support_slot_mask_version = true;
            break;
        }
    }
    if (!support_slot_mask_version) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    supported_slot_mask = spdm_context->local_context.local_supported_slot_mask;

    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context.local_cert_chain_provision[index] == NULL) {
            continue;
        }
        /* A populated slot must be indicated as supported (SupportedSlotMask covers
         * ProvisionedSlotMask). */
        if ((supported_slot_mask & (1 << index)) == 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_supported_slot_mask - slot %d populated but not in "
                           "SupportedSlotMask 0x%02x\n", index, supported_slot_mask));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_validate_multi_key_slot_info(libspdm_context_t *spdm_context)
{
    uint8_t index;
    spdm_certificate_info_t cert_info;
    spdm_key_usage_bit_mask_t key_usage_bit_mask;

    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context.local_cert_chain_provision[index] == NULL) {
            continue;
        }
        cert_info = spdm_context->local_context.local_cert_info[index];
        key_usage_bit_mask = spdm_context->local_context.local_key_usage_bit_mask[index];

        /* CertModel validity (Table 42). CertificateInfo reserved bits shall be zero. */
        if ((cert_info & (uint8_t)(~SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK)) != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_multi_key_slot_info - slot %d CertificateInfo 0x%02x "
                           "has reserved bits set\n", index, cert_info));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        /* CertModel value shall be a defined model (not a reserved value). */
        if ((cert_info & SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK) >
            SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_multi_key_slot_info - slot %d CertModel %d is "
                           "reserved\n", index, cert_info & SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        /* A populated slot in a multi-key connection is in the "exists with key and cert" state,
         * so its CertModel shall be non-zero. */
        if ((cert_info & SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK) ==
            SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_multi_key_slot_info - slot %d populated but CertModel "
                           "is zero\n", index));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        /* The GenericCert model applies only to slots greater than 0. */
        if (((cert_info & SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK) ==
             SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT) && (index == 0)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_multi_key_slot_info - slot 0 must not use the "
                           "GenericCert model\n"));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        /* The AliasCert model is forbidden unless ALIAS_CERT_CAP is set (Table 15). */
        if (((cert_info & SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK) ==
             SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT) &&
            !libspdm_is_capabilities_flag_supported(
                spdm_context, false, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_multi_key_slot_info - slot %d uses the AliasCert "
                           "model but ALIAS_CERT_CAP is not set\n", index));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        /* KeyUsageMask validity (Table 43). Reserved bits shall be zero. */
        if ((key_usage_bit_mask & (uint16_t)(~SPDM_KEY_USAGE_BIT_MASK)) != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_multi_key_slot_info - slot %d KeyUsageMask 0x%04x has "
                           "reserved bits set\n", index, key_usage_bit_mask));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        /* Slot 0 shall set at least one of KeyExUse, ChallengeUse, MeasurementUse, or
         * EndpointInfoUse. */
        if ((index == 0) &&
            ((key_usage_bit_mask &
              (SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE |
               SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
               SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE |
               SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE)) == 0)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_validate_multi_key_slot_info - slot 0 KeyUsageMask 0x%04x sets "
                           "none of KeyEx/Challenge/Measurement/EndpointInfo use\n",
                           key_usage_bit_mask));
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
        /* Cross-check the reported per-slot values against KEY_PAIR_INFO: the slot's key pair must
         * claim this slot in its AssocCertSlotMask, the reported KeyUsageMask must match the key
         * pair's CurrentKeyUsage, and CurrentKeyUsage shall be within KeyUsageCapabilities. */
        if (spdm_context->local_context.local_key_pair_id[index] != 0) {
            uint8_t key_pair_id;
            uint8_t total_key_pairs;
            uint16_t capabilities;
            uint16_t key_usage_capabilities;
            uint16_t current_key_usage;
            uint32_t asym_algo_capabilities;
            uint32_t current_asym_algo;
            uint32_t pqc_asym_algo_capabilities;
            uint32_t current_pqc_asym_algo;
            uint8_t assoc_cert_slot_mask;
            bool kp_result;

            key_pair_id = spdm_context->local_context.local_key_pair_id[index];
            kp_result = libspdm_read_key_pair_info(
                spdm_context, key_pair_id, &total_key_pairs, &capabilities,
                &key_usage_capabilities, &current_key_usage, &asym_algo_capabilities,
                &current_asym_algo, &pqc_asym_algo_capabilities, &current_pqc_asym_algo,
                &assoc_cert_slot_mask, NULL, NULL);
            if (!kp_result) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "libspdm_validate_multi_key_slot_info - slot %d KeyPairID %d read "
                               "failed\n", index, key_pair_id));
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            if ((assoc_cert_slot_mask & (1 << index)) == 0) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "libspdm_validate_multi_key_slot_info - slot %d KeyPairID %d does "
                               "not claim this slot in AssocCertSlotMask 0x%02x\n",
                               index, key_pair_id, assoc_cert_slot_mask));
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            if (key_usage_bit_mask != current_key_usage) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "libspdm_validate_multi_key_slot_info - slot %d KeyUsageMask 0x%04x "
                               "does not match KeyPairID %d CurrentKeyUsage 0x%04x\n",
                               index, key_usage_bit_mask, key_pair_id, current_key_usage));
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            /* CurrentKeyUsage shall be a subset of KeyUsageCapabilities (Table 111). */
            if ((current_key_usage & (uint16_t)(~key_usage_capabilities)) != 0) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "libspdm_validate_multi_key_slot_info - slot %d KeyUsageMask 0x%04x "
                               "exceeds KeyPairID %d KeyUsageCapabilities 0x%04x\n",
                               index, key_usage_bit_mask, key_pair_id, key_usage_capabilities));
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
        }
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_get_response_digests(libspdm_context_t *spdm_context, size_t request_size,
                                              const void *request,
                                              size_t *response_size,
                                              void *response)
{
    const spdm_get_digest_request_t *spdm_request;
    spdm_digest_response_t *spdm_response;
    size_t index;
    bool no_local_cert_chain;
    uint32_t hash_size;
    uint8_t *digest;
    libspdm_return_t status;
    bool result;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    /*total populated slot count*/
    uint8_t slot_count;
    /*populated slot index*/
    uint8_t slot_index;
    size_t additional_size;
    spdm_key_pair_id_t *key_pair_id;
    spdm_certificate_info_t *cert_info;
    spdm_key_usage_bit_mask_t *key_usage_bit_mask;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_DIGESTS);

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_DIGESTS, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }
    session_info = NULL;
    if (spdm_context->last_spdm_request_session_id_valid) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context,
            spdm_context->last_spdm_request_session_id);
        if (session_info == NULL) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    }

    if (request_size < sizeof(spdm_get_digest_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_context->local_context.cert_slot_reset_mask != 0) {
        LIBSPDM_ASSERT(spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    no_local_cert_chain = true;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context
            .local_cert_chain_provision[index] != NULL) {
            no_local_cert_chain = false;
        }
    }
    if (no_local_cert_chain) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }

    /* The reported per-slot values are provisioned by the integrator; verify they are internally
     * consistent before emitting them. A failure here is a local misconfiguration. */
    status = libspdm_validate_supported_slot_mask(spdm_context);
    LIBSPDM_ASSERT(!LIBSPDM_STATUS_IS_ERROR(status));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
    }
    /* The per-slot KeyPairID, CertificateInfo and KeyUsageMask fields are only emitted for a
     * multi-key connection, so there is nothing to validate otherwise. */
    if (spdm_context->connection_info.multi_key_conn_rsp) {
        status = libspdm_validate_multi_key_slot_info(spdm_context);
        LIBSPDM_ASSERT(!LIBSPDM_STATUS_IS_ERROR(status));
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED, 0, response_size, response);
        }
    }

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    slot_count = libspdm_get_cert_slot_count(spdm_context);
    additional_size = 0;
    if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        spdm_context->connection_info.multi_key_conn_rsp) {
        additional_size = sizeof(spdm_key_pair_id_t) + sizeof(spdm_certificate_info_t) +
                          sizeof(spdm_key_usage_bit_mask_t);
    }
    LIBSPDM_ASSERT(*response_size >=
                   sizeof(spdm_digest_response_t) + (hash_size + additional_size) * slot_count);
    *response_size = sizeof(spdm_digest_response_t) + (hash_size + additional_size) * slot_count;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_DIGESTS;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        spdm_response->header.param1 = spdm_context->local_context.local_supported_slot_mask;
    }

    digest = (void *)(spdm_response + 1);
    key_pair_id = (spdm_key_pair_id_t *)((uint8_t *)digest + hash_size * slot_count);
    cert_info = (spdm_certificate_info_t *)((uint8_t *)key_pair_id +
                                            sizeof(spdm_key_pair_id_t) * slot_count);
    key_usage_bit_mask = (spdm_key_usage_bit_mask_t *)((uint8_t *)cert_info +
                                                       sizeof(spdm_certificate_info_t) *
                                                       slot_count);

    slot_index = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context
            .local_cert_chain_provision[index] != NULL) {
            spdm_response->header.param2 |= (1 << index);
            result = libspdm_generate_cert_chain_hash(spdm_context, index,
                                                      &digest[hash_size * slot_index]);
            if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
                spdm_context->connection_info.multi_key_conn_rsp) {
                key_pair_id[slot_index] = spdm_context->local_context.local_key_pair_id[index];
                cert_info[slot_index] = spdm_context->local_context.local_cert_info[index];
                key_usage_bit_mask[slot_index] =
                    spdm_context->local_context.local_key_usage_bit_mask[index];
            }
            slot_index++;
            if (!result) {
                return libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                    0, response_size, response);
            }
        }
    }

    if (session_info == NULL) {
        /* Log to transcript. */
        const size_t spdm_request_size = sizeof(spdm_get_digest_request_t);

        status = libspdm_append_message_b(spdm_context, spdm_request, spdm_request_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }

        status = libspdm_append_message_b(spdm_context, spdm_response, *response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }

        if (spdm_context->connection_info.multi_key_conn_rsp) {
            status = libspdm_append_message_d(spdm_context, spdm_response, *response_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                       response_size, response);
            }
        }
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS) {
        libspdm_set_connection_state(spdm_context,
                                     LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
