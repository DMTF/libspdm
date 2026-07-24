/**
 *  Copyright Notice:
 *  Copyright 2024-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

libspdm_return_t libspdm_get_response_set_key_pair_info_ack(libspdm_context_t *spdm_context,
                                                            size_t request_size,
                                                            const void *request,
                                                            size_t *response_size,
                                                            void *response)
{
    const spdm_set_key_pair_info_request_t *spdm_request;
    spdm_set_key_pair_info_ack_response_t *spdm_response;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint8_t assoc_cert_slot_mask;
    uint8_t key_pair_id;
    uint8_t total_key_pairs;
    bool result;

    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;
    uint8_t desired_pqc_asym_algo_len;
    uint32_t desired_pqc_asym_algo;
    uint8_t operation;
    bool need_reset;
    const uint8_t *ptr;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_SET_KEY_PAIR_INFO);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_SET_KEY_PAIR_INFO,
                                               response_size, response);
    }

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(spdm_context,
                                                       spdm_request->header.request_response_code,
                                                       response_size, response);
    }

    if (request_size < sizeof(spdm_set_key_pair_info_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

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

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_SET_KEY_PAIR_INFO, response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_set_key_pair_info_ack_response_t));

    libspdm_zero_mem(response, *response_size);

    total_key_pairs = 0;
    key_pair_id = spdm_request->key_pair_id;
    result = libspdm_read_key_pair_info(
        spdm_context,
        key_pair_id,
        &total_key_pairs,
        &capabilities,
        &key_usage_capabilities,
        &current_key_usage,
        &asym_algo_capabilities,
        &current_asym_algo,
        &pqc_asym_algo_capabilities,
        &current_pqc_asym_algo,
        &assoc_cert_slot_mask,
        NULL, NULL);
    if ((key_pair_id == 0) || (key_pair_id > total_key_pairs)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    operation = spdm_request->header.param1;

    /* Validate the Operation value up front, before parsing the operation-specific fields. */
    if (operation > SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (operation != SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
        if (request_size < sizeof(spdm_set_key_pair_info_request_t) +
            sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }

        ptr = (const uint8_t*)(spdm_request + 1);
        ptr += sizeof(uint8_t);

        desired_key_usage = libspdm_read_uint16((const uint8_t *)ptr);
        ptr += sizeof(uint16_t);

        desired_asym_algo = libspdm_read_uint32((const uint8_t *)ptr);
        ptr += sizeof(uint32_t);

        desired_assoc_cert_slot_mask = *ptr;
        ptr += sizeof(uint8_t);

        desired_pqc_asym_algo = 0;
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            if (request_size < sizeof(spdm_set_key_pair_info_request_t) +
                sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                sizeof(uint8_t)) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                       response_size, response);
            }

            desired_pqc_asym_algo_len = *ptr;
            ptr += sizeof(uint8_t);

            if (request_size < sizeof(spdm_set_key_pair_info_request_t) +
                sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                sizeof(uint8_t) + desired_pqc_asym_algo_len) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                       response_size, response);
            }

            if (desired_pqc_asym_algo_len > sizeof(uint32_t)) {
                desired_pqc_asym_algo_len = sizeof(uint32_t);
            }
            libspdm_copy_mem (&desired_pqc_asym_algo, sizeof(desired_pqc_asym_algo),
                              ptr, desired_pqc_asym_algo_len);
            ptr += desired_pqc_asym_algo_len;
        }

    } else {
        desired_key_usage = 0;
        desired_asym_algo = 0;
        desired_pqc_asym_algo = 0;
        desired_assoc_cert_slot_mask = 0;
    }

    if (((capabilities & SPDM_KEY_PAIR_CAP_GEN_KEY_CAP) == 0) &&
        (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (((capabilities & SPDM_KEY_PAIR_CAP_ERASABLE_CAP) == 0) &&
        (operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (((capabilities & SPDM_KEY_PAIR_CAP_CERT_ASSOC_CAP) == 0) &&
        (desired_assoc_cert_slot_mask != 0) &&
        (desired_assoc_cert_slot_mask != assoc_cert_slot_mask)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (((capabilities & SPDM_KEY_PAIR_CAP_KEY_USAGE_CAP) == 0) && (desired_key_usage != 0)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((desired_key_usage != 0) &&
        ((key_usage_capabilities | desired_key_usage) != key_usage_capabilities)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (((capabilities & SPDM_KEY_PAIR_CAP_ASYM_ALGO_CAP) == 0) &&
        ((desired_asym_algo != 0) || (desired_pqc_asym_algo != 0))) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (!libspdm_onehot0(desired_asym_algo) || !libspdm_onehot0(desired_pqc_asym_algo)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((desired_asym_algo != 0) && (desired_pqc_asym_algo != 0)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((desired_asym_algo != 0) &&
        ((asym_algo_capabilities | desired_asym_algo) != asym_algo_capabilities)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((desired_pqc_asym_algo != 0) &&
        ((pqc_asym_algo_capabilities | desired_pqc_asym_algo) != pqc_asym_algo_capabilities)) {
        /* Per DSP0274 Table 115, the Requester shall only select from bits set in the
         * capabilities. A DesiredPqcAsymAlgo outside PqcAsymAlgoCapabilities is the same class
         * of malformed request as the DesiredAsymAlgo case above, so use InvalidRequest for
         * both. */
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (((capabilities & SPDM_KEY_PAIR_CAP_SHAREABLE_CAP) == 0) &&
        (!libspdm_onehot0(desired_assoc_cert_slot_mask))) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if ((operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) ||
        (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION)) {
        if (assoc_cert_slot_mask != 0) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                                                   response_size, response);
        }
    }

    /* Per DSP0274, a request for key generation (GenerateKeyPair) when no asymmetric algorithm
     * has been selected yet should be answered with ERROR(OperationFailed). The algorithm is
     * selected either by this request (DesiredAsymAlgo/DesiredPqcAsymAlgo) or already configured
     * for the key pair (CurrentAsymAlgo/CurrentPqcAsymAlgo). */
    if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
        if ((desired_asym_algo == 0) && (desired_pqc_asym_algo == 0) &&
            (current_asym_algo == 0) && (current_pqc_asym_algo == 0)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                                                   response_size, response);
        }
    }

    /* Per DSP0274, the value of a key pair is bound to its selected asymmetric algorithm
     * (CurrentAsymAlgo). Once a key pair is generated for a KeyPairID, a ParameterChange that
     * would change the algorithm of the generated key pair shall be rejected with
     * InvalidRequest. A key pair is considered generated here when an algorithm is already
     * configured (CurrentAsymAlgo or CurrentPqcAsymAlgo is set). A desired algorithm of 0 means
     * "do not change", so only a non-zero desired algorithm that differs from the current one is
     * rejected. */
    if (operation == SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION) {
        if (((current_asym_algo != 0) || (current_pqc_asym_algo != 0)) &&
            (((desired_asym_algo != 0) && (desired_asym_algo != current_asym_algo)) ||
             ((desired_pqc_asym_algo != 0) && (desired_pqc_asym_algo != current_pqc_asym_algo)))) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    /* Within one connection a certificate slot resolves to a single KeyPairID for the negotiated
     * algorithm: DIGESTS returns exactly one KeyPairID per slot. Two different KeyPairIDs of the
     * SAME asymmetric algorithm must therefore not both be associated with the same slot, otherwise
     * that slot's KeyPairID would be ambiguous. Reject a request that would associate a slot which
     * a different, same-algorithm KeyPairID already owns.
     *
     * DSP0274 does not define an error code for this conflict; OperationFailed is used here as a
     * libspdm policy, consistent with the other association-conflict cases in the SET_KEY_PAIR_INFO
     * error-handling clause. A slot shared across DIFFERENT algorithms is allowed (only one such
     * key pair is active per connection), so the algorithm is part of the match. */
    if (desired_assoc_cert_slot_mask != 0) {
        uint32_t effective_asym_algo =
            (desired_asym_algo != 0) ? desired_asym_algo : current_asym_algo;
        uint32_t effective_pqc_asym_algo =
            (desired_pqc_asym_algo != 0) ? desired_pqc_asym_algo : current_pqc_asym_algo;

        if ((effective_asym_algo != 0) || (effective_pqc_asym_algo != 0)) {
            uint8_t other_key_pair_id;

            for (other_key_pair_id = 1; other_key_pair_id <= total_key_pairs;
                 other_key_pair_id++) {
                uint16_t other_capabilities;
                uint16_t other_key_usage_capabilities;
                uint16_t other_current_key_usage;
                uint32_t other_asym_algo_capabilities;
                uint32_t other_current_asym_algo;
                uint32_t other_pqc_asym_algo_capabilities;
                uint32_t other_current_pqc_asym_algo;
                uint8_t other_assoc_cert_slot_mask;

                if (other_key_pair_id == key_pair_id) {
                    continue;
                }
                if (!libspdm_read_key_pair_info(
                        spdm_context, other_key_pair_id, &total_key_pairs, &other_capabilities,
                        &other_key_usage_capabilities, &other_current_key_usage,
                        &other_asym_algo_capabilities, &other_current_asym_algo,
                        &other_pqc_asym_algo_capabilities, &other_current_pqc_asym_algo,
                        &other_assoc_cert_slot_mask, NULL, NULL)) {
                    continue;
                }
                if ((other_current_asym_algo == effective_asym_algo) &&
                    (other_current_pqc_asym_algo == effective_pqc_asym_algo) &&
                    ((other_assoc_cert_slot_mask & desired_assoc_cert_slot_mask) != 0)) {
                    return libspdm_generate_error_response(
                        spdm_context, SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                        response_size, response);
                }
            }
        }
    }

    if (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_14) {
        need_reset = libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_RESET_CAP);
    } else {
        need_reset = false;
    }
    result = libspdm_write_key_pair_info(
        spdm_context,
        key_pair_id,
        operation,
        desired_key_usage,
        desired_asym_algo,
        desired_pqc_asym_algo,
        desired_assoc_cert_slot_mask,
        &need_reset);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_OPERATION_FAILED, 0,
                                               response_size, response);
    }

    spdm_response = response;
    *response_size = sizeof(spdm_set_key_pair_info_ack_response_t);

    if (need_reset) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, 0,
                                               response_size, response);
    } else {
        /* Update context with new key pair information if a reset is not needed. */
        uint8_t old_assoc_cert_slot_mask = assoc_cert_slot_mask;
        uint8_t new_assoc_cert_slot_mask;
        uint16_t new_current_key_usage;
        uint8_t slot_index;

        if (operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
            new_current_key_usage = 0;
            new_assoc_cert_slot_mask = 0;
        } else if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
            new_current_key_usage = desired_key_usage;
            new_assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        } else {
            /* SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION */
            new_current_key_usage =
                (desired_key_usage != 0) ? desired_key_usage : current_key_usage;
            new_assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        }

        for (slot_index = 0; slot_index < SPDM_MAX_SLOT_COUNT; slot_index++) {
            if ((new_assoc_cert_slot_mask & (1 << slot_index)) != 0) {
                /* Slot is (still) associated with this KeyPairID. */
                spdm_context->local_context.local_key_pair_id[slot_index] = key_pair_id;
                spdm_context->local_context.local_key_usage_bit_mask[slot_index] =
                    new_current_key_usage;
            } else if (((old_assoc_cert_slot_mask & (1 << slot_index)) != 0) &&
                       (spdm_context->local_context.local_key_pair_id[slot_index] == key_pair_id)) {
                /* Slot was associated with this KeyPairID and has now been removed. */
                spdm_context->local_context.local_key_pair_id[slot_index] = 0;
                spdm_context->local_context.local_key_usage_bit_mask[slot_index] = 0;
            }
        }

        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_SET_KEY_PAIR_INFO_ACK;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP*/
