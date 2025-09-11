/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include <stddef.h>

/**
 * This function checks the compatibility of the received SPDM version,
 * if received version is valid, subsequent spdm communication will follow this version.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  version       The SPDM message version.
 *
 *
 * @retval true   The received SPDM version is valid.
 * @retval false  The received SPDM version is invalid.
 **/
static bool libspdm_check_request_version_compatibility(libspdm_context_t *spdm_context,
                                                        uint8_t version)
{
    uint8_t local_ver;
    size_t index;

    for (index = 0; index < spdm_context->local_context.version.spdm_version_count; index++) {
        local_ver = libspdm_get_version_from_version_number(
            spdm_context->local_context.version.spdm_version[index]);
        if (local_ver == version) {
            spdm_context->connection_info.version = version << SPDM_VERSION_NUMBER_SHIFT_BIT;
            return true;
        }
    }
    return false;
}

/**
 * This function checks the compatibility of the received GET_CAPABILITES flag.
 * Some flags are mutually inclusive/exclusive.
 *
 * @param  capabilities_flag  The received CAPABILITIES Flag.
 * @param  version            The SPDM message version.
 *
 *
 * @retval true   The received Capabilities flag is valid.
 * @retval false  The received Capabilities flag is invalid.
 **/
static bool libspdm_check_request_flag_compatibility(uint32_t capabilities_flag, uint8_t version)
{
    const uint8_t cert_cap = (uint8_t)(capabilities_flag >> 1) & 0x01;
    const uint8_t chal_cap = (uint8_t)(capabilities_flag >> 2) & 0x01;
    const uint8_t encrypt_cap = (uint8_t)(capabilities_flag >> 6) & 0x01;
    const uint8_t mac_cap = (uint8_t)(capabilities_flag >> 7) & 0x01;
    const uint8_t mut_auth_cap = (uint8_t)(capabilities_flag >> 8) & 0x01;
    const uint8_t key_ex_cap = (uint8_t)(capabilities_flag >> 9) & 0x01;
    const uint8_t psk_cap = (uint8_t)(capabilities_flag >> 10) & 0x03;
    const uint8_t encap_cap = (uint8_t)(capabilities_flag >> 12) & 0x01;
    const uint8_t hbeat_cap = (uint8_t)(capabilities_flag >> 13) & 0x01;
    const uint8_t key_upd_cap = (uint8_t)(capabilities_flag >> 14) & 0x01;
    const uint8_t handshake_in_the_clear_cap = (uint8_t)(capabilities_flag >> 15) & 0x01;
    const uint8_t pub_key_id_cap = (uint8_t)(capabilities_flag >> 16) & 0x01;
    const uint8_t ep_info_cap = (uint8_t)(capabilities_flag >> 22) & 0x03;
    const uint8_t event_cap = (uint8_t)(capabilities_flag >> 25) & 0x01;
    const uint8_t multi_key_cap = (uint8_t)(capabilities_flag >> 26) & 0x03;

    /* Checks common to 1.1 and higher */
    if (version >= SPDM_MESSAGE_VERSION_11) {
        /* Illegal to return reserved values. */
        if ((psk_cap == 2) || (psk_cap == 3)) {
            return false;
        }

        /* Checks that originate from key exchange capabilities. */
        if ((key_ex_cap == 1) || (psk_cap != 0)) {
            if ((mac_cap == 0) && (encrypt_cap == 0)) {
                return false;
            }
        } else {
            if ((mac_cap == 1) || (encrypt_cap == 1) || (handshake_in_the_clear_cap == 1) ||
                (hbeat_cap == 1) || (key_upd_cap == 1)) {
                return false;
            }
            if (version >= SPDM_MESSAGE_VERSION_13) {
                if (event_cap == 1) {
                    return false;
                }
            }
        }
        if ((key_ex_cap == 0) && (psk_cap == 1)) {
            if (handshake_in_the_clear_cap == 1) {
                return false;
            }
        }

        /* Checks that originate from certificate or public key capabilities. */
        if ((cert_cap == 1) || (pub_key_id_cap == 1)) {
            /* Certificate capabilities and public key capabilities cannot both be set. */
            if ((cert_cap == 1) && (pub_key_id_cap == 1)) {
                return false;
            }
            /* If certificates or public keys are enabled then at least one of these capabilities
             * must be enabled to use the key. */
            if ((chal_cap == 0) && (key_ex_cap == 0)) {
                if (version >= SPDM_MESSAGE_VERSION_13) {
                    if ((ep_info_cap == 0) || (ep_info_cap == 1)) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        } else {
            /* If certificates or public keys are not enabled then these capabilities
             * cannot be enabled. */
            if ((chal_cap == 1) || (mut_auth_cap == 1)) {
                return false;
            }
            if (version >= SPDM_MESSAGE_VERSION_13) {
                if (ep_info_cap == 2) {
                    return false;
                }
            }
        }

        /* Checks that originate from mutual authentication capabilities. */
        if (mut_auth_cap == 1) {
            /* Mutual authentication with asymmetric keys can only occur through the basic mutual
             * authentication flow (CHAL_CAP == 1) or the session-based mutual authentication flow
             * (KEY_EX_CAP == 1). */
            if ((key_ex_cap == 0) && (chal_cap == 0)) {
                return false;
            }
        }
    }

    /* Checks specific to 1.1. */
    if (version == SPDM_MESSAGE_VERSION_11) {
        if ((mut_auth_cap == 1) && (encap_cap == 0)) {
            return false;
        }
    }

    /* Checks specific to 1.3 and higher. */
    if (version >= SPDM_MESSAGE_VERSION_13) {
        /* Illegal to return reserved values. */
        if ((ep_info_cap == 3) || (multi_key_cap == 3)) {
            return false;
        }
        if ((multi_key_cap != 0) && ((pub_key_id_cap == 1) || (cert_cap == 0))) {
            return false;
        }
    }

    /* Checks that are deferred to when a message is received.
     *
     * If the Requester supports key exchange then MAC_CAP must be set. In addition, if the
     * negotiated SPDM version is greater than 1.1 then the negotiated opaque data format must be
     * OpaqueDataFmt1.
     */

    return true;
}

libspdm_return_t libspdm_get_response_capabilities(libspdm_context_t *spdm_context,
                                                   size_t request_size,
                                                   const void *request,
                                                   size_t *response_size,
                                                   void *response)
{
    const spdm_get_capabilities_request_t *spdm_request;
    spdm_capabilities_response_t *spdm_response;
    libspdm_return_t status;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_CAPABILITIES);

    /* -=[Verify State Phase]=- */
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context, spdm_request->header.request_response_code,  response_size, response);
    }
    if (spdm_context->connection_info.connection_state != LIBSPDM_CONNECTION_STATE_AFTER_VERSION) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (!libspdm_check_request_version_compatibility(
            spdm_context, spdm_request->header.spdm_version)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if (request_size < sizeof(spdm_get_capabilities_request_t)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        } else {
            request_size = sizeof(spdm_get_capabilities_request_t);
        }
    } else if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (request_size < sizeof(spdm_get_capabilities_request_t) -
            sizeof(spdm_request->data_transfer_size) - sizeof(spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        } else {
            request_size = sizeof(spdm_get_capabilities_request_t) -
                           sizeof(spdm_request->data_transfer_size) -
                           sizeof(spdm_request->max_spdm_msg_size);
        }
    } else {
        if (request_size < sizeof(spdm_message_header_t)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        } else {
            request_size = sizeof(spdm_message_header_t);
        }
    }
    if (!libspdm_check_request_flag_compatibility(
            spdm_request->flags, spdm_request->header.spdm_version)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if ((spdm_request->data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12) ||
            (spdm_request->data_transfer_size > spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
        if (((spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP) == 0) &&
            (spdm_request->data_transfer_size != spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (spdm_request->ct_exponent > LIBSPDM_MAX_CT_EXPONENT) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    /* Check that if Param1[0] is set, Requester must have CHUNK_CAP */
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13 &&
        (spdm_request->header.param1 & SPDM_GET_CAPABILITIES_REQUEST_PARAM1_SUPPORTED_ALGORITHMS) &&
        ((spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP) == 0)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST,
                                               0,
                                               response_size,
                                               response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    size_t required_size;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        required_size = sizeof(spdm_capabilities_response_t);
    } else {
        required_size = offsetof(spdm_capabilities_response_t, data_transfer_size);
    }

    uint32_t response_flags = libspdm_mask_capability_flags(
        spdm_context, false, spdm_context->local_context.capability.flags);

    bool supported_algs_requested =
        (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        ((spdm_request->header.param1 & SPDM_GET_CAPABILITIES_REQUEST_PARAM1_SUPPORTED_ALGORITHMS) != 0) &&
        ((spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP) != 0) &&
        ((response_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP) != 0);

    if (supported_algs_requested) {
        uint8_t table_count = 0;
        if (spdm_context->local_context.algorithm.dhe_named_group != 0) {
            table_count++;
        }
        if (spdm_context->local_context.algorithm.aead_cipher_suite != 0) {
            table_count++;
        }
        if (spdm_context->local_context.algorithm.req_base_asym_alg != 0) {
            table_count++;
        }
        if (spdm_context->local_context.algorithm.key_schedule != 0) {
            table_count++;
        }

        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            if (spdm_context->local_context.algorithm.req_pqc_asym_alg != 0) {
                table_count++;
            }
            if (spdm_context->local_context.algorithm.kem_alg != 0) {
                table_count++;
            }
        }

        required_size += sizeof(spdm_supported_algorithms_block_t) +
                         (table_count * sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    }

    LIBSPDM_ASSERT(*response_size >= required_size);
    *response_size = required_size;

    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CAPABILITIES;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->ct_exponent = spdm_context->local_context.capability.ct_exponent;
    spdm_response->flags = response_flags;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_response->data_transfer_size =
            spdm_context->local_context.capability.data_transfer_size;
        spdm_response->max_spdm_msg_size =
            spdm_context->local_context.capability.max_spdm_msg_size;
    }

    if (supported_algs_requested) {
        uint8_t index = 0;

        /* Allocate space for the supported_algorithms block at the end of the response */
        spdm_supported_algorithms_block_t *supported_algorithms =
            (spdm_supported_algorithms_block_t*)((uint8_t*)spdm_response + sizeof(spdm_capabilities_response_t));

        supported_algorithms->param2 = 0;
        supported_algorithms->length = sizeof(spdm_supported_algorithms_block_t);
        supported_algorithms->measurement_specification =
            spdm_context->local_context.algorithm.measurement_spec;
        supported_algorithms->other_params_support =
            spdm_context->local_context.algorithm.other_params_support;
        supported_algorithms->base_asym_algo=
            spdm_context->local_context.algorithm.base_asym_algo;
        supported_algorithms->base_hash_algo=
            spdm_context->local_context.algorithm.base_hash_algo;

        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            supported_algorithms->pqc_asym_algo =
                spdm_context->local_context.algorithm.pqc_asym_algo;
        } else {
            supported_algorithms->pqc_asym_algo = 0;
        }

        libspdm_zero_mem(supported_algorithms->reserved2, sizeof(supported_algorithms->reserved2));
        supported_algorithms->ext_asym_count = 0;
        supported_algorithms->ext_hash_count = 0;
        supported_algorithms->reserved3 = 0;
        supported_algorithms->mel_specification =
            spdm_context->local_context.algorithm.mel_spec;

        spdm_negotiate_algorithms_common_struct_table_t *struct_table =
            (spdm_negotiate_algorithms_common_struct_table_t*)(
                (uint8_t*)supported_algorithms +
                sizeof(spdm_supported_algorithms_block_t)
                );

        if (spdm_context->local_context.algorithm.dhe_named_group != 0) {
            struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
            struct_table[index].alg_count = 0x20;
            struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.dhe_named_group;
            index++;
        }

        if (spdm_context->local_context.algorithm.aead_cipher_suite != 0) {
            struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
            struct_table[index].alg_count = 0x20;
            struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.aead_cipher_suite;
            index++;
        }

        if (spdm_context->local_context.algorithm.req_base_asym_alg != 0) {
            struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
            struct_table[index].alg_count = 0x20;
            struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.req_base_asym_alg;
            index++;
        }

        if (spdm_context->local_context.algorithm.key_schedule != 0) {
            struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
            struct_table[index].alg_count = 0x20;
            struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.key_schedule;
            index++;
        }

        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            if (spdm_context->local_context.algorithm.req_pqc_asym_alg != 0) {
                struct_table[index].alg_type =
                    SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG;
                struct_table[index].alg_count = 0x20;
                struct_table[index].alg_supported =
                    (uint16_t)spdm_context->local_context.algorithm.req_pqc_asym_alg;
                index++;
            }
            if (spdm_context->local_context.algorithm.kem_alg != 0) {
                struct_table[index].alg_type =
                    SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG;
                struct_table[index].alg_count = 0x20;
                struct_table[index].alg_supported =
                    (uint16_t)spdm_context->local_context.algorithm.kem_alg;
                index++;
            }
        }

        supported_algorithms->param1 = index;
        supported_algorithms->length +=
            supported_algorithms->param1*
            sizeof(spdm_negotiate_algorithms_common_struct_table_t);

    } else if (spdm_response->header.spdm_version < SPDM_MESSAGE_VERSION_12) {
        *response_size = sizeof(spdm_capabilities_response_t) -
                         sizeof(spdm_response->data_transfer_size) -
                         sizeof(spdm_response->max_spdm_msg_size);
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
        spdm_response->ext_flags =
            libspdm_mask_capability_ext_flags(spdm_context, false,
                                              spdm_context->local_context.capability.ext_flags);
    } else {
        spdm_response->ext_flags = 0;
    }

    /* -=[Process Request Phase]=- */
    status = libspdm_append_message_a(spdm_context, spdm_request, request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    status = libspdm_append_message_a(spdm_context, spdm_response, *response_size);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_context->connection_info.capability.ct_exponent = spdm_request->ct_exponent;
    } else {
        spdm_context->connection_info.capability.ct_exponent = 0;
    }

    spdm_context->connection_info.capability.flags =
        libspdm_mask_capability_flags(spdm_context, true, spdm_request->flags);

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.capability.data_transfer_size =
            spdm_request->data_transfer_size;
        spdm_context->connection_info.capability.max_spdm_msg_size =
            spdm_request->max_spdm_msg_size;
    } else {
        spdm_context->connection_info.capability.data_transfer_size = 0;
        spdm_context->connection_info.capability.max_spdm_msg_size = 0;
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
        spdm_context->connection_info.capability.ext_flags =
            libspdm_mask_capability_ext_flags(spdm_context, true, spdm_request->ext_flags);
    } else {
        spdm_context->connection_info.capability.ext_flags = 0;
    }

    /* -=[Update State Phase]=- */
    libspdm_set_connection_state(spdm_context, LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES);

    return LIBSPDM_STATUS_SUCCESS;
}
