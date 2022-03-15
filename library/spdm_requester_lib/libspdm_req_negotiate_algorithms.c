/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification;
    uint8_t other_params_support;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;
    uint8_t reserved2[12];
    uint8_t ext_asym_count;
    uint8_t ext_hash_count;
    uint16_t reserved3;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_negotiate_algorithms_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification_sel;
    uint8_t other_params_support;
    uint32_t measurement_hash_algo;
    uint32_t base_asym_sel;
    uint32_t base_hash_sel;
    uint8_t reserved2[12];
    uint8_t ext_asym_sel_count;
    uint8_t ext_hash_sel_count;
    uint16_t reserved3;
    uint32_t ext_asym_sel;
    uint32_t ext_hash_sel;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_algorithms_response_max_t;
#pragma pack()

/**
 * This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.
 *
 * @param  spdm_context A pointer to the SPDM context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         NEGOTIATE_ALGORITHMS was sent and ALGORITHMS was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send NEGOTIATE_ALGORITHMS due to Requester's state.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the ALGORITHMS response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The ALGORITHMS response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 * @retval LIBSPDM_STATUS_NEGOTIATION_FAIL
 *         The Requester and Responder could not agree on mutual algorithms.
 *         Note: This return value may be removed in the future.
 **/
libspdm_return_t libspdm_try_negotiate_algorithms(libspdm_context_t *spdm_context)
{
    libspdm_return_t status;
    libspdm_negotiate_algorithms_request_mine_t spdm_request;
    libspdm_algorithms_response_max_t spdm_response;
    uintn spdm_response_size;
    uint32_t algo_size;
    uintn index;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    uint8_t fixed_alg_size;
    uint8_t ext_alg_count;

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL, SPDM_NEGOTIATE_ALGORITHMS);

    if (spdm_context->connection_info.connection_state !=
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = libspdm_get_connection_version (spdm_context);
    if (spdm_request.header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request.length = sizeof(spdm_request);
        /* Number of Algorithms Structure Tables*/
        spdm_request.header.param1 = 4;
    } else {
        spdm_request.length = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
        spdm_request.header.param1 = 0;
    }
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    spdm_request.measurement_specification = spdm_context->local_context.algorithm.measurement_spec;
    if (spdm_request.header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request.other_params_support =
        spdm_context->local_context.algorithm.other_params_support;
    }
    spdm_request.base_asym_algo = spdm_context->local_context.algorithm.base_asym_algo;
    spdm_request.base_hash_algo = spdm_context->local_context.algorithm.base_hash_algo;
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;
    spdm_request.struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_request.struct_table[0].alg_count = 0x20;
    spdm_request.struct_table[0].alg_supported =
        spdm_context->local_context.algorithm.dhe_named_group;
    spdm_request.struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    spdm_request.struct_table[1].alg_count = 0x20;
    spdm_request.struct_table[1].alg_supported =
        spdm_context->local_context.algorithm.aead_cipher_suite;
    spdm_request.struct_table[2].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    spdm_request.struct_table[2].alg_count = 0x20;
    spdm_request.struct_table[2].alg_supported =
        spdm_context->local_context.algorithm.req_base_asym_alg;
    spdm_request.struct_table[3].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    spdm_request.struct_table[3].alg_count = 0x20;
    spdm_request.struct_table[3].alg_supported =
        spdm_context->local_context.algorithm.key_schedule;

    status = libspdm_send_spdm_request(spdm_context, NULL, spdm_request.length, &spdm_request);
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
        status = libspdm_handle_simple_error_response(
            spdm_context, spdm_response.header.param1);

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
    } else if (spdm_response.header.request_response_code != SPDM_ALGORITHMS) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size < sizeof(spdm_algorithms_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response.ext_asym_sel_count > 1) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response.ext_hash_sel_count > 1) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size <
        sizeof(spdm_algorithms_response_t) +
        sizeof(uint32_t) * spdm_response.ext_asym_sel_count +
        sizeof(uint32_t) * spdm_response.ext_hash_sel_count +
        sizeof(spdm_negotiate_algorithms_common_struct_table_t) *
        spdm_response.header.param1) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    struct_table =
        (void *)((uintn)&spdm_response +
                 sizeof(spdm_algorithms_response_t) +
                 sizeof(uint32_t) * spdm_response.ext_asym_sel_count +
                 sizeof(uint32_t) * spdm_response.ext_hash_sel_count);
    if (spdm_response.header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        for (index = 0; index < spdm_response.header.param1; index++) {
            if ((uintn)&spdm_response + spdm_response_size <
                (uintn)struct_table) {
                return LIBSPDM_STATUS_INVALID_MSG_SIZE;
            }
            if ((uintn)&spdm_response + spdm_response_size -
                (uintn)struct_table <
                sizeof(spdm_negotiate_algorithms_common_struct_table_t)) {
                return LIBSPDM_STATUS_INVALID_MSG_SIZE;
            }
            fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
            ext_alg_count = struct_table->alg_count & 0xF;
            if (fixed_alg_size != 2) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
            if (ext_alg_count > 1) {
                return LIBSPDM_STATUS_INVALID_MSG_FIELD;
            }
            if ((uintn)&spdm_response + spdm_response_size -
                (uintn)struct_table -
                sizeof(spdm_negotiate_algorithms_common_struct_table_t) <
                sizeof(uint32_t) * ext_alg_count) {
                return LIBSPDM_STATUS_INVALID_MSG_SIZE;
            }
            struct_table =
                (void *)((uintn)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }
    }
    spdm_response_size = (uintn)struct_table - (uintn)&spdm_response;
    if (spdm_response_size != spdm_response.length) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    /* Cache data*/

    status = libspdm_append_message_a(spdm_context, &spdm_request, spdm_request.length);
    /* TODO: Replace with LIBSPDM_RET_ON_ERR. */
    if (RETURN_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    status = libspdm_append_message_a(spdm_context, &spdm_response, spdm_response_size);
    /* TODO: Replace with LIBSPDM_RET_ON_ERR. */
    if (RETURN_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    spdm_context->connection_info.algorithm.measurement_spec =
        spdm_response.measurement_specification_sel;
    if (spdm_response.header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.algorithm.other_params_support =
            spdm_response.other_params_support;
    }
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        spdm_response.measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        spdm_response.base_asym_sel;
    spdm_context->connection_info.algorithm.base_hash_algo =
        spdm_response.base_hash_sel;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
        if (spdm_context->connection_info.algorithm.measurement_spec !=
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        algo_size = libspdm_get_measurement_hash_size(
            spdm_context->connection_info.algorithm
            .measurement_hash_algo);
        if (algo_size == 0) {
            return LIBSPDM_STATUS_NEGOTIATION_FAIL;
        }
    }
    algo_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (algo_size == 0) {
        return LIBSPDM_STATUS_NEGOTIATION_FAIL;
    }
    if ((spdm_context->connection_info.algorithm.base_hash_algo &
         spdm_context->local_context.algorithm.base_hash_algo) == 0) {
        return LIBSPDM_STATUS_NEGOTIATION_FAIL;
    }
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        algo_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
        if (algo_size == 0) {
            return LIBSPDM_STATUS_NEGOTIATION_FAIL;
        }
        if ((spdm_context->connection_info.algorithm.base_asym_algo &
             spdm_context->local_context.algorithm.base_asym_algo) == 0) {
            return LIBSPDM_STATUS_NEGOTIATION_FAIL;
        }
    }

    if (spdm_response.header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        struct_table =
            (void *)((uintn)&spdm_response +
                     sizeof(spdm_algorithms_response_t) +
                     sizeof(uint32_t) *
                     spdm_response.ext_asym_sel_count +
                     sizeof(uint32_t) *
                     spdm_response.ext_hash_sel_count);
        for (index = 0; index < spdm_response.header.param1; index++) {
            switch (struct_table->alg_type) {
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
                spdm_context->connection_info.algorithm
                .dhe_named_group =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
                spdm_context->connection_info.algorithm
                .aead_cipher_suite =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
                spdm_context->connection_info.algorithm
                .req_base_asym_alg =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
                spdm_context->connection_info.algorithm
                .key_schedule =
                    struct_table->alg_supported;
                break;
            }
            ext_alg_count = struct_table->alg_count & 0xF;
            struct_table =
                (void *)((uintn)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }

        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
            algo_size = libspdm_get_dhe_pub_key_size(
                spdm_context->connection_info.algorithm
                .dhe_named_group);
            if (algo_size == 0) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
            if ((spdm_context->connection_info.algorithm.dhe_named_group &
                 spdm_context->local_context.algorithm.dhe_named_group) == 0) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
            libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
            algo_size = libspdm_get_aead_key_size(
                spdm_context->connection_info.algorithm
                .aead_cipher_suite);
            if (algo_size == 0) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
            if ((spdm_context->connection_info.algorithm.aead_cipher_suite &
                 spdm_context->local_context.algorithm.aead_cipher_suite) == 0) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
            algo_size = libspdm_get_req_asym_signature_size(
                spdm_context->connection_info.algorithm
                .req_base_asym_alg);
            if (algo_size == 0) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
            if ((spdm_context->connection_info.algorithm.req_base_asym_alg &
                 spdm_context->local_context.algorithm.req_base_asym_alg) == 0) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
            libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
            if (spdm_context->connection_info.algorithm
                .key_schedule !=
                SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
            if ((spdm_context->connection_info.algorithm.key_schedule &
                 spdm_context->local_context.algorithm.key_schedule) == 0) {
                return LIBSPDM_STATUS_NEGOTIATION_FAIL;
            }
            if (spdm_response.header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
                if ((spdm_context->connection_info.algorithm.other_params_support &
                     SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) !=
                    SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1) {
                    return LIBSPDM_STATUS_NEGOTIATION_FAIL;
                }
            }
        }
    } else {
        spdm_context->connection_info.algorithm.dhe_named_group = 0;
        spdm_context->connection_info.algorithm.aead_cipher_suite = 0;
        spdm_context->connection_info.algorithm.req_base_asym_alg = 0;
        spdm_context->connection_info.algorithm.key_schedule = 0;
    }

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS. It may retry
 * NEGOTIATE_ALGORITHMS multiple times if the Responder replies with a Busy error.
 *
 * @param  spdm_context A pointer to the SPDM context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         NEGOTIATE_ALGORITHMS was sent and ALGORITHMS was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send NEGOTIATE_ALGORITHMS due to Requester's state.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the ALGORITHMS response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The ALGORITHMS response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 * @retval LIBSPDM_STATUS_NEGOTIATION_FAIL
 *         The Requester and Responder could not agree on mutual algorithms.
 *         Note: This return value may be removed in the future.
 **/
libspdm_return_t libspdm_negotiate_algorithms(libspdm_context_t *spdm_context)
{
    uintn retry;
    libspdm_return_t status;

    spdm_context->crypto_request = false;
    retry = spdm_context->retry_times;
    do {
        status = libspdm_try_negotiate_algorithms(spdm_context);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
