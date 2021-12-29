/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_requester_lib.h"


/* current version libspdm does not support any ext algo.*/
/* the requester will not build ext algo in request.*/
/* the requester will ignore the ext algo in response.*/


#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification;
    uint8_t reserved;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;
    uint8_t reserved2[12];
    uint8_t ext_asym_count;
    uint8_t ext_hash_count;
    uint16_t reserved3;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} spdm_negotiate_algorithms_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification_sel;
    uint8_t reserved;
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
} spdm_algorithms_response_max_t;
#pragma pack()

/**
  This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The NEGOTIATE_ALGORITHMS is sent and the ALGORITHMS is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status try_spdm_negotiate_algorithms(IN spdm_context_t *spdm_context)
{
    return_status status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_algorithms_response_max_t spdm_response;
    uintn spdm_response_size;
    uint32_t algo_size;
    uintn index;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    uint8_t fixed_alg_size;
    uint8_t ext_alg_count;

    spdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                    SPDM_NEGOTIATE_ALGORITHMS);

    if (spdm_context->connection_info.connection_state !=
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
        return RETURN_UNSUPPORTED;
    }

    zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = spdm_get_connection_version (spdm_context);
    if (spdm_request.header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request.length = sizeof(spdm_request);
        spdm_request.header.param1 =
            4; /* Number of Algorithms Structure Tables*/
    } else {
        spdm_request.length = sizeof(spdm_request) -
                      sizeof(spdm_request.struct_table);
        spdm_request.header.param1 = 0;
    }
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    spdm_request.measurement_specification =
        spdm_context->local_context.algorithm.measurement_spec;
    spdm_request.base_asym_algo =
        spdm_context->local_context.algorithm.base_asym_algo;
    spdm_request.base_hash_algo =
        spdm_context->local_context.algorithm.base_hash_algo;
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;
    spdm_request.struct_table[0].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    spdm_request.struct_table[0].alg_count = 0x20;
    spdm_request.struct_table[0].alg_supported =
        spdm_context->local_context.algorithm.dhe_named_group;
    spdm_request.struct_table[1].alg_type =
        SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
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

    status = spdm_send_spdm_request(spdm_context, NULL, spdm_request.length,
                    &spdm_request);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }

    spdm_response_size = sizeof(spdm_response);
    zero_mem(&spdm_response, sizeof(spdm_response));
    status = spdm_receive_spdm_response(
        spdm_context, NULL, &spdm_response_size, &spdm_response);
    if (RETURN_ERROR(status)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.request_response_code == SPDM_ERROR) {
        status = spdm_handle_simple_error_response(
            spdm_context, spdm_response.header.param1);
        if (RETURN_ERROR(status)) {
            return status;
        }
    } else if (spdm_response.header.request_response_code !=
           SPDM_ALGORITHMS) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size < sizeof(spdm_algorithms_response_t)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size > sizeof(spdm_response)) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.spdm_version != spdm_request.header.spdm_version){
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.ext_asym_sel_count > 1) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.ext_hash_sel_count > 1) {
        return RETURN_DEVICE_ERROR;
    }
    if (spdm_response_size <
        sizeof(spdm_algorithms_response_t) +
            sizeof(uint32_t) * spdm_response.ext_asym_sel_count +
            sizeof(uint32_t) * spdm_response.ext_hash_sel_count +
            sizeof(spdm_negotiate_algorithms_common_struct_table_t) *
                spdm_response.header.param1) {
        return RETURN_DEVICE_ERROR;
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
                return RETURN_DEVICE_ERROR;
            }
            if ((uintn)&spdm_response + spdm_response_size -
                    (uintn)struct_table <
                sizeof(spdm_negotiate_algorithms_common_struct_table_t)) {
                return RETURN_DEVICE_ERROR;
            }
            fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
            ext_alg_count = struct_table->alg_count & 0xF;
            if (fixed_alg_size != 2) {
                return RETURN_DEVICE_ERROR;
            }
            if (ext_alg_count > 1) {
                return RETURN_DEVICE_ERROR;
            }
            if ((uintn)&spdm_response + spdm_response_size -
                    (uintn)struct_table -
                    sizeof(spdm_negotiate_algorithms_common_struct_table_t) <
                sizeof(uint32_t) * ext_alg_count) {
                return RETURN_DEVICE_ERROR;
            }
            struct_table =
                (void *)((uintn)struct_table +
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                     sizeof(uint32_t) * ext_alg_count);
        }
    }
    spdm_response_size = (uintn)struct_table - (uintn)&spdm_response;
    if (spdm_response_size != spdm_response.length) {
        return RETURN_DEVICE_ERROR;
    }

    
    /* Cache data*/
    
    status = libspdm_append_message_a(spdm_context, &spdm_request,
                       spdm_request.length);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    status = libspdm_append_message_a(spdm_context, &spdm_response,
                       spdm_response_size);
    if (RETURN_ERROR(status)) {
        return RETURN_SECURITY_VIOLATION;
    }

    spdm_context->connection_info.algorithm.measurement_spec =
        spdm_response.measurement_specification_sel;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        spdm_response.measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        spdm_response.base_asym_sel;
    spdm_context->connection_info.algorithm.base_hash_algo =
        spdm_response.base_hash_sel;

    if (spdm_is_capabilities_flag_supported(
            spdm_context, TRUE, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
        if (spdm_context->connection_info.algorithm.measurement_spec !=
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
            return RETURN_SECURITY_VIOLATION;
        }
        algo_size = libspdm_get_measurement_hash_size(
            spdm_context->connection_info.algorithm
                .measurement_hash_algo);
        if (algo_size == 0) {
            return RETURN_SECURITY_VIOLATION;
        }
    }
    algo_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (algo_size == 0) {
        return RETURN_SECURITY_VIOLATION;
    }
    if ((spdm_context->connection_info.algorithm.base_hash_algo & spdm_context->local_context.algorithm.base_hash_algo) == 0) {
        return RETURN_SECURITY_VIOLATION;
    }
    if (spdm_is_capabilities_flag_supported(
            spdm_context, TRUE, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        algo_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
        if (algo_size == 0) {
            return RETURN_SECURITY_VIOLATION;
        }
        if ((spdm_context->connection_info.algorithm.base_asym_algo & spdm_context->local_context.algorithm.base_asym_algo) == 0) {
            return RETURN_SECURITY_VIOLATION;
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

        if (spdm_is_capabilities_flag_supported(
                spdm_context, TRUE,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
            algo_size = libspdm_get_dhe_pub_key_size(
                spdm_context->connection_info.algorithm
                    .dhe_named_group);
            if (algo_size == 0) {
                return RETURN_SECURITY_VIOLATION;
            }
            if ((spdm_context->connection_info.algorithm.dhe_named_group & spdm_context->local_context.algorithm.dhe_named_group) == 0) {
                return RETURN_SECURITY_VIOLATION;
            }
        }
        if (spdm_is_capabilities_flag_supported(
                spdm_context, TRUE,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
            spdm_is_capabilities_flag_supported(
                spdm_context, TRUE,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
            algo_size = libspdm_get_aead_key_size(
                spdm_context->connection_info.algorithm
                    .aead_cipher_suite);
            if (algo_size == 0) {
                return RETURN_SECURITY_VIOLATION;
            }
            if ((spdm_context->connection_info.algorithm.aead_cipher_suite & spdm_context->local_context.algorithm.aead_cipher_suite) == 0) {
                return RETURN_SECURITY_VIOLATION;
            }
        }
        if (spdm_is_capabilities_flag_supported(
                spdm_context, TRUE,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
            algo_size = libspdm_get_req_asym_signature_size(
                spdm_context->connection_info.algorithm
                    .req_base_asym_alg);
            if (algo_size == 0) {
                return RETURN_SECURITY_VIOLATION;
            }
            if ((spdm_context->connection_info.algorithm.req_base_asym_alg & spdm_context->local_context.algorithm.req_base_asym_alg) == 0) {
                return RETURN_SECURITY_VIOLATION;
            }
        }
        if (spdm_is_capabilities_flag_supported(
                spdm_context, TRUE,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
            spdm_is_capabilities_flag_supported(
                spdm_context, TRUE,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
            if (spdm_context->connection_info.algorithm
                    .key_schedule !=
                SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
                return RETURN_SECURITY_VIOLATION;
            }
            if ((spdm_context->connection_info.algorithm.key_schedule & spdm_context->local_context.algorithm.key_schedule) == 0) {
                return RETURN_SECURITY_VIOLATION;
            }
        }
    } else {
        spdm_context->connection_info.algorithm.dhe_named_group = 0;
        spdm_context->connection_info.algorithm.aead_cipher_suite = 0;
        spdm_context->connection_info.algorithm.req_base_asym_alg = 0;
        spdm_context->connection_info.algorithm.key_schedule = 0;
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    return RETURN_SUCCESS;
}

/**
  This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The NEGOTIATE_ALGORITHMS is sent and the ALGORITHMS is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status spdm_negotiate_algorithms(IN spdm_context_t *spdm_context)
{
    uintn retry;
    return_status status;

    retry = spdm_context->retry_times;
    do {
        status = try_spdm_negotiate_algorithms(spdm_context);
        if (RETURN_NO_RESPONSE != status) {
            return status;
        }
    } while (retry-- != 0);

    return status;
}
