/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#pragma pack(1)
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
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_algorithms_response_spdm11_t;
#pragma pack()

libspdm_return_t libspdm_requester_negotiate_algorithms_test_send_message(
    void *spdm_context, uintn request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xA:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xC:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xD:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xF:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x10:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x11:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x12:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x13:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x14:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x15:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x16:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x17:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x18:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x19:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1A:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1C:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1D:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1E:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1F:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x20:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return RETURN_DEVICE_ERROR;
    }
}

libspdm_return_t libspdm_requester_negotiate_algorithm_test_receive_message(
    void *spdm_context, uintn *response_size,
    void *response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;

    case 0x2: {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response.header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x5: {
        spdm_error_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response.header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6: {
        static uintn sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t spdm_response;

            libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response.header.param2 = 0;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
        } else if (sub_index1 == 1) {
            spdm_algorithms_response_t spdm_response;

            libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response.header.request_response_code =
                SPDM_ALGORITHMS;
            spdm_response.header.param1 = 0;
            spdm_response.header.param2 = 0;
            spdm_response.length =
                sizeof(spdm_algorithms_response_t);
            spdm_response.measurement_specification_sel =
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
            spdm_response.measurement_hash_algo =
                m_libspdm_use_measurement_hash_algo;
            spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
            spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
            spdm_response.ext_asym_sel_count = 0;
            spdm_response.ext_hash_sel_count = 0;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
        }
        sub_index1++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: {
        spdm_error_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response.header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response.header.param2 = 0;
        spdm_response.extend_error_data.rd_exponent = 1;
        spdm_response.extend_error_data.rd_tm = 1;
        spdm_response.extend_error_data.request_code =
            SPDM_NEGOTIATE_ALGORITHMS;
        spdm_response.extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = 0;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = 0;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = 0;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_response),
                                              &spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_message_header_t), &spdm_response,
                                               response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;


        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_algorithms_response_t)/2, &spdm_response,
                                               response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 2;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 2;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    /* case 0x11:
     * {
     *   spdm_algorithms_response_t    spdm_response;*/

    /*   libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
     *   spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
     *   spdm_response.header.request_response_code = SPDM_ALGORITHMS;
     *   spdm_response.header.param1 = 0;
     *   spdm_response.header.param2 = 0;
     *   spdm_response.length = sizeof(spdm_algorithms_response_t);
     *   spdm_response.measurement_specification_sel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
     *   spdm_response.measurement_hash_algo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
     *   spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
     *   spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
     *   spdm_response.ext_asym_sel_count = 0;
     *   spdm_response.ext_hash_sel_count = 0;*/

    /*   libspdm_transport_test_encode_message (spdm_context, NULL, false, false, sizeof(spdm_response), &spdm_response, response_size, response);
     * }
     *   return LIBSPDM_STATUS_SUCCESS;*/

    case 0x11:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo|
                                              SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo|
                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15:
    {
        spdm_algorithms_response_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(spdm_algorithms_response_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo|
                                      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported =
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1A:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported =
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1B:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = BIT5;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1C:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo |
                                                      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1D:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo |
                                                      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1E:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo |
                                                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1F:
    {
        libspdm_algorithms_response_spdm11_t spdm_response;

        libspdm_zero_mem (&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ALGORITHMS;
        spdm_response.header.param1 = 4;
        spdm_response.header.param2 = 0;
        spdm_response.length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response.measurement_specification_sel =
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_response.measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response.base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response.base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response.ext_asym_sel_count = 0;
        spdm_response.ext_hash_sel_count = 0;
        spdm_response.struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response.struct_table[0].alg_count = 0x20;
        spdm_response.struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response.struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response.struct_table[1].alg_count = 0x20;
        spdm_response.struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response.struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response.struct_table[2].alg_count = 0x20;
        spdm_response.struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response.struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response.struct_table[3].alg_count = 0x20;
        spdm_response.struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo | BIT5;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_response),
                                               &spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return RETURN_DEVICE_ERROR;
    }
}

void libspdm_test_requester_negotiate_algorithms_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
#endif
}

void libspdm_test_requester_negotiate_algorithms_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     sizeof(spdm_negotiate_algorithms_request_t) +
                     sizeof(spdm_algorithms_response_t));
#endif
}

void libspdm_test_requester_negotiate_algorithms_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
#endif
}

void libspdm_test_requester_negotiate_algorithms_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
#endif
}

void libspdm_test_requester_negotiate_algorithms_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
#endif
}

void libspdm_test_requester_negotiate_algorithms_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     sizeof(spdm_negotiate_algorithms_request_t) +
                     sizeof(spdm_algorithms_response_t));
#endif
}

void libspdm_test_requester_negotiate_algorithms_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
#endif
}

void libspdm_test_requester_negotiate_algorithms_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

void libspdm_test_requester_negotiate_algorithms_case9(void **state)
{
}

void libspdm_test_requester_negotiate_algorithms_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo = 0;
    spdm_context->connection_info.algorithm.base_asym_algo = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
    assert_int_equal(
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        0);
}

void libspdm_test_requester_negotiate_algorithms_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo = 0;
    spdm_context->connection_info.algorithm.base_asym_algo = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
    assert_int_equal(spdm_context->connection_info.algorithm.base_asym_algo,
                     0);
}

void libspdm_test_requester_negotiate_algorithms_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo = 0;
    spdm_context->connection_info.algorithm.base_asym_algo = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = 0;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
    assert_int_equal(spdm_context->connection_info.algorithm.base_hash_algo,
                     0);
}

void libspdm_test_requester_negotiate_algorithms_case13(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

void libspdm_test_requester_negotiate_algorithms_case14(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

void libspdm_test_requester_negotiate_algorithms_case15(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

void libspdm_test_requester_negotiate_algorithms_case16(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

void libspdm_test_requester_negotiate_algorithms_case17(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case18(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case19(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case20(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case21(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case22(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

void libspdm_test_requester_negotiate_algorithms_case23(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal (spdm_context->transcript.message_a.buffer_size,
                      sizeof(spdm_negotiate_algorithms_request_t) + 4*
                      sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                      sizeof(libspdm_algorithms_response_spdm11_t));
#endif
}

void libspdm_test_requester_negotiate_algorithms_case24(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case25(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case26(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case27(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case28(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case29(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case30(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

void libspdm_test_requester_negotiate_algorithms_case31(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

libspdm_test_context_t m_libspdm_requester_negotiate_algorithms_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_requester_negotiate_algorithms_test_send_message,
    libspdm_requester_negotiate_algorithm_test_receive_message,
};

int libspdm_requester_negotiate_algorithms_test_main(void)
{
    const struct CMUnitTest spdm_requester_negotiate_algorithms_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case1),
        /* Successful response*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case2),
        /* connection_state check failed*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case9),
        /* When spdm_response.measurement_hash_algo is 0*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case10),
        /* When spdm_response.base_asym_sel is 0*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case11),
        /* When spdm_response.base_hash_sel is 0*/
        cmocka_unit_test(
            libspdm_test_requester_negotiate_algorithms_case12),
        /* When spdm_response has a size of header and SPDM_ALGORITHMS code*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case13),
        /* When spdm_response has a size greater than header and smaller than algorithm and SPDM_ALGORITHMS code*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case14),
        /* When spdm_response has ext_asym_sel_count > 1*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case15),
        /* When spdm_response has ExtAsymHashCount > 1*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case16),
        /* When spdm_response returns an unlisted measurement_hash_algo
         * cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case17),
         * When spdm_response returns an unlisted base_asym_sel*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case17),
        /* When spdm_response returns an unlisted base_hash_sel*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case18),
        /* When spdm_response returns multiple measurement_hash_algo*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case19),
        /* When spdm_response returns multiple base_asym_sel*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case20),
        /* When spdm_response returns multiple base_hash_sel*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case21),
        /* Request and response mismatch version*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case22),
        /* Successful V1.1 response*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case23),
        /* When spdm_response returns an unlisted DheAlgo*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case24),
        /* When spdm_response returns an unlisted AEADAlgo*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case25),
        /* When spdm_response returns an unlisted ReqAsymAlgo*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case26),
        /* When spdm_response returns an unlisted key_schedule*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case27),
        /* When spdm_response returns multiple DheAlgo*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case28),
        /* When spdm_response returns multiple AEADAlgo*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case29),
        /* When spdm_response returns multiple ReqAsymAlgo*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case30),
        /* When spdm_response returns multiple key_schedule*/
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case31),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_negotiate_algorithms_test_context);

    return cmocka_run_group_tests(spdm_requester_negotiate_algorithms_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
