/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_IL1IL2_BUFFER_SIZE];

#define LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE 0x20
static uint8_t m_endpoint_info_buffer[LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE];

static libspdm_return_t libspdm_requester_get_endpoint_info_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    size_t header_size;
    uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

    memcpy(message_buffer, request, request_size);

    spdm_test_context = libspdm_get_test_context();
    header_size = sizeof(libspdm_test_message_header_t);
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        /*should not reach here*/
        LIBSPDM_ASSERT(0);
    case 0x3:
    case 0x4:
    case 0x5:
    case 0x6:
    case 0x7:
    case 0x8:
    case 0x9:
    case 0xA:
    case 0xB:
    case 0xC:
    case 0xD:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, request_size - header_size);
        m_libspdm_local_buffer_size += request_size - header_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE:
    case 0xF:
        /*should not reach here*/
        LIBSPDM_ASSERT(0);
    case 0x10:
    case 0x11:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x12:
        m_libspdm_local_buffer_size = 0;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x13:
    case 0x14:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, request_size - header_size);
        m_libspdm_local_buffer_size += request_size - header_size;
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

static libspdm_return_t libspdm_requester_get_endpoint_info_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    uint32_t endpoint_info_buffer_size;

    endpoint_info_buffer_size = LIBSPDM_TEST_ENDPOINT_INFO_BUFFER_SIZE;
    spdm_test_context = libspdm_get_test_context();
    libspdm_generate_device_endpoint_info(
        spdm_context, SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
        &endpoint_info_buffer_size, m_endpoint_info_buffer);
    switch (spdm_test_context->case_id) {
    case 0x1:
        /*should not reach here*/
        LIBSPDM_ASSERT(0);

    case 0x2:
        /*should not reach here*/
        LIBSPDM_ASSERT(0);

    case 0x3: { /*ERROR SPDM_ERROR_CODE_INVALID_REQUEST*/
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: { /*ERROR SPDM_ERROR_CODE_BUSY*/
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x5: { /*ERROR SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6: { /*ERROR SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        spdm_error_response_data_response_not_ready_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version =
            SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code =
            SPDM_GET_ENDPOINT_INFO;
        spdm_response->extend_error_data.token = 1;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            spdm_response_size, spdm_response,
            response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: { /*ERROR unexpected*/
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        if(error_code <= 0xff) {
            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            /*busy is treated in cases 3 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x8: { /*ENDPOINT_INFO with wrong response code*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO + 1;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(hash_data, libspdm_get_hash_size(m_libspdm_use_hash_algo));
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_ENDPOINT_INFO,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: { /*ENDPOINT_INFO with wrong version*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(hash_data, libspdm_get_hash_size(m_libspdm_use_hash_algo));
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_ENDPOINT_INFO,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: { /*ENDPOINT_INFO without signature*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: { /*ENDPOINT_INFO with invalid signature (random)*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_get_random_number(sig_size, ptr);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: { /*ENDPOINT_INFO with invalid signature (all bytes are 0)*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        for (uint32_t index = 0; index < sig_size; index++) {
            ptr[index] = 0x00;
        }
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: { /*ENDPOINT_INFO with wrong ep_info_length*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size + 1; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(hash_data, libspdm_get_hash_size(m_libspdm_use_hash_algo));
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_ENDPOINT_INFO,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE:
        /*should not reach here*/
        LIBSPDM_ASSERT(0);

    case 0xF:
        /*should not reach here*/
        LIBSPDM_ASSERT(0);

    case 0x10: { /*ENDPOINT_INFO with wrong slot id*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             +sizeof(uint32_t) +
                             endpoint_info_buffer_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 1; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: { /*ENDPOINT_INFO with wrong ep_info_length*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             +sizeof(uint32_t) +
                             endpoint_info_buffer_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        *(uint32_t *)ptr = endpoint_info_buffer_size + 1; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: { /*ENDPOINT_INFO message with signature*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(hash_data, libspdm_get_hash_size(m_libspdm_use_hash_algo));
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_ENDPOINT_INFO,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: { /*ENDPOINT_INFO with wrong slot_id*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 2; /* wrong slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(hash_data, libspdm_get_hash_size(m_libspdm_use_hash_algo));
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_ENDPOINT_INFO,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: { /*correct ENDPOINT_INFO message with signature*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;

        spdm_response_size = sizeof(spdm_endpoint_info_response_t) +
                             SPDM_NONCE_SIZE + sizeof(uint32_t) +
                             endpoint_info_buffer_size +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ENDPOINT_INFO;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0; /* slot_id */
        ptr = (uint8_t *)(spdm_response + 1);

        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;

        *(uint32_t *)ptr = endpoint_info_buffer_size; /* ep_info_len */
        ptr += sizeof(uint32_t);

        libspdm_copy_mem(ptr, endpoint_info_buffer_size,
                         m_endpoint_info_buffer, endpoint_info_buffer_size);
        ptr += endpoint_info_buffer_size;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(hash_data, libspdm_get_hash_size(m_libspdm_use_hash_algo));
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_ENDPOINT_INFO,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 *                    with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce_in[index] = 0x5c;
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 2: Error case, connection version is lower than 1.3
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce_in[index] = 0x5c;
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}


/**
 * Test 3: Error case, get an error response with code SPDM_ERROR_CODE_INVALID_REQUEST
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 *                    with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 4: Error case, always get an error response with code SPDM_ERROR_CODE_BUSY
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 *                    with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 5: Error case, get an error response with code SPDM_ERROR_CODE_REQUEST_RESYNCH
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 *                    with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 6: Error case, always get an error response with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code,
 *                    with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 7: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
static void libspdm_test_requester_get_endpoint_info_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state =
            LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        libspdm_reset_message_a(spdm_context);
        libspdm_reset_message_e(spdm_context, NULL);

        status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                           sub_code, slot_id,
                                           &ep_info_length, ep_info_record,
                                           requester_nonce_in, requester_nonce,
                                           responder_nonce);

        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        LIBSPDM_ASSERT_INT_EQUAL_CASE(spdm_context->transcript.message_e.buffer_size,
                                      0, error_code);
#endif
        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            /*busy is treated in cases 3 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
    free(data);
}

/**
 * Test 8: Error case, response with wrong response code
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 9: Error case, response with wrong version
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 10: Error case, response without signature
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 11: Error case, response with invalid signature (random)
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 12: Error case, response with invalid signature (all bytes are 0)
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 13: Error case, response with wrong ep_info_length
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 14: Error case, responder capability flag is NO_SIG but request signature
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG; /*NO_SIG*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 15: Error case, request no signature but slot id not 0
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG;

    slot_id = 1;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes = 0;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       NULL, NULL, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 16: Error case, request no signature but responder's slot id not 0
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG;

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes = 0;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       NULL, NULL, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 17: Error case, request no signature and response with wrong ep_info_length
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG;

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes = 0;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       NULL, NULL, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 18: Error case, request no signature but response with signature
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG;

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes = 0;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       NULL, NULL, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 19: Error case, response with wrong slot_id
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
static void libspdm_test_requester_get_endpoint_info_err_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = LIBSPDM_MAX_ENDPOINT_INFO_LENGTH;

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 20: Error case, input buffer ep_info_length too small.
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_err_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t sub_code;
    uint8_t request_attributes;
    uint8_t slot_id;
    uint32_t ep_info_length;
    uint8_t ep_info_record[LIBSPDM_MAX_ENDPOINT_INFO_LENGTH];
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    slot_id = 0;
    sub_code = SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER;
    request_attributes =
        SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED;
    ep_info_length = 0; /* Too small */

    libspdm_get_random_number(SPDM_NONCE_SIZE, requester_nonce_in);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
    }

    status = libspdm_get_endpoint_info(spdm_context, NULL, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#endif
}

int libspdm_requester_get_endpoint_info_error_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_endpoint_info_tests[] = {
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case1),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case2),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case3),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case4),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case5),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case6),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case7),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case8),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case9),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case10),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case11),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case12),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case13),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case14),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case15),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case16),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case17),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case18),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case19),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_err_case20),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        libspdm_requester_get_endpoint_info_test_send_message,
        libspdm_requester_get_endpoint_info_test_receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(spdm_requester_get_endpoint_info_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
