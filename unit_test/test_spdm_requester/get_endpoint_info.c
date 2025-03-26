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
    case 0x2:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, request_size - header_size);
        m_libspdm_local_buffer_size += request_size - header_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3: {
        static size_t sub_index = 0;
        if (sub_index == 0) {
            m_libspdm_local_buffer_size = 0;
            libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                             (const uint8_t *)request + header_size, request_size - header_size);
            m_libspdm_local_buffer_size += request_size - header_size;
            sub_index++;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
    case 0x5:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, request_size - header_size);
        m_libspdm_local_buffer_size += request_size - header_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7: {
        uint32_t *session_id;
        libspdm_session_info_t *session_info;
        bool is_app_message;
        uint8_t *app_message;
        size_t app_message_size;

        m_libspdm_local_buffer_size = 0;
        session_id = NULL;
        session_info = libspdm_get_session_info_via_session_id(spdm_context, 0xFFFFFFFF);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Request (0x%zx):\n", request_size));
        libspdm_dump_hex(request, request_size);
        libspdm_get_scratch_buffer (spdm_context, (void **)&app_message, &app_message_size);
        libspdm_transport_test_decode_message(
            spdm_context, &session_id, &is_app_message,
            false, request_size, message_buffer,
            &app_message_size, (void **)&app_message);
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         app_message, app_message_size);
        m_libspdm_local_buffer_size += app_message_size;
    }
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
    case 0x1: { /*correct ENDPOINT_INFO message with signature*/
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

    case 0x2: { /*ERROR BUSY + ENDPOINT_INFO w/ signature*/
        static size_t sub_index1 = 0;
        if (sub_index1 == 0) {
            /*SPDM_ERROR with SPDM_ERROR_CODE_BUSY*/
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_13;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index1++;
        } else if (sub_index1 == 1) {
            /*correct ENDPOINT_INFO message with signature*/
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
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: { /*ERROR NOT_READY + ENDPOINT_INFO w/ signature*/
        static size_t sub_index2 = 0;
        if (sub_index2 == 0) {
            /*SPDM_ERROR with SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
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
            sub_index2++;
        } else if (sub_index2 == 1) {
            /*correct ENDPOINT_INFO message with signature*/
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
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: { /*correct ENDPOINT_INFO message with signature and slot_id = 1*/
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
        spdm_response->header.param2 = 1; /* slot_id */
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

    case 0x5: { /*correct ENDPOINT_INFO message with signature and use provisioned key*/
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
        spdm_response->header.param2 = 0xF; /* slot_id */
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

    case 0x6: { /*correct ENDPOINT_INFO message without signature*/
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

    case 0x7: { /*correct session based ENDPOINT_INFO message with signature*/
        spdm_endpoint_info_response_t *spdm_response;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
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

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);

        libspdm_transport_test_encode_message(spdm_context, &session_id, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Successful response to get a endpoint info with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_case1(void **state)
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

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        assert_int_equal (requester_nonce_in[index], requester_nonce[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_il1il2);
#endif
    free(data);
}

/**
 * Test 2: Successful response to get a endpoint info with signature,
 *         after getting SPDM_ERROR_CODE_BUSY on first attempt
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_case2(void **state)
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

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        assert_int_equal (requester_nonce_in[index], requester_nonce[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_il1il2);
#endif
    free(data);
}

/**
 * Test 3: Successful response to get a endpoint info with signature,
 *         after getting SPDM_ERROR_CODE_RESPONSE_NOT_READY on first attempt
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_case3(void **state)
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

    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
            assert_int_equal (requester_nonce_in[index], requester_nonce[index]);
        }
        /* Completion of GET_ENDPOINT_INFO sets IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#else
        assert_null(spdm_context->transcript.digest_context_il1il2);
#endif
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }
    free(data);
}

/**
 * Test 4: Successful response to get a endpoint info with signature with slot_id = 1
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_case4(void **state)
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP;
    libspdm_read_responder_public_certificate_chain_per_slot(1, m_libspdm_use_hash_algo,
                                                             m_libspdm_use_asym_algo, &data,
                                                             &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[1].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[1].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[1].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[1].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[1].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[1].leaf_cert_public_key);
#endif

    slot_id = 1;
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

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        assert_int_equal (requester_nonce_in[index], requester_nonce[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_il1il2);
#endif
    free(data);
}

/**
 * Test 5: Successful response to get a endpoint info with signature
 *         Using provisioned public key (slot_id = 0xF)
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
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
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
    libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data, &data_size);
    spdm_context->local_context.peer_public_key_provision = data;
    spdm_context->local_context.peer_public_key_provision_size = data_size;

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, NULL);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    slot_id = 0xF;
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

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        assert_int_equal (requester_nonce_in[index], requester_nonce[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_e.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_il1il2);
#endif
    free(data);
}

/**
 * Test 6: Successful response to get a endpoint info without signature
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
static void libspdm_test_requester_get_endpoint_info_case6(void **state)
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
    spdm_test_context->case_id = 0x6;
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

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 7: Successful response to get a session based endpoint info with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty session_transcript.message_e
 **/
static void libspdm_test_requester_get_endpoint_info_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
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
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_e(spdm_context, session_info);

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

    status = libspdm_get_endpoint_info(spdm_context, &session_id, request_attributes,
                                       sub_code, slot_id,
                                       &ep_info_length, ep_info_record,
                                       requester_nonce_in, requester_nonce,
                                       responder_nonce);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        assert_int_equal (requester_nonce_in[index], requester_nonce[index]);
    }
    /* Completion of GET_ENDPOINT_INFO sets IL1/IL2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_e.buffer_size, 0);
#else
    assert_null(session_info->session_transcript.digest_context_il1il2);
#endif
    free(data);
}

int libspdm_requester_get_endpoint_info_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_endpoint_info_tests[] = {
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_case1),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_case2),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_case3),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_case4),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_case5),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_case6),
        cmocka_unit_test(libspdm_test_requester_get_endpoint_info_case7),
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
