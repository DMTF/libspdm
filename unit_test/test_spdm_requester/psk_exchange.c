/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP

#define SPDM_BIN_STR_2_LABEL "rsp hs data"
#define SPDM_BIN_STR_7_LABEL "finished"

static uintn m_local_buffer_size;
static uint8_t m_local_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
static uint8_t m_local_psk_hint[32];

uintn spdm_test_get_psk_exchange_request_size(IN void *spdm_context,
                                              IN void *buffer,
                                              IN uintn buffer_size)
{
    spdm_psk_exchange_request_t *spdm_request;
    uintn message_size;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code != SPDM_PSK_EXCHANGE) {
        return buffer_size;
    }

    message_size = sizeof(spdm_psk_exchange_request_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    message_size += spdm_request->psk_hint_length +
                    spdm_request->context_length +
                    spdm_request->opaque_length;
    if (buffer_size < message_size) {
        return buffer_size;
    }

    /* Good message, return actual size*/
    return message_size;
}

return_status spdm_requester_psk_exchange_test_send_message(
    IN void *spdm_context, IN uintn request_size, IN void *request,
    IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;
    uintn header_size;
    uintn message_size;

    spdm_test_context = get_spdm_test_context();
    header_size = sizeof(test_message_header_t);
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;
    case 0x2:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x3:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x4:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x5:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x6:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x7:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x8:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0x9: {
        static uintn sub_index = 0;
        if (sub_index == 0) {
            m_local_buffer_size = 0;
            message_size = spdm_test_get_psk_exchange_request_size(
                spdm_context, (uint8_t *)request + header_size,
                request_size - header_size);
            copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                       (uint8_t *)request + header_size, message_size);
            m_local_buffer_size += message_size;
            sub_index++;
        }
    }
        return RETURN_SUCCESS;
    case 0xA:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    case 0xB:
        m_local_buffer_size = 0;
        message_size = spdm_test_get_psk_exchange_request_size(
            spdm_context, (uint8_t *)request + header_size,
            request_size - header_size);
        copy_mem_s(m_local_buffer, sizeof(m_local_buffer),
                   (uint8_t *)request + header_size, message_size);
        m_local_buffer_size += message_size;
        return RETURN_SUCCESS;
    default:
        return RETURN_DEVICE_ERROR;
    }
}

return_status spdm_requester_psk_exchange_test_receive_message(
    IN void *spdm_context, IN OUT uintn *response_size,
    IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;

    case 0x2: {
        spdm_psk_exchange_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        uintn opaque_psk_exchange_rsp_size;
        void *data;
        uintn data_size;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
        uint8_t bin_str2[128];
        uintn bin_str2_size;
        uint8_t bin_str7[128];
        uintn bin_str7_size;
        uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_use_hash_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_use_dhe_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            spdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        temp_buf_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                        LIBSPDM_PSK_CONTEXT_LENGTH +
                        opaque_psk_exchange_rsp_size + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            spdm_allocate_rsp_session_id(spdm_context);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        copy_mem_s(&m_local_buffer[m_local_buffer_size],
                   sizeof(m_local_buffer)
                   - (&m_local_buffer[m_local_buffer_size] - m_local_buffer),
                   spdm_response, (uintn)ptr - (uintn)spdm_response);
        m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
        DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
               m_local_buffer_size));
        internal_dump_hex(m_local_buffer, m_local_buffer_size);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        libspdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        zero_mem(m_local_psk_hint, 32);
        copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
                   TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_use_hash_algo, m_local_psk_hint,
                sizeof(TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x3: {
        spdm_psk_exchange_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        uintn opaque_psk_exchange_rsp_size;
        void *data;
        uintn data_size;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
        uint8_t bin_str2[128];
        uintn bin_str2_size;
        uint8_t bin_str7[128];
        uintn bin_str7_size;
        uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_use_hash_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_use_dhe_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            spdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        temp_buf_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                        LIBSPDM_PSK_CONTEXT_LENGTH +
                        opaque_psk_exchange_rsp_size + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            spdm_allocate_rsp_session_id(spdm_context);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        copy_mem_s(&m_local_buffer[m_local_buffer_size],
                   sizeof(m_local_buffer)
                   - (&m_local_buffer[m_local_buffer_size] - m_local_buffer),
                   spdm_response, (uintn)ptr - (uintn)spdm_response);
        m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
        DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
               m_local_buffer_size));
        internal_dump_hex(m_local_buffer, m_local_buffer_size);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        libspdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        zero_mem(m_local_psk_hint, 32);
        copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
                   TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_use_hash_algo, m_local_psk_hint,
                sizeof(TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x4: {
        spdm_error_response_t spdm_response;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x5: {
        spdm_error_response_t spdm_response;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x6: {
        static uintn sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t spdm_response;

            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
            sub_index1++;
        } else if (sub_index1 == 1) {
            spdm_psk_exchange_response_t *spdm_response;
            uint32_t hash_size;
            uint32_t hmac_size;
            uint8_t *ptr;
            uintn opaque_psk_exchange_rsp_size;
            void *data;
            uintn data_size;
            uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
            uint8_t *cert_buffer;
            uintn cert_buffer_size;
            uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
            large_managed_buffer_t th_curr;
            uint8_t bin_str2[128];
            uintn bin_str2_size;
            uint8_t bin_str7[128];
            uintn bin_str7_size;
            uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
            uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
            uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn temp_buf_size;

            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_use_asym_algo;
            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_use_hash_algo;
            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm.dhe_named_group =
                m_use_dhe_algo;
            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm
            .measurement_hash_algo =
                m_use_measurement_hash_algo;
            hash_size = libspdm_get_hash_size(m_use_hash_algo);
            hmac_size = libspdm_get_hash_size(m_use_hash_algo);
            opaque_psk_exchange_rsp_size =
                spdm_get_opaque_data_version_selection_data_size(
                    spdm_context);
            temp_buf_size = sizeof(spdm_psk_exchange_response_t) +
                            0 + LIBSPDM_PSK_CONTEXT_LENGTH +
                            opaque_psk_exchange_rsp_size +
                            hmac_size;
            spdm_response = (void *)temp_buf;

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_PSK_EXCHANGE_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->rsp_session_id =
                spdm_allocate_rsp_session_id(spdm_context);
            spdm_response->reserved = 0;
            spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
            spdm_response->opaque_length =
                (uint16_t)opaque_psk_exchange_rsp_size;
            ptr = (void *)(spdm_response + 1);
            /* zero_mem (ptr, hash_size);
             * ptr += hash_size;*/
            libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
            ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
            spdm_build_opaque_data_version_selection_data(
                spdm_context, &opaque_psk_exchange_rsp_size,
                ptr);
            ptr += opaque_psk_exchange_rsp_size;
            copy_mem_s(&m_local_buffer[m_local_buffer_size],
                       sizeof(m_local_buffer)
                       - (&m_local_buffer[m_local_buffer_size] - m_local_buffer),
                       spdm_response, (uintn)ptr - (uintn)spdm_response);
            m_local_buffer_size +=
                ((uintn)ptr - (uintn)spdm_response);
            DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
                   m_local_buffer_size));
            internal_dump_hex(m_local_buffer, m_local_buffer_size);
            init_managed_buffer(&th_curr,
                                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
            read_responder_public_certificate_chain(
                m_use_hash_algo, m_use_asym_algo, &data,
                &data_size, NULL, NULL);
            cert_buffer = (uint8_t *)data +
                          sizeof(spdm_cert_chain_t) + hash_size;
            cert_buffer_size =
                data_size -
                (sizeof(spdm_cert_chain_t) + hash_size);
            libspdm_hash_all(m_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            append_managed_buffer(&th_curr, m_local_buffer,
                                  m_local_buffer_size);
            libspdm_hash_all(m_use_hash_algo,
                             get_managed_buffer(&th_curr),
                             get_managed_buffer_size(&th_curr),
                             hash_data);
            free(data);
            bin_str2_size = sizeof(bin_str2);
            libspdm_bin_concat(SPDM_BIN_STR_2_LABEL,
                               sizeof(SPDM_BIN_STR_2_LABEL) - 1, hash_data,
                               (uint16_t)hash_size, hash_size, bin_str2,
                               &bin_str2_size);
            zero_mem(m_local_psk_hint, 32);
            copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
                       TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
            libspdm_psk_handshake_secret_hkdf_expand(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    m_use_hash_algo, m_local_psk_hint,
                    sizeof(TEST_PSK_HINT_STRING), bin_str2,
                    bin_str2_size, response_handshake_secret,
                    hash_size);
            bin_str7_size = sizeof(bin_str7);
            libspdm_bin_concat(SPDM_BIN_STR_7_LABEL,
                               sizeof(SPDM_BIN_STR_7_LABEL) - 1, NULL,
                               (uint16_t)hash_size, hash_size, bin_str7,
                               &bin_str7_size);
            libspdm_hkdf_expand(m_use_hash_algo,
                                response_handshake_secret, hash_size,
                                bin_str7, bin_str7_size,
                                response_finished_key, hash_size);
            libspdm_hmac_all(m_use_hash_algo,
                             get_managed_buffer(&th_curr),
                             get_managed_buffer_size(&th_curr),
                             response_finished_key, hash_size, ptr);
            ptr += hmac_size;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false, temp_buf_size,
                temp_buf, response_size, response);
        }
    }
        return RETURN_SUCCESS;

    case 0x7: {
        spdm_error_response_t spdm_response;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t spdm_response;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response.header.param2 = 0;
        spdm_response.extend_error_data.rd_exponent = 1;
        spdm_response.extend_error_data.rd_tm = 1;
        spdm_response.extend_error_data.request_code =
            SPDM_PSK_EXCHANGE;
        spdm_response.extend_error_data.token = 0;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x9: {
        static uintn sub_index2 = 0;
        if (sub_index2 == 0) {
            spdm_error_response_data_response_not_ready_t
                spdm_response;

            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response.header.param2 = 0;
            spdm_response.extend_error_data.rd_exponent = 1;
            spdm_response.extend_error_data.rd_tm = 1;
            spdm_response.extend_error_data.request_code =
                SPDM_PSK_EXCHANGE;
            spdm_response.extend_error_data.token = 1;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
            sub_index2++;
        } else if (sub_index2 == 1) {
            spdm_psk_exchange_response_t *spdm_response;
            uint32_t hash_size;
            uint32_t hmac_size;
            uint8_t *ptr;
            uintn opaque_psk_exchange_rsp_size;
            void *data;
            uintn data_size;
            uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
            uint8_t *cert_buffer;
            uintn cert_buffer_size;
            uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
            large_managed_buffer_t th_curr;
            uint8_t bin_str2[128];
            uintn bin_str2_size;
            uint8_t bin_str7[128];
            uintn bin_str7_size;
            uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
            uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
            uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn temp_buf_size;

            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_use_asym_algo;
            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_use_hash_algo;
            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm.dhe_named_group =
                m_use_dhe_algo;
            ((spdm_context_t *)spdm_context)
            ->connection_info.algorithm
            .measurement_hash_algo =
                m_use_measurement_hash_algo;
            hash_size = libspdm_get_hash_size(m_use_hash_algo);
            hmac_size = libspdm_get_hash_size(m_use_hash_algo);
            opaque_psk_exchange_rsp_size =
                spdm_get_opaque_data_version_selection_data_size(
                    spdm_context);
            temp_buf_size = sizeof(spdm_psk_exchange_response_t) +
                            0 + LIBSPDM_PSK_CONTEXT_LENGTH +
                            opaque_psk_exchange_rsp_size +
                            hmac_size;
            spdm_response = (void *)temp_buf;

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_PSK_EXCHANGE_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->rsp_session_id =
                spdm_allocate_rsp_session_id(spdm_context);
            spdm_response->reserved = 0;
            spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
            spdm_response->opaque_length =
                (uint16_t)opaque_psk_exchange_rsp_size;
            ptr = (void *)(spdm_response + 1);
            /* zero_mem (ptr, hash_size);
             * ptr += hash_size;*/
            libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
            ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
            spdm_build_opaque_data_version_selection_data(
                spdm_context, &opaque_psk_exchange_rsp_size,
                ptr);
            ptr += opaque_psk_exchange_rsp_size;
            copy_mem_s(&m_local_buffer[m_local_buffer_size],
                       sizeof(m_local_buffer)
                       - (&m_local_buffer[m_local_buffer_size] - m_local_buffer),
                       spdm_response, (uintn)ptr - (uintn)spdm_response);
            m_local_buffer_size +=
                ((uintn)ptr - (uintn)spdm_response);
            DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
                   m_local_buffer_size));
            internal_dump_hex(m_local_buffer, m_local_buffer_size);
            init_managed_buffer(&th_curr,
                                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
            read_responder_public_certificate_chain(
                m_use_hash_algo, m_use_asym_algo, &data,
                &data_size, NULL, NULL);
            cert_buffer = (uint8_t *)data +
                          sizeof(spdm_cert_chain_t) + hash_size;
            cert_buffer_size =
                data_size -
                (sizeof(spdm_cert_chain_t) + hash_size);
            libspdm_hash_all(m_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            append_managed_buffer(&th_curr, m_local_buffer,
                                  m_local_buffer_size);
            libspdm_hash_all(m_use_hash_algo,
                             get_managed_buffer(&th_curr),
                             get_managed_buffer_size(&th_curr),
                             hash_data);
            free(data);
            bin_str2_size = sizeof(bin_str2);
            libspdm_bin_concat(SPDM_BIN_STR_2_LABEL,
                               sizeof(SPDM_BIN_STR_2_LABEL) - 1, hash_data,
                               (uint16_t)hash_size, hash_size, bin_str2,
                               &bin_str2_size);
            zero_mem(m_local_psk_hint, 32);
            copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
                       TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
            libspdm_psk_handshake_secret_hkdf_expand(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    m_use_hash_algo, m_local_psk_hint,
                    sizeof(TEST_PSK_HINT_STRING), bin_str2,
                    bin_str2_size, response_handshake_secret,
                    hash_size);
            bin_str7_size = sizeof(bin_str7);
            libspdm_bin_concat(SPDM_BIN_STR_7_LABEL,
                               sizeof(SPDM_BIN_STR_7_LABEL) - 1, NULL,
                               (uint16_t)hash_size, hash_size, bin_str7,
                               &bin_str7_size);
            libspdm_hkdf_expand(m_use_hash_algo,
                                response_handshake_secret, hash_size,
                                bin_str7, bin_str7_size,
                                response_finished_key, hash_size);
            libspdm_hmac_all(m_use_hash_algo,
                             get_managed_buffer(&th_curr),
                             get_managed_buffer_size(&th_curr),
                             response_finished_key, hash_size, ptr);
            ptr += hmac_size;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false, temp_buf_size,
                temp_buf, response_size, response);
        }
    }
        return RETURN_SUCCESS;

    case 0xA:
    {
        static uint16_t error_code = SPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t spdm_response;

        if(error_code <= 0xff) {
            zero_mem (&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = (uint8_t) error_code;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                                sizeof(spdm_response), &spdm_response,
                                                response_size, response);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == SPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = SPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = SPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return RETURN_SUCCESS;

    case 0xB: {
        spdm_psk_exchange_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        uintn opaque_psk_exchange_rsp_size;
        void *data;
        uintn data_size;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
        uint8_t bin_str2[128];
        uintn bin_str2_size;
        uint8_t bin_str7[128];
        uintn bin_str7_size;
        uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_use_hash_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_use_dhe_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            spdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        temp_buf_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                        LIBSPDM_PSK_CONTEXT_LENGTH +
                        opaque_psk_exchange_rsp_size + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            spdm_allocate_rsp_session_id(spdm_context);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        copy_mem_s(&m_local_buffer[m_local_buffer_size],
                   sizeof(m_local_buffer)
                   - (&m_local_buffer[m_local_buffer_size] - m_local_buffer),
                   spdm_response, (uintn)ptr - (uintn)spdm_response);
        m_local_buffer_size += ((uintn)ptr - (uintn)spdm_response);
        DEBUG((DEBUG_INFO, "m_local_buffer_size (0x%x):\n",
               m_local_buffer_size));
        internal_dump_hex(m_local_buffer, m_local_buffer_size);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        libspdm_hash_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        zero_mem(m_local_psk_hint, 32);
        copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
                   TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_use_hash_algo, m_local_psk_hint,
                sizeof(TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    default:
        return RETURN_DEVICE_ERROR;
    }
}

void test_spdm_requester_psk_exchange_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

void test_spdm_requester_psk_exchange_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void test_spdm_requester_psk_exchange_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_UNSUPPORTED);
    free(data);
}

void test_spdm_requester_psk_exchange_case4(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

void test_spdm_requester_psk_exchange_case5(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_NO_RESPONSE);
    free(data);
}

void test_spdm_requester_psk_exchange_case6(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(session_id, 0xFFFEFFFE);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void test_spdm_requester_psk_exchange_case7(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
    free(data);
}

void test_spdm_requester_psk_exchange_case8(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

void test_spdm_requester_psk_exchange_case9(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(session_id, 0xFFFDFFFD);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void test_spdm_requester_psk_exchange_case10(void **state) {
    return_status status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t  *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    uintn data_size;
    void                 *hash;
    uintn hash_size;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                             &hash, &hash_size);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem (m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;

    error_code = SPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        libspdm_reset_message_a(spdm_context);

        heartbeat_period = 0;
        zero_mem(measurement_hash, sizeof(measurement_hash));
        status = spdm_send_receive_psk_exchange (spdm_context,
                                                 SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                 0,
                                                 &session_id, &heartbeat_period, measurement_hash);
        /* assert_int_equal (status, RETURN_DEVICE_ERROR);*/
        ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == SPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = SPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = SPDM_ERROR_CODE_RESERVED_FD;
        }
    }

    free(data);
}

void test_spdm_requester_psk_exchange_case11(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem_s(spdm_context->connection_info.peer_used_cert_chain_buffer,
               sizeof(spdm_context->connection_info.peer_used_cert_chain_buffer),
               data, data_size);
#endif
    zero_mem(m_local_psk_hint, 32);
    copy_mem_s(&m_local_psk_hint[0], sizeof(m_local_psk_hint),
               TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    spdm_context->local_context.psk_hint_size =
        sizeof(TEST_PSK_HINT_STRING);
    spdm_context->local_context.psk_hint = m_local_psk_hint;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    heartbeat_period = 0;
    zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_send_receive_psk_exchange(
        spdm_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data);
}

spdm_test_context_t m_spdm_requester_psk_exchange_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_requester_psk_exchange_test_send_message,
    spdm_requester_psk_exchange_test_receive_message,
};

int spdm_requester_psk_exchange_test_main(void)
{
    const struct CMUnitTest spdm_requester_psk_exchange_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case1),
        /* Successful response*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case2),
        /* connection_state check failed*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case9),
        /* Unexpected errors*/
        cmocka_unit_test(test_spdm_requester_psk_exchange_case10),
    };

    setup_spdm_test_context(&m_spdm_requester_psk_exchange_test_context);

    return cmocka_run_group_tests(spdm_requester_psk_exchange_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP*/
