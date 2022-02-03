/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

static uintn m_local_buffer_size;
static uint8_t m_local_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

void spdm_secured_message_set_response_finished_key(
    IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
    spdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    ASSERT(key_size == secured_message_context->hash_size);
    copy_mem(
        secured_message_context->handshake_secret.response_finished_key,
        key, secured_message_context->hash_size);
    secured_message_context->finished_key_ready = true;
}

return_status spdm_requester_finish_test_send_message(IN void *spdm_context,
                                                      IN uintn request_size,
                                                      IN void *request,
                                                      IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;
    uint8_t *ptr;

    spdm_test_context = get_spdm_test_context();
    ptr = (uint8_t *)request;
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;
    case 0x2:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x3:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x4:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x5:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x6:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x7:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x8:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x9: {
        static uintn sub_index = 0;
        if (sub_index == 0) {
            m_local_buffer_size = 0;
            copy_mem(m_local_buffer, &ptr[1], request_size - 1);
            m_local_buffer_size += (request_size - 1);
            sub_index++;
        }
    }
        return RETURN_SUCCESS;
    case 0xA:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0xB:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0xC:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0xD:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0xE:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0xF:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x10:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x11:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x12:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x13:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    case 0x14:
        m_local_buffer_size = 0;
        copy_mem(m_local_buffer, &ptr[1], request_size - 1);
        m_local_buffer_size += (request_size - 1);
        return RETURN_SUCCESS;
    default:
        return RETURN_DEVICE_ERROR;
    }
}

return_status spdm_requester_finish_test_receive_message(
    IN void *spdm_context, IN OUT uintn *response_size,
    IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;

    case 0x2: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x3: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

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
            spdm_finish_response_t *spdm_response;
            uint32_t hash_size;
            uint32_t hmac_size;
            uint8_t *ptr;
            void *data;
            uintn data_size;
            uint8_t *cert_buffer;
            uintn cert_buffer_size;
            uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
            large_managed_buffer_t th_curr;
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
            temp_buf_size =
                sizeof(spdm_finish_response_t) + hmac_size;
            spdm_response = (void *)temp_buf;

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_FINISH_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            ptr = (void *)(spdm_response + 1);
            copy_mem(&m_local_buffer[m_local_buffer_size],
                     spdm_response, sizeof(spdm_finish_response_t));
            m_local_buffer_size += sizeof(spdm_finish_response_t);
            read_responder_public_certificate_chain(
                m_use_hash_algo, m_use_asym_algo, &data,
                &data_size, NULL, NULL);
            init_managed_buffer(&th_curr,
                                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
            cert_buffer = (uint8_t *)data;
            cert_buffer_size = data_size;
            libspdm_hash_all(m_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            append_managed_buffer(&th_curr, cert_buffer_hash,
                                  hash_size);
            /* session_transcript.message_k is 0*/
            append_managed_buffer(&th_curr, m_local_buffer,
                                  m_local_buffer_size);
            set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE,
                    (uint8_t)(0xFF));
            libspdm_hmac_all(m_use_hash_algo,
                             get_managed_buffer(&th_curr),
                             get_managed_buffer_size(&th_curr),
                             response_finished_key, hash_size, ptr);
            ptr += hmac_size;
            free(data);

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
        spdm_response.extend_error_data.request_code = SPDM_FINISH;
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
                SPDM_FINISH;
            spdm_response.extend_error_data.token = 1;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
            sub_index2++;
        } else if (sub_index2 == 1) {
            spdm_finish_response_t *spdm_response;
            uint32_t hash_size;
            uint32_t hmac_size;
            uint8_t *ptr;
            void *data;
            uintn data_size;
            uint8_t *cert_buffer;
            uintn cert_buffer_size;
            uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
            large_managed_buffer_t th_curr;
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
            temp_buf_size =
                sizeof(spdm_finish_response_t) + hmac_size;
            spdm_response = (void *)temp_buf;

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_FINISH_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            ptr = (void *)(spdm_response + 1);
            copy_mem(&m_local_buffer[m_local_buffer_size],
                     spdm_response, sizeof(spdm_finish_response_t));
            m_local_buffer_size += sizeof(spdm_finish_response_t);
            read_responder_public_certificate_chain(
                m_use_hash_algo, m_use_asym_algo, &data,
                &data_size, NULL, NULL);
            init_managed_buffer(&th_curr,
                                LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
            cert_buffer = (uint8_t *)data;
            cert_buffer_size = data_size;
            libspdm_hash_all(m_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            append_managed_buffer(&th_curr, cert_buffer_hash,
                                  hash_size);
            /* session_transcript.message_k is 0*/
            append_managed_buffer(&th_curr, m_local_buffer,
                                  m_local_buffer_size);
            set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE,
                    (uint8_t)(0xFF));
            libspdm_hmac_all(m_use_hash_algo,
                             get_managed_buffer(&th_curr),
                             get_managed_buffer_size(&th_curr),
                             response_finished_key, hash_size, ptr);
            ptr += hmac_size;
            free(data);

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
    case 0xB:
    {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0xC: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0xD: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0xE: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        /*wrong response code*/
        spdm_response->header.request_response_code = SPDM_FINISH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0xF: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x10: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.req_base_asym_alg =
            m_use_req_asym_algo;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        read_requester_public_certificate_chain(m_use_hash_algo,
                                                m_use_req_asym_algo, &data,
                                                &data_size, NULL, NULL);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         req_cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, req_cert_buffer_hash,
                              hash_size);
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x11: {
        spdm_finish_response_t *spdm_response;
        uint32_t hmac_size;
        uint8_t *ptr;
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.req_base_asym_alg =
            m_use_req_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_use_hash_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_use_dhe_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_use_measurement_hash_algo;
        hmac_size = libspdm_get_hash_size(m_use_hash_algo);
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        set_mem(ptr, hmac_size, (uint8_t)(0x00)); /*all-zero MAC*/
        ptr += hmac_size;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x12: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t zero_data[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.req_base_asym_alg =
            m_use_req_asym_algo;
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
        temp_buf_size = sizeof(spdm_finish_response_t) + hmac_size;
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        set_mem(zero_data, hash_size, (uint8_t)(0x00));
        libspdm_hmac_all(m_use_hash_algo, zero_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x13: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.req_base_asym_alg =
            m_use_req_asym_algo;
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
        temp_buf_size = sizeof(spdm_finish_response_t) +
                        2*hmac_size; /* 2x HMAC size*/
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        read_requester_public_certificate_chain(m_use_hash_algo,
                                                m_use_req_asym_algo, &data,
                                                &data_size, NULL, NULL);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         req_cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, req_cert_buffer_hash,
                              hash_size);
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        copy_mem(ptr, ptr + hmac_size, hmac_size); /* 2x HMAC size*/
        ptr += 2*hmac_size;
        free(data);

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, temp_buf_size,
                                           temp_buf, response_size,
                                           response);
    }
        return RETURN_SUCCESS;

    case 0x14: {
        spdm_finish_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *data;
        uintn data_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        large_managed_buffer_t th_curr;
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];
        uint8_t temp_buf[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn temp_buf_size;

        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_use_asym_algo;
        ((spdm_context_t *)spdm_context)
        ->connection_info.algorithm.req_base_asym_alg =
            m_use_req_asym_algo;
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
        temp_buf_size = sizeof(spdm_finish_response_t) +
                        hmac_size/2;/* half HMAC size*/
        spdm_response = (void *)temp_buf;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        copy_mem(&m_local_buffer[m_local_buffer_size], spdm_response,
                 sizeof(spdm_finish_response_t));
        m_local_buffer_size += sizeof(spdm_finish_response_t);
        read_responder_public_certificate_chain(m_use_hash_algo,
                                                m_use_asym_algo, &data,
                                                &data_size, NULL, NULL);
        init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        read_requester_public_certificate_chain(m_use_hash_algo,
                                                m_use_req_asym_algo, &data,
                                                &data_size, NULL, NULL);
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
                         req_cert_buffer_hash);
        /* transcript.message_a size is 0*/
        append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        /* session_transcript.message_k is 0*/
        append_managed_buffer(&th_curr, req_cert_buffer_hash,
                              hash_size);
        append_managed_buffer(&th_curr, m_local_buffer,
                              m_local_buffer_size);
        set_mem(response_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
        libspdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
                         get_managed_buffer_size(&th_curr),
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size/2; /* half HMAC size*/
        set_mem(ptr, hmac_size/2, (uint8_t) 0x00);
        free(data);

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

/**
 * Test 1: when no FINISH_RSP message is received, and the client returns a
 * device error.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_finish_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 2: receiving a correct FINISH_RSP message with only MAC (no
 * mutual authentication) and 'handshake in the clear'.
 * Expected behavior: client returns a Status of RETURN_SUCCESS and
 * session is established.
 **/
void test_spdm_requester_finish_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

/**
 * Test 3: requester state has not been negotiated, as if GET_VERSION, GET_CAPABILITIES and
 * NEGOTIATE_ALGORITHMS had not been exchanged.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void test_spdm_requester_finish_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_UNSUPPORTED);
    free(data);
}

/**
 * Test 4: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating InvalidParameters.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_finish_case4(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 5: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the Busy status of the responder.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_finish_case5(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_NO_RESPONSE);
    free(data);
}

/**
 * Test 6: the requester is setup correctly (see Test 2), but, on the first try,
 * receiving a Busy ERROR message, and on retry, receiving a correct FINISH_RSP
 * message with only MAC (no mutual authentication).
 * Expected behavior: client returns a Status of RETURN_SUCCESS.
 **/
void test_spdm_requester_finish_case6(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

/**
 * Test 7: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the RequestResynch status of the responder.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
 * communication is reset to expect a new GET_VERSION message.
 **/
void test_spdm_requester_finish_case7(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
    free(data);
}

/**
 * Test 8: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the ResponseNotReady status of the responder.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR,.
 **/
void test_spdm_requester_finish_case8(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 9: the requester is setup correctly (see Test 2), but, on the first try,
 * receiving a ResponseNotReady ERROR message, and on retry, receiving a correct
 * FINISH_RSP message with only MAC (no mutual authentication).
 * Expected behavior: client returns a Status of RETURN_SUCCESS.
 **/
void test_spdm_requester_finish_case9(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

/**
 * Test 10: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_finish_case10(void **state) {
    return_status status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t  *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void                 *data;
    uintn data_size;
    void                 *hash;
    uintn hash_size;
    spdm_session_info_t    *session_info;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size,
                                             &hash, &hash_size);
    spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size = data_size;
    copy_mem (spdm_context->connection_info.peer_used_cert_chain_buffer, data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;

    error_code = SPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        libspdm_reset_message_a(spdm_context);

        session_info = &spdm_context->session_info[0];
        spdm_session_info_init (spdm_context, session_info, session_id, false);
        hash_size = libspdm_get_hash_size (m_use_hash_algo);
        set_mem (m_dummy_buffer, hash_size, (uint8_t)(0xFF));
        spdm_secured_message_set_response_finished_key (session_info->secured_message_context,
                                                        m_dummy_buffer, hash_size);
        libspdm_secured_message_set_session_state (session_info->secured_message_context,
                                                   LIBSPDM_SESSION_STATE_HANDSHAKING);

        status = spdm_send_receive_finish (spdm_context, session_id, req_slot_id_param);
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

void test_spdm_requester_finish_case11(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size,
                     0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 12: requester is not setup correctly to support key exchange
 * (no capabilities). The responder would attempt to return a correct
 * FINISH_RSP message.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void test_spdm_requester_finish_case12(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags = 0;
    /* no key exchange capabilities (requester)*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_UNSUPPORTED);
    free(data);
}

/**
 * Test 13: requester is not setup correctly to accept key exchange and
 * finish at this point (at least NEGOTIATE_ALGORITHMS is required, if
 * the public key was provisioned before the key exchange). The
 * responder would attempt to return a correct FINISH_RSP message.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void test_spdm_requester_finish_case13(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_UNSUPPORTED);
    free(data);
}

/**
 * Test 14: receiving an incorrect FINISH_RSP message, with wrong response
 * code, but all other field correct.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_finish_case14(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 15: requester is not setup correctly by not initializing a
 * session during KEY_EXCHANGE. The responder would attempt to
 * return a correct FINISH_RSP message.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void test_spdm_requester_finish_case15(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
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
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_NOT_STARTED);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    req_slot_id_param = 0;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_UNSUPPORTED);
    free(data);
}

/**
 * Test 16: receiving a correct FINISH_RSP message with a correct MAC,
 * mutual authentication and 'handshake in the clear'.
 * Expected behavior: client returns a Status of RETURN_SUCCESS and
 * session is established.
 **/
void test_spdm_requester_finish_case16(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    req_slot_id_param = 0;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    spdm_context->local_context.
    local_cert_chain_provision_size[req_slot_id_param] = data_size;
    spdm_context->local_context.
    local_cert_chain_provision[req_slot_id_param] = data;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.slot_count = 1;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

/**
 * Test 17: receiving a FINISH_RSP message with an incorrect MAC
 * (all-zero), mutual authentication, and 'handshake in the clear'.
 * Expected behavior: client returns a Status of RETURN_SECURITY_VIOLATION.
 **/
void test_spdm_requester_finish_case17(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    req_slot_id_param = 0;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    spdm_context->local_context.
    local_cert_chain_provision_size[req_slot_id_param] = data_size;
    spdm_context->local_context.
    local_cert_chain_provision[req_slot_id_param] = data;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.slot_count = 1;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
    free(data);
}

/**
 * Test 18: receiving a FINISH_RSP message with an incorrect MAC
 * (arbitrary), mutual authentication, and 'handshake in the clear'.
 * Expected behavior: client returns a Status of RETURN_SECURITY_VIOLATION.
 **/
void test_spdm_requester_finish_case18(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    req_slot_id_param = 0;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    spdm_context->local_context.
    local_cert_chain_provision_size[req_slot_id_param] = data_size;
    spdm_context->local_context.
    local_cert_chain_provision[req_slot_id_param] = data;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.slot_count = 1;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
    free(data);
}

/**
 * Test 19: receiving a FINISH_RSP message with an incorrect MAC size (a
 * correct MAC repeated twice), mutual authentication, and 'handshake in
 * the clear'.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_finish_case19(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    req_slot_id_param = 0;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    spdm_context->local_context.
    local_cert_chain_provision_size[req_slot_id_param] = data_size;
    spdm_context->local_context.
    local_cert_chain_provision[req_slot_id_param] = data;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.slot_count = 1;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 20: receiving a FINISH_RSP message an incorrect MAC size (only the
 * correct first half of the MAC), mutual authentication, and 'handshake
 * in the clear'.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_finish_case20(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t req_slot_id_param;
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    spdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                                            m_use_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_use_req_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
             data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain_buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_leaf_cert_public_key);
#endif

    req_slot_id_param = 0;
    read_requester_public_certificate_chain(m_use_hash_algo,
                                            m_use_req_asym_algo, &data,
                                            &data_size, &hash, &hash_size);
    spdm_context->local_context.
    local_cert_chain_provision_size[req_slot_id_param] = data_size;
    spdm_context->local_context.
    local_cert_chain_provision[req_slot_id_param] = data;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_use_hash_algo);
    set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    spdm_secured_message_set_response_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.slot_count = 1;
    status = spdm_send_receive_finish(spdm_context, session_id,
                                      req_slot_id_param);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

spdm_test_context_t m_spdm_requester_finish_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_requester_finish_test_send_message,
    spdm_requester_finish_test_receive_message,
};

int spdm_requester_finish_test_main(void)
{
    const struct CMUnitTest spdm_requester_finish_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(test_spdm_requester_finish_case1),
        /* Successful response*/
        cmocka_unit_test(test_spdm_requester_finish_case2),
        /* connection_state check failed*/
        cmocka_unit_test(test_spdm_requester_finish_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_requester_finish_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(test_spdm_requester_finish_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(test_spdm_requester_finish_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(test_spdm_requester_finish_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(test_spdm_requester_finish_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(test_spdm_requester_finish_case9),
        /* Unexpected errors*/
        cmocka_unit_test(test_spdm_requester_finish_case10),
        /* Buffer reset*/
        cmocka_unit_test(test_spdm_requester_finish_case11),
        /* No correct setup*/
        cmocka_unit_test(test_spdm_requester_finish_case12),
        cmocka_unit_test(test_spdm_requester_finish_case13),
        cmocka_unit_test(test_spdm_requester_finish_case14),
        cmocka_unit_test(test_spdm_requester_finish_case15),
        /* Successful response*/
        cmocka_unit_test(test_spdm_requester_finish_case16),
        /* Response with invalid MAC*/
        cmocka_unit_test(test_spdm_requester_finish_case17),
        cmocka_unit_test(test_spdm_requester_finish_case18),
        /* Response with invalid MAC size*/
        cmocka_unit_test(test_spdm_requester_finish_case19),
        cmocka_unit_test(test_spdm_requester_finish_case20),
    };

    setup_spdm_test_context(&m_spdm_requester_finish_test_context);

    return cmocka_run_group_tests(spdm_requester_finish_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
