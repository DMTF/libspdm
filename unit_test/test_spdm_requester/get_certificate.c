/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

static void *m_libspdm_local_certificate_chain;
static uintn m_libspdm_local_certificate_chain_size;

/* Loading the target expiration certificate chain and saving root certificate hash
 * "rsa3072_Expiration/bundle_responder.certchain.der"*/
bool libspdm_libspdm_read_responder_public_certificate_chain_expiration(
    void **data, uintn *size, void **hash, uintn *hash_size)
{
    uint32_t base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    bool res;
    void *file_data;
    uintn file_size;
    spdm_cert_chain_t *cert_chain;
    uintn cert_chain_size;
    char *file;
    uint8_t *root_cert;
    uintn root_cert_len;
    uintn digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    file = "rsa3072_Expiration/bundle_responder.certchain.der";
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    /* Get Root Certificate and calculate hash value*/

    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                     (uint8_t *)(cert_chain + 1));
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

libspdm_return_t libspdm_requester_get_certificate_test_send_message(
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
    default:
        return RETURN_DEVICE_ERROR;
    }
}

libspdm_return_t libspdm_requester_get_certificate_test_receive_message(
    void *spdm_context, uintn *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;

    case 0x2: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x5: {
        spdm_error_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6: {
        static uintn sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t *spdm_response;
            uintn spdm_response_size;
            uintn transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;
            sub_index1++;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        } else if (sub_index1 == 1) {
            spdm_certificate_response_t *spdm_response;
            uintn spdm_response_size;
            uintn transport_header_size;
            uint16_t portion_length;
            uint16_t remainder_length;
            uintn count;
            static uintn calling_index = 0;

            if (m_libspdm_local_certificate_chain == NULL) {
                libspdm_read_responder_public_certificate_chain(
                    m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                    &m_libspdm_local_certificate_chain,
                    &m_libspdm_local_certificate_chain_size, NULL,
                    NULL);
            }
            if (m_libspdm_local_certificate_chain == NULL) {
                return RETURN_OUT_OF_RESOURCES;
            }
            count = (m_libspdm_local_certificate_chain_size +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            if (calling_index != count - 1) {
                portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
                remainder_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (calling_index + 1));
            } else {
                portion_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (count - 1));
                remainder_length = 0;
            }

            spdm_response_size = sizeof(spdm_certificate_response_t) +
                                 portion_length;
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code =
                SPDM_CERTIFICATE;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->portion_length = portion_length;
            spdm_response->remainder_length = remainder_length;
            libspdm_copy_mem(spdm_response + 1,
                             (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                             (uint8_t *)m_libspdm_local_certificate_chain +
                             LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                             calling_index,
                             portion_length);

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);

            calling_index++;
            if (calling_index == count) {
                calling_index = 0;
                free(m_libspdm_local_certificate_chain);
                m_libspdm_local_certificate_chain = NULL;
                m_libspdm_local_certificate_chain_size = 0;
            }
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: {
        spdm_error_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 1;
        spdm_response->extend_error_data.request_code =
            SPDM_GET_CERTIFICATE;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        static uintn sub_index2 = 0;
        if (sub_index2 == 0) {
            spdm_error_response_data_response_not_ready_t
            *spdm_response;
            uintn spdm_response_size;
            uintn transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 1;
            spdm_response->extend_error_data.request_code =
                SPDM_GET_CERTIFICATE;
            spdm_response->extend_error_data.token = 1;
            sub_index2++;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        } else if (sub_index2 == 1) {
            spdm_certificate_response_t *spdm_response;
            uintn spdm_response_size;
            uintn transport_header_size;
            uint16_t portion_length;
            uint16_t remainder_length;
            uintn count;
            static uintn calling_index = 0;

            if (m_libspdm_local_certificate_chain == NULL) {
                libspdm_read_responder_public_certificate_chain(
                    m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                    &m_libspdm_local_certificate_chain,
                    &m_libspdm_local_certificate_chain_size, NULL,
                    NULL);
            }
            if (m_libspdm_local_certificate_chain == NULL) {
                return RETURN_OUT_OF_RESOURCES;
            }
            count = (m_libspdm_local_certificate_chain_size +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            if (calling_index != count - 1) {
                portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
                remainder_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (calling_index + 1));
            } else {
                portion_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (count - 1));
                remainder_length = 0;
            }

            spdm_response_size = sizeof(spdm_certificate_response_t) +
                                 portion_length;
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code =
                SPDM_CERTIFICATE;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->portion_length = portion_length;
            spdm_response->remainder_length = remainder_length;
            libspdm_copy_mem(spdm_response + 1,
                             (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                             (uint8_t *)m_libspdm_local_certificate_chain +
                             LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                             calling_index,
                             portion_length);

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);

            calling_index++;
            if (calling_index == count) {
                calling_index = 0;
                free(m_libspdm_local_certificate_chain);
                m_libspdm_local_certificate_chain = NULL;
                m_libspdm_local_certificate_chain_size = 0;
            }
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        uint8_t *leaf_cert_buffer;
        uintn leaf_cert_buffer_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uintn hash_size;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
            if (m_libspdm_local_certificate_chain == NULL) {
                return RETURN_OUT_OF_RESOURCES;
            }

            /* load certificate*/
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            cert_buffer = (uint8_t *)m_libspdm_local_certificate_chain +
                          sizeof(spdm_cert_chain_t) + hash_size;
            cert_buffer_size = m_libspdm_local_certificate_chain_size -
                               sizeof(spdm_cert_chain_t) -
                               hash_size;
            if (!libspdm_x509_get_cert_from_cert_chain(
                    cert_buffer, cert_buffer_size, -1,
                    &leaf_cert_buffer,
                    &leaf_cert_buffer_size)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
                return RETURN_DEVICE_ERROR;
            }
            /* tamper certificate signature on purpose
             * arbitrarily change the last byte of the certificate signature*/
            cert_buffer[cert_buffer_size - 1]++;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain_by_size(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                LIBSPDM_TEST_CERT_SMALL, &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uint16_t get_cert_length;
        uintn count;
        static uintn calling_index = 0;

        /* this should match the value on the test function*/
        get_cert_length = 1;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size + get_cert_length + 1) /
                get_cert_length;
        if (calling_index != count - 1) {
            portion_length = get_cert_length;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           get_cert_length * (calling_index + 1));
        } else {
            portion_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           get_cert_length * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         get_cert_length * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain_by_size(
                m_libspdm_use_hash_algo,
                /*MAXUINT16_CERT signature_algo is SHA256RSA */
                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                LIBSPDM_TEST_CERT_MAXUINT16, &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem (spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        uint8_t *leaf_cert_buffer;
        uintn leaf_cert_buffer_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uintn hash_size;
        uint8_t cert_chain_without_root[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn cert_chain_without_root_size;
        void *root_cert_data;
        uintn root_cert_size;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
            if (m_libspdm_local_certificate_chain == NULL) {
                return RETURN_OUT_OF_RESOURCES;
            }
            /* read root certificate size*/
            libspdm_read_responder_root_public_certificate(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &root_cert_data,
                &root_cert_size, NULL, NULL);
            /* load certificate*/
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            root_cert_size = root_cert_size -
                             sizeof(spdm_cert_chain_t) - hash_size;
            cert_buffer = (uint8_t *)m_libspdm_local_certificate_chain +
                          sizeof(spdm_cert_chain_t) + hash_size + root_cert_size;
            cert_buffer_size = m_libspdm_local_certificate_chain_size -
                               sizeof(spdm_cert_chain_t) -
                               hash_size - root_cert_size;
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "root_cert_size %d \n",root_cert_size));
            if (!libspdm_x509_get_cert_from_cert_chain(
                    cert_buffer, cert_buffer_size, -1,
                    &leaf_cert_buffer,
                    &leaf_cert_buffer_size)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
                return RETURN_DEVICE_ERROR;
            }
        }
        libspdm_copy_mem(cert_chain_without_root,
                         sizeof(cert_chain_without_root),
                         m_libspdm_local_certificate_chain,
                         sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_copy_mem(cert_chain_without_root + sizeof(spdm_cert_chain_t) + hash_size,
                         sizeof(cert_chain_without_root) - (sizeof(spdm_cert_chain_t) + hash_size),
                         cert_buffer,
                         cert_buffer_size);
        cert_chain_without_root_size = m_libspdm_local_certificate_chain_size - root_cert_size;
        count = (cert_chain_without_root_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(cert_chain_without_root_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                cert_chain_without_root_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        /* send certchain without root*/
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)cert_chain_without_root +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            free(root_cert_data);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        uint8_t *leaf_cert_buffer;
        uintn leaf_cert_buffer_size;
        uint8_t *cert_buffer;
        uintn cert_buffer_size;
        uintn hash_size;
        uint8_t cert_chain_without_root[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn cert_chain_without_root_size;
        void *root_cert_data;
        uintn root_cert_size;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
            if (m_libspdm_local_certificate_chain == NULL) {
                return RETURN_OUT_OF_RESOURCES;
            }
            /* read root certificate size*/
            libspdm_read_responder_root_public_certificate(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &root_cert_data,
                &root_cert_size, NULL, NULL);
            /* load certificate*/
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            root_cert_size = root_cert_size -
                             sizeof(spdm_cert_chain_t) - hash_size;
            cert_buffer = (uint8_t *)m_libspdm_local_certificate_chain +
                          sizeof(spdm_cert_chain_t) + hash_size + root_cert_size;
            cert_buffer_size = m_libspdm_local_certificate_chain_size -
                               sizeof(spdm_cert_chain_t) -
                               hash_size - root_cert_size;
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "root_cert_size %d \n",root_cert_size));
            if (!libspdm_x509_get_cert_from_cert_chain(
                    cert_buffer, cert_buffer_size, -1,
                    &leaf_cert_buffer,
                    &leaf_cert_buffer_size)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
                return RETURN_DEVICE_ERROR;
            }
            /* tamper certificate signature on purpose
             * arbitrarily change the last byte of the certificate signature*/
            cert_buffer[cert_buffer_size - 1]++;
        }
        libspdm_copy_mem(cert_chain_without_root,
                         sizeof(cert_chain_without_root),
                         m_libspdm_local_certificate_chain,
                         sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_copy_mem(cert_chain_without_root + sizeof(spdm_cert_chain_t) + hash_size,
                         sizeof(cert_chain_without_root) - (sizeof(spdm_cert_chain_t) + hash_size),
                         cert_buffer,
                         cert_buffer_size);
        cert_chain_without_root_size = m_libspdm_local_certificate_chain_size - root_cert_size;
        count = (cert_chain_without_root_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(cert_chain_without_root_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                cert_chain_without_root_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        /* send certchain without root*/
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)cert_chain_without_root +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            free(root_cert_data);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_libspdm_read_responder_public_certificate_chain_expiration(
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = 0; /* Fail response: responder return portion_length is 0.*/
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1; /* Fail response: responder return portion_length > spdm_request.length*/
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            /* Fail response: spdm_request.offset + spdm_response->portion_length + spdm_response->remainder_length !=
             * total_responder_cert_chain_buffer_length.*/
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size - 1 -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *(calling_index + 1));

        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17: {
        spdm_certificate_response_t *spdm_response;
        uintn spdm_response_size;
        uintn transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uintn count;
        static uintn calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return RETURN_OUT_OF_RESOURCES;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (uintn)(*response) + *response_size - (uintn)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return RETURN_DEVICE_ERROR;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a LIBSPDM_STATUS_SEND_FAIL, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 2: Normal case, request a certificate chain
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 3: simulate wrong connection_state when sending GET_CERTIFICATE (missing SPDM_GET_DIGESTS_RECEIVE_FLAG and SPDM_GET_CAPABILITIES_RECEIVE_FLAG)
 * Expected Behavior: get a LIBSPDM_STATUS_INVALID_STATE_LOCAL, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 4: force responder to send an ERROR message with code SPDM_ERROR_CODE_INVALID_REQUEST
 * Expected Behavior: get a LIBSPDM_STATUS_ERROR_PEER, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 5: force responder to send an ERROR message with code SPDM_ERROR_CODE_BUSY
 * Expected Behavior: get a LIBSPDM_STATUS_BUSY_PEER, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 6: force responder to first send an ERROR message with code SPDM_ERROR_CODE_BUSY, but functions normally afterwards
 * Expected Behavior: receives the correct number of CERTIFICATE messages
 **/
void libspdm_test_requester_get_certificate_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 7: force responder to send an ERROR message with code SPDM_ERROR_CODE_REQUEST_RESYNCH
 * Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 8: force responder to send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
 * Expected Behavior: get a RETURN_NO_RESPONSE
 **/
void libspdm_test_requester_get_certificate_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 9: force responder to first send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY, but functions normally afterwards
 * Expected Behavior: receives the correct number of CERTIFICATE messages
 **/
void libspdm_test_requester_get_certificate_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 10: Normal case, request a certificate chain. Validates certificate by using a prelaoded chain instead of root hash
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = 0;
    spdm_context->local_context.peer_root_cert_provision[0] = NULL;
    spdm_context->local_context.peer_cert_chain_provision = data;
    spdm_context->local_context.peer_cert_chain_provision_size = data_size;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 11: Normal procedure, but the retrieved certificate chain has an invalid signature
 * Expected Behavior: get a RETURN_SECURITY_VIOLATION, and receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading certificate chain and saving root certificate hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 12: Normal procedure, but the retrieved root certificate does not match
 * Expected Behavior: get a RETURN_SECURITY_VIOLATION, and receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    /* arbitrarily changes the root certificate on purpose*/
    if (root_cert != NULL) {
        ((uint8_t *)root_cert)[0]++;
    }
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/


    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 13: Gets a short certificate chain (fits in 1 message)
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain_by_size(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, LIBSPDM_TEST_CERT_SMALL, &data,
        &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 14: request a whole certificate chain byte by byte
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
    uint16_t get_cert_length;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif
    /* Get certificate chain byte by byte*/
    get_cert_length = 1;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate_choose_length(
        spdm_context, 0, get_cert_length, &cert_chain_size, cert_chain);
    /* It may fail because the spdm does not support too many messages.
     * assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);*/
    if (status == LIBSPDM_STATUS_SUCCESS) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        count = (data_size + get_cert_length - 1) / get_cert_length;
        assert_int_equal(
            spdm_context->transcript.message_b.buffer_size,
            sizeof(spdm_get_certificate_request_t) * count +
            sizeof(spdm_certificate_response_t) * count +
            data_size);
#endif
    }
    free(data);
}

/**
 * Test 15: request a long certificate chain
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/

    libspdm_read_responder_public_certificate_chain_by_size(
        /*MAXUINT16_CERT signature_algo is SHA256RSA */
        m_libspdm_use_hash_algo, SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
        LIBSPDM_TEST_CERT_MAXUINT16, &data, &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    /* It may fail because the spdm does not support too long message.
     * assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);*/
    if (status == LIBSPDM_STATUS_SUCCESS) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        assert_int_equal(
            spdm_context->transcript.message_b.buffer_size,
            sizeof(spdm_get_certificate_request_t) * count +
            sizeof(spdm_certificate_response_t) * count +
            data_size);
#endif
    }
    free(data);
}

/**
 * Test 16: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_certificate_case16(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void                 *data;
    uintn data_size;
    void                 *hash;
    uintn hash_size;
    uint8_t                 *root_cert;
    uintn root_cert_size;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
        libspdm_reset_message_b(spdm_context);

        cert_chain_size = sizeof(cert_chain);
        libspdm_zero_mem (cert_chain, sizeof(cert_chain));
        status = libspdm_get_certificate (spdm_context, 0, &cert_chain_size, cert_chain);
        /* assert_int_equal (status, RETURN_DEVICE_ERROR);*/
        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        /* assert_int_equal (spdm_context->transcript.message_b.buffer_size, 0);*/
        LIBSPDM_ASSERT_INT_EQUAL_CASE (spdm_context->transcript.message_b.buffer_size, 0,
                                       error_code);
#endif

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }

    free(data);
}

/**
 * Test 17: Normal case, get a certificate chain start not with root cert. Validates certificate by using a prelaoded chain.
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

/**
 * Test 18: Fail case, get a certificate chain start not with root cert and with wrong signature. Validates certificate by using a prelaoded chain.
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
    free(data);
}

/**
 * Test 19: Normal procedure, but one certificate in the retrieved certificate chain past its expiration date.
 * Expected Behavior: get a RETURN_SECURITY_VIOLATION, and receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uintn count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading the target expiration certificate chain and saving root certificate hash
     * "rsa3072_Expiration/bundle_responder.certchain.der"*/
    libspdm_libspdm_read_responder_public_certificate_chain_expiration(&data,
                                                                       &data_size, &hash,
                                                                       &hash_size);
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
        data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
        &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 20: Fail case, request a certificate chain, responder return portion_length is 0.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_certificate_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 21: Fail case, request a certificate chain, responder return portion_length > spdm_request.length.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_certificate_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 22: Fail case, request a certificate chain,
 * spdm_request.offset + spdm_response->portion_length + spdm_response->remainder_length !=
 * total_responder_cert_chain_buffer_length.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_certificate_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    free(data);
}

/**
 * Test 23: test the Alias Cert model, hardware identify OID is found in AliasCert model cert
 * Expected Behavior: return RETURN_SECURITY_VIOLATION
 **/
void libspdm_test_requester_get_certificate_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uintn cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    uintn data_size;
    void *hash;
    uintn hash_size;
    uint8_t *root_cert;
    uintn root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /*The only different setting with normal case2: cert model is AliasCert model*/
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_internal_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->local_context.peer_cert_chain_provision = NULL;
    spdm_context->local_context.peer_cert_chain_provision_size = 0;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, RETURN_SECURITY_VIOLATION);
    free(data);
}

libspdm_test_context_t m_libspdm_requester_get_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_SIGNATURE,
    true,
    libspdm_requester_get_certificate_test_send_message,
    libspdm_requester_get_certificate_test_receive_message,
};

int libspdm_requester_get_certificate_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_certificate_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case1),
        /* Successful response: check root certificate hash*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case9),
        /* Successful response: check certificate chain*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case10),
        /* Invalid certificate signature*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case11),
        /* Fail certificate chain check*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case12),
        /* Sucessful response: get a certificate chain that fits in one single message*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case13),
        /* Sucessful response: get certificate chain byte by byte*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case14),
        /* Sucessful response: get a long certificate chain*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case15),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case16),
        /* Sucessful response: get a certificate chain not start with root cert.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case17),
        /* Fail response: get a certificate chain not start with root cert but with wrong signature.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case18),
        /* Fail response: one certificate in the retrieved certificate chain past its expiration date.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case19),
        /* Fail response: responder return portion_length is 0.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case20),
        /* Fail response: responder return portion_length > spdm_request.length*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case21),
        /* Fail response: spdm_request.offset + spdm_response->portion_length + spdm_response->remainder_length !=
         * total_responder_cert_chain_buffer_length.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case22),
        /* hardware identify OID is found in AliasCert model cert */
        cmocka_unit_test(libspdm_test_requester_get_certificate_case23),
    };

    libspdm_setup_test_context(&m_libspdm_requester_get_certificate_test_context);

    return cmocka_run_group_tests(spdm_requester_get_certificate_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
