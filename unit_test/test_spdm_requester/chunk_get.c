/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CHUNK_CAP

static void* m_libspdm_local_certificate_chain;
static size_t m_libspdm_local_certificate_chain_size;

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

static size_t m_libspdm_local_buffer_2_size;
static uint8_t m_libspdm_local_buffer_2[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

/* Override the LIBSPDM_DATA_TRANSFER_SIZE just for the unit tests in this file.
 * All other unit tests have the default data transfer size due to the specific
 * unit tests requests and responses hardcode for each test case. */
#define LIBSPDM_UNIT_TEST_DATA_TRANSFER_SIZE (64)

/* Loading the target expiration certificate chain and saving root certificate hash
 * "rsa3072_Expiration/bundle_responder.certchain.der"*/
bool libspdm_libspdm_read_responder_public_certificate_chain_expiration(
    void** data, size_t* size, void** hash, size_t* hash_size);

#define CHUNK_GET_UNIT_TEST_CHUNK_HANDLE (10)
libspdm_return_t libspdm_requester_chunk_get_test_send_message(
    void* spdm_context, size_t request_size, const void* request,
    uint64_t timeout)
{
    libspdm_test_context_t* spdm_test_context;
    uint8_t message_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];

    memcpy(message_buffer, request, request_size);

    spdm_test_context = libspdm_get_test_context();
    if (spdm_test_context->case_id == 0x1) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    else {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_chunk_get_test_receive_message(
    void* spdm_context, size_t* response_size,
    void** response, uint64_t timeout)
{
    libspdm_test_context_t* spdm_test_context;
    uint8_t chunk_handle = CHUNK_GET_UNIT_TEST_CHUNK_HANDLE;
    static uint8_t sub_index = 0;

    spdm_test_context = libspdm_get_test_context();
    if (spdm_test_context->case_id == 0x1) {
        size_t transport_header_size;

        if (sub_index == 0x0) {
            sub_index++;
            spdm_error_response_t* error_rsp;
            size_t error_rsp_size;

            error_rsp_size = sizeof(spdm_error_response_t) + sizeof(uint8_t);
            transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
            error_rsp = (void*) ((uint8_t*) *response + transport_header_size);

            error_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
            error_rsp->header.request_response_code = SPDM_ERROR;
            error_rsp->header.param1 = SPDM_ERROR_CODE_LARGE_RESPONSE;
            error_rsp->header.param2 = 0;
            *((uint8_t*) (error_rsp + 1)) = chunk_handle;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                error_rsp_size, error_rsp,
                response_size, response);

            return LIBSPDM_STATUS_SUCCESS;
        }
        else {
            spdm_chunk_response_response_t* chunk_rsp;
            size_t chunk_rsp_size;

            /* Refers to just the certificate portion in the cert response */
            uint16_t sub_cert_portion_length;
            uint16_t sub_cert_remainder_length;
            size_t   sub_cert_count;
            static size_t sub_cert_index = 0;
            static spdm_certificate_response_t* cert_rsp = NULL;
            static size_t cert_rsp_size = 0;
            static size_t cert_rsp_copied = 0;
            static size_t cert_rsp_remaining = 0;
            size_t cert_rsp_data_this_chunk;
            static uint16_t chunk_seq_no = 0;
            static size_t total_cert_copied_all_chunks = 0;

            if (m_libspdm_local_certificate_chain == NULL) {
                libspdm_read_responder_public_certificate_chain(
                    m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                    &m_libspdm_local_certificate_chain,
                    &m_libspdm_local_certificate_chain_size, NULL, NULL);
            }
            if (m_libspdm_local_certificate_chain == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }

            sub_cert_count = (m_libspdm_local_certificate_chain_size +
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

            if (sub_cert_index != sub_cert_count - 1) {
                sub_cert_portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
                sub_cert_remainder_length =
                    (uint16_t) (m_libspdm_local_certificate_chain_size -
                        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                        (sub_cert_index + 1));
            }
            else {
                sub_cert_portion_length = (uint16_t) (
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (sub_cert_count - 1));
                sub_cert_remainder_length = 0;
            }

            if (cert_rsp_copied == 0) {
                libspdm_zero_mem(m_libspdm_local_buffer_2, sizeof(m_libspdm_local_buffer_2));

                transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
                cert_rsp
                    = (spdm_certificate_response_t*)
                      ((uint8_t*) m_libspdm_local_buffer_2 + transport_header_size);

                cert_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
                cert_rsp->header.request_response_code = SPDM_CERTIFICATE;
                cert_rsp->header.param1 = 0;
                cert_rsp->header.param2 = 0;
                cert_rsp->portion_length = sub_cert_portion_length;
                cert_rsp->remainder_length = sub_cert_remainder_length;

                libspdm_copy_mem(cert_rsp + 1,
                    sub_cert_portion_length,
                    (uint8_t*) m_libspdm_local_certificate_chain +
                        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * sub_cert_index,
                    sub_cert_portion_length);

                cert_rsp_size = sizeof(spdm_certificate_response_t) + sub_cert_portion_length;
                m_libspdm_local_buffer_2_size = cert_rsp_size;
                cert_rsp_remaining = cert_rsp_size;
                cert_rsp_copied = 0;

                cert_rsp_data_this_chunk = LIBSPDM_UNIT_TEST_DATA_TRANSFER_SIZE
                    - sizeof(spdm_chunk_response_response_t) - sizeof(uint32_t);
                cert_rsp_data_this_chunk = min(cert_rsp_remaining, cert_rsp_data_this_chunk);

                transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
                chunk_rsp = (void*) ((uint8_t*) *response + transport_header_size);

                chunk_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
                chunk_rsp->header.request_response_code = SPDM_CHUNK_RESPONSE;
                chunk_rsp->header.param1 = 0;
                chunk_rsp->header.param2 = chunk_handle;
                *((uint32_t*) (chunk_rsp + 1)) = (uint32_t) cert_rsp_remaining;

                if (cert_rsp_data_this_chunk == cert_rsp_remaining) {
                    chunk_rsp->header.param1 = SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK;
                }

                uint8_t* copy_to = (uint8_t*) chunk_rsp
                    + sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t);

                libspdm_copy_mem(copy_to,
                    *response_size - (copy_to - (uint8_t*)*response),
                    (uint8_t*) cert_rsp + cert_rsp_copied,
                    cert_rsp_data_this_chunk);

                chunk_rsp_size = sizeof(spdm_chunk_response_response_t)
                    + sizeof(uint32_t) + cert_rsp_data_this_chunk;

                cert_rsp_copied += cert_rsp_data_this_chunk;
                cert_rsp_remaining -= cert_rsp_data_this_chunk;
                chunk_rsp->chunk_size = (uint32_t) cert_rsp_data_this_chunk;
                chunk_rsp->chunk_seq_no = chunk_seq_no = 0;
                chunk_seq_no++;
            }
            else {
                cert_rsp_data_this_chunk = LIBSPDM_UNIT_TEST_DATA_TRANSFER_SIZE
                    - sizeof(spdm_chunk_response_response_t);
                cert_rsp_data_this_chunk = min(cert_rsp_remaining, cert_rsp_data_this_chunk);

                transport_header_size = libspdm_transport_test_get_header_size(spdm_context);
                chunk_rsp = (void*) ((uint8_t*) *response + transport_header_size);

                chunk_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
                chunk_rsp->header.request_response_code = SPDM_CHUNK_RESPONSE;
                chunk_rsp->header.param1 = 0;
                chunk_rsp->header.param2 = chunk_handle;

                if (cert_rsp_data_this_chunk == cert_rsp_remaining) {
                    chunk_rsp->header.param1 = SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK;
                }

                uint8_t* copy_to = (uint8_t*) chunk_rsp
                    + sizeof(spdm_chunk_response_response_t);

                libspdm_copy_mem(copy_to,
                    *response_size - (copy_to - (uint8_t*) *response),
                    (uint8_t*) cert_rsp + cert_rsp_copied,
                    cert_rsp_data_this_chunk);

                chunk_rsp_size = sizeof(spdm_chunk_response_response_t) + cert_rsp_data_this_chunk;

                cert_rsp_copied += cert_rsp_data_this_chunk;
                cert_rsp_remaining -= cert_rsp_data_this_chunk;
                chunk_rsp->chunk_size = (uint32_t) cert_rsp_data_this_chunk;
                chunk_rsp->chunk_seq_no = chunk_seq_no++;
            }

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_rsp,
                response_size, response);

            if (cert_rsp_copied >= cert_rsp_size) {
                sub_cert_index++;
                cert_rsp = NULL;
                cert_rsp_size = 0;
                cert_rsp_copied = 0;
                cert_rsp_remaining = 0;
                chunk_seq_no = 0;
                sub_index = 0;
            }
            if (sub_cert_index == sub_cert_count) {
                sub_cert_index = 0;
                free(m_libspdm_local_certificate_chain);
                m_libspdm_local_certificate_chain = NULL;
                m_libspdm_local_certificate_chain_size = 0;
                sub_index = 0;
            }
            return LIBSPDM_STATUS_SUCCESS;
        }
    }
    else {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

void libspdm_test_requester_chunk_get_case1(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;
    const uint8_t* root_cert;
    size_t root_cert_size;
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
    #endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
        SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP);

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.data_transfer_size
        = LIBSPDM_UNIT_TEST_DATA_TRANSFER_SIZE;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t*) data + sizeof(spdm_cert_chain_t) + hash_size,
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

libspdm_test_context_t m_libspdm_requester_chunk_get_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_chunk_get_test_send_message,
    libspdm_requester_chunk_get_test_receive_message,
};

int libspdm_requester_chunk_get_test_main(void)
{
    const struct CMUnitTest spdm_requester_chunk_get_tests[] = {
        /* Request a certificate in portions, each portion in chunks */
        cmocka_unit_test(libspdm_test_requester_chunk_get_case1),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_chunk_get_test_context);

    return cmocka_run_group_tests(spdm_requester_chunk_get_tests,
        libspdm_unit_test_group_setup,
        libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CHUNK_CAP*/
