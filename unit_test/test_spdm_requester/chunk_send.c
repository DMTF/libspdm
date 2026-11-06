/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

static bool m_libspdm_chunk_send_last_chunk = false;
static uint8_t m_libspdm_chunk_send_chunk_handle = 0;
static uint16_t m_libspdm_chunk_send_chunk_seq_no = 0;
static uint32_t m_libspdm_chunk_send_chunk_seq_no_14 = 0;
static uint8_t m_libspdm_chunk_response_data[256];
static size_t m_libspdm_chunk_response_data_size;
static uint8_t m_libspdm_chunk_response_chunk_handle = 0;
static uint32_t m_libspdm_chunk_response_chunk_seq_no_14 = 0;

/* Override the LIBSPDM_DATA_TRANSFER_SIZE just for the unit tests in this file.
 * All other unit tests have the default data transfer size due to the specific
 * unit tests requests and responses hardcode for each test case. */
#define CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE (42)

/* The SPDM 1.2 and 1.3 chunk transfer size limit is
 * (DataTransferSize - sizeof(spdm_chunk_send_request_t)) * 65536 - sizeof(uint32_t).
 * 65549 is the smallest DataTransferSize whose limit exceeds UINT32_MAX:
 * (65549 - 12) * 65536 - 4 = 4295032828, which wraps to 65532 in 32 bits. */
#define CHUNK_SEND_REQUESTER_UNIT_TEST_LARGE_DATA_TRANSFER_SIZE (65549)

/* A request that does not fit in one message. */
static uint8_t m_libspdm_chunk_send_large_request[
    CHUNK_SEND_REQUESTER_UNIT_TEST_LARGE_DATA_TRANSFER_SIZE + 1];
static uint32_t m_libspdm_chunk_send_large_message_size;
static size_t m_libspdm_chunk_send_bytes_received;

/* A VENDOR_DEFINED_RESPONSE with no vendor ID and a 1-byte payload. With CHUNK_SEND_ACK, it fills a
 * multiple of LIBSPDM_TEST_ALIGNMENT, so the test transport adds no padding. */
#define CHUNK_SEND_REQUESTER_UNIT_TEST_VENDOR_RESPONSE_SIZE \
    (sizeof(spdm_vendor_defined_response_msg_t) + sizeof(uint16_t) + 1)

static void libspdm_requester_chunk_send_test_case1_build_algorithms_response(
    void* context, void* response, size_t* response_size)
{
    spdm_algorithms_response_t* spdm_response;

    *response_size = sizeof(spdm_algorithms_response_t);
    spdm_response = (spdm_algorithms_response_t*) response;

    libspdm_zero_mem(spdm_response, *response_size);
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_response->header.request_response_code = SPDM_ALGORITHMS;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->length = sizeof(spdm_algorithms_response_t);
    spdm_response->measurement_specification_sel = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
    spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
    spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
    spdm_response->ext_asym_sel_count = 0;
    spdm_response->ext_hash_sel_count = 0;
}

static void libspdm_requester_chunk_send_test_case15_build_algorithms_response(
    void* context, void* response, size_t* response_size)
{
    spdm_algorithms_response_t* spdm_response;

    *response_size = sizeof(spdm_algorithms_response_t);
    spdm_response = (spdm_algorithms_response_t*) response;

    libspdm_zero_mem(spdm_response, *response_size);
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_response->header.request_response_code = SPDM_ALGORITHMS;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->length = sizeof(spdm_algorithms_response_t);
    spdm_response->measurement_specification_sel = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
    spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
    spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
    spdm_response->ext_asym_sel_count = 0;
    spdm_response->ext_hash_sel_count = 0;
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_test_context_t* spdm_test_context;
    const spdm_chunk_send_request_t* chunk_send;
    const spdm_chunk_send_request_14_t* chunk_send_14;

    spdm_test_context = libspdm_get_test_context();

    chunk_send = (const spdm_chunk_send_request_t*)
                 ((const uint8_t*) request + sizeof(libspdm_test_message_header_t));

    chunk_send_14 = (const spdm_chunk_send_request_14_t*)
                    ((const uint8_t*) request + sizeof(libspdm_test_message_header_t));

    m_libspdm_chunk_send_chunk_handle = chunk_send->header.param2;
    m_libspdm_chunk_send_chunk_seq_no = chunk_send->chunk_seq_no;
    m_libspdm_chunk_send_chunk_seq_no_14 = chunk_send_14->chunk_seq_no;

    if (chunk_send->header.param1 & SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK) {
        m_libspdm_chunk_send_last_chunk = true;
    } else {
        m_libspdm_chunk_send_last_chunk = false;
    }

    if (spdm_test_context->case_id == 1) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 2) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    if (spdm_test_context->case_id == 3) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 4) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 5) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 6) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 7) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 8) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 9) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 10) {
        if (chunk_send->header.request_response_code == SPDM_CHUNK_SEND) {
            return LIBSPDM_STATUS_SUCCESS;
        }
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    if (spdm_test_context->case_id == 11) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 12) {
        /* Here the send request message should always be SPDM_CHUNK_SEND,
         * if not then something is wrong. */
        LIBSPDM_ASSERT(chunk_send->header.request_response_code == SPDM_CHUNK_SEND);
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 13) {
        /* Should never reach here since the test case is meant to fail before send */
        LIBSPDM_ASSERT(0);
    }
    if (spdm_test_context->case_id == 14) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 15) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 16) {
        const spdm_chunk_get_request_14_t* chunk_get_14;

        chunk_get_14 = (const spdm_chunk_get_request_14_t*)
                       ((const uint8_t*) request + sizeof(libspdm_test_message_header_t));

        if (chunk_get_14->header.request_response_code == SPDM_CHUNK_GET) {
            m_libspdm_chunk_response_chunk_handle = chunk_get_14->header.param2;
            m_libspdm_chunk_response_chunk_seq_no_14 = chunk_get_14->chunk_seq_no;
        }

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 17) {
        if (chunk_send->chunk_seq_no == 0) {
            m_libspdm_chunk_send_large_message_size =
                libspdm_read_uint32((const uint8_t *)(chunk_send + 1));
            m_libspdm_chunk_send_bytes_received = 0;
        }
        m_libspdm_chunk_send_bytes_received += chunk_send->chunk_size;
        return LIBSPDM_STATUS_SUCCESS;
    }
    return LIBSPDM_STATUS_SEND_FAIL;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_chunk_send_ack_response_t *chunk_send_ack_rsp;
    spdm_chunk_send_ack_response_14_t *chunk_send_ack_rsp_14;
    spdm_error_response_t *error_response;
    size_t chunk_rsp_size;
    uint8_t *chunk_copy_to;
    size_t chunk_size;

    spdm_test_context = libspdm_get_test_context();

    if ((spdm_test_context->case_id == 1) || (spdm_test_context->case_id == 10) ||
        (spdm_test_context->case_id == 11)) {
        /* Successful chunk send of algorithms request */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        if (m_libspdm_chunk_send_last_chunk) {

            chunk_copy_to = (uint8_t*) (chunk_send_ack_rsp + 1);
            chunk_size = *response_size - (chunk_copy_to - (uint8_t*) *response);

            libspdm_requester_chunk_send_test_case1_build_algorithms_response(
                spdm_context, chunk_copy_to, &chunk_size);
            chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t) + chunk_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_send_ack_rsp,
                response_size, response);
        } else {
            chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_send_ack_rsp,
                response_size, response);
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 2) {
        /* Request fail send
         * Should never reach here since the test case is meant to fail at send */
        LIBSPDM_ASSERT(0);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (spdm_test_context->case_id == 3) {
        /* Response fail receive */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (spdm_test_context->case_id == 4) {
        /* Response has bad SPDM version */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_11; /* Bad SPDM version */
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 5) {
        /* Response has bad request response code */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_ERROR; /* Bad response code */
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = 0;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 6) {
        /* Response has bad response size */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        chunk_rsp_size = 4; /* Bad response size */

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);


        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 7) {
        /* Response has early error detected */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1
            = SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        error_response = (void*) (chunk_send_ack_rsp + 1);
        error_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        error_response->header.request_response_code = SPDM_ERROR;
        error_response->header.param1 = SPDM_ERROR_CODE_UNSPECIFIED;
        error_response->header.param2 = 0;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t) + sizeof(spdm_error_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 8) {
        /* Response has bad chunk handle */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;

        /* Bad chunk handle */
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle - 1;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 9) {
        /* Response has bad chunk seq no */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;

        /* Bad Chunk Seq No */
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no - 1;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 12) {
        /* ErrorCode == LargeResponse shall not be allowed in ResponseToLargeRequest */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1
            = SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        error_response = (void*) (chunk_send_ack_rsp + 1);
        error_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        error_response->header.request_response_code = SPDM_ERROR;

        /* ErrorCode == LargeResponse in ResponseToLargeRequest */
        error_response->header.param1 = SPDM_ERROR_CODE_LARGE_RESPONSE;
        error_response->header.param2 = 0;
        *((uint8_t*) (error_response + 1)) = 0;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t) + sizeof(spdm_error_response_t) +
                         sizeof(uint8_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 13) {
        /* Should never reach here since the test case is meant to fail before send */
        LIBSPDM_ASSERT(0);
    }
    if (spdm_test_context->case_id == 14) {
        /* Response an arror response with RequestResynch */
        error_response = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));
        error_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        error_response->header.request_response_code = SPDM_ERROR;
        error_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        error_response->header.param2 = 0;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            sizeof(spdm_error_response_t), error_response,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 15) {
        /* Successful chunk send of algorithms request with SPDM 1.4*/
        chunk_send_ack_rsp_14
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp_14->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        chunk_send_ack_rsp_14->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp_14->header.param1 = 0;
        chunk_send_ack_rsp_14->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp_14->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no_14;

        if (m_libspdm_chunk_send_last_chunk) {

            chunk_copy_to = (uint8_t*) (chunk_send_ack_rsp_14 + 1);
            chunk_size = *response_size - (chunk_copy_to - (uint8_t*) *response);

            libspdm_requester_chunk_send_test_case15_build_algorithms_response(
                spdm_context, chunk_copy_to, &chunk_size);
            chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_14_t) + chunk_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_send_ack_rsp_14,
                response_size, response);
        } else {
            chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_14_t);
            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_send_ack_rsp_14,
                response_size, response);
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 16) {
        /* Successful chunk send of algorithms request with SPDM 1.4*/
        spdm_chunk_response_response_14_t *chunk_response_rsp_14;
        spdm_error_data_large_response_t *error_data_large_response;
        size_t chunk_response_header_size;
        static bool chunk_get_start = false;
        static uint32_t chunk_data_offset = 0;

        if (chunk_get_start) {
            chunk_response_rsp_14
                = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));
            chunk_response_rsp_14->header.spdm_version = SPDM_MESSAGE_VERSION_14;
            chunk_response_rsp_14->header.request_response_code = SPDM_CHUNK_RESPONSE;
            chunk_response_rsp_14->header.param1 = 0;
            chunk_response_rsp_14->header.param2 = m_libspdm_chunk_response_chunk_handle;
            chunk_response_rsp_14->chunk_seq_no = m_libspdm_chunk_response_chunk_seq_no_14;
            chunk_response_header_size = sizeof(spdm_chunk_response_response_14_t);
            chunk_copy_to = (uint8_t*) (chunk_response_rsp_14 + 1);
            if (chunk_response_rsp_14->chunk_seq_no == 0) {
                libspdm_write_uint32(chunk_copy_to, (uint32_t)m_libspdm_chunk_response_data_size);
                chunk_copy_to += sizeof(uint32_t);
                chunk_response_header_size += sizeof(uint32_t);
            }
            chunk_response_rsp_14->chunk_size = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE -
                                                (uint32_t)chunk_response_header_size;
            if (chunk_response_rsp_14->chunk_size > (uint32_t)m_libspdm_chunk_response_data_size - chunk_data_offset) {
                chunk_response_rsp_14->chunk_size = (uint32_t)m_libspdm_chunk_response_data_size - chunk_data_offset;
                chunk_response_rsp_14->header.param1 |= SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK;
            }
            libspdm_copy_mem(chunk_copy_to, *response_size - chunk_response_header_size,
                             m_libspdm_chunk_response_data + chunk_data_offset, chunk_response_rsp_14->chunk_size);
            chunk_data_offset += chunk_response_rsp_14->chunk_size;
            chunk_rsp_size = chunk_response_header_size + chunk_response_rsp_14->chunk_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_response_rsp_14,
                response_size, response);
        } else if (m_libspdm_chunk_send_last_chunk) {
            /* size of ResponseToLargeRequest is 36 < DataTransferSize
             * size of CHUNK_SEND_ACK is 44 > DataTransferSize
             * first message should be SPDM_ERROR with ErrorCode == LargeResponse */
            chunk_get_start = true;

            error_response
                = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));
            error_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
            error_response->header.request_response_code = SPDM_ERROR;
            error_response->header.param1 = SPDM_ERROR_CODE_LARGE_RESPONSE;
            error_response->header.param2 = 0;
            error_data_large_response = (spdm_error_data_large_response_t *)(error_response + 1);
            error_data_large_response->handle = 1;

            m_libspdm_chunk_response_data_size = sizeof(m_libspdm_chunk_response_data);
            libspdm_requester_chunk_send_test_case15_build_algorithms_response(
                spdm_context, m_libspdm_chunk_response_data, &m_libspdm_chunk_response_data_size);

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_error_response_t) + sizeof(spdm_error_data_large_response_t),
                error_response, response_size, response);
        } else {
            chunk_send_ack_rsp_14
                = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

            chunk_send_ack_rsp_14->header.spdm_version = SPDM_MESSAGE_VERSION_14;
            chunk_send_ack_rsp_14->header.request_response_code = SPDM_CHUNK_SEND_ACK;
            chunk_send_ack_rsp_14->header.param1 = 0;
            chunk_send_ack_rsp_14->header.param2 = m_libspdm_chunk_send_chunk_handle;
            chunk_send_ack_rsp_14->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no_14;

            chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_14_t);
            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_send_ack_rsp_14,
                response_size, response);
        }

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 17) {
        /* Acknowledge each chunk, and return a VENDOR_DEFINED_RESPONSE with the last. */
        spdm_vendor_defined_response_msg_t *vendor_response;

        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;
        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);

        if (m_libspdm_chunk_send_last_chunk) {
            vendor_response = (void*) (chunk_send_ack_rsp + 1);
            libspdm_zero_mem(vendor_response, CHUNK_SEND_REQUESTER_UNIT_TEST_VENDOR_RESPONSE_SIZE);
            vendor_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
            vendor_response->header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
            libspdm_write_uint16((uint8_t*) (vendor_response + 1), 1);
            ((uint8_t*) (vendor_response + 1))[sizeof(uint16_t)] = 0xa5;
            chunk_rsp_size += CHUNK_SEND_REQUESTER_UNIT_TEST_VENDOR_RESPONSE_SIZE;
        }

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    return LIBSPDM_STATUS_RECEIVE_FAIL;
}

static libspdm_return_t libspdm_test_requester_chunk_send_generic_test_case(
    void** state, uint32_t case_id)
{
    /* Copied from Neg. Algorithms test case 2 */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = case_id;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (case_id == 15 || case_id == 16) {
        spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                                SPDM_VERSION_NUMBER_SHIFT_BIT;
    }
    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    if (case_id != 10) {
        spdm_context->connection_info.capability.data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.data_transfer_size
            = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.sender_data_transfer_size
            = LIBSPDM_DATA_TRANSFER_SIZE;
    } else {
        spdm_context->connection_info.capability.data_transfer_size
            = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.sender_data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
    }
    if (case_id == 16) {
        spdm_context->connection_info.capability.data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.sender_data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
    }

    if (case_id == 11) {
        spdm_context->connection_info.capability.max_spdm_msg_size = 42;
    }

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    return status;
}

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
static libspdm_return_t libspdm_test_requester_chunk_send_vendor_specific_test_case(
    void** state, uint32_t case_id)
{
    /* Use vendor specific request to generate a large request. */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    uint16_t standard_id = 6;
    uint8_t vendor_id_len = 2;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH] = {0xAA, 0xAA};
    uint32_t data_len = 65535;
    uint8_t data[65535] = {0};

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = case_id;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Large request need a large scratch buffer. */
    spdm_context->connection_info.capability.max_spdm_msg_size = 0x12000;
    spdm_context->local_context.capability.max_spdm_msg_size = 0x12000;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.data_transfer_size
        = sizeof(spdm_chunk_send_request_t) + 1;
    spdm_context->local_context.capability.sender_data_transfer_size
        = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.is_requester = true;

    libspdm_unit_test_resize_scratch_buffer(spdm_test_context);

    libspdm_reset_message_a(spdm_context);

    status = libspdm_vendor_send_request_receive_response(spdm_context, NULL,
                                                          standard_id, vendor_id_len, vendor_id,
                                                          data_len, data,
                                                          &standard_id, &vendor_id_len, vendor_id,
                                                          &data_len, data);
    return status;
}
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

static void req_chunk_send_case1(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 1);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

static void req_chunk_send_case2(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 2);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

static void req_chunk_send_case3(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 3);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

static void req_chunk_send_case4(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t* large_message;
    uint32_t large_message_capacity;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 4);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_false(spdm_context->chunk_context.send.chunk_in_use);
    assert_null(spdm_context->chunk_context.send.large_message);
    assert_int_equal(spdm_context->chunk_context.send.large_message_size, 0);
    assert_int_equal(spdm_context->chunk_context.send.large_message_capacity, 0);

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);
    large_message = (uint8_t*)scratch_buffer +
                    libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    large_message_capacity = libspdm_get_scratch_buffer_large_message_capacity(spdm_context);
    for (index = 0; index < large_message_capacity; index++) {
        assert_int_equal(large_message[index], 0);
    }
}

static void req_chunk_send_case5(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 5);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

static void req_chunk_send_case6(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 6);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

static void req_chunk_send_case7(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 7);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

static void req_chunk_send_case8(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 8);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void req_chunk_send_case9(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t* large_message;
    uint32_t large_message_capacity;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 9);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_false(spdm_context->chunk_context.send.chunk_in_use);
    assert_null(spdm_context->chunk_context.send.large_message);
    assert_int_equal(spdm_context->chunk_context.send.large_message_size, 0);
    assert_int_equal(spdm_context->chunk_context.send.large_message_capacity, 0);

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);
    large_message = (uint8_t*)scratch_buffer +
                    libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    large_message_capacity = libspdm_get_scratch_buffer_large_message_capacity(spdm_context);
    for (index = 0; index < large_message_capacity; index++) {
        assert_int_equal(large_message[index], 0);
    }
}

static void req_chunk_send_case10(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 10);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

static void req_chunk_send_case11(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 11);
    assert_int_equal(status, LIBSPDM_STATUS_PEER_BUFFER_TOO_SMALL);
}

/**
 * Test 12: ErrorCode == LargeResponse shall not be allowed in ResponseToLargeRequest.
 * Expected behavior: returns a status of LIBSPDM_STATUS_ERROR_PEER,
 * Received an unexpected error message.
 **/
static void req_chunk_send_case12(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 12);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
/**
 * Test 13: Request size shall not exceed max supported transfer size.
 * Expected behavior: returns a status of LIBSPDM_STATUS_SEND_FAIL,
 **/
static void req_chunk_send_case13(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_vendor_specific_test_case(state, 13);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

/**
 * Test 14: the requester is sending CHUNK_SEND, but receives an
 * ERROR message indicating the RequestResynch status of the responder
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
 * communication is reset to expect a new GET_VERSION message.
 **/
static void req_chunk_send_case14(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 14);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

static void req_chunk_send_case15(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 15);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

static void req_chunk_send_case16(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 16);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 17: a 65550-byte request, when the smaller of the Responder's DataTransferSize and the
 * Requester's transmit size is 65549.
 * Expected behavior: the Requester sends the request in two CHUNK_SEND messages, and returns the
 * response that comes with the last CHUNK_SEND_ACK.
 **/
static void req_chunk_send_case17(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    spdm_message_header_t* request;
    uint32_t data_transfer_size;
    uint32_t large_message_size;
    uint8_t response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void* response;
    size_t response_size;
    spdm_vendor_defined_response_msg_t* vendor_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 17;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    data_transfer_size = CHUNK_SEND_REQUESTER_UNIT_TEST_LARGE_DATA_TRANSFER_SIZE;
    spdm_context->connection_info.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.sender_data_transfer_size = data_transfer_size;

    large_message_size = sizeof(m_libspdm_chunk_send_large_request);
    spdm_context->connection_info.capability.max_spdm_msg_size = large_message_size;
    spdm_context->local_context.capability.max_spdm_msg_size = large_message_size;
    libspdm_unit_test_resize_scratch_buffer(spdm_test_context);

    libspdm_zero_mem(m_libspdm_chunk_send_large_request,
                     sizeof(m_libspdm_chunk_send_large_request));
    request = (spdm_message_header_t*) m_libspdm_chunk_send_large_request;
    request->spdm_version = SPDM_MESSAGE_VERSION_12;
    request->request_response_code = SPDM_VENDOR_DEFINED_REQUEST;

    m_libspdm_chunk_send_large_message_size = 0;
    m_libspdm_chunk_send_bytes_received = 0;
    status = libspdm_send_spdm_request(spdm_context, NULL, large_message_size, request);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(m_libspdm_chunk_send_large_message_size, large_message_size);
    assert_int_equal(m_libspdm_chunk_send_bytes_received, large_message_size);
    assert_int_equal(m_libspdm_chunk_send_chunk_seq_no, 1);
    assert_true(m_libspdm_chunk_send_last_chunk);

    response = response_buffer;
    response_size = sizeof(response_buffer);
    status = libspdm_receive_spdm_response(spdm_context, NULL, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, CHUNK_SEND_REQUESTER_UNIT_TEST_VENDOR_RESPONSE_SIZE);
    vendor_response = response;
    assert_int_equal(vendor_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(vendor_response->header.request_response_code, SPDM_VENDOR_DEFINED_RESPONSE);
    assert_int_equal(vendor_response->len, 0);
    assert_int_equal(libspdm_read_uint16((const uint8_t*) (vendor_response + 1)), 1);
    assert_int_equal(((const uint8_t*) (vendor_response + 1))[sizeof(uint16_t)], 0xa5);
    assert_false(spdm_context->chunk_context.send.chunk_in_use);
}

int libspdm_req_chunk_send_test(void)
{
    /* Test the CHUNK_SEND handlers in various requester handlers */
    const struct CMUnitTest test_cases[] = {
        /* Request Algorithms successfully sent in chunks. */
        cmocka_unit_test(req_chunk_send_case1),
        /* Chunk Request fail send */
        cmocka_unit_test(req_chunk_send_case2),
        /* Chunk Response fail receive */
        cmocka_unit_test(req_chunk_send_case3),
        /* Chunk Response has bad SPDM version */
        cmocka_unit_test(req_chunk_send_case4),
        /* Chunk Response has bad request response code */
        cmocka_unit_test(req_chunk_send_case5),
        /* Chunk Response has bad response size */
        cmocka_unit_test(req_chunk_send_case6),
        /* Chunk Response has early error detected */
        cmocka_unit_test(req_chunk_send_case7),
        /* Chunk Response has bad chunk handle */
        cmocka_unit_test(req_chunk_send_case8),
        /* Chunk Response has bad chunk seq no */
        cmocka_unit_test(req_chunk_send_case9),
        /* sent in chunks due to greater than the sending transmit buffer size. */
        cmocka_unit_test(req_chunk_send_case10),
        /* requester message size greater than the responder max_spdm_msg_size, return LIBSPDM_STATUS_PEER_BUFFER_TOO_SMALL */
        cmocka_unit_test(req_chunk_send_case11),
        /* ErrorCode == LargeResponse shall not be allowed in ResponseToLargeRequest */
        cmocka_unit_test(req_chunk_send_case12),
#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
        /* Request size exceed max chunks */
        cmocka_unit_test(req_chunk_send_case13),
#endif
        /* Received and error message indicating RequestResynch */
        cmocka_unit_test(req_chunk_send_case14),
        /* Request Algorithms successfully sent in chunks, with SPDM 1.4 */
        cmocka_unit_test(req_chunk_send_case15),
        /* Request Algorithms successfully sent in chunks, with SPDM 1.4
         * size of ResponseToLargeRequest is 36 < DataTransferSize
         * size of CHUNK_SEND_ACK is 44 > DataTransferSize */
        cmocka_unit_test(req_chunk_send_case16),
        /* Request larger than 65532 bytes, with a DataTransferSize of 65549 */
        cmocka_unit_test(req_chunk_send_case17),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP*/
