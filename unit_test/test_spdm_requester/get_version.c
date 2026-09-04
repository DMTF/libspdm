/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];
} libspdm_version_response_mine_t;
#pragma pack()

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SUCCESS;
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
    case 0x10: {
        const uint8_t *ptr = (const uint8_t *)request;

        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         &ptr[1], request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
    }
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
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_version_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_version_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
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
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
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
        static size_t sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        } else if (sub_index1 == 1) {
            libspdm_version_response_mine_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(libspdm_version_response_mine_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_VERSION;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->version_number_entry_count = 2;
            spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
            spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        }
        sub_index1++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
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
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code = SPDM_GET_VERSION;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        uint8_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_message_header_t) - 1;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response[0] = SPDM_MESSAGE_VERSION_10;
        spdm_response[1] = SPDM_VERSION;
        spdm_response[2] = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[2] = 0x12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0xA0 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0xA1 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_GET_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem (spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;

            libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /* skip some reserved error codes (0d to 3e) */
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        /* skip response not ready, request resync, and some reserved codes (44 to fc) */
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 5;
        spdm_response->version_number_entry[0] = 0x42 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x52 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[2] = 0x12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[3] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[4] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_response_size = 10;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         (uint8_t *)spdm_response, spdm_response_size);
        m_libspdm_local_buffer_size += spdm_response_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: {
        spdm_message_header_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_message_header_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->request_response_code = SPDM_VERSION;
        spdm_response->param1 = 0;
        spdm_response->param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);

    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        spdm_version_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_version_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = LIBSPDM_MAX_VERSION_COUNT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);

    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 5;
        spdm_response->version_number_entry[0] = 0x42 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x52 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[2] = 0x12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[3] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[4] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Can be populated with new test.
 **/

/*
 * static void req_get_version_case1(void **state)
 * {
 * }
 */

/**
 * Test 2: receiving a correct VERSION message with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS.
 **/
static void req_get_version_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 3: Can be populated with new test.
 **/

/*
 * static void req_get_version_case3(void **state)
 * {
 * }
 */

/**
 * Test 4: receiving an ERROR response with code InvalidRequest.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_ERROR_PEER.
 **/
static void req_get_version_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

/**
 * Test 5: receiving a Busy ERROR response on every attempt.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_BUSY_PEER after exhausting
 * retries.
 **/
static void req_get_version_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t retry_times;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    retry_times = spdm_context->retry_times;
    spdm_context->retry_times = 0;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);

    spdm_context->retry_times = retry_times;
}

/**
 * Test 6: on the first try, receiving a Busy ERROR message, and on retry, receiving
 * a correct VERSION message with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS.
 **/
static void req_get_version_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t retry_times;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    retry_times = spdm_context->retry_times;
    spdm_context->retry_times = 3;
    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_context->retry_times = retry_times;
}

/**
 * Test 7: receiving an ERROR response with code RequestResynch.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_RESYNCH_PEER and resets
 * the connection state.
 **/
static void req_get_version_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
 * Test 8: receiving an ERROR response with code ResponseNotReady.
 * Expected behavior: GET_VERSION rejects this special error and returns
 * LIBSPDM_STATUS_ERROR_PEER.
 **/
static void req_get_version_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

/**
 * Test 9: receiving a transport-decoded response shorter than the SPDM message header.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_version_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 10: receiving a VERSION message with a larger list of available versions than indicated.
 * The presence of only two versions are indicated, but the VERSION message presents a list
 * with 3 versions: 1.0, 1.1 and 1.2.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS, but truncate the message
 * to consider only the two first versions, as indicated in the message.
 **/
static void req_get_version_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 11: receiving a correct VERSION message with versions unsupported by the requester.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_NEGOTIATION_FAIL.
 **/
static void req_get_version_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
}

/**
 * Test 12: receiving a VERSION response whose header advertises SPDM version 1.1.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_version_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 13: receiving a response whose request_response_code is GET_VERSION instead of
 * VERSION.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_version_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: receiving unexpected ERROR responses other than Busy, ResponseNotReady, and
 * RequestResynch.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_ERROR_PEER for every
 * enumerated error code.
 **/
static void req_get_version_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while (error_code <= 0xFF) {
        status = libspdm_get_version(spdm_context, NULL, NULL);
        LIBSPDM_ASSERT_INT_EQUAL_CASE(status, LIBSPDM_STATUS_ERROR_PEER, error_code);

        error_code++;
        if (error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if (error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if (error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

/**
 * Test 15: receiving a VERSION message with unordered version list.
 * Requester list:5.5, 0.9, 1.0, 1.1
 * Responder list:4.2, 5.2, 1.2, 1.1, 1.0
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS and right negotiated version 1.1.
 **/
static void req_get_version_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t version_count;
    spdm_version_number_t version[SPDM_MAX_VERSION_COUNT];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    version_count = spdm_context->local_context.version.spdm_version_count;
    libspdm_copy_mem(version, sizeof(version),
                     spdm_context->local_context.version.spdm_version,
                     version_count * sizeof(spdm_version_number_t));
    spdm_context->local_context.version.spdm_version_count = 4;
    spdm_context->local_context.version.spdm_version[0] = 0x55 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[1] = 0x09 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[2] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[3] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT, 0x11);

    spdm_context->local_context.version.spdm_version_count = version_count;
    libspdm_copy_mem(spdm_context->local_context.version.spdm_version,
                     sizeof(spdm_context->local_context.version.spdm_version),
                     version,
                     version_count * sizeof(spdm_version_number_t));
}

/**
 * Test 16: receiving a correct VERSION message with available version 1.0 and 1.1.
 * Buffers A, B and C already have arbitrary data.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS, buffers A, B and C
 * should be first reset, and then buffer A receives only the exchanged GET_VERSION
 * and VERSION messages.
 **/
static void req_get_version_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    /*filling buffers with arbitrary data*/
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, 10, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = 10;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_set_mem(spdm_context->transcript.message_b.buffer, 8, (uint8_t) 0xEE);
    spdm_context->transcript.message_b.buffer_size = 8;
    libspdm_set_mem(spdm_context->transcript.message_c.buffer, 12, (uint8_t) 0xDD);
    spdm_context->transcript.message_c.buffer_size = 12;
#endif

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, m_libspdm_local_buffer_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%zx):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer,
                        m_libspdm_local_buffer, m_libspdm_local_buffer_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
}

/**
 * Test 17: receiving a VERSION response that contains only the SPDM message header.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_version_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 18: receiving a VERSION response whose declared entry count requires more bytes
 * than the message provides.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_version_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 19: transcript message A cannot fit the outgoing GET_VERSION request.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_BUFFER_FULL and does not
 * retain transcript data.
 **/
static void req_get_version_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t max_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    max_buffer_size = spdm_context->transcript.message_a.max_buffer_size;
    spdm_context->transcript.message_a.max_buffer_size =
        sizeof(spdm_get_version_request_t) - 1;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_FULL);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);

    spdm_context->transcript.message_a.max_buffer_size = max_buffer_size;
}

/**
 * Test 20: transcript message A can fit the GET_VERSION request but not the VERSION
 * response.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_BUFFER_FULL and resets
 * transcript message A.
 **/
static void req_get_version_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t max_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    max_buffer_size = spdm_context->transcript.message_a.max_buffer_size;
    spdm_context->transcript.message_a.max_buffer_size =
        sizeof(spdm_get_version_request_t);

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_FULL);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);

    spdm_context->transcript.message_a.max_buffer_size = max_buffer_size;
}

/**
 * Test 21: caller-provided version entry buffer is too small for the responder list.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_BUFFER_TOO_SMALL, updates
 * the required count, and resets transcript message A.
 **/
static void req_get_version_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t version_count;
    spdm_version_number_t version[2];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    version_count = 1;
    libspdm_zero_mem(version, sizeof(version));

    status = libspdm_get_version(spdm_context, &version_count, version);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(version_count, 2);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
}

/**
 * Test 22: receiving an unordered VERSION list with a sufficiently large caller buffer.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_SUCCESS and sorts the
 * copied version list.
 **/
static void req_get_version_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t version_count;
    uint8_t local_version_count;
    spdm_version_number_t version[SPDM_MAX_VERSION_COUNT];
    spdm_version_number_t local_version[SPDM_MAX_VERSION_COUNT];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    local_version_count = spdm_context->local_context.version.spdm_version_count;
    libspdm_copy_mem(local_version, sizeof(local_version),
                     spdm_context->local_context.version.spdm_version,
                     local_version_count * sizeof(spdm_version_number_t));

    spdm_context->local_context.version.spdm_version_count = 4;
    spdm_context->local_context.version.spdm_version[0] = 0x55 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[1] = 0x09 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[2] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[3] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    version_count = 5;
    libspdm_zero_mem(version, sizeof(version));

    status = libspdm_get_version(spdm_context, &version_count, version);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(version_count, 5);
    assert_int_equal(version[0] >> SPDM_VERSION_NUMBER_SHIFT_BIT, 0x52);
    assert_int_equal(version[1] >> SPDM_VERSION_NUMBER_SHIFT_BIT, 0x42);
    assert_int_equal(version[2] >> SPDM_VERSION_NUMBER_SHIFT_BIT, 0x12);
    assert_int_equal(version[3] >> SPDM_VERSION_NUMBER_SHIFT_BIT, 0x11);
    assert_int_equal(version[4] >> SPDM_VERSION_NUMBER_SHIFT_BIT, 0x10);

    spdm_context->local_context.version.spdm_version_count = local_version_count;
    libspdm_copy_mem(spdm_context->local_context.version.spdm_version,
                     sizeof(spdm_context->local_context.version.spdm_version),
                     local_version,
                     local_version_count * sizeof(spdm_version_number_t));
}

int libspdm_req_get_version_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* cmocka_unit_test(req_get_version_case1), */
        cmocka_unit_test(req_get_version_case2),
        /* cmocka_unit_test(req_get_version_case3), */
        cmocka_unit_test(req_get_version_case4),
        cmocka_unit_test(req_get_version_case5),
        cmocka_unit_test(req_get_version_case6),
        cmocka_unit_test(req_get_version_case7),
        cmocka_unit_test(req_get_version_case8),
        cmocka_unit_test(req_get_version_case9),
        cmocka_unit_test(req_get_version_case10),
        cmocka_unit_test(req_get_version_case11),
        cmocka_unit_test(req_get_version_case12),
        cmocka_unit_test(req_get_version_case13),
        cmocka_unit_test(req_get_version_case14),
        cmocka_unit_test(req_get_version_case15),
        cmocka_unit_test(req_get_version_case16),
        cmocka_unit_test(req_get_version_case17),
        cmocka_unit_test(req_get_version_case18),
        cmocka_unit_test(req_get_version_case19),
        cmocka_unit_test(req_get_version_case20),
        cmocka_unit_test(req_get_version_case21),
        cmocka_unit_test(req_get_version_case22),
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
