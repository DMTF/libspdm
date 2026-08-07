/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#define LIBSPDM_DEFAULT_CAPABILITY_FLAG \
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP)

#define LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11 \
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)

#define LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP

#define LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 \
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)

#define LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_12 \
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)

 #define LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13 \
     (LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 | \
      LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_12 | \
      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG  | \
      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP | \
      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP | \
      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY | \
      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP)

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
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
    case 0xa:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xb:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xc:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xd:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xe:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xf:
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
    case 0x1a:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1b:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1c:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1d:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1E:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1F:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x20: {
        const uint8_t *ptr = (const uint8_t *)request;

        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x21:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x22:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x23:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x24:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x25:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x26:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x27:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x28:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x29:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2A:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2B:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2C:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2D:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2E:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2F:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x30:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x31:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x32:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x33:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x34:
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
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

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
            spdm_capabilities_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_capabilities_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_CAPABILITIES;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->ct_exponent = 0;
            spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

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
        spdm_response->extend_error_data.request_code = SPDM_GET_CAPABILITIES;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;

    case 0xa: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
             SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xb: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            !(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xc: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xd: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            sizeof(spdm_message_header_t), spdm_response,
            response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xe: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            sizeof(spdm_capabilities_response_t) + sizeof(uint8_t), spdm_response,
            response_size, response);
    }
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;

    case 0xf: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            sizeof(spdm_capabilities_response_t) - sizeof(uint8_t), spdm_response,
            response_size, response);
    }
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;

    case 0x10: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));
        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^ (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^ (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1a: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1b: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_GET_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1c: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = 0xFF;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1d:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem(spdm_response, spdm_response_size);
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

    case 0x1e: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1F:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x20: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

        spdm_response_size = sizeof(spdm_capabilities_response_t) -
                             sizeof(spdm_response->data_transfer_size) -
                             sizeof(spdm_response->max_spdm_msg_size);

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

    case 0x21: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_12;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x22: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x23: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x24: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t) +
                             sizeof(spdm_supported_algorithms_block_t) + 4*
                             sizeof(spdm_negotiate_algorithms_common_struct_table_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        /* Allocate space for the supported_algorithms block at the end of the response */
        spdm_supported_algorithms_block_t *supported_algorithms =
            (spdm_supported_algorithms_block_t*)((uint8_t*)spdm_response +
                                                 sizeof(spdm_capabilities_response_t) );

        supported_algorithms->param1 = 4;
        supported_algorithms->param2 = 0;
        supported_algorithms->length = sizeof(spdm_supported_algorithms_block_t) +
                                       4 *
                                       sizeof( spdm_negotiate_algorithms_common_struct_table_t);
        supported_algorithms->measurement_specification = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        supported_algorithms->other_params_support = 0;
        supported_algorithms->base_asym_algo = m_libspdm_use_asym_algo;
        supported_algorithms->base_hash_algo = m_libspdm_use_hash_algo;
        supported_algorithms->ext_asym_count = 0;
        supported_algorithms->ext_hash_count = 0;
        supported_algorithms->mel_specification = SPDM_MEL_SPECIFICATION_DMTF;

        spdm_negotiate_algorithms_common_struct_table_t *struct_table =
            (spdm_negotiate_algorithms_common_struct_table_t *)(supported_algorithms + 1);

        struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        struct_table[0].alg_count = 0x20;
        struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;

        struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        struct_table[1].alg_count = 0x20;
        struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;;

        struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        struct_table[2].alg_count = 0x20;
        struct_table[2].alg_supported = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

        struct_table[3].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        struct_table[3].alg_count = 0x20;
        struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x25: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x26: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x27: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x28: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_RESET_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        spdm_response->ext_flags = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x29: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2A: {
        spdm_capabilities_response_t *spdm_response;
        spdm_supported_algorithms_block_t *supported_algorithms;
        spdm_negotiate_algorithms_common_struct_table_t *struct_table;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t) +
                             sizeof(spdm_supported_algorithms_block_t) + 6 *
                             sizeof(spdm_negotiate_algorithms_common_struct_table_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 =
            SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        spdm_response->ext_flags = 0;

        supported_algorithms = (spdm_supported_algorithms_block_t *)(
            (uint8_t *)spdm_response + sizeof(spdm_capabilities_response_t));
        supported_algorithms->param1 = 6;
        supported_algorithms->param2 = 0;
        supported_algorithms->length = sizeof(spdm_supported_algorithms_block_t) +
                                       6 *
                                       sizeof(spdm_negotiate_algorithms_common_struct_table_t);
        supported_algorithms->measurement_specification = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        supported_algorithms->other_params_support = 0;
        supported_algorithms->base_asym_algo = m_libspdm_use_asym_algo;
        supported_algorithms->base_hash_algo = m_libspdm_use_hash_algo;
        supported_algorithms->pqc_asym_algo = SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44;
        supported_algorithms->ext_asym_count = 0;
        supported_algorithms->ext_hash_count = 0;
        supported_algorithms->mel_specification = SPDM_MEL_SPECIFICATION_DMTF;

        struct_table = (spdm_negotiate_algorithms_common_struct_table_t *)(supported_algorithms + 1);
        struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        struct_table[0].alg_count = 0x20;
        struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
        struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        struct_table[1].alg_count = 0x20;
        struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
        struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        struct_table[2].alg_count = 0x20;
        struct_table[2].alg_supported = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
        struct_table[3].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        struct_table[3].alg_count = 0x20;
        struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
        struct_table[4].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG;
        struct_table[4].alg_count = 0x20;
        struct_table[4].alg_supported = SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44;
        struct_table[5].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG;
        struct_table[5].alg_count = 0x20;
        struct_table[5].alg_supported = SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2B: {
        static size_t sub_index2 = 0;

        if (sub_index2 == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                                  false, spdm_response_size,
                                                  spdm_response,
                                                  response_size, response);
        } else {
            spdm_capabilities_response_t *spdm_response;
            spdm_supported_algorithms_block_t *supported_algorithms;
            spdm_negotiate_algorithms_common_struct_table_t *struct_table;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_capabilities_response_t) +
                                 sizeof(spdm_supported_algorithms_block_t) + 6 *
                                 sizeof(spdm_negotiate_algorithms_common_struct_table_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_14;
            spdm_response->header.request_response_code = SPDM_CAPABILITIES;
            spdm_response->header.param1 =
                SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS;
            spdm_response->header.param2 = 0;
            spdm_response->ct_exponent = 0;
            spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
            spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
            spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
            spdm_response->ext_flags = 0;

            supported_algorithms = (spdm_supported_algorithms_block_t *)(
                (uint8_t *)spdm_response + sizeof(spdm_capabilities_response_t));
            supported_algorithms->param1 = 6;
            supported_algorithms->param2 = 0;
            supported_algorithms->length = sizeof(spdm_supported_algorithms_block_t) +
                                           6 * sizeof(spdm_negotiate_algorithms_common_struct_table_t);
            supported_algorithms->measurement_specification =
                SPDM_MEASUREMENT_SPECIFICATION_DMTF;
            supported_algorithms->other_params_support = 0;
            supported_algorithms->base_asym_algo = m_libspdm_use_asym_algo;
            supported_algorithms->base_hash_algo = m_libspdm_use_hash_algo;
            supported_algorithms->pqc_asym_algo =
                SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44;
            supported_algorithms->ext_asym_count = 0;
            supported_algorithms->ext_hash_count = 0;
            supported_algorithms->mel_specification = SPDM_MEL_SPECIFICATION_DMTF;

            struct_table =
                (spdm_negotiate_algorithms_common_struct_table_t *)(supported_algorithms + 1);
            struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
            struct_table[0].alg_count = 0x20;
            struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
            struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
            struct_table[1].alg_count = 0x20;
            struct_table[1].alg_supported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
            struct_table[2].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
            struct_table[2].alg_count = 0x20;
            struct_table[2].alg_supported =
                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
            struct_table[3].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
            struct_table[3].alg_count = 0x20;
            struct_table[3].alg_supported = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
            struct_table[4].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG;
            struct_table[4].alg_count = 0x20;
            struct_table[4].alg_supported = SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44;
            struct_table[5].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG;
            struct_table[5].alg_count = 0x20;
            struct_table[5].alg_supported = SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512;

            libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                                  false, spdm_response_size,
                                                  spdm_response,
                                                  response_size, response);
        }
        sub_index2++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2C: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t) +
                             sizeof(spdm_supported_algorithms_block_t) - 1;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 =
            SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2D: {
        spdm_capabilities_response_t *spdm_response;
        spdm_supported_algorithms_block_t *supported_algorithms;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t) +
                             sizeof(spdm_supported_algorithms_block_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 =
            SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        supported_algorithms = (void *)((uint8_t *)spdm_response +
                                        sizeof(spdm_capabilities_response_t));
        supported_algorithms->length = sizeof(spdm_supported_algorithms_block_t) - 1;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2E: {
        spdm_capabilities_response_t *spdm_response;
        spdm_supported_algorithms_block_t *supported_algorithms;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t) +
                             sizeof(spdm_supported_algorithms_block_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 =
            SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        supported_algorithms = (void *)((uint8_t *)spdm_response +
                                        sizeof(spdm_capabilities_response_t));
        supported_algorithms->length = sizeof(spdm_supported_algorithms_block_t) + 1;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x2F: {
        spdm_capabilities_response_t *spdm_response;
        spdm_supported_algorithms_block_t *supported_algorithms;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t) +
                             sizeof(spdm_supported_algorithms_block_t) +
                             sizeof(spdm_negotiate_algorithms_common_struct_table_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 =
            SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        supported_algorithms = (void *)((uint8_t *)spdm_response +
                                        sizeof(spdm_capabilities_response_t));
        supported_algorithms->length = sizeof(spdm_supported_algorithms_block_t);
        supported_algorithms->param1 = 1;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x30: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                               (3u << 22) |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x31: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x32: {
        spdm_message_header_t *spdm_response;
        size_t transport_header_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response, sizeof(*spdm_response));
        spdm_response->spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->request_response_code = SPDM_CAPABILITIES;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_message_header_t) - 1,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x33: {
        spdm_capabilities_response_t *spdm_response;
        size_t transport_header_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response, sizeof(*spdm_response));
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, sizeof(spdm_capabilities_response_t) - 1,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x34: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG |
                               SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

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

/*
 * static void req_get_capabilities_case1(void **state)
 * {
 * }
 */

static void req_get_capabilities_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     LIBSPDM_DEFAULT_CAPABILITY_FLAG);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/*
 * static void req_get_capabilities_case3(void **state)
 * {
 * }
 */

/*
 * static void req_get_capabilities_case4(void **state)
 * {
 * }
 */

/*
 * static void req_get_capabilities_case5(void **state)
 * {
 * }
 */

static void req_get_capabilities_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     LIBSPDM_DEFAULT_CAPABILITY_FLAG);
}

/*
 * static void req_get_capabilities_case7(void **state)
 * {
 * }
 */

/*
 * static void req_get_capabilities_case8(void **state)
 * {
 * }
 */

/*
 * static void req_get_capabilities_case9(void **state)
 * {
 * }
 */

static void req_get_capabilities_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xa;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
                      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
                      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
                      SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP));
}

static void req_get_capabilities_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xb;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(
        spdm_context->connection_info.capability.flags,
        !(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP));
}

static void req_get_capabilities_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xc;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);
}

/**
 * Test 13: Responder returns a CAPABILITIES message that is shorter than the
 * SPDM 1.0 minimum size.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_capabilities_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xd;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 14: Transport decode reports an invalid GET_CAPABILITIES response size.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_capabilities_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xe;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 15: Transport decode reports a truncated GET_CAPABILITIES response.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_capabilities_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xf;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

static void req_get_capabilities_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11);
}

/**
 * Test 17: Responder clears ENCAP_CAP while MUT_AUTH_CAP remains set.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 18: Responder clears KEY_EX_CAP but leaves dependent capability bits set.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 19: Responder reports KEY_EX_CAP without MAC_CAP or ENCRYPT_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 20: Responder sets CERT_CAP and PUB_KEY_ID_CAP together.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1a;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 21: Responder returns the wrong message code.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1b;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 22: Responder returns a mismatched SPDM version in CAPABILITIES.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1c;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 23: Responder returns every simple error except the explicitly-handled ones.
 * Expected behavior: returns with status LIBSPDM_STATUS_ERROR_PEER.
 **/
static void req_get_capabilities_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1d;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while (error_code <= 0xff) {
        spdm_context->connection_info.connection_state =
            LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
        libspdm_reset_message_a(spdm_context);

        status = libspdm_get_capabilities(spdm_context);
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
 * Test 24: Responder enables ALIAS_CERT_CAP without CERT_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1e;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 25: Transport receive fails while waiting for CAPABILITIES.
 * Expected behavior: returns with status LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void req_get_capabilities_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 26: Responder sets EVENT_CAP without session capabilities in SPDM 1.3.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x25;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 27: Responder enables CERT_CAP in SPDM 1.3 without a usable follow-on capability.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x26;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 28: Responder sets MUT_AUTH_CAP without CHAL_CAP or KEY_EX_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x27;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 29: Responder sets SET_KEY_PAIR_RESET_CAP without SET_KEY_PAIR_INFO_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case29(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x28;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;
    spdm_context->local_context.capability.ext_flags = 0;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    spdm_context->local_context.capability.ext_flags = 0;
}

/**
 * Test 30: Responder sets PUB_KEY_ID_CAP together with MULTI_KEY_CAP in SPDM 1.3.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x29;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 31: CAPABILITIES request succeeds in SPDM 1.4 and returns SupportedAlgorithms data.
 * Expected behavior: returns with status LIBSPDM_STATUS_SUCCESS.
 **/
static void req_get_capabilities_case31(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1024];
    size_t supported_algs_length;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2A;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;
    spdm_context->local_context.capability.ext_flags = 0;
    supported_algs_length = sizeof(supported_algs_buffer);

    status = libspdm_get_capabilities_with_supported_algs(
        spdm_context, &supported_algs_length, supported_algs_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(supported_algs_length > 0);
    spdm_context->local_context.capability.ext_flags = 0;
}

static void req_get_capabilities_case32(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t arbitrary_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    /*filling A with arbitrary data*/
    arbitrary_size = 10;
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, arbitrary_size, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = arbitrary_size;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11);
    libspdm_dump_hex(spdm_context->transcript.message_a.buffer,
                     spdm_context->transcript.message_a.buffer_size);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     arbitrary_size + m_libspdm_local_buffer_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%zx):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size,
                        m_libspdm_local_buffer, m_libspdm_local_buffer_size);
}

static void req_get_capabilities_case33(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.max_spdm_msg_size,
                     LIBSPDM_MAX_SPDM_MSG_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.data_transfer_size,
                     LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_12);
}


/**
 * Test 34: Message A has room for the request but not the response.
 * Expected behavior: returns with status LIBSPDM_STATUS_BUFFER_FULL.
 **/
static void req_get_capabilities_case34(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x22;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;
    request_size = sizeof(spdm_get_capabilities_request_t);
    spdm_context->transcript.message_a.buffer_size =
        spdm_context->transcript.message_a.max_buffer_size - request_size;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_FULL);

    spdm_context->transcript.message_a.buffer_size = 0;
}

/**
 * Test 37: SupportedAlgorithms buffer is smaller than the returned block.
 * Expected behavior: returns with status LIBSPDM_STATUS_BUFFER_TOO_SMALL.
 **/
static void req_get_capabilities_case37(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1];
    size_t supported_algs_length;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2A;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;
    spdm_context->local_context.capability.ext_flags = 0;
    supported_algs_length = sizeof(supported_algs_buffer);

    status = libspdm_get_capabilities_with_supported_algs(
        spdm_context, &supported_algs_length, supported_algs_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_true(supported_algs_length > sizeof(supported_algs_buffer));
    spdm_context->local_context.capability.ext_flags = 0;
}

/**
 * Test 38: Peer first returns Busy, then returns a valid SupportedAlgorithms response.
 * Expected behavior: returns with status LIBSPDM_STATUS_SUCCESS.
 **/
static void req_get_capabilities_case38(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1024];
    size_t supported_algs_length;
    uint8_t retry_times;
    uint64_t retry_delay_time;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2B;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_14 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;
    spdm_context->local_context.capability.ext_flags = 0;
    retry_times = spdm_context->retry_times;
    retry_delay_time = spdm_context->retry_delay_time;
    spdm_context->retry_times = 1;
    spdm_context->retry_delay_time = 0;
    supported_algs_length = sizeof(supported_algs_buffer);

    status = libspdm_get_capabilities_with_supported_algs(
        spdm_context, &supported_algs_length, supported_algs_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(supported_algs_length > 0);
    spdm_context->retry_times = retry_times;
    spdm_context->retry_delay_time = retry_delay_time;
    spdm_context->local_context.capability.ext_flags = 0;
}

/**
 * Test 39: SupportedAlgorithms bit is set but the fixed block header is truncated.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case39(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1024];
    size_t supported_algs_length = sizeof(supported_algs_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2C;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities_with_supported_algs(
        spdm_context, &supported_algs_length, supported_algs_buffer);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 40: SupportedAlgorithms block length is smaller than its fixed header.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case40(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1024];
    size_t supported_algs_length = sizeof(supported_algs_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2D;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities_with_supported_algs(
        spdm_context, &supported_algs_length, supported_algs_buffer);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 41: SupportedAlgorithms block length exceeds the received CAPABILITIES payload.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case41(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1024];
    size_t supported_algs_length = sizeof(supported_algs_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2E;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities_with_supported_algs(
        spdm_context, &supported_algs_length, supported_algs_buffer);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 42: SupportedAlgorithms block length does not match its declared table count.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case42(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1024];
    size_t supported_algs_length = sizeof(supported_algs_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2F;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities_with_supported_algs(
        spdm_context, &supported_algs_length, supported_algs_buffer);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 43: Responder returns a reserved EP_INFO_CAP value in SPDM 1.3.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case43(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x30;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 44: Responder sets MULTI_KEY_CAP without GET_KEY_PAIR_INFO_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case44(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x31;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 45: Responder returns fewer than four header bytes.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case45(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x32;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 46: SPDM 1.2 CAPABILITIES response is smaller than the fixed structure.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_SIZE.
 **/
static void req_get_capabilities_case46(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x33;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 47: Responder returns the reserved MULTI_KEY_CAP value (both bits set) in SPDM 1.3.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void req_get_capabilities_case47(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x34;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void req_get_capabilities_case35(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x23;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;

    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.max_spdm_msg_size,
                     LIBSPDM_MAX_SPDM_MSG_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.data_transfer_size,
                     LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13);
}

static void req_get_capabilities_case36(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t supported_algs_buffer[1024];
    size_t supported_algs_length = sizeof(supported_algs_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x24;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;

    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    status = libspdm_get_capabilities_with_supported_algs(spdm_context, &supported_algs_length,
                                                          &supported_algs_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.capability.max_spdm_msg_size,
                     LIBSPDM_MAX_SPDM_MSG_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.data_transfer_size,
                     LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.ct_exponent, 0);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_13);
}

int libspdm_req_get_capabilities_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* cmocka_unit_test(req_get_capabilities_case1), */
        cmocka_unit_test(req_get_capabilities_case2),
        /* cmocka_unit_test(req_get_capabilities_case3),
         * cmocka_unit_test(req_get_capabilities_case4),
         * cmocka_unit_test(req_get_capabilities_case5), */
        cmocka_unit_test(req_get_capabilities_case6),
        /* cmocka_unit_test(req_get_capabilities_case7),
         * cmocka_unit_test(req_get_capabilities_case8),
         * cmocka_unit_test(req_get_capabilities_case9), */
        cmocka_unit_test(req_get_capabilities_case10),
        cmocka_unit_test(req_get_capabilities_case11),
        cmocka_unit_test(req_get_capabilities_case12),
        cmocka_unit_test(req_get_capabilities_case13),
        cmocka_unit_test(req_get_capabilities_case14),
        cmocka_unit_test(req_get_capabilities_case15),
        cmocka_unit_test(req_get_capabilities_case16),
        cmocka_unit_test(req_get_capabilities_case17),
        cmocka_unit_test(req_get_capabilities_case18),
        cmocka_unit_test(req_get_capabilities_case19),
        cmocka_unit_test(req_get_capabilities_case20),
        cmocka_unit_test(req_get_capabilities_case21),
        cmocka_unit_test(req_get_capabilities_case22),
        cmocka_unit_test(req_get_capabilities_case23),
        cmocka_unit_test(req_get_capabilities_case24),
        cmocka_unit_test(req_get_capabilities_case25),
        cmocka_unit_test(req_get_capabilities_case26),
        cmocka_unit_test(req_get_capabilities_case27),
        cmocka_unit_test(req_get_capabilities_case28),
        cmocka_unit_test(req_get_capabilities_case29),
        cmocka_unit_test(req_get_capabilities_case30),
        cmocka_unit_test(req_get_capabilities_case31),
        cmocka_unit_test(req_get_capabilities_case32),
        cmocka_unit_test(req_get_capabilities_case33),
        cmocka_unit_test(req_get_capabilities_case34),
        cmocka_unit_test(req_get_capabilities_case35),
        cmocka_unit_test(req_get_capabilities_case36),
        cmocka_unit_test(req_get_capabilities_case37),
        cmocka_unit_test(req_get_capabilities_case38),
        cmocka_unit_test(req_get_capabilities_case39),
        cmocka_unit_test(req_get_capabilities_case40),
        cmocka_unit_test(req_get_capabilities_case41),
        cmocka_unit_test(req_get_capabilities_case42),
        cmocka_unit_test(req_get_capabilities_case43),
        cmocka_unit_test(req_get_capabilities_case44),
        cmocka_unit_test(req_get_capabilities_case45),
        cmocka_unit_test(req_get_capabilities_case46),
        cmocka_unit_test(req_get_capabilities_case47),
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
