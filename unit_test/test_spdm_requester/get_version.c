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
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];
} spdm_version_response_mine_t;
#pragma pack()

return_status spdm_requester_get_version_test_send_message(
    void *spdm_context, uintn request_size, const void *request,
    uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;
    case 0x2:
        return RETURN_SUCCESS;
    case 0x3:
        return RETURN_SUCCESS;
    case 0x4:
        return RETURN_SUCCESS;
    case 0x5:
        return RETURN_SUCCESS;
    case 0x6:
        return RETURN_SUCCESS;
    case 0x7:
        return RETURN_SUCCESS;
    case 0x8:
        return RETURN_SUCCESS;
    case 0x9:
        return RETURN_SUCCESS;
    case 0xA:
        return RETURN_SUCCESS;
    case 0xB:
        return RETURN_SUCCESS;
    case 0xC:
        return RETURN_SUCCESS;
    case 0xD:
        return RETURN_SUCCESS;
    case 0xE:
        return RETURN_SUCCESS;
    case 0xF:
        return RETURN_SUCCESS;
    default:
        return RETURN_DEVICE_ERROR;
    }
}

return_status spdm_requester_get_version_test_receive_message(
    void *spdm_context, uintn *response_size,
    void *response, uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;

    case 0x2: {
        spdm_version_response_mine_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_VERSION;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.version_number_entry_count = 2;
        spdm_response.version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x3: {
        spdm_version_response_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_VERSION;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.version_number_entry_count = 0;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0x4: {
        spdm_error_response_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

            zero_mem(&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
        } else if (sub_index1 == 1) {
            spdm_version_response_mine_t spdm_response;

            zero_mem(&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response.header.request_response_code =
                SPDM_VERSION;
            spdm_response.header.param1 = 0;
            spdm_response.header.param2 = 0;
            spdm_response.version_number_entry_count = 2;
            spdm_response.version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
            spdm_response.version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
        }
        sub_index1++;
    }
        return RETURN_SUCCESS;

    case 0x7: {
        spdm_error_response_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response.header.param2 = 0;
        spdm_response.extend_error_data.rd_exponent = 1;
        spdm_response.extend_error_data.rd_tm = 1;
        spdm_response.extend_error_data.request_code = SPDM_GET_VERSION;
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

            zero_mem(&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response.header.param2 = 0;
            spdm_response.extend_error_data.rd_exponent = 1;
            spdm_response.extend_error_data.rd_tm = 1;
            spdm_response.extend_error_data.request_code =
                SPDM_GET_VERSION;
            spdm_response.extend_error_data.token = 1;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
        } else if (sub_index2 == 1) {
            spdm_version_response_mine_t spdm_response;

            zero_mem(&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response.header.request_response_code =
                SPDM_VERSION;
            spdm_response.header.param1 = 0;
            spdm_response.header.param2 = 0;
            spdm_response.version_number_entry_count = 2;
            spdm_response.version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
            spdm_response.version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

            spdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                sizeof(spdm_response), &spdm_response,
                response_size, response);
        }
        sub_index2++;
    }
        return RETURN_SUCCESS;

    case 0xA: {
        spdm_version_response_mine_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_VERSION;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.version_number_entry_count = 2;
        spdm_response.version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[2] = 0x12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0xB: {
        spdm_version_response_mine_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_VERSION;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.version_number_entry_count = 2;
        spdm_response.version_number_entry[0] = 0xA0 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[1] = 0xA1 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0xC: {
        spdm_version_response_mine_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_VERSION;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.version_number_entry_count = 2;
        spdm_response.version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0xD: {
        spdm_version_response_mine_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_GET_VERSION;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.version_number_entry_count = 2;
        spdm_response.version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;

    case 0xE:
    {
        static uint16_t error_code = SPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t spdm_response;

        if(error_code <= 0xff) {
            zero_mem (&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = (uint8_t) error_code;

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

    case 0xF: {
        spdm_version_response_mine_t spdm_response;

        zero_mem(&spdm_response, sizeof(spdm_response));
        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response.header.request_response_code = SPDM_VERSION;
        spdm_response.header.param1 = 0;
        spdm_response.header.param2 = 0;
        spdm_response.version_number_entry_count = 5;
        spdm_response.version_number_entry[0] = 0x42 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[1] = 0x52 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[2] = 0x12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[3] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response.version_number_entry[4] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_transport_test_encode_message(spdm_context, NULL, false,
                                           false, sizeof(spdm_response),
                                           &spdm_response,
                                           response_size, response);
    }
        return RETURN_SUCCESS;
    default:
        return RETURN_DEVICE_ERROR;
    }
}

/**
 * Test 1: when no VERSION message is received, and the client returns a device error.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case1(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 2: receiving a correct VERSION message with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void test_spdm_requester_get_version_case2(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
}

/**
 * Test 3: receiving a correct VERSION message header, but with 0 versions available.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case3(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 4: receiving an InvalidRequest ERROR message from the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case4(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 5: receiving an Busy ERROR message correct VERSION message from the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case5(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_NO_RESPONSE);
}

/**
 * Test 6: on the first try, receiving a Busy ERROR message, and on retry, receiving
 * a correct VERSION message with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void test_spdm_requester_get_version_case6(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
}

/**
 * Test 7: receiving a RequestResynch ERROR message from the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the
 * internal state should be reset.
 * Note: As from 1.1.c, this is an unexpected behavior, as the responder should not
 * respond a GET_VERSION message with a RequestResynch. It should expect a GET_VERSION.
 **/
void test_spdm_requester_get_version_case7(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
 * Test 8: receiving a ResponseNotReady ERROR message from the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 * Note: As from 1.0.0, this is an unexpected behavior, as the responder should not
 * respond a GET_VERSION message with a ResponseNotReady.
 **/
void test_spdm_requester_get_version_case8(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 9: on the first try, receiving a ResponseNotReady ERROR message, and on retry,
 * receiving a correct VERSION message with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 * Note: The responder should not
 * respond a GET_VERSION message with a ResponseNotReady.
 **/
void test_spdm_requester_get_version_case9(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 10: receiving a VERSION message with a larger list of available versions than indicated.
 * The presence of only two versions are indicated, but the VERSION message presents a list
 * with 3 versions: 1.0, 1.1 and 1.2.
 * Expected behavior: client returns a status of RETURN_SUCCESS, but truncate the message
 * to consider only the two first versions, as indicated in the message.
 **/
void test_spdm_requester_get_version_case10(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
}

/**
 * Test 11: receiving a correct VERSION message with available version 10.0 and 10.1, but
 * the requester do not have compatible versions with the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case11(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 12: receiving a VERSION message in SPDM version 1.1 (in the header), but correct
 * 1.0-version format, with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case12(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 13: receiving a VERSION message with wrong SPDM request_response_code (in this
 * case, GET_VERSION 0x84 instead of VERSION 0x04). The remaining data is a correct
 * VERSION message, with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case13(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
 * Test 14: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_requester_get_version_case14(void **state) {
    return_status status;
    spdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    error_code = SPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        /* no additional state control is necessary as a new GET_VERSION resets the state*/
        status = spdm_get_version (spdm_context, NULL, NULL);
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
}

/**
 * Test 15: receiving a VERSION message with unordered vesion list.
 * Requester list:5.5, 4.5, 0.9, 1.0, 1.1
 * Responder list:4.2, 5.2, 1.2, 1.1, 1.0
 * Expected behavior: client returns a status of RETURN_SUCCESS and right negotiated version 1.1.
 **/
void test_spdm_requester_get_version_case15(void **state)
{
    return_status status;
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->local_context.version.spdm_version_count = 5;
    spdm_context->local_context.version.spdm_version[0] = 0x55 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[1] = 0x45 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[2] = 0x09 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[3] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[4] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    status = spdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, RETURN_SUCCESS);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT, 0x11);
}

spdm_test_context_t mSpdmRequesterGetVersionTestContext = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    true,
    spdm_requester_get_version_test_send_message,
    spdm_requester_get_version_test_receive_message,
};

int spdm_requester_get_version_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_version_tests[] = {
        cmocka_unit_test(test_spdm_requester_get_version_case1),
        cmocka_unit_test(test_spdm_requester_get_version_case2),
        cmocka_unit_test(test_spdm_requester_get_version_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_requester_get_version_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(test_spdm_requester_get_version_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(test_spdm_requester_get_version_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(test_spdm_requester_get_version_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(test_spdm_requester_get_version_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(test_spdm_requester_get_version_case9),
        /* Successful response*/
        cmocka_unit_test(test_spdm_requester_get_version_case10),
        /* Successful response + device error*/
        cmocka_unit_test(test_spdm_requester_get_version_case11),
        cmocka_unit_test(test_spdm_requester_get_version_case12),
        cmocka_unit_test(test_spdm_requester_get_version_case13),
        /* Unexpected errors*/
        cmocka_unit_test(test_spdm_requester_get_version_case14),
        /* Successful response for unordered version set*/
        cmocka_unit_test(test_spdm_requester_get_version_case15),
    };

    setup_spdm_test_context(&mSpdmRequesterGetVersionTestContext);

    return cmocka_run_group_tests(spdm_requester_get_version_tests,
                                  spdm_unit_test_group_setup,
                                  spdm_unit_test_group_teardown);
}
