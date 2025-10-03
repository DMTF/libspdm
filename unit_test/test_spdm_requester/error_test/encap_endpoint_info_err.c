/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    /* param1 - subcode of the request
     * param2 - Bit[7:4]: reserved
     *          Bit[3:0]: slot_id */
    uint8_t request_attributes;
    uint8_t reserved[3];
    uint8_t nonce[32];
} spdm_get_endpoint_info_request_max_t;
#pragma pack()

/* request signature, correct */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request_err1 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request_err1_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* request signature, but version 12 */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request_err2 = {
    { SPDM_MESSAGE_VERSION_12, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request_err2_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* request signature, but no nonce */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request_err3 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* no nonce */
};
size_t m_libspdm_get_endpoint_info_request_err3_size =
    sizeof(spdm_get_endpoint_info_request_t);

/* request signature, but invalid slot_id */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request_err4 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0xA},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request_err4_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* request signature, correct, with slot_id == 0xF */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request_err5 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 0xF},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request_err5_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* request signature, correct, with slot_id == 0x1 */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request_err6 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER, 1},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request_err6_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/* request signature, but sub_code invalid */
spdm_get_endpoint_info_request_max_t m_libspdm_get_endpoint_info_request_err7 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO,
      2, 0},
    SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
    {0, 0, 0},
    /* nonce */
};
size_t m_libspdm_get_endpoint_info_request_err7_size =
    sizeof(spdm_get_endpoint_info_request_t) + SPDM_NONCE_SIZE;

/**
 * Test 1: Error case, connection version is lower than 1.3
 * Expected Behavior: generate an ERROR_RESPONSE with code
 *                    SPDM_ERROR_CODE_UNSUPPORTED_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    /* connection version is lower than 1.3 */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err1.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err1_size,
        &m_libspdm_get_endpoint_info_request_err1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_ENDPOINT_INFO);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 2: Error Case: Requester does not support EP_INFO_CAP
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNSUPPORTED_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0; /* no EP_INFO_CAP */
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err1.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err1_size,
        &m_libspdm_get_endpoint_info_request_err1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_ENDPOINT_INFO);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 3: Error Case: Request contains mismatch version
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err2.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err2_size,
        &m_libspdm_get_endpoint_info_request_err2, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 4: Error Case: Signature was required, but responder only support EP_INFO_CAP_NO_SIG
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNSUPPORTED_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err1.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err1_size,
        &m_libspdm_get_endpoint_info_request_err1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_ENDPOINT_INFO);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 5: Error Case: Signature was required, but there is no nonce in request
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err3_size,
        &m_libspdm_get_endpoint_info_request_err3, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 6: Error Case: Request contains invalid slot_id
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err4.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err4_size,
        &m_libspdm_get_endpoint_info_request_err4, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 7: Error case, signature was required
 *         but local_cert_chain_provision[slot_id] == NULL
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    /* no initialization for spdm_context->local_context.local_cert_chain_provision */
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = 0;
        spdm_context->local_context.local_cert_chain_provision[i] = NULL;
    }

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err1.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err1_size,
        &m_libspdm_get_endpoint_info_request_err1, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 8: Error case, signature was required, slot_id == 0xF
 *         but local_public_key_provision == NULL
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    /* no initialization for spdm_context->local_context.local_public_key_provision */
    spdm_context->local_context.local_public_key_provision = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err5.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err5_size,
        &m_libspdm_get_endpoint_info_request_err5, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 9: Error case, signature was required, multi_key_conn_rsp is set
 *         but local_key_usage_bit_mask[slot_id] not meet requirement
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size, NULL, NULL);

    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
        spdm_context->local_context.local_cert_chain_provision[0] = data;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
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
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            data, data_size,
            &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
    }

    session_info = NULL;
    spdm_context->connection_info.multi_key_conn_rsp = true;
    /* no initialization for spdm_context->local_context.local_key_usage_bit_mask */
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_key_usage_bit_mask[i] = 0;
    }

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err6.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err6_size,
        &m_libspdm_get_endpoint_info_request_err6, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

/**
 * Test 10: Error case, invalid sub_code
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_requester_encap_endpoint_info_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t* session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    session_info = NULL;

    libspdm_reset_message_encap_e(spdm_context, session_info);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_endpoint_info_request_err7.nonce);

    status = libspdm_get_encap_response_endpoint_info(
        spdm_context, m_libspdm_get_endpoint_info_request_err7_size,
        &m_libspdm_get_endpoint_info_request_err7, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* response size check */
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    /* response message check */
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* transcript.message_encap_e size check */
    assert_int_equal(spdm_context->transcript.message_encap_e.buffer_size, 0);
#endif
}

int libspdm_req_encap_endpoint_info_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Connection version is lower than 1.3 */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case1),
        /* Requester does not support EP_INFO_CAP */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case2),
        /* Request contains mismatch version */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case3),
        /* Signature was required, but responder only support EP_INFO_CAP_NO_SIG */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case4),
        /* Signature was required, but there is no nonce in request */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case5),
        /* Request contains invalid slot_id */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case6),
        /* Signature was required but local_cert_chain_provision[slot_id] == NULL */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case7),
        /* Signature was required, slot_id == 0xF but local_public_key_provision == NULL */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case8),
        /* Signature was required, multi_key_conn_rsp is set but
         * local_key_usage_bit_mask[slot_id] not meet requirement
         */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case9),
        /* Invalid sub_code */
        cmocka_unit_test(libspdm_test_requester_encap_endpoint_info_err_case10),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (...) */
