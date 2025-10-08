/**
 *  Copyright Notice:
 *  Copyright 2024-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP

extern bool g_event_get_types_error;

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    g_event_get_types_error = false;
}

/**
 * Test 1: Responder has not set EVENT_CAP.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void libspdm_test_responder_supported_event_types_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_supported_event_types_request_t spdm_request;
    size_t spdm_request_size = sizeof(spdm_request);
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size = sizeof(response);
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;

    set_standard_state(spdm_context);

    /* Responder is not an event notifier. */
    spdm_context->local_context.capability.flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request.header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_get_response_supported_event_types(spdm_context,
                                                        spdm_request_size, &spdm_request,
                                                        &response_size, response);
    spdm_response = (spdm_error_response_t *)response;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_SUPPORTED_EVENT_TYPES);
}

/**
 * Test 2: Negotiated SPDM version does not support GET_SUPPORTED_EVENT_TYPES request message.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSUPPORTED_REQUEST.
 **/
static void libspdm_test_responder_supported_event_types_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_supported_event_types_request_t spdm_request;
    size_t spdm_request_size = sizeof(spdm_request);
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size = sizeof(response);
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;

    set_standard_state(spdm_context);

    /* Invalid SPDM version for the GET_SUPPORTED_EVENT_TYPES request message. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_get_response_supported_event_types(spdm_context,
                                                        spdm_request_size, &spdm_request,
                                                        &response_size, response);
    spdm_response = (spdm_error_response_t *)response;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_SUPPORTED_EVENT_TYPES);
}

/**
 * Test 3: Size of GET_SUPPORTED_EVENT_TYPES request message is incorrect.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void libspdm_test_responder_supported_event_types_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_supported_event_types_request_t spdm_request;
    size_t spdm_request_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size = sizeof(response);
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 3;

    set_standard_state(spdm_context);

    /* Incorrect request message size. */
    spdm_request_size = sizeof(spdm_request) + 1;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request.header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_get_response_supported_event_types(spdm_context,
                                                        spdm_request_size, &spdm_request,
                                                        &response_size, response);
    spdm_response = (spdm_error_response_t *)response;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 4: SPDM version field in GET_SUPPORTED_EVENT_TYPES request message does not match the
 *         connection's negotiated version.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_VERSION_MISMATCH.
 **/
static void libspdm_test_responder_supported_event_types_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_supported_event_types_request_t spdm_request;
    size_t spdm_request_size = sizeof(spdm_request);
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size = sizeof(response);
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 4;

    set_standard_state(spdm_context);

    /* Value is not equal to the negotiated SPDM version (1.3). */
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_14;
    spdm_request.header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_get_response_supported_event_types(spdm_context,
                                                        spdm_request_size, &spdm_request,
                                                        &response_size, response);
    spdm_response = (spdm_error_response_t *)response;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 5: Call to libspdm_event_get_types fails.
 * Expected Behavior: Responder returns SPDM_ERROR_CODE_UNSPECIFIED.
 **/
static void libspdm_test_responder_supported_event_types_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_supported_event_types_request_t spdm_request;
    size_t spdm_request_size = sizeof(spdm_request);
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size = sizeof(response);
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 5;

    set_standard_state(spdm_context);

    /* Induce error in libspdm_event_get_types. */
    g_event_get_types_error = true;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request.header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_get_response_supported_event_types(spdm_context,
                                                        spdm_request_size, &spdm_request,
                                                        &response_size, response);
    spdm_response = (spdm_error_response_t *)response;

    g_event_get_types_error = false;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
}

int libspdm_rsp_supported_event_types_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_responder_supported_event_types_err_case1),
        cmocka_unit_test(libspdm_test_responder_supported_event_types_err_case2),
        cmocka_unit_test(libspdm_test_responder_supported_event_types_err_case3),
        cmocka_unit_test(libspdm_test_responder_supported_event_types_err_case4),
        cmocka_unit_test(libspdm_test_responder_supported_event_types_err_case5),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
