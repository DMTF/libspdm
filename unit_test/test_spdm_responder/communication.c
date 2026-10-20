/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

/* The responses that send_message was given since the case started, and the last of them. */
static size_t m_response_count;
static uint8_t m_response[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static size_t m_response_size;

#if ((LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)) && \
    (LIBSPDM_AEAD_AES_256_GCM_SUPPORT)
static const uint32_t m_session_id = 0xFFFFFFFF;

/* Application data. The second byte of each is what PLDM over MCTP sends first in a request and in
 * its response with instance ID 8, and is also an SPDM request or response code. */
static const uint8_t m_app_request[] = {0xA1, 0x88, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8};
static const uint8_t m_app_response[] = {0xB1, 0x08, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8};

/* The last request that get_app_response was given. */
static uint8_t m_app_request_received[LIBSPDM_MAX_SPDM_MSG_SIZE];
static size_t m_app_request_received_size;
static uint32_t m_app_request_session_id;
static bool m_app_request_is_app_message;

/* The Integrator's function, which answers any request with m_app_response. */
static libspdm_return_t get_app_response(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size, void *response)
{
    libspdm_copy_mem(m_app_request_received, sizeof(m_app_request_received),
                     request, request_size);
    m_app_request_received_size = request_size;
    m_app_request_session_id = (session_id != NULL) ? *session_id : 0;
    m_app_request_is_app_message = is_app_message;

    libspdm_copy_mem(response, *response_size, m_app_response, sizeof(m_app_response));
    *response_size = sizeof(m_app_response);

    return LIBSPDM_STATUS_SUCCESS;
}

/* One context both encodes and decodes each secured message, so this undoes the increment of the
 * sequence number by the encode. */
static void rewind_sequence_number(libspdm_context_t *spdm_context, bool is_request)
{
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, m_session_id);
    assert_non_null(session_info);
    secured_message_context = session_info->secured_message_context;

    if (is_request) {
        secured_message_context->application_secret.request_data_sequence_number--;
    } else {
        secured_message_context->application_secret.response_data_sequence_number--;
    }
}
#endif /* ((LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)) && (..) */

static libspdm_return_t send_message(
    void *spdm_context, size_t response_size, const void *response, uint64_t timeout)
{
    m_response_count++;
    libspdm_copy_mem(m_response, sizeof(m_response), response, response_size);
    m_response_size = response_size;

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *request_size, void **request, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        spdm_get_version_request_t *spdm_request;
        size_t spdm_request_size;
        size_t transport_header_size;

        spdm_request_size = sizeof(spdm_get_version_request_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_request = (void *)((uint8_t *)*request + transport_header_size);

        libspdm_zero_mem(spdm_request, spdm_request_size);
        spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_request->header.request_response_code = SPDM_GET_VERSION;
        spdm_request->header.param1 = 0;
        spdm_request->header.param2 = 0;

        return libspdm_transport_test_encode_message(spdm_context, NULL, false, true,
                                                     spdm_request_size, spdm_request,
                                                     request_size, request);
    }

    case 0x2:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    #if ((LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)) && \
        (LIBSPDM_AEAD_AES_256_GCM_SUPPORT)
    case 0x3: {
        libspdm_return_t status;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;
        uint8_t *app_request;
        uint32_t session_id;

        /* The encryption writes a header before the application data and random bytes after it,
         * so the application data is placed in the scratch buffer, where there is room for both
         * and no overlap with the request. */
        libspdm_get_scratch_buffer(spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        app_request = scratch_buffer + LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        libspdm_copy_mem(app_request, scratch_buffer_size - LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                         m_app_request, sizeof(m_app_request));

        session_id = m_session_id;
        status = libspdm_transport_test_encode_message(spdm_context, &session_id, true, true,
                                                       sizeof(m_app_request), app_request,
                                                       request_size, request);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        rewind_sequence_number(spdm_context, true);

        return LIBSPDM_STATUS_SUCCESS;
    }
    #endif /* ((LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)) && (..) */

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Dispatch a GET_VERSION request.
 * Expected Behavior: libspdm_responder_dispatch_message returns success after sending one
 * VERSION response, and the connection state moves to after VERSION.
 **/
static void rsp_communication_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t *session_id;
    bool is_app_message;
    uint8_t *response;
    size_t response_size;
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    m_response_count = 0;

    status = libspdm_responder_dispatch_message(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(m_response_count, 1);

    libspdm_get_scratch_buffer(spdm_context, (void **)&response, &response_size);
    status = libspdm_transport_test_decode_message(spdm_context, &session_id, &is_app_message,
                                                   false, m_response_size, m_response,
                                                   &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_null(session_id);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AFTER_VERSION);
}

/**
 * Test 2: Receiving the request fails.
 * Expected Behavior: libspdm_responder_dispatch_message returns the receive failure without
 * sending a response.
 **/
static void rsp_communication_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    m_response_count = 0;

    status = libspdm_responder_dispatch_message(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
    assert_int_equal(m_response_count, 0);
}

/**
 * Test 3: Dispatch application data that the Requester sent in an established session.
 * Expected Behavior: libspdm_responder_dispatch_message gives the application data to the
 * Integrator's function as application data, and sends one response that holds that function's
 * application data in the same session.
 **/
static void rsp_communication_case3(void **state)
{
#if ((LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)) && \
    (LIBSPDM_AEAD_AES_256_GCM_SUPPORT)
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t *session_id;
    bool is_app_message;
    uint8_t *response;
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    m_response_count = 0;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_register_get_response_func(spdm_context, get_app_response);

    status = libspdm_responder_dispatch_message(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_true(m_app_request_is_app_message);
    assert_int_equal(m_app_request_session_id, m_session_id);
    assert_int_equal(m_app_request_received_size, sizeof(m_app_request));
    assert_memory_equal(m_app_request_received, m_app_request, sizeof(m_app_request));

    assert_int_equal(m_response_count, 1);
    rewind_sequence_number(spdm_context, false);
    libspdm_get_scratch_buffer(spdm_context, (void **)&response, &response_size);
    status = libspdm_transport_test_decode_message(spdm_context, &session_id, &is_app_message,
                                                   false, m_response_size, m_response,
                                                   &response_size, (void **)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(session_id);
    assert_int_equal(*session_id, m_session_id);
    assert_true(is_app_message);
    assert_int_equal(response_size, sizeof(m_app_response));
    assert_memory_equal(response, m_app_response, sizeof(m_app_response));

    spdm_context->get_response_func = NULL;
    libspdm_free_session_id(spdm_context, m_session_id);
#else
    skip();
#endif
}

int libspdm_rsp_communication_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_communication_case1),
        cmocka_unit_test(rsp_communication_case2),
        cmocka_unit_test(rsp_communication_case3),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
