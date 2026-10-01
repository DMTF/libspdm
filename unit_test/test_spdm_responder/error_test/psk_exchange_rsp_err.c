/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

static uint8_t m_libspdm_psk_exchange_request[sizeof(spdm_psk_exchange_request_t) +
                                              sizeof(LIBSPDM_TEST_PSK_HINT_STRING) +
                                              LIBSPDM_PSK_CONTEXT_LENGTH +
                                              SPDM_MAX_OPAQUE_DATA_SIZE + 4];

/**
 * Test 1: The Requester's OpaqueDataLength is greater than SPDM_MAX_OPAQUE_DATA_SIZE, and
 *         PSK_EXCHANGE carries that much OpaqueData.
 * Expected behavior: the Responder returns an ERROR message with ErrorCode=InvalidRequest,
 *                    without processing the OpaqueData or creating a session.
 **/
static void rsp_psk_exchange_rsp_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    spdm_psk_exchange_request_t *spdm_request;
    size_t spdm_request_size;
    uint8_t *ptr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_request = (void *)m_libspdm_psk_exchange_request;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request->header.request_response_code = SPDM_PSK_EXCHANGE;
    spdm_request->header.param1 = SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
    spdm_request->header.param2 = 0;
    spdm_request->req_session_id = 0xFFFF;
    spdm_request->psk_hint_length = (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    spdm_request->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    /* {ERROR} OpaqueDataLength is greater than SPDM_MAX_OPAQUE_DATA_SIZE. */
    spdm_request->opaque_length = SPDM_MAX_OPAQUE_DATA_SIZE + 4;

    ptr = (uint8_t *)(spdm_request + 1);
    libspdm_copy_mem(ptr, spdm_request->psk_hint_length,
                     LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += spdm_request->psk_hint_length;
    libspdm_set_mem(ptr, spdm_request->context_length, 0x5A);
    ptr += spdm_request->context_length;
    libspdm_zero_mem(ptr, spdm_request->opaque_length);
    ptr += spdm_request->opaque_length;
    spdm_request_size = (size_t)(ptr - m_libspdm_psk_exchange_request);

    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(spdm_context, spdm_request_size, spdm_request,
                                               &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->session_info[0].session_id, INVALID_SESSION_ID);
}

int libspdm_rsp_psk_exchange_rsp_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_psk_exchange_rsp_err_case1),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
