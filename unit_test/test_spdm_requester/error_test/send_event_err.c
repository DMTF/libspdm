/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP

static uint32_t m_session_id = 0xffffffff;

static struct m_test_params {
    uint32_t event_count;
    size_t events_list_size;
    uint8_t events_list[0x1000];
} m_test_params;

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    assert_true(false);
    return LIBSPDM_STATUS_SEND_FAIL;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    assert_true(false);
    return LIBSPDM_STATUS_RECEIVE_FAIL;
}

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->latest_session_id = m_session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
}

/**
 * Test 1: Requester has not set EVENT_CAP.
 * Expected behavior: returns with LIBSPDM_STATUS_SUCCESS.
 **/
static void req_send_event_err_case1(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    set_standard_state(spdm_context);

    /* Clear EVENT_CAP. */
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 2: Connection version does not support SEND_EVENT.
 * Expected behavior: returns with LIBSPDM_STATUS_SUCCESS.
 **/
static void req_send_event_err_case2(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_return_t status;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    set_standard_state(spdm_context);

    /* Set version to 1.2, which does not support SEND_EVENT. */
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    m_test_params.event_count = 3;
    m_test_params.events_list_size = 100;

    for (int unsigned index = 0; index < m_test_params.events_list_size; index++) {
        m_test_params.events_list[index] = (uint8_t)index;
    }

    status = libspdm_send_event(spdm_context, m_session_id, m_test_params.event_count,
                                m_test_params.events_list_size, m_test_params.events_list);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

int libspdm_req_send_event_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_send_event_err_case1),
        cmocka_unit_test(req_send_event_err_case2),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
