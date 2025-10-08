/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP)

static uint8_t m_spdm_request_buffer[0x1000];
static uint8_t m_spdm_response_buffer[0x1000];

static const uint32_t m_session_id = 0xffffffff;

extern bool g_event_all_subscribe;
extern bool g_event_all_unsubscribe;

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
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
}

/**
 * Test 1: Successful response to subscribe event types that clears all events.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS with the expected values.
 **/
static void req_encap_subscribe_event_types_ack_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_subscribe_event_types_request_t *subscribe_event_types;
    size_t request_size;
    spdm_subscribe_event_types_ack_response_t *subscribe_event_types_ack;
    size_t response_size =  sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    subscribe_event_types = (spdm_subscribe_event_types_request_t *)m_spdm_request_buffer;

    subscribe_event_types->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    subscribe_event_types->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES;
    subscribe_event_types->header.param1 = 0;
    subscribe_event_types->header.param2 = 0;

    request_size = sizeof(spdm_message_header_t);

    status = libspdm_get_encap_subscribe_event_types_ack(spdm_context,
                                                         request_size,
                                                         m_spdm_request_buffer,
                                                         &response_size,
                                                         m_spdm_response_buffer);

    subscribe_event_types_ack = (spdm_subscribe_event_types_ack_response_t *)m_spdm_response_buffer;

    assert_int_equal(response_size, sizeof(spdm_subscribe_event_types_ack_response_t));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(subscribe_event_types_ack->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(subscribe_event_types_ack->header.request_response_code,
                     SPDM_SUBSCRIBE_EVENT_TYPES_ACK);
    assert_int_equal(subscribe_event_types_ack->header.param1, 0);
    assert_int_equal(subscribe_event_types_ack->header.param2, 0);

    assert_true(!g_event_all_subscribe && g_event_all_unsubscribe);
}

static void req_encap_subscribe_event_types_ack_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_subscribe_event_types_request_t *subscribe_event_types;
    size_t request_size;
    spdm_subscribe_event_types_ack_response_t *subscribe_event_types_ack;
    size_t response_size =  sizeof(m_spdm_response_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    subscribe_event_types = (spdm_subscribe_event_types_request_t *)m_spdm_request_buffer;

    subscribe_event_types->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    subscribe_event_types->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES;
    subscribe_event_types->header.param1 = 1;
    subscribe_event_types->header.param2 = 0;

    generate_dmtf_event_group(subscribe_event_types + 1,
                              (uint8_t *)&subscribe_event_types->subscribe_list_len,
                              0, true, true, false, false);

    request_size = sizeof(spdm_subscribe_event_types_request_t) +
                   subscribe_event_types->subscribe_list_len;

    status = libspdm_get_encap_subscribe_event_types_ack(spdm_context,
                                                         request_size,
                                                         m_spdm_request_buffer,
                                                         &response_size,
                                                         m_spdm_response_buffer);

    subscribe_event_types_ack = (spdm_subscribe_event_types_ack_response_t *)m_spdm_response_buffer;

    assert_int_equal(response_size, sizeof(spdm_subscribe_event_types_ack_response_t));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(subscribe_event_types_ack->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(subscribe_event_types_ack->header.request_response_code,
                     SPDM_SUBSCRIBE_EVENT_TYPES_ACK);
    assert_int_equal(subscribe_event_types_ack->header.param1, 0);
    assert_int_equal(subscribe_event_types_ack->header.param2, 0);

    assert_true(!g_event_all_subscribe && !g_event_all_unsubscribe);
}

int libspdm_req_encap_subscribe_event_types_ack_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_encap_subscribe_event_types_ack_case1),
        cmocka_unit_test(req_encap_subscribe_event_types_ack_case2),
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

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP) */
