/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP)

static uint8_t m_send_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];
static uint8_t m_receive_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];
static uint32_t m_session_id = 0xFFFFFFFF;

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

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
 * Test 1: Responder forms expected encapsulated GET_SUPPORTED_EVENT_TYPES request.
 **/
static void rsp_encap_supported_event_types_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size;
    spdm_get_supported_event_types_request_t *spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    request_buffer_size = sizeof(m_send_buffer);
    status = libspdm_get_encap_request_get_supported_event_types(
        spdm_context, &request_buffer_size, m_send_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(request_buffer_size, sizeof(spdm_get_supported_event_types_request_t));

    spdm_request = (spdm_get_supported_event_types_request_t *)m_send_buffer;
    assert_int_equal(spdm_request->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_request->header.request_response_code, SPDM_GET_SUPPORTED_EVENT_TYPES);
    assert_int_equal(spdm_request->header.param1, 0);
    assert_int_equal(spdm_request->header.param2, 0);

    assert_int_equal(spdm_context->encap_context.last_encap_request_size,
                     sizeof(spdm_get_supported_event_types_request_t));
    assert_int_equal(spdm_context->encap_context.last_encap_request_header.spdm_version,
                     SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_context->encap_context.last_encap_request_header.request_response_code,
                     SPDM_GET_SUPPORTED_EVENT_TYPES);
}

/**
 * Test 2: Responder accepts valid encapsulated SUPPORTED_EVENT_TYPES response.
 **/
static void rsp_encap_supported_event_types_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_supported_event_types_response_t *spdm_response;
    uint8_t *event_list;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    spdm_response = (spdm_supported_event_types_response_t *)m_receive_buffer;
    event_list = (uint8_t *)(spdm_response + 1);

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_SUPPORTED_EVENT_TYPES;
    spdm_response->header.param1 = 1;
    spdm_response->header.param2 = 0;
    spdm_response->supported_event_groups_list_len = 4;
    event_list[0] = 0x01;
    event_list[1] = 0x02;
    event_list[2] = 0x03;
    event_list[3] = 0x04;

    response_size = sizeof(spdm_supported_event_types_response_t) + 4;
    need_continue = true;

    status = libspdm_process_encap_response_supported_event_types(
        spdm_context, response_size, spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_false(need_continue);
}

/**
 * Test 3: init helper sets encapsulated GET_SUPPORTED_EVENT_TYPES sequence.
 **/
static void rsp_encap_supported_event_types_case3(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x03;

    set_standard_state(spdm_context);

    libspdm_init_get_supported_event_types_encap_state(spdm_context, m_session_id);

    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP);
    assert_int_equal(spdm_context->encap_context.current_request_op_code, 0);
    assert_int_equal(spdm_context->encap_context.request_id, 0);
    assert_int_equal(spdm_context->encap_context.request_op_code_count, 1);
    assert_int_equal(spdm_context->encap_context.request_op_code_sequence[0],
                     SPDM_GET_SUPPORTED_EVENT_TYPES);
    assert_int_equal(spdm_context->encap_context.session_id, m_session_id);
}

int libspdm_rsp_encap_supported_event_types_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_encap_supported_event_types_case1),
        cmocka_unit_test(rsp_encap_supported_event_types_case2),
        cmocka_unit_test(rsp_encap_supported_event_types_case3),
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
