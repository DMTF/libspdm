/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#define LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT SPDM_MAX_VERSION_COUNT

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];
} libspdm_version_response_mine_t;
#pragma pack()

spdm_get_version_request_t m_libspdm_get_version_request1 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_VERSION,
    },
};
size_t m_libspdm_get_version_request1_size = sizeof(m_libspdm_get_version_request1);

spdm_get_version_request_t m_libspdm_get_version_request3 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_VERSION,
    },
};
size_t m_libspdm_get_version_request3_size = sizeof(m_libspdm_get_version_request3);

spdm_get_version_request_t m_libspdm_get_version_request4 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_VERSION,
    },
};
size_t m_libspdm_get_version_request4_size = sizeof(m_libspdm_get_version_request4);

/**
 * Test 1: receiving a correct GET_VERSION from the requester.
 * Expected behavior: the responder accepts the request, produces a valid VERSION
 * response message, and then resets the connection state.
 **/
static void rsp_version_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT *
                     sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AFTER_VERSION);
}

/**
 * Test 2:
 * Expected behavior:
 **/
static void rsp_version_case2(void **state)
{
}

/**
 * Test 3: receiving a correct GET_VERSION from the requester, but the responder is in
 * a Busy state.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the Buse state.
 **/
static void rsp_version_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_BUSY);
}

/**
 * Test 4: receiving a correct GET_VERSION from the requester, but the responder requires
 * resynchronization with the requester.
 * Expected behavior: the requester resets the communication upon receiving the GET_VERSION
 * message, fulfilling the resynchronization. A valid VERSION message is produced.
 **/
static void rsp_version_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT *
                     sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);
}

/**
 * Test 6: receiving a GET_VERSION message in SPDM version 1.1 (in the header), but correct
 * 1.0-version format.
 * Expected behavior: the responder refuses the GET_VERSION message, produces an
 * ERROR message indicating the VersionMismatch, and will not reset the connection state.
 **/
static void rsp_version_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request3_size,
                                          &m_libspdm_get_version_request3,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_10);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AUTHENTICATED);
}

/**
 * Test 7: can be populated with new test.
 **/
static void rsp_version_case7(void **state)
{
}

/**
 * Test 8: receiving a correct GET_VERSION from the requester. Buffers A, B and C
 * already have arbitrary data.
 * Expected behavior: the responder accepts the request and produces a valid VERSION
 * response message, buffers A, B and C should be first reset, and then buffer A
 * receives only the exchanged GET_VERSION and VERSION messages.
 **/
static void rsp_version_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    /*filling buffers with arbitrary data*/
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, 10, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = 10;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_set_mem(spdm_context->transcript.message_b.buffer, 8, (uint8_t) 0xEE);
    spdm_context->transcript.message_b.buffer_size = 8;
    libspdm_set_mem(spdm_context->transcript.message_c.buffer, 12, (uint8_t) 0xDD);
    spdm_context->transcript.message_c.buffer_size = 12;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_version(
        spdm_context, m_libspdm_get_version_request1_size, &m_libspdm_get_version_request1,
        &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT * sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);

    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     m_libspdm_get_version_request1_size + response_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer,
                        &m_libspdm_get_version_request1, m_libspdm_get_version_request1_size);
    assert_memory_equal(
        spdm_context->transcript.message_a.buffer + m_libspdm_get_version_request1_size,
        response, response_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
}

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
/**
 * Test 9: receiving a correct GET_VERSION from the requester while encapsulated flows are in
 * progress both outside of a session and within a session, each of them interrupted by an
 * encapsulated ERROR(ResponseNotReady) that the responder has yet to follow up on.
 * Expected behavior: the responder produces a valid VERSION response, and the GET_VERSION ends
 * every encapsulated flow and discards every pending ResponseNotReady, so that no flow of the
 * previous connection can be resumed in the new one.
 **/
static void rsp_version_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    /* A Requester-initiated flow outside of a session, interrupted by ResponseNotReady. */
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.request_id = 2;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = true;
    spdm_context->encap_context.response_not_ready_flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    /* A session-based mutual authentication flow within a session, likewise interrupted. */
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, 0xFFFFFFFF,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
    session_info->encap_context.request_id = 1;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    session_info->encap_context.response_not_ready = true;
    session_info->encap_context.response_not_ready_flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT *
                     sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);

    /* No flow survives GET_VERSION, and no interrupted flow can be resumed after it. */
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    assert_false(spdm_context->encap_context.response_not_ready);
    assert_false(session_info->encap_context.response_not_ready);
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    /* The session that the flow belonged to is gone as well. */
    assert_int_equal(session_info->session_id, INVALID_SESSION_ID);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

int libspdm_rsp_version_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_version_case1),
        /* Invalid request*/
        cmocka_unit_test(rsp_version_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(rsp_version_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(rsp_version_case4),
        /* Invalid request*/
        cmocka_unit_test(rsp_version_case6),
        /* Invalid request*/
        cmocka_unit_test(rsp_version_case7),
        /* Buffer verification*/
        cmocka_unit_test(rsp_version_case8),
#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
        /* Encapsulated flows and pending ResponseNotReady are ended */
        cmocka_unit_test(rsp_version_case9),
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
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
